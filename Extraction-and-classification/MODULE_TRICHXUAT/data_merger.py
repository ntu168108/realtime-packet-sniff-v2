# -*- coding: utf-8 -*-
"""
data_merger.py - Bước 4: Data Merging & Cleanup.

Merge hai DataFrame từ Argus và Zeek, xử lý trùng lặp MAC,
fill NaN, dọn dẹp file rác và xuất CSV cuối cùng.
"""

import pandas as pd
import logging
import os
import shutil

from config import MERGE_KEYS, MAC_FILL_VALUE, ARGUS_BINARY, ARGUS_TEMP_CSV, ZEEK_TEMP_CSV, OUTPUT_CSV, DEFAULT_OUTPUT_DIR
from zeek_handler import cleanup_zeek_logs

logger = logging.getLogger(__name__)


def merge_and_export(
    df_argus: pd.DataFrame,
    df_zeek: pd.DataFrame,
    work_dir: str,
    output_name: str = None,
    output_dir: str = None,
    cleanup: bool = True,
    base_name: str = None,
) -> str:
    """
    Merge 2 DataFrame, xử lý MAC trùng lặp, cleanup và xuất CSV.

    Args:
        df_argus:    DataFrame từ Argus (đã chuẩn hóa).
        df_zeek:     DataFrame từ Zeek (đã chuẩn hóa).
        work_dir:    Thư mục làm việc (chứa file trung gian).
        output_name: Tên file output (mặc định: final_features_nb15_with_mac.csv).
        output_dir:  Thư mục chứa file CSV đầu ra (mặc định: DEFAULT_OUTPUT_DIR).
        cleanup:     Có xóa file trung gian không (mặc định: True).

    Returns:
        Đường dẫn tuyệt đối tới file CSV cuối cùng.
    """
    if output_name is None:
        output_name = OUTPUT_CSV

    if output_dir is None:
        output_dir = DEFAULT_OUTPUT_DIR
    os.makedirs(output_dir, exist_ok=True)

    output_path = os.path.join(output_dir, output_name)

    # ------------------------------------------------------------------
    # Bước 4a: Merge hai DataFrame trên 5-tuple key
    # ------------------------------------------------------------------
    logger.info("Dang merge DataFrame...")
    logger.info("  Argus: %d dong | Zeek: %d dong", len(df_argus), len(df_zeek))
    logger.info("  Merge keys: %s", MERGE_KEYS)

    # ------------------------------------------------------------------
    # Chống nhân dòng (many-to-many): trong traffic DoS, nhiều flow có
    # cùng 5-tuple. Nếu merge thẳng trên 5-tuple sẽ tạo tích Descartes.
    # Giải pháp: gán occurrence-index (_occ) = thứ tự xuất hiện của flow
    # trong từng nhóm 5-tuple cho cả 2 nguồn, rồi merge trên (5-tuple + _occ).
    # => flow thứ N của Argus khớp đúng flow thứ N của Zeek (1-1).
    # ------------------------------------------------------------------
    df_argus = df_argus.copy()
    df_zeek = df_zeek.copy()
    df_argus["_occ"] = df_argus.groupby(MERGE_KEYS).cumcount()
    df_zeek["_occ"] = df_zeek.groupby(MERGE_KEYS).cumcount()

    df_merged = pd.merge(
        df_argus,
        df_zeek,
        on=MERGE_KEYS + ["_occ"],
        how="outer",           # Giữ tất cả dòng từ cả 2 nguồn
        suffixes=("_x", "_y"),  # Argus = _x, Zeek = _y
    )

    # _occ chỉ phục vụ căn chỉnh, bỏ sau khi merge
    if "_occ" in df_merged.columns:
        df_merged = df_merged.drop(columns=["_occ"])

    logger.info("  Ket qua merge: %d dong, %d cot", len(df_merged), len(df_merged.columns))

    # ------------------------------------------------------------------
    # Bước 4b: Xử lý trùng lặp MAC
    # Ưu tiên MAC từ Argus (_x). Nếu NaN thì dùng Zeek (_y).
    # ------------------------------------------------------------------
    df_merged = _resolve_mac_duplicates(df_merged, "src_mac")
    df_merged = _resolve_mac_duplicates(df_merged, "dst_mac")
    df_merged = _resolve_state_duplicates(df_merged)

    # ------------------------------------------------------------------
    # Bước 4c: Fill NaN cho tất cả cột MAC và trường HTTP/FTP mới
    # ------------------------------------------------------------------
    for mac_col in ["src_mac", "dst_mac"]:
        if mac_col in df_merged.columns:
            df_merged[mac_col] = df_merged[mac_col].fillna(MAC_FILL_VALUE)
            # Thay chuỗi rỗng bằng giá trị mặc định
            df_merged[mac_col] = df_merged[mac_col].replace("", MAC_FILL_VALUE)

    # Truong so HTTP/FTP -> fill '0'
    new_cols_num = ["trans_depth", "res_bdy_len", "is_ftp_login"]
    for col in new_cols_num:
        if col in df_merged.columns:
            df_merged[col] = df_merged[col].fillna("0")
            df_merged[col] = df_merged[col].replace("", "0")

    # Truong chuoi lam key (http_method, ftp_cmd) -> fill rong, KHONG ep '0'
    # (gia tri rong = flow khong phai HTTP/FTP -> gate 0 o add_features)
    new_cols_str = ["http_method", "ftp_cmd"]
    for col in new_cols_str:
        if col in df_merged.columns:
            df_merged[col] = df_merged[col].fillna("")

    logger.info("Da fill NaN cho MAC bang '%s', truong so HTTP/FTP bang '0', truong key chuoi bang rong.", MAC_FILL_VALUE)

    # ------------------------------------------------------------------
    # Bước 4d: Sắp xếp lại thứ tự cột cho đẹp
    # ------------------------------------------------------------------
    df_merged = _reorder_columns(df_merged)

    # ------------------------------------------------------------------
    # Bước 4e: Xuất CSV cuối cùng
    # ------------------------------------------------------------------
    df_merged.to_csv(output_path, index=False, encoding="utf-8")
    logger.info("Da xuat file ket qua: %s (%d dong)", output_path, len(df_merged))

    # ------------------------------------------------------------------
    # Bước 4f: Cleanup file trung gian
    # ------------------------------------------------------------------
    if cleanup:
        _cleanup_temp_files(work_dir, base_name=base_name, output_dir=output_dir, output_name=output_name)

    return output_path


def _resolve_mac_duplicates(df: pd.DataFrame, mac_col: str) -> pd.DataFrame:
    """
    Xử lý trùng lặp cột MAC sau khi merge.

    Sau merge, src_mac sẽ tách thành src_mac_x (Argus) và src_mac_y (Zeek).
    Logic: Ưu tiên Argus (_x). Nếu Argus NaN, dùng Zeek (_y).

    Args:
        df:      DataFrame đã merge.
        mac_col: Tên cột MAC gốc (vd: 'src_mac').

    Returns:
        DataFrame với cột MAC đã được gộp.
    """
    col_x = f"{mac_col}_x"
    col_y = f"{mac_col}_y"

    if col_x in df.columns and col_y in df.columns:
        logger.info("Dang gop %s: uu tien Argus (_x), fallback Zeek (_y)", mac_col)

        # Ưu tiên Argus. Nếu NaN hoặc rỗng, dùng Zeek.
        df[mac_col] = df[col_x].where(
            df[col_x].notna() & (df[col_x] != ""),
            df[col_y],
        )

        # Xóa cột thừa
        df = df.drop(columns=[col_x, col_y])
        logger.info("  Da xoa cot thua: %s, %s", col_x, col_y)

    elif col_x in df.columns and col_y not in df.columns:
        # Chỉ có Argus → rename lại
        df = df.rename(columns={col_x: mac_col})

    elif col_y in df.columns and col_x not in df.columns:
        # Chỉ có Zeek → rename lại
        df = df.rename(columns={col_y: mac_col})

    return df


def _resolve_state_duplicates(df: pd.DataFrame) -> pd.DataFrame:
    """
    Xử lý trùng lặp cột state sau khi merge.

    Sau merge, state sẽ tách thành state_x (Argus) và state_y (Zeek).
    Logic: Ưu tiên Zeek (_y) vì Zeek nhận diện chi tiết hơn cho TCP/IP state. Fallback Argus (_x).

    Args:
        df: DataFrame đã merge.

    Returns:
        DataFrame với cột state đã được gộp.
    """
    col_x = "state_x"
    col_y = "state_y"

    if col_x in df.columns and col_y in df.columns:
        logger.info("Dang gop state: uu tien Zeek (_y), fallback Argus (_x)")
        df["state"] = df[col_y].where(
            df[col_y].notna() & (df[col_y] != ""),
            df[col_x],
        )
        df = df.drop(columns=[col_x, col_y])
        logger.info("  Da xoa cot thua: %s, %s", col_x, col_y)
    elif col_x in df.columns:
        df = df.rename(columns={col_x: "state"})
    elif col_y in df.columns:
        df = df.rename(columns={col_y: "state"})

    return df


def _reorder_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Sắp xếp lại thứ tự cột theo logic:
    MAC → IP → Port → Protocol → Service/State → Metrics.

    Args:
        df: DataFrame cần sắp xếp.

    Returns:
        DataFrame với cột đã sắp xếp lại.
    """
    priority_order = [
        "src_mac", "dst_mac",
        "srcip", "dstip",
        "sport", "dport",
        "proto",
        "service", "state",
        "dur",
        "spkts", "dpkts",
        "sbytes", "dbytes",
        "sttl", "dttl",
        "smeansz", "dmeansz",
        "trans_depth", "res_bdy_len", "http_method",
        "is_ftp_login", "ftp_cmd",
    ]

    # Lấy các cột có trong DataFrame theo thứ tự ưu tiên
    ordered = [col for col in priority_order if col in df.columns]
    # Thêm các cột còn lại (nếu có) mà không nằm trong priority
    remaining = [col for col in df.columns if col not in ordered]
    final_order = ordered + remaining

    return df[final_order]


def _cleanup_temp_files(work_dir: str, base_name: str = None, output_dir: str = None, output_name: str = None) -> None:
    """
    Xóa các file trung gian: traffic.argus, argus_temp.csv,
    zeek_temp.csv, và thư mục Zeek logs. Bảo tồn file http.log
    bằng cách copy nó sang thư mục đích dưới dạng <base_name>_http.log.

    Args:
        work_dir:    Thư mục làm việc.
        base_name:   Tên base name dùng để đặt tên http.log.
        output_dir:  Thư mục đích để copy http.log.
        output_name: Tên file output chính để suy luận base_name dự phòng.
    """
    # 1. Xác định base_name dự phòng nếu bị thiếu
    if base_name is None:
        if output_name:
            name_part, _ = os.path.splitext(os.path.basename(output_name))
            if name_part.endswith("_raw"):
                base_name = name_part[:-4]
            else:
                base_name = name_part
        else:
            base_name = "traffic"

    # 2. Thực hiện Smart Cleanup cho http.log
    from zeek_handler import ZEEK_LOG_DIR
    zeek_log_dir = os.path.join(work_dir, ZEEK_LOG_DIR)
    http_paths = [
        os.path.join(zeek_log_dir, "http.log"),
        os.path.join(work_dir, "http.log")
    ]
    
    dest_dir = output_dir if output_dir else work_dir
    os.makedirs(dest_dir, exist_ok=True)
    
    for http_path in http_paths:
        if os.path.isfile(http_path):
            dest_path = os.path.join(dest_dir, f"{base_name}_http.log")
            try:
                shutil.copy2(http_path, dest_path)
                logger.info("Smart Cleanup: Da copy http.log den %s", dest_path)
            except Exception as e:
                logger.error("Smart Cleanup: Loi khi copy http.log: %s", e)
            break

    # 3. Tiến hành xóa các file tạm như cũ
    temp_files = [
        os.path.join(work_dir, ARGUS_BINARY),
        os.path.join(work_dir, ARGUS_TEMP_CSV),
        os.path.join(work_dir, ZEEK_TEMP_CSV),
    ]

    for fpath in temp_files:
        if os.path.isfile(fpath):
            os.remove(fpath)
            logger.info("Da xoa file tam: %s", fpath)

    # Xóa thư mục Zeek logs
    cleanup_zeek_logs(work_dir)

    logger.info("Cleanup file trung gian hoan tat.")
