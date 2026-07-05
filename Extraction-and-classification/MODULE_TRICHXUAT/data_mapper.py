# -*- coding: utf-8 -*-
"""
data_mapper.py - Bước 3: Data Mapping (Đổi tên cột chuẩn hóa).

Đọc 2 file CSV tạm (argus_temp.csv, zeek_temp.csv),
rename các cột theo chuẩn UNSW-NB15 và chuẩn hóa dữ liệu
trước khi merge.
"""

import pandas as pd
import logging

from config import ARGUS_RENAME_MAP, ZEEK_RENAME_MAP

logger = logging.getLogger(__name__)


def map_data(argus_csv: str, zeek_csv: str) -> tuple:
    """
    Đọc 2 file CSV trung gian, đổi tên cột và chuẩn hóa dữ liệu.

    Args:
        argus_csv: Đường dẫn tới file argus_temp.csv.
        zeek_csv:  Đường dẫn tới file zeek_temp.csv.

    Returns:
        Tuple (df_argus, df_zeek) - 2 DataFrame đã chuẩn hóa.
    """
    # ------------------------------------------------------------------
    # Đọc CSV
    # ------------------------------------------------------------------
    logger.info("Dang doc file Argus CSV: %s", argus_csv)
    df_argus = pd.read_csv(argus_csv, dtype=str, keep_default_na=False)
    logger.info("  -> %d dong, %d cot", len(df_argus), len(df_argus.columns))

    logger.info("Dang doc file Zeek CSV: %s", zeek_csv)
    df_zeek = pd.read_csv(zeek_csv, dtype=str, keep_default_na=False)
    logger.info("  -> %d dong, %d cot", len(df_zeek), len(df_zeek.columns))

    # ------------------------------------------------------------------
    # Loại bỏ khoảng trắng thừa ở tên cột (ra có thể thêm space)
    # ------------------------------------------------------------------
    df_argus.columns = [col.strip() for col in df_argus.columns]
    df_zeek.columns = [col.strip() for col in df_zeek.columns]

    # ------------------------------------------------------------------
    # Rename cột theo mapping chuẩn NB15
    # ------------------------------------------------------------------
    logger.info("Dang doi ten cot Argus theo chuan NB15...")
    df_argus = df_argus.rename(columns=ARGUS_RENAME_MAP)
    logger.debug("  Cot Argus sau rename: %s", list(df_argus.columns))

    logger.info("Dang doi ten cot Zeek theo chuan NB15...")
    df_zeek = df_zeek.rename(columns=ZEEK_RENAME_MAP)
    logger.debug("  Cot Zeek sau rename: %s", list(df_zeek.columns))

    # ------------------------------------------------------------------
    # Chuẩn hóa cột proto (lowercase thống nhất)
    # ------------------------------------------------------------------
    if "proto" in df_argus.columns:
        df_argus["proto"] = df_argus["proto"].str.strip().str.lower()
    if "proto" in df_zeek.columns:
        df_zeek["proto"] = df_zeek["proto"].str.strip().str.lower()

    logger.info("Da chuan hoa cot proto -> lowercase.")

    # ------------------------------------------------------------------
    # Chuẩn hóa sport/dport cho ICMP
    # ICMP không có port, Argus/Zeek có thể trả "0", "0x..."
    # hoặc giá trị type/code. Ép tất cả về string để merge không lỗi.
    # ------------------------------------------------------------------
    df_argus = _normalize_ports(df_argus)
    df_zeek = _normalize_ports(df_zeek)

    # ------------------------------------------------------------------
    # Loại bỏ khoảng trắng thừa trong giá trị các cột dùng để merge
    # ------------------------------------------------------------------
    merge_cols = ["srcip", "dstip", "sport", "dport", "proto"]
    for col in merge_cols:
        if col in df_argus.columns:
            df_argus[col] = df_argus[col].str.strip()
        if col in df_zeek.columns:
            df_zeek[col] = df_zeek[col].str.strip()

    logger.info("Data mapping hoan tat.")
    return df_argus, df_zeek


def _normalize_ports(df: pd.DataFrame) -> pd.DataFrame:
    """
    Chuẩn hóa sport và dport:
    - Ép kiểu về string
    - Với ICMP (proto == 'icmp'), đặt port = '0'
      vì ICMP không có khái niệm port thực sự.

    Args:
        df: DataFrame cần chuẩn hóa.

    Returns:
        DataFrame đã chuẩn hóa.
    """
    for port_col in ["sport", "dport"]:
        if port_col not in df.columns:
            continue

        # Đảm bảo tất cả là string
        df[port_col] = df[port_col].astype(str).str.strip()

        # Với dòng ICMP, chuẩn hóa port về '0'
        if "proto" in df.columns:
            icmp_mask = df["proto"].str.lower() == "icmp"
            df.loc[icmp_mask, port_col] = "0"

        # Thay thế các giá trị trống/rỗng bằng '0'
        df[port_col] = df[port_col].replace({"": "0", " ": "0"})

    logger.debug("Da chuan hoa port (ICMP -> 0, empty -> 0).")
    return df
