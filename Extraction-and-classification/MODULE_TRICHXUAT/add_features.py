#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
add_features.py - Đổi tên cột, tạo đặc trưng rule-based và sliding window cho dataset UNSW-NB15.
"""
import pandas as pd
import numpy as np
import argparse
import sys
import time
import os
from typing import List

def setup_logging():
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    return logging.getLogger("add_features")

logger = setup_logging()

def compute_sliding_counts(values: List, window_size: int = 100) -> List:
    """
    Tính số lượng phần tử trùng với phần tử hiện tại trong cửa sổ trượt look-back kích thước window_size.
    Độ phức tạp thời gian: O(N) bằng giải thuật Sliding Frequency Dictionary.
    """
    counts = {}
    res = []
    for i, val in enumerate(values):
        if i >= window_size:
            old_val = values[i - window_size]
            counts[old_val] -= 1
        counts[val] = counts.get(val, 0) + 1
        res.append(counts[val])
    return res

def compute_sliding_counts_gated(keys: List, gates: List, window_size: int = 100) -> List:
    """
    Biến thể của compute_sliding_counts dùng cho ct_flw_http_mthd (Alg 3.4)
    và ct_ftp_cmd (Alg 3.6).

    Chỉ những flow có gate == 1 (tức có HTTP method / FTP command) mới được
    đưa vào cửa sổ trượt và được đếm. Flow có gate == 0 (không phải HTTP/FTP,
    hoặc không có method/command) luôn nhận giá trị 0, đúng nhánh "else -> 0"
    trong thuật toán gốc.

    Args:
        keys:        Danh sách khóa kết hợp (vd: srcip_dstip_sport_dport).
        gates:       Danh sách cờ 0/1 cùng độ dài với keys.
        window_size: Kích thước cửa sổ look-back (mặc định 100).
    """
    counts = {}
    window = []  # các (key, gate) đang nằm trong cửa sổ
    res = []
    for i, (key, gate) in enumerate(zip(keys, gates)):
        if i >= window_size:
            old_key, old_gate = window[i - window_size]
            if old_gate:
                counts[old_key] -= 1
        window.append((key, gate))
        if gate:
            counts[key] = counts.get(key, 0) + 1
            res.append(counts[key])
        else:
            res.append(0)
    return res

DEFAULTS = {
    "src_mac": "00:00:00:00:00:00",
    "dst_mac": "00:00:00:00:00:00",
    "srcip": "0.0.0.0",
    "dstip": "0.0.0.0",
    "sport": "0",
    "dport": "0",
    "proto": "unknown",
    "service": "-",
    "state": "INT",
    
    "dur": 0.0,
    "spkts": 0,
    "dpkts": 0,
    "sbytes": 0,
    "dbytes": 0,
    "sttl": 0,
    "dttl": 0,
    "sload": 0.0,
    "dload": 0.0,
    "sloss": 0,
    "dloss": 0,
    "swin": 0,
    "dwin": 0,
    "stcpb": 0,
    "dtcpb": 0,
    "smean": 0,
    "dmean": 0,
    "smeansz": 0,
    "dmeansz": 0,
    "sjit": 0.0,
    "djit": 0.0,
    "sinpkt": 0.0,
    "dinpkt": 0.0,
    "tcprtt": 0.0,
    "synack": 0.0,
    "ackdat": 0.0,
    "stime": 0.0,
    "ltime": 0.0,
    
    "trans_depth": 0,
    "response_body_len": 0,
    "res_bdy_len": 0,
    "is_ftp_login": 0,
    "ct_ftp_cmd": 0,
    "ct_flw_http_mthd": 0,

    # Helper tu zeek_temp.csv: gia tri method/command (string) lam mot phan key.
    # Dung de tinh ct_flw_http_mthd / ct_ftp_cmd theo cua so truot, sau do drop.
    "http_method": "",
    "ftp_cmd": "",
    
    "rate": 0.0,
    "is_sm_ips_ports": 0,
    "ct_state_ttl": 0,
    
    "ct_dst_ltm": 0,
    "ct_src_ltm": 0,
    "ct_srv_dst": 0,
    "ct_srv_src": 0,
    "ct_src_dport_ltm": 0,
    "ct_dst_sport_ltm": 0,
    "ct_dst_src_ltm": 0
}

def sanitize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Làm sạch toàn bộ DataFrame: ép kiểu và lấp đầy toàn bộ giá trị NaN/Null/trống.
    """
    logger.info("  Dang chuan hoa kieu du lieu va lam sach cac gia tri NaN/Null...")
    df = df.copy()
    for col in df.columns:
        if col in DEFAULTS:
            default_val = DEFAULTS[col]
            if isinstance(default_val, float):
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(default_val)
            elif isinstance(default_val, int) and not isinstance(default_val, bool):
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(default_val).astype('int64')
            else:
                df[col] = df[col].astype(str).str.strip()
                df[col] = df[col].replace(["nan", "None", "", "-", "-1"], default_val)
                df[col] = df[col].fillna(default_val)
        else:
            df[col] = df[col].fillna("")
    return df

def parse_dtcpb(series: pd.Series) -> pd.Series:
    """Vectorized: clean Destination TCP base sequence number."""
    return pd.to_numeric(series, errors="coerce").fillna(0).clip(lower=0).astype(int)


def parse_service(series: pd.Series) -> pd.Series:
    """Vectorized: normalize Application Layer Protocol (service) string."""
    return series.astype(str).str.strip().str.lower().fillna("-")

def sanitize_features(feature_dict: dict) -> dict:
    """
    Rà soát lần cuối toàn bộ dictionary chứa các đặc trưng trước khi xuất.
    Nếu phát hiện None, NaN, hoặc rỗng:
      - Nếu là trường dạng số (float/int), chuyển thành 0 (hoặc 0.0) dựa trên DEFAULTS.
      - Nếu là trường dạng chuỗi (string), chuyển thành "-".
    """
    import math
    sanitized = {}
    for key, val in feature_dict.items():
        is_null_or_empty = False
        if val is None or val == "":
            is_null_or_empty = True
        elif isinstance(val, float) and math.isnan(val):
            is_null_or_empty = True
            
        if is_null_or_empty:
            # Xác định kiểu dữ liệu mặc định
            default_val = DEFAULTS.get(key, "-")
            if isinstance(default_val, (int, float)) and not isinstance(default_val, bool):
                sanitized[key] = default_val
            else:
                sanitized[key] = "-"
        else:
            sanitized[key] = val
    return sanitized

def main():
    parser = argparse.ArgumentParser(description="Xu ly chuan hoa va bo sung dac trung UNSW-NB15.")
    parser.add_argument("input_csv", help="Duong dan toi file CSV du lieu mang (vi du: final_features_nb15_with_mac.csv).")
    parser.add_argument("-o", "--output", help="Duong dan file dau ra. Mac dinh ghi de hoac tao moi.")
    args = parser.parse_args()

    input_path = os.path.abspath(args.input_csv)
    if args.output:
        output_path = os.path.abspath(args.output)
    else:
        # Tự động xác định tên đầu ra dựa trên base_name
        dir_name = os.path.dirname(input_path)
        filename = os.path.basename(input_path)
        name_part, _ = os.path.splitext(filename)
        if name_part.endswith("_raw"):
            base_name = name_part[:-4]
        else:
            base_name = name_part
        output_path = os.path.join(dir_name, f"{base_name}_dos_features.csv")

    if not os.path.isfile(input_path):
        logger.error(f"Khong tim thay file dau vao: '{input_path}'")
        sys.exit(1)

    logger.info("=" * 60)
    logger.info(f"BAT DAU XU LY DAC TRUNG")
    logger.info(f"File dau vao: {input_path}")
    logger.info(f"File dau ra : {output_path}")
    logger.info("=" * 60)

    start_time = time.time()

    # Đọc dữ liệu
    logger.info("Dang doc file CSV...")
    
    # Đọc trước một vài dòng để lấy danh sách cột
    df_head = pd.read_csv(input_path, nrows=5)
    str_cols = ["src_mac", "dst_mac", "srcip", "dstip", "sport", "dport", "proto", "service", "state"]
    dtype_dict = {c: str for c in str_cols if c in df_head.columns}
    
    df = pd.read_csv(input_path, dtype=dtype_dict)
    logger.info(f"Da load {len(df):,} dong, {len(df.columns)} cot.")

    # Làm sạch và ép kiểu dữ liệu hệ thống
    df = sanitize_dataframe(df)

    # -------------------------------------------------------------
    # BƯỚC 1: Đổi tên các trường
    # -------------------------------------------------------------
    logger.info("-" * 60)
    logger.info("BUOC 1: Doi ten cac truong...")
    rename_map = {
        "smeansz": "smean",
        "dmeansz": "dmean",
        "res_bdy_len": "response_body_len"
    }
    # Chỉ đổi những cột có tồn tại
    existing_rename = {k: v for k, v in rename_map.items() if k in df.columns}
    if existing_rename:
        df = df.rename(columns=existing_rename)
        logger.info(f"  Da doi ten: {existing_rename}")
    else:
        logger.info("  Khong tim thay cac truong can doi ten (co the da duoc doi tu truoc).")

    # -------------------------------------------------------------
    # BƯỚC 2: Tạo các tính năng dựa trên luật logic tĩnh (Rule-based)
    # -------------------------------------------------------------
    logger.info("-" * 60)
    logger.info("BUOC 2: Tao cac tinh nang Rule-based...")

    # 2.1 Cột rate — đọc trực tiếp từ Argus (chuẩn NB15 gốc, lệnh rasqlinsert +rate).
    # Argus tự tính rate; ta KHÔNG tái định nghĩa bằng công thức phi-chính-thống.
    # Giá trị rỗng/NaN (flow Argus không có rate) -> 0.0.
    logger.info("  Su dung cot 'rate' tu Argus (chuan NB15 goc)...")
    if "rate" not in df.columns:
        logger.warning("  Khong tim thay cot 'rate' tu Argus -> dat 0.0 cho toan bo.")
        df["rate"] = 0.0
    else:
        df["rate"] = (
            pd.to_numeric(df["rate"], errors="coerce")
            .replace([np.inf, -np.inf], 0.0)
            .fillna(0.0)
        )

    # 2.2 Cột is_sm_ips_ports
    logger.info("  Tinh toan cot 'is_sm_ips_ports'...")
    srcip = df["srcip"].fillna("").astype(str).str.strip()
    dstip = df["dstip"].fillna("").astype(str).str.strip()
    sport = df["sport"].fillna("").astype(str).str.strip()
    dport = df["dport"].fillna("").astype(str).str.strip()

    df["is_sm_ips_ports"] = ((srcip == dstip) & (sport == dport)).astype(int)

    # 2.3 Cột ct_state_ttl
    logger.info("  Tinh toan cot 'ct_state_ttl'...")
    sttl = pd.to_numeric(df["sttl"], errors="coerce").fillna(-1).astype(int)
    dttl = pd.to_numeric(df["dttl"], errors="coerce").fillna(-1).astype(int)
    state = df["state"].fillna("").astype(str).str.strip().str.upper()

    conds = [
        sttl.isin([62, 63, 254, 255]) & dttl.isin([252, 253]) & (state == "FIN"),
        sttl.isin([0, 62, 254]) & (dttl == 0) & (state == "INT"),
        sttl.isin([62, 254]) & dttl.isin([60, 252, 253]) & (state == "CON"),
        (sttl == 254) & (dttl == 252) & (state == "ACC"),
        (sttl == 254) & (dttl == 252) & (state == "CLO"),
        (sttl == 254) & (dttl == 0) & (state == "REQ")
    ]
    choices = [1, 2, 3, 4, 5, 6]
    df["ct_state_ttl"] = np.select(conds, choices, default=0)

    # 2.4 Áp dụng guard clauses cho sinpkt, dinpkt, sjit, djit dựa trên số lượng gói tin
    logger.info("  Ap dung guard clauses cho sinpkt, dinpkt, sjit, djit...")
    # sinpkt / dinpkt: cần ít nhất 2 gói tin ở chiều đó, ngược lại bằng 0
    df.loc[df["spkts"] < 2, "sinpkt"] = 0.0
    df.loc[df["dpkts"] < 2, "dinpkt"] = 0.0
    # sjit / djit: cần ít nhất 3 gói tin ở chiều đó (tức là 2 khoảng thời gian), ngược lại bằng 0
    df.loc[df["spkts"] < 3, "sjit"] = 0.0
    df.loc[df["dpkts"] < 3, "djit"] = 0.0

    # 2.5 Xử lý bắt lỗi đặc biệt cho dtcpb và service
    logger.info("  Ap dung parse bat loi (try-except) cho dtcpb va service...")
    df["dtcpb"] = parse_dtcpb(df["dtcpb"])
    df["service"] = parse_service(df["service"])

    # -------------------------------------------------------------
    # BƯỚC 3: Tạo các tính năng Sliding Window (Cửa sổ trượt 100)
    # -------------------------------------------------------------
    logger.info("-" * 60)
    logger.info("BUOC 3: Tao cac tinh nang Sliding Window (Cua so truot look-back = 100)...")

    # 3.1 Đảm bảo DataFrame được sắp xếp tăng dần theo ltime
    logger.info("  Sap xep DataFrame theo ltime tang dan...")
    if "ltime" in df.columns:
        ltime_numeric = pd.to_numeric(df["ltime"], errors="coerce")
        # Giữ nguyên cấu trúc ban đầu bằng cách sắp xếp theo ltime, các dòng NaN sẽ đặt ở cuối
        # Dùng mergesort để giữ tính ổn định (stable sorting)
        df = df.iloc[ltime_numeric.argsort(kind='mergesort')].reset_index(drop=True)
    else:
        logger.warning("  Canh bao: Khong tim thay cot 'ltime' trong DataFrame de sap xep!")

    # 3.2 Chuẩn bị các trường đầu vào cho sliding window
    logger.info("  Chuan bi du lieu va khoa phu cho cua so truot...")
    dstip_list = df["dstip"].fillna("-").astype(str).str.strip().tolist()
    srcip_list = df["srcip"].fillna("-").astype(str).str.strip().tolist()
    sport_list = df["sport"].fillna("-").astype(str).str.strip().tolist()
    dport_list = df["dport"].fillna("-").astype(str).str.strip().tolist()
    service_list = df["service"].fillna("-").astype(str).str.strip().str.lower().tolist()

    # Tạo các key kết hợp cho so khớp đa điều kiện
    srv_dst = [f"{srv}_{dst}" for srv, dst in zip(service_list, dstip_list)]
    srv_src = [f"{srv}_{src}" for srv, src in zip(service_list, srcip_list)]
    src_dport = [f"{src}_{dp}" for src, dp in zip(srcip_list, dport_list)]
    dst_sport = [f"{dst}_{sp}" for dst, sp in zip(dstip_list, sport_list)]
    src_dst = [f"{src}_{dst}" for src, dst in zip(srcip_list, dstip_list)]

    # 3.3 Tính toán 7 cột đặc trưng look-back
    window_size = 100

    logger.info("  Tinh toan 7 cot sliding window...")
    for name, keys in (
        ("ct_dst_ltm", dstip_list), ("ct_src_ltm", srcip_list),
        ("ct_srv_dst", srv_dst), ("ct_srv_src", srv_src),
        ("ct_src_dport_ltm", src_dport), ("ct_dst_sport_ltm", dst_sport),
        ("ct_dst_src_ltm", src_dst),
    ):
        df[name] = compute_sliding_counts(keys, window_size)

    # 3.4 ct_flw_http_mthd (Alg 3.4) + ct_ftp_cmd (Alg 3.6)
    base_tuple = [
        f"{src}_{dst}_{sp}_{dp}"
        for src, dst, sp, dp in zip(srcip_list, dstip_list, sport_list, dport_list)
    ]

    if "http_method" in df.columns:
        http_mthd = df["http_method"].fillna("").astype(str).str.strip().str.upper().tolist()
    else:
        http_mthd = [""] * len(df)
    http_gate = [1 if m else 0 for m in http_mthd]
    http_key = [f"{bt}_{m}" for bt, m in zip(base_tuple, http_mthd)]
    df["ct_flw_http_mthd"] = compute_sliding_counts_gated(http_key, http_gate, window_size)

    if "ftp_cmd" in df.columns:
        ftp_cmd = df["ftp_cmd"].fillna("").astype(str).str.strip().str.upper().tolist()
    else:
        ftp_cmd = [""] * len(df)
    ftp_gate = [1 if c else 0 for c in ftp_cmd]
    ftp_key = [f"{bt}_{c}" for bt, c in zip(base_tuple, ftp_cmd)]
    df["ct_ftp_cmd"] = compute_sliding_counts_gated(ftp_key, ftp_gate, window_size)

    # Drop cột helper (giá trị method/command chỉ phục vụ tính toán, không thuộc bộ đặc trưng NB15)
    df = df.drop(columns=[c for c in ["http_method", "ftp_cmd"] if c in df.columns])

    # -------------------------------------------------------------
    # Ghi file kết quả
    # -------------------------------------------------------------
    logger.info("-" * 60)
    logger.info("  Ra soat va chuan hoa lan cuoi (sanitize_features)...")
    records = df.to_dict(orient="records")
    sanitized_records = [sanitize_features(r) for r in records]
    df = pd.DataFrame(sanitized_records)

    logger.info(f"Dang ghi ket qua ra file: {output_path}...")
    df.to_csv(output_path, index=False)
    
    elapsed = time.time() - start_time
    logger.info("=" * 60)
    logger.info("XU LY HOAN TAT THANH CONG!")
    logger.info(f"  Thoi gian thuc thi: {elapsed:.2f} giay")
    logger.info(f"  So dong ket qua   : {len(df):,}")
    logger.info(f"  So cot ket qua    : {len(df.columns)}")
    logger.info("=" * 60)

if __name__ == "__main__":
    main()
