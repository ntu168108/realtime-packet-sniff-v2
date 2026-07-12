#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
dos_classifier.py — Module phân loại DoS chuyên biệt và cảnh báo thông minh.

Đóng vai trò là lõi phân loại (Classification Engine) cho hệ thống IDS.
- Đầu vào: File CSV chứa các flow mạng đã được lọc và thư mục chứa file http.log của Zeek.
- Cơ chế: 3 bộ scoring riêng biệt cho SYN Flood, UDP Flood, ICMP Flood.
         Vectorized scoring bằng Pandas + NumPy, truy ngược context User từ Zeek log.
- Cảnh báo: In dòng cảnh báo màu trên Terminal khi phát hiện DoS theo từng loại cụ thể.
"""

import os
import sys
import argparse
import logging
import re
import pandas as pd
import numpy as np
from typing import Dict, Tuple, Optional

# Import bộ lọc đặc trưng DoS — dùng làm bước tiền xử lý tự động
from family_filter import run_family

# Hỗ trợ mã hóa trên Windows để tránh lỗi UnicodeEncodeError khi in emoji
for s in (sys.stdout, sys.stderr):
    if hasattr(s, "reconfigure"):
        try:
            s.reconfigure(errors="replace")
        except Exception:
            pass

# ---------------------------------------------------------------------------
# Cấu hình Baseline — 3 bộ scoring chuyên biệt
# ---------------------------------------------------------------------------
#
# Thiết kế dựa trên baseline thống kê UNSW-NB15 (tập feature cuối = K&S 19 ∪ Al-D):
#   - Kasongo & Sun (2020) [19]: sttl, ct_state_ttl, sbytes, dbytes, smean, dmean,
#     rate, sloss, dloss, tcprtt, synack, ct_srv_dst, ct_dst_src_ltm,
#     ct_dst_sport_ltm, ct_src_dport_ltm, ct_srv_src, proto, state, service
#   - Al-Daweri et al. [9]: dur, proto, sbytes, dbytes, sttl, dttl, djit, synack, ackdat
#   LƯU Ý: sload/dload/spkts/dpkts KHÔNG thuộc 2 nguồn -> đã loại khỏi bộ đặc trưng.
#
# Mỗi loại tấn công có bộ rule + ngưỡng riêng, tránh false positive do
# áp dụng rule TCP lên flow UDP/ICMP (và ngược lại).
# ---------------------------------------------------------------------------

BASELINE_CONFIG = {
    # ===========================================================================
    # Ngưỡng chung (shared thresholds) — dùng cho nhiều bộ scoring
    # ===========================================================================
    # LƯU Ý: sload/dload/spkts/dpkts đã bị loại khỏi bộ đặc trưng (không thuộc
    # 2 nguồn K&S 19 + Al-Daweri). Các ngưỡng liên quan đã được gỡ bỏ.
    'common_thresholds': {
        'sttl_high': 200,               # sttl >= 200 → spoofed TTL (baseline: DoS median = 254)
        'ct_state_ttl_min': 2,           # ct_state_ttl >= 2 → nghi DoS
        'dmean_max': 10,                 # dmean < 10 → server không phản hồi
        'rate_min': 50.0,                # rate > 50 pps
        'ct_dst_src_ltm_min': 3,         # ct_dst_src_ltm > 3
        'ct_dst_src_ltm_sat': 50,        # ct_dst_src_ltm >= 50 → cua so look-back (100) bao hoa = flood lap lien tuc
        'ct_dst_sport_ltm_min': 1,       # ct_dst_sport_ltm > 1
        'ct_src_dport_ltm_min': 1,       # ct_src_dport_ltm > 1
    },

    # ===========================================================================
    # SYN FLOOD — proto='tcp', kết nối không hoàn thành 3-way handshake
    # ===========================================================================
    # Đặc điểm: Gửi SYN liên tục, server không kịp SYN-ACK → half-open.
    # Trường hợp 1 (NB15 baseline): Spoofed IP → state=INT, sttl=254, dttl=0
    # Trường hợp 2 (hping3 thực tế): Real IP → state=REJ/S0/RSTRH,
    #   server gửi RST reject, synack=0, tcprtt=0
    # ===========================================================================
    'syn_flood': {
        'scores': {
            'sttl_high':          20,     # sttl >= 200 (spoofed TTL, importance 0.803)
            'state_int':          15,     # state == 'INT' (interrupted — spoofed IP attack)
            'state_s0':           15,     # state == 'S0' (SYN sent, no SYN-ACK — classic SYN flood)
            'state_rej':          10,     # state == 'REJ' (server reject — hping3 SYN flood)
            'state_rstrh':        10,     # state == 'RSTRH' (RST from server, half-open)
            'synack_zero':        15,     # synack == 0 → không hoàn thành handshake
            'tcprtt_zero':        10,     # tcprtt == 0 → không có phản hồi TCP
            'ct_state_ttl_high':  10,     # ct_state_ttl >= 2
            'dttl_zero':          10,     # dttl == 0 → đích không phản hồi
            'dbytes_zero':        10,     # dbytes == 0 → one-way flood
            'dmean_low':           5,     # dmean < 10
            'rate_high':           5,     # rate > 50 pps
            'ct_dst_src_ltm':      5,     # lặp nhiều kết nối src→dst
            'service_none':        5,     # service = '-' (không xác định)
        },
        'threshold': 42,                  # Ngưỡng SYN Flood (hiệu chỉnh sau khi gỡ sload/dload/dpkts)
    },

    # ===========================================================================
    # UDP FLOOD — proto='udp', gửi datagram liên tục không cần handshake
    # ===========================================================================
    # Đặc điểm: Gửi UDP packets ồ ạt, server phản hồi ICMP unreachable hoặc drop.
    # Dấu hiệu: dbytes=0, dpkts=0, dttl=0 (hoặc giá trị thấp), rate cao,
    #            service='-' (không phải DNS/NTP hợp lệ)
    # ===========================================================================
    'udp_flood': {
        'scores': {
            'sttl_high':          20,     # sttl >= 200 (spoofed TTL)
            'dbytes_zero':        15,     # dbytes == 0 → one-way flood
            'dttl_zero':          10,     # dttl == 0 → đích không phản hồi
            'rate_high':          10,     # rate > 50 pps → tốc độ cao
            'service_none':        5,     # service = '-' (không hợp lệ)
            'ct_dst_src_ltm':      5,     # lặp nhiều kết nối
            'dmean_low':           5,     # dmean < 10 → không phản hồi
        },
        'threshold': 32,                  # Ngưỡng UDP Flood (hiệu chỉnh sau khi gỡ sload/dload/dpkts)
    },

    # ===========================================================================
    # ICMP FLOOD — proto='icmp', gửi echo request liên tục (ping flood / smurf)
    # ===========================================================================
    # Đặc điểm: Gửi ICMP echo request liên tục, state='ECO' (echo).
    # Dấu hiệu: state=ECO, dbytes=0, dpkts=0, sloss=0, rate cao
    # ===========================================================================
    'icmp_flood': {
        'scores': {
            'sttl_high':          20,     # sttl >= 200 (spoofed TTL)
            'dbytes_zero':        15,     # dbytes == 0 → không có reply
            'state_eco':          10,     # state == 'ECO' (echo request)
            'dttl_zero':          10,     # dttl == 0 → đích không phản hồi
            'rate_high':          10,     # rate > 50 pps
            'ct_dst_src_ltm_sat': 20,     # ct_dst_src_ltm >= 50 → flood lap lien tuc (bat ping flood co phan hoi, ngoai baseline spoofed)
            'sloss_zero':          5,     # sloss == 0 → gửi chính xác (flood)
        },
        'threshold': 28,                  # Ngưỡng ICMP Flood (hiệu chỉnh sau khi gỡ sload/dload/dpkts)
    },
}

# ---------------------------------------------------------------------------
# Cấu hình Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Hàm truy ngược thông tin User (Cross-reference Zeek Log)
# ---------------------------------------------------------------------------
def load_zeek_http_log(zeek_dir: str) -> Dict[Tuple[str, str], str]:
    """
    Đọc http.log và xây dựng bảng lookup O(1) theo (id.orig_h, id.orig_p).
    Tối ưu hóa: Load file duy nhất 1 lần lúc khởi động.

    Args:
        zeek_dir: Đường dẫn đến thư mục chứa file http.log hoặc đường dẫn trực tiếp.

    Returns:
        Dict với key là (orig_ip, orig_port) dạng chuỗi, value là User Agent / Username.
    """
    lookup_dict = {}
    http_log_path = None

    if not zeek_dir:
        return lookup_dict

    # Xác định đường dẫn chính xác tới http.log
    if os.path.isfile(zeek_dir):
        bname = os.path.basename(zeek_dir)
        if bname == "http.log" or bname.endswith("_http.log"):
            http_log_path = zeek_dir
    else:
        # Tìm trong thư mục trực tiếp
        candidate = os.path.join(zeek_dir, "http.log")
        if os.path.isfile(candidate):
            http_log_path = candidate
        else:
            # Tìm trong thư mục con zeek_logs
            candidate_sub = os.path.join(zeek_dir, "zeek_logs", "http.log")
            if os.path.isfile(candidate_sub):
                http_log_path = candidate_sub
            else:
                # Quét đệ quy tìm http.log
                for root, _, files in os.walk(zeek_dir):
                    if "http.log" in files:
                        http_log_path = os.path.join(root, "http.log")
                        break

    if not http_log_path:
        logger.warning("Không tìm thấy file http.log. Sẽ bỏ qua phần truy ngược User.")
        return lookup_dict

    logger.info("Đang nạp file log: %s", http_log_path)
    try:
        with open(http_log_path, "r", encoding="utf-8") as f:
            headers = []
            separator = "\t"  # Mặc định của Zeek log
            
            for line in f:
                line = line.rstrip("\n\r")
                if not line:
                    continue
                
                # Parse cấu hình separator của Zeek
                if line.startswith("#separator"):
                    parts = line.split(" ")
                    if len(parts) > 1:
                        sep_str = parts[1]
                        if sep_str == "\\x09":
                            separator = "\t"
                        elif sep_str == " ":
                            separator = " "
                    continue
                
                # Parse danh sách trường
                if line.startswith("#fields"):
                    headers = line.split(separator)[1:]  # Bỏ qua phần '#fields'
                    continue
                
                # Bỏ qua các dòng comment khác
                if line.startswith("#"):
                    continue
                
                # Xử lý dòng dữ liệu
                if not headers:
                    continue
                
                parts = line.split(separator)
                if len(parts) < len(headers):
                    continue
                
                # Ánh xạ trường sang giá trị
                record = dict(zip(headers, parts))
                
                orig_h = record.get("id.orig_h")
                orig_p = record.get("id.orig_p")
                
                if not orig_h or not orig_p:
                    continue
                
                # Lấy user_agent và username
                user_agent = record.get("user_agent", "-")
                username = record.get("username", "-")
                
                # Chuẩn hoá các giá trị rỗng/mặc định của Zeek
                if user_agent in ("-", "", "(empty)"):
                    user_agent = ""
                if username in ("-", "", "(empty)"):
                    username = ""
                
                # Hợp nhất thông tin
                user_info = ""
                if user_agent and username:
                    user_info = f"{username} ({user_agent})"
                elif user_agent:
                    user_info = user_agent
                elif username:
                    user_info = username
                
                if user_info:
                    # Key dạng tuple (str, str)
                    key = (str(orig_h).strip(), str(orig_p).strip())
                    
                    # Ưu tiên ghi nhận log có dữ liệu đầy đủ nhất
                    if key not in lookup_dict or len(user_info) > len(lookup_dict[key]):
                        lookup_dict[key] = user_info
                        
        logger.info("Đã nạp thành công %d bản ghi HTTP để lookup.", len(lookup_dict))
    except Exception as exc:
        logger.error("Lỗi khi đọc file http.log: %s", exc)

    return lookup_dict


# ---------------------------------------------------------------------------
# Helper: trích xuất cột numerical an toàn
# ---------------------------------------------------------------------------
def _num(df: pd.DataFrame, col_name: str, default: float = 0.0) -> np.ndarray:
    """
    Trả về numpy array của cột *col_name* nếu tồn tại trong DataFrame,
    ngược lại trả về mảng zeros có cùng chiều dài.

    Args:
        df: DataFrame nguồn.
        col_name: Tên cột cần trích xuất.
        default: Giá trị mặc định nếu cột không tồn tại.

    Returns:
        numpy array chứa giá trị cột hoặc mảng hằng số *default*.
    """
    if col_name in df.columns:
        return pd.to_numeric(df[col_name], errors='coerce').fillna(default).values
    return np.full(len(df), default)


def _cat(df: pd.DataFrame, col_name: str) -> np.ndarray:
    """
    Trả về numpy array (object dtype) của cột categorical đã chuẩn hoá
    (strip + lowercase). Nếu cột không tồn tại, trả mảng chuỗi rỗng.

    Args:
        df: DataFrame nguồn.
        col_name: Tên cột cần trích xuất.

    Returns:
        numpy array chứa giá trị chuẩn hoá hoặc chuỗi rỗng.
    """
    if col_name in df.columns:
        return df[col_name].astype(str).str.strip().str.lower().values
    return np.full(len(df), '', dtype=object)


# ---------------------------------------------------------------------------
# Pre-compute tất cả boolean conditions 1 lần duy nhất
# ---------------------------------------------------------------------------
def _precompute_conditions(
    df: pd.DataFrame, config: dict
) -> dict:
    """
    Tính trước tất cả boolean arrays dùng chung cho cả 3 bộ scoring.
    Chỉ gọi 1 lần, tránh tính lại trùng lặp.

    Args:
        df: DataFrame nguồn.
        config: BASELINE_CONFIG chứa 'common_thresholds'.

    Returns:
        Dict mapping tên condition → boolean numpy array.
    """
    th = config['common_thresholds']
    n = len(df)

    # ----- Categorical arrays (1 lần duy nhất) -----
    proto_arr   = _cat(df, 'proto')
    state_arr   = _cat(df, 'state')
    service_arr = _cat(df, 'service')

    # ----- Numerical arrays (1 lần duy nhất) -----
    sttl_arr         = _num(df, 'sttl', 0.0)
    dttl_arr         = _num(df, 'dttl', 0.0)
    ct_state_ttl_arr = _num(df, 'ct_state_ttl', 0.0)
    dbytes_arr       = _num(df, 'dbytes', 0.0)
    dmean_arr        = _num(df, 'dmean', 0.0)
    rate_arr         = _num(df, 'rate', 0.0)
    synack_arr       = _num(df, 'synack', 0.0)
    tcprtt_arr       = _num(df, 'tcprtt', 0.0)
    sloss_arr        = _num(df, 'sloss', 0.0)
    ct_dst_src_ltm_arr = _num(df, 'ct_dst_src_ltm', 0.0)
    dport_arr        = _num(df, 'dport', 0.0)

    # ----- Protocol masks -----
    is_tcp  = proto_arr == 'tcp'
    is_udp  = proto_arr == 'udp'
    is_icmp = proto_arr == 'icmp'

    # ----- UDP whitelist: loại trừ traffic hợp lệ -----
    # mDNS (port 5353), DHCP (port 67-68), broadcast/multicast
    is_mdns = (dport_arr == 5353)
    is_dhcp = (dport_arr == 67) | (dport_arr == 68)
    srcip_arr = _cat(df, 'srcip')
    is_broadcast = (
        (srcip_arr == '0.0.0.0')
        | (srcip_arr == '255.255.255.255')
    )
    # Multicast: 224.0.0.0/4 (IPv4 224.-239.) hoặc IPv6 ff::
    # LƯU Ý: dùng pandas .str thay cho np.char.startswith — np.char yêu cầu mảng
    # kiểu <U (fixed-width unicode); mảng srcip là object dtype nên np.char ném
    # UFuncNoLoopError trên NumPy >= 2.0. pandas .str.match/.startswith hoạt động
    # với mọi phiên bản NumPy và tự bỏ qua NaN an toàn.
    _srcip_ser = pd.Series(srcip_arr, dtype="object").astype(str)
    is_multicast = (
        _srcip_ser.str.match(r"^(22[4-9]|23[0-9])\.").fillna(False)
        | _srcip_ser.str.startswith("ff")
    ).to_numpy(dtype=bool)
    # UDP nghi ngờ = UDP nhưng KHÔNG phải mDNS/DHCP/broadcast/multicast
    is_udp_suspect = is_udp & ~is_mdns & ~is_dhcp & ~is_broadcast & ~is_multicast

    # ----- Shared feature conditions -----
    conds = {
        # Protocol masks
        'is_tcp':  is_tcp,
        'is_udp':  is_udp,
        'is_udp_suspect': is_udp_suspect,
        'is_icmp': is_icmp,

        # TTL & trạng thái
        'sttl_high':          sttl_arr >= th['sttl_high'],
        'ct_state_ttl_high':  ct_state_ttl_arr >= th['ct_state_ttl_min'],
        # _num() fills NaN with 0.0, so "missing" and "explicitly zero" both
        # count as dttl_zero. No extra isna() check needed.
        'dttl_zero':          dttl_arr == 0,

        # Lưu lượng
        'dbytes_zero':  dbytes_arr == 0,
        'dmean_low':    dmean_arr < th['dmean_max'],
        'rate_high':    rate_arr > th['rate_min'],

        # TCP-specific
        'synack_zero':  synack_arr == 0,
        'tcprtt_zero':  tcprtt_arr == 0,

        # Mất gói
        'sloss_zero':   sloss_arr == 0,

        # Connection tracking
        'ct_dst_src_ltm':  ct_dst_src_ltm_arr > th['ct_dst_src_ltm_min'],
        'ct_dst_src_ltm_sat':  ct_dst_src_ltm_arr >= th['ct_dst_src_ltm_sat'],  # cua so look-back bao hoa

        # State-specific — SYN Flood có nhiều biến thể state
        'state_int':    state_arr == 'int',     # Interrupted (spoofed IP → server không reply)
        'state_rej':    state_arr == 'rej',     # Rejected (server gửi RST — hping3 pattern)
        'state_s0':     state_arr == 's0',      # SYN sent, no SYN-ACK (half-open)
        'state_rstrh':  state_arr == 'rstrh',   # RST from server, half-open
        'state_eco':    state_arr == 'eco',     # ICMP echo

        # Service
        'service_none': (service_arr == '-') | (service_arr == '') | (
            df['service'].isna().values if 'service' in df.columns else np.zeros(n, dtype=bool)
        ),
    }

    return conds


# ---------------------------------------------------------------------------
# Logic Chấm Điểm Vectorized — 3 bộ scoring riêng biệt
# ---------------------------------------------------------------------------
def evaluate_dos_scores(df: pd.DataFrame, config: dict) -> pd.DataFrame:
    """
    Tính điểm rủi ro chuyên biệt cho từng loại tấn công DoS.

    Tạo 3 cột mới:
      - syn_score:     Điểm SYN Flood (chỉ cho proto=tcp)
      - udp_score:     Điểm UDP Flood (chỉ cho proto=udp)
      - icmp_score:    Điểm ICMP Flood (chỉ cho proto=icmp)
      - dos_score:     Điểm tổng hợp = max(syn, udp, icmp)

    Args:
        df: DataFrame chứa dữ liệu flow mạng.
        config: BASELINE_CONFIG chứa 3 bộ scoring + common_thresholds.

    Returns:
        DataFrame gốc kèm thêm 4 cột điểm rủi ro.
    """
    # Pre-compute tất cả conditions 1 lần
    conds = _precompute_conditions(df, config)

    # ----- SYN Flood Score (chỉ cho TCP) -----
    proto_mask = conds['is_tcp']
    n = len(proto_mask)
    syn_scores = np.zeros(n, dtype=np.float64)
    for rule_name, score_value in config['syn_flood']['scores'].items():
        if rule_name in conds:
            syn_scores += np.where(proto_mask & conds[rule_name], score_value, 0)

    # ----- UDP Flood Score (chỉ cho UDP nghi ngờ — loại trừ mDNS/DHCP/broadcast) -----
    proto_mask = conds['is_udp_suspect']
    n = len(proto_mask)
    udp_scores = np.zeros(n, dtype=np.float64)
    for rule_name, score_value in config['udp_flood']['scores'].items():
        if rule_name in conds:
            udp_scores += np.where(proto_mask & conds[rule_name], score_value, 0)

    # ----- ICMP Flood Score (chỉ cho ICMP) -----
    proto_mask = conds['is_icmp']
    n = len(proto_mask)
    icmp_scores = np.zeros(n, dtype=np.float64)
    for rule_name, score_value in config['icmp_flood']['scores'].items():
        if rule_name in conds:
            icmp_scores += np.where(proto_mask & conds[rule_name], score_value, 0)

    # Gán vào DataFrame
    df['syn_score']     = syn_scores.astype(int)
    df['udp_score']     = udp_scores.astype(int)
    df['icmp_score']    = icmp_scores.astype(int)

    # dos_score = điểm cao nhất trong 3 bộ (tương thích ngược)
    df['dos_score'] = np.maximum.reduce([
        syn_scores, udp_scores, icmp_scores
    ]).astype(int)

    logger.info(
        "Scoring hoàn tất: SYN max=%d, UDP max=%d, ICMP max=%d",
        int(syn_scores.max()) if len(syn_scores) > 0 else 0,
        int(udp_scores.max()) if len(udp_scores) > 0 else 0,
        int(icmp_scores.max()) if len(icmp_scores) > 0 else 0,
    )

    return df


# ---------------------------------------------------------------------------
# Phân loại DoS Subtype (Vectorized)
# ---------------------------------------------------------------------------
def classify_dos_subtype(df: pd.DataFrame, config: dict) -> pd.DataFrame:
    """
    Phân loại DoS subtype dựa trên điểm chuyên biệt vượt ngưỡng riêng.

    Logic:
      1. SYN Flood:  syn_score >= syn_threshold
      2. UDP Flood:  udp_score >= udp_threshold
      3. ICMP Flood: icmp_score >= icmp_threshold
      4. Normal:     không vượt ngưỡng nào

    Nếu flow vượt ngưỡng nhiều bộ (hiếm khi xảy ra vì mỗi bộ chỉ chấm
    cho đúng proto), ưu tiên bộ có điểm cao nhất.

    Args:
        df: DataFrame đã có các cột scoring.
        config: BASELINE_CONFIG chứa threshold cho từng loại.

    Returns:
        DataFrame gốc kèm thêm cột 'attack_type'.
    """
    syn_th     = config['syn_flood']['threshold']
    udp_th     = config['udp_flood']['threshold']
    icmp_th    = config['icmp_flood']['threshold']

    # Boolean masks: vượt ngưỡng riêng
    is_syn     = df['syn_score'].values >= syn_th
    is_udp     = df['udp_score'].values >= udp_th
    is_icmp    = df['icmp_score'].values >= icmp_th

    # Bất kỳ loại nào vượt ngưỡng → là DoS
    is_dos = is_syn | is_udp | is_icmp

    # Gán kết quả — dòng không vượt ngưỡng giữ NaN
    # Thứ tự gán: ICMP → UDP → SYN (last-write-wins → SYN > UDP > ICMP),
    # khớp với thứ tự ưu tiên của np.select ban đầu.
    df['attack_type'] = np.nan
    df.loc[is_icmp, 'attack_type'] = 'ICMP Flood'
    df.loc[is_udp,  'attack_type'] = 'UDP Flood'
    df.loc[is_syn,  'attack_type'] = 'SYN Flood'

    # Log thống kê
    n_syn     = int(is_syn.sum())
    n_udp     = int(is_udp.sum())
    n_icmp    = int(is_icmp.sum())
    n_dos     = int(is_dos.sum())

    logger.info(
        "Phân loại subtype: SYN=%d, UDP=%d, ICMP=%d → Tổng DoS=%d",
        n_syn, n_udp, n_icmp, n_dos
    )

    return df


# ---------------------------------------------------------------------------
# In bảng thống kê subtype
# ---------------------------------------------------------------------------
def print_summary(df: pd.DataFrame, config: dict) -> None:
    """
    In bảng thống kê phân phối subtype (count + %) cho các flows vượt ngưỡng,
    kèm ngưỡng riêng của từng loại.

    Args:
        df: DataFrame đã có cột 'attack_type' và các cột scoring.
        config: BASELINE_CONFIG chứa threshold cho từng loại.
    """
    dos_flows = df[df['attack_type'].notna()]
    total = len(dos_flows)

    if total == 0:
        print("\n  Không có flow nào vượt ngưỡng DoS.")
        return

    counts = dos_flows['attack_type'].value_counts()

    # Bảng mapping subtype → threshold
    threshold_map = {
        'SYN Flood':   config['syn_flood']['threshold'],
        'UDP Flood':   config['udp_flood']['threshold'],
        'ICMP Flood':  config['icmp_flood']['threshold'],
    }

    print(f"\n{'='*72}")
    print(f"  📊 THỐNG KÊ PHÂN PHỐI DoS SUBTYPE")
    print(f"{'='*72}")
    print(f"  {'Subtype':<20} {'Threshold':>10} {'Count':>8}   {'%':>7}")
    print(f"  {'-'*20} {'-'*10} {'-'*8}   {'-'*7}")

    for subtype, count in counts.items():
        pct = count / total * 100
        th = threshold_map.get(subtype, '?')
        print(f"  {subtype:<20} {'>= ' + str(th):>10} {count:>8}   {pct:>6.1f}%")

    print(f"  {'-'*20} {'-'*10} {'-'*8}   {'-'*7}")
    print(f"  {'TỔNG CỘNG':<20} {'':>10} {total:>8}   {100.0:>6.1f}%")
    print(f"{'='*72}")

    # Thống kê bổ sung: phân phối điểm
    print(f"\n  📈 PHÂN PHỐI ĐIỂM (chỉ các flow DoS):")
    score_cols = {
        'SYN Flood':   'syn_score',
        'UDP Flood':   'udp_score',
        'ICMP Flood':  'icmp_score',
    }
    for subtype in counts.index:
        col = score_cols.get(subtype)
        if col and col in df.columns:
            sub_df = dos_flows[dos_flows['attack_type'] == subtype]
            if len(sub_df) > 0:
                scores = sub_df[col]
                print(
                    f"     {subtype:<16}: "
                    f"min={int(scores.min()):>3}, "
                    f"median={int(scores.median()):>3}, "
                    f"max={int(scores.max()):>3}, "
                    f"mean={scores.mean():>6.1f}"
                )
    print()


# ---------------------------------------------------------------------------
# Phát Xuất Cảnh Báo
# ---------------------------------------------------------------------------
def process_and_alert(df: pd.DataFrame, http_lookup: dict, config: dict) -> int:
    """
    Duyệt qua các flow bị đánh dấu là DoS và xuất cảnh báo màu.

    Args:
        df: DataFrame đã được chấm điểm và phân loại.
        http_lookup: Bảng tra cứu User từ http.log.
        config: BASELINE_CONFIG.

    Returns:
        Số lượng flow DoS phát hiện được.
    """
    # Lọc ra các dòng có attack_type (tức đã vượt ngưỡng)
    dos_flows = df[df['attack_type'].notna()]
    alert_count = len(dos_flows)
    
    if alert_count == 0:
        logger.info("Không phát hiện cuộc tấn công DoS nào vượt ngưỡng.")
        return 0

    # Tìm cột MAC nguồn khả dụng
    mac_col = None
    for col in ['src_mac', 'srcmac', 'smac', 'orig_l2_addr']:
        if col in df.columns:
            mac_col = col
            break

    # Dict màu ANSI phân biệt theo subtype
    SUBTYPE_COLORS = {
        'SYN Flood':   "\033[91m",   # đỏ sáng
        'UDP Flood':   "\033[93m",   # vàng
        'ICMP Flood':  "\033[95m",   # tím
    }
    DEFAULT_COLOR = "\033[91m"
    RESET_COLOR = "\033[0m"

    # Mapping subtype → cột score tương ứng
    score_col_map = {
        'SYN Flood':   'syn_score',
        'UDP Flood':   'udp_score',
        'ICMP Flood':  'icmp_score',
    }

    for _, row in dos_flows.iterrows():
        srcip = str(row.get('srcip', 'N/A')).strip()
        proto = row.get('proto', 'N/A')
        
        # Đảm bảo port hiển thị dạng số nguyên sạch
        sport = row.get('sport', 0)
        dport = row.get('dport', 0)
        sport_str = str(int(sport)) if pd.notna(sport) else 'N/A'
        dport_str = str(int(dport)) if pd.notna(dport) else 'N/A'
        
        # Lấy điểm của đúng subtype
        attack_type = row.get('attack_type', 'SYN Flood')
        if pd.isna(attack_type) or attack_type is None:
            attack_type = 'SYN Flood'

        score_col = score_col_map.get(attack_type, 'dos_score')
        sub_score = int(row.get(score_col, row.get('dos_score', 0)))

        src_mac = str(row.get(mac_col, 'N/A')).strip() if (mac_col and pd.notna(row.get(mac_col))) else 'N/A'
        
        # Tự động chuẩn hóa hiển thị nếu srcip chứa định dạng địa chỉ MAC
        mac_pattern = re.compile(r'^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$')
        if mac_pattern.match(srcip):
            if src_mac == 'N/A' or src_mac == '' or not mac_pattern.match(src_mac):
                src_mac = srcip
            srcip = "N/A (L2 Frame)"
            
        service = str(row.get('service', '')).strip().lower()

        # Truy ngược thông tin User
        user_agent = "N/A (L3/L4 Attack)"
        if service == 'http':
            key = (srcip, sport_str)
            user_agent = http_lookup.get(key, "N/A (L3/L4 Attack)")

        # Chọn màu theo subtype
        color = SUBTYPE_COLORS.get(attack_type, DEFAULT_COLOR)

        # Xây dựng chuỗi sub-scores hiển thị
        sub_scores_str = (
            f"SYN:{int(row.get('syn_score', 0))} "
            f"UDP:{int(row.get('udp_score', 0))} "
            f"ICMP:{int(row.get('icmp_score', 0))}"
        )

        # In cảnh báo với màu và tên subtype phân biệt
        alert_line = (
            f"[🚨 {attack_type.upper()}] "
            f"IP: {srcip} | MAC: {src_mac} | "
            f"Proto: {proto} | Port: {sport_str} -> {dport_str} | "
            f"Score: {sub_score} ({sub_scores_str}) | "
            f"Info: {user_agent}"
        )
        print(f"{color}{alert_line}{RESET_COLOR}")

    return alert_count

# ---------------------------------------------------------------------------
# Hàm Main
# ---------------------------------------------------------------------------
def main() -> None:

    parser = argparse.ArgumentParser(
        description=(
            "IDS Classification Engine — Phân loại DoS chuyên biệt: "
            "SYN Flood, UDP Flood, và ICMP Flood."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--csv",
        required=True,
        help="Đường dẫn đến file CSV chứa dải flow mạng đã lọc."
    )
    parser.add_argument(
        "--zeek-dir",
        default="",
        help="Thư mục chứa file http.log của Zeek để truy xuất context User."
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=None,
        help=(
            "Ghi đè ngưỡng chung cho TẤT CẢ sub-type. "
            "Nếu không truyền, mỗi sub-type sẽ dùng ngưỡng riêng: "
            f"SYN={BASELINE_CONFIG['syn_flood']['threshold']}, "
            f"UDP={BASELINE_CONFIG['udp_flood']['threshold']}, "
            f"ICMP={BASELINE_CONFIG['icmp_flood']['threshold']}."
        )
    )
    parser.add_argument(
        "--skip-filter",
        action="store_true",
        default=False,
        help=(
            "Bỏ qua bước lọc đặc trưng (dos_feature_filter). "
            "Dùng khi file CSV đầu vào đã được lọc sẵn."
        )
    )

    args = parser.parse_args()

    # Xác thực đường dẫn file CSV
    if not os.path.isfile(args.csv):
        logger.error("File CSV đầu vào không tồn tại: %s", args.csv)
        sys.exit(1)

    # ----- Bước 0: Tự động lọc đặc trưng nếu chưa lọc -----
    if not args.skip_filter:
        logger.info("="*60)
        logger.info("BƯỚC 0: Lọc đặc trưng DoS (dos_feature_filter)...")
        logger.info("="*60)

        # Tạo tên file đầu ra cho bước lọc
        csv_path_raw = os.path.abspath(args.csv)
        csv_dir_raw = os.path.dirname(csv_path_raw)
        name_part_raw, _ = os.path.splitext(os.path.basename(csv_path_raw))
        if name_part_raw.endswith("_dos_features"):
            # Đã có hậu tố _dos_features → giữ nguyên
            filtered_output = csv_path_raw
            logger.info("File đầu vào đã có hậu tố '_dos_features', bỏ qua bước lọc.")
        else:
            if name_part_raw.endswith("_raw"):
                base_name_raw = name_part_raw[:-4]
            else:
                base_name_raw = name_part_raw
            filtered_output = os.path.join(csv_dir_raw, f"{base_name_raw}_dos_features.csv")

            # Gọi hàm lọc đặc trưng
            run_family("DoS", csv_path_raw, filtered_output)
            logger.info("Đã lọc xong → Sử dụng file: %s", filtered_output)

        # Cập nhật đường dẫn CSV cho các bước tiếp theo
        args.csv = filtered_output
    else:
        logger.info("Bỏ qua bước lọc đặc trưng (--skip-filter).")

    # Nếu user truyền --threshold, ghi đè tất cả sub-type
    if args.threshold is not None:
        logger.info("Ghi đè ngưỡng chung: %d cho tất cả sub-type.", args.threshold)
        BASELINE_CONFIG['syn_flood']['threshold']   = args.threshold
        BASELINE_CONFIG['udp_flood']['threshold']    = args.threshold
        BASELINE_CONFIG['icmp_flood']['threshold']   = args.threshold

    logger.info(
        "IDS Engine khởi tạo. Threshold: SYN=%d, UDP=%d, ICMP=%d",
        BASELINE_CONFIG['syn_flood']['threshold'],
        BASELINE_CONFIG['udp_flood']['threshold'],
        BASELINE_CONFIG['icmp_flood']['threshold'],
    )

    # 1. Load http.log Zeek (Lookup O(1))
    http_lookup = {}
    csv_path = os.path.abspath(args.csv)
    csv_dir = os.path.dirname(csv_path)
    csv_filename = os.path.basename(csv_path)
    name_part, _ = os.path.splitext(csv_filename)
    if name_part.endswith("_dos_features"):
        base_name = name_part[:-13]
    elif name_part.endswith("_raw"):
        base_name = name_part[:-4]
    else:
        base_name = name_part

    if args.zeek_dir:
        http_lookup = load_zeek_http_log(args.zeek_dir)
    else:
        # Tự động tìm kiếm file <base_name>_http.log cùng thư mục
        http_log_candidate = os.path.join(csv_dir, f"{base_name}_http.log")
        if os.path.isfile(http_log_candidate):
            logger.info("Tự động tìm thấy file HTTP log: %s", http_log_candidate)
            http_lookup = load_zeek_http_log(http_log_candidate)
        else:
            logger.warning("Không tìm thấy file HTTP log tại: %s. Trả thông tin User-Agent về 'N/A'.", http_log_candidate)

    # 2. Đọc file CSV (đã lọc hoặc gốc)
    logger.info("Đang đọc và phân tích file: %s", args.csv)
    try:
        df = pd.read_csv(args.csv, low_memory=False)
    except Exception as exc:
        logger.error("Không thể đọc file CSV: %s", exc)
        sys.exit(1)

    # Tối ưu hoá bộ nhớ nếu DataFrame lớn
    if len(df) > 0:
        logger.info("Đã nạp %d dòng dữ liệu.", len(df))
    else:
        logger.warning("File CSV rỗng.")
        sys.exit(0)

    # 3. Tính toán điểm rủi ro chuyên biệt (3 bộ scoring riêng biệt)
    logger.info("Đang tính toán Risk Score chuyên biệt (SYN/UDP/ICMP)...")
    df = evaluate_dos_scores(df, BASELINE_CONFIG)

    # 4. Phân loại DoS subtype (dựa trên ngưỡng riêng)
    logger.info("Đang phân loại DoS subtype...")
    df = classify_dos_subtype(df, BASELINE_CONFIG)

    # 5. Trích xuất cảnh báo
    logger.info("Đang quét và phát xuất cảnh báo DoS...")
    total_alerts = process_and_alert(df, http_lookup, BASELINE_CONFIG)

    # 6. In bảng thống kê phân phối subtype
    print_summary(df, BASELINE_CONFIG)
    
    logger.info("Hoàn thành! Tổng cộng phát hiện %d cuộc tấn công DoS.", total_alerts)

if __name__ == "__main__":
    main()
