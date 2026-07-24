#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
unified_classifier.py — Bộ phân loại HỢP NHẤT: 1 flow -> đúng 1 nhãn.

Vì sao cần module này (bối cảnh):
---------------------------------
Kiến trúc cũ chạy 7 filter họ tấn công ĐỘC LẬP, mỗi filter ghi 1 bảng riêng và
KHÔNG so sánh điểm với nhau (không argmax). Hệ quả trên traffic THẬT:

  * DoS bị bỏ lọt 100%: `dos.json` dùng ngưỡng UNSW-NB15 (sttl>=142.5, rate>=112k)
    trong khi flood thật từ hping3 --rand-source bị Argus gộp thành flow 1-GÓI
    (rate=0, sload=0, sttl=64) → không bao giờ chạm ngưỡng.
  * Cùng 1 flow flood 1-gói lại trúng ngưỡng Fuzzers VÀ Reconnaissance cùng lúc
    (đều là "gói nhỏ, ngắn, đơn lẻ") → 1 flow vật lý mang nhiều nhãn, và vì
    `flows_all` là Merge của 7 bảng nên 1 flow bị đếm tới 7 lần.
  * `dos_classifier.py` (chấm điểm CỘNG DỒN theo state/synack/dttl — hoạt động
    tốt trên flow 1-gói) lại chỉ IN ra terminal, không ghi vào `predicted_class`.

Module này gộp lại thành MỘT quyết định nhất quán cho mỗi flow:

  1. Chấm điểm 6 họ (Exploits/Shellcode/Generic/Analysis/Reconnaissance/Fuzzers)
     bằng chữ ký `signatures/<family>.json` (giữ nguyên các cột *_score cũ).
  2. Phát hiện DoS bằng lõi CỘNG DỒN của dos_classifier (bắt được flood 1-gói)
     KÈM cổng volumetric ở cấp segment (đếm số flow flood-like tới cùng dstip)
     để chặn false-positive kiểu 1 truy vấn DNS one-way lẻ.
  3. Giải quyết về ĐÚNG 1 nhãn theo ưu tiên độ nghiêm trọng/đặc hiệu:
        DoS > Exploits > Shellcode > Generic > Analysis > Reconnaissance > Fuzzers
     (khi nhiều họ cùng vượt ngưỡng, chọn điểm cao nhất; hoà điểm → theo ưu tiên).

Đầu ra: DataFrame gốc + các cột `*_score`, `dos_score`, `attack_subtype`,
`predicted_class` (đúng 1 nhãn). Có thể gọi in-process qua `classify_segment()`
hoặc chạy CLI để xuất 1 CSV đã phân loại.
"""
from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import sys
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd

# Cho phép import các module cùng thư mục khi chạy như script độc lập.
_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from baseline_filter import load_signature, _evaluate_rule_vectorized  # noqa: E402
from dos_classifier import BASELINE_CONFIG, evaluate_dos_scores  # noqa: E402

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cấu hình (override qua biến môi trường để hiệu chỉnh khi triển khai)
# ---------------------------------------------------------------------------
# Cổng volumetric: 1 flow chỉ bị coi là DoS khi vừa "trông giống flood" (điểm
# cộng dồn vượt ngưỡng) VỪA thuộc về một đích đang chịu tải bất thường —
# nghĩa là có ÍT NHẤT ngần này flow flood-like cùng đổ về 1 dstip trong segment.
# Chặn false-positive: 1 truy vấn DNS/UDP one-way lẻ (chỉ 1 flow tới resolver)
# sẽ KHÔNG bị gọi là DoS dù điểm per-flow cao.
DOS_MIN_FLOWS_PER_DST = int(os.environ.get("DOS_MIN_FLOWS_PER_DST", "40"))

# Đường thoát cho flood cổ điển KHÔNG spoofed-source: 1 flow đơn lẻ nhưng bản
# thân nó đã có tốc độ rất cao (nhiều gói/giây trong cùng flow) → là flood ngay
# cả khi chỉ có 1 dòng. Áp cho traffic KHÔNG bị --rand-source băm nhỏ.
DOS_HIGH_RATE = float(os.environ.get("DOS_HIGH_RATE", "5000"))

# FIX (lỗi #5 — scan bị gán nhầm DoS): cổng volumetric cũ chỉ đếm số flow
# flood-like theo dstip, nên một port-scan 500 cổng vào 1 host trông y hệt một
# SYN-flood 500 flow vào 1 host. Đặc trưng phân biệt duy nhất ở tầng flow-only
# là ĐỘ ĐA DẠNG CỔNG ĐÍCH: flood dồn vào 1 (hoặc rất ít) cổng; scan trải trên
# hàng trăm cổng. Một đích chỉ được coi là "đang chịu flood" khi lượng flow
# flood-like đổ về nó tập trung vào không quá ngần này cổng riêng biệt.
# Đã thực nghiệm: KB1 (500 cổng) 500/500 -> 0/500 DoS; flood thật (1 cổng)
# giữ nguyên 500/500 DoS. Xem PATCH_SPEC_scan_vs_flood.md.
DOS_MAX_DPORT_SPREAD = int(os.environ.get("DOS_MAX_DPORT_SPREAD", "8"))

# FIX (lỗi #6 — rate là tỷ số, không phải tốc độ đo): rate = spkts/dur khiến
# một probe ĐƠN GÓI với dur ~0.2ms đạt rate = 5000, chạm thẳng DOS_HIGH_RATE
# dù chỉ có đúng 1 gói tin. Một gói tin không cấu thành "tốc độ cao". Chỉ tin
# vào tín hiệu rate khi flow có đủ số gói để tốc độ mang ý nghĩa thống kê.
DOS_MIN_PKTS_FOR_RATE = int(os.environ.get("DOS_MIN_PKTS_FOR_RATE", "4"))

# FIX (lỗi #2 — heuristic ".255" loại nhầm victim hợp lệ trên mạng > /24):
# Danh sách CIDR của (các) mạng LAN thật đang giám sát, phân tách bởi dấu
# phẩy (vd "192.168.100.0/23,10.0.0.0/24"). Khi được cấu hình, địa chỉ
# broadcast được tính CHÍNH XÁC theo subnet mask thật (ipaddress.broadcast_address)
# thay vì suy đoán "kết thúc bằng .255 => broadcast /24" — suy đoán đó sai với
# bất kỳ mạng nào lớn hơn /24 (VD /23: .255 là host hợp lệ, không phải broadcast)
# và đã được thực nghiệm xác nhận gây bỏ lọt 100% một SYN-flood có victim IP
# kết thúc .255 (xem defect_test_and_remediation.md).
# Để trống (mặc định) => KHÔNG áp heuristic .255 nữa (an toàn hơn: chấp nhận có
# thể sót một vài gói broadcast /24 thật còn hơn loại nhầm victim /23+).
_LAN_CIDRS_RAW = os.environ.get("LAN_CIDRS", "").strip()
try:
    LAN_NETWORKS = [ipaddress.ip_network(c.strip(), strict=False)
                    for c in _LAN_CIDRS_RAW.split(",") if c.strip()]
except ValueError:
    logger.warning("LAN_CIDRS không hợp lệ (%r) — bỏ qua, không áp broadcast mask theo subnet.",
                    _LAN_CIDRS_RAW)
    LAN_NETWORKS = []


def _configured_broadcast_mask(ip_series: pd.Series) -> np.ndarray:
    """True khi địa chỉ khớp broadcast address của một trong các LAN_NETWORKS
    đã cấu hình (tính đúng theo subnet mask thật). Trả về mảng toàn False khi
    LAN_NETWORKS rỗng (không suy đoán octet cuối nữa — xem ghi chú ở LAN_CIDRS)."""
    n = len(ip_series)
    if not LAN_NETWORKS:
        return np.zeros(n, dtype=bool)
    broadcast_strs = {str(net.broadcast_address) for net in LAN_NETWORKS
                       if net.version == 4}
    if not broadcast_strs:
        return np.zeros(n, dtype=bool)
    return ip_series.isin(broadcast_strs).to_numpy(bool)

# Mô hình mối đe doạ: IDS giám sát host trên MẠNG NỘI BỘ; kẻ tấn công và victim
# ở gần nhau (ít hop). dttl là TTL còn lại của gói PHẢN HỒI từ đích — đích nội bộ
# cho dttl ~64 (không qua router), còn server internet cho dttl thấp hơn nhiều
# (42/43 = ~20 hop). Traffic duyệt web ra ngoài (HTTPS download lớn) hay trúng
# chữ ký Exploits (nhiều byte/gói) → chặn bằng cách CHỈ gán nhãn HỌ khi đích ở
# gần (dttl >= ngưỡng) HOẶC đích không phản hồi (dttl == 0, one-way). KHÔNG áp cho
# DoS (flood một chiều tự có dttl=0). Đặt 0 để tắt cổng này.
FAMILY_MIN_DTTL = int(os.environ.get("FAMILY_MIN_DTTL", "60"))

# Ngưỡng flood-like per-flow cho 3 subtype (kế thừa dos_classifier, có thể chỉnh).
_DOS_TH = {
    "SYN Flood": int(os.environ.get("DOS_SYN_THRESHOLD",
                                    str(BASELINE_CONFIG["syn_flood"]["threshold"]))),
    "UDP Flood": int(os.environ.get("DOS_UDP_THRESHOLD",
                                    str(BASELINE_CONFIG["udp_flood"]["threshold"]))),
    "ICMP Flood": int(os.environ.get("DOS_ICMP_THRESHOLD",
                                     str(BASELINE_CONFIG["icmp_flood"]["threshold"]))),
}

# Thứ tự ưu tiên khi nhiều họ cùng vượt ngưỡng (đặc hiệu/nghiêm trọng giảm dần).
# DoS xử lý riêng (ưu tiên cao nhất) nên không nằm trong danh sách này.
FAMILY_PRIORITY = [
    "Exploits",
    "Shellcode",
    "Generic",
    "Analysis",
    "Reconnaissance",
    "Fuzzers",
]

_SCORE_COL = {
    "Exploits": "exploits_score",
    "Shellcode": "shellcode_score",
    "Generic": "generic_score",
    "Analysis": "analysis_score",
    "Reconnaissance": "reconnaissance_score",
    "Fuzzers": "fuzzers_score",
}

# Cổng đích: các cổng dịch vụ khám phá LAN vốn multicast/broadcast bản chất —
# mDNS(5353), LLMNR(5355), SSDP(1900), NetBIOS(137/138), DHCP(67/68), SNMP-trap(162),
# DNS(53), NTP(123)... Traffic tới các cổng này là "tiếng ồn hạ tầng" LAN benign,
# hay có sttl=255/one-way → dễ trúng chữ ký "spoofed TTL / gói nhỏ". Loại khỏi
# phân loại HỌ. LƯU Ý: các cổng này KHÔNG loại khỏi phát hiện DoS — một UDP flood
# có thể nhắm chính port 53/123, nên DoS chỉ loại theo ĐÍCH multicast/broadcast
# (xem _multicast_broadcast_dst_mask), không theo port.
_BENIGN_LAN_DPORTS = {5353, 5355, 1900, 137, 138, 67, 68, 546, 547, 162, 5354, 53, 123}


def _multicast_broadcast_dst_mask(df: pd.DataFrame) -> np.ndarray:
    """True khi ĐÍCH là multicast/broadcast (224.0.0.0/4, ff::, 255.255.255.255,
    hoặc .255 cuối /24). Flood/exploit/scan thật nhắm địa chỉ UNICAST của victim;
    traffic tới nhóm địa chỉ này (SSDP 239.255.255.250, mDNS 224.0.0.251...) là
    khám phá dịch vụ LAN benign. An toàn để loại khỏi CẢ DoS lẫn các họ khác."""
    n = len(df)
    if "dstip" not in df.columns:
        return np.zeros(n, dtype=bool)
    s = df["dstip"].astype(str).str.strip().str.lower()
    m = np.zeros(n, dtype=bool)
    m |= s.str.match(r"^(22[4-9]|23[0-9])\.").fillna(False).to_numpy(bool)  # IPv4 multicast
    m |= s.str.startswith("ff").to_numpy(bool)                              # IPv6 multicast
    m |= (s == "255.255.255.255").to_numpy(bool)                           # broadcast toàn mạng
    # FIX (lỗi #2): thay suy đoán "endswith .255 => broadcast /24" bằng broadcast
    # address tính đúng theo subnet thật (LAN_CIDRS). Suy đoán cũ sai trên mạng
    # lớn hơn /24 (vd /23: .255 là HOST hợp lệ) và đã gây bỏ lọt 100% một
    # SYN-flood có victim IP kết thúc .255 trong thực nghiệm tái tạo — xem
    # defect_test_and_remediation.md. Không cấu hình LAN_CIDRS => không áp mask
    # này (an toàn hơn: chấp nhận sót vài gói broadcast /24 còn hơn loại nhầm
    # victim /23+ khỏi toàn bộ phân loại).
    m |= _configured_broadcast_mask(s)
    return m


def _benign_infra_mask(df: pd.DataFrame) -> np.ndarray:
    """True cho traffic hạ tầng LAN benign (multicast/broadcast/khám phá dịch vụ).

    Tấn công (flood, exploit, scan) nhắm địa chỉ UNICAST của victim. Traffic tới
    multicast (224.0.0.0/4, ff::/8), broadcast, hoặc các cổng khám phá LAN là nền
    mạng bình thường — không phải mục tiêu phân loại họ tấn công. Loại chúng ở đây
    diệt tận gốc nhóm false-positive lớn nhất trên capture thật (mDNS sttl=255...).
    Lưu ý: KHÔNG loại khỏi phát hiện DoS — DoS đã có cổng volumetric riêng và lõi
    dos_classifier vốn tự bỏ qua mDNS/DHCP/broadcast/multicast.
    """
    n = len(df)
    mask = np.zeros(n, dtype=bool)
    for ipcol in ("dstip", "srcip"):
        if ipcol in df.columns:
            s = df[ipcol].astype(str).str.strip().str.lower()
            mask |= s.str.match(r"^(22[4-9]|23[0-9])\.").fillna(False).to_numpy(bool)  # IPv4 multicast
            mask |= s.str.startswith("ff").to_numpy(bool)                                # IPv6 multicast
            mask |= (s == "255.255.255.255").to_numpy(bool)                              # broadcast
            mask |= (s == "0.0.0.0").to_numpy(bool)                                      # DHCP discover
    if "dstip" in df.columns:
        # FIX (lỗi #2): xem ghi chú tương ứng trong _multicast_broadcast_dst_mask
        # ở trên — thay suy đoán .255/24 bằng broadcast address theo LAN_CIDRS
        # thật đã cấu hình.
        mask |= _configured_broadcast_mask(
            df["dstip"].astype(str).str.strip().str.lower()
        )
    for pcol in ("dport", "sport"):
        if pcol in df.columns:
            p = pd.to_numeric(df[pcol], errors="coerce").fillna(-1).astype(int)
            mask |= p.isin(_BENIGN_LAN_DPORTS).to_numpy(bool)
    return mask


# ---------------------------------------------------------------------------
# Chấm điểm 1 họ (không ghi predicted_class — chỉ trả về mảng điểm + ngưỡng)
# ---------------------------------------------------------------------------
def _family_scores(df: pd.DataFrame, class_name: str,
                   signatures_dir: Optional[Path] = None) -> tuple[np.ndarray, int]:
    """Trả về (mảng điểm có gate min_decisive, ngưỡng) cho 1 họ tấn công.

    Dùng lại đúng logic chấm điểm của baseline_filter (decisive/support +
    cổng min_decisive_required) nhưng KHÔNG quyết định nhãn ở đây — việc gán
    nhãn để bước hợp nhất lo, nhằm đảm bảo mỗi flow chỉ nhận đúng 1 nhãn.
    """
    sig = load_signature(class_name, signatures_dir)
    scoring = sig["scoring"]
    w_dec, w_sup = scoring["weight_decisive"], scoring["weight_support"]
    min_dec, threshold = scoring["min_decisive_required"], scoring["threshold"]

    n = len(df)
    dec_score = np.zeros(n, dtype=np.int64)
    sup_score = np.zeros(n, dtype=np.int64)
    dec_hits = np.zeros(n, dtype=np.int64)
    missing: set = set()

    for rule in sig["signature"]["decisive"]:
        hits = _evaluate_rule_vectorized(rule, df, missing)
        dec_hits += hits.astype(np.int64)
        dec_score += hits.astype(np.int64) * w_dec
    for rule in sig["signature"]["support"]:
        hits = _evaluate_rule_vectorized(rule, df, missing)
        sup_score += hits.astype(np.int64) * w_sup

    total = dec_score + sup_score
    total = np.where(dec_hits >= min_dec, total, 0)  # cổng min_decisive
    return total.astype(np.int64), int(threshold)


# ---------------------------------------------------------------------------
# Phát hiện DoS: điểm cộng dồn per-flow + cổng volumetric cấp segment
# ---------------------------------------------------------------------------
def _detect_dos(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Trả về (is_dos: bool[n], subtype: object[n], dos_score: int64[n],
    flood_like_ungated: bool[n] — flood-like nhưng chưa qua cổng volumetric,
    xem FIX lỗ hổng #3 ở cuối hàm).

    Một flow là DoS khi:
      (A) "trông giống flood" — điểm cộng dồn SYN/UDP/ICMP (dos_classifier) vượt
          ngưỡng subtype tương ứng; VÀ
      (B) có tín hiệu VOLUME, một trong hai:
          - dst_pressure: đích của nó nhận >= DOS_MIN_FLOWS_PER_DST flow flood-like
            trong segment (đặc trưng flood spoofed-source băm nhỏ) VÀ lượng flow đó
            dồn vào <= DOS_MAX_DPORT_SPREAD cổng riêng biệt (FIX lỗi #5 — nếu trải
            trên nhiều cổng thì đó là port-scan, không phải flood);
          - high_rate: bản thân flow có rate >= DOS_HIGH_RATE (flood cổ điển 1 flow)
            VÀ có >= DOS_MIN_PKTS_FOR_RATE gói (FIX lỗi #6 — rate của flow đơn gói
            là hiện vật phép chia spkts/dur, không phải tốc độ thật).

    Điều kiện (B) chính là thứ mà kiến trúc cũ thiếu: nó phân biệt "flood thật"
    với "1 flow one-way lẻ trông giống flood" (vd 1 truy vấn DNS không có phản hồi
    trong segment). Hai vế bổ sung ở trên phân biệt tiếp "flood thật" với
    "port-scan" — hai thứ gần như trùng nhau ở cấp flow nếu chỉ đếm số lượng.
    """
    scored = evaluate_dos_scores(df.copy(), BASELINE_CONFIG)
    syn = scored["syn_score"].values
    udp = scored["udp_score"].values
    icmp = scored["icmp_score"].values
    dos_score = scored["dos_score"].values

    # (A) flood-like theo từng subtype
    is_syn = syn >= _DOS_TH["SYN Flood"]
    is_udp = udp >= _DOS_TH["UDP Flood"]
    is_icmp = icmp >= _DOS_TH["ICMP Flood"]
    flood_like = is_syn | is_udp | is_icmp

    # (B) tín hiệu volume: đếm số flow flood-like theo từng dstip trong segment,
    # KÈM độ đa dạng cổng đích của chính nhóm flood-like đó (FIX lỗi #5).
    n = len(df)
    if "dstip" in df.columns:
        dstip = df["dstip"].astype(str).values
        # PHẢI chuẩn hoá dport về số nguyên trước khi đếm cổng riêng biệt.
        # Nếu dùng giá trị thô: dport thiếu (NaN — xảy ra thật với flow ICMP
        # không có cổng đích, hoặc ô CSV rỗng) sẽ làm phình số cổng "riêng biệt",
        # vì từ Python 3.10 hash(NaN) dựa trên id() và `nan != nan` nên MỖI NaN
        # là một phần tử set riêng. Hệ quả đã đo được: flood 500 flow với
        # dport=NaN cho spread=500 > ngưỡng -> dst_pressure=False -> BỎ LỌT
        # hoàn toàn (500/500 DoS -> 0/500). Gộp mọi dport thiếu về một sentinel
        # (-1, tách biệt với cổng 0 hợp lệ) để chúng đếm là ĐÚNG MỘT cổng.
        dport_arr = (pd.to_numeric(df["dport"], errors="coerce")
                     .fillna(-1).astype("int64").values
                     if "dport" in df.columns else np.zeros(n, dtype="int64"))
        floodlike_per_dst: dict[str, int] = {}
        floodlike_dports: dict[str, set] = {}
        for i in range(n):
            if flood_like[i]:
                d = dstip[i]
                floodlike_per_dst[d] = floodlike_per_dst.get(d, 0) + 1
                floodlike_dports.setdefault(d, set()).add(dport_arr[i])
        # Một đích chỉ "đang chịu flood" khi vừa nhận đủ nhiều flow flood-like
        # VỪA bị dồn vào ít cổng. Port-scan thoả điều kiện đầu nhưng trải trên
        # hàng trăm cổng nên bị loại tại đây — đó là toàn bộ mục đích của fix.
        dst_pressure = np.array(
            [(floodlike_per_dst.get(dstip[i], 0) >= DOS_MIN_FLOWS_PER_DST)
             and (len(floodlike_dports.get(dstip[i], ())) <= DOS_MAX_DPORT_SPREAD)
             for i in range(n)], dtype=bool)
    else:
        dst_pressure = np.zeros(n, dtype=bool)

    rate = pd.to_numeric(df.get("rate", pd.Series(np.zeros(n))),
                         errors="coerce").fillna(0).values
    # FIX (lỗi #6): rate cao trên flow ĐƠN GÓI là hiện vật của phép chia
    # spkts/dur với dur ~ RTT LAN, không phải tốc độ flood. Chỉ tin tín hiệu
    # rate khi flow có đủ số gói để "tốc độ" mang ý nghĩa thống kê.
    _spkts = pd.to_numeric(df.get("spkts", pd.Series(np.zeros(n))),
                           errors="coerce").fillna(0).values
    high_rate = (rate >= DOS_HIGH_RATE) & (_spkts >= DOS_MIN_PKTS_FOR_RATE)

    is_dos = flood_like & (dst_pressure | high_rate)
    # Loại đích multicast/broadcast: SSDP(239.255.255.250)/mDNS... là khám phá LAN
    # benign, KHÔNG phải flood nhắm victim. (dos_classifier gốc chỉ loại multicast
    # theo srcip nên bỏ sót các burst tới ĐÍCH multicast — vá tại đây.)
    not_infra = ~_multicast_broadcast_dst_mask(df)
    is_dos &= not_infra

    # Subtype cho các flow DoS (ưu tiên SYN > UDP > ICMP khi cùng vượt — hiếm).
    subtype = np.full(n, "", dtype=object)
    subtype[is_dos & is_icmp] = "ICMP Flood"
    subtype[is_dos & is_udp] = "UDP Flood"
    subtype[is_dos & is_syn] = "SYN Flood"

    # FIX (lỗ hổng #3 — ngưỡng cứng DOS_MIN_FLOWS_PER_DST gây gán nhầm họ):
    # flow "trông giống flood" (A đúng) nhưng CHƯA đủ tín hiệu volume để qua
    # cổng (B) (vd flood mới bắt đầu, chưa đủ DOS_MIN_FLOWS_PER_DST=40 flow
    # trong segment) trước đây rơi tự do vào vòng chấm điểm 6 họ bên dưới —
    # và vì đặc trưng flood 1-gói (spkts thấp, sbytes thấp, dur~0) khớp gần
    # hết chữ ký "decisive" của Reconnaissance, nó bị gán NHẦM HỌ thay vì bị
    # bỏ lọt trung tính. Thực nghiệm tái tạo: 39 flow -> "Reconnaissance",
    # 40 flow -> "DoS" (xem defect_test_and_remediation.md). Đánh dấu các
    # flow này riêng để classify_segment() gán nhãn trung tính, không cho
    # rơi vào vòng chấm điểm họ.
    flood_like_ungated = flood_like & not_infra & ~is_dos

    return is_dos, subtype, dos_score.astype(np.int64), flood_like_ungated


# ---------------------------------------------------------------------------
# Hàm chính: phân loại hợp nhất cho 1 segment
# ---------------------------------------------------------------------------
def classify_segment(df: pd.DataFrame,
                     signatures_dir: Optional[Path] = None) -> pd.DataFrame:
    """Gán ĐÚNG 1 `predicted_class` cho mỗi flow trong DataFrame của 1 segment.

    Thêm các cột: 6 cột `<family>_score`, `dos_score`, `attack_subtype`,
    `predicted_class`. Không thay đổi các cột feature sẵn có.
    """
    df = df.copy()
    n = len(df)
    if n == 0:
        for c in _SCORE_COL.values():
            df[c] = pd.Series(dtype="int64")
        df["dos_score"] = pd.Series(dtype="int64")
        df["attack_subtype"] = pd.Series(dtype="object")
        df["predicted_class"] = pd.Series(dtype="object")
        return df

    # Cổng giao thức: chữ ký UNSW-NB15 CHỈ định nghĩa trên IP transport thật
    # (tcp/udp/icmp). Traffic L2/control-plane trong capture thật — ARP, STP
    # (ethertype dạng số như 35130), IPv6-ND (ipv6-icmp), LLC... — bị Argus ghi
    # thành "flow" spkts thấp/sttl=0 và sẽ vô cớ trúng các chữ ký "gói nhỏ"
    # (Fuzzers/Reconnaissance/Shellcode). Đây là nguồn false-positive lớn nhất
    # trên mạng thật. Chỉ cho phép gán nhãn họ khi proto ∈ {tcp,udp,icmp}.
    proto_norm = (df["proto"].astype(str).str.strip().str.lower().values
                  if "proto" in df.columns else np.full(n, "", dtype=object))
    is_ip_transport = np.isin(proto_norm, ["tcp", "udp", "icmp"])
    # Traffic hạ tầng LAN benign (multicast/broadcast/mDNS...) không được gán nhãn họ.
    benign_infra = _benign_infra_mask(df)
    eligible = is_ip_transport & ~benign_infra
    # Cổng "đích ở gần" (mô hình đe doạ LAN): loại traffic tới server internet xa.
    if FAMILY_MIN_DTTL > 0 and "dttl" in df.columns:
        dttl = pd.to_numeric(df["dttl"], errors="coerce").fillna(0).values
        near_or_oneway = (dttl >= FAMILY_MIN_DTTL) | (dttl == 0)
        eligible &= near_or_oneway

    # 1) Điểm 6 họ + ngưỡng riêng (chỉ áp cho flow IP transport)
    fam_score: dict[str, np.ndarray] = {}
    fam_thresh: dict[str, int] = {}
    for fam in FAMILY_PRIORITY:
        s, th = _family_scores(df, fam, signatures_dir)
        s = np.where(eligible, s, 0)  # non-IP hoặc hạ tầng benign → điểm 0
        fam_score[fam] = s
        fam_thresh[fam] = th
        df[_SCORE_COL[fam]] = s

    # 2) DoS (cộng dồn + volumetric)
    is_dos, subtype, dos_score, flood_like_ungated = _detect_dos(df)
    df["dos_score"] = dos_score

    # 3) Hợp nhất về 1 nhãn theo ưu tiên
    predicted = np.full(n, "Normal", dtype=object)

    # Các họ vượt ngưỡng → chọn theo (điểm cao nhất, rồi ưu tiên độ đặc hiệu).
    # best_pri: chỉ số ưu tiên (nhỏ = đặc hiệu hơn); best_score dùng để phá hoà.
    best_family = np.full(n, "", dtype=object)
    best_score = np.zeros(n, dtype=np.int64)
    best_pri = np.full(n, len(FAMILY_PRIORITY), dtype=np.int64)
    for pri, fam in enumerate(FAMILY_PRIORITY):
        s = fam_score[fam]
        passes = s >= fam_thresh[fam]
        take = passes & (
            (s > best_score) | ((s == best_score) & (pri < best_pri))
        )
        best_family[take] = fam
        best_score[take] = s[take]
        best_pri[take] = pri

    has_family = best_family != ""
    predicted[has_family] = best_family[has_family]

    # FIX (lỗ hổng #3): flow flood-like nhưng chưa qua cổng volumetric
    # (DOS_MIN_FLOWS_PER_DST/DOS_HIGH_RATE) trước đây rơi vào bất kỳ họ nào có
    # chữ ký khớp (thường là Reconnaissance, vì đặc trưng 1-gói gần giống nhau)
    # — đổi 1 loại lỗi (DoS bị bỏ lọt vì chưa đủ volume) lấy 1 loại lỗi khác
    # (gán nhầm họ, dứt khoát sai). Ưu tiên nhãn trung tính "Suspicious-Low-Volume"
    # cho các flow này thay vì để rơi tự do vào vòng chấm điểm họ ở trên — nhãn
    # này không tồn tại trong 7 họ UNSW-NB15 gốc, cần thêm vào tầng hiển
    # thị/dashboard như một mức cảnh báo riêng (không phải Normal, không phải
    # DoS xác nhận). Áp SAU khi gán họ (ghi đè) nhưng TRƯỚC khi DoS ghi đè cuối
    # cùng, để một flow vừa flood-like vừa qua được cổng volumetric vẫn thành DoS.
    #
    # FIX (lỗi #5): sau khi cổng đa dạng cổng đích loại port-scan khỏi DoS, toàn
    # bộ flow scan trở thành flood_like_ungated. KHÔNG được gán chúng thành
    # Suspicious-Low-Volume — chúng đã có reconnaissance_score vượt ngưỡng và
    # nhãn ĐÚNG của chúng là Reconnaissance; gán nhãn trung tính ở đây chỉ là đổi
    # một nhãn sai (DoS) lấy một nhãn sai khác. Nhãn trung tính chỉ dành cho flow
    # flood-like mà KHÔNG họ nào nhận (thực sự không phân loại được).
    predicted[flood_like_ungated & ~has_family] = "Suspicious-Low-Volume"

    # DoS ưu tiên cao nhất — ghi đè mọi nhãn họ (kể cả Suspicious-Low-Volume).
    predicted[is_dos] = "DoS"

    df["attack_subtype"] = np.where(is_dos, subtype, "")
    df["predicted_class"] = predicted
    return df


# ---------------------------------------------------------------------------
# CLI: đọc 1 CSV (đã có đặc trưng) -> ghi 1 CSV đã phân loại hợp nhất
# ---------------------------------------------------------------------------
def run(input_csv: str, output_csv: Optional[str] = None) -> pd.DataFrame:
    in_path = Path(input_csv)
    if not in_path.is_file():
        raise FileNotFoundError(f"Input CSV not found: {in_path}")
    df = pd.read_csv(in_path, low_memory=False)
    out = classify_segment(df)
    if output_csv is None:
        base = in_path.stem
        if base.endswith("_dos_features"):
            base = base[: -len("_dos_features")]
        elif base.endswith("_raw"):
            base = base[:-4]
        output_csv = str(in_path.parent / f"{base}_classified.csv")
    Path(output_csv).parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(output_csv, index=False)
    logger.info("unified_classifier: %d flows -> %s", len(out), output_csv)
    return out


# Tên 7 họ và thư mục filter tương ứng (khớp FILTERS trong auto_pipeline + sink).
_FAMILY_DIRNAME = {
    "DoS": "Filter_DoS_feature",
    "Exploits": "Filter_Exploits_feature",
    "Fuzzers": "Filter_Fuzzers_feature",
    "Generic": "Filter_Generic_feature",
    "Analysis": "Filter_Analysis_feature",
    "Reconnaissance": "Filter_Reconnaissance_feature",
    "Shellcode": "Filter_Shellcode_feature",
}


def write_family_csvs(input_csv: str, csv_root: str) -> dict:
    """Phân loại HỢP NHẤT 1 lần rồi ghi 7 CSV per-family (tương thích sink cũ).

    Với mỗi họ F, CSV `Filter_F_feature/<base>_<f>_features.csv` chứa TOÀN BỘ flow
    của segment nhưng `predicted_class` = F CHỈ ở những flow mà nhãn hợp nhất là F,
    còn lại = "Normal". Nhờ vậy mỗi flow vật lý chỉ mang nhãn tấn công ở ĐÚNG 1
    bảng — chấm dứt việc 1 flow bị nhiều họ nhận cùng lúc và bị đếm 7 lần trong
    `flows_all` (Merge). Không đổi schema/sink — chỉ đổi NỘI DUNG nhãn.

    Trả về {family_lowercase: csv_path} cho toàn bộ 7 họ.
    """
    in_path = Path(input_csv)
    df = pd.read_csv(in_path, low_memory=False)
    classified = classify_segment(df)

    base = in_path.stem
    if base.endswith("_dos_features"):
        base = base[: -len("_dos_features")]
    elif base.endswith("_raw"):
        base = base[:-4]

    root = Path(csv_root)
    unified_label = classified["predicted_class"].astype(str).values
    out_map: dict = {}
    for fam, dirname in _FAMILY_DIRNAME.items():
        out_dir = root / dirname
        out_dir.mkdir(parents=True, exist_ok=True)
        out_csv = out_dir / f"{base}_{fam.lower()}_features.csv"
        fam_df = classified.copy()
        # Chiếu nhãn hợp nhất về đúng họ này (còn lại Normal).
        fam_df["predicted_class"] = np.where(unified_label == fam, fam, "Normal")
        fam_df.to_csv(out_csv, index=False)
        out_map[fam.lower()] = str(out_csv)
    logger.info(
        "write_family_csvs: %d flows -> 7 per-family CSV (nhãn hợp nhất: %s)",
        len(classified), classified["predicted_class"].value_counts().to_dict())
    return out_map


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    ap = argparse.ArgumentParser(
        description="Unified single-label classifier (DoS volumetric + 6 families).")
    ap.add_argument("input", help="CSV đầu vào (đã trích đặc trưng, *_dos_features.csv).")
    ap.add_argument("-o", "--output", default=None, help="CSV đầu ra đã phân loại.")
    args = ap.parse_args()
    out = run(args.input, args.output)
    dist = out["predicted_class"].value_counts().to_dict()
    logger.info("Phân phối nhãn: %s", dist)


if __name__ == "__main__":
    main()
