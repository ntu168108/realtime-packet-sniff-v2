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
    m |= s.str.endswith(".255").to_numpy(bool)                             # broadcast /24 (heuristic)
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
        # broadcast .255 cuối (heuristic /24)
        mask |= df["dstip"].astype(str).str.endswith(".255").to_numpy(bool)
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
def _detect_dos(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    """Trả về (is_dos: bool[n], subtype: object[n]).

    Một flow là DoS khi:
      (A) "trông giống flood" — điểm cộng dồn SYN/UDP/ICMP (dos_classifier) vượt
          ngưỡng subtype tương ứng; VÀ
      (B) có tín hiệu VOLUME: hoặc đích của nó nhận >= DOS_MIN_FLOWS_PER_DST flow
          flood-like trong segment (đặc trưng flood spoofed-source băm nhỏ),
          hoặc bản thân flow có rate >= DOS_HIGH_RATE (flood cổ điển 1 flow).

    Điều kiện (B) chính là thứ mà kiến trúc cũ thiếu: nó phân biệt "flood thật"
    với "1 flow one-way lẻ trông giống flood" (vd 1 truy vấn DNS không có phản hồi
    trong segment).
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

    # (B) tín hiệu volume: đếm số flow flood-like theo từng dstip trong segment
    n = len(df)
    if "dstip" in df.columns:
        dstip = df["dstip"].astype(str).values
        floodlike_per_dst: dict[str, int] = {}
        for i in range(n):
            if flood_like[i]:
                d = dstip[i]
                floodlike_per_dst[d] = floodlike_per_dst.get(d, 0) + 1
        dst_pressure = np.array(
            [floodlike_per_dst.get(dstip[i], 0) >= DOS_MIN_FLOWS_PER_DST
             for i in range(n)], dtype=bool)
    else:
        dst_pressure = np.zeros(n, dtype=bool)

    rate = pd.to_numeric(df.get("rate", pd.Series(np.zeros(n))),
                         errors="coerce").fillna(0).values
    high_rate = rate >= DOS_HIGH_RATE

    is_dos = flood_like & (dst_pressure | high_rate)
    # Loại đích multicast/broadcast: SSDP(239.255.255.250)/mDNS... là khám phá LAN
    # benign, KHÔNG phải flood nhắm victim. (dos_classifier gốc chỉ loại multicast
    # theo srcip nên bỏ sót các burst tới ĐÍCH multicast — vá tại đây.)
    is_dos &= ~_multicast_broadcast_dst_mask(df)

    # Subtype cho các flow DoS (ưu tiên SYN > UDP > ICMP khi cùng vượt — hiếm).
    subtype = np.full(n, "", dtype=object)
    subtype[is_dos & is_icmp] = "ICMP Flood"
    subtype[is_dos & is_udp] = "UDP Flood"
    subtype[is_dos & is_syn] = "SYN Flood"
    return is_dos, subtype, dos_score.astype(np.int64)


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
    is_dos, subtype, dos_score = _detect_dos(df)
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

    # DoS ưu tiên cao nhất — ghi đè mọi nhãn họ.
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
