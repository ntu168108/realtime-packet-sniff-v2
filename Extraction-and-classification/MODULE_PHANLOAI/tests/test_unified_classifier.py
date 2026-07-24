# -*- coding: utf-8 -*-
"""Unit tests cho unified_classifier — bám các kịch bản traffic THẬT đã quan sát.

Các dòng dữ liệu dưới đây lấy đúng đặc trưng đo được từ capture thật (ens19,
2026-07-11) của hệ thống: flood hping3 --rand-source bị Argus gộp thành flow
1-GÓI (rate=0, sttl=64), mDNS/SSDP benign sttl=255, download HTTPS ngoài
(dttl thấp do nhiều hop), exploit HTTP nội bộ (dttl=64).
"""
import sys
from pathlib import Path

import pandas as pd
import pytest

_MOD = Path(__file__).resolve().parent.parent
if str(_MOD) not in sys.path:
    sys.path.insert(0, str(_MOD))

from unified_classifier import classify_segment  # noqa: E402


def _syn_flood_rows(n=60):
    """SYN flood spoofed-source: mỗi IP nguồn khác nhau, flow 1-gói tới victim."""
    return [{
        "srcip": f"103.{i%256}.{(i*7)%256}.{(i*13)%256}", "dstip": "192.168.101.135",
        "sport": 40000 + i, "dport": 80, "proto": "tcp", "state": "s0",
        "service": "-", "sttl": 64, "dttl": 0, "ct_state_ttl": 0,
        "synack": 0.0, "tcprtt": 0.0, "dbytes": 0, "dmean": 0, "rate": 0.0,
        "sload": 0.0, "sloss": 0, "ct_dst_src_ltm": 1, "spkts": 1, "sbytes": 118,
        "dpkts": 0, "smean": 118, "dur": 0.0,
    } for i in range(n)]


def _benign_mdns_rows(n=10):
    """mDNS/SSDP benign: sttl cao, đích multicast — KHÔNG được là tấn công."""
    return [{
        "srcip": "192.168.1.84", "dstip": "239.255.255.250",
        "sport": 50000 + i, "dport": 1900, "proto": "udp", "state": "s0",
        "service": "-", "sttl": 255, "dttl": 0, "ct_state_ttl": 0,
        "synack": 0.0, "tcprtt": 0.0, "dbytes": 0, "dmean": 0, "rate": 1.4,
        "sload": 0.0, "sloss": 0, "ct_dst_src_ltm": 1, "spkts": 4, "sbytes": 848,
        "dpkts": 0, "smean": 212, "dur": 0.0,
    } for i in range(n)]


def _benign_ext_https_rows(n=10):
    """Download HTTPS ra server internet: nhiều byte/gói nhưng dttl thấp (hop)."""
    return [{
        "srcip": "192.168.105.200", "dstip": "47.89.128.168",
        "sport": 51000 + i, "dport": 443, "proto": "tcp", "state": "sf",
        "service": "-", "sttl": 64, "dttl": 43, "ct_state_ttl": 0,
        "synack": 0.01, "tcprtt": 0.02, "dbytes": 200000, "dmean": 1400,
        "rate": 500.0, "sload": 100000.0, "sloss": 0, "ct_dst_src_ltm": 1,
        "spkts": 150, "sbytes": 360000, "dpkts": 200, "smean": 1400, "dur": 2.0,
    } for i in range(n)]


def _exploit_rows(n=8):
    """Exploit HTTP nội bộ (victim cùng LAN → dttl=64): payload lớn, spkts cao."""
    return [{
        "srcip": "192.168.106.60", "dstip": "192.168.101.135",
        "sport": 37750 + i, "dport": 80, "proto": "tcp", "state": "sf",
        "service": "http", "sttl": 64, "dttl": 64, "ct_state_ttl": 1,
        "synack": 0.01, "tcprtt": 0.02, "dbytes": 21495, "dmean": 537,
        "rate": 200.0, "sload": 50000.0, "sloss": 0, "ct_dst_src_ltm": 1,
        "spkts": 42, "sbytes": 12451, "dpkts": 40, "smean": 296,
        "dur": 0.4, "response_body_len": 0, "dloss": 0,
    } for i in range(n)]


def test_syn_flood_single_packet_flows_labeled_dos():
    """Flood 1-gói (rate=0, sttl=64) PHẢI ra DoS — thứ mà ngưỡng NB15 cũ bỏ lọt."""
    df = pd.DataFrame(_syn_flood_rows(60))
    out = classify_segment(df)
    assert (out["predicted_class"] == "DoS").mean() >= 0.95
    assert (out["attack_subtype"] == "SYN Flood").sum() >= 55


def test_dos_not_labeled_as_fuzzers_or_recon():
    """Flow flood KHÔNG được đồng thời mang nhãn Fuzzers/Reconnaissance nữa."""
    df = pd.DataFrame(_syn_flood_rows(60))
    out = classify_segment(df)
    assert (out["predicted_class"] == "Fuzzers").sum() == 0
    assert (out["predicted_class"] == "Reconnaissance").sum() == 0


def test_single_label_per_flow():
    """Mỗi flow đúng 1 nhãn — không có cột điểm nào 'thắng' chồng chéo bảng khác."""
    df = pd.DataFrame(_syn_flood_rows(50) + _exploit_rows(8))
    out = classify_segment(df)
    # predicted_class là 1 chuỗi đơn — bất biến quan trọng nhất của thiết kế mới.
    assert out["predicted_class"].map(lambda x: isinstance(x, str)).all()
    assert set(out["predicted_class"].unique()) <= {
        "DoS", "Exploits", "Shellcode", "Generic", "Analysis",
        "Reconnaissance", "Fuzzers", "Normal"}


def test_mdns_ssdp_multicast_is_normal():
    """mDNS/SSDP benign (đích multicast, sttl=255) KHÔNG được là DoS/attack."""
    df = pd.DataFrame(_benign_mdns_rows(60))  # đủ đông để thử kích hoạt volumetric
    out = classify_segment(df)
    assert (out["predicted_class"] != "Normal").sum() == 0


def test_external_https_download_not_exploit():
    """Download HTTPS ra ngoài (dttl thấp) KHÔNG được gán nhãn Exploits."""
    df = pd.DataFrame(_benign_ext_https_rows(10))
    out = classify_segment(df)
    assert (out["predicted_class"] == "Exploits").sum() == 0


def test_internal_exploit_detected():
    """Exploit nội bộ (dttl=64, payload lớn) PHẢI ra Exploits."""
    df = pd.DataFrame(_exploit_rows(8))
    out = classify_segment(df)
    assert (out["predicted_class"] == "Exploits").mean() >= 0.75


def test_low_false_positive_on_mixed_benign():
    """Nền benign trộn (mDNS + HTTPS ngoài) phải gần như sạch (FP thấp)."""
    df = pd.DataFrame(_benign_mdns_rows(30) + _benign_ext_https_rows(20))
    out = classify_segment(df)
    fp = (out["predicted_class"] != "Normal").mean()
    assert fp <= 0.05, f"FP rate too high: {fp:.2%}"


def test_empty_input():
    df = pd.DataFrame(columns=["srcip", "dstip", "proto", "sttl"])
    out = classify_segment(df)
    assert len(out) == 0
    assert "predicted_class" in out.columns


def test_non_ip_protocols_are_normal():
    """ARP/STP/ethertype số — traffic L2 — KHÔNG được thành attack."""
    rows = [{
        "srcip": "192.168.1.5", "dstip": "192.168.1.6", "sport": 0, "dport": 0,
        "proto": p, "state": "con", "service": "-", "sttl": 0, "dttl": 0,
        "ct_state_ttl": 0, "spkts": 1, "sbytes": 60, "dbytes": 0, "dur": 0.0,
        "rate": 0.0, "synack": 0.0, "tcprtt": 0.0, "dmean": 0, "sloss": 0,
        "ct_dst_src_ltm": 1,
    } for p in ["arp", "35130", "llc", "ipv6-icmp"]]
    out = classify_segment(pd.DataFrame(rows))
    assert (out["predicted_class"] == "Normal").all()


def _port_scan_rows(n=500, dstip="192.168.101.135"):
    """Port-scan Nmap: 1 SYN probe/cổng, n cổng KHÁC NHAU, cùng 1 host.

    Đặc trưng đo được thật: spkts=1, sbytes=60, dur cực ngắn (LAN RTT),
    khiến rate = spkts/dur bị đẩy lên hàng nghìn. Trước bản vá, 100% số flow
    này bị gán nhãn DoS (khớp KB1 của báo cáo NCKH: 248/377 luồng sai).
    """
    import random
    rng = random.Random(0)
    rows = []
    for i in range(n):
        dur = rng.uniform(0.0003, 0.0015)
        rows.append({
            "srcip": "192.168.106.60", "dstip": dstip,
            "sport": 40000, "dport": 1 + i, "proto": "tcp", "state": "s0",
            "service": "-", "sttl": 64, "dttl": 0, "ct_state_ttl": 0,
            "synack": 0.0, "tcprtt": 0.0, "dbytes": 0, "dmean": 0,
            "rate": 1.0 / dur, "sload": 0.0, "sloss": 0, "ct_dst_src_ltm": 10,
            "spkts": 1, "sbytes": 60, "dpkts": 0, "smean": 60, "dur": dur,
        })
    return rows


def test_port_scan_not_labeled_dos():
    """KB1: quét 500 cổng của 1 host KHÔNG được là DoS (lỗi báo cáo NCKH ghi nhận)."""
    df = pd.DataFrame(_port_scan_rows(500))
    out = classify_segment(df)
    assert (out["predicted_class"] == "DoS").sum() == 0


def test_port_scan_labeled_reconnaissance():
    """Và phải ra đúng họ Reconnaissance, KHÔNG phải Suspicious-Low-Volume."""
    df = pd.DataFrame(_port_scan_rows(500))
    out = classify_segment(df)
    assert (out["predicted_class"] == "Reconnaissance").mean() >= 0.95


def test_single_port_flood_still_dos_after_scan_fix():
    """Kiểm soát false-negative: flood dồn 1 cổng PHẢI vẫn là DoS sau bản vá."""
    df = pd.DataFrame(_syn_flood_rows(500))   # toàn bộ dport=80
    out = classify_segment(df)
    assert (out["predicted_class"] == "DoS").mean() >= 0.95


def test_single_packet_probe_does_not_trip_high_rate():
    """rate cao do dur cực ngắn trên flow 1 GÓI không được kích hoạt cổng DoS."""
    rows = _port_scan_rows(10)
    for r in rows:
        r["rate"] = 50000.0          # rate rất cao...
        r["spkts"] = 1               # ...nhưng chỉ 1 gói -> không đáng tin
    out = classify_segment(pd.DataFrame(rows))
    assert (out["predicted_class"] == "DoS").sum() == 0


def test_multi_port_flood_within_spread_still_dos():
    """Biên: flood trải trên 5 cổng (<= DOS_MAX_DPORT_SPREAD) vẫn PHẢI là DoS.

    Chốt lại rằng ngưỡng đa dạng cổng không siết quá tay thành false-negative.
    """
    rows = _syn_flood_rows(500)
    for i, r in enumerate(rows):
        r["dport"] = 80 + (i % 5)
    out = classify_segment(pd.DataFrame(rows))
    assert (out["predicted_class"] == "DoS").mean() >= 0.95


def test_flood_with_missing_dport_still_dos():
    """Flood mà dport THIẾU (NaN) phải vẫn là DoS — chống false-negative.

    Cổng đa dạng cổng đích đếm số dport riêng biệt. Nếu dport thiếu được đếm
    thô, mỗi NaN thành một phần tử set riêng (Python >=3.10: hash(NaN) theo
    id(), và nan != nan) → spread = số flow → dst_pressure=False → bỏ lọt
    100%. Đã đo được đúng như vậy trước khi chuẩn hoá dport: 500/500 DoS
    thành 0/500. Xảy ra thật với flow ICMP (không có cổng đích) và ô CSV rỗng.
    """
    import numpy as np
    for missing in (np.nan, "", None):
        rows = _syn_flood_rows(500)
        for r in rows:
            r["dport"] = missing
        out = classify_segment(pd.DataFrame(rows))
        got = (out["predicted_class"] == "DoS").mean()
        assert got >= 0.95, f"dport={missing!r}: chỉ {got:.1%} ra DoS"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
