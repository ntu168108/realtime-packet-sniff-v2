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


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
