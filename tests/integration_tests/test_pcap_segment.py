import struct
from integration.pcap_segment import build_segment, parse_segment

def test_roundtrip_meta_and_pcap():
    pkts = [(1000, 0, b"\xaa"*20), (1001, 500, b"\xbb"*30)]
    meta = {"segment_id": "abc", "interface": "ens33", "n_pkts": 2}
    blob = build_segment(pkts, meta)
    got_meta, pcap_bytes = parse_segment(blob)
    assert got_meta["segment_id"] == "abc"
    assert got_meta["n_pkts"] == 2
    # pcap global header magic (little endian microsec)
    assert pcap_bytes[:4] == struct.pack("<I", 0xa1b2c3d4)
    # 2 records present
    assert len(pcap_bytes) == 24 + (16+20) + (16+30)

def test_empty_packet_list_yields_valid_pcap_header():
    pkts = []
    meta = {"segment_id": "empty", "interface": "ens33", "n_pkts": 0}
    blob = build_segment(pkts, meta)
    got_meta, pcap_bytes = parse_segment(blob)
    assert got_meta["n_pkts"] == 0
    # Only the 24-byte global header remains
    assert len(pcap_bytes) == 24
    assert pcap_bytes[:4] == struct.pack("<I", 0xa1b2c3d4)
