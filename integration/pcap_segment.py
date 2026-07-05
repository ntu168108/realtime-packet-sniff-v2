"""Serialize gói tin thành 1 blob: [len header][header JSON][pcap file bytes]."""
import json
import struct

_PCAP_MAGIC = 0xa1b2c3d4
_LINKTYPE_EN10MB = 1

def _pcap_global_header() -> bytes:
    return struct.pack("<IHHiIII", _PCAP_MAGIC, 2, 4, 0, 0, 65535, _LINKTYPE_EN10MB)

def build_segment(packets, meta) -> bytes:
    body = _pcap_global_header()
    for ts_sec, ts_usec, data in packets:
        body += struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)) + data
    header = json.dumps(meta).encode("utf-8")
    return struct.pack(">I", len(header)) + header + body

def parse_segment(blob):
    (hlen,) = struct.unpack(">I", blob[:4])
    meta = json.loads(blob[4:4+hlen].decode("utf-8"))
    pcap_bytes = blob[4+hlen:]
    return meta, pcap_bytes
