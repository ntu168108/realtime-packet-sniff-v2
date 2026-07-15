# -*- coding: utf-8 -*-
"""
config.py - Cấu hình trung tâm cho module trích xuất đặc trưng PCAP.

Chứa danh sách trường, mapping đổi tên cột, merge keys,
và các hằng số dùng chung trong toàn bộ pipeline.
"""

# ============================================================
# Argus - Danh sách trường cần trích xuất
# ============================================================
ARGUS_FIELDS = [
    "smac",      # Source MAC address
    "dmac",      # Destination MAC address
    "saddr",     # Source IP address
    "daddr",     # Destination IP address
    "sport",     # Source port
    "dport",     # Destination port
    "proto",     # Protocol
    "state",     # Transaction state
    "dur",       # Duration
    "sbytes",    # Source-to-destination bytes
    "dbytes",    # Destination-to-source bytes
    "rate",      # Flow rate (goi/giay) - Argus xuat truc tiep (chuan NB15)
    "sttl",      # Source-to-destination TTL
    "dttl",      # Destination-to-source TTL
    "sloss",     # Source packets loss
    "dloss",     # Destination packets loss
    "sload",     # Source bits per second
    "dload",     # Destination bits per second
    "spkts",     # Source-to-destination packet count
    "dpkts",     # Destination-to-source packet count
    "swin",      # Source TCP window advertisement
    "dwin",      # Destination TCP window advertisement
    "stcpb",     # Source TCP base sequence number
    "dtcpb",     # Destination TCP base sequence number
    "smeansz",   # Source mean packet size
    "dmeansz",   # Destination mean packet size
    "sjit",      # Source jitter
    "djit",      # Destination jitter
    "stime",     # Start time
    "ltime",     # Last time
    "sintpkt",   # Source inter-packet arrival time
    "dintpkt",   # Destination inter-packet arrival time
    "tcprtt",    # TCP connection setup round-trip time
    "synack",    # TCP connection setup time, SYN to SYN-ACK
    "ackdat",    # TCP connection setup time, SYN-ACK to ACK
]

# ============================================================
# Zeek - Danh sách trường cần trích xuất
# ============================================================
ZEEK_FIELDS = [
    "orig_l2_addr",  # Source MAC (Layer 2)
    "resp_l2_addr",  # Destination MAC (Layer 2)
    "id.orig_h",     # Source IP
    "id.resp_h",     # Destination IP
    "id.orig_p",     # Source port
    "id.resp_p",     # Destination port
    "proto",         # Protocol
    "service",       # Application-layer service (http, dns, ...)
    "conn_state",    # Connection state (S0, SF, REJ, ...)
    "trans_depth",   # HTTP request pipeline depth
    "res_bdy_len",   # HTTP response body length
    "http_method",   # Gia tri HTTP method (GET/POST/...) -> key cho ct_flw_http_mthd (Alg 3.4)
    "is_ftp_login",  # FTP login status
    "ftp_cmd",       # Gia tri FTP command (USER/PASS/...) -> key cho ct_ftp_cmd (Alg 3.6)
]

# ============================================================
# Data Mapping - Đổi tên cột theo chuẩn UNSW-NB15
# ============================================================
ARGUS_RENAME_MAP = {
    "smac":  "src_mac",
    "dmac":  "dst_mac",
    "saddr": "srcip",
    "daddr": "dstip",
    "sport": "sport",
    "dport": "dport",
    "proto": "proto",
    "sintpkt": "sinpkt",
    "dintpkt": "dinpkt",
}

ZEEK_RENAME_MAP = {
    "orig_l2_addr": "src_mac",
    "resp_l2_addr": "dst_mac",
    "id.orig_h":    "srcip",
    "id.resp_h":    "dstip",
    "id.orig_p":    "sport",
    "id.resp_p":    "dport",
    "proto":        "proto",
    "service":      "service",
    "conn_state":   "state",
}

# ============================================================
# Merge - Bộ khóa gộp 2 DataFrame (5-tuple)
# ============================================================
# Không đưa MAC vào merge key để tránh lỗi lệch luồng
# nếu 1 trong 2 tool nhận diện thiếu MAC.
MERGE_KEYS = ["srcip", "dstip", "sport", "dport", "proto"]

# ============================================================
# Giá trị mặc định thay thế MAC bị thiếu (NaN)
# ============================================================
MAC_FILL_VALUE = "00:00:00:00:00:00"

# ============================================================
# Đường dẫn tới các công cụ CLI (Argus, ra, Zeek)
# ============================================================
import shutil
import os

def _find_tool(name: str, extra_paths: list = None) -> str:
    """Tìm đường dẫn tuyệt đối tới tool, kiểm tra PATH + các vị trí phổ biến."""
    # Thử tìm trong PATH trước
    found = shutil.which(name)
    if found:
        return found
    # Thử các vị trí phổ biến
    search_dirs = extra_paths or []
    search_dirs.extend([
        "/opt/zeek/bin",
        "/usr/local/bin",
        "/usr/sbin",
        "/usr/bin",
    ])
    for d in search_dirs:
        candidate = os.path.join(d, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    # Trả về tên gốc (sẽ báo lỗi rõ ràng khi subprocess chạy)
    return name

ARGUS_BIN = _find_tool("argus")
RA_BIN    = _find_tool("ra")
ZEEK_BIN  = _find_tool("zeek")

# ============================================================
# Đường dẫn mặc định cho file đầu vào / đầu ra
# ============================================================
# Derive từ vị trí file này (MODULE_TRICHXUAT → EC → CSV/CSV_Full_feature),
# hoặc override qua env NB15_OUTPUT_DIR.
from pathlib import Path
_THIS_DIR = Path(__file__).resolve().parent                # .../MODULE_TRICHXUAT
_EC_ROOT  = _THIS_DIR.parent                                # .../Extraction-and-classification

DEFAULT_PCAP_DIR   = str(_EC_ROOT / "Filepcap")
DEFAULT_OUTPUT_DIR = str(_EC_ROOT / "CSV" / "CSV_Full_feature")

# Allow runtime override via env (consumer sets NB15_OUTPUT_DIR to point at $EC).
DEFAULT_OUTPUT_DIR = os.environ.get("NB15_OUTPUT_DIR", DEFAULT_OUTPUT_DIR)

# ============================================================
# Tên file trung gian & output
# ============================================================
ARGUS_BINARY   = "traffic.argus"
ARGUS_TEMP_CSV = "argus_temp.csv"
ZEEK_TEMP_CSV  = "zeek_temp.csv"
ZEEK_LOG_DIR   = "zeek_logs"
OUTPUT_CSV     = "final_features_nb15_with_mac.csv"

