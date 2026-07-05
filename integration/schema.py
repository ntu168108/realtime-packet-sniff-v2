"""Single source of truth for ClickHouse column types and audit metadata.

Derived from a real `*_dos_features.csv` header + pandas dtypes inspection
(UNSW-NB15 49/45 column feature set). IP/host/MAC/proto/state/service/predicted_class
columns are mapped to ClickHouse `String`; integer-like to `Int64`; float-like
to `Float64`. The 7 `flows_<family>` tables share the same column set (the union
of all per-family columns); missing-per-family columns are written as default
zero / empty string.
"""
from __future__ import annotations

from typing import Dict, List, Tuple


# 7 attack families per UNSW-NB15.
FAMILIES: List[str] = [
    "dos",
    "exploits",
    "fuzzers",
    "generic",
    "analysis",
    "reconnaissance",
    "shellcode",
]


# Raw CSV columns (49 UNSW-NB15) used to derive CSV_COLUMNS for the full
# features file (49 cols). Per-family filtered files are subsets of CSV_COLUMNS.
# We track the FULL union across per-family files for the schema (45 cols,
# because some columns are dropped during feature selection).
CSV_COLUMNS_FULL: List[str] = [
    "src_mac", "dst_mac", "srcip", "dstip", "sport", "dport", "proto",
    "service", "state", "dur", "spkts", "dpkts", "sbytes", "dbytes", "sttl",
    "dttl", "smean", "dmean", "trans_depth", "response_body_len",
    "is_ftp_login", "rate", "sloss", "dloss", "sload", "dload", "swin",
    "dwin", "stcpb", "dtcpb", "sjit", "djit", "stime", "ltime", "sinpkt",
    "dinpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports",
    "ct_state_ttl", "ct_dst_ltm", "ct_src_ltm", "ct_srv_dst", "ct_srv_src",
    "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "ct_flw_http_mthd", "ct_ftp_cmd",
]


# The actual columns present in the union of per-family *_features.csv files
# (the schema for `flows_<family>` is built from this union).
CSV_COLUMNS: List[str] = [
    "src_mac", "dst_mac", "srcip", "dstip", "sport", "dport", "ltime",
    "sttl", "ct_state_ttl", "dttl", "sbytes", "dbytes", "smean", "dmean",
    "dur", "spkts", "dpkts", "sloss", "dloss", "tcprtt", "synack", "ackdat",
    "rate", "sload", "dload", "ct_srv_src", "ct_srv_dst", "ct_dst_src_ltm",
    "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_src_ltm", "ct_dst_ltm",
    "ct_flw_http_mthd", "trans_depth", "response_body_len", "proto", "state",
    "service",
    # score + predicted_class are family-specific
    "analysis_score", "exploits_score", "fuzzers_score", "generic_score",
    "reconnaissance_score", "shellcode_score",
    "predicted_class",
]


# Map CSV column name -> ClickHouse type. Determined from pandas dtype inspection
# of real CSVs:
#   object (string) columns -> String (srcip/dstip/src_mac/dst_mac/proto/state/service/predicted_class)
#   int64 columns           -> Int64
#   float64 columns         -> Float64
# Integer counts (counts like ct_*) are non-negative; could be UInt64 but Int64
# is safe and consistent.
_STRING_COLUMNS = {
    "src_mac", "dst_mac", "srcip", "dstip", "proto", "state", "service",
    "predicted_class",
}

CSV_COLUMN_TYPES: Dict[str, str] = {}
for c in CSV_COLUMNS:
    if c in _STRING_COLUMNS:
        CSV_COLUMN_TYPES[c] = "String"
    elif c.endswith("_score"):
        # *_score are integers (0 or 1) per pandas dtypes.
        CSV_COLUMN_TYPES[c] = "Int64"
    else:
        # Numeric columns. We default to Float64; explicit int columns are
        # enumerated below (verified from pandas int64 dtypes).
        CSV_COLUMN_TYPES[c] = "Float64"

# Numeric columns verified as int64 in the real data. Override the Float64 default.
_INT_COLUMNS = {
    "sport", "dport", "ltime", "sttl", "ct_state_ttl", "dttl", "sbytes",
    "dbytes", "smean", "dmean", "spkts", "dpkts", "sloss", "dloss",
    "ct_srv_src", "ct_srv_dst", "ct_dst_src_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_src_ltm", "ct_dst_ltm", "ct_flw_http_mthd",
    "trans_depth", "response_body_len",
}
for c in _INT_COLUMNS:
    if c in CSV_COLUMN_TYPES:
        CSV_COLUMN_TYPES[c] = "Int64"


# Audit columns prepended/appended to feature columns in each flows_<family> table.
# Order matters for the generated DDL: audit + features are all merged into one
# column list per table. The schema is identical across all 7 family tables.
AUDIT_COLUMNS: List[Tuple[str, str]] = [
    ("ts", "DateTime64(3)"),
    ("segment_id", "String"),
    ("attack_family", "LowCardinality(String)"),
    ("attack_subtype", "LowCardinality(String)"),
    ("is_attack", "UInt8"),
    ("interface", "LowCardinality(String)"),
    ("t_window", "LowCardinality(String)"),
    ("pcap_file", "String"),
]


def all_table_columns() -> List[Tuple[str, str]]:
    """Return the (name, ch_type) list for a flows_<family> table.

    Order: audit columns first, then feature columns. Feature columns are the
    union from CSV_COLUMNS in declaration order.
    """
    return AUDIT_COLUMNS + [(c, CSV_COLUMN_TYPES[c]) for c in CSV_COLUMNS]
