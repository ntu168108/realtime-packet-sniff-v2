"""Load config từ config.yaml + env override."""
import copy
import os

import yaml

_DEFAULTS = {
    "kafka": {
        "bootstrap": "localhost:9092",
        "topic": "raw_pcap_segments",
        "segment_seconds": 60,
        "segment_max_bytes": 64 * 1024 * 1024,
        # Trần CỨNG số gói mỗi segment. Chống DoS: một trận flood gói nhỏ có
        # thể nhồi ~880k gói vào 64MiB → khi trích đặc trưng sẽ cạn RAM. Cắt
        # ở 100k giữ segment đủ nhỏ để Argus/Zeek/pandas xử lý an toàn.
        "segment_max_packets": 100_000,
    },
    "clickhouse": {
        "host": "localhost",
        "port": 9000,
        "database": "network_ids",
        "batch_size": 10000,
    },
    "capture": {
        "interface": "ens33",
        "bpf": "not port 22",
        "keep_local_pcap": False,
        # Ngưỡng tự bảo vệ chống DoS (DosGuard). pps = gói/giây.
        "dos_trigger_pps": 50_000,   # vượt mức này → bật chế độ cắt tải (DoS)
        "dos_clear_pps": 15_000,     # xuống dưới mức này → tắt (hysteresis)
        "dos_target_pps": 10_000,    # mức gói/giây ta CHẤP NHẬN thu khi bị DoS
    },
}


def _merge(base, over):
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge(base[k], v)
        else:
            base[k] = v
    return base


def load_config(path=None):
    cfg = copy.deepcopy(_DEFAULTS)
    path = path or os.path.join(os.path.dirname(__file__), "..", "config.yaml")
    if os.path.exists(path):
        with open(path) as f:
            _merge(cfg, yaml.safe_load(f) or {})
    if os.environ.get("KAFKA_BOOTSTRAP"):
        cfg["kafka"]["bootstrap"] = os.environ["KAFKA_BOOTSTRAP"]
    if os.environ.get("CLICKHOUSE_HOST"):
        cfg["clickhouse"]["host"] = os.environ["CLICKHOUSE_HOST"]
    return cfg
