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
