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
        # --- Tự bảo vệ chống DoS (DosGuard) ---
        # Cơ chế pps tuyệt đối (nhỏ/lab; con số tuyệt đối, KHÔNG co giãn theo NIC).
        "dos_trigger_pps": 50_000,   # vượt mức này → bật chế độ cắt tải (DoS)
        "dos_clear_pps": 15_000,     # xuống dưới mức này → tắt (hysteresis)
        "dos_target_pps": 10_000,    # mức gói/giây CHẤP NHẬN thu khi bị DoS
        # Cơ chế backpressure (NIC-agnostic): cắt tải khi pipeline THỰC SỰ hụt
        # hơi (kernel/queue drop, hàng đợi đầy) — đúng cho mọi tốc độ NIC.
        "dos_backpressure": True,
        "dos_queue_high_ratio": 0.5,  # hàng đợi đầy >= mức này → tăng cắt tải
        "dos_queue_low_ratio": 0.2,   # hàng đợi <= mức này + hết drop → giảm dần
        # Cắt tải CÓ CHỌN LỌC theo đích: chỉ hạ luồng đổ vào victim tập trung,
        # giữ nguyên traffic hợp lệ tới đích khác. Đặt dos_victim_share=0 để tắt.
        "dos_victim_share": 0.5,      # 1 đích chiếm >= tỉ lệ này → coi là victim
        "dos_victim_min_pps": 1_000,  # và vượt mức pps này (tránh báo nhầm lúc nhàn)
        "dos_max_drop": 200,          # trần tỉ lệ bỏ gói (giữ tối thiểu 1/200)
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
