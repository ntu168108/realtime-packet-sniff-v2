from integration.config import load_config

def test_defaults_and_env_override(monkeypatch):
    monkeypatch.setenv("KAFKA_BOOTSTRAP", "k:1234")
    cfg = load_config(path="/nonexistent.yaml")
    assert cfg["kafka"]["topic"] == "raw_pcap_segments"
    assert cfg["kafka"]["bootstrap"] == "k:1234"
    assert cfg["kafka"]["segment_seconds"] == 60
    assert cfg["clickhouse"]["database"] == "network_ids"

def test_yaml_override(tmp_path, monkeypatch):
    monkeypatch.delenv("KAFKA_BOOTSTRAP", raising=False)
    monkeypatch.delenv("CLICKHOUSE_HOST", raising=False)
    yaml = tmp_path / "c.yaml"
    yaml.write_text("kafka:\n  bootstrap: yml:9092\n  segment_seconds: 5\n")
    cfg = load_config(path=str(yaml))
    assert cfg["kafka"]["bootstrap"] == "yml:9092"
    assert cfg["kafka"]["segment_seconds"] == 5
    # untouched defaults survive
    assert cfg["clickhouse"]["database"] == "network_ids"

def test_clickhouse_env_override(monkeypatch):
    monkeypatch.delenv("KAFKA_BOOTSTRAP", raising=False)
    monkeypatch.setenv("CLICKHOUSE_HOST", "ch.example")
    cfg = load_config(path="/nonexistent.yaml")
    assert cfg["clickhouse"]["host"] == "ch.example"


def test_capture_defaults_include_adaptive_dos_keys():
    cfg = load_config(path="/nonexistent-so-defaults-only.yaml")
    cap = cfg["capture"]
    assert cap["dos_backpressure"] is True
    assert cap["dos_queue_high_ratio"] == 0.5
    assert cap["dos_queue_low_ratio"] == 0.2
    assert cap["dos_victim_share"] == 0.5
    assert cap["dos_victim_min_pps"] == 1_000
    assert cap["dos_max_drop"] == 200
