"""Tests for /var/lib/sniff-web/last_capture.json read/write/malformed handling."""
import json
import os
import time
import pytest


@pytest.fixture
def persistence_dir(tmp_path):
    d = tmp_path / "sniff-web"
    d.mkdir()
    return str(d)


def test_write_then_read_returns_same_config(persistence_dir):
    from web_server import write_last_capture, read_last_capture
    cfg = {"interface": "ens18", "bpf_filter": "tcp", "snaplen": 65535,
           "promisc": True, "auto_restore": True, "saved_at": "2026-06-26T12:00:00Z"}
    write_last_capture(persistence_dir, cfg)
    out = read_last_capture(persistence_dir)
    assert out == cfg


def test_read_missing_file_returns_none(tmp_path):
    from web_server import read_last_capture
    assert read_last_capture(str(tmp_path)) is None


def test_read_malformed_file_returns_none_and_logs(persistence_dir, caplog):
    from web_server import read_last_capture
    import logging
    p = os.path.join(persistence_dir, "last_capture.json")
    with open(p, "w") as f:
        f.write("this is not json {{{")
    with caplog.at_level(logging.WARNING):
        out = read_last_capture(persistence_dir)
    assert out is None
    assert "malformed" in caplog.text.lower() or "corrupt" in caplog.text.lower() or "invalid" in caplog.text.lower()


def test_write_creates_dir_if_missing(tmp_path):
    from web_server import write_last_capture, read_last_capture
    target = str(tmp_path / "does" / "not" / "exist")
    cfg = {"interface": "lo", "auto_restore": True}
    write_last_capture(target, cfg)
    out = read_last_capture(target)
    assert out is not None
    assert out["interface"] == "lo"


def test_write_validates_required_keys(persistence_dir):
    from web_server import write_last_capture
    with pytest.raises(ValueError):
        write_last_capture(persistence_dir, {"interface": "lo"})  # missing auto_restore