"""Tests for web: section of config.yaml loader."""
import os
import tempfile
import pytest
import yaml


@pytest.fixture
def tmp_config_path(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump({
        "web": {
            "bind": "127.0.0.1",
            "port": 9000,
            "username": "tester",
            "password_hash": "$2b$12$abcdefghijklmnopqrstuv",
            "jwt_secret": "supersecret",
            "jwt_expiry_seconds": 3600,
            "auto_restore": False,
        }
    }))
    return p


def test_load_web_config_returns_dict(tmp_config_path):
    from web_server import load_web_config
    cfg = load_web_config(str(tmp_config_path))
    assert cfg["bind"] == "127.0.0.1"
    assert cfg["port"] == 9000
    assert cfg["username"] == "tester"


def test_load_web_config_missing_section_returns_defaults(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("capture:\n  interface: lo\n")
    from web_server import load_web_config
    cfg = load_web_config(str(p))
    assert cfg["bind"] == "0.0.0.0"
    assert cfg["port"] == 8000
    assert cfg["username"] == "admin"
