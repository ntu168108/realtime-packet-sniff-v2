"""Tests for PCAP manager + config + system info endpoints."""
import os
import pytest
import yaml
from fastapi.testclient import TestClient


@pytest.fixture
def setup_env(monkeypatch, tmp_path):
    monkeypatch.setattr("web_server.PERSISTENCE_DIR_OVERRIDE", str(tmp_path))

    pcap_dir = tmp_path / "sniff_data"
    pcap_dir.mkdir()
    (pcap_dir / "capture_20260626_120000.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)
    (pcap_dir / "capture_20260626_130000.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 200)

    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump({
        "capture": {"output": {"base_dir": str(pcap_dir)}},
        "web": {"bind": "0.0.0.0", "port": 8000, "username": "admin",
                "password_hash": "x", "jwt_secret": "y"},
    }))

    import bcrypt, importlib, web_server
    importlib.reload(web_server)
    web_server.configure_auth("admin", bcrypt.hashpw(b"sniff", bcrypt.gensalt()).decode(), "s", 60)
    monkeypatch.setattr(web_server, "load_web_config", lambda p: yaml.safe_load(open(config_path).read()))
    monkeypatch.setattr(web_server, "_CONFIG_PATH", str(config_path))
    return TestClient(web_server.app)


def _login(c):
    return c.post("/api/auth/login", json={"username": "admin", "password": "sniff"}).json()["token"]


def test_pcap_files_list(setup_env):
    client = setup_env
    tok = _login(client)
    r = client.get("/api/pcap/files", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    files = r.json()
    assert len(files) == 2
    names = sorted([f["name"] for f in files])
    assert names == ["capture_20260626_120000.pcap", "capture_20260626_130000.pcap"]


def test_config_get_returns_sanitized(setup_env):
    client = setup_env
    tok = _login(client)
    r = client.get("/api/config", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    body = r.json()
    for k in ("web.password_hash", "web.jwt_secret"):
        if "." in k:
            section, key = k.split(".", 1)
            assert body.get(section, {}).get(key, "") == ""


def test_config_put_updates_allowlisted_keys(setup_env):
    client = setup_env
    tok = _login(client)
    r = client.put("/api/config", headers={"Authorization": f"Bearer {tok}"},
                   json={"display": {"display_filter": "tcp"}})
    assert r.status_code == 200


def test_config_put_rejects_disallowed_keys(setup_env):
    client = setup_env
    tok = _login(client)
    r = client.put("/api/config", headers={"Authorization": f"Bearer {tok}"},
                   json={"web": {"password_hash": "hacked"}})
    assert r.status_code == 400


def test_system_info_returns_required_keys(setup_env):
    client = setup_env
    tok = _login(client)
    r = client.get("/api/system/info", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    body = r.json()
    for k in ("hostname", "uptime_seconds", "loadavg", "cpu_count",
             "mem_total_mb", "mem_available_mb", "disk_total_gb", "disk_used_gb", "nic_count"):
        assert k in body


def test_all_misc_endpoints_require_auth(setup_env):
    client = setup_env
    for path in ["/api/pcap/files", "/api/config", "/api/system/info"]:
        assert client.get(path).status_code == 401


def test_pcap_download_via_query_token(setup_env, tmp_path):
    """<a download> links cannot set Authorization header; backend must accept ?token=."""
    client = setup_env
    tok = _login(client)
    # Discover an existing pcap file from setup_env (which creates 2 in tmp_path/sniff_data)
    import os as _os
    pcap_dir = next(d for d in tmp_path.iterdir() if d.is_dir() and d.name == "sniff_data")
    pcap_files = list(pcap_dir.glob("*.pcap*"))
    assert pcap_files, "setup_env should have created test pcap files"
    fname = pcap_files[0].name
    # Request with ?token= only (no Authorization header) — simulates <a download>
    r = client.get(f"/api/pcap/download/{fname}?token={tok}")
    assert r.status_code == 200, f"pcap download via ?token= failed: {r.status_code} {r.text}"
    assert r.content[:4] == b"\xd4\xc3\xb2\xa1", "Expected pcap magic bytes (libpcap format)"


def test_pcap_download_rejects_bad_token(setup_env):
    client = setup_env
    r = client.get("/api/pcap/download/foo.pcap?token=invalid")
    assert r.status_code == 401