"""Tests for /api/capture/* endpoints with a mocked CaptureEngine."""
import pytest
from fastapi.testclient import TestClient


class MockEngine:
    def __init__(self):
        self.is_running = False
        self.is_paused = False
        self._setup_called = False
        self._start_called = False
        self._stop_called = False

    def setup(self): self._setup_called = True
    def start(self):
        self._start_called = True; self.is_running = True; self.is_paused = False
    def stop(self):
        self._stop_called = True; self.is_running = False
    def toggle_pause(self):
        self.is_paused = not self.is_paused; return self.is_paused
    def get_status(self):
        return {"interface": "lo", "running": self.is_running, "paused": self.is_paused,
                "uptime": 1.0, "packets": 0, "bytes": 0, "dropped": 0,
                "pps": 0, "bps": 0, "protocols": {}}
    def get_top_conversations(self, n=20):
        return []


@pytest.fixture
def client_with_mock_engine(monkeypatch, tmp_path):
    import bcrypt, importlib, web_server
    importlib.reload(web_server)
    web_server.PERSISTENCE_DIR_OVERRIDE = str(tmp_path)

    engine = MockEngine()
    web_server._test_engine_factory = lambda **kwargs: engine

    # core.capture.get_interfaces() strips 'lo' on systems with >1 NIC.
    # Test contract: 'lo' should validate as a valid interface for /api/capture/start.
    web_server.validate_interface = lambda iface: True
    web_server.get_interfaces = lambda: ["lo", "eth0"]
    web_server.get_interface_info = lambda i: {"name": i, "exists": True}

    # Pre-configure auth (startup will run again, but we re-configure after).
    pw_hash = bcrypt.hashpw(b"sniff", bcrypt.gensalt()).decode()
    web_server.configure_auth("admin", pw_hash, "test_secret", 60)

    client = TestClient(web_server.app)
    # Run startup to populate app.state, then shutdown.
    with client:
        pass
    # startup() resets auth with config defaults — restore test credentials.
    web_server.configure_auth("admin", pw_hash, "test_secret", 60)
    return client, engine


def _login(client):
    return client.post("/api/auth/login", json={"username": "admin", "password": "sniff"}).json()["token"]


def test_start_returns_ok_and_calls_setup_start(client_with_mock_engine):
    client, engine = client_with_mock_engine
    tok = _login(client)
    r = client.post("/api/capture/start", headers={"Authorization": f"Bearer {tok}"},
                    json={"interface": "lo", "bpf_filter": "", "snaplen": 65535,
                          "promisc": True, "auto_restore": True})
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True
    assert engine._setup_called
    assert engine._start_called
    assert engine.is_running


def test_start_twice_returns_400(client_with_mock_engine):
    client, _ = client_with_mock_engine
    tok = _login(client)
    body = {"interface": "lo", "auto_restore": False}
    assert client.post("/api/capture/start", headers={"Authorization": f"Bearer {tok}"}, json=body).status_code == 200
    assert client.post("/api/capture/start", headers={"Authorization": f"Bearer {tok}"}, json=body).status_code == 400


def test_stop_when_not_running_returns_400(client_with_mock_engine):
    client, _ = client_with_mock_engine
    tok = _login(client)
    assert client.post("/api/capture/stop", headers={"Authorization": f"Bearer {tok}"}).status_code == 400


def test_stop_calls_engine_stop(client_with_mock_engine):
    client, engine = client_with_mock_engine
    tok = _login(client)
    client.post("/api/capture/start", headers={"Authorization": f"Bearer {tok}"},
                json={"interface": "lo", "auto_restore": False})
    assert client.post("/api/capture/stop", headers={"Authorization": f"Bearer {tok}"}).status_code == 200
    assert engine._stop_called


def test_toggle_pause_flags_paused(client_with_mock_engine):
    client, _ = client_with_mock_engine
    tok = _login(client)
    client.post("/api/capture/start", headers={"Authorization": f"Bearer {tok}"},
                json={"interface": "lo", "auto_restore": False})
    r = client.post("/api/capture/toggle-pause", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    assert r.json()["paused"] is True


def test_status_always_returns_200_even_when_stopped(client_with_mock_engine):
    client, _ = client_with_mock_engine
    tok = _login(client)
    r = client.get("/api/capture/status", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    body = r.json()
    assert body["running"] is False
    assert "packets" in body


def test_endpoints_require_auth(client_with_mock_engine):
    client, _ = client_with_mock_engine
    assert client.post("/api/capture/start", json={"interface": "lo"}).status_code == 401
    assert client.get("/api/capture/status").status_code == 401
