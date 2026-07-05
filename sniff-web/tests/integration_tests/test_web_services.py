"""Tests for /api/services/* with mocked systemctl subprocess."""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client_with_mock(monkeypatch, tmp_path):
    monkeypatch.setattr("web_server.PERSISTENCE_DIR_OVERRIDE", str(tmp_path))

    import bcrypt, importlib, web_server
    importlib.reload(web_server)
    web_server.configure_auth("admin", bcrypt.hashpw(b"sniff", bcrypt.gensalt()).decode(), "s", 60)

    calls = []
    def fake_systemctl(name, action):
        calls.append((name, action))
        return {"ok": True, "stdout": "", "stderr": "", "exit_code": 0}
    monkeypatch.setattr(web_server, "run_systemctl", fake_systemctl)
    return TestClient(web_server.app), calls, web_server


def _login(client):
    return client.post("/api/auth/login", json={"username": "admin", "password": "sniff"}).json()["token"]


def test_list_services_returns_known_set(client_with_mock):
    client, _, _ = client_with_mock
    tok = _login(client)
    r = client.get("/api/services/list", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    names = [s["name"] for s in r.json()]
    for expected in ["kafka", "sniff-producer", "ec-consumer", "clickhouse-server", "grafana-server", "sniff-web"]:
        assert expected in names


def test_restart_allowed_service(client_with_mock):
    client, calls, _ = client_with_mock
    tok = _login(client)
    r = client.post("/api/services/kafka/restart", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    assert ("kafka", "restart") in calls


def test_unknown_service_returns_400(client_with_mock):
    client, _, _ = client_with_mock
    tok = _login(client)
    r = client.post("/api/services/evil-svc/restart", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 400


def test_invalid_action_returns_400(client_with_mock):
    client, _, _ = client_with_mock
    tok = _login(client)
    r = client.post("/api/services/kafka/destroy", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 400


def test_sudo_failure_returns_500(client_with_mock, monkeypatch):
    client, _, web_server = client_with_mock
    monkeypatch.setattr(web_server, "run_systemctl",
                        lambda n, a: {"ok": False, "stdout": "", "stderr": "sudo: permission denied", "exit_code": 1})
    tok = _login(client)
    r = client.post("/api/services/kafka/restart", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 500
    assert "permission denied" in r.json()["detail"]


def test_service_endpoints_require_auth(client_with_mock):
    client, _, _ = client_with_mock
    r = client.get("/api/services/list")
    assert r.status_code == 401