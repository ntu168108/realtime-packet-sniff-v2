"""Verify every endpoint (except /api/auth/login) requires authentication."""
import time
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr("web_server.PERSISTENCE_DIR_OVERRIDE", str(tmp_path))

    import bcrypt, importlib, web_server
    importlib.reload(web_server)
    web_server.configure_auth("admin", bcrypt.hashpw(b"sniff", bcrypt.gensalt()).decode(), "s", 60)
    return TestClient(web_server.app)


def test_login_endpoint_is_public(client):
    assert client.post("/api/auth/login", json={"username": "admin", "password": "WRONG"}).status_code == 401


def test_login_endpoint_returns_200_with_correct_creds(client):
    assert client.post("/api/auth/login", json={"username": "admin", "password": "sniff"}).status_code == 200


@pytest.mark.parametrize("method,path", [
    ("GET", "/api/interfaces"),
    ("POST", "/api/capture/start"),
    ("POST", "/api/capture/stop"),
    ("POST", "/api/capture/toggle-pause"),
    ("GET", "/api/capture/status"),
    ("GET", "/api/capture/last-config"),
    ("GET", "/api/capture/conversations"),
    ("GET", "/api/services/list"),
    ("POST", "/api/services/kafka/restart"),
    ("GET", "/api/kafka/topics"),
    ("GET", "/api/kafka/lag"),
    ("POST", "/api/clickhouse/query"),
    ("GET", "/api/clickhouse/counts"),
    ("GET", "/api/pcap/files"),
    ("GET", "/api/pcap/download/foo.pcap"),
    ("GET", "/api/config"),
    ("PUT", "/api/config"),
    ("GET", "/api/system/info"),
])
def test_endpoint_requires_auth(client, method, path):
    if method == "POST":
        r = client.post(path, json={})
    elif method == "PUT":
        r = client.put(path, json={})
    else:
        r = client.get(path)
    assert r.status_code == 401, f"{method} {path} returned {r.status_code}"


def test_expired_token_rejected(client):
    import jwt
    expired = jwt.encode({"sub": "admin", "exp": int(time.time()) - 60}, "s", algorithm="HS256")
    assert client.get("/api/capture/status", headers={"Authorization": f"Bearer {expired}"}).status_code == 401
