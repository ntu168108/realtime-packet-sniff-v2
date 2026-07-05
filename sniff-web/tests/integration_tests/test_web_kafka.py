"""Tests for /api/kafka/* with mocked kafka client."""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr("web_server.PERSISTENCE_DIR_OVERRIDE", str(tmp_path))

    import bcrypt, importlib, web_server
    importlib.reload(web_server)
    web_server.configure_auth("admin", bcrypt.hashpw(b"sniff", bcrypt.gensalt()).decode(), "s", 60)

    monkeypatch.setattr(web_server, "list_kafka_topics",
                        lambda: {"topics": [
                            {"name": "raw_pcap_segments", "partitions": 1, "replication": 1},
                            {"name": "__consumer_offsets", "partitions": 50, "replication": 1},
                        ]})
    monkeypatch.setattr(web_server, "kafka_lag",
                        lambda group: {"group": group, "total_lag": 5,
                                       "partitions": [{"topic": "raw_pcap_segments", "partition": 0, "lag": 5}]})
    return TestClient(web_server.app)


def _login(client):
    return client.post("/api/auth/login", json={"username": "admin", "password": "sniff"}).json()["token"]


def test_topics_returns_list(client):
    tok = _login(client)
    r = client.get("/api/kafka/topics", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    names = [t["name"] for t in r.json()["topics"]]
    assert "raw_pcap_segments" in names


def test_lag_default_group_is_ec_consumer(client):
    tok = _login(client)
    r = client.get("/api/kafka/lag", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    assert r.json()["group"] == "ec-consumer"


def test_lag_custom_group(client):
    tok = _login(client)
    r = client.get("/api/kafka/lag?group=foo", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    assert r.json()["group"] == "foo"


def test_kafka_down_returns_503(client, monkeypatch):
    import web_server
    def fail(): raise ConnectionError("kafka unreachable")
    monkeypatch.setattr(web_server, "list_kafka_topics", fail)
    tok = _login(client)
    r = client.get("/api/kafka/topics", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 503


def test_requires_auth(client):
    assert client.get("/api/kafka/topics").status_code == 401
