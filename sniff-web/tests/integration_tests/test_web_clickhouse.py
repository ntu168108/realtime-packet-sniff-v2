"""Tests for /api/clickhouse/* with allowlist enforcement."""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr("web_server.PERSISTENCE_DIR_OVERRIDE", str(tmp_path))

    import bcrypt, importlib, web_server
    importlib.reload(web_server)
    web_server.configure_auth("admin", bcrypt.hashpw(b"sniff", bcrypt.gensalt()).decode(), "s", 60)

    captured = {}
    def fake_query(sql, max_rows=1000):
        captured["last_sql"] = sql
        return {"columns": ["n"], "rows": [[42]], "elapsed_ms": 1.5}
    monkeypatch.setattr(web_server, "query_clickhouse", fake_query)
    return TestClient(web_server.app), captured


def _login(client):
    return client.post("/api/auth/login", json={"username": "admin", "password": "sniff"}).json()["token"]


def test_select_passes_through(client):
    c, captured = client
    tok = _login(c)
    r = c.post("/api/clickhouse/query", headers={"Authorization": f"Bearer {tok}"},
               json={"sql": "SELECT count() FROM network_ids.flows_all"})
    assert r.status_code == 200
    assert r.json()["rows"] == [[42]]
    assert "SELECT" in captured["last_sql"]


def test_show_passes_through(client):
    c, _ = client
    tok = _login(c)
    r = c.post("/api/clickhouse/query", headers={"Authorization": f"Bearer {tok}"},
               json={"sql": "SHOW TABLES FROM network_ids"})
    assert r.status_code == 200


def test_insert_blocked(client):
    c, _ = client
    tok = _login(c)
    r = c.post("/api/clickhouse/query", headers={"Authorization": f"Bearer {tok}"},
               json={"sql": "INSERT INTO flows_all VALUES (1,2,3)"})
    assert r.status_code == 400


def test_drop_blocked(client):
    c, _ = client
    tok = _login(c)
    assert c.post("/api/clickhouse/query", headers={"Authorization": f"Bearer {tok}"},
                  json={"sql": "DROP TABLE flows_all"}).status_code == 400


def test_truncate_blocked(client):
    c, _ = client
    tok = _login(c)
    assert c.post("/api/clickhouse/query", headers={"Authorization": f"Bearer {tok}"},
                  json={"sql": "TRUNCATE TABLE flows_all"}).status_code == 400


def test_alter_blocked(client):
    c, _ = client
    tok = _login(c)
    assert c.post("/api/clickhouse/query", headers={"Authorization": f"Bearer {tok}"},
                  json={"sql": "ALTER TABLE flows_all DELETE WHERE 1=1"}).status_code == 400


def test_max_rows_enforced(client, monkeypatch):
    c, _ = client
    captured = {}
    def cap(sql, max_rows=1000):
        captured["max_rows"] = max_rows
        return {"columns": [], "rows": [], "elapsed_ms": 0.1}
    import web_server
    monkeypatch.setattr(web_server, "query_clickhouse", cap)
    tok = _login(c)
    c.post("/api/clickhouse/query", headers={"Authorization": f"Bearer {tok}"},
           json={"sql": "SELECT 1", "max_rows": 5000})
    assert captured["max_rows"] == 1000


def test_empty_sql_rejected(client):
    c, _ = client
    tok = _login(c)
    r = c.post("/api/clickhouse/query", headers={"Authorization": f"Bearer {tok}"}, json={"sql": ""})
    assert r.status_code == 400


def test_endpoint_requires_auth(client):
    c, _ = client
    assert c.post("/api/clickhouse/query", json={"sql": "SELECT 1"}).status_code == 401