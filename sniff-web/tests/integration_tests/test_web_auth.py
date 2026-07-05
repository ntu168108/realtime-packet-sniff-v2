"""Tests for JWT auth: token roundtrip, expiry, dependency injection."""
import time
import pytest
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient


@pytest.fixture
def app_with_auth(monkeypatch):
    import importlib, bcrypt
    import web_server
    importlib.reload(web_server)
    web_server._JWT_SECRET = "test_secret_for_unit_tests"
    web_server._JWT_EXPIRY = 60

    app = FastAPI()

    @app.get("/protected")
    def protected(user=Depends(web_server.require_user)):
        return {"user": user["username"]}

    @app.post("/api/auth/login")
    def login(body: dict):
        return web_server.login(body.get("username"), body.get("password"))

    @app.post("/api/auth/change-password")
    def change_pwd(body: dict, user=Depends(web_server.require_user)):
        return web_server.change_password(user["username"], body.get("new_password"))

    return app


@pytest.fixture
def client(app_with_auth):
    return TestClient(app_with_auth)


def test_login_with_correct_credentials_returns_token(app_with_auth, monkeypatch):
    import bcrypt, web_server
    web_server._PASSWORD_HASH = bcrypt.hashpw(b"sniff", bcrypt.gensalt()).decode()
    client = TestClient(app_with_auth)
    r = client.post("/api/auth/login", json={"username": "admin", "password": "sniff"})
    assert r.status_code == 200
    body = r.json()
    assert "token" in body
    assert isinstance(body["token"], str)
    assert len(body["token"]) > 20


def test_login_with_wrong_password_returns_401(app_with_auth):
    import bcrypt, web_server
    web_server._PASSWORD_HASH = bcrypt.hashpw(b"sniff", bcrypt.gensalt()).decode()
    client = TestClient(app_with_auth)
    r = client.post("/api/auth/login", json={"username": "admin", "password": "WRONG"})
    assert r.status_code == 401


def test_protected_endpoint_rejects_missing_token(app_with_auth):
    client = TestClient(app_with_auth)
    r = client.get("/protected")
    assert r.status_code == 401


def test_protected_endpoint_accepts_valid_token(app_with_auth):
    import bcrypt, web_server
    web_server._PASSWORD_HASH = bcrypt.hashpw(b"sniff", bcrypt.gensalt()).decode()
    client = TestClient(app_with_auth)
    token_resp = client.post("/api/auth/login", json={"username": "admin", "password": "sniff"})
    token = token_resp.json()["token"]
    r = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["user"] == "admin"


def test_protected_endpoint_rejects_expired_token(app_with_auth):
    import jwt, web_server
    expired = jwt.encode({"sub": "admin", "exp": int(time.time()) - 10},
                         "test_secret_for_unit_tests", algorithm="HS256")
    client = TestClient(app_with_auth)
    r = client.get("/protected", headers={"Authorization": f"Bearer {expired}"})
    assert r.status_code == 401


def test_make_token_decode_token_roundtrip():
    from web_server import make_token, decode_token
    tok = make_token({"sub": "alice"}, secret="s3cret", expiry_s=300)
    payload = decode_token(tok, secret="s3cret")
    assert payload["sub"] == "alice"
