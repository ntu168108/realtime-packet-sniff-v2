"""SNIFF Web GUI — FastAPI backend.

Single pane of glass for the realtime-packet-sniff IDS pipeline:
controls the in-process capture engine, manages systemd services,
queries Kafka and ClickHouse, manages rotated PCAP files.
"""
from __future__ import annotations

import json
import logging
import os
import copy
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

DEFAULTS: Dict[str, Any] = {
    "bind": "0.0.0.0",
    "port": 8000,
    "username": "admin",
    "password_hash": "",
    "jwt_secret": "",
    "jwt_expiry_seconds": 86400,
    "auto_restore": True,
    "persistence_dir": "/var/lib/sniff-web",
    # External integrations (surfaced on /credentials, linked from Dashboard)
    "grafana_url": "",
    "grafana_admin_password": "",
    "grafana_dashboard_path": "/d/network-ids/network-ids-overview",
    "integrations": {
        "clickhouse": {"url": "http://localhost:8123", "username": "default", "password": ""},
        "kafka":      {"url": "localhost:9092", "username": "", "password": "", "protocol": "PLAINTEXT"},
    },
    # Server-side history buffers for the dashboard
    "alert_ring_size": 20,
    "rate_history_size": 60,        # samples
    "rate_history_interval": 5,     # seconds per sample
}


def _resolve_config_yaml() -> Path:
    """Try CWD first (systemd unit WorkingDirectory), then repo root.
    Returns the resolved path; existence not checked.
    """
    cand = Path(_CONFIG_PATH)
    if cand.is_file():
        return cand.resolve()
    fallback = Path(__file__).resolve().parent.parent / _CONFIG_PATH
    if fallback.is_file():
        return fallback.resolve()
    return cand  # Caller decides what to do if missing.


def load_web_config(path: str) -> Dict[str, Any]:
    """Load the `web:` section from config.yaml. Returns DEFAULTS merged with file values."""
    p = _resolve_config_yaml() if path == "config.yaml" else Path(path)
    if not p.exists():
        return dict(DEFAULTS)
    with p.open("r", encoding="utf-8") as f:
        full = yaml.safe_load(f) or {}
    web = full.get("web", {}) or {}
    merged = dict(DEFAULTS)
    merged.update(web)
    return merged


# ---------------------------------------------------------------------------
# Persistence layer (Task 3): last_capture.json
# ---------------------------------------------------------------------------

logger = logging.getLogger("sniff_web")

_LAST_CAPTURE_FILENAME = "last_capture.json"
_REQUIRED_KEYS = {"interface", "auto_restore"}


def read_last_capture(persistence_dir: str) -> Optional[dict]:
    """Read last capture config. Returns None if file missing or malformed."""
    path = Path(persistence_dir) / _LAST_CAPTURE_FILENAME
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Last capture config at %s is malformed: %s", path, exc)
        return None
    if not isinstance(data, dict):
        logger.warning("Last capture config at %s is not a dict", path)
        return None
    return data


def write_last_capture(persistence_dir: str, cfg: dict) -> None:
    """Persist capture config atomically. Validates required keys."""
    missing = _REQUIRED_KEYS - set(cfg.keys())
    if missing:
        raise ValueError(f"Missing required keys: {missing}")
    p = Path(persistence_dir)
    p.mkdir(parents=True, exist_ok=True)
    target = p / _LAST_CAPTURE_FILENAME
    tmp = target.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    tmp.replace(target)


# ---------------------------------------------------------------------------
# Auth layer (Task 2): JWT + bcrypt
# ---------------------------------------------------------------------------

import secrets
import time
import bcrypt
import jwt
from fastapi import Depends, Header, HTTPException, Query, status

_USERNAME = "admin"
_PASSWORD_HASH = ""
_JWT_SECRET = ""
_JWT_EXPIRY = 86400


def configure_auth(username: str, password_hash: str, jwt_secret: str, jwt_expiry: int) -> None:
    global _USERNAME, _PASSWORD_HASH, _JWT_SECRET, _JWT_EXPIRY
    _USERNAME = username
    _PASSWORD_HASH = password_hash
    _JWT_SECRET = jwt_secret or secrets.token_urlsafe(32)
    _JWT_EXPIRY = jwt_expiry


def make_token(payload: dict, secret=None, expiry_s=None) -> str:
    sec = secret or _JWT_SECRET
    exp = expiry_s if expiry_s is not None else _JWT_EXPIRY
    now = int(time.time())
    full = {**payload, "iat": now, "exp": now + exp, "sub": payload.get("sub", _USERNAME)}
    return jwt.encode(full, sec, algorithm="HS256")


def decode_token(token: str, secret=None) -> dict:
    sec = secret or _JWT_SECRET
    return jwt.decode(token, sec, algorithms=["HS256"])


def require_user(authorization: str = Header(None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = decode_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")
    return {"username": payload["sub"]}


def require_user_query_or_header(
    authorization: Optional[str] = Header(None),
    token: Optional[str] = Query(None),
) -> dict:
    """FastAPI dependency: accept JWT from Authorization header OR ?token= query.

    Used by /api/pcap/download/{name} so browser <a download> tags (which
    cannot set Authorization headers) can pass the JWT via the URL.
    """
    raw = None
    if authorization and authorization.lower().startswith("bearer "):
        raw = authorization.split(" ", 1)[1].strip()
    elif token:
        raw = token
    if not raw:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")
    try:
        payload = decode_token(raw)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")
    return {"username": payload["sub"]}


def login(username: str, password: str) -> dict:
    if username != _USERNAME:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    if not _PASSWORD_HASH:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Auth not configured")
    if not bcrypt.checkpw(password.encode("utf-8"), _PASSWORD_HASH.encode("utf-8")):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    token = make_token({"sub": username})
    return {"token": token, "expires_in": _JWT_EXPIRY}


def change_password(username: str, new_password: str) -> dict:
    if username != _USERNAME:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid user")
    global _PASSWORD_HASH
    _PASSWORD_HASH = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Capture layer (Task 4): FastAPI app + lifecycle endpoints
# ---------------------------------------------------------------------------

import sys
import subprocess
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

# `core/` lives one level above this file (at the repo root) and
# `sniff-web/` modules (e.g. requirements_web helpers) live next to it.
# Insert the repo root FIRST so that `import core.capture` resolves
# regardless of CWD; the systemd unit's PYTHONPATH also carries the
# repo root (see install_web.sh step [5/8]).
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))                # has core/, modules/, sniff.py
sys.path.insert(0, str(Path(__file__).resolve().parent))   # has web_*.py siblings

try:
    from core.capture import CaptureEngine, get_interfaces, validate_interface, get_interface_info
    from core.decoder import decode_packet
    from core.rotator import HourlyRotator
except ImportError as e:
    logger.warning("Could not import core.capture: %s", e)
    CaptureEngine = None
    get_interfaces = None
    validate_interface = None
    get_interface_info = None
    decode_packet = None
    HourlyRotator = None

PERSISTENCE_DIR_OVERRIDE = None
_test_engine_factory = None


def _make_engine(**kwargs):
    if _test_engine_factory is not None:
        return _test_engine_factory(**kwargs)
    if CaptureEngine is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Capture engine unavailable")
    return CaptureEngine(**kwargs)


def _make_rotator(interface: str, snaplen: int):
    """Build an HourlyRotator from app.state.full_config (capture.output.*).

    Returns None when core.rotator is unavailable or config is missing — the
    CaptureEngine still runs (packets stream to the UI), only the on-disk
    pcap files are skipped. The UI shows a non-fatal warning in that case.
    """
    if HourlyRotator is None:
        logger.warning("HourlyRotator unavailable; PCAP files will NOT be written")
        return None
    cfg = getattr(app.state, "full_config", {}) or {}
    out = (cfg.get("capture") or {}).get("output") or {}
    if not out:
        logger.warning("capture.output missing in config; PCAP files will NOT be written")
        return None
    logger.info("Building HourlyRotator: base_dir=%s interface=%s snaplen=%d retention=%d max_file=%d",
                out.get("base_dir"), interface, snaplen,
                int(out.get("retention_days", 7)), int(out.get("max_file_size", 500 * 1024 * 1024)))
    return HourlyRotator(
        base_dir=out.get("base_dir", "./sniff_data"),
        interface=interface,
        snaplen=snaplen,
        retention_days=int(out.get("retention_days", 7)),
        max_file_size=int(out.get("max_file_size", 500 * 1024 * 1024)),
        compress=bool(out.get("compress", False)),
    )


# ---------------------------------------------------------------------------
# Sync sniff-producer service with /capture (Task v0.4.0)
# ---------------------------------------------------------------------------
# Before v0.4.0 the web UI's /capture page ran its own in-process CaptureEngine
# (for real-time packet display via WebSocket), while the Kafka/ClickHouse
# classification pipeline was driven by the separate `sniff-producer` systemd
# service which read `config.yaml` at start-up. As a result changing the
# interface in /capture only affected the UI; the IDS pipeline kept capturing
# whatever was in config.yaml — usually out of sync with what the operator
# saw on screen.
#
# In v0.4.0 the /capture page also rewrites `capture.interface`/`capture.bpf_filter`
# in config.yaml and triggers a `systemctl restart sniff-producer`, so the UI
# and the IDS pipeline always point at the same NIC. The sudoers allowlist
# installed by install_web.sh permits `sniff-web` to run `systemctl restart
# sniff-producer` (and friends) without a password.


def _update_capture_section_yaml(interface: str, bpf_filter: Optional[str]) -> tuple:
    """Atomically update capture.interface (and optionally bpf_filter) in
    config.yaml so the sniff-producer service picks them up on next start.

    Returns (ok, message). All other keys are preserved; YAML formatting and
    comments are lost (yaml.safe_dump is the cheapest correct option). For
    production deployments where config.yaml is generated by install_web.sh
    this is acceptable.
    """
    path = _resolve_config_yaml()
    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except OSError as exc:
        return False, f"cannot read {path}: {exc}"
    cap = data.setdefault("capture", {})
    cap["interface"] = interface
    if bpf_filter is not None:
        cap["bpf_filter"] = bpf_filter
    try:
        tmp = path.with_suffix(path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False,
                           allow_unicode=True)
        tmp.replace(path)
    except OSError as exc:
        return False, f"cannot write {path}: {exc}"
    logger.info("Updated capture.interface=%r in %s", interface, path)
    return True, f"updated capture.interface={interface!r} in {path}"


def _restart_sniff_producer() -> tuple:
    """Restart the sniff-producer systemd service non-interactively.

    The sudoers file installed by install_web.sh grants the `sniff-web` user
    permission to run `systemctl {start,stop,restart,…} sniff-producer` (and
    peers) without a password — see deploy/sudoers/sniff-web and step [4/8]
    of scripts/install_web.sh. We invoke `sudo -n` so the call fails fast
    rather than hanging on a missing password if the allowlist is missing.
    """
    try:
        proc = subprocess.run(
            ["sudo", "-n", "systemctl", "restart", "sniff-producer"],
            capture_output=True, text=True, timeout=15,
        )
    except subprocess.TimeoutExpired:
        return False, "systemctl restart sniff-producer timed out after 15s"
    except FileNotFoundError:
        return False, "sudo binary not found on PATH"
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()
        return False, f"systemctl restart failed: {msg}"
    logger.info("sniff-producer restarted successfully")
    return True, "sniff-producer restarted"


def _interface_ipv4(iface: str) -> Optional[str]:
    """Return the first IPv4 address bound to `iface`, or None if not found.

    Uses psutil (already in sniff-web/requirements-web.txt for system-info
    queries); falls back to the bind/connect trick on `0.0.0.0` if psutil is
    not importable for any reason. Returns None when the interface has no
    IPv4 address (e.g. unconfigured NIC).
    """
    try:
        import psutil  # type: ignore
        addrs = psutil.net_if_addrs().get(iface, [])
        for a in addrs:
            if getattr(a, "family", None) == psutil.AF_INET and a.address:
                return a.address
    except Exception as exc:
        logger.debug("psutil.net_if_addrs(%r) failed: %s", iface, exc)
    return None


# ---------------------------------------------------------------------------
# Packet broadcast pipeline (asyncio queues + callbacks + WS fan-out)
# ---------------------------------------------------------------------------

import asyncio
import contextlib
from collections import deque

_loop: Optional[asyncio.AbstractEventLoop] = None
_pkt_queue: Optional[asyncio.Queue] = None
_drop_queue: Optional[asyncio.Queue] = None
# Opt-in L7 decode (DNS/HTTP/TLS/DHCP/NTP/QUIC info) for the live packet table.
# Off by default: deep decode is CPU-heavier than the fast header-only path.
_deep_decode_enabled = False

# v0.4.1 — bound on how long a slow WebSocket client can stall the packet
# broadcast. Without this, a single stuck browser tab freezes _fan_out,
# which fills _pkt_queue (maxsize=4000), which raises QueueFull on every
# packet, which floods journal logs and (more importantly) blocks the
# asyncio loop long enough that HTTP requests time out — operator sees
# the web UI as "frozen". 1 s is generous for local LAN browsers but
# short enough that a wedged client is evicted in well under a second.
WS_SEND_TIMEOUT: float = 1.0

# ---------------------------------------------------------------------------
# Dashboard history buffers (rate_history + alert ring)
# ---------------------------------------------------------------------------
# Configured in configure_dashboard_history() from web config on startup.
_alert_ring: "deque[dict]" = deque(maxlen=20)
_rate_pps: "deque[float]" = deque(maxlen=60)
_rate_bps: "deque[float]" = deque(maxlen=60)
_rate_ts: "deque[float]" = deque(maxlen=60)
_history_task: Optional[asyncio.Task] = None


def configure_dashboard_history(alert_ring_size: int, rate_history_size: int) -> None:
    """Re-size the history buffers from config. Called once on startup."""
    global _alert_ring, _rate_pps, _rate_bps, _rate_ts
    _alert_ring = deque(maxlen=max(1, int(alert_ring_size)))
    _rate_pps = deque(maxlen=max(1, int(rate_history_size)))
    _rate_bps = deque(maxlen=max(1, int(rate_history_size)))
    _rate_ts = deque(maxlen=max(1, int(rate_history_size)))


def record_alert(det: dict) -> None:
    """Append an alert to the ring. Safe to call from any thread."""
    if not isinstance(det, dict):
        return
    _alert_ring.append(det)


def snapshot_rate_history() -> dict:
    return {
        "pps": list(_rate_pps),
        "bps": list(_rate_bps),
        "ts":  list(_rate_ts),
    }


async def _history_loop(interval_s: float) -> None:
    """Sample capture stats every `interval_s` seconds into _rate_* deques."""
    while True:
        try:
            await asyncio.sleep(interval_s)
            eng = getattr(app.state, "engine", None)
            if eng is None:
                # Engine absent — record zeros so the sparkline stays continuous
                _rate_pps.append(0.0)
                _rate_bps.append(0.0)
                _rate_ts.append(time.time())
                continue
            try:
                status = eng.get_status()
            except Exception as exc:                                # pragma: no cover
                logger.debug("history sample failed: %s", exc)
                continue
            _rate_pps.append(float(status.get("pps", 0.0) or 0.0))
            _rate_bps.append(float(status.get("bps", 0.0) or 0.0))
            _rate_ts.append(time.time())
        except asyncio.CancelledError:
            return
        except Exception as exc:                                    # pragma: no cover
            logger.debug("history_loop error: %s", exc)


def _enqueue_from_thread(q, payload) -> None:
    """Thread-safe enqueue into the asyncio loop. Drops silently if loop/queue
    isn't ready yet (e.g. callbacks fired before lifespan startup)."""
    try:
        loop = _loop
        if loop is None or q is None:
            return
        loop.call_soon_threadsafe(q.put_nowait, payload)
    except Exception as exc:
        logger.debug("enqueue failed: %s", exc)


def _cb_packet(pkt_info):
    """Called from Scapy's thread for each captured packet. Crosses thread boundary via call_soon_threadsafe."""
    _enqueue_from_thread(_pkt_queue, pkt_info)


def _cb_drop(reason: str, count: int):
    """Called from Scapy's thread when packets are dropped."""
    _enqueue_from_thread(_drop_queue, {"reason": reason, "count": count})


async def _fan_out(clients: set, msg: str):
    """Send JSON message to all connected WebSocket clients; drop dead ones.

    Each send_text is wrapped in asyncio.wait_for(WS_SEND_TIMEOUT) so a
    slow client (browser tab in background, network glitch) cannot block
    the entire broadcast loop. Timed-out clients are dropped — they will
    reconnect on the next /ws/connect if the browser still has the tab
    open. Without this guard, one stuck client is enough to halt packet
    fan-out for everyone else; combined with a full asyncio.Queue that
    would freeze all HTTP handlers because uvicorn runs the asyncio loop
    in a single worker (see deploy/systemd/sniff-web.service --workers 1).
    """
    if not clients:
        return
    targets = list(clients)
    coros = [_send_with_timeout(ws, msg) for ws in targets]
    results = await asyncio.gather(*coros, return_exceptions=True)
    dead = {ws for ws, r in zip(targets, results) if isinstance(r, BaseException)}
    clients -= dead


async def _send_with_timeout(ws, msg: str):
    """send_text with a hard cap. TimeoutError / disconnect → caller drops the client."""
    try:
        await asyncio.wait_for(ws.send_text(msg), timeout=WS_SEND_TIMEOUT)
    except asyncio.TimeoutError:
        logger.debug("WS send_text timeout after %.1fs, dropping client", WS_SEND_TIMEOUT)
        raise
    except Exception as exc:
        logger.debug("WS send_text error: %s", exc)
        raise


async def _broadcast_packets():
    """Drain pkt_queue, decode packets, fan out to /ws/packets subscribers at ~20 Hz."""
    while True:
        await asyncio.sleep(0.05)
        if not packet_clients:
            # Drain to avoid stale accumulation when no clients
            while True:
                try:
                    _pkt_queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                except Exception:
                    break
            continue
        batch = []
        for _ in range(32):
            try:
                pkt = _pkt_queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            except Exception:
                continue
            try:
                d = decode_packet(pkt.data, deep=_deep_decode_enabled)
                batch.append({
                    "stt": pkt.stt,
                    "ts": pkt.ts_sec + pkt.ts_usec / 1_000_000,
                    "src": d.src_addr, "dst": d.dst_addr,
                    "src_port": d.src_port, "dst_port": d.dst_port,
                    "src_mac": d.ethernet.src_mac if d.ethernet else "",
                    "dst_mac": d.ethernet.dst_mac if d.ethernet else "",
                    "proto": d.protocol_name, "len": pkt.caplen,
                    "info": (d.info_str or "")[:160],
                })
            except Exception:
                continue
        if batch:
            await _fan_out(packet_clients, json.dumps({"type": "packets", "data": batch}))


async def _broadcast_stats():
    """1Hz stats broadcaster: pulls engine.get_status() and counts drop events."""
    drop_total = 0
    while True:
        await asyncio.sleep(1.0)
        # Drain drop queue, accumulate total
        while True:
            try:
                ev = _drop_queue.get_nowait()
                drop_total += ev.get("count", 0)
            except asyncio.QueueEmpty:
                break
            except Exception:
                break
        if not stats_clients:
            continue
        eng = getattr(app.state, "engine", None)
        if eng and getattr(eng, "is_running", False):
            try:
                status = eng.get_status()
            except Exception:
                status = {"running": True, "paused": False, "interface": None,
                          "packets": 0, "bytes": 0, "dropped": 0,
                          "pps": 0, "bps": 0, "protocols": {}, "uptime": 0}
        else:
            status = dict(_EMPTY_STATUS)
        status["ws_drop_total"] = drop_total
        await _fan_out(stats_clients, json.dumps({"type": "stats", "data": status}))


class StartBody(BaseModel):
    interface: str
    bpf_filter: str = ""
    snaplen: int = Field(default=65535, ge=64, le=65535)
    promisc: bool = True
    auto_restore: bool = True


app = FastAPI(title="SNIFF Web GUI", version="0.3.0")


@app.post("/api/auth/login")
def api_login(body: dict):
    return login(body.get("username"), body.get("password"))


@app.on_event("startup")
async def _on_startup():
    cfg = load_web_config("config.yaml")
    persistence = PERSISTENCE_DIR_OVERRIDE or cfg["persistence_dir"]
    # Test override: when SNIFF_WEB_TEST=1, configure auth from env vars so the
    # Playwright webServer can boot without writing a real config.yaml.
    if os.environ.get("SNIFF_WEB_TEST") == "1":
        _u = os.environ.get("SNIFF_WEB_TEST_USERNAME", "admin")
        _p = os.environ.get("SNIFF_WEB_TEST_PASSWORD", "sniff")
        configure_auth(username=_u,
                       password_hash=bcrypt.hashpw(_p.encode(), bcrypt.gensalt()).decode(),
                       jwt_secret="test_secret", jwt_expiry=3600)
    else:
        configure_auth(username=cfg["username"], password_hash=cfg["password_hash"],
                       jwt_secret=cfg["jwt_secret"], jwt_expiry=cfg["jwt_expiry_seconds"])
    app.state.persistence_dir = persistence
    # Cache the parsed web config so request handlers don't re-parse YAML
    # on every call. /api/auth/change-password invalidates this.
    app.state.web_config = cfg
    # Also cache the FULL config.yaml (top-level keys: capture, web, ...).
    # Some handlers (e.g. _make_rotator) need the `capture.output` block
    # which lives at the top level, not under `web:`.
    try:
        with open("config.yaml", "r", encoding="utf-8") as f:
            app.state.full_config = yaml.safe_load(f) or {}
    except OSError:
        try:
            with open(Path(__file__).resolve().parent.parent / "config.yaml",
                      "r", encoding="utf-8") as f:
                app.state.full_config = yaml.safe_load(f) or {}
        except OSError:
            app.state.full_config = {}

    # Initialize asyncio queues and start broadcast tasks
    global _loop, _pkt_queue, _drop_queue, _history_task
    _loop = asyncio.get_running_loop()
    # v0.4.1 — packet queue raised from 4000 to 32 768 to keep pace with
    # high-rate captures (~30 pps sustained). With 4000 we hit QueueFull
    # within ~130 s of capture-vs-broadcast skew, raising exceptions that
    # flood journal logs; 32 768 ≈ 18 min of headroom at 30 pps, more
    # than enough to ride out a slow WS client or a brief stall.
    _pkt_queue = asyncio.Queue(maxsize=32768)
    _drop_queue = asyncio.Queue(maxsize=1000)
    asyncio.create_task(_broadcast_packets())
    asyncio.create_task(_broadcast_stats())

    # Dashboard history buffers + 5-second sampler
    configure_dashboard_history(
        alert_ring_size=cfg.get("alert_ring_size", 20),
        rate_history_size=cfg.get("rate_history_size", 60),
    )
    interval = float(cfg.get("rate_history_interval", 5) or 5)
    _history_task = asyncio.create_task(_history_loop(interval))
    if cfg["auto_restore"]:
        last = read_last_capture(persistence)
        if last and last.get("auto_restore") and last.get("interface"):
            if validate_interface(last["interface"]):
                logger.info("Auto-restoring capture on %s", last["interface"])
                rotator = _make_rotator(last["interface"], last.get("snaplen", 65535))
                app.state.engine = _make_engine(
                    interface=last["interface"], bpf_filter=last.get("bpf_filter", ""),
                    snaplen=last.get("snaplen", 65535), promisc=last.get("promisc", True),
                    rotator=rotator,
                    on_packet_filtered=_cb_packet, on_drop=_cb_drop)
                app.state.rotator = rotator
                app.state.engine.setup()
                app.state.engine.start()
            else:
                logger.warning("Auto-restore skipped: interface %s not found", last.get("interface"))


@app.on_event("shutdown")
async def _on_shutdown():
    eng = getattr(app.state, "engine", None)
    if eng and getattr(eng, "is_running", False):
        eng.stop()
    rotator = getattr(app.state, "rotator", None)
    if rotator is not None:
        try:
            rotator.close()
        except Exception as exc:
            logger.debug("rotator close error: %s", exc)
    if _history_task is not None:
        _history_task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await _history_task


@app.get("/api/interfaces")
def api_interfaces(user=Depends(require_user)):
    if get_interfaces is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "core.capture unavailable")
    return [get_interface_info(i) for i in get_interfaces()]


@app.post("/api/capture/start")
def api_start(body: StartBody, user=Depends(require_user)):
    if not validate_interface(body.interface):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Interface '{body.interface}' not found")
    eng = getattr(app.state, "engine", None)
    if eng and getattr(eng, "is_running", False):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Capture already running")
    rotator = _make_rotator(body.interface, body.snaplen)
    new_engine = _make_engine(interface=body.interface, bpf_filter=body.bpf_filter,
                              snaplen=body.snaplen, promisc=body.promisc,
                              rotator=rotator,
                              on_packet_filtered=_cb_packet, on_drop=_cb_drop)
    new_engine.setup()
    new_engine.start()
    app.state.engine = new_engine
    app.state.rotator = rotator
    write_last_capture(app.state.persistence_dir, {
        "interface": body.interface, "bpf_filter": body.bpf_filter, "snaplen": body.snaplen,
        "promisc": body.promisc, "auto_restore": body.auto_restore,
        "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })

    # ---- v0.4.0: sync sniff-producer service so Kafka/ClickHouse pipeline
    # mirrors the interface the operator just selected in the web UI.
    # Update capture.interface in config.yaml atomically, then trigger
    # `systemctl restart sniff-producer` (sudoers-allowed). Failures are
    # reported back to the caller but do NOT undo the in-process engine —
    # the web UI keeps streaming packets; only the classification pipeline
    # may be temporarily out of sync.
    yaml_ok, yaml_msg = _update_capture_section_yaml(body.interface, body.bpf_filter)
    svc_ok, svc_msg = _restart_sniff_producer()

    return {
        "ok": True,
        "sniff_producer": {
            "config_updated": yaml_ok,
            "config_msg": yaml_msg,
            "restarted": svc_ok,
            "restart_msg": svc_msg,
        },
    }


@app.post("/api/capture/stop")
def api_stop(user=Depends(require_user)):
    eng = getattr(app.state, "engine", None)
    if not eng or not getattr(eng, "is_running", False):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No capture running")
    eng.stop()
    return {"ok": True}


@app.post("/api/capture/toggle-pause")
def api_toggle_pause(user=Depends(require_user)):
    eng = getattr(app.state, "engine", None)
    if not eng or not getattr(eng, "is_running", False):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No capture running")
    paused = eng.toggle_pause()
    return {"paused": paused}


@app.get("/api/capture/status")
def api_status(user=Depends(require_user)):
    eng = getattr(app.state, "engine", None)
    if not eng:
        return dict(_EMPTY_STATUS)
    return eng.get_status()


@app.get("/api/capture/last-config")
def api_last_config(user=Depends(require_user)):
    cfg = read_last_capture(app.state.persistence_dir)
    if cfg is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No last config")
    return cfg


@app.get("/api/capture/conversations")
def api_conversations(n: int = 20, user=Depends(require_user)):
    eng = getattr(app.state, "engine", None)
    if not eng or not getattr(eng, "is_running", False):
        return []
    return eng.get_top_conversations(n)


@app.get("/api/capture/deep-decode")
def api_get_deep_decode(user=Depends(require_user)):
    return {"enabled": _deep_decode_enabled}


@app.post("/api/capture/deep-decode")
def api_set_deep_decode(body: dict, user=Depends(require_user)):
    global _deep_decode_enabled
    _deep_decode_enabled = bool(body.get("enabled"))
    return {"enabled": _deep_decode_enabled}


# ---------------------------------------------------------------------------
# Dashboard summary + alert ingest + integrations (Task: visual dashboard)
# ---------------------------------------------------------------------------

@app.get("/api/dashboard/summary")
def api_dashboard_summary(user=Depends(require_user)):
    """Aggregated payload for the redesigned Dashboard in one round-trip."""
    eng = getattr(app.state, "engine", None)
    if eng is not None:
        try:
            capture = eng.get_status()
        except Exception:
            capture = {"running": False, "pps": 0, "bps": 0, "packets": 0,
                       "dropped": 0, "protocols": {}, "uptime": 0}
        try:
            top = eng.get_top_conversations(10)
        except Exception:
            top = []
    else:
        capture = {"running": False, "pps": 0, "bps": 0, "packets": 0,
                   "dropped": 0, "protocols": {}, "uptime": 0}
        top = []

    cfg = getattr(app.state, "web_config", {}) or {}
    grafana_url = (cfg.get("grafana_url") or "").rstrip("/")
    grafana_path = cfg.get("grafana_dashboard_path") or "/d/network-ids/network-ids-overview"
    grafana_full = f"{grafana_url}{grafana_path}" if grafana_url else ""

    return {
        "capture": capture,
        "services": list_services_status(),
        "counts": _clickhouse_counts_safe(),
        "protocols": capture.get("protocols", {}) or {},
        "top_talkers": top,
        "alerts_recent": list(_alert_ring),
        "rate_history": snapshot_rate_history(),
        "grafana_url": grafana_full,
        "generated_at": time.time(),
    }


def _clickhouse_counts_safe() -> dict:
    """Run the same SELECTs as /api/clickhouse/counts but inline, so the
    Depends(require_user) context isn't required and failures are swallowed."""
    families = ["dos", "exploits", "fuzzers", "generic", "analysis",
                "reconnaissance", "shellcode"]
    out = {}
    try:
        r = query_clickhouse("SELECT count() FROM network_ids.flows_all", 1)
        out["flows_all"] = r["rows"][0][0] if r["rows"] else 0
        for fam in families:
            # All 7 flows_<family> tables score the SAME underlying flow set
            # (each row appears in every table), so a plain count() is always
            # identical across families and tells you nothing about
            # classification. is_attack=1 is what actually differs per family.
            r = query_clickhouse(f"SELECT count() FROM network_ids.flows_{fam} WHERE is_attack = 1", 1)
            out[f"flows_{fam}"] = r["rows"][0][0] if r["rows"] else 0
        r = query_clickhouse("SELECT count() FROM network_ids.pipeline_runs", 1)
        out["pipeline_runs"] = r["rows"][0][0] if r["rows"] else 0
    except Exception as exc:                                    # pragma: no cover
        logger.debug("clickhouse counts failed: %s", exc)
        return {}
    return out


@app.post("/api/alerts")
def api_alerts_ingest(det: dict, user=Depends(require_user)):
    """Append a Detection into the alert ring. Producers call this from
    LiveRunner / alert sinks. Returns the alert_id stored."""
    det = dict(det or {})
    det.setdefault("received_at", time.time())
    if "alert_id" not in det and det.get("label"):
        det["alert_id"] = f"{det.get('label')}-{int(det.get('ts_sec', time.time()))}-{int(time.time()*1000) % 100000}"
    record_alert(det)
    return {"ok": True, "alert_id": det.get("alert_id")}


@app.get("/api/integrations/credentials")
def api_integrations_credentials(user=Depends(require_user)):
    """Return per-service URL + username + password for the /credentials page.

    The sniff_web admin password is NOT returned in plaintext — only the
    bcrypt hash is in the config — so we render a hint instead. Other
    services return whatever is configured (empty string → "not configured").

    Host resolution (v0.4.0+): prefer the IPv4 of the currently-captured
    interface (so the URLs on /credentials match what the operator is
    actually looking at), fall back to the web.bind address, then to the
    host's primary IP. This is the single source of truth for "what
    hostname should I point Grafana/ClickHouse/Kafka at when surfacing
    links to the user".
    """
    cfg = getattr(app.state, "web_config", {}) or {}
    integrations = cfg.get("integrations") or {}
    ch = integrations.get("clickhouse") or {}
    kf = integrations.get("kafka") or {}

    bind = cfg.get("bind", "0.0.0.0")
    port = cfg.get("port", 8000)

    # 1) Prefer the IPv4 of the interface that's actively being captured.
    eng = getattr(app.state, "engine", None)
    running_iface = getattr(eng, "interface", None) if eng else None
    host = _interface_ipv4(running_iface) if running_iface else None

    # 2) Fall back to the web.bind address (may be 0.0.0.0/:: or a specific IP).
    if not host:
        if bind in ("0.0.0.0", "::"):
            # Show the host's primary IP rather than 0.0.0.0 — more useful as a link
            import socket
            try:
                host = socket.gethostbyname(socket.gethostname())
            except Exception:
                host = "localhost"
        else:
            host = bind

    return {
        "sniff_web": {
            "url": f"http://{host}:{port}",
            "username": cfg.get("username") or "admin",
            # bcrypt hash isn't reversible — hint the user where the password lives
            "password": None,
            "password_hint": "Set in config.yaml under web.password_hash (or auto-generated by install_web.sh)",
            "note": "Password is bcrypt-hashed; cannot be displayed. Change via /api/auth/change-password.",
        },
        "grafana": {
            "url": (cfg.get("grafana_url") or f"http://{host}:3000"),
            "username": "admin",
            "password": cfg.get("grafana_admin_password") or None,
            "dashboard_path": cfg.get("grafana_dashboard_path") or "/d/network-ids/network-ids-overview",
            "note": "Default is admin/admin unless overridden.",
        },
        "clickhouse": {
            "url": ch.get("url") or "http://localhost:8123",
            "username": ch.get("username") or "default",
            "password": ch.get("password") or None,
            "native_port": 9000,
            "note": "HTTP interface for read-only SQL queries.",
        },
        "kafka": {
            "url": kf.get("url") or "localhost:9092",
            "username": kf.get("username") or None,
            "password": kf.get("password") or None,
            "protocol": kf.get("protocol") or "PLAINTEXT",
            "note": "PLAINTEXT bootstrap; SASL not yet configured.",
        },
    }


# ---------------------------------------------------------------------------
# Systemd service control (Task 5)
# ---------------------------------------------------------------------------

SERVICE_ALLOWLIST = {"kafka", "sniff-producer", "ec-consumer", "clickhouse-server", "grafana-server", "sniff-web"}
SERVICE_ACTIONS = {"start", "stop", "restart", "enable", "disable"}


def run_systemctl(name: str, action: str) -> dict:
    if name not in SERVICE_ALLOWLIST or action not in SERVICE_ACTIONS:
        raise ValueError(f"Disallowed: {action} {name}")
    try:
        proc = subprocess.run(["sudo", "-n", "systemctl", action, name],
                              capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        return {"ok": False, "stdout": "", "stderr": "systemctl timeout", "exit_code": 124}
    except FileNotFoundError:
        return {"ok": False, "stdout": "", "stderr": "sudo not found", "exit_code": 127}
    return {"ok": proc.returncode == 0, "stdout": proc.stdout,
            "stderr": proc.stderr, "exit_code": proc.returncode}


def list_services_status() -> list:
    out = []
    for name in sorted(SERVICE_ALLOWLIST):
        try:
            proc = subprocess.run(["systemctl", "is-active", name],
                                  capture_output=True, text=True, timeout=5)
            active = proc.stdout.strip() == "active"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            active = False
        out.append({"name": name, "active": active})
    return out


@app.get("/api/services/list")
def api_services_list(user=Depends(require_user)):
    return list_services_status()


@app.post("/api/services/{name}/{action}")
def api_services_action(name: str, action: str, user=Depends(require_user)):
    if name not in SERVICE_ALLOWLIST:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Service '{name}' not in allowlist")
    if action not in SERVICE_ACTIONS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Action '{action}' not allowed")
    result = run_systemctl(name, action)
    if not result["ok"]:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,
                            result["stderr"] or f"systemctl {action} {name} failed")
    return {"ok": True, "exit_code": result["exit_code"]}


CH_ALLOWLIST_PREFIXES = ("SELECT ", "SHOW ", "DESCRIBE ", "DESC ", "EXISTS ", "SELECT 1")
CH_MAX_ROWS_HARD_LIMIT = 1000


def query_clickhouse(sql: str, max_rows: int = 1000) -> dict:
    from clickhouse_driver import Client
    import time as _t
    # Resolve CH connection from web.integrations.clickhouse (or fall back to defaults).
    web_cfg = load_web_config("config.yaml")
    ch_cfg = (web_cfg.get("integrations") or {}).get("clickhouse") or {}
    # clickhouse_driver uses the NATIVE protocol (port 9000), NOT the HTTP
    # interface (8123) referenced in the dashboard 'url' field. Use the
    # native port unless an explicit override is present.
    from urllib.parse import urlparse
    url = ch_cfg.get("url", "http://localhost:8123")
    parsed = urlparse(url) if "://" in url else None
    host = (parsed.hostname if parsed else None) or (url.split(":", 1)[0] if url else "localhost") or "localhost"
    port = ch_cfg.get("native_port") or 9000
    user = ch_cfg.get("username") or "default"
    password = ch_cfg.get("password") or None
    client_kwargs = {"host": host, "port": int(port), "database": "network_ids"}
    if user:
        client_kwargs["user"] = user
    if password:
        client_kwargs["password"] = password
    client = Client(**client_kwargs)
    start = _t.time()
    rows = client.execute(sql, with_column_types=True)
    elapsed = (_t.time() - start) * 1000
    if not rows:
        return {"columns": [], "rows": [], "elapsed_ms": elapsed}
    data, types = rows
    columns = [t[0] for t in types]
    truncated = data[:max_rows]
    return {"columns": columns, "rows": [list(r) for r in truncated], "elapsed_ms": elapsed}


@app.post("/api/clickhouse/query")
def api_clickhouse_query(body: dict, user=Depends(require_user)):
    sql = (body.get("sql") or "").strip()
    if not sql:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Empty SQL")
    upper = sql.upper().lstrip()
    if not any(upper.startswith(p) for p in CH_ALLOWLIST_PREFIXES):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Only SELECT/SHOW/DESCRIBE/EXISTS allowed")
    max_rows = min(int(body.get("max_rows", 1000)), CH_MAX_ROWS_HARD_LIMIT)
    try:
        return query_clickhouse(sql, max_rows)
    except Exception as exc:
        logger.warning("ClickHouse query failed: %s", exc)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, f"ClickHouse error: {exc}")


@app.get("/api/clickhouse/counts")
def api_clickhouse_counts(user=Depends(require_user)):
    families = ["dos", "exploits", "fuzzers", "generic", "analysis", "reconnaissance", "shellcode"]
    out = {}
    try:
        result = query_clickhouse("SELECT count() FROM network_ids.flows_all", 1)
        out["flows_all"] = result["rows"][0][0] if result["rows"] else 0
        for fam in families:
            # See _clickhouse_counts_safe(): count of flows classified as an
            # attack of THIS family, not a raw row count (which is identical
            # across all 7 tables since they share the same flow set).
            r = query_clickhouse(f"SELECT count() FROM network_ids.flows_{fam} WHERE is_attack = 1", 1)
            out[f"flows_{fam}"] = r["rows"][0][0] if r["rows"] else 0
        r = query_clickhouse("SELECT count() FROM network_ids.pipeline_runs", 1)
        out["pipeline_runs"] = r["rows"][0][0] if r["rows"] else 0
        return out
    except Exception as exc:
        logger.warning("ClickHouse counts failed: %s", exc)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "ClickHouse unavailable")


# ---------------------------------------------------------------------------
# Kafka admin (Task 7): topics list + consumer-group lag
# ---------------------------------------------------------------------------

KAFKA_BOOTSTRAP = "localhost:9092"


def list_kafka_topics() -> dict:
    from kafka.admin import KafkaAdminClient
    admin = KafkaAdminClient(bootstrap_servers=KAFKA_BOOTSTRAP, request_timeout_ms=5000)
    try:
        topics_meta = admin.describe_topics()
    finally:
        admin.close()
    out = []
    for t in topics_meta:
        if t["topic"].startswith("__"):
            continue
        partitions = t.get("partitions", [])
        replication = len(partitions[0].get("replicas", [])) if partitions else 0
        out.append({"name": t["topic"], "partitions": len(partitions), "replication": replication})
    return {"topics": sorted(out, key=lambda x: x["name"])}


def kafka_lag(group: str) -> dict:
    from kafka import KafkaConsumer, TopicPartition
    consumer = KafkaConsumer(bootstrap_servers=KAFKA_BOOTSTRAP, group_id=group,
                             enable_auto_commit=False, consumer_timeout_ms=2000)
    try:
        partitions = consumer.partitions_for_topic("raw_pcap_segments") or set()
        tps = [TopicPartition("raw_pcap_segments", p) for p in partitions]
        if not tps:
            return {"group": group, "total_lag": 0, "partitions": []}
        consumer.assign(tps)
        end_offsets = consumer.end_offsets(tps)
        total = 0
        per_partition = []
        for tp in tps:
            try:
                committed = consumer.committed(tp) or 0
            except Exception:
                committed = 0
            lag = max(0, end_offsets[tp] - committed)
            total += lag
            per_partition.append({"topic": tp.topic, "partition": tp.partition, "lag": lag})
        return {"group": group, "total_lag": total, "partitions": per_partition}
    finally:
        consumer.close()


@app.get("/api/kafka/topics")
def api_kafka_topics(user=Depends(require_user)):
    try:
        return list_kafka_topics()
    except Exception as exc:
        logger.warning("Kafka topics failed: %s", exc)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Kafka unavailable")


@app.get("/api/kafka/lag")
def api_kafka_lag(group: str = "ec-consumer", user=Depends(require_user)):
    try:
        return kafka_lag(group)
    except Exception as exc:
        logger.warning("Kafka lag failed: %s", exc)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Kafka unavailable")


# ---------------------------------------------------------------------------
# Task 8: PCAP manager + Config + System info
# ---------------------------------------------------------------------------

_CONFIG_PATH = "config.yaml"


CONFIG_WRITABLE = {
    "display.display_filter", "display.exclude_ports", "display.cache_size",
    "live.enabled",
    "modules.enabled", "modules.auto_discover",
    "performance.ring_buffer_size", "performance.batch_size",
    "performance.enable_deep_decode", "performance.gc_interval",
}
_SANITIZE_HIDE = {"web.password_hash", "web.jwt_secret"}


def _read_full_config() -> dict:
    p = _resolve_config_yaml()
    if not p.exists():
        return {}
    with p.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _sanitize_config(cfg: dict) -> dict:
    out = copy.deepcopy(cfg)
    for dotted in _SANITIZE_HIDE:
        section, key = dotted.split(".", 1)
        if section in out and isinstance(out[section], dict):
            out[section][key] = ""
    return out


@app.get("/api/pcap/files")
def api_pcap_files(user=Depends(require_user)):
    cfg = _read_full_config()
    base = cfg.get("capture", {}).get("output", {}).get("base_dir", "./sniff_data")
    base_path = Path(base)
    if not base_path.exists():
        return []
    # HourlyRotator writes {base}/YYYY-MM-DD/{interface}_YYYY-MM-DD_HH.pcap[.gz]
    # so we have to rglob the directory tree, not just the top level.
    out = []
    candidates = list(base_path.glob("*.pcap*"))
    candidates.extend(base_path.rglob("*.pcap*"))
    seen = set()
    for p in candidates:
        if str(p) in seen:
            continue
        seen.add(str(p))
        try:
            st = p.stat()
        except OSError:
            continue
        out.append({
            "name": p.name,
            "relpath": str(p.relative_to(base_path)),
            "size": st.st_size,
            "mtime": int(st.st_mtime),
        })
    out.sort(key=lambda x: x["mtime"], reverse=True)
    return out[:500]


@app.get("/api/pcap/download/{relpath:path}")
def api_pcap_download(relpath: str, user=Depends(require_user_query_or_header)):
    """Download a rotated PCAP file. Accepts JWT via Authorization header OR ?token= query.

    The query-param variant exists because <a download> anchor tags cannot set
    Authorization headers — the frontend embeds ?token= in the URL for those.

    `relpath` is path-relative-to-base (e.g. `2026-06-27/ens18_2026-06-27_07.pcap`).
    We guard against `..` traversal by resolving the candidate and confirming
    it stays under the configured base_dir.
    """
    # Path traversal guard
    if ".." in relpath or relpath.startswith("/"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid filename")
    cfg = _read_full_config()
    base = cfg.get("capture", {}).get("output", {}).get("base_dir", "./sniff_data")
    base_path = Path(base).resolve()
    target = (base_path / relpath).resolve()
    try:
        target.relative_to(base_path)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Path escapes base_dir")
    if not target.exists() or not target.is_file():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found")
    return FileResponse(str(target), filename=target.name, media_type="application/octet-stream")


@app.get("/api/config")
def api_config_get(user=Depends(require_user)):
    try:
        return _sanitize_config(_read_full_config())
    except Exception as exc:
        logger.warning("Read config failed: %s", exc)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Config unreadable")


@app.put("/api/config")
def api_config_put(body: dict, user=Depends(require_user)):
    full = _read_full_config()
    for top, sub in body.items():
        if not isinstance(sub, dict):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"'{top}' must be object")
        for k in sub.keys():
            dotted = f"{top}.{k}"
            if dotted not in CONFIG_WRITABLE:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Key '{dotted}' not writable via web")
    full.update(body)
    p = _resolve_config_yaml()
    with p.open("w", encoding="utf-8") as f:
        yaml.safe_dump(full, f, default_flow_style=False)
    return {"ok": True}


# ---------------------------------------------------------------------------
# WebSocket endpoints (Task 9): packets, stats, services
# ---------------------------------------------------------------------------

from fastapi import WebSocket, WebSocketDisconnect, Query

packet_clients: set = set()
stats_clients: set = set()
services_clients: set = set()

_EMPTY_STATUS = {
    "running": False, "paused": False, "interface": None,
    "packets": 0, "bytes": 0, "dropped": 0,
    "queue_dropped": 0, "write_dropped": 0,
    "queue_size": 0, "queue_capacity": 0, "queue_dropped_total": 0,
    "pps": 0, "bps": 0, "protocols": {}, "uptime": 0,
}


async def _verify_ws_token(websocket: WebSocket, token: str = Query("")) -> bool:
    if not token:
        await websocket.close(code=1008, reason="Missing token")
        return False
    try:
        decode_token(token)
    except Exception:
        await websocket.close(code=1008, reason="Invalid token")
        return False
    return True


async def _ws_endpoint(websocket: WebSocket, token: str, client_set: set,
                      send_fn, ping_interval: float = 1.0) -> None:
    """Generic WS handler: auth → loop (send payload + heartbeat drain)."""
    if not await _verify_ws_token(websocket, token):
        return
    await websocket.accept()
    client_set.add(websocket)
    try:
        while True:
            try:
                payload = send_fn()
            except Exception:
                payload = None
            if payload is not None:
                await websocket.send_json(payload)
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=ping_interval)
            except asyncio.TimeoutError:
                pass
    except WebSocketDisconnect:
        client_set.discard(websocket)


@app.websocket("/ws/packets")
async def ws_packets(websocket: WebSocket, token: str = Query("")):
    await _ws_endpoint(websocket, token, packet_clients,
                       send_fn=lambda: None, ping_interval=50)


@app.websocket("/ws/stats")
async def ws_stats(websocket: WebSocket, token: str = Query("")):
    def _stats_payload():
        eng = getattr(app.state, "engine", None)
        if eng and getattr(eng, "is_running", False):
            try:
                return {"type": "stats", "data": eng.get_status()}
            except Exception:
                pass
        return {"type": "stats", "data": dict(_EMPTY_STATUS)}
    await _ws_endpoint(websocket, token, stats_clients, send_fn=_stats_payload)


@app.websocket("/ws/services")
async def ws_services(websocket: WebSocket, token: str = Query("")):
    def _services_payload():
        try:
            return {"type": "services", "data": list_services_status()}
        except Exception:
            return {"type": "services", "data": []}
    await _ws_endpoint(websocket, token, services_clients, send_fn=_services_payload)


# ---------------------------------------------------------------------------
# Static frontend (built by `vite build` → web/dist). Registered LAST so
# /api and /ws routes (registered above) take precedence in Starlette's
# first-match route resolution. SPA fallback: any non-API GET that misses
# serves index.html so client-side routes like /dashboard resolve.
# ---------------------------------------------------------------------------

_STATIC_DIR = Path(__file__).parent / "web" / "dist"


if _STATIC_DIR.is_dir():
    app.mount("/assets", StaticFiles(directory=str(_STATIC_DIR / "assets")), name="assets")

    @app.get("/", include_in_schema=False)
    def _root_index():
        return FileResponse(str(_STATIC_DIR / "index.html"))

    @app.get("/{full_path:path}", include_in_schema=False)
    def _spa_fallback(full_path: str):
        candidate = _STATIC_DIR / full_path
        if candidate.is_file():
            return FileResponse(str(candidate))
        return FileResponse(str(_STATIC_DIR / "index.html"))
