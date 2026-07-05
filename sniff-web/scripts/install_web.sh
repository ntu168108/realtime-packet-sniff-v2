#!/bin/bash
# Idempotent installer for sniff-web.
# Usage: sudo bash sniff-web/scripts/install_web.sh
#
# What it does (8 steps — zero-touch, fresh install is ready to use after):
#   1. Install Python deps from sniff-web/requirements-web.txt
#   2. Install Node.js + npm (if missing) and build the React/Vite frontend
#   3. Grant setcap cap_net_admin,cap_net_raw to /usr/bin/python3
#      (so the capture engine can open raw sockets without running as root)
#   4. Install /etc/sudoers.d/sniff-web (allowlist for systemctl + 6 services)
#   5. Render sniff-web.service from the template, substitute REPO_DIR,
#      real username, and the site-packages path into PYTHONPATH
#   6. Generate $REPO_DIR/config.yaml from config.yaml.example with a real
#      bcrypt hash for the default password and a random JWT secret
#      (skipped if config.yaml already exists)
#   7. Prepare /var/lib/sniff-web (state) and /var/log/sniff-web (logs) +
#      install /etc/logrotate.d/sniff-web
#   8. daemon-reload + enable + restart sniff-web
set -euo pipefail

# Resolve repo root robustly regardless of CWD. We do this in two steps:
#   1. realpath on BASH_SOURCE[0] → absolute path of this script
#      (works whether the user invoked us as `bash sniff-web/scripts/install_web.sh`,
#       `sudo bash sniff-web/scripts/install_web.sh`, or with absolute path)
#   2. lùi 2 cấp từ script dir để ra repo root:
#      <repo>/sniff-web/scripts/install_web.sh  →  <repo>
SCRIPT_DIR="$(cd "$(dirname "$(realpath "${BASH_SOURCE[0]}")")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_DIR"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root (sudo bash $0)" >&2
    exit 1
fi

# Resolve the real (non-root) user that invoked sudo so the service and
# state directories don't end up owned by an arbitrary hard-coded user.
REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
if [[ "$REAL_USER" == "root" ]]; then
    echo "WARNING: running as root with no SUDO_USER; defaulting to 'tu'." >&2
    echo "         (install_web.sh will patch this on a normal 'sudo bash'.)" >&2
    REAL_USER="tu"
fi
REAL_GROUP="$(id -gn "$REAL_USER" 2>/dev/null || echo "$REAL_USER")"

echo "==> Install target user: ${REAL_USER}:${REAL_GROUP}"

# ----------------------------- [1/8] Python deps -----------------------------
echo "==> [1/8] Installing Python deps (sniff-web/requirements-web.txt)"
# Use --break-system-packages on Ubuntu 24.04 where PEP 668 blocks system pip.
# On Ubuntu 22.04 pip honours the flag silently (no-op).
PIP_EXTRA_ARGS=""
if python3 -m pip install --help 2>&1 | grep -q -- "--break-system-packages"; then
    PIP_EXTRA_ARGS="--break-system-packages"
fi
python3 -m pip install --quiet $PIP_EXTRA_ARGS \
    --ignore-installed \
    -r sniff-web/requirements-web.txt

# ----------------------------- [2/8] Node + frontend build -------------------
echo "==> [2/8] Installing Node deps + building frontend"

# Ensure node + npm are present. Most Ubuntu server images don't ship them.
if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
    echo "    node/npm not found; installing via apt..."
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        nodejs npm
fi

# Some distros (Ubuntu 22.04) ship an old node (v12) that vite >=5 won't run on.
NODE_MAJOR="$(node -e 'console.log(process.versions.node.split(".")[0])' 2>/dev/null || echo 0)"
if [[ "${NODE_MAJOR:-0}" -lt 18 ]]; then
    echo "    node ${NODE_MAJOR:-?}.x too old for vite >=5; installing NodeSource 20.x..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl ca-certificates
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nodejs
fi

cd "$REPO_DIR/sniff-web/web"
if [[ ! -d node_modules ]]; then
    npm install
fi
npm run build
# Fail loud if the build produced nothing — otherwise uvicorn will serve 404s.
if [[ ! -f dist/index.html ]]; then
    echo "ERROR: npm run build did not produce dist/index.html" >&2
    echo "       re-run with 'cd sniff-web/web && npm install && npm run build' to diagnose" >&2
    exit 1
fi
cd "$REPO_DIR"

# ----------------------------- [3/8] setcap on python3 -----------------------
echo "==> [3/8] Granting setcap cap_net_admin,cap_net_raw to python3"
PYTHON_BIN="$(command -v python3)"
if [[ -z "$PYTHON_BIN" ]]; then
    echo "ERROR: python3 not found" >&2
    exit 1
fi
# Resolve symlinks — on Debian/Ubuntu /usr/bin/python3 is usually a symlink to
# python3.X and setcap refuses to follow symlinks ("Invalid file"). Apply
# setcap to the real binary instead.
PYTHON_REAL="$(realpath "$PYTHON_BIN")"
setcap cap_net_admin,cap_net_raw+ep "$PYTHON_REAL"
echo "    setcap on $PYTHON_REAL OK (resolved from $PYTHON_BIN)"

# ----------------------------- [4/8] sudoers ---------------------------------
echo "==> [4/8] Installing sudoers rule"
SUDOERS_SRC="$REPO_DIR/sniff-web/deploy/sudoers/sniff-web"
SUDOERS_DEST="/etc/sudoers.d/sniff-web"
if ! visudo -c -f "$SUDOERS_SRC" >/dev/null 2>&1; then
    echo "ERROR: sudoers file failed validation" >&2
    visudo -c -f "$SUDOERS_SRC"
    exit 1
fi
# Patch the username in the sudoers file from 'tu' to the real user.
TMP_SUDOERS="$(mktemp)"
sed "s|^tu ALL=(root) NOPASSWD:|${REAL_USER} ALL=(root) NOPASSWD:|" \
    "$SUDOERS_SRC" > "$TMP_SUDOERS"
# Re-validate after substitution.
if ! visudo -c -f "$TMP_SUDOERS" >/dev/null 2>&1; then
    echo "ERROR: patched sudoers file failed validation" >&2
    visudo -c -f "$TMP_SUDOERS"
    rm -f "$TMP_SUDOERS"
    exit 1
fi
install -m 0440 -o root -g root "$TMP_SUDOERS" "$SUDOERS_DEST"
rm -f "$TMP_SUDOERS"
echo "    $SUDOERS_DEST installed (user=${REAL_USER})"

# ----------------------------- [5/8] systemd unit ----------------------------
echo "==> [5/8] Installing systemd unit"
UNIT_SRC="$REPO_DIR/sniff-web/deploy/systemd/sniff-web.service"
UNIT_DEST="/etc/systemd/system/sniff-web.service"
if [[ ! -f "$UNIT_SRC" ]]; then
    echo "ERROR: unit template $UNIT_SRC missing" >&2
    exit 1
fi
TMP_UNIT="$(mktemp)"
SITE_PKG="$(python3 -c 'import site; print(site.getusersitepackages())')"
sed \
    -e "s|/opt/realtime-packet-sniff|${REPO_DIR}|g" \
    -e "s|^User=tu|User=${REAL_USER}|" \
    -e "s|^Environment=PYTHONPATH=.*|Environment=PYTHONPATH=${SITE_PKG}:${REPO_DIR}|" \
    "$UNIT_SRC" > "$TMP_UNIT"
install -m 0644 -o root -g root "$TMP_UNIT" "$UNIT_DEST"
rm -f "$TMP_UNIT"
echo "    $UNIT_DEST installed (repo=${REPO_DIR}, user=${REAL_USER})"

# ----------------------------- [6/8] config.yaml (NEW) -----------------------
# Generate a real config.yaml from the example so the user can log in
# immediately. Skipped if config.yaml already exists (preserve user edits).
echo "==> [6/8] Generating config.yaml with real bcrypt hash + JWT secret"
CONFIG_DEST="$REPO_DIR/config.yaml"
CONFIG_EXAMPLE="$REPO_DIR/config.yaml.example"
GENERATED_PASSWORD="sniff"   # default; user can change via UI or /api/auth/change-password

if [[ -f "$CONFIG_DEST" ]]; then
    # Check if the existing file has a real bcrypt hash (not the placeholder).
    # If it does, leave it alone. If not (e.g. someone copied config.yaml.example
    # by hand), regenerate from the example.
    EXISTING_HASH="$(python3 -c "
import yaml
try:
    with open('$CONFIG_DEST') as f:
        c = yaml.safe_load(f) or {}
    print((c.get('web') or {}).get('password_hash', '') or '')
except Exception:
    print('')
" 2>/dev/null || true)"
    if [[ -n "$EXISTING_HASH" && "$EXISTING_HASH" != *REPLACE_WITH_REAL_BCRYPT_HASH* ]]; then
        echo "    config.yaml already exists with a real password_hash — keeping it"
        REGEN=0
    else
        echo "    config.yaml exists but password_hash is a placeholder — regenerating"
        REGEN=1
    fi
else
    echo "    no config.yaml yet — generating from example"
    REGEN=1
fi

if [[ "${REGEN:-0}" == "1" ]]; then
    # Always start from a clean copy of the example, then patch the two
    # secret fields. This avoids the duplicate-key issue in config.yaml.example
    # (where `web:` appears at two indentation levels) and keeps the rest of
    # the user's intended settings intact.
    cp "$CONFIG_EXAMPLE" "$CONFIG_DEST"
    PASSWORD="$GENERATED_PASSWORD" CONFIG="$CONFIG_DEST" python3 - <<'PYEOF'
import os, secrets, yaml, bcrypt
with open(os.environ["CONFIG"]) as f:
    cfg = yaml.safe_load(f) or {}
web = cfg.setdefault("web", {})
web["password_hash"] = bcrypt.hashpw(os.environ["PASSWORD"].encode(), bcrypt.gensalt()).decode()
web["jwt_secret"] = secrets.token_urlsafe(32)
with open(os.environ["CONFIG"], "w") as f:
    yaml.safe_dump(cfg, f, default_flow_style=False, sort_keys=False)
print("Generated config.yaml")
PYEOF
fi

# Lock down the file — it contains the bcrypt hash + JWT secret. Group/world
# read is unnecessary and slightly increases blast radius of any local compromise.
chown "${REAL_USER}:${REAL_GROUP}" "$CONFIG_DEST"
chmod 0640 "$CONFIG_DEST"
echo "    $CONFIG_DEST (chown ${REAL_USER}:${REAL_GROUP}, mode 0640)"

# ----------------------------- [7/8] state + log dirs + logrotate ------------
echo "==> [7/8] Preparing persistence dir + log dir + logrotate"
mkdir -p /var/lib/sniff-web /var/log/sniff-web
chown -R "${REAL_USER}:${REAL_GROUP}" /var/lib/sniff-web /var/log/sniff-web
chmod 0750 /var/lib/sniff-web /var/log/sniff-web

# Logrotate so the service log doesn't fill the disk.
# sniff-web writes to journald (StandardOutput=journal), but the installer and
# capture engine also write to /var/log/sniff-web/*.log when run by hand.
LOGROTATE_DEST="/etc/logrotate.d/sniff-web"
cat > "$LOGROTATE_DEST" <<'LOGROTATE_EOF'
/var/log/sniff-web/*.log {
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    create 0640 tu tu
    sharedscripts
}
LOGROTATE_EOF
# Replace the hard-coded 'tu' in the logrotate file with the real user.
sed -i "s|^    create 0640 tu tu|    create 0640 ${REAL_USER} ${REAL_GROUP}|" "$LOGROTATE_DEST"
chmod 0644 "$LOGROTATE_DEST"
echo "    /var/lib/sniff-web + /var/log/sniff-web ready, logrotate installed"

# ----------------------------- [8/8] enable + start --------------------------
echo "==> [8/8] Enabling + starting sniff-web"
systemctl daemon-reload
systemctl enable sniff-web
systemctl restart sniff-web

# Wait briefly for uvicorn to bind, then sanity-check.
sleep 2
if systemctl is-active --quiet sniff-web; then
    STATUS="RUNNING"
else
    STATUS="FAILED — check: journalctl -u sniff-web -n 50"
fi

echo ""
echo "==============================================="
echo "  sniff-web install: $STATUS"
echo "==============================================="
HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo "URL:      http://${HOST_IP:-localhost}:8000"
echo "Username: admin"
echo "Password: ${GENERATED_PASSWORD}  (CHANGE IMMEDIATELY in config.yaml)"
echo ""
echo "Verify it works:"
echo "  curl -sS -X POST http://localhost:8000/api/auth/login \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"username\":\"admin\",\"password\":\"sniff\"}' | python3 -m json.tool"
echo ""
echo "Change the password later (pick one):"
echo "  - via the UI:  Settings → Change password"
echo "  - via CLI:     python3 -c \"import bcrypt; print(bcrypt.hashpw(b'NEW', bcrypt.gensalt()).decode())\""
echo "                 then paste into $CONFIG_DEST under web.password_hash"
echo "                 and run: sudo systemctl restart sniff-web"
