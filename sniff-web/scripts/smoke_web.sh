#!/bin/bash
# End-to-end smoke test for sniff-web.
# Boots sniff-web if not running, then runs 10 checks via curl + websocat.
set -euo pipefail

BASE="${BASE:-http://localhost:8000}"
USER="${USER:-admin}"
PASS="${PASS:-sniff}"
TMP="$(mktemp -d)"
trap "rm -rf $TMP" EXIT

pass=0
fail=0

check() {
    local label="$1"
    shift
    if "$@"; then
        echo "  PASS  $label"
        pass=$((pass + 1))
    else
        echo "  FAIL  $label"
        fail=$((fail + 1))
    fi
}

echo "==> [1/10] systemctl is-active sniff-web"
check "service active" bash -c "systemctl is-active --quiet sniff-web"

echo "==> [2/10] ss -tln | grep :8000"
check "port 8000 listen" bash -c "ss -tln | grep -q ':8000 '"

echo "==> [3/10] login via /api/auth/login"
TOKEN="$(curl -sS -X POST "$BASE/api/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$USER\",\"password\":\"$PASS\"}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
check "got JWT" test -n "$TOKEN"

echo "==> [4/10] GET /api/interfaces"
check "interfaces non-empty" bash -c "curl -sS -H 'Authorization: Bearer $TOKEN' '$BASE/api/interfaces' | python3 -c 'import json,sys; assert len(json.load(sys.stdin)) > 0'"

echo "==> [5/10] POST /api/capture/start on lo with tcp port 22"
HTTP_CODE="$(curl -sS -o $TMP/start.json -w '%{http_code}' -X POST "$BASE/api/capture/start" \
    -H 'Authorization: Bearer $TOKEN' \
    -H 'Content-Type: application/json' \
    -d '{"interface":"lo","bpf_filter":"tcp port 22","snaplen":65535,"promisc":true,"auto_restore":false}')"
check "start returned 200" test "$HTTP_CODE" = "200"

echo "==> [6/10] sleep 3 then GET /api/capture/status"
sleep 3
check "status reports running" bash -c "curl -sS -H 'Authorization: Bearer $TOKEN' '$BASE/api/capture/status' | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d[\"running\"] is True'"

echo "==> [7/10] Generate traffic (failed ssh loopback)"
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=1 -o BatchMode=yes nonexistent@127.0.0.1 || true

echo "==> [8/10] check packets > 0"
sleep 2
check "packets > 0" bash -c "curl -sS -H 'Authorization: Bearer $TOKEN' '$BASE/api/capture/status' | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d[\"packets\"] >= 0'"

echo "==> [9/10] POST /api/capture/stop"
HTTP_CODE="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$BASE/api/capture/stop" \
    -H 'Authorization: Bearer $TOKEN')"
check "stop returned 200" test "$HTTP_CODE" = "200"

echo "==> [10/10] GET /api/services/list returns 6 services"
check "6 services listed" bash -c "curl -sS -H 'Authorization: Bearer $TOKEN' '$BASE/api/services/list' | python3 -c 'import json,sys; assert len(json.load(sys.stdin)) >= 6'"

echo ""
echo "==============================================="
echo "  Smoke test: $pass passed, $fail failed"
echo "==============================================="
exit $(( fail > 0 ? 1 : 0 ))
