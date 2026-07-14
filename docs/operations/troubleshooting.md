# Troubleshooting

---

## Step 11 — Common pitfalls

| Symptom | Root cause | Fix |
|---------|-----------|-----|
| `ModuleNotFoundError: No module named 'sniff-web.web_server'` | Old unit used hyphenated module name | Re-run `sudo bash sniff-web/scripts/install_web.sh` |
| `npm: command not found` | Old script didn't install Node | Re-run installer (new version auto-installs Node 18+) |
| `vite build` fails with "Node version too low" | Ubuntu 22.04 ships Node 12 | Re-run installer (auto-upgrades to NodeSource 20.x) |
| Service starts but UI returns 404 | Frontend build skipped/failed | Re-run installer (new version verifies `dist/index.html`) |
| `chown: invalid user: 'tu:tu'` | Hard-coded user (old bug) | Run via `sudo bash` so `$SUDO_USER` is set |
| Login fails with `admin/sniff` | `config.yaml` has placeholder bcrypt hash, OR `web:` is indented under `capture:` in your config | Re-run installer (auto-generates) — or move `web:` to top-level in your config.yaml |

---

## Step 11 — Capture sync troubleshooting

- If `POST /api/capture/start` returns `sniff_producer.restarted=false`, run
  `sudo -n systemctl restart sniff-producer` manually. If that prompts for a
  password, the sudoers allowlist is missing or stale — re-run
  `sudo bash sniff-web/scripts/install_web.sh` (Step 4 installs
  `/etc/sudoers.d/sniff-web`).
- If the capture engine runs but Kafka stays silent, check that the new
  interface still exists with `ip link show` and that `cap_net_admin` /
  `cap_net_raw` are set on `/usr/bin/python3` (Step 3 of the installer).

---

## Troubleshooting

### ❌ `sniff-producer` logs `[Error 10] MessageSizeTooLargeError`

Kafka's default `message.max.bytes` (1 MiB) is smaller than a pcap segment
blob (`segment_max_bytes`, default 64 MiB). The producer's own
`max_request_size` is already sized correctly — this is a **topic-level**
broker setting that also needs raising:

```bash
/opt/kafka/bin/kafka-configs.sh --bootstrap-server localhost:9092 \
    --entity-type topics --entity-name raw_pcap_segments \
    --alter --add-config max.message.bytes=104857600

sudo systemctl restart sniff-producer
```

See [Installation Step 3.4](../getting-started/installation.md#34-raise-the-topics-max-message-size).

### ❌ Web GUI Dashboard shows the exact same number on every `flows_<family>` card

Expected if you're on a checkout before 2026-07-14: all 7 per-family tables
share the same underlying flow set (see
[architecture.md § Per-family tables](architecture.md#per-family-tables)), so
a plain `count()` per table is always identical and looks like fake/uniform
data. Fixed by querying `WHERE is_attack = 1` per family instead — `git pull`
(or check `sniff-web/web_server.py::_clickhouse_counts_safe`) if you still see
identical numbers. Full explanation in `sniff-web/docs/WEB_GUI.md`.

### ❌ Segments reach `ec-consumer` but `pipeline_runs.status` is always `failed`

Check `sudo journalctl -u ec-consumer -n 50` for the actual traceback — this
symptom has several unrelated root causes, all fixed as of the version
matching this doc:

- `NameError: name 'setup_logging' is not defined` (extractor.py) — outdated
  checkout predating the fix; `git pull` / re-clone.
- `NameError: name 'wanted_fields' is not defined` (zeek_handler.py) — same.
- `AttributeError: 'int' object has no attribute 'fillna'` (add_features.py) —
  same.
- `ModuleNotFoundError: No module named 'family_filter'` (auto_pipeline.py) —
  same.
- `auto_pipeline.py` reports `PIPELINE HOAN TAT` (success) but ClickHouse
  never gets rows and `ec-consumer` still marks the segment `failed` — the
  consumer was looking for the 7 per-family CSVs in the wrong directory
  (`CSV/CSV_Full_feature/` instead of each family's own
  `CSV/Filter_<Family>_feature/`). Fixed in `integration/ec_consumer.py`;
  re-clone/pull if you still see this.
- `ValueError: operands could not be broadcast together ... (N,) (17,)` from
  `dos_classifier.py` — `np.char.startswith()` was called with a tuple of
  multicast prefixes, which it doesn't support (unlike Python's
  `str.startswith()`). This one is caught and only logged as a warning
  (`DoS Classifier khong chay duoc`, non-fatal), but it left `predicted_class`
  empty for every row. Fixed by OR-ing per-prefix masks in a loop; re-clone/
  pull if you still see the warning.

### ❌ `sniff-producer` cannot connect to Kafka

```bash
sudo systemctl status kafka
ss -tlnp | grep 9092
/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list
```

### ❌ `ec-consumer` — ClickHouse connection refused

```bash
sudo systemctl status clickhouse-server
ss -tlnp | grep 9000
clickhouse-client --query "SELECT 1"
```

### ❌ Pipeline reports "argus not found" or "zeek not found"

```bash
which argus zeek
# If missing, add to PATH:
export PATH=$PATH:/opt/zeek/bin:/usr/local/bin
sudo ln -sf /opt/zeek/bin/zeek /usr/local/bin/zeek
```

### ❌ `dos_classifier.py` import error

```bash
cd Extraction-and-classification/MODULE_PHANLOAI
python3 -c "import dos_classifier; print('OK')"
# If pandas is missing:
pip install pandas numpy
```

### ❌ Grafana shows no data

```bash
# 1. Check the data source is provisioned
curl -s -u admin:admin http://localhost:3000/api/datasources | python3 -m json.tool

# 2. Check ClickHouse has rows
clickhouse-client --query "SELECT count() FROM network_ids.flows_all"

# 3. Re-check provisioning files and restart
ls /etc/grafana/provisioning/datasources/
sudo systemctl restart grafana-server
```

### ❌ Reset Kafka completely

```bash
# WARNING: this deletes ALL Kafka data
sudo systemctl stop kafka
sudo rm -rf /var/lib/kafka-logs
KAFKA_CLUSTER_ID=$(/opt/kafka/bin/kafka-storage.sh random-uuid)
/opt/kafka/bin/kafka-storage.sh format \
    -t $KAFKA_CLUSTER_ID \
    -c /opt/kafka/config/server.properties

sudo systemctl start kafka
/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 \
    --create --topic raw_pcap_segments --partitions 1 --replication-factor 1
```

> - `random-uuid` — generates a unique cluster ID
> - `format` — initialises the storage directory with that cluster ID (one-time setup only)

### ❌ Purge old ClickHouse data manually

```bash
# Delete data older than 7 days from all family tables
for family in dos exploits fuzzers generic analysis reconnaissance shellcode; do
    clickhouse-client --query \
        "ALTER TABLE network_ids.flows_${family} DELETE WHERE ts < now() - INTERVAL 7 DAY"
done

# Or change the TTL permanently (default is 14 days)
for family in dos exploits fuzzers generic analysis reconnaissance shellcode; do
    clickhouse-client --query \
        "ALTER TABLE network_ids.flows_${family} MODIFY TTL toDateTime(ts) + INTERVAL 7 DAY"
done
```

### ❌ ClickHouse install hangs at "Set password for default user"

The `clickhouse-server` postinst script pops an **ncurses dialog** unless
`DEBIAN_FRONTEND=noninteractive` and `CLICKHOUSE_PASSWORD` are set.

```bash
# Option 1 — reinstall without the prompt
export CLICKHOUSE_PASSWORD=ClickHousePass
sudo DEBIAN_FRONTEND=noninteractive apt-get install --reinstall -y \
    -o Dpkg::Options="--force-confdef" \
    -o Dpkg::Options="--force-confold" \
    clickhouse-server

# Option 2 — if ClickHouse is already installed, add the password by hand
sudo sed -i 's|<password></password>|<password>ClickHousePass</password>|' \
    /etc/clickhouse-server/users.xml
sudo systemctl restart clickhouse-server
```

### ❌ `sniff-web.service` fails with `ModuleNotFoundError: No module named 'sniff_web'`

The old unit file used `sniff-web.web_server:app` — Python can't import a module
with a hyphen in its name. The new template uses `web_server:app` (because
`WorkingDirectory` is already `sniff-web/`).

```bash
# Check current ExecStart
cat /etc/systemd/system/sniff-web.service | grep ExecStart

# If you still see 'sniff-web.web_server:app', re-run the installer
sudo bash sniff-web/scripts/install_web.sh

# Or patch by hand
sudo sed -i 's|uvicorn sniff-web.web_server:app|uvicorn web_server:app|' \
    /etc/systemd/system/sniff-web.service
sudo systemctl daemon-reload
sudo systemctl restart sniff-web
```

### ❌ `npm: command not found` during `install_web.sh`

```bash
# Install Node.js + npm via apt
if ! command -v node >/dev/null 2>&1; then
    sudo apt-get install -y nodejs npm
fi

# If apt's Node.js is too old (<18, e.g. on Ubuntu 22.04), use NodeSource 20.x
if [[ "$(node -e 'console.log(process.versions.node.split(".")[0])')" -lt 18 ]]; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash -
    sudo apt-get install -y nodejs
fi

# Re-run the installer
sudo bash sniff-web/scripts/install_web.sh
```

### ❌ `chown: invalid user: 'tu:tu'` during `install_web.sh`

Old installer hard-coded the user. Run via `sudo bash` (so `$SUDO_USER` is set):

```bash
sudo bash sniff-web/scripts/install_web.sh

# Or patch by hand if the user really isn't `tu`
REAL_USER=$(whoami)
sudo sed -i "s|^chown -R tu:tu|chown -R ${REAL_USER}:${REAL_USER}|" \
    sniff-web/scripts/install_web.sh
sudo sed -i "s|^User=tu|User=${REAL_USER}|" \
    sniff-web/deploy/systemd/sniff-web.service
sudo sed -i "s|^tu ALL=(root) NOPASSWD:|${REAL_USER} ALL=(root) NOPASSWD:|" \
    sniff-web/deploy/sudoers/sniff-web
sudo bash sniff-web/scripts/install_web.sh
```