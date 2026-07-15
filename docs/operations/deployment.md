# Deployment

---

## Step 7 — Configure the Pipeline

### 7.1 Create `config.yaml`

```bash
cp config.yaml.example config.yaml
```

Edit the following keys:

```yaml
capture:
  interface: ens33          # ← your actual interface name
  bpf: "not port 22"        # exclude SSH to reduce noise
  keep_local_pcap: false    # set to true to keep pcap files after processing

kafka:
  bootstrap: localhost:9092
  topic: raw_pcap_segments
  segment_seconds: 60       # flush every 60 seconds …
  segment_max_bytes: 67108864  # … or at 64 MiB, whichever comes first

clickhouse:
  host: localhost
  port: 9000
  database: network_ids
  batch_size: 10000         # rows per INSERT batch
```

### 7.2 Check the Extraction-and-classification path

The pipeline auto-discovers `Extraction-and-classification/` relative to the repo root in most layouts. If you clone to a non-standard location, set:

```bash
export NB15_EC=/path/to/Extraction-and-classification
```

> **⚠ Bắt buộc — xóa CSV mẫu khỏi thư mục runtime.** Nếu thư mục
> `CSV/CSV_Full_feature/` còn các file `sample_*_features.csv`, EC consumer sẽ
> **tái dùng chúng cho MỌI segment** thay vì trích xuất pcap thật → toàn bộ flow
> trong ClickHouse là dữ liệu giả (`10.0.0.5→10.0.0.9`, feature=0). Dọn trước khi chạy:
> ```bash
> find "$NB15_EC/CSV/CSV_Full_feature" -name 'sample_*_features.csv' -delete
> find "$NB15_EC/CSV/CSV_Full_feature" -name 'sample_raw.csv' -delete
> ```

---

## Step 8 — Initialise the ClickHouse Schema

```bash
clickhouse-client --multiquery < sql/clickhouse_init.sql

# Verify tables
clickhouse-client --query "SHOW TABLES FROM network_ids"
```

Expected output:

```
flows_all
flows_analysis
flows_dos
flows_exploits
flows_fuzzers
flows_generic
flows_reconnaissance
flows_shellcode
pipeline_runs
```

**Schema notes:**
- `flows_<family>` use `ReplacingMergeTree` — re-processing the same segment never duplicates rows (idempotent by design).
- `flows_all` is a `Merge` view across all 7 family tables — use it for cross-family queries.
- `pipeline_runs` is a `MergeTree` audit table — one row per consumed segment.
- Default TTL: **14 days** — rows older than that are automatically dropped.

---

## Step 9 — Install systemd Services

### 9.1 Copy the unit files

```bash
sudo cp deploy/systemd/kafka.service           /etc/systemd/system/
sudo cp deploy/systemd/sniff-producer.service  /etc/systemd/system/
sudo cp deploy/systemd/ec-consumer.service     /etc/systemd/system/
```

### 9.2 Patch paths and user to match your environment

```bash
REPO_DIR=$(pwd)

sudo sed -i "s|/home/tu/realtime-packet-sniff|${REPO_DIR}|g" \
    /etc/systemd/system/kafka.service \
    /etc/systemd/system/sniff-producer.service \
    /etc/systemd/system/ec-consumer.service

sudo sed -i "s|User=tu|User=${USER}|g" \
    /etc/systemd/system/kafka.service \
    /etc/systemd/system/ec-consumer.service

# Add PYTHONPATH so systemd finds packages installed with --break-system-packages
PYPATH=$(python3 -c "import site; print(site.getusersitepackages())")
sudo sed -i "s|Environment=PYTHONPATH=.*|Environment=PYTHONPATH=${PYPATH}|g" \
    /etc/systemd/system/sniff-producer.service \
    /etc/systemd/system/ec-consumer.service
```

### 9.3 Unit file reference

**`kafka.service`** — single-broker KRaft (`User=tu` here is a placeholder
patched to your own user by 9.2 above; without that patch the service fails
to start on any machine where the login user isn't literally `tu`):
```ini
[Unit]
Description=Apache Kafka (KRaft)
After=network.target
[Service]
User=tu
Environment=KAFKA_HEAP_OPTS=-Xmx1g -Xms512m
ExecStart=/opt/kafka/bin/kafka-server-start.sh /opt/kafka/config/server.properties
ExecStop=/opt/kafka/bin/kafka-server-stop.sh
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
```

**`sniff-producer.service`** — capture engine → Kafka (needs root for raw sockets):
```ini
[Unit]
Description=SNIFF Packet Producer
After=network.target kafka.service
Requires=kafka.service

[Service]
WorkingDirectory=/home/tu/realtime-packet-sniff
ExecStart=/usr/bin/python3 -m integration.run_producer
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**`ec-consumer.service`** — Kafka → Argus+Zeek → ClickHouse:
```ini
[Unit]
Description=SNIFF EC Consumer (Extract + Classify)
After=network.target kafka.service clickhouse-server.service
Requires=kafka.service

[Service]
User=tu
WorkingDirectory=/home/tu/realtime-packet-sniff
ExecStart=/usr/bin/python3 -m integration.ec_consumer
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### 9.4 Reload systemd and enable services

```bash
sudo systemctl daemon-reload
sudo systemctl enable kafka sniff-producer ec-consumer
```

---

## Step 10 — Start & Verify

### 10.1 Start services in order

```bash
# Kafka must come first
sudo systemctl start kafka
sleep 5
sudo systemctl status kafka

# Then the producer
sudo systemctl start sniff-producer
sleep 3
sudo systemctl status sniff-producer

# Finally the consumer (ClickHouse must already be up)
sudo systemctl start ec-consumer
sudo systemctl status ec-consumer
```

### 10.2 Check the full stack

```bash
sudo systemctl is-active kafka sniff-producer ec-consumer clickhouse-server grafana-server
# Expected: active active active active active

# Follow ec-consumer logs live
sudo journalctl -u ec-consumer -f
```

### 10.3 Send test traffic

```bash
# Capture 30 seconds of live traffic
sudo tcpdump -i ens33 -w /tmp/test.pcap -G 30 -W 1

# Or replay an existing pcap
sudo tcpreplay -i ens33 --mbps=10 /path/to/sample.pcap
```

After ~90 seconds (60 s segment window + processing time), check for data:

```bash
# Kafka: how many messages have been published
/opt/kafka/bin/kafka-run-class.sh kafka.tools.GetOffsetShell \
    --broker-list localhost:9092 --topic raw_pcap_segments

# ClickHouse: total rows ingested
clickhouse-client --query "SELECT count() FROM network_ids.flows_all"

# Breakdown by attack family
clickhouse-client --query \
    "SELECT attack_family, count() AS cnt
     FROM network_ids.flows_all
     WHERE is_attack = 1
     GROUP BY attack_family
     ORDER BY cnt DESC"

# Pipeline health — last 5 runs
clickhouse-client --query \
    "SELECT started_at, status, total_flows, duration_sec, error_msg
     FROM network_ids.pipeline_runs
     ORDER BY started_at DESC LIMIT 5"
```

**Nghiệm thu chống "flow giả"** — 3 truy vấn sau phải cho kết quả đúng, nếu không là pipeline đang nạp dữ liệu mẫu chứ không phải traffic thật:

```bash
# (1) KHÔNG còn dữ liệu mẫu synthetic → kỳ vọng 0
clickhouse-client --query \
    "SELECT count() FROM network_ids.flows_all WHERE srcip='10.0.0.5' AND dstip='10.0.0.9'"

# (2) Có flow feature THẬT (khác 0) → kỳ vọng > 0
clickhouse-client --query \
    "SELECT count() FROM network_ids.flows_all WHERE spkts > 0 OR sbytes > 0"

# (3) Không còn nhãn rỗng → kỳ vọng 0
clickhouse-client --query \
    "SELECT count() FROM network_ids.flows_all WHERE predicted_class = ''"
```

### 10.4 Open Grafana

Navigate to `http://<server-ip>:3000` → **Dashboards → IDS → "SNIFF IDS Pipeline"**.  
If the dashboard is empty, wait another minute and click **Refresh**.

---

## Step 11 — Web GUI (sniff-web) [Optional]

> Optional companion to the IDS pipeline. Provides a browser-based control panel
> for the capture engine and all 5 systemd services.
>
> 🎯 **Zero-touch install:** After running `install_web.sh`, open
> `http://<server>:8000` and log in with `admin` / `sniff` — no extra commands
> needed.
>
> **Fixes from earlier versions:**
> 1. `install_web.sh` hard-coded the user `tu` — fails on any other account.
> 2. It ran `npm install` without checking that Node.js exists — fails on
>    stock Ubuntu servers.
> 3. The unit file used module `sniff-web.web_server:app` — Python refuses
>    to import modules whose name contains `-`, so the service crashed with
>    `ModuleNotFoundError` immediately.
> 4. `PYTHONPATH` in the unit was hard-coded to `/home/tu/.local/...` —
>    valid on exactly one machine.
> 5. Frontend build was never verified — service could start with a 404-only UI.
> 6. **`config.yaml.example` had `web:` indented under `capture:`** — YAML parser
>    treats it as `capture.web` (nested), so `load_web_config` returns defaults
>    only and every login returns 401 even with a correct hash.
> 7. **Installer did not generate `config.yaml`** — user had to run a bcrypt
>    snippet manually after install. Fresh install was broken by default.

### 11.1 Prerequisites

| Component | Minimum version | Reason |
|-----------|-----------------|-------|
| Python | 3.10+ | installed in Step 2 |
| Node.js | **18+** (vite ≥5 needs ≥18, Ubuntu 22.04 ships 12) | build the React frontend |
| npm | 9+ | bundled with Node 18+ |
| Free disk | 800 MB | node_modules (~500 MB) + frontend build |

The new `install_web.sh` auto-installs Node.js if missing (or upgrades to
NodeSource 20.x if apt's version is too old) and verifies the build produced
`dist/index.html`.

### 11.2 Install

```bash
sudo bash sniff-web/scripts/install_web.sh
```

This script runs 8 idempotent steps:

1. **Python deps** — installs `sniff-web/requirements-web.txt` (fastapi, uvicorn,
   python-multipart, pyjwt, bcrypt, clickhouse-driver, kafka-python-ng,
   websockets, psutil, httpx2 for tests). Uses
   `--break-system-packages` on Ubuntu 24.04 and `--ignore-installed` to
   coexist with apt-installed PyJWT.
2. **Node + frontend** — installs Node.js if missing, then `npm install` +
   `npm run build`. Fails loudly if `dist/index.html` is missing.
3. **setcap** — `cap_net_admin,cap_net_raw+ep` on `/usr/bin/python3` (follows
   the symlink so the capability lands on `python3.12`).
4. **sudoers** — installs `/etc/sudoers.d/sniff-web`. Patches `tu` →
   `${SUDO_USER}`; re-validates with `visudo -c` before copying.
5. **systemd unit** — renders `sniff-web.service`. Patches repo path,
   `User`, and `PYTHONPATH` (taken from `site.getusersitepackages()`).
   `ExecStart=... uvicorn web_server:app ...` (the hyphenated
   `sniff-web.web_server:app` is fixed).
6. **config.yaml** — if missing, copies `config.yaml.example` and patches
   `web.password_hash` (bcrypt of default password `sniff`) +
   `web.jwt_secret` (random 32-byte URL-safe token). If `config.yaml` already
   exists with a real hash, leaves it alone (preserves user customisations).
   Chown to the real user, mode `0640`.
7. **state + log dirs + logrotate** — `/var/lib/sniff-web/` (state) and
   `/var/log/sniff-web/` (logs), chown real user, mode `0750`. Installs
   `/etc/logrotate.d/sniff-web` (rotate daily, keep 7 days, compress).
8. **enable + start** — `systemctl enable + restart sniff-web`, waits 2 s,
   reports RUNNING / FAILED.

Final output:

```
===============================================
  sniff-web install: RUNNING
===============================================
URL:      http://192.168.1.93:8000
Username: admin
Password: sniff  (CHANGE IMMEDIATELY in config.yaml)
```

### 11.3 Open the UI

Navigate to `http://<server>:8000` — default credentials: `admin` / `sniff`.

**Change the password** (pick one):

- via UI: Settings → Change password
- via CLI:
  ```bash
  NEW_HASH=$(python3 -c "import bcrypt; print(bcrypt.hashpw(b'NEW', bcrypt.gensalt()).decode())")
  python3 -c "
  import yaml
  with open('config.yaml') as f:
      cfg = yaml.safe_load(f) or {}
  cfg.setdefault('web', {})['password_hash'] = '$NEW_HASH'
  with open('config.yaml', 'w') as f:
      yaml.safe_dump(cfg, f, default_flow_style=False, sort_keys=False)
  "
  sudo systemctl restart sniff-web
  ```

**Auto-restore after reboot:** click Start with the "auto-restore on reboot"
checkbox. The last capture config persists to
`/var/lib/sniff-web/last_capture.json`; the service lifespan reads it on boot.

See [`sniff-web/docs/WEB_GUI.md`](https://github.com/ntu168108/realtime-packet-sniff-v2/blob/main/sniff-web/docs/WEB_GUI.md) for the full API and UI tour.

### 11.5 Capture interface sync (v0.4.0)

Starting with v0.4.0 the `/capture` page keeps the UI capture engine and the
background `sniff-producer` service in lockstep. Clicking **Start** does all
of the following in one shot:

1. Applies the new interface / BPF filter to the in-process capture engine.
2. Writes `capture.interface` and `capture.bpf_filter` back to `config.yaml`.
3. Runs `sudo systemctl restart sniff-producer` (covered by the
   `/etc/sudoers.d/sniff-web` allowlist installed by `install_web.sh`).

**Verify it's working:**

```bash
# 1. The config was updated
grep -A1 '^capture:' /var/lib/sniff-web/config.yaml | head -4

# 2. The producer picked up the new interface
sudo journalctl -u sniff-producer -n 20 --no-pager | grep -i interface

# 3. The API reports a successful sync
curl -s -b /tmp/cookie.txt http://localhost:8000/api/capture/status | jq .sniff_producer
```

---

## Day-to-Day Operations

### Start / stop / restart

```bash
sudo systemctl start   kafka sniff-producer ec-consumer
sudo systemctl stop    ec-consumer sniff-producer kafka
sudo systemctl restart ec-consumer   # after a code change
```

### View logs

```bash
sudo journalctl -u ec-consumer -f                            # live tail
sudo journalctl -u ec-consumer --no-pager | grep -E "ERROR|FAILED|segment="
sudo journalctl -u sniff-producer -n 50 --no-pager
```

### Useful ClickHouse queries

```sql
-- Attack distribution by family
SELECT attack_family, count() AS c
FROM network_ids.flows_all
WHERE is_attack = 1
GROUP BY attack_family ORDER BY c DESC;

-- Top 10 attacker IPs
SELECT srcip, count() AS c
FROM network_ids.flows_all
WHERE is_attack = 1
GROUP BY srcip ORDER BY c DESC LIMIT 10;

-- Attack timeline (per minute)
SELECT toStartOfMinute(ts) AS t, attack_family, count() AS c
FROM network_ids.flows_all
WHERE is_attack = 1
GROUP BY t, attack_family ORDER BY t;

-- Pipeline health — last 10 runs
SELECT started_at, status, total_flows, duration_sec, error_msg
FROM network_ids.pipeline_runs
ORDER BY started_at DESC LIMIT 10;
```

### Run the classifier manually

```bash
cd Extraction-and-classification

# Run the full 4-step pipeline on a pcap file
python3 MODULE_AUTO/auto_pipeline.py /path/to/capture.pcap

# Run the DoS classifier standalone
python3 MODULE_PHANLOAI/dos_classifier.py \
    --csv CSV/CSV_Full_feature/capture_dos_features.csv \
    --skip-filter

# Run all unit tests
python3 -m pytest MODULE_PHANLOAI/tests/ -v
```