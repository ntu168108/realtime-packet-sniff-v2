# Self-Deployment Guide — realtime-packet-sniff IDS

> Step-by-step instructions to install and run the full IDS stack on a fresh Ubuntu server,  
> from dependency setup through to Grafana displaying live attack data.

**Tested on:** Ubuntu 22.04 / 24.04 LTS (x86-64)  
**Estimated setup time:** 45 – 90 minutes  
**Version:** v0.4.0

---

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Architecture Overview](#2-architecture-overview)
3. [Step 1 — Prepare the System](#step-1--prepare-the-system)
4. [Step 2 — Python & Clone Repo](#step-2--python--clone-repo)
5. [Step 3 — Apache Kafka (KRaft)](#step-3--apache-kafka-kraft)
6. [Step 4 — ClickHouse](#step-4--clickhouse)
7. [Step 5 — Grafana](#step-5--grafana)
8. [Step 6 — Argus & Zeek](#step-6--argus--zeek)
9. [Step 7 — Configure the Pipeline](#step-7--configure-the-pipeline)
10. [Step 8 — Initialise the ClickHouse Schema](#step-8--initialise-the-clickhouse-schema)
11. [Step 9 — Install systemd Services](#step-9--install-systemd-services)
12. [Step 10 — Start & Verify](#step-10--start--verify)
13. [Quick Install (capture tool only)](#quick-install-capture-tool-only)
14. [Day-to-Day Operations](#day-to-day-operations)
15. [Troubleshooting](#troubleshooting)

---

## 1. System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8 GB+ |
| Disk | 20 GB | 50 GB+ (Kafka + ClickHouse long-term storage) |
| OS | Ubuntu 22.04 LTS | Ubuntu 24.04 LTS |
| Python | 3.8+ | 3.10+ |
| Java | 11+ (for Kafka) | 17 |
| Network interface | 1 NIC | 2 NICs (1 mgmt + 1 SPAN/mirror) |

> **Note:** Root or `sudo` access is required throughout.  
> The default interface in this guide is `ens33` — replace it with your actual interface name.

---

## 2. Architecture Overview

The system has **5 components** running in a chain:

```
NIC (ens33)
    │ libpcap / scapy
    ▼
[sniff-producer]          ← Python, systemd service (root)
    │ ~60 s pcap blob
    ▼
[Kafka topic: raw_pcap_segments]   ← Apache Kafka KRaft
    │
    ▼
[ec-consumer]             ← Python, systemd service (non-root)
    │ Argus + Zeek → UNSW-NB15 feature extraction
    │ auto_pipeline.py → 7 filters + DoS classifier
    ▼
[ClickHouse]              ← stores classified flow records
    │
    ▼
[Grafana]                 ← real-time attack visualisation
```

**Detailed data flow:**
1. `sniff-producer` captures packets from the NIC, buffers ~60 seconds, packs them into a blob and publishes to Kafka.
2. `ec-consumer` reads the blob from Kafka and writes a temporary `.pcap` file to `/dev/shm`.
3. `auto_pipeline.py` processes the `.pcap` through 4 stages:
   - **Step 1/4:** `extractor.py` (Argus + Zeek) → raw UNSW-NB15 feature CSV.
   - **Step 2/4:** `add_features.py` → adds 49 DoS-specific columns.
   - **Step 3/4:** 7 per-family filters → 7 labelled CSV files.
   - **Step 4/4:** `dos_classifier.py` → detailed SYN / UDP / ICMP Flood scoring.
4. `ClickHouseSink` writes results to 7 `flows_<family>` tables + the `pipeline_runs` audit table.
5. Grafana reads ClickHouse and renders the dashboard.

**v0.4.0 — Web ↔ Producer sync:** the `sniff-web` UI no longer just runs the
in-process capture engine. When the operator changes the interface or BPF
filter on the `/capture` page and clicks **Start**, `sniff-web` also writes
those values to `config.yaml` and runs `sudo systemctl restart sniff-producer`,
so the Kafka/ClickHouse pipeline always points at the same NIC as the UI.

---

## Step 1 — Prepare the System

### 1.1 Update the system and install base tools

```bash
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y \
    curl wget git unzip \
    build-essential \
    libpcap-dev \
    tcpdump tcpreplay \
    python3 python3-pip \
    openjdk-17-jre-headless
```

> - `curl wget git unzip` — download tools and source control
> - `build-essential` — C/C++ compiler toolchain (required by some Python packages)
> - `libpcap-dev` — raw packet capture library, required by scapy
> - `tcpdump tcpreplay` — traffic inspection and replay tools
> - `python3 python3-pip` — Python runtime and pip
> - `openjdk-17-jre-headless` — Java runtime required by Kafka

### 1.2 Identify your network interface

```bash
ip link show
# Note the name of the interface you want to sniff on, e.g. ens33, eth0, enp3s0
```

> If you are running on a VM (VMware / VirtualBox), set the target NIC to  
> **Promiscuous Mode** so it can capture all traffic on the segment, not just its own.

---

## Step 2 — Python & Clone Repo

### 2.1 Clone the repository

```bash
git clone https://github.com/ntu168108/realtime-packet-sniff.git
cd realtime-packet-sniff
```

### 2.2 Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

> From this point on, **always activate the venv** before running Python commands:  
> `source /path/to/realtime-packet-sniff/.venv/bin/activate`

### 2.3 Install Python dependencies

```bash
# Capture tool (scapy only)
pip install -r requirements.txt

# Full IDS pipeline (Kafka, ClickHouse, pandas, …)
pip install -r requirements-integration.txt
```

**Key packages:**

| Package | Version | Used for |
|---------|---------|----------|
| `scapy` | ≥2.5.0 | Packet capture via libpcap |
| `kafka-python-ng` | 2.2.3 | Kafka producer / consumer |
| `clickhouse-driver` | 0.2.9 | Inserting data into ClickHouse |
| `pandas` | 2.2.2 | CSV processing, scoring |
| `numpy` | 1.26.4 | Vectorized scoring |
| `pyyaml` | 6.0.1 | Config file parsing |

### 2.3 Verify the installation

```bash
python3 -c "from core import capture; from cli import app; print('core & cli OK')"
python3 -c "from integration import ec_consumer, clickhouse_sink; print('integration OK')"
```

---

## Step 3 — Apache Kafka (KRaft)

> This setup uses Kafka in **KRaft mode** — no ZooKeeper required.

### 3.1 Download and extract Kafka

```bash
KAFKA_VERSION="4.3.1"
wget https://downloads.apache.org/kafka/${KAFKA_VERSION}/kafka_2.13-${KAFKA_VERSION}.tgz
sudo tar -xzf kafka_2.13-${KAFKA_VERSION}.tgz -C /opt/
sudo ln -sf /opt/kafka_2.13-${KAFKA_VERSION} /opt/kafka
```

> - `wget ...tgz` — download the latest Kafka release
> - `tar -xzf ... -C /opt/` — extract into `/opt/`
> - `ln -sf` — create a `/opt/kafka` symlink pointing at the versioned directory (makes future upgrades easier)

### 3.2 Apply the Kafka configuration

```bash
sudo cp deploy/kafka/server.properties /opt/kafka/config/server.properties
```

> Copies the pre-configured KRaft `server.properties` from the repo over Kafka's default config.

Key settings in `server.properties`:

```properties
process.roles=broker,controller       # KRaft mode — no ZooKeeper
node.id=1
controller.quorum.voters=1@localhost:9093
listeners=PLAINTEXT://localhost:9092,CONTROLLER://localhost:9093
advertised.listeners=PLAINTEXT://localhost:9092
log.dirs=/var/lib/kafka-logs
log.retention.ms=3600000              # keep data for 1 hour (adjust as needed)
log.retention.bytes=2147483648        # or 2 GiB per partition
```

### 3.3 Format storage and create the topic

```bash
sudo mkdir -p /var/lib/kafka-logs /opt/kafka/logs
sudo chown $USER:$USER /var/lib/kafka-logs /opt/kafka/logs

# Generate a cluster ID and format storage
KAFKA_CLUSTER_ID=$(/opt/kafka/bin/kafka-storage.sh random-uuid)
/opt/kafka/bin/kafka-storage.sh format \
    -t $KAFKA_CLUSTER_ID \
    -c /opt/kafka/config/server.properties


# Start Kafka temporarily to create the topic
/opt/kafka/bin/kafka-server-start.sh /opt/kafka/config/server.properties &
sleep 10

# Create the topic
/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 \
    --create --topic raw_pcap_segments \
    --partitions 1 \
    --replication-factor 1

# Verify
/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list

# Stop Kafka — systemd will manage it from now on
/opt/kafka/bin/kafka-server-stop.sh
```

> - `random-uuid` — generates a unique cluster ID
> - `format` — initialises the storage directory with that cluster ID (one-time setup only)

---

## Step 4 — ClickHouse

> **Fix from earlier version:** the old guide used the RPM GPG-key path
> (`/rpm/lts/repodata/repomd.xml.key`) for Debian/Ubuntu. ClickHouse signs both
> RPM and deb repos with the same key, so the URL *worked* but was semantically
> wrong and gave a confusing error on some Ubuntu mirrors. We now use the
> deb-flavoured path and add a fallback.
>
> On Ubuntu 24.04 the `clickhouse-server` postinst script pops an **ncurses
> dialog** asking for the default password — this blocks automation. We pre-set
> `CLICKHOUSE_PASSWORD` and use `DEBIAN_FRONTEND=noninteractive`.

### 4.1 Install via apt

```bash
# 1. Prereqs + set default password via env so the postinst script is silent.
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    apt-transport-https ca-certificates dirmngr gnupg

# 2. Add the ClickHouse GPG signing key.
#    Prefer the /deb/ path (matches the docs at clickhouse.com/docs/install/debian_ubuntu)
#    with a /rpm/ fallback that still returns 200 because the key is shared.
sudo mkdir -p /usr/share/keyrings
curl -fsSL 'https://packages.clickhouse.com/deb/lts/release.key' 2>/dev/null \
    | sudo gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg 2>/dev/null \
    || curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' \
        | sudo gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg

# 3. Add the apt repo. `arch=...` makes apt reject packages for the wrong arch.
ARCH=$(dpkg --print-architecture)
echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg arch=${ARCH}] \
    https://packages.clickhouse.com/deb stable main" | \
    sudo tee /etc/apt/sources.list.d/clickhouse.list

# 4. Install. CLICKHOUSE_PASSWORD stops the ncurses password prompt.
export CLICKHOUSE_DB=default
export CLICKHOUSE_USER=default
export CLICKHOUSE_PASSWORD=ClickHousePass
export CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    -o Dpkg::Options::="--force-confdef" \
    -o Dpkg::Options::="--force-confold" \
    clickhouse-server clickhouse-client
```

> - `apt-transport-https ca-certificates dirmngr gnupg` — enables apt to fetch over HTTPS
> - `gpg --dearmor` — stores the signing key for apt's `signed-by=` directive
> - `tee /etc/apt/sources.list.d/clickhouse.list` — registers the apt repository
> - `CLICKHOUSE_PASSWORD` — required to silence the interactive postinst prompt
> - `--force-confdef --force-confold` — never prompts on config file updates
> - `clickhouse-server` — the main database service
> - `clickhouse-client` — CLI for running queries and verifying the install

### 4.2 Start ClickHouse

```bash
sudo systemctl enable clickhouse-server
sudo systemctl start clickhouse-server
sudo systemctl status clickhouse-server
```

### 4.3 Verify

```bash
clickhouse-client --password 'ClickHousePass' --query "SELECT version()"
# Expected: a version string such as 24.3.1.2672

# (Optional) Save the password so you don't type it again:
echo "CLICKHOUSE_PASSWORD=ClickHousePass" | sudo tee /etc/clickhouse-client.env
```

---

## Step 5 — Grafana

### 5.1 Install via apt

```bash
sudo apt-get install -y apt-transport-https software-properties-common
wget -q -O - https://apt.grafana.com/gpg.key | \
    sudo gpg --dearmor -o /usr/share/keyrings/grafana.key

echo "deb [signed-by=/usr/share/keyrings/grafana.key] \
    https://apt.grafana.com stable main" | \
    sudo tee /etc/apt/sources.list.d/grafana.list

sudo apt-get update
sudo apt-get install -y grafana
```

> - `gpg --dearmor` — adds the Grafana GPG signing key
> - `tee /etc/apt/sources.list.d/grafana.list` — registers the Grafana apt repository

### 5.2 Install the ClickHouse data source plugin

```bash
sudo grafana cli plugins install grafana-clickhouse-datasource
```

### 5.3 Provision the data source and dashboard automatically

```bash
sudo cp deploy/grafana/datasource.yaml  /etc/grafana/provisioning/datasources/
sudo cp deploy/grafana/dashboards.yaml  /etc/grafana/provisioning/dashboards/
sudo cp deploy/grafana/dashboard.json   /var/lib/grafana/dashboards/


sudo systemctl enable grafana-server
sudo systemctl start grafana-server
```

> - `datasource.yaml` — auto-configures the ClickHouse connection on Grafana startup
> - `dashboards.yaml` — tells Grafana where to find the dashboard files
> - `dashboard.json` — the IDS pipeline dashboard

> **Access Grafana:** `http://<server-ip>:3000`  
> Default credentials: `admin` / `admin` (change on first login)  
> Dashboard: **IDS → "SNIFF IDS Pipeline"**

---

## Step 6 — Argus & Zeek

> **Fixes from earlier version:**
> 1. The old Argus source URL `https://openargus.org/download/argus-3.0.8.tar.gz`
>    returns **404** — openargus.org migrated to `qosient.com/argus/`. New URL:
>    `https://qosient.com/argus/src/argus-3.0.8.tar.gz`.
> 2. The script `https://raw.githubusercontent.com/zeek/zeek-docs/master/scripts/zeek-setup.sh`
>    no longer exists. The official recommendation (from zeek.org/get-zeek/) is to
>    add the **OpenSUSE Build Service** apt repo `security:zeek`.
> 3. `argus-server/argus-client` and `zeek` packages are **not in the default
>    Ubuntu 22.04/24.04 apt repos** — must build from source or use OBS.
> 4. Several packages (especially `libpcap-dev`, `bison`, `flex`, `cmake` for
>    Argus) prompt for input or show ncurses dialogs. Always pass
>    `DEBIAN_FRONTEND=noninteractive`.

### 6.1 Install Argus

**Option 1 — Build from source (works on every Ubuntu):**

```bash
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential flex bison libpcap-dev libreadline-dev \
    libsasl2-dev libssl-dev libcurl4-openssl-dev pkg-config

# New URL (qosient.com — openargus.org moved domains)
ARGUS_VERSION="3.0.8"
cd /tmp
curl -fSL "https://qosient.com/argus/src/argus-${ARGUS_VERSION}.tar.gz" -o argus.tar.gz
tar xzf argus.tar.gz && cd "argus-${ARGUS_VERSION}"
./configure --prefix=/usr/local
make -j"$(nproc)"
sudo make install
sudo ldconfig

# Symlink so `argus` and `ra` are on the default PATH
sudo ln -sf /usr/local/bin/argus /usr/local/bin/argus-server
sudo ln -sf /usr/local/bin/ra    /usr/local/bin/argus-client
```

**Option 2 — Try apt first (Ubuntu 24.04+ may have them):**

```bash
if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y argus-server argus-client 2>/dev/null; then
    echo "Argus installed from apt"
else
    echo "Argus not in apt — falling back to Option 1"
fi
```

**Verify:**

```bash
argus -V 2>&1 | head -3
ra -V    2>&1 | head -3
which argus ra
```

> - `argus` (also called `argus-server`) — generates flow records from pcap files
> - `ra` (also called `argus-client`) — tool for reading/querying flow records
> - If `./configure` reports missing libraries, install the matching apt package and re-run.

### 6.2 Install Zeek

**Recommended — via the OpenSUSE Build Service repo:**

```bash
# 1. Add the OBS GPG key
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key \
    | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/zeek-obs.gpg

# (For Ubuntu 22.04, replace the URL below with .../xUbuntu_22.04/)

# 2. Register the repo
echo "deb [signed-by=/etc/apt/trusted.gpg.d/zeek-obs.gpg] \
    http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /" | \
    sudo tee /etc/apt/sources.list.d/zeek.list

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y zeek

# 3. Zeek binaries land in /opt/zeek/bin/. Symlink so `which` finds them.
echo 'export PATH=/opt/zeek/bin:$PATH' | sudo tee /etc/profile.d/zeek.sh >/dev/null
sudo chmod +x /etc/profile.d/zeek.sh
sudo ln -sf /opt/zeek/bin/zeek    /usr/local/bin/zeek
sudo ln -sf /opt/zeek/bin/zeekctl /usr/local/bin/zeekctl
sudo ln -sf /opt/zeek/bin/zkg     /usr/local/bin/zkg 2>/dev/null || true
```

> - OpenSUSE Build Service (`security:zeek`) is the **officially recommended**
>   install method per zeek.org/get-zeek/. Do **not** use the old github
>   setup script — it's been removed.
> - Repos are available for Ubuntu 22.04, 24.04 and Debian 11, 12.
> - Zeek binaries live in `/opt/zeek/bin/` by default, hence the symlinks.

**Fallback — official binary tarball (if OBS is unreachable):**

```bash
ZEEK_VERSION=$(curl -fsSL https://api.github.com/repos/zeek/zeek/releases/latest \
    | grep tag_name | head -1 | cut -d'"' -f4)
cd /tmp
curl -fSL "https://download.zeek.org/zeek-${ZEEK_VERSION}.linux-x86_64.tar.gz" -o zeek.tar.gz
sudo tar -xzf zeek.tar.gz -C /opt/
sudo mv /opt/zeek-* /opt/zeek 2>/dev/null || true
sudo ln -sf /opt/zeek/bin/zeek    /usr/local/bin/zeek
sudo ln -sf /opt/zeek/bin/zeekctl /usr/local/bin/zeekctl
```

### 6.3 Confirm both tools are reachable

```bash
# All three binaries must resolve
which argus ra zeek

# Confirm versions
argus -V 2>&1 | head -2
zeek --version
```

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

sudo sed -i "s|User=tu|User=${USER}|g" /etc/systemd/system/ec-consumer.service

# Thêm PYTHONPATH để systemd tìm thấy packages đã cài với --break-system-packages
PYPATH=$(python3 -c "import site; print(site.getusersitepackages())")
sudo sed -i "s|Environment=PYTHONPATH=.*|Environment=PYTHONPATH=${PYPATH}|g" \
    /etc/systemd/system/sniff-producer.service \
    /etc/systemd/system/ec-consumer.service
```

### 9.3 Unit file reference

**`kafka.service`** — single-broker KRaft:
```ini
[Unit]
Description=Apache Kafka (KRaft)
After=network.target

[Service]
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

### 10.4 Open Grafana

Navigate to `http://<server-ip>:3000` → **Dashboards → IDS → "SNIFF IDS Pipeline"**.  
If the dashboard is empty, wait another minute and click **Refresh**.

---

## Quick Install (capture tool only)

If you only need the interactive capture tool (TUI / daemon / live NDJSON stream) without Kafka, ClickHouse, or Grafana:

```bash
# One-liner
curl -fsSL https://raw.githubusercontent.com/ntu168108/realtime-packet-sniff/main/install.sh -o /tmp/install.sh && sudo bash /tmp/install.sh --verbose

# Or manually
git clone https://github.com/ntu168108/realtime-packet-sniff.git
cd realtime-packet-sniff
pip install --break-system-packages .

# Usage
sudo sniff                          # interactive menu
sudo sniff -i ens33                 # capture on ens33
sudo sniff -i ens33 --live | jq .   # live NDJSON stream
sudo sniff -i ens33 -d              # background daemon
sudo sniff --status                 # daemon status
sudo sniff --stop                   # stop the daemon
```

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
|-----------|-----------------|--------|
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
   pyjwt, bcrypt, clickhouse-driver, kafka-python-ng, psutil). Uses
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

See `sniff-web/docs/WEB_GUI.md` for the full API and UI tour.

### 11.4 Common pitfalls

| Symptom | Root cause | Fix |
|---------|-----------|-----|
| `ModuleNotFoundError: No module named 'sniff-web.web_server'` | Old unit used hyphenated module name | Re-run `sudo bash sniff-web/scripts/install_web.sh` |
| `npm: command not found` | Old script didn't install Node | Re-run installer (new version auto-installs Node 18+) |
| `vite build` fails with "Node version too low" | Ubuntu 22.04 ships Node 12 | Re-run installer (auto-upgrades to NodeSource 20.x) |
| Service starts but UI returns 404 | Frontend build skipped/failed | Re-run installer (new version verifies `dist/index.html`) |
| `chown: invalid user: 'tu:tu'` | Hard-coded user (old bug) | Run via `sudo bash` so `$SUDO_USER` is set |
| Login fails with `admin/sniff` | `config.yaml` has placeholder bcrypt hash, OR `web:` is indented under `capture:` in your config | Re-run installer (auto-generates) — or move `web:` to top-level in your config.yaml |

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

**Troubleshooting:**

- If `POST /api/capture/start` returns `sniff_producer.restarted=false`, run
  `sudo -n systemctl restart sniff-producer` manually. If that prompts for a
  password, the sudoers allowlist is missing or stale — re-run
  `sudo bash sniff-web/scripts/install_web.sh` (Step 4 installs
  `/etc/sudoers.d/sniff-web`).
- If the capture engine runs but Kafka stays silent, check that the new
  interface still exists with `ip link show` and that `cap_net_admin` /
  `cap_net_raw` are set on `/usr/bin/python3` (Step 3 of the installer).

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

---

## Troubleshooting

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
    -o Dpkg::Options::="--force-confdef" \
    -o Dpkg::Options::="--force-confold" \
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

---

## Directory Reference

```
realtime-packet-sniff/
├── sniff.py                    # Capture tool CLI entry point
├── install.sh                  # One-liner installer (capture tool)
├── config.yaml.example         # Config template → copy to config.yaml
├── requirements.txt            # Capture tool deps
├── requirements-integration.txt # Full IDS pipeline deps
├── core/                       # Capture engine (capture, decoder, buffer, …)
├── cli/                        # TUI, daemon, live printer
├── ui/                         # Colour helpers for the TUI
├── modules/                    # Plugin analyzers (port scan, DNS tunnel, beaconing)
├── integration/                # Kafka producer/consumer, ClickHouse sink, schema
├── Extraction-and-classification/
│   ├── MODULE_TRICHXUAT/       # Argus + Zeek → UNSW-NB15 feature extraction
│   ├── MODULE_PHANLOAI/        # 7 filters + dos_classifier + signatures
│   └── MODULE_AUTO/            # Orchestrator: auto_pipeline.py
├── deploy/
│   ├── systemd/                # Unit files: kafka, sniff-producer, ec-consumer
│   ├── kafka/                  # server.properties (KRaft)
│   └── grafana/                # Datasource + dashboard provisioning
├── sql/
│   └── clickhouse_init.sql     # DDL: 7 flows_<family> + flows_all + pipeline_runs
├── tests/integration_tests/    # 36 automated tests
└── docs/
    ├── ARCHITECTURE.md         # Detailed architecture, blob format, CH schema
    └── OPERATIONS.md           # Operations runbook, queries, retention
```

---

*This guide covers v0.4.0 — see the [Releases page](https://github.com/ntu168108/realtime-packet-sniff/releases) for the latest changes.*
