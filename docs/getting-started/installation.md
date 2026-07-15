# Installation

**Tested on:** Ubuntu 22.04 / 24.04 LTS (x86-64)  
**Estimated setup time:** 45 – 90 minutes  
**Version:** v1.1.0 (main branch; see `CHANGELOG.md` for fixes since this tag)

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
git clone https://github.com/ntu168108/realtime-packet-sniff-v2.git
cd realtime-packet-sniff-v2
```

### 2.2 Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

> From this point on, **always activate the venv** before running Python commands:  
> `source /path/to/realtime-packet-sniff-v2/.venv/bin/activate`

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
| `scapy` | ==2.7.0 | Packet capture via libpcap |
| `kafka-python-ng` | 2.2.3 | Kafka producer / consumer |
| `clickhouse-driver` | 0.2.10 | Inserting data into ClickHouse |
| `pandas` | 2.3.3 | CSV processing, scoring |
| `numpy` | 2.2.6 | Vectorized scoring |
| `pyyaml` | 6.0.3 | Config file parsing |
| `pytest` | 9.1.1 | Running the integration test suite |

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

### 3.4 Raise the topic's max message size

> **Required** — Kafka's cluster-wide default `message.max.bytes` is **1 MiB**.
> A pcap segment blob (`segment_max_bytes`, default 64 MiB) is always larger
> than that, so without this step the producer fails every publish with
> `MessageSizeTooLargeError` even though its own `max_request_size` is already
> sized correctly. This is a **topic-level** config, not a producer setting —
> raising `max_request_size` alone does not fix it.

```bash
/opt/kafka/bin/kafka-configs.sh --bootstrap-server localhost:9092 \
    --entity-type topics --entity-name raw_pcap_segments \
    --alter --add-config max.message.bytes=104857600

# Verify
/opt/kafka/bin/kafka-configs.sh --bootstrap-server localhost:9092 \
    --entity-type topics --entity-name raw_pcap_segments --describe
```

> On a multi-broker cluster you would also raise `replica.fetch.max.bytes` on
> each broker (a static config — set it in `server.properties` and restart
> the broker, it cannot be changed dynamically). Skip this on the
> single-broker KRaft setup described here (`replication-factor=1` means
> there are no replica fetches).

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
    -o Dpkg::Options="--force-confold" \
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

## Quick Install (capture tool only)

If you only need the interactive capture tool (TUI / daemon / live NDJSON stream) without Kafka, ClickHouse, or Grafana:

```bash
# One-liner
curl -fsSL https://raw.githubusercontent.com/ntu168108/realtime-packet-sniff-v2/main/install.sh -o /tmp/install.sh && sudo bash /tmp/install.sh --verbose

# Or manually
git clone https://github.com/ntu168108/realtime-packet-sniff-v2.git
cd realtime-packet-sniff-v2
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

## Directory Reference

```
realtime-packet-sniff-v2/
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
├── tests/integration_tests/    # 52 automated tests
└── docs/
    ├── index.md                # English home page
    ├── getting-started/        # quickstart, installation, configuration
    ├── operations/             # deployment, architecture, troubleshooting
    └── vi/                     # Vietnamese translations
```
