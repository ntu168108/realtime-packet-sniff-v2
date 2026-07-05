# Hướng dẫn tự triển khai — realtime-packet-sniff IDS

> Hướng dẫn từng bước để cài đặt và vận hành toàn bộ hệ thống IDS trên một máy chủ Ubuntu mới,  
> từ việc cài phụ thuộc cho đến khi Grafana hiển thị dữ liệu tấn công mạng thời gian thực.

**Hệ điều hành được kiểm thử:** Ubuntu 22.04 / 24.04 LTS (x86-64)  
**Thời gian cài đặt ước tính:** 45 – 90 phút  
**Phiên bản:** v0.3.0

---

## Mục lục

1. [Yêu cầu hệ thống](#1-yêu-cầu-hệ-thống)
2. [Tổng quan kiến trúc](#2-tổng-quan-kiến-trúc)
3. [Bước 1 — Chuẩn bị hệ thống](#bước-1--chuẩn-bị-hệ-thống)
4. [Bước 2 — Cài Python & clone repo](#bước-2--cài-python--clone-repo)
5. [Bước 3 — Cài Apache Kafka (KRaft)](#bước-3--cài-apache-kafka-kraft)
6. [Bước 4 — Cài ClickHouse](#bước-4--cài-clickhouse)
7. [Bước 5 — Cài Grafana](#bước-5--cài-grafana)
8. [Bước 6 — Cài Argus & Zeek](#bước-6--cài-argus--zeek)
9. [Bước 7 — Cấu hình pipeline](#bước-7--cấu-hình-pipeline)
10. [Bước 8 — Khởi tạo schema ClickHouse](#bước-8--khởi-tạo-schema-clickhouse)
11. [Bước 9 — Cài systemd services](#bước-9--cài-systemd-services)
12. [Bước 10 — Khởi động & kiểm tra](#bước-10--khởi-động--kiểm-tra)
13. [Bước 11 — Cài Web GUI (sniff-web)](#bước-11--cài-web-gui-sniff-web)
14. [Cài đặt nhanh (capture tool đơn thuần)](#cài-đặt-nhanh-capture-tool-đơn-thuần)
15. [Vận hành hàng ngày](#vận-hành-hàng-ngày)
16. [Xử lý sự cố thường gặp](#xử-lý-sự-cố-thường-gặp)

---

## 1. Yêu cầu hệ thống

| Thành phần | Tối thiểu | Khuyến nghị |
|-----------|----------|-------------|
| CPU | 2 nhân | 4+ nhân |
| RAM | 4 GB | 8 GB+ |
| Ổ cứng | 20 GB | 50 GB+ (Kafka + ClickHouse lưu dữ liệu lâu dài) |
| Hệ điều hành | Ubuntu 22.04 LTS | Ubuntu 24.04 LTS |
| Python | 3.8+ | 3.10+ |
| Java | 11+ (cho Kafka) | 17 |
| Network interface | 1 NIC | 2 NIC (1 quản trị + 1 SPAN/mirror) |

> **Lưu ý:** Cần quyền `root` hoặc `sudo` cho toàn bộ quá trình cài đặt.  
> Tên interface mặc định trong hướng dẫn là `ens33` — thay bằng interface thực tế của bạn.

---

## 2. Tổng quan kiến trúc

Hệ thống gồm **5 thành phần** chạy chuỗi nhau:

```
NIC (ens33)
    │ libpcap / scapy
    ▼
[sniff-producer]          ← Python, chạy dưới systemd (root)
    │ ~60s pcap blob
    ▼
[Kafka topic: raw_pcap_segments]   ← Apache Kafka KRaft
    │
    ▼
[ec-consumer]             ← Python, chạy dưới systemd (user thường)
    │ Argus + Zeek → trích xuất đặc trưng UNSW-NB15
    │ auto_pipeline.py → 7 filter + DoS classifier
    ▼
[ClickHouse]              ← database lưu flows đã phân loại
    │
    ▼
[Grafana]                 ← dashboard trực quan hóa tấn công
```

**Luồng dữ liệu chi tiết:**
1. `sniff-producer` bắt gói tin từ NIC, gom ~60 giây, đóng gói thành blob → đẩy lên Kafka.
2. `ec-consumer` đọc blob từ Kafka, giải nén ra file `.pcap` tạm trong `/dev/shm`.
3. `auto_pipeline.py` xử lý file `.pcap` qua 4 bước:
   - **Bước 1/4:** `extractor.py` (Argus + Zeek) → trích đặc trưng UNSW-NB15 ra CSV thô.
   - **Bước 2/4:** `add_features.py` → bổ sung 49 cột đặc trưng DoS.
   - **Bước 3/4:** 7 filter theo họ tấn công → 7 file CSV phân loại riêng.
   - **Bước 4/4:** `dos_classifier.py` → phân loại chi tiết SYN / UDP / ICMP Flood.
4. `ClickHouseSink` ghi kết quả vào 7 bảng `flows_<family>` + bảng audit `pipeline_runs`.
5. Grafana đọc ClickHouse và hiển thị dashboard.

---

## Bước 1 — Chuẩn bị hệ thống

### 1.1 Cập nhật hệ thống và cài công cụ cơ bản

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

> - `curl wget git unzip` — công cụ tải file và quản lý source code
> - `build-essential` — compiler C/C++ (cần để build một số package)
> - `libpcap-dev` — thư viện bắt gói tin, scapy cần để hoạt động
> - `tcpdump tcpreplay` — công cụ kiểm tra và replay traffic
> - `python3 python3-pip` — Python runtime và pip
> - `openjdk-17-jre-headless` — Java runtime cho Kafka

### 1.2 Kiểm tra interface mạng

```bash
ip link show
# Ghi lại tên interface bạn muốn bắt gói tin, ví dụ: ens33, eth0, enp3s0
```

> Nếu dùng máy ảo (VMware/VirtualBox), nên thêm interface ở chế độ **Promiscuous Mode**  
> để bắt được traffic của cả mạng, không chỉ của máy ảo đó.

---

## Bước 2 — Cài Python & clone repo

### 2.1 Clone repository

```bash
git clone https://github.com/ntu168108/realtime-packet-sniff.git
cd realtime-packet-sniff
```

### 2.2 Cài các phụ thuộc Python

```bash
pip install --break-system-packages -r requirements.txt
pip install --break-system-packages -r requirements-integration.txt
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
```

> - `requirements.txt` — scapy và capture tool
> - `requirements-integration.txt` — Kafka, ClickHouse, pandas, ...
> - `--break-system-packages` — bắt buộc trên Ubuntu 24.04
> - `export PATH=...` — thêm `~/.local/bin` vào PATH để dùng được `scapy`, `pytest` trực tiếp

**Danh sách packages chính:**

| Package | Phiên bản | Dùng để |
|---------|-----------|---------|
| `scapy` | ≥2.5.0 | Bắt gói tin qua libpcap |
| `kafka-python-ng` | 2.2.3 | Kafka producer/consumer |
| `clickhouse-driver` | 0.2.9 | Ghi dữ liệu vào ClickHouse |
| `pandas` | 2.2.2 | Xử lý CSV, tính điểm phân loại |
| `numpy` | 1.26.4 | Vectorized scoring |
| `pyyaml` | 6.0.1 | Đọc file cấu hình |

### 2.3 Kiểm tra cài đặt

```bash
python3 -c "from core import capture; from cli import app; print('core & cli OK')"
python3 -c "from integration import ec_consumer, clickhouse_sink; print('integration OK')"
```

---

## Bước 3 — Cài Apache Kafka (KRaft)

> Kafka dùng chế độ **KRaft** (không cần ZooKeeper).

### 3.1 Tải và giải nén Kafka

```bash
KAFKA_VERSION="4.3.1"
wget https://downloads.apache.org/kafka/${KAFKA_VERSION}/kafka_2.13-${KAFKA_VERSION}.tgz
sudo tar -xzf kafka_2.13-${KAFKA_VERSION}.tgz -C /opt/
sudo ln -sf /opt/kafka_2.13-${KAFKA_VERSION} /opt/kafka
```

> - `wget ...tgz` — tải bản Kafka mới nhất về
> - `tar -xzf ... -C /opt/` — giải nén vào `/opt/`
> - `ln -sf` — tạo symlink `/opt/kafka` trỏ vào thư mục vừa giải nén, dễ nâng cấp sau này

### 3.2 Cấu hình Kafka KRaft

```bash
# Sao chép file cấu hình từ repo
sudo cp deploy/kafka/server.properties /opt/kafka/config/server.properties
```

> Lệnh này lấy file cấu hình có sẵn trong repo (đã chỉnh sẵn cho KRaft) ghi đè lên file mặc định của Kafka.

Nội dung quan trọng trong `server.properties`:

```properties
# Chế độ KRaft — không cần ZooKeeper
process.roles=broker,controller
node.id=1
controller.quorum.voters=1@localhost:9093

# Địa chỉ lắng nghe
listeners=PLAINTEXT://localhost:9092,CONTROLLER://localhost:9093
advertised.listeners=PLAINTEXT://localhost:9092

# Nơi lưu dữ liệu Kafka
log.dirs=/var/lib/kafka-logs

# Giữ dữ liệu 1 giờ (tùy chỉnh nếu cần)
log.retention.ms=3600000
log.retention.bytes=2147483648
```

### 3.3 Khởi tạo cluster và tạo topic

```bash
# Tạo thư mục lưu trữ
sudo mkdir -p /var/lib/kafka-logs /opt/kafka/logs
sudo chown $USER:$USER /var/lib/kafka-logs /opt/kafka/logs

# Tạo cluster ID và format storage
KAFKA_CLUSTER_ID=$(/opt/kafka/bin/kafka-storage.sh random-uuid)
/opt/kafka/bin/kafka-storage.sh format \
    -t $KAFKA_CLUSTER_ID \
    -c /opt/kafka/config/server.properties


# Khởi động Kafka thủ công để tạo topic
/opt/kafka/bin/kafka-server-start.sh /opt/kafka/config/server.properties &
sleep 10

# Tạo topic nhận pcap segments
/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 \
    --create --topic raw_pcap_segments \
    --partitions 1 \
    --replication-factor 1

# Kiểm tra topic đã tạo thành công
/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list

# Dừng Kafka tạm (systemd sẽ quản lý sau)
/opt/kafka/bin/kafka-server-stop.sh
```

> - `random-uuid` — tạo ID duy nhất cho cluster Kafka
> - `format` — khởi tạo thư mục lưu trữ với cluster ID đó (chỉ cần làm 1 lần)

---

## Bước 4 — Cài ClickHouse

> **Lỗi đã sửa:** URL GPG key trong phiên bản cũ nằm ở đường dẫn `/rpm/` (cho RedHat)
> gây nhầm lẫn. ClickHouse dùng chung một signing key cho cả deb và rpm, đường dẫn
> mới đúng ngữ nghĩa hơn và ClickHouse cũng ghi rõ trong docs chính thức. Ngoài ra
> `clickhouse-server` ở Ubuntu 24.04 có hỏi password mặc định trong dialog ncurses —
> phải đặt trước qua env var và `DEBIAN_FRONTEND=noninteractive` để cài không bị treo.

### 4.1 Cài ClickHouse qua apt

```bash
# Cài trước prereqs + đặt password mặc định cho user `default`
# để package post-install script không bị treo ở dialog ncurses.
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    apt-transport-https ca-certificates dirmngr gnupg

# Thêm ClickHouse GPG key (dùng đường dẫn /deb/ cho hệ thống Debian/Ubuntu,
# key này cũng được ClickHouse ghi trong docs chính thức tại clickhouse.com/docs/install/debian_ubuntu).
# (Đường dẫn /rpm/lts/... vẫn hoạt động nhưng không nhất quán — phiên bản cũ đã
#  dùng sai URL này và gây lỗi "key not found" trên một số bản Ubuntu.)
sudo mkdir -p /usr/share/keyrings
curl -fsSL 'https://packages.clickhouse.com/deb/lts/release.key' 2>/dev/null \
    | sudo gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg 2>/dev/null \
    || curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' \
        | sudo gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg

# Repo deb (component 'main' trỏ vào dists/stable/main — cấu trúc thực tế của repo)
ARCH=$(dpkg --print-architecture)
echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg arch=${ARCH}] \
    https://packages.clickhouse.com/deb stable main" | \
    sudo tee /etc/apt/sources.list.d/clickhouse.list

# Pre-set default user password để tránh dialog tương tác.
# Đổi 'ClickHousePass' thành mật khẩu thật của bạn.
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

> - `apt-transport-https ca-certificates dirmngr gnupg` — prereqs cần thiết
> - `CLICKHOUSE_PASSWORD` — đặt password trước để postinst script không hỏi
> - `--force-confdef --force-confold` — không hỏi khi ghi đè config cũ
> - **Quan trọng:** key `/deb/lts/release.key` có thể trả 404 trên một số mirror —
>   lệnh trên đã có fallback dùng URL `/rpm/...` (vẫn trả 200, key là chung cho cả hai repo).
> - `clickhouse-server` — service database chính
> - `clickhouse-client` — CLI để query và kiểm tra

### 4.2 Khởi động ClickHouse

```bash
sudo systemctl enable clickhouse-server
sudo systemctl start clickhouse-server
sudo systemctl status clickhouse-server
```

### 4.3 Kiểm tra kết nối

```bash
clickhouse-client --password 'ClickHousePass' --query "SELECT version()"
# Kết quả mong đợi: số phiên bản như 24.3.1.2672

# (Tuỳ chọn) lưu password để không phải gõ lại:
echo "CLICKHOUSE_PASSWORD=ClickHousePass" | sudo tee /etc/clickhouse-client.env
# rồi thêm vào ~/.bashrc: alias clickhouse-client='clickhouse-client --password "$(cat /etc/clickhouse-client.env | cut -d= -f2)"'
```

---

## Bước 5 — Cài Grafana

### 5.1 Cài Grafana qua apt

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

> - `gpg --dearmor` — thêm GPG key xác thực package Grafana
> - `tee /etc/apt/sources.list.d/grafana.list` — thêm repo Grafana vào apt

### 5.2 Cài plugin ClickHouse cho Grafana

```bash
sudo grafana cli plugins install grafana-clickhouse-datasource
```

### 5.3 Cấu hình datasource và dashboard tự động

```bash
# Sao chép file provisioning từ repo
sudo cp deploy/grafana/datasource.yaml  /etc/grafana/provisioning/datasources/
sudo cp deploy/grafana/dashboards.yaml  /etc/grafana/provisioning/dashboards/
sudo cp deploy/grafana/dashboard.json   /var/lib/grafana/dashboards/


sudo systemctl enable grafana-server
sudo systemctl start grafana-server
```

> - `datasource.yaml` — tự động cấu hình kết nối tới ClickHouse khi Grafana khởi động
> - `dashboards.yaml` — chỉ cho Grafana biết tìm dashboard ở đâu
> - `dashboard.json` — file dashboard hiển thị dữ liệu IDS pipeline

> **Truy cập Grafana:** `http://<IP-máy-chủ>:3000`  
> Tài khoản mặc định: `admin` / `admin` (đổi ngay lần đầu đăng nhập)  
> Dashboard: **IDS → "SNIFF IDS Pipeline"**

---

## Bước 6 — Cài Argus & Zeek

> **Lỗi đã sửa (phiên bản cũ):**
> - URL Argus source cũ `https://openargus.org/download/argus-3.0.8.tar.gz` trả **404**.
>   OpenArgus đã chuyển sang `qosient.com/argus/` — URL mới là
>   `https://qosient.com/argus/src/argus-3.0.8.tar.gz`.
> - Script `https://raw.githubusercontent.com/zeek/zeek-docs/master/scripts/zeek-setup.sh`
>   không tồn tại nữa. Cách chính thức là thêm apt repo **OpenSUSE Build Service**
>   (`security:zeek`) mà Zeek team khuyến nghị tại zeek.org/get-zeek/.
> - Lệnh `apt-get install -y argus-server argus-client` và `zeek` không có sẵn
>   trong repo mặc định của Ubuntu 22.04/24.04 — phải build from source hoặc dùng OBS.
> - Một số package (đặc biệt libpcap-dev, bison, flex, cmake khi build Argus) hỏi
>   xác nhận hoặc hiển thị ncurses dialog. Cần `DEBIAN_FRONTEND=noninteractive`.

### 6.1 Cài Argus

**Cách 1 — Build từ source (khuyến nghị, hoạt động trên mọi Ubuntu):**

```bash
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential flex bison libpcap-dev libreadline-dev \
    libsasl2-dev libssl-dev libcurl4-openssl-dev pkg-config

# URL mới (qosient.com — openargus.org đã chuyển domain)
ARGUS_VERSION="3.0.8"
cd /tmp
curl -fSL "https://qosient.com/argus/src/argus-${ARGUS_VERSION}.tar.gz" -o argus.tar.gz
tar xzf argus.tar.gz && cd "argus-${ARGUS_VERSION}"
./configure --prefix=/usr/local
make -j"$(nproc)"
sudo make install
sudo ldconfig

# Symlink để 'argus' và 'ra' nằm trong PATH mặc định
sudo ln -sf /usr/local/bin/argus /usr/local/bin/argus-server
sudo ln -sf /usr/local/bin/ra    /usr/local/bin/argus-client
```

**Cách 2 — Thử apt (Ubuntu 24.04+ có thể đã có):**

```bash
if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y argus-server argus-client 2>/dev/null; then
    echo "Argus cài thành công từ apt"
else
    echo "Argus không có trong apt repo — chuyển sang build from source (Cách 1)"
    # Chạy lại Cách 1 ở trên
fi
```

**Kiểm tra:**

```bash
argus -V 2>&1 | head -3
ra -V    2>&1 | head -3
which argus ra
```

> - `argus` (còn gọi là `argus-server`) — service tạo flow record từ pcap
> - `ra` (còn gọi là `argus-client`) — tool đọc và query flow record
> - Nếu lệnh `./configure` báo thiếu thư viện, cài thêm gói tương ứng rồi chạy lại.

### 6.2 Cài Zeek

**Cách chính thức (khuyến nghị) — qua OpenSUSE Build Service:**

```bash
# Cài GPG key cho OBS
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key \
    | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/zeek-obs.gpg

# (Tuỳ chọn) Nếu bạn dùng Ubuntu 22.04 thay vì 24.04, đổi URL sau:
#   https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/

# Thêm repo vào apt
echo "deb [signed-by=/etc/apt/trusted.gpg.d/zeek-obs.gpg] \
    http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /" | \
    sudo tee /etc/apt/sources.list.d/zeek.list

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y zeek

# Sau khi cài, Zeek ở /opt/zeek/bin/. Thêm vào PATH + symlink:
echo 'export PATH=/opt/zeek/bin:$PATH' | sudo tee /etc/profile.d/zeek.sh >/dev/null
sudo chmod +x /etc/profile.d/zeek.sh
sudo ln -sf /opt/zeek/bin/zeek    /usr/local/bin/zeek
sudo ln -sf /opt/zeek/bin/zeekctl /usr/local/bin/zeekctl
sudo ln -sf /opt/zeek/bin/zkg     /usr/local/bin/zkg 2>/dev/null || true
```

> - OpenSUSE Build Service (`security:zeek`) là cách Zeek team khuyến nghị chính thức
>   trên zeek.org/get-zeek/ — KHÔNG dùng script github cũ (đã bị xoá).
> - Repo có sẵn cho Ubuntu 22.04, 24.04 và Debian 11, 12.
> - Zeek CLI mặc định ở `/opt/zeek/bin/`, vì vậy cần symlink để tìm được qua `which`.

**Cách thay thế — nếu OBS không dùng được (firewall, mirror chặn):**

```bash
# Download binary tarball chính thức từ download.zeek.org
ZEEK_VERSION=$(curl -fsSL https://api.github.com/repos/zeek/zeek/releases/latest \
    | grep tag_name | head -1 | cut -d'"' -f4)
cd /tmp
curl -fSL "https://download.zeek.org/zeek-${ZEEK_VERSION}.linux-x86_64.tar.gz" -o zeek.tar.gz
sudo tar -xzf zeek.tar.gz -C /opt/
sudo mv /opt/zeek-* /opt/zeek 2>/dev/null || true
sudo ln -sf /opt/zeek/bin/zeek    /usr/local/bin/zeek
sudo ln -sf /opt/zeek/bin/zeekctl /usr/local/bin/zeekctl
```

### 6.3 Kiểm tra cả hai đã hoạt động

```bash
# Phải thấy path của cả 3 binary
which argus ra zeek

# Confirm version
argus -V 2>&1 | head -2
zeek --version
```

---

## Bước 7 — Cấu hình pipeline

### 7.1 Tạo file `config.yaml`

```bash
cp config.yaml.example config.yaml
```

Chỉnh các giá trị sau trong `config.yaml`:

```yaml
capture:
  interface: ens33          # ← thay bằng tên interface thực tế của bạn
  bpf: "not port 22"        # loại SSH ra để không nhiễu log
  keep_local_pcap: false    # true nếu muốn giữ file pcap sau khi xử lý

kafka:
  bootstrap: localhost:9092
  topic: raw_pcap_segments
  segment_seconds: 60       # gom packet trong 60 giây rồi flush
  segment_max_bytes: 67108864  # hoặc flush sớm nếu vượt 64 MB

clickhouse:
  host: localhost
  port: 9000
  database: network_ids
  batch_size: 10000         # số dòng mỗi lần INSERT
```

### 7.2 Kiểm tra đường dẫn EC

```bash
# Pipeline cần biết thư mục Extraction-and-classification nằm ở đâu
# Mặc định: tự tìm ở <repo>/Extraction-and-classification (đúng trong hầu hết trường hợp)
# Nếu clone ở vị trí khác, đặt biến môi trường:
export NB15_EC=/đường/dẫn/tới/Extraction-and-classification
```

---

## Bước 8 — Khởi tạo schema ClickHouse

```bash
# Tạo database và 9 bảng (7 flows_<family> + flows_all + pipeline_runs)
clickhouse-client --multiquery < sql/clickhouse_init.sql

# Kiểm tra bảng đã tạo
clickhouse-client --query "SHOW TABLES FROM network_ids"
```

Kết quả mong đợi:

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

> **Giải thích schema:**
> - `flows_<family>` dùng engine `ReplacingMergeTree` — cho phép ghi lại cùng một segment mà không bị nhân đôi dữ liệu (idempotent re-processing).
> - `flows_all` là Merge view — cho phép query tất cả 7 bảng cùng lúc.
> - `pipeline_runs` ghi audit mỗi segment: thời gian chạy, số flow, lỗi nếu có.
> - TTL mặc định: **14 ngày** — dữ liệu cũ hơn tự động xóa.

---

## Bước 9 — Cài systemd services

### 9.1 Sao chép unit files

```bash
sudo cp deploy/systemd/kafka.service           /etc/systemd/system/
sudo cp deploy/systemd/sniff-producer.service  /etc/systemd/system/
sudo cp deploy/systemd/ec-consumer.service     /etc/systemd/system/
```

### 9.2 Chỉnh đường dẫn trong unit files

Mở từng file và thay `WorkingDirectory` + `ExecStart` cho khớp với đường dẫn thực tế:

```bash
REPO_DIR=$(pwd)   # phải chạy trong thư mục repo

# Thay đường dẫn trong cả 3 file
sudo sed -i "s|/home/tu/realtime-packet-sniff|${REPO_DIR}|g" \
    /etc/systemd/system/kafka.service \
    /etc/systemd/system/sniff-producer.service \
    /etc/systemd/system/ec-consumer.service

# Thay tên user trong ec-consumer.service (service này chạy không cần root)
sudo sed -i "s|User=tu|User=${USER}|g" /etc/systemd/system/ec-consumer.service

# Thêm PYTHONPATH để systemd tìm thấy packages đã cài với --break-system-packages
PYPATH=$(python3 -c "import site; print(site.getusersitepackages())")
sudo sed -i "s|Environment=PYTHONPATH=.*|Environment=PYTHONPATH=${PYPATH}|g" \
    /etc/systemd/system/sniff-producer.service \
    /etc/systemd/system/ec-consumer.service
```

### 9.3 Nội dung 3 unit files (để tham chiếu)

**`kafka.service`** — Kafka KRaft broker:
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

**`sniff-producer.service`** — Capture + đẩy lên Kafka (cần root vì raw socket):
```ini
[Unit]
Description=SNIFF Packet Producer
After=network.target kafka.service
Requires=kafka.service

[Service]
User=root
WorkingDirectory=/home/tu/realtime-packet-sniff
Environment=PYTHONPATH=/home/tu/.local/lib/python3.12/site-packages
ExecStart=/usr/bin/python3 -m integration.run_producer
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**`ec-consumer.service`** — Đọc Kafka → Argus+Zeek → ClickHouse:
```ini
[Unit]
Description=SNIFF EC Consumer (Extract + Classify)
After=network.target kafka.service clickhouse-server.service
Requires=kafka.service

[Service]
User=tu
WorkingDirectory=/home/tu/realtime-packet-sniff
Environment=PYTHONPATH=/home/tu/.local/lib/python3.12/site-packages
ExecStart=/usr/bin/python3 -m integration.ec_consumer
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### 9.4 Reload và enable

```bash
sudo systemctl daemon-reload
sudo systemctl enable kafka sniff-producer ec-consumer
```

---

## Bước 10 — Khởi động & kiểm tra

### 10.1 Khởi động theo thứ tự

```bash
# 1. Kafka phải chạy trước
sudo systemctl start kafka
sleep 5
sudo systemctl status kafka

# 2. Sau đó chạy producer
sudo systemctl start sniff-producer
sleep 3
sudo systemctl status sniff-producer

# 3. Cuối cùng chạy consumer (cần ClickHouse đã sẵn sàng)
sudo systemctl start ec-consumer
sudo systemctl status ec-consumer
```

### 10.2 Kiểm tra toàn bộ stack

```bash
# Xem trạng thái tất cả cùng lúc
sudo systemctl is-active kafka sniff-producer ec-consumer clickhouse-server grafana-server
# Kết quả mong đợi: active active active active active

# Xem log ec-consumer realtime
sudo journalctl -u ec-consumer -f
```

### 10.3 Test bằng cách replay traffic mẫu

```bash
# Capture 30 giây thử
sudo tcpdump -i ens33 -w /tmp/test.pcap -G 30 -W 1

# Hoặc nếu có file pcap có sẵn
sudo tcpreplay -i ens33 --mbps=10 /đường/dẫn/file.pcap
```

Sau ~90 giây (60s segment + thời gian xử lý), kiểm tra dữ liệu:

```bash
# Kafka: số message đã publish
/opt/kafka/bin/kafka-run-class.sh kafka.tools.GetOffsetShell \
    --broker-list localhost:9092 --topic raw_pcap_segments

# ClickHouse: tổng số flow đã ghi
clickhouse-client --query "SELECT count() FROM network_ids.flows_all"

# Xem phân bố theo họ tấn công
clickhouse-client --query \
    "SELECT attack_family, count() AS so_luong
     FROM network_ids.flows_all
     WHERE is_attack = 1
     GROUP BY attack_family
     ORDER BY so_luong DESC"

# Xem pipeline health
clickhouse-client --query \
    "SELECT started_at, status, total_flows, duration_sec, error_msg
     FROM network_ids.pipeline_runs
     ORDER BY started_at DESC LIMIT 5"
```

### 10.4 Kiểm tra Grafana

Mở trình duyệt: `http://<IP-máy-chủ>:3000`
- Đăng nhập: `admin` / `admin`
- Vào **Dashboards → IDS → "SNIFF IDS Pipeline"**
- Nếu dashboard trống, chờ thêm 1-2 phút và nhấn **Refresh**

---

## Cài đặt nhanh (capture tool đơn thuần)

Nếu chỉ muốn dùng công cụ bắt gói tin (TUI/daemon/live stream) **không cần** Kafka/ClickHouse/Grafana:

```bash
# Cài đặt 1 lệnh
curl -fsSL https://raw.githubusercontent.com/ntu168108/realtime-packet-sniff/main/install.sh -o /tmp/install.sh && sudo bash /tmp/install.sh --verbose

# Hoặc cài thủ công
git clone https://github.com/ntu168108/realtime-packet-sniff.git
cd realtime-packet-sniff
pip install --break-system-packages .

# Sử dụng
sudo sniff                          # Menu tương tác
sudo sniff -i ens33                 # Bắt gói tin trên ens33
sudo sniff -i ens33 --live | jq .   # Stream NDJSON ra stdout
sudo sniff -i ens33 -d              # Chạy nền (daemon)
sudo sniff --status                 # Xem trạng thái daemon
sudo sniff --stop                   # Dừng daemon
```

---

## Vận hành hàng ngày

### Khởi động / dừng / restart

```bash
# Khởi động tất cả
sudo systemctl start kafka sniff-producer ec-consumer

# Dừng tất cả
sudo systemctl stop ec-consumer sniff-producer kafka

# Restart ec-consumer sau khi đổi code
sudo systemctl restart ec-consumer
```

### Xem log

```bash
# Theo dõi realtime
sudo journalctl -u ec-consumer -f

# Lọc lỗi
sudo journalctl -u ec-consumer --no-pager | grep -E "ERROR|FAILED|segment="

# Xem 50 dòng gần nhất của producer
sudo journalctl -u sniff-producer -n 50 --no-pager
```

### Query ClickHouse hữu ích

```sql
-- Tổng số flow theo gia đình tấn công
SELECT attack_family, count() AS c
FROM network_ids.flows_all
WHERE is_attack = 1
GROUP BY attack_family ORDER BY c DESC;

-- Top 10 IP tấn công
SELECT srcip, count() AS c
FROM network_ids.flows_all
WHERE is_attack = 1
GROUP BY srcip ORDER BY c DESC LIMIT 10;

-- Timeline tấn công (mỗi phút)
SELECT toStartOfMinute(ts) AS t, attack_family, count() AS c
FROM network_ids.flows_all
WHERE is_attack = 1
GROUP BY t, attack_family ORDER BY t;

-- Kiểm tra pipeline health
SELECT started_at, status, total_flows, duration_sec, error_msg
FROM network_ids.pipeline_runs
ORDER BY started_at DESC LIMIT 10;
```

### Chạy test bộ phân loại thủ công

```bash
cd Extraction-and-classification

# Test toàn bộ 7 filter
python3 -m pytest MODULE_PHANLOAI/tests/ -v

# Chạy pipeline thủ công trên 1 file pcap
python3 MODULE_AUTO/auto_pipeline.py /đường/dẫn/file.pcap

# Chạy DoS classifier riêng lẻ
python3 MODULE_PHANLOAI/dos_classifier.py \
    --csv CSV/CSV_Full_feature/ten_file_dos_features.csv \
    --skip-filter
```

---

## Bước 11 — Cài Web GUI (sniff-web)

> Bước bổ sung tùy chọn, không cần thiết cho hệ thống IDS đã chạy ở Bước 10.
> Web GUI cho phép điều khiển capture + 5 services từ trình duyệt.
>
> 🎯 **Bản mới (zero-touch):** Sau khi chạy xong `install_web.sh`, có thể mở trình
> duyệt ngay tại `http://<server>:8000` và đăng nhập với `admin / sniff` — không
> cần chạy thêm bất kỳ lệnh nào.
>
> **Các lỗi đã sửa (qua các commit trước):**
> 1. `install_web.sh` hardcode user `tu` → fail trên mọi user khác
> 2. Script chạy `npm install` mà không kiểm tra Node.js → fail trên Ubuntu server thuần
> 3. Unit file dùng module `sniff-web.web_server:app` → Python không import được
> 4. PYTHONPATH hardcode → chỉ đúng 1 máy
> 5. Frontend build không verify → UI 404
> 6. **`config.yaml.example` có `web:` ở sai indent** → parser thấy `capture.web` thay vì top-level `web`, login luôn 401 ngay cả khi hash đúng (FIX trong bản này)
> 7. **Script không tự tạo `config.yaml`** với bcrypt hash thật → fresh install phải tự chạy thêm lệnh gen hash (FIX trong bản này)

### 11.1 Yêu cầu trước khi cài

| Thành phần | Phiên bản tối thiểu | Lý do |
|------------|----------------------|--------|
| Python | 3.10+ | đã cài ở Bước 2 |
| Node.js | **18+** (vite 5 không chạy trên Node 12) | build React frontend |
| npm | 9+ | kèm theo Node 18+ |
| disk trống | 800 MB | node_modules (~500MB) + frontend build |

### 11.2 Cài Web GUI

```bash
sudo bash sniff-web/scripts/install_web.sh
```

Lệnh này chạy **8 bước idempotent** (chạy lại không hỏng):

1. **Python deps**: cài `sniff-web/requirements-web.txt` với `--break-system-packages`
   trên Ubuntu 24.04 và `--ignore-installed` để tránh xung đột với PyJWT do apt cài.
2. **Node + frontend**: tự cài Node.js nếu thiếu (apt hoặc NodeSource 20.x);
   build `sniff-web/web/dist/` qua `npm run build`. **Verify** `dist/index.html` tồn tại.
3. **setcap**: `cap_net_admin,cap_net_raw+ep` cho `/usr/bin/python3` (resolve symlink).
4. **sudoers**: cài `/etc/sudoers.d/sniff-web`. Patch user `tu` → `${SUDO_USER}`. Validate
   qua `visudo -c` trước khi copy.
5. **systemd unit**: render `sniff-web.service`. Patch repo path, user, PYTHONPATH.
   `ExecStart=... uvicorn web_server:app ...` (đã fix từ `sniff-web.web_server:app`).
6. **config.yaml**: nếu chưa có → copy từ example + generate bcrypt hash cho password
   mặc định `sniff` + random JWT secret. Nếu đã có hash thật → giữ nguyên (preserve
   user customizations). Chown user, mode 0640.
7. **state + log dirs + logrotate**: tạo `/var/lib/sniff-web/` và `/var/log/sniff-web/`,
   cài `/etc/logrotate.d/sniff-web` (rotate daily, giữ 7 ngày, compress).
8. **enable + start**: `systemctl enable + restart sniff-web`, đợi 2s, báo RUNNING/FAILED.

Output cuối:

```
===============================================
  sniff-web install: RUNNING
===============================================
URL:      http://192.168.1.93:8000
Username: admin
Password: sniff  (CHANGE IMMEDIATELY in config.yaml)
```

### 11.3 Mở Web GUI

**Mở trình duyệt:** `http://<server>:8000` — đăng nhập `admin` / `sniff` (đổi pass ngay
trong UI hoặc bằng lệnh ở mục 11.5).

**Tự khởi động capture sau reboot:** Bấm Start trong UI với checkbox "auto-restore
on reboot". Config được lưu vào `/var/lib/sniff-web/last_capture.json`; lifespan
startup đọc và tự restart capture.

### 11.4 Lỗi thường gặp & fix

| Triệu chứng | Nguyên nhân | Cách sửa |
|-------------|-------------|----------|
| `ModuleNotFoundError: No module named 'sniff-web.web_server'` | Phiên bản cũ | Re-run `sudo bash sniff-web/scripts/install_web.sh` |
| `npm: command not found` | Ubuntu server không có node | Re-run script — tự cài Node 18+ |
| `vite build` fail vì Node < 18 | Ubuntu 22.04 mặc định Node 12 | Re-run script — tự nâng lên NodeSource 20.x |
| Service start xong nhưng UI trả 404 | Frontend build thiếu | Re-run script — verify `dist/index.html` |
| `chown: invalid user: 'tu:tu'` | User không phải `tu` | Re-run script — dùng `${SUDO_USER}` thực |
| Login 401 với `admin/sniff` ngay sau install | `config.yaml` không có hash thật | Re-run script — bản mới auto-generate |
| `setcap: Invalid file '/usr/bin/python3'` | Symlink | Re-run script — fix realpath |

### 11.5 Đổi mật khẩu admin

```bash
# Cách 1: qua UI — vào Settings → Change password (dễ nhất)

# Cách 2: qua CLI
NEW_HASH=$(python3 -c "import bcrypt; print(bcrypt.hashpw(b'MAT_KHAU_MOI', bcrypt.gensalt()).decode())")
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

Xem `sniff-web/docs/WEB_GUI.md` để biết chi tiết API và UI.

## Xử lý sự cố thường gặp

### ❌ `sniff-producer` không kết nối được Kafka

```bash
# Kiểm tra Kafka có đang chạy không
sudo systemctl status kafka
# Kiểm tra port 9092 có mở không
ss -tlnp | grep 9092
# Thử kết nối thủ công
/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list
```

### ❌ `ec-consumer` lỗi "ClickHouse connection refused"

```bash
sudo systemctl status clickhouse-server
# Kiểm tra port 9000
ss -tlnp | grep 9000
# Test kết nối
clickhouse-client --query "SELECT 1"
```

### ❌ Pipeline báo lỗi "argus not found" hoặc "zeek not found"

```bash
which argus zeek
# Nếu không tìm thấy, thêm vào PATH:
export PATH=$PATH:/opt/zeek/bin:/usr/local/bin
# Hoặc tạo symlink:
sudo ln -sf /opt/zeek/bin/zeek /usr/local/bin/zeek
```

### ❌ `dos_classifier.py` lỗi import

```bash
cd Extraction-and-classification/MODULE_PHANLOAI
python3 -c "import dos_classifier; print('OK')"
# Nếu lỗi pandas: pip install pandas numpy
```

### ❌ Grafana không thấy dữ liệu

```bash
# 1. Kiểm tra datasource
curl -s -u admin:admin http://localhost:3000/api/datasources | python3 -m json.tool

# 2. Kiểm tra ClickHouse có dữ liệu không
clickhouse-client --query "SELECT count() FROM network_ids.flows_all"

# 3. Kiểm tra provisioning
ls /etc/grafana/provisioning/datasources/
ls /var/lib/grafana/dashboards/
sudo systemctl restart grafana-server
```

### ❌ Kafka tích lũy dữ liệu cũ, cần reset

```bash
# XÓA TOÀN BỘ DỮ LIỆU KAFKA — chỉ làm khi chắc chắn
sudo systemctl stop kafka
sudo rm -rf /var/lib/kafka-logs
KAFKA_CLUSTER_ID=$(/opt/kafka/bin/kafka-storage.sh random-uuid)
/opt/kafka/bin/kafka-storage.sh format \
    -t $KAFKA_CLUSTER_ID \
    -c /opt/kafka/config/server.properties

sudo systemctl start kafka
# Tạo lại topic
/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 \
    --create --topic raw_pcap_segments --partitions 1 --replication-factor 1
```

> - `random-uuid` — tạo ID duy nhất cho cluster Kafka
> - `format` — khởi tạo thư mục lưu trữ với cluster ID đó (chỉ cần làm 1 lần)

### ❌ ClickHouse TTL — xóa dữ liệu cũ thủ công

```bash
# Xóa dữ liệu cũ hơn 7 ngày trong flows_dos
clickhouse-client --query \
    "ALTER TABLE network_ids.flows_dos DELETE WHERE ts < now() - INTERVAL 7 DAY"

# Hoặc đổi TTL cho tất cả bảng (ví dụ: 7 ngày)
for family in dos exploits fuzzers generic analysis reconnaissance shellcode; do
    clickhouse-client --query \
        "ALTER TABLE network_ids.flows_${family} MODIFY TTL toDateTime(ts) + INTERVAL 7 DAY"
done
```

### ❌ ClickHouse bị treo ở dialog "Set password for default user"

Đây là lỗi **ncurses prompt** khi `clickhouse-server` postinst script chạy
mà không có `DEBIAN_FRONTEND=noninteractive`. Fix bằng 1 trong 2 cách:

```bash
# Cách 1 — Reinstall không hỏi
export CLICKHOUSE_PASSWORD=ClickHousePass
sudo DEBIAN_FRONTEND=noninteractive apt-get install --reinstall -y \
    -o Dpkg::Options::="--force-confdef" \
    -o Dpkg::Options::="--force-confold" \
    clickhouse-server

# Cách 2 — Nếu ClickHouse đã cài nhưng chưa có user default
# Sửa /etc/clickhouse-server/users.xml: thêm user 'default' với <password>...</password>
sudo systemctl restart clickhouse-server
```

### ❌ `sniff-web.service` fail với `ModuleNotFoundError: No module named 'sniff_web'`

Lỗi này do **phiên bản cũ** của `sniff-web.service` template dùng module
`sniff-web.web_server:app` — Python không thể import module có dấu gạch ngang
(`-`) trong tên. Phiên bản mới đã đổi thành `web_server:app` (vì
`WorkingDirectory` đã ở `sniff-web/`).

```bash
# Xem unit file hiện tại
cat /etc/systemd/system/sniff-web.service | grep ExecStart

# Nếu vẫn thấy 'sniff-web.web_server:app' → chạy lại installer để fix
sudo bash sniff-web/scripts/install_web.sh

# Hoặc patch thủ công
sudo sed -i 's|uvicorn sniff-web.web_server:app|uvicorn web_server:app|' \
    /etc/systemd/system/sniff-web.service
sudo systemctl daemon-reload
sudo systemctl restart sniff-web
```

### ❌ `npm: command not found` khi cài sniff-web

```bash
# Cài Node.js + npm (Ubuntu 22.04/24.04)
if ! command -v node >/dev/null 2>&1; then
    sudo apt-get install -y nodejs npm
fi

# Nếu phiên bản node cũ (<18), dùng NodeSource 20.x
if [[ "$(node -e 'console.log(process.versions.node.split(".")[0])')" -lt 18 ]]; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash -
    sudo apt-get install -y nodejs
fi

# Sau đó re-run installer
sudo bash sniff-web/scripts/install_web.sh
```

### ❌ `chown: invalid user: 'tu:tu'` khi cài sniff-web

Phiên bản cũ hardcode user `tu` trong `install_web.sh`. Bản mới dùng
`${SUDO_USER}` tự động. Nếu gặp lỗi này:

```bash
# Chạy lại qua sudo (không phải root trực tiếp) để SUDO_USER được set
sudo bash sniff-web/scripts/install_web.sh

# Hoặc patch thủ công nếu user thật không phải 'tu'
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

## Cấu trúc thư mục tham chiếu

```
realtime-packet-sniff/
├── sniff.py                    # Entry point CLI capture tool
├── install.sh                  # Installer 1 lệnh (capture tool)
├── config.yaml.example         # Mẫu cấu hình → copy thành config.yaml
├── requirements.txt            # Deps capture tool
├── requirements-integration.txt # Deps pipeline IDS
├── core/                       # Engine bắt gói tin (capture, decoder, buffer,...)
├── cli/                        # TUI, daemon, live printer
├── ui/                         # Màu sắc và helpers TUI
├── modules/                    # Plugin analyzer (port scan, DNS tunnel, beaconing)
├── integration/                # Kafka producer/consumer, ClickHouse sink, schema
├── Extraction-and-classification/
│   ├── MODULE_TRICHXUAT/       # Argus + Zeek → trích xuất đặc trưng UNSW-NB15
│   ├── MODULE_PHANLOAI/        # 7 filter + dos_classifier + signatures
│   └── MODULE_AUTO/            # Orchestrator auto_pipeline.py
├── deploy/
│   ├── systemd/                # Unit files: kafka, sniff-producer, ec-consumer
│   ├── kafka/                  # server.properties (KRaft)
│   └── grafana/                # datasource, dashboard provisioning
├── sql/
│   └── clickhouse_init.sql     # DDL tạo database và 9 bảng
├── tests/integration_tests/    # 36 test tự động
└── docs/
    ├── ARCHITECTURE.md         # Kiến trúc chi tiết, format blob, schema CH
    └── OPERATIONS.md           # Runbook vận hành, query, retention
```

---

*Hướng dẫn này áp dụng cho v0.3.0 — xem [CHANGELOG](https://github.com/ntu168108/realtime-packet-sniff/releases) để biết thay đổi mới nhất.*
