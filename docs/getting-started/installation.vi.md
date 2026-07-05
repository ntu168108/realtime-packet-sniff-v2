# Cài đặt — realtime-packet-sniff IDS

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
git clone https://github.com/ntu168108/realtime-packet-sniff-v2.git
cd realtime-packet-sniff-v2
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
    -o Dpkg::Options="--force-confdef" \
    -o Dpkg::Options="--force-confold" \
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