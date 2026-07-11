# Xử lý sự cố — realtime-packet-sniff IDS

## Xử lý sự cố thường gặp

### ❌ `sniff-producer` báo lỗi `[Error 10] MessageSizeTooLargeError`

`message.max.bytes` mặc định của Kafka (1 MiB) nhỏ hơn blob pcap segment
(`segment_max_bytes`, mặc định 64 MiB). `max_request_size` phía producer đã
đúng — đây là cấu hình **ở cấp topic** trên broker, cần tăng riêng:

```bash
/opt/kafka/bin/kafka-configs.sh --bootstrap-server localhost:9092 \
    --entity-type topics --entity-name raw_pcap_segments \
    --alter --add-config max.message.bytes=104857600

sudo systemctl restart sniff-producer
```

Xem [Cài đặt bước 3.4](../getting-started/installation.vi.md#34-tang-gioi-han-kich-thuoc-message-cua-topic).

### ❌ Segment tới được `ec-consumer` nhưng `pipeline_runs.status` luôn là `failed`

Xem traceback thật qua `sudo journalctl -u ec-consumer -n 50` — triệu chứng
này có nhiều nguyên nhân khác nhau, tất cả đã fix ở phiên bản khớp tài liệu
này:

- `NameError: name 'setup_logging' is not defined` (extractor.py) — checkout
  cũ trước khi có bản fix; `git pull` / clone lại.
- `NameError: name 'wanted_fields' is not defined` (zeek_handler.py) — tương tự.
- `AttributeError: 'int' object has no attribute 'fillna'` (add_features.py) —
  tương tự.
- `ModuleNotFoundError: No module named 'family_filter'` (auto_pipeline.py) —
  tương tự.
- `auto_pipeline.py` báo `PIPELINE HOAN TAT` (thành công) nhưng ClickHouse
  không có dòng nào và `ec-consumer` vẫn đánh dấu segment `failed` — consumer
  tìm 7 CSV theo family sai thư mục (`CSV/CSV_Full_feature/` thay vì đúng
  `CSV/Filter_<Family>_feature/` của từng family). Đã fix trong
  `integration/ec_consumer.py`; clone/pull lại nếu vẫn gặp.
- `ValueError: operands could not be broadcast together ... (N,) (17,)` từ
  `dos_classifier.py` — `np.char.startswith()` được gọi với tuple nhiều
  prefix multicast, hàm này không hỗ trợ kiểu đó (khác với `str.startswith()`
  của Python). Lỗi bị bắt và chỉ log warning (`DoS Classifier khong chay
  duoc`, không chặn pipeline), nhưng khiến `predicted_class` rỗng ở mọi dòng.
  Đã fix bằng cách OR từng prefix trong vòng lặp; clone/pull lại nếu vẫn thấy
  warning này.

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
    -o Dpkg::Options="--force-confdef" \
    -o Dpkg::Options="--force-confold" \
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

*Hướng dẫn này áp dụng cho v1.0.0 — xem [CHANGELOG](https://github.com/ntu168108/realtime-packet-sniff-v2/releases) để biết thay đổi mới nhất.*