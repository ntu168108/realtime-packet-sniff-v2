# Triển khai & vận hành — realtime-packet-sniff IDS

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

> **⚠ Bắt buộc — xóa CSV mẫu khỏi thư mục runtime.** Nếu `CSV/CSV_Full_feature/`
> còn `sample_*_features.csv`, EC consumer sẽ **tái dùng chúng cho MỌI segment**
> thay vì trích xuất pcap thật → flow trong ClickHouse toàn là dữ liệu giả
> (`10.0.0.5→10.0.0.9`, feature=0). Dọn trước khi chạy:
> ```bash
> find "$NB15_EC/CSV/CSV_Full_feature" -name 'sample_*_features.csv' -delete
> find "$NB15_EC/CSV/CSV_Full_feature" -name 'sample_raw.csv' -delete
> ```

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

# Thay tên user trong kafka.service va ec-consumer.service (2 service nay
# chay khong can root; neu quen kafka.service, systemctl start kafka se
# fail tren may khac vi user "tu" khong ton tai)
sudo sed -i "s|User=tu|User=${USER}|g" \
    /etc/systemd/system/kafka.service \
    /etc/systemd/system/ec-consumer.service

# Thêm PYTHONPATH để systemd tìm thấy packages đã cài với --break-system-packages
PYPATH=$(python3 -c "import site; print(site.getusersitepackages())")
sudo sed -i "s|Environment=PYTHONPATH=.*|Environment=PYTHONPATH=${PYPATH}|g" \
    /etc/systemd/system/sniff-producer.service \
    /etc/systemd/system/ec-consumer.service
```

### 9.3 Nội dung 3 unit files (để tham chiếu)

**`kafka.service`** — Kafka KRaft broker (`User=tu` chỉ là placeholder, được
patch lại thành user thật ở bước 9.2 trên; nếu quên patch, service sẽ không
khởi động được trên máy nào không có user tên `tu`):
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

## 11. Cập nhật bộ phân loại (unified_classifier) & hiệu chỉnh

Từ bản `fix/classification-accuracy-real-traffic`, tầng phân loại dùng
`Extraction-and-classification/MODULE_PHANLOAI/unified_classifier.py` — hợp nhất
1 nhãn/flow + phát hiện DoS volumetric. **Không đổi schema/sink/Grafana**, nên
triển khai lại chỉ là cập nhật code Python + restart `ec-consumer`.

### 11.1 Triển khai lại

```bash
cd ~/realtime-packet-sniff-v2
git fetch origin
git checkout fix/classification-accuracy-real-traffic   # hoặc: git pull khi đã merge vào main
# KHÔNG cần đổi ClickHouse: schema/DDL giữ nguyên. KHÔNG cần cài thêm dependency.
sudo systemctl restart ec-consumer
sudo journalctl -u ec-consumer -f      # theo dõi vài segment mới
```

Các segment MỚI (đến sau khi restart) sẽ được gán nhãn bằng bộ phân loại mới.
Dữ liệu CŨ trong ClickHouse giữ nguyên nhãn cũ — nếu cần gán lại, replay pcap gốc
(mục 10.3) hoặc `TRUNCATE` các bảng `flows_*` rồi replay.

### 11.2 Nghiệm thu nhanh sau khi triển khai

```bash
# 1) DoS phải xuất hiện với subtype thật (SYN/UDP/ICMP), KHÔNG chỉ mDNS/STP:
clickhouse-client --query \
  "SELECT attack_subtype, count() FROM network_ids.flows_all
   WHERE attack_family='dos' AND is_attack=1
   GROUP BY attack_subtype"

# 2) Kiểm tra flow flood tới victim đã là DoS (thay IP victim của bạn):
clickhouse-client --query \
  "SELECT predicted_class, count() FROM network_ids.flows_all
   WHERE dstip='192.168.101.135' GROUP BY predicted_class ORDER BY count() DESC"

# 3) mDNS/SSDP KHÔNG còn bị gắn DoS (kỳ vọng 0):
clickhouse-client --query \
  "SELECT count() FROM network_ids.flows_all
   WHERE predicted_class='DoS' AND (dport IN (5353,1900) OR dstip LIKE '239.%' OR dstip LIKE '224.%')"
```

### 11.3 Hiệu chỉnh (tùy môi trường mạng) qua biến môi trường

Đặt trong unit file `deploy/systemd/ec-consumer.service` (thêm dòng
`Environment=...`) rồi `sudo systemctl daemon-reload && sudo systemctl restart ec-consumer`:

| Biến | Mặc định | Ý nghĩa / khi nào chỉnh |
|---|---|---|
| `DOS_MIN_FLOWS_PER_DST` | `40` | Số flow flood-like tối thiểu tới cùng 1 đích/segment để coi là flood. Tăng nếu mạng có burst benign lớn (VD nhiều client tới 1 server); giảm nếu muốn nhạy hơn. |
| `DOS_MAX_DPORT_SPREAD` | `8` | Số cổng đích riêng biệt TỐI ĐA mà lượng flow flood-like tới 1 đích được phép trải ra và vẫn bị coi là flood. Đây là thứ phân biệt flood (dồn vào ít cổng) với port-scan (trải hàng trăm cổng) — không có nó, một cuộc quét 500 cổng bị gán nhãn DoS hàng loạt. **Cẩn thận khi giảm:** hạ quá thấp sẽ bỏ lọt flood đa cổng thật. Tăng nếu môi trường có flood nhắm nhiều cổng dịch vụ cùng lúc. |
| `DOS_HIGH_RATE` | `5000` | Ngưỡng pps của 1 flow đơn để tự coi là flood (flood cổ điển không spoof). |
| `DOS_MIN_PKTS_FOR_RATE` | `4` | Số gói (`spkts`) tối thiểu để tín hiệu `DOS_HIGH_RATE` được tin cậy. `rate = spkts/dur` là tỷ số, nên một probe ĐƠN GÓI với `dur` cỡ 0,2 ms đạt `rate = 5000` dù chỉ có 1 gói. Tăng nếu vẫn thấy probe ngắn bị gán DoS; giảm về `1` để trở lại hành vi cũ (không khuyến nghị). |
| `FAMILY_MIN_DTTL` | `60` | "Đích ở gần" (ít hop) mới gán nhãn HỌ — chặn false-positive từ traffic đi ra internet. Đặt `0` để TẮT nếu bạn giám sát cả traffic tới host ở xa. |
| `DOS_SYN_THRESHOLD` / `DOS_UDP_THRESHOLD` / `DOS_ICMP_THRESHOLD` | `42/32/28` | Ngưỡng điểm cộng dồn per-flow cho từng subtype DoS. |

> **Lưu ý ngưỡng cũ:** `signatures/dos.json`, `generic.json`, `shellcode.json`
> vẫn dùng ngưỡng UNSW-NB15 (`sttl>=142.5/200`) cho các cột `*_score`, nhưng
> QUYẾT ĐỊNH nhãn giờ do `unified_classifier` đảm nhiệm. Nếu bạn tự hiệu chỉnh
> chữ ký cho traffic thật, sửa các file JSON đó — điểm sẽ được unified đọc lại.

### 11.4 Chống quá tải khi bị flood (DosGuard — tầng producer)

Khác với 11.3 (biến môi trường của `ec-consumer`), các khoá dưới đây đặt trong
`config.yaml` mục `capture:` và áp cho **`sniff-producer`**. Sau khi sửa:
`sudo systemctl restart sniff-producer`.

| Khoá (trong `config.yaml` → `capture:`) | Mặc định | Ý nghĩa / khi nào chỉnh |
|---|---|---|
| `dos_backpressure` | `true` | Bật cắt tải theo backpressure (drop/queue thật) — NIC-agnostic, KHUYẾN NGHỊ để `true`. Với NIC 10G/100G đây là cơ chế chính; ngưỡng pps tuyệt đối gần như vô dụng ở tốc độ đó. |
| `dos_queue_high_ratio` | `0.5` | Hàng đợi đầy ≥ tỉ lệ này → tăng cắt tải. Hạ xuống để phản ứng sớm hơn. |
| `dos_queue_low_ratio` | `0.2` | Hàng đợi ≤ tỉ lệ này + hết drop → giảm cắt tải dần, rồi trở lại 1/1. |
| `dos_victim_share` | `0.5` | 1 đích chiếm ≥ tỉ lệ này tổng gói → coi là victim, chỉ cắt luồng tới nó, giữ traffic hợp lệ khác. Đặt `0` để tắt cắt-tải-chọn-lọc. |
| `dos_victim_min_pps` | `1000` | Ngưỡng pps tối thiểu của 1 đích để bị coi là victim (tránh báo nhầm lúc mạng nhàn). |
| `dos_max_drop` | `200` | Trần tỉ lệ bỏ gói (giữ tối thiểu 1/200) — dù flood cực lớn vẫn còn mẫu để phân loại. |
| `dos_trigger_pps` / `dos_clear_pps` / `dos_target_pps` | `50000/15000/10000` | Ngưỡng pps tuyệt đối (cơ chế cũ, mạng nhỏ/lab). Sample cuối = `max(backpressure, pps)`. |

> **NIC nhanh (10G/100G):** để `dos_backpressure: true` và **bỏ qua** việc chỉnh
> `dos_trigger_pps` (ngưỡng tuyệt đối không co giãn theo NIC). Guard sẽ tự cắt tải
> khi thực sự hụt hơi. Nếu vẫn drop nhiều ở kernel, vấn đề là TRẦN BẮT GÓI của
> tầng Python/Scapy — cần kernel sampling (PACKET_FANOUT/XDP) hoặc flow telemetry
> (sFlow/IPFIX), không phải chỉnh guard.

---

<span id="day-to-day-operations"></span>
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

> ⚠️ **Build sẽ FAIL nếu Node < 20.19:** `vite@8` và `@vitejs/plugin-react@6`
> đang được pin trong `package.json`/`package-lock.json` của frontend đều yêu
> cầu `"engines": { "node": "^20.19.0 || >=22.12.0" }` (xác nhận qua
> `npm view vite engines` / `npm view @vitejs/plugin-react engines`, và đã tái
> hiện thực tế — cài Node 18.19.1 thì `npm install` chạy được, chỉ warn
> `EBADENGINE`, nhưng `npm run build` crash ngay với lỗi:
> `SyntaxError: The requested module 'node:util' does not provide an export
> named 'styleText'` — API này chỉ có từ Node 20.12 trở lên. Kiểm tra version
> hiện có trước:
> ```bash
> node -v
> ```

| Thành phần | Phiên bản tối thiểu | Lý do |
|------------|----------------------|--------|
| Python | 3.10+ | đã cài ở Bước 2 |
| Node.js | **20.19+** (hoặc 22.12+; khuyến nghị Node 22 LTS) — `vite@8`/`@vitejs/plugin-react@6` yêu cầu, Node cũ hơn sẽ crash với lỗi `styleText` ở trên | build React frontend |
| npm | 10+ | kèm theo Node 20.19+ |
| disk trống | 800 MB | node_modules (~500MB) + frontend build |

**Nâng cấp Node.js**, chọn 1 trong 2 cách:

a) **Qua NodeSource (khuyến nghị cho server, persistent qua reboot):**

```bash
sudo apt-get remove -y nodejs
sudo apt-get autoremove -y
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs
node -v   # xác nhận v22.x.x
```

b) **Qua nvm** (nếu không muốn đổi Node hệ thống — lưu ý cách này chỉ ảnh
   hưởng bước build một lần, không ảnh hưởng lúc service chạy thật vì
   sniff-web chỉ serve file tĩnh + Python backend sau khi build xong):

```bash
nvm install 22
nvm use 22
node -v
```

**Nếu đã lỡ cài `node_modules` bằng Node cũ**, xóa và cài lại sạch trước khi
build lại:

```bash
cd sniff-web/web
rm -rf node_modules package-lock.json
npm install
npm run build
ls -la dist/index.html   # phải tồn tại, xác nhận build thành công
```

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
| `SyntaxError: ... does not provide an export named 'styleText'` | Node quá cũ (< 20.12), không đủ cho vite 8/rolldown | Nâng Node lên 22 LTS (xem 11.1), xóa node_modules, npm install + npm run build lại |

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

---

## Cấu trúc thư mục tham chiếu

```
realtime-packet-sniff-v2/
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
    ├── index.md                # Trang chủ tiếng Anh
    ├── getting-started/        # quickstart, installation, configuration
    ├── operations/             # deployment, architecture, troubleshooting
    └── vi/                     # Bản dịch tiếng Việt
```