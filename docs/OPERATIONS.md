# SNIFF IDS Pipeline — Operations Runbook

Runbook vận hành hệ thống giám sát / phát hiện tấn công mạng dựa trên
SNIFF + Kafka + Extraction-Classification (Argus/Zeek) + ClickHouse +
Grafana, host `<server-ip>` (Ubuntu 24.04).

---

## 1. Kiến trúc 1 dòng

`sniff (libpcap trên ens33) → Kafka topic raw_pcap_segments → ec-consumer (Argus+Zeek → 7 bộ phân loại UNSW-NB15) → ClickHouse database network_ids (8 bảng) → Grafana dashboard`

```
┌────────────┐   pcap blob    ┌──────────┐    msg    ┌──────────────┐
│  SNIFF     │──────────────▶ │  Kafka   │──────────▶│ ec-consumer  │
│  capture   │   topic=raw_   │  KRaft   │           │ (Argus+Zeek) │
│  ens33     │   pcap_segments│ :9092    │           └──────┬───────┘
└────────────┘                └──────────┘                  │
                                                            ▼
                              ┌──────────────┐   ┌────────────────────┐
                              │   Grafana    │◀──│   ClickHouse       │
                              │  :3000       │   │   network_ids      │
                              │  dashboard   │   │   flows_<family>   │
                              │  "SNIFF IDS  │   │   flows_all        │
                              │   Pipeline"  │   │   pipeline_runs    │
                              └──────────────┘   └────────────────────┘
```

Mỗi segment Kafka chứa ~60 giây capture (cấu hình qua `config.yaml`
`kafka.segment_seconds`); blob gồm `[4B header-len][JSON meta][pcap
file bytes]` (xem `integration/pcap_segment.py`).

---

## 2. Khởi động / dừng / trạng thái 3 service chính

Cả 3 chạy dưới systemd. File unit ở `deploy/systemd/`, đã cài vào
`/etc/systemd/system/`. Service Kafka là single-broker KRaft.

```bash
# Trạng thái
sudo systemctl is-active kafka sniff-producer ec-consumer
sudo systemctl status kafka sniff-producer ec-consumer --no-pager

# Khởi động / dừng
sudo systemctl start   kafka sniff-producer ec-consumer
sudo systemctl stop    kafka sniff-producer ec-consumer
sudo systemctl restart kafka sniff-producer ec-consumer

# Auto-start sau reboot (đã bật)
sudo systemctl enable  kafka sniff-producer ec-consumer
```

**Thứ tự phụ thuộc:**
- `kafka` không phụ thuộc gì.
- `sniff-producer` yêu cầu `kafka` (Requires=kafka.service, sau network.target).
- `ec-consumer` yêu cầu `kafka` và phải có `clickhouse-server` (clickhouse-server không nằm trong unit-files này nhưng phải chạy trước).

```bash
# ClickHouse & Grafana (chạy song song, không do script này quản lý nhưng cần thiết)
sudo systemctl status clickhouse-server grafana-server
```

**Xem log:**

```bash
# Tail 30 dòng mới nhất
sudo journalctl -u kafka         -n 30 --no-pager
sudo journalctl -u sniff-producer -n 30 --no-pager
sudo journalctl -u ec-consumer    -n 30 --no-pager

# Theo dõi realtime
sudo journalctl -u ec-consumer -f

# Lọc theo segment_id cụ thể
sudo journalctl -u ec-consumer --no-pager | grep "segment=<sid>"

# Lọc heartbeat / lỗi
sudo journalctl -u ec-consumer --no-pager | grep -E "heartbeat|FAILED|segment="
```

Log format: `YYYY-MM-DD HH:MM:SS,ms | LEVEL | <logger-name> | <message>`
với các dòng của ec-consumer có prefix `[segment=<sid>]` do `_SegmentAdapter`
chèn vào (xem `integration/ec_consumer.py`).

---

## 3. Bơm traffic test bằng tcpreplay

Có sẵn `/tmp/sample.pcap` (~400 gói SYN flood + UDP giả lập). Để replay:

```bash
# 1 lần, tốc độ 10 Mbps (mặc định trong plan)
echo "1" | sudo -S tcpreplay -i ens33 --mbps=10 /tmp/sample.pcap

# Lặp 3 lần
for i in 1 2 3; do echo "1" | sudo -S tcpreplay -i ens33 --mbps=10 /tmp/sample.pcap; done

# Capture riêng để so sánh
echo "1" | sudo -S tcpdump -i ens33 -w /tmp/cap-$(date +%s).pcap -c 1000
```

Sau ~60-90 giây (chờ `segment_seconds` flush + consumer xử lý), kiểm tra:

```bash
# Số segment Kafka đã publish
/opt/kafka/bin/kafka-run-class.sh kafka.tools.GetOffsetShell \
  --broker-list localhost:9092 --topic raw_pcap_segments

# ClickHouse: tổng số dòng
clickhouse-client --query "SELECT count() FROM network_ids.flows_all"

# ClickHouse: dòng theo family
clickhouse-client --query "SELECT attack_family, count() FROM network_ids.flows_all GROUP BY attack_family"
```

---

## 4. Truy cập Grafana

- URL: <http://<server-ip>:3000>
- User/Pass mặc định: `admin` / `admin` (đã đổi ở lần đăng nhập đầu)
- Dashboard: **IDS → "SNIFF IDS Pipeline"** (4 panel)
  - Attacks timeline by family (timeseries)
  - Top attackers (table, top 10 src_ip)
  - Count by family (table)
  - Pipeline health (table, 50 run gần nhất từ `pipeline_runs`)

Nếu dashboard trống: chờ ~90s sau lần tcpreplay đầu tiên; kiểm tra
datasource `ClickHouse` đã provision chưa
(`curl -s -u admin:admin http://localhost:3000/api/datasources | grep -i clickhouse`).

---

## 5. Query ClickHouse hữu ích

Database `network_ids`. Bảng:

| Bảng                  | Engine              | Mô tả                          |
|-----------------------|---------------------|--------------------------------|
| `flows_dos`           | ReplacingMergeTree  | Flow đã phân loại DoS          |
| `flows_exploits`      | ReplacingMergeTree  | ... Exploits                   |
| `flows_fuzzers`       | ReplacingMergeTree  | ... Fuzzers                    |
| `flows_generic`       | ReplacingMergeTree  | ... Generic                    |
| `flows_analysis`      | ReplacingMergeTree  | ... Analysis                   |
| `flows_reconnaissance`| ReplacingMergeTree  | ... Reconnaissance             |
| `flows_shellcode`     | ReplacingMergeTree  | ... Shellcode                  |
| `flows_all`           | Merge               | View hợp nhất 7 bảng trên      |
| `pipeline_runs`       | MergeTree           | Audit mỗi segment đã xử lý     |

Tất cả `flows_<family>` có cột audit giống nhau: `ts`, `segment_id`,
`attack_family`, `attack_subtype`, `is_attack`, `interface`,
`t_window`, `pcap_file`, plus 46 cột feature UNSW-NB15.

```sql
-- 5a. Tổng số flow đã ghi nhận
SELECT count() FROM network_ids.flows_all;

-- 5b. Phân bố family (có/không lọc attack)
SELECT attack_family, count() AS c
FROM network_ids.flows_all
WHERE is_attack = 1
GROUP BY attack_family
ORDER BY c DESC;

-- 5c. Top 10 IP tấn công theo số flow attack
SELECT srcip, count() AS c
FROM network_ids.flows_all
WHERE is_attack = 1
GROUP BY srcip
ORDER BY c DESC
LIMIT 10;

-- 5d. Theo thời gian (mỗi phút)
SELECT toStartOfMinute(ts) AS t, attack_family, count() AS c
FROM network_ids.flows_all
WHERE is_attack = 1
GROUP BY t, attack_family
ORDER BY t;

-- 5e. Health pipeline 24h gần nhất
SELECT started_at, segment_id, status, total_flows,
       dos, exploits, fuzzers, generic, analysis, reconnaissance, shellcode,
       duration_sec, error_msg
FROM network_ids.pipeline_runs
WHERE started_at > now() - INTERVAL 24 HOUR
ORDER BY started_at DESC;

-- 5f. Dedup / tổng số segment_id đã xử lý
SELECT uniqExact(segment_id) FROM network_ids.flows_all;
```

> **Lưu ý:** các bảng `flows_<family>` dùng ReplacingMergeTree; query
> đếm chính xác cần `SELECT count() FROM ... FINAL` (hoặc chạy
> `OPTIMIZE TABLE network_ids.flows_dos FINAL` để merge).

---

## 6. Vị trí cấu hình & schema

| File                                | Mục đích                                          |
|-------------------------------------|---------------------------------------------------|
| `config.yaml` (project root)        | Cấu hình runtime (segment, bpf, clickhouse,...)  |
| `config.yaml.example`               | Mẫu tham chiếu                                    |
| `integration/config.py`             | Loader (defaults + YAML + env override)           |
| `integration/schema.py`             | Cột CSV/CH chuẩn (single source of truth)         |
| `integration/pcap_segment.py`       | Serialize/deserialize blob                        |
| `integration/kafka_segmenter.py`    | Gom packet → publish Kafka                        |
| `integration/ec_consumer.py`        | Consumer + `process_segment` + main loop          |
| `integration/clickhouse_sink.py`    | Batch insert per-family CSV → CH                  |
| `integration/run_producer.py`       | Entrypoint producer                               |
| `sql/clickhouse_init.sql`           | DDL: 7 bảng flows + flows_all + pipeline_runs     |
| `deploy/systemd/*.service`          | Unit systemd                                      |
| `deploy/kafka/server.properties`    | Kafka KRaft config                                |
| `deploy/grafana/datasource.yaml`    | Grafana datasource provisioning                   |
| `deploy/grafana/dashboard.json`     | Dashboard "SNIFF IDS Pipeline"                    |
| `deploy/grafana/dashboards.yaml`    | Dashboard provider                                |
| `Extraction-and-classification/`    | Repo pipeline Argus+Zeek (submodule / clone)      |

### Các khóa cấu hình thường đụng (`config.yaml`)

```yaml
kafka:
  bootstrap: localhost:9092          # KAFKA_BOOTSTRAP env override
  topic: raw_pcap_segments
  segment_seconds: 60                # gom packet 60s rồi flush
  segment_max_bytes: 67108864        # 64 MiB
clickhouse:
  host: localhost                    # CLICKHOUSE_HOST env override
  port: 9000
  database: network_ids
  batch_size: 10000
capture:
  interface: ens33
  bpf: "not port 22"                 # loại SSH để khỏi nhiễu
  keep_local_pcap: false
```

---

## 7. Retention & TTL

| Hệ thống       | Giá trị hiện tại                          | Cách chỉnh                                   |
|-----------------|-------------------------------------------|----------------------------------------------|
| Kafka topic     | `log.retention.ms=3600000` (1h)           | `kafka-configs.sh --alter --add-config`     |
|                 | `log.retention.bytes=2147483648` (2GB/partition) | hoặc sửa `/opt/kafka/config/kraft/server.properties` rồi restart |
|                 | `log.retention.check.interval.ms=300000`  |                                              |
| ClickHouse TTL  | `toDateTime(ts) + toIntervalDay(14)`      | Sửa `sql/clickhouse_init.sql` + `ALTER TABLE` |

Xem lại giá trị hiện tại:

```bash
# Kafka
/opt/kafka/bin/kafka-configs.sh --bootstrap-server localhost:9092 \
  --describe --topic raw_pcap_segments
grep -E "log.retention" /opt/kafka/config/kraft/server.properties

# ClickHouse
clickhouse-client --query "SHOW CREATE TABLE network_ids.flows_dos"
```

---

## 8. Lưu ý & fallback

- **Zeek** cài ở `/opt/zeek/bin/zeek` (không nằm trong `$PATH` mặc định).
  Đã symlink `/usr/local/bin/zeek -> /opt/zeek/bin/zeek` để chạy trực
  tiếp `zeek`. Có thể dùng `command -v zeek` để kiểm tra.

- **tshark** là fallback (đã cài) cho trường hợp Argus/Zeek không hoạt
  động. Hiện tại pipeline chính dùng Argus+Zeek; consumer KHÔNG tự
  fallback sang tshark — chỉnh `integration/ec_consumer.default_runner`
  nếu cần.

- **tmpfs** `/dev/shm` được dùng để ghi pcap tạm giữa Kafka và pipeline;
  nếu host không có tmpfs (vd macOS), `SHM_DIR` tự fallback về
  `tempfile.gettempdir()` (xem `integration/ec_consumer.py`).

- **Kafka KRaft** (không cần ZooKeeper); cluster metadata ở
  `/var/lib/kafka-logs`. Nếu muốn reset hoàn toàn:
  `rm -rf /var/lib/kafka-logs && /opt/kafka/bin/kafka-storage.sh format ...`

  cho lệnh một dòng.

- **Test nhanh sau khi đổi config:**
  ```bash
  cd /home/tu/sniff && .venv/bin/python -m pytest tests/integration_tests/ -q
  ```