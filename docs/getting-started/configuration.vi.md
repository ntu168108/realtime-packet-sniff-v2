# Cấu hình

Công cụ capture và web GUI đều đọc chung 1 file YAML, `config.yaml`, ở thư mục
gốc dự án. File mẫu tham chiếu ở
[`config.yaml.example`](https://github.com/ntu168108/realtime-packet-sniff-v2/blob/main/config.yaml.example)
— copy sang `config.yaml` rồi chỉnh sửa.

```bash
cp config.yaml.example config.yaml
```

> `config.yaml` nằm trong `.gitignore` vì nó chứa hash `bcrypt` của mật khẩu
> và JWT secret. **Không bao giờ commit file này.**

## Các key cấp cao nhất

| Key | Công dụng |
|-----|---------|
| `capture.interface` | NIC dùng để bắt gói (vd `eth0`, `ens33`). |
| `capture.bpf_filter` | BPF filter phía kernel; để trống = bắt tất cả. |
| `capture.snaplen` | Độ dài bắt tối đa mỗi gói. `65535` = tối đa. |
| `capture.promisc` | Chế độ promiscuous (mặc định `true`). |
| `capture.buffer_profile` | Một trong `low`, `balanced`, `fast`, `max`. |
| `capture.output.base_dir` | Nơi ghi file PCAP. |
| `capture.output.retention_days` | Số ngày giữ file (`0` = giữ mãi mãi). |
| `capture.output.rotate_interval` | Số giây giữa các lần rotate bắt buộc. |
| `capture.output.max_file_size` | Số byte trước khi rotate bắt buộc. |
| `capture.output.compress` | Nén gzip file đã rotate. |
| `display.display_filter` | Filter kiểu Wireshark, áp dụng sau khi decode. |
| `display.exclude_ports` | Danh sách port bỏ qua trước khi decode. |
| `display.cache_size` | Kích thước cache danh sách gói tin. |
| `live.enabled` | Ép chế độ live NDJSON (bỏ qua TUI). |
| `modules.enabled` | Danh sách plug-in module bật (để trống = bật hết). |
| `modules.auto_discover` | Tự động nạp module từ thư mục `modules/`. |
| `performance.ring_buffer_size` | Kích thước ring buffer lock-free (số gói). |
| `performance.batch_size` | Số gói xử lý mỗi batch decode. |
| `performance.enable_deep_decode` | Decode L7 DNS/HTTP/TLS (tốn CPU). |
| `performance.gc_interval` | Chu kỳ GC định kỳ, tính bằng giây. |
| `daemon.pid_file` | Đường dẫn file PID của daemon. |
| `daemon.log_file` | Đường dẫn file log của daemon. |
| `daemon.log_level` | `DEBUG` / `INFO` / `WARNING` / `ERROR`. |
| `web.*` | Cấu hình web GUI (xem bên dưới). |
| `web.integrations.*` | Các URL bên ngoài hiển thị trên Dashboard. |
| `capture.evidence_dumpcap` | (Producer/pipeline) Ghi PCAP bằng chứng qua `dumpcap`, chống mất gói burst. |
| `capture.evidence_buffer_mb` | Kernel buffer cho dumpcap (MiB), mặc định 512. |

> **Tinh chỉnh chống mất gói khi tải cao (burst/DoS).** Cấu hình cũ
> (`buffer_profile: balanced`, `ring_buffer_size: 65536`, `batch_size: 256`,
> `gc_interval: 30`) làm mất tới ~60% gói trong burst (vd cú POST 100 MB). Khuyến
> nghị: `buffer_profile: max`, `ring_buffer_size: 1048576`, `batch_size: 1024`,
> `gc_interval: 0`. Với nhánh producer/pipeline, bật `capture.evidence_dumpcap: true`
> để `dumpcap` ghi bản pcap bằng chứng không drop, và trên NIC chạy
> `sudo ethtool -K <iface> gro off lro off` (bắt gói thật thay vì khung GRO gộp).

## Các key của Web GUI (`web:`)

Block `web:` phải nằm ở **cấp cao nhất** của YAML, KHÔNG được lồng trong
`capture:` — `sniff-web/web_server.py` đọc nó dưới dạng `c['web']`. Nếu bị thụt
vào (lồng trong `capture:`), giá trị sẽ âm thầm rơi về mặc định và mọi lần
đăng nhập đều trả về 401.

| Key | Công dụng |
|-----|---------|
| `web.bind` | `0.0.0.0` (mọi interface) hoặc `127.0.0.1` (chỉ loopback). |
| `web.port` | Port HTTP (mặc định `8000`). |
| `web.username` | Username admin duy nhất. |
| `web.password_hash` | Hash bcrypt của mật khẩu admin. |
| `web.jwt_secret` | Secret ký ngẫu nhiên cho session token. |
| `web.jwt_expiry_seconds` | Thời gian sống của token (mặc định `86400` = 24 giờ). |
| `web.auto_restore` | Khôi phục cấu hình capture gần nhất khi service khởi động. |
| `web.persistence_dir` | Nơi lưu `last_capture.json` và các file PCAP. |
| `web.grafana_url` | Link hiển thị ở thẻ "Live monitoring" trên Dashboard. |
| `web.integrations.clickhouse.*` | URL HTTP / credentials ClickHouse (SQL console chỉ đọc). |
| `web.integrations.kafka.*` | Bootstrap + credentials Kafka. |
| `web.alert_ring_size` | Ring buffer trong bộ nhớ cho alert trên dashboard. |
| `web.rate_history_size` | Số mẫu giữ lại cho biểu đồ tốc độ. |
| `web.rate_history_interval` | Số giây giữa mỗi mẫu tốc độ. |

## Override qua biến môi trường

Tầng integration (`integration/config.py`) đọc thêm các biến môi trường sau,
chồng lên giá trị trong YAML:

| Biến môi trường | Override cho |
|---------|-----------|
| `KAFKA_BOOTSTRAP` | `kafka.bootstrap` |
| `KAFKA_TOPIC` | `kafka.topic` |
| `CLICKHOUSE_HOST` | `clickhouse.host` |
| `CLICKHOUSE_PORT` | `clickhouse.port` |
| `CLICKHOUSE_DB` | `clickhouse.database` |
| `SHM_DIR` | Thư mục tmpfs cho pcap từng segment (mặc định `/dev/shm`) |
| `REPO_DIR` | Thư mục gốc dự án (tự phát hiện nếu không đặt) |

## Quy ước đường dẫn khi chạy dưới systemd

Khi `sniff-web.service` chạy với `ProtectSystem=strict`, chỉ những path nằm
trong `ReadWritePaths=` mới ghi được. Unit mặc định cho phép
`/var/lib/sniff-web/`. Đặt

```yaml
capture:
  output:
    base_dir: /var/lib/sniff-web/sniff_data
```

thì chạy được ngay không cần chỉnh gì thêm. Đặt `base_dir: ./sniff_data` sẽ
gây lỗi "Read-only file system" lúc chạy thật.
