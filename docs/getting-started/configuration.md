# Configuration

The capture tool and web GUI read a single YAML file, `config.yaml`, in the
project root. A reference is in [`config.yaml.example`](https://github.com/ntu168108/realtime-packet-sniff-v2/blob/main/config.yaml.example)
— copy it to `config.yaml` and edit.

```bash
cp config.yaml.example config.yaml
```

> `config.yaml` is in `.gitignore` because it carries your `bcrypt` password
> hash and JWT secret. **Never commit it.**

## Top-level keys

| Key | Purpose |
|-----|---------|
| `capture.interface` | NIC to sniff on (e.g. `eth0`, `ens33`). |
| `capture.bpf_filter` | Kernel-side BPF filter; empty = capture all. |
| `capture.snaplen` | Per-packet capture length. `65535` = max. |
| `capture.promisc` | Promiscuous mode (default `true`). |
| `capture.buffer_profile` | One of `low`, `balanced`, `fast`, `max`. |
| `capture.output.base_dir` | Where PCAP files are written. |
| `capture.output.retention_days` | Days to keep files (`0` = forever). |
| `capture.output.rotate_interval` | Seconds between forced rotations. |
| `capture.output.max_file_size` | Bytes before forced rotation. |
| `capture.output.compress` | Gzip rotated files. |
| `display.display_filter` | Wireshark-style post-decode filter. |
| `display.exclude_ports` | List of ports to drop before decode. |
| `display.cache_size` | Packet list cache size. |
| `live.enabled` | Force live NDJSON mode (skip TUI). |
| `modules.enabled` | Plug-in modules to enable (empty = all). |
| `modules.auto_discover` | Auto-load modules from `modules/`. |
| `performance.ring_buffer_size` | Lock-free ring buffer size (packets). |
| `performance.batch_size` | Packets per batch decode. |
| `performance.enable_deep_decode` | L7 DNS/HTTP/TLS decode (CPU-heavy). |
| `performance.gc_interval` | Periodic GC interval, seconds. |
| `daemon.pid_file` | Daemon PID file path. |
| `daemon.log_file` | Daemon log file path. |
| `daemon.log_level` | `DEBUG` / `INFO` / `WARNING` / `ERROR`. |
| `web.*` | Web GUI settings (see below). |
| `web.integrations.*` | External URLs shown on the Dashboard. |
| `capture.evidence_dumpcap` | (Producer/pipeline) Ghi PCAP bằng chứng qua `dumpcap`, chống mất gói burst. |
| `capture.evidence_buffer_mb` | Kernel buffer cho dumpcap (MiB), mặc định 512. |

> **Tinh chỉnh chống mất gói khi tải cao (burst/DoS).** Cấu hình cũ
> (`buffer_profile: balanced`, `ring_buffer_size: 65536`, `batch_size: 256`,
> `gc_interval: 30`) làm mất tới ~60% gói trong burst (vd cú POST 100 MB). Khuyến
> nghị: `buffer_profile: max`, `ring_buffer_size: 1048576`, `batch_size: 1024`,
> `gc_interval: 0`. Với nhánh producer/pipeline, bật `capture.evidence_dumpcap: true`
> để `dumpcap` ghi bản pcap bằng chứng không drop, và trên NIC chạy
> `sudo ethtool -K <iface> gro off lro off` (bắt gói thật thay vì khung GRO gộp).

## Web GUI keys (`web:`)

The `web:` block must be at the **top level** of the YAML, NOT nested under
`capture:` — `sniff-web/web_server.py` reads it as `c['web']`. An indented
copy silently falls back to defaults and every login returns 401.

| Key | Purpose |
|-----|---------|
| `web.bind` | `0.0.0.0` (all) or `127.0.0.1` (loopback only). |
| `web.port` | HTTP port (default `8000`). |
| `web.username` | Single-admin username. |
| `web.password_hash` | bcrypt hash of the admin password. |
| `web.jwt_secret` | Random signing secret for session tokens. |
| `web.jwt_expiry_seconds` | Token lifetime (default `86400` = 24 h). |
| `web.auto_restore` | Restore last capture config on service start. |
| `web.persistence_dir` | Where `last_capture.json` and PCAPs live. |
| `web.grafana_url` | Link shown on the Dashboard's "Live monitoring" card. |
| `web.integrations.clickhouse.*` | ClickHouse HTTP URL / credentials (read-only SQL console). |
| `web.integrations.kafka.*` | Kafka bootstrap + credentials. |
| `web.alert_ring_size` | In-memory ring buffer for dashboard alerts. |
| `web.rate_history_size` | Number of samples kept for rate charts. |
| `web.rate_history_interval` | Seconds per rate sample. |

## Environment overrides

The integration layer (`integration/config.py`) reads these env vars on top of
the YAML:

| Env var | Overrides |
|---------|-----------|
| `KAFKA_BOOTSTRAP` | `kafka.bootstrap` |
| `KAFKA_TOPIC` | `kafka.topic` |
| `CLICKHOUSE_HOST` | `clickhouse.host` |
| `CLICKHOUSE_PORT` | `clickhouse.port` |
| `CLICKHOUSE_DB` | `clickhouse.database` |
| `SHM_DIR` | tmpfs directory for per-segment pcaps (default `/dev/shm`) |
| `REPO_DIR` | project root (auto-detected otherwise) |

## Path conventions under systemd

When `sniff-web.service` runs with `ProtectSystem=strict`, only paths in
`ReadWritePaths=` are writable. The default unit allows
`/var/lib/sniff-web/`. Setting

```yaml
capture:
  output:
    base_dir: /var/lib/sniff-web/sniff_data
```

works out of the box. Setting `base_dir: ./sniff_data` causes
"Read-only file system" errors at runtime.