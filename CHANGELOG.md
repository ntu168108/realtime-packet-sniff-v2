# Changelog

All notable changes to `realtime-packet-sniff-v2` are documented in this file.

## [Unreleased] - fix/ec-pipeline-real-data-bugs

### Fixed
- **Extract+Classify stage never produced real flow data — every segment
  either crashed or fell through to nothing**, discovered while deploying the
  full stack (Kafka + ClickHouse + Grafana + Argus + Zeek) end-to-end and
  driving it with live captured traffic. Six separate bugs, each blocking the
  next step in the chain:
  - **`Extraction-and-classification/MODULE_TRICHXUAT/extractor.py`** —
    `main()` called `setup_logging(verbose=...)` but the function was never
    defined in the module (`NameError`). Added a `setup_logging()` that wires
    `logging.basicConfig` to the module's existing `LOG_FORMAT`/`LOG_DATE_FMT`.
  - **`Extraction-and-classification/MODULE_TRICHXUAT/zeek_handler.py`** —
    the CSV-writing loop iterated an undefined `wanted_fields` name; the
    actual computed column list is `csv_columns` (`NameError`).
  - **`Extraction-and-classification/MODULE_TRICHXUAT/add_features.py`** —
    `parse_dtcpb` / `parse_service` are vectorized (`Series -> Series`)
    functions but were invoked via `.apply(...)`, which calls them per-scalar
    instead, raising `AttributeError: 'int' object has no attribute 'fillna'`.
    Call them directly on the column instead.
  - **`Extraction-and-classification/MODULE_AUTO/auto_pipeline.py`** — imported
    `family_filter` without first adding `MODULE_PHANLOAI` to `sys.path`
    (`ModuleNotFoundError`) in step 3/4 (the 7 per-family filters).
  - **`integration/ec_consumer.py`** (root cause of "no real data ever reaches
    ClickHouse") — `default_runner()` globbed all 7 families from
    `CSV/CSV_Full_feature/`, but `auto_pipeline.py` actually writes each
    family's filtered CSV into its own `CSV/Filter_<Family>_feature/`
    directory. The consumer never found real per-family output, so every
    segment was marked `status=failed` and ClickHouse never got real rows.
  - **`Extraction-and-classification/MODULE_PHANLOAI/dos_classifier.py`** —
    `np.char.startswith()` does not accept a tuple of prefixes the way
    Python's `str.startswith()` does; it broadcasts element-wise against the
    input array, so passing a 17-item multicast-prefix tuple raised
    `ValueError: operands could not be broadcast together` whenever a
    segment's row count wasn't exactly 17. This silently killed the DoS
    classification step (masked by a blanket except/warn), leaving
    `predicted_class` empty in ClickHouse. Fixed by OR-ing the per-prefix
    boolean masks in a loop instead.
- Also required, at the infra level (not a code bug but a deployment gotcha
  worth documenting): Kafka's default `message.max.bytes` (1 MiB) rejects
  pcap segment blobs larger than that even though the producer's
  `max_request_size` is already sized for `segment_max_bytes` — see the new
  Step 3.4 in [Installation](docs/getting-started/installation.md) and the
  Troubleshooting entry for `MessageSizeTooLargeError`.

Verified end-to-end on a live deployment: captured real traffic → Kafka →
Argus/Zeek → 7 family filters → DoS classifier → ClickHouse now shows real,
non-sample flow rows with populated `predicted_class` for every new segment.

## [Unreleased] - fix/flow-gia-va-mat-goi

### Fixed
- **Flow giả trong ClickHouse** — trước đây mọi flow là dữ liệu mẫu synthetic
  (`10.0.0.5→10.0.0.9`, `udp:53`, `src_mac=ff:ff:ff:ff:ff:ff`, feature toàn 0),
  hoàn toàn không phải traffic bắt được.
  - Bỏ 8 file mẫu `Extraction-and-classification/CSV/CSV_Full_feature/sample_*`
    (bị consumer tái dùng) + gitignore output runtime.
  - **`integration/ec_consumer.py`** — `default_runner._collect_outputs()` neo
    theo stem của segment (`name.startswith(base + "_")`), không còn nhặt file
    mẫu/segment khác qua fast-path.
  - **`integration/clickhouse_sink.py`** — guard `_is_placeholder_row()` loại dòng
    broadcast-src-MAC / feature=0; ép `predicted_class` rỗng → `Normal`; chặn nạp
    khi 0 dòng hợp lệ.
  - **Sửa guard loại nhầm CSV thưa (hồi quy CI):** phiên bản đầu coi `src_mac`
    RỖNG/THIẾU và cột volume vắng mặt là "giả", làm rớt mọi dòng của CSV chỉ có
    `srcip/dstip/sport` → 6 job Backend đỏ (`test_sink_handles_missing_columns`,
    `test_sink_batches_large_csv`). Guard nay chỉ loại khi `src_mac` HIỆN DIỆN và
    là broadcast/all-zero, hoặc toàn bộ cột volume ĐỀU CÓ và = 0; thiếu cột không
    còn bị coi là giả (giữ đúng hợp đồng "tolerate missing columns" của sink).
    Thêm test `test_sink_rejects_placeholder_fake_flows` khoá lại hành vi này.
- **Mất ~60% gói khi tải cao** (đo bằng thiết bị bắt song song, tập trung ở burst).
  - **`config.yaml.example`** — `buffer_profile: max`, `ring_buffer_size: 1048576`,
    `batch_size: 1024`, `gc_interval: 0`.
  - **`core/capture.py`** — `_update_drop_stats()` đọc đúng drop hàng đợi từ
    `RingBuffer.dropped` (drop-oldest trước đây đếm thiếu vì `put_nowait()` luôn True).

### Added
- **`core/native_writer.py`** — `DumpcapWriter`: ghi PCAP bằng chứng qua `dumpcap`
  (kernel buffer lớn) gần như không drop; phơi `drop_stats()` để giám sát.
- **`integration/run_producer.py`** — gắn `DumpcapWriter` (tùy chọn qua
  `capture.evidence_dumpcap`, hỏng thì bỏ qua, không chặn producer) + log
  `evidence_drop` trong cảnh báo DoS.
- Docs: khuyến nghị tinh chỉnh chống burst (`docs/getting-started/configuration.md`),
  bước xóa CSV mẫu + truy vấn nghiệm thu chống flow-giả (`docs/operations/deployment.md`).

## [v1.1.0] - 2026-07-06

### Added
- **DoS self-protection (load-shedding) layer** so a packet flood can no longer OOM the host. Previously the only DoS detection ran at the *end* of the pipeline (`dos_classifier`), so a flood exhausted RAM before it was ever flagged. Detection now happens at capture ingest:
  - **`integration/dos_guard.py` (new)** — `DosGuard` detects floods from the capture engine's `pps` and sheds load by keeping only 1/N packets. Hysteresis via `dos_trigger_pps` (default 50k) / `dos_clear_pps` (15k) / `dos_target_pps` (10k). `should_keep()` is a per-packet, lock-free decision.
  - **`integration/run_producer.py`** — wires `DosGuard` into the capture callback (`on_pkt` drops flood packets) and runs a 1 Hz monitor thread that logs `DoS SUSPECTED pps=… giu_1/N top_talkers=…`.
  - **`integration/kafka_segmenter.py`** — new hard cap `segment_max_packets` (default 100k); a segment now flushes on packet count too, not just bytes/time (a 64 MiB flood segment held ~880k tiny packets).
  - **`integration/ec_consumer.py`** — circuit breaker: segments above `EC_MAX_PKTS_PER_SEGMENT` (default 150k) are marked `dos_shed` and skip the heavy Argus/Zeek/pandas extraction; `main()` now commits `dos_shed` so oversized segments are not reprocessed forever.
  - **`integration/config.py`** — defaults for `kafka.segment_max_packets` and `capture.dos_trigger_pps` / `dos_clear_pps` / `dos_target_pps`.

### Fixed
- **`core/capture.py` could not be imported** — it imported `BoundedRingBuffer` from `core/buffer.py`, which never defined that class, raising `ImportError` on every load of the capture engine. Added `BoundedRingBuffer` (a bounded, drop-newest back-pressure ring buffer).

## [v1.0.0] - 2026-07-05

### Added
- **New repository `ntu168108/realtime-packet-sniff-v2`**: a polished, "clean" version hosted on GitHub Pages with bilingual docs (English + Vietnamese via `mkdocs-static-i18n`).
- **MkDocs site** (`mkdocs.yml`, `docs/`): English + Vietnamese documentation covering Quickstart, Installation, Configuration, Deployment, Architecture, and Troubleshooting.
- **CI matrix** (`.github/workflows/web-gui.yml`): Python 3.10 / 3.11 / 3.12 × Ubuntu 22.04 / 24.04 for backend tests; Node 20 / 22 for frontend build.
- **Docs CI** (`.github/workflows/docs.yml`): builds mkdocs with `--strict` and deploys to GitHub Pages on push to `main`.
- **Release workflow** (`.github/workflows/release.yml`): tag-driven GitHub Release with auto-generated notes.
- **Best-practices files**: PR template, bug/feature issue templates, `CODEOWNERS`, weekly `dependabot.yml` (pip + GitHub Actions), `SECURITY.md`, `CONTRIBUTING.md`.
- **Dependabot** groups all Python deps into a single weekly PR.
### Changed
- Repository restructured: `README_VI.md`, `DEPLOYMENT.md`, `HUONG_DAN_TRIEN_KHAI.md` are removed; their content is migrated into `docs/` (English) and `docs/*.vi.md` (Vietnamese).
- Root `README.md` slimmed to ~50 lines pointing to the docs site.
- All source file paths in docs use v2 repo URL (`github.com/ntu168108/realtime-packet-sniff-v2`).

## [v0.4.0] - 2026-06-29

### Added
- **Web `/capture` syncs `sniff-producer`**: clicking Start on the Capture page now also rewrites `capture.interface` in `config.yaml` and triggers `sudo systemctl restart sniff-producer`, so the web UI and the Kafka/ClickHouse classification pipeline always point at the same NIC. The sudoers allowlist installed by `install_web.sh` covers this; if the allowlist is missing the API response surfaces the error.
- **`/credentials` auto-detects IP per interface**: the host field used to surface URLs for Grafana, ClickHouse, Kafka, and the sniff-web UI itself is now the IPv4 address of the currently-captured interface (via `psutil.net_if_addrs()`), with the previous behavior as fallback.
### Changed
- `POST /api/capture/start` response now includes a `sniff_producer` block with `config_updated`, `config_msg`, `restarted`, `restart_msg` so the UI can surface sync failures.

## [v0.3.0] - earlier
- Initial public release (DEPLOYMENT.md baseline).
