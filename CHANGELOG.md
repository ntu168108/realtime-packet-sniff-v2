# Changelog

All notable changes to `realtime-packet-sniff-v2` are documented in this file.

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
