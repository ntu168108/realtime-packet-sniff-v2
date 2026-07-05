# Changelog

All notable changes to `realtime-packet-sniff` are documented in this file.

## [v0.4.0] - 2026-06-29

### Added
- **Web `/capture` syncs `sniff-producer`**: clicking Start on the Capture page now also rewrites `capture.interface` in `config.yaml` and triggers `sudo systemctl restart sniff-producer`, so the web UI and the Kafka/ClickHouse classification pipeline always point at the same NIC. The sudoers allowlist installed by `install_web.sh` covers this; if the allowlist is missing the API response surfaces the error.
- **`/credentials` auto-detects IP per interface**: the host field used to surface URLs for Grafana, ClickHouse, Kafka, and the sniff-web UI itself is now the IPv4 address of the currently-captured interface (via `psutil.net_if_addrs()`), with the previous behavior as fallback.
### Changed
- `POST /api/capture/start` response now includes a `sniff_producer` block with `config_updated`, `config_msg`, `restarted`, `restart_msg` so the UI can surface sync failures.

## [v0.3.0] - earlier
- Initial public release (DEPLOYMENT.md baseline).
