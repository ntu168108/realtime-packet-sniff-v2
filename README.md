# realtime-packet-sniff 🛰️

> Real-time packet capture, decoding, and IDS pipeline for Linux.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux-lightgrey.svg)]()
[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](CHANGELOG.md)
[![Docs](https://img.shields.io/badge/docs-mkdocs--material-blue.svg)](https://ntu168108.github.io/realtime-packet-sniff-v2/)

**📖 [Full documentation → ntu168108.github.io/realtime-packet-sniff-v2](https://ntu168108.github.io/realtime-packet-sniff-v2/)**

---

SNIFF is a real-time packet capture tool with an interactive TUI, a background
daemon, and a live NDJSON stream mode. The same capture engine feeds a full
IDS pipeline that streams pcap segments to Kafka, extracts per-flow features
with Argus + Zeek, classifies them against the UNSW-NB15 attack taxonomy with
seven per-family feature filters (and a rule-based DoS scoring engine),
and ships results to ClickHouse for visualisation in Grafana.

**🇻🇳 [Tài liệu tiếng Việt](https://ntu168108.github.io/realtime-packet-sniff-v2/vi/)**

---

## Quick install

```bash
curl -fsSL https://raw.githubusercontent.com/ntu168108/realtime-packet-sniff-v2/main/install.sh -o /tmp/install.sh && sudo bash /tmp/install.sh --verbose
```

This installs the `sniff` CLI and its `scapy` dependency. The full IDS
pipeline (Kafka, ClickHouse, Grafana, Argus, Zeek) is documented in the
[Deployment guide](https://ntu168108.github.io/realtime-packet-sniff-v2/operations/deployment/).

## License

[MIT](LICENSE) — see the `LICENSE` file.

## Acknowledgements

- [UNSW-NB15 dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset) and its feature scheme.
- [Argus](https://openargus.org/), [Zeek](https://zeek.org/) for per-flow feature extraction.
- [Scapy](https://scapy.net/) for the libpcap capture backend.
- [Apache Kafka](https://kafka.apache.org/), [ClickHouse](https://clickhouse.com/), [Grafana](https://grafana.com/) for storage and observability.
