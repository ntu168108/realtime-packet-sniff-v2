# Quickstart

Get from a fresh Ubuntu box to your first captured packets in under 5 minutes.

## Prerequisites

- Linux (Ubuntu 22.04 / 24.04 LTS tested)
- Python 3.8+
- Root or `sudo` access (raw sockets need CAP_NET_RAW)
- A network interface to capture on

## One-line install

```bash
curl -fsSL https://raw.githubusercontent.com/ntu168108/realtime-packet-sniff-v2/main/install.sh -o /tmp/install.sh && sudo bash /tmp/install.sh --verbose
```

The installer:

1. Checks for `python3`, `pip`, `libpcap`, and ≥ 200 MB free disk.
2. Installs `scapy` and the `sniff` command via `pip install .`.
3. Optionally installs the systemd daemon unit (`--skip-systemd` to opt out).

## First capture

```bash
# Interactive menu (lists interfaces, lets you pick)
sudo sniff

# Direct: capture on eth0 with live NDJSON stream
sudo sniff -i eth0 --live | jq .

# Direct: capture on eth0 with a kernel BPF filter
sudo sniff -i eth0 -f "tcp port 443"
```

## Daemon mode

```bash
sudo sniff -i eth0 -d              # background daemon
sudo sniff --status                 # check it
sudo sniff --stop                   # graceful then SIGKILL
```

Daemon writes PCAPs to `./sniff_data/` (or `/var/lib/sniff-web/sniff_data/` under systemd — see [Configuration](configuration.md)).

## What's next?

- **Build the full IDS pipeline** (Kafka + ClickHouse + Grafana + Argus + Zeek) → see [Deployment](../operations/deployment.md)
- **Understand the data flow** → see [Architecture](../operations/architecture.md)
- **Hit a wall?** → see [Troubleshooting](../operations/troubleshooting.md)
- **Prefer Vietnamese?** → use the language switcher in the top bar.