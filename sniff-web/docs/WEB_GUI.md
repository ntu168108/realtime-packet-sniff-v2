# SNIFF Web GUI

> Web-based control panel for `realtime-packet-sniff`. Replaces the TUI for capture
> control and adds a single pane of glass for managing Kafka, ClickHouse, services,
> PCAP files, and config.

## Architecture (1-minute tour)

```
[ sniffer NIC ] ─── libpcap ──▶ [ CaptureEngine ] ──▶ [ asyncio.Queue ]
                                                   │
                                                   └─▶ [ WebSocket clients ]
                                                   └─▶ [ /api/capture/status ]

[ systemd ] ◀── sudoers NOPASSWD ── [ sniff-web (User=tu) ] ──▶ [ Kafka / ClickHouse / PCAP dir ]
```

`sniff-web` runs as `tu` with `setcap cap_net_admin,cap_net_raw+ep` on Python
(capture raw socket without root) and a restricted `sudoers` rule allowing only
`systemctl {start,stop,restart,enable,disable}` on 6 known services.

## Install

```bash
git clone https://github.com/ntu168108/realtime-packet-sniff.git
cd realtime-packet-sniff
sudo bash sniff-web/scripts/install_web.sh
```

Open `http://<server>:8000`. Default credentials: `admin` / `sniff`.

**Change the password before exposing to LAN:**

```bash
python3 -c "import bcrypt; print(bcrypt.hashpw(b'NEW_PASS', bcrypt.gensalt()).decode())"
# paste output into config.yaml under web.password_hash
sudo systemctl restart sniff-web
```

## Pages

| Route | Purpose |
|---|---|
| `/dashboard` | Service status grid + ClickHouse counts |
| `/capture` | Start/stop/pause capture; live packet table |
| `/services` | Per-service start/stop/restart |
| `/pcap` | List + download rotated PCAP files |
| `/kafka` | Topic list + consumer-group lag |
| `/clickhouse` | Read-only SQL console with 4 presets |
| `/config` | Edit display.display_filter (read-only view of full config) |
| `/system` | Hostname, uptime, CPU/mem/disk/NIC stats |

## Auto-restore on reboot

The last capture config is persisted to `/var/lib/sniff-web/last_capture.json`
on every `POST /api/capture/start`. When `sniff-web.service` starts (after a
reboot), if `auto_restore: true` was set on the last start, the same interface
+ BPF + snaplen + promisc are restored.

## Hardening notes

- Web GUI binds `0.0.0.0:8000` by default; restrict via firewall or bind
  `127.0.0.1` (edit `config.yaml` `web.bind`).
- `systemd` unit runs with `NoNewPrivileges`, `ProtectSystem=strict`,
  `ProtectHome=read-only`, `PrivateTmp=true`.
- `sudoers` rule is allowlist — adding a new service requires explicit edit.
- ClickHouse SQL is allowlist-prefixed (SELECT/SHOW/DESCRIBE/EXISTS only).
- Config writes are allowlist-keyed (display/live/modules/performance only).

## Out of scope (per spec)

- Deep packet decode (`deep=False`).
- LDAP / OAuth authentication.
- Mobile responsive UI (desktop ≥ 1024 px).
- Replacing `sniff-producer.service` (it stays; web GUI is a control panel).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `No readable meta.properties` | Kafka storage stale | `sudo systemctl stop kafka && sudo rm -rf /var/lib/kafka-logs/* && sudo -E /opt/kafka/bin/kafka-storage.sh format -t $(uuidgen) -c /opt/kafka/config/server.properties && sudo systemctl start kafka` |
| `sudo: a password is required` on service control | sudoers rule missing | Re-run `sudo bash sniff-web/scripts/install_web.sh` |
| Capture starts but no packets | interface down or wrong BPF | Check `ip link`; try empty BPF filter |
| WebSocket disconnects often | network jitter | `useWebSocket` auto-reconnects every 2s |
| `401 Unauthorized` on every endpoint | JWT expired | Logout + login again (24h expiry) |
