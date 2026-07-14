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
| `/dashboard` | Live traffic gauges/sparklines, ClickHouse per-family attack counts + donut charts, protocol breakdown, services + Grafana link, top talkers, recent alerts |
| `/capture` | Start/stop/pause capture; live packet table (with MAC addresses); ring buffer fill + drop-cause breakdown; deep-decode (L7) toggle; live conversations; protocol breakdown |
| `/services` | Per-service start/stop/restart |
| `/pcap` | List + download rotated PCAP files |
| `/kafka` | Topic list + consumer-group lag |
| `/clickhouse` | Read-only SQL console with 4 presets; deep-links from Dashboard cards via `?table=<name>` auto-run a detail query |
| `/config` | Edit display.display_filter (read-only view of full config) |

`/system` (hostname/uptime/CPU/mem/disk/NIC) was **removed 2026-07-14** — it
showed host-machine info irrelevant to the IDS's job. If you're on an older
checkout and still see it, `git pull`.

### Dashboard: reading the ClickHouse cards correctly

All 7 `flows_<family>` tables score the **same underlying flow set** (see
[architecture.md § Per-family tables](../../docs/operations/architecture.md#per-family-tables)) —
every flow is written to every family table, `is_attack=1` in at most one of
them. A naive `SELECT count() FROM flows_dos` is therefore **identical**
across all 7 tables and tells you nothing about classification — it looked
like fabricated/uniform data even though the schema is correct by design.

`_clickhouse_counts_safe()` (backend, feeds `/api/dashboard/summary.counts`)
and `GET /api/clickhouse/counts` both query
`SELECT count() FROM flows_<family> WHERE is_attack = 1` per family instead,
so the Dashboard cards and the "Attack family share" donut show real,
differing numbers. `flows_all` stays a true total (no `WHERE`). If you add a
new consumer of these counts, keep this in mind — don't regress to a plain
`count()` per family.

### Capture page: deep decode (L7) toggle

The live packet table's `Info` column defaults to the **fast** decode path
(`core.decoder.decode_packet(data, deep=False)`) — TCP flags/seq, UDP length,
ICMP type, no CPU cost beyond L2-L4 headers. Ethernet `src_mac`/`dst_mac` are
part of that fast path too (Layer 2, always parsed) so MAC addresses show up
in the table with zero extra cost, regardless of the toggle.

Checking **"deep decode (L7)"** flips a module-level flag in `web_server.py`
(`_deep_decode_enabled`, via `GET/POST /api/capture/deep-decode`) that makes
`_broadcast_packets()` call `decode_packet(data, deep=True)` instead — adding
DNS query names, HTTP method/host, TLS SNI, DHCP, NTP, QUIC info to the `Info`
column. This is CPU-heavier per packet, hence off by default and **not**
persisted across a `sniff-web` restart (always resets to `False` on boot).

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

- Deep packet decode **on by default** — it's available as an opt-in toggle
  on `/capture` (see above), but the live table still defaults to the fast
  path; deep decode is never forced on for every packet automatically.
- LDAP / OAuth authentication.
- Mobile responsive UI (desktop ≥ 1024 px).
- Replacing `sniff-producer.service` (it stays; web GUI is a control panel).

## Frontend theme & design notes (for future UI work)

- Plain React + Vite + hand-rolled CSS (`sniff-web/web/src/styles/global.css`)
  — **no Tailwind, no component library, no animation library** (Framer
  Motion/GSAP/etc.). This is intentional: the app is small enough that a CSS
  framework or motion library would be pure overhead. Charts (`Sparkline`,
  `Gauge`, `DonutChart`, `ProtocolBars`) are all inline SVG built by hand.
  Keep it that way unless the app's scope changes substantially — don't add
  a dependency to solve something 20 lines of CSS/SVG already solves.
- Color tokens live in `:root` in `global.css`. Current palette ("Obsidian"):
  off-black background (`--bg: #0a0a0c`), single accent
  `--accent: #4a7ba6` (muted slate-blue — history: was cyan originally, then
  ember/amber, now this; if changing again, keep it to **one** desaturated
  accent color, not neon/purple). Headline text/numbers use
  `--text-bright: #ffffff`; body text uses the softer `--text`.
- `prefers-reduced-motion: reduce` is handled globally (one rule caps all
  `animation`/`transition` durations near-zero) — new animations don't need
  their own reduced-motion override, that global rule already covers them.
- An ambient scanline/vignette `body::after` overlay was tried and then
  **removed** (reported as visually cluttered) — don't re-add a full-page
  texture overlay without checking with whoever's driving the design first.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `No readable meta.properties` | Kafka storage stale | `sudo systemctl stop kafka && sudo rm -rf /var/lib/kafka-logs/* && sudo -E /opt/kafka/bin/kafka-storage.sh format -t $(uuidgen) -c /opt/kafka/config/server.properties && sudo systemctl start kafka` |
| `sudo: a password is required` on service control | sudoers rule missing | Re-run `sudo bash sniff-web/scripts/install_web.sh` |
| Capture starts but no packets | interface down or wrong BPF | Check `ip link`; try empty BPF filter |
| WebSocket disconnects often | network jitter | `useWebSocket` auto-reconnects every 2s |
| `401 Unauthorized` on every endpoint | JWT expired | Logout + login again (24h expiry) |
