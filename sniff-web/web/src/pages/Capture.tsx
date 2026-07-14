import { useCallback, useEffect, useState, useRef } from 'react';
import { useApi } from '../hooks/useApi';
import { useWebSocket } from '../hooks/useWebSocket';
import { PacketTableInner } from '../components/PacketTable';
import { ProtocolBars } from '../components/ProtocolBars';
import { ApiError } from '../hooks/useApi';
import type { InterfaceInfo, CaptureStatus, PacketRow, LastConfig, TopTalker } from '../types';

const MAX_PACKETS = 5000;

function fmtDuration(seconds: number): string {
  const s = Math.floor(seconds);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  return h > 0 ? `${h}h ${m}m ${sec}s` : m > 0 ? `${m}m ${sec}s` : `${sec}s`;
}

export default function Capture() {
  const api = useApi();
  const [interfaces, setInterfaces] = useState<InterfaceInfo[]>([]);
  const [status, setStatus] = useState<CaptureStatus | null>(null);
  const [iface, setIface] = useState<string>('');
  const [bpf, setBpf] = useState('');
  const [snaplen, setSnaplen] = useState(65535);
  const [promisc, setPromisc] = useState(true);
  const [autoRestore, setAutoRestore] = useState(true);
  const [packets, setPackets] = useState<PacketRow[]>([]);
  const [autoScroll, setAutoScroll] = useState(true);
  const [tableFilter, setTableFilter] = useState('');
  const parentRef = useRef<HTMLDivElement>(null);
  const [error, setError] = useState<string | null>(null);
  const [diagnostic, setDiagnostic] = useState<string | null>(null);
  const [lastConfig, setLastConfig] = useState<LastConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [deepDecode, setDeepDecode] = useState(false);
  const [conversations, setConversations] = useState<TopTalker[]>([]);

  // Stats WS for status
  useWebSocket<{ type: string; data: CaptureStatus }>('/ws/stats', (msg) => {
    if (msg.type === 'stats') setStatus(msg.data);
  });

  // Packets WS — append + trim
  useWebSocket<{ type: string; data: PacketRow[] }>('/ws/packets', (msg) => {
    if (msg.type === 'packets' && msg.data?.length) {
      setPackets((prev) => {
        const next = [...prev, ...msg.data];
        return next.length > MAX_PACKETS ? next.slice(next.length - MAX_PACKETS) : next;
      });
    }
  });

  useEffect(() => {
    (async () => {
      try {
        const ifs = await api.get<InterfaceInfo[]>('/api/interfaces');
        setInterfaces(ifs);
        if (ifs.length && !iface) setIface(ifs[0].name);
      } catch (e: unknown) {
        // 503 from /api/interfaces means the backend couldn't import core.capture.
        // Show a diagnostic so the operator knows where to look.
        const msg = e instanceof ApiError && e.status === 503
          ? 'core.capture unavailable — sniff-web could not import core.capture.'
          : e instanceof Error ? e.message : String(e);
        setError(msg);
        if (e instanceof ApiError && e.status === 503) {
          setDiagnostic(
            'The backend tried to import `core.capture` but the module is unreachable.\n' +
            'Most common cause: PYTHONPATH does not include the repo root.\n' +
            'Fix on the server:\n' +
            '  1. systemctl cat sniff-web | grep -i PYTHONPATH\n' +
            '  2. The line should end with :<repo-root>, e.g.\n' +
            '       Environment=PYTHONPATH=...site-packages:/opt/realtime-packet-sniff\n' +
            '  3. sudo systemctl daemon-reload && sudo systemctl restart sniff-web\n' +
            '  4. journalctl -u sniff-web -n 80 --no-pager  (look for the import error)'
          );
        }
      }
      try {
        const lc = await api.get<LastConfig>('/api/capture/last-config');
        setLastConfig(lc);
        setIface(lc.interface);
        setBpf(lc.bpf_filter || '');
        setSnaplen(lc.snaplen);
        setPromisc(lc.promisc);
        setAutoRestore(lc.auto_restore);
      } catch {
        /* no last config — first run */
      } finally {
        setLoading(false);
      }
      try {
        const dd = await api.get<{ enabled: boolean }>('/api/capture/deep-decode');
        setDeepDecode(dd.enabled);
      } catch {
        /* leave default */
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Live top conversations from the capture engine itself (not the ClickHouse-
  // classified ones on the Dashboard) — only meaningful while running.
  useEffect(() => {
    if (!status?.running) { setConversations([]); return; }
    let cancelled = false;
    const load = async () => {
      try {
        const c = await api.get<TopTalker[]>('/api/capture/conversations?n=10');
        if (!cancelled) setConversations(c);
      } catch {
        /* transient — keep last value */
      }
    };
    load();
    const t = setInterval(load, 3000);
    return () => { cancelled = true; clearInterval(t); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status?.running]);

  async function toggleDeepDecode() {
    const next = !deepDecode;
    setDeepDecode(next); // optimistic
    try {
      await api.post('/api/capture/deep-decode', { enabled: next });
    } catch (e: unknown) {
      setDeepDecode(!next); // revert on failure
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    setDiagnostic(null);
    try {
      const ifs = await api.get<InterfaceInfo[]>('/api/interfaces');
      setInterfaces(ifs);
      if (ifs.length && !iface) setIface(ifs[0].name);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [api, iface]);

  async function start() {
    setError(null);
    try {
      await api.post('/api/capture/start', {
        interface: iface,
        bpf_filter: bpf,
        snaplen,
        promisc,
        auto_restore: autoRestore,
      });
      setPackets([]);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }
  async function stop() {
    try {
      await api.post('/api/capture/stop');
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }
  async function togglePause() {
    try {
      await api.post('/api/capture/toggle-pause');
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 56px - 32px)' }}>
      <div className="card">
        <h2>Capture control</h2>
        {error && (
          <div className="error">
            <div>{error}</div>
            {diagnostic && (
              <pre
                className="mono"
                style={{
                  fontSize: 11,
                  whiteSpace: 'pre-wrap',
                  marginTop: 8,
                  padding: 8,
                  background: 'var(--surf2)',
                  borderRadius: 4,
                }}
              >
                {diagnostic}
              </pre>
            )}
          </div>
        )}
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div>
            <label className="muted" style={{ fontSize: 11 }}>
              Interface
            </label>
            <br />
            {interfaces.length === 0 ? (
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <span className="muted mono" style={{ fontSize: 12 }}>
                  {loading ? 'loading…' : 'none detected'}
                </span>
                <button className="btn ghost" onClick={reload} disabled={loading}>
                  Reload
                </button>
              </div>
            ) : (
              <select
                value={iface}
                onChange={(e) => setIface(e.target.value)}
                disabled={!!status?.running}
              >
                {interfaces.map((i) => (
                  <option key={i.name} value={i.name}>
                    {i.name} ({i.ipv4 || 'no IP'})
                  </option>
                ))}
              </select>
            )}
          </div>
          <div>
            <label className="muted" style={{ fontSize: 11 }}>
              BPF filter
            </label>
            <br />
            <input
              value={bpf}
              onChange={(e) => setBpf(e.target.value)}
              placeholder="tcp port 80"
              style={{ width: 280 }}
              disabled={!!status?.running}
            />
          </div>
          <div>
            <label className="muted" style={{ fontSize: 11 }}>
              Snaplen
            </label>
            <br />
            <input
              type="number"
              value={snaplen}
              onChange={(e) => setSnaplen(parseInt(e.target.value) || 65535)}
              style={{ width: 80 }}
              disabled={!!status?.running}
            />
          </div>
          <label className="muted" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <input
              type="checkbox"
              checked={promisc}
              onChange={(e) => setPromisc(e.target.checked)}
              disabled={!!status?.running}
            />
            promisc
          </label>
          <label className="muted" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <input
              type="checkbox"
              checked={autoRestore}
              onChange={(e) => setAutoRestore(e.target.checked)}
              disabled={!!status?.running}
            />
            auto-restore on reboot
          </label>
          <label className="muted" style={{ display: 'flex', alignItems: 'center', gap: 4 }} title="Adds DNS/HTTP/TLS SNI/DHCP/NTP/QUIC to the Info column. Costs more CPU per packet.">
            <input
              type="checkbox"
              checked={deepDecode}
              onChange={toggleDeepDecode}
            />
            deep decode (L7)
          </label>
          <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
            {!status?.running ? (
              <button className="btn" onClick={start} disabled={!iface}>
                Start
              </button>
            ) : (
              <>
                <button className="btn warn" onClick={togglePause}>
                  {status.paused ? 'Resume' : 'Pause'}
                </button>
                <button className="btn danger" onClick={stop}>
                  Stop
                </button>
              </>
            )}
          </div>
        </div>
        {status && (
          <>
            <div style={{ marginTop: 12, display: 'flex', gap: 24, flexWrap: 'wrap', alignItems: 'center' }}>
              <span className={`pill ${status.running ? (status.paused ? 'paused' : 'active') : 'stopped'}`}>
                {status.running ? (status.paused ? 'paused' : 'running') : 'stopped'}
              </span>
              {status.running && (
                <>
                  <span className="mono">
                    on <strong>{status.interface ?? '—'}</strong>
                  </span>
                  <span className="mono">
                    up <strong>{fmtDuration(status.uptime)}</strong>
                  </span>
                </>
              )}
              <span className="mono">
                <strong>{status.packets.toLocaleString()}</strong> packets
              </span>
              <span className="mono">
                <strong>{status.pps.toLocaleString()}</strong> pps
              </span>
              <span className="mono">
                <strong>{(status.bps / 1024).toFixed(1)}</strong> KB/s
              </span>
              <span className="mono" title="ring-buffer overflow / pcap write backlog">
                <strong>{status.dropped.toLocaleString()}</strong> dropped
                {(status.queue_dropped ?? 0) > 0 || (status.write_dropped ?? 0) > 0 ? (
                  <span className="muted"> (queue {(status.queue_dropped ?? 0).toLocaleString()}, write {(status.write_dropped ?? 0).toLocaleString()})</span>
                ) : null}
              </span>
            </div>
            {status.running && (status.queue_capacity ?? 0) > 0 && (
              <div style={{ marginTop: 10 }}>
                {(() => {
                  const cap = status.queue_capacity ?? 1;
                  const size = status.queue_size ?? 0;
                  const pct = Math.min(100, (size / cap) * 100);
                  const barColor = pct >= 90 ? 'var(--danger)' : pct >= 60 ? 'var(--warn)' : 'var(--success)';
                  return (
                    <>
                      <div className="gauge-label" style={{ marginBottom: 4 }}>
                        Ring buffer — {size.toLocaleString()} / {cap.toLocaleString()} ({pct.toFixed(0)}%)
                      </div>
                      <div className="proto-bar-track">
                        <div className="proto-bar-fill" style={{ width: `${pct}%`, background: barColor }} />
                      </div>
                    </>
                  );
                })()}
              </div>
            )}
          </>
        )}
      </div>

      <div className="card" style={{ flex: 1, overflow: 'hidden', padding: 0 }}>
        <PacketTableInner
          packets={packets}
          filter={tableFilter}
          setFilter={setTableFilter}
          autoScroll={autoScroll}
          setAutoScroll={setAutoScroll}
          parentRef={parentRef}
          onAppend={() => {}}
        />
      </div>

      {status?.running && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginTop: 12 }}>
          <div className="card" style={{ marginBottom: 0 }}>
            <h2>Protocol breakdown</h2>
            <ProtocolBars counts={status.protocols ?? {}} />
          </div>
          <div className="card" style={{ marginBottom: 0 }}>
            <h2>Live conversations</h2>
            <div className="top-talkers">
              {conversations.map((t) => (
                <div className="top-row" key={`${t.src}->${t.dst}-${t.proto}`}>
                  <div className="top-flow">
                    <span className="muted">{t.proto}</span>&nbsp;
                    {t.src} → {t.dst}
                  </div>
                  <div className="top-bytes">{(t.bytes / 1024).toFixed(1)} KB</div>
                  <div className="top-pkts">{t.packets.toLocaleString()} pkts</div>
                </div>
              ))}
              {conversations.length === 0 && (
                <div className="muted" style={{ padding: 8 }}>No conversations yet.</div>
              )}
            </div>
          </div>
        </div>
      )}

      {lastConfig && (
        <div className="card" style={{ marginTop: 12 }}>
          <h2>Last persisted config</h2>
          <pre
            className="mono"
            style={{ fontSize: 12, margin: 0, whiteSpace: 'pre-wrap', color: 'var(--muted)' }}
          >
{`interface      : ${lastConfig.interface}
bpf_filter     : ${lastConfig.bpf_filter || '(none)'}
snaplen        : ${lastConfig.snaplen}
promisc        : ${lastConfig.promisc}
auto_restore   : ${lastConfig.auto_restore}
saved_at       : ${lastConfig.saved_at}`}
          </pre>
        </div>
      )}
    </div>
  );
}