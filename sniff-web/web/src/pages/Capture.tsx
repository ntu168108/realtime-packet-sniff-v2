import { useCallback, useEffect, useState, useRef } from 'react';
import { useApi } from '../hooks/useApi';
import { useWebSocket } from '../hooks/useWebSocket';
import { PacketTableInner } from '../components/PacketTable';
import { ApiError } from '../hooks/useApi';
import type { InterfaceInfo, CaptureStatus, PacketRow, LastConfig } from '../types';

const MAX_PACKETS = 5000;

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
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

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
          <div style={{ marginTop: 12, display: 'flex', gap: 24, flexWrap: 'wrap' }}>
            <span className={`pill ${status.running ? (status.paused ? 'paused' : 'active') : 'stopped'}`}>
              {status.running ? (status.paused ? 'paused' : 'running') : 'stopped'}
            </span>
            <span className="mono">
              <strong>{status.packets.toLocaleString()}</strong> packets
            </span>
            <span className="mono">
              <strong>{status.pps.toLocaleString()}</strong> pps
            </span>
            <span className="mono">
              <strong>{(status.bps / 1024).toFixed(1)}</strong> KB/s
            </span>
            <span className="mono">
              <strong>{status.dropped.toLocaleString()}</strong> dropped
            </span>
          </div>
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