import { useEffect, useMemo, useState } from 'react';
import { useApi } from '../hooks/useApi';
import { useWebSocket } from '../hooks/useWebSocket';
import { CountCard } from '../components/CountCard';
import { Sparkline } from '../components/Sparkline';
import { Gauge } from '../components/Gauge';
import { ProtocolBars } from '../components/ProtocolBars';
import { AlertFeed } from '../components/AlertFeed';
import type { CaptureStatus, DashboardSummary, ServiceStatus } from '../types';

/**
 * NDR-style Dashboard.
 * - Zone 1 (sticky traffic): PPS / BPS gauges + counters, live via /ws/stats
 * - Zone 2: services status grid + Grafana link/embed
 * - Zone 3: ClickHouse counts + pps/bps sparkline + protocol breakdown
 * - Zone 4: top talkers + recent alerts
 *
 * Everything is one /api/dashboard/summary round-trip + WS for live capture stats.
 */
export default function Dashboard() {
  const api = useApi();
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [capture, setCapture] = useState<CaptureStatus | null>(null);
  const [services, setServices] = useState<ServiceStatus[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [showEmbed, setShowEmbed] = useState(false);

  // Live capture stats — overrides the summary's stale capture object
  useWebSocket<{ type: string; data: CaptureStatus }>('/ws/stats', (msg) => {
    if (msg.type === 'stats') setCapture(msg.data);
  });

  // Live services status
  useWebSocket<{ type: string; data: ServiceStatus[] }>('/ws/services', (msg) => {
    if (msg.type === 'services') setServices(msg.data);
  });

  // Initial + 10s refresh of the aggregate summary
  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const s = await api.get<DashboardSummary>('/api/dashboard/summary');
        if (!cancelled) setSummary(s);
      } catch (e: any) {
        if (!cancelled) setError(e.message);
      }
    };
    load();
    const t = setInterval(load, 10000);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  // Pick whichever capture status is fresher (WS > summary)
  const liveCapture = capture ?? summary?.capture ?? null;

  // Compute the max for gauges from the sparkline history (so the dial scales sensibly)
  const ppsHistory = summary?.rate_history?.pps ?? [];
  const bpsHistory = summary?.rate_history?.bps ?? [];
  const ppsMax = useMemo(() => Math.max(100, ...ppsHistory.map((v) => v * 1.2)), [ppsHistory]);
  const bpsMax = useMemo(() => Math.max(1024, ...bpsHistory.map((v) => v * 1.2)), [bpsHistory]);

  return (
    <div>
      <h1 style={{ marginTop: 0 }}>Dashboard</h1>
      {error && <div className="error">{error}</div>}

      {/* ---------- ZONE 1: sticky traffic header ---------- */}
      <div className="card">
        <h2>Live traffic</h2>
        <div className="dash-zone-traffic">
          <div className="card gauge-card" style={{ marginBottom: 0 }}>
            <Gauge
              value={liveCapture?.pps ?? 0}
              max={ppsMax}
              label="PPS"
              sub={`peak ${Math.max(0, ...ppsHistory).toFixed(0)}`}
            />
          </div>
          <div className="card gauge-card" style={{ marginBottom: 0 }}>
            <Gauge
              value={(liveCapture?.bps ?? 0) / 1024}
              max={Math.max(1, bpsMax / 1024)}
              label="KB/s"
              sub={`peak ${(Math.max(0, ...bpsHistory) / 1024).toFixed(1)}`}
            />
          </div>
          <div className="card" style={{ marginBottom: 0, display: 'flex', flexDirection: 'column', gap: 6 }}>
            <div className="gauge-label">Packets</div>
            <div className="gauge-value">{(liveCapture?.packets ?? 0).toLocaleString()}</div>
            <div className="gauge-sub">dropped {(liveCapture?.dropped ?? 0).toLocaleString()}</div>
            <div className="gauge-sub">
              interface: <strong>{liveCapture?.interface ?? '—'}</strong>
            </div>
            <div className="gauge-sub">
              status:&nbsp;
              <span
                className={`pill ${
                  liveCapture?.running
                    ? liveCapture?.paused ? 'paused' : 'active'
                    : 'stopped'
                }`}
              >
                {liveCapture?.running ? (liveCapture?.paused ? 'paused' : 'running') : 'stopped'}
              </span>
            </div>
          </div>
          <div className="card" style={{ marginBottom: 0 }}>
            <div className="gauge-label">PPS — last 5 min</div>
            <Sparkline values={ppsHistory} ariaLabel="packets per second history" />
            <div className="gauge-label" style={{ marginTop: 8 }}>KB/s — last 5 min</div>
            <Sparkline values={bpsHistory.map((b) => b / 1024)} stroke="var(--success)" fill="var(--success)" ariaLabel="kilobytes per second history" />
          </div>
        </div>
      </div>

      {/* ---------- ZONE 2: services + Grafana ---------- */}
      <div className="dash-zone-mid">
        <div className="card">
          <h2>Services</h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: 8 }}>
            {(services.length ? services : summary?.services ?? []).map((s) => (
              <div key={s.name} className="card" style={{ padding: 8, marginBottom: 0 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span className="mono">{s.name}</span>
                  <span className={`pill ${s.active ? 'active' : 'inactive'}`}>
                    {s.active ? 'active' : 'inactive'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
        <div className="card grafana-card">
          <h2>Live monitoring → Grafana</h2>
          {summary?.grafana_url ? (
            <>
              <div className="grafana-url">{summary.grafana_url}</div>
              <div className="grafana-row">
                <a className="btn" href={summary.grafana_url} target="_blank" rel="noopener noreferrer">
                  Open Grafana in new tab
                </a>
                <button className="btn ghost" onClick={() => setShowEmbed((v) => !v)}>
                  {showEmbed ? 'Hide embedded panel' : 'Show embedded panel'}
                </button>
              </div>
              {showEmbed && (
                <div className="grafana-embed">
                  <iframe
                    src={`${summary.grafana_url}?kiosk&theme=dark`}
                    title="Grafana"
                  />
                </div>
              )}
            </>
          ) : (
            <div className="muted">
              Grafana not configured. Set <code>web.grafana_url</code> in <code>config.yaml</code> to enable.
            </div>
          )}
        </div>
      </div>

      {/* ---------- ZONE 3: ClickHouse counts + protocols ---------- */}
      <div className="dash-zone-bot">
        <div className="card">
          <h2>ClickHouse flow counts</h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(150px, 1fr))', gap: 8 }}>
            <CountCard label="flows_all"          value={summary?.counts?.flows_all ?? null} />
            <CountCard label="dos"                value={summary?.counts?.flows_dos ?? null} />
            <CountCard label="exploits"           value={summary?.counts?.flows_exploits ?? null} />
            <CountCard label="fuzzers"            value={summary?.counts?.flows_fuzzers ?? null} />
            <CountCard label="generic"            value={summary?.counts?.flows_generic ?? null} />
            <CountCard label="analysis"           value={summary?.counts?.flows_analysis ?? null} />
            <CountCard label="reconnaissance"     value={summary?.counts?.flows_reconnaissance ?? null} />
            <CountCard label="shellcode"          value={summary?.counts?.flows_shellcode ?? null} />
            <CountCard label="pipeline_runs"      value={summary?.counts?.pipeline_runs ?? null} />
          </div>
        </div>
        <div className="card">
          <h2>Protocol breakdown</h2>
          <ProtocolBars counts={liveCapture?.protocols ?? summary?.protocols ?? {}} />
        </div>
      </div>

      {/* ---------- ZONE 4: top talkers + alerts ---------- */}
      <div className="dash-zone-bot">
        <div className="card">
          <h2>Top talkers</h2>
          <div className="top-talkers">
            {(summary?.top_talkers ?? []).slice(0, 8).map((t) => (
              <div className="top-row" key={`${t.src}->${t.dst}`}>
                <div className="top-flow">
                  <span className="muted">{t.proto}</span>&nbsp;
                  {t.src} → {t.dst}
                </div>
                <div className="top-bytes">{(t.bytes / 1024).toFixed(1)} KB</div>
                <div className="top-pkts">{t.packets.toLocaleString()} pkts</div>
              </div>
            ))}
            {(summary?.top_talkers ?? []).length === 0 && (
              <div className="muted" style={{ padding: 8 }}>
                No conversations yet — start a capture to populate.
              </div>
            )}
          </div>
        </div>
        <div className="card">
          <h2>Recent alerts</h2>
          <AlertFeed alerts={summary?.alerts_recent ?? []} />
        </div>
      </div>
    </div>
  );
}
