import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useApi } from '../hooks/useApi';
import { useWebSocket } from '../hooks/useWebSocket';
import { CountCard } from '../components/CountCard';
import { Sparkline } from '../components/Sparkline';
import { Gauge } from '../components/Gauge';
import { ProtocolBars, DEFAULT_PALETTE as PROTO_PALETTE } from '../components/ProtocolBars';
import { AlertFeed } from '../components/AlertFeed';
import { DonutChart, type DonutSlice } from '../components/DonutChart';
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
  // Rolling peak of the live (WS) values, not just the last 10s summary snapshot —
  // otherwise a small live spike between summary polls could exceed a stale max
  // and instantly peg the gauge into the red.
  const [livePeak, setLivePeak] = useState({ pps: 0, bps: 0 });

  // Live capture stats — overrides the summary's stale capture object
  useWebSocket<{ type: string; data: CaptureStatus }>('/ws/stats', (msg) => {
    if (msg.type === 'stats') {
      setCapture(msg.data);
      setLivePeak((p) => ({
        pps: Math.max(p.pps, msg.data.pps ?? 0),
        bps: Math.max(p.bps, msg.data.bps ?? 0),
      }));
    }
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

  // Compute the max for gauges from sparkline history AND the live WS peak, with
  // generous headroom (2x) so normal fluctuation doesn't peg the needle into red —
  // the danger zone should mean "near capacity", not "traffic moved a bit".
  const ppsHistory = summary?.rate_history?.pps ?? [];
  const bpsHistory = summary?.rate_history?.bps ?? [];
  const ppsMax = useMemo(
    () => Math.max(100, livePeak.pps * 2, ...ppsHistory.map((v) => v * 2)),
    [ppsHistory, livePeak.pps],
  );
  const bpsMax = useMemo(
    () => Math.max(1024, livePeak.bps * 2, ...bpsHistory.map((v) => v * 2)),
    [bpsHistory, livePeak.bps],
  );

  const protocolCounts = liveCapture?.protocols ?? summary?.protocols ?? {};
  const protocolSlices: DonutSlice[] = useMemo(
    () => Object.entries(protocolCounts)
      .filter(([, n]) => n > 0)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
      .map(([name, value]) => ({ name, value, color: PROTO_PALETTE[name] ?? 'var(--accent)' })),
    [protocolCounts],
  );
  const totalPackets = protocolSlices.reduce((s, x) => s + x.value, 0);

  const ATTACK_FAMILY_COLORS: Record<string, string> = {
    dos: '#c8506a', exploits: '#d97a3f', fuzzers: '#d99a3f',
    generic: '#726e68', analysis: '#3aa66d', reconnaissance: '#8a6a4f', shellcode: '#a85a7a',
  };
  const attackSlices: DonutSlice[] = useMemo(() => {
    const c = summary?.counts;
    if (!c) return [];
    return (['dos', 'exploits', 'fuzzers', 'generic', 'analysis', 'reconnaissance', 'shellcode'] as const)
      .map((fam) => ({ name: fam, value: c[`flows_${fam}` as keyof typeof c] ?? 0, color: ATTACK_FAMILY_COLORS[fam] }))
      .filter((s) => s.value > 0);
  }, [summary?.counts]);
  const totalAttackFlows = attackSlices.reduce((s, x) => s + x.value, 0);

  return (
    <div className="dash-page">
      <h1 style={{ marginTop: 0 }}>Dashboard</h1>
      {error && <div className="error">{error}</div>}

      {/* ---------- ZONE 1: sticky traffic header ---------- */}
      <div className={`card ${liveCapture?.running ? 'card-live' : ''}`}>
        <h2>
          {liveCapture?.running && <span className="live-dot" aria-hidden="true" />}
          Live traffic
        </h2>
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
            <Sparkline values={ppsHistory} unit="pps" ariaLabel="packets per second history" />
            <div className="gauge-label" style={{ marginTop: 8 }}>KB/s — last 5 min</div>
            <Sparkline values={bpsHistory.map((b) => b / 1024)} unit="KB/s" stroke="var(--success)" fill="var(--success)" ariaLabel="kilobytes per second history" />
          </div>
        </div>
      </div>

      {/* ---------- ZONE 2 (was 3): ClickHouse counts + protocols — has charts, kept high ---------- */}
      <div className="dash-zone-charts">
        <div className="card">
          <h2>ClickHouse flow counts</h2>
          {attackSlices.length > 0 && (
            <div>
              <div className="gauge-label" style={{ marginBottom: 10, fontSize: 13 }}>Attack family share</div>
              <DonutChart
                slices={attackSlices}
                size={200}
                thickness={22}
                centerValue={totalAttackFlows.toLocaleString()}
                centerLabel="flows"
                ariaLabel="attack family breakdown"
              />
            </div>
          )}
          <div className="muted" style={{ fontSize: 11, marginTop: 16, marginBottom: 8 }}>
            flows_all = total flows ingested. Per-family cards below = flows classified as that family's attack (is_attack=1), not raw row counts.
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(190px, 1fr))', gap: 12 }}>
            <CountCard label="flows_all (total)"  value={summary?.counts?.flows_all ?? null} to="/clickhouse?table=flows_all" size="lg" />
            <CountCard label="dos attacks"                value={summary?.counts?.flows_dos ?? null} to="/clickhouse?table=flows_dos" />
            <CountCard label="exploits attacks"           value={summary?.counts?.flows_exploits ?? null} to="/clickhouse?table=flows_exploits" />
            <CountCard label="fuzzers attacks"            value={summary?.counts?.flows_fuzzers ?? null} to="/clickhouse?table=flows_fuzzers" />
            <CountCard label="generic attacks"            value={summary?.counts?.flows_generic ?? null} to="/clickhouse?table=flows_generic" />
            <CountCard label="analysis attacks"           value={summary?.counts?.flows_analysis ?? null} to="/clickhouse?table=flows_analysis" />
            <CountCard label="reconnaissance attacks"     value={summary?.counts?.flows_reconnaissance ?? null} to="/clickhouse?table=flows_reconnaissance" />
            <CountCard label="shellcode attacks"          value={summary?.counts?.flows_shellcode ?? null} to="/clickhouse?table=flows_shellcode" />
            <CountCard label="pipeline_runs"      value={summary?.counts?.pipeline_runs ?? null} to="/clickhouse?table=pipeline_runs" />
          </div>
        </div>
        <div className="card">
          <h2>Protocol breakdown</h2>
          <DonutChart
            slices={protocolSlices}
            size={200}
            thickness={22}
            centerValue={totalPackets.toLocaleString()}
            centerLabel="packets"
            ariaLabel="protocol breakdown"
          />
          <div style={{ marginTop: 20 }}>
            <ProtocolBars counts={liveCapture?.protocols ?? summary?.protocols ?? {}} />
          </div>
        </div>
      </div>

      {/* ---------- ZONE 3 (was 2): services + Grafana — no chart, pushed below the chart zones ---------- */}
      <div className="dash-zone-mid">
        <div className="card">
          <h2>Services</h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: 8 }}>
            {(services.length ? services : summary?.services ?? []).map((s) => (
              <Link key={s.name} to="/services" className="card-link">
                <div className="card" style={{ padding: 8, marginBottom: 0 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span className="mono">{s.name}</span>
                    <span className={`pill ${s.active ? 'active' : 'inactive'}`}>
                      {s.active ? 'active' : 'inactive'}
                    </span>
                  </div>
                </div>
              </Link>
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

      {/* ---------- ZONE 4: top talkers + alerts — plain lists, no chart, stay last ---------- */}
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
