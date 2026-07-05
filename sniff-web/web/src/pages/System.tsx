import { useEffect, useState } from 'react';
import { useApi } from '../hooks/useApi';
import { CountCard } from '../components/CountCard';
import type { SystemInfo } from '../types';

export default function System() {
  const api = useApi();
  const [info, setInfo] = useState<SystemInfo | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try { setInfo(await api.get<SystemInfo>('/api/system/info')); }
      catch (e: any) { setError(e.message); }
    })();
  }, []);

  if (error) return <div className="error">{error}</div>;
  if (!info) return <p className="muted">Loading...</p>;

  return (
    <div>
      <h1 style={{ marginTop: 0 }}>System</h1>
      <div className="card">
        <h2>Host</h2>
        <p>hostname: <span className="mono">{info.hostname}</span></p>
        <p>uptime: <span className="mono">{Math.floor(info.uptime_seconds / 3600)}h {Math.floor((info.uptime_seconds % 3600) / 60)}m</span></p>
      </div>
      <div className="card">
        <h2>Resources</h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(150px, 1fr))', gap: 8 }}>
          <CountCard label="CPUs" value={info.cpu_count} />
          <CountCard label="load 1m" value={info.loadavg[0]} />
          <CountCard label="load 5m" value={info.loadavg[1]} />
          <CountCard label="load 15m" value={info.loadavg[2]} />
          <CountCard label="mem total (MB)" value={info.mem_total_mb} />
          <CountCard label="mem avail (MB)" value={info.mem_available_mb} />
          <CountCard label="disk total (GB)" value={info.disk_total_gb} />
          <CountCard label="disk used (GB)" value={info.disk_used_gb} />
          <CountCard label="NICs" value={info.nic_count} />
        </div>
      </div>
    </div>
  );
}