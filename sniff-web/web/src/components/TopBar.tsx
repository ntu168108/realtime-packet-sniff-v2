import { useEffect, useState } from 'react';
import { useApi } from '../hooks/useApi';
import type { SystemInfo } from '../types';

export function TopBar({ user, onLogout }: { user: string; onLogout: () => void }) {
  const api = useApi();
  const [info, setInfo] = useState<SystemInfo | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const d = await api.get<SystemInfo>('/api/system/info');
        if (!cancelled) setInfo(d);
      } catch { /* swallow */ }
    };
    load();
    const t = setInterval(load, 30000);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  return (
    <header className="topbar">
      <span className="logo">SNIFF</span>
      {info && (
        <span className="muted mono" style={{ fontSize: 12 }}>
          uptime {Math.floor(info.uptime_seconds / 3600)}h
          {' · '}load {info.loadavg.map((n) => n.toFixed(2)).join(' ')}
          {' · '}{info.cpu_count} CPUs
        </span>
      )}
      <span className="grow" />
      <span className="user">{user}</span>
      <button onClick={onLogout}>Logout</button>
    </header>
  );
}