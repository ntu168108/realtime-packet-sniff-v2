import { useState } from 'react';
import { useApi } from '../hooks/useApi';

export function ServiceCard({ name, active }: { name: string; active: boolean }) {
  const api = useApi();
  const [busy, setBusy] = useState<string | null>(null);

  async function doAction(action: string) {
    setBusy(action);
    try {
      await api.post(`/api/services/${name}/${action}`);
    } catch (e: any) {
      alert(`Failed: ${e.message}`);
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="card">
      <h2>{name}</h2>
      <div style={{ marginBottom: 12 }}>
        <span className={`pill ${active ? 'active' : 'inactive'}`}>
          {active ? 'active' : 'inactive'}
        </span>
      </div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {['start', 'stop', 'restart'].map((a) => (
          <button key={a} className="btn ghost" disabled={busy !== null} onClick={() => doAction(a)}>
            {a}
          </button>
        ))}
      </div>
    </div>
  );
}