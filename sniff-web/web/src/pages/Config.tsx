import { useEffect, useState } from 'react';
import { useApi } from '../hooks/useApi';

export default function Config() {
  const api = useApi();
  const [config, setConfig] = useState<any>(null);
  const [displayFilter, setDisplayFilter] = useState('');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const c = await api.get<any>('/api/config');
        setConfig(c);
        setDisplayFilter(c?.display?.display_filter || '');
      } catch (e: any) { setError(e.message); }
    })();
  }, []);

  async function save() {
    setError(null);
    try {
      await api.put('/api/config', { display: { display_filter: displayFilter } });
    } catch (e: any) { setError(e.message); }
  }

  return (
    <div>
      <h1 style={{ marginTop: 0 }}>Config</h1>
      {error && <div className="error">{error}</div>}
      <div className="card">
        <h2>Editable via web</h2>
        <label>display.display_filter</label>
        <input value={displayFilter} onChange={(e) => setDisplayFilter(e.target.value)} style={{ width: '100%' }} />
        <button className="btn" onClick={save} style={{ marginTop: 8 }}>Save</button>
      </div>
      <div className="card">
        <h2>Full config (read-only, secrets hidden)</h2>
        <pre className="mono" style={{ fontSize: 12, maxHeight: 480, overflow: 'auto' }}>
          {JSON.stringify(config, null, 2)}
        </pre>
      </div>
    </div>
  );
}