import { useState } from 'react';
import { useApi } from '../hooks/useApi';

const PRESETS = [
  'SELECT count() FROM network_ids.flows_all',
  'SELECT attack_family, count() FROM network_ids.flows_all WHERE is_attack=1 GROUP BY attack_family',
  'SELECT * FROM network_ids.pipeline_runs ORDER BY run_id DESC LIMIT 20',
  'SHOW TABLES FROM network_ids',
];

export default function ClickHousePage() {
  const api = useApi();
  const [sql, setSql] = useState(PRESETS[0]);
  const [columns, setColumns] = useState<string[]>([]);
  const [rows, setRows] = useState<any[][]>([]);
  const [elapsed, setElapsed] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function run(q?: string) {
    setError(null);
    const query = q ?? sql;
    try {
      const r = await api.post<{ columns: string[]; rows: any[][]; elapsed_ms: number }>(
        '/api/clickhouse/query',
        { sql: query, max_rows: 500 },
      );
      setColumns(r.columns);
      setRows(r.rows);
      setElapsed(r.elapsed_ms);
    } catch (e: any) {
      setError(e.message);
      setColumns([]); setRows([]); setElapsed(null);
    }
  }

  return (
    <div>
      <h1 style={{ marginTop: 0 }}>ClickHouse</h1>
      <div className="card">
        <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
          {PRESETS.map((p) => (
            <button key={p} className="btn ghost mono" style={{ fontSize: 11 }} onClick={() => { setSql(p); run(p); }}>
              {p.length > 50 ? p.slice(0, 47) + '...' : p}
            </button>
          ))}
        </div>
        <textarea
          value={sql}
          onChange={(e) => setSql(e.target.value)}
          rows={4}
          style={{ width: '100%', fontFamily: 'var(--mono)' }}
        />
        <div style={{ marginTop: 8 }}>
          <button className="btn" onClick={() => run()}>Run (read-only)</button>
          {elapsed !== null && <span className="muted" style={{ marginLeft: 12 }}>{elapsed.toFixed(1)} ms · {rows.length} row{rows.length === 1 ? '' : 's'}</span>}
        </div>
        {error && <div className="error" style={{ marginTop: 12 }}>{error}</div>}
      </div>
      <div className="card" style={{ overflowX: 'auto' }}>
        {rows.length === 0 ? (
          <p className="muted">No results yet.</p>
        ) : (
          <table>
            <thead>
              <tr>{columns.map((c) => <th key={c}>{c}</th>)}</tr>
            </thead>
            <tbody>
              {rows.map((row, i) => (
                <tr key={i}>
                  {row.map((cell, j) => <td key={j} className="mono">{String(cell)}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
