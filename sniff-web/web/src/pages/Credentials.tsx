import { useEffect, useState } from 'react';
import { useApi } from '../hooks/useApi';
import { useCopyToClipboard } from '../hooks/useCopyToClipboard';
import type { IntegrationsPayload } from '../types';

interface Row {
  label: string;
  data: {
    url: string;
    username: string;
    password: string | null;
    password_hint?: string;
    note?: string;
    dashboard_path?: string;
    native_port?: number;
    protocol?: string;
  };
}

const ROW_ORDER: Array<{ key: keyof IntegrationsPayload; label: string }> = [
  { key: 'sniff_web',  label: 'SNIFF Web (this UI)' },
  { key: 'grafana',    label: 'Grafana' },
  { key: 'clickhouse', label: 'ClickHouse' },
  { key: 'kafka',      label: 'Kafka' },
];

/**
 * Credentials / quick-login panel.
 * - One row per integration service.
 * - URL + username copy-to-clipboard buttons; password only if it was
 *   configured in config.yaml (the SNIFF Web admin bcrypt-hash is never
 *   sent back, so its password cell stays "not retrievable").
 */
export default function Credentials() {
  const api = useApi();
  const [creds, setCreds] = useState<IntegrationsPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { copy, copied } = useCopyToClipboard(1200);

  useEffect(() => {
    (async () => {
      try {
        const c = await api.get<IntegrationsPayload>('/api/integrations/credentials');
        setCreds(c);
      } catch (e: any) {
        setError(e.message);
      }
    })();
  }, []);

  if (error) {
    return (
      <div>
        <h1 style={{ marginTop: 0 }}>Credentials</h1>
        <div className="error">{error}</div>
      </div>
    );
  }
  if (!creds) {
    return (
      <div>
        <h1 style={{ marginTop: 0 }}>Credentials</h1>
        <p className="muted">Loading…</p>
      </div>
    );
  }

  const rows: Row[] = ROW_ORDER.map((r) => ({ label: r.label, data: creds[r.key] }));

  return (
    <div>
      <h1 style={{ marginTop: 0 }}>Credentials</h1>
      <p className="muted" style={{ marginTop: 0 }}>
        Quick-login info for each module the SNIFF stack ships with.
        Passwords are only shown when set in <code>config.yaml</code> — rotate them on the upstream service.
      </p>

      <div className="card" style={{ padding: 0 }}>
        <table className="cred-table">
          <thead>
            <tr>
              <th style={{ width: 160 }}>Service</th>
              <th>URL / endpoint</th>
              <th style={{ width: 160 }}>Username</th>
              <th style={{ width: 220 }}>Password</th>
              <th>Notes</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(({ label, data }) => (
              <tr key={label}>
                <td className="label-cell">{label}</td>
                <td>
                  <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                    <span className="url">{data.url}</span>
                    <button
                      type="button"
                      className={`copy-btn ${copied === data.url ? 'copied' : ''}`}
                      onClick={() => copy(data.url)}
                    >
                      {copied === data.url ? 'copied' : 'copy'}
                    </button>
                  </div>
                </td>
                <td>
                  <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                    <span className="mono">{data.username || '—'}</span>
                    {data.username && (
                      <button
                        type="button"
                        className={`copy-btn ${copied === data.username ? 'copied' : ''}`}
                        onClick={() => copy(data.username)}
                      >
                        {copied === data.username ? 'copied' : 'copy'}
                      </button>
                    )}
                  </div>
                </td>
                <td>
                  {data.password ? (
                    <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                      <span className="mono">{'•'.repeat(Math.max(8, data.password.length))}</span>
                      <button
                        type="button"
                        className={`copy-btn ${copied === data.password ? 'copied' : ''}`}
                        onClick={() => copy(data.password!)}
                      >
                        {copied === data.password ? 'copied' : 'copy'}
                      </button>
                    </div>
                  ) : data.password_hint ? (
                    <span className="hint">{data.password_hint}</span>
                  ) : (
                    <span className="muted">not configured</span>
                  )}
                </td>
                <td>
                  <div className="muted" style={{ fontSize: 11 }}>
                    {data.note}
                    {data.dashboard_path && <div>dashboard: <code>{data.dashboard_path}</code></div>}
                    {data.native_port && <div>native port: <code>{data.native_port}</code></div>}
                    {data.protocol && <div>protocol: <code>{data.protocol}</code></div>}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}