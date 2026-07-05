import { useEffect, useState } from 'react';
import { useApi, getToken } from '../hooks/useApi';
import type { PcapFile } from '../types';

function fmtBytes(n: number): string {
  if (n > 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  if (n > 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

export default function PcapFiles() {
  const api = useApi();
  const [files, setFiles] = useState<PcapFile[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try { setFiles(await api.get<PcapFile[]>('/api/pcap/files')); }
      catch (e: any) { setError(e.message); }
    })();
  }, []);

  function downloadUrl(name: string): string {
    const tok = getToken();
    return `/api/pcap/download/${encodeURIComponent(name)}?token=${encodeURIComponent(tok || '')}`;
  }

  return (
    <div>
      <h1 style={{ marginTop: 0 }}>PCAP files</h1>
      {error && <div className="error">{error}</div>}
      <div className="card">
        <table>
          <thead><tr><th>Name</th><th>Size</th><th>Modified</th><th></th></tr></thead>
          <tbody>
            {files.map((f) => (
              <tr key={f.name}>
                <td className="mono">{f.name}</td>
                <td className="mono">{fmtBytes(f.size)}</td>
                <td className="mono">{new Date(f.mtime * 1000).toISOString().replace('T', ' ').slice(0, 19)}</td>
                <td><a className="btn ghost" href={downloadUrl(f.name)} download>Download</a></td>
              </tr>
            ))}
            {files.length === 0 && <tr><td colSpan={4} className="muted">No PCAP files found.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}
