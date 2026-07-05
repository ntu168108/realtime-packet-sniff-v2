import { useEffect, useState } from 'react';
import { useApi } from '../hooks/useApi';
import type { KafkaTopic, KafkaLag } from '../types';

export default function KafkaPage() {
  const api = useApi();
  const [topics, setTopics] = useState<KafkaTopic[]>([]);
  const [lag, setLag] = useState<KafkaLag | null>(null);
  const [group, setGroup] = useState('ec-consumer');
  const [error, setError] = useState<string | null>(null);

  async function load() {
    setError(null);
    try {
      const t = await api.get<{ topics: KafkaTopic[] }>('/api/kafka/topics');
      setTopics(t.topics);
      const l = await api.get<KafkaLag>(`/api/kafka/lag?group=${encodeURIComponent(group)}`);
      setLag(l);
    } catch (e: any) { setError(e.message); }
  }

  useEffect(() => { load(); }, []);

  return (
    <div>
      <h1 style={{ marginTop: 0 }}>Kafka</h1>
      {error && <div className="error">{error}</div>}
      <div className="card">
        <h2>Topics</h2>
        <table>
          <thead><tr><th>Name</th><th>Partitions</th><th>Replication</th></tr></thead>
          <tbody>
            {topics.map((t) => (
              <tr key={t.name}>
                <td className="mono">{t.name}</td>
                <td className="mono">{t.partitions}</td>
                <td className="mono">{t.replication}</td>
              </tr>
            ))}
            {topics.length === 0 && <tr><td colSpan={3} className="muted">No topics or Kafka unreachable.</td></tr>}
          </tbody>
        </table>
      </div>
      <div className="card">
        <h2>Consumer-group lag</h2>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 }}>
          <label>Group:</label>
          <input value={group} onChange={(e) => setGroup(e.target.value)} />
          <button className="btn ghost" onClick={load}>Refresh</button>
        </div>
        {lag && (
          <>
            <p>Total lag: <strong className="mono">{lag.total_lag.toLocaleString()}</strong></p>
            <table>
              <thead><tr><th>Topic</th><th>Partition</th><th>Lag</th></tr></thead>
              <tbody>
                {lag.partitions.map((p) => (
                  <tr key={`${p.topic}-${p.partition}`}>
                    <td className="mono">{p.topic}</td>
                    <td className="mono">{p.partition}</td>
                    <td className="mono">{p.lag.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </div>
    </div>
  );
}
