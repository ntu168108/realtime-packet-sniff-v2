export function CountCard({ label, value }: { label: string; value: number | null }) {
  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      <div className="muted" style={{ fontSize: 11, textTransform: 'uppercase' }}>{label}</div>
      <div className="mono" style={{ fontSize: 24, color: 'var(--accent)' }}>
        {value === null ? '—' : value.toLocaleString()}
      </div>
    </div>
  );
}