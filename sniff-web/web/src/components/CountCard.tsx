import { Link } from 'react-router-dom';

interface CountCardProps {
  label: string;
  value: number | null;
  to?: string;         // when set, the whole card links to a detail page
  size?: 'md' | 'lg';  // 'lg' for the headline metrics, 'md' (default) for secondary ones
}

export function CountCard({ label, value, to, size = 'md' }: CountCardProps) {
  const valueSize = size === 'lg' ? 32 : 24;
  const body = (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 4, marginBottom: 0 }}>
      <div className="muted" style={{ fontSize: 11, textTransform: 'uppercase' }}>{label}</div>
      <div className="mono" style={{ fontSize: valueSize, color: 'var(--accent)', fontWeight: size === 'lg' ? 700 : 400 }}>
        {value === null ? '—' : value.toLocaleString()}
      </div>
    </div>
  );

  if (!to) return body;
  return (
    <Link to={to} className="card-link" aria-label={`${label}: view details`}>
      {body}
    </Link>
  );
}
