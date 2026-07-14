import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';

interface CountCardProps {
  label: string;
  value: number | null;
  to?: string;         // when set, the whole card links to a detail page
  size?: 'md' | 'lg';  // 'lg' for the headline metrics, 'md' (default) for secondary ones
}

/** Tweens the displayed number toward `target` over ~500ms on change. */
function useCountUp(target: number | null) {
  const [display, setDisplay] = useState(target);
  const fromRef = useRef(target);

  useEffect(() => {
    if (target === null) { setDisplay(null); fromRef.current = null; return; }
    const from = fromRef.current ?? target;
    const start = performance.now();
    const duration = 500;
    let raf: number;
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3); // ease-out cubic
      setDisplay(Math.round(from + (target - from) * eased));
      if (t < 1) raf = requestAnimationFrame(tick);
      else fromRef.current = target;
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target]);

  return display;
}

export function CountCard({ label, value, to, size = 'md' }: CountCardProps) {
  const valueSize = size === 'lg' ? 40 : 28;
  const display = useCountUp(value);
  const body = (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 0, padding: 14 }}>
      <div className="muted" style={{ fontSize: 12, textTransform: 'uppercase' }}>{label}</div>
      <div className="mono" style={{ fontSize: valueSize, color: 'var(--text-bright)', fontWeight: size === 'lg' ? 700 : 500 }}>
        {display === null ? '—' : display.toLocaleString()}
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
