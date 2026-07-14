import { useEffect, useState } from 'react';

export interface DonutSlice {
  name: string;
  value: number;
  color: string; // CSS color or var(--x)
}

interface DonutChartProps {
  slices: DonutSlice[];
  size?: number;      // px, square
  thickness?: number; // stroke width
  centerLabel?: string;
  centerValue?: string;
  ariaLabel?: string;
}

/**
 * Hand-rolled SVG donut chart — no chart library.
 * - Draws each slice via stroke-dasharray/-dashoffset on a circle.
 * - One-shot draw-in animation on mount (not a perpetual loop).
 * - Hovered slice thickens slightly via CSS, as a lightweight tooltip substitute.
 */
export function DonutChart({
  slices,
  size = 140,
  thickness = 16,
  centerLabel,
  centerValue,
  ariaLabel = 'donut chart',
}: DonutChartProps) {
  const [drawn, setDrawn] = useState(false);
  const [hovered, setHovered] = useState<string | null>(null);

  useEffect(() => {
    const t = requestAnimationFrame(() => setDrawn(true));
    return () => cancelAnimationFrame(t);
  }, []);

  const filtered = slices.filter((s) => s.value > 0);
  const total = filtered.reduce((s, x) => s + x.value, 0);
  const r = (size - thickness) / 2;
  const circumference = 2 * Math.PI * r;
  const cx = size / 2;
  const cy = size / 2;

  if (total === 0) {
    return <div className="muted" style={{ padding: 8 }}>No data yet.</div>;
  }

  let offsetAcc = 0;

  return (
    <div className="donut-chart">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={ariaLabel}>
        <g transform={`rotate(-90 ${cx} ${cy})`}>
          <circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--surf2)" strokeWidth={thickness} />
          {filtered.map((s) => {
            const frac = s.value / total;
            const dash = frac * circumference;
            const gap = circumference - dash;
            const dashoffset = -offsetAcc * circumference;
            offsetAcc += frac;
            const isHovered = hovered === s.name;
            return (
              <circle
                key={s.name}
                cx={cx}
                cy={cy}
                r={r}
                fill="none"
                stroke={s.color}
                strokeWidth={isHovered ? thickness + 3 : thickness}
                strokeDasharray={`${drawn ? dash : 0} ${drawn ? gap : circumference}`}
                strokeDashoffset={dashoffset}
                style={{ transition: 'stroke-dasharray 600ms ease-out, stroke-width 150ms ease-out' }}
                onMouseEnter={() => setHovered(s.name)}
                onMouseLeave={() => setHovered(null)}
              />
            );
          })}
        </g>
        {(centerLabel || centerValue) && (
          <>
            {centerValue && (
              <text x={cx} y={cy - 2} textAnchor="middle" className="mono" fontSize={size * 0.14} fill="var(--text)">
                {centerValue}
              </text>
            )}
            {centerLabel && (
              <text x={cx} y={cy + size * 0.13} textAnchor="middle" fontSize={size * 0.08} fill="var(--muted)">
                {centerLabel}
              </text>
            )}
          </>
        )}
      </svg>
      <div className="donut-legend">
        {filtered.map((s) => (
          <div
            key={s.name}
            className="donut-legend-row"
            onMouseEnter={() => setHovered(s.name)}
            onMouseLeave={() => setHovered(null)}
          >
            <span className="donut-swatch" style={{ background: s.color }} />
            <span className="donut-legend-name">{s.name}</span>
            <span className="donut-legend-pct muted mono">{((s.value / total) * 100).toFixed(1)}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}
