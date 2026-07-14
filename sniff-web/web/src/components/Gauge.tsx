import React from 'react';

interface GaugeProps {
  /** Current value (e.g. packets/sec). */
  value: number;
  /** Scale to render against. If 0, the gauge stays at zero. */
  max: number;
  /** Display label, e.g. "PPS" / "KB/s". */
  label: string;
  /** Optional sub-line, e.g. "peak 12.3k". */
  sub?: string;
  /** Optional formatter for the value (defaults to toLocaleString). */
  format?: (v: number) => string;
  /** Optional SVG width in px. Defaults to 200. */
  width?: number;
  /** Optional SVG height in px. Defaults to 120. */
  height?: number;
}

/**
 * Half-donut gauge with a colored arc and a needle.
 * - Auto-scales `max`: if `value > max`, max is bumped up so the gauge never clips.
 * - Pure inline SVG, no chart library.
 */
export function Gauge({
  value,
  max,
  label,
  sub,
  format,
  width = 200,
  height = 120,
}: GaugeProps) {
  const dangerFraction = 0.9;
  const warnFraction = 0.6;
  const safeMax = Math.max(max, value, 1);
  const fraction = Math.min(Math.max(value / safeMax, 0), 1);
  const fmt = format ?? ((v: number) =>
    v >= 1_000_000 ? `${(v / 1_000_000).toFixed(2)}M`
    : v >= 1_000 ? `${(v / 1_000).toFixed(1)}k`
    : Math.round(v).toLocaleString()
  );

  // Geometry — half-donut from -180° (left) to 0° (right).
  const cx = width / 2;
  const cy = height * 0.92;
  const r = Math.min(width * 0.42, height * 0.85);

  // Donut segment from -180° to 0°. Convert: angle 0 = right, 180 = left.
  // We start at angle 180° (left), sweep clockwise 180° to 0° (right).
  // SVG arc: x = cx + r*cos(rad), y = cy + r*sin(rad).
  // At 180°: (cx-r, cy); at 0°: (cx+r, cy).
  function arcPath(startDeg: number, endDeg: number, radius: number): string {
    const rad = (d: number) => (d * Math.PI) / 180;
    const sx = cx + radius * Math.cos(rad(startDeg));
    const sy = cy + radius * Math.sin(rad(startDeg));
    const ex = cx + radius * Math.cos(rad(endDeg));
    const ey = cy + radius * Math.sin(rad(endDeg));
    const sweep = endDeg - startDeg;
    const largeArc = Math.abs(sweep) > 180 ? 1 : 0;
    const sweepFlag = sweep > 0 ? 1 : 0;
    return `M${sx},${sy} A${radius},${radius} 0 ${largeArc} ${sweepFlag} ${ex},${ey}`;
  }

  // Track (full 180° arc) — the filled arc is the SAME full path, always drawn;
  // its visible length is controlled by stroke-dasharray so it can transition
  // smoothly (dasharray/dashoffset are CSS-animatable, unlike the `d` attribute).
  const trackPath = arcPath(180, 360, r);
  const arcLength = Math.PI * r; // length of a 180° arc of radius r

  // Color band thresholds.
  const color =
    fraction >= dangerFraction ? 'var(--danger)'
    : fraction >= warnFraction ? 'var(--warn)'
    : 'var(--success)';

  // Needle: fixed-length line pointing right from center, rotated via CSS
  // transform (transitions smoothly) instead of recomputing x2/y2 each render.
  const needleDeg = 180 + fraction * 180 - 360; // -180 (empty, left) .. 0 (full, right)

  return (
    <div className="gauge-card">
      <svg viewBox={`0 0 ${width} ${height}`} className="gauge-svg" role="img" aria-label={`${label} gauge`}>
        <path d={trackPath} stroke="var(--surf2)" strokeWidth={10} fill="none" strokeLinecap="round" />
        <path
          d={trackPath}
          stroke={color}
          strokeWidth={10}
          fill="none"
          strokeLinecap="round"
          strokeDasharray={`${fraction * arcLength} ${arcLength}`}
          style={{ transition: 'stroke-dasharray 500ms ease-out, stroke 400ms ease-out' }}
        />
        <line
          x1={cx}
          y1={cy}
          x2={cx + (r - 4)}
          y2={cy}
          stroke={color}
          strokeWidth={2}
          strokeLinecap="round"
          style={{
            transformOrigin: `${cx}px ${cy}px`,
            transform: `rotate(${needleDeg}deg)`,
            transition: 'transform 500ms ease-out, stroke 400ms ease-out',
          }}
        />
        <circle cx={cx} cy={cy} r={4} fill={color} style={{ transition: 'fill 400ms ease-out' }} />
      </svg>
      <div className="gauge-label">{label}</div>
      <div className="gauge-value">{fmt(value)}</div>
      {sub && <div className="gauge-sub">{sub}</div>}
    </div>
  );
}
