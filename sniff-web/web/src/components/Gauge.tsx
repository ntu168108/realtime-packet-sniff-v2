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

  // Track (full 180° arc).
  const trackPath = arcPath(180, 360, r);

  // Filled portion maps 0..1 → 180°..360°.
  const filledEnd = 180 + fraction * 180;
  const filledPath = fraction > 0 ? arcPath(180, filledEnd, r) : '';

  // Color band thresholds.
  const color =
    fraction >= dangerFraction ? 'var(--danger)'
    : fraction >= warnFraction ? 'var(--warn)'
    : 'var(--success)';

  // Needle.
  const needleRad = (filledEnd * Math.PI) / 180;
  const nx = cx + (r - 4) * Math.cos(needleRad);
  const ny = cy + (r - 4) * Math.sin(needleRad);

  return (
    <div className="gauge-card">
      <svg viewBox={`0 0 ${width} ${height}`} className="gauge-svg" role="img" aria-label={`${label} gauge`}>
        <path d={trackPath} stroke="var(--surf2)" strokeWidth={10} fill="none" strokeLinecap="round" />
        {fraction > 0 && (
          <path d={filledPath} stroke={color} strokeWidth={10} fill="none" strokeLinecap="round" />
        )}
        <line x1={cx} y1={cy} x2={nx} y2={ny} stroke={color} strokeWidth={2} strokeLinecap="round" />
        <circle cx={cx} cy={cy} r={4} fill={color} />
      </svg>
      <div className="gauge-label">{label}</div>
      <div className="gauge-value">{fmt(value)}</div>
      {sub && <div className="gauge-sub">{sub}</div>}
    </div>
  );
}
