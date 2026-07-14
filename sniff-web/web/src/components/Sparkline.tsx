import React from 'react';

interface SparklineProps {
  values: number[];
  width?: number;
  height?: number;
  stroke?: string;          // CSS color or var
  fill?: string;            // CSS color or var (for area)
  ariaLabel?: string;
  unit?: string;            // suffix for the axis labels, e.g. "pps", "KB/s"
  formatValue?: (v: number) => string;
}

/**
 * Lightweight inline-SVG sparkline.
 * - No external chart library; bundle size stays small.
 * - When given <2 points, draws a flat line at the y-axis center.
 * - Scales y by max(value, 1) so zero is at the bottom.
 * - Optional min/max axis labels + a mid gridline, so the trend reads as a
 *   real chart (magnitude + shape) instead of a decorative squiggle.
 */
export function Sparkline({
  values,
  width = 240,
  height = 36,
  stroke = 'var(--accent)',
  fill = 'var(--accent)',
  ariaLabel = 'sparkline',
  unit = '',
  formatValue = (v) => v.toFixed(v >= 100 ? 0 : 1),
}: SparklineProps) {
  if (!values || values.length === 0) {
    return (
      <svg viewBox={`0 0 ${width} ${height}`} className="spark-svg" role="img" aria-label={ariaLabel}>
        <line x1={0} y1={height - 0.5} x2={width} y2={height - 0.5} className="spark-axis" />
        <text x={width / 2} y={height / 2 + 4} textAnchor="middle" className="muted" fontSize="11">
          no data
        </text>
      </svg>
    );
  }

  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const stepX = values.length > 1 ? width / (values.length - 1) : width;
  const padY = 2;
  const usableH = height - 2 * padY;

  const points = values.map((v, i) => {
    const x = i * stepX;
    const y = padY + (1 - v / max) * usableH;
    return [x, y] as const;
  });

  const linePath = points.map(([x, y], i) => (i === 0 ? `M${x},${y}` : `L${x},${y}`)).join(' ');
  const areaPath = `${linePath} L${width},${height} L0,${height} Z`;
  const midY = padY + usableH / 2;

  return (
    <div className="spark-chart">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="none"
        className="spark-svg"
        role="img"
        aria-label={ariaLabel}
      >
        <line x1={0} y1={midY} x2={width} y2={midY} className="spark-axis" strokeDasharray="2,3" />
        <line x1={0} y1={height - 0.5} x2={width} y2={height - 0.5} className="spark-axis" />
        <path d={areaPath} style={{ fill, stroke: 'none', opacity: 0.18 }} />
        <path d={linePath} style={{ fill: 'none', stroke, strokeWidth: 1.5, strokeLinejoin: 'round' }} />
      </svg>
      <div className="spark-axis-labels">
        <span>{formatValue(max)} {unit}</span>
        <span>{formatValue(min)} {unit}</span>
      </div>
    </div>
  );
}
