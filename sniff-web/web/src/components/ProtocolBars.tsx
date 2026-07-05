import React from 'react';

interface ProtocolBarsProps {
  counts: Record<string, number>;
  /** Show at most N rows; remaining roll up into "other". */
  maxRows?: number;
  /** Optional accent overrides per protocol name (CSS color string). */
  palette?: Record<string, string>;
}

const DEFAULT_PALETTE: Record<string, string> = {
  TCP:    'var(--accent)',
  UDP:    'var(--success)',
  ICMP:   'var(--warn)',
  ICMPv6: 'var(--warn)',
  ARP:    'var(--muted)',
  IGMP:   'var(--muted)',
  IPv4:   'var(--surf2)',
  IPv6:   'var(--surf2)',
  OTHER:  'var(--border)',
};

/**
 * Horizontal stacked bars for a per-protocol counter map.
 * Stable order: by count desc, with TCP/UDP pinned to top.
 */
export function ProtocolBars({ counts, maxRows = 8, palette }: ProtocolBarsProps) {
  const entries = Object.entries(counts || {})
    .filter(([, n]) => n > 0)
    .sort((a, b) => {
      // Pin TCP/UDP to top regardless of count
      const pin = (k: string) => (k === 'TCP' ? 0 : k === 'UDP' ? 1 : 2);
      const pa = pin(a[0]);
      const pb = pin(b[0]);
      if (pa !== pb) return pa - pb;
      return b[1] - a[1];
    });

  if (entries.length === 0) {
    return <div className="muted" style={{ padding: 8 }}>No protocol data yet.</div>;
  }

  const head = entries.slice(0, maxRows);
  const rest = entries.slice(maxRows);
  const otherTotal = rest.reduce((s, [, n]) => s + n, 0);
  if (otherTotal > 0) head.push(['other', otherTotal]);

  const total = head.reduce((s, [, n]) => s + n, 0) || 1;
  const pal = palette ?? DEFAULT_PALETTE;

  return (
    <div className="proto-bars">
      {head.map(([name, n]) => {
        const pct = (n / total) * 100;
        const color = pal[name] ?? 'var(--accent)';
        return (
          <div className="proto-row" key={name}>
            <div className="proto-name">{name}</div>
            <div className="proto-bar-track">
              <div className="proto-bar-fill" style={{ width: `${pct}%`, background: color }} />
            </div>
            <div className="proto-count">{n.toLocaleString()}</div>
          </div>
        );
      })}
    </div>
  );
}
