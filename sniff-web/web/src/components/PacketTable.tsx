import { useRef, useState, useEffect } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import type { PacketRow } from '../types';

const PROTO_COLORS: Record<string, string> = {
  TCP: '#4a90e8',
  UDP: '#7b68ee',
  DNS: '#28e4ff',
  TLS: '#a56ef0',
  HTTP: '#f0a030',
  ICMP: '#78909c',
  ARP: '#4ecb8a',
  QUIC: '#e8857a',
};
const DEFAULT_COLOR = '#546e7a';

interface InnerProps {
  packets: PacketRow[];
  filter: string;
  setFilter: (v: string) => void;
  autoScroll: boolean;
  setAutoScroll: (v: boolean) => void;
  parentRef: React.RefObject<HTMLDivElement>;
  onAppend: (rows: PacketRow[]) => void;
}

export function PacketTableInner({
  packets,
  filter,
  setFilter,
  autoScroll,
  setAutoScroll,
  parentRef,
}: InnerProps) {
  const filtered = filter
    ? packets.filter((p) =>
        [p.src, p.dst, p.proto, p.info, p.src_mac, p.dst_mac].some((s) => (s ?? '').toLowerCase().includes(filter.toLowerCase()))
      )
    : packets;

  const virtualizer = useVirtualizer({
    count: filtered.length,
    getScrollElement: () => parentRef.current,
    // Rows with a MAC address wrap to 2 lines and are taller than 34px;
    // measureElement (below, on each row) re-measures the real DOM height
    // after render so later rows don't get positioned assuming a fixed
    // 34px and overlap the row above them.
    estimateSize: () => 34,
    overscan: 10,
  });

  useEffect(() => {
    if (autoScroll && parentRef.current) {
      parentRef.current.scrollTop = parentRef.current.scrollHeight;
    }
  }, [filtered.length, autoScroll]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ display: 'flex', gap: 8, padding: 8, borderBottom: '1px solid var(--border)' }}>
        <input
          placeholder="Filter (src/dst/proto/info)"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          style={{ flex: 1 }}
        />
        <label className="muted" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <input
            type="checkbox"
            checked={autoScroll}
            onChange={(e) => setAutoScroll(e.target.checked)}
          />
          auto-scroll
        </label>
      </div>
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '60px 100px 190px 190px 70px 60px 1fr',
          padding: '6px 8px',
          background: 'var(--surf2)',
          fontSize: 11,
          color: 'var(--muted)',
          textTransform: 'uppercase',
        }}
      >
        <span>#</span>
        <span>Time</span>
        <span>Source</span>
        <span>Destination</span>
        <span>Proto</span>
        <span>Len</span>
        <span>Info</span>
      </div>
      <div ref={parentRef} style={{ flex: 1, overflow: 'auto' }}>
        <div style={{ height: `${virtualizer.getTotalSize()}px`, position: 'relative' }}>
          {virtualizer.getVirtualItems().map((v) => {
            const p = filtered[v.index];
            const color = PROTO_COLORS[p.proto] ?? DEFAULT_COLOR;
            const ts = new Date(p.ts * 1000);
            const time = `${String(ts.getHours()).padStart(2, '0')}:${String(ts.getMinutes()).padStart(2, '0')}:${String(ts.getSeconds()).padStart(2, '0')}.${String(ts.getMilliseconds()).padStart(3, '0')}`;
            return (
              <div
                key={p.stt}
                ref={virtualizer.measureElement}
                data-index={v.index}
                style={{
                  position: 'absolute',
                  top: 0,
                  left: 0,
                  width: '100%',
                  transform: `translateY(${v.start}px)`,
                  display: 'grid',
                  gridTemplateColumns: '60px 100px 190px 190px 70px 60px 1fr',
                  padding: '4px 8px',
                  alignItems: 'center',
                  fontSize: 12,
                  borderBottom: '1px solid var(--border)',
                }}
              >
                <span className="mono" style={{ borderLeft: `3px solid ${color}`, paddingLeft: 4 }}>
                  {p.stt}
                </span>
                <span className="mono">{time}</span>
                <span className="mono" style={{ lineHeight: 1.3, overflowWrap: 'anywhere', minWidth: 0 }}>
                  {p.src}
                  {p.src_port ? `:${p.src_port}` : ''}
                  {p.src_mac && (
                    <>
                      <br />
                      <span className="muted" style={{ fontSize: 10 }}>{p.src_mac}</span>
                    </>
                  )}
                </span>
                <span className="mono" style={{ lineHeight: 1.3, overflowWrap: 'anywhere', minWidth: 0 }}>
                  {p.dst}
                  {p.dst_port ? `:${p.dst_port}` : ''}
                  {p.dst_mac && (
                    <>
                      <br />
                      <span className="muted" style={{ fontSize: 10 }}>{p.dst_mac}</span>
                    </>
                  )}
                </span>
                <span className="mono" style={{ color }}>
                  {p.proto}
                </span>
                <span className="mono">{p.len}</span>
                <span
                  className="mono"
                  style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                >
                  {p.info}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}