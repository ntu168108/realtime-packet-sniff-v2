import React from 'react';
import type { AlertItem } from '../types';
import { useCopyToClipboard } from '../hooks/useCopyToClipboard';

interface AlertFeedProps {
  alerts: AlertItem[];
}

/**
 * Compact alert list with copy-to-clipboard.
 * - Sorted newest-first (assumes server appends in order).
 * - Renders a one-shot "copied" pill on each row for 1s.
 */
export function AlertFeed({ alerts }: AlertFeedProps) {
  const { copy, copied: copiedId } = useCopyToClipboard();

  if (!alerts || alerts.length === 0) {
    return <div className="muted" style={{ padding: 8 }}>No alerts yet.</div>;
  }

  // newest first
  const items = [...alerts].reverse();

  return (
    <div className="alert-feed">
      {items.map((a) => {
        const ts = a.received_at ?? a.ts_sec ?? 0;
        const when = ts ? new Date(ts * 1000).toLocaleTimeString() : '—';
        const flow = [a.src, a.dst].filter(Boolean).join(' → ') || a.proto || '';
        const prio = (a.priority || 'medium').toLowerCase();
        return (
          <div className="alert-row" key={a.alert_id || `${a.label}-${ts}`}>
            <div className="ts">{when}</div>
            <div>
              <span className={`pill ${prio}`}>{prio}</span>
            </div>
            <div className="label">{a.label}</div>
            <div className="flow">{flow}</div>
            <button
              type="button"
              className={`btn ghost copy ${copiedId === a.alert_id ? 'copied' : ''}`}
              onClick={() => copy(a.alert_id)}
              title={a.alert_id}
            >
              {copiedId === a.alert_id ? 'copied' : 'copy id'}
            </button>
          </div>
        );
      })}
    </div>
  );
}