import { useEffect, useRef, useState } from 'react';

export function useWebSocket<T = any>(
  path: string,
  onMessage: (msg: T) => void
): { connected: boolean } {
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectRef = useRef<ReturnType<typeof setTimeout>>();

  useEffect(() => {
    let active = true;

    const connect = () => {
      const tok = localStorage.getItem('sniff_jwt');
      if (!tok) return;
      const proto = location.protocol === 'https:' ? 'wss' : 'ws';
      const url = `${proto}://${location.host}${path}?token=${encodeURIComponent(tok)}`;
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        if (active) reconnectRef.current = setTimeout(connect, 2000);
      };
      ws.onerror = () => ws.close();
      ws.onmessage = (e) => {
        try {
          const parsed = JSON.parse(e.data);
          onMessage(parsed);
        } catch {
          // ignore malformed
        }
      };
    };

    connect();
    return () => {
      active = false;
      clearTimeout(reconnectRef.current);
      wsRef.current?.close();
    };
  }, [path]);

  return { connected };
}