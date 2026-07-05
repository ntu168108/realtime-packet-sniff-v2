import { useCallback, useState } from 'react';

export function useCopyToClipboard(timeoutMs = 1000) {
  const [copied, setCopied] = useState<string | null>(null);
  const copy = useCallback(async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      // Fallback for browsers blocking the Clipboard API
      const ta = document.createElement('textarea');
      ta.value = value;
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); } catch { /* swallow */ }
      document.body.removeChild(ta);
    }
    setCopied(value);
    setTimeout(() => setCopied((cur) => (cur === value ? null : cur)), timeoutMs);
  }, [timeoutMs]);
  return { copy, copied };
}