import { useCallback } from 'react';

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

export function getToken(): string | null {
  return localStorage.getItem('sniff_jwt');
}

export function setToken(t: string | null) {
  if (t) localStorage.setItem('sniff_jwt', t);
  else localStorage.removeItem('sniff_jwt');
}

export async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const tok = getToken();
  const headers = new Headers(init?.headers);
  if (tok) headers.set('Authorization', `Bearer ${tok}`);
  if (init?.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  const r = await fetch(path, { ...init, headers });
  if (r.status === 401) {
    setToken(null);
    window.location.href = '/login';
    throw new ApiError('Unauthorized', 401);
  }
  if (!r.ok) {
    const body = await r.json().catch(() => ({ detail: r.statusText }));
    throw new ApiError(body.detail || `HTTP ${r.status}`, r.status);
  }
  return r.json();
}

export function useApi() {
  return {
    get: useCallback(<T = any>(p: string) => request<T>(p), []),
    post: useCallback(<T = any>(p: string, body?: any) =>
      request<T>(p, { method: 'POST', body: body ? JSON.stringify(body) : undefined }), []),
    put: useCallback(<T = any>(p: string, body?: any) =>
      request<T>(p, { method: 'PUT', body: body ? JSON.stringify(body) : undefined }), []),
  };
}