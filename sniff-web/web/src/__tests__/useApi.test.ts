import { describe, it, expect, vi, beforeEach } from 'vitest';

describe('useApi', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it('getToken reads from localStorage', async () => {
    localStorage.setItem('sniff_jwt', 'abc');
    const { getToken } = await import('../hooks/useApi');
    expect(getToken()).toBe('abc');
  });

  it('setToken null removes from localStorage', async () => {
    localStorage.setItem('sniff_jwt', 'abc');
    const { setToken, getToken } = await import('../hooks/useApi');
    setToken(null);
    expect(getToken()).toBeNull();
  });

  it('401 redirects to /login and clears token', async () => {
    localStorage.setItem('sniff_jwt', 'old');
    const fetchMock = vi.fn().mockResolvedValue({
      status: 401,
      ok: false,
      json: () => Promise.resolve({ detail: 'expired' }),
    });
    (globalThis as any).fetch = fetchMock;

    // Mock window.location
    const origLocation = window.location;
    delete (window as any).location;
    (window as any).location = { href: '' };

    const { request } = await import('../hooks/useApi');
    await expect(request('/api/x')).rejects.toThrow(/Unauthorized|expired/);
    expect(localStorage.getItem('sniff_jwt')).toBeNull();
    expect((window as any).location.href).toBe('/login');

    (window as any).location = origLocation;
  });
});