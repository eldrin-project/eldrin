import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { app } from '../index';

function req(env: Partial<Env>) {
  return app.fetch(
    new Request('http://localhost/api/connection', { headers: { 'X-Eldrin-User-Id': 'u1' } }),
    { DB: makeDb(), ...env } as unknown as Env,
  );
}

// Minimal D1 stub: migrations run against it; return empty results.
function makeDb() {
  const stmt = { bind: () => stmt, all: async () => ({ results: [] }), run: async () => ({}), first: async () => null };
  return { prepare: () => stmt, batch: async () => [], exec: async () => ({}) } as unknown as D1Database;
}

describe('GET /api/connection', () => {
  beforeEach(() => {
    vi.spyOn(console, 'log').mockImplementation(() => undefined);
    vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    vi.spyOn(console, 'info').mockImplementation(() => undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('reports not configured when env vars missing', async () => {
    const res = await req({ FACTORIAL_API_BASE_URL: '', FACTORIAL_API_KEY: '' });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ configured: false, baseUrl: null });
  });

  it('reports configured when both env vars present, without leaking the key', async () => {
    const res = await req({ FACTORIAL_API_BASE_URL: 'https://api.eu2.demo.factorial.dev', FACTORIAL_API_KEY: 'secret' });
    const body = await res.json();
    expect(body).toEqual({ configured: true, baseUrl: 'https://api.eu2.demo.factorial.dev' });
    expect(JSON.stringify(body)).not.toContain('secret');
  });

  it('returns 401 without a shell user', async () => {
    const res = await app.fetch(new Request('http://localhost/api/connection'), { DB: makeDb(), FACTORIAL_API_BASE_URL: 'x', FACTORIAL_API_KEY: 'y' } as unknown as Env);
    expect(res.status).toBe(401);
  });
});
