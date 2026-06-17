import { describe, it, expect, vi, afterEach } from 'vitest';
import { createFactorialClient } from '../services/factorial-client';

const env = { FACTORIAL_API_BASE_URL: 'https://api.eu2.demo.factorial.dev', FACTORIAL_API_KEY: 'k' };

afterEach(() => vi.restoreAllMocks());

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

describe('factorial-client', () => {
  it('GETs with x-api-key header and the dated /api/2026-04-01/resources base', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse({ data: [{ id: 1 }], meta: {} }));
    const client = createFactorialClient(env);
    const out = await client.get<{ data: { id: number }[] }>('/employees/employees');
    expect(out.data[0].id).toBe(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://api.eu2.demo.factorial.dev/api/2026-04-01/resources/employees/employees');
    expect((init?.headers as Record<string, string>)['x-api-key']).toBe('k');
  });

  it('throws FactorialError on non-2xx with status', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse({ message: 'nope' }, 403));
    const client = createFactorialClient(env);
    await expect(client.get('/employees/employees')).rejects.toMatchObject({ name: 'FactorialError', status: 403 });
  });

  it('getAll follows cursor pagination via after_id until has_next_page is false', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse({ data: [{ id: 1 }], meta: { has_next_page: true, end_cursor: 'CUR1' } }))
      .mockResolvedValueOnce(jsonResponse({ data: [{ id: 2 }], meta: { has_next_page: false, end_cursor: 'CUR2' } }));
    const client = createFactorialClient(env);
    const all = await client.getAll<{ id: number }>('/employees/employees');
    expect(all.map((x) => x.id)).toEqual([1, 2]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    // first call has no after_id; second call carries after_id=CUR1
    expect(fetchMock.mock.calls[0][0]).not.toContain('after_id');
    expect(fetchMock.mock.calls[1][0]).toContain('after_id=CUR1');
  });

  it('getAll preserves an existing query string when appending after_id', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse({ data: [{ id: 1 }], meta: { has_next_page: true, end_cursor: 'C' } }))
      .mockResolvedValueOnce(jsonResponse({ data: [{ id: 2 }], meta: { has_next_page: false } }));
    const client = createFactorialClient(env);
    await client.getAll<{ id: number }>('/employees/employees?only_active=true');
    expect(fetchMock.mock.calls[1][0]).toContain('only_active=true');
    expect(fetchMock.mock.calls[1][0]).toContain('after_id=C');
  });
});
