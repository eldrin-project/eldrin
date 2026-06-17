import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { employeesRoutes } from '../routes/employees';

function ctxApp() {
  return employeesRoutes;
}

describe('GET /api/employees', () => {
  beforeEach(() => {
    vi.spyOn(console, 'log').mockImplementation(() => undefined);
    vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    vi.spyOn(console, 'info').mockImplementation(() => undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns 401 without user', async () => {
    const res = await ctxApp().fetch(new Request('http://localhost/api/employees'), {} as Env);
    expect(res.status).toBe(401);
  });
});
