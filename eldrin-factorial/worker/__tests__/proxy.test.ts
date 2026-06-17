import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { teamsRoutes } from '../routes/teams';

describe('GET /api/teams', () => {
  beforeEach(() => {
    vi.spyOn(console, 'log').mockImplementation(() => undefined);
    vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    vi.spyOn(console, 'info').mockImplementation(() => undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('401 without user', async () => {
    const res = await teamsRoutes.fetch(
      new Request('http://localhost/api/teams'),
      {} as Env,
    );
    expect(res.status).toBe(401);
  });
});
