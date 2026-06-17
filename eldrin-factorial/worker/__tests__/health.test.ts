import { describe, it, expect } from 'vitest';
import { app } from '../index';

const env = {} as unknown as Env;

describe('health', () => {
  it('returns ok status', async () => {
    const res = await app.fetch(new Request('http://localhost/health'), env);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: 'ok', app: 'eldrin-factorial' });
  });
});
