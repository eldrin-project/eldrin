import { Hono } from 'hono';
import type { Database } from '../db';
import { runSync } from '../services/sync';
import { FactorialError } from '../services/factorial-client';

type Variables = { db: Database; userId: string };

export const syncRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

syncRoutes.post('/api/sync', async (c) => {
  const userId = c.get('userId');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);

  if (!c.env.FACTORIAL_API_BASE_URL?.trim() || !c.env.FACTORIAL_API_KEY?.trim()) {
    return c.json({ error: 'Factorial is not configured' }, 400);
  }

  try {
    const result = await runSync(c.get('db'), c.env);
    return c.json(result);
  } catch (e) {
    const status = e instanceof FactorialError ? e.status : 500;
    return c.json({ error: e instanceof Error ? e.message : 'Sync failed' }, status as 400 | 500);
  }
});
