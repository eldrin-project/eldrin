import { Hono } from 'hono';
import type { Database } from '../db';
import { createFactorialClient, FactorialError } from '../services/factorial-client';

type Variables = { db: Database; userId: string };

export const timeoffRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

timeoffRoutes.get('/api/timeoff', async (c) => {
  const userId = c.get('userId');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);
  if (!c.env.FACTORIAL_API_BASE_URL?.trim() || !c.env.FACTORIAL_API_KEY?.trim()) {
    return c.json({ error: 'Factorial is not configured' }, 400);
  }
  try {
    const timeoff = await createFactorialClient(c.env).getAll('/timeoff/leaves');
    return c.json({ timeoff });
  } catch (e) {
    const status = e instanceof FactorialError ? e.status : 500;
    return c.json({ error: e instanceof Error ? e.message : 'Failed to fetch time off' }, status as 400 | 500);
  }
});
