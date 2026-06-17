import { Hono } from 'hono';
import type { Database } from '../db';

type Variables = { db: Database; userId: string };

export const connectionRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

connectionRoutes.get('/api/connection', (c) => {
  const userId = c.get('userId');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);

  const baseUrl = c.env.FACTORIAL_API_BASE_URL?.trim() || '';
  const apiKey = c.env.FACTORIAL_API_KEY?.trim() || '';
  const configured = baseUrl.length > 0 && apiKey.length > 0;

  return c.json({ configured, baseUrl: configured ? baseUrl : null });
});
