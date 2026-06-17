import { Hono } from 'hono';
import { cors } from 'hono/cors';

type Variables = { userId: string };

export const app = new Hono<{ Bindings: Env; Variables: Variables }>();

app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-Eldrin-User-Id'],
}));

app.get('/health', (c) => c.json({ status: 'ok', app: 'eldrin-factorial' }));

app.get('*', async (c) => c.env.ASSETS.fetch(c.req.raw));

export default {
  fetch: app.fetch,
  scheduled: async (_event: ScheduledEvent, _env: Env) => {},
};
