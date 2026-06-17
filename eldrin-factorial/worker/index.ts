import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { runMigrations } from '@eldrin-project/eldrin-app-core';
import migrations from './migrations.generated';
import { createDb, type Database } from './db';
import { connectionRoutes } from './routes/connection';
import { syncRoutes } from './routes/sync';

type Variables = { db: Database; userId: string };

export const app = new Hono<{ Bindings: Env; Variables: Variables }>();

app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-Eldrin-User-Id'],
}));

app.get('/health', (c) => c.json({ status: 'ok', app: 'eldrin-factorial' }));

app.use('/api/*', async (c, next) => {
  const headerUserId = c.req.header('X-Eldrin-User-Id');
  if (headerUserId) {
    c.set('userId', headerUserId);
  } else {
    const auth = c.req.header('Authorization');
    if (auth?.startsWith('Bearer ')) {
      try {
        const payload = JSON.parse(atob(auth.slice(7).split('.')[1]));
        if (payload.sub) c.set('userId', payload.sub);
      } catch { /* invalid JWT — route handlers return 401 */ }
    }
  }
  await next();
});

let migrationsComplete = false;
app.use('/api/*', async (c, next) => {
  if (!migrationsComplete) {
    const result = await runMigrations(c.env.DB, {
      migrations,
      onLog: (msg: string, level: string) =>
        console[level as 'log' | 'warn' | 'error'](`[factorial] ${msg}`),
    });
    if (!result.success) {
      return c.json({ error: 'Migration failed', details: result.error?.message }, 500);
    }
    migrationsComplete = true;
  }
  c.set('db', createDb(c.env as unknown as Record<string, unknown>));
  await next();
});

app.route('', connectionRoutes);
app.route('', syncRoutes);

app.get('*', async (c) => c.env.ASSETS.fetch(c.req.raw));

export default {
  fetch: app.fetch,
  scheduled: async (_event: ScheduledEvent, _env: Env) => {},
};
