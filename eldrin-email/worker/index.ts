import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { runMigrations } from '@eldrin-project/eldrin-app-core';
import migrations from './migrations.generated';
import { createDb, type Database } from './db';
import { mailboxRoutes } from './routes/mailbox';
import { emailRoutes } from './routes/emails';
import { templateRoutes } from './routes/templates';
import { trackingRoutes } from './routes/tracking';
import { integrationRoutes } from './routes/integration';
import { eventRoutes } from './routes/events';
import { handleScheduled } from './cron';

type Variables = {
  db: Database;
  userId: string;
};

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// CORS
app.use(
  '*',
  cors({
    origin: '*',
    allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'X-Eldrin-User-Id'],
  }),
);

// Health check (public, before migration middleware)
app.get('/health', (c) => c.json({ status: 'ok', app: 'eldrin-email' }));

// Auth: resolve userId from header (production proxy) or Bearer JWT (dev mode).
// In production, the shell proxy verifies the JWT and injects X-Eldrin-User-Id.
// In dev mode (cross-origin), the JWT comes directly from the shell.
app.use('/api/*', async (c, next) => {
  const headerUserId = c.req.header('X-Eldrin-User-Id');
  if (headerUserId) {
    c.set('userId', headerUserId);
  } else {
    const auth = c.req.header('Authorization');
    if (auth?.startsWith('Bearer ')) {
      try {
        const payload = JSON.parse(atob(auth.slice(7).split('.')[1]));
        if (payload.sub) {
          c.set('userId', payload.sub);
        }
      } catch { /* invalid JWT — let route handlers return 401 */ }
    }
  }
  await next();
});

// Migration runner + database context
let migrationsComplete = false;

app.use('/api/*', async (c, next) => {
  if (!migrationsComplete) {
    const result = await runMigrations(c.env.DB, {
      migrations,
      onLog: (msg: string, level: string) =>
        console[level as 'log' | 'warn' | 'error'](`[email] ${msg}`),
    });
    if (!result.success) {
      return c.json(
        { error: 'Migration failed', details: result.error?.message },
        500,
      );
    }
    migrationsComplete = true;
  }

  const db = createDb(c.env as unknown as Record<string, unknown>);
  c.set('db', db);
  await next();
});

// Phase 2: Mailbox connection (Gmail OAuth)
// Phase 3: Sync routes (manual sync trigger)
app.route('', mailboxRoutes);

// Phase 4: Inbox, thread, sent, search routes
app.route('', emailRoutes);

// Phase 6: Email templates
app.route('', templateRoutes);

// Phase 7: Email open & click tracking (public endpoints)
app.route('', trackingRoutes);

// Phase 8: Cross-app integration (send-template, history, events)
app.route('', integrationRoutes);
app.route('', eventRoutes);

// Static asset fallback
app.get('*', async (c) => {
  return c.env.ASSETS.fetch(c.req.raw);
});

export default {
  fetch: app.fetch,
  scheduled: async (_event: ScheduledEvent, env: Env) => {
    await handleScheduled(env);
  },
};
