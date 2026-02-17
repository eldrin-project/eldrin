import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { runMigrations } from '@eldrin-project/eldrin-app-core';
import migrations from './migrations.generated';
import { createDb, type Database } from './db';
import { mailboxRoutes } from './routes/mailbox';
import { emailRoutes } from './routes/emails';
import { handleScheduled } from './cron';

type Variables = {
  db: Database;
};

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// CORS
app.use(
  '*',
  cors({
    origin: '*',
    allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization'],
  }),
);

// Health check (public, before migration middleware)
app.get('/health', (c) => c.json({ status: 'ok', app: 'eldrin-email' }));

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

// Event webhook handler (receives platform events)
app.post('/api/_events/webhook', async (c) => {
  const body = await c.req.json();
  console.log('[email] Received event:', body.type);
  // Event handling will be implemented in Phase 8
  return c.json({ received: true });
});

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
