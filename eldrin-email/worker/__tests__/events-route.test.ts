import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Hono } from 'hono';

// Mock send dependencies so the send path runs without real providers
const sendMessage = vi.fn().mockResolvedValue({ id: 'prov-msg-1', threadId: 'prov-thread-1' });

vi.mock('../services/providers', () => ({
  getProvider: vi.fn(() => ({ sendMessage })),
  getAccessToken: vi.fn().mockResolvedValue('mock-access-token'),
}));

vi.mock('../services/tracking', () => ({
  prepareTrackedEmail: vi.fn().mockResolvedValue({ html: '<p>tracked</p>' }),
}));

import { eventRoutes } from '../routes/events';

const SERVICE_SECRET = 'test-service-secret';
const mockEnv = { JWT_SECRET: SERVICE_SECRET } as Env;

const ACTIVE_MAILBOX = {
  id: 'mb-1',
  userId: 'user-1',
  provider: 'gmail',
  emailAddress: 'me@example.com',
  displayName: 'Me',
  syncStatus: 'active',
};

// ── Mock database ────────────────────────────────────────────────────────────

function createMockDb(data: { mailbox?: Record<string, unknown> | null } = {}) {
  return {
    query: {
      connectedMailboxes: {
        findFirst: vi.fn().mockResolvedValue(data.mailbox ?? null),
        findMany: vi.fn().mockResolvedValue([]),
      },
      emailTemplates: {
        findFirst: vi.fn().mockResolvedValue(null),
      },
      emails: {
        findMany: vi.fn().mockResolvedValue([]),
      },
      emailTracking: {
        findMany: vi.fn().mockResolvedValue([]),
      },
    },
    insert: vi.fn().mockReturnValue({
      values: vi.fn().mockResolvedValue(undefined),
    }),
    delete: vi.fn().mockReturnValue({
      where: vi.fn().mockResolvedValue(undefined),
    }),
  };
}

// ── Test app factory ─────────────────────────────────────────────────────────

function createTestApp(db: ReturnType<typeof createMockDb>) {
  const app = new Hono<{ Bindings: Env }>();
  app.use('*', async (c, next) => {
    (c as any).set('db', db);
    await next();
  });
  app.route('', eventRoutes as any);
  return app;
}

function createExecutionCtx(tasks: Promise<unknown>[]) {
  return {
    waitUntil: (p: Promise<unknown>) => {
      tasks.push(p);
    },
    passThroughOnException: () => {},
    props: {},
  } as ExecutionContext;
}

async function post(
  app: ReturnType<typeof createTestApp>,
  body: unknown,
  options: {
    headers?: Record<string, string>;
    env?: Env;
    tasks?: Promise<unknown>[];
  } = {},
) {
  const headers = options.headers ?? { 'X-Eldrin-App-Secret': SERVICE_SECRET };
  return app.request(
    '/api/_events/webhook',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...headers },
      body: JSON.stringify(body),
    },
    options.env ?? mockEnv,
    createExecutionCtx(options.tasks ?? []),
  );
}

const SEND_PAYLOAD = {
  to: ['jane@acme.com'],
  subject: 'Hello',
  bodyHtml: '<p>Hi Jane</p>',
};

// ── Tests ────────────────────────────────────────────────────────────────────

describe('POST /api/_events/webhook', () => {
  beforeEach(() => {
    sendMessage.mockClear();
  });

  it('handles the live core envelope { deliveryId, event: {...} }', async () => {
    const db = createMockDb({ mailbox: ACTIVE_MAILBOX });
    const app = createTestApp(db);
    const tasks: Promise<unknown>[] = [];

    const res = await post(
      app,
      {
        deliveryId: 42,
        event: {
          id: 'evt-1',
          type: 'email.send.requested',
          source: 'eldrin-crm',
          version: 1,
          payload: { ...SEND_PAYLOAD, userId: 'user-1' },
        },
      },
      { tasks },
    );

    expect(res.status).toBe(200);
    expect(((await res.json()) as { received: boolean }).received).toBe(true);

    await Promise.all(tasks);
    expect(sendMessage).toHaveBeenCalledTimes(1);
    expect(sendMessage).toHaveBeenCalledWith(
      'mock-access-token',
      expect.objectContaining({ to: ['jane@acme.com'], subject: 'Hello' }),
    );
    // Thread + email rows stored
    expect(db.insert).toHaveBeenCalledTimes(2);
  });

  it('handles the flat dev shape { type, payload, userId }', async () => {
    const db = createMockDb({ mailbox: ACTIVE_MAILBOX });
    const app = createTestApp(db);
    const tasks: Promise<unknown>[] = [];

    const res = await post(
      app,
      { type: 'email.send.requested', payload: SEND_PAYLOAD, userId: 'user-1' },
      { tasks },
    );

    expect(res.status).toBe(200);
    await Promise.all(tasks);
    expect(sendMessage).toHaveBeenCalledTimes(1);
  });

  it('prefers the payload userId over the top-level one', async () => {
    const db = createMockDb({ mailbox: ACTIVE_MAILBOX });
    const app = createTestApp(db);
    const tasks: Promise<unknown>[] = [];

    await post(
      app,
      {
        type: 'email.send.requested',
        payload: { ...SEND_PAYLOAD, userId: 'payload-user' },
        userId: 'top-level-user',
      },
      { tasks },
    );

    await Promise.all(tasks);
    expect(db.query.connectedMailboxes.findFirst).toHaveBeenCalled();
    expect(sendMessage).toHaveBeenCalledTimes(1);
  });

  it('drops email.send.requested without a userId anywhere', async () => {
    const db = createMockDb({ mailbox: ACTIVE_MAILBOX });
    const app = createTestApp(db);
    const tasks: Promise<unknown>[] = [];

    const res = await post(
      app,
      { type: 'email.send.requested', payload: SEND_PAYLOAD },
      { tasks },
    );

    expect(res.status).toBe(200);
    await Promise.all(tasks);
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it('handles user.deleted from the live envelope', async () => {
    const db = createMockDb();
    const app = createTestApp(db);
    const tasks: Promise<unknown>[] = [];

    const res = await post(
      app,
      {
        deliveryId: 7,
        event: {
          id: 'evt-2',
          type: 'user.deleted',
          source: 'eldrin-core',
          version: 1,
          payload: { userId: 'user-9' },
        },
      },
      { tasks },
    );

    expect(res.status).toBe(200);
    await Promise.all(tasks);
    expect(db.query.connectedMailboxes.findMany).toHaveBeenCalled();
  });

  it('acknowledges unknown event types', async () => {
    const db = createMockDb();
    const app = createTestApp(db);

    const res = await post(app, { type: 'user.updated', payload: {} });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { received: boolean }).received).toBe(true);
  });

  it('rejects requests without the service secret', async () => {
    const db = createMockDb();
    const app = createTestApp(db);

    const res = await post(app, { type: 'user.updated', payload: {} }, { headers: {} });
    expect(res.status).toBe(401);
    expect(((await res.json()) as { error: string }).error).toBe('Invalid service secret');
  });

  it('rejects requests with a wrong service secret', async () => {
    const db = createMockDb();
    const app = createTestApp(db);

    const res = await post(
      app,
      { type: 'user.updated', payload: {} },
      { headers: { 'X-Eldrin-App-Secret': 'wrong-secret' } },
    );
    expect(res.status).toBe(401);
  });

  it('stays open when JWT_SECRET is not configured (standalone dev)', async () => {
    const db = createMockDb();
    const app = createTestApp(db);

    const res = await post(
      app,
      { type: 'user.updated', payload: {} },
      { headers: {}, env: {} as Env },
    );
    expect(res.status).toBe(200);
  });

  it('rejects bodies without a type', async () => {
    const db = createMockDb();
    const app = createTestApp(db);

    const res = await post(app, { payload: {} });
    expect(res.status).toBe(400);
  });
});
