import { describe, it, expect, vi } from 'vitest';
import { Hono } from 'hono';

// Mock body-fetch to avoid complex setup
vi.mock('../services/body-fetch', () => ({
  fetchThreadBodies: vi.fn().mockResolvedValue([]),
}));

// Mock send dependencies
vi.mock('../services/crypto', () => ({
  decryptToken: vi.fn().mockResolvedValue('mock-access-token'),
  encryptToken: vi.fn().mockResolvedValue('mock-encrypted'),
}));

vi.mock('../services/oauth-gmail', () => ({
  refreshGmailToken: vi.fn().mockResolvedValue({
    accessToken: 'refreshed-token',
    expiresIn: 3600,
  }),
}));

vi.mock('../services/gmail-client', () => ({
  sendMessage: vi.fn().mockResolvedValue({
    id: 'gmail-msg-1',
    threadId: 'gmail-thread-1',
    labelIds: ['SENT'],
  }),
}));

import { emailRoutes } from '../routes/emails';

// ── Mock database ────────────────────────────────────────────────────────────

function createMockDb(data: {
  mailboxes?: { id: string; userId: string; emailAddress?: string; syncDepth?: string; accessTokenEncrypted?: string; refreshTokenEncrypted?: string; tokenExpiresAt?: number; displayName?: string | null }[];
  threads?: Record<string, unknown>[];
  emails?: Record<string, unknown>[];
} = {}) {
  const mailboxes = data.mailboxes ?? [];
  const threads = data.threads ?? [];
  const emailRows = data.emails ?? [];

  return {
    query: {
      connectedMailboxes: {
        findMany: vi.fn().mockResolvedValue(mailboxes),
        findFirst: vi.fn().mockImplementation((opts?: any) => {
          if (opts?.where && mailboxes.length > 0) return Promise.resolve(mailboxes[0]);
          return Promise.resolve(mailboxes[0] ?? null);
        }),
      },
      emailThreads: {
        findFirst: vi.fn().mockImplementation(() => {
          return Promise.resolve(threads[0] ?? null);
        }),
        findMany: vi.fn().mockResolvedValue(threads),
      },
      emails: {
        findFirst: vi.fn().mockResolvedValue(emailRows[0] ?? null),
        findMany: vi.fn().mockResolvedValue(emailRows),
      },
    },
    select: vi.fn().mockReturnValue({
      from: vi.fn().mockReturnValue({
        where: vi.fn().mockReturnValue({
          orderBy: vi.fn().mockReturnValue({
            limit: vi.fn().mockReturnValue({
              offset: vi.fn().mockResolvedValue(threads),
            }),
          }),
        }),
      }),
    }),
    update: vi.fn().mockReturnValue({
      set: vi.fn().mockReturnValue({
        where: vi.fn().mockResolvedValue(undefined),
      }),
    }),
    insert: vi.fn().mockReturnValue({
      values: vi.fn().mockResolvedValue(undefined),
    }),
  };
}

// ── Test app factory ─────────────────────────────────────────────────────────

function createTestApp(db: ReturnType<typeof createMockDb>) {
  const app = new Hono<{ Bindings: { JWT_SECRET: string; GOOGLE_CLIENT_ID: string; GOOGLE_CLIENT_SECRET: string } }>();
  app.use('*', async (c, next) => {
    (c as any).set('db', db);
    const userId = c.req.header('X-Eldrin-User-Id');
    if (userId) (c as any).set('userId', userId);
    await next();
  });
  app.route('', emailRoutes as any);
  return app;
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('GET /api/inbox', () => {
  it('returns 401 without user header', async () => {
    const db = createMockDb();
    const app = createTestApp(db);

    const res = await app.request('/api/inbox');
    expect(res.status).toBe(401);
  });

  it('returns empty list when user has no mailboxes', async () => {
    const db = createMockDb({ mailboxes: [] });
    const app = createTestApp(db);

    const res = await app.request('/api/inbox', {
      headers: { 'X-Eldrin-User-Id': 'user-1' },
    });
    expect(res.status).toBe(200);

    const json = (await res.json()) as any;
    expect(json.data).toEqual([]);
    expect(json.pagination.total).toBe(0);
  });
});

describe('GET /api/inbox/:threadId', () => {
  it('returns 401 without user header', async () => {
    const db = createMockDb();
    const app = createTestApp(db);

    const res = await app.request('/api/inbox/thread-1');
    expect(res.status).toBe(401);
  });

  it('returns 404 when user has no mailboxes', async () => {
    const db = createMockDb({ mailboxes: [] });
    const app = createTestApp(db);

    const res = await app.request('/api/inbox/thread-1', {
      headers: { 'X-Eldrin-User-Id': 'user-1' },
    });
    expect(res.status).toBe(404);
  });
});

describe('PATCH /api/inbox/:threadId', () => {
  it('returns 401 without user header', async () => {
    const db = createMockDb();
    const app = createTestApp(db);

    const res = await app.request('/api/inbox/thread-1', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ isStarred: true }),
    });
    expect(res.status).toBe(401);
  });
});

describe('GET /api/sent', () => {
  it('returns 401 without user header', async () => {
    const db = createMockDb();
    const app = createTestApp(db);

    const res = await app.request('/api/sent');
    expect(res.status).toBe(401);
  });

  it('returns empty list when user has no mailboxes', async () => {
    const db = createMockDb({ mailboxes: [] });
    const app = createTestApp(db);

    const res = await app.request('/api/sent', {
      headers: { 'X-Eldrin-User-Id': 'user-1' },
    });
    expect(res.status).toBe(200);

    const json = (await res.json()) as any;
    expect(json.data).toEqual([]);
  });
});

describe('GET /api/email/search', () => {
  it('returns 401 without user header', async () => {
    const db = createMockDb();
    const app = createTestApp(db);

    const res = await app.request('/api/email/search?q=test');
    expect(res.status).toBe(401);
  });

  it('returns empty when no query provided', async () => {
    const db = createMockDb({ mailboxes: [{ id: 'mb-1', userId: 'user-1' }] });
    const app = createTestApp(db);

    const res = await app.request('/api/email/search', {
      headers: { 'X-Eldrin-User-Id': 'user-1' },
    });
    expect(res.status).toBe(200);

    const json = (await res.json()) as any;
    expect(json.data).toEqual([]);
  });
});

describe('POST /api/email/send', () => {
  it('returns 401 without user header', async () => {
    const db = createMockDb();
    const app = createTestApp(db);

    const res = await app.request('/api/email/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mailboxId: 'mb-1',
        to: ['test@example.com'],
        subject: 'Test',
        bodyHtml: '<p>Hello</p>',
      }),
    });
    expect(res.status).toBe(401);
  });

  it('returns 400 when required fields missing', async () => {
    const db = createMockDb({ mailboxes: [{ id: 'mb-1', userId: 'user-1' }] });
    const app = createTestApp(db);

    const res = await app.request('/api/email/send', {
      method: 'POST',
      headers: {
        'X-Eldrin-User-Id': 'user-1',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ mailboxId: 'mb-1' }),
    });
    expect(res.status).toBe(400);
  });

  it('returns 404 when mailbox not owned by user', async () => {
    const db = createMockDb({ mailboxes: [] });
    // Override findFirst to return null for ownership check
    db.query.connectedMailboxes.findFirst = vi.fn().mockResolvedValue(null);
    const app = createTestApp(db);

    const res = await app.request('/api/email/send', {
      method: 'POST',
      headers: {
        'X-Eldrin-User-Id': 'user-1',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        mailboxId: 'mb-1',
        to: ['test@example.com'],
        subject: 'Test',
        bodyHtml: '<p>Hello</p>',
      }),
    });
    expect(res.status).toBe(404);
  });
});
