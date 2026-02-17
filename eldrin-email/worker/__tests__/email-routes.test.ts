import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Hono } from 'hono';

// Mock body-fetch to avoid complex setup
vi.mock('../services/body-fetch', () => ({
  fetchThreadBodies: vi.fn().mockResolvedValue([]),
}));

import { emailRoutes } from '../routes/emails';

// ── Mock database ────────────────────────────────────────────────────────────

function createMockDb(data: {
  mailboxes?: { id: string; userId: string }[];
  threads?: Record<string, unknown>[];
  emails?: Record<string, unknown>[];
} = {}) {
  const mailboxes = data.mailboxes ?? [];
  const threads = data.threads ?? [];
  const emailRows = data.emails ?? [];

  return {
    query: {
      connectedMailboxes: {
        findMany: vi.fn().mockImplementation(({ where }: any) => {
          return Promise.resolve(mailboxes);
        }),
        findFirst: vi.fn().mockImplementation(() => {
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
  };
}

// ── Test app factory ─────────────────────────────────────────────────────────

function createTestApp(db: ReturnType<typeof createMockDb>) {
  const app = new Hono();
  app.use('*', async (c, next) => {
    c.set('db', db);
    await next();
  });
  app.route('', emailRoutes);
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

    const json = await res.json();
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

    const json = await res.json();
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

    const json = await res.json();
    expect(json.data).toEqual([]);
  });
});
