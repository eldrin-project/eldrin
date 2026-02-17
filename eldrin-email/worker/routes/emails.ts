/**
 * Inbox, sent, thread, and search API routes.
 *
 * All routes are user-scoped: users only see threads/emails from their own mailboxes.
 * Thread detail transparently fetches bodies on demand when sync_depth is metadata/thread_only.
 */

import { Hono } from 'hono';
import { eq, and, desc, asc, like, or, sql, inArray } from 'drizzle-orm';
import { connectedMailboxes, emailThreads, emails, type Database } from '../db';
import { generateId, now } from '../utils';
import { fetchThreadBodies } from '../services/body-fetch';
import { decryptToken } from '../services/crypto';
import { refreshGmailToken } from '../services/oauth-gmail';
import { sendMessage } from '../services/gmail-client';

type Variables = { db: Database; userId: string };

export const emailRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

// ── Helpers ──────────────────────────────────────────────────────────────────

async function getUserMailboxIds(db: Database, userId: string): Promise<string[]> {
  const mailboxes = await db.query.connectedMailboxes.findMany({
    where: eq(connectedMailboxes.userId, userId),
    columns: { id: true },
  });
  return mailboxes.map((m) => m.id);
}

// ── GET /api/inbox — list email threads ──────────────────────────────────────

emailRoutes.get('/api/inbox', async (c) => {
  const userId = c.get('userId');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);

  const db = c.get('db');
  const mailboxIds = await getUserMailboxIds(db, userId);
  if (mailboxIds.length === 0) {
    return c.json({ data: [], pagination: { page: 1, limit: 25, total: 0, pages: 0 } });
  }

  const page = Math.max(1, Number(c.req.query('page')) || 1);
  const limit = Math.min(100, Math.max(1, Number(c.req.query('limit')) || 25));
  const search = c.req.query('search') || '';
  const unreadOnly = c.req.query('unread') === 'true';

  // Build where clause
  const conditions = [
    inArray(emailThreads.mailboxId, mailboxIds),
    eq(emailThreads.isDeleted, false),
    eq(emailThreads.isArchived, false),
  ];
  if (unreadOnly) {
    conditions.push(eq(emailThreads.isRead, false));
  }
  if (search) {
    conditions.push(like(emailThreads.subject, `%${search}%`));
  }
  const where = and(...conditions);

  // Parallel fetch: threads + count
  const offset = (page - 1) * limit;

  const [threads, countResult] = await Promise.all([
    db.select().from(emailThreads)
      .where(where)
      .orderBy(desc(emailThreads.lastMessageAt))
      .limit(limit)
      .offset(offset),
    db.select({ total: sql<number>`count(*)` }).from(emailThreads).where(where),
  ]);

  const total = countResult[0]?.total ?? 0;

  // For each thread, get the latest message for preview data
  const threadPreviews = await Promise.all(
    threads.map(async (thread) => {
      const latestEmail = await db.query.emails.findFirst({
        where: eq(emails.threadId, thread.id),
        orderBy: [desc(emails.receivedAt)],
        columns: {
          fromAddress: true,
          fromName: true,
          snippet: true,
          receivedAt: true,
        },
      });

      return {
        id: thread.id,
        subject: thread.subject,
        fromAddress: latestEmail?.fromAddress ?? '',
        fromName: latestEmail?.fromName ?? null,
        snippet: latestEmail?.snippet ?? '',
        lastMessageAt: thread.lastMessageAt,
        messageCount: thread.messageCount,
        isRead: thread.isRead,
        isStarred: thread.isStarred,
      };
    }),
  );

  return c.json({
    data: threadPreviews,
    pagination: { page, limit, total, pages: Math.ceil(total / limit) },
  });
});

// ── GET /api/inbox/:threadId — get thread with all messages ──────────────────

emailRoutes.get('/api/inbox/:threadId', async (c) => {
  const userId = c.get('userId');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);

  const threadId = c.req.param('threadId');
  const db = c.get('db');
  const mailboxIds = await getUserMailboxIds(db, userId);
  if (mailboxIds.length === 0) return c.json({ error: 'Thread not found' }, 404);

  const thread = await db.query.emailThreads.findFirst({
    where: and(
      eq(emailThreads.id, threadId),
      inArray(emailThreads.mailboxId, mailboxIds),
    ),
  });

  if (!thread) return c.json({ error: 'Thread not found' }, 404);

  // Get the mailbox for this thread (needed for body fetch)
  const mailbox = await db.query.connectedMailboxes.findFirst({
    where: eq(connectedMailboxes.id, thread.mailboxId),
  });

  // Fetch bodies on demand if sync_depth is metadata/thread_only
  if (mailbox && mailbox.syncDepth !== 'full') {
    try {
      await fetchThreadBodies(db, mailbox, threadId, c.env);
    } catch {
      // Body fetch failed — continue with whatever we have
    }
  }

  // Fetch all messages in the thread
  const messages = await db.query.emails.findMany({
    where: eq(emails.threadId, threadId),
    orderBy: [asc(emails.receivedAt)],
  });

  // Mark thread as read
  if (!thread.isRead) {
    await db.update(emailThreads)
      .set({ isRead: true, updatedAt: now() })
      .where(eq(emailThreads.id, threadId));
  }

  // Parse JSON arrays for each message
  const formattedMessages = messages.map((m) => ({
    id: m.id,
    fromAddress: m.fromAddress,
    fromName: m.fromName,
    toAddresses: JSON.parse(m.toAddresses),
    ccAddresses: m.ccAddresses ? JSON.parse(m.ccAddresses) : [],
    bccAddresses: m.bccAddresses ? JSON.parse(m.bccAddresses) : [],
    subject: m.subject,
    bodyText: m.bodyText,
    bodyHtml: m.bodyHtml,
    snippet: m.snippet,
    hasAttachments: m.hasAttachments,
    direction: m.direction,
    sentAt: m.sentAt,
    receivedAt: m.receivedAt,
    isRead: m.isRead,
  }));

  return c.json({
    thread: {
      id: thread.id,
      subject: thread.subject,
      messageCount: thread.messageCount,
      isRead: true, // We just marked it
      isStarred: thread.isStarred,
      isArchived: thread.isArchived,
      lastMessageAt: thread.lastMessageAt,
    },
    messages: formattedMessages,
  });
});

// ── PATCH /api/inbox/:threadId — update thread state ─────────────────────────

emailRoutes.patch('/api/inbox/:threadId', async (c) => {
  const userId = c.get('userId');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);

  const threadId = c.req.param('threadId');
  const db = c.get('db');
  const mailboxIds = await getUserMailboxIds(db, userId);

  const thread = await db.query.emailThreads.findFirst({
    where: and(
      eq(emailThreads.id, threadId),
      inArray(emailThreads.mailboxId, mailboxIds),
    ),
  });

  if (!thread) return c.json({ error: 'Thread not found' }, 404);

  const body = await c.req.json() as {
    isRead?: boolean;
    isStarred?: boolean;
    isArchived?: boolean;
  };

  const updates: Record<string, unknown> = { updatedAt: now() };
  if (body.isRead !== undefined) updates.isRead = body.isRead;
  if (body.isStarred !== undefined) updates.isStarred = body.isStarred;
  if (body.isArchived !== undefined) updates.isArchived = body.isArchived;

  await db.update(emailThreads)
    .set(updates)
    .where(eq(emailThreads.id, threadId));

  return c.json({ updated: true });
});

// ── GET /api/sent — list sent emails ─────────────────────────────────────────

emailRoutes.get('/api/sent', async (c) => {
  const userId = c.get('userId');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);

  const db = c.get('db');
  const mailboxIds = await getUserMailboxIds(db, userId);
  if (mailboxIds.length === 0) {
    return c.json({ data: [], pagination: { page: 1, limit: 25, total: 0, pages: 0 } });
  }

  const page = Math.max(1, Number(c.req.query('page')) || 1);
  const limit = Math.min(100, Math.max(1, Number(c.req.query('limit')) || 25));
  const search = c.req.query('search') || '';

  const conditions = [
    inArray(emails.mailboxId, mailboxIds),
    eq(emails.direction, 'outbound'),
  ];
  if (search) {
    conditions.push(
      or(
        like(emails.subject, `%${search}%`),
        like(emails.fromAddress, `%${search}%`),
      )!,
    );
  }
  const where = and(...conditions);

  const offset = (page - 1) * limit;

  const [sentEmails, countResult] = await Promise.all([
    db.select({
      id: emails.id,
      threadId: emails.threadId,
      toAddresses: emails.toAddresses,
      subject: emails.subject,
      snippet: emails.snippet,
      sentAt: emails.sentAt,
      receivedAt: emails.receivedAt,
    }).from(emails)
      .where(where)
      .orderBy(desc(emails.receivedAt))
      .limit(limit)
      .offset(offset),
    db.select({ total: sql<number>`count(*)` }).from(emails).where(where),
  ]);

  const total = countResult[0]?.total ?? 0;

  const data = sentEmails.map((e) => ({
    id: e.id,
    threadId: e.threadId,
    toAddresses: JSON.parse(e.toAddresses),
    subject: e.subject,
    snippet: e.snippet,
    sentAt: e.sentAt ?? e.receivedAt,
  }));

  return c.json({
    data,
    pagination: { page, limit, total, pages: Math.ceil(total / limit) },
  });
});

// ── GET /api/email/search — full-text search ─────────────────────────────────

emailRoutes.get('/api/email/search', async (c) => {
  const userId = c.get('userId');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);

  const db = c.get('db');
  const mailboxIds = await getUserMailboxIds(db, userId);
  if (mailboxIds.length === 0) {
    return c.json({ data: [], pagination: { page: 1, limit: 25, total: 0, pages: 0 } });
  }

  const q = c.req.query('q') || '';
  if (!q) return c.json({ data: [], pagination: { page: 1, limit: 25, total: 0, pages: 0 } });

  const page = Math.max(1, Number(c.req.query('page')) || 1);
  const limit = Math.min(100, Math.max(1, Number(c.req.query('limit')) || 25));
  const offset = (page - 1) * limit;

  const where = and(
    inArray(emails.mailboxId, mailboxIds),
    or(
      like(emails.subject, `%${q}%`),
      like(emails.fromAddress, `%${q}%`),
      like(emails.bodyText, `%${q}%`),
    ),
  );

  const [results, countResult] = await Promise.all([
    db.select({
      id: emails.id,
      threadId: emails.threadId,
      fromAddress: emails.fromAddress,
      fromName: emails.fromName,
      subject: emails.subject,
      snippet: emails.snippet,
      receivedAt: emails.receivedAt,
      direction: emails.direction,
    }).from(emails)
      .where(where)
      .orderBy(desc(emails.receivedAt))
      .limit(limit)
      .offset(offset),
    db.select({ total: sql<number>`count(*)` }).from(emails).where(where),
  ]);

  const total = countResult[0]?.total ?? 0;

  return c.json({
    data: results,
    pagination: { page, limit, total, pages: Math.ceil(total / limit) },
  });
});

// ── POST /api/email/send — send an email ──────────────────────────────────────

emailRoutes.post('/api/email/send', async (c) => {
  const userId = c.get('userId');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);

  const db = c.get('db');
  const body = await c.req.json() as {
    mailboxId: string;
    to: string[];
    cc?: string[];
    bcc?: string[];
    subject: string;
    bodyHtml: string;
    bodyText?: string;
    inReplyTo?: string;
    threadId?: string;
    scheduledAt?: number;
  };

  // Validate required fields
  if (!body.mailboxId || !body.to?.length || !body.subject || !body.bodyHtml) {
    return c.json({ error: 'Missing required fields: mailboxId, to, subject, bodyHtml' }, 400);
  }

  // Verify mailbox ownership
  const mailbox = await db.query.connectedMailboxes.findFirst({
    where: and(
      eq(connectedMailboxes.id, body.mailboxId),
      eq(connectedMailboxes.userId, userId),
    ),
  });

  if (!mailbox) return c.json({ error: 'Mailbox not found' }, 404);

  // Resolve provider thread ID if replying within an existing thread
  let providerThreadId: string | undefined;
  let localThreadId = body.threadId;

  if (localThreadId) {
    const thread = await db.query.emailThreads.findFirst({
      where: eq(emailThreads.id, localThreadId),
      columns: { providerThreadId: true },
    });
    if (thread) providerThreadId = thread.providerThreadId;
  }

  const timestamp = now();
  const emailId = generateId();

  // If scheduled for the future, store without sending
  if (body.scheduledAt && body.scheduledAt > timestamp) {
    // Create or find thread for the scheduled email
    if (!localThreadId) {
      localThreadId = generateId();
      await db.insert(emailThreads).values({
        id: localThreadId,
        mailboxId: mailbox.id,
        providerThreadId: `local-${localThreadId}`,
        subject: body.subject,
        lastMessageAt: timestamp,
        messageCount: 1,
        isRead: true,
        createdAt: timestamp,
        updatedAt: timestamp,
      });
    }

    await db.insert(emails).values({
      id: emailId,
      threadId: localThreadId,
      mailboxId: mailbox.id,
      providerMessageId: `scheduled-${emailId}`,
      messageId: `<${emailId}@eldrin-email.local>`,
      inReplyTo: body.inReplyTo ?? null,
      fromAddress: mailbox.emailAddress,
      fromName: mailbox.displayName,
      toAddresses: JSON.stringify(body.to),
      ccAddresses: JSON.stringify(body.cc ?? []),
      bccAddresses: JSON.stringify(body.bcc ?? []),
      subject: body.subject,
      bodyText: body.bodyText ?? null,
      bodyHtml: body.bodyHtml,
      snippet: (body.bodyText ?? body.bodyHtml.replace(/<[^>]*>/g, '')).slice(0, 200),
      hasAttachments: false,
      direction: 'outbound',
      sentAt: null,
      receivedAt: timestamp,
      labels: JSON.stringify([]),
      isRead: true,
      status: 'scheduled',
      scheduledAt: body.scheduledAt,
      createdAt: timestamp,
    });

    return c.json({ id: emailId, status: 'scheduled', scheduledAt: body.scheduledAt });
  }

  // Send immediately via Gmail API
  let accessToken = await decryptToken(mailbox.accessTokenEncrypted, c.env.JWT_SECRET);

  // Refresh if expired
  if (mailbox.tokenExpiresAt <= timestamp) {
    const refreshToken = await decryptToken(mailbox.refreshTokenEncrypted, c.env.JWT_SECRET);
    const refreshed = await refreshGmailToken(
      refreshToken,
      c.env.GOOGLE_CLIENT_ID,
      c.env.GOOGLE_CLIENT_SECRET,
    );
    accessToken = refreshed.accessToken;

    const newEncrypted = await (await import('../services/crypto')).encryptToken(
      refreshed.accessToken,
      c.env.JWT_SECRET,
    );
    await db.update(connectedMailboxes)
      .set({
        accessTokenEncrypted: newEncrypted,
        tokenExpiresAt: timestamp + refreshed.expiresIn * 1000,
        updatedAt: timestamp,
      })
      .where(eq(connectedMailboxes.id, mailbox.id));
  }

  const gmailResult = await sendMessage(accessToken, {
    from: mailbox.emailAddress,
    to: body.to,
    cc: body.cc,
    bcc: body.bcc,
    subject: body.subject,
    bodyHtml: body.bodyHtml,
    bodyText: body.bodyText,
    inReplyTo: body.inReplyTo,
    threadId: providerThreadId,
  });

  // Create or update thread
  if (!localThreadId) {
    localThreadId = generateId();
    await db.insert(emailThreads).values({
      id: localThreadId,
      mailboxId: mailbox.id,
      providerThreadId: gmailResult.threadId,
      subject: body.subject,
      lastMessageAt: timestamp,
      messageCount: 1,
      isRead: true,
      createdAt: timestamp,
      updatedAt: timestamp,
    });
  } else {
    await db.update(emailThreads)
      .set({
        lastMessageAt: timestamp,
        messageCount: sql`${emailThreads.messageCount} + 1`,
        updatedAt: timestamp,
      })
      .where(eq(emailThreads.id, localThreadId));
  }

  // Store sent email
  await db.insert(emails).values({
    id: emailId,
    threadId: localThreadId,
    mailboxId: mailbox.id,
    providerMessageId: gmailResult.id,
    messageId: `<${gmailResult.id}@gmail.com>`,
    inReplyTo: body.inReplyTo ?? null,
    fromAddress: mailbox.emailAddress,
    fromName: mailbox.displayName,
    toAddresses: JSON.stringify(body.to),
    ccAddresses: JSON.stringify(body.cc ?? []),
    bccAddresses: JSON.stringify(body.bcc ?? []),
    subject: body.subject,
    bodyText: body.bodyText ?? null,
    bodyHtml: body.bodyHtml,
    snippet: (body.bodyText ?? body.bodyHtml.replace(/<[^>]*>/g, '')).slice(0, 200),
    hasAttachments: false,
    direction: 'outbound',
    sentAt: timestamp,
    receivedAt: timestamp,
    labels: JSON.stringify(['SENT']),
    isRead: true,
    status: 'sent',
    createdAt: timestamp,
  });

  return c.json({ id: emailId, status: 'sent', threadId: localThreadId });
});
