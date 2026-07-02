/**
 * Cross-app integration API routes.
 *
 * These endpoints allow other Eldrin apps (CRM, Invoicing, Workflows) to:
 * - Send emails using templates with merge field resolution
 * - Query email history for a contact or related record
 *
 * Authentication is handled by the platform proxy — the requesting app's
 * user context is forwarded via X-Eldrin-User-Id / Authorization headers.
 */

import { Hono } from 'hono';
import { eq, and, desc, or, like, sql, inArray } from 'drizzle-orm';
import { connectedMailboxes, emailThreads, emails, emailTemplates, emailTracking, type Database } from '../db';
import { generateId, now } from '../utils';
import { resolveMergeFields } from '../services/merge-fields';
import { getProvider, getAccessToken } from '../services/providers';
import { prepareTrackedEmail } from '../services/tracking';

type Variables = { db: Database; userId: string };

export const integrationRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

// ── Helpers ──────────────────────────────────────────────────────────────────

async function getUserMailbox(db: Database, userId: string) {
  return db.query.connectedMailboxes.findFirst({
    where: and(
      eq(connectedMailboxes.userId, userId),
      eq(connectedMailboxes.syncStatus, 'active'),
    ),
  });
}

// ── POST /api/email/send-template — send using a template ────────────────────

integrationRoutes.post('/api/email/send-template', async (c) => {
  const userId = c.get('userId');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);

  const db = c.get('db');
  const body = await c.req.json() as {
    templateId: string;
    to: string[];
    cc?: string[];
    bcc?: string[];
    mergeContext?: Record<string, unknown>;
    mailboxId?: string;
    relatedApp?: string;
    relatedRecordId?: string;
  };

  if (!body.templateId || !body.to?.length) {
    return c.json({ error: 'Missing required fields: templateId, to' }, 400);
  }

  // Fetch template
  const template = await db.query.emailTemplates.findFirst({
    where: and(
      eq(emailTemplates.id, body.templateId),
      or(
        eq(emailTemplates.ownerId, userId),
        eq(emailTemplates.isShared, true),
      ),
    ),
  });

  if (!template) return c.json({ error: 'Template not found' }, 404);

  // Resolve merge fields
  const context = body.mergeContext ?? {};
  const subject = resolveMergeFields(template.subject, context);
  const bodyHtml = resolveMergeFields(template.bodyHtml, context);
  const bodyText = template.bodyText
    ? resolveMergeFields(template.bodyText, context)
    : undefined;

  // Find mailbox — use specified mailboxId or first active mailbox
  let mailbox;
  if (body.mailboxId) {
    mailbox = await db.query.connectedMailboxes.findFirst({
      where: and(
        eq(connectedMailboxes.id, body.mailboxId),
        eq(connectedMailboxes.userId, userId),
      ),
    });
  } else {
    mailbox = await getUserMailbox(db, userId);
  }

  if (!mailbox) {
    return c.json({ error: 'No connected mailbox found' }, 404);
  }

  const timestamp = now();
  const emailId = generateId();

  // Get access token via provider abstraction
  const provider = getProvider(mailbox.provider);
  const accessToken = await getAccessToken(db, mailbox, c.env, provider);

  // Inject tracking
  const baseUrl = new URL(c.req.url).origin;
  let sendHtml = bodyHtml;

  try {
    const tracked = await prepareTrackedEmail(db, bodyHtml, emailId, baseUrl);
    sendHtml = tracked.html;
  } catch {
    // Send without tracking
  }

  // Send via provider
  const sendResult = await provider.sendMessage(accessToken, {
    from: mailbox.emailAddress,
    to: body.to,
    cc: body.cc,
    bcc: body.bcc,
    subject,
    bodyHtml: sendHtml,
    bodyText,
  });

  // Create thread
  const threadId = generateId();
  await db.insert(emailThreads).values({
    id: threadId,
    mailboxId: mailbox.id,
    providerThreadId: sendResult.threadId,
    subject,
    lastMessageAt: timestamp,
    messageCount: 1,
    isRead: true,
    createdAt: timestamp,
    updatedAt: timestamp,
  });

  // Store sent email
  await db.insert(emails).values({
    id: emailId,
    threadId,
    mailboxId: mailbox.id,
    providerMessageId: sendResult.id,
    messageId: `<${sendResult.id}@${mailbox.provider}.provider>`,
    fromAddress: mailbox.emailAddress,
    fromName: mailbox.displayName,
    toAddresses: JSON.stringify(body.to),
    ccAddresses: JSON.stringify(body.cc ?? []),
    bccAddresses: JSON.stringify(body.bcc ?? []),
    subject,
    bodyText: bodyText ?? null,
    bodyHtml: bodyHtml,
    snippet: (bodyText ?? bodyHtml.replace(/<[^>]*>/g, '')).slice(0, 200),
    hasAttachments: false,
    direction: 'outbound',
    sentAt: timestamp,
    receivedAt: timestamp,
    labels: JSON.stringify(['SENT']),
    isRead: true,
    status: 'sent',
    relatedApp: body.relatedApp ?? null,
    relatedRecordId: body.relatedRecordId ?? null,
    createdAt: timestamp,
  });

  // Increment template usage
  await db.update(emailTemplates)
    .set({ usageCount: sql`${emailTemplates.usageCount} + 1` })
    .where(eq(emailTemplates.id, body.templateId));

  return c.json({ id: emailId, status: 'sent', threadId, templateId: body.templateId });
});

// ── GET /api/email/history — email history for a contact email ───────────────

integrationRoutes.get('/api/email/history', async (c) => {
  const userId = c.get('userId');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);

  const contactEmail = c.req.query('contactEmail');
  if (!contactEmail) {
    return c.json({ error: 'Missing required query param: contactEmail' }, 400);
  }

  const db = c.get('db');

  // Get user's mailboxes
  const mailboxes = await db.query.connectedMailboxes.findMany({
    where: eq(connectedMailboxes.userId, userId),
    columns: { id: true },
  });
  const mailboxIds = mailboxes.map((m) => m.id);
  if (mailboxIds.length === 0) {
    return c.json({ data: [], pagination: { page: 1, limit: 25, total: 0, pages: 0 } });
  }

  const page = Math.max(1, Number(c.req.query('page')) || 1);
  const limit = Math.min(100, Math.max(1, Number(c.req.query('limit')) || 25));
  const offset = (page - 1) * limit;

  // Match emails where the contact appears in from or to addresses
  const where = and(
    inArray(emails.mailboxId, mailboxIds),
    or(
      eq(emails.fromAddress, contactEmail),
      like(emails.toAddresses, `%${contactEmail}%`),
    ),
  );

  const [results, countResult] = await Promise.all([
    db.select({
      id: emails.id,
      threadId: emails.threadId,
      fromAddress: emails.fromAddress,
      fromName: emails.fromName,
      toAddresses: emails.toAddresses,
      subject: emails.subject,
      snippet: emails.snippet,
      direction: emails.direction,
      sentAt: emails.sentAt,
      receivedAt: emails.receivedAt,
      relatedApp: emails.relatedApp,
      relatedRecordId: emails.relatedRecordId,
      openCount: emailTracking.openCount,
      clickCount: emailTracking.clickCount,
    }).from(emails)
      .leftJoin(emailTracking, eq(emails.id, emailTracking.emailId))
      .where(where)
      .orderBy(desc(emails.receivedAt))
      .limit(limit)
      .offset(offset),
    db.select({ total: sql<number>`count(*)` }).from(emails).where(where),
  ]);

  const total = countResult[0]?.total ?? 0;

  const data = results.map((e) => ({
    id: e.id,
    threadId: e.threadId,
    fromAddress: e.fromAddress,
    fromName: e.fromName,
    toAddresses: JSON.parse(e.toAddresses),
    subject: e.subject,
    snippet: e.snippet,
    direction: e.direction,
    sentAt: e.sentAt,
    receivedAt: e.receivedAt,
    relatedApp: e.relatedApp,
    relatedRecordId: e.relatedRecordId,
    openCount: e.openCount ?? 0,
    clickCount: e.clickCount ?? 0,
  }));

  return c.json({
    data,
    pagination: { page, limit, total, pages: Math.ceil(total / limit) },
  });
});

// ── GET /api/email/history/record — email history for a related record ───────

integrationRoutes.get('/api/email/history/record', async (c) => {
  const userId = c.get('userId');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);

  const relatedApp = c.req.query('relatedApp');
  const relatedRecordId = c.req.query('relatedRecordId');

  if (!relatedApp || !relatedRecordId) {
    return c.json({ error: 'Missing required query params: relatedApp, relatedRecordId' }, 400);
  }

  const db = c.get('db');

  const mailboxes = await db.query.connectedMailboxes.findMany({
    where: eq(connectedMailboxes.userId, userId),
    columns: { id: true },
  });
  const mailboxIds = mailboxes.map((m) => m.id);
  if (mailboxIds.length === 0) {
    return c.json({ data: [], pagination: { page: 1, limit: 25, total: 0, pages: 0 } });
  }

  const page = Math.max(1, Number(c.req.query('page')) || 1);
  const limit = Math.min(100, Math.max(1, Number(c.req.query('limit')) || 25));
  const offset = (page - 1) * limit;

  const where = and(
    inArray(emails.mailboxId, mailboxIds),
    eq(emails.relatedApp, relatedApp),
    eq(emails.relatedRecordId, relatedRecordId),
  );

  const [results, countResult] = await Promise.all([
    db.select({
      id: emails.id,
      threadId: emails.threadId,
      fromAddress: emails.fromAddress,
      fromName: emails.fromName,
      toAddresses: emails.toAddresses,
      subject: emails.subject,
      snippet: emails.snippet,
      direction: emails.direction,
      sentAt: emails.sentAt,
      receivedAt: emails.receivedAt,
      openCount: emailTracking.openCount,
      clickCount: emailTracking.clickCount,
    }).from(emails)
      .leftJoin(emailTracking, eq(emails.id, emailTracking.emailId))
      .where(where)
      .orderBy(desc(emails.receivedAt))
      .limit(limit)
      .offset(offset),
    db.select({ total: sql<number>`count(*)` }).from(emails).where(where),
  ]);

  const total = countResult[0]?.total ?? 0;

  const data = results.map((e) => ({
    id: e.id,
    threadId: e.threadId,
    fromAddress: e.fromAddress,
    fromName: e.fromName,
    toAddresses: JSON.parse(e.toAddresses),
    subject: e.subject,
    snippet: e.snippet,
    direction: e.direction,
    sentAt: e.sentAt,
    receivedAt: e.receivedAt,
    openCount: e.openCount ?? 0,
    clickCount: e.clickCount ?? 0,
  }));

  return c.json({
    data,
    pagination: { page, limit, total, pages: Math.ceil(total / limit) },
  });
});
