/**
 * Platform event webhook handler.
 *
 * Receives events pushed from the eldrin-core event bus. The live core
 * delivers `{ deliveryId, event: { id, type, source, payload, version } }`;
 * a flat `{ type, payload, userId? }` shape is also accepted for dev/testing.
 * Events are acknowledged immediately and processed asynchronously via waitUntil.
 */

import { Hono } from 'hono';
import { eq, and, or, inArray } from 'drizzle-orm';
import { connectedMailboxes, emailThreads, emails, emailTemplates, emailTracking, trackingEvents, type Database } from '../db';
import { generateId, now } from '../utils';
import { resolveMergeFields } from '../services/merge-fields';
import { getProvider, getAccessToken } from '../services/providers';
import { prepareTrackedEmail } from '../services/tracking';

type Variables = { db: Database; userId: string };

/**
 * Validate the shared service secret sent by eldrin-core on pushed events.
 *
 * When JWT_SECRET is configured the `X-Eldrin-App-Secret` header must match
 * it; when unset the webhook stays open (standalone dev without a core).
 * Plain equality is sufficient for the single-tenant platform today; kept in
 * one helper so it can be swapped for an HMAC-based scheme later.
 */
function isValidServiceSecret(
  configuredSecret: string | undefined,
  header: string | undefined,
): boolean {
  if (!configuredSecret) return true;
  return header === configuredSecret;
}

interface EventEnvelope {
  type: string;
  source: string | null;
  payload: Record<string, unknown>;
}

function parseEnvelope(body: unknown): EventEnvelope | null {
  if (typeof body !== 'object' || body === null) return null;
  const record = body as Record<string, unknown>;
  // Live core shape: { deliveryId, event: { type, source, payload } }
  const candidate =
    typeof record.event === 'object' && record.event !== null
      ? (record.event as Record<string, unknown>)
      : record;

  if (typeof candidate.type !== 'string' || candidate.type.length === 0) return null;
  const payload =
    typeof candidate.payload === 'object' && candidate.payload !== null
      ? (candidate.payload as Record<string, unknown>)
      : {};
  return {
    type: candidate.type,
    source: typeof candidate.source === 'string' ? candidate.source : null,
    payload,
  };
}

export const eventRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

// ── POST /api/_events/webhook — receive platform events ─────────────────────

eventRoutes.post('/api/_events/webhook', async (c) => {
  if (!isValidServiceSecret(c.env.JWT_SECRET, c.req.header('X-Eldrin-App-Secret'))) {
    return c.json({ error: 'Invalid service secret' }, 401);
  }

  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }

  const envelope = parseEnvelope(body);
  if (!envelope) {
    return c.json({ error: 'Missing event type' }, 400);
  }

  console.log('[email] Received event:', envelope.type);

  const db = c.get('db');

  switch (envelope.type) {
    case 'email.send.requested': {
      // The live envelope carries userId inside the event payload; the flat
      // dev shape may still put it at the top level of the body.
      const topLevelUserId = (body as Record<string, unknown>).userId;
      const userId =
        typeof envelope.payload.userId === 'string'
          ? envelope.payload.userId
          : typeof topLevelUserId === 'string'
            ? topLevelUserId
            : undefined;
      c.executionCtx.waitUntil(
        handleSendRequested(db, envelope.payload, userId, c.env, c.req.url),
      );
      break;
    }

    case 'user.deleted':
      c.executionCtx.waitUntil(
        handleUserDeleted(db, envelope.payload),
      );
      break;

    default:
      console.log('[email] Unhandled event type:', envelope.type);
  }

  return c.json({ received: true });
});

// ── Event handlers ──────────────────────────────────────────────────────────

async function handleSendRequested(
  db: Database,
  payload: Record<string, unknown>,
  userId: string | undefined,
  env: Env,
  requestUrl: string,
): Promise<void> {
  try {
    if (!userId) {
      console.error('[email] email.send.requested: missing userId');
      return;
    }

    const to = payload.to as string[];
    const subject = payload.subject as string;
    let bodyHtml = payload.bodyHtml as string;
    const bodyText = payload.bodyText as string | undefined;
    const templateId = payload.templateId as string | undefined;
    const mergeContext = payload.mergeContext as Record<string, unknown> | undefined;
    const relatedApp = payload.relatedApp as string | undefined;
    const relatedRecordId = payload.relatedRecordId as string | undefined;

    if (!to?.length || (!subject && !templateId)) {
      console.error('[email] email.send.requested: missing to or subject');
      return;
    }

    // If template is specified, resolve it
    let finalSubject = subject;
    let finalBodyHtml = bodyHtml;
    let finalBodyText = bodyText;

    if (templateId) {
      const template = await db.query.emailTemplates.findFirst({
        where: and(
          eq(emailTemplates.id, templateId),
          or(
            eq(emailTemplates.ownerId, userId),
            eq(emailTemplates.isShared, true),
          ),
        ),
      });

      if (!template) {
        console.error('[email] email.send.requested: template not found:', templateId);
        return;
      }

      const context = mergeContext ?? {};
      finalSubject = resolveMergeFields(template.subject, context);
      finalBodyHtml = resolveMergeFields(template.bodyHtml, context);
      if (template.bodyText) {
        finalBodyText = resolveMergeFields(template.bodyText, context);
      }
    }

    if (!finalSubject || !finalBodyHtml) {
      console.error('[email] email.send.requested: could not resolve subject/body');
      return;
    }

    // Find user's active mailbox
    const mailbox = await db.query.connectedMailboxes.findFirst({
      where: and(
        eq(connectedMailboxes.userId, userId),
        eq(connectedMailboxes.syncStatus, 'active'),
      ),
    });

    if (!mailbox) {
      console.error('[email] email.send.requested: no active mailbox for user:', userId);
      return;
    }

    const timestamp = now();
    const emailId = generateId();

    // Get access token via provider abstraction
    const provider = getProvider(mailbox.provider);
    const accessToken = await getAccessToken(db, mailbox, env, provider);

    // Inject tracking
    const baseUrl = new URL(requestUrl).origin;
    let sendHtml = finalBodyHtml;
    try {
      const tracked = await prepareTrackedEmail(db, finalBodyHtml, emailId, baseUrl);
      sendHtml = tracked.html;
    } catch {
      // Continue without tracking
    }

    // Send via provider
    const sendResult = await provider.sendMessage(accessToken, {
      from: mailbox.emailAddress,
      to,
      subject: finalSubject,
      bodyHtml: sendHtml,
      bodyText: finalBodyText,
    });

    // Store
    const threadId = generateId();
    await db.insert(emailThreads).values({
      id: threadId,
      mailboxId: mailbox.id,
      providerThreadId: sendResult.threadId,
      subject: finalSubject,
      lastMessageAt: timestamp,
      messageCount: 1,
      isRead: true,
      createdAt: timestamp,
      updatedAt: timestamp,
    });

    await db.insert(emails).values({
      id: emailId,
      threadId,
      mailboxId: mailbox.id,
      providerMessageId: sendResult.id,
      messageId: `<${sendResult.id}@${mailbox.provider}.provider>`,
      fromAddress: mailbox.emailAddress,
      fromName: mailbox.displayName,
      toAddresses: JSON.stringify(to),
      ccAddresses: JSON.stringify([]),
      bccAddresses: JSON.stringify([]),
      subject: finalSubject,
      bodyText: finalBodyText ?? null,
      bodyHtml: finalBodyHtml,
      snippet: (finalBodyText ?? finalBodyHtml.replace(/<[^>]*>/g, '')).slice(0, 200),
      hasAttachments: false,
      direction: 'outbound',
      sentAt: timestamp,
      receivedAt: timestamp,
      labels: JSON.stringify(['SENT']),
      isRead: true,
      status: 'sent',
      relatedApp: relatedApp ?? null,
      relatedRecordId: relatedRecordId ?? null,
      createdAt: timestamp,
    });

    console.log('[email] email.send.requested: sent', emailId, 'to', to.join(', '));
  } catch (err) {
    console.error('[email] email.send.requested failed:', err);
  }
}

async function handleUserDeleted(
  db: Database,
  payload: Record<string, unknown>,
): Promise<void> {
  try {
    const userId = payload.userId as string;
    if (!userId) {
      console.error('[email] user.deleted: missing userId in payload');
      return;
    }

    // Find all mailboxes for this user
    const mailboxes = await db.query.connectedMailboxes.findMany({
      where: eq(connectedMailboxes.userId, userId),
      columns: { id: true },
    });

    if (mailboxes.length === 0) {
      console.log('[email] user.deleted: no mailboxes for user:', userId);
      return;
    }

    const mailboxIds = mailboxes.map((m) => m.id);

    // Delete tracking events and records for emails in these mailboxes
    const userEmails = await db.query.emails.findMany({
      where: inArray(emails.mailboxId, mailboxIds),
      columns: { id: true },
    });
    const emailIds = userEmails.map((e) => e.id);

    if (emailIds.length > 0) {
      const trackingRecords = await db.query.emailTracking.findMany({
        where: inArray(emailTracking.emailId, emailIds),
        columns: { trackingId: true },
      });
      const trackingIds = trackingRecords.map((t) => t.trackingId);

      if (trackingIds.length > 0) {
        await db.delete(trackingEvents)
          .where(inArray(trackingEvents.trackingId, trackingIds));
        await db.delete(emailTracking)
          .where(inArray(emailTracking.emailId, emailIds));
      }
    }

    // Cascade: threads → emails are deleted by FK cascade
    // Delete threads for these mailboxes
    await db.delete(emailThreads)
      .where(inArray(emailThreads.mailboxId, mailboxIds));

    // Delete user's templates
    await db.delete(emailTemplates)
      .where(eq(emailTemplates.ownerId, userId));

    // Delete mailboxes (this also cascades emails via FK)
    await db.delete(connectedMailboxes)
      .where(eq(connectedMailboxes.userId, userId));

    console.log(
      '[email] user.deleted: cleaned up',
      mailboxes.length, 'mailbox(es) for user:', userId,
    );
  } catch (err) {
    console.error('[email] user.deleted cleanup failed:', err);
  }
}
