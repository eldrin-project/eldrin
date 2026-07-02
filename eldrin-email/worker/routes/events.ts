/**
 * Platform event webhook handler.
 *
 * Receives events from the Eldrin platform event bus and processes them.
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

export const eventRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

// ── POST /api/_events/webhook — receive platform events ─────────────────────

eventRoutes.post('/api/_events/webhook', async (c) => {
  const body = await c.req.json() as {
    type: string;
    payload: Record<string, unknown>;
    userId?: string;
  };

  console.log('[email] Received event:', body.type);

  const db = c.get('db');

  switch (body.type) {
    case 'email.send.requested':
      c.executionCtx.waitUntil(
        handleSendRequested(db, body.payload, body.userId, c.env, c.req.url),
      );
      break;

    case 'user.deleted':
      c.executionCtx.waitUntil(
        handleUserDeleted(db, body.payload),
      );
      break;

    default:
      console.log('[email] Unhandled event type:', body.type);
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
