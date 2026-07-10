/**
 * Email sync engine.
 *
 * Fetches new emails from connected accounts (Gmail, Outlook, etc.),
 * deduplicates by Message-ID, stores them in D1, and updates the sync cursor.
 *
 * Provider-agnostic: uses the EmailProvider interface so sync logic
 * is identical regardless of the email service.
 *
 * Respects mailbox sync_depth:
 * - full: store everything including body
 * - metadata: store headers/snippet only, body fetched on demand
 * - thread_only: only create/update email_threads rows, no per-message rows
 */

import { eq, and } from 'drizzle-orm';
import type { Database } from '../db';
import { connectedMailboxes, emailThreads, emails } from '../db/schema';
import { generateId, now } from '../utils';
import { getProvider, getAccessToken, ProviderApiError } from './providers';
import type { MessageRef, ParsedEmail } from './providers';
import {
  buildEventBodyText,
  emitEmailReceived,
  type EmailReceivedPayload,
} from './event-emitter';

// ── Types ────────────────────────────────────────────────────────────────────

type MailboxRow = typeof connectedMailboxes.$inferSelect;

export interface SyncResult {
  mailboxId: string;
  messagesProcessed: number;
  threadsCreated: number;
  threadsUpdated: number;
  emailsInserted: number;
  skippedDuplicates: number;
  errors: string[];
}

// ── Configuration ────────────────────────────────────────────────────────────

const DEFAULT_SYNC_DAYS = 30;
const FIRST_SYNC_MAX_MESSAGES = 500;

// ── Thread management ────────────────────────────────────────────────────────

async function findOrCreateThread(
  db: Database,
  mailboxId: string,
  parsed: ParsedEmail,
): Promise<{ threadId: string; isNew: boolean }> {
  const existing = await db.query.emailThreads.findFirst({
    where: and(
      eq(emailThreads.mailboxId, mailboxId),
      eq(emailThreads.providerThreadId, parsed.providerThreadId),
    ),
  });

  if (existing) {
    // Update thread metadata if this message is newer
    if (parsed.receivedAt > existing.lastMessageAt) {
      await db.update(emailThreads)
        .set({
          lastMessageAt: parsed.receivedAt,
          messageCount: existing.messageCount + 1,
          subject: parsed.subject || existing.subject,
          isRead: parsed.isRead && existing.isRead,
          updatedAt: now(),
        })
        .where(eq(emailThreads.id, existing.id));
    } else {
      await db.update(emailThreads)
        .set({
          messageCount: existing.messageCount + 1,
          updatedAt: now(),
        })
        .where(eq(emailThreads.id, existing.id));
    }
    return { threadId: existing.id, isNew: false };
  }

  const threadId = generateId();
  const timestamp = now();

  await db.insert(emailThreads).values({
    id: threadId,
    mailboxId,
    providerThreadId: parsed.providerThreadId,
    subject: parsed.subject,
    lastMessageAt: parsed.receivedAt,
    messageCount: 1,
    isRead: parsed.isRead,
    createdAt: timestamp,
    updatedAt: timestamp,
  });

  return { threadId, isNew: true };
}

// ── Message processing ───────────────────────────────────────────────────────

function determineDirection(parsed: ParsedEmail, mailboxEmail: string): 'inbound' | 'outbound' {
  return parsed.fromAddress.toLowerCase() === mailboxEmail.toLowerCase()
    ? 'outbound'
    : 'inbound';
}

async function isMessageDuplicate(db: Database, messageId: string): Promise<boolean> {
  const existing = await db.query.emails.findFirst({
    where: eq(emails.messageId, messageId),
    columns: { id: true },
  });
  return !!existing;
}

async function insertEmail(
  db: Database,
  threadId: string,
  mailboxId: string,
  parsed: ParsedEmail,
  direction: 'inbound' | 'outbound',
  includeBody: boolean,
): Promise<void> {
  await db.insert(emails).values({
    id: generateId(),
    threadId,
    mailboxId,
    providerMessageId: parsed.providerMessageId,
    messageId: parsed.messageId,
    inReplyTo: parsed.inReplyTo,
    fromAddress: parsed.fromAddress,
    fromName: parsed.fromName,
    toAddresses: JSON.stringify(parsed.toAddresses),
    ccAddresses: JSON.stringify(parsed.ccAddresses),
    bccAddresses: JSON.stringify(parsed.bccAddresses),
    subject: parsed.subject,
    bodyText: includeBody ? parsed.bodyText : null,
    bodyHtml: includeBody ? parsed.bodyHtml : null,
    snippet: parsed.snippet,
    hasAttachments: parsed.hasAttachments,
    direction,
    sentAt: parsed.sentAt,
    receivedAt: parsed.receivedAt,
    labels: JSON.stringify(parsed.labels),
    isRead: parsed.isRead,
    createdAt: now(),
  });
}

// ── Core sync logic ──────────────────────────────────────────────────────────

/**
 * Sync a single mailbox.
 */
export async function syncMailbox(
  db: Database,
  mailbox: MailboxRow,
  env: Env,
): Promise<SyncResult> {
  const result: SyncResult = {
    mailboxId: mailbox.id,
    messagesProcessed: 0,
    threadsCreated: 0,
    threadsUpdated: 0,
    emailsInserted: 0,
    skippedDuplicates: 0,
    errors: [],
  };

  try {
    const provider = getProvider(mailbox.provider);
    const accessToken = await getAccessToken(db, mailbox, env, provider);
    const syncDepth = mailbox.syncDepth as 'full' | 'metadata' | 'thread_only';
    const syncDays = mailbox.syncDays ?? DEFAULT_SYNC_DAYS;

    // Determine which messages to fetch
    let messageRefs: MessageRef[];

    if (mailbox.syncCursor) {
      // Incremental sync
      const { refs, cursorInvalid } = await provider.collectIncrementalRefs(
        accessToken,
        mailbox.syncCursor,
      );
      if (cursorInvalid) {
        // Cursor expired — fall back to first sync
        console.log(`[email] Cursor invalid for ${mailbox.emailAddress}, doing full sync`);
        messageRefs = await provider.collectFirstSyncRefs(accessToken, syncDays, FIRST_SYNC_MAX_MESSAGES);
      } else {
        messageRefs = refs;
      }
    } else {
      // First sync
      messageRefs = await provider.collectFirstSyncRefs(accessToken, syncDays, FIRST_SYNC_MAX_MESSAGES);
    }

    // Determine the format for getMessage based on sync depth
    const format = syncDepth === 'full' ? 'full' as const : 'metadata' as const;

    // Collect new inbound emails for event emission
    const newInboundEmails: EmailReceivedPayload[] = [];

    // Process each message
    for (const ref of messageRefs) {
      try {
        const parsed = await provider.getMessage(accessToken, ref.id, format);
        result.messagesProcessed++;

        const direction = determineDirection(parsed, mailbox.emailAddress);

        if (syncDepth === 'thread_only') {
          // Only create/update thread rows, no per-message emails rows
          const { isNew } = await findOrCreateThread(db, mailbox.id, parsed);
          if (isNew) result.threadsCreated++;
          else result.threadsUpdated++;
        } else {
          // Check for duplicate by Message-ID
          if (await isMessageDuplicate(db, parsed.messageId)) {
            result.skippedDuplicates++;
            continue;
          }

          // Find or create thread
          const { threadId, isNew } = await findOrCreateThread(db, mailbox.id, parsed);
          if (isNew) result.threadsCreated++;
          else result.threadsUpdated++;

          // Insert email row
          const includeBody = syncDepth === 'full';
          await insertEmail(db, threadId, mailbox.id, parsed, direction, includeBody);
          result.emailsInserted++;

          // Track new inbound emails for event emission
          if (direction === 'inbound') {
            newInboundEmails.push({
              messageId: parsed.messageId,
              threadId,
              mailboxId: mailbox.id,
              mailboxEmail: mailbox.emailAddress,
              from: parsed.fromAddress,
              to: parsed.toAddresses,
              subject: parsed.subject,
              snippet: parsed.snippet,
              // Truncated plain text for downstream signature parsing; null
              // when this sync depth fetched no body (metadata format).
              bodyText: buildEventBodyText(parsed.bodyText, parsed.bodyHtml),
              receivedAt: parsed.receivedAt,
            });
          }
        }
      } catch (err) {
        // 404 = message deleted/trashed between list and get — normal, skip silently
        if (err instanceof ProviderApiError && err.status === 404) {
          result.skippedDuplicates++;
          continue;
        }

        const msg = err instanceof Error ? err.message : String(err);
        result.errors.push(`Message ${ref.id}: ${msg}`);

        // On rate limit, stop processing
        if (err instanceof ProviderApiError && err.status === 429) {
          result.errors.push('Rate limited by provider API, stopping sync');
          break;
        }
      }
    }

    // Emit email.received events for new inbound emails (fire-and-forget)
    if (newInboundEmails.length > 0) {
      Promise.allSettled(
        newInboundEmails.map((payload) => emitEmailReceived(env, payload)),
      ).catch(() => {});
    }

    // Get the latest sync cursor
    const newCursor = await provider.getSyncCursor(accessToken);
    const timestamp = now();

    // Update mailbox sync state
    await db.update(connectedMailboxes)
      .set({
        lastSyncAt: timestamp,
        syncCursor: newCursor,
        syncStatus: result.errors.length > 0 ? 'error' : 'active',
        errorMessage: result.errors.length > 0
          ? result.errors.slice(0, 3).join('; ')
          : null,
        updatedAt: timestamp,
      })
      .where(eq(connectedMailboxes.id, mailbox.id));

  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    result.errors.push(msg);

    // Mark mailbox as error
    await db.update(connectedMailboxes)
      .set({
        syncStatus: 'error',
        errorMessage: msg.slice(0, 500),
        updatedAt: now(),
      })
      .where(eq(connectedMailboxes.id, mailbox.id));
  }

  return result;
}
