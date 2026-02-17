/**
 * Email sync engine.
 *
 * Fetches new emails from connected Gmail accounts, deduplicates by Message-ID,
 * stores them in D1, and updates the sync cursor for incremental sync.
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
import { decryptToken, encryptToken } from './crypto';
import { refreshGmailToken } from './oauth-gmail';
import {
  listMessages,
  listHistory,
  getMessage,
  getProfile,
  parseGmailMessage,
  GmailApiError,
  type ParsedEmail,
  type GmailMessageRef,
} from './gmail-client';

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

const FIRST_SYNC_DAYS = 30;
const FIRST_SYNC_MAX_MESSAGES = 500;

// ── Token management ─────────────────────────────────────────────────────────

/**
 * Get a valid access token — decrypts and refreshes if expired.
 * Updates the DB with new encrypted access token if refreshed.
 */
async function getAccessToken(
  db: Database,
  mailbox: MailboxRow,
  env: Env,
): Promise<string> {
  const accessToken = await decryptToken(mailbox.accessTokenEncrypted, env.JWT_SECRET);

  // If token hasn't expired yet, use it directly
  if (mailbox.tokenExpiresAt > now()) {
    return accessToken;
  }

  // Refresh the token
  const refreshToken = await decryptToken(mailbox.refreshTokenEncrypted, env.JWT_SECRET);
  const refreshed = await refreshGmailToken(
    refreshToken,
    env.GOOGLE_CLIENT_ID,
    env.GOOGLE_CLIENT_SECRET,
  );

  // Store the new encrypted access token
  const newEncrypted = await encryptToken(refreshed.accessToken, env.JWT_SECRET);
  const timestamp = now();

  await db.update(connectedMailboxes)
    .set({
      accessTokenEncrypted: newEncrypted,
      tokenExpiresAt: timestamp + refreshed.expiresIn * 1000,
      updatedAt: timestamp,
    })
    .where(eq(connectedMailboxes.id, mailbox.id));

  return refreshed.accessToken;
}

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
 * Collect message refs for first sync (last N days, up to max messages).
 */
async function collectFirstSyncRefs(
  accessToken: string,
): Promise<GmailMessageRef[]> {
  const since = new Date(Date.now() - FIRST_SYNC_DAYS * 24 * 60 * 60 * 1000);
  const query = `after:${since.getFullYear()}/${since.getMonth() + 1}/${since.getDate()}`;

  const refs: GmailMessageRef[] = [];
  let pageToken: string | undefined;

  do {
    const response = await listMessages(accessToken, query, 100, pageToken);
    if (response.messages) {
      refs.push(...response.messages);
    }
    pageToken = response.nextPageToken;
  } while (pageToken && refs.length < FIRST_SYNC_MAX_MESSAGES);

  return refs.slice(0, FIRST_SYNC_MAX_MESSAGES);
}

/**
 * Collect message refs for incremental sync (since last historyId).
 */
async function collectIncrementalRefs(
  accessToken: string,
  historyId: string,
): Promise<{ refs: GmailMessageRef[]; cursorInvalid: boolean }> {
  const refs: GmailMessageRef[] = [];
  let pageToken: string | undefined;

  try {
    do {
      const response = await listHistory(accessToken, historyId, pageToken);
      if (response.history) {
        for (const entry of response.history) {
          if (entry.messagesAdded) {
            refs.push(...entry.messagesAdded.map((a) => a.message));
          }
        }
      }
      pageToken = response.nextPageToken;
    } while (pageToken);
  } catch (err) {
    // historyId expired or invalid — fall back to full sync
    if (err instanceof GmailApiError && (err.status === 404 || err.status === 410)) {
      return { refs: [], cursorInvalid: true };
    }
    throw err;
  }

  return { refs, cursorInvalid: false };
}

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
    const accessToken = await getAccessToken(db, mailbox, env);
    const syncDepth = mailbox.syncDepth as 'full' | 'metadata' | 'thread_only';

    // Determine which messages to fetch
    let messageRefs: GmailMessageRef[];

    if (mailbox.syncCursor) {
      // Incremental sync
      const { refs, cursorInvalid } = await collectIncrementalRefs(
        accessToken,
        mailbox.syncCursor,
      );
      if (cursorInvalid) {
        // Cursor expired — fall back to first sync
        console.log(`[email] Cursor invalid for ${mailbox.emailAddress}, doing full sync`);
        messageRefs = await collectFirstSyncRefs(accessToken);
      } else {
        messageRefs = refs;
      }
    } else {
      // First sync
      messageRefs = await collectFirstSyncRefs(accessToken);
    }

    // Determine the format for getMessage based on sync depth
    const format = syncDepth === 'full' ? 'full' as const : 'metadata' as const;

    // Process each message
    for (const ref of messageRefs) {
      try {
        const raw = await getMessage(accessToken, ref.id, format);
        const parsed = parseGmailMessage(raw);
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
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        result.errors.push(`Message ${ref.id}: ${msg}`);

        // On rate limit, stop processing
        if (err instanceof GmailApiError && err.status === 429) {
          result.errors.push('Rate limited by Gmail API, stopping sync');
          break;
        }
      }
    }

    // Get the latest historyId for the cursor
    const profile = await getProfile(accessToken);
    const timestamp = now();

    // Update mailbox sync state
    await db.update(connectedMailboxes)
      .set({
        lastSyncAt: timestamp,
        syncCursor: profile.historyId,
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
