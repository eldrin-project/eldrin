/**
 * On-demand body fetch service.
 *
 * When sync_depth is 'metadata' or 'thread_only', email bodies are not stored
 * during sync. This service fetches full message content from the provider API
 * when a user opens a message, and optionally caches it in D1.
 */

import { eq, and } from 'drizzle-orm';
import type { Database } from '../db';
import { connectedMailboxes, emails } from '../db/schema';
import { decryptToken, encryptToken } from './crypto';
import { refreshGmailToken } from './oauth-gmail';
import { getMessage, parseGmailMessage } from './gmail-client';
import { now } from '../utils';

type MailboxRow = typeof connectedMailboxes.$inferSelect;

// ── Token management (shared pattern with email-sync) ────────────────────────

async function getAccessToken(
  db: Database,
  mailbox: MailboxRow,
  env: Env,
): Promise<string> {
  const accessToken = await decryptToken(mailbox.accessTokenEncrypted, env.JWT_SECRET);

  if (mailbox.tokenExpiresAt > now()) {
    return accessToken;
  }

  const refreshToken = await decryptToken(mailbox.refreshTokenEncrypted, env.JWT_SECRET);
  const refreshed = await refreshGmailToken(
    refreshToken,
    env.GOOGLE_CLIENT_ID,
    env.GOOGLE_CLIENT_SECRET,
  );

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

// ── Public API ───────────────────────────────────────────────────────────────

export interface FetchedBody {
  bodyText: string | null;
  bodyHtml: string | null;
}

/**
 * Fetch and cache the body for a single email.
 * If the body is already stored, returns it directly.
 */
export async function fetchMessageBody(
  db: Database,
  mailbox: MailboxRow,
  emailId: string,
  env: Env,
): Promise<FetchedBody> {
  // Check if we already have the body cached
  const email = await db.query.emails.findFirst({
    where: and(
      eq(emails.id, emailId),
      eq(emails.mailboxId, mailbox.id),
    ),
  });

  if (!email) {
    throw new Error('Email not found');
  }

  // If body is already stored, return it
  if (email.bodyText !== null || email.bodyHtml !== null) {
    return { bodyText: email.bodyText, bodyHtml: email.bodyHtml };
  }

  // Fetch from provider
  const accessToken = await getAccessToken(db, mailbox, env);

  try {
    const raw = await getMessage(accessToken, email.providerMessageId, 'full');
    const parsed = parseGmailMessage(raw);

    // Cache the fetched body in D1
    await db.update(emails)
      .set({
        bodyText: parsed.bodyText,
        bodyHtml: parsed.bodyHtml,
      })
      .where(eq(emails.id, emailId));

    return { bodyText: parsed.bodyText, bodyHtml: parsed.bodyHtml };
  } catch {
    return { bodyText: null, bodyHtml: '[Body unavailable — provider API error]' };
  }
}

/**
 * Fetch bodies for all messages in a thread.
 * Used by the thread view API to load a complete conversation.
 */
export async function fetchThreadBodies(
  db: Database,
  mailbox: MailboxRow,
  threadId: string,
  env: Env,
): Promise<FetchedBody[]> {
  const threadEmails = await db.query.emails.findMany({
    where: and(
      eq(emails.threadId, threadId),
      eq(emails.mailboxId, mailbox.id),
    ),
    orderBy: (e, { asc }) => [asc(e.receivedAt)],
  });

  if (threadEmails.length === 0) {
    throw new Error('Thread not found or has no emails');
  }

  const accessToken = await getAccessToken(db, mailbox, env);
  const results: FetchedBody[] = [];

  for (const email of threadEmails) {
    // Skip if body already cached
    if (email.bodyText !== null || email.bodyHtml !== null) {
      results.push({ bodyText: email.bodyText, bodyHtml: email.bodyHtml });
      continue;
    }

    try {
      const raw = await getMessage(accessToken, email.providerMessageId, 'full');
      const parsed = parseGmailMessage(raw);

      // Cache in D1
      await db.update(emails)
        .set({
          bodyText: parsed.bodyText,
          bodyHtml: parsed.bodyHtml,
        })
        .where(eq(emails.id, email.id));

      results.push({ bodyText: parsed.bodyText, bodyHtml: parsed.bodyHtml });
    } catch {
      results.push({ bodyText: null, bodyHtml: '[Body unavailable — provider API error]' });
    }
  }

  return results;
}
