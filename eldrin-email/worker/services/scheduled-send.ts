/**
 * Scheduled send processor.
 *
 * Finds emails with status='scheduled' and scheduled_at <= now(),
 * sends them via the Gmail API, and updates their status to 'sent'.
 */

import { eq, and, lte } from 'drizzle-orm';
import type { Database } from '../db';
import { connectedMailboxes, emailThreads, emails } from '../db/schema';
import { now } from '../utils';
import { decryptToken, encryptToken } from './crypto';
import { refreshGmailToken } from './oauth-gmail';
import { sendMessage } from './gmail-client';

/**
 * Process all scheduled emails that are due.
 */
export async function processScheduledSends(db: Database, env: Env): Promise<number> {
  const timestamp = now();

  const dueEmails = await db.query.emails.findMany({
    where: and(
      eq(emails.status, 'scheduled'),
      lte(emails.scheduledAt, timestamp),
    ),
  });

  if (dueEmails.length === 0) return 0;

  let sent = 0;

  for (const email of dueEmails) {
    try {
      // Get the mailbox for this email
      const mailbox = await db.query.connectedMailboxes.findFirst({
        where: eq(connectedMailboxes.id, email.mailboxId),
      });

      if (!mailbox || mailbox.syncStatus === 'error') {
        console.error(`[email] Scheduled send: mailbox ${email.mailboxId} not available`);
        continue;
      }

      // Get access token (refresh if needed)
      let accessToken = await decryptToken(mailbox.accessTokenEncrypted, env.JWT_SECRET);

      if (mailbox.tokenExpiresAt <= timestamp) {
        const refreshToken = await decryptToken(mailbox.refreshTokenEncrypted, env.JWT_SECRET);
        const refreshed = await refreshGmailToken(
          refreshToken,
          env.GOOGLE_CLIENT_ID,
          env.GOOGLE_CLIENT_SECRET,
        );
        accessToken = refreshed.accessToken;

        const newEncrypted = await encryptToken(refreshed.accessToken, env.JWT_SECRET);
        await db.update(connectedMailboxes)
          .set({
            accessTokenEncrypted: newEncrypted,
            tokenExpiresAt: timestamp + refreshed.expiresIn * 1000,
            updatedAt: timestamp,
          })
          .where(eq(connectedMailboxes.id, mailbox.id));
      }

      // Resolve provider thread ID
      let providerThreadId: string | undefined;
      const thread = await db.query.emailThreads.findFirst({
        where: eq(emailThreads.id, email.threadId),
        columns: { providerThreadId: true },
      });
      if (thread && !thread.providerThreadId.startsWith('local-')) {
        providerThreadId = thread.providerThreadId;
      }

      // Send via Gmail
      const result = await sendMessage(accessToken, {
        from: mailbox.emailAddress,
        to: JSON.parse(email.toAddresses),
        cc: email.ccAddresses ? JSON.parse(email.ccAddresses) : undefined,
        bcc: email.bccAddresses ? JSON.parse(email.bccAddresses) : undefined,
        subject: email.subject ?? '',
        bodyHtml: email.bodyHtml ?? '',
        bodyText: email.bodyText ?? undefined,
        inReplyTo: email.inReplyTo ?? undefined,
        threadId: providerThreadId,
      });

      // Update email record
      await db.update(emails)
        .set({
          status: 'sent',
          sentAt: now(),
          providerMessageId: result.id,
          messageId: `<${result.id}@gmail.com>`,
        })
        .where(eq(emails.id, email.id));

      // Update thread with real provider thread ID if it was a local placeholder
      if (thread?.providerThreadId.startsWith('local-')) {
        await db.update(emailThreads)
          .set({
            providerThreadId: result.threadId,
            updatedAt: now(),
          })
          .where(eq(emailThreads.id, email.threadId));
      }

      sent++;
      console.log(`[email] Scheduled send: sent email ${email.id}`);
    } catch (err) {
      console.error(`[email] Scheduled send failed for ${email.id}:`, err);
    }
  }

  return sent;
}
