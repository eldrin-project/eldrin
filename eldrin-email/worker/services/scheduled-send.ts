/**
 * Scheduled send processor.
 *
 * Finds emails with status='scheduled' and scheduled_at <= now(),
 * sends them via the appropriate provider, and updates their status to 'sent'.
 */

import { eq, and, lte } from 'drizzle-orm';
import type { Database } from '../db';
import { connectedMailboxes, emailThreads, emails } from '../db/schema';
import { now } from '../utils';
import { getProvider, getAccessToken } from './providers';

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

      // Get access token via provider abstraction
      const provider = getProvider(mailbox.provider);
      const accessToken = await getAccessToken(db, mailbox, env, provider);

      // Resolve provider thread ID
      let providerThreadId: string | undefined;
      const thread = await db.query.emailThreads.findFirst({
        where: eq(emailThreads.id, email.threadId),
        columns: { providerThreadId: true },
      });
      if (thread && !thread.providerThreadId.startsWith('local-')) {
        providerThreadId = thread.providerThreadId;
      }

      // Send via provider
      const result = await provider.sendMessage(accessToken, {
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
          messageId: `<${result.id}@${mailbox.provider}.provider>`,
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
