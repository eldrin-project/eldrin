/**
 * Cloudflare Workers scheduled event handler.
 *
 * Runs every 15 minutes to sync all active mailboxes and process scheduled sends.
 */

import { eq } from 'drizzle-orm';
import { createDb } from './db';
import { connectedMailboxes } from './db/schema';
import { syncMailbox } from './services/email-sync';
import { processScheduledSends } from './services/scheduled-send';

export async function handleScheduled(env: Env): Promise<void> {
  const db = createDb(env as unknown as Record<string, unknown>);

  // Process scheduled sends first (time-sensitive)
  try {
    const sent = await processScheduledSends(db, env);
    if (sent > 0) console.log(`[email] Sent ${sent} scheduled email(s)`);
  } catch (err) {
    console.error('[email] Scheduled send processing failed:', err);
  }

  // Get all active mailboxes
  const activeMailboxes = await db.query.connectedMailboxes.findMany({
    where: eq(connectedMailboxes.syncStatus, 'active'),
  });

  if (activeMailboxes.length === 0) {
    console.log('[email] No active mailboxes to sync');
    return;
  }

  console.log(`[email] Syncing ${activeMailboxes.length} active mailbox(es)`);

  // Sync sequentially to respect rate limits
  for (const mailbox of activeMailboxes) {
    try {
      const result = await syncMailbox(db, mailbox, env);
      console.log(
        `[email] Synced ${mailbox.emailAddress}: ` +
        `${result.emailsInserted} new, ${result.skippedDuplicates} dupes, ` +
        `${result.errors.length} errors`,
      );
    } catch (err) {
      console.error(`[email] Sync failed for ${mailbox.emailAddress}:`, err);
    }
  }
}
