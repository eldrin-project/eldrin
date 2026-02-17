import { sqliteTable, text, integer, index, uniqueIndex } from 'drizzle-orm/sqlite-core';

// ── Phase 2: Connected Mailboxes ─────────────────────────────────────────────

export const connectedMailboxes = sqliteTable(
  'connected_mailboxes',
  {
    id: text('id').primaryKey(),
    userId: text('user_id').notNull(),
    provider: text('provider').notNull(), // gmail | outlook | imap
    emailAddress: text('email_address').notNull(),
    displayName: text('display_name'),
    accessTokenEncrypted: text('access_token_encrypted').notNull(),
    refreshTokenEncrypted: text('refresh_token_encrypted').notNull(),
    tokenExpiresAt: integer('token_expires_at', { mode: 'number' }).notNull(),
    lastSyncAt: integer('last_sync_at', { mode: 'number' }),
    syncStatus: text('sync_status').notNull().default('active'), // active | paused | error
    syncDepth: text('sync_depth').notNull().default('metadata'), // full | metadata | thread_only
    syncCursor: text('sync_cursor'),
    errorMessage: text('error_message'),
    createdAt: integer('created_at', { mode: 'number' }).notNull(),
    updatedAt: integer('updated_at', { mode: 'number' }).notNull(),
  },
  (table) => [
    index('idx_mailboxes_user_id').on(table.userId),
    uniqueIndex('idx_mailboxes_provider_email').on(table.provider, table.emailAddress),
    index('idx_mailboxes_sync_status').on(table.syncStatus),
  ],
);

// Future phases:
// Phase 3: email_threads, emails
// Phase 6: email_templates
// Phase 7: email_tracking, tracking_events
