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
    syncDays: integer('sync_days', { mode: 'number' }).notNull().default(30), // 0 = all
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

// ── Phase 3: Email Threads & Messages ────────────────────────────────────────

export const emailThreads = sqliteTable(
  'email_threads',
  {
    id: text('id').primaryKey(),
    mailboxId: text('mailbox_id')
      .notNull()
      .references(() => connectedMailboxes.id, { onDelete: 'cascade' }),
    providerThreadId: text('provider_thread_id').notNull(),
    subject: text('subject'),
    lastMessageAt: integer('last_message_at', { mode: 'number' }).notNull(),
    messageCount: integer('message_count', { mode: 'number' }).notNull().default(1),
    isRead: integer('is_read', { mode: 'boolean' }).notNull().default(false),
    isStarred: integer('is_starred', { mode: 'boolean' }).notNull().default(false),
    isArchived: integer('is_archived', { mode: 'boolean' }).notNull().default(false),
    isDeleted: integer('is_deleted', { mode: 'boolean' }).notNull().default(false),
    createdAt: integer('created_at', { mode: 'number' }).notNull(),
    updatedAt: integer('updated_at', { mode: 'number' }).notNull(),
  },
  (table) => [
    index('idx_threads_mailbox').on(table.mailboxId),
    index('idx_threads_last_message').on(table.mailboxId, table.lastMessageAt),
    uniqueIndex('idx_threads_provider').on(table.mailboxId, table.providerThreadId),
  ],
);

export const emails = sqliteTable(
  'emails',
  {
    id: text('id').primaryKey(),
    threadId: text('thread_id')
      .notNull()
      .references(() => emailThreads.id, { onDelete: 'cascade' }),
    mailboxId: text('mailbox_id')
      .notNull()
      .references(() => connectedMailboxes.id, { onDelete: 'cascade' }),
    providerMessageId: text('provider_message_id').notNull(),
    messageId: text('message_id').notNull().unique(),
    inReplyTo: text('in_reply_to'),
    fromAddress: text('from_address').notNull(),
    fromName: text('from_name'),
    toAddresses: text('to_addresses').notNull(), // JSON array
    ccAddresses: text('cc_addresses'), // JSON array
    bccAddresses: text('bcc_addresses'), // JSON array
    subject: text('subject'),
    bodyText: text('body_text'), // NULL when sync_depth is metadata/thread_only
    bodyHtml: text('body_html'), // NULL when sync_depth is metadata/thread_only
    snippet: text('snippet'),
    hasAttachments: integer('has_attachments', { mode: 'boolean' }).notNull().default(false),
    direction: text('direction').notNull(), // inbound | outbound
    sentAt: integer('sent_at', { mode: 'number' }),
    receivedAt: integer('received_at', { mode: 'number' }).notNull(),
    labels: text('labels'), // JSON array
    isRead: integer('is_read', { mode: 'boolean' }).notNull().default(false),
    status: text('status').notNull().default('sent'), // sent | scheduled | draft
    scheduledAt: integer('scheduled_at', { mode: 'number' }),
    relatedApp: text('related_app'), // Cross-app provenance (e.g. 'eldrin-crm')
    relatedRecordId: text('related_record_id'), // Source record ID (e.g. deal ID)
    createdAt: integer('created_at', { mode: 'number' }).notNull(),
  },
  (table) => [
    index('idx_emails_thread').on(table.threadId),
    index('idx_emails_mailbox_received').on(table.mailboxId, table.receivedAt),
    index('idx_emails_from').on(table.fromAddress),
    index('idx_emails_is_read').on(table.isRead),
    index('idx_emails_status').on(table.status, table.scheduledAt),
    index('idx_emails_related').on(table.relatedApp, table.relatedRecordId),
  ],
);

// ── Phase 6: Email Templates ────────────────────────────────────────────────

export const emailTemplates = sqliteTable(
  'email_templates',
  {
    id: text('id').primaryKey(),
    name: text('name').notNull(),
    subject: text('subject').notNull(),
    bodyHtml: text('body_html').notNull(),
    bodyText: text('body_text'),
    mergeFields: text('merge_fields'), // JSON array of detected field names
    category: text('category'),
    isShared: integer('is_shared', { mode: 'boolean' }).notNull().default(false),
    usageCount: integer('usage_count', { mode: 'number' }).notNull().default(0),
    ownerId: text('owner_id').notNull(),
    createdAt: integer('created_at', { mode: 'number' }).notNull(),
    updatedAt: integer('updated_at', { mode: 'number' }).notNull(),
  },
  (table) => [
    index('idx_templates_owner').on(table.ownerId),
    index('idx_templates_shared').on(table.isShared),
    index('idx_templates_category').on(table.category),
  ],
);

// ── Phase 7: Email Tracking ─────────────────────────────────────────────────

export const emailTracking = sqliteTable(
  'email_tracking',
  {
    id: text('id').primaryKey(),
    emailId: text('email_id').notNull(),
    trackingId: text('tracking_id').notNull().unique(),
    openCount: integer('open_count', { mode: 'number' }).notNull().default(0),
    clickCount: integer('click_count', { mode: 'number' }).notNull().default(0),
    firstOpenedAt: integer('first_opened_at', { mode: 'number' }),
    lastOpenedAt: integer('last_opened_at', { mode: 'number' }),
    createdAt: integer('created_at', { mode: 'number' }).notNull(),
  },
  (table) => [
    index('idx_tracking_email').on(table.emailId),
    uniqueIndex('idx_tracking_tracking_id').on(table.trackingId),
  ],
);

export const trackingEvents = sqliteTable(
  'tracking_events',
  {
    id: text('id').primaryKey(),
    trackingId: text('tracking_id').notNull(),
    eventType: text('event_type').notNull(), // 'open' | 'click'
    url: text('url'),
    userAgent: text('user_agent'),
    ipAddress: text('ip_address'),
    createdAt: integer('created_at', { mode: 'number' }).notNull(),
  },
  (table) => [
    index('idx_tracking_events_tracking').on(table.trackingId),
  ],
);
