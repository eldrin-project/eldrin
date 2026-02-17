# Phase 3: Email Sync Engine

## Overview

Implement the background email sync engine that periodically fetches new emails from connected Gmail accounts, deduplicates by Message-ID, stores them in D1, and emits `email.received` platform events. This is the core data pipeline that powers the inbox UI and cross-app integration.

Covers REQ-EM-1.04, REQ-EM-1.05, REQ-EM-1.07, REQ-EM-1.09, REQ-EM-1.10, REQ-EM-6.01.

## Dependencies

- **Phase 2** — Mailbox connections with encrypted tokens

## Steps

### 3.1 Create email storage migration

Create `migrations/002-emails.sql`:

**`email_threads`**:
- `id` TEXT PRIMARY KEY
- `mailbox_id` TEXT NOT NULL (FK)
- `provider_thread_id` TEXT NOT NULL
- `subject` TEXT
- `last_message_at` INTEGER NOT NULL
- `message_count` INTEGER NOT NULL DEFAULT 1
- `is_read` INTEGER NOT NULL DEFAULT 0
- `is_starred` INTEGER NOT NULL DEFAULT 0
- `is_archived` INTEGER NOT NULL DEFAULT 0
- `is_deleted` INTEGER NOT NULL DEFAULT 0
- `created_at` INTEGER NOT NULL
- `updated_at` INTEGER NOT NULL

**`emails`**:
- `id` TEXT PRIMARY KEY
- `thread_id` TEXT NOT NULL (FK to email_threads)
- `mailbox_id` TEXT NOT NULL (FK to connected_mailboxes)
- `provider_message_id` TEXT NOT NULL — provider's internal ID
- `message_id` TEXT UNIQUE NOT NULL — RFC 2822 Message-ID header (for dedup)
- `in_reply_to` TEXT — Message-ID of parent message
- `from_address` TEXT NOT NULL
- `from_name` TEXT
- `to_addresses` TEXT NOT NULL (JSON array)
- `cc_addresses` TEXT (JSON array)
- `bcc_addresses` TEXT (JSON array)
- `subject` TEXT
- `body_text` TEXT — NULL when sync_depth is 'metadata' or 'thread_only'
- `body_html` TEXT — NULL when sync_depth is 'metadata' or 'thread_only'
- `snippet` TEXT — first ~100 chars for list preview (always stored)
- `has_attachments` INTEGER NOT NULL DEFAULT 0
- `direction` TEXT NOT NULL (inbound/outbound)
- `sent_at` INTEGER
- `received_at` INTEGER NOT NULL
- `labels` TEXT (JSON array — provider labels/folders)
- `is_read` INTEGER NOT NULL DEFAULT 0
- `created_at` INTEGER NOT NULL

Indexes: `(thread_id)`, `(mailbox_id, received_at)`, `(message_id)` UNIQUE, `(from_address)`, `(is_read)`.

### 3.2 Add Drizzle schema

Add email_threads and emails tables to `worker/db/schema.ts`.

### 3.3 Implement Gmail API client

Create `worker/services/gmail-client.ts`:

- `listMessages(accessToken, query, pageToken?)` — Gmail `messages.list` API
- `getMessage(accessToken, messageId, format)` — Gmail `messages.get` (full or metadata)
- `parseGmailMessage(raw)` — extract from, to, cc, subject, body (text + HTML), snippet, Message-ID, In-Reply-To, labels, attachments flag
- `getThreadMessages(accessToken, threadId)` — get all messages in a thread
- Handle pagination via `nextPageToken`
- Token refresh wrapper: if 401, refresh token and retry once

### 3.4 Implement sync service

Create `worker/services/email-sync.ts`:

- `syncMailbox(db, mailbox, env)`:
  1. Decrypt access token; refresh if expired (update in DB)
  2. Read `mailbox.sync_depth` to determine storage behavior
  3. Fetch messages since `last_sync_at` (or last 30 days for first sync)
  4. Use `sync_cursor` (Gmail `historyId`) for incremental sync
  5. For each message, respect `sync_depth`:
     - Check `message_id` in DB for dedup (skip if exists)
     - **`full`**: fetch full message (metadata + body), store everything
     - **`metadata`** (default): fetch metadata format from provider (from, to, cc, subject, snippet, headers) — skip body. Store envelope fields, leave `body_text`/`body_html` NULL
     - **`thread_only`**: only create/update `email_threads` row (subject, last_message_at, count). Skip per-message `emails` rows entirely
     - Find or create thread by `provider_thread_id`
     - Determine direction (outbound if from_address matches mailbox email)
     - Emit `email.received` event for inbound emails (uses envelope data, no body needed)
  6. Update `last_sync_at` and `sync_cursor`
  7. On error: set `sync_status = 'error'`, emit `email.mailbox.error`

- Handle Gmail API quotas gracefully (429 → backoff)
- Limit first sync to most recent 500 messages (configurable)
- **Note**: `metadata` mode uses Gmail's `format=metadata` which is ~10x smaller per message than `format=full`, significantly reducing API quota usage and sync time

### 3.5 Implement on-demand body fetch

Create `worker/services/body-fetch.ts`:

- `fetchMessageBody(db, mailbox, providerMessageId)`:
  1. Decrypt mailbox access token; refresh if expired
  2. Call provider API to fetch full message body (Gmail `messages.get` with `format=full`)
  3. Parse body_html and body_text from the response
  4. Optionally update the `emails` row with fetched body (cache for future requests)
  5. Return `{ bodyHtml, bodyText }`

- `fetchThreadBodies(db, mailbox, threadId)`:
  - For `thread_only` depth: also fetch the per-message envelope data
  - For `metadata` depth: fetch body for each message in the thread
  - Used by the thread view API (Phase 4) and cross-app history API (Phase 8)

- Token refresh is handled transparently (same wrapper as sync)
- If provider API is unavailable, return a "body unavailable" placeholder

### 3.6 Create cron trigger

`worker/cron.ts`:
- Cloudflare `scheduled` event handler
- Query all mailboxes where `sync_status = 'active'`
- Run `syncMailbox()` for each (sequentially to respect rate limits)
- Add to `wrangler.jsonc`: `"triggers": { "crons": ["*/15 * * * *"] }`

### 3.7 Add manual sync endpoint

Add to `worker/routes/mailbox.ts`:
- `POST /api/mailboxes/:id/sync` — trigger immediate sync for a single mailbox
- Rate limit: max once per 60 seconds per mailbox

### 3.8 Add "Sync now" to settings UI

Update `MailboxSettings.tsx`:
- "Sync now" button per mailbox (calls `POST /api/mailboxes/:id/sync`)
- Shows "Syncing..." spinner while in progress
- Updates last sync time on completion

## Test Gate

```bash
cd eldrin-email && npm run build
cd eldrin-email && npm run test    # Sync service tests (mocked Gmail API)
```

- First sync fetches last 30 days of email
- Subsequent syncs use historyId cursor (incremental)
- Duplicate emails are skipped (Message-ID dedup)
- Inbound emails emit `email.received` platform event
- Sync errors set mailbox status to `error`
- Manual sync button triggers immediate sync
- Sync depth `full`: body_html/body_text populated in emails table
- Sync depth `metadata`: body columns are NULL, envelope data stored
- Sync depth `thread_only`: only email_threads rows created, no emails rows
- On-demand body fetch works for `metadata` and `thread_only` depths

## Files Created

| File | Purpose |
|------|---------|
| `migrations/002-emails.sql` | Email threads and messages tables |
| `worker/services/gmail-client.ts` | Gmail API client (list, get, parse) |
| `worker/services/email-sync.ts` | Background sync engine (depth-aware) |
| `worker/services/body-fetch.ts` | On-demand body fetch from provider API |
| `worker/cron.ts` | Scheduled event handler |

## Files Modified

| File | Change |
|------|--------|
| `worker/db/schema.ts` | Add email_threads and emails tables |
| `worker/index.ts` | Register cron handler, sync route |
| `worker/routes/mailbox.ts` | Add manual sync endpoint |
| `wrangler.jsonc` | Add cron trigger config |
| `src/pages/settings/MailboxSettings.tsx` | Add "Sync now" button |

## Finalize

- [ ] Manual validation: connect Gmail, run sync, emails appear in D1
- [ ] Manual validation: incremental sync only fetches new messages
- [ ] Manual validation: `email.received` events are emitted
- [ ] Commit: `feat(email): add email sync engine with Gmail API`
- [ ] Update STATUS.md → complete, create DONE.md
