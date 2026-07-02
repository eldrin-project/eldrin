# Phase 3: Email Sync Engine — DONE

## Completed: 2026-02-17

## What was built

### Database
- `migrations/002-emails.sql` — `email_threads` and `emails` tables with indexes, FK cascade deletes
- `worker/db/schema.ts` — Drizzle ORM schemas for both tables

### Gmail API Client (`worker/services/gmail-client.ts`)
- `listMessages()` — paginated message listing with query (for first sync)
- `listHistory()` — incremental history API (for cursor-based sync)
- `getMessage()` — fetch single message (format=metadata or format=full)
- `getProfile()` — get user's historyId for sync cursor
- `parseGmailMessage()` — normalize raw Gmail response to `ParsedEmail`:
  - Email address parsing (display name + address extraction)
  - Address list parsing (To, Cc, Bcc)
  - Base64url body decoding
  - Recursive MIME multipart body extraction
  - Attachment detection via `attachmentId`
  - Read status from UNREAD label
- `GmailApiError` — typed error with HTTP status code

### Sync Service (`worker/services/email-sync.ts`)
- `syncMailbox(db, mailbox, env)` — core sync engine:
  - Token management: decrypt, refresh if expired, update DB
  - First sync: last 30 days, up to 500 messages
  - Incremental sync: via `historyId` cursor (messagesAdded events)
  - Cursor expiry: falls back to full scan on 404/410
  - Depth-aware storage:
    - `full` — fetch with format=full, store body
    - `metadata` — fetch with format=metadata, body columns NULL
    - `thread_only` — only create/update email_threads rows
  - Deduplication by RFC 2822 Message-ID
  - Direction detection (inbound/outbound by comparing from_address to mailbox email)
  - Thread management: find-or-create by provider_thread_id
  - Rate limit handling: stops on 429
  - Error tracking: sets mailbox sync_status to 'error' on failure

### Body Fetch Service (`worker/services/body-fetch.ts`)
- `fetchMessageBody()` — fetch and cache a single email's body on demand
- `fetchThreadBodies()` — fetch bodies for all messages in a thread
- Returns cached body if already stored, fetches from provider API otherwise
- Graceful degradation: returns placeholder if provider API unavailable

### Cron Handler (`worker/cron.ts`)
- Cloudflare `scheduled` event handler
- Queries all active mailboxes, syncs sequentially
- Registered in `wrangler.jsonc`: `*/15 * * * *`

### API Routes
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/mailboxes/:id/sync` | Trigger immediate sync (60s rate limit) |

### Frontend
- "Sync now" button per mailbox card in MailboxSettings.tsx
- Spinner animation during sync, disabled when paused
- Shows result count on completion
- `api.syncMailboxNow()` function in API layer

### Configuration
- `wrangler.jsonc` — added `triggers.crons: ["*/15 * * * *"]`
- `worker/index.ts` — exports `{ fetch, scheduled }` instead of bare Hono app

### Tests (54 passing)
- `health.test.ts` (4) — manifest validation
- `crypto.test.ts` (6) — round-trip, IV randomness, wrong key, edge cases
- `oauth-gmail.test.ts` (9) — auth URL, code exchange, refresh, user info, revocation
- `gmail-client.test.ts` (24) — API calls (list, history, get, profile), error handling, message parsing (addresses, body extraction, nested MIME, attachments, labels, dedup fallback)
- `email-sync.test.ts` (11) — first sync, incremental sync, dedup, sync depths (full/metadata/thread_only), token refresh, error handling, empty lists, cursor update

## Test gate
- `npm run build` — zero TypeScript errors
- `npm run test` — 54 tests passing
