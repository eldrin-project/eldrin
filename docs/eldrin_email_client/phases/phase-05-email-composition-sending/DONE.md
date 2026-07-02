# Phase 5: Email Composition & Sending — DONE

## Completed: 2026-02-17

## Summary

Built the full email compose flow with a TipTap-powered rich text editor, Gmail API sending, reply/forward threading, and scheduled sends processed by the cron handler.

## What Was Built

### Gmail Send Client — `worker/services/gmail-client.ts`

- `buildRawMessage()` — constructs RFC 2822 multipart/alternative (text + HTML)
- `encodeBase64Url()` — URL-safe base64 encoding for Gmail API
- `sendMessage(accessToken, params)` — sends via `POST /messages/send` with optional `threadId` for threading
- `SendMessageParams`: from, to, cc, bcc, subject, bodyHtml, bodyText, inReplyTo, references, threadId

### Send Route — `POST /api/email/send`

Added to `worker/routes/emails.ts`:
- Validates: mailboxId ownership, required fields (to, subject, bodyHtml)
- **Immediate send**: decrypts tokens, refreshes if expired, calls Gmail API, stores email + thread
- **Scheduled send**: stores with `status='scheduled'` and `scheduledAt`, no API call yet
- Returns: `{ id, status: 'sent' | 'scheduled', threadId? }`

### Scheduled Send Handler — `worker/services/scheduled-send.ts`

- `processScheduledSends(db, env)` — queries emails where `status='scheduled' AND scheduled_at <= now()`
- Sends each via Gmail API, updates status to `sent`, fixes provider IDs
- Handles `local-*` placeholder thread IDs → replaces with real Gmail thread ID after send
- Added to `worker/cron.ts` — runs before mailbox sync (time-sensitive)

### Migration — `migrations/003-scheduled-send.sql`

- Added `status TEXT NOT NULL DEFAULT 'sent'` to `emails` table
- Added `scheduled_at INTEGER` to `emails` table
- Index: `idx_emails_status(status, scheduled_at)`

### ComposeModal — `src/pages/compose/ComposeModal.tsx`

- Full-featured email compose modal with:
  - **Email pill input** (To, Cc, Bcc): comma/enter/tab to add, backspace to remove
  - **Subject line** input
  - **TipTap rich text editor**: bold, italic, underline, link, bullet/numbered lists, horizontal rule
  - **From selector**: when user has multiple mailboxes
  - **Cc/Bcc toggle**: hidden by default
  - **Send now**: immediate Gmail API send
  - **Schedule**: date/time picker, future validation
  - **Quoted body**: reply/forward includes original message as blockquote
- Backdrop + centered modal with responsive layout

### Reply & Forward — `src/pages/inbox/ThreadView.tsx`

- Enabled Reply/Reply All/Forward buttons on each message
- `handleReply()`: prefills To (original sender), adds "Re:" prefix, sets inReplyTo + threadId
- `handleReplyAll()`: includes all original To/Cc recipients
- `handleForward()`: empty To, "Fwd:" prefix, no threadId (new thread)
- All include original body as quoted HTML

### Compose Trigger — `src/pages/inbox/InboxList.tsx`

- "Compose" button (primary, with `+` icon) in toolbar
- Opens ComposeModal in `mode: 'new'`
- After send: refreshes inbox

## Files Created

| File | Purpose |
|------|---------|
| `migrations/003-scheduled-send.sql` | Status + scheduled_at columns |
| `worker/services/scheduled-send.ts` | Scheduled send processor |
| `src/pages/compose/ComposeModal.tsx` | TipTap email composer |

## Files Modified

| File | Change |
|------|--------|
| `worker/db/schema.ts` | Added status + scheduledAt columns, status index |
| `worker/services/gmail-client.ts` | Added sendMessage, buildRawMessage, gmailFetch init param |
| `worker/routes/emails.ts` | Added POST /api/email/send endpoint |
| `worker/cron.ts` | Added processScheduledSends call |
| `src/api.ts` | Added sendEmail function + SendEmailParams type |
| `src/pages/inbox/ThreadView.tsx` | Enabled reply/forward buttons, ComposeModal integration |
| `src/pages/inbox/InboxList.tsx` | Added Compose button + ComposeModal |
| `package.json` | Added TipTap dependencies |

## Dependencies Added

- `@tiptap/react`, `@tiptap/starter-kit`, `@tiptap/extension-link`, `@tiptap/extension-underline`, `@tiptap/pm`

## Tests

- 3 new route tests for POST /api/email/send (auth, validation, ownership)
- **66 total tests passing** (54 prior + 12 route tests)

## Build

- Zero TypeScript errors
- `npm run build` passes clean
