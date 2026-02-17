# Phase 4: Inbox & Thread UI

## Overview

Build the inbox list page and thread/conversation view. Users see their synced emails in a familiar inbox layout, can mark as read/unread, star, archive, and open threads to see the full conversation. Includes search.

Covers REQ-EM-2.01 through REQ-EM-2.06.

## Dependencies

- **Phase 3** — Synced email data in D1

## Steps

### 4.1 Create inbox API routes

Create `worker/routes/emails.ts`:

- `GET /api/inbox` — list email threads, ordered by last_message_at DESC
  - Query params: `page`, `limit`, `search`, `unread` (boolean filter)
  - Returns: thread ID, subject, from (latest message), snippet, date, unread, starred, message count
- `GET /api/inbox/:threadId` — get thread with all messages
  - Returns: thread metadata + messages array ordered by sent_at
  - **Sync depth handling**: if mailbox `sync_depth` is `metadata` or `thread_only`, transparently calls `fetchThreadBodies()` (Phase 3.5) to retrieve message bodies from the provider API before returning. The response shape is identical regardless of sync depth — callers don't need to know.
  - For `thread_only`: also fetches the per-message envelope data (from, to, subject, etc.)
- `PATCH /api/inbox/:threadId` — update thread state
  - Body: `{ isRead?, isStarred?, isArchived? }`
- `GET /api/sent` — list sent emails, ordered by sent_at DESC
  - Same pagination/search as inbox
- `GET /api/email/search` — full-text search across subject, from, body_text
  - Query params: `q`, `page`, `limit`

### 4.2 Build InboxList page

Create `src/pages/inbox/InboxList.tsx`:

- Email list with columns: sender avatar/initial, sender name, subject + snippet, date, star toggle
- Unread emails: bold text, subtle background highlight
- Click row → navigate to thread view
- Top toolbar: search input, "Unread" filter toggle, refresh button
- Pagination at bottom
- Empty state: "Your inbox is empty" with mailbox connection prompt if no mailbox connected
- Responsive: stack on mobile

### 4.3 Build ThreadView page

Create `src/pages/inbox/ThreadView.tsx`:

- Thread header: subject, participant list, message count
- Back button to return to inbox
- Messages listed chronologically:
  - Each message: sender avatar, name, email, timestamp
  - Expandable body (collapsed by default for older messages, latest expanded)
  - HTML body rendered in a sandboxed container (or sanitized HTML)
  - Fallback to plain text if no HTML
  - **Loading state**: for `metadata`/`thread_only` sync depths, show a skeleton/spinner while body is being fetched on demand (~200-300ms). Thread envelope data (subject, participants) renders instantly.
- Actions: Reply, Reply All, Forward buttons (placeholder until Phase 5)
- Mark as read when thread is opened

### 4.4 Build SentList page

Create `src/pages/sent/SentList.tsx`:

- Similar to InboxList but showing outbound emails
- Columns: recipient(s), subject + snippet, date
- Click → thread view
- Search and pagination

### 4.5 Wire up routing

Update `src/root.component.tsx`:
- `/eldrin-email/inbox` → InboxList
- `/eldrin-email/inbox/:threadId` → ThreadView
- `/eldrin-email/sent` → SentList
- `/eldrin-email/templates` → (placeholder from Phase 1)
- `/eldrin-email/settings` → MailboxSettings

## Test Gate

```bash
cd eldrin-email && npm run build
cd eldrin-email && npm run test
```

- Inbox shows synced emails sorted by date
- Unread filter works
- Search returns matching threads
- Thread view shows full conversation (bodies fetched on demand for non-full sync depths)
- Opening a thread marks it as read
- Star toggle persists
- Sent view shows outbound emails

## Files Created

| File | Purpose |
|------|---------|
| `worker/routes/emails.ts` | Inbox, sent, thread, search endpoints |
| `src/pages/inbox/InboxList.tsx` | Inbox list page |
| `src/pages/inbox/ThreadView.tsx` | Conversation thread view |
| `src/pages/sent/SentList.tsx` | Sent mail list page |

## Files Modified

| File | Change |
|------|--------|
| `worker/index.ts` | Register email routes |
| `src/root.component.tsx` | Add inbox, thread, sent routes |

## Finalize

- [ ] Manual validation: inbox lists synced emails, search works
- [ ] Manual validation: thread view shows conversation
- [ ] Manual validation: star, read/unread, archive actions work
- [ ] Commit: `feat(email): add inbox and thread view UI`
- [ ] Update STATUS.md → complete, create DONE.md
