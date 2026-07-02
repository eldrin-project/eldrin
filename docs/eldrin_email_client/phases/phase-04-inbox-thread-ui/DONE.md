# Phase 4: Inbox & Thread UI — DONE

## Completed: 2026-02-17

## Summary

Built the full inbox, thread view, and sent mail UI with 5 backend API endpoints. Users can browse their inbox, read conversations, star/archive threads, search emails, and view sent messages.

## What Was Built

### Backend — `worker/routes/emails.ts`

5 API endpoints, all user-scoped via `X-Eldrin-User-Id` + mailbox ownership check:

| Endpoint | Purpose |
|----------|---------|
| `GET /api/inbox` | List threads with pagination, search, unread filter |
| `GET /api/inbox/:threadId` | Thread detail with all messages, auto body fetch |
| `PATCH /api/inbox/:threadId` | Update isRead/isStarred/isArchived |
| `GET /api/sent` | List outbound emails with pagination/search |
| `GET /api/email/search` | Full-text search across subject, from, body_text |

- `getUserMailboxIds(db, userId)` helper scopes all queries to user's mailboxes
- Thread detail transparently calls `fetchThreadBodies()` when sync_depth !== 'full'
- Opening a thread auto-marks it as read

### Frontend Types — `src/types/email.ts`

- `Pagination`, `ThreadPreview`, `EmailMessage`, `ThreadDetail`, `SentEmailRow`, `SearchResult`

### API Layer — `src/api.ts`

Added 5 functions: `listInbox`, `getThread`, `updateThread`, `listSent`, `searchEmails`

### InboxList — `src/pages/inbox/InboxList.tsx`

- Thread rows with avatar initial, sender name, subject+snippet, star toggle, smart date formatting
- Debounced search (300ms), unread filter toggle, refresh button
- Unread indicator (bold text + blue dot)
- Empty state with "Connect Mailbox" CTA
- Pagination with Previous/Next

### ThreadView — `src/pages/inbox/ThreadView.tsx`

- Thread header with back button, subject, message count
- Thread actions: Star, Archive, Mark read/unread
- Collapsible `MessageCard` component (latest expanded by default)
- `MessageBody`: HTML body in sandboxed `<iframe srcDoc={...} sandbox="" />` with auto-resize, plain text fallback
- Reply/Reply All/Forward buttons (disabled placeholders for Phase 5)

### SentList — `src/pages/sent/SentList.tsx`

- Outbound email list with recipient display, subject+snippet, date
- Click navigates to thread view
- Search and pagination

### Routing — `src/root.component.tsx`

- `/eldrin-email/inbox` → InboxList
- `/eldrin-email/inbox/:threadId` → ThreadView
- `/eldrin-email/sent` → SentList

## Tests

- 9 new route tests in `worker/__tests__/email-routes.test.ts`
- Auth (401 without header), empty states (no mailboxes), search with no query
- **63 total tests passing** (54 prior + 9 new)

## Build

- Zero TypeScript errors
- `npm run build` passes clean
