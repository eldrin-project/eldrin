# Phase 4: Inbox & Thread UI

## Status: complete
## Started: 2026-02-17
## Completed: 2026-02-17

## Progress:
- [x] Step 4.1: Create inbox API routes
- [x] Step 4.2: Build InboxList page
- [x] Step 4.3: Build ThreadView page
- [x] Step 4.4: Build SentList page
- [x] Step 4.5: Wire up routing

## Notes:
- 5 API endpoints: GET /api/inbox, GET /api/inbox/:threadId, PATCH /api/inbox/:threadId, GET /api/sent, GET /api/email/search
- Thread detail transparently fetches bodies on demand for metadata/thread_only sync depths
- Opening a thread auto-marks it as read
- InboxList: debounced search, unread filter, star toggle, pagination, smart date formatting
- ThreadView: collapsible messages, latest expanded by default, HTML body in sandboxed iframe
- SentList: recipient display, navigates to thread view
- All routes user-scoped via X-Eldrin-User-Id + mailbox ownership check
- 63 tests passing (54 prior + 9 new route tests)
- Build passes with zero TypeScript errors
