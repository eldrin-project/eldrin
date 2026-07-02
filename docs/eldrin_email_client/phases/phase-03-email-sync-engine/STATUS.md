# Phase 3: Email Sync Engine

## Status: complete
## Started: 2026-02-17
## Completed: 2026-02-17

## Progress:
- [x] Step 3.1: Create email storage migration
- [x] Step 3.2: Add Drizzle schema
- [x] Step 3.3: Implement Gmail API client
- [x] Step 3.4: Implement sync service (depth-aware: full/metadata/thread_only)
- [x] Step 3.5: Implement on-demand body fetch service
- [x] Step 3.6: Create cron trigger
- [x] Step 3.7: Add manual sync endpoint
- [x] Step 3.8: Add "Sync now" to settings UI

## Notes:
- Gmail client uses format=metadata for efficient sync, format=full only for body fetch
- Sync depth fully respected: full (body stored), metadata (headers+snippet only), thread_only (only thread rows)
- Incremental sync via Gmail historyId cursor; falls back to full scan when cursor expires (404/410)
- Message dedup by RFC 2822 Message-ID header
- Rate limit: manual sync max once per 60 seconds per mailbox
- Cron: every 15 minutes (`*/15 * * * *` in wrangler.jsonc)
- Body fetch caches fetched bodies in D1 for subsequent reads
- 54 tests passing (4 scaffold + 6 crypto + 9 OAuth + 24 Gmail client + 11 sync)
- Build passes with zero TypeScript errors
