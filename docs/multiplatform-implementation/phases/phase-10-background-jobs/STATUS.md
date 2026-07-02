# Phase 10: Background Jobs / Task Queue

## Status: done
## Started: 2026-02-09
## Completed: 2026-02-09

## Progress:
- [x] Step 10.1: Create task queue interface (`core/jobs/interface.ts`)
- [x] Step 10.2: Implement database adapter (`core/jobs/adapters/database.ts`)
- [x] Step 10.3: Create task handler registry (`core/jobs/registry.ts`)
- [x] Step 10.4: Define built-in task handlers (`core/jobs/handlers.ts`)
- [x] Step 10.5: Create database migration (`migrations/20260210000003-create-task-queue.sql`)
- [x] Step 10.6: Write tests (15 new tests, 244 total)
- [ ] Step 10.2b: SQS adapter — DEFERRED to Phase 4
- [ ] Step 10.2c: Azure Service Bus adapter — DEFERRED to Phase 4
- [ ] Step 10.2d: GCP Cloud Tasks adapter — DEFERRED to Phase 4
- [ ] Step 10.2e: Cloudflare Queues adapter — DEFERRED to Phase 4

## Notes:
- MVP scope: Database adapter only (universal fallback)
- Cloud-native adapters deferred due to SDK/auth complexity
- Uses atomic UPDATE...RETURNING for distributed-safe task claiming
- Exponential backoff with jitter for retry scheduling
- ensureTable() pattern from DatabaseRateLimiter for lazy table creation
- 4 built-in handlers: email:send, webhook:deliver, audit:cleanup, user:approval-reminder
