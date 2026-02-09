# Phase 2: Unified Hono App

## Status: done
## Started: 2025-02-09
## Completed: 2025-02-09

## Progress:
- [x] Step 2.1: Create `core/app.ts` with `createApp()` factory and all routes
- [x] Step 2.2: Update `core/index.ts` with createApp export
- [x] Step 2.3: Write unit tests for route registration and parity (14 tests)
- [x] Step 2.4: E2E regression — entry points not modified, passes trivially

## Notes:
- 76 total tests pass (62 existing + 14 new)
- 33 routes + 1 catch-all registered in unified app
- Auth middleware with public route skipping (uses existing isPublicRoute())
- Per-route requirePermission() middleware for 11 permission-guarded routes
- Ported permission checks from worker/index.ts (server was missing them — known bug)
- Entry points (worker/index.ts, server/index.ts) NOT modified — unified app tested independently
- TestAppVariables/TestAppEnv now alias AppVariables/AppEnv from core/app.ts
