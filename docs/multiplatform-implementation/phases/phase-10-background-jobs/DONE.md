# Phase 10: Background Jobs / Task Queue — DONE

## Summary
Added a pluggable task queue system with a database-backed universal fallback adapter. Includes a task handler registry, 4 built-in handlers (email:send, webhook:deliver, audit:cleanup, user:approval-reminder), and a migration file. Uses atomic UPDATE...RETURNING for distributed-safe task claiming and exponential backoff with jitter for retries.

## Files Created (7 source + 2 test)

### Source
| File | Purpose | Lines |
|------|---------|-------|
| `core/jobs/interface.ts` | TaskQueue, TaskProcessor, TaskHandler, TaskContext types | ~70 |
| `core/jobs/registry.ts` | TaskHandlerRegistry class | ~25 |
| `core/jobs/adapters/database.ts` | Database-backed queue with polling + atomic claim | ~135 |
| `core/jobs/handlers.ts` | 4 built-in handler factories | ~95 |
| `core/jobs/factory.ts` | `createTaskQueue(db)` factory | ~12 |
| `core/jobs/index.ts` | Barrel exports | ~25 |
| `migrations/20260210000003-create-task-queue.sql` | Task queue table schema + indexes | ~25 |

### Tests
| File | Tests |
|------|-------|
| `core/jobs/registry.test.ts` | 4 |
| `core/jobs/adapters/database.test.ts` | 11 |
| **Total new** | **15** |

## Files Modified
| File | Change |
|------|--------|
| `core/app.ts` | Added `TaskQueue` import, `jobs?: { queue?: TaskQueue }` to CreateAppOptions |
| `core/routes/index.ts` | Added TaskQueue, TaskProcessor, TaskDefinition, TaskHandler, TaskContext re-exports |

## Test Results
```
Test Files  33 passed (33)
     Tests  244 passed (244)
  Duration  748ms
```

## Phase Gate
- [x] All 244 unit tests pass
- [x] TypeScript compiles with zero errors
- [x] TaskQueue interface defines enqueue() and schedule()
- [x] TaskProcessor interface defines processNext()
- [x] Database adapter uses atomic UPDATE...RETURNING for task claiming
- [x] Exponential backoff with jitter for retry scheduling
- [x] Tasks transition: pending → processing → completed/failed → dead
- [x] ensureTable() creates table lazily on first use
- [x] Registry dispatches to correct handler by type
- [x] Registry throws on unknown task type
- [x] 4 built-in handlers: email:send, webhook:deliver, audit:cleanup, user:approval-reminder
- [x] Migration SQL file documents schema for manual deployments
