# Phase 10: Background Jobs / Task Queue

## Overview

Pluggable task queue system with database-backed universal fallback and cloud-native adapters (SQS, Service Bus, Cloud Tasks, Cloudflare Queues).

## Dependencies

- Phase 2 (unified Hono app)
- Phase 9 (observability — logger for task execution)

## Steps

### 10.1 Task queue interface — `core/jobs/interface.ts`

`TaskQueue`: `enqueue()`, `schedule()`. `TaskDefinition`: type, payload, maxRetries. `TaskHandler`: type, handle(). `TaskContext`: taskId, attempt, db, logger.

### 10.2 Provider implementations

| File | Backend | Est. lines |
|------|---------|-----------|
| `core/jobs/adapters/database.ts` | DB-backed polling (`task_queue` table) | ~120 |
| `core/jobs/adapters/sqs.ts` | AWS SQS | ~80 |
| `core/jobs/adapters/azure-service-bus.ts` | Azure Service Bus | ~80 |
| `core/jobs/adapters/cloud-tasks.ts` | GCP Cloud Tasks | ~80 |
| `core/jobs/adapters/cf-queues.ts` | Cloudflare Queues | ~60 |

### 10.3 Task handler registry — `core/jobs/registry.ts`

### 10.4 Built-in task types

- `webhook:deliver`, `email:send`, `audit:cleanup`, `user:approval-reminder`

### 10.5 Database migration — `task_queue` table

### 10.6 Tests

| Test file | Cases |
|-----------|-------|
| `core/jobs/adapters/database.test.ts` | ~10 |
| `core/jobs/registry.test.ts` | ~4 |

## Test Gate

```bash
cd eldrin-core && npx vitest run -- core/jobs/   # ~14 tests
```


## Commit

After all tests pass, commit the changes to the relevant submodule(s) using conventional commits format, then update the parent repo submodule reference.
