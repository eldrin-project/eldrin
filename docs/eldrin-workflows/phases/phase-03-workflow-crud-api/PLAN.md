# Phase 3: Workflow CRUD API

## Overview

Implement the full workflow CRUD API using Hono route handlers and Drizzle ORM queries. This includes creating, reading, updating, and deleting workflows, plus activate/deactivate toggling. All queries go through Drizzle for database portability.

## Dependencies

- Phase 2 (database layer — Drizzle schema and factory exist)

## Steps

### 3.1 Create workflow routes module

Create **`worker/routes/workflows.ts`** with a Hono sub-app:

```typescript
import { Hono } from 'hono';
import { eq, like, and, desc } from 'drizzle-orm';
import { workflows } from '../db/schema';
```

Endpoints:
- `GET /workflows` — list with pagination (`?page=1&limit=20`), filtering (`?status=active&search=term`), sorted by `created_at DESC`
- `POST /workflows` — create with UUID generation, JSON definition validation
- `GET /workflows/:id` — get by ID, 404 if not found
- `PATCH /workflows/:id` — partial update (name, description, definition)
- `DELETE /workflows/:id` — delete workflow (cascade deletes runs/steps)
- `POST /workflows/:id/activate` — set `is_active = true`
- `POST /workflows/:id/deactivate` — set `is_active = false`

### 3.2 Implement workflow definition validation

Create **`worker/validation.ts`**:

Validate the workflow definition JSON structure:
- `version` must be 1
- `trigger` must have `type` (event, cron, webhook, manual) and `config`
- `steps` must be a non-empty array
- Each step must have `name`, `type`, and `config`
- `conditions` (optional) must be an array of `{ field, operator, value }`

Return structured validation errors (field path + message).

### 3.3 Add event emission

Import `createEventClient` from SDK and emit events on mutations:
- `workflow.created` — payload: `{ workflowId, name, triggerType }`
- `workflow.updated` — payload: `{ workflowId, name, changes: string[] }`
- `workflow.deleted` — payload: `{ workflowId, name }`
- `workflow.activated` / `workflow.deactivated` — payload: `{ workflowId, name }`

Fire-and-forget pattern (same as react-todo): errors logged but don't block response.

### 3.4 Wire up routes in main app

Update **`worker/index.ts`**:
- Import workflow routes
- Mount at root: `app.route('/', workflowRoutes)`
- Add permission middleware using SDK's `createPermissionMiddleware`

### 3.5 Add UUID generation utility

Create **`worker/utils.ts`** with a UUID generator:

```typescript
export function generateId(): string {
  return crypto.randomUUID();
}

export function now(): number {
  return Date.now();
}
```

### 3.6 Test all endpoints

Verify with curl or a REST client:
- CRUD operations work correctly
- Invalid definitions return 400 with validation errors
- Non-existent IDs return 404
- Pagination returns correct page/limit/total
- Events are emitted (check console logs)

## Test Gate

```bash
cd eldrin-workflows && npm run dev
# Test CRUD
curl -X POST http://localhost:4008/api/workflows -H "Content-Type: application/json" -d '...'
curl http://localhost:4008/api/workflows
curl http://localhost:4008/api/workflows/:id
curl -X PATCH http://localhost:4008/api/workflows/:id -d '...'
curl -X DELETE http://localhost:4008/api/workflows/:id
```

Acceptance criteria:
1. All 7 endpoints return correct responses
2. Invalid workflow definitions are rejected with 400 + validation details
3. Pagination works (`?page=2&limit=10`)
4. Search filter works (`?search=term`)
5. Activate/deactivate toggles `is_active`
6. Events emitted on mutations

## Files Created

| File | Purpose |
|------|---------|
| `worker/routes/workflows.ts` | Workflow CRUD route handlers |
| `worker/validation.ts` | Workflow definition JSON validation |
| `worker/utils.ts` | UUID generation, timestamp helpers |

## Files Modified

| File | Change |
|------|--------|
| `worker/index.ts` | Mount workflow routes, add permission middleware |

## Finalize

- [ ] Manual validation: test all endpoints with curl
- [ ] Commit: `feat: add workflow CRUD API with Drizzle queries`
- [ ] Update `STATUS.md` → complete, create `DONE.md`
