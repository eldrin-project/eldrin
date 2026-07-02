# Phase 5: Triggers (Event + Manual)

## Overview

Connect the execution engine to trigger sources. Implement the event trigger (receives platform events via wildcard subscription, matches against active workflows) and the manual trigger (user clicks "Run now"). Add condition evaluation to filter events before execution.

## Dependencies

- Phase 4 (execution engine — need `executeWorkflow()` to call)

## Steps

### 5.1 Implement condition evaluation engine

Create **`worker/engine/conditions.ts`**:

Evaluates an array of conditions against trigger data. Implements all operators from requirements:
- Comparison: `eq`, `neq`, `gt`, `gte`, `lt`, `lte`
- String: `contains`, `not_contains`, `starts_with`, `ends_with`
- Existence: `exists`, `not_exists`
- Set: `in`, `not_in`

Each condition has `{ field, operator, value }`. Field uses dot-notation path into the trigger data. All conditions must pass (AND logic).

### 5.2 Implement event trigger handler

Create **`worker/routes/events.ts`**:

`POST /api/_events/webhook` — internal endpoint called by the platform when events occur:
1. Parse event payload (type, data, metadata)
2. Query active workflows where `trigger.type === 'event'`
3. For each matching workflow:
   a. Parse definition, check `trigger.config.event` matches event type (exact or wildcard)
   b. Evaluate conditions against event payload
   c. If conditions pass: call `executeWorkflow()`
4. Return 200 (acknowledge receipt — execution is fire-and-forget)

Support event pattern matching:
- Exact: `user.created` matches `user.created`
- Wildcard: `user.*` matches `user.created`, `user.updated`

### 5.3 Implement manual trigger endpoint

Add to **`worker/routes/workflows.ts`**:

`POST /workflows/:id/run` — manual trigger:
1. Fetch workflow by ID, verify it exists
2. Call `executeWorkflow()` with `triggerType: 'manual'` and optional request body as trigger data
3. Return the created run record (202 Accepted)

### 5.4 Wire up event webhook route

Update **`worker/index.ts`**:
- Mount event webhook route (should be before permission middleware — internal endpoint)
- Add basic authentication for the webhook (verify platform-to-app secret or JWT)

### 5.5 Test trigger scenarios

Test cases:
- Manual trigger creates and executes a run
- Event webhook with matching event type triggers workflow
- Event webhook with non-matching event type is ignored
- Conditions filter: matching conditions → execute, non-matching → skip
- Multiple active workflows can match the same event

## Test Gate

```bash
cd eldrin-workflows && npm run dev
# Manual trigger
curl -X POST http://localhost:4008/api/workflows/:id/run

# Simulate event
curl -X POST http://localhost:4008/api/_events/webhook \
  -H "Content-Type: application/json" \
  -d '{ "type": "user.created", "payload": { "email": "test@example.com" } }'
```

Acceptance criteria:
1. Manual trigger creates a run and executes the workflow
2. Event webhook matches active workflows by event type
3. Conditions correctly filter events (AND logic)
4. Non-matching events return 200 but don't create runs
5. Multiple workflows can be triggered by the same event
6. Run detail shows correct trigger type and trigger data

## Files Created

| File | Purpose |
|------|---------|
| `worker/engine/conditions.ts` | Condition evaluation engine |
| `worker/routes/events.ts` | Platform event webhook handler |

## Files Modified

| File | Change |
|------|--------|
| `worker/routes/workflows.ts` | Add manual trigger endpoint |
| `worker/index.ts` | Mount event webhook route |

## Finalize

- [ ] Manual validation: test manual trigger + simulated event webhook
- [ ] Commit: `feat: add event and manual triggers with condition evaluation`
- [ ] Update `STATUS.md` → complete, create `DONE.md`
