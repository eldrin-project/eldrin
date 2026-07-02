# Phase 4: Execution Engine

## Overview

Build the core workflow execution engine: the system that takes a workflow definition, resolves template variables, executes steps sequentially, tracks run/step status in the database, and handles errors. This is the most complex backend phase.

## Dependencies

- Phase 3 (workflow CRUD API — workflows exist in DB to execute)

## Steps

### 4.1 Define step runner interface

Create **`worker/engine/types.ts`**:

```typescript
export interface ExecutionContext {
  workflowId: string;
  runId: string;
  trigger: { type: string; data: Record<string, unknown> };
  payload: Record<string, unknown>;
  steps: Record<string, { output: unknown }>;  // Named step outputs
  env: Record<string, unknown>;
}

export interface StepResult {
  success: boolean;
  output?: unknown;
  error?: string;
}

export interface StepRunner {
  type: string;
  execute(config: Record<string, unknown>, context: ExecutionContext): Promise<StepResult>;
}
```

### 4.2 Implement template interpolation

Create **`worker/engine/interpolation.ts`**:

Resolves `{{path.to.value}}` patterns against the execution context:
- `{{payload.*}}` — trigger event payload
- `{{trigger.*}}` — trigger metadata
- `{{steps.stepName.output.*}}` — output from a named previous step
- `{{env.VARIABLE}}` — environment variable

Support nested path resolution with dot notation. Handle missing paths gracefully (return empty string or throw based on config).

### 4.3 Implement built-in step runners

Create **`worker/engine/steps/`** directory with one file per step type:

**`http-request.ts`** — `http_request` step:
- Makes outbound HTTP requests (GET/POST/PUT/DELETE)
- Config: `{ url, method, headers, body }`
- Returns: `{ statusCode, headers, body }`
- Handles timeouts (configurable, default 30s)

**`send-email.ts`** — `send_email` step:
- Calls platform email API or uses environment email provider
- Config: `{ to, subject, body, template }`
- Returns: `{ sent: true, messageId }`

**`emit-event.ts`** — `emit_event` step:
- Emits platform event via SDK's `createEventClient`
- Config: `{ event, payload }`
- Returns: `{ emitted: true }`

**`delay.ts`** — `delay` step:
- Pauses execution for configured duration
- Config: `{ duration, unit }` (seconds, minutes, hours)
- Returns: `{ waited: true, durationMs }`
- Implementation: `await new Promise(resolve => setTimeout(resolve, ms))`

### 4.4 Create step runner registry

Create **`worker/engine/registry.ts`**:

```typescript
const runners = new Map<string, StepRunner>();

export function registerStep(runner: StepRunner) {
  runners.set(runner.type, runner);
}

export function getStepRunner(type: string): StepRunner | undefined {
  return runners.get(type);
}
```

Register all built-in steps at module load time.

### 4.5 Implement execution engine

Create **`worker/engine/executor.ts`**:

Main function: `executeWorkflow(db, workflow, triggerData, env)`

Flow:
1. Create a `workflow_runs` record (status: 'running')
2. Parse workflow definition
3. Evaluate conditions against trigger data — skip if conditions not met
4. For each step in sequence:
   a. Create `workflow_run_steps` record (status: 'running')
   b. Resolve template variables in step config
   c. Look up step runner from registry
   d. Execute step runner with resolved config
   e. Update step record (status: 'completed' or 'failed', output/error)
   f. If step failed: mark run as 'failed', stop execution
   g. Add step output to context for next steps
5. Mark run as 'completed' when all steps succeed

### 4.6 Add run management routes

Create **`worker/routes/runs.ts`**:

- `GET /workflows/:id/runs` — list runs for a workflow (paginated, sorted by started_at DESC)
- `GET /runs/:runId` — get run detail with all steps
- `POST /runs/:runId/cancel` — cancel a running workflow (set status to 'cancelled')

### 4.7 Wire up run routes

Update **`worker/index.ts`** to mount run routes.

## Test Gate

```bash
cd eldrin-workflows && npm run dev
# Create a workflow, then trigger it manually
curl -X POST http://localhost:4008/api/workflows -d '{ "name": "Test", "definition": { ... } }'
curl -X POST http://localhost:4008/api/workflows/:id/run
curl http://localhost:4008/api/runs/:runId   # Check execution result
```

Acceptance criteria:
1. Execution creates run + step records in DB
2. Template interpolation resolves `{{payload.x}}` correctly
3. `http_request` step makes outbound HTTP calls
4. `delay` step pauses for configured duration
5. Failed steps mark run as 'failed' with error details
6. Run detail shows step-by-step timeline with inputs/outputs
7. Cancel endpoint sets run status to 'cancelled'

## Files Created

| File | Purpose |
|------|---------|
| `worker/engine/types.ts` | Step runner interface, execution context types |
| `worker/engine/interpolation.ts` | Template `{{variable}}` resolution |
| `worker/engine/executor.ts` | Main execution loop |
| `worker/engine/registry.ts` | Step runner registry |
| `worker/engine/steps/http-request.ts` | HTTP request step runner |
| `worker/engine/steps/send-email.ts` | Email step runner |
| `worker/engine/steps/emit-event.ts` | Event emission step runner |
| `worker/engine/steps/delay.ts` | Delay step runner |
| `worker/routes/runs.ts` | Run management routes |

## Files Modified

| File | Change |
|------|--------|
| `worker/index.ts` | Mount run routes |

## Finalize

- [ ] Manual validation: create workflow, trigger, inspect run detail
- [ ] Commit: `feat: add workflow execution engine with built-in steps`
- [ ] Update `STATUS.md` → complete, create `DONE.md`
