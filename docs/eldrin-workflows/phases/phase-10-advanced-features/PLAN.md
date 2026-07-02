# Phase 10: Advanced Triggers & Steps

## Overview

Extend the workflow engine with advanced capabilities: inbound webhook triggers, conditional branching, parallel step execution, transform steps, cross-app API calls, retry logic, and workflow versioning.

Detailed plan will be written when implementation begins.

## Dependencies

- Phase 9 (platform cron API — all trigger types available)

## Key Deliverables

### Inbound webhook triggers
- `POST /trigger/:path` — public endpoint for external systems
- Match path against active workflows with `trigger.type === 'webhook'` and matching `trigger.config.path`
- Authentication: API key, HMAC signature, or open (configurable per workflow)

### Conditional branching
- `condition` step type with if/else branches
- Definition: `{ type: "condition", config: { conditions: [...], onTrue: [...steps], onFalse: [...steps] } }`
- Execution engine handles nested step arrays
- Visual builder: condition node with two output handles (Phase 8 extension)

### Parallel step execution
- `parallel` step type that executes child steps concurrently
- Definition: `{ type: "parallel", config: { steps: [...] } }`
- Wait for all to complete (or fail-fast on first error)
- All parallel step outputs available to subsequent steps

### Transform steps
- `transform` step type for data mapping between steps
- Config: JavaScript expression or JSONPath mapping
- Enables reshaping data between incompatible step outputs/inputs

### call_app_api step
- Makes authenticated requests to other Eldrin apps via the platform proxy
- Config: `{ appId, path, method, body }`
- Uses platform JWT for authentication

### Retry configuration
- Per-step retry config: `{ maxRetries, backoffMs, retryOn: ['5xx', 'timeout'] }`
- Exponential backoff with jitter
- Step status tracks retry attempts

### Workflow versioning
- Snapshot the workflow definition when a run starts
- Runs reference the definition version, not the current definition
- Enables safe editing of active workflows

## Test Gate

- Webhook trigger fires from external POST
- Conditional branching follows correct path
- Parallel steps execute concurrently
- Transform step reshapes data correctly
- Retry recovers from transient failures
- Editing a workflow doesn't affect in-flight runs

## Finalize

- [ ] Commit: `feat: add advanced triggers and step types`
- [ ] Update `STATUS.md` → complete, create `DONE.md`
