# Phase 9: Platform Cron Hook API — Implementation Plan

## Architecture

**Platform-managed cron hooks**: eldrin-core owns the `app_cron_hooks` table. Apps register/unregister hooks via HTTP API. Platform evaluates cron expressions and calls app callbacks when due.

```
┌─────────────────────────────────────────────────────────────────┐
│                        PLATFORM (eldrin-core)                    │
│                                                                  │
│  ┌──────────────┐    ┌─────────────────┐    ┌───────────────┐  │
│  │ CRUD API     │    │ app_cron_hooks   │    │ Cron Processor│  │
│  │ POST/DELETE  │───>│ table            │<───│ (every 60s)   │  │
│  │ /api/cron-   │    │ - expression     │    │ query due     │  │
│  │  hooks       │    │ - next_run_at    │    │ hooks, call   │  │
│  └──────────────┘    │ - callback_path  │    │ app callbacks │  │
│        ▲              └─────────────────┘    └───────┬───────┘  │
│        │                                             │           │
│  ┌─────┴──────────────────────────────────┐          │           │
│  │ Tick trigger (provider-specific)        │          │           │
│  │ • CF: scheduled handler (Cron Trigger) │          │           │
│  │ • Bun/Node: setInterval(60s)           │          │           │
│  │ • Lambda/Azure/GCP: external scheduler │          │           │
│  │   → POST /api/_internal/tick           │          │           │
│  └────────────────────────────────────────┘          │           │
└──────────────────────────────────────────────────────┼───────────┘
                                                       │
                    POST ${app_url}${callback_path}    │
                                                       ▼
┌──────────────────────────────────────────────────────────────────┐
│                    APP (eldrin-workflows)                         │
│                                                                   │
│  ┌────────────────────┐    ┌──────────────────────────────────┐  │
│  │ POST /api/_cron/   │    │ Activate handler                 │  │
│  │   callback         │    │ → registers hook with platform   │  │
│  │ Matches workflow,  │    │ → DELETE ${PLATFORM_URL}/api/    │  │
│  │ calls executor     │    │   cron-hooks/:id on deactivate   │  │
│  └────────────────────┘    └──────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

## Cross-provider tick mechanism

| Provider | Mechanism | Code change needed? |
|----------|-----------|-------------------|
| Cloudflare Workers | `scheduled` event handler (Cron Trigger) | Yes — add `scheduled` export |
| Standalone (Bun) | `setInterval(processCronHooks, 60_000)` | Yes — add interval in `main()` |
| Node containers (ECS, Cloud Run, Azure Container) | `setInterval(processCronHooks, 60_000)` | Yes — add interval in `main()` |
| AWS Lambda | EventBridge rule → POST to API Gateway → tick endpoint | No — uses HTTP tick endpoint |
| Azure Functions | Timer trigger → POST to function HTTP endpoint → tick | No — uses HTTP tick endpoint |
| GCP Cloud Functions | Cloud Scheduler → POST to function URL → tick endpoint | No — uses HTTP tick endpoint |

## Step-by-step implementation

### Part A: eldrin-core (platform)

#### A1. Install croner package
- `npm install croner` in eldrin-core
- `croner` is 5KB, pure JS, isomorphic — works in Workers, Node, Bun

#### A2. Migration: `app_cron_hooks` table
- File: `migrations/20260213000001-app-cron-hooks.sql`
- Columns: id, app_id, expression, callback_path, payload, is_active, last_run_at, next_run_at, created_at, updated_at
- Index on (is_active, next_run_at) for efficient due-hook queries
- Index on app_id for per-app listing

#### A3. Cron processor
- File: `core/cron/processor.ts`
- `processCronHooks(db: DatabaseAdapter)` — queries due hooks, calls app callbacks via fetch, updates last_run_at + next_run_at
- `getNextCronRun(expression: string, after?: Date)` — uses croner to calculate
- Error handling: log failures, don't block other hooks

#### A4. CRUD route handlers
- File: `core/routes/cron-hooks.ts`
- `POST /api/cron-hooks` — register (validates expression, calculates next_run_at)
- `DELETE /api/cron-hooks/:hookId` — remove
- `GET /api/cron-hooks` — list (filtered by appId query param)
- Auth: requires valid JWT (same as other platform routes)
- App ID from request body/query — platform trusts the JWT holder

#### A5. Register routes + tick endpoint
- File: `core/app.ts` — add cron-hooks routes under /api/cron-hooks
- `POST /api/_internal/tick` — protected by CRON_SECRET env var header check
- Tick endpoint calls processCronHooks(db) and returns summary

#### A6. Add migration to runner
- File: `server/migrations.ts` — add new migration file to the list

#### A7. Provider: Cloudflare scheduled handler
- File: `providers/cloudflare/index.ts` — export `scheduled` alongside `fetch`
- `scheduled` handler: init app (same lazy-init), call processCronHooks(db)
- File: `wrangler.jsonc` — add `"triggers": { "crons": ["* * * * *"] }`

#### A8. Provider: Standalone + Node setInterval
- File: `providers/standalone/index.ts` — add `setInterval(tick, 60_000)` after server starts
- File: `providers/node/entrypoint.ts` — add `setInterval(tick, 60_000)` after server starts
- Tick function: creates DB instance, calls processCronHooks(db)
- Add a console log for tick cycle visibility

### Part B: eldrin-workflows (app)

#### B1. Cron callback handler
- File: `worker/routes/cron.ts`
- `POST /api/_cron/callback` — receives { hookId, timestamp } from platform
- Queries active workflows with `trigger.type === 'cron'`
- Could store hookId→workflowId mapping for direct lookup
- Calls `executeWorkflow()` (same as event trigger)

#### B2. Workflow activate/deactivate — register/unregister hooks
- File: `worker/routes/workflows.ts`
- On activate: if `trigger.type === 'cron'`, POST to `${PLATFORM_URL}/api/cron-hooks`
  - Sends: appId, expression, callbackPath, hookId (= workflow ID)
  - Uses forwarded Authorization header from original request
- On deactivate: DELETE `${PLATFORM_URL}/api/cron-hooks/${workflowId}`
- On delete: also DELETE the hook if workflow was active
- `PLATFORM_URL` env var (e.g., `http://localhost:8787` in dev)

#### B3. Mount cron routes
- File: `worker/index.ts` — import and mount cronRoutes

#### B4. Enable cron trigger in TriggerConfig
- File: `src/components/editor/TriggerConfig.tsx`
- Remove `disabled` attribute on cron input
- Replace "Phase 9" text with helpful description
- Add common preset buttons (every 5 min, hourly, daily, weekly)
- Optional: client-side validation with croner (add to package.json)

#### B5. Validation
- File: `worker/validation.ts` — ensure cron trigger with expression passes validation

## Auth flow for hook registration

```
User → POST /api/app/eldrin-workflows/workflows/:id/activate
       (Authorization: Bearer <user-jwt>)
       │
       ▼
Platform proxy → App activate handler
       │
       │  App reads trigger.type === 'cron'
       │  App calls: POST ${PLATFORM_URL}/api/cron-hooks
       │             Authorization: Bearer <user-jwt>  (forwarded)
       │             Body: { appId, expression, callbackPath, hookId }
       │
       ▼
Platform validates JWT, parses expression, stores hook
       │
       ▼
App returns { workflow } to user
```

## Config / env vars needed

- `CRON_SECRET` — env var for protecting the HTTP tick endpoint (all providers)
- `PLATFORM_URL` — env var in eldrin-workflows for app→platform API calls

## Test gate

1. Register a cron hook via POST /api/cron-hooks → returns hook with next_run_at
2. List hooks via GET /api/cron-hooks?appId=eldrin-workflows → shows registered hook
3. Cron processor finds due hook and calls callback → workflow executes
4. Deactivating workflow → DELETE removes the hook
5. Build passes in both repos
