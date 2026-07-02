# eldrin-workflows — Implementation Plan

## Overview

Build the **eldrin-workflows** extension app: a visual automation builder ("When X happens, do Y") that runs as a standalone Eldrin extension. Users define workflows with triggers, conditions, and action steps. The platform executes them automatically when trigger conditions are met.

This is the first Eldrin extension app built with **Hono** (routing) + **Drizzle ORM** (database portability), making it the reference implementation for production-quality Eldrin apps.

### Requirements

Full requirements document: `docs/requirements/eldrin-workflows.md`

### Key Technical Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Repo structure | New repo → parent submodule | Like eldrin-invoicing, eldrin-catalog |
| Backend routing | Hono | Cleaner than bare fetch handler; matches eldrin-core |
| ORM | Drizzle | Zero deps, ~7.4kb, first-class D1/PG/Turso/SQLite |
| Migration strategy | drizzle-kit generates + SDK `runMigrations()` executes | Dialect-aware DDL + SDK tracking |
| Frontend UI | daisyUI 5 | Matches react-todo post-migration; shared theme |
| Visual builder | reactflow | MIT, widely used for node editors |

---

## Implementation Order

```
Phase 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11
```

| # | Phase | Effort | Status |
|---|-------|--------|--------|
| 1 | [Project Scaffolding & Dev Environment](#phase-1-project-scaffolding--dev-environment) | Medium | not_started |
| 2 | [Database Layer (Drizzle ORM)](#phase-2-database-layer-drizzle-orm) | Medium | not_started |
| 3 | [Workflow CRUD API](#phase-3-workflow-crud-api) | Medium | not_started |
| 4 | [Execution Engine](#phase-4-execution-engine) | Large | not_started |
| 5 | [Triggers (Event + Manual)](#phase-5-triggers-event--manual) | Medium | not_started |
| 6 | [Frontend — Workflow Management](#phase-6-frontend--workflow-management) | Medium | not_started |
| 7 | [Frontend — Workflow Editor](#phase-7-frontend--workflow-editor) | Medium-Large | not_started |
| 8 | [Visual Builder (reactflow)](#phase-8-visual-builder-reactflow) | Large | not_started |
| 9 | [Platform Cron Hook API](#phase-9-platform-cron-hook-api) | Small-Medium | not_started |
| 10 | [Advanced Triggers & Steps](#phase-10-advanced-triggers--steps) | Large | not_started |
| 11 | [Templates & Polish](#phase-11-templates--polish) | Medium | not_started |

### Dependencies

```
Phase 1 → 2 → 3 → 4 → 5   (backend pipeline)
Phase 1 → 6                  (frontend shell)
Phase 3 + 4 + 5 → 6          (frontend needs working API)
Phase 6 → 7 → 8              (editor builds on list pages, visual builder extends editor)
Phase 4 + 5 → 9              (cron needs engine + trigger infra)
Phase 9 → 10                  (advanced features need cron)
Phase 7 + 10 → 11            (templates need editor + advanced steps)
```

### MVP boundary

**Phases 1–7** deliver a fully functional workflow engine with JSON-based editing. Users can create workflows, configure triggers/steps via forms, and view execution history. This is a usable product.

**Phases 8–11** add the visual builder, cron triggers, advanced step types, and templates — these elevate the UX but aren't required for initial launch.

---

## Phase 1: Project Scaffolding & Dev Environment

**Effort**: Medium | **Files**: ~15 new

Scaffold the `eldrin-workflows` repo with the standard Eldrin extension app structure. Key difference from react-todo: uses **Hono** for backend routing instead of a bare fetch handler.

### Project structure

```
eldrin-workflows/
├── migrations/                    # SQL migration files
├── public/
│   ├── _headers
│   └── eldrin-app.manifest.json   # App manifest
├── scripts/
│   └── generate-migrations.ts     # SQL → TypeScript module
├── src/                           # React frontend
│   ├── components/
│   ├── pages/
│   ├── eldrin-workflows.tsx       # single-spa entry
│   ├── root.component.tsx         # Main React component
│   ├── main.tsx                   # Standalone dev entry
│   └── index.css                  # daisyUI theme
├── worker/                        # Hono backend
│   ├── index.ts                   # Hono app + routes
│   ├── routes/                    # Route handlers (per resource)
│   └── migrations.generated.ts    # Auto-generated
├── package.json
├── vite.config.ts
├── wrangler.jsonc
├── tsconfig.json                  # Project references
├── tsconfig.app.json              # Frontend
├── tsconfig.worker.json           # Worker
├── tsconfig.node.json             # Build scripts
└── worker-configuration.d.ts      # Env types
```

### Manifest highlights

```json
{
  "id": "eldrin-workflows",
  "name": "Workflows",
  "permissions": [
    { "resource": "workflows", "actions": ["read", "create", "update", "delete"] },
    { "resource": "workflow-runs", "actions": ["read", "delete"] }
  ],
  "api": {
    "routes": [
      { "method": "GET", "path": "/workflows", "permission": "workflows:read" },
      { "method": "POST", "path": "/workflows", "permission": "workflows:create" },
      ...
    ]
  },
  "events": {
    "subscribes": [{ "pattern": "*", "delivery": "push" }]
  },
  "database": {
    "name": "eldrin-workflows",
    "migrationsPath": "migrations",
    "handledBy": "worker"
  },
  "ui": {
    "sideNav": [
      { "label": "Workflows", "icon": "workflow", "path": "/eldrin-workflows/workflows" }
    ]
  }
}
```

### Test gate

- `npm run dev` serves the app on its port
- Health endpoint returns 200
- Shell can mount the micro-frontend via single-spa
- `npm run build` produces dist output

---

## Phase 2: Database Layer (Drizzle ORM)

**Effort**: Medium | **Files**: ~5 new, ~2 modified

Set up Drizzle ORM as the database layer — the first Eldrin app to use an ORM. Defines schema for 3 tables, creates a database factory for multi-environment support, and integrates with the SDK's migration runner.

### Drizzle schema (3 tables)

- `workflows` — id, name, description, definition (JSON as TEXT), is_active, created_by, timestamps
- `workflow_runs` — id, workflow_id (FK), trigger_type, trigger_data, status, timestamps, error
- `workflow_run_steps` — id, run_id (FK), step_index, step_type, status, input, output, timestamps

### Database factory

```typescript
// worker/db/index.ts
export function createDb(env: Record<string, unknown>) {
  if (env.DB) return drizzleD1(env.DB as D1Database, { schema });
  if (env.HYPERDRIVE) return drizzlePg((env.HYPERDRIVE as Hyperdrive).connectionString, { schema });
  if (env.DATABASE_URL) return drizzlePg(env.DATABASE_URL as string, { schema });
  // Turso, SQLite fallbacks
}
```

### Test gate

- Migrations run on D1 via `wrangler dev`
- Schema types are correct (TypeScript compilation)
- `_eldrin_migrations` table tracks applied migrations

---

## Phase 3: Workflow CRUD API

**Effort**: Medium | **Files**: ~4 new, ~2 modified

Hono route handlers for full workflow lifecycle management. All queries through Drizzle.

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/workflows` | List (paginated, filterable by status/name) |
| POST | `/workflows` | Create workflow |
| GET | `/workflows/:id` | Get by ID |
| PATCH | `/workflows/:id` | Update workflow |
| DELETE | `/workflows/:id` | Delete workflow |
| POST | `/workflows/:id/activate` | Enable |
| POST | `/workflows/:id/deactivate` | Disable |

### Key concerns

- JSON validation for workflow definition schema
- Permission middleware (manifest-driven, SDK)
- Event emission: `workflow.created`, `workflow.updated`, `workflow.deleted`
- Pagination: `?page=1&limit=20&status=active&search=term`

### Test gate

- All 7 endpoints return correct responses
- Invalid workflow definitions are rejected with 400
- Permission middleware blocks unauthorized access
- Events are emitted on mutations

---

## Phase 4: Execution Engine

**Effort**: Large | **Files**: ~8 new, ~2 modified

The core engine that processes workflow definitions: resolves templates, executes steps sequentially, tracks run/step status, and handles errors.

### Architecture

```
POST /workflows/:id/run  or  event webhook
  → createRun(workflow, triggerData)
  → evaluateConditions(workflow.conditions, triggerData)
  → for each step:
      resolveTemplates(step.config, context)
      → stepRunners[step.type].execute(resolvedConfig)
      → updateStepStatus(success/failure)
  → updateRunStatus(completed/failed)
```

### Step runner interface

```typescript
interface StepRunner {
  type: string;
  execute(config: Record<string, unknown>, context: ExecutionContext): Promise<StepResult>;
}
```

### Built-in steps

| Type | Description |
|------|-------------|
| `http_request` | Outbound HTTP (GET/POST/PUT/DELETE) |
| `send_email` | Email via platform API |
| `emit_event` | Emit platform event |
| `delay` | Wait N seconds/minutes/hours |

### Template interpolation

Resolves `{{payload.email}}`, `{{steps.stepName.output.id}}`, `{{env.VARIABLE}}` patterns against the execution context.

### Test gate

- Manual trigger creates a run, executes steps, records status
- `http_request` step makes outbound calls
- `delay` step pauses execution for configured duration
- Failed steps mark the run as failed
- Template interpolation resolves nested paths

---

## Phase 5: Triggers (Event + Manual)

**Effort**: Medium | **Files**: ~3 new, ~2 modified

Connect the execution engine to trigger sources: platform events (wildcard subscription) and manual triggers.

### Event trigger flow

```
Platform emits event → POST /api/_events/webhook
  → find active workflows where trigger.type === "event"
  → filter by trigger.config.event matching event type
  → evaluateConditions per workflow
  → executeWorkflow for each match
```

### Condition evaluation

Implements the operator set from requirements: `eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `contains`, `not_contains`, `starts_with`, `ends_with`, `exists`, `not_exists`, `in`, `not_in`.

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/workflows/:id/run` | Manual trigger |
| GET | `/workflows/:id/runs` | List runs |
| GET | `/runs/:runId` | Run detail with steps |
| POST | `/runs/:runId/cancel` | Cancel running workflow |
| POST | `/api/_events/webhook` | Platform event push (internal) |

### Test gate

- Manual trigger creates and executes a run
- Event webhook matches active workflows by event type
- Conditions filter out non-matching events
- Run detail includes step-by-step timeline

---

## Phase 6: Frontend — Workflow Management

**Effort**: Medium | **Files**: ~6 new, ~2 modified

Core management UI: list workflows, view run history, inspect run details.

### Pages

1. **Workflow List** (`/workflows`) — table with name, trigger type, last run status, active toggle, edit/delete actions
2. **Run History** (`/workflows/:id/runs`) — table with status badge, trigger type, started/completed timestamps, duration, step count
3. **Run Detail** (`/workflows/:id/runs/:runId`) — step-by-step timeline with expandable input/output JSON, status per step, error messages

### Key patterns

- `useAuthHeaders()` from SDK for API calls
- daisyUI components (table, badge, toggle, card, modal)
- MutationObserver theme sync (same as react-todo)
- Tab-based or route-based navigation within the app

### Test gate

- Workflow list loads and displays workflows
- Status toggle calls activate/deactivate API
- Run history shows runs for a workflow
- Run detail shows step timeline with expandable data
- Dark mode works correctly

---

## Phase 7: Frontend — Workflow Editor

**Effort**: Medium-Large | **Files**: ~8 new, ~2 modified

JSON-based workflow editor with form overlays for trigger and step configuration. This is the Phase 1 (pre-visual-builder) editor.

### Components

1. **Workflow Editor Page** (`/workflows/new`, `/workflows/:id/edit`)
2. **Trigger Config Form** — dropdown for type, dynamic config form per type
3. **Step List** — ordered list of steps, add/remove/reorder
4. **Step Config Form** — dynamic form per step type (http_request fields, email fields, etc.)
5. **Condition Builder** — field/operator/value rows with add/remove
6. **JSON Preview** — read-only JSON view of the full definition
7. **Validation Feedback** — inline errors for invalid definitions

### Test gate

- Can create a new workflow via the editor
- Trigger type selection shows correct config form
- Steps can be added, configured, reordered, removed
- Saving produces a valid workflow definition
- Validation errors display inline

---

## Phase 8: Visual Builder (reactflow)

**Effort**: Large | **Files**: ~10 new

Replace the JSON + forms editor with a drag-and-drop visual node editor using reactflow. Detailed plan will be written when implementation begins.

### Key deliverables

- reactflow integration with custom node types (trigger, step, condition, end)
- Step palette with drag-to-add
- Connection drawing between nodes
- Click-to-configure panels
- Bidirectional sync: visual ↔ JSON definition
- Live validation (highlight invalid nodes)

---

## Phase 9: Platform Cron Hook API

**Effort**: Small-Medium | **Files**: ~4 new in eldrin-core, ~2 new in eldrin-workflows

**Cross-repo phase**: Adds a generic cron hook API to **eldrin-core** that any app can use. Detailed plan will be written when implementation begins.

### Key deliverables

- `app_cron_hooks` table in eldrin-core
- Register/unregister endpoints
- Cron processing: check due hooks, POST to app callbacks
- Cloudflare Cron Trigger support
- Cron trigger type in eldrin-workflows

---

## Phase 10: Advanced Triggers & Steps

**Effort**: Large | **Files**: ~8 new

Extend the engine with advanced capabilities. Detailed plan will be written when implementation begins.

### Key deliverables

- Inbound webhook triggers (`POST /trigger/:path`)
- Conditional branching (if/else nodes)
- Parallel step execution
- Transform/map steps
- `call_app_api` step type
- Retry configuration per step
- Workflow versioning (definition snapshots per run)

---

## Phase 11: Templates & Polish

**Effort**: Medium | **Files**: ~5 new

Pre-built workflow templates and UX improvements. Detailed plan will be written when implementation begins.

### Key deliverables

- 5 built-in templates (from requirements: welcome email, admin notification, cleanup, invoice follow-up, app install report)
- Template gallery page (`/workflows/templates`)
- Clone-to-create flow
- Workflow duplicate action
- UX polish: loading skeletons, error states, empty states, confirmation dialogs

---

## Reference

- **Requirements**: `docs/requirements/eldrin-workflows.md`
- **Database portability tech debt**: `docs/technical-debt/react-todo-database-portability.md`
- **SDK database adapter**: `eldrin-app-core/src/database/interface.ts`
- **React-todo (reference app)**: `react-todo/` (project structure, manifest, worker, frontend)
- **Drizzle ORM docs**: https://orm.drizzle.team
