# eldrin-workflows — Extension App Requirements

## Decision

**Extracted from eldrin-core Feature 8 (Workflow Engine)** and redesigned as a standalone extension app. The workflow engine is optional complexity — powerful but not foundational. Making it an extension keeps eldrin-core lean and lets the workflow engine iterate independently.

## Concept

Visual automation builder: **"When X happens, do Y"**. Users define workflows with triggers, conditions, and action steps. The platform executes them automatically when trigger conditions are met.

Example: *"When a new user is created with the admin role, send a welcome email and POST a notification to Slack."*

## Architecture

```
eldrin-workflows (extension app)
├── Backend (Hono, own database — D1, PostgreSQL, SQLite, or Turso)
│   ├── Workflow CRUD API (Drizzle ORM for portable queries)
│   ├── Execution engine
│   ├── Step runners (email, HTTP, emit event, delay, ...)
│   └── Event listener (subscribes to platform events via * wildcard)
├── Frontend (React micro-frontend, single-spa)
│   ├── Workflow list + enable/disable
│   ├── Visual builder (node editor)
│   ├── Run history + step inspector
│   └── Template library
└── Manifest
    ├── events.subscribes: [{ pattern: "*", delivery: "push" }]
    ├── ui.sideNav: [{ label: "Workflows", path: "/workflows" }]
    └── database: { name: "WORKFLOWS_DB", migrationsPath: "..." }
```

### How it integrates with eldrin-core

| Concern | Mechanism |
|---------|-----------|
| **Event triggers** | Subscribe to `*` wildcard via manifest — platform pushes all events to the app's webhook endpoint |
| **Cron triggers** | Requires a platform-level cron hook API (see [Platform prerequisites](#platform-prerequisites)) |
| **Webhook triggers** | Receives inbound webhooks at its own endpoint, matches against workflow triggers |
| **Action: send email** | Calls platform API `POST /api/app/eldrin-workflows/email` (proxied) or uses own email provider |
| **Action: HTTP request** | Direct outbound HTTP from the app's backend |
| **Action: emit event** | Calls `POST /api/events/emit` via `window.__ELDRIN__.authenticatedFetch()` |
| **Action: call app API** | Calls other apps via the platform proxy `/api/app/{targetAppId}/...` |
| **Auth** | Inherits platform JWT — all API calls go through the authenticated proxy |
| **Navigation** | Declared in manifest `ui.sideNav`, shell renders it automatically |

### Database backend selection

The platform supports multiple database backends. The workflows app inherits the customer's deployment choice:

| Deployment | Database | Mechanism |
|------------|----------|-----------|
| Cloudflare Workers | D1 (SQLite) | `env.DB` binding in `wrangler.jsonc` |
| Cloudflare Workers | PostgreSQL | Hyperdrive binding (`env.HYPERDRIVE`) |
| Cloudflare Workers | Turso | `TURSO_URL` + `TURSO_AUTH_TOKEN` env vars |
| Standalone (Bun) | SQLite | `DATABASE_PATH` env var |
| Containers (AWS/Azure/GCP) | PostgreSQL | `DATABASE_URL` env var |

The app does **not** choose the backend — it adapts to the environment. See [Database Strategy](#database-strategy) for how this works.

### Why not in core

1. **Optional** — not every deployment needs workflow automation
2. **Large scope** — drag-and-drop visual builder is a significant frontend project on its own
3. **Opinionated** — workflow engines are domain-specific; different customers want different step types
4. **Independent iteration** — can ship updates without touching core
5. **Separation of concerns** — core handles identity, security, app loading; workflows are a business feature

## Database Strategy

### ORM: Drizzle ORM (recommended)

The workflows app should use **Drizzle ORM** for database access instead of raw SQL. This is a deliberate departure from the react-todo pattern (which uses direct `env.DB.prepare()` calls) and addresses a known portability gap.

#### Why Drizzle

| Criterion | Drizzle | Kysely | Prisma | Raw SQL (current SDK) |
|-----------|---------|--------|--------|----------------------|
| Bundle size | ~7.4kb gzipped | ~10kb | ~200kb+ | 0 |
| Workers/Edge support | First-class | Community D1 dialect | Limited edge adapter | N/A |
| D1 support | Native | Community plugin | No | Direct API |
| PostgreSQL support | Native | Native | Native | SDK adapter |
| Turso support | Native | No | No | SDK adapter |
| Type safety | Schema-as-code | Query builder types | Generated types | None |
| Dependencies | 0 | 0 | Heavy (engine binary) | 0 |
| Migration tooling | drizzle-kit CLI | Manual | prisma migrate | SDK runner |

**Drizzle is the clear choice**: zero dependencies, ~7.4kb, first-class support for every database the platform supports, and schema-as-TypeScript gives compile-time safety for queries.

#### How Drizzle integrates with the SDK

Drizzle wraps the raw database drivers directly — it does **not** use the SDK's `DatabaseAdapter`. The integration model:

```
┌─────────────────────────────────────────────┐
│  Application code (Hono route handlers)     │
│  ↓ uses Drizzle's type-safe query API       │
├─────────────────────────────────────────────┤
│  Drizzle ORM                                │
│  ↓ wraps raw driver per environment         │
├──────────┬──────────┬───────────┬───────────┤
│  D1 API  │ pg       │ Turso SDK │ bun:sqlite│
│  (CF)    │ (Hyper.) │ (HTTP)    │ (Bun)     │
└──────────┴──────────┴───────────┴───────────┘
```

- **Schema**: Defined once in TypeScript (e.g., `src/db/schema.ts`) — Drizzle infers column types per dialect
- **Migrations**: Generated by `drizzle-kit` (dialect-aware SQL output) or kept as hand-written SQL run by the SDK's `runMigrations()` — TBD during Phase 1
- **Instantiation**: A factory function creates the right Drizzle instance based on environment:

```typescript
// db/index.ts — creates Drizzle instance per environment
import { drizzle as drizzleD1 } from 'drizzle-orm/d1';
import { drizzle as drizzlePg } from 'drizzle-orm/node-postgres';
import * as schema from './schema';

export function createDb(env: Record<string, unknown>) {
  if (env.DB) return drizzleD1(env.DB as D1Database, { schema });
  if (env.HYPERDRIVE) return drizzlePg((env.HYPERDRIVE as Hyperdrive).connectionString, { schema });
  if (env.DATABASE_URL) return drizzlePg(env.DATABASE_URL as string, { schema });
  // ... Turso, SQLite fallbacks
}
```

- **Queries**: Fully type-safe, portable across all backends:

```typescript
// Same code runs on D1, PostgreSQL, SQLite, Turso
const activeWorkflows = await db
  .select()
  .from(workflows)
  .where(eq(workflows.isActive, true));
```

#### Migration strategy decision (Phase 1)

Two viable approaches — decide during implementation:

| Approach | Pros | Cons |
|----------|------|------|
| **drizzle-kit** generates migrations | Dialect-aware SQL, schema diffing, studio UI | New tool in the pipeline, separate from SDK |
| **SDK `runMigrations()`** with hand-written SQL | Consistent with other Eldrin apps, manifest integration | Must write portable SQL manually, no type safety for DDL |

**Recommendation**: Use `drizzle-kit` for migration generation (it produces SQL files that the SDK runner can still execute). This gives dialect-aware DDL without abandoning the SDK's migration tracking.

### Portable SQL rules

If hand-writing migrations (or reviewing drizzle-kit output), follow these rules for D1/PostgreSQL/SQLite compatibility:

| Concern | Portable pattern | Avoid |
|---------|-----------------|-------|
| Booleans | `INTEGER NOT NULL DEFAULT 0` | `BOOLEAN` (PostgreSQL-only native), `NOT col` (SQLite-only toggle) |
| JSON | `TEXT` | `JSONB` (PostgreSQL-only; Drizzle abstracts this) |
| Timestamps | `INTEGER` (Unix ms) | `TIMESTAMP` (PostgreSQL-only) |
| UUIDs | `TEXT PRIMARY KEY` | `UUID` type (PostgreSQL-only) |
| Placeholders | `?` (SDK adapter converts to `$1, $2...` for PostgreSQL) | `$1` directly |
| Schema isolation | PostgreSQL: `SET search_path TO workflows` | Assuming single schema |
| Auto-increment | Don't use; generate UUIDs in app code | `AUTOINCREMENT`, `SERIAL` |
| String functions | `LIKE` | `ILIKE` (PostgreSQL-only; use `LOWER()` + `LIKE` for case-insensitive) |

> **Note**: When using Drizzle, most of these concerns are handled automatically — the ORM generates dialect-appropriate SQL. These rules matter mainly for hand-written migrations and seed data.

## Data Model

> **Portability note**: The schema below uses portable types (TEXT, INTEGER) that work across D1/SQLite and PostgreSQL. When using Drizzle ORM, define the schema in TypeScript — Drizzle maps to the appropriate dialect types automatically (e.g., `text('definition')` becomes TEXT on SQLite and TEXT on PostgreSQL, with optional `.json()` modifier for type inference).

### `workflows`

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT PK | UUID (generated in app code) |
| name | TEXT | Human-readable name |
| description | TEXT | Optional description |
| definition | TEXT | JSON workflow definition (see schema below) |
| is_active | INTEGER | 0 or 1 — whether the workflow is enabled |
| created_by | TEXT | User ID of creator |
| updated_at | INTEGER | Unix timestamp (ms) |
| created_at | INTEGER | Unix timestamp (ms) |

### `workflow_runs`

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT PK | UUID (generated in app code) |
| workflow_id | TEXT FK | References `workflows.id` |
| trigger_type | TEXT | "event", "cron", "webhook", "manual" |
| trigger_data | TEXT | JSON — event payload, cron expression, etc. |
| status | TEXT | pending, running, completed, failed, cancelled |
| started_at | INTEGER | Unix timestamp (ms) |
| completed_at | INTEGER | Null until done |
| error | TEXT | Null unless failed |

### `workflow_run_steps`

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT PK | UUID (generated in app code) |
| run_id | TEXT FK | References `workflow_runs.id` |
| step_index | INTEGER | Order in the workflow (0-based) |
| step_type | TEXT | "send_email", "http_request", "emit_event", "delay", ... |
| status | TEXT | pending, running, completed, failed, skipped |
| input | TEXT | JSON — resolved inputs after template interpolation |
| output | TEXT | JSON — step result or error details |
| started_at | INTEGER | Unix timestamp (ms) |
| completed_at | INTEGER | Null until done |

## Workflow Definition Schema

```json
{
  "version": 1,
  "trigger": {
    "type": "event",
    "config": {
      "event": "user.created"
    }
  },
  "conditions": [
    {
      "field": "payload.platformRoles",
      "operator": "contains",
      "value": "admin"
    }
  ],
  "steps": [
    {
      "name": "Send welcome email",
      "type": "send_email",
      "config": {
        "to": "{{payload.email}}",
        "subject": "Welcome, {{payload.firstName}}!",
        "template": "admin-welcome"
      }
    },
    {
      "name": "Notify Slack",
      "type": "http_request",
      "config": {
        "url": "https://hooks.slack.com/services/...",
        "method": "POST",
        "headers": { "Content-Type": "application/json" },
        "body": "{\"text\": \"New admin: {{payload.email}}\"}"
      }
    },
    {
      "name": "Log audit event",
      "type": "emit_event",
      "config": {
        "event": "workflow.admin-onboarding.completed",
        "payload": { "userId": "{{payload.id}}" }
      }
    }
  ]
}
```

### Trigger types

| Type | Config | Source |
|------|--------|--------|
| `event` | `{ event: "user.created" }` | Platform event pub/sub (wildcard subscription) |
| `cron` | `{ expression: "0 9 * * MON" }` | Platform cron hook (see prerequisites) |
| `webhook` | `{ path: "/trigger/my-hook" }` | Inbound HTTP to the app |
| `manual` | `{}` | User clicks "Run now" in the UI |

### Condition operators

`eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `contains`, `not_contains`, `starts_with`, `ends_with`, `exists`, `not_exists`, `in`, `not_in`

### Step types (built-in)

| Type | Description |
|------|-------------|
| `send_email` | Send email via platform email provider |
| `http_request` | Outbound HTTP request (GET/POST/PUT/DELETE) |
| `emit_event` | Emit a platform event |
| `delay` | Wait N seconds/minutes/hours before next step |
| `condition` | Branch: if/else based on previous step output |
| `transform` | Map/reshape data between steps |
| `call_app_api` | Call another Eldrin app's API via the proxy |

### Template interpolation

Step configs support `{{path.to.value}}` syntax resolved against the trigger data and previous step outputs:

- `{{payload.*}}` — trigger event payload
- `{{trigger.*}}` — trigger metadata (type, timestamp)
- `{{steps.stepName.output.*}}` — output from a named previous step
- `{{env.VARIABLE}}` — app environment variable

## API Endpoints

All under the app's proxy prefix: `/api/app/eldrin-workflows/...`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/workflows` | List workflows (paginated, filterable) |
| POST | `/workflows` | Create workflow |
| GET | `/workflows/:id` | Get workflow by ID |
| PATCH | `/workflows/:id` | Update workflow |
| DELETE | `/workflows/:id` | Delete workflow |
| POST | `/workflows/:id/activate` | Enable workflow |
| POST | `/workflows/:id/deactivate` | Disable workflow |
| POST | `/workflows/:id/run` | Manual trigger |
| GET | `/workflows/:id/runs` | List runs for a workflow |
| GET | `/runs/:runId` | Get run details with steps |
| POST | `/runs/:runId/cancel` | Cancel a running workflow |
| GET | `/templates` | List built-in templates |
| POST | `/api/_events/webhook` | Platform event push endpoint (internal) |
| POST | `/trigger/:path` | Inbound webhook trigger endpoint |

## Frontend

### Pages

1. **Workflow List** (`/workflows`) — table with name, trigger type, last run, status toggle, actions
2. **Workflow Builder** (`/workflows/new`, `/workflows/:id/edit`) — visual node editor
3. **Run History** (`/workflows/:id/runs`) — table with status, trigger, duration, step count
4. **Run Detail** (`/workflows/:id/runs/:runId`) — step-by-step timeline with inputs/outputs
5. **Templates** (`/workflows/templates`) — gallery of pre-built workflows to clone

### Visual Builder (Phase 2)

The builder is the most complex UI component. It could be phased:

- **Phase 1**: JSON editor with schema validation + form-based step configuration (functional but not visual)
- **Phase 2**: Drag-and-drop node editor with connections, step palette, live preview

Libraries to evaluate: `reactflow` (MIT, widely used for node editors), or custom canvas.

## Platform Prerequisites

### Cron Hook API (optional, small addition to eldrin-core)

For cron-triggered workflows, the platform needs a generic mechanism for apps to register scheduled callbacks. This is useful beyond just workflows (any app might want cron).

| Table | Columns |
|-------|---------|
| `app_cron_hooks` | id, app_id, expression, callback_path, is_active, last_run_at, next_run_at |

| Endpoint | Description |
|----------|-------------|
| `POST /api/app/:appId/cron` | Register a cron hook |
| `DELETE /api/app/:appId/cron/:hookId` | Remove a cron hook |

**Processing**: A platform-level cron job (or Cloudflare Cron Trigger) checks `app_cron_hooks` every minute and POSTs to `{app_url}{callback_path}` for due hooks.

This is a **small, generic addition** (~100-150 LOC + 1 migration) that benefits all apps, not just workflows.

## Implementation Phases

### Phase 1: Foundation
- Scaffold `eldrin-workflows` repo using `eldrin-app-core` SDK
- Set up Drizzle ORM: schema definition, database factory, drizzle-kit config
- Database migrations (3 tables) — generated via drizzle-kit or hand-written portable SQL
- Verify migrations run on D1, PostgreSQL, and SQLite (test with docker-compose PostgreSQL + local D1)
- Workflow CRUD API (Hono + Drizzle queries)
- Basic execution engine (sequential steps)
- Built-in steps: `http_request`, `send_email`, `emit_event`, `delay`
- Event trigger (subscribe to `*`, match active workflows)
- Manual trigger
- Frontend: workflow list, JSON-based editor, run history

### Phase 2: Visual Builder
- Drag-and-drop node editor (evaluate reactflow)
- Step palette with drag-to-add
- Connection drawing between nodes
- Step configuration panels
- Live validation

### Phase 3: Advanced Features
- Cron triggers (requires platform cron hook API)
- Webhook triggers
- Conditional branching (if/else nodes)
- Parallel step execution
- Transform steps
- Template library
- Retry configuration per step
- Workflow versioning

## Template Ideas

| Template | Trigger | Steps |
|----------|---------|-------|
| Welcome email | `user.created` | send_email |
| Admin notification | `user.created` where role=admin | http_request (Slack) |
| Cleanup old data | cron daily | call_app_api |
| Invoice follow-up | `invoice.overdue` | delay 3d → send_email |
| App install report | `app.installed` | http_request (analytics) + send_email (admin) |

## Open Questions

1. **Execution context**: Should workflow steps run with the creator's permissions or a service account?
2. **Secrets management**: How do steps reference API keys / tokens for outbound HTTP? Per-workflow secrets or app-level env vars?
3. **Rate limiting**: Should there be a max concurrent runs per workflow? Max steps per workflow?
4. **Multi-tenancy**: One workflow app per deployment, or shared across tenants?
5. **Error handling**: Auto-retry failed steps? Configurable per step? Dead-letter for persistently failing workflows?
6. **Migration tooling**: Use `drizzle-kit generate` (dialect-aware) or keep SDK's `runMigrations()` with hand-written SQL? Can we combine both — drizzle-kit generates, SDK runner executes?
7. **PostgreSQL schema isolation**: Should the workflows app use a dedicated PostgreSQL schema (e.g., `workflows`) to isolate its tables from other apps sharing the same database? The SDK supports this via `postgresSchema` config.
8. **JSON querying**: On PostgreSQL, `TEXT` JSON columns can't use `->` operators (need `JSONB`). Should we use Drizzle's `.json()` column modifier and let it map to `JSONB` on PostgreSQL / `TEXT` on SQLite? This affects whether we can query into workflow definitions server-side.
