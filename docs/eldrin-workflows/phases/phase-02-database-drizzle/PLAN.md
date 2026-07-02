# Phase 2: Database Layer (Drizzle ORM)

## Overview

Set up Drizzle ORM as the database access layer — the first Eldrin extension app to use an ORM instead of raw SQL. Defines the schema for 3 tables, creates a database factory for multi-environment support (D1, PostgreSQL, Turso, SQLite), and integrates with the SDK's migration runner for tracking.

This phase establishes the pattern that eldrin-workflows (and future apps) will follow for database-portable queries.

## Dependencies

- Phase 1 (project scaffolding — repo, deps, configs exist)

## Steps

### 2.1 Define Drizzle schema

Create **`worker/db/schema.ts`** with the 3 tables from the requirements:

```typescript
import { sqliteTable, text, integer, index } from 'drizzle-orm/sqlite-core';

export const workflows = sqliteTable('workflows', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  description: text('description'),
  definition: text('definition').notNull(),    // JSON as TEXT
  isActive: integer('is_active', { mode: 'boolean' }).notNull().default(false),
  createdBy: text('created_by').notNull(),
  createdAt: integer('created_at', { mode: 'number' }).notNull(),
  updatedAt: integer('updated_at', { mode: 'number' }).notNull(),
}, (table) => [
  index('idx_workflows_is_active').on(table.isActive),
  index('idx_workflows_created_by').on(table.createdBy),
]);

export const workflowRuns = sqliteTable('workflow_runs', {
  id: text('id').primaryKey(),
  workflowId: text('workflow_id').notNull().references(() => workflows.id, { onDelete: 'cascade' }),
  triggerType: text('trigger_type').notNull(),        // "event", "cron", "webhook", "manual"
  triggerData: text('trigger_data'),                   // JSON
  status: text('status').notNull().default('pending'), // pending, running, completed, failed, cancelled
  startedAt: integer('started_at', { mode: 'number' }),
  completedAt: integer('completed_at', { mode: 'number' }),
  error: text('error'),
}, (table) => [
  index('idx_runs_workflow_id').on(table.workflowId),
  index('idx_runs_status').on(table.status),
  index('idx_runs_started_at').on(table.startedAt),
]);

export const workflowRunSteps = sqliteTable('workflow_run_steps', {
  id: text('id').primaryKey(),
  runId: text('run_id').notNull().references(() => workflowRuns.id, { onDelete: 'cascade' }),
  stepIndex: integer('step_index').notNull(),
  stepType: text('step_type').notNull(),
  status: text('status').notNull().default('pending'),
  input: text('input'),    // JSON — resolved config
  output: text('output'),  // JSON — step result
  startedAt: integer('started_at', { mode: 'number' }),
  completedAt: integer('completed_at', { mode: 'number' }),
}, (table) => [
  index('idx_steps_run_id').on(table.runId),
  index('idx_steps_status').on(table.status),
]);
```

**Design decisions**:
- `definition`, `triggerData`, `input`, `output` are `TEXT` (not JSONB) for SQLite/D1 portability — Drizzle handles dialect differences
- `INTEGER` with `mode: 'boolean'` for `is_active` — portable across all backends
- `INTEGER` with `mode: 'number'` for timestamps — Unix ms
- Cascade delete: runs deleted when workflow deleted, steps deleted when run deleted
- UUIDs generated in app code (not auto-increment)

### 2.2 Create database factory

Create **`worker/db/index.ts`**:

```typescript
import { drizzle as drizzleD1 } from 'drizzle-orm/d1';
import * as schema from './schema';

// Re-export schema for query imports
export * from './schema';
export { schema };

// Type for the database instance
export type Database = ReturnType<typeof createDb>;

// Phase 1: D1 only (current deployment target)
export function createDb(env: Record<string, unknown>) {
  const d1 = env.DB as D1Database;
  return drizzleD1(d1, { schema });
}

// TODO Phase 2+: Multi-database support
// if (env.HYPERDRIVE) return drizzlePg(...)
// if (env.DATABASE_URL) return drizzlePg(...)
// if (env.TURSO_URL) return drizzleTurso(...)
```

Start with D1-only. Multi-database factory will be expanded when testing on other backends.

### 2.3 Write SQL migrations

Create hand-written SQL migration files that match the Drizzle schema:

**`migrations/20250101000000-create-workflows-table.sql`**:
```sql
CREATE TABLE workflows (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  definition TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 0,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX idx_workflows_is_active ON workflows(is_active);
CREATE INDEX idx_workflows_created_by ON workflows(created_by);
```

**`migrations/20250101000001-create-workflow-runs-table.sql`**:
```sql
CREATE TABLE workflow_runs (
  id TEXT PRIMARY KEY,
  workflow_id TEXT NOT NULL,
  trigger_type TEXT NOT NULL,
  trigger_data TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  started_at INTEGER,
  completed_at INTEGER,
  error TEXT,
  FOREIGN KEY (workflow_id) REFERENCES workflows(id) ON DELETE CASCADE
);

CREATE INDEX idx_runs_workflow_id ON workflow_runs(workflow_id);
CREATE INDEX idx_runs_status ON workflow_runs(status);
CREATE INDEX idx_runs_started_at ON workflow_runs(started_at);
```

**`migrations/20250101000002-create-workflow-run-steps-table.sql`**:
```sql
CREATE TABLE workflow_run_steps (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  step_index INTEGER NOT NULL,
  step_type TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  input TEXT,
  output TEXT,
  started_at INTEGER,
  completed_at INTEGER,
  FOREIGN KEY (run_id) REFERENCES workflow_runs(id) ON DELETE CASCADE
);

CREATE INDEX idx_steps_run_id ON workflow_run_steps(run_id);
CREATE INDEX idx_steps_status ON workflow_run_steps(status);
```

**Note**: No seed data — workflows are user-created, unlike react-todo's sample todos.

### 2.4 Generate migration TypeScript module

Run the generation script (created in Phase 1):

```bash
npm run generate:migrations
```

Verify `worker/migrations.generated.ts` is created with all 3 migration files.

### 2.5 Wire up migration runner in the worker

Update **`worker/index.ts`** to run migrations on first request:

```typescript
import { runMigrations } from '@eldrin-project/eldrin-app-core';
import migrations from './migrations.generated';
import { createDb } from './db';

let migrationsComplete = false;

app.use('*', async (c, next) => {
  // Run migrations once
  if (!migrationsComplete) {
    const result = await runMigrations(c.env.DB, {
      migrations,
      onLog: (msg, level) => console[level](`[workflows] ${msg}`),
    });
    if (!result.success) {
      return c.json({ error: 'Migration failed', details: result.error?.message }, 500);
    }
    migrationsComplete = true;
  }

  // Attach db instance to context
  const db = createDb(c.env as unknown as Record<string, unknown>);
  c.set('db', db);

  await next();
});
```

### 2.6 Add Drizzle config (optional, for drizzle-kit)

Create **`drizzle.config.ts`** for future use with `drizzle-kit`:

```typescript
import { defineConfig } from 'drizzle-kit';

export default defineConfig({
  schema: './worker/db/schema.ts',
  out: './migrations',
  dialect: 'sqlite',
});
```

This enables `npx drizzle-kit generate` for future schema changes.

### 2.7 Test migrations

Start `wrangler dev` and hit the health endpoint — migrations should run on first request.

Verify:
- All 3 tables created
- `_eldrin_migrations` table tracks applied migrations with checksums
- Subsequent requests don't re-run migrations

## Test Gate

```bash
cd eldrin-workflows && npm run generate:migrations  # Generates TS module
cd eldrin-workflows && npm run build                # Compiles with schema types
cd eldrin-workflows && npm run dev                  # Dev server + migrations
curl http://localhost:4008/health                   # 200 (migrations ran)
```

Acceptance criteria:
1. Migration generation script produces `worker/migrations.generated.ts` with 3 files
2. `npx tsc -b` compiles cleanly (Drizzle schema types are valid)
3. Migrations run on first request via `wrangler dev`
4. `_eldrin_migrations` table exists with 3 entries
5. Tables `workflows`, `workflow_runs`, `workflow_run_steps` exist with correct schema

## Files Created

| File | Purpose |
|------|---------|
| `worker/db/schema.ts` | Drizzle schema definition (3 tables) |
| `worker/db/index.ts` | Database factory + re-exports |
| `migrations/20250101000000-create-workflows-table.sql` | workflows table |
| `migrations/20250101000001-create-workflow-runs-table.sql` | workflow_runs table |
| `migrations/20250101000002-create-workflow-run-steps-table.sql` | workflow_run_steps table |
| `drizzle.config.ts` | drizzle-kit configuration |

## Files Modified

| File | Change |
|------|--------|
| `worker/index.ts` | Add migration runner middleware + db context |

## Finalize

- [ ] Manual validation: `wrangler dev`, verify tables exist, verify migration tracking
- [ ] Commit: `feat: add Drizzle ORM schema and database layer`
- [ ] Update `STATUS.md` → complete, create `DONE.md`
