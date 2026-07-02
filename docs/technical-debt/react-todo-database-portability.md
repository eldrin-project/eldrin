# Tech Debt: react-todo Database Portability

## Problem

The react-todo app uses Cloudflare D1's raw API (`env.DB.prepare(...)`) directly in the worker code. This was fine when the platform was Cloudflare-only, but now that eldrin-core supports multiple database backends (D1, PostgreSQL via Hyperdrive, Turso, standalone SQLite), the todo app cannot run on any backend other than D1.

This is the same gap that the eldrin-workflows requirements now explicitly avoid by mandating Drizzle ORM from day one.

## Current State

### Direct D1 API usage in `worker/index.ts`

Every query in the worker uses `env.DB.prepare()` — the raw D1 client:

```typescript
// Example: listing todos
const stmt = env.DB.prepare('SELECT * FROM todos WHERE 1=1');
const { results } = await stmt.bind(...queryParams).all();

// Example: creating a todo
await env.DB.prepare(
  'INSERT INTO todos (...) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)'
).bind(...).run();
```

### Non-portable SQL patterns

| Pattern | Location | Issue |
|---------|----------|-------|
| `NOT completed` | toggle endpoint | SQLite boolean toggle; PostgreSQL needs `completed = NOT completed` or `CASE` |
| `NULLS LAST` | todo list query | Works on both, but worth noting |
| `strftime('%s', 'now')` | migration seed data | SQLite-only function; PostgreSQL uses `EXTRACT(EPOCH FROM NOW())` |
| `CHECK(priority IN (...))` | todos table | Works on both, but Drizzle would enforce at type level |
| `INTEGER ... DEFAULT 0` | completed column | Portable, but semantically a boolean |

### What works today

- The SDK's `runMigrations()` is used correctly for migration execution
- Event emission via `createEventClient()` is backend-agnostic
- Permission middleware via `createPermissionMiddleware()` is backend-agnostic
- Frontend is pure REST — no database coupling

## Target State

Replace direct D1 API calls with **Drizzle ORM**, matching the approach mandated for eldrin-workflows. This makes react-todo the reference implementation for multi-database Eldrin apps.

### Architecture after migration

```
worker/index.ts (Hono route handlers)
  ↓ uses type-safe Drizzle queries
worker/db/schema.ts (Drizzle schema definition)
worker/db/index.ts (database factory — creates Drizzle instance per env)
  ↓ wraps raw driver
D1 | PostgreSQL (Hyperdrive) | Turso | bun:sqlite
```

## Migration Plan

### Step 1: Add Drizzle ORM dependency

```bash
cd react-todo
npm install drizzle-orm
npm install -D drizzle-kit
```

Drizzle has zero runtime dependencies and adds ~7.4kb gzipped to the bundle.

### Step 2: Define Drizzle schema

Create `worker/db/schema.ts` with the existing table structure expressed as Drizzle schema:

```typescript
import { sqliteTable, text, integer, index } from 'drizzle-orm/sqlite-core';

export const categories = sqliteTable('categories', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  color: text('color').default('#3B82F6'),
  createdAt: integer('created_at', { mode: 'number' }).notNull(),
  updatedAt: integer('updated_at', { mode: 'number' }).notNull(),
}, (table) => [
  index('idx_categories_name').on(table.name),
]);

export const todos = sqliteTable('todos', {
  id: text('id').primaryKey(),
  title: text('title').notNull(),
  description: text('description'),
  dueDate: integer('due_date', { mode: 'number' }),
  priority: text('priority', { enum: ['low', 'medium', 'high'] }).notNull().default('medium'),
  completed: integer('completed', { mode: 'boolean' }).notNull().default(false),
  categoryId: text('category_id').references(() => categories.id, { onDelete: 'set null' }),
  createdAt: integer('created_at', { mode: 'number' }).notNull(),
  updatedAt: integer('updated_at', { mode: 'number' }).notNull(),
}, (table) => [
  index('idx_todos_completed').on(table.completed),
  index('idx_todos_priority').on(table.priority),
  index('idx_todos_due_date').on(table.dueDate),
  index('idx_todos_category_id').on(table.categoryId),
  index('idx_todos_created_at').on(table.createdAt),
]);
```

> Note: Drizzle's SQLite schema works for D1 and bun:sqlite. For PostgreSQL, Drizzle's query builder generates the appropriate SQL dialect automatically — the schema definition is shared.

### Step 3: Create database factory

Create `worker/db/index.ts`:

```typescript
import { drizzle as drizzleD1 } from 'drizzle-orm/d1';
import * as schema from './schema';

// Phase 1: D1 only (current behavior, but through Drizzle)
export function createDb(env: Record<string, unknown>) {
  const d1 = env.DB as D1Database;
  return drizzleD1(d1, { schema });
}

// Phase 2: Multi-database (add when needed)
// if (env.HYPERDRIVE) return drizzlePg(...)
// if (env.DATABASE_URL) return drizzlePg(...)
```

### Step 4: Migrate route handlers

Replace raw SQL with Drizzle queries. Example transformations:

**Before (raw D1):**
```typescript
const { results } = await env.DB.prepare(
  'SELECT * FROM todos WHERE completed = 0 ORDER BY created_at DESC'
).all();
```

**After (Drizzle):**
```typescript
const results = await db
  .select()
  .from(todos)
  .where(eq(todos.completed, false))
  .orderBy(desc(todos.createdAt));
```

**Before (insert):**
```typescript
await env.DB.prepare(
  'INSERT INTO todos (id, title, ...) VALUES (?, ?, ...)'
).bind(id, title, ...).run();
```

**After (Drizzle):**
```typescript
await db.insert(todos).values({
  id, title, description, dueDate, priority,
  completed: false, categoryId, createdAt: now, updatedAt: now,
});
```

### Step 5: Update migration strategy

**Option A** (minimal change): Keep existing `.sql` migration files + SDK runner. Drizzle is used only for queries.

**Option B** (full Drizzle): Use `drizzle-kit generate` for future migrations. Keep existing `.sql` files for the initial schema (already applied in production).

Recommendation: **Option A for now** — it's lower risk and the existing migrations already work. Switch to drizzle-kit when adding new tables.

### Step 6: Fix non-portable SQL in seeds

Update `strftime('%s', 'now') * 1000` in migration seed data. Since seeds run once, this is low priority — but for new migrations, use integer literals or app-generated values instead of SQL functions.

### Step 7: Test on multiple backends

1. **D1** (existing): `wrangler dev` — should work as-is
2. **PostgreSQL**: Use `docker-compose` from eldrin-core (PostgreSQL on port 5432), configure `DATABASE_URL`
3. **SQLite (Bun)**: Run standalone server with `DATABASE_PATH`

### Step 8: Update wrangler.jsonc for Hyperdrive (optional)

Add Hyperdrive binding alongside D1 for deployments that prefer PostgreSQL:

```jsonc
{
  "hyperdrive": [
    {
      "binding": "HYPERDRIVE",
      "id": "<hyperdrive-config-id>"
    }
  ]
}
```

## Effort Estimate

| Step | Scope | Complexity |
|------|-------|------------|
| 1. Add Drizzle dependency | 1 file | Trivial |
| 2. Define schema | 1 new file (~50 LOC) | Low |
| 3. Database factory | 1 new file (~20 LOC) | Low |
| 4. Migrate route handlers | 1 file (~200 LOC changed) | Medium — 13 query sites to convert |
| 5. Migration strategy | Decision + config | Low |
| 6. Fix seed SQL | 2 migration files | Trivial |
| 7. Multi-backend testing | Test matrix | Medium |
| 8. Hyperdrive config | 1 file | Trivial |

**Total**: ~1-2 sessions of focused work. The react-todo app is small enough to be a clean reference migration.

## Success Criteria

- [ ] All 13 database query sites use Drizzle instead of raw `env.DB.prepare()`
- [ ] App runs on D1 (Wrangler dev) with no behavior changes
- [ ] App runs on PostgreSQL (docker-compose) with the same test scenarios
- [ ] App runs on standalone SQLite (Bun) with the same test scenarios
- [ ] Existing migration files still work (no breaking changes to deployed databases)
- [ ] No regressions in frontend behavior (REST API contract unchanged)

## Priority

**Medium** — not blocking any current work, but should be completed before eldrin-workflows Phase 1 starts. The workflows app should be able to point to react-todo as the reference implementation for "how to use Drizzle in an Eldrin app".

## Related

- [eldrin-workflows requirements](../requirements/eldrin-workflows.md) — Database Strategy section mandates Drizzle ORM
- [eldrin-app-core DatabaseAdapter](../../eldrin-app-core/src/database/interface.ts) — SDK adapter layer (Drizzle bypasses this for queries, SDK still used for migration tracking)
