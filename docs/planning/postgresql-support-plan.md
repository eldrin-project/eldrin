# Plan: Add PostgreSQL Support Alongside D1 (SQLite)

## Overview
Add PostgreSQL support to the angular-todo app, allowing configuration-based switching between D1 (SQLite) and PostgreSQL via Cloudflare Hyperdrive.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     worker/index.ts                         │
│          (uses DatabaseAdapter abstraction)                 │
└─────────────────────────────────────────────────────────────┘
                            │
                ┌───────────┴───────────┐
                ▼                       ▼
    ┌─────────────────┐       ┌─────────────────┐
    │   D1Adapter     │       │ PostgresAdapter │
    │   (SQLite)      │       │  (Hyperdrive)   │
    └─────────────────┘       └─────────────────┘
```

Configuration: `DATABASE_TYPE` environment variable (`d1` | `postgres`)

---

## Implementation Steps

### Step 1: Create PostgreSQL Adapter in eldrin-core

**File:** `/Users/tibor/projects/eldrin/eldrin-core/adapters/database/postgres.ts`

- Implement `DatabaseAdapter` interface (same pattern as D1Adapter)
- Convert `?` placeholders to `$1, $2, ...` in prepared statements
- Use `pg` client (node-postgres) compatible with Cloudflare Hyperdrive
- Export `createPostgresAdapter(connectionString)` factory function

**File:** `/Users/tibor/projects/eldrin/eldrin-core/adapters/database/index.ts`
- Export the new PostgreSQL adapter

### Step 2: Create Database Factory in angular-todo

**File:** `/Users/tibor/projects/eldrin/angular-todo/worker/db/index.ts`

```typescript
export function createDatabaseAdapter(env: Env): DatabaseAdapter {
  if (env.DATABASE_TYPE === 'postgres' && env.HYPERDRIVE) {
    return createPostgresAdapter(env.HYPERDRIVE.connectionString);
  }
  return createD1Adapter(env.DB);
}
```

### Step 3: Update Environment Types

**File:** `/Users/tibor/projects/eldrin/angular-todo/worker/env.d.ts`

Add:
```typescript
HYPERDRIVE?: Hyperdrive;
DATABASE_TYPE?: 'd1' | 'postgres';
```

### Step 4: Refactor Worker to Use Abstraction

**File:** `/Users/tibor/projects/eldrin/angular-todo/worker/index.ts`

Replace all `env.DB.prepare()` calls with adapter:
```typescript
// Before
const { results } = await env.DB.prepare('SELECT * FROM todos').all();

// After
const db = createDatabaseAdapter(env);
const { results } = await db.prepare('SELECT * FROM todos').all();
```

Key changes:
- Create adapter once per request
- Replace ~15 direct `env.DB` calls with `db` adapter calls
- Update migration runner to accept `DatabaseAdapter`

### Step 5: Create PostgreSQL Migrations

**File:** `/Users/tibor/projects/eldrin/angular-todo/worker/migrations/postgres/`

Create PostgreSQL-specific migrations (same schema, different SQL):
- Timestamps use `BIGINT` (same as SQLite INTEGER)
- `NULLS LAST` works in both
- Boolean stored as `INTEGER` (0/1) for compatibility

### Step 6: Update Wrangler Configuration

**File:** `/Users/tibor/projects/eldrin/angular-todo/wrangler.jsonc`

Add Hyperdrive configuration (commented out by default):
```jsonc
// "hyperdrive": [
//   {
//     "binding": "HYPERDRIVE",
//     "id": "<your-hyperdrive-id>"
//   }
// ]
```

### Step 7: Add Dependencies

**File:** `/Users/tibor/projects/eldrin/eldrin-core/package.json`

Add `pg` as optional peer dependency for PostgreSQL support.

---

## SQL Dialect Handling

| Feature | SQLite | PostgreSQL | Solution |
|---------|--------|------------|----------|
| Placeholders | `?` | `$1, $2...` | Convert in PostgresAdapter |
| Boolean | `INTEGER` | Works with `0/1` | No change needed |
| `NOT completed` | Works | Works | No change needed |
| `NULLS LAST` | Works | Works | No change needed |
| Timestamps | `INTEGER` (ms) | `BIGINT` (ms) | Compatible |

The SQL in this app is simple CRUD and works in both dialects with only placeholder conversion.

---

## Files to Modify

1. **`/Users/tibor/projects/eldrin/eldrin-core/adapters/database/postgres.ts`** - NEW: PostgreSQL adapter
2. **`/Users/tibor/projects/eldrin/eldrin-core/adapters/database/index.ts`** - Export new adapter
3. **`/Users/tibor/projects/eldrin/angular-todo/worker/db/index.ts`** - NEW: Database factory
4. **`/Users/tibor/projects/eldrin/angular-todo/worker/env.d.ts`** - Add Hyperdrive types
5. **`/Users/tibor/projects/eldrin/angular-todo/worker/index.ts`** - Use abstraction layer
6. **`/Users/tibor/projects/eldrin/angular-todo/wrangler.jsonc`** - Hyperdrive config
7. **`/Users/tibor/projects/eldrin/eldrin-core/package.json`** - pg dependency

---

## Usage After Implementation

**For D1 (default):**
```bash
# No changes needed - works as before
wrangler dev
```

**For PostgreSQL:**
```bash
# 1. Create Hyperdrive configuration
wrangler hyperdrive create my-hyperdrive --connection-string="postgres://..."

# 2. Update wrangler.jsonc with hyperdrive binding

# 3. Set environment variable
# In wrangler.jsonc or Cloudflare dashboard:
# DATABASE_TYPE=postgres
```

---

## Rollback

If PostgreSQL causes issues:
1. Set `DATABASE_TYPE=d1` or remove the variable
2. All existing D1 functionality continues working unchanged
