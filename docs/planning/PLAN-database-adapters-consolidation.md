# Plan: Move Database Adapters from eldrin-core to eldrin-app-core SDK

## Goal
Have angular-todo use database adapters from `@eldrin-project/eldrin-app-core` SDK instead of its own `worker/db.ts`.

## Current State

### eldrin-core/adapters/database/
- `interface.ts` - `DatabaseAdapter`, `PreparedStatement`, `DatabaseResults` interfaces
- `d1.ts` - D1Adapter for Cloudflare Workers
- `postgres.ts` - PostgresAdapter for PostgreSQL/Hyperdrive
- `sqlite.ts` - SQLiteAdapter for Bun standalone
- `factory.ts` - `createDatabaseAdapter()` and `detectDatabaseType()` functions

### angular-todo/worker/db.ts
- Same interfaces (slightly different)
- D1Adapter and PostgresAdapter implementations
- **Extra features not in eldrin-core:**
  - Schema support (`DATABASE_SCHEMA` env var, `SET search_path TO`)
  - Fresh connection per query pattern (avoids stale connections in local dev)
  - `createDatabaseFromEnv(env)` - simplified env-based factory
  - `getDatabaseType(env)` - returns `'d1' | 'postgres'`

## Changes Required

### 1. eldrin-app-core (SDK)

**Add new directory:** `src/database/`

| File | Content |
|------|---------|
| `src/database/interface.ts` | Copy from eldrin-core, keep `batch()` method |
| `src/database/d1.ts` | Copy from eldrin-core |
| `src/database/postgres.ts` | Merge: eldrin-core's structure + angular-todo's schema support & fresh connections |
| `src/database/factory.ts` | Copy from eldrin-core, add schema support to config |
| `src/database/index.ts` | Export all types and factories |

**Update:** `src/index.ts`
- Add exports for database module

### 2. angular-todo

**Update:** `worker/index.ts`
- Change import from `'./db'` to `'@eldrin-project/eldrin-app-core'`
- Update function calls to use new API (if needed)

**Delete:** `worker/db.ts`

### 3. eldrin-core (cleanup)

**Add dependency:** `@eldrin-project/eldrin-app-core` (file:../eldrin-app-core) in package.json

**Update imports in these files:**

| File | Current Import | New Import |
|------|----------------|------------|
| `worker/index.ts:8` | `from '../adapters/database'` | `from '@eldrin-project/eldrin-app-core'` |
| `server/index.ts:11-12` | `from '../adapters/database'` + `from '../adapters/database/sqlite'` | `from '@eldrin-project/eldrin-app-core'` |
| `server/migrations.ts:7` | `from '../adapters/database'` | `from '@eldrin-project/eldrin-app-core'` |
| `core/types.ts:7` | `from '../adapters/database'` | `from '@eldrin-project/eldrin-app-core'` |
| `core/utils.ts:7` | `from '../adapters/database'` | `from '@eldrin-project/eldrin-app-core'` |

**Delete directory:** `adapters/database/` (all files: interface.ts, d1.ts, postgres.ts, sqlite.ts, factory.ts, index.ts)

## Critical Files

| File | Action |
|------|--------|
| `/eldrin-app-core/src/database/interface.ts` | Create |
| `/eldrin-app-core/src/database/d1.ts` | Create |
| `/eldrin-app-core/src/database/postgres.ts` | Create (with schema + fresh connections) |
| `/eldrin-app-core/src/database/sqlite.ts` | Create |
| `/eldrin-app-core/src/database/factory.ts` | Create |
| `/eldrin-app-core/src/database/index.ts` | Create |
| `/eldrin-app-core/src/index.ts` | Update exports |
| `/eldrin-app-core/package.json` | No change needed (no new deps) |
| `/angular-todo/worker/index.ts` | Update imports |
| `/angular-todo/worker/db.ts` | Delete |
| `/eldrin-core/package.json` | Add `@eldrin-project/eldrin-app-core` dependency |
| `/eldrin-core/worker/index.ts` | Update imports |
| `/eldrin-core/server/index.ts` | Update imports |
| `/eldrin-core/server/migrations.ts` | Update imports |
| `/eldrin-core/core/types.ts` | Update imports |
| `/eldrin-core/core/utils.ts` | Update imports |
| `/eldrin-core/adapters/database/*` | Delete entire directory |

## API Changes

### Before (angular-todo)
```typescript
import { createDatabaseFromEnv, getDatabaseType, type DatabaseAdapter } from './db';

const dbType = getDatabaseType(env);
const db = await createDatabaseFromEnv(env);
```

### After (from SDK)
```typescript
import {
  createDatabaseFromEnv,
  getDatabaseType,
  type DatabaseAdapter
} from '@eldrin-project/eldrin-app-core';

const dbType = getDatabaseType(env);
const db = await createDatabaseFromEnv(env);
```

The API remains the same - only the import path changes.

## Execution Order
1. Create database module in eldrin-app-core (copy from eldrin-core + angular-todo enhancements)
2. Update eldrin-app-core exports
3. Build eldrin-app-core (`npm run build`)
4. Update eldrin-core:
   - Add dependency to package.json
   - Update all imports
   - Run `npm install`
   - Delete `adapters/database/` directory
5. Test eldrin-core (`npm run build`)
6. Update angular-todo:
   - Update imports in worker/index.ts
   - Delete worker/db.ts
7. Test angular-todo (`npm run build`)
