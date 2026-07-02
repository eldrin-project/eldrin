# Phase 1: SDK Fixes (eldrin-app-core)

## Overview

Fix migration runner type signatures from `D1Database` to `DatabaseAdapter`. Add Turso/libSQL HTTP adapter and Node.js SQLite adapter (better-sqlite3). Update database factory with auto-detection.

## Dependencies

- Phase 0 (testing foundation)

## Steps

### 1.1 Fix `eldrin-app-core/src/migrations/runner.ts`

- Change `db: D1Database` → `db: DatabaseAdapter` (lines 41, 210)
- Change `D1PreparedStatement[]` → `PreparedStatement[]` (line 142)
- Add import: `import type { DatabaseAdapter, PreparedStatement } from '../database/interface';`

### 1.2 Fix `eldrin-app-core/src/migrations/rollback.ts`

- Change `db: D1Database` → `db: DatabaseAdapter` (line 30)
- Change `D1PreparedStatement[]` → `PreparedStatement[]` (line 121)
- Add same import

### 1.3 Add Turso/libSQL adapter — `src/database/turso.ts`

- ~280 lines, uses Turso's HTTP pipeline API (`POST /v3/pipeline`)
- Zero native dependencies — works in Workers, Lambda, Azure Functions, Cloud Functions, Node, Bun
- URL normalization: `libsql://` → `https://`, strip trailing slashes
- JS type → Turso arg conversion (text, integer, float, null, blob)
- Batch sends all statements in single HTTP request for atomicity
- Factory function: `createTursoAdapter(url, authToken)`

### 1.4 Update database factory — `src/database/factory.ts`

- Add `'turso'` and `'sqlite'` to `DatabaseType`
- Add `tursoUrl`, `tursoAuthToken` to `DatabaseFactoryConfig`
- Extend `DatabaseEnv` with `DATABASE_PATH`, `TURSO_URL`, `TURSO_AUTH_TOKEN`
- Add `turso` and `sqlite` cases to `createDatabaseAdapter()`
- SQLite auto-detects Bun vs Node.js via `globalThis.Bun`
- Detection priority: D1 > Turso > Hyperdrive > DATABASE_URL > DATABASE_PATH

### 1.5 Add Node.js SQLite adapter — `src/database/sqlite-node.ts`

- ~160 lines, uses `better-sqlite3`
- Same pattern as `bun:sqlite` adapter (sync ops wrapped in async interface)
- Enables WAL mode and foreign keys by default
- Factory: `createNodeSQLiteAdapter(dbPath)`

### 1.6 Update `src/database/index.ts`

- Add type exports for `NodeSQLiteAdapter` and `TursoAdapter`

### 1.7 Tests

| Test file | Cases |
|-----------|-------|
| `src/database/turso.test.ts` | 13 (URL normalization, all/first/run, batch, errors, params) |
| `src/database/sqlite-node.test.ts` | 11 (mock better-sqlite3, all/first/run, batch, exec, close) |
| `src/database/factory.test.ts` | 15 (detectDatabaseType, getDatabaseType, auto-detection) |

## Test Gate

```bash
cd eldrin-app-core && npx vitest run    # 84/84 tests pass (45 existing + 39 new)
cd eldrin-core && npx vitest run        # 16/16 still pass (regression)
```

## Files Created

- `eldrin-app-core/src/database/turso.ts`
- `eldrin-app-core/src/database/sqlite-node.ts`
- `eldrin-app-core/src/database/turso.test.ts`
- `eldrin-app-core/src/database/sqlite-node.test.ts`
- `eldrin-app-core/src/database/factory.test.ts`

## Files Modified

- `eldrin-app-core/src/migrations/runner.ts` — D1 → DatabaseAdapter types
- `eldrin-app-core/src/migrations/rollback.ts` — D1 → DatabaseAdapter types
- `eldrin-app-core/src/database/factory.ts` — Turso + SQLite support
- `eldrin-app-core/src/database/index.ts` — New type exports
