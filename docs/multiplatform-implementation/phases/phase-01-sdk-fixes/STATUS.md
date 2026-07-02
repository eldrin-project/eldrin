# Phase 1: SDK Fixes (eldrin-app-core)

## Status: done
## Started: 2025-01-01
## Completed: 2025-01-01

## Progress:
- [x] Step 1.1: Fix runner.ts types (D1Database → DatabaseAdapter)
- [x] Step 1.2: Fix rollback.ts types (D1Database → DatabaseAdapter)
- [x] Step 1.3: Add Turso/libSQL adapter (turso.ts)
- [x] Step 1.4: Update database factory (factory.ts)
- [x] Step 1.5: Add Node.js SQLite adapter (sqlite-node.ts)
- [x] Step 1.6: Update database index exports
- [x] Step 1.7: Write tests (turso, sqlite-node, factory)

## Notes:
- 84/84 tests passing in eldrin-app-core (45 existing + 39 new)
- 16/16 tests passing in eldrin-core (regression OK)
- Turso adapter uses HTTP pipeline API (`POST /v3/pipeline`), zero native deps
- Node.js SQLite adapter uses better-sqlite3 for Lambda/EFS, Azure Functions/Azure Files, GCP/Filestore
- Runtime auto-detection: `globalThis.Bun` selects bun:sqlite vs better-sqlite3
- Database detection priority: D1 > Turso > Hyperdrive > DATABASE_URL > DATABASE_PATH
