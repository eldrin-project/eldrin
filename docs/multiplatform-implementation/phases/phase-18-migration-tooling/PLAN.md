# Phase 18: Provider Migration Tooling

## Overview

Data export/import tools and database migration utility (SQLite ↔ PostgreSQL). CLI commands integrated into standalone server.

## Dependencies

- Phase 2 (unified Hono app — database adapter available)

## Steps

### 18.1 Data export/import — `core/migration/`

`exportData(db, options)` → `ReadableStream`. `importData(db, data, options)` → `ImportResult`.

Options: `includeUsers`, `includeApps`, `includePermissions`, `includeAuditLog`, `format: 'json' | 'sql'`.

### 18.2 CLI commands

```
eldrin export --output backup.json --include users,apps,permissions
eldrin import --input backup.json --dry-run
eldrin import --input backup.json --confirm
eldrin migrate-db --from sqlite --to postgresql --source ./data/eldrin.db --target postgres://...
```

### 18.3 Database migration utility — `core/migration/db-migrate.ts`

Transfers data between SQLite and PostgreSQL. Handles schema differences (`INTEGER` booleans → `BOOLEAN`). Validates row counts post-migration.

### 18.4 Tests

| Test file | Cases |
|-----------|-------|
| `core/migration/export.test.ts` | ~6 |
| `core/migration/import.test.ts` | ~6 |
| `core/migration/db-migrate.test.ts` | ~5 |

## Test Gate

```bash
cd eldrin-core && npx vitest run -- core/migration/   # ~17 tests
```


## Commit

After all tests pass, commit the changes to the relevant submodule(s) using conventional commits format, then update the parent repo submodule reference.
