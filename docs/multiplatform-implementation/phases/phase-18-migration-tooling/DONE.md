# Phase 18: Provider Migration Tooling — DONE

## Completed: 2026-02-09

## What was delivered

### Data export (`core/migration/export.ts`)
- `exportData(db, options)` — exports selected tables as structured JSON
- Options: `includeUsers`, `includeApps`, `includePermissions`, `includeAuditLog`
- Always includes structural tables: `auth_providers`, `events`, `event_subscriptions`
- Never exports runtime state: `_revoked_tokens`, `_user_revocations`, `_task_queue`
- Returns `ExportData` with version, timestamp, and table-to-rows map

### Data import (`core/migration/import.ts`)
- `importData(db, data, options)` — imports ExportData into a database
- FK-safe import order: permissions → users → auth → apps → join tables → audit
- Uses `INSERT OR IGNORE` to gracefully skip duplicates
- Dry-run mode: reports row counts without writing
- Returns per-table insert/skip counts

### Database migration (`core/migration/db-migrate.ts`)
- `migrateDatabase(source, target, options)` — transfers data between databases
- Boolean conversion: SQLite `INTEGER` (0/1) ↔ PostgreSQL `BOOLEAN` (true/false)
- Affected columns: `is_active`, `email_verified`, `enabled`, `auto_link_by_email`, `auto_create_users`
- Clears target tables in reverse FK order before importing
- No conversion for same-type migrations

### CLI commands (integrated into `providers/standalone/index.ts`)
- `eldrin-core export --output backup.json [--include users,apps,permissions,audit]`
- `eldrin-core import --input backup.json --dry-run` (preview)
- `eldrin-core import --input backup.json --confirm` (apply)
- `eldrin-core migrate-db --from sqlite --to postgresql --source ./data/eldrin.db --target postgres://...`

## Files created (6)
- `core/migration/export.ts` — Export function and types
- `core/migration/import.ts` — Import function with FK-safe ordering
- `core/migration/db-migrate.ts` — Cross-database migration with boolean conversion
- `core/migration/export.test.ts` — 7 export tests
- `core/migration/import.test.ts` — 6 import tests
- `core/migration/db-migrate.test.ts` — 5 migration tests

## Files modified (1)
- `providers/standalone/index.ts` — Added CLI subcommand handling

## Phase gate
- [x] 318 tests pass (300 existing + 18 new migration tests)
- [x] `tsc -b` clean (zero errors)
- [x] Export/import handles all 16 exportable tables
- [x] Boolean conversion works bidirectionally (SQLite ↔ PostgreSQL)
- [x] Import respects FK constraints via ordered insertion
- [x] CLI commands integrated with safety gates (--dry-run/--confirm)
