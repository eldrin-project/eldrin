# Phase 18: Provider Migration Tooling

## Status: done
## Started: 2026-02-09
## Completed: 2026-02-09

## Progress:
- [x] Step 18.1: Create data export function (core/migration/export.ts)
- [x] Step 18.2: Create data import function (core/migration/import.ts)
- [x] Step 18.3: Create database migration utility (core/migration/db-migrate.ts)
- [x] Step 18.4: Add CLI commands to standalone server
- [x] Step 18.5: Write tests (18 cases across 3 files)

## Notes:
- Export supports 4 flags: includeUsers, includeApps, includePermissions, includeAuditLog
- Always exports structural tables (auth_providers, events, event_subscriptions)
- Never exports runtime state (_revoked_tokens, _task_queue, etc.)
- Import uses FK-safe ordering: platform_roles → permissions → users → apps → join tables → audit
- Import uses INSERT OR IGNORE to handle duplicates gracefully
- DB migration converts boolean columns between SQLite (0/1) and PostgreSQL (true/false)
- CLI commands: export, import (with --dry-run/--confirm safety gate), migrate-db
- 318 tests pass (300 existing + 18 new migration tests)
