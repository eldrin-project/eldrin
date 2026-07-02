# Phase 2: Database Layer (Drizzle ORM) — DONE

Completed: 2026-02-13

## Summary

Added Drizzle ORM as the database access layer — the first Eldrin extension app to use an ORM. Defined schema for 3 tables (workflows, workflow_runs, workflow_run_steps), created database factory, hand-wrote SQL migrations, and wired up the SDK migration runner.

## Verification

- `tsc -b` — clean (0 errors)
- `npm run build` — succeeds (worker 178kb with Drizzle)
- `npm run generate:migrations` — produces 3 migration files
- Migration middleware runs on `/api/*` routes only

## Files Created

| File | Purpose |
|------|---------|
| `worker/db/schema.ts` | Drizzle schema (3 tables, indexes, foreign keys) |
| `worker/db/index.ts` | Database factory + re-exports |
| `migrations/20250101000000-create-workflows-table.sql` | workflows table |
| `migrations/20250101000001-create-workflow-runs-table.sql` | workflow_runs table |
| `migrations/20250101000002-create-workflow-run-steps-table.sql` | workflow_run_steps table |
| `drizzle.config.ts` | drizzle-kit configuration |
