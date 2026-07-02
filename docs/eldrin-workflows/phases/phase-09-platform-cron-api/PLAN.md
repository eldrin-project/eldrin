# Phase 9: Platform Cron Hook API

## Overview

**Cross-repo phase**: Add a generic cron hook API to **eldrin-core** that any extension app can use to register scheduled callbacks. Then implement cron trigger support in eldrin-workflows. This is a platform capability — not workflows-specific — but the workflows app drives the need.

Detailed plan will be written when implementation begins.

## Dependencies

- Phase 4 + 5 (execution engine + triggers exist in eldrin-workflows)

## Key Deliverables

### eldrin-core additions

**Database migration** — `app_cron_hooks` table:
| Column | Type | Description |
|--------|------|-------------|
| id | TEXT PK | UUID |
| app_id | TEXT | App that registered the hook |
| expression | TEXT | Cron expression (e.g., `0 9 * * MON`) |
| callback_path | TEXT | Path to POST to when due |
| is_active | INTEGER | 0 or 1 |
| last_run_at | INTEGER | Last execution timestamp |
| next_run_at | INTEGER | Next scheduled execution |

**API endpoints**:
- `POST /api/app/:appId/cron` — register a cron hook
- `DELETE /api/app/:appId/cron/:hookId` — remove a cron hook
- `GET /api/app/:appId/cron` — list registered hooks

**Cron processor**:
- Cloudflare: Cron Trigger (scheduled event handler)
- Standalone: `setInterval` or Bun cron
- Every minute: query due hooks, POST to app's callback_path

### eldrin-workflows additions

**Cron trigger handler**:
- `POST /api/_cron/callback` — endpoint called by platform when cron fires
- Match against active workflows with `trigger.type === 'cron'`
- Execute matching workflows

**Workflow lifecycle**:
- On workflow activate with cron trigger: register cron hook with platform
- On workflow deactivate/delete: unregister cron hook

## Scope

~100-150 LOC in eldrin-core (migration + 2 routes + processor)
~50 LOC in eldrin-workflows (callback handler + register/unregister)

## Test Gate

- Register a cron hook via API
- Cron processor fires at scheduled time
- Workflow with cron trigger executes on schedule
- Deactivating workflow unregisters cron hook

## Finalize

- [ ] Commit (eldrin-core): `feat: add generic cron hook API for extension apps`
- [ ] Commit (eldrin-workflows): `feat: add cron trigger support`
- [ ] Update `STATUS.md` → complete, create `DONE.md`
