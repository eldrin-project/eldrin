# Phase 9: Platform Cron Hook API — DONE

## Summary
Platform-managed cron hook API added to eldrin-core, enabling any extension app (starting with eldrin-workflows) to register scheduled callbacks. The platform evaluates cron expressions and calls app endpoints when hooks are due.

## Files Created

### eldrin-core
| File | Purpose |
|------|---------|
| `migrations/20260213000001-app-cron-hooks.sql` | Migration: `app_cron_hooks` table with partial index on `(next_run_at) WHERE is_active = 1` |
| `core/cron/processor.ts` | `processCronHooks(db)`, `getNextCronRun()`, `validateCronExpression()` |
| `core/routes/cron-hooks.ts` | CRUD handlers: register (upsert), unregister, list, tick |

### eldrin-workflows
| File | Purpose |
|------|---------|
| `worker/routes/cron.ts` | `POST /api/_cron/callback` — receives platform cron callbacks, executes workflow |

## Files Modified

### eldrin-core
| File | Change |
|------|--------|
| `core/routes/index.ts` | Export 4 cron-hooks handlers |
| `core/app.ts` | Register 4 routes: POST/DELETE/GET `/api/cron-hooks`, POST `/api/_internal/tick` |
| `core/auth/middleware.ts` | Add `/api/_internal/tick` to PUBLIC_ROUTES |
| `providers/cloudflare/index.ts` | Add `scheduled` handler with `ctx.waitUntil(processCronHooks(db))` |
| `providers/standalone/index.ts` | Add `setInterval(() => processCronHooks(db), 60_000)` |
| `providers/node/entrypoint.ts` | Add `setInterval(() => processCronHooks(db), 60_000)` |
| `wrangler.jsonc` | Add `"triggers": { "crons": ["* * * * *"] }` |

### eldrin-workflows
| File | Change |
|------|--------|
| `worker/routes/workflows.ts` | Add `registerCronHook()`, `unregisterCronHook()`, wire to activate/deactivate/delete |
| `worker/index.ts` | Mount `cronRoutes` |
| `src/components/editor/TriggerConfig.tsx` | Enable cron trigger with presets, croner validation, next-run preview |

## Dependencies Added
- `croner` — eldrin-core and eldrin-workflows (lightweight isomorphic cron expression parser)

## Architecture

```
Cloudflare Cron Trigger ("* * * * *")
    │
    ▼
scheduled() handler
    │
    ▼
processCronHooks(db)
    ├── Query: SELECT ... FROM app_cron_hooks WHERE is_active = 1 AND next_run_at <= now
    ├── Lookup: app_url FROM platform_apps WHERE id = hook.app_id
    ├── Fetch: POST ${app_url}${callback_path} with { hookId, timestamp }
    └── Update: next_run_at = getNextCronRun(expression)

For standalone/containers: setInterval(..., 60_000)
For serverless (Lambda/Azure/GCP): external scheduler → POST /api/_internal/tick (CRON_SECRET auth)
```

## API Surface

### Platform API (eldrin-core)
- `POST /api/cron-hooks` — Register/update a cron hook (auth-gated)
- `DELETE /api/cron-hooks/:hookId` — Unregister a cron hook (auth-gated)
- `GET /api/cron-hooks?appId=...` — List hooks (auth-gated)
- `POST /api/_internal/tick` — Trigger cron processing (CRON_SECRET auth)

### App Callback (eldrin-workflows)
- `POST /api/_cron/callback` — Receive cron callback from platform

## Verification
- `tsc -b`: clean
- `vitest run`: 368 tests pass (48 files)
- `npm run build` (eldrin-workflows): clean
