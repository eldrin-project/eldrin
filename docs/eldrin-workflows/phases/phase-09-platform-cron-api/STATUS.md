# Phase 9: Platform Cron Hook API

## Status: complete
## Started: 2026-02-13
## Completed: 2026-02-13

## Progress:
- [x] Add `app_cron_hooks` migration to eldrin-core
- [x] Implement register/unregister/list endpoints in eldrin-core
- [x] Implement cron processor (CF Cron Trigger + standalone)
- [x] Add cron callback handler to eldrin-workflows
- [x] Wire up workflow activate/deactivate to register/unregister hooks
- [x] Enable cron trigger UI with expression presets and validation
- [x] Type-check and build both repos

## Notes:
Cross-repo phase: modifies both eldrin-core and eldrin-workflows.

### Architecture: Platform-managed cron hooks
- eldrin-core owns `app_cron_hooks` table and evaluates cron expressions via `croner`
- Single `* * * * *` Cloudflare Cron Trigger powers the tick; standalone/containers use `setInterval`
- Serverless providers (Lambda/Azure/GCP) use `POST /api/_internal/tick` via external scheduler
- Apps register/unregister hooks via REST API (`POST/DELETE /api/cron-hooks`)
- hookId = workflowId convention for 1:1 mapping

### Verification
- eldrin-core: `tsc -b` clean, 368 tests pass (48 files), build succeeds
- eldrin-workflows: `npm run build` clean (worker + client bundles)
