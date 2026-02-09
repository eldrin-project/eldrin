# Phase 4: Cloud Provider Adapters — DONE

## Completed: 2026-02-09

## Summary

Created thin provider adapters for 6 cloud platforms that use the shared `bootstrapApp()` helper and `createApp()` factory, eliminating route duplication between the old `worker/index.ts` (323 lines) and `server/index.ts` (450 lines).

## Architecture

All adapters follow the same 3-step pattern:
1. **Create database** — platform-specific (D1, SQLite, `createDatabaseFromEnv()`)
2. **Bootstrap** — shared `bootstrapApp(db, secrets, mode)` creates all services and returns a configured Hono app
3. **Serve** — platform-specific HTTP serving

## Files Created (13 source + 3 test)

| File | Purpose | Lines |
|------|---------|-------|
| `providers/bootstrap.ts` | Shared service initialization | ~70 |
| `providers/cloudflare/index.ts` | Cloudflare Workers adapter | ~65 |
| `providers/standalone/index.ts` | Bun standalone adapter | ~130 |
| `providers/aws/lambda.ts` | AWS Lambda + API Gateway adapter | ~50 |
| `providers/node/entrypoint.ts` | Node.js container entry (shared) | ~50 |
| `providers/azure/functions.ts` | Azure Functions V4 adapter | ~55 |
| `providers/gcp/cloud-functions.ts` | GCP Cloud Functions adapter | ~85 |
| `providers/aws/ecs/Dockerfile` | AWS ECS container | ~22 |
| `providers/azure/container/Dockerfile` | Azure Container Apps | ~22 |
| `providers/gcp/cloud-run/Dockerfile` | GCP Cloud Run container | ~18 |
| `providers/gcp/cloud-run/app.yaml` | Cloud Run config | ~10 |
| `providers/cloudflare/index.test.ts` | CF adapter tests (6) | ~148 |
| `providers/aws/lambda.test.ts` | Lambda adapter tests (4) | ~153 |
| `providers/standalone/index.test.ts` | Standalone adapter tests (4) | ~66 |

## Files Modified

| File | Change |
|------|--------|
| `wrangler.jsonc` | `main` → `providers/cloudflare/index.ts` |
| `package.json` | New scripts, optional peer deps |
| `vitest.config.ts` | Added `providers/**/*.test.ts` include |

## Test Results

- 14 new provider tests (all passing)
- 282 total tests (all passing)
- Zero TypeScript errors

## Key Decisions

- **File moves deferred to Phase 5**: `server/config.ts`, `server/migrations.ts`, `server/embedded-assets.ts` stay in place; standalone adapter imports via `../../server/`
- **Old entry points kept**: `worker/index.ts` and `server/index.ts` still functional; Phase 5 replaces with shims
- **Cloud SDK deps as optional peerDependencies**: only installed when deploying to specific platform
- **Shared container entrypoint**: AWS ECS, Azure Container Apps, and GCP Cloud Run all use `providers/node/entrypoint.ts`
