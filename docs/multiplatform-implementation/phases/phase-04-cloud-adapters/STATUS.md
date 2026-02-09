# Phase 4: Cloud Provider Adapters

## Status: done
## Started: 2026-02-09
## Completed: 2026-02-09

## Progress:
- [x] Step 4.0: Create shared bootstrap helper (`providers/bootstrap.ts`)
- [x] Step 4.1: Create Cloudflare adapter (`providers/cloudflare/index.ts`)
- [x] Step 4.2: Update `wrangler.jsonc` main entry to point to new adapter
- [x] Step 4.3: Create AWS Lambda adapter (`providers/aws/lambda.ts`)
- [x] Step 4.4: Create AWS ECS Dockerfile (`providers/aws/ecs/Dockerfile`)
- [x] Step 4.5: Create Azure Functions adapter (`providers/azure/functions.ts`)
- [x] Step 4.6: Create Azure Container Dockerfile (`providers/azure/container/Dockerfile`)
- [x] Step 4.7: Create GCP Cloud Functions adapter (`providers/gcp/cloud-functions.ts`)
- [x] Step 4.8: Create GCP Cloud Run Dockerfile + app.yaml
- [x] Step 4.9: Create standalone adapter (`providers/standalone/index.ts`)
- [x] Step 4.10: Create Node.js container entrypoint (`providers/node/entrypoint.ts`)
- [x] Step 4.11: Update package.json (scripts, peer deps) and vitest.config.ts
- [x] Step 4.12: Write tests (14 provider tests across 3 files)
- [x] Step 4.13: Full test suite passes (282 tests), zero TS errors

## Notes:
- Shared `bootstrapApp()` in `providers/bootstrap.ts` wires all services (cache, email, storage, jobs, audit, token revocation) and calls `createApp()` — all adapters use this
- server/config.ts, server/migrations.ts, server/embedded-assets.ts NOT moved (deferred to Phase 5) — standalone adapter imports from `../../server/`
- worker/index.ts and server/index.ts kept in place (Phase 5 replaces with shims)
- Cloud SDK dependencies (@hono/node-server, @azure/functions, @google-cloud/functions-framework) added as optional peerDependencies
- Container adapters (ECS, Azure Container, Cloud Run) all share `providers/node/entrypoint.ts`
