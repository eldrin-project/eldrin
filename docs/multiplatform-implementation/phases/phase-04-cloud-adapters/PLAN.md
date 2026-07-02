# Phase 4: Cloud Provider Adapters

## Overview

Create thin adapter wrappers for each cloud provider that initialize the correct services and mount the unified `createApp()` Hono app. Move standalone server to `providers/standalone/`.

## Dependencies

- Phase 2 (unified Hono app)
- Phase 8 (secrets)
- Phase 9 (observability)

## Steps

### 4.1 Cloudflare adapter — `providers/cloudflare/index.ts` (~30 lines)

Wrapper Hono app with `{ Bindings: CloudflareBindings }`, creates D1Adapter, mounts core app, asset fallback.

### 4.2 Move `wrangler.jsonc` to `providers/cloudflare/wrangler.jsonc`

### 4.3 AWS Lambda adapter — `providers/aws/lambda.ts` (~25 lines)

`hono/aws-lambda` adapter, DB from env vars, `export const handler = handle(app)`.

### 4.4 AWS ECS adapter — `providers/aws/ecs/entrypoint.ts` + `Dockerfile`

`@hono/node-server` + `serveStatic`, PostgreSQL or SQLite from env.

### 4.5 Azure Functions adapter — `providers/azure/functions.ts` + `host.json`

### 4.6 Azure Container adapter — `providers/azure/container/entrypoint.ts` + `Dockerfile`

### 4.7 GCP Cloud Functions adapter — `providers/gcp/cloud-functions.ts`

### 4.8 GCP Cloud Run adapter — `providers/gcp/cloud-run/entrypoint.ts` + `Dockerfile` + `app.yaml`

### 4.9 Move standalone server to `providers/standalone/`

Files: `index.ts`, `config.ts`, `migrations.ts`, `embedded-assets.ts`

### 4.10 Tests

| Test file | Cases |
|-----------|-------|
| `providers/cloudflare/index.test.ts` | ~6 |
| `providers/aws/lambda.test.ts` | ~4 |
| `providers/standalone/index.test.ts` | ~4 |

## Test Gate

```bash
cd eldrin-core && npx vitest run -- providers/   # ~14 tests
```

## Files Created

~10 adapter files + 3 Dockerfiles + test files

## Files Modified/Moved

- `server/index.ts` → `providers/standalone/index.ts`
- `server/config.ts` → `providers/standalone/config.ts`
- `server/migrations.ts` → `providers/standalone/migrations.ts`
- `server/embedded-assets.ts` → `providers/standalone/embedded-assets.ts`


## Commit

After all tests pass, commit the changes to the relevant submodule(s) using conventional commits format, then update the parent repo submodule reference.
