# Phase 5: Build System — DONE

## Completed: 2026-02-09

## What was delivered

### Server-side bundling with tsup
- 4 Node.js adapter entries bundled via tsup (esbuild): AWS Lambda, Node.js (ECS/Cloud Run/Azure Container), Azure Functions, GCP Cloud Functions
- `@eldrin-project/eldrin-app-core` (local `file:` dependency) bundled via `noExternal` — containers get self-contained JS
- Shared code extracted into chunks (~164 KB shared, each adapter entry < 1.5 KB)
- Native modules (`pg`, `bun:sqlite`, `better-sqlite3`) and framework peer deps left external

### Vite config split
- `vite.config.base.ts` — frontend-only (React + Tailwind), no Cloudflare plugin
- `vite.config.ts` — extends base, adds `cloudflare()` plugin for CF deployments

### Backward-compatibility shims
- `worker/index.ts`: 323 → 2 lines (re-export from `providers/cloudflare/`)
- `server/index.ts`: 450 → 2 lines (side-effect import from `providers/standalone/`)

### Build scripts
- `build` — Generic container/Lambda build (tsc -b + frontend + tsup)
- `build:cloudflare` — CF-specific (tsc -b + vite with CF plugin)
- `build:standalone` — Bun binary (frontend + embed-assets + bun compile)
- `build:server` — tsup only (server bundles)
- `build:frontend` — vite only (frontend assets, no CF plugin)

### TypeScript configuration
- `tsconfig.server.json` includes `providers/**/*.ts` for IDE type-checking
- `tsconfig.worker.json` no longer includes `worker/` (shim expands import graph beyond CF types)
- Root `tsc -b` references unchanged (app, node, worker) — server config excluded due to bun-types conflicts

## Files created (3)
- `tsup.config.ts`
- `vite.config.base.ts`
- `build.test.ts`

## Files modified (8)
- `vite.config.ts` — extends base + CF plugin only
- `package.json` — build scripts + tsup devDep
- `tsconfig.server.json` — added providers/ to include
- `tsconfig.worker.json` — removed worker/ from include
- `worker/index.ts` — replaced with 2-line shim
- `server/index.ts` — replaced with 2-line shim
- `scripts/build-binary.ts` — entry → providers/standalone/
- `vitest.config.ts` — added build.test.ts to include

## Phase gate
- [x] 288 tests pass (282 existing + 6 new build structural tests)
- [x] `tsc -b` clean (zero errors)
- [x] `npm run build:server` produces dist/providers/*.js via tsup
- [x] tsup splitting works — shared chunk + 4 small adapter entries
