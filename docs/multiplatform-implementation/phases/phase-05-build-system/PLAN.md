# Phase 5: Build System

## Overview

Set up per-target build scripts. Extract base Vite config, add `tsup` for server bundles, create build scripts for all cloud targets.

## Dependencies

- Phase 4 (cloud provider adapters exist to build)

## Steps

### 5.1 Create `vite.config.base.ts`

Frontend-only: React + Tailwind, resolve aliases. No Cloudflare plugin.

### 5.2 Update `vite.config.ts`

Extends base, adds `cloudflare()` plugin. Backward compatible.

### 5.3 Update `package.json`

Add per-target build scripts:
```
build:frontend, build:cloudflare, build:aws-lambda, build:aws-ecs,
build:azure-func, build:gcp-cf, build:gcp-run, build:standalone
```

Add dev dependencies: `@hono/node-server`, `tsup`

### 5.4 Backward-compatibility shims

- `worker/index.ts` → re-export from `providers/cloudflare/`
- `server/index.ts` → re-export from `providers/standalone/`

### 5.5 Tests — `build.test.ts` (~8 cases)

- Each build script produces expected output
- Backward-compat shims resolve correctly
- TypeScript compilation succeeds
- No Cloudflare-specific imports in `core/` directory

## Test Gate

```bash
cd eldrin-core && npx vitest run -- build.test.ts   # ~8 tests
# All target builds succeed
```

## Files Created

- `eldrin-core/vite.config.base.ts`
- `eldrin-core/build.test.ts`

## Files Modified

- `eldrin-core/vite.config.ts`
- `eldrin-core/package.json`
- `eldrin-core/worker/index.ts` (re-export shim)
- `eldrin-core/server/index.ts` (re-export shim)


## Commit

After all tests pass, commit the changes to the relevant submodule(s) using conventional commits format, then update the parent repo submodule reference.
