# Phase 2: Unified Hono App (`core/app.ts`)

## Overview

Create a factory function returning a fully configured Hono app with all routes, eliminating the duplication between `worker/index.ts` (323 lines) and `server/index.ts` (451 lines).

## Dependencies

- Phase 1 (SDK fixes — `DatabaseAdapter` interface)
- Phase 0 (testing infrastructure)

## Steps

### 2.1 Create `eldrin-core/core/app.ts`

```typescript
export type AppVariables = {
  db: DatabaseAdapter;
  jwtSecret: string;
  auth?: JWTPayload;
  deploymentMode: 'local' | 'cloud';
};
export type AppEnv = { Variables: AppVariables };

export function createApp(): Hono<AppEnv> { ... }
```

Port all ~35 routes from `worker/index.ts` with permission checks (server was missing these — bug fix).

Key references:
- `eldrin-core/worker/index.ts` — complete permission checks per route
- `eldrin-core/server/index.ts` — Hono route patterns
- `eldrin-core/core/routes/index.ts` — all handler exports

### 2.2 Update `eldrin-core/core/index.ts`

Add: `export { createApp, type AppVariables, type AppEnv } from './app';`

### 2.3 Tests — `core/app.test.ts`

Route registration tests (~15 cases):
- `createApp()` returns a Hono instance
- All expected routes are registered
- Public routes return 200 without auth
- Protected routes return 401 without auth token
- Protected routes return 200 with valid auth token
- Permission-guarded routes return 403 with insufficient permissions
- Route handlers receive db from context variables
- Unknown routes return 404

Route parity tests (~5 cases):
- Every route in `worker/index.ts` has a corresponding route in `createApp()`
- Permission checks match between worker and unified app

### 2.4 E2E regression

Run `npm run e2e -- e2e/baseline.spec.ts` — all baseline tests still pass after consolidation.

## Test Gate

```bash
cd eldrin-core && npx vitest run -- core/app.test.ts   # ~20 unit tests
cd eldrin-core && npx playwright test e2e/baseline.spec.ts  # E2E regression
```

## Files Created

- `eldrin-core/core/app.ts` (~280 lines)
- `eldrin-core/core/app.test.ts` (~20 test cases)

## Files Modified

- `eldrin-core/core/index.ts` — add `createApp` export


## Commit

After all tests pass, commit the changes to the relevant submodule(s) using conventional commits format, then update the parent repo submodule reference.
