# Phase 0: Testing Foundation

## Overview

Set up Vitest + Playwright in eldrin-core and establish shared test patterns. eldrin-app-core already has Vitest; eldrin-core has zero testing infrastructure.

## Dependencies

None — this is the first phase.

## Steps

### 0.1 Add Vitest to eldrin-core

- Install `vitest`, `@vitest/coverage-v8`
- Create `eldrin-core/vitest.config.ts` with `globals: true`, `environment: 'node'`, include `core/**/*.test.ts`
- Add scripts: `test`, `test:run`, `test:coverage`

### 0.2 Create test utilities — `core/test-utils/`

| File | Purpose | Est. lines |
|------|---------|-----------|
| `mock-db.ts` | In-memory `DatabaseAdapter` mock backed by Map | ~80 |
| `mock-storage.ts` | In-memory `StorageAdapter` | ~40 |
| `mock-cache.ts` | In-memory `CacheAdapter` | ~30 |
| `mock-logger.ts` | Captures log entries for assertion | ~20 |
| `fixtures.ts` | Factory functions: `createTestUser()`, `createTestJWTPayload()`, `createTestApp()` | ~60 |
| `hono-helpers.ts` | `createTestApp()`, `makeAuthenticatedRequest()` | ~40 |

### 0.3 Playwright E2E setup

- Install `@playwright/test`
- Create `eldrin-core/playwright.config.ts` with `testDir: './e2e'`, webServer on port 4000
- Add scripts: `e2e`, `e2e:ui`

### 0.4 E2E test utilities — `e2e/helpers/`

| File | Purpose |
|------|---------|
| `auth.ts` | `loginAsAdmin()`, `loginAs()`, `logout()` |
| `api.ts` | `apiLogin()`, `authenticatedRequest()` |
| `setup.ts` | `resetDatabase()` |

### 0.5 Baseline E2E tests — `e2e/baseline.spec.ts`

~10 cases validating app works before any changes: login/logout, dashboard, protected routes, health endpoint, static assets.

## Test Gate

```bash
cd eldrin-core && npx vitest run          # Unit tests pass
cd eldrin-core && npx playwright test     # E2E baseline passes
```

## Files Created

- `eldrin-core/vitest.config.ts`
- `eldrin-core/playwright.config.ts`
- `eldrin-core/core/test-utils/mock-db.ts`
- `eldrin-core/core/test-utils/mock-storage.ts`
- `eldrin-core/core/test-utils/mock-cache.ts`
- `eldrin-core/core/test-utils/mock-logger.ts`
- `eldrin-core/core/test-utils/fixtures.ts`
- `eldrin-core/core/test-utils/hono-helpers.ts`
- `eldrin-core/core/test-utils/index.ts`
- `eldrin-core/e2e/helpers/auth.ts`
- `eldrin-core/e2e/helpers/api.ts`
- `eldrin-core/e2e/baseline.spec.ts`
- `eldrin-core/core/test-utils/*.test.ts` (3 test files)
