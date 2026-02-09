# Phase 11: Rate Limiting & API Protection

## Overview

Add configurable rate limiting middleware with multiple backends. Applied aggressively to auth endpoints, lighter limits on general API.

## Dependencies

- Phase 2 (unified Hono app — middleware to apply)
- Phase 15 (cache — optional Redis/KV backend)

## Steps

### 11.1 Rate limiter interface — `core/security/rate-limiter.ts`

`RateLimiter`: `check(key, limit, windowMs)` → `RateLimitResult { allowed, remaining, resetAt, retryAfter }`.

### 11.2 Implementations

| File | Backend | Est. lines |
|------|---------|-----------|
| `core/security/rate-limiters/memory.ts` | In-memory sliding window (single-instance) | ~50 |
| `core/security/rate-limiters/database.ts` | DB-backed (distributed, universal) | ~60 |
| `core/security/rate-limiters/kv.ts` | Cloudflare KV / Redis-like | ~40 |

### 11.3 Hono middleware — `core/security/rate-limit-middleware.ts`

Applied to auth endpoints (10 attempts/min/IP), lighter on general API. Returns 429 with `Retry-After` header.

### 11.4 IP extraction utility

Handles `X-Forwarded-For`, `CF-Connecting-IP`, `X-Real-IP` with configurable trusted proxy depth.

### 11.5 Tests

| Test file | Cases |
|-----------|-------|
| `core/security/rate-limiters/memory.test.ts` | ~6 |
| `core/security/rate-limiters/database.test.ts` | ~5 |
| `core/security/rate-limit-middleware.test.ts` | ~5 |
| `core/security/ip-extraction.test.ts` | ~4 |
| `e2e/security/rate-limiting.spec.ts` | ~3 |

## Test Gate

```bash
cd eldrin-core && npx vitest run -- core/security/   # ~20 tests
cd eldrin-core && npx playwright test e2e/security/rate-limiting.spec.ts   # ~3 E2E
cd eldrin-core && npx playwright test e2e/baseline.spec.ts                 # Regression
```


## Commit

After all tests pass, commit the changes to the relevant submodule(s) using conventional commits format, then update the parent repo submodule reference.
