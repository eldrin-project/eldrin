# Phase 11: Rate Limiting & API Protection — DONE

## Completed: 2025-02-09

## Summary
Created configurable rate limiting middleware with three backends (memory, database, cache) and IP extraction utility. Auth endpoints get 10 req/min/IP, general API gets 100 req/min/IP. Returns 429 with Retry-After header. Integrated into unified app via `CreateAppOptions`.

## Test Gate
- `npx vitest run core/security/` — 34 tests passed (12 existing + 22 new)
- `npx vitest run` — 110 total tests passed (no regressions)

## Files Created
- `core/security/rate-limiter.ts` — RateLimiter interface + RateLimitResult type
- `core/security/ip-extraction.ts` — extractClientIP() with CF-Connecting-IP, X-Forwarded-For, X-Real-IP
- `core/security/rate-limiters/memory.ts` — MemoryRateLimiter (sliding window)
- `core/security/rate-limiters/database.ts` — DatabaseRateLimiter (fixed window, atomic upsert)
- `core/security/rate-limiters/cache.ts` — CacheRateLimiter (CacheAdapter-backed)
- `core/security/rate-limiters/index.ts` — barrel exports
- `core/security/rate-limit-middleware.ts` — Hono middleware with RateLimitConfig
- `core/security/ip-extraction.test.ts` — 6 tests
- `core/security/rate-limiters/memory.test.ts` — 6 tests
- `core/security/rate-limiters/database.test.ts` — 5 tests
- `core/security/rate-limit-middleware.test.ts` — 5 tests

## Files Modified
- `core/security/index.ts` — added rate limiting barrel exports
- `core/app.ts` — added rateLimiting to CreateAppOptions, wired rateLimitMiddleware
