# Phase 11: Rate Limiting & API Protection

## Status: done
## Started: 2025-02-09
## Completed: 2025-02-09

## Progress:
- [x] Step 11.1: Create rate limiter interface
- [x] Step 11.2: Implement memory, database, cache adapters
- [x] Step 11.3: Create Hono middleware
- [x] Step 11.4: Create IP extraction utility
- [x] Step 11.5: Write unit tests (22 cases)
- [x] Step 11.6: Integrate into unified app (CreateAppOptions.rateLimiting)
- [x] Step 11.7: Full regression — 110 tests pass

## Notes:
- Three rate limiter backends: memory (sliding window), database (fixed window), cache (CacheAdapter-backed)
- Memory limiter: true sliding window with timestamp arrays per key
- Database limiter: atomic `ON CONFLICT DO UPDATE` upsert, `_rate_limits` table with `cleanup()` method
- Cache limiter: wraps `CacheAdapter` interface (works with any Phase 15 backend)
- Auth endpoints: 10 req/min/IP, General API: 100 req/min/IP (configurable)
- IP extraction: CF-Connecting-IP > X-Forwarded-For > X-Real-IP, configurable trusted proxy depth
- Standard X-RateLimit-* headers on all responses, 429 + Retry-After when blocked
- E2E tests skipped — entry points not yet wired to unified app
