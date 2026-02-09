# Phase 15: Cache Layer

## Overview

Add a `CacheAdapter` interface with in-memory, KV, Redis, and database backends. Used for JWKS caching, OIDC discovery, auth provider config, user permissions, and rate limit counters.

## Dependencies

- Phase 0 (testing infrastructure)

## Steps

### 15.1 Cache interface — `core/cache/interface.ts`

```typescript
export interface CacheAdapter {
  get<T>(key: string): Promise<T | null>;
  set<T>(key: string, value: T, ttlMs?: number): Promise<void>;
  delete(key: string): Promise<void>;
  has(key: string): Promise<boolean>;
}
```

### 15.2 Implementations

| File | Backend | Est. lines |
|------|---------|-----------|
| `core/cache/adapters/memory.ts` | In-memory Map with TTL | ~50 |
| `core/cache/adapters/kv.ts` | Cloudflare KV | ~30 |
| `core/cache/adapters/redis.ts` | Redis / ElastiCache / Azure Cache / Memorystore | ~40 |
| `core/cache/adapters/database.ts` | DB-backed (universal fallback) | ~50 |

### 15.3 Use cases

- JWKS caching (TTL: 1 hour)
- OIDC discovery caching (TTL: 24 hours)
- Auth provider config (TTL: 5 minutes)
- User permissions (TTL: 1 minute, invalidated on change)
- Rate limit counters (when KV/Redis available)

### 15.4 Add to `AppVariables`

### 15.5 Tests

| Test file | Cases |
|-----------|-------|
| `core/cache/adapters/memory.test.ts` | ~7 |
| `core/cache/adapters/database.test.ts` | ~5 |

## Test Gate

```bash
cd eldrin-core && npx vitest run -- core/cache/   # ~12 tests
```


## Commit

After all tests pass, commit the changes to the relevant submodule(s) using conventional commits format, then update the parent repo submodule reference.
