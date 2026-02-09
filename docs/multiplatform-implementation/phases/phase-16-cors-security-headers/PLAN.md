# Phase 16: CORS & Security Headers

## Overview

Configurable security headers middleware: CORS, CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy. Different defaults for dev vs production.

## Dependencies

- Phase 2 (unified Hono app — middleware to apply)

## Steps

### 16.1 Security headers middleware — `core/security/headers.ts`

`SecurityHeadersConfig` with CORS (origins, methods, headers, credentials, maxAge), CSP, HSTS, X-Frame-Options, etc.

### 16.2 Default configuration

- **Dev**: `origins: ['*']`, relaxed CSP
- **Production**: origins from `ALLOWED_ORIGINS` env var, strict CSP, HSTS enabled

### 16.3 Configuration

```
ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
CORS_CREDENTIALS=true
HSTS_MAX_AGE=31536000
```

### 16.4 Tests

| Test file | Cases |
|-----------|-------|
| `core/security/headers.test.ts` | ~10 |
| `e2e/security/headers.spec.ts` | ~4 |

## Test Gate

```bash
cd eldrin-core && npx vitest run -- core/security/headers.test.ts          # ~10 tests
cd eldrin-core && npx playwright test e2e/security/headers.spec.ts         # ~4 E2E
cd eldrin-core && npx playwright test e2e/baseline.spec.ts                 # Regression
```


## Commit

After all tests pass, commit the changes to the relevant submodule(s) using conventional commits format, then update the parent repo submodule reference.
