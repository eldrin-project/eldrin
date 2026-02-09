# Phase 12: Session Revocation & Token Blacklist

## Overview

Add token revocation support via JTI (JWT ID) claims. Database-backed revocation store with auto-cleanup.

## Dependencies

- Phase 2 (unified Hono app — middleware integration)

## Steps

### 12.1 Token revocation interface — `core/auth/token-revocation.ts`

`TokenRevocationStore`: `revoke(jti, expiresAt)`, `isRevoked(jti)`, `revokeAllForUser(userId)`, `cleanup()`.

### 12.2 Database-backed implementation

`revoked_tokens` table with `jti`, `user_id`, `revoked_at`, `expires_at`. Auto-cleanup via background task.

### 12.3 JWT changes

Add `jti` claim to `JWTPayload`. Modify `createToken()` to generate unique jti. Modify `checkAuth()` to check revocation store.

### 12.4 Integration points

- Logout → revoke current token
- User disable/delete → `revokeAllForUser()`
- Password change → `revokeAllForUser()` (force re-login)
- Admin "force logout" → revoke specific/all user tokens

### 12.5 Database migration — `revoked_tokens` table

### 12.6 Tests

| Test file | Cases |
|-----------|-------|
| `core/auth/token-revocation.test.ts` | ~11 |
| `e2e/auth/token-revocation.spec.ts` | ~4 |

## Test Gate

```bash
cd eldrin-core && npx vitest run -- core/auth/token-revocation.test.ts   # ~11 tests
cd eldrin-core && npx playwright test e2e/auth/token-revocation.spec.ts  # ~4 E2E
cd eldrin-core && npx playwright test e2e/baseline.spec.ts               # Regression
```


## Commit

After all tests pass, commit the changes to the relevant submodule(s) using conventional commits format, then update the parent repo submodule reference.
