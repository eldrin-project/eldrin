# Phase 12: Session Revocation & Token Blacklist — DONE

## What was built

Server-side token revocation for Eldrin's JWT auth system. Tokens can now be invalidated immediately on logout, password change, user disable, and user deletion.

## Architecture

### Two-level revocation strategy
- **Individual**: `revoke(jti, expiresAt)` — blacklists a single token (logout)
- **Bulk**: `revokeAllForUser(userId)` — stores a timestamp; tokens issued before it are rejected (password change, disable, delete)

### New files
- `core/auth/token-revocation/interface.ts` — `TokenRevocationStore` interface
- `core/auth/token-revocation/memory.ts` — `MemoryRevocationStore` (dev/test)
- `core/auth/token-revocation/database.ts` — `DatabaseRevocationStore` (production)
- `core/auth/token-revocation/index.ts` — barrel exports
- `core/auth/token-revocation.test.ts` — 13 unit tests
- `migrations/20260209000001-token-revocation.sql` — migration SQL

### Modified files
- `core/auth/types.ts` — added `jti: string` to `JWTPayload`
- `core/auth/jwt.ts` — `createToken()` generates jti, `verifyToken()` validates it
- `core/auth/middleware.ts` — `extractAuth()` checks revocation store
- `core/auth/index.ts` — exports token-revocation module
- `core/app.ts` — `AppVariables.revocationStore`, `CreateAppOptions.tokenRevocation`, wired into middleware + routes
- `core/routes/auth.ts` — `handleLogout()` revokes token
- `core/routes/users.ts` — `handleUpdateUser()`, `handleUpdateUserPassword()`, `handleDeleteUser()` revoke tokens
- `core/test-utils/fixtures.ts` — `createTestJWTPayload()` includes jti

## Test results

```
123 tests pass (13 new + 110 existing)
TypeScript: zero errors
```
