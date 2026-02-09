# Phase 3: Pluggable Auth Provider System

## Overview

Add a pluggable authentication system supporting multiple identity providers simultaneously (local email/password, Microsoft Entra, Google, AWS Cognito, generic OIDC). Includes account linking, JIT user creation with pending approval, and JWKS token validation using Web Crypto API.

## Dependencies

- Phase 2 (unified Hono app — routes to add providers to)
- Phase 8 (secrets — for storing client secrets)
- Phase 9 (observability — logger for auth events)
- Phase 12 (token revocation — logout revokes tokens)
- Phase 13 (audit logging — record auth events)
- Phase 15 (cache — JWKS key caching)

## Steps

### 3.1 Auth provider interface — `core/auth/providers/interface.ts`

Define `AuthProviderType`, `AuthProviderConfig`, `OIDCProviderConfig`, `LocalProviderConfig`, `AuthIdentity`, `AuthProvider` interfaces.

### 3.2 Provider implementations

| File | Purpose | Est. lines |
|------|---------|-----------|
| `core/auth/providers/local.ts` | Wraps existing email/password | ~40 |
| `core/auth/providers/oidc-base.ts` | Base OIDC provider (discovery, JWKS, token validation) | ~150 |
| `core/auth/providers/entra.ts` | Microsoft Entra ID | ~40 |
| `core/auth/providers/google.ts` | Google Identity | ~30 |
| `core/auth/providers/cognito.ts` | AWS Cognito | ~30 |
| `core/auth/providers/oidc-generic.ts` | Generic OIDC catch-all | ~10 |

### 3.3 Provider registry — `core/auth/providers/registry.ts`

`AuthProviderRegistry` class — register/get/getEnabled providers. `fromDatabase()` reads `auth_providers` table.

### 3.4 JWKS token validation — `core/auth/jwks.ts`

`JWKSClient` (fetch + cache JWKS keys), `verifyJWKSToken()` using Web Crypto API.

### 3.5 Account linking — `core/auth/account-linking.ts`

`resolveExternalIdentity()`, `linkIdentity()`, `getUserIdentities()`, `unlinkIdentity()`.

Resolution logic: (1) lookup by provider+subject → (2) lookup by email → (3) create pending user.

### 3.6 Database migration

Create `auth_providers` and `user_identities` tables. Add `status` column to `users` table.

### 3.7 New auth routes — `core/routes/auth-providers.ts`

| Route | Method | Auth | Purpose |
|-------|--------|------|---------|
| `/api/auth/providers` | GET | No | List enabled providers |
| `/api/auth/providers/:id/authorize` | GET | No | Redirect to IdP |
| `/api/auth/callback` | GET | No | OIDC callback |
| `/api/auth/token-exchange` | POST | No | Exchange IdP token for Eldrin JWT |
| `/api/auth/identities` | GET | Yes | List user's linked identities |
| `/api/auth/link` | POST | Yes | Link identity |
| `/api/auth/link/:identityId` | DELETE | Yes | Unlink identity |

### 3.8 New user management routes

| Route | Method | Permission | Purpose |
|-------|--------|------------|---------|
| `/api/users/pending` | GET | `users:read` | List pending users |
| `/api/users/:userId/approve` | POST | `users:write` | Approve pending user |
| `/api/users/:userId/reject` | POST | `users:write` | Reject pending user |

### 3.9 Frontend changes

- Update `Login.tsx` — fetch providers, show SSO buttons + local form
- New `AuthCallback.tsx` — handle OIDC redirect callback
- New `AccountLinking.tsx` — manage linked identities
- Update `authStore.ts` — add `loginWithProvider()`, `handleCallback()`

### 3.10 Auth provider configuration via env vars

Providers configured via env vars + upserted into `auth_providers` table on startup.

## Test Gate

```bash
cd eldrin-core && npx vitest run -- core/auth/ core/routes/auth-providers.test.ts core/routes/users.test.ts
# ~77 unit tests

cd eldrin-core && npx playwright test e2e/auth/
# ~23 E2E auth tests

cd eldrin-core && npx playwright test e2e/baseline.spec.ts
# Regression
```

## Files Created

~12 source files, ~10 test files, 1 migration, 2 frontend components

## Files Modified

- `core/auth/types.ts` — add `jti` to JWTPayload
- `core/routes/users.ts` — add pending/approve/reject routes
- `src/pages/Login.tsx` — show provider buttons
- `src/stores/authStore.ts` — add OIDC login methods


## Commit

After all tests pass, commit the changes to the relevant submodule(s) using conventional commits format, then update the parent repo submodule reference.
