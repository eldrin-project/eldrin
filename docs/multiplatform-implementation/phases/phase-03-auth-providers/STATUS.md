# Phase 3: Pluggable Auth Provider System

## Status: done
## Started: 2026-02-09
## Completed: 2026-02-09

## Progress:
- [x] Step 3.1: Create auth provider interface (`core/auth/providers/interface.ts`)
- [x] Step 3.2: Implement providers (local, OIDC base, Entra, Google, Cognito, generic)
- [x] Step 3.3: Create provider registry (`core/auth/providers/registry.ts`)
- [x] Step 3.4: Implement JWKS token validation (`core/auth/jwks.ts`)
- [x] Step 3.5: Implement account linking (`core/auth/account-linking.ts`)
- [x] Step 3.6: Create database migration (auth_providers, user_identities, users.status)
- [x] Step 3.7: Create auth provider routes (`core/routes/auth-providers.ts`)
- [x] Step 3.8: Add pending user routes (GET pending, POST approve, POST reject)
- [ ] Step 3.9: Frontend changes — DEFERRED (backend-only this phase)
- [x] Step 3.10: OIDC state utility (`core/auth/oidc-state.ts`)
- [x] Step 3.11: Wire into app.ts, update middleware, types, index files
- [x] Step 3.12: Write unit tests (66 new tests, 204 total)
- [x] Step 3.13: Full test suite passes (26 files, 204 tests)

## Notes:
- Frontend changes (Login SSO buttons, AuthCallback.tsx, AccountLinking.tsx) deferred to later phase
- OAuth state is fully stateless via AES-GCM encrypted parameter (no cookies/DB)
- PKCE used for all OIDC flows per OAuth 2.1 recommendation
- Login query now also checks `status = 'active'` alongside `is_active = 1`
- Fixed `.all()` result destructuring bug (`{ results }` pattern)
- Route ordering: `/api/users/pending` registered before `/api/users/:userId`
