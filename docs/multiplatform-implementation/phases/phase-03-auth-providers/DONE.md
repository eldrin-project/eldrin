# Phase 3: Pluggable Auth Provider System — DONE

## Summary
Added a pluggable authentication provider system supporting local email/password, Microsoft Entra ID, Google, AWS Cognito, and generic OIDC providers. Includes JWKS RS256 token verification, PKCE-based authorization code flow, stateless encrypted OAuth state, account linking with 4-step resolution cascade, and pending user approval workflow.

## Files Created (15 source + 7 test)

### Source
| File | Purpose | Lines |
|------|---------|-------|
| `migrations/20260210000001-auth-providers.sql` | DB migration (auth_providers, user_identities, users.status) | ~30 |
| `core/auth/providers/interface.ts` | Types: AuthProvider, AuthProviderConfig, OIDCTokenClaims, etc. | ~168 |
| `core/auth/providers/local.ts` | LocalAuthProvider (throws on OIDC methods) | ~35 |
| `core/auth/providers/oidc-base.ts` | OIDCBaseProvider (discovery, PKCE, token exchange, JWKS) | ~178 |
| `core/auth/providers/entra.ts` | EntraAuthProvider (tenant-specific issuer) | ~22 |
| `core/auth/providers/google.ts` | GoogleAuthProvider (accounts.google.com) | ~20 |
| `core/auth/providers/cognito.ts` | CognitoAuthProvider (region + pool issuer) | ~25 |
| `core/auth/providers/oidc-generic.ts` | createGenericOIDCProvider() factory | ~15 |
| `core/auth/providers/registry.ts` | AuthProviderRegistry (register, get, fromDatabase) | ~95 |
| `core/auth/providers/index.ts` | Barrel exports | ~25 |
| `core/auth/jwks.ts` | JWKSClient + verifyJWKSToken (RS256, Web Crypto) | ~235 |
| `core/auth/oidc-state.ts` | PKCE generation + AES-GCM encrypted state | ~161 |
| `core/auth/account-linking.ts` | resolveExternalIdentity, link/unlink/get identities | ~228 |
| `core/routes/auth-providers.ts` | 7 route handlers + HTML callback bridge | ~383 |

### Tests
| File | Tests |
|------|-------|
| `core/auth/oidc-state.test.ts` | 10 |
| `core/auth/jwks.test.ts` | 15 |
| `core/auth/providers/oidc-base.test.ts` | 7 |
| `core/auth/providers/providers.test.ts` | 9 |
| `core/auth/providers/registry.test.ts` | 8 |
| `core/auth/account-linking.test.ts` | 12 |
| `core/routes/auth-providers.test.ts` | 5 |
| **Total new** | **66** |

## Files Modified
| File | Change |
|------|--------|
| `core/auth/types.ts` | Added `status?: string` to UserRecord and User |
| `core/auth/middleware.ts` | Added 3 public routes to PUBLIC_ROUTES |
| `core/auth/index.ts` | Added exports for JWKS, OIDC state, providers, account-linking |
| `core/routes/users.ts` | Added handleGetPendingUsers, handleApproveUser, handleRejectUser |
| `core/routes/auth.ts` | Login query now checks `status = 'active'` |
| `core/routes/index.ts` | Added exports for pending user + auth provider routes |
| `core/app.ts` | Added authProviders option, mounted all new routes |
| `core/test-utils/fixtures.ts` | Added createTestAuthProviderConfig, createTestAuthIdentity |

## Test Results
```
Test Files  26 passed (26)
     Tests  204 passed (204)
  Duration  760ms
```

## Phase Gate
- [x] All 204 unit tests pass
- [x] TypeScript compiles with zero errors
- [x] All OIDC providers create correct issuer URLs
- [x] JWKS client caches keys and handles rotation
- [x] OAuth state encrypts/decrypts with 10-minute expiry
- [x] Account linking resolves existing/linked/pending/rejected
- [x] Public routes skip auth middleware
- [x] Pending user routes registered before /:userId catch-all
