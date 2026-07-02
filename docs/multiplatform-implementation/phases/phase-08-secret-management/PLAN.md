# Phase 8: Secret Management

## Overview

Centralize secret retrieval behind a `SecretProvider` interface so the app doesn't care where secrets come from — env vars, cloud vault, or config file.

## Dependencies

- Phase 0 (testing infrastructure)

## Steps

### 8.1 Secret provider interface — `core/secrets/interface.ts`

```typescript
export interface SecretProvider {
  get(key: string): Promise<string | undefined>;
  getRequired(key: string): Promise<string>;  // throws if missing
}
```

### 8.2 Provider implementations

| File | Backend | Est. lines |
|------|---------|-----------|
| `core/secrets/adapters/env.ts` | `process.env` / Cloudflare env bindings | ~20 |
| `core/secrets/adapters/aws-secrets-manager.ts` | AWS Secrets Manager | ~50 |
| `core/secrets/adapters/azure-key-vault.ts` | Azure Key Vault | ~50 |
| `core/secrets/adapters/gcp-secret-manager.ts` | GCP Secret Manager | ~50 |

### 8.3 Composite provider — `core/secrets/composite.ts`

Chains providers with fallback: try cloud vault first, then env vars. Caches resolved values in-memory for the request lifecycle.

### 8.4 Integration

Replace all `getJWTSecret(env)` and direct `process.env` reads with `secrets.getRequired('JWT_SECRET')`. Set `SecretProvider` on `AppVariables` by each cloud adapter.

### 8.5 Tests

| Test file | Cases |
|-----------|-------|
| `core/secrets/adapters/env.test.ts` | ~4 |
| `core/secrets/composite.test.ts` | ~5 |

## Test Gate

```bash
cd eldrin-core && npx vitest run -- core/secrets/   # ~9 tests
```


## Commit

After all tests pass, commit the changes to the relevant submodule(s) using conventional commits format, then update the parent repo submodule reference.
