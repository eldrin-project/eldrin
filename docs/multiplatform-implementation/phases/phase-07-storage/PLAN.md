# Phase 7: Storage Abstraction Layer

## Overview

Abstract file/blob storage behind a unified `StorageAdapter` interface. Implementations for local filesystem, S3, Azure Blob, GCS, and Cloudflare R2.

## Dependencies

- Phase 2 (unified Hono app — routes to add storage endpoints to)

## Steps

### 7.1 Storage interface — `core/storage/interface.ts`

Define `StorageAdapter`, `StorageObject`, `PutOptions`, `ListOptions`, `StorageListResult`.

Key methods: `put()`, `get()`, `delete()`, `list()`, `getSignedUrl()`.

### 7.2 Provider implementations

| File | Backend | Est. lines |
|------|---------|-----------|
| `core/storage/adapters/local.ts` | Local filesystem (Bun/Node `fs`) | ~80 |
| `core/storage/adapters/s3.ts` | AWS S3 (also MinIO-compatible) — raw fetch + SigV4 | ~100 |
| `core/storage/adapters/azure-blob.ts` | Azure Blob Storage | ~100 |
| `core/storage/adapters/gcs.ts` | Google Cloud Storage | ~100 |
| `core/storage/adapters/r2.ts` | Cloudflare R2 (S3-compatible subset) | ~60 |

### 7.3 Storage configuration

```
STORAGE_PROVIDER=s3|azure-blob|gcs|r2|local
STORAGE_BUCKET=my-eldrin-bucket
STORAGE_REGION=us-east-1
STORAGE_PATH=./data/storage    # Local only
```

### 7.4 Storage routes — `core/routes/storage.ts`

| Route | Method | Auth | Purpose |
|-------|--------|------|---------|
| `/api/storage/upload` | POST | Yes | Upload file (multipart) |
| `/api/storage/download/:key` | GET | Yes | Download file |
| `/api/storage/list` | GET | Yes | List files |
| `/api/storage/delete/:key` | DELETE | Yes | Delete file |
| `/api/storage/signed-url/:key` | GET | Yes | Get pre-signed URL |

### 7.5 Add `StorageAdapter` to `AppVariables`

### 7.6 Tests

| Test file | Cases |
|-----------|-------|
| `core/storage/adapters/local.test.ts` | ~8 |
| `core/storage/adapters/s3.test.ts` | ~6 (mocked fetch) |
| `core/routes/storage.test.ts` | ~6 |
| `e2e/storage.spec.ts` | ~5 |

## Test Gate

```bash
cd eldrin-core && npx vitest run -- core/storage/ core/routes/storage.test.ts   # ~20 tests
cd eldrin-core && npx playwright test e2e/storage.spec.ts                       # ~5 E2E
cd eldrin-core && npx playwright test e2e/baseline.spec.ts                      # Regression
```


## Commit

After all tests pass, commit the changes to the relevant submodule(s) using conventional commits format, then update the parent repo submodule reference.
