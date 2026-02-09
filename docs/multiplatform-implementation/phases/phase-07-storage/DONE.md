# Phase 7: Storage Abstraction Layer — DONE

## Summary
Added a pluggable storage system with a unified `StorageAdapter` interface, two adapters (local filesystem + S3-compatible), a factory, 5 HTTP routes, and 24 tests. The S3 adapter uses raw `fetch()` with Web Crypto API SigV4 signing — no AWS SDK dependency. Works with MinIO, AWS S3, and any S3-compatible store.

## Files Created (8 source + 3 test)

### Source
| File | Purpose | Lines |
|------|---------|-------|
| `core/storage/interface.ts` | StorageAdapter, StorageObject, PutOptions, ListOptions types | ~50 |
| `core/storage/adapters/s3-signer.ts` | AWS SigV4 signing via Web Crypto API (header + pre-signed URL) | ~165 |
| `core/storage/adapters/s3.ts` | S3StorageAdapter: put, get, delete, list, getSignedUrl | ~170 |
| `core/storage/adapters/local.ts` | LocalStorageAdapter: fs-based with .meta.json sidecars | ~130 |
| `core/storage/factory.ts` | `createStorageAdapter(secrets)` — reads STORAGE_PROVIDER | ~35 |
| `core/storage/index.ts` | Barrel exports | ~20 |
| `core/routes/storage.ts` | 5 route handlers: upload, download, list, delete, signed-url | ~130 |

### Tests
| File | Tests |
|------|-------|
| `core/storage/adapters/local.test.ts` | 9 |
| `core/storage/adapters/s3.test.ts` | 7 |
| `core/routes/storage.test.ts` | 8 |
| **Total new** | **24** |

## Files Modified
| File | Change |
|------|--------|
| `core/app.ts` | Added `StorageAdapter` import, `storage?: { adapter?: StorageAdapter }` to CreateAppOptions, 5 storage routes with permission guards |
| `core/routes/index.ts` | Added storage route handler exports + StorageAdapter type/factory re-exports |

## Test Results
```
Test Files  36 passed (36)
     Tests  268 passed (268)
  Duration  843ms
```

## Phase Gate
- [x] All 268 unit tests pass
- [x] TypeScript compiles with zero errors
- [x] StorageAdapter interface defines put(), get(), delete(), list(), getSignedUrl()
- [x] Local adapter stores files with .meta.json sidecar for metadata
- [x] S3 adapter uses SigV4 signing via Web Crypto API (no SDK dependency)
- [x] S3 adapter supports custom endpoints (MinIO/forcePathStyle)
- [x] Factory reads STORAGE_PROVIDER from SecretProvider
- [x] 5 HTTP routes with permission guards (storage:read, storage:write, storage:delete)
- [x] Upload handler validates key (path traversal protection) and file size
- [x] Download handler returns binary data with correct Content-Type
- [x] Pre-signed URL generation for S3 (query-string auth)
- [x] 501 response when storage adapter not configured
