# Phase 1: Structure & Submission

## Overview

Add the backend infrastructure for marketplace app documentation: R2 bucket bindings, docs validation in the submission handler, and new API endpoints for fetching documentation metadata and files.

This phase makes documentation a supported artifact in the release pipeline. Publishers can include a `docs/` directory in their submissions, and the marketplace can serve those files to the frontend.

**Note**: For initial testing, docs files will be manually uploaded to R2. Full submission handler integration with R2 (replacing GitHub) is tracked separately.

## Dependencies

None — this is the first phase.

## Steps

### 1.1 Add R2 bucket bindings to wrangler.jsonc

Add two R2 bucket bindings to `eldrin-website/wrangler.jsonc`:

```jsonc
"r2_buckets": [
  { "binding": "RELEASES_BUCKET", "bucket_name": "eldrin-releases" },
  { "binding": "RELEASES_STAGING_BUCKET", "bucket_name": "eldrin-releases-staging" }
]
```

### 1.2 Update Env type with R2 bindings

In `eldrin-website/worker/index.ts`, extend the `LicenseEnv` interface:

```typescript
interface LicenseEnv {
  // ... existing fields
  RELEASES_BUCKET: R2Bucket
  RELEASES_STAGING_BUCKET: R2Bucket
}
```

### 1.3 Create `_meta.json` validation helper

Create `eldrin-website/worker/handlers/docs-validation.ts`:

- `validateDocsMeta(meta: unknown): { valid: boolean; error?: string }`
- Validates required fields: `title`, `sections`
- Validates each section has `title` and valid `audience` (`all`, `business`, `technical`)
- Returns descriptive error messages for validation failures

### 1.4 Add docs validation to submission handler

In `eldrin-website/worker/handlers/submission.ts`, after manifest validation:

1. Check if any submitted file has a path starting with `docs/`
2. If `docs/` files exist, require `docs/_meta.json` among them
3. Parse and validate `_meta.json` using the helper from step 1.3
4. Validate that each section listed in `_meta.json` has a corresponding `.md` file
5. Validate image size limits: individual images max 2 MB, total `docs/assets/` max 20 MB
6. On validation failure, return `{ success: false, error: '...' }`

### 1.5 Create `GET /api/marketplace/docs` endpoint

In `eldrin-website/worker/index.ts`, add a new route:

```
GET /api/marketplace/docs?developerId=X&appId=Y&version=Z
```

Handler logic:
1. Validate query params (`developerId`, `appId` required; `version` optional)
2. Fetch `{developerId}/{appId}/versions.json` from `RELEASES_BUCKET`
3. If `version` not specified, use `latest` from `versions.json`
4. Fetch `{developerId}/{appId}/v{version}/docs/_meta.json` from `RELEASES_BUCKET`
5. Return: `{ meta: {...}, availableVersions: ["1.1.0", "1.0.0"] }`
6. If no docs exist, return: `{ meta: null, availableVersions: [...] }`

Caching:
- Versioned request (specific version): `Cache-Control: public, max-age=31536000, immutable`
- Latest (no version): `Cache-Control: public, max-age=300`

### 1.6 Extend `POST /api/marketplace/file` to read from R2

The existing endpoint fetches files from GitHub. Switch to R2 as the primary source:

1. If the request includes `developerId`, `appId`, and `version` params:
   - Construct R2 key: `{developerId}/{appId}/v{version}/{path}`
   - Fetch from `RELEASES_BUCKET`
   - Return with appropriate `Content-Type` (text/markdown for `.md`, image/* for images, etc.)
   - Add `Cache-Control: public, max-age=31536000, immutable` for versioned content
2. For non-docs file requests (app bundles, manifests), keep the existing GitHub fetch logic

Content-Type detection:
- `.md` → `text/markdown; charset=utf-8`
- `.json` → `application/json`
- `.png` → `image/png`
- `.jpg` / `.jpeg` → `image/jpeg`
- `.svg` → `image/svg+xml`
- `.webp` → `image/webp`
- Default → `application/octet-stream`

### 1.7 Manual R2 upload for testing

Create a test `docs/` directory structure that can be manually uploaded to R2 for Phase 2/3 development:

```
eldrin.io/workflows/versions.json
eldrin.io/workflows/v1.0.0/docs/_meta.json
eldrin.io/workflows/v1.0.0/docs/overview.md
eldrin.io/workflows/v1.0.0/docs/features.md
eldrin.io/workflows/v1.0.0/docs/getting-started.md
```

Document the manual upload process using `wrangler r2 object put`.

## Test Gate

```bash
cd eldrin-website && npx tsc -b              # TypeScript compiles
cd eldrin-website && npm run build            # Build succeeds
```

Acceptance criteria:
1. `GET /api/marketplace/docs?developerId=eldrin.io&appId=workflows` returns metadata
2. `POST /api/marketplace/file` with `{ path: "docs/overview.md" }` returns markdown content
3. Submission with invalid `_meta.json` returns 400 with descriptive error
4. R2 responses include correct `Content-Type` and `Cache-Control` headers

## Files Created

| File | Purpose |
|------|---------|
| `worker/handlers/docs-validation.ts` | `_meta.json` schema validation |

## Files Modified

| File | Change |
|------|--------|
| `wrangler.jsonc` | Add `r2_buckets` bindings |
| `worker/index.ts` | Add R2 to `LicenseEnv`, add `GET /api/marketplace/docs` route |
| `worker/handlers/submission.ts` | Add docs validation after manifest check |

## Finalize

- [ ] Manual validation: API endpoints respond correctly with R2 data
- [ ] Commit: `feat: add R2-backed documentation API for marketplace apps`
- [ ] Update `STATUS.md` → complete, create `DONE.md`
