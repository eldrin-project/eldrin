# Phase 4: Preview Mode

## Overview

Let publishers preview their staged documentation before it's promoted to production. When a publisher views their own app's detail page and a staging version exists, they see a "Preview unreleased version" button. Activating preview mode sets a cookie that routes all API calls for that app through the staging R2 bucket.

## Dependencies

- Phase 3 (Documentation Navigation — sidebar, version selector, full routing)

## Steps

### 4.1 Extend docs API to check staging bucket

In `GET /api/marketplace/docs`, add logic to check the staging bucket:

1. If the request includes a valid session cookie (publisher is logged in):
   - Fetch `versions.json` from both `RELEASES_BUCKET` and `RELEASES_STAGING_BUCKET`
   - Compare: if staging has a version newer than prod's latest, include `stagingVersion` in response
   - Only include staging info if the session's `developerId` matches the app's developer
2. Response shape (extended):
   ```json
   {
     "meta": { ... },
     "availableVersions": ["1.1.0", "1.0.0"],
     "stagingVersion": "1.2.0"
   }
   ```
3. `stagingVersion` is `null` / omitted for non-publishers

### 4.2 Add preview cookie handling to file endpoint

In `POST /api/marketplace/file`:

1. Check for `preview_{appId}=true` cookie on the request
2. If cookie is present AND the requester is the app's publisher:
   - Read from `RELEASES_STAGING_BUCKET` instead of `RELEASES_BUCKET`
   - Set `Cache-Control: no-store` (staging content may change)
3. Add a `POST /api/marketplace/preview` endpoint:
   - `{ action: "enable", appId: "..." }` → set `preview_{appId}=true` cookie (HttpOnly, SameSite=Strict, Path=/marketplace/{developerId}/{appId})
   - `{ action: "disable", appId: "..." }` → clear the cookie

### 4.3 Create PreviewBanner component

Create `eldrin-website/src/pages/Marketplace/PreviewBanner.tsx`:

- Sticky banner at the top of the content area (below page header)
- Yellow/amber background (`amber-500/10` bg, `amber-500` text)
- Text: "Preview mode — viewing unreleased version v{version}"
- "Exit preview" button on the right
- Clicking "Exit preview" calls `POST /api/marketplace/preview { action: "disable" }` and reloads

### 4.4 Add preview button to page header

In `AppDetailPage.tsx`, when `stagingVersion` is present in the docs response:

- Show "Preview v{stagingVersion}" button next to the version selector
- Button style: outlined, `amber-500` accent
- Clicking it calls `POST /api/marketplace/preview { action: "enable" }` and reloads
- Only visible to the app's publisher (checked via `stagingVersion` presence — backend enforces access control)

### 4.5 Update version selector for preview mode

When preview mode is active:
- Include the staging version in the version selector dropdown
- Mark it with a badge: "(Preview)"
- Selecting it navigates to that version's documentation (fetched from staging)

### 4.6 Access control verification

Ensure that:
- `stagingVersion` is only returned when the logged-in user's `developerId` matches
- Preview cookie is only honored when the requester is the publisher
- Non-publishers never see the preview button or staged content
- Unauthenticated visitors never see preview content

## Test Gate

```bash
cd eldrin-website && npx tsc -b              # TypeScript compiles
cd eldrin-website && npm run build            # Build succeeds
```

Acceptance criteria:
1. Publisher sees "Preview v{version}" button when staging has newer content
2. Clicking "Preview" sets cookie, page shows staging content
3. Preview banner is visible with "Exit preview" button
4. Non-publishers never see preview button or staging content
5. "Exit preview" clears cookie and shows production content
6. Version selector shows staged version with "(Preview)" badge

## Files Created

| File | Purpose |
|------|---------|
| `src/pages/Marketplace/PreviewBanner.tsx` | Preview mode indicator + exit button |

## Files Modified

| File | Change |
|------|--------|
| `worker/index.ts` | Add `POST /api/marketplace/preview` route, update docs/file endpoints |
| `src/pages/Marketplace/AppDetailPage.tsx` | Add preview button, wire PreviewBanner |
| `src/pages/Marketplace/VersionSelector.tsx` | Show staged version with badge |

## Finalize

- [ ] Manual validation: Test preview as publisher, verify non-publisher can't see staging
- [ ] Commit: `feat: add documentation preview mode for publishers`
- [ ] Update `STATUS.md` → complete, create `DONE.md`
