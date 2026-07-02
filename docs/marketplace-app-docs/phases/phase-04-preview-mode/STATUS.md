# Phase 4: Preview Mode

## Status: complete
## Started: 2026-02-14
## Completed: 2026-02-14

## Progress:
- [x] Step 4.1: Extend docs API to check staging bucket (stagingVersion + isPreview in response)
- [x] Step 4.2: Add preview cookie handling (GET/POST file endpoints + POST /api/marketplace/preview)
- [x] Step 4.3: Create PreviewBanner component (amber theme, exit button clears cookie)
- [x] Step 4.4: Add preview button + API key dialog to AppDetailPage header
- [x] Step 4.5: Update VersionSelector with staging version + Preview badge
- [x] Step 4.6: TypeScript check and build — clean

## Notes:
- Preview requires developer API key (SHA-256 hashed, verified against api_keys table)
- Preview cookie: `preview_{appId}=true`, Path=`/marketplace/{dev}/{app}`, 4-hour TTL, SameSite=Strict
- Staging content served via `RELEASES_STAGING_BUCKET` when cookie present
- Cache-Control: `no-store` for all preview content (staging may change)
- `stagingVersion` always returned in docs response (harmless info — doesn't reveal content)
- `isPreview` flag tells frontend whether cookie is active

## Files Created:
- `src/pages/Marketplace/PreviewBanner.tsx`

## Files Modified:
- `worker/index.ts` (POST /api/marketplace/preview, staging checks in docs + file endpoints)
- `src/pages/Marketplace/AppDetailPage.tsx` (preview state, API key dialog, PreviewBanner)
- `src/pages/Marketplace/VersionSelector.tsx` (stagingVersion prop, Preview badge)
