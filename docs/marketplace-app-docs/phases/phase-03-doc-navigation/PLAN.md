# Phase 3: Documentation Navigation

## Overview

Build the sidebar navigation, audience filter, version selector, and section routing for the app detail page. This transforms the single-content-area page from Phase 2 into a full documentation browser.

The sidebar is constructed from `_meta.json` sections. Users can filter by audience (All / Business / Technical), switch between versions, and navigate directly to any section via URL.

## Dependencies

- Phase 2 (App Detail Page with markdown rendering)

## Steps

### 3.1 Implement URL routing for sections and versions

Parse the URL pattern `/marketplace/{developerId}/{appId}[/v{version}][/{section}]`:

- Extract `developerId` and `appId` from route params
- Parse remaining path segments to determine version and section:
  - Segment starting with `v` + digits → version (e.g., `v1.0.0`)
  - Other segment → section name (e.g., `getting-started`)
  - `changelog-history` → reserved built-in section
- Default: latest version, `overview` section

Create a `useDocRoute()` hook that returns `{ developerId, appId, version, section }` parsed from the current URL.

### 3.2 Create DocSidebar component

Create `eldrin-website/src/pages/Marketplace/DocSidebar.tsx`:

**Structure**:
- Section list from `_meta.json`, grouped visually:
  - Business sections: overview, features, pricing
  - Getting started sections: getting-started, configuration, usage
  - Technical sections: api, permissions, integrations, troubleshooting
  - Special: changelog, changelog-history
- Separators between groups (thin `ink-700` line)
- Active section highlighted with `electric-600` background

**Props**:
- `meta`: parsed `_meta.json`
- `currentSection`: active section name
- `audienceFilter`: `'all' | 'business' | 'technical'`
- `onSectionChange`: callback
- `hasMultipleVersions`: whether to show changelog-history link

**Behavior**:
- Clicking a section updates the URL (via `useNavigate`) and triggers content fetch
- Sections filtered by `audienceFilter` — if a section's `audience` doesn't match, it's hidden
- `audience: 'all'` sections always visible regardless of filter

### 3.3 Create AudienceFilter component

Create audience filter toggle at the bottom of the sidebar:

- Three options: All, Business, Technical
- Segmented control (button group) style
- Default: "All" (show everything)
- Persisted in `localStorage` under `eldrin-marketplace-audience-filter`
- When filter changes, if current section is hidden by the filter, navigate to `overview`

### 3.4 Create VersionSelector component

Dropdown in the page header showing all versions with `docs: true`:

- Fetches version list from `GET /api/marketplace/docs` response's `availableVersions`
- Defaults to latest version
- Selecting a version navigates to `/marketplace/{developerId}/{appId}/v{version}/{currentSection}`
- Preserves the active section when switching versions
- If the selected section doesn't exist in the new version's `_meta.json`, fall back to `overview`

### 3.5 Create ChangelogHistory page

A built-in section (not from markdown) that aggregates changelogs across all versions:

- Fetches `changelog.md` from every version in `versions.json` (in parallel)
- Renders them in reverse chronological order
- Each version's changelog under a heading: `## v{version} — {releaseDate}`
- Shown in sidebar as "Changelog History" when multiple versions exist
- Route: `/marketplace/{developerId}/{appId}/changelog-history`

### 3.6 Wire sidebar into AppDetailPage

Update `AppDetailPage.tsx` to include the sidebar layout:

**Layout** (below the header):
```
┌──────────┬──────────────────────────────────────┐
│ Sidebar  │  Content area                        │
│ (250px)  │  (flex-1)                             │
│          │                                      │
│ Sections │  Rendered markdown                    │
│ ──────── │                                      │
│ Filter   │                                      │
└──────────┴──────────────────────────────────────┘
```

- Sidebar: `w-64` fixed, `border-r border-ink-700`, sticky (`top-[73px]` below header)
- Content: `flex-1`, `max-w-4xl`, proper padding
- On mobile: sidebar collapses to a dropdown or hamburger menu

### 3.7 Handle navigation edge cases

- **Unknown section**: Redirect to app's overview page (replace in history)
- **Unknown version**: Redirect to latest version, same section (replace in history)
- **Section missing in version**: When switching versions, if section doesn't exist in new version, redirect to overview
- **Direct URL access**: Works via SPA fallback (already configured in `wrangler.jsonc`)

## Test Gate

```bash
cd eldrin-website && npx tsc -b              # TypeScript compiles
cd eldrin-website && npm run build            # Build succeeds
```

Acceptance criteria:
1. Sidebar shows correct sections from `_meta.json`
2. Clicking a section updates URL and renders that section's markdown
3. Audience filter hides/shows sections based on audience
4. Version selector switches between versions
5. Changelog History aggregates all versions' changelogs
6. Direct URL access (e.g., `/marketplace/eldrin.io/workflows/getting-started`) works
7. Unknown sections redirect to overview
8. Mobile layout is usable (sidebar collapses)

## Files Created

| File | Purpose |
|------|---------|
| `src/pages/Marketplace/DocSidebar.tsx` | Section navigation sidebar |
| `src/pages/Marketplace/VersionSelector.tsx` | Version dropdown component |
| `src/pages/Marketplace/ChangelogHistory.tsx` | Aggregated changelog page |
| `src/pages/Marketplace/useDocRoute.ts` | URL parsing hook |

## Files Modified

| File | Change |
|------|--------|
| `src/pages/Marketplace/AppDetailPage.tsx` | Add sidebar layout, wire routing |
| `src/pages/Marketplace/MarkdownRenderer.tsx` | Update internal link resolution for section URLs |

## Finalize

- [ ] Manual validation: Test sidebar, filter, version selector, URL patterns, edge cases
- [ ] Commit: `feat: add documentation sidebar, audience filter, and version selector`
- [ ] Update `STATUS.md` → complete, create `DONE.md`
