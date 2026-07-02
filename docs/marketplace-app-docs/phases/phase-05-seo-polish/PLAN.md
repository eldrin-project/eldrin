# Phase 5: SEO & Polish

## Overview

Add meta tags, breadcrumbs, keyboard navigation, and caching headers to the marketplace documentation pages. These improvements make the documentation more discoverable, navigable, and performant.

## Dependencies

- Phase 3 (Documentation Navigation — full routing in place)

## Steps

### 5.1 Add dynamic document title and meta tags

Update `AppDetailPage.tsx` to set `document.title` based on context:

- App overview: `{appName} — Eldrin Marketplace`
- Specific section: `{sectionTitle} — {appName} — Eldrin Marketplace`
- 404: `App Not Found — Eldrin Marketplace`

Add Open Graph meta tags via `document.head` manipulation:
- `og:title`: Same as document title
- `og:description`: App tagline or description
- `og:type`: `article`
- `og:url`: Current canonical URL

Use a `useDocumentTitle(title)` hook pattern to set/restore title on mount/unmount.

### 5.2 Add breadcrumb navigation

Create `eldrin-website/src/pages/Marketplace/Breadcrumbs.tsx`:

**Path**: Marketplace > {Developer} > {App} > {Section}

- Each segment is a clickable link (except the last)
- Styled with `ink-400` color, `>` separator
- Placed between the top bar and the app header
- Responsive: on mobile, show only `← {App Name}` (compact)

### 5.3 Add keyboard navigation

In `DocSidebar.tsx`, add keyboard support:

- `↑` / `↓`: Move focus between sidebar items
- `Enter`: Navigate to focused section
- `Home` / `End`: Jump to first/last section
- Focus ring: `ring-2 ring-electric-500` on focused item
- Trap focus within sidebar when it has focus (but don't steal focus from content)

### 5.4 Add caching headers to API responses

In `worker/index.ts`, add `Cache-Control` headers:

| Endpoint | Scenario | Header |
|----------|----------|--------|
| `GET /api/marketplace/docs` | Specific version | `public, max-age=31536000, immutable` |
| `GET /api/marketplace/docs` | Latest (no version) | `public, max-age=300` |
| `POST /api/marketplace/file` | Versioned path | `public, max-age=31536000, immutable` |
| `POST /api/marketplace/file` | Preview mode | `no-store` |
| `GET /api/marketplace/versions` | Always | `public, max-age=60` |

### 5.5 Add loading and transition polish

- Skeleton loader for markdown content (3 animated bars of varying width)
- Framer Motion `AnimatePresence` for section transitions (fade + slide)
- Smooth scroll to top when navigating between sections
- Content area minimum height to prevent layout shift

## Test Gate

```bash
cd eldrin-website && npx tsc -b              # TypeScript compiles
cd eldrin-website && npm run build            # Build succeeds
```

Acceptance criteria:
1. Page title updates correctly when navigating between apps and sections
2. Breadcrumbs show correct hierarchy with clickable links
3. Keyboard navigation works in sidebar (arrow keys, Enter)
4. API responses include correct `Cache-Control` headers
5. Section transitions are smooth with no layout shift

## Files Created

| File | Purpose |
|------|---------|
| `src/pages/Marketplace/Breadcrumbs.tsx` | Breadcrumb navigation component |

## Files Modified

| File | Change |
|------|--------|
| `src/pages/Marketplace/AppDetailPage.tsx` | Add breadcrumbs, document title, loading states |
| `src/pages/Marketplace/DocSidebar.tsx` | Add keyboard navigation |
| `worker/index.ts` | Add Cache-Control headers to marketplace endpoints |

## Finalize

- [ ] Manual validation: Test meta tags, breadcrumbs, keyboard nav, caching headers
- [ ] Commit: `feat: add SEO meta tags, breadcrumbs, and keyboard navigation`
- [ ] Update `STATUS.md` → complete, create `DONE.md`
