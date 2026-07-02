# Marketplace App Documentation — Implementation Plan

## Overview

Add versioned, inline documentation to the Eldrin marketplace. Currently, app detail info shows in a modal with an external link to `docs.eldrin.io`. This plan replaces that with a **standalone app detail page** that renders markdown documentation stored in R2, versioned per release.

Documentation becomes a first-class part of the publishing process — submitted alongside code, immutable per version, rendered inline in the marketplace.

### Requirements

Full requirements document: `docs/requirements/marketplace-app-docs.md`

### Key Technical Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Storage | Cloudflare R2 | Same platform, S3-compatible, direct Worker bindings |
| Markdown rendering | `react-markdown` + `remark-gfm` | Pure markdown (no MDX), GFM tables/checkboxes |
| Documentation structure | Fixed-name convention (`docs/` dir) | Simple for publishers, no config learning curve |
| Metadata | `_meta.json` per version | Controls section order, titles, audience hints |
| Versioning | Snapshot per release | Immutable — allows aggressive caching |
| App detail page | Replaces modal with standalone page | Full layout for docs, sidebar, version selector |
| Preview | Cookie-based staging bucket reads | Publisher-only, per-app scoped |

---

## Implementation Order

```
Phase 1 → 2 → 3 → 4 → 5 → 6
```

| # | Phase | Effort | Status |
|---|-------|--------|--------|
| 1 | [Structure & Submission](#phase-1-structure--submission) | Medium | not_started |
| 2 | [App Detail Page](#phase-2-app-detail-page) | Large | not_started |
| 3 | [Documentation Navigation](#phase-3-documentation-navigation) | Medium | not_started |
| 4 | [Preview Mode](#phase-4-preview-mode) | Medium | not_started |
| 5 | [SEO & Polish](#phase-5-seo--polish) | Small | not_started |
| 6 | [First-Party Docs](#phase-6-first-party-docs) | Medium | not_started |

### Dependencies

```
Phase 1 → 2 → 3   (backend API → page layout → navigation)
Phase 3 → 4        (navigation must exist before preview mode)
Phase 3 → 5        (polish builds on working navigation)
Phase 5 → 6        (write docs after system is polished)
```

### MVP Boundary

**Phases 1–3** deliver a functional documentation system: R2 storage, standalone app detail page, sidebar navigation with audience filtering, version selector.

**Phases 4–6** add preview mode, SEO polish, and real documentation content — valuable but not required for initial launch.

---

## Phase 1: Structure & Submission

**Effort**: Medium | **Files**: ~3 modified, ~1 new

Add R2 bucket bindings, docs validation in the submission handler, and a new `GET /api/marketplace/docs` endpoint. Extend `POST /api/marketplace/file` to serve documentation files and assets from R2.

### Key deliverables

- R2 bucket bindings (`RELEASES_BUCKET`, `RELEASES_STAGING_BUCKET`) in `wrangler.jsonc`
- `_meta.json` schema validation in submission handler
- `GET /api/marketplace/docs` — returns metadata + available versions
- `POST /api/marketplace/file` extended to read from R2
- Caching headers (immutable for versioned content, short TTL for latest)

### Test gate

- `_meta.json` with invalid schema → submission rejected with 400
- `GET /api/marketplace/docs` returns metadata for a manually uploaded app
- `POST /api/marketplace/file` retrieves markdown and image files from R2

---

## Phase 2: App Detail Page

**Effort**: Large | **Files**: ~4 new, ~2 modified

Create standalone `/marketplace/{developerId}/{appId}` page replacing the modal. Combines existing modal content (app metadata) with markdown documentation rendering.

### Key deliverables

- Standalone `AppDetailPage` component with header, content area
- `react-markdown` + `remark-gfm` for markdown rendering
- Custom components for image URL rewriting and internal link resolution
- App cards in marketplace grid become links (no more modal)
- Error handling: 404, unknown section redirect, missing docs fallback

### Test gate

- Clicking an app card navigates to `/marketplace/{developerId}/{appId}`
- App metadata (name, description, features, dependencies) displays in page header
- Markdown documentation renders with proper formatting, images, and links
- Back to marketplace navigation works

---

## Phase 3: Documentation Navigation

**Effort**: Medium | **Files**: ~3 new, ~2 modified

Build the sidebar, audience filter, version selector, and section routing.

### Key deliverables

- Sidebar built from `_meta.json` sections
- Audience filter toggle (All / Business / Technical)
- Version selector dropdown
- Routing: `/marketplace/{developerId}/{appId}[/v{version}][/{section}]`
- Changelog History aggregation page (built-in, fetches from all versions)

### Test gate

- Sidebar shows correct sections from `_meta.json`
- Audience filter hides/shows relevant sections
- Version selector navigates between versions
- Section URLs are bookmarkable and directly accessible

---

## Phase 4: Preview Mode

**Effort**: Medium | **Files**: ~2 new, ~2 modified

Let publishers preview staged documentation before promotion to production.

### Key deliverables

- Staging `versions.json` comparison to detect unreleased versions
- "Preview unreleased version" button (publisher-only)
- Preview cookie (scoped to app path)
- Staging bucket reads when preview active
- Preview banner with "Exit preview" button
- Access control (match session `developerId` to app owner)

### Test gate

- Publisher sees preview button when staging has newer version
- Preview mode shows staging content
- Non-publishers never see preview button
- "Exit preview" returns to production content

---

## Phase 5: SEO & Polish

**Effort**: Small | **Files**: ~2 modified

Meta tags, breadcrumbs, keyboard navigation, and caching headers.

### Key deliverables

- `document.title` and meta tags per app/section
- Breadcrumb navigation (Marketplace > Developer > App > Section)
- Keyboard navigation (arrow keys for sidebar)
- Caching headers on API responses (immutable for versioned, short TTL for latest)
- Direct URL access works (SPA fallback already configured)

### Test gate

- Page title reflects current app and section
- Breadcrumbs show correct hierarchy
- API responses include appropriate cache headers

---

## Phase 6: First-Party Docs

**Effort**: Medium | **Files**: ~20 new (markdown + assets)

Write actual documentation for Eldrin apps using this system. Validates the full publish → view cycle.

### Key deliverables

- Documentation for `eldrin-workflows` (overview, features, getting-started, usage, api, changelog)
- Documentation for `eldrin-invoicing` (overview, features, getting-started)
- Manual R2 upload and end-to-end validation
- Screenshots and diagrams in `assets/` directories

### Test gate

- Both apps' documentation renders correctly in the marketplace
- All images load properly
- Internal cross-references between docs pages work
- Version selector shows correct versions

---

## Reference

- **Requirements**: `docs/requirements/marketplace-app-docs.md`
- **eldrin-website source**: `eldrin-website/` (marketplace frontend + worker backend)
- **Current marketplace page**: `eldrin-website/src/pages/Marketplace/index.tsx`
- **Worker API**: `eldrin-website/worker/index.ts`
- **Submission handler**: `eldrin-website/worker/handlers/submission.ts`
