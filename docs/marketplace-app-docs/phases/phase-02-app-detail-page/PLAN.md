# Phase 2: App Detail Page

## Overview

Replace the current app detail modal with a standalone page at `/marketplace/{developerId}/{appId}`. This page combines existing modal content (app name, description, features, dependencies, hooks, events) with a content area for rendering markdown documentation.

The page has two main zones: a **header** with app metadata and action buttons, and a **content area** that renders the selected documentation section. In this phase, the content area renders a single section (overview by default); sidebar navigation comes in Phase 3.

## Dependencies

- Phase 1 (R2 API endpoints for fetching documentation)

## Steps

### 2.1 Install markdown rendering dependencies

```bash
cd eldrin-website && npm install react-markdown remark-gfm
```

### 2.2 Create AppDetailPage component

Create `eldrin-website/src/pages/Marketplace/AppDetailPage.tsx`:

**Page layout** (top to bottom):
1. **Top bar**: "Back to Marketplace" link + version badge
2. **App header**: Icon, app name, developer ID, version, tagline (from `_meta.json`), description
3. **Action buttons**: "Get Started" (→ `/setup`), "View Source" (if applicable)
4. **Metadata grid**: Domain, dependencies, features (from hardcoded APPS data)
5. **Content area**: Renders markdown documentation (or "No documentation available" fallback)

**Data fetching**:
- App metadata: From the existing hardcoded `APPS` array (matched by `appId`)
- Documentation metadata: `GET /api/marketplace/docs?developerId=X&appId=Y`
- Documentation content: `POST /api/marketplace/file` with `{ path: "docs/overview.md", ... }`

**States**:
- Loading: Skeleton UI while fetching docs
- Loaded: Renders markdown content
- No docs: Shows app metadata with "No documentation available" message
- Error/404: Shows "App not found" with link back to marketplace

### 2.3 Create markdown rendering component

Create `eldrin-website/src/pages/Marketplace/MarkdownRenderer.tsx`:

A wrapper around `react-markdown` + `remark-gfm` with custom component overrides:

**Image resolution**: Custom `img` component that rewrites relative `src` paths:
```
assets/screenshot.png
  → /api/marketplace/file?developerId=X&appId=Y&version=Z&path=docs/assets/screenshot.png
```

**Link resolution**: Custom `a` component that handles:
- Internal doc links (`configuration.md` → `/marketplace/{developerId}/{appId}[/v{version}]/configuration`)
- External links (`https://...`) → open in new tab with `target="_blank" rel="noopener"`

**Styling**: Apply typography styles to rendered markdown:
- Headings: `font-heading` (JetBrains Mono), appropriate sizes, `ink-100` color
- Paragraphs: `font-body` (IBM Plex Sans), `ink-300` color, `leading-relaxed`
- Code blocks: `font-mono`, `bg-ink-900` background, syntax highlighting (optional)
- Tables: `ink-700` borders, `ink-800` header background
- Lists: Proper indentation and bullet styling
- Blockquotes: `electric-500` left border accent
- Horizontal rules: `ink-700` color

### 2.4 Add routes to main.tsx

In `eldrin-website/src/main.tsx`, add new routes:

```tsx
<Route path="/marketplace/:developerId/:appId/*" element={<AppDetailPage />} />
```

This catches all sub-paths (version, section) — the component itself parses the URL.

### 2.5 Update AppCard to navigate instead of opening modal

In `eldrin-website/src/pages/Marketplace/index.tsx`:

1. Change `AppCard` click handler from `setSelectedApp(app)` to `navigate(`/marketplace/eldrin.io/${app.id}`)`
   - Note: `developerId` is hardcoded as `eldrin.io` for now since all apps are first-party
2. Import `useNavigate` from `react-router-dom`
3. Remove the `selectedApp` state and `AppDetailModal` component (or keep modal as fallback for apps without docs — decision needed)

### 2.6 Handle error cases

In `AppDetailPage`:
- **Unknown app**: If `appId` doesn't match any app in the `APPS` array, show a 404-style page with "App not found" and a link back to `/marketplace`
- **Missing docs**: If `GET /api/marketplace/docs` returns `meta: null`, show app metadata with a "No documentation available yet" message in the content area
- **API errors**: Show a retry button with error message

### 2.7 Style the page to match Refined Industrial theme

Apply the existing design system:
- Use `grain` overlay, `glass` effects, `bg-grid` backgrounds
- Match the color palette: `ink-*` for text, `electric-*` for accents
- Use `font-display`, `font-heading`, `font-body` for typography
- Add Framer Motion animations for page transitions and content loading
- Responsive layout: single column on mobile, full layout on desktop

## Test Gate

```bash
cd eldrin-website && npx tsc -b              # TypeScript compiles
cd eldrin-website && npm run build            # Build succeeds
```

Acceptance criteria:
1. Clicking an app card in the marketplace grid navigates to `/marketplace/eldrin.io/{appId}`
2. App detail page shows app metadata (name, description, features, dependencies)
3. If docs are available (R2), markdown renders with proper formatting
4. If no docs, shows "No documentation available" fallback
5. "Back to Marketplace" link works
6. Images in markdown render via the file API
7. External links open in new tab
8. Page matches the Refined Industrial design theme

## Files Created

| File | Purpose |
|------|---------|
| `src/pages/Marketplace/AppDetailPage.tsx` | Standalone app detail page |
| `src/pages/Marketplace/MarkdownRenderer.tsx` | react-markdown wrapper with custom components |

## Files Modified

| File | Change |
|------|--------|
| `src/main.tsx` | Add `/marketplace/:developerId/:appId/*` route |
| `src/pages/Marketplace/index.tsx` | Change AppCard to navigate, remove modal |
| `package.json` | Add `react-markdown`, `remark-gfm` dependencies |

## Finalize

- [ ] Manual validation: Navigate to app detail page, verify markdown rendering, test all states
- [ ] Commit: `feat: add standalone app detail page with markdown documentation`
- [ ] Update `STATUS.md` → complete, create `DONE.md`
