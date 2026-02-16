# Marketplace App Documentation — Requirements

## Problem

Extension app documentation currently links to `docs.eldrin.io/apps/{appId}`, which is the **developer documentation site** (SDK guides, API reference). This is the wrong audience — marketplace visitors are business decision-makers, IT administrators, and end users who need product information, setup guides, and usage instructions.

App documentation should live **in the marketplace itself**, be **versioned alongside releases**, and serve **both business and technical audiences**.

## Goals

1. Documentation is a first-class part of the publishing process — submitted alongside code
2. Each version ships its own documentation snapshot (immutable per version)
3. The marketplace renders documentation inline (no external redirects)
4. Publishers control content structure via a simple markdown convention
5. Documentation supports both business audiences (pricing, features, use cases) and technical audiences (setup, configuration, API, troubleshooting)

## Non-Goals

- WYSIWYG documentation editor in the marketplace UI (publishers author locally)
- Auto-generated API documentation from manifest (possible future enhancement)
- Documentation translation/i18n (deferred)
- Documentation search across apps (deferred — per-app search only via Cmd+K)

---

## Documentation Structure

### Convention: `docs/` directory in app release

Publishers include a `docs/` directory in their submission. The structure follows a **fixed-name convention** — the marketplace knows how to render each file by its filename, not by configuration.

```
{appId}/
├── eldrin-app.manifest.json
├── bundle.js
├── migrations/
└── docs/
    ├── _meta.json              # Documentation metadata (required)
    │
    │── overview.md             # Product overview — the "landing page"
    │── features.md             # Feature list with descriptions
    │── pricing.md              # Plans, pricing tiers, feature comparison
    │── changelog.md            # Changes in this version only
    │
    │── getting-started.md      # Quick start / onboarding guide
    │── configuration.md        # Settings, environment variables, options
    │── usage.md                # Day-to-day usage guide
    │
    │── api.md                  # API reference (endpoints, payloads)
    │── permissions.md          # Required permissions and roles
    │── integrations.md         # How this app integrates with others
    │── troubleshooting.md      # Common issues and solutions
    │
    └── assets/                 # Images, diagrams referenced in markdown
        ├── screenshot-dashboard.png
        ├── architecture.svg
        └── ...
```

### `_meta.json` — Documentation Metadata

```json
{
  "title": "Workflow Engine",
  "tagline": "Automate any business process with visual workflows",
  "icon": "workflow",
  "sections": {
    "overview": { "title": "Overview", "audience": "all" },
    "features": { "title": "Features", "audience": "all" },
    "pricing": { "title": "Pricing", "audience": "business" },
    "changelog": { "title": "What's New", "audience": "all" },
    "getting-started": { "title": "Getting Started", "audience": "technical" },
    "configuration": { "title": "Configuration", "audience": "technical" },
    "usage": { "title": "Usage Guide", "audience": "all" },
    "api": { "title": "API Reference", "audience": "technical" },
    "permissions": { "title": "Permissions", "audience": "technical" },
    "integrations": { "title": "Integrations", "audience": "all" },
    "troubleshooting": { "title": "Troubleshooting", "audience": "technical" }
  }
}
```

**Rules:**
- `_meta.json` is **required** if a `docs/` directory is present
- Only files listed in `sections` are rendered; extra `.md` files are ignored
- `audience` is a hint for UI filtering (e.g., "Show technical docs" toggle)
- Section order in the JSON determines navigation order
- All section keys are optional — publishers include only what applies

### Markdown Conventions

- Standard GitHub-Flavored Markdown (GFM)
- Image references use relative paths: `![Dashboard](assets/screenshot-dashboard.png)`
- Internal cross-references between docs pages: `[See Configuration](configuration.md)`
- Frontmatter is **not used** — metadata lives in `_meta.json`
- No custom components or MDX — pure markdown for portability

**Link resolution at render time**: Both image paths and internal doc links are rewritten by the frontend before rendering. A custom `react-markdown` components config handles both:
- `assets/screenshot.png` → `/api/marketplace/file?...&path=docs/assets/screenshot.png`
- `configuration.md` → `/marketplace/{developerId}/{appId}[/v{version}]/configuration`

External links (`https://...`) are left unchanged and open in a new tab.

---

## Publishing Process Changes

### Submission Handler (`POST /api/apps/submit`)

The existing submission handler processes files by path. Documentation files follow the same flow:

1. **Validation**: If `docs/` directory is present, `docs/_meta.json` must exist and be valid JSON
2. **Asset size limits**: Individual images max 2 MB, total `docs/assets/` max 20 MB
3. **Markdown validation**: Files listed in `_meta.json` sections must exist in `docs/`
4. **Storage**: Files are uploaded to R2 under the key prefix `{developerId}/{appId}/v{version}/docs/`

### Storage: Cloudflare R2 Buckets

Release artifacts (app bundles, migrations, and documentation) are stored in Cloudflare R2 using the S3-compatible API.

**Two-stage release pipeline:**

| Bucket | Purpose | URL |
|--------|---------|-----|
| `eldrin-releases-staging` | Submissions land here for validation/review | `https://<ACCOUNT_ID>.r2.cloudflarestorage.com/eldrin-releases-staging` |
| `eldrin-releases` | Validated releases promoted to production | `https://<ACCOUNT_ID>.r2.cloudflarestorage.com/eldrin-releases` |

**Flow**: Submit → staging bucket → review/validate → promote to prod bucket

> **Note**: Migrating the submission handler to use R2 instead of the GitHub repo is out of scope for this document. For initial testing, files will be manually uploaded to the R2 buckets.

### R2 Object Key Structure

```
eldrin-releases[-staging]/
└── eldrin.io/
    └── workflows/
        ├── versions.json
        ├── migrations/
        │   └── index.json
        ├── v1.0.0/
        │   ├── eldrin-app.manifest.json
        │   ├── bundle.enc.js
        │   ├── meta.json
        │   └── docs/
        │       ├── _meta.json
        │       ├── overview.md
        │       ├── features.md
        │       ├── getting-started.md
        │       ├── usage.md
        │       ├── changelog.md
        │       └── assets/
        │           └── workflow-builder.png
        └── v1.1.0/
            └── docs/
                └── ...   # Each version has its own snapshot
```

**Example R2 keys:**
- `eldrin.io/workflows/versions.json`
- `eldrin.io/workflows/v1.0.0/docs/_meta.json`
- `eldrin.io/workflows/v1.0.0/docs/overview.md`
- `eldrin.io/workflows/v1.0.0/docs/assets/workflow-builder.png`

### Version Manifest Extension

`versions.json` gains a `docs` flag per version:

```json
{
  "latest": "1.1.0",
  "versions": [
    {
      "version": "1.1.0",
      "releaseDate": "2026-02-14",
      "docs": true,
      "changes": { "features": ["..."], "fixes": [], "breaking": [] }
    },
    {
      "version": "1.0.0",
      "releaseDate": "2026-01-15",
      "docs": true,
      "changes": { "features": ["..."], "fixes": [], "breaking": [] }
    }
  ]
}
```

---

## Marketplace Frontend Changes

### App Detail Page (replaces modal)

The current app detail modal is replaced by a **standalone page** at `/marketplace/{developerId}/{appId}`. This page combines the existing modal content (description, features, dependencies, pricing) with the full documentation — giving publishers a proper product page.

#### Page Layout

```
┌─────────────────────────────────────────────────────┐
│  ← Back to Marketplace          Version: v1.1.0 ▼  │
├─────────────────────────────────────────────────────┤
│                                                     │
│  [Icon]  Workflow Engine                            │
│  by Eldrin Team · v1.1.0 · Updated Feb 2026         │
│  "Automate any business process with visual..."     │
│                                                     │
│  [Get Started]  [View Source]                        │
│                                                     │
├──────────┬──────────────────────────────────────────┤
│ Sidebar  │  Content area                            │
│          │                                          │
│ Overview │  (renders selected section as markdown)  │
│ Features │                                          │
│ Pricing  │                                          │
│ ──────── │                                          │
│ Getting  │                                          │
│  Started │                                          │
│ Config   │                                          │
│ Usage    │                                          │
│ ──────── │                                          │
│ API Ref  │                                          │
│ Perms    │                                          │
│ Integr.  │                                          │
│ Trouble  │                                          │
│ ──────── │                                          │
│ Changelog│                                          │
│ Changelog│                                          │
│  History │  (built-in, aggregates all versions)      │
│          │                                          │
│ Audience │                                          │
│ [All|Biz │                                          │
│  |Tech]  │                                          │
└──────────┴──────────────────────────────────────────┘
```

#### Page Sections

1. **Header**: App icon, name, developer, version, tagline (from `_meta.json`), action buttons
2. **Sidebar**: Navigation built from `_meta.json` sections, grouped by audience. Audience filter at the bottom toggles which sections are visible
3. **Content area**: Renders the selected markdown section. Markdown is rendered client-side (`react-markdown` + `remark-gfm`)
4. **App metadata**: Domain, dependencies, hooks, events — the info currently in the modal — displayed either in the header area or as a dedicated "Overview" section

#### App Card in Marketplace Grid

The marketplace grid cards change behavior:
- **Click** → navigates to `/marketplace/{developerId}/{appId}` (the standalone page)
- No more modal — the card is a link

### Routes

```
/marketplace                                              → app grid (existing)
/marketplace/{developerId}/{appId}                        → latest version, overview
/marketplace/{developerId}/{appId}/v1.0.0                 → specific version, overview
/marketplace/{developerId}/{appId}/getting-started        → latest version, specific section
/marketplace/{developerId}/{appId}/v1.0.0/getting-started → specific version, specific section
/marketplace/{developerId}/{appId}/changelog-history      → dynamic aggregated changelog (all versions)
```

Pattern: `/marketplace/{developerId}/{appId}[/v{version}][/{section}]`

The `v` prefix distinguishes version segments from section segments (no section name starts with `v` followed by digits).

`changelog-history` is a reserved section name — it's a built-in page rendered by the marketplace (not from a markdown file). It fetches `changelog.md` from every version and renders them aggregated.

### Error Handling

- **Unknown app or developer**: `/marketplace/unknown.io/foo` → 404 page with "App not found" and link back to marketplace grid
- **Unknown section**: `/marketplace/eldrin.io/workflows/nonexistent` → redirect to the app's overview page
- **Unknown version**: `/marketplace/eldrin.io/workflows/v99.0.0` → redirect to latest version, same section
- **Missing docs**: If an app has no `docs/` directory, the detail page shows the app metadata (from manifest) with a "No documentation available" message in the content area

### Version Selector

A dropdown in the page header shows all versions that have `docs: true`. Defaults to latest. Selecting a version navigates to `/marketplace/{developerId}/{appId}/v{version}[/{currentSection}]`, preserving the active section.

---

## Marketplace API Changes

### New Endpoint: `GET /api/marketplace/docs`

Fetches `_meta.json` and `versions.json` from the R2 prod bucket to render the documentation sidebar and version selector.

```
GET /api/marketplace/docs?developerId=eldrin.io&appId=workflows&version=1.0.0

Response:
{
  "meta": { ... },                    // _meta.json contents
  "availableVersions": ["1.1.0", "1.0.0"]
}
```

### Existing Endpoint Extension: `POST /api/marketplace/file`

Currently fetches files from the GitHub marketplace-dist repo. This will be migrated to fetch from the R2 prod bucket instead. Documentation pages and assets use this same endpoint:

```json
{
  "developerId": "eldrin.io",
  "appId": "workflows",
  "version": "1.0.0",
  "path": "docs/overview.md"
}
```

**Backend resolves to R2 key**: `eldrin.io/workflows/v1.0.0/docs/overview.md`

For image assets, the endpoint streams the binary response with appropriate `Content-Type` headers (e.g., `image/png`, `image/svg+xml`).

### Caching

Documentation is immutable per version — once a version is promoted to prod, its files never change. This allows aggressive caching:

- **Versioned content** (e.g., `/v1.0.0/docs/overview.md`): `Cache-Control: public, max-age=31536000, immutable` (1 year)
- **Latest-version content** (no version in URL): `Cache-Control: public, max-age=300` (5 minutes — may change when a new version is published)
- **`versions.json`**: `Cache-Control: public, max-age=60` (1 minute — updated on each release)
- **Preview/staging content**: `Cache-Control: no-store` (never cache, content may change at any time)

### Image URL Resolution

Markdown files reference images with relative paths (`![alt](assets/screenshot.png)`). The frontend must rewrite these paths at render time before passing to `react-markdown`. A custom `img` component (or remark plugin) transforms relative `src` values into API calls:

```
assets/screenshot.png
  → /api/marketplace/file?developerId=eldrin.io&appId=workflows&version=1.0.0&path=docs/assets/screenshot.png
```

### R2 Bucket Binding

The marketplace Worker needs R2 bindings in its `wrangler.jsonc`:

```jsonc
{
  "r2_buckets": [
    { "binding": "RELEASES_BUCKET", "bucket_name": "eldrin-releases" },
    { "binding": "RELEASES_STAGING_BUCKET", "bucket_name": "eldrin-releases-staging" }
  ]
}
```

API handlers use the binding directly (`env.RELEASES_BUCKET.get(key)`) — no S3 SDK needed.

### Preview Mode

Preview mode lets publishers see their staged documentation before promoting to production.

**Visibility**: When a logged-in publisher views their own app's detail page, the marketplace fetches `versions.json` from both the prod and staging buckets. If the staging bucket contains a version newer than the latest published version, a **"Preview unreleased version"** button appears in the page header (next to the version selector). The staging bucket maintains its own `versions.json` — submissions update it when files land in staging.

**Activation**: Clicking the button sets a `preview=true` cookie scoped to that app's path. While the cookie is active:
- All API calls for that app read from `RELEASES_STAGING_BUCKET` instead of `RELEASES_BUCKET`
- A persistent banner is shown: "Preview mode — viewing unreleased version" with a **"Exit preview"** button
- The version selector shows the staged version(s) alongside published ones

**Deactivation**: Clicking "Exit preview" clears the cookie and reloads the page with production content.

**Access control**: Preview mode is only available to the **logged-in publisher who owns the app** (verified by matching the session's `developerId` against the app's `developerId`). Other visitors never see the preview button or staged content.

---

## Content Guidelines for Publishers

### Required Sections (minimum viable documentation)

| Section | Purpose | Audience |
|---------|---------|----------|
| `overview.md` | What the app does, key value propositions, screenshots | All |
| `getting-started.md` | Installation and initial setup steps | Technical |

### Recommended Sections

| Section | Purpose | Audience |
|---------|---------|----------|
| `features.md` | Detailed feature descriptions with screenshots | All |
| `pricing.md` | Plans, tiers, feature comparison table | Business |
| `usage.md` | Day-to-day workflows and how-to guides | All |
| `configuration.md` | Settings reference, environment variables | Technical |
| `changelog.md` | Changes in this version (new features, fixes, breaking changes) | All |

### Optional Sections

| Section | Purpose | Audience |
|---------|---------|----------|
| `api.md` | REST API endpoints, request/response examples | Technical |
| `permissions.md` | Required roles and permission breakdown | Technical |
| `integrations.md` | How the app connects with other Eldrin apps | All |
| `troubleshooting.md` | FAQs, common errors, debug steps | Technical |

### Image Guidelines

- Screenshots: 1200px wide max, PNG or WebP preferred
- Diagrams: SVG preferred for scalability
- File names: kebab-case, descriptive (`workflow-builder-screenshot.png`)
- Alt text: Required for accessibility (`![Workflow builder showing a 3-step automation](assets/workflow-builder.png)`)

---

## Implementation Phases

### Phase 1: Structure & Submission
- Define `docs/` directory convention and `_meta.json` schema
- Add docs validation to the submission handler (validate `_meta.json`, check file existence, enforce size limits)
- Add `docs` flag to `versions.json`
- For initial testing: manually upload docs to R2 buckets (full R2 submission migration is out of scope)

### Phase 2: App Detail Page
- Create standalone `/marketplace/{developerId}/{appId}` page with header, sidebar, content layout
- Move existing modal content (description, domain, features, dependencies, events) into the page header/overview
- Replace modal trigger on marketplace grid cards with a link to the detail page
- Implement markdown rendering with image support (`react-markdown` + `remark-gfm`)

### Phase 3: Documentation Navigation
- Build sidebar from `_meta.json` sections
- Add audience filter toggle (All / Business / Technical)
- Add version selector dropdown
- Implement `/marketplace/{developerId}/{appId}[/v{version}][/{section}]` routing

### Phase 4: Preview Mode
- Implement staging `versions.json` comparison to detect unreleased versions
- Add "Preview unreleased version" button for logged-in app owners
- Implement preview cookie, staging bucket reads, and "Exit preview" flow
- Add preview banner UI

### Phase 5: SEO & Polish
- Add meta tags (title, description, og:image) per app/section
- Ensure direct URL access works (SSR or prerender for crawlers)
- Add breadcrumbs and keyboard navigation
- Configure caching headers (immutable for versioned content, short TTL for latest)

### Phase 6: First-Party Docs
- Write documentation for eldrin-workflows using this system
- Write documentation for eldrin-invoicing
- Validate the full publish → view cycle

---

## Decisions

1. **Changelog**: Each version ships its own `changelog.md` describing only that version's changes. The marketplace automatically provides a "Changelog History" page (by convention, not configured in `_meta.json`) that fetches `changelog.md` from every version in `versions.json` and renders them in reverse chronological order, each under a version heading. The sidebar always shows this entry when multiple versions exist. Publishers only maintain a single `changelog.md` per release — the aggregation happens at render time.

2. **Draft/preview**: Publishers can preview documentation before publishing. The staging bucket (`eldrin-releases-staging`) serves as the preview environment — submissions land there first, and the marketplace exposes a preview mode that reads from staging instead of prod. This lets publishers see their docs rendered exactly as they'll appear before promoting to production.

3. **Custom sections**: Fixed set only for now. Publishers use the predefined section names (`overview.md`, `features.md`, etc.). Custom section support may be added later based on publisher feedback.
