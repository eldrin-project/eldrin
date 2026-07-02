# Phase 6: First-Party Docs

## Overview

Write actual documentation for Eldrin's first-party apps using the marketplace documentation system. This validates the full publish → view cycle and provides reference examples for third-party publishers.

## Dependencies

- Phase 5 (SEO & Polish — all frontend features complete)

## Steps

### 6.1 Write eldrin-workflows documentation

Create the following files under a `docs/` directory (to be uploaded to R2):

**`_meta.json`**:
```json
{
  "title": "Workflow Engine",
  "tagline": "Automate any business process with visual workflows",
  "icon": "workflow",
  "sections": {
    "overview": { "title": "Overview", "audience": "all" },
    "features": { "title": "Features", "audience": "all" },
    "getting-started": { "title": "Getting Started", "audience": "technical" },
    "usage": { "title": "Usage Guide", "audience": "all" },
    "api": { "title": "API Reference", "audience": "technical" },
    "changelog": { "title": "What's New", "audience": "all" }
  }
}
```

**Content files** (minimum 6):
- `overview.md` — What workflows does, key value propositions, architecture diagram
- `features.md` — Trigger types, step types, conditions, execution engine
- `getting-started.md` — Install, configure first workflow, test it
- `usage.md` — Day-to-day: creating workflows, monitoring runs, troubleshooting
- `api.md` — All REST endpoints with request/response examples
- `changelog.md` — v1.0.0 changes

**Screenshots** in `assets/`:
- `workflow-builder.png` — Visual builder screenshot
- `run-history.png` — Run history table
- `step-config.png` — Step configuration form

### 6.2 Write eldrin-invoicing documentation

Create minimal documentation set:

**`_meta.json`**:
```json
{
  "title": "Invoicing",
  "tagline": "Professional invoicing for small businesses",
  "icon": "receipt",
  "sections": {
    "overview": { "title": "Overview", "audience": "all" },
    "features": { "title": "Features", "audience": "all" },
    "getting-started": { "title": "Getting Started", "audience": "technical" }
  }
}
```

**Content files** (minimum 3):
- `overview.md` — What invoicing does, key features
- `features.md` — Client management, invoice templates, payment tracking
- `getting-started.md` — Install and create first invoice

### 6.3 Upload documentation to R2

Use `wrangler r2 object put` to upload files to the production R2 bucket:

```bash
# Upload versions.json
wrangler r2 object put eldrin-releases/eldrin.io/workflows/versions.json \
  --file ./docs-content/workflows/versions.json

# Upload docs files
wrangler r2 object put eldrin-releases/eldrin.io/workflows/v1.0.0/docs/_meta.json \
  --file ./docs-content/workflows/docs/_meta.json
wrangler r2 object put eldrin-releases/eldrin.io/workflows/v1.0.0/docs/overview.md \
  --file ./docs-content/workflows/docs/overview.md
# ... repeat for all files
```

### 6.4 Validate end-to-end

1. Navigate to `/marketplace/eldrin.io/workflows`
2. Verify all sections render correctly
3. Verify images load
4. Verify internal doc links work
5. Verify version selector shows correct versions
6. Verify audience filter hides/shows correct sections
7. Test direct URL access (e.g., `/marketplace/eldrin.io/workflows/getting-started`)
8. Repeat for invoicing

### 6.5 Create publisher documentation guide

Write a guide for third-party publishers explaining:
- Directory structure convention
- `_meta.json` format and fields
- Markdown conventions and image guidelines
- How to test documentation locally before submission

## Test Gate

Acceptance criteria:
1. Both apps' documentation renders correctly in the marketplace
2. All images load via the file API
3. Internal cross-references between doc pages work
4. Version selector functions correctly
5. Audience filter correctly categorizes sections
6. Direct URL access works for all section URLs

## Files Created

| File | Purpose |
|------|---------|
| `docs-content/workflows/versions.json` | Workflow versions manifest |
| `docs-content/workflows/docs/_meta.json` | Workflow documentation metadata |
| `docs-content/workflows/docs/overview.md` | Workflow overview |
| `docs-content/workflows/docs/features.md` | Workflow features |
| `docs-content/workflows/docs/getting-started.md` | Workflow quick start |
| `docs-content/workflows/docs/usage.md` | Workflow usage guide |
| `docs-content/workflows/docs/api.md` | Workflow API reference |
| `docs-content/workflows/docs/changelog.md` | Workflow v1.0.0 changes |
| `docs-content/invoicing/versions.json` | Invoicing versions manifest |
| `docs-content/invoicing/docs/_meta.json` | Invoicing documentation metadata |
| `docs-content/invoicing/docs/overview.md` | Invoicing overview |
| `docs-content/invoicing/docs/features.md` | Invoicing features |
| `docs-content/invoicing/docs/getting-started.md` | Invoicing quick start |

## Finalize

- [ ] Manual validation: Full end-to-end test of both apps' documentation
- [ ] Commit: `docs: add first-party documentation for workflows and invoicing`
- [ ] Update `STATUS.md` → complete, create `DONE.md`
