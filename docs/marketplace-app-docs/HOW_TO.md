# How To — Marketplace App Documentation Implementation

Quick-reference instructions for working with the marketplace app documentation implementation plan.

---

## Check Implementation Progress

### Quick Status

```bash
# See which phases are done
ls docs/marketplace-app-docs/phases/*/DONE.md 2>/dev/null

# See all phase statuses
grep -r "^## Status:" docs/marketplace-app-docs/phases/*/STATUS.md
```

### Phase Details

Each phase folder at `docs/marketplace-app-docs/phases/phase-NN-*/` contains:

| File | Purpose |
|------|---------|
| `PLAN.md` | Detailed implementation steps, file paths, test gates |
| `STATUS.md` | Progress tracking with checkboxes |
| `DONE.md` | Present only when phase is complete (with test results) |

### Implementation Order

```
Phase 1 → 2 → 3 → 4 → 5 → 6
```

MVP boundary: Phases 1–3 deliver a functional documentation system.

---

## Run the App Locally

```bash
# Navigate to the website project
cd eldrin-website

# Install dependencies
npm install

# Start dev server (Cloudflare Workers + Vite)
npm run dev

# Open in browser
open http://localhost:4100/marketplace
```

---

## Run Tests

```bash
# Type checking
cd eldrin-website && npx tsc -b

# Build check
cd eldrin-website && npm run build
```

---

## Add a New Phase

1. Create folder: `docs/marketplace-app-docs/phases/phase-NN-description/`
2. Create `PLAN.md` with: overview, dependencies, steps, test gate, files created/modified
3. Create `STATUS.md` with template:

```markdown
# Phase N: Title

## Status: not_started
## Started: -
## Completed: -

## Progress:
- [ ] Step N.1: Description
- [ ] Step N.2: Description

## Notes:
```

4. When complete, create `DONE.md`:

```markdown
# Phase N: Title — DONE

Completed: YYYY-MM-DD

## Summary
Brief description of what was accomplished.

## Verification
- `npx tsc -b` — clean
- `npm run build` — succeeds
```

---

## Master Plan Reference

The full implementation plan with all phase details:

`docs/marketplace-app-docs/marketplace-app-docs-plan.md`

The requirements document:

`docs/requirements/marketplace-app-docs.md`

The marketplace source code:

`eldrin-website/`
