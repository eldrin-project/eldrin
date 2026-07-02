# How To — Eldrin Feature Development

Quick-reference instructions for working with the feature roadmap.

---

## Check Implementation Progress

### Quick Status

```bash
# See which features are done
ls docs/features/phases/*/DONE.md 2>/dev/null

# See all feature statuses
grep -r "^## Status:" docs/features/phases/*/STATUS.md
```

### Feature Details

Each feature folder at `docs/features/phases/feature-NN-*/` contains:

| File | Purpose |
|------|---------|
| `PLAN.md` | Detailed implementation steps, file paths, test gates |
| `STATUS.md` | Progress tracking with checkboxes |
| `DONE.md` | Present only when feature is complete (with test results) |

### Implementation Order

```
Feature 1 (Dark Mode) → 2 (Localization) → 3 (User Profile) → 4 (User Invitations) → 5 (Two-Factor Auth) → 6 (Webhooks) → 7 (Global Search) → 8 (Workflow Engine)
```

---

## Add a New Feature

1. Create folder: `docs/features/phases/feature-NN-description/`
2. Create `PLAN.md` with: overview, dependencies, steps, test gate, files created/modified
3. Create `STATUS.md` with template:

```markdown
# Feature N: Title

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
# Feature N: Title — COMPLETE

Completed: YYYY-MM-DD
Test results: X/X unit tests, Y/Y E2E tests
```

---

## Run Tests

```bash
# eldrin-core unit tests
cd eldrin-core && npx vitest run

# Type checking
cd eldrin-core && npx tsc -b

# E2E tests
cd eldrin-core && npx playwright test
```

---

## Master Plan Reference

The full feature roadmap with all technical details:

`docs/features/eldrin-core-features.md`

The multi-cloud infrastructure plan (complete):

`docs/multiplatform-implementation/eldrin-core-multi-cloud.md`
