# How To — Template Projects Migration

Quick-reference instructions for working with the migration roadmap.

---

## Check Implementation Progress

### Quick Status

```bash
# See which phases are done
ls docs/template-projects-migration/phases/*/DONE.md 2>/dev/null

# See all phase statuses
grep -r "^## Status:" docs/template-projects-migration/phases/*/STATUS.md
```

### Phase Details

Each phase folder at `docs/template-projects-migration/phases/phase-NN-*/` contains:

| File | Purpose |
|------|---------|
| `PLAN.md` | Detailed implementation steps, file paths, test gates |
| `STATUS.md` | Progress tracking with checkboxes |
| `DONE.md` | Present only when phase is complete (with test results) |

### Implementation Order

```
Phase 0 → 1 → 2 → 3 → 4 → 5 → 6 → 7
```

---

## Run Extension Apps

```bash
# From parent repo
npm run dev:react      # port 4004
npm run dev:angular    # port 4005
npm run dev:vue        # port 4006
npm run dev:svelte     # port 4007
```

## Build Extension Apps

```bash
npm run build:react
npm run build:angular
npm run build:vue
npm run build:svelte

# Or all at once
npm run build:all
```

---

## Master Plan Reference

The full migration plan with all technical details:

`docs/template-projects-migration/master-plan.md`
