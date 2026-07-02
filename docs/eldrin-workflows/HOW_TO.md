# How To — eldrin-workflows Implementation

Quick-reference instructions for working with the eldrin-workflows implementation plan.

---

## Check Implementation Progress

### Quick Status

```bash
# See which phases are done
ls docs/eldrin-workflows/phases/*/DONE.md 2>/dev/null

# See all phase statuses
grep -r "^## Status:" docs/eldrin-workflows/phases/*/STATUS.md
```

### Phase Details

Each phase folder at `docs/eldrin-workflows/phases/phase-NN-*/` contains:

| File | Purpose |
|------|---------|
| `PLAN.md` | Detailed implementation steps, file paths, test gates |
| `STATUS.md` | Progress tracking with checkboxes |
| `DONE.md` | Present only when phase is complete (with test results) |

### Implementation Order

```
Phase 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11
```

MVP boundary: Phases 1–7 deliver a functional workflow engine with JSON-based editing.

---

## Run the App Locally

```bash
# Navigate to the workflows app
cd eldrin-workflows

# Install dependencies
npm install

# Generate migration TypeScript module
npm run generate:migrations

# Start dev server (Cloudflare Workers + Vite)
npm run dev

# Or run with shell integration (start eldrin-core first)
cd ../eldrin-core && npm run dev    # Shell on port 5173
cd ../eldrin-workflows && npm run dev  # App on its port
```

### With Docker (PostgreSQL)

```bash
# Start PostgreSQL via eldrin-core docker-compose
cd eldrin-core && docker compose up -d postgres

# Set DATABASE_URL for standalone mode
export DATABASE_URL="postgresql://eldrin:eldrin@localhost:5432/eldrin"
cd eldrin-workflows && npm run dev
```

---

## Run Tests

```bash
# Unit tests
cd eldrin-workflows && npx vitest run

# Type checking
cd eldrin-workflows && npx tsc -b

# Build check
cd eldrin-workflows && npm run build
```

---

## Add a New Phase

1. Create folder: `docs/eldrin-workflows/phases/phase-NN-description/`
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
- `npx vitest run` — X/X tests pass
```

---

## Master Plan Reference

The full implementation plan with all phase details:

`docs/eldrin-workflows/eldrin-workflows-plan.md`

The requirements document:

`docs/requirements/eldrin-workflows.md`

The react-todo reference implementation (current extension app pattern):

`react-todo/`
