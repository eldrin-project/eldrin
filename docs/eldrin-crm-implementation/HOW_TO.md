# How To — eldrin-crm Implementation

Quick-reference instructions for working with the eldrin-crm implementation plan.

---

## Check Implementation Progress

### Quick Status

```bash
# See which super-phases are done
ls docs/eldrin-crm-implementation/*/DONE.md 2>/dev/null

# See super-phase statuses
grep -r "^## Status:" docs/eldrin-crm-implementation/*/STATUS.md

# See all sub-phase statuses (Phase 1 MVP)
grep -r "^## Status:" docs/eldrin-crm-implementation/01_core_crm_foundation_mvp/phases/*/STATUS.md

# See which sub-phases are done
ls docs/eldrin-crm-implementation/01_core_crm_foundation_mvp/phases/*/DONE.md 2>/dev/null
```

### Folder Structure

```
docs/eldrin-crm-implementation/
├── eldrin-crm-requirements.md          # Requirements (324 total)
├── eldrin-crm-plan.md                  # Master plan
├── HOW_TO.md                           # This file
│
├── 01_core_crm_foundation_mvp/         # Super Phase 1 (MVP)
│   ├── PLAN.md                         # MVP overview + architecture
│   ├── STATUS.md                       # Tracks all sub-phases
│   └── phases/
│       ├── phase-01-project-scaffolding/
│       │   ├── PLAN.md
│       │   └── STATUS.md
│       ├── phase-02-contact-company-management/
│       │   ├── PLAN.md
│       │   └── STATUS.md
│       └── ...                         # phase-03 through phase-11
│
├── 02_sales_automation_productivity/   # Super Phase 2
│   ├── PLAN.md
│   └── STATUS.md
│
└── (03–08 created when Phase 2 nears completion)
```

Each sub-phase folder contains:

| File | Purpose |
|------|---------|
| `PLAN.md` | Detailed implementation steps, file paths, test gates |
| `STATUS.md` | Progress tracking with checkboxes |
| `DONE.md` | Present only when phase is complete (with test results) |

### Implementation Order

**Super Phase 1 — Core CRM Foundation (MVP):**
```
01 → 02 → 03 → 04 → 05 → 06 → 07 → 08 → 09 → 10 → 11
```

MVP boundary: Sub-phases 01–09 deliver a functional CRM. Sub-phases 10–11 add the differentiators.

**Super Phase 2 — Sales Automation & Productivity:**
```
01 → 02 → 03 → 04 → 05 → 06 → 07 → 08 → 09 → 10
```

### Finding the Next Task

1. Check `01_core_crm_foundation_mvp/STATUS.md` for overall MVP progress
2. Find the first sub-phase where `STATUS.md` shows `Status: not_started` or `in_progress`
3. Read that sub-phase's `PLAN.md` for implementation details
4. Update `STATUS.md` as you work (check off steps, add notes)
5. Create `DONE.md` when all tests pass and the phase gate is met
6. Update the super-phase `STATUS.md` to reflect the completed sub-phase

---

## Run the App Locally

```bash
# Navigate to the CRM app
cd eldrin-crm

# Install dependencies
npm install

# Generate migration TypeScript module
npm run generate:migrations

# Start dev server (Cloudflare Workers + Vite)
npm run dev

# Or run with shell integration (start eldrin-core first)
cd ../eldrin-core && npm run dev    # Shell on port 5173
cd ../eldrin-crm && npm run dev     # App on its port
```

### With Docker (PostgreSQL)

```bash
# Start PostgreSQL via eldrin-core docker-compose
cd eldrin-core && docker compose up -d postgres

# Set DATABASE_URL for standalone mode
export DATABASE_URL="postgresql://eldrin:eldrin@localhost:5432/eldrin"
cd eldrin-crm && npm run dev
```

---

## Run Tests

```bash
# Unit tests
cd eldrin-crm && npx vitest run

# Type checking
cd eldrin-crm && npx tsc -b

# Build check
cd eldrin-crm && npm run build
```

---

## Add a New Sub-Phase

1. Create folder inside the super-phase: `NN_super_phase/phases/phase-NN-description/`
2. Create `PLAN.md` with: overview, dependencies, steps, test gate, files created/modified
3. Create `STATUS.md` with template:

```markdown
# Sub-Phase NN: Title

## Status: not_started
## Started: -
## Completed: -

## Progress:
- [ ] Step NN.1: Description
- [ ] Step NN.2: Description

## Notes:
```

4. When complete, create `DONE.md`:

```markdown
# Sub-Phase NN: Title — DONE

Completed: YYYY-MM-DD

## Summary
Brief description of what was accomplished.

## Verification
- `npx tsc -b` — clean
- `npx vitest run` — X/X tests pass
```

5. Update the super-phase `STATUS.md` to mark the sub-phase as complete.

---

## Add a New Super-Phase

1. Create folder: `docs/eldrin-crm-implementation/NN_description/`
2. Create `PLAN.md` with: overview, sub-phase list, architecture notes
3. Create `STATUS.md` tracking all sub-phases
4. Create `phases/` directory with sub-phase folders
5. Update `eldrin-crm-plan.md` to reference the new super-phase

---

## Master Plan Reference

The full implementation plan with all super-phase details:

`docs/eldrin-crm-implementation/eldrin-crm-plan.md`

The requirements document:

`docs/eldrin-crm-implementation/eldrin-crm-requirements.md`

The eldrin-workflows reference implementation:

`eldrin-workflows/`
