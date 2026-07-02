# Phase 6: Frontend — Workflow Management

## Overview

Build the core management UI: workflow list with status toggles, run history table, and run detail inspector. These are read-heavy pages that display data from the API built in Phases 3–5.

## Dependencies

- Phase 5 (triggers — full backend API available)
- Phase 1 (frontend shell — single-spa entry, root component, daisyUI theme)

## Steps

### 6.1 Set up client-side routing

Update **`src/root.component.tsx`**:

Implement simple pathname-based routing (same pattern as react-todo) or use a lightweight router. Routes:
- `/eldrin-workflows/workflows` — workflow list
- `/eldrin-workflows/workflows/new` — create (Phase 7)
- `/eldrin-workflows/workflows/:id` — workflow detail / run history
- `/eldrin-workflows/workflows/:id/edit` — edit (Phase 7)
- `/eldrin-workflows/workflows/:id/runs/:runId` — run detail

### 6.2 Create API client

Create **`src/api.ts`**:

Centralized API functions using `fetch` + `useAuthHeaders()`:
- `getWorkflows(params)` — list with pagination/filter
- `getWorkflow(id)` — get single workflow
- `activateWorkflow(id)` / `deactivateWorkflow(id)` — toggle
- `deleteWorkflow(id)` — delete
- `triggerWorkflow(id)` — manual trigger
- `getWorkflowRuns(workflowId, params)` — list runs
- `getRun(runId)` — run detail with steps

### 6.3 Build workflow list page

Create **`src/pages/WorkflowList.tsx`**:

- Table with columns: name, trigger type, status (active/inactive toggle), last run (status badge + timestamp), actions (edit, run, delete)
- Search input (filters by name)
- "New Workflow" button → `/workflows/new`
- daisyUI components: table, toggle, badge, btn, dropdown
- Empty state when no workflows exist
- Loading skeleton during fetch

### 6.4 Build run history page

Create **`src/pages/WorkflowDetail.tsx`**:

- Workflow header: name, description, status toggle, edit/delete/run buttons
- Run history table: status badge (pending/running/completed/failed/cancelled), trigger type, started at, duration, step count
- Pagination
- Click row → navigate to run detail

### 6.5 Build run detail page

Create **`src/pages/RunDetail.tsx`**:

- Run header: workflow name, status badge, trigger type, timestamps
- Step timeline: vertical list of steps, each showing:
  - Step index, name, type, status badge
  - Duration
  - Expandable section: input JSON, output JSON (or error)
- Cancel button (if status is 'running')

### 6.6 Create shared components

Create reusable components in **`src/components/`**:
- `StatusBadge.tsx` — maps status strings to daisyUI badge variants
- `Pagination.tsx` — page navigation controls
- `EmptyState.tsx` — placeholder for empty lists
- `ConfirmDialog.tsx` — daisyUI modal for delete confirmations

## Test Gate

```bash
cd eldrin-workflows && npm run dev
# Navigate to workflow list, create workflows via API, verify UI
```

Acceptance criteria:
1. Workflow list displays all workflows with correct data
2. Status toggle calls activate/deactivate API
3. Run history shows runs for selected workflow
4. Run detail shows step-by-step timeline with expandable data
5. Delete shows confirmation dialog, then removes workflow
6. "Run now" triggers workflow and shows new run in history
7. Dark mode works correctly on all pages
8. Empty states display when no data

## Files Created

| File | Purpose |
|------|---------|
| `src/pages/WorkflowList.tsx` | Workflow list with table and actions |
| `src/pages/WorkflowDetail.tsx` | Workflow detail + run history |
| `src/pages/RunDetail.tsx` | Run step-by-step inspector |
| `src/api.ts` | API client functions |
| `src/components/StatusBadge.tsx` | Status → badge mapping |
| `src/components/Pagination.tsx` | Page navigation |
| `src/components/EmptyState.tsx` | Empty list placeholder |
| `src/components/ConfirmDialog.tsx` | Delete confirmation modal |

## Files Modified

| File | Change |
|------|--------|
| `src/root.component.tsx` | Add routing to pages |

## Finalize

- [ ] Manual validation: navigate all pages, test toggle, delete, run now
- [ ] Commit: `feat: add workflow management frontend (list, runs, detail)`
- [ ] Update `STATUS.md` → complete, create `DONE.md`
