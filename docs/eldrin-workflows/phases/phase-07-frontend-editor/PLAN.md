# Phase 7: Frontend — Workflow Editor (JSON + Forms)

## Overview

Build the workflow creation/editing UI using a JSON editor with form overlays. This is the Phase 1 editor — functional and complete, but not yet visual (the drag-and-drop builder comes in Phase 8). Users configure triggers, conditions, and steps through structured forms that produce valid workflow definition JSON.

## Dependencies

- Phase 6 (frontend management pages — routing and API client exist)

## Steps

### 7.1 Create workflow editor page

Create **`src/pages/WorkflowEditor.tsx`**:

Main editor layout:
- Header: workflow name input, save/cancel buttons
- Left panel: trigger config + condition builder
- Center: step list (ordered, add/remove/reorder)
- Right panel or modal: step config form (opens when step selected)
- Bottom: JSON preview (read-only, collapsible)

### 7.2 Build trigger configuration form

Create **`src/components/editor/TriggerConfig.tsx`**:

- Trigger type dropdown: event, manual, webhook, cron
- Dynamic config form per type:
  - **event**: event type input (e.g., `user.created`), with suggestions
  - **manual**: no config needed (empty state message)
  - **webhook**: path input (e.g., `/trigger/my-hook`)
  - **cron**: expression input with helper (disabled until Phase 9)

### 7.3 Build condition builder

Create **`src/components/editor/ConditionBuilder.tsx`**:

- List of condition rows, each with: field input, operator dropdown, value input
- Add/remove condition buttons
- Operator dropdown populated from the full operator set (eq, neq, gt, contains, etc.)
- "All conditions must match" label (AND logic)

### 7.4 Build step list component

Create **`src/components/editor/StepList.tsx`**:

- Ordered list of configured steps
- Each step shows: index, name, type badge, edit/remove buttons
- "Add Step" button at the bottom
- Drag-to-reorder (basic HTML drag, or up/down buttons for simplicity)

### 7.5 Build step configuration forms

Create **`src/components/editor/StepConfig.tsx`** with sub-forms per type:

- **`HttpRequestForm`** — method dropdown, URL input, headers key-value pairs, body textarea
- **`SendEmailForm`** — to, subject, body/template inputs
- **`EmitEventForm`** — event type, payload key-value pairs
- **`DelayForm`** — duration input, unit dropdown (seconds/minutes/hours)

Each form shows template variable hints (e.g., "Use `{{payload.email}}` for trigger data").

### 7.6 Build JSON preview panel

Create **`src/components/editor/JsonPreview.tsx`**:

- Read-only JSON display of the complete workflow definition
- Syntax-highlighted (use a lightweight library or CSS-only styling)
- Copy-to-clipboard button
- Collapsible/expandable

### 7.7 Add validation feedback

Create **`src/components/editor/ValidationErrors.tsx`**:

- Inline error messages next to invalid fields
- Summary at the top when save is attempted with errors
- Uses the same validation rules as the backend (shared or replicated)

### 7.8 Implement save flow

Wire up the editor to the API:
- Create mode: `POST /workflows` → navigate to workflow detail
- Edit mode: `PATCH /workflows/:id` → navigate back to detail
- Show toast on success/failure (Sonner)

## Test Gate

```bash
cd eldrin-workflows && npm run dev
# Navigate to /workflows/new, build a workflow, save, verify in list
```

Acceptance criteria:
1. Can create a new workflow with trigger, conditions, and steps
2. Trigger type selection shows correct config form
3. Steps can be added, configured, reordered, and removed
4. JSON preview updates in real-time as form changes
5. Validation errors show inline on invalid inputs
6. Save creates the workflow and navigates to detail page
7. Edit mode loads existing workflow and saves changes
8. Template variable hints are visible in step forms

## Files Created

| File | Purpose |
|------|---------|
| `src/pages/WorkflowEditor.tsx` | Main editor page layout |
| `src/components/editor/TriggerConfig.tsx` | Trigger type + config form |
| `src/components/editor/ConditionBuilder.tsx` | Condition rows builder |
| `src/components/editor/StepList.tsx` | Ordered step list |
| `src/components/editor/StepConfig.tsx` | Per-type step config forms |
| `src/components/editor/JsonPreview.tsx` | JSON definition preview |
| `src/components/editor/ValidationErrors.tsx` | Validation feedback |

## Files Modified

| File | Change |
|------|--------|
| `src/root.component.tsx` | Add routes for /new and /:id/edit |
| `src/pages/WorkflowList.tsx` | "New Workflow" button navigates to editor |
| `src/pages/WorkflowDetail.tsx` | "Edit" button navigates to editor |
| `src/api.ts` | Add createWorkflow, updateWorkflow functions |

## Finalize

- [ ] Manual validation: create workflow end-to-end, edit existing, verify JSON output
- [ ] Commit: `feat: add workflow editor with form-based configuration`
- [ ] Update `STATUS.md` → complete, create `DONE.md`
