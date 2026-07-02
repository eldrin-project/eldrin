# Phase 8: Visual Builder (reactflow)

## Overview

Replace the JSON + forms editor (Phase 7) with a drag-and-drop visual node editor using **reactflow**. This is the signature UX feature — users build workflows by dragging step nodes onto a canvas, drawing connections, and configuring each node through side panels.

Detailed plan will be written when implementation begins.

## Dependencies

- Phase 7 (frontend editor — the form-based editor that this replaces as default)

## Key Deliverables

### reactflow integration
- Install `@xyflow/react` (formerly reactflow)
- Set up canvas with zoom, pan, minimap
- Custom node types: trigger, step, condition, end

### Node types
- **Trigger node**: displays trigger type + icon, single output handle
- **Step node**: displays step name + type icon, input/output handles
- **Condition node**: displays condition, true/false output handles (branching in Phase 10)
- **End node**: marks workflow completion

### Step palette
- Sidebar or drawer listing available step types
- Drag from palette onto canvas to add
- Grouped by category (communication, logic, integration)

### Connection drawing
- Draw edges between node handles
- Validate connections (e.g., can't connect to self, must flow forward)
- Animated edges showing execution direction

### Configuration panels
- Click node → opens config panel (right sidebar or modal)
- Same forms as Phase 7 (TriggerConfig, StepConfig, etc.)
- Changes immediately reflected in the node display

### Bidirectional sync
- Visual changes update the JSON definition
- JSON changes (e.g., from import) update the visual layout
- Auto-layout algorithm for imported workflows

### Live validation
- Highlight invalid nodes in red
- Show error tooltips on hover
- Prevent save when validation fails

## Test Gate

- Drag step from palette onto canvas
- Draw connections between nodes
- Click node → configure via form
- Save → valid JSON definition produced
- Load existing workflow → nodes positioned correctly
- Delete node → connections update
- Undo/redo support

## Files Created (estimated)

| File | Purpose |
|------|---------|
| `src/components/builder/WorkflowCanvas.tsx` | reactflow canvas setup |
| `src/components/builder/TriggerNode.tsx` | Custom trigger node |
| `src/components/builder/StepNode.tsx` | Custom step node |
| `src/components/builder/ConditionNode.tsx` | Custom condition node |
| `src/components/builder/StepPalette.tsx` | Draggable step types sidebar |
| `src/components/builder/ConfigPanel.tsx` | Node configuration panel |
| `src/components/builder/utils.ts` | Definition ↔ node conversion |

## Finalize

- [ ] Manual validation: build complete workflow visually, save, execute, verify
- [ ] Commit: `feat: add visual workflow builder with reactflow`
- [ ] Update `STATUS.md` → complete, create `DONE.md`
