# Visual Message-Mapping Canvas — Design Spec (SP5)

**Status:** approved (design), ready for implementation plan
**Date:** 2026-06-28
**Sub-project:** SP5 — first slice of the "Both surfaces" visual editor for the CPI-style integration flow platform
**Repos:** `eldrin-integration` (SDK), `eldrin-factorial` (manifest), `eldrin-core` (shell UI)

---

## 1. Scope & Decomposition

SAP CPI has two distinct visual surfaces:

| Surface | Shows | Backing model | Editable today |
|---|---|---|---|
| **Flow graph** (top level) | source → map → transform → destination nodes + edges | `FlowGraph.nodes/edges` | structure not editable in SP4c |
| **Message mapping** (drill-in) | source-fields ↔ target-fields with transformer chips | `FlowDraft.connections` (`ConnectionDraft[]`) | yes — via SP4c form |

"Both surfaces" is 2+ sub-projects. **SP5 = the message-mapping canvas** (the SAP-CPI signature two-column field-linking screen). **SP6 (deferred)** = the outer flow-graph overview, with the map node double-click drilling into the SP5 canvas.

Rationale: the mapping canvas is where the editing value is, it drops onto the existing `FlowDraft`/`applyDraft` safety boundary with zero persistence changes, and it sidesteps the harder "editable flow structure / arbitrary source-destination" questions the outer graph raises. Highest value, lowest structural risk, first.

## 2. Architecture & React Flow Port

**Location:** all inside `eldrin-core/src/pages/integrations/`. eldrin-core gains `@xyflow/react` (^12.10 — same major as `eldrin-workflows`, proven against React 19).

**Central principle — the canvas is a new _view_ over the existing model, not a new model.** `flow-edit-model.ts` (`applyDraft`, which deep-copies and swaps only `map.config.connections` + `trigger`) and `save-flow.ts` (optimistic-lock POST) stay **byte-for-byte untouched**. The canvas reads a `FlowDraft` and emits a `FlowDraft` — exactly what the form editor does today.

```
FlowGraph ──toFlowDraft()──▶ FlowDraft ──┬──▶ [FlowEditor]    (SP4c, unchanged logic, now controlled)
                                          └──▶ [MappingCanvas] (SP5, new view)
              FlowGraph ◀──applyDraft()──── FlowDraft (emitted by whichever view is active)
                                                   │
                                            save-flow.ts (unchanged)
```

**Ported from `eldrin-workflows` (adapt, not copy — different domain):**
- React Flow shell: `<ReactFlow>` + `Background`/`Controls`/`MiniMap`, `proOptions hideAttribution`, `nodeTypes` registry, `useNodesState`/`useEdgesState`.
- The **prop↔graph sync pattern** (`definitionToGraph` + `internalUpdateRef` loop guard) — adapted into `draftToGraph`.
- Custom node component structure, palette/config-panel layout idiom, daisyUI styling.

**New (workflows is a linear chain; we are a bipartite field-linker):**
- Two-column layout (source fields left, target fields right) instead of a vertical chain.
- **User-created draggable edges** — workflows uses `nodesConnectable={false}` (auto-edges); we need `onConnect` so users drag source→target. This is the core new interaction.
- Transformer chip per target connection, opening the existing typed-arg editor.

## 3. Field-Derivation SDK Endpoint

Columns exist in the descriptor (`storedResourceDDL(tableName, columns)`) but aren't exposed over the API today. SP5 adds one bounded endpoint.

**`GET /api/flows/:id/fields`** (admin-gated, registered _before_ `/api/flows/:id`, matching the `/builtin-specs` and `/effective` pattern):

```json
{
  "targetFields": ["full_name", "email", "job_title", "team_id", "label"],
  "sourceFields": ["full_name", "email", "job_title", "team_id"]
}
```

- **`targetFields`** — the destination table's column names, derived from the descriptor's resource column list for the table named in the flow's destination node (`destination.config.table`).
- **`sourceFields`** — the union of all `sources[]` already referenced across the flow's connections. The descriptor doesn't enumerate remote API fields (the source is a raw HTTP fetch), so this gives the real, in-use source fields without inventing a schema the SDK lacks.

**Why a dedicated route, not extending `/effective`:** `/effective` returns _all_ flows and is fetched on every studio load; fields are per-flow and only needed when one editor opens. A per-id route keeps `/effective` lean and mirrors `/builtin-specs`.

**Free-text escape hatch (critical):** `targetFields`/`sourceFields` _seed_ the columns and offer autocomplete; they never _restrict_. The canvas still lets you type a name not in the derived lists. A flow with no destination columns still works (you get the in-use fields). Derivation enriches; it never gates.

**Manifest:** add the route to `eldrin-factorial`'s manifest with `flows:read`.

## 4. Canvas Component & Interaction

**Three regions** (bipartite, mirroring the workflows idiom):

```
┌─────────────┬──────────────────────────────────┬──────────────┐
│ Source       │           Canvas                 │ Connection    │
│ fields       │  [full_name]●───────●[full_name] │ inspector     │
│ (palette)    │  [email    ]●───────●[email    ] │               │
│ [+ add src]  │  [job_title]●──┐  ┌──●[label] 🔧 │ target: label │
│              │  [team_id  ]●  └──┘  ●[team_id  ] │ concat( — )   │
└─────────────┴──────────────────────────────────┴──────────────┘
```

- **Left palette** — derived `sourceFields` as draggable/clickable chips + "add source" free-text.
- **Center canvas** — two node columns. Source nodes carry a right-side (source) handle; target nodes a left-side (target) handle. **Each edge = one `(source, target)` membership** in a `ConnectionDraft`. A target with multiple incoming edges = a multi-source connection (`label ← [full_name, job_title]`).
- **Right inspector** — on target-node select: shows the connection's `transformKind` (passthrough/builtin/snippet) and, for builtin, the **typed-arg editor reused from `ConnectionRowEditor.tsx`** (the `BUILTIN_SPECS`-driven inputs verified in SP4c). The 🔧 chip on a target node opens this.

**Core new interaction — `onConnect`:** dragging source→target adds that source to the target's `ConnectionDraft.sources[]` (creating the `ConnectionDraft` if the target had none). Deleting an edge removes that source. Deleting a target node removes the whole connection. **All mutate the `FlowDraft` immutably** (spread, new arrays); the canvas never mutates React Flow node state directly — nodes/edges are always re-derived from the draft via `draftToGraph`, the same one-way pattern as workflows' `definitionToGraph`.

**React Flow config:** `nodesConnectable={true}` (the key difference from workflows), `nodesDraggable={false}` (fixed computed two-column layout — keeps the graph readable and round-trips cleanly), custom `SourceFieldNode`/`TargetFieldNode`, `onConnect`/`onEdgesDelete` handlers.

**Inline validation:** before enabling Save, run `applyDraft` on the live draft; a target whose builtin is missing a required arg shows a warning badge using `applyDraft`'s error message. The canvas cannot save an invalid flow.

## 5. Form ↔ Canvas Toggle & State

Both views are **controlled over one `FlowDraft`**. A new parent owns the shared state:

```
FlowEditorShell  (owns: draft, view, specs, fields, save)
├── [ Form | Canvas ]  ← segmented toggle (default 'form')
├── view==='form'   → <FlowEditor draft … onDraftChange />        (SP4c, made controlled)
└── view==='canvas' → <MappingCanvas draft fields specs onDraftChange />  (SP5)
                                          │
                                  Save → applyDraft(original,…) → saveFlow   (shared, unchanged)
```

- **Toggling `view` swaps the renderer with zero data conversion** — same `FlowDraft` instance, so an edit in either view is instantly visible in the other. This is the payoff of "canvas is a view over the model."
- **One SP4c refactor:** `FlowEditor.tsx` currently owns its draft via `toFlowDraft`; make it _controlled_ (accept `draft`/`onDraftChange`, lift `toFlowDraft` to the shell). Mechanical, covered by existing `flow-edit-model` tests; the form's behavior is unchanged, only ownership moves up.
- **Save is shared and singular** — one Save button on the shell, one `applyDraft`→`saveFlow` path, one 200/400/409 status display, regardless of active view.
- **Fields fetch:** the shell fetches `/fields` once when an editor opens (alongside the existing specs fetch) and passes it to the canvas. The form doesn't need it (free-text). Lazy, per-open.

## 6. Round-Trip & Testing

```
load:   FlowGraph ─toFlowDraft()─▶ FlowDraft ─draftToGraph()─▶ {nodes,edges}  →  canvas renders
                    (SP4c, kept)              (SP5, NEW)
edit:   onConnect/onEdgesDelete/inspector ─▶ onDraftChange(nextDraft)  (immutable)
save:   FlowDraft ─applyDraft(original,…)─▶ FlowGraph ─saveFlow()─▶ POST /flows/:id  (SP4c, unchanged)
```

The two new pure functions — `draftToGraph(draft, fields)` and the `onConnect`/edge-delete reducers — are the heart of SP5 and are **pure and unit-testable without a browser**, like `flow-edit-model.ts` today. Logic proven by units; the browser only proves the wiring.

**Testing** (80%+, TDD; matches the studio's established approach — logic units + Playwright smoke, no `@testing-library/react`):

1. **`draft-graph-model.test.ts` (core unit):**
   - `draftToGraph`: `label ← [full_name, job_title]` → 1 target node, 2 incoming edges; passthrough/builtin/snippet render the right chip; free-text fields not in `fields` still appear.
   - `onConnect` reducer: `email→label` adds `email` to `label.sources[]`, immutably (original draft unchanged — asserts the immutability rule).
   - edge-delete reducer: removing one of two edges leaves the other; removing the last **removes the connection** (a target with no sources isn't a valid connection).
   - **round-trip invariant:** `draftToGraph` then fold edges back ⇒ original `FlowDraft.connections` (no silent loss/reorder).
2. **`fields` endpoint (SDK unit):** `targetFields` from destination columns, `sourceFields` from in-use sources; no destination columns → empty `targetFields`, still returns in-use sources; admin-gated (401 unauth).
3. **`FlowEditorShell` toggle (unit):** form↔canvas swap preserves the same `draft` reference; Save calls `applyDraft`+`saveFlow` once regardless of view.
4. **Playwright smoke (`mapping-canvas.spec.ts`):** `loginAsAdmin` → open editor → switch to Canvas → drag source onto target → Save → version bump. (Runs at live-verify; browsers absent here.)
5. **Live-verify (the recorded lesson):** drive the real canvas via chrome-devtools — drag-connect, change a transformer chip, Save, confirm version bump + correct `%3A`-encoded POST preserving source/dest/edges. Where cross-repo seams surface.

**Task breakdown** (detailed in the plan):
1. SDK `GET /api/flows/:id/fields` endpoint + test.
2. `eldrin-factorial` manifest route (`flows:read`).
3. eldrin-core `@xyflow/react` dep + `integrations-api` fetch fn for `/fields`.
4. `draft-graph-model.ts` pure functions + tests.
5. `SourceFieldNode`/`TargetFieldNode` + `MappingCanvas`.
6. `FlowEditorShell` + make `FlowEditor` controlled.
7. Playwright smoke.

## Global Constraints (carried from the platform spec)

- `applyDraft` and `save-flow.ts` are the safety boundary — **unchanged**. The canvas only ever produces/consumes a `FlowDraft`.
- Immutability: all draft edits return new objects/arrays; never mutate the original draft or React Flow node state directly.
- Free-text never restricted: derived fields seed/autocomplete only.
- New flow routes are admin-gated and registered before `/api/flows/:id`.
- Manifest routes: reads = `flows:read`.
- No `@testing-library/react`; logic units + Playwright smoke.
- `@xyflow/react` ^12.x (React 19 compatible), matching `eldrin-workflows`.
```
