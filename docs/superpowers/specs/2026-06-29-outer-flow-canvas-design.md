# Outer Flow-Graph Canvas — Design Spec (SP8)

**Status:** approved (design), ready for implementation plan
**Date:** 2026-06-29
**Sub-project:** SP8 — the visual studio for the whole flow graph + draft/publish lifecycle in the UI
**Repos:** `eldrin-core` (primary — the studio), `eldrin-integration` (one additive read-only SDK route), `eldrin-factorial` (rebuild + live-verify)

---

## Context

SP1–SP7 built the runtime and persistence: the executor (SP1/1.5), field-mapping engine (SP2), flow persistence + CRUD (SP3), the read-only studio + form editor (SP4), the visual message-mapping canvas (SP5), the routing engine — `route` nodes + per-edge `when` conditions branching to N destinations (SP6), and the draft/published lifecycle (SP7). Today's eldrin-core editor can edit **only the connections inside a single `map` node** (`FlowDraft = {trigger, connections}`; `applyDraft` rebuilds just that node's connections and preserves the rest of the flow JSON verbatim). It cannot add/remove/reorder nodes or author the route branches SP6 made runnable, and the SP7 lifecycle routes (`/publish`, `/republish`, `/versions`, draft-if-exists `GET /:id`, `hasDraft`) exist but are unused by the UI.

SP8 closes both gaps: a structural node-graph canvas for the whole flow, plus the lifecycle wired into the UI.

## Decisions locked during brainstorming

- **All three parts ship as one SP8:** (A) lifecycle UI, (B) structural canvas, (C) mapping drill-in.
- **Edit the `FlowGraph` directly** as the editable document (not an extended `FlowDraft`, not a separate structural draft). Pure immutable reducers return new `FlowGraph`s. One source of truth, no draft↔graph translation layer.
- **Layout A — canvas + side inspector:** left-to-right node graph on the left, a context inspector panel on the right edits the selected node. The `map` node drills into the existing SP5 mapping canvas full-width.
- **Editing surface = pipeline shape + routing:** add/remove/reorder `transform`/`filter`/`map` nodes; add a `route` node and author its `when` branches; pick `destination` tables from a descriptor-provided catalog dropdown. **`source` nodes render read-only** (their transport/auth comes from the descriptor and is out of scope). Editing source config is a possible future sub-project.
- **One new SDK route `GET /api/flows/catalog`** supplies the table catalog; everything else reuses SP7 routes.
- **Lifecycle UX = explicit Save draft + Publish,** with a Versions panel for Rollback.

## 1. Architecture

```
IntegrationList (open by id, draft badge)
  └── FlowEditorShell  (orchestrator: holds the FlowGraph in state, view toggle)
        ├── view: Structure → StructuralCanvas (xyflow) + NodeInspector (right pane)
        ├── view: Mapping   → MappingCanvas (SP5, unchanged) — drill-in for a map node
        ├── view: Form      → FlowEditor (SP4, unchanged)
        ├── LifecyclePanel  (Save draft / Publish)
        └── VersionsPanel   (history + Rollback)
```

- **eldrin-core is the primary repo.** The only SDK change is one additive read-only route.
- `@xyflow/react` 12 is already a core dependency (added in SP5).
- The structural canvas is a **pure render** of the `FlowGraph`; user gestures call a pure reducer and set the new `FlowGraph` in state. Save serializes the `FlowGraph` straight to `POST /api/flows/:id` — no rebuild step, because the graph *is* the document.

## 2. The Structural Editing Model (`flow-graph-model.ts`)

A new pure module in `eldrin-core/src/pages/integrations/`. The `FlowGraph` (`{id, integrationId, trigger, nodes, edges}`) is the editable document. All reducers are immutable — they return a **new** `FlowGraph` and never mutate the input (mirrors `draft-graph-model.ts`).

Node kinds (from the SDK `NodeKind`): `source · transform · filter · map · route · destination`.

**Reducers (each `FlowGraph → FlowGraph`):**

- `addNode(flow, kind, afterNodeId): FlowGraph` — insert a `transform`/`filter`/`map`/`route`/`destination` node into the linear chain after `afterNodeId`. Splices the one passthrough edge `afterNodeId→B` into `afterNodeId→new→B`. The new node gets a generated id and a default config:
  - `transform` / `filter` → `{ mode: 'snippet', snippet: '' }`
  - `map` → `{ connections: [] }`
  - `route` → `{}` (branch logic lives on outgoing `edge.when`)
  - `destination` → `{ kind: 'd1', table: <first catalog table or ''>, mode: 'stored' }`
- `removeNode(flow, nodeId): FlowGraph` — drop the node and heal the chain by reconnecting its single predecessor to its single successor. Returns the flow **unchanged** when `nodeId` is a `source` node (sources are not removable) — the caller surfaces the reason as an inspector warning.
- `connect(flow, fromId, toId): FlowGraph` — add an edge (used mainly for route fan-out: route → multiple destinations). No-op if the edge already exists.
- `disconnect(flow, edge): FlowGraph` — remove the matching edge.
- `addBranch(flow, routeId, toId): FlowGraph` — add a `route`-outgoing edge to `toId` with an empty `when: ''`.
- `setWhen(flow, fromId, toId, expr): FlowGraph` — set (or clear, when `expr` is empty) the `when` condition on the `fromId→toId` edge.
- `setNodeConfig(flow, nodeId, config): FlowGraph` — replace one node's `config`. The inspector edits and the map drill-in (a new `MapConfig`) both feed this.

**Client-side guardrails (server stays authoritative).** The model also exposes a pure `graphIssues(flow, catalog): string[]` that lists the obvious invariant violations so the canvas can warn inline and disable Save when it already knows the flow is invalid:
- a `route` node with fewer than 2 outgoing edges, or any route out-edge with an empty `when`;
- a `destination` node naming a table not in the catalog;
- a node unreachable from the source (orphaned by an edit).

These are **UX only**. The real gate is the server's `validateFlow` on every Save and Publish (SP6 made it routing-aware); a flow that slips past the client guardrails still returns a 400 with the validator's message, surfaced exactly as the current editor does.

## 3. Components & Data Flow

**New / changed files** (`eldrin-core/src/pages/integrations/`), kept small per the lightweight-components rule:

- `flow-graph-model.ts` + `.test.ts` — the reducers + `graphIssues` (Section 2). The core unit-test target.
- `graph-render.ts` + `.test.ts` — pure `FlowGraph → { nodes: Node[]; edges: Edge[] }` for xyflow. Left-to-right layering by distance from the source; route fan-out stacks branch destinations vertically. Mirrors `draft-graph-model.ts`'s `draftToGraph`.
- `StructuralCanvas.tsx` — the xyflow canvas (Layout A left pane). Renders `graph-render` output; select/connect/add gestures call reducers and lift the new `FlowGraph` via `onFlowChange`.
- `NodeInspector.tsx` — the right pane; switches on the selected node's kind. Sub-inspectors as their own small files:
  - `RouteInspector.tsx` — branch list, per-branch `when` editor, target picker (from catalog).
  - `DestinationInspector.tsx` — table dropdown (catalog) + storage mode.
  - `TransformFilterInspector.tsx` — snippet/native-hook editor.
  - `source` → a read-only display (no edits).
- `integration-catalog.ts` + `.test.ts` — `fetchCatalog(appId, authFetch): Promise<Result<Catalog>>` for `GET /api/flows/catalog`; `Catalog = { tables: { name: string; columns: string[] }[] }`.
- `integrations-api.ts` (small change) — extend the `StoredFlow` type (returned by `fetchFlow`/`GET /:id`) with `status: 'draft' | 'published' | 'archived'` (SP7 added it server-side; the core type predates it), so the shell can show whether it opened a draft or the published flow.
- `LifecyclePanel.tsx` — Save draft + Publish buttons + status.
- `VersionsPanel.tsx` — version history list + Rollback (republish) action; fed by `GET /api/flows/:id/versions`.
- **`FlowEditorShell.tsx` (rework)** — the orchestrator. Its prop contract changes from `flow: FlowGraph` to `flowId: string` (+ `appId`, `onClose`, `onSaved`): on mount it fetches `GET /api/flows/:id` (draft-if-exists) into `FlowGraph` state and reads `version`/`status` from that response, rather than receiving `item.flow`/`item.version` from the list. It holds the `FlowGraph` in state, owns the **Structure | Mapping | Form** view toggle, and mounts the canvas + inspector + lifecycle/versions panels. (`fetchFlow` in `integrations-api.ts` already exists for `GET /:id`, returning `StoredFlow` with `flow`/`version`.)
- **`IntegrationList.tsx` (small change)** — pass `flowId={item.flow.id}` to the shell (which then fetches the draft) instead of `flow={item.flow}`/`baseVersion`, and render a "draft pending" badge when `hasDraft`. Surface `hasDraft` through `EffectiveFlow`.

**The existing `MappingCanvas` / `flow-edit-model.ts` (`applyDraft`) / `save-flow.ts` stay unchanged** — they become the map-node drill-in. The shell hands the mapping canvas one node's connections (today's `FlowDraft`), and the drill-in's result feeds back via `setNodeConfig(flow, mapNodeId, newMapConfig)`.

**Data flow:**

```
open editor   → GET /api/flows/:id            → draft-if-exists FlowGraph → editor state
              → GET /api/flows/catalog        → destination dropdowns + per-destination target fields
              → GET /api/flows/:id/fields     → mapping drill-in source/target fields (as today)
edit (canvas) → reducer(flowGraph) → new FlowGraph in state            [NO server call]
Save draft    → POST /api/flows/:id {flow, baseVersion}     → validateFlow → draft     (200 / 400 / 409)
Publish       → POST /api/flows/:id/publish {baseVersion}   → validateFlow(live ctx) → published
Rollback      → POST /api/flows/:id/republish {version}     → restore historical version
```

## 4. SDK Change & Validation

**One new SDK route** (`eldrin-integration`, `src/host/create-worker.ts`), additive and read-only:

```
GET /api/flows/catalog        (admin-gated: 401 unauth, 403 non-admin — same as the other flow routes)
  → { tables: [{ name: string, columns: string[] }] }
```

- Built from `effective.resources`, filtered to **stored** resources (`supportedModes` includes `'stored'`), with `columns = storedColumnsOf(resource)` — reusing the exact helper `GET /api/flows/:id/fields` already uses, so the catalog matches what the executor stores.
- Registered **before** `/api/flows/:id` (Hono ordering — same precaution as `/effective` and `/builtin-specs`).
- No schema change, no executor change.

**Validation strategy — unchanged contract, server authoritative:**
- Every **Save draft** (`POST /:id`) and **Publish** (`POST /publish`) runs `validateFlow` against live `knownTables`/hooks, exactly as SP7 wired it. The canvas now *produces* richer flows (routes, multiple destinations, reordered pipelines) but they pass through the same SP6 routing-aware gate.
- **Client guardrails** (`graphIssues`, Section 2) are UX only — inline inspector warnings; Save/Publish disabled while the client model knows the flow is invalid. They never replace the server check.
- **Error surfacing** stays as the current editor: 400 → inline validation error; 409 → conflict + reload; 403 → forbidden.

**Cross-repo build seam (recurring lesson):** the catalog route is an SDK source change consumed via the built `dist/`. After the SDK task, `npm run build` in `eldrin-integration` **and** rebuild `eldrin-factorial` before live-verifying — unit suites prove the route, not the bundle seam (the SP5 stale-dist lesson). The plan's final step live-verifies the whole path in the running app.

## 5. Testing & Task Breakdown

**Testing** (TDD, ≥80%, Vitest units + Playwright for the critical flow):

- **`flow-graph-model.test.ts`** (core): each reducer pure + immutable — `addNode` splices and rewires the chain; `removeNode` heals predecessor→successor and is blocked (no-op) for `source`; `addBranch`/`setWhen` produce route edges carrying `when`; `setNodeConfig` swaps one config; `connect`/`disconnect` for fan-out; `graphIssues` flags route-needs-≥2-branches, unknown destination table, orphaned node. Assert the input `FlowGraph` is never mutated.
- **`graph-render.test.ts`**: a `FlowGraph` (including a route with 2 branches → 2 destinations) renders the expected xyflow node/edge set with left-to-right layering and stacked branches.
- **`integration-catalog.test.ts`**: `fetchCatalog` parses `{tables}`, handles 403/error.
- **SDK `create-worker.test.ts`**: `GET /api/flows/catalog` returns stored tables + columns; admin-gated (401/403); registered before `:id`.
- **Lifecycle**: opening via `GET /:id` loads the draft; Save→draft, Publish→published, Rollback→republish call the right routes with the right body; `hasDraft` badge renders.
- **Playwright smoke** (extends the SP5 smoke): open a flow → add a `route` node → add a second `destination` → set a `when` → Save draft → Publish; assert the published version advanced.

**Task breakdown** (the plan details each as TDD steps):
1. **SDK:** `GET /api/flows/catalog` route + tests; build dist.
2. `integration-catalog.ts` fetch client + `EffectiveFlow.hasDraft` + `StoredFlow.status` surfacing + tests.
3. **`flow-graph-model.ts`** reducers + `graphIssues` + tests (the core — largest unit task).
4. `graph-render.ts` + tests.
5. `StructuralCanvas.tsx` + node components.
6. `NodeInspector.tsx` + `RouteInspector` / `DestinationInspector` / `TransformFilterInspector`.
7. `LifecyclePanel.tsx` + `VersionsPanel.tsx` (Save draft / Publish / Rollback).
8. **`FlowEditorShell.tsx` rework** — Structure | Mapping | Form toggle, open-by-id, wire panels; map-node drill-in to the existing `MappingCanvas` via `setNodeConfig`.
9. `IntegrationList.tsx` — open-by-id + draft badge.
10. Playwright smoke + live-verify the cross-repo path (rebuild SDK dist + factorial).

## Global Constraints (carried from the platform spec)

- **eldrin-core is the primary repo;** the only SDK change is the additive read-only `GET /api/flows/catalog`. No schema/executor change.
- **`@xyflow/react` 12 is already a core dependency** (SP5) — no new dependency.
- **Edit the `FlowGraph` directly;** all reducers immutable (return new graphs, never mutate input). No `console.log`.
- **`validateFlow` is the single server-side source of truth;** it runs on every Save draft and Publish. Client guardrails are UX only.
- **Backward-compatible `POST /api/flows/:id`** (still `{flow, baseVersion}`, 200/400/409); saves become drafts (SP7).
- **Editor opens via `GET /api/flows/:id`** (draft-if-exists), not from `/effective` — continues an in-progress draft rather than forking from published.
- **Source nodes are read-only** in the canvas; the editing surface is pipeline shape + routing only.
- **Rebuild the SDK `dist/` + `eldrin-factorial` before live-verifying** (the SP5 stale-dist lesson). Live-verify the cross-repo path as the final task.
- Conventional commits, **attribution disabled** (no Co-Authored-By footers). Coverage ≥ 80%. Tests: `cd eldrin-core && npx vitest run` (+ `npx playwright test`); `cd eldrin-integration && npx vitest run`.
