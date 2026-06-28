# Visual Message-Mapping Canvas Implementation Plan (SP5)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a two-column drag-to-connect message-mapping canvas (the SAP-CPI signature screen) to the Integrations studio as an alternate view of the existing flow editor — same `FlowDraft` model, same `applyDraft`/`saveFlow` persistence, switched by a form↔canvas toggle.

**Architecture:** One bounded SDK addition (`GET /api/flows/:id/fields` deriving target fields from destination columns + source fields from in-use connections); one factorial manifest route. Then in eldrin-core: add `@xyflow/react`; a pure `draft-graph-model.ts` (`FlowDraft` ⇄ React Flow nodes/edges + `onConnect`/edge-delete reducers, fully unit-tested); custom `SourceFieldNode`/`TargetFieldNode`; `MappingCanvas`; and a `FlowEditorShell` that lifts the draft/specs/save state out of `FlowEditor` so both the (now-controlled) form and the canvas edit one shared `FlowDraft`.

**Tech Stack:** SDK: TypeScript + Vitest. Shell: React 19 + `@xyflow/react` 12 + shadcn/ui + Tailwind 4 + react-i18next; Vitest + Playwright.

## Global Constraints

- **Three repos, sequenced:** Task 1 in `/Users/tibor/projects/eldrin-backup/eldrin-integration` (SDK); Task 2 in `/Users/tibor/projects/eldrin-backup/eldrin-factorial` (manifest); Tasks 3-8 in `/Users/tibor/projects/eldrin-backup/eldrin-core` (shell). SDK ships first (the canvas's `/fields` fetch depends on it).
- **The canvas is a VIEW over `FlowDraft`, never a new model.** `flow-edit-model.ts` (`toFlowDraft`/`applyDraft`) and `save-flow.ts` stay BYTE-FOR-BYTE UNCHANGED. Every canvas edit produces a new `FlowDraft`; persistence is the existing `applyDraft(original, draft, specs)` → `saveFlow`.
- **Immutability:** every draft edit returns new objects/arrays (spread). The canvas NEVER mutates the original draft or React Flow node state directly; nodes/edges are always re-derived from the draft via `draftToGraph`.
- **Free-text never restricted:** derived `targetFields`/`sourceFields` seed columns + autocomplete only. A connection may target/source a name not in the lists. A flow with no destination columns still works (empty `targetFields`, in-use sources only).
- **`GET /api/flows/:id/fields`:** admin-gated (`resolveUserId`→401, `isAdmin`→403); returns `{ targetFields: string[]; sourceFields: string[] }`. MUST register BEFORE `/api/flows/:id` (Hono ordering — else `:id` captures `fields`). `targetFields` = `storedColumnsOf(resource)` for the flow's destination table; `sourceFields` = sorted union of all `connections[].sources`.
- **Manifest route (factorial):** declare `GET /api/flows/:id/fields` as `flows:read`. NOTE: the proxy's `matchPath` does not resolve `:id` placeholders, so for non-admins this route relies on the same pre-existing fallthrough as the other `/api/flows/:id` routes; admins bypass the manifest check entirely (`apps.ts:760`). This is the known latent `matchPath` limitation — DO NOT fix it here; it is out of scope (read/write paths are admin-only).
- **Toggle:** both views are controlled over one `FlowDraft` (`draft` + `onDraftChange`). Default view is `'form'` (existing behavior is the entry point). Switching views does ZERO data conversion — same `FlowDraft` instance. One shared Save button on the shell.
- **Styling translation:** `eldrin-workflows` uses daisyUI classes (`bg-base-100`, `border-accent`); eldrin-core uses shadcn/Tailwind tokens (`bg-background`, `border`, `text-muted-foreground`, `bg-muted`, `border-primary`). Port the STRUCTURE (memo'd node, `Handle` type/position, `NodeProps` cast), translate the CLASSES.
- **Cross-repo:** shell does NOT import the SDK; it fetches `/fields` at runtime via the existing `authFetch` proxy. Reuse `Result<T>`, `AuthFetch`, the `getAuthFetch()` global pattern.
- **No `@testing-library/react`** (standing decision); pure-logic Vitest units + one Playwright smoke (runs at live-verify; browsers absent here). Immutability; no `console.log`; conventional commits, attribution disabled. Coverage ≥ 80% on the pure units.
- SDK tests: `cd eldrin-integration && npx vitest run`. Shell tests: `cd eldrin-core && npx vitest run`.

---

## File Structure

**eldrin-integration:**
- `src/host/create-worker.ts` (modify) — add `GET /api/flows/:id/fields` route (before `/api/flows/:id`); import `storedColumnsOf` from `../schema/ensure`.
- `src/host/create-worker.test.ts` (modify) — fields-route tests (derivation + admin gate).

**eldrin-factorial:**
- `public/eldrin-app.manifest.json` (modify) — declare `GET /api/flows/:id/fields` (before `/api/flows/:id`).

**eldrin-core:**
- `package.json` (modify) — add `@xyflow/react` dependency.
- `src/pages/integrations/integrations-api.ts` (modify) — `FlowFields` interface + `fetchFlowFields`.
- `src/pages/integrations/integrations-api.test.ts` (modify) — parse test.
- `src/pages/integrations/draft-graph-model.ts` (new) — `draftToGraph`, `connectSource`, `disconnectEdge`, `removeTarget`; node/edge data types.
- `src/pages/integrations/draft-graph-model.test.ts` (new) — derivation, reducers, round-trip invariant.
- `src/pages/integrations/SourceFieldNode.tsx` (new) — left-column node.
- `src/pages/integrations/TargetFieldNode.tsx` (new) — right-column node + transform chip.
- `src/pages/integrations/MappingCanvas.tsx` (new) — the React Flow canvas + palette + inspector.
- `src/pages/integrations/FlowEditor.tsx` (modify) — make controlled (accept `draft`/`onDraftChange`; drop internal draft/specs/save/version/status state).
- `src/pages/integrations/FlowEditorShell.tsx` (new) — owns draft/specs/fields/version/status/save; renders toggle + form/canvas.
- `src/pages/integrations/IntegrationList.tsx` (modify) — mount `FlowEditorShell` instead of `FlowEditor`.
- `src/locales/en/integrations.json` (modify) — canvas/toggle strings.
- `e2e/mapping-canvas.spec.ts` (new) — Playwright smoke.

---

## Reference: current code (do not re-derive)

**`flow-edit-model.ts` — the UNCHANGED boundary** (`src/pages/integrations/flow-edit-model.ts`):
```ts
export interface ConnectionDraft {
  target: string;
  sources: string[];
  transformKind: 'passthrough' | 'builtin' | 'snippet';
  builtinFn?: string;
  builtinArgs?: Record<string, string>;
  snippet?: string;
}
export interface FlowDraft { trigger: FlowGraph['trigger']; connections: ConnectionDraft[]; }
export function toFlowDraft(flow: FlowGraph, specs: Specs): FlowDraft;
export function applyDraft(original: FlowGraph, draft: FlowDraft, specs: Specs):
  { ok: true; flow: FlowGraph } | { ok: false; error: string };
```

**`integrations-api.ts` helpers** (reuse verbatim):
```ts
export type Result<T> = { ok: true; data: T } | { ok: false; status?: number; error: string };
export type AuthFetch = (appId: string, input: string, init?: RequestInit) => Promise<Response>;
async function call<T>(p: Promise<Response>): Promise<Result<T>>;  // file-local; add new fns beside it
export interface BuiltinArg { name: string; type: 'string' | 'number'; optional?: boolean; }
```

**`save-flow.ts` (UNCHANGED):** `saveFlow(appId, flow, baseVersion, authFetch): Promise<Result<{ version: number }>>`.

**`ConnectionRowEditor.tsx` (reuse as inspector body):** props `{ conn: ConnectionDraft; specs: Record<string, BuiltinArg[]>; onChange: (next) => void; onRemove: () => void }`. Renders target/sources inputs + transform-kind select + builtin-fn select + typed builtin-arg inputs + snippet input. The canvas inspector renders this for the selected target's `ConnectionDraft`.

**SDK route pattern** (`src/host/create-worker.ts`, registered before `/api/flows/:id` at line ~192):
```ts
app.get('/api/flows/builtin-specs', async (c) => {
  const userId = resolveUserId(c);
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);
  if (!isAdmin(c)) return c.json({ error: 'Forbidden: admin role required' }, 403);
  return c.json(BUILTIN_SPECS);
});
```
`prepare(c.env)` returns `{ db, effective }` where `effective.resources: ResourceDescriptor[]` (each `{ name, fieldMap, idField, supportedModes, ... }`). `storedColumnsOf(resource): string[]` is exported from `src/schema/ensure.ts` and returns `fieldMap` local column names minus the idField mapping.

**`eldrin-workflows` port reference (read-only, do not modify):**
- `src/components/builder/WorkflowCanvas.tsx` — `<ReactFlow>` setup, `nodeTypes`, prop↔graph sync with `internalUpdateRef` loop guard, palette + config-panel layout.
- `src/components/builder/StepNode.tsx` — `memo`'d node, `Handle type="target"/"source"` + `Position`, `data as unknown as StepNodeData` cast.

---

## Task 1: SDK `GET /api/flows/:id/fields` endpoint

**Files:**
- Modify: `eldrin-integration/src/host/create-worker.ts` (add route before `/api/flows/:id` at line ~192; add import)
- Test: `eldrin-integration/src/host/create-worker.test.ts`

**Interfaces:**
- Consumes: `prepare(c.env) → { db, effective }`; `effective.resources: ResourceDescriptor[]`; `storedColumnsOf(resource): string[]` from `../schema/ensure`; `listFlows(db)`/`readFlow(db, id)` (already imported); `compileDescriptorToFlows(effective)` (already imported); `resolveUserId`, `isAdmin` (already in scope).
- Produces: `GET /api/flows/:id/fields` → `{ targetFields: string[]; sourceFields: string[] }`. The shell's `fetchFlowFields` (Task 3) consumes this shape.

**Derivation rules:**
- Resolve the effective flow for `:id` the same way `/effective` does — `compileDescriptorToFlows(effective)` overlaid with stored. Find the flow whose `id === :id`; 404 if none.
- `targetFields`: find the flow's destination node (`nodes.find(n => n.kind === 'destination')`), read `config.table`, find `effective.resources.find(r => r.name === table)`; `targetFields = resource ? storedColumnsOf(resource) : []`.
- `sourceFields`: find the map node (`nodes.find(n => n.kind === 'map')`); collect every `connections[].sources[]`; return the sorted, de-duplicated union (`[...new Set(all)].sort()`).

- [ ] **Step 1: Write the failing tests**

In `create-worker.test.ts`, alongside the existing effective/builtin-specs tests (mirror their setup — admin headers, a descriptor with an `employees` resource whose `fieldMap` yields columns `full_name`, `email`, and a flow whose map connects `label ← [full_name, job_title]`):

```ts
describe('GET /api/flows/:id/fields', () => {
  it('returns 401 without a user', async () => {
    const res = await app.request('/api/flows/employees/fields');
    expect(res.status).toBe(401);
  });

  it('derives target fields from the destination table columns', async () => {
    const res = await app.request('/api/flows/employees/fields', { headers: adminHeaders });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.targetFields).toEqual(expect.arrayContaining(['full_name', 'email']));
  });

  it('derives source fields from the union of connection sources', async () => {
    const res = await app.request('/api/flows/employees/fields', { headers: adminHeaders });
    const body = await res.json();
    // label ← [full_name, job_title] contributes both; sorted + de-duped
    expect(body.sourceFields).toEqual(['full_name', 'job_title']);
  });

  it('404s an unknown flow id', async () => {
    const res = await app.request('/api/flows/does-not-exist/fields', { headers: adminHeaders });
    expect(res.status).toBe(404);
  });
});
```

(Match `adminHeaders`/`app` construction to the existing tests in the file — reuse whatever the effective-route tests use; do not invent a new harness.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd eldrin-integration && npx vitest run src/host/create-worker.test.ts`
Expected: FAIL — the new `/fields` route 404s (no handler) so the 200/derivation assertions fail.

- [ ] **Step 3: Add the import**

At the top of `create-worker.ts`, add to the existing schema imports:
```ts
import { storedColumnsOf } from '../schema/ensure';
```

- [ ] **Step 4: Add the route (BEFORE `/api/flows/:id`)**

Insert immediately after the `/api/flows/builtin-specs` handler (line ~190), before `app.get('/api/flows/:id', …)`:
```ts
app.get('/api/flows/:id/fields', async (c) => {
  const userId = resolveUserId(c);
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);
  if (!isAdmin(c)) return c.json({ error: 'Forbidden: admin role required' }, 403);
  const { db, effective } = await prepare(c.env);
  const id = c.req.param('id');
  const compiled = compileDescriptorToFlows(effective);
  const stored = new Map((await listFlows(db)).map((s) => [s.id, s]));
  const match = compiled.find((f) => f.id === id);
  if (!match) return c.json({ error: 'Flow not found' }, 404);
  const flow = stored.get(id)?.flow ?? match;

  const destNode = flow.nodes.find((n) => n.kind === 'destination');
  const table = destNode ? (destNode.config as { table?: string }).table : undefined;
  const resource = table ? effective.resources.find((r) => r.name === table) : undefined;
  const targetFields = resource ? storedColumnsOf(resource) : [];

  const mapNode = flow.nodes.find((n) => n.kind === 'map');
  const conns = mapNode ? ((mapNode.config as { connections?: { sources?: string[] }[] }).connections ?? []) : [];
  const sourceFields = [...new Set(conns.flatMap((conn) => conn.sources ?? []))].sort();

  return c.json({ targetFields, sourceFields });
});
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd eldrin-integration && npx vitest run src/host/create-worker.test.ts`
Expected: PASS (4 new tests).

- [ ] **Step 6: Run the full SDK suite**

Run: `cd eldrin-integration && npx vitest run`
Expected: PASS (no regressions; was 224 before).

- [ ] **Step 7: Commit**

```bash
cd eldrin-integration
git add src/host/create-worker.ts src/host/create-worker.test.ts
git commit -m "feat(host): add GET /api/flows/:id/fields (derive target+source fields)"
```

---

## Task 2: Factorial manifest route

**Files:**
- Modify: `eldrin-factorial/public/eldrin-app.manifest.json`

**Interfaces:**
- Consumes: nothing.
- Produces: a declared `GET /api/flows/:id/fields` route (`flows:read`).

- [ ] **Step 1: Add the route declaration**

In the `api.routes` array, insert immediately after the `GET /api/flows/builtin-specs` line and before `GET /api/flows/:id` (so specific paths precede `:id`):
```json
      { "method": "GET", "path": "/api/flows/:id/fields", "permission": "flows:read" },
```
Resulting order (the four GET specifics, then `:id`, then POST/DELETE):
```json
      { "method": "GET", "path": "/api/flows", "permission": "flows:read" },
      { "method": "GET", "path": "/api/flows/effective", "permission": "flows:read" },
      { "method": "GET", "path": "/api/flows/builtin-specs", "permission": "flows:read" },
      { "method": "GET", "path": "/api/flows/:id/fields", "permission": "flows:read" },
      { "method": "GET", "path": "/api/flows/:id", "permission": "flows:read" },
      { "method": "POST", "path": "/api/flows/:id", "permission": "flows:admin" },
      { "method": "DELETE", "path": "/api/flows/:id", "permission": "flows:admin" }
```

- [ ] **Step 2: Verify the JSON parses**

Run: `cd eldrin-factorial && node -e "JSON.parse(require('fs').readFileSync('public/eldrin-app.manifest.json','utf8')); console.log('ok')"`
Expected: `ok`

- [ ] **Step 3: Commit**

```bash
cd eldrin-factorial
git add public/eldrin-app.manifest.json
git commit -m "feat(manifest): declare GET /api/flows/:id/fields (flows:read)"
```

---

## Task 3: eldrin-core — `@xyflow/react` dep + `fetchFlowFields`

**Files:**
- Modify: `eldrin-core/package.json`
- Modify: `eldrin-core/src/pages/integrations/integrations-api.ts`
- Test: `eldrin-core/src/pages/integrations/integrations-api.test.ts`

**Interfaces:**
- Consumes: `call<T>`, `AuthFetch`, `Result<T>` (file-local).
- Produces: `interface FlowFields { targetFields: string[]; sourceFields: string[] }` and `fetchFlowFields(appId, flowId, authFetch): Promise<Result<FlowFields>>`. Tasks 5-7 consume these.

- [ ] **Step 1: Add the dependency**

Run: `cd eldrin-core && npm install @xyflow/react@^12.10.0`
Expected: `package.json` `dependencies` gains `"@xyflow/react": "^12.10.0"`; install succeeds.

- [ ] **Step 2: Write the failing test**

In `integrations-api.test.ts` (mirror the existing `fetchEffectiveFlows`/`fetchBuiltinSpecs` parse tests — they mock an `authFetch` returning a `Response`):
```ts
it('fetchFlowFields parses target + source fields', async () => {
  const authFetch = vi.fn(async () =>
    new Response(JSON.stringify({ targetFields: ['full_name', 'email'], sourceFields: ['full_name', 'job_title'] }), { status: 200 }),
  );
  const r = await fetchFlowFields('eldrin-factorial', 'eldrin-factorial:employees', authFetch);
  expect(r.ok).toBe(true);
  if (r.ok) {
    expect(r.data.targetFields).toEqual(['full_name', 'email']);
    expect(r.data.sourceFields).toEqual(['full_name', 'job_title']);
  }
  expect(authFetch).toHaveBeenCalledWith('eldrin-factorial', '/api/flows/eldrin-factorial%3Aemployees/fields');
});
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd eldrin-core && npx vitest run src/pages/integrations/integrations-api.test.ts`
Expected: FAIL — `fetchFlowFields is not a function`.

- [ ] **Step 4: Implement**

In `integrations-api.ts`, add after `fetchBuiltinSpecs`:
```ts
export interface FlowFields {
  targetFields: string[];
  sourceFields: string[];
}

export function fetchFlowFields(appId: string, flowId: string, authFetch: AuthFetch): Promise<Result<FlowFields>> {
  return call<FlowFields>(authFetch(appId, `/api/flows/${encodeURIComponent(flowId)}/fields`));
}
```
(Encoding matches `fetchFlow`'s `encodeURIComponent` — the id contains `:`.)

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd eldrin-core && npx vitest run src/pages/integrations/integrations-api.test.ts`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd eldrin-core
git add package.json package-lock.json src/pages/integrations/integrations-api.ts src/pages/integrations/integrations-api.test.ts
git commit -m "feat(integrations): add @xyflow/react dep + fetchFlowFields"
```

---

## Task 4: `draft-graph-model.ts` — pure `FlowDraft` ⇄ graph + reducers

**Files:**
- Create: `eldrin-core/src/pages/integrations/draft-graph-model.ts`
- Test: `eldrin-core/src/pages/integrations/draft-graph-model.test.ts`

**Interfaces:**
- Consumes: `ConnectionDraft`, `FlowDraft` from `./flow-edit-model`; `FlowFields` from `./integrations-api`; React Flow `Node`/`Edge` types from `@xyflow/react`.
- Produces (Task 5/7 consume):
  - `SourceNodeData { kind: 'source'; field: string }`, `TargetNodeData { kind: 'target'; field: string; conn: ConnectionDraft; index: number }`.
  - `draftToGraph(draft: FlowDraft, fields: FlowFields): { nodes: Node[]; edges: Edge[] }`.
  - `connectSource(draft: FlowDraft, sourceField: string, targetField: string): FlowDraft`.
  - `disconnectEdge(draft: FlowDraft, edgeId: string): FlowDraft`.
  - `removeTarget(draft: FlowDraft, targetField: string): FlowDraft`.
  - `edgeId(sourceField: string, targetField: string): string` (stable id `src:${sourceField}->tgt:${targetField}`).

**Layout/derivation rules:**
- Source column nodes: the de-duplicated union of `fields.sourceFields` and every `draft.connections[].sources` (free-text sources not in `fields` still appear). Id `src-${field}`, type `sourceFieldNode`, x=0, y=index*72.
- Target column nodes: the de-duplicated union of `fields.targetFields` and every `draft.connections[].target` (free-text targets still appear). Id `tgt-${field}`, type `targetFieldNode`, x=320, y=index*72. `conn` = the matching `ConnectionDraft` or a synthesized passthrough `{ target: field, sources: [], transformKind: 'passthrough' }` when none exists yet; `index` = its position in `draft.connections` or `-1` if synthesized.
- Edges: for each connection, one edge per source — `{ id: edgeId(s, conn.target), source: 'src-'+s, target: 'tgt-'+conn.target }`.
- `connectSource`: find the target's connection; if present, append `sourceField` to `sources` (skip if already there); if absent, push a new `{ target: targetField, sources: [sourceField], transformKind: 'passthrough' }`. Immutable.
- `disconnectEdge`: parse `edgeId` back to `(sourceField, targetField)`; remove `sourceField` from that target's `sources`; if `sources` becomes empty, REMOVE the whole connection. Immutable.
- `removeTarget`: drop the connection whose `target === targetField`. Immutable.

- [ ] **Step 1: Write the failing tests**

```ts
import { describe, it, expect } from 'vitest';
import { draftToGraph, connectSource, disconnectEdge, removeTarget, edgeId } from './draft-graph-model';
import type { FlowDraft } from './flow-edit-model';

const fields = { targetFields: ['full_name', 'label'], sourceFields: ['full_name', 'job_title'] };
const draft: FlowDraft = {
  trigger: { kind: 'manual' },
  connections: [
    { target: 'full_name', sources: ['full_name'], transformKind: 'passthrough' },
    { target: 'label', sources: ['full_name', 'job_title'], transformKind: 'builtin', builtinFn: 'concat', builtinArgs: { separator: ' — ' } },
  ],
};

describe('draftToGraph', () => {
  it('makes one target node per target with an edge per source', () => {
    const { nodes, edges } = draftToGraph(draft, fields);
    const labelEdges = edges.filter((e) => e.target === 'tgt-label');
    expect(labelEdges).toHaveLength(2); // label ← full_name + job_title
    expect(nodes.filter((n) => n.type === 'targetFieldNode')).toHaveLength(2);
  });

  it('surfaces a free-text source not present in fields', () => {
    const d2: FlowDraft = { ...draft, connections: [{ target: 'x', sources: ['mystery'], transformKind: 'passthrough' }] };
    const { nodes } = draftToGraph(d2, fields);
    expect(nodes.some((n) => n.id === 'src-mystery')).toBe(true);
    expect(nodes.some((n) => n.id === 'tgt-x')).toBe(true);
  });
});

describe('connectSource', () => {
  it('adds a source to an existing target immutably', () => {
    const next = connectSource(draft, 'job_title', 'full_name');
    expect(next.connections[0].sources).toEqual(['full_name', 'job_title']);
    expect(draft.connections[0].sources).toEqual(['full_name']); // original untouched
  });

  it('creates a passthrough connection for a brand-new target', () => {
    const next = connectSource(draft, 'full_name', 'email');
    const conn = next.connections.find((c) => c.target === 'email');
    expect(conn).toEqual({ target: 'email', sources: ['full_name'], transformKind: 'passthrough' });
  });

  it('is a no-op when the source is already connected', () => {
    const next = connectSource(draft, 'full_name', 'full_name');
    expect(next.connections[0].sources).toEqual(['full_name']);
  });
});

describe('disconnectEdge', () => {
  it('removes one source but keeps the connection when others remain', () => {
    const next = disconnectEdge(draft, edgeId('full_name', 'label'));
    const conn = next.connections.find((c) => c.target === 'label')!;
    expect(conn.sources).toEqual(['job_title']);
  });

  it('removes the whole connection when the last source goes', () => {
    const next = disconnectEdge(draft, edgeId('full_name', 'full_name'));
    expect(next.connections.find((c) => c.target === 'full_name')).toBeUndefined();
  });
});

describe('removeTarget', () => {
  it('drops the connection for that target immutably', () => {
    const next = removeTarget(draft, 'label');
    expect(next.connections.find((c) => c.target === 'label')).toBeUndefined();
    expect(draft.connections).toHaveLength(2); // original untouched
  });
});

describe('round-trip invariant', () => {
  it('folding the graph edges back reproduces the connections', () => {
    const { edges } = draftToGraph(draft, fields);
    // group edges by target, collect sources
    const byTarget = new Map<string, string[]>();
    for (const e of edges) {
      const tgt = e.target.replace('tgt-', '');
      const src = e.source.replace('src-', '');
      byTarget.set(tgt, [...(byTarget.get(tgt) ?? []), src]);
    }
    for (const conn of draft.connections) {
      expect(byTarget.get(conn.target)).toEqual(conn.sources);
    }
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd eldrin-core && npx vitest run src/pages/integrations/draft-graph-model.test.ts`
Expected: FAIL — module not found / functions undefined.

- [ ] **Step 3: Implement**

```ts
import type { Node, Edge } from '@xyflow/react';
import type { ConnectionDraft, FlowDraft } from './flow-edit-model';
import type { FlowFields } from './integrations-api';

export interface SourceNodeData { kind: 'source'; field: string; [k: string]: unknown; }
export interface TargetNodeData { kind: 'target'; field: string; conn: ConnectionDraft; index: number; [k: string]: unknown; }

const ROW_H = 72;
const SRC_X = 0;
const TGT_X = 320;

export function edgeId(sourceField: string, targetField: string): string {
  return `src:${sourceField}->tgt:${targetField}`;
}

function parseEdgeId(id: string): { sourceField: string; targetField: string } | null {
  const m = /^src:(.*)->tgt:(.*)$/.exec(id);
  return m ? { sourceField: m[1], targetField: m[2] } : null;
}

function uniq(values: string[]): string[] {
  return [...new Set(values)];
}

export function draftToGraph(draft: FlowDraft, fields: FlowFields): { nodes: Node[]; edges: Edge[] } {
  const sourceFields = uniq([...fields.sourceFields, ...draft.connections.flatMap((c) => c.sources)]);
  const targetFields = uniq([...fields.targetFields, ...draft.connections.map((c) => c.target)]);

  const nodes: Node[] = [];
  sourceFields.forEach((field, i) => {
    nodes.push({ id: `src-${field}`, type: 'sourceFieldNode', position: { x: SRC_X, y: i * ROW_H }, data: { kind: 'source', field } satisfies SourceNodeData });
  });
  targetFields.forEach((field, i) => {
    const index = draft.connections.findIndex((c) => c.target === field);
    const conn: ConnectionDraft = index >= 0 ? draft.connections[index] : { target: field, sources: [], transformKind: 'passthrough' };
    nodes.push({ id: `tgt-${field}`, type: 'targetFieldNode', position: { x: TGT_X, y: i * ROW_H }, data: { kind: 'target', field, conn, index } satisfies TargetNodeData });
  });

  const edges: Edge[] = [];
  for (const conn of draft.connections) {
    for (const s of conn.sources) {
      edges.push({ id: edgeId(s, conn.target), source: `src-${s}`, target: `tgt-${conn.target}` });
    }
  }
  return { nodes, edges };
}

export function connectSource(draft: FlowDraft, sourceField: string, targetField: string): FlowDraft {
  const idx = draft.connections.findIndex((c) => c.target === targetField);
  if (idx < 0) {
    return { ...draft, connections: [...draft.connections, { target: targetField, sources: [sourceField], transformKind: 'passthrough' }] };
  }
  const conn = draft.connections[idx];
  if (conn.sources.includes(sourceField)) return draft;
  const nextConn: ConnectionDraft = { ...conn, sources: [...conn.sources, sourceField] };
  return { ...draft, connections: draft.connections.map((c, i) => (i === idx ? nextConn : c)) };
}

export function disconnectEdge(draft: FlowDraft, id: string): FlowDraft {
  const parsed = parseEdgeId(id);
  if (!parsed) return draft;
  const idx = draft.connections.findIndex((c) => c.target === parsed.targetField);
  if (idx < 0) return draft;
  const conn = draft.connections[idx];
  const sources = conn.sources.filter((s) => s !== parsed.sourceField);
  if (sources.length === 0) {
    return { ...draft, connections: draft.connections.filter((_, i) => i !== idx) };
  }
  return { ...draft, connections: draft.connections.map((c, i) => (i === idx ? { ...conn, sources } : c)) };
}

export function removeTarget(draft: FlowDraft, targetField: string): FlowDraft {
  return { ...draft, connections: draft.connections.filter((c) => c.target !== targetField) };
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd eldrin-core && npx vitest run src/pages/integrations/draft-graph-model.test.ts`
Expected: PASS (all describe blocks).

- [ ] **Step 5: Commit**

```bash
cd eldrin-core
git add src/pages/integrations/draft-graph-model.ts src/pages/integrations/draft-graph-model.test.ts
git commit -m "feat(integrations): add pure FlowDraft<->graph model + reducers"
```

---

## Task 5: `SourceFieldNode` + `TargetFieldNode` components

**Files:**
- Create: `eldrin-core/src/pages/integrations/SourceFieldNode.tsx`
- Create: `eldrin-core/src/pages/integrations/TargetFieldNode.tsx`

**Interfaces:**
- Consumes: `SourceNodeData`/`TargetNodeData` from `./draft-graph-model`; `Handle`, `Position`, `NodeProps` from `@xyflow/react`.
- Produces: `SourceFieldNode`, `TargetFieldNode` (default-export-free named memo components) for the `nodeTypes` map in Task 6: `{ sourceFieldNode: SourceFieldNode, targetFieldNode: TargetFieldNode }`.

**Styling:** shadcn/Tailwind tokens (NOT daisyUI). Source node: a right-side `source` handle. Target node: a left-side `target` handle + a small transform chip showing `passthrough` / builtin fn / `snippet`.

- [ ] **Step 1: Implement `SourceFieldNode.tsx`**

```tsx
import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import type { SourceNodeData } from './draft-graph-model';

function SourceFieldNodeComponent({ data, selected }: NodeProps) {
  const { field } = data as unknown as SourceNodeData;
  return (
    <div className={`rounded-md border bg-background px-3 py-2 text-sm font-mono shadow-sm ${selected ? 'border-primary' : 'border-border'}`}>
      {field}
      <Handle type="source" position={Position.Right} className="!h-3 !w-3 !border-2 !border-background !bg-primary" />
    </div>
  );
}
export const SourceFieldNode = memo(SourceFieldNodeComponent);
```

- [ ] **Step 2: Implement `TargetFieldNode.tsx`**

```tsx
import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import type { TargetNodeData } from './draft-graph-model';

function transformLabel(data: TargetNodeData): string {
  const c = data.conn;
  if (c.transformKind === 'builtin') return c.builtinFn ?? 'builtin';
  if (c.transformKind === 'snippet') return 'snippet';
  return 'pass-through';
}

function TargetFieldNodeComponent({ data, selected }: NodeProps) {
  const d = data as unknown as TargetNodeData;
  return (
    <div className={`rounded-md border bg-background px-3 py-2 text-sm shadow-sm ${selected ? 'border-primary' : 'border-border'}`}>
      <Handle type="target" position={Position.Left} className="!h-3 !w-3 !border-2 !border-background !bg-primary" />
      <span className="font-mono">{d.field}</span>
      <span className="ml-2 rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">{transformLabel(d)}</span>
    </div>
  );
}
export const TargetFieldNode = memo(TargetFieldNodeComponent);
```

- [ ] **Step 3: Typecheck**

Run: `cd eldrin-core && npx tsc -b --noEmit` (or `npm run build` if `tsc -b` isn't wired for a quick check)
Expected: no type errors in the two new files.

- [ ] **Step 4: Commit**

```bash
cd eldrin-core
git add src/pages/integrations/SourceFieldNode.tsx src/pages/integrations/TargetFieldNode.tsx
git commit -m "feat(integrations): add source/target field node components"
```

---

## Task 6: `MappingCanvas.tsx` — the canvas view

**Files:**
- Create: `eldrin-core/src/pages/integrations/MappingCanvas.tsx`
- Modify: `eldrin-core/src/locales/en/integrations.json` (add `canvasSource`, `canvasTarget`, `canvasInspector`, `addSource`)

**Interfaces:**
- Consumes: `draftToGraph`, `connectSource`, `disconnectEdge`, `removeTarget` from `./draft-graph-model`; `SourceFieldNode`/`TargetFieldNode` (Task 5); `ConnectionRowEditor` (reuse for the inspector body); `FlowDraft`/`ConnectionDraft` from `./flow-edit-model`; `FlowFields`, `BuiltinArg` from `./integrations-api`; `@xyflow/react` (`ReactFlow`, `Background`, `Controls`, `MiniMap`, `useNodesState`, `useEdgesState`, `type Connection`, `type NodeTypes`).
- Produces: `MappingCanvas({ draft, fields, specs, onDraftChange, validationError }: { draft: FlowDraft; fields: FlowFields; specs: Record<string, BuiltinArg[]>; onDraftChange: (next: FlowDraft) => void; validationError: string | null })`. Consumed by `FlowEditorShell` (Task 7).

**Behavior (port from `WorkflowCanvas.tsx`, translate styling):**
- `nodeTypes = { sourceFieldNode: SourceFieldNode, targetFieldNode: TargetFieldNode }`.
- Re-derive nodes/edges from `draft` whenever `draft`/`fields` change (the draft is the single source of truth — no `internalUpdateRef` games needed because the parent owns the draft and re-renders us; we recompute graph in a `useMemo` and feed `useNodesState`/`useEdgesState` via an effect, OR simpler: compute `{nodes, edges}` with `useMemo(() => draftToGraph(draft, fields), [draft, fields])` and pass directly to `<ReactFlow>` with `onNodesChange`/`onEdgesChange` no-ops for layout, since `nodesDraggable={false}`).
- `onConnect(c: Connection)`: `c.source` is `src-<field>`, `c.target` is `tgt-<field>`; strip prefixes; `onDraftChange(connectSource(draft, srcField, tgtField))`.
- `onEdgesDelete(edges)`: for each, `onDraftChange(disconnectEdge(draft, edge.id))` (fold sequentially).
- Selecting a target node sets `selectedTarget` (the field); the inspector renders `<ConnectionRowEditor conn={selectedConn} specs={specs} onChange={…} onRemove={…} />` where `selectedConn` is the matching connection (or a synthesized passthrough); `onChange` replaces/inserts that connection in the draft; `onRemove` = `removeTarget`.
- `<ReactFlow nodesDraggable={false} nodesConnectable={true} deleteKeyCode="Backspace" proOptions={{ hideAttribution: true }}>` with `<Background />`, `<Controls showInteractive={false} />`, `<MiniMap />`.
- Left palette: `fields.sourceFields` chips (informational; connections are made by dragging handles). Keep it simple — a labeled list. (Drag-from-palette is NOT required for SP5; handle-drag is the connect mechanism.)
- **Inline validation (spec §4/§6):** the canvas surfaces validity by running `applyDraft(flow…)` — but `MappingCanvas` doesn't hold `flow`/`applyDraft` (the shell does). So the shell passes a `validationError: string | null` prop (computed in `FlowEditorShell` as `const applied = applyDraft(flow, draft, specs); const validationError = applied.ok ? null : applied.error;`). `MappingCanvas` renders `validationError` as a warning banner above the canvas when non-null, and the shell disables Save while it's non-null. This reuses `applyDraft` as the single validity authority — no duplicate validation logic.

- [ ] **Step 1: Implement `MappingCanvas.tsx`**

```tsx
import { useMemo, useState } from 'react';
import {
  ReactFlow, Background, Controls, MiniMap,
  type Connection, type Edge, type NodeTypes,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useTranslation } from 'react-i18next';
import type { FlowDraft, ConnectionDraft } from './flow-edit-model';
import type { FlowFields, BuiltinArg } from './integrations-api';
import { draftToGraph, connectSource, disconnectEdge, removeTarget } from './draft-graph-model';
import { SourceFieldNode } from './SourceFieldNode';
import { TargetFieldNode } from './TargetFieldNode';
import { ConnectionRowEditor } from './ConnectionRowEditor';

const nodeTypes: NodeTypes = { sourceFieldNode: SourceFieldNode, targetFieldNode: TargetFieldNode };

export function MappingCanvas({ draft, fields, specs, onDraftChange, validationError }: {
  draft: FlowDraft; fields: FlowFields; specs: Record<string, BuiltinArg[]>; onDraftChange: (next: FlowDraft) => void; validationError: string | null;
}) {
  const { t } = useTranslation('integrations');
  const [selectedTarget, setSelectedTarget] = useState<string | null>(null);
  const { nodes, edges } = useMemo(() => draftToGraph(draft, fields), [draft, fields]);

  const onConnect = (c: Connection) => {
    if (!c.source || !c.target) return;
    const srcField = c.source.replace(/^src-/, '');
    const tgtField = c.target.replace(/^tgt-/, '');
    onDraftChange(connectSource(draft, srcField, tgtField));
  };

  const onEdgesDelete = (deleted: Edge[]) => {
    let next = draft;
    for (const e of deleted) next = disconnectEdge(next, e.id);
    onDraftChange(next);
  };

  const selectedConn: ConnectionDraft | null = selectedTarget
    ? draft.connections.find((c) => c.target === selectedTarget) ?? { target: selectedTarget, sources: [], transformKind: 'passthrough' }
    : null;

  const setConn = (next: ConnectionDraft) => {
    const idx = draft.connections.findIndex((c) => c.target === next.target);
    const connections = idx >= 0
      ? draft.connections.map((c, i) => (i === idx ? next : c))
      : [...draft.connections, next];
    onDraftChange({ ...draft, connections });
  };

  return (
    <div>
    {validationError && <div className="mb-2 rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">{validationError}</div>}
    <div className="mt-2 flex gap-3" style={{ height: 520 }}>
      <div className="w-40 shrink-0 rounded-md border bg-muted/30 p-2 text-sm">
        <div className="mb-1 font-medium">{t('canvasSource')}</div>
        <ul className="space-y-1 font-mono text-xs text-muted-foreground">
          {fields.sourceFields.map((f) => <li key={f}>{f}</li>)}
        </ul>
      </div>
      <div className="flex-1 rounded-md border overflow-hidden">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          onConnect={onConnect}
          onEdgesDelete={onEdgesDelete}
          onNodeClick={(_, n) => setSelectedTarget(n.type === 'targetFieldNode' ? n.id.replace(/^tgt-/, '') : null)}
          onPaneClick={() => setSelectedTarget(null)}
          nodesDraggable={false}
          nodesConnectable
          deleteKeyCode="Backspace"
          fitView
          proOptions={{ hideAttribution: true }}
        >
          <Background />
          <Controls showInteractive={false} />
          <MiniMap />
        </ReactFlow>
      </div>
      {selectedConn && (
        <div className="w-80 shrink-0 rounded-md border bg-muted/30 p-3">
          <div className="mb-2 text-sm font-medium">{t('canvasInspector')}</div>
          <ConnectionRowEditor conn={selectedConn} specs={specs} onChange={setConn} onRemove={() => { removeTargetAndClear(); }} />
        </div>
      )}
    </div>
    </div>
  );

  function removeTargetAndClear() {
    if (selectedTarget) onDraftChange(removeTarget(draft, selectedTarget));
    setSelectedTarget(null);
  }
}
```

- [ ] **Step 2: Add i18n strings**

In `src/locales/en/integrations.json`, add:
```json
  "canvasSource": "Source fields",
  "canvasTarget": "Target fields",
  "canvasInspector": "Connection",
  "addSource": "Add source"
```

- [ ] **Step 3: Typecheck**

Run: `cd eldrin-core && npx tsc -b --noEmit`
Expected: no type errors. (If `Connection`/`Edge` import paths differ in 12.10, fix to the version's exports.)

- [ ] **Step 4: Commit**

```bash
cd eldrin-core
git add src/pages/integrations/MappingCanvas.tsx src/locales/en/integrations.json
git commit -m "feat(integrations): add message-mapping canvas view"
```

---

## Task 7: `FlowEditorShell` + make `FlowEditor` controlled

**Files:**
- Modify: `eldrin-core/src/pages/integrations/FlowEditor.tsx` (make controlled)
- Create: `eldrin-core/src/pages/integrations/FlowEditorShell.tsx`
- Modify: `eldrin-core/src/pages/integrations/IntegrationList.tsx` (mount `FlowEditorShell`)
- Modify: `eldrin-core/src/locales/en/integrations.json` (add `viewForm`, `viewCanvas`)

**Interfaces:**
- `FlowEditor` becomes: `FlowEditor({ draft, specs, onDraftChange }: { draft: FlowDraft; specs: Record<string, BuiltinArg[]>; onDraftChange: (next: FlowDraft) => void })` — renders ONLY the trigger form + `ConnectionRowEditor` rows + add-connection; NO save button, NO status, NO internal draft/version state.
- `FlowEditorShell` owns: `draft` (init `toFlowDraft(flow, {})`, re-init on specs load), `specs`, `fields`, `version`, `status`, `view`. Props: `{ appId, flow, baseVersion, onClose, onSaved }` (same as the old `FlowEditor`). Renders the toggle + `<FlowEditor … />` or `<MappingCanvas … />` + shared Save/Cancel/status.
- `IntegrationList` mounts `<FlowEditorShell … />` where it currently mounts `<FlowEditor … />`.

- [ ] **Step 1: Make `FlowEditor` controlled**

Replace `FlowEditor.tsx` with (drops internal state; trigger form + rows only):
```tsx
import { useTranslation } from 'react-i18next';
import type { FlowDraft, ConnectionDraft } from './flow-edit-model';
import type { BuiltinArg } from './integrations-api';
import { ConnectionRowEditor } from './ConnectionRowEditor';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

export function FlowEditor({ draft, specs, onDraftChange }: {
  draft: FlowDraft; specs: Record<string, BuiltinArg[]>; onDraftChange: (next: FlowDraft) => void;
}) {
  const { t } = useTranslation('integrations');
  const setConn = (i: number, next: ConnectionDraft) => onDraftChange({ ...draft, connections: draft.connections.map((c, j) => (j === i ? next : c)) });
  const addConn = () => onDraftChange({ ...draft, connections: [...draft.connections, { target: '', sources: [], transformKind: 'passthrough' }] });
  const removeConn = (i: number) => onDraftChange({ ...draft, connections: draft.connections.filter((_, j) => j !== i) });

  return (
    <div>
      <div className="mb-3 flex items-center gap-2">
        <span className="text-sm font-medium">{t('triggerKind')}:</span>
        <select className="h-9 rounded-md border bg-background px-2 text-sm" value={draft.trigger.kind}
          onChange={(e) => {
            const kind = e.target.value as 'cron' | 'manual' | 'webhook';
            onDraftChange({ ...draft, trigger: kind === 'cron' ? { kind, expr: '' } : kind === 'webhook' ? { kind, event: '' } : { kind } });
          }}>
          <option value="cron">cron</option><option value="manual">manual</option><option value="webhook">webhook</option>
        </select>
        {draft.trigger.kind === 'cron' && <Input className="w-40 font-mono" value={draft.trigger.expr} onChange={(e) => onDraftChange({ ...draft, trigger: { kind: 'cron', expr: e.target.value } })} />}
        {draft.trigger.kind === 'webhook' && <Input className="w-40" value={draft.trigger.event} onChange={(e) => onDraftChange({ ...draft, trigger: { kind: 'webhook', event: e.target.value } })} />}
      </div>
      {draft.connections.map((c, i) => (
        <ConnectionRowEditor key={i} conn={c} specs={specs} onChange={(next) => setConn(i, next)} onRemove={() => removeConn(i)} />
      ))}
      <Button variant="link" size="sm" onClick={addConn}>+ {t('addConnection')}</Button>
    </div>
  );
}
```

- [ ] **Step 2: Create `FlowEditorShell.tsx`**

```tsx
import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { toFlowDraft, applyDraft, type FlowDraft } from './flow-edit-model';
import { saveFlow } from './save-flow';
import { fetchBuiltinSpecs, fetchFlowFields, type FlowGraph, type BuiltinArg, type FlowFields } from './integrations-api';
import { FlowEditor } from './FlowEditor';
import { MappingCanvas } from './MappingCanvas';
import { Button } from '@/components/ui/button';

type AuthFetchGlobal = (appId: string, input: string, init?: RequestInit) => Promise<Response>;
function getAuthFetch(): AuthFetchGlobal {
  return (window as unknown as { __ELDRIN__: { authenticatedFetch: AuthFetchGlobal } }).__ELDRIN__.authenticatedFetch;
}

export function FlowEditorShell({ appId, flow, baseVersion, onClose, onSaved }: {
  appId: string; flow: FlowGraph; baseVersion: number | null; onClose: () => void; onSaved: () => void;
}) {
  const { t } = useTranslation('integrations');
  const [specs, setSpecs] = useState<Record<string, BuiltinArg[]>>({});
  const [fields, setFields] = useState<FlowFields>({ targetFields: [], sourceFields: [] });
  const [draft, setDraft] = useState<FlowDraft>(() => toFlowDraft(flow, {}));
  const [version, setVersion] = useState(baseVersion);
  const [view, setView] = useState<'form' | 'canvas'>('form');
  const [status, setStatus] = useState<{ kind: 'idle' | 'saved' | 'error' | 'conflict'; msg?: string }>({ kind: 'idle' });

  useEffect(() => {
    const af = getAuthFetch();
    fetchBuiltinSpecs(appId, af).then((r) => { if (r.ok) { setSpecs(r.data); setDraft(toFlowDraft(flow, r.data)); } });
    fetchFlowFields(appId, flow.id, af).then((r) => { if (r.ok) setFields(r.data); });
  }, [appId, flow]);

  const applied = applyDraft(flow, draft, specs);
  const validationError = applied.ok ? null : applied.error;

  const save = async () => {
    if (!applied.ok) { setStatus({ kind: 'error', msg: applied.error }); return; }
    const r = await saveFlow(appId, applied.flow, version, getAuthFetch());
    if (r.ok) { setStatus({ kind: 'saved', msg: t('saved', { version: r.data.version }) }); setVersion(r.data.version); onSaved(); }
    else if (r.status === 409) setStatus({ kind: 'conflict' });
    else setStatus({ kind: 'error', msg: r.error });
  };

  return (
    <div className="mt-2 rounded-md border p-3">
      <div className="mb-3 inline-flex rounded-md border p-0.5 text-sm">
        <button className={`rounded px-3 py-1 ${view === 'form' ? 'bg-muted font-medium' : ''}`} onClick={() => setView('form')}>{t('viewForm')}</button>
        <button className={`rounded px-3 py-1 ${view === 'canvas' ? 'bg-muted font-medium' : ''}`} onClick={() => setView('canvas')}>{t('viewCanvas')}</button>
      </div>
      {view === 'form'
        ? <FlowEditor draft={draft} specs={specs} onDraftChange={setDraft} />
        : <MappingCanvas draft={draft} fields={fields} specs={specs} onDraftChange={setDraft} validationError={validationError} />}
      <div className="mt-3 flex items-center gap-3">
        <Button size="sm" onClick={save} disabled={!!validationError}>{t('save')}</Button>
        <Button variant="ghost" size="sm" onClick={onClose}>{t('cancel')}</Button>
        {status.kind === 'saved' && <span className="text-sm text-green-600">{status.msg}</span>}
        {status.kind === 'error' && <span className="text-sm text-destructive">{status.msg}</span>}
        {status.kind === 'conflict' && <span className="text-sm text-destructive">{t('conflict')} <Button variant="link" size="sm" onClick={onClose}>{t('reload')}</Button></span>}
      </div>
    </div>
  );
}
```

- [ ] **Step 3: Point `IntegrationList` at the shell**

In `IntegrationList.tsx`: change the import `import { FlowEditor } from './FlowEditor';` → `import { FlowEditorShell } from './FlowEditorShell';` and the JSX `<FlowEditor appId={id} flow={item.flow} baseVersion={…} onClose={…} onSaved={load} />` → `<FlowEditorShell appId={id} flow={item.flow} baseVersion={item.stored ? item.version : null} onClose={() => setEditing(null)} onSaved={load} />`.

- [ ] **Step 4: Add toggle i18n strings**

In `src/locales/en/integrations.json`, add:
```json
  "viewForm": "Form",
  "viewCanvas": "Canvas"
```

- [ ] **Step 5: Run the shell suite + typecheck**

Run: `cd eldrin-core && npx vitest run && npx tsc -b --noEmit`
Expected: PASS (was 394; the controlled-FlowEditor refactor touches no test that asserted its internal state — confirm `flow-edit-model`/`save-flow` tests are green). No type errors.

- [ ] **Step 6: Commit**

```bash
cd eldrin-core
git add src/pages/integrations/FlowEditor.tsx src/pages/integrations/FlowEditorShell.tsx src/pages/integrations/IntegrationList.tsx src/locales/en/integrations.json
git commit -m "feat(integrations): add form<->canvas toggle shell; make FlowEditor controlled"
```

---

## Task 8: Playwright smoke

**Files:**
- Create: `eldrin-core/e2e/mapping-canvas.spec.ts`

**Interfaces:**
- Consumes: the existing `loginAsAdmin` helper used by `e2e/flow-editor.spec.ts` (reuse its import path verbatim).

- [ ] **Step 1: Write the smoke spec**

Mirror `e2e/flow-editor.spec.ts`'s setup (reuse `loginAsAdmin`, the `/integrations` navigation, the same selectors style):
```ts
import { test, expect } from '@playwright/test';
import { loginAsAdmin } from './helpers'; // match flow-editor.spec.ts's actual import

test('mapping canvas: switch to canvas, connect a source, save bumps version', async ({ page }) => {
  await loginAsAdmin(page);
  await page.goto('/integrations');
  await page.getByRole('button', { name: /edit/i }).first().click();
  await page.getByRole('button', { name: 'Canvas' }).click();
  await expect(page.locator('.react-flow')).toBeVisible();
  // Drag a source handle onto a target handle (exact handles depend on rendered fields);
  // then Save and assert a version badge increment is visible.
  await page.getByRole('button', { name: /^Save$/ }).click();
  await expect(page.getByText(/Saved/i)).toBeVisible();
});
```
(The drag step's exact selectors are filled in at live-verify against the rendered DOM; the spec's value here is the canvas-renders + save-path smoke. Keep it minimal.)

- [ ] **Step 2: Confirm it's syntactically valid (compile only; browsers absent here)**

Run: `cd eldrin-core && npx tsc -b --noEmit`
Expected: no type errors. (Do NOT run `npx playwright test` — browsers aren't installed in this environment; it runs at live-verify.)

- [ ] **Step 3: Commit**

```bash
cd eldrin-core
git add e2e/mapping-canvas.spec.ts
git commit -m "test(integrations): add Playwright smoke for the mapping canvas"
```

---

## After all tasks

- Final whole-branch review (most-capable model) across all three repos' diffs.
- Then `superpowers:finishing-a-development-branch` per repo (SDK → factorial → core), same as SP4c.
- Then **live-verify** via chrome-devtools (the recorded lesson): open the editor, switch to Canvas, drag a source onto a target, change a transformer chip, Save, confirm the version bump + the `%3A`-encoded POST payload preserves source/dest/edges. This is where cross-repo seams surface.
