# Outer Flow-Graph Canvas (SP8) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A visual studio in eldrin-core for the whole flow graph — add/remove/reorder pipeline nodes, author route branches to N destinations, drill into the SP5 mapping canvas — plus the SP7 draft/publish lifecycle wired into the UI.

**Architecture:** The `FlowGraph` (`{id, integrationId, trigger, nodes, edges}`) is the editable document. Pure immutable reducers (`flow-graph-model.ts`) return new `FlowGraph`s; a pure renderer (`graph-render.ts`) turns a `FlowGraph` into xyflow nodes/edges; a structural canvas + side inspector (Layout A) drives the reducers; the existing SP5 `MappingCanvas` becomes the map-node drill-in. One additive read-only SDK route (`GET /api/flows/catalog`) supplies the destination-table catalog. Saving serializes the `FlowGraph` straight to `POST /api/flows/:id` (a draft); Publish/Rollback call the existing SP7 routes.

**Tech Stack:** React 19, `@xyflow/react` 12 (already a dep), Zustand-free local component state, Vitest + Playwright (eldrin-core); Hono + Vitest (eldrin-integration SDK).

## Global Constraints

- **eldrin-core is the primary repo;** the only SDK change is the additive read-only `GET /api/flows/catalog`. No schema/executor change.
- **`@xyflow/react` 12 is already a core dependency** (SP5) — no new dependency.
- **Edit the `FlowGraph` directly;** all reducers immutable — return a new graph, never mutate the input.
- **No `console.log`** in production code.
- **`validateFlow` is the single server-side source of truth;** it runs on every Save draft and Publish. Client guardrails (`graphIssues`) are UX only.
- **Backward-compatible `POST /api/flows/:id`** (still body `{flow, baseVersion}`, 200/400/409); saves become drafts (SP7).
- **Editor opens via `GET /api/flows/:id`** (draft-if-exists), not from `/effective` — continues an in-progress draft.
- **Source nodes are read-only** in the canvas; editing surface = pipeline shape + routing only.
- **Rebuild the SDK `dist/` (`npm run build` in eldrin-integration) + eldrin-factorial before live-verifying** (the SP5 stale-dist lesson).
- Conventional commits, **attribution disabled** (no Co-Authored-By / attribution footers). Coverage ≥ 80%.
- Test commands: `cd eldrin-core && npx vitest run` (+ `npx playwright test`); `cd eldrin-integration && npx vitest run`.

## File Structure

**eldrin-integration (SDK):**
- `src/host/create-worker.ts` — add `GET /api/flows/catalog` route (Task 1).
- `src/host/create-worker.test.ts` — catalog route tests (Task 1).

**eldrin-core (`src/pages/integrations/`):**
- `integration-catalog.ts` + `.test.ts` — `fetchCatalog`, `Catalog` type (Task 2).
- `integrations-api.ts` — extend `EffectiveFlow` with `hasDraft`, `StoredFlow` with `status` (Task 2).
- `flow-graph-model.ts` + `.test.ts` — immutable structural reducers + `graphIssues` (Task 3).
- `graph-render.ts` + `.test.ts` — pure `FlowGraph → {nodes, edges}` for xyflow (Task 4).
- `StructuralCanvas.tsx`, `FlowNode.tsx` — the xyflow canvas + node component (Task 5).
- `NodeInspector.tsx`, `RouteInspector.tsx`, `DestinationInspector.tsx`, `TransformFilterInspector.tsx` (Task 6).
- `LifecyclePanel.tsx`, `VersionsPanel.tsx` (Task 7).
- `FlowEditorShell.tsx` — reworked orchestrator (Task 8).
- `IntegrationList.tsx` — open-by-id + draft badge (Task 9).
- `e2e/` Playwright smoke (Task 10).

---

### Task 1: SDK route `GET /api/flows/catalog`

**Files:**
- Modify: `eldrin-integration/src/host/create-worker.ts` (add route after `/api/flows/builtin-specs`, before `/api/flows/:id`)
- Test: `eldrin-integration/src/host/create-worker.test.ts` (inside the existing `describe('/api/flows routes', ...)` block)

**Interfaces:**
- Consumes: `storedColumnsOf(resource)` from `../schema/ensure` (already imported in create-worker.ts); `effective.resources` (array of `ResourceDescriptor` with `name`, `fieldMap`, `idField`, `supportedModes`); the `prepare(c.env)` helper returning `{ db, effective }`; `resolveUserId`, `isAdmin`.
- Produces: `GET /api/flows/catalog` → `{ tables: { name: string; columns: string[] }[] }`. Consumed by eldrin-core Task 2's `fetchCatalog`.

- [ ] **Step 1: Write the failing tests**

Add to `create-worker.test.ts` inside the `describe('/api/flows routes', ...)` block (after the existing POST tests). These reuse the block's `adminJwt`, `nonAdminJwt`, `flowsEnv`, and `worker` (the `beforeEach` seeds a `storedResourceDDL('clients', ['name TEXT'])` and `config` whose resource `clients` has `fieldMap` producing column `name`):

```typescript
it('GET /api/flows/catalog without auth → 401', async () => {
  const res = await worker.fetch(new Request('http://x/api/flows/catalog'), flowsEnv, {} as any);
  expect(res.status).toBe(401);
});

it('GET /api/flows/catalog as non-admin → 403', async () => {
  const res = await worker.fetch(
    new Request('http://x/api/flows/catalog', { headers: { Authorization: 'Bearer ' + nonAdminJwt } }),
    flowsEnv, {} as any,
  );
  expect(res.status).toBe(403);
});

it('GET /api/flows/catalog as admin → stored tables with columns', async () => {
  const res = await worker.fetch(
    new Request('http://x/api/flows/catalog', { headers: { Authorization: 'Bearer ' + adminJwt } }),
    flowsEnv, {} as any,
  );
  expect(res.status).toBe(200);
  const body = await res.json() as { tables: { name: string; columns: string[] }[] };
  const clients = body.tables.find((t) => t.name === 'clients');
  expect(clients).toBeDefined();
  expect(clients!.columns).toContain('name'); // from the config resource's fieldMap (idField excluded)
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd eldrin-integration && npx vitest run src/host/create-worker.test.ts -t "catalog"`
Expected: FAIL — the 3 tests 404 (route not registered) / mismatch.

- [ ] **Step 3: Implement the route**

In `create-worker.ts`, add this route immediately AFTER the `app.get('/api/flows/builtin-specs', ...)` block and BEFORE `app.get('/api/flows/:id/fields', ...)` (so Hono matches `/catalog` literally, not as `:id`):

```typescript
  // Catalog of destination tables (stored resources) + their columns — for the structural canvas.
  // Registered before /api/flows/:id so 'catalog' is not treated as an id.
  app.get('/api/flows/catalog', async (c) => {
    const userId = resolveUserId(c);
    if (!userId) return c.json({ error: 'Unauthorized' }, 401);
    if (!isAdmin(c)) return c.json({ error: 'Forbidden: admin role required' }, 403);
    const { effective } = await prepare(c.env);
    const tables = effective.resources
      .filter((r) => r.supportedModes.includes('stored'))
      .map((r) => ({ name: r.name, columns: storedColumnsOf(r) }));
    return c.json({ tables });
  });
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd eldrin-integration && npx vitest run src/host/create-worker.test.ts -t "catalog"`
Expected: PASS (3/3).

- [ ] **Step 5: Typecheck + full SDK suite**

Run: `cd eldrin-integration && npx tsc -b --noEmit && npx vitest run`
Expected: tsc clean; all tests green.

- [ ] **Step 6: Build the SDK dist (consumed by dependents)**

Run: `cd eldrin-integration && npm run build`
Expected: build succeeds (the new route reaches `dist/`).

- [ ] **Step 7: Commit**

```bash
cd eldrin-integration
git add src/host/create-worker.ts src/host/create-worker.test.ts dist
git commit -m "feat(integration): add GET /api/flows/catalog route for the structural canvas"
```

---

### Task 2: Catalog fetch client + type surfacing (eldrin-core)

**Files:**
- Create: `eldrin-core/src/pages/integrations/integration-catalog.ts`
- Create: `eldrin-core/src/pages/integrations/integration-catalog.test.ts`
- Modify: `eldrin-core/src/pages/integrations/integrations-api.ts` (extend `EffectiveFlow` and `StoredFlow`)

**Interfaces:**
- Consumes: `Result<T>`, `AuthFetch`, `call` pattern from `integrations-api.ts` (`call<T>(p: Promise<Response>): Promise<Result<T>>`, and `authFetch(appId, path)`).
- Produces:
  - `Catalog = { tables: CatalogTable[] }`, `CatalogTable = { name: string; columns: string[] }`.
  - `fetchCatalog(appId: string, authFetch: AuthFetch): Promise<Result<Catalog>>`.
  - `EffectiveFlow.hasDraft: boolean` and `StoredFlow.status: 'draft' | 'published' | 'archived'` (consumed by Tasks 7/8/9).

- [ ] **Step 1: Write the failing test**

Create `integration-catalog.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import { fetchCatalog } from './integration-catalog';
import type { AuthFetch } from './integrations-api';

function fakeFetch(status: number, body: unknown): AuthFetch {
  return async () => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

describe('fetchCatalog', () => {
  it('parses { tables } on 200', async () => {
    const af = fakeFetch(200, { tables: [{ name: 'clients', columns: ['name', 'email'] }] });
    const r = await fetchCatalog('acme', af);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.data.tables[0]).toEqual({ name: 'clients', columns: ['name', 'email'] });
  });

  it('returns an error result on 403', async () => {
    const af = fakeFetch(403, { error: 'Forbidden' });
    const r = await fetchCatalog('acme', af);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.status).toBe(403);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd eldrin-core && npx vitest run src/pages/integrations/integration-catalog.test.ts`
Expected: FAIL — `fetchCatalog` not found.

- [ ] **Step 3: Implement the fetch client**

Create `integration-catalog.ts`. Re-use the same `call<T>` envelope `integrations-api.ts` uses (copy its shape rather than importing the private helper):

```typescript
import type { Result, AuthFetch } from './integrations-api';

export interface CatalogTable {
  name: string;
  columns: string[];
}

export interface Catalog {
  tables: CatalogTable[];
}

export async function fetchCatalog(appId: string, authFetch: AuthFetch): Promise<Result<Catalog>> {
  try {
    const res = await authFetch(appId, '/api/flows/catalog');
    const body = await res.json().catch(() => undefined);
    if (res.ok) return { ok: true, data: body as Catalog };
    const error = (body && (body as { error?: string }).error) || `Request failed with status ${res.status}`;
    return { ok: false, status: res.status, error };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd eldrin-core && npx vitest run src/pages/integrations/integration-catalog.test.ts`
Expected: PASS (2/2).

- [ ] **Step 5: Extend the API types**

In `integrations-api.ts`, add `status` to `StoredFlow` and `hasDraft` to `EffectiveFlow`:

```typescript
export interface StoredFlow {
  id: string;
  integrationId: string;
  flow: FlowGraph;
  version: number;
  status: 'draft' | 'published' | 'archived';   // SP7 added this server-side
  createdAt: number;
  updatedAt: number;
}
```

```typescript
export interface EffectiveFlow {
  flow: FlowGraph;
  version: number | null;
  stored: boolean;
  hasDraft: boolean;   // SP7: an unpublished draft exists for this id
}
```

- [ ] **Step 6: Typecheck**

Run: `cd eldrin-core && npx tsc -b --noEmit`
Expected: clean (adding optional-to-consumers fields; existing reads still compile — verify no consumer destructures these as required-missing).

- [ ] **Step 7: Commit**

```bash
cd eldrin-core
git add src/pages/integrations/integration-catalog.ts src/pages/integrations/integration-catalog.test.ts src/pages/integrations/integrations-api.ts
git commit -m "feat(integrations): add fetchCatalog client + surface hasDraft/status types"
```

---

### Task 3: Structural editing model `flow-graph-model.ts` (the core)

**Files:**
- Create: `eldrin-core/src/pages/integrations/flow-graph-model.ts`
- Create: `eldrin-core/src/pages/integrations/flow-graph-model.test.ts`

**Interfaces:**
- Consumes: `FlowGraph` from `integrations-api.ts` (`{ id, integrationId, trigger, nodes: {id,kind,config}[], edges: {from,to,when?}[] }`); `Catalog` from `integration-catalog.ts`.
- Produces (all pure, immutable):
  - `addNode(flow: FlowGraph, kind: NodeKind, afterNodeId: string, genId: () => string): FlowGraph`
  - `removeNode(flow: FlowGraph, nodeId: string): FlowGraph`
  - `connect(flow: FlowGraph, fromId: string, toId: string): FlowGraph`
  - `disconnect(flow: FlowGraph, fromId: string, toId: string): FlowGraph`
  - `addBranch(flow: FlowGraph, routeId: string, toId: string): FlowGraph`
  - `setWhen(flow: FlowGraph, fromId: string, toId: string, expr: string): FlowGraph`
  - `setNodeConfig(flow: FlowGraph, nodeId: string, config: unknown): FlowGraph`
  - `graphIssues(flow: FlowGraph, catalog: Catalog): string[]`
  - `type NodeKind = 'source' | 'transform' | 'filter' | 'map' | 'route' | 'destination'`
  These are consumed by Tasks 5 (canvas gestures), 6 (inspector), and 8 (shell).

- [ ] **Step 1: Write the failing tests**

Create `flow-graph-model.test.ts`. A small linear fixture `source → map → destination`:

```typescript
import { describe, it, expect } from 'vitest';
import {
  addNode, removeNode, connect, disconnect, addBranch, setWhen, setNodeConfig, graphIssues,
} from './flow-graph-model';
import type { FlowGraph } from './integrations-api';

let counter = 0;
const genId = () => `n${++counter}`;

function base(): FlowGraph {
  return {
    id: 'acme:clients',
    integrationId: 'acme',
    trigger: { kind: 'manual' },
    nodes: [
      { id: 'source', kind: 'source', config: {} },
      { id: 'map', kind: 'map', config: { connections: [] } },
      { id: 'destination', kind: 'destination', config: { kind: 'd1', table: 'clients', mode: 'stored' } },
    ],
    edges: [{ from: 'source', to: 'map' }, { from: 'map', to: 'destination' }],
  };
}

const catalog = { tables: [{ name: 'clients', columns: ['name'] }, { name: 'archive', columns: ['name'] }] };

describe('addNode', () => {
  it('splices a filter node into the chain after map, rewiring map→destination', () => {
    counter = 0;
    const flow = base();
    const next = addNode(flow, 'filter', 'map', genId);
    // new node id n1; chain becomes map→n1→destination
    expect(next.nodes.some((n) => n.id === 'n1' && n.kind === 'filter')).toBe(true);
    expect(next.edges).toContainEqual({ from: 'map', to: 'n1' });
    expect(next.edges).toContainEqual({ from: 'n1', to: 'destination' });
    expect(next.edges).not.toContainEqual({ from: 'map', to: 'destination' });
    // original untouched
    expect(flow.edges).toContainEqual({ from: 'map', to: 'destination' });
  });

  it('gives a destination node a default config naming the first catalog table is NOT its job — default is empty table', () => {
    counter = 0;
    const next = addNode(base(), 'destination', 'map', genId);
    const node = next.nodes.find((n) => n.id === 'n1')!;
    expect(node.config).toEqual({ kind: 'd1', table: '', mode: 'stored' });
  });

  it('defaults a transform node to an empty snippet', () => {
    counter = 0;
    const next = addNode(base(), 'transform', 'source', genId);
    const node = next.nodes.find((n) => n.id === 'n1')!;
    expect(node.config).toEqual({ mode: 'snippet', snippet: '' });
  });
});

describe('removeNode', () => {
  it('heals the chain: removing map reconnects source→destination', () => {
    const next = removeNode(base(), 'map');
    expect(next.nodes.some((n) => n.id === 'map')).toBe(false);
    expect(next.edges).toContainEqual({ from: 'source', to: 'destination' });
  });

  it('is a no-op for a source node (returns the same graph value)', () => {
    const flow = base();
    const next = removeNode(flow, 'source');
    expect(next.nodes.some((n) => n.id === 'source')).toBe(true);
    expect(next.edges).toEqual(flow.edges);
  });
});

describe('route branches', () => {
  it('addBranch adds a route out-edge with empty when; setWhen sets it', () => {
    counter = 0;
    let flow = addNode(base(), 'route', 'map', genId); // route = n1, edge map→n1, n1→destination
    flow = addBranch(flow, 'n1', 'destination');
    const branch = flow.edges.find((e) => e.from === 'n1' && e.to === 'destination')!;
    expect(branch.when).toBe('');
    flow = setWhen(flow, 'n1', 'destination', 'row.active === true');
    expect(flow.edges.find((e) => e.from === 'n1' && e.to === 'destination')!.when).toBe('row.active === true');
  });
});

describe('connect / disconnect / setNodeConfig immutability', () => {
  it('connect adds an edge and does not mutate the input', () => {
    const flow = base();
    const next = connect(flow, 'map', 'source'); // arbitrary extra edge for the test
    expect(next.edges).toContainEqual({ from: 'map', to: 'source' });
    expect(flow.edges).not.toContainEqual({ from: 'map', to: 'source' });
  });

  it('disconnect removes the matching edge', () => {
    const next = disconnect(base(), 'map', 'destination');
    expect(next.edges).not.toContainEqual({ from: 'map', to: 'destination' });
  });

  it('setNodeConfig replaces one config immutably', () => {
    const flow = base();
    const next = setNodeConfig(flow, 'destination', { kind: 'd1', table: 'archive', mode: 'stored' });
    expect((next.nodes.find((n) => n.id === 'destination')!.config as any).table).toBe('archive');
    expect((flow.nodes.find((n) => n.id === 'destination')!.config as any).table).toBe('clients');
  });
});

describe('graphIssues', () => {
  it('flags a destination naming a table not in the catalog', () => {
    const flow = setNodeConfig(base(), 'destination', { kind: 'd1', table: 'ghost', mode: 'stored' });
    expect(graphIssues(flow, catalog).some((m) => m.includes('ghost'))).toBe(true);
  });

  it('flags a route with fewer than 2 branches or an empty when', () => {
    counter = 0;
    const flow = addNode(base(), 'route', 'map', genId); // route n1 has a single out-edge n1→destination, no when
    const issues = graphIssues(flow, catalog);
    expect(issues.some((m) => m.toLowerCase().includes('route'))).toBe(true);
  });

  it('is clean for the base linear flow', () => {
    expect(graphIssues(base(), catalog)).toEqual([]);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd eldrin-core && npx vitest run src/pages/integrations/flow-graph-model.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement the model**

Create `flow-graph-model.ts`:

```typescript
import type { FlowGraph } from './integrations-api';
import type { Catalog } from './integration-catalog';

export type NodeKind = 'source' | 'transform' | 'filter' | 'map' | 'route' | 'destination';

type Node = FlowGraph['nodes'][number];
type Edge = FlowGraph['edges'][number];

function defaultConfig(kind: NodeKind): unknown {
  switch (kind) {
    case 'transform':
    case 'filter': return { mode: 'snippet', snippet: '' };
    case 'map': return { connections: [] };
    case 'route': return {};
    case 'destination': return { kind: 'd1', table: '', mode: 'stored' };
    default: return {};
  }
}

/** Insert a node into the linear chain after `afterNodeId`, splicing the single outgoing edge. */
export function addNode(flow: FlowGraph, kind: NodeKind, afterNodeId: string, genId: () => string): FlowGraph {
  const id = genId();
  const node: Node = { id, kind, config: defaultConfig(kind) };
  const outIdx = flow.edges.findIndex((e) => e.from === afterNodeId);
  const edges: Edge[] = [...flow.edges];
  if (outIdx >= 0) {
    const succ = edges[outIdx].to;
    edges.splice(outIdx, 1, { from: afterNodeId, to: id }, { from: id, to: succ });
  } else {
    edges.push({ from: afterNodeId, to: id });
  }
  return { ...flow, nodes: [...flow.nodes, node], edges };
}

/** Remove a node and heal the chain (reconnect its single predecessor to its single successor). Source nodes are not removable. */
export function removeNode(flow: FlowGraph, nodeId: string): FlowGraph {
  const node = flow.nodes.find((n) => n.id === nodeId);
  if (!node || node.kind === 'source') return flow;
  const preds = flow.edges.filter((e) => e.to === nodeId).map((e) => e.from);
  const succs = flow.edges.filter((e) => e.from === nodeId).map((e) => e.to);
  const edges = flow.edges.filter((e) => e.from !== nodeId && e.to !== nodeId);
  // Heal: single predecessor + single successor → bridge them.
  if (preds.length === 1 && succs.length === 1) {
    edges.push({ from: preds[0], to: succs[0] });
  }
  return { ...flow, nodes: flow.nodes.filter((n) => n.id !== nodeId), edges };
}

export function connect(flow: FlowGraph, fromId: string, toId: string): FlowGraph {
  if (flow.edges.some((e) => e.from === fromId && e.to === toId)) return flow;
  return { ...flow, edges: [...flow.edges, { from: fromId, to: toId }] };
}

export function disconnect(flow: FlowGraph, fromId: string, toId: string): FlowGraph {
  return { ...flow, edges: flow.edges.filter((e) => !(e.from === fromId && e.to === toId)) };
}

export function addBranch(flow: FlowGraph, routeId: string, toId: string): FlowGraph {
  if (flow.edges.some((e) => e.from === routeId && e.to === toId)) return flow;
  return { ...flow, edges: [...flow.edges, { from: routeId, to: toId, when: '' }] };
}

export function setWhen(flow: FlowGraph, fromId: string, toId: string, expr: string): FlowGraph {
  return {
    ...flow,
    edges: flow.edges.map((e) =>
      e.from === fromId && e.to === toId ? { ...e, when: expr } : e),
  };
}

export function setNodeConfig(flow: FlowGraph, nodeId: string, config: unknown): FlowGraph {
  return { ...flow, nodes: flow.nodes.map((n) => (n.id === nodeId ? { ...n, config } : n)) };
}

/** UX-only client guardrails. The server's validateFlow is authoritative. */
export function graphIssues(flow: FlowGraph, catalog: Catalog): string[] {
  const issues: string[] = [];
  const tableNames = new Set(catalog.tables.map((t) => t.name));

  for (const n of flow.nodes) {
    if (n.kind === 'destination') {
      const table = (n.config as { table?: string }).table ?? '';
      if (!tableNames.has(table)) {
        issues.push(`destination '${n.id}': table '${table}' is not an available table`);
      }
    }
    if (n.kind === 'route') {
      const outs = flow.edges.filter((e) => e.from === n.id);
      if (outs.length < 2) {
        issues.push(`route '${n.id}' needs at least 2 branches`);
      }
      if (outs.some((e) => !e.when || e.when.trim() === '')) {
        issues.push(`route '${n.id}' has a branch with no condition`);
      }
    }
  }

  // Reachability from the source node(s).
  const sources = flow.nodes.filter((n) => n.kind === 'source').map((n) => n.id);
  const reachable = new Set<string>(sources);
  let grew = true;
  while (grew) {
    grew = false;
    for (const e of flow.edges) {
      if (reachable.has(e.from) && !reachable.has(e.to)) { reachable.add(e.to); grew = true; }
    }
  }
  for (const n of flow.nodes) {
    if (n.kind !== 'source' && !reachable.has(n.id)) {
      issues.push(`node '${n.id}' is not reachable from the source`);
    }
  }
  return issues;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd eldrin-core && npx vitest run src/pages/integrations/flow-graph-model.test.ts`
Expected: PASS (all). If the `destination` default-table test conflicts with a reading of the spec, note the spec says "first catalog table **or** `''`"; this plan picks `''` and lets the inspector default the dropdown — keep the test asserting `''`.

- [ ] **Step 5: Typecheck**

Run: `cd eldrin-core && npx tsc -b --noEmit`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
cd eldrin-core
git add src/pages/integrations/flow-graph-model.ts src/pages/integrations/flow-graph-model.test.ts
git commit -m "feat(integrations): add immutable FlowGraph structural reducers + graphIssues"
```

---

### Task 4: Graph renderer `graph-render.ts`

**Files:**
- Create: `eldrin-core/src/pages/integrations/graph-render.ts`
- Create: `eldrin-core/src/pages/integrations/graph-render.test.ts`

**Interfaces:**
- Consumes: `FlowGraph` from `integrations-api.ts`; `Node`, `Edge` types from `@xyflow/react`.
- Produces: `graphToFlow(flow: FlowGraph): { nodes: Node[]; edges: Edge[] }`. Each xyflow node has `id` = the FlowGraph node id, `type: 'flowNode'`, `data: { kind, label, config }`. Each xyflow edge id = `${from}->${to}`, `label` = the edge's `when` (if any). Consumed by Task 5's `StructuralCanvas`.

- [ ] **Step 1: Write the failing test**

Create `graph-render.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import { graphToFlow } from './graph-render';
import type { FlowGraph } from './integrations-api';

const routed: FlowGraph = {
  id: 'acme:clients', integrationId: 'acme', trigger: { kind: 'manual' },
  nodes: [
    { id: 'source', kind: 'source', config: {} },
    { id: 'map', kind: 'map', config: { connections: [] } },
    { id: 'route', kind: 'route', config: {} },
    { id: 'd1', kind: 'destination', config: { kind: 'd1', table: 'active', mode: 'stored' } },
    { id: 'd2', kind: 'destination', config: { kind: 'd1', table: 'archive', mode: 'stored' } },
  ],
  edges: [
    { from: 'source', to: 'map' }, { from: 'map', to: 'route' },
    { from: 'route', to: 'd1', when: 'row.active === true' },
    { from: 'route', to: 'd2', when: 'row.active === false' },
  ],
};

describe('graphToFlow', () => {
  it('renders one xyflow node per FlowGraph node, carrying kind in data', () => {
    const { nodes } = graphToFlow(routed);
    expect(nodes).toHaveLength(5);
    expect(nodes.find((n) => n.id === 'route')!.data.kind).toBe('route');
  });

  it('renders an edge per FlowGraph edge with the when as label', () => {
    const { edges } = graphToFlow(routed);
    expect(edges).toHaveLength(4);
    const branch = edges.find((e) => e.id === 'route->d1')!;
    expect(branch.label).toBe('row.active === true');
  });

  it('lays nodes out left-to-right by distance from the source', () => {
    const { nodes } = graphToFlow(routed);
    const x = (id: string) => nodes.find((n) => n.id === id)!.position.x;
    expect(x('source')).toBeLessThan(x('map'));
    expect(x('map')).toBeLessThan(x('route'));
    expect(x('route')).toBeLessThan(x('d1'));
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd eldrin-core && npx vitest run src/pages/integrations/graph-render.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement the renderer**

Create `graph-render.ts`:

```typescript
import type { Node, Edge } from '@xyflow/react';
import type { FlowGraph } from './integrations-api';

const COL_W = 200;
const ROW_H = 90;

/** BFS distance (column) from any source node. */
function columns(flow: FlowGraph): Map<string, number> {
  const dist = new Map<string, number>();
  const queue: string[] = [];
  for (const n of flow.nodes) if (n.kind === 'source') { dist.set(n.id, 0); queue.push(n.id); }
  while (queue.length) {
    const id = queue.shift()!;
    const d = dist.get(id)!;
    for (const e of flow.edges) {
      if (e.from === id && !dist.has(e.to)) { dist.set(e.to, d + 1); queue.push(e.to); }
    }
  }
  // Any orphan node gets pushed to the far right so it stays visible.
  const maxD = Math.max(0, ...dist.values());
  for (const n of flow.nodes) if (!dist.has(n.id)) dist.set(n.id, maxD + 1);
  return dist;
}

export function graphToFlow(flow: FlowGraph): { nodes: Node[]; edges: Edge[] } {
  const col = columns(flow);
  const perCol = new Map<number, number>(); // running row index per column
  const nodes: Node[] = flow.nodes.map((n) => {
    const c = col.get(n.id) ?? 0;
    const row = perCol.get(c) ?? 0;
    perCol.set(c, row + 1);
    const label = n.kind === 'destination' ? `${n.kind}: ${(n.config as { table?: string }).table ?? ''}` : n.kind;
    return {
      id: n.id,
      type: 'flowNode',
      position: { x: c * COL_W, y: row * ROW_H },
      data: { kind: n.kind, label, config: n.config },
    };
  });
  const edges: Edge[] = flow.edges.map((e) => ({
    id: `${e.from}->${e.to}`,
    source: e.from,
    target: e.to,
    ...(e.when ? { label: e.when } : {}),
  }));
  return { nodes, edges };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd eldrin-core && npx vitest run src/pages/integrations/graph-render.test.ts`
Expected: PASS (3/3).

- [ ] **Step 5: Typecheck**

Run: `cd eldrin-core && npx tsc -b --noEmit`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
cd eldrin-core
git add src/pages/integrations/graph-render.ts src/pages/integrations/graph-render.test.ts
git commit -m "feat(integrations): add pure FlowGraph->xyflow renderer"
```

---

### Task 5: Structural canvas component `StructuralCanvas.tsx` + `FlowNode.tsx`

**Files:**
- Create: `eldrin-core/src/pages/integrations/FlowNode.tsx`
- Create: `eldrin-core/src/pages/integrations/StructuralCanvas.tsx`

**Interfaces:**
- Consumes: `graphToFlow` (Task 4); `addNode`, `connect`, `disconnect`, `addBranch`, `type NodeKind` (Task 3); `FlowGraph` from `integrations-api.ts`; `@xyflow/react` (`ReactFlow`, `Background`, `Controls`, `MiniMap`, `type NodeTypes`, `type Connection`, `type Edge`). Mirror the existing `MappingCanvas.tsx` setup (`nodeTypes`, `proOptions={{ hideAttribution: true }}`, `'@xyflow/react/dist/style.css'`).
- Produces: `<StructuralCanvas flow onFlowChange onSelectNode selectedNodeId />` where `onFlowChange(next: FlowGraph)` and `onSelectNode(nodeId: string | null)`. Consumed by Task 8's shell.

> No unit test for the React component itself (covered by the Task 10 Playwright smoke + the pure model/render tests). This task's gate is: it compiles, renders, and wires gestures to the Task 3 reducers.

- [ ] **Step 1: Implement `FlowNode.tsx`**

A small presentational node coloured by kind (mirrors `SourceFieldNode`/`TargetFieldNode` style):

```tsx
import { Handle, Position, type NodeProps } from '@xyflow/react';

const KIND_STYLE: Record<string, string> = {
  source: 'border-blue-400 bg-blue-50',
  transform: 'border-gray-400 bg-white',
  filter: 'border-gray-400 bg-white',
  map: 'border-gray-500 bg-white',
  route: 'border-orange-400 bg-orange-50',
  destination: 'border-green-500 bg-green-50',
};

export function FlowNode({ data, selected }: NodeProps) {
  const kind = (data as { kind: string }).kind;
  const label = (data as { label: string }).label;
  return (
    <div className={`rounded-md border px-3 py-2 text-xs ${KIND_STYLE[kind] ?? 'border-gray-300 bg-white'} ${selected ? 'ring-2 ring-primary' : ''}`}>
      <Handle type="target" position={Position.Left} />
      <span className="font-mono">{label}</span>
      <Handle type="source" position={Position.Right} />
    </div>
  );
}
```

- [ ] **Step 2: Implement `StructuralCanvas.tsx`**

```tsx
import { useMemo } from 'react';
import { ReactFlow, Background, Controls, MiniMap, type NodeTypes, type Connection, type Edge } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useTranslation } from 'react-i18next';
import type { FlowGraph } from './integrations-api';
import { graphToFlow } from './graph-render';
import { connect as connectNodes, disconnect } from './flow-graph-model';
import { FlowNode } from './FlowNode';
import { Button } from '@/components/ui/button';

const nodeTypes: NodeTypes = { flowNode: FlowNode };

export function StructuralCanvas({ flow, selectedNodeId, onFlowChange, onSelectNode }: {
  flow: FlowGraph;
  selectedNodeId: string | null;
  onFlowChange: (next: FlowGraph) => void;
  onSelectNode: (id: string | null) => void;
}) {
  const { t } = useTranslation('integrations');
  const { nodes, edges } = useMemo(() => graphToFlow(flow), [flow]);

  const onConnect = (c: Connection) => {
    if (!c.source || !c.target) return;
    onFlowChange(connectNodes(flow, c.source, c.target));
  };
  const onEdgesDelete = (deleted: Edge[]) => {
    let next = flow;
    for (const e of deleted) {
      const [from, to] = e.id.split('->');
      next = disconnect(next, from, to);
    }
    onFlowChange(next);
  };

  return (
    <div className="mt-2 rounded-md border overflow-hidden" style={{ height: 520 }}>
      <ReactFlow
        nodes={nodes.map((n) => ({ ...n, selected: n.id === selectedNodeId }))}
        edges={edges}
        nodeTypes={nodeTypes}
        onConnect={onConnect}
        onEdgesDelete={onEdgesDelete}
        onNodeClick={(_, n) => onSelectNode(n.id)}
        onPaneClick={() => onSelectNode(null)}
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
  );
}
```

(The "+ Add node" affordance lives in the inspector/toolbar in Task 6/8, which calls `addNode`; `t` is imported now so the toolbar copy in Task 8 can be added without re-touching imports — if lint flags `t`/`Button` as unused at this step, remove them here and re-add in Task 8.)

- [ ] **Step 3: Typecheck + lint**

Run: `cd eldrin-core && npx tsc -b --noEmit && npm run lint`
Expected: clean (resolve any unused-import lint as noted above).

- [ ] **Step 4: Commit**

```bash
cd eldrin-core
git add src/pages/integrations/FlowNode.tsx src/pages/integrations/StructuralCanvas.tsx
git commit -m "feat(integrations): add structural canvas + flow node component"
```

---

### Task 6: Node inspector `NodeInspector.tsx` + sub-inspectors

**Files:**
- Create: `eldrin-core/src/pages/integrations/RouteInspector.tsx`
- Create: `eldrin-core/src/pages/integrations/DestinationInspector.tsx`
- Create: `eldrin-core/src/pages/integrations/TransformFilterInspector.tsx`
- Create: `eldrin-core/src/pages/integrations/NodeInspector.tsx`

**Interfaces:**
- Consumes: Task 3 reducers (`addBranch`, `setWhen`, `disconnect`, `setNodeConfig`, `removeNode`, `addNode`); `Catalog` (Task 2); `FlowGraph` from `integrations-api.ts`.
- Produces: `<NodeInspector flow nodeId catalog onFlowChange onOpenMapping />` — the right pane. `onOpenMapping(nodeId)` is called when the selected node is a `map` node and the user clicks "Edit mapping" (Task 8 swaps to the SP5 canvas). Consumed by Task 8.

> Component task — gate is compile + render + correct reducer calls; behaviour covered by Task 10 smoke.

- [ ] **Step 1: Implement `DestinationInspector.tsx`**

```tsx
import { useTranslation } from 'react-i18next';
import type { FlowGraph } from './integrations-api';
import type { Catalog } from './integration-catalog';
import { setNodeConfig } from './flow-graph-model';

export function DestinationInspector({ flow, nodeId, catalog, onFlowChange }: {
  flow: FlowGraph; nodeId: string; catalog: Catalog; onFlowChange: (f: FlowGraph) => void;
}) {
  const { t } = useTranslation('integrations');
  const node = flow.nodes.find((n) => n.id === nodeId)!;
  const cfg = node.config as { kind: string; table: string; mode: string };
  return (
    <div className="space-y-2 text-sm">
      <label className="block font-medium">{t('inspectorTable')}</label>
      <select
        className="w-full rounded-md border px-2 py-1"
        value={cfg.table}
        onChange={(e) => onFlowChange(setNodeConfig(flow, nodeId, { ...cfg, table: e.target.value }))}
      >
        <option value="">—</option>
        {catalog.tables.map((tbl) => <option key={tbl.name} value={tbl.name}>{tbl.name}</option>)}
      </select>
    </div>
  );
}
```

- [ ] **Step 2: Implement `RouteInspector.tsx`**

```tsx
import { useTranslation } from 'react-i18next';
import type { FlowGraph } from './integrations-api';
import type { Catalog } from './integration-catalog';
import { addBranch, setWhen, disconnect } from './flow-graph-model';
import { Button } from '@/components/ui/button';

export function RouteInspector({ flow, nodeId, catalog, onFlowChange }: {
  flow: FlowGraph; nodeId: string; catalog: Catalog; onFlowChange: (f: FlowGraph) => void;
}) {
  const { t } = useTranslation('integrations');
  const branches = flow.edges.filter((e) => e.from === nodeId);
  const destinations = flow.nodes.filter((n) => n.kind === 'destination');
  return (
    <div className="space-y-3 text-sm">
      <div className="font-medium">{t('inspectorBranches')}</div>
      {branches.map((b) => (
        <div key={b.to} className="rounded-md border p-2">
          <div className="mb-1 font-mono text-xs">→ {b.to}</div>
          <input
            className="w-full rounded-md border px-2 py-1 font-mono text-xs"
            placeholder={t('inspectorWhenPlaceholder')}
            value={b.when ?? ''}
            onChange={(e) => onFlowChange(setWhen(flow, nodeId, b.to, e.target.value))}
          />
          <Button variant="ghost" size="sm" className="mt-1" onClick={() => onFlowChange(disconnect(flow, nodeId, b.to))}>
            {t('inspectorRemoveBranch')}
          </Button>
        </div>
      ))}
      <div className="flex items-center gap-2">
        <select id={`add-branch-${nodeId}`} className="rounded-md border px-2 py-1 text-xs" defaultValue="">
          <option value="" disabled>{t('inspectorPickDestination')}</option>
          {destinations.map((d) => <option key={d.id} value={d.id}>{d.id}</option>)}
        </select>
        <Button
          size="sm"
          onClick={() => {
            const sel = document.getElementById(`add-branch-${nodeId}`) as HTMLSelectElement | null;
            if (sel?.value) onFlowChange(addBranch(flow, nodeId, sel.value));
          }}
        >
          {t('inspectorAddBranch')}
        </Button>
      </div>
    </div>
  );
}
```

- [ ] **Step 3: Implement `TransformFilterInspector.tsx`**

```tsx
import { useTranslation } from 'react-i18next';
import type { FlowGraph } from './integrations-api';
import { setNodeConfig } from './flow-graph-model';

export function TransformFilterInspector({ flow, nodeId, onFlowChange }: {
  flow: FlowGraph; nodeId: string; onFlowChange: (f: FlowGraph) => void;
}) {
  const { t } = useTranslation('integrations');
  const node = flow.nodes.find((n) => n.id === nodeId)!;
  const cfg = node.config as { mode: 'snippet' | 'native'; snippet?: string; hook?: string };
  return (
    <div className="space-y-2 text-sm">
      <label className="block font-medium">{t('inspectorSnippet')}</label>
      <textarea
        className="h-28 w-full rounded-md border px-2 py-1 font-mono text-xs"
        value={cfg.snippet ?? ''}
        onChange={(e) => onFlowChange(setNodeConfig(flow, nodeId, { mode: 'snippet', snippet: e.target.value }))}
      />
    </div>
  );
}
```

- [ ] **Step 4: Implement `NodeInspector.tsx`**

```tsx
import { useTranslation } from 'react-i18next';
import type { FlowGraph } from './integrations-api';
import type { Catalog } from './integration-catalog';
import { removeNode } from './flow-graph-model';
import { RouteInspector } from './RouteInspector';
import { DestinationInspector } from './DestinationInspector';
import { TransformFilterInspector } from './TransformFilterInspector';
import { Button } from '@/components/ui/button';

export function NodeInspector({ flow, nodeId, catalog, onFlowChange, onOpenMapping }: {
  flow: FlowGraph; nodeId: string | null; catalog: Catalog;
  onFlowChange: (f: FlowGraph) => void; onOpenMapping: (nodeId: string) => void;
}) {
  const { t } = useTranslation('integrations');
  if (!nodeId) return <div className="w-80 shrink-0 rounded-md border bg-muted/30 p-3 text-sm text-muted-foreground">{t('inspectorEmpty')}</div>;
  const node = flow.nodes.find((n) => n.id === nodeId);
  if (!node) return null;

  return (
    <div className="w-80 shrink-0 rounded-md border bg-muted/30 p-3">
      <div className="mb-2 flex items-center justify-between">
        <span className="text-sm font-medium">{t('inspectorTitle', { kind: node.kind })}</span>
        {node.kind !== 'source' && (
          <Button variant="ghost" size="sm" onClick={() => onFlowChange(removeNode(flow, node.id))}>{t('inspectorRemoveNode')}</Button>
        )}
      </div>
      {node.kind === 'source' && <p className="text-xs text-muted-foreground">{t('inspectorSourceReadonly')}</p>}
      {node.kind === 'map' && <Button size="sm" onClick={() => onOpenMapping(node.id)}>{t('inspectorEditMapping')}</Button>}
      {node.kind === 'route' && <RouteInspector flow={flow} nodeId={node.id} catalog={catalog} onFlowChange={onFlowChange} />}
      {node.kind === 'destination' && <DestinationInspector flow={flow} nodeId={node.id} catalog={catalog} onFlowChange={onFlowChange} />}
      {(node.kind === 'transform' || node.kind === 'filter') && <TransformFilterInspector flow={flow} nodeId={node.id} onFlowChange={onFlowChange} />}
    </div>
  );
}
```

- [ ] **Step 5: Add i18n keys**

Add the new keys used above to the integrations namespace (find the file: `cd eldrin-core && grep -rl "canvasInspector" src/`). Add: `inspectorEmpty`, `inspectorTitle` (`"Inspector: {{kind}}"`), `inspectorRemoveNode`, `inspectorSourceReadonly`, `inspectorEditMapping`, `inspectorBranches`, `inspectorWhenPlaceholder`, `inspectorRemoveBranch`, `inspectorPickDestination`, `inspectorAddBranch`, `inspectorTable`, `inspectorSnippet`.

- [ ] **Step 6: Typecheck + lint**

Run: `cd eldrin-core && npx tsc -b --noEmit && npm run lint`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
cd eldrin-core
git add src/pages/integrations/NodeInspector.tsx src/pages/integrations/RouteInspector.tsx src/pages/integrations/DestinationInspector.tsx src/pages/integrations/TransformFilterInspector.tsx src/i18n
git commit -m "feat(integrations): add node inspector + route/destination/transform sub-inspectors"
```

---

### Task 7: Lifecycle + versions panels

**Files:**
- Create: `eldrin-core/src/pages/integrations/LifecyclePanel.tsx`
- Create: `eldrin-core/src/pages/integrations/VersionsPanel.tsx`
- Modify: `eldrin-core/src/pages/integrations/integrations-api.ts` (add `publishFlow`, `republishFlow`, `fetchVersions`)
- Test: `eldrin-core/src/pages/integrations/integrations-api.test.ts` (add cases for the new calls)

**Interfaces:**
- Consumes: `AuthFetch`, `Result`, `StoredFlow` (`integrations-api.ts`); `saveFlow` (`save-flow.ts`) for Save draft.
- Produces:
  - `publishFlow(appId, flowId, baseVersion, authFetch): Promise<Result<{ version: number }>>` → `POST /api/flows/:id/publish` body `{ baseVersion }`.
  - `republishFlow(appId, flowId, version, authFetch): Promise<Result<{ version: number }>>` → `POST /api/flows/:id/republish` body `{ version }`.
  - `fetchVersions(appId, flowId, authFetch): Promise<Result<StoredFlow[]>>` → `GET /api/flows/:id/versions`.
  - `<LifecyclePanel onSaveDraft onPublish status disabled />`, `<VersionsPanel versions onRollback />`. Consumed by Task 8.

- [ ] **Step 1: Write failing API tests**

Add to `integrations-api.test.ts` (mirror its existing fetch-mock style):

```typescript
import { publishFlow, republishFlow, fetchVersions } from './integrations-api';

it('publishFlow POSTs to /publish with baseVersion', async () => {
  let captured: any = null;
  const af: AuthFetch = async (_app, path, init) => {
    captured = { path, body: JSON.parse(String(init?.body)) };
    return new Response(JSON.stringify({ version: 3 }), { status: 200 });
  };
  const r = await publishFlow('acme', 'acme:clients', 2, af);
  expect(r.ok).toBe(true);
  expect(captured.path).toBe('/api/flows/acme%3Aclients/publish');
  expect(captured.body).toEqual({ baseVersion: 2 });
});

it('republishFlow POSTs to /republish with version', async () => {
  let captured: any = null;
  const af: AuthFetch = async (_app, path, init) => {
    captured = { path, body: JSON.parse(String(init?.body)) };
    return new Response(JSON.stringify({ version: 5 }), { status: 200 });
  };
  await republishFlow('acme', 'acme:clients', 5, af);
  expect(captured.path).toBe('/api/flows/acme%3Aclients/republish');
  expect(captured.body).toEqual({ version: 5 });
});

it('fetchVersions GETs the versions list', async () => {
  const af: AuthFetch = async () => new Response(JSON.stringify([{ id: 'acme:clients', version: 2, status: 'published' }]), { status: 200 });
  const r = await fetchVersions('acme', 'acme:clients', af);
  expect(r.ok).toBe(true);
  if (r.ok) expect(r.data[0].status).toBe('published');
});
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd eldrin-core && npx vitest run src/pages/integrations/integrations-api.test.ts -t "publishFlow|republishFlow|fetchVersions"`
Expected: FAIL — functions not found.

- [ ] **Step 3: Implement the API calls**

Append to `integrations-api.ts` (reuse the existing `call<T>` helper already in the file):

```typescript
export function publishFlow(appId: string, flowId: string, baseVersion: number | null, authFetch: AuthFetch): Promise<Result<{ version: number }>> {
  return call<{ version: number }>(authFetch(appId, `/api/flows/${encodeURIComponent(flowId)}/publish`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ baseVersion }),
  }));
}

export function republishFlow(appId: string, flowId: string, version: number, authFetch: AuthFetch): Promise<Result<{ version: number }>> {
  return call<{ version: number }>(authFetch(appId, `/api/flows/${encodeURIComponent(flowId)}/republish`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ version }),
  }));
}

export function fetchVersions(appId: string, flowId: string, authFetch: AuthFetch): Promise<Result<StoredFlow[]>> {
  return call<StoredFlow[]>(authFetch(appId, `/api/flows/${encodeURIComponent(flowId)}/versions`));
}
```

- [ ] **Step 4: Run to verify they pass**

Run: `cd eldrin-core && npx vitest run src/pages/integrations/integrations-api.test.ts -t "publishFlow|republishFlow|fetchVersions"`
Expected: PASS (3/3).

- [ ] **Step 5: Implement `LifecyclePanel.tsx`**

```tsx
import { useTranslation } from 'react-i18next';
import { Button } from '@/components/ui/button';

export function LifecyclePanel({ onSaveDraft, onPublish, saveDisabled, publishDisabled, status }: {
  onSaveDraft: () => void; onPublish: () => void;
  saveDisabled: boolean; publishDisabled: boolean;
  status: { kind: 'idle' | 'saved' | 'published' | 'error' | 'conflict'; msg?: string };
}) {
  const { t } = useTranslation('integrations');
  return (
    <div className="mt-3 flex items-center gap-3">
      <Button size="sm" onClick={onSaveDraft} disabled={saveDisabled}>{t('saveDraft')}</Button>
      <Button size="sm" variant="secondary" onClick={onPublish} disabled={publishDisabled}>{t('publish')}</Button>
      {status.kind === 'saved' && <span className="text-sm text-green-600">{status.msg}</span>}
      {status.kind === 'published' && <span className="text-sm text-green-700">{status.msg}</span>}
      {status.kind === 'error' && <span className="text-sm text-destructive">{status.msg}</span>}
      {status.kind === 'conflict' && <span className="text-sm text-destructive">{t('conflict')}</span>}
    </div>
  );
}
```

- [ ] **Step 6: Implement `VersionsPanel.tsx`**

```tsx
import { useTranslation } from 'react-i18next';
import type { StoredFlow } from './integrations-api';
import { Button } from '@/components/ui/button';

export function VersionsPanel({ versions, onRollback }: {
  versions: StoredFlow[]; onRollback: (version: number) => void;
}) {
  const { t } = useTranslation('integrations');
  if (versions.length === 0) return null;
  return (
    <div className="mt-3 rounded-md border p-3 text-sm">
      <div className="mb-2 font-medium">{t('versionsTitle')}</div>
      <ul className="space-y-1">
        {versions.map((v) => (
          <li key={v.version} className="flex items-center justify-between">
            <span className="font-mono text-xs">v{v.version} · {v.status}</span>
            {v.status !== 'draft' && (
              <Button variant="link" size="sm" onClick={() => onRollback(v.version)}>{t('rollback')}</Button>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
```

- [ ] **Step 7: Add i18n keys + typecheck**

Add `saveDraft`, `publish`, `versionsTitle`, `rollback` to the integrations namespace. Run: `cd eldrin-core && npx tsc -b --noEmit && npm run lint`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
cd eldrin-core
git add src/pages/integrations/LifecyclePanel.tsx src/pages/integrations/VersionsPanel.tsx src/pages/integrations/integrations-api.ts src/pages/integrations/integrations-api.test.ts src/i18n
git commit -m "feat(integrations): add lifecycle (save-draft/publish) + versions/rollback panels"
```

---

### Task 8: Rework `FlowEditorShell.tsx` — open-by-id orchestrator

**Files:**
- Modify: `eldrin-core/src/pages/integrations/FlowEditorShell.tsx` (rewrite)

**Interfaces:**
- Consumes: `fetchFlow` (`integrations-api.ts`, `GET /:id` → `StoredFlow` with `flow`/`version`/`status`); `fetchCatalog` (Task 2); `fetchFlowFields`, `fetchBuiltinSpecs` (existing); `saveFlow` (existing); `publishFlow`, `republishFlow`, `fetchVersions` (Task 7); `StructuralCanvas` (Task 5); `NodeInspector` (Task 6); `LifecyclePanel`, `VersionsPanel` (Task 7); the existing `MappingCanvas` + `toFlowDraft`/`applyDraft` (SP5) for the map drill-in; `addNode`, `setNodeConfig`, `graphIssues`, `type NodeKind` (Task 3).
- Produces: `<FlowEditorShell appId flowId onClose onSaved />` — **prop contract changes** from `flow`/`baseVersion` to `flowId`. Consumed by Task 9's `IntegrationList`.

- [ ] **Step 1: Rewrite the shell**

Replace `FlowEditorShell.tsx` with the open-by-id orchestrator. Key behaviours: fetch the flow + catalog on mount; hold `flow: FlowGraph` and `version` in state; view toggle `structure | mapping | form`; a small toolbar to add nodes; map drill-in via `toFlowDraft`/`applyDraft`; Save draft (`saveFlow`), Publish (`publishFlow`), Rollback (`republishFlow` + reload). The map drill-in writes back via `setNodeConfig(flow, mapNodeId, newMapConfig)`.

```tsx
import { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchFlow, fetchBuiltinSpecs, fetchFlowFields, publishFlow, republishFlow, fetchVersions, type FlowGraph, type BuiltinArg, type FlowFields, type StoredFlow } from './integrations-api';
import { fetchCatalog, type Catalog } from './integration-catalog';
import { saveFlow } from './save-flow';
import { addNode, setNodeConfig, graphIssues, type NodeKind } from './flow-graph-model';
import { toFlowDraft, applyDraft, type FlowDraft } from './flow-edit-model';
import { StructuralCanvas } from './StructuralCanvas';
import { NodeInspector } from './NodeInspector';
import { MappingCanvas } from './MappingCanvas';
import { LifecyclePanel } from './LifecyclePanel';
import { VersionsPanel } from './VersionsPanel';
import { Button } from '@/components/ui/button';

type AuthFetchGlobal = (appId: string, input: string, init?: RequestInit) => Promise<Response>;
function getAuthFetch(): AuthFetchGlobal {
  return (window as unknown as { __ELDRIN__: { authenticatedFetch: AuthFetchGlobal } }).__ELDRIN__.authenticatedFetch;
}

const ADDABLE: NodeKind[] = ['transform', 'filter', 'map', 'route', 'destination'];
let nodeSeq = 0;
const genId = () => `node-${Date.now()}-${++nodeSeq}`;

export function FlowEditorShell({ appId, flowId, onClose, onSaved }: {
  appId: string; flowId: string; onClose: () => void; onSaved: () => void;
}) {
  const { t } = useTranslation('integrations');
  const [flow, setFlow] = useState<FlowGraph | null>(null);
  const [version, setVersion] = useState<number | null>(null);
  const [catalog, setCatalog] = useState<Catalog>({ tables: [] });
  const [specs, setSpecs] = useState<Record<string, BuiltinArg[]>>({});
  const [fields, setFields] = useState<FlowFields>({ targetFields: [], sourceFields: [] });
  const [versions, setVersions] = useState<StoredFlow[]>([]);
  const [view, setView] = useState<'structure' | 'mapping' | 'form'>('structure');
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [mappingNodeId, setMappingNodeId] = useState<string | null>(null);
  const [status, setStatus] = useState<{ kind: 'idle' | 'saved' | 'published' | 'error' | 'conflict'; msg?: string }>({ kind: 'idle' });

  const reload = useCallback(async () => {
    const af = getAuthFetch();
    const r = await fetchFlow(appId, flowId, af);
    if (r.ok) { setFlow(r.data.flow); setVersion(r.data.version); }
    fetchCatalog(appId, af).then((c) => { if (c.ok) setCatalog(c.data); });
    fetchBuiltinSpecs(appId, af).then((s) => { if (s.ok) setSpecs(s.data); });
    fetchFlowFields(appId, flowId, af).then((f) => { if (f.ok) setFields(f.data); });
    fetchVersions(appId, flowId, af).then((v) => { if (v.ok) setVersions(v.data); });
  }, [appId, flowId]);

  useEffect(() => { reload(); }, [reload]);

  if (!flow) return <div className="mt-2 rounded-md border p-3 text-sm text-muted-foreground">…</div>;

  const issues = graphIssues(flow, catalog);
  const invalid = issues.length > 0;

  const saveDraft = async () => {
    const r = await saveFlow(appId, flow, version, getAuthFetch());
    if (r.ok) { setVersion(r.data.version); setStatus({ kind: 'saved', msg: t('savedDraft', { version: r.data.version }) }); onSaved(); reload(); }
    else if (r.status === 409) setStatus({ kind: 'conflict' });
    else setStatus({ kind: 'error', msg: r.error });
  };
  const publish = async () => {
    const r = await publishFlow(appId, flowId, version, getAuthFetch());
    if (r.ok) { setStatus({ kind: 'published', msg: t('published', { version: r.data.version }) }); onSaved(); reload(); }
    else if (r.status === 409) setStatus({ kind: 'conflict' });
    else setStatus({ kind: 'error', msg: r.error });
  };
  const rollback = async (v: number) => {
    const r = await republishFlow(appId, flowId, v, getAuthFetch());
    if (r.ok) { setStatus({ kind: 'published', msg: t('published', { version: r.data.version }) }); onSaved(); reload(); }
    else setStatus({ kind: 'error', msg: r.error });
  };

  // Map drill-in: edit one map node's connections via the SP5 canvas, write back with setNodeConfig.
  const openMapping = (nodeId: string) => { setMappingNodeId(nodeId); setView('mapping'); };
  const mapNode = mappingNodeId ? flow.nodes.find((n) => n.id === mappingNodeId) : null;
  const mapDraft: FlowDraft | null = mapNode
    ? toFlowDraft({ ...flow, nodes: [mapNode] } as FlowGraph, specs) // toFlowDraft reads the map node + trigger
    : null;
  const onMapDraftChange = (next: FlowDraft) => {
    if (!mapNode) return;
    const applied = applyDraft({ ...flow, nodes: [mapNode] } as FlowGraph, next, specs);
    if (applied.ok) {
      const newMapConfig = applied.flow.nodes.find((n) => n.id === mapNode.id)!.config;
      setFlow(setNodeConfig(flow, mapNode.id, newMapConfig));
    }
  };

  return (
    <div className="mt-2 rounded-md border p-3">
      <div className="mb-3 inline-flex rounded-md border p-0.5 text-sm">
        <button className={`rounded px-3 py-1 ${view === 'structure' ? 'bg-muted font-medium' : ''}`} onClick={() => setView('structure')}>{t('viewStructure')}</button>
        <button className={`rounded px-3 py-1 ${view === 'mapping' ? 'bg-muted font-medium' : ''}`} onClick={() => setView('mapping')} disabled={!mappingNodeId}>{t('viewMapping')}</button>
      </div>

      {view === 'structure' && (
        <>
          <div className="mb-2 flex items-center gap-2 text-sm">
            <span className="text-muted-foreground">{t('addNode')}:</span>
            {ADDABLE.map((k) => (
              <Button key={k} variant="outline" size="sm" onClick={() => {
                const anchor = selectedNode ?? flow.nodes[flow.nodes.length - 1].id;
                setFlow(addNode(flow, k, anchor, genId));
              }}>{k}</Button>
            ))}
          </div>
          {invalid && <div className="mb-2 rounded-md border border-amber-500/50 bg-amber-50 px-3 py-2 text-xs text-amber-800">{issues.join(' · ')}</div>}
          <div className="flex gap-3">
            <div className="flex-1"><StructuralCanvas flow={flow} selectedNodeId={selectedNode} onFlowChange={setFlow} onSelectNode={setSelectedNode} /></div>
            <NodeInspector flow={flow} nodeId={selectedNode} catalog={catalog} onFlowChange={setFlow} onOpenMapping={openMapping} />
          </div>
        </>
      )}

      {view === 'mapping' && mapDraft && (
        <MappingCanvas draft={mapDraft} fields={fields} specs={specs} onDraftChange={onMapDraftChange} validationError={null} />
      )}

      <LifecyclePanel onSaveDraft={saveDraft} onPublish={publish} saveDisabled={invalid} publishDisabled={invalid} status={status} />
      <VersionsPanel versions={versions} onRollback={rollback} />
      <div className="mt-2"><Button variant="ghost" size="sm" onClick={onClose}>{t('cancel')}</Button></div>
    </div>
  );
}
```

- [ ] **Step 2: Add i18n keys**

Add `viewStructure`, `viewMapping`, `addNode`, `savedDraft` (`"Draft saved (v{{version}})"`), `published` (`"Published v{{version}}"`) to the integrations namespace. (`cancel`, `conflict` already exist.)

- [ ] **Step 3: Typecheck + lint + unit suite**

Run: `cd eldrin-core && npx tsc -b --noEmit && npm run lint && npx vitest run`
Expected: tsc clean; lint clean; all units green. (`toFlowDraft`/`applyDraft` are called with a one-node view of the flow — confirm they only read `nodes.find(kind==='map')` + `trigger`, which they do.)

- [ ] **Step 4: Commit**

```bash
cd eldrin-core
git add src/pages/integrations/FlowEditorShell.tsx src/i18n
git commit -m "feat(integrations): rework FlowEditorShell as open-by-id structural orchestrator"
```

---

### Task 9: `IntegrationList.tsx` — open-by-id + draft badge

**Files:**
- Modify: `eldrin-core/src/pages/integrations/IntegrationList.tsx`

**Interfaces:**
- Consumes: `EffectiveFlow.hasDraft` (Task 2); the reworked `<FlowEditorShell appId flowId onClose onSaved />` (Task 8).
- Produces: nothing downstream.

- [ ] **Step 1: Update the editor mount + badge**

In `IntegrationList.tsx`, change the `FlowEditorShell` invocation to pass `flowId` instead of `flow`/`baseVersion`, and add a "draft pending" badge when `item.hasDraft`:

```tsx
{item.hasDraft && (
  <span className="rounded bg-amber-100 px-1.5 py-0.5 text-xs text-amber-800">{t('draftPending')}</span>
)}
```

```tsx
{editing === item.flow.id && (
  <FlowEditorShell
    appId={id}
    flowId={item.flow.id}
    onClose={() => setEditing(null)}
    onSaved={load}
  />
)}
```

Place the badge inside the existing `<span className="flex items-center gap-3">` next to the `v{version}`/`default` label.

- [ ] **Step 2: Add i18n key + typecheck + lint**

Add `draftPending` (`"draft pending"`). Run: `cd eldrin-core && npx tsc -b --noEmit && npm run lint`
Expected: clean (the old `baseVersion`/`flow` props are gone; tsc confirms no other caller relies on them).

- [ ] **Step 3: Commit**

```bash
cd eldrin-core
git add src/pages/integrations/IntegrationList.tsx src/i18n
git commit -m "feat(integrations): open editor by id + show draft-pending badge"
```

---

### Task 10: Playwright smoke + cross-repo live-verify

**Files:**
- Modify/Create: the eldrin-core Playwright integrations smoke (find it: `cd eldrin-core && grep -rl "mapping canvas\|MappingCanvas\|integrations" e2e tests 2>/dev/null` — extend the SP5 smoke file).

**Interfaces:**
- Consumes: the running app with `eldrin-factorial` mounted. No new code interfaces.

- [ ] **Step 1: Rebuild the SDK dist + dependents (the stale-dist lesson)**

Run:
```bash
cd eldrin-integration && npm run build
cd ../eldrin-factorial && npm run build
```
Expected: both build clean; the catalog route + draft/publish are now in the bundles the running app serves.

- [ ] **Step 2: Add the structural smoke test**

Extend the SP5 integrations Playwright spec with a structural-editing flow. Use the existing spec's login/navigation helpers (open the Integrations admin section, expand an integration, click Edit). Then:

```typescript
test('structural canvas: add a route + second destination, save draft, publish', async ({ page }) => {
  // ... reuse the spec's existing setup to open a flow in the editor (Structure view) ...
  // Add a destination node
  await page.getByRole('button', { name: 'destination' }).click();
  // Add a route node
  await page.getByRole('button', { name: 'route' }).click();
  // Select the route node on the canvas and add a branch with a when
  // (selectors follow the FlowNode label text, e.g. page.getByText('route'))
  await page.getByText('route', { exact: true }).first().click();
  // In the RouteInspector, pick a destination and add the branch, then type a when
  // ... fill the when input, click "Add branch" ...
  // Save draft
  await page.getByRole('button', { name: /save draft/i }).click();
  await expect(page.getByText(/draft saved/i)).toBeVisible();
  // Publish
  await page.getByRole('button', { name: /^publish$/i }).click();
  await expect(page.getByText(/published v/i)).toBeVisible();
});
```

Keep selectors resilient (role + accessible name, matching the i18n copy). If the existing smoke uses a fixed test integration/flow, reuse it; do not invent new backend seed data.

- [ ] **Step 3: Run the Playwright suite**

Run: `cd eldrin-core && npx playwright test`
Expected: the new test passes alongside the existing SP4/SP5 smokes. If the dev server must be running, follow the existing spec's webServer config.

- [ ] **Step 4: Live-verify the cross-repo path manually**

Start the app (per eldrin-core CLAUDE.md / existing dev flow), open the Integrations admin section, open a flow:
- The editor opens in **Structure** view showing the node graph (source read-only).
- The **destination dropdown** lists catalog tables (proves `GET /api/flows/catalog` reached the running app through the rebuilt dist).
- Add a route + second destination, set a `when`, **Save draft** → list shows the **draft-pending** badge; the published flow is unchanged.
- **Publish** → the version advances; reopen confirms the routed flow persisted.

Record the result (version before/after) in the commit message or the SDD ledger.

- [ ] **Step 5: Commit**

```bash
cd eldrin-core
git add e2e
git commit -m "test(integrations): add structural-canvas + draft/publish Playwright smoke"
```

---

## Self-Review

**1. Spec coverage:**
- §1 Architecture → Tasks 5/6/8 (canvas + inspector + shell). ✓
- §2 editing model (reducers + `graphIssues`) → Task 3. ✓
- §3 components (catalog client, graph-render, canvas, inspectors, lifecycle/versions, shell rework, list) → Tasks 2,4,5,6,7,8,9. ✓
- §3 `StoredFlow.status` + open-by-id contract → Task 2 + Task 8. ✓
- §4 SDK `GET /api/flows/catalog` + validation-on-save/publish → Task 1 (route) + Task 8 (save/publish call the SP7 routes that run `validateFlow`). ✓
- §4 cross-repo build seam → Task 1 Step 6 (build dist) + Task 10 Steps 1/4. ✓
- §5 testing (model, render, catalog, lifecycle API, Playwright) → Tasks 3,4,2,7,10. ✓
- Lifecycle UX (Save draft/Publish/Rollback/draft badge) → Tasks 7,8,9. ✓

**2. Placeholder scan:** No TBD/TODO. The one judgement call (destination default table = `''` vs first catalog table) is made explicit in Task 3 Step 4 and asserted in the test. The Playwright selectors are described against the actual i18n copy rather than left vague; the implementer is told to reuse the existing spec's setup.

**3. Type consistency:** `FlowGraph` shape `{id, integrationId, trigger, nodes:{id,kind,config}[], edges:{from,to,when?}[]}` is used consistently (Tasks 3,4,5,6,8). Reducer signatures in Task 3's Produces match their call sites (Tasks 5,6,8). `Catalog`/`CatalogTable` defined in Task 2 and consumed in Tasks 3,6,8. `StoredFlow.status` added in Task 2 and read in Tasks 7,8. `publishFlow`/`republishFlow`/`fetchVersions` signatures in Task 7 match Task 8's calls. `<FlowEditorShell appId flowId onClose onSaved>` defined in Task 8, called in Task 9.

**Note for the implementer (Task 8):** the map drill-in passes a one-node view `{...flow, nodes: [mapNode]}` to `toFlowDraft`/`applyDraft`. This is safe only because those functions read exactly `nodes.find(n => n.kind === 'map')` + `trigger` (verified against `flow-edit-model.ts`). If a future change makes them read other nodes, pass the whole flow and target the map node by id instead.
