# Flow Persistence & CRUD API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make flows editable, versioned, persisted data in `@eldrin-project/eldrin-integration` — a `_integration_flows` table, optimistic-lock CRUD, full validation, admin-gated REST routes, and a stored-overrides-compiled execution overlay.

**Architecture:** A new `_integration_flows` table (one row per flow, optimistic-lock `version`) stores flow graphs as JSON. `loadEffectiveFlows` overlays stored flows onto the descriptor-compiled defaults at sync time (stored replaces compiled, per flow id). `validateFlow` (structural + graph + reference) gates every write. Four admin-gated `/api/flows` routes mount via the host's existing `options.extend` seam. `topoSort` lifts from `execute.ts` to a shared `graph.ts` reused by validation.

**Tech Stack:** TypeScript 5.9 (strict), Vitest, in-memory better-sqlite3 adapter (`makeTestDb`), Hono routes.

## Global Constraints

- **SDK only.** All changes in `/Users/tibor/projects/eldrin-backup/eldrin-integration`. No UI.
- **No behavior change with no stored flows.** With an empty `_integration_flows`, `loadEffectiveFlows` returns the compiled set unchanged → Factorial byte-identical. The existing regression gate must stay green THROUGH the new overlay path.
- **Optimistic-lock versioning, latest-only.** One row per flow id; `version` increments on write; `writeFlow(baseVersion=null)` = create (409 if exists), `writeFlow(baseVersion=N)` = update (409 if stored version ≠ N), writes `version: N+1`. NO history table, NO rollback (deferred to a UI slice).
- **`flow.id` (`"<integration>:<resource>"`) is the persistence key.** Overlay substitutes only compiled flows whose id has a stored match (iterate compiled, not stored).
- **Validation fail-fast:** `validateFlow` throws `IntegrationError(msg, 400)` on first failure. Three layers in order: structural → graph → reference. Snippet `code` stored, NOT executed, at validate time.
- **Graph validation reuses `topoSort`** (lifted to `src/flow/graph.ts`); both `execute.ts` and `validate.ts` import it. The lift is behavior-preserving.
- **All 4 `/api/flows` routes admin-gated:** `resolveUserId` → 401, then `isAdmin` → 403 (mirror the `/api/schema/prune` handler exactly). Mounted via `options.extend?.(app)` — actually mounted INSIDE `createIntegrationWorker` before the wildcard routes, NOT via the user's extend callback (see Task 5).
- **Response envelope:** `c.json(data)` success; `c.json({ error }, status)` failure; `status = e instanceof IntegrationError ? e.status : 500`.
- **`FLOWS_DDL` added to `SDK_TABLES`** so `ensureManagementTables` creates `_integration_flows` (no migration file — config-derived schema).
- **Immutability**; no `console.log`; parameterized SQL; double-quoted identifiers. Conventional commits, attribution disabled. Coverage ≥ 80%.
- Run tests from `/Users/tibor/projects/eldrin-backup/eldrin-integration` with `npx vitest run`.

---

## File Structure

- `src/flow/graph.ts` (new) — `topoSort(flow): FlowNode[]` lifted from `execute.ts`.
- `src/flow/execute.ts` (modify) — import `topoSort` from `./graph`; delete the local copy.
- `src/schema/tables.ts` (modify) — add `FLOWS_DDL`, append to `SDK_TABLES`.
- `src/flow/store.ts` (new) — `StoredFlow`, `readFlow`, `listFlows`, `writeFlow`, `deleteFlow`, `loadEffectiveFlows`.
- `src/flow/store.test.ts` (new).
- `src/flow/validate.ts` (new) — `validateFlow`, `FlowValidationContext`.
- `src/flow/validate.test.ts` (new).
- `src/flow/graph.test.ts` (new) — topoSort behavior (moved/added).
- `src/sync/index.ts` (modify) — `runResourceSync` consults a stored flow (overlay) before compiling.
- `src/host/create-worker.ts` (modify) — mount the 4 `/api/flows` routes; capture `boundHooks`.
- `src/host/create-worker.test.ts` (modify) — route tests.
- `src/index.ts` (modify) — export the new public surface.

---

## Reference: current code (do not re-derive)

`src/schema/tables.ts`: `SDK_TABLES` is `[SYNC_STATE_DDL, INTEGRATION_CONFIG_DDL, WEBHOOK_DELIVERIES_DDL]`. DDL consts are template strings `CREATE TABLE IF NOT EXISTS ...`.

`src/flow/execute.ts` lines 13-41: `function topoSort(flow: Flow): FlowNode[]` (Kahn's; throws `IntegrationError('edge references unknown node: ...', 400)` and `IntegrationError('flow has a cycle', 400)`). It is private; `executeFlow` calls it at the top.

`src/flow/types.ts`: `Flow { id, integrationId, trigger, nodes: FlowNode[], edges: FlowEdge[] }`; `FlowNode { id, kind: NodeKind, config: NodeConfig }`; `NodeKind = 'source'|'map'|'transform'|'filter'|'route'|'destination'`; `MapConfig { connections: Connection[] }`; `Connection { target, sources: string[], transform?: TransformerRef }`; `TransformerRef = {kind:'builtin',fn,args?} | {kind:'snippet',code}`; `TransformConfig`/`FilterConfig = {mode:'native',hook} | {mode:'snippet',snippet}`; `DestinationConfig { kind:'d1', table, mode, ordered? }`; `TriggerConfig = {kind:'cron',expr} | {kind:'webhook',event} | {kind:'manual'}`.

`src/flow/compile.ts`: `compileDescriptorToFlows(descriptor): Flow[]`, `compileResourceToFlow(integrationId, resource): Flow`.

`src/flow/transformers/index.ts`: `BUILTINS: Record<string, BuiltinFn>`.

`src/host/bind-hooks.ts`: `HookRegistry = Record<string, HookFn>`.

`src/host/create-worker.ts`: line 74 `const seed = bindHooks(parseConfig(config), options.hooks ?? {})`; line 75 `const evalSnippet = createSnippetEvaluator()`; `prepare(env)` ~88-99 returns `{ db, effective }`; `options.extend?.(app)` at line 142; `app.post('/api/sync')` at 112 calls `runAllSync(effective, deps)`; `/api/schema/prune` handler at 163-171 is the admin-gate template; `resolveUserId(c)` and `isAdmin(c)` helpers at lines 23-51.

`src/sync/index.ts`: `runResourceSync(resource, deps)` builds an `ExecuteDeps` and calls `executeFlow(compileResourceToFlow('integration', resource), deps)`. `runAllSync(descriptor, deps)` filters to `defaultMode==='stored' && supportedModes.includes('stored')` and calls `runResourceSync` per resource. `SyncDeps` has `db, transport, now, genId, hooks?, evalSnippet?`.

`DatabaseAdapter` (`@eldrin-project/eldrin-app-core`): `.prepare(sql).bind(...).run()/.all<T>()/.first<T>()`.

Test adapter: `makeTestDb(ddl: string[])` from `src/test-helpers.ts`. `IntegrationError(message, status)` from `src/errors.ts`.

---

### Task 1: Lift `topoSort` to a shared `graph.ts`

**Files:**
- Create: `src/flow/graph.ts`
- Modify: `src/flow/execute.ts`
- Test: `src/flow/graph.test.ts`

**Interfaces:**
- Consumes: `Flow`, `FlowNode` from `./types`; `IntegrationError` from `../errors`.
- Produces: `export function topoSort(flow: Flow): FlowNode[]`. Consumed by `execute.ts` (Task 1) and `validate.ts` (Task 4).

- [ ] **Step 1: Write the failing test**

```ts
// src/flow/graph.test.ts
import { describe, it, expect } from 'vitest';
import { topoSort } from './graph';
import { IntegrationError } from '../errors';
import type { Flow } from './types';

function flow(nodes: { id: string }[], edges: { from: string; to: string }[]): Flow {
  return {
    id: 'i:r', integrationId: 'i', trigger: { kind: 'manual' },
    nodes: nodes.map((n) => ({ id: n.id, kind: 'route', config: {} as never })),
    edges,
  };
}

describe('topoSort', () => {
  it('orders a linear chain source->mid->dest', () => {
    const ordered = topoSort(flow(
      [{ id: 'a' }, { id: 'b' }, { id: 'c' }],
      [{ from: 'a', to: 'b' }, { from: 'b', to: 'c' }],
    ));
    expect(ordered.map((n) => n.id)).toEqual(['a', 'b', 'c']);
  });
  it('throws IntegrationError on a cycle', () => {
    expect(() => topoSort(flow(
      [{ id: 'a' }, { id: 'b' }],
      [{ from: 'a', to: 'b' }, { from: 'b', to: 'a' }],
    ))).toThrow(/cycle/i);
  });
  it('throws IntegrationError on an edge to an unknown node', () => {
    expect(() => topoSort(flow([{ id: 'a' }], [{ from: 'a', to: 'ghost' }]))).toThrow(/unknown node/i);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/flow/graph.test.ts`
Expected: FAIL — `Cannot find module './graph'`.

- [ ] **Step 3: Create `src/flow/graph.ts` (move the function verbatim from execute.ts)**

```ts
import { IntegrationError } from '../errors';
import type { Flow, FlowNode } from './types';

/** Kahn's algorithm. Throws IntegrationError on cycle or unknown node reference. */
export function topoSort(flow: Flow): FlowNode[] {
  const byId = new Map(flow.nodes.map((n) => [n.id, n]));
  const indegree = new Map<string, number>(flow.nodes.map((n) => [n.id, 0]));
  const outgoing = new Map<string, string[]>(flow.nodes.map((n) => [n.id, []]));

  for (const e of flow.edges) {
    if (!byId.has(e.from) || !byId.has(e.to)) {
      throw new IntegrationError(`edge references unknown node: ${e.from} -> ${e.to}`, 400);
    }
    indegree.set(e.to, (indegree.get(e.to) ?? 0) + 1);
    outgoing.get(e.from)!.push(e.to);
  }

  const queue = flow.nodes.filter((n) => (indegree.get(n.id) ?? 0) === 0).map((n) => n.id);
  const ordered: FlowNode[] = [];
  while (queue.length > 0) {
    const id = queue.shift()!;
    ordered.push(byId.get(id)!);
    for (const next of outgoing.get(id)!) {
      const d = (indegree.get(next) ?? 0) - 1;
      indegree.set(next, d);
      if (d === 0) queue.push(next);
    }
  }

  if (ordered.length !== flow.nodes.length) {
    throw new IntegrationError('flow has a cycle', 400);
  }
  return ordered;
}
```

In `src/flow/execute.ts`: delete the local `topoSort` function (lines ~13-42) and add to the imports:

```ts
import { topoSort } from './graph';
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run src/flow/graph.test.ts src/flow/execute.test.ts`
Expected: PASS — graph tests pass AND the existing execute tests (which exercise cycle/unknown-node detection through `executeFlow`) stay green, proving the lift is behavior-preserving.

- [ ] **Step 5: Commit**

```bash
git add src/flow/graph.ts src/flow/graph.test.ts src/flow/execute.ts
git commit -m "refactor(flow): lift topoSort to a shared graph module"
```

---

### Task 2: `_integration_flows` table DDL

**Files:**
- Modify: `src/schema/tables.ts`
- Test: `src/schema/tables.test.ts` (extend)

**Interfaces:**
- Produces: `export const FLOWS_DDL: string`; `SDK_TABLES` includes it. Consumed by Task 3 (store) and `ensureManagementTables`.

- [ ] **Step 1: Write the failing test (append to `src/schema/tables.test.ts`)**

```ts
import { FLOWS_DDL, SDK_TABLES } from './tables';

describe('flows table DDL', () => {
  it('FLOWS_DDL creates _integration_flows with id PK and version', () => {
    expect(FLOWS_DDL).toMatch(/CREATE TABLE IF NOT EXISTS _integration_flows/);
    expect(FLOWS_DDL).toMatch(/id TEXT PRIMARY KEY/);
    expect(FLOWS_DDL).toMatch(/integration_id TEXT NOT NULL/);
    expect(FLOWS_DDL).toMatch(/flow_json TEXT NOT NULL/);
    expect(FLOWS_DDL).toMatch(/version INTEGER NOT NULL/);
  });
  it('SDK_TABLES includes FLOWS_DDL', () => {
    expect(SDK_TABLES).toContain(FLOWS_DDL);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/schema/tables.test.ts`
Expected: FAIL — `FLOWS_DDL` not exported.

- [ ] **Step 3: Edit `src/schema/tables.ts`**

Add after `WEBHOOK_DELIVERIES_DDL`:

```ts
export const FLOWS_DDL =
  `CREATE TABLE IF NOT EXISTS _integration_flows (` +
  `id TEXT PRIMARY KEY, integration_id TEXT NOT NULL, flow_json TEXT NOT NULL, ` +
  `version INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`;
```

Update `SDK_TABLES`:

```ts
export const SDK_TABLES: string[] = [
  SYNC_STATE_DDL,
  INTEGRATION_CONFIG_DDL,
  WEBHOOK_DELIVERIES_DDL,
  FLOWS_DDL,
];
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/schema/tables.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/schema/tables.ts src/schema/tables.test.ts
git commit -m "feat(flow): add _integration_flows table DDL"
```

---

### Task 3: Flow store + optimistic lock + overlay

**Files:**
- Create: `src/flow/store.ts`
- Test: `src/flow/store.test.ts`

**Interfaces:**
- Consumes: `Flow` from `./types`; `IntegrationDescriptor` from `../descriptor`; `compileDescriptorToFlows` from `./compile`; `IntegrationError` from `../errors`; `DatabaseAdapter` from `@eldrin-project/eldrin-app-core`; `FLOWS_DDL` (table assumed created by caller in tests via `makeTestDb`).
- Produces: `StoredFlow`, `readFlow`, `listFlows`, `writeFlow`, `deleteFlow`, `loadEffectiveFlows` (signatures below). Consumed by Task 5 (routes) and the sync overlay.

- [ ] **Step 1: Write the failing test**

```ts
// src/flow/store.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import { readFlow, listFlows, writeFlow, deleteFlow, loadEffectiveFlows } from './store';
import { FLOWS_DDL } from '../schema/tables';
import { IntegrationError } from '../errors';
import { makeTestDb } from '../test-helpers';
import type { Flow } from './types';
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';

const flow = (id: string): Flow => ({
  id, integrationId: 'factorial', trigger: { kind: 'manual' },
  nodes: [
    { id: 'source', kind: 'source', config: { transport: { method: 'GET', path: '/x' }, idField: 'id' } as never },
    { id: 'destination', kind: 'destination', config: { kind: 'd1', table: 'x', mode: 'stored' } as never },
  ],
  edges: [{ from: 'source', to: 'destination' }],
});
let n = 0;
const now = () => 1000 + n++;

describe('flow store', () => {
  let db: DatabaseAdapter;
  beforeEach(async () => { db = await makeTestDb([FLOWS_DDL]); n = 0; });

  it('create then read round-trips deep-equal at version 1', async () => {
    const stored = await writeFlow(db, flow('factorial:employees'), null, now);
    expect(stored.version).toBe(1);
    const read = await readFlow(db, 'factorial:employees');
    expect(read!.flow).toEqual(flow('factorial:employees'));
    expect(read!.version).toBe(1);
  });

  it('second create on same id throws 409 already exists', async () => {
    await writeFlow(db, flow('factorial:employees'), null, now);
    await expect(writeFlow(db, flow('factorial:employees'), null, now)).rejects.toMatchObject({ status: 409 });
  });

  it('update with correct baseVersion bumps version', async () => {
    await writeFlow(db, flow('factorial:employees'), null, now);
    const updated = await writeFlow(db, flow('factorial:employees'), 1, now);
    expect(updated.version).toBe(2);
  });

  it('update with stale baseVersion throws 409 conflict', async () => {
    await writeFlow(db, flow('factorial:employees'), null, now); // v1
    await writeFlow(db, flow('factorial:employees'), 1, now);    // v2
    await expect(writeFlow(db, flow('factorial:employees'), 1, now)).rejects.toMatchObject({ status: 409 });
  });

  it('readFlow returns null when absent', async () => {
    expect(await readFlow(db, 'nope')).toBeNull();
  });

  it('listFlows returns all stored with metadata', async () => {
    await writeFlow(db, flow('factorial:employees'), null, now);
    await writeFlow(db, flow('factorial:projects'), null, now);
    const all = await listFlows(db);
    expect(all.map((f) => f.id).sort()).toEqual(['factorial:employees', 'factorial:projects']);
  });

  it('deleteFlow removes the row (true), false when absent', async () => {
    await writeFlow(db, flow('factorial:employees'), null, now);
    expect(await deleteFlow(db, 'factorial:employees')).toBe(true);
    expect(await readFlow(db, 'factorial:employees')).toBeNull();
    expect(await deleteFlow(db, 'factorial:employees')).toBe(false);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/flow/store.test.ts`
Expected: FAIL — `Cannot find module './store'`.

- [ ] **Step 3: Write `src/flow/store.ts`**

```ts
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';
import type { IntegrationDescriptor } from '../descriptor';
import { IntegrationError } from '../errors';
import { compileDescriptorToFlows } from './compile';
import type { Flow } from './types';

export interface StoredFlow {
  id: string;
  integrationId: string;
  flow: Flow;
  version: number;
  createdAt: number;
  updatedAt: number;
}

interface FlowRow {
  id: string;
  integration_id: string;
  flow_json: string;
  version: number;
  created_at: number;
  updated_at: number;
}

function toStored(row: FlowRow): StoredFlow {
  return {
    id: row.id,
    integrationId: row.integration_id,
    flow: JSON.parse(row.flow_json) as Flow,
    version: row.version,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export async function readFlow(db: DatabaseAdapter, id: string): Promise<StoredFlow | null> {
  const row = await db.prepare('SELECT * FROM _integration_flows WHERE id = ?').bind(id).first<FlowRow>();
  return row ? toStored(row) : null;
}

export async function listFlows(db: DatabaseAdapter): Promise<StoredFlow[]> {
  const res = await db.prepare('SELECT * FROM _integration_flows ORDER BY id').all<FlowRow>();
  return res.results.map(toStored);
}

export async function writeFlow(
  db: DatabaseAdapter,
  flow: Flow,
  baseVersion: number | null,
  now: () => number,
): Promise<StoredFlow> {
  const existing = await readFlow(db, flow.id);
  if (baseVersion === null) {
    if (existing) throw new IntegrationError(`flow already exists: ${flow.id}`, 409);
    const ts = now();
    await db
      .prepare(
        `INSERT INTO _integration_flows (id, integration_id, flow_json, version, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .bind(flow.id, flow.integrationId, JSON.stringify(flow), 1, ts, ts)
      .run();
    return { id: flow.id, integrationId: flow.integrationId, flow, version: 1, createdAt: ts, updatedAt: ts };
  }
  if (!existing) throw new IntegrationError(`flow not found: ${flow.id}`, 404);
  if (existing.version !== baseVersion) {
    throw new IntegrationError(`version conflict: ${flow.id} is at version ${existing.version}, not ${baseVersion}`, 409);
  }
  const ts = now();
  const nextVersion = existing.version + 1;
  await db
    .prepare(
      `UPDATE _integration_flows SET flow_json = ?, version = ?, updated_at = ? WHERE id = ? AND version = ?`,
    )
    .bind(JSON.stringify(flow), nextVersion, ts, flow.id, baseVersion)
    .run();
  return { id: flow.id, integrationId: flow.integrationId, flow, version: nextVersion, createdAt: existing.createdAt, updatedAt: ts };
}

export async function deleteFlow(db: DatabaseAdapter, id: string): Promise<boolean> {
  const existing = await readFlow(db, id);
  if (!existing) return false;
  await db.prepare('DELETE FROM _integration_flows WHERE id = ?').bind(id).run();
  return true;
}

/** Compiled defaults with stored overrides applied per flow id. */
export async function loadEffectiveFlows(
  db: DatabaseAdapter,
  descriptor: IntegrationDescriptor,
): Promise<Flow[]> {
  const compiled = compileDescriptorToFlows(descriptor);
  const out: Flow[] = [];
  for (const def of compiled) {
    const stored = await readFlow(db, def.id);
    out.push(stored ? stored.flow : def);
  }
  return out;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/flow/store.test.ts`
Expected: PASS (all 7).

- [ ] **Step 5: Commit**

```bash
git add src/flow/store.ts src/flow/store.test.ts
git commit -m "feat(flow): add flow store with optimistic-lock versioning and overlay"
```

---

### Task 4: Flow validation

**Files:**
- Create: `src/flow/validate.ts`
- Test: `src/flow/validate.test.ts`

**Interfaces:**
- Consumes: `Flow`, `FlowNode`, `MapConfig`, `Connection`, `TransformConfig`, `FilterConfig`, `DestinationConfig`, `SourceConfig`, `NodeKind` from `./types`; `topoSort` from `./graph`; `BUILTINS` from `./transformers`; `HookRegistry` from `../host/bind-hooks`; `IntegrationError` from `../errors`.
- Produces: `FlowValidationContext`, `validateFlow(flow, ctx)`. Consumed by Task 5 (upsert route).

- [ ] **Step 1: Write the failing test**

```ts
// src/flow/validate.test.ts
import { describe, it, expect } from 'vitest';
import { validateFlow } from './validate';
import type { Flow } from './types';

const ctx = { hooks: { myHook: () => ({}) }, knownTables: new Set(['employees']) };

function base(): Flow {
  return {
    id: 'factorial:employees', integrationId: 'factorial', trigger: { kind: 'manual' },
    nodes: [
      { id: 'source', kind: 'source', config: { transport: { method: 'GET', path: '/e' }, idField: 'id' } as never },
      { id: 'map', kind: 'map', config: { connections: [{ target: 'email', sources: ['email'] }] } as never },
      { id: 'destination', kind: 'destination', config: { kind: 'd1', table: 'employees', mode: 'stored' } as never },
    ],
    edges: [{ from: 'source', to: 'map' }, { from: 'map', to: 'destination' }],
  };
}

describe('validateFlow', () => {
  it('accepts a valid flow', () => {
    expect(() => validateFlow(base(), ctx)).not.toThrow();
  });
  it('accepts a snippet connection without executing the code', () => {
    const f = base();
    (f.nodes[1].config as { connections: unknown[] }).connections = [
      { target: 'label', sources: ['name'], transform: { kind: 'snippet', code: 'this would throw if run' } },
    ];
    expect(() => validateFlow(f, ctx)).not.toThrow();
  });
  it('rejects duplicate node ids', () => {
    const f = base(); f.nodes[1].id = 'source';
    expect(() => validateFlow(f, ctx)).toThrow(/duplicate node id/i);
  });
  it('rejects an unknown node kind', () => {
    const f = base(); (f.nodes[1] as { kind: string }).kind = 'bogus';
    expect(() => validateFlow(f, ctx)).toThrow(/unknown node kind/i);
  });
  it('rejects a map connection with empty sources', () => {
    const f = base();
    (f.nodes[1].config as { connections: unknown[] }).connections = [{ target: 'email', sources: [] }];
    expect(() => validateFlow(f, ctx)).toThrow(/sources/i);
  });
  it('rejects an edge to a missing node', () => {
    const f = base(); f.edges.push({ from: 'map', to: 'ghost' });
    expect(() => validateFlow(f, ctx)).toThrow(/unknown node/i);
  });
  it('rejects zero source nodes', () => {
    const f = base(); (f.nodes[0] as { kind: string }).kind = 'route';
    expect(() => validateFlow(f, ctx)).toThrow(/exactly one source/i);
  });
  it('rejects two destination nodes', () => {
    const f = base();
    f.nodes.push({ id: 'd2', kind: 'destination', config: { kind: 'd1', table: 'employees', mode: 'stored' } as never });
    f.edges.push({ from: 'map', to: 'd2' });
    expect(() => validateFlow(f, ctx)).toThrow(/exactly one destination/i);
  });
  it('rejects a cycle', () => {
    const f = base(); f.edges.push({ from: 'destination', to: 'source' });
    expect(() => validateFlow(f, ctx)).toThrow(/cycle/i);
  });
  it('rejects a native transform hook not in the registry', () => {
    const f = base();
    f.nodes.splice(2, 0, { id: 't', kind: 'transform', config: { mode: 'native', hook: 'missing' } as never });
    f.edges = [{ from: 'source', to: 'map' }, { from: 'map', to: 't' }, { from: 't', to: 'destination' }];
    expect(() => validateFlow(f, ctx)).toThrow(/hook .* not found/i);
  });
  it('rejects a builtin fn not in BUILTINS', () => {
    const f = base();
    (f.nodes[1].config as { connections: unknown[] }).connections = [
      { target: 'x', sources: ['y'], transform: { kind: 'builtin', fn: 'nope' } },
    ];
    expect(() => validateFlow(f, ctx)).toThrow(/builtin .* not found/i);
  });
  it('rejects a destination table not in knownTables', () => {
    const f = base();
    (f.nodes[2].config as { table: string }).table = 'unmanaged';
    expect(() => validateFlow(f, ctx)).toThrow(/table .* not/i);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/flow/validate.test.ts`
Expected: FAIL — `Cannot find module './validate'`.

- [ ] **Step 3: Write `src/flow/validate.ts`**

```ts
import { IntegrationError } from '../errors';
import { topoSort } from './graph';
import { BUILTINS } from './transformers';
import type { HookRegistry } from '../host/bind-hooks';
import type {
  Flow, FlowNode, NodeKind, MapConfig, Connection, TransformConfig, FilterConfig, DestinationConfig,
} from './types';

export interface FlowValidationContext {
  hooks: HookRegistry;
  knownTables: Set<string>;
}

const KINDS: ReadonlySet<NodeKind> = new Set(['source', 'map', 'transform', 'filter', 'route', 'destination']);

function fail(msg: string): never {
  throw new IntegrationError(msg, 400);
}

export function validateFlow(flow: Flow, ctx: FlowValidationContext): void {
  // 1. Structural
  if (!flow.id || flow.id.trim() === '') fail('flow id is required');
  if (!flow.integrationId || flow.integrationId.trim() === '') fail('flow integrationId is required');
  if (!Array.isArray(flow.nodes) || flow.nodes.length === 0) fail('flow requires at least one node');
  const seen = new Set<string>();
  for (const node of flow.nodes) {
    if (!node.id) fail('node id is required');
    if (seen.has(node.id)) fail(`duplicate node id: ${node.id}`);
    seen.add(node.id);
    if (!KINDS.has(node.kind)) fail(`unknown node kind: ${node.kind}`);
    validateNodeConfig(node, ctx);
  }

  // 2. Graph — edge integrity + acyclic (topoSort throws IntegrationError on cycle / unknown node)
  topoSort(flow);
  const sources = flow.nodes.filter((n) => n.kind === 'source');
  const dests = flow.nodes.filter((n) => n.kind === 'destination');
  if (sources.length !== 1) fail(`flow requires exactly one source node (found ${sources.length})`);
  if (dests.length !== 1) fail(`flow requires exactly one destination node (found ${dests.length})`);

  // 3. Reference — destination table known (per-node hook/builtin checks done in validateNodeConfig)
  const destCfg = dests[0].config as DestinationConfig;
  if (!ctx.knownTables.has(destCfg.table)) fail(`destination table '${destCfg.table}' not in known tables`);
}

function validateNodeConfig(node: FlowNode, ctx: FlowValidationContext): void {
  switch (node.kind) {
    case 'map': {
      const cfg = node.config as MapConfig;
      if (!Array.isArray(cfg.connections)) fail(`map node ${node.id}: connections must be an array`);
      for (const conn of cfg.connections) validateConnection(node.id, conn, ctx);
      break;
    }
    case 'transform':
    case 'filter': {
      const cfg = node.config as TransformConfig | FilterConfig;
      if (cfg.mode === 'native') {
        if (!ctx.hooks[cfg.hook]) fail(`${node.kind} node ${node.id}: hook '${cfg.hook}' not found in registry`);
      } else if (cfg.mode !== 'snippet') {
        fail(`${node.kind} node ${node.id}: invalid mode`);
      }
      break;
    }
    case 'destination': {
      const cfg = node.config as DestinationConfig;
      if (cfg.kind !== 'd1') fail(`destination node ${node.id}: unsupported kind '${cfg.kind}'`);
      if (!cfg.table) fail(`destination node ${node.id}: table is required`);
      break;
    }
    // source / route: no extra reference checks in this slice
  }
}

function validateConnection(nodeId: string, conn: Connection, ctx: FlowValidationContext): void {
  if (!conn.target) fail(`map node ${nodeId}: connection requires a target`);
  if (!Array.isArray(conn.sources) || conn.sources.length === 0) {
    fail(`map node ${nodeId}: connection '${conn.target}' requires non-empty sources`);
  }
  if (conn.transform) {
    if (conn.transform.kind === 'builtin') {
      if (!BUILTINS[conn.transform.fn]) fail(`map node ${nodeId}: builtin '${conn.transform.fn}' not found`);
    } else if (conn.transform.kind !== 'snippet') {
      fail(`map node ${nodeId}: invalid transform kind`);
    }
    // snippet code is stored, not executed, at validate time
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/flow/validate.test.ts`
Expected: PASS (all 12).

- [ ] **Step 5: Commit**

```bash
git add src/flow/validate.ts src/flow/validate.test.ts
git commit -m "feat(flow): add structural + graph + reference flow validation"
```

---

### Task 5: Mount `/api/flows` routes + sync overlay

**Files:**
- Modify: `src/host/create-worker.ts`
- Modify: `src/sync/index.ts`
- Test: `src/host/create-worker.test.ts` (extend)

**Interfaces:**
- Consumes: `readFlow`, `listFlows`, `writeFlow`, `deleteFlow` (Task 3); `validateFlow` (Task 4); the existing `resolveUserId`/`isAdmin`/`prepare`.
- Produces: 4 admin-gated routes; `runResourceSync` consulting stored flows.

- [ ] **Step 1: Write the failing route tests (append to `src/host/create-worker.test.ts`)**

Follow the existing prune-route test style in that file (it builds a worker via `createIntegrationWorker` and calls `app.fetch` / the exported `fetch` with crafted `Request`s + Authorization headers). Add:

```ts
// admin JWT: header.payload.sig where payload = base64({"sub":"u","platformRoles":["admin"]})
// non-admin JWT: payload = base64({"sub":"u"})
// Reuse the helpers already present in this test file for building these requests.

describe('/api/flows routes', () => {
  const validFlow = {
    id: 'eldrin-factorial:employees', integrationId: 'eldrin-factorial', trigger: { kind: 'manual' },
    nodes: [
      { id: 'source', kind: 'source', config: { transport: { method: 'GET', path: '/e' }, idField: 'id' } },
      { id: 'map', kind: 'map', config: { connections: [{ target: 'email', sources: ['email'] }] } },
      { id: 'destination', kind: 'destination', config: { kind: 'd1', table: 'employees', mode: 'stored' } },
    ],
    edges: [{ from: 'source', to: 'map' }, { from: 'map', to: 'destination' }],
  };

  it('POST /api/flows/:id without auth → 401', async () => { /* no Authorization → expect 401 */ });
  it('POST /api/flows/:id as non-admin → 403', async () => { /* non-admin JWT → 403 */ });
  it('POST /api/flows/:id as admin with valid flow → 200 + version 1', async () => { /* → {flow, version:1} */ });
  it('POST with body id != path id → 400', async () => { /* flow.id mismatch → 400 */ });
  it('POST with an invalid flow (cycle) → 400', async () => { /* add destination→source edge → 400 */ });
  it('POST update with stale baseVersion → 409', async () => { /* create then update baseVersion 1 twice → 409 */ });
  it('GET /api/flows as admin → lists stored flows', async () => { /* after a create → array contains the id */ });
  it('GET /api/flows/:id unstored → 404', async () => {});
  it('DELETE /api/flows/:id existing → 200 {deleted:true}; absent → 404', async () => {});
});
```

(Write these out fully using the test file's existing request-builder helpers and the in-memory `adapterFactory` the prune tests use, so `_integration_flows` exists via `ensureManagementTables`. The assertions are the behavior in the comments.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/host/create-worker.test.ts`
Expected: FAIL — routes not mounted (404 / wrong status).

- [ ] **Step 3: Mount the routes in `src/host/create-worker.ts`**

Add imports:

```ts
import { readFlow, listFlows, writeFlow, deleteFlow } from '../flow/store';
import { validateFlow } from '../flow/validate';
```

Capture the bound hook registry at worker scope (near line 74-75):

```ts
const boundHooks: HookRegistry = options.hooks ?? {};
```

Mount the 4 routes immediately AFTER `options.extend?.(app)` (line 142) and BEFORE the `/api/:resource/:id` wildcard, so specific `/api/flows` paths win over `/api/:resource`:

```ts
app.get('/api/flows', async (c) => {
  const userId = resolveUserId(c);
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);
  if (!isAdmin(c)) return c.json({ error: 'Forbidden: admin role required' }, 403);
  const { db } = await prepare(c.env);
  const flows = await listFlows(db);
  return c.json(flows.map((f) => ({ id: f.id, integrationId: f.integrationId, version: f.version, updatedAt: f.updatedAt })));
});

app.get('/api/flows/:id', async (c) => {
  const userId = resolveUserId(c);
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);
  if (!isAdmin(c)) return c.json({ error: 'Forbidden: admin role required' }, 403);
  const { db } = await prepare(c.env);
  const stored = await readFlow(db, c.req.param('id'));
  return stored ? c.json(stored) : c.json({ error: 'Flow not found' }, 404);
});

app.post('/api/flows/:id', async (c) => {
  const userId = resolveUserId(c);
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);
  if (!isAdmin(c)) return c.json({ error: 'Forbidden: admin role required' }, 403);
  const { db, effective } = await prepare(c.env);
  const body = await c.req.json().catch(() => null);
  if (!body?.flow) return c.json({ error: 'Missing flow in body' }, 400);
  if (body.flow.id !== c.req.param('id')) return c.json({ error: 'Flow id mismatch' }, 400);
  try {
    validateFlow(body.flow, { hooks: boundHooks, knownTables: new Set(effective.resources.map((r) => r.name)) });
    const stored = await writeFlow(db, body.flow, body.baseVersion ?? null, () => Date.now());
    return c.json({ flow: stored.flow, version: stored.version });
  } catch (e) {
    const status = e instanceof IntegrationError ? e.status : 500;
    return c.json({ error: e instanceof Error ? e.message : 'Write failed' }, status as 400 | 404 | 409 | 500);
  }
});

app.delete('/api/flows/:id', async (c) => {
  const userId = resolveUserId(c);
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);
  if (!isAdmin(c)) return c.json({ error: 'Forbidden: admin role required' }, 403);
  const { db } = await prepare(c.env);
  const removed = await deleteFlow(db, c.req.param('id'));
  return removed ? c.json({ deleted: true }) : c.json({ error: 'Flow not found' }, 404);
});
```

(Ensure `HookRegistry` is imported — it already is at line 8. Ensure `IntegrationError` is imported in this file — it is used by the prune/sync handlers already.)

- [ ] **Step 4: Wire the sync overlay in `src/sync/index.ts`**

`runResourceSync(resource, deps)` currently does `executeFlow(compileResourceToFlow('integration', resource), deps)`. Change it to consult a stored flow first. The descriptor id used by `compileResourceToFlow` is `'integration'` in the current code; the stored flow id from the host is `"<descriptor.id>:<resource.name>"`. To overlay correctly, `runResourceSync` needs the stored flow keyed by the SAME id the compiler produces. Add an optional `effectiveFlow?: Flow` to `SyncDeps` that the caller (host) supplies, OR have `runResourceSync` look it up. Simplest, matches the spec's `loadEffectiveFlows`:

In `runResourceSync`, after building the compiled flow, check the store:

```ts
import { readFlow } from '../flow/store';
// ...
const compiled = compileResourceToFlow('integration', resource);
const stored = await readFlow(deps.db, compiled.id);
const flow = stored ? stored.flow : compiled;
const result = await executeFlow(flow, { /* existing deps */ });
```

**CRITICAL id-mismatch bug to fix here (confirmed in the current code):** `runResourceSync` (sync/index.ts:36) hardcodes `compileResourceToFlow('integration', resource)` → flow id `"integration:<resource.name>"`. But `compileDescriptorToFlows` (compile.ts:68) uses the REAL `descriptor.id` → `"<descriptor.id>:<resource.name>"` (e.g. `"eldrin-factorial:employees"`). The host's `/api/flows` routes store/list flows under the real-descriptor-id form. So if `runResourceSync` keeps looking up `"integration:..."`, the overlay **never connects** — a stored flow silently does nothing. **Fix: thread the real integration id into `runResourceSync`** so its compiled id matches stored ids.

Add `integrationId?: string` to `SyncDeps` and use it (falling back to `'integration'` only if absent, preserving existing standalone tests):

```ts
// SyncDeps gains:  integrationId?: string;
const integrationId = deps.integrationId ?? 'integration';
const compiled = compileResourceToFlow(integrationId, resource);
const stored = await readFlow(deps.db, compiled.id);
const flow = stored ? stored.flow : compiled;
const result = await executeFlow(flow, { /* existing deps */ });
```

Then in `create-worker.ts`'s `buildDeps`, set `integrationId: seed.id` on the returned `SyncDeps` (the host knows the real descriptor id via `seed.id`/`effective.id`). This makes `runAllSync` → `runResourceSync` compile flows under `"<seed.id>:<resource>"`, matching exactly what the `/api/flows` routes persist. Confirm `seed.id` is the same id `compileDescriptorToFlows` would use (it is — both derive from the parsed descriptor). Record in the report that you fixed this mismatch.

- [ ] **Step 5: Run the full suite + typecheck + build**

Run: `npx vitest run && npx tsc --noEmit && npm run build`
Expected: all PASS; the regression gate green (no stored flows → overlay is pass-through); build clean.

- [ ] **Step 6: Commit**

```bash
git add src/host/create-worker.ts src/sync/index.ts src/host/create-worker.test.ts
git commit -m "feat(flow): mount admin-gated /api/flows CRUD routes and stored-flow sync overlay"
```

---

### Task 6: Exports, regression gate, coverage, README, Factorial

**Files:**
- Modify: `src/index.ts`
- Test: `src/flow/store.test.ts` (add overlay test)
- Modify: `README.md`

**Interfaces:**
- Consumes: all prior tasks.

- [ ] **Step 1: Add the `loadEffectiveFlows` overlay test (append to `src/flow/store.test.ts`)**

```ts
import { compileDescriptorToFlows } from './compile';
import type { IntegrationDescriptor } from '../descriptor';

const descriptor: IntegrationDescriptor = {
  id: 'integration',
  connection: { transport: 'http', baseUrl: 'x', auth: { strategy: 'apiKey' } },
  resources: [
    { name: 'employees', transport: { method: 'GET', path: '/e' }, idField: 'id', fieldMap: { id: 'remote_id', email: 'email' }, supportedModes: ['stored'], defaultMode: 'stored' },
  ],
};

describe('loadEffectiveFlows overlay', () => {
  let db: DatabaseAdapter;
  beforeEach(async () => { db = await makeTestDb([FLOWS_DDL]); n = 0; });

  it('returns compiled defaults unchanged when no stored flows', async () => {
    const effective = await loadEffectiveFlows(db, descriptor);
    expect(effective).toEqual(compileDescriptorToFlows(descriptor));
  });

  it('replaces a compiled flow with the stored override for the same id', async () => {
    const compiledId = compileDescriptorToFlows(descriptor)[0].id; // "integration:employees"
    const override = { ...compileDescriptorToFlows(descriptor)[0], trigger: { kind: 'cron', expr: '*/5 * * * *' } as const };
    await writeFlow(db, override, null, now);
    const effective = await loadEffectiveFlows(db, descriptor);
    expect(effective[0].id).toBe(compiledId);
    expect(effective[0].trigger).toEqual({ kind: 'cron', expr: '*/5 * * * *' });
  });
});
```

- [ ] **Step 2: Run it**

Run: `npx vitest run src/flow/store.test.ts`
Expected: PASS.

- [ ] **Step 3: Update `src/index.ts` exports**

```ts
export { readFlow, listFlows, writeFlow, deleteFlow, loadEffectiveFlows, type StoredFlow } from './flow/store';
export { validateFlow, type FlowValidationContext } from './flow/validate';
export { topoSort } from './flow/graph';
export { FLOWS_DDL } from './schema/tables';
```

(Verify no duplicate-export errors; `FLOWS_DDL` joins the existing `tables.ts` export line if present, else add it.)

- [ ] **Step 4: Full suite + coverage + typecheck + build**

Run: `npx vitest run --coverage && npx tsc --noEmit && npm run build`
Expected: all PASS; `src/flow/` (incl. `store.ts`, `validate.ts`, `graph.ts`) coverage ≥ 80%; build clean, no better-sqlite3 in bundle.

- [ ] **Step 5: Verify the regression gate + Factorial**

Run:
```bash
npx vitest run src/flow/regression.test.ts
npm run build
cd /Users/tibor/projects/eldrin-backup/eldrin-factorial && npx vitest run worker/__tests__/host-sync.test.ts
```
Expected: regression gate PASS (no stored flows → overlay pass-through → byte-identical); Factorial host-sync PASS (full_name='Grace Hopper'). Report both.

- [ ] **Step 6: Update README**

In `eldrin-integration/README.md`, add a "Flow persistence" subsection under the Flow model: flows can be stored in `_integration_flows` (one row per flow, optimistic-lock `version`); a stored flow overrides the descriptor-compiled default at sync time via `loadEffectiveFlows`; admin-gated `/api/flows` routes (list/read/upsert/delete) manage them; writes are validated (structural + graph + reference) before persist. Note version history/rollback is deferred. ~10 lines, match existing tone.

- [ ] **Step 7: Commit**

```bash
git add src/index.ts src/flow/store.test.ts README.md
git commit -m "feat(flow): export persistence API; verify overlay regression parity; document"
```

---

## Post-implementation: live verification (manual, not a task)

After all tasks pass + SDK rebuilt + preview restarted: with no stored flows, sync behaves as today. Optionally `curl` an admin POST to `/api/flows/eldrin-factorial:employees` with a tweaked flow (e.g. a `formatDate` builtin connection) and confirm the next sync reflects it — proving the overlay end-to-end.

## Notes

- **Integration-id consistency (Task 5 Step 4):** the stored-flow overlay only connects if `compileResourceToFlow`'s integration id matches the id under which flows are stored. Resolve this end-to-end — read the current `runResourceSync` id usage and keep it consistent; record the choice.
- **Route ordering:** `/api/flows` and `/api/flows/:id` MUST be registered before `/api/:resource` and `/api/:resource/:id`, or the wildcard resource routes will shadow them. Mount right after `options.extend?.(app)`.
- **`topoSort` reuse** keeps validation and execution agreeing on graph validity — do not fork the cycle/edge logic.
