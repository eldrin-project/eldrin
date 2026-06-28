# Flow Graph Model & Executor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the hardcoded `mapRows` sync pipeline in `@eldrin-project/eldrin-integration` with a serializable graph flow model executed by a single graph executor, with a compiler that lowers the existing `IntegrationDescriptor` into flows so Factorial runs unchanged.

**Architecture:** A flow is plain data (typed nodes + edges). `compileDescriptorToFlows` lowers each resource into one `Flow`; `executeFlow` topologically walks any flow, threading a record stream source→map→[transform/filter]→destination. `runResourceSync` is rewritten internally to compile-one-resource-then-execute, keeping its public signature so `runAllSync`, `runScheduled`, and both host call sites are untouched. `mapRows`/`MappedRow` are deleted.

**Tech Stack:** TypeScript 5.8+ (strict), Vitest, in-memory better-sqlite3 test adapter (`src/test-helpers.ts`), `@eldrin-project/eldrin-app-core` `DatabaseAdapter`.

## Global Constraints

- **SDK only.** All changes are in `/Users/tibor/projects/eldrin-backup/eldrin-integration`. No UI, no flow persistence/CRUD, no host route changes beyond what `runResourceSync`'s internal rewrite requires.
- **Immutability.** Never mutate inputs; build new objects with spread (`{ ...x }`). The `raw` payload is immutable; nodes replace `current` with new objects.
- **No `console.log`** in production code.
- **No snippet evaluation.** `mode:'snippet'` transform/filter nodes and conditional route edges throw `NotImplementedError`. `evalSnippet` is an optional, slice-1-absent dep.
- **SQL identifiers must be double-quoted** in all DDL/DML the destination node emits (consistent with hardened `src/schema/ensure.ts`/`prune.ts`). This is a behavior-preserving improvement over the old unquoted `runResourceSync` upsert; the regression gate compares row contents, not SQL text.
- **Behavior preservation (regression gate):** the new path must produce byte-identical D1 table contents to the old `mapRows`/`runResourceSync` path for Factorial — same columns, values, row count, including hook-derived `full_name`.
- **Map direction:** `MapConfig.fields` is `localColumn → remoteKey` (inverse of descriptor `fieldMap`). The compiler inverts.
- **Sync gating preserved:** only resources with `defaultMode === 'stored' && supportedModes.includes('stored')` are executed during sync (matches old `runAllSync`/`runScheduled`/`dueResources`).
- **Coverage ≥ 80%.**
- **Conventional commits**, attribution disabled.
- Run all tests from `/Users/tibor/projects/eldrin-backup/eldrin-integration` with `npx vitest run`.

---

## File Structure

- `src/flow/types.ts` (new) — `Flow`, `FlowNode`, `FlowEdge`, `NodeKind`, `NodeConfig` union, `TriggerConfig`, `Row`, `ExecuteDeps`, `ExecuteResult`. Type-only.
- `src/flow/compile.ts` (new) — `compileDescriptorToFlows(descriptor): Flow[]`.
- `src/flow/execute.ts` (new) — `executeFlow(flow, deps): Promise<ExecuteResult>`, plus internal topo-sort.
- `src/flow/compile.test.ts` (new) — compiler unit tests.
- `src/flow/execute.test.ts` (new) — executor unit tests (per node kind).
- `src/flow/execute-integration.test.ts` (new) — compile+execute against in-memory D1.
- `src/flow/regression.test.ts` (new) — old `mapRows` path vs new path identical-output gate.
- `src/sync/index.ts` (modify) — rewrite `runResourceSync` internals to compile+execute; keep signature. Remove `mapRows` import.
- `src/sync/map.ts` (delete) — after `mapRows` no longer referenced.
- `src/index.ts` (modify) — add flow exports; remove `mapRows`/`MappedRow` exports.

---

## Reference: existing signatures (do not re-derive)

From `@eldrin-project/eldrin-app-core`:
```ts
interface DatabaseAdapter {
  prepare(sql: string): {
    bind(...args: unknown[]): { run(): Promise<unknown>; all<T>(): Promise<{ results: T[] }>; first<T>(): Promise<T | null> };
    run(): Promise<unknown>;
    all<T>(): Promise<{ results: T[] }>;
    first<T>(): Promise<T | null>;
  };
}
```

From `src/transport/index.ts`:
```ts
export interface Transport { fetchAll(resource: ResourceDescriptor): Promise<Record<string, unknown>[]>; }
```

From `src/host/bind-hooks.ts`:
```ts
export type HookFn = (...args: any[]) => any;
export type HookRegistry = Record<string, HookFn>;
```

From `src/descriptor/index.ts` (reused): `IntegrationDescriptor`, `ResourceDescriptor`, `HttpResourceTransport`, `PaginationKind`, `StorageMode`, `ResourceHooks`.

From `src/sync/index.ts` (current): `SyncDeps { db, transport, now: () => number, genId: () => string }`, `SyncResult { resource: string; count: number }`, `runResourceSync(resource, deps)`, `runAllSync(descriptor, deps)`.

From `src/errors.ts`: `IntegrationError(message, status)`, `NotImplementedError(message)`.

Test adapter: `src/test-helpers.ts` exports an in-memory better-sqlite3 `DatabaseAdapter` (inspect the file for the exact factory name before writing tests — it is used by existing `*.test.ts` files in `src/schema/` and `src/sync/`).

---

### Task 1: Flow type model

**Files:**
- Create: `src/flow/types.ts`
- Test: `src/flow/types.test.ts`

**Interfaces:**
- Consumes: `HttpResourceTransport`, `PaginationKind`, `StorageMode` from `../descriptor`; `Transport` from `../transport`; `HookRegistry` from `../host/bind-hooks`; `DatabaseAdapter` from `@eldrin-project/eldrin-app-core`.
- Produces: all flow types listed below, imported by Tasks 2–6.

- [ ] **Step 1: Write the failing test**

```ts
// src/flow/types.test.ts
import { describe, it, expect } from 'vitest';
import type { Flow, FlowNode, TransformConfig } from './types';

describe('flow types', () => {
  it('constructs a minimal linear flow value', () => {
    const flow: Flow = {
      id: 'factorial:employees',
      integrationId: 'factorial',
      trigger: { kind: 'manual' },
      nodes: [
        { id: 'source', kind: 'source', config: { transport: { method: 'GET', path: '/employees' }, idField: 'id' } },
        { id: 'map', kind: 'map', config: { fields: { first_name: 'first_name' } } },
        { id: 'destination', kind: 'destination', config: { kind: 'd1', table: 'employees', mode: 'stored' } },
      ],
      edges: [
        { from: 'source', to: 'map' },
        { from: 'map', to: 'destination' },
      ],
    };
    expect(flow.nodes).toHaveLength(3);
    const t: TransformConfig = { mode: 'native', hook: 'transform' };
    expect(t.mode).toBe('native');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/flow/types.test.ts`
Expected: FAIL — `Cannot find module './types'`.

- [ ] **Step 3: Write minimal implementation**

```ts
// src/flow/types.ts
import type { HttpResourceTransport, PaginationKind, StorageMode } from '../descriptor';
import type { Transport } from '../transport';
import type { HookRegistry } from '../host/bind-hooks';
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';

export type NodeKind = 'source' | 'map' | 'transform' | 'filter' | 'route' | 'destination';

export interface FlowNode {
  id: string;
  kind: NodeKind;
  config: NodeConfig;
}

export interface FlowEdge {
  from: string;
  to: string;
  when?: string;
}

export type TriggerConfig =
  | { kind: 'cron'; expr: string }
  | { kind: 'webhook'; event: string }
  | { kind: 'manual' };

export interface Flow {
  id: string;
  integrationId: string;
  trigger: TriggerConfig;
  nodes: FlowNode[];
  edges: FlowEdge[];
}

export interface SourceConfig {
  transport: HttpResourceTransport;
  idField: string;
  pagination?: PaginationKind;
}

export interface MapConfig {
  fields: Record<string, string>; // localColumn -> remoteKey
}

export type TransformConfig =
  | { mode: 'native'; hook: string }
  | { mode: 'snippet'; snippet: string };

export type FilterConfig =
  | { mode: 'native'; hook: string }
  | { mode: 'snippet'; snippet: string };

export interface RouteConfig {
  _route?: never; // marker only; branch logic lives on outgoing edge.when
}

export interface DestinationConfig {
  kind: 'd1';
  table: string;
  mode: StorageMode;
}

export type NodeConfig =
  | SourceConfig | MapConfig | TransformConfig
  | FilterConfig | RouteConfig | DestinationConfig;

export interface Row {
  remoteId: string;
  raw: Record<string, unknown>;
  current: Record<string, unknown>;
}

export interface ExecuteDeps {
  transport: Transport;
  db: DatabaseAdapter;
  hooks: HookRegistry;
  now: () => number;
  genId: () => string;
  evalSnippet?: (snippet: string, row: Row) => unknown;
}

export interface ExecuteResult {
  flowId: string;
  recordsIn: number;
  recordsOut: number;
  errors: { nodeId: string; remoteId?: string; message: string }[];
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/flow/types.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/flow/types.ts src/flow/types.test.ts
git commit -m "feat(flow): add flow graph type model"
```

---

### Task 2: Descriptor → flow compiler

**Files:**
- Create: `src/flow/compile.ts`
- Test: `src/flow/compile.test.ts`

**Interfaces:**
- Consumes: `IntegrationDescriptor`, `ResourceDescriptor` from `../descriptor`; all types from `./types` (Task 1).
- Produces: `compileDescriptorToFlows(descriptor: IntegrationDescriptor): Flow[]` and `compileResourceToFlow(integrationId: string, resource: ResourceDescriptor): Flow` (the per-resource compiler, exported for reuse by the `runResourceSync` rewrite in Task 5).

- [ ] **Step 1: Write the failing test**

```ts
// src/flow/compile.test.ts
import { describe, it, expect } from 'vitest';
import { compileDescriptorToFlows, compileResourceToFlow } from './compile';
import type { IntegrationDescriptor, ResourceDescriptor } from '../descriptor';

function resource(over: Partial<ResourceDescriptor> = {}): ResourceDescriptor {
  return {
    name: 'employees',
    transport: { method: 'GET', path: '/employees' },
    idField: 'id',
    fieldMap: { id: 'remote_id_unused', first_name: 'first_name', last_name: 'last_name' },
    supportedModes: ['stored'],
    defaultMode: 'stored',
    ...over,
  };
}

const descriptor: IntegrationDescriptor = {
  id: 'factorial',
  connection: { transport: 'http', baseUrl: 'https://x', auth: { strategy: 'apiKey' } },
  resources: [resource()],
};

describe('compileDescriptorToFlows', () => {
  it('emits one flow per resource with the id <integration>:<resource>', () => {
    const flows = compileDescriptorToFlows(descriptor);
    expect(flows).toHaveLength(1);
    expect(flows[0].id).toBe('factorial:employees');
    expect(flows[0].integrationId).toBe('factorial');
  });

  it('inverts fieldMap into map.fields and skips the idField entry', () => {
    const flow = compileResourceToFlow('factorial', resource());
    const map = flow.nodes.find((n) => n.id === 'map')!;
    // localColumn -> remoteKey; id entry skipped (it is the fixed remote_id)
    expect((map.config as { fields: Record<string, string> }).fields).toEqual({
      first_name: 'first_name',
      last_name: 'last_name',
    });
  });

  it('omits transform/beforeUpsert nodes when no hooks present', () => {
    const flow = compileResourceToFlow('factorial', resource());
    expect(flow.nodes.map((n) => n.id)).toEqual(['source', 'map', 'destination']);
    expect(flow.edges).toEqual([
      { from: 'source', to: 'map' },
      { from: 'map', to: 'destination' },
    ]);
  });

  it('emits a native transform node when hooks.transform present', () => {
    const flow = compileResourceToFlow('factorial', resource({ hooks: { transform: (r) => r } }));
    const t = flow.nodes.find((n) => n.id === 'transform')!;
    expect(t.config).toEqual({ mode: 'native', hook: 'transform' });
    expect(flow.nodes.map((n) => n.id)).toEqual(['source', 'map', 'transform', 'destination']);
    expect(flow.edges).toEqual([
      { from: 'source', to: 'map' },
      { from: 'map', to: 'transform' },
      { from: 'transform', to: 'destination' },
    ]);
  });

  it('emits a native beforeUpsert node after transform when present', () => {
    const flow = compileResourceToFlow('factorial', resource({
      hooks: { transform: (r) => r, beforeUpsert: (m) => m },
    }));
    expect(flow.nodes.map((n) => n.id)).toEqual(['source', 'map', 'transform', 'beforeUpsert', 'destination']);
  });

  it('derives cron trigger from refresh.schedule', () => {
    const flow = compileResourceToFlow('factorial', resource({ refresh: { schedule: '0 * * * *' } }));
    expect(flow.trigger).toEqual({ kind: 'cron', expr: '0 * * * *' });
  });

  it('derives webhook trigger when webhook present and no schedule', () => {
    const flow = compileResourceToFlow('factorial', resource({
      webhook: { event: 'employee.changed', match: () => 1 },
    }));
    expect(flow.trigger).toEqual({ kind: 'webhook', event: 'employee.changed' });
  });

  it('falls back to manual trigger when neither schedule nor webhook present', () => {
    const flow = compileResourceToFlow('factorial', resource());
    expect(flow.trigger).toEqual({ kind: 'manual' });
  });

  it('sets destination table to resource name and mode to defaultMode', () => {
    const flow = compileResourceToFlow('factorial', resource({ defaultMode: 'stored' }));
    const d = flow.nodes.find((n) => n.id === 'destination')!;
    expect(d.config).toEqual({ kind: 'd1', table: 'employees', mode: 'stored' });
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/flow/compile.test.ts`
Expected: FAIL — `Cannot find module './compile'`.

- [ ] **Step 3: Write minimal implementation**

```ts
// src/flow/compile.ts
import type { IntegrationDescriptor, ResourceDescriptor } from '../descriptor';
import type { Flow, FlowNode, FlowEdge, TriggerConfig } from './types';

function triggerOf(resource: ResourceDescriptor): TriggerConfig {
  if (resource.refresh?.schedule) return { kind: 'cron', expr: resource.refresh.schedule };
  if (resource.webhook) return { kind: 'webhook', event: resource.webhook.event };
  return { kind: 'manual' };
}

function invertFieldMap(resource: ResourceDescriptor): Record<string, string> {
  const fields: Record<string, string> = {};
  for (const [remoteKey, localCol] of Object.entries(resource.fieldMap)) {
    if (remoteKey === resource.idField) continue; // fixed remote_id column
    fields[localCol] = remoteKey;
  }
  return fields;
}

export function compileResourceToFlow(
  integrationId: string,
  resource: ResourceDescriptor,
): Flow {
  const nodes: FlowNode[] = [
    {
      id: 'source',
      kind: 'source',
      config: {
        transport: resource.transport,
        idField: resource.idField,
        pagination: resource.transport.pagination,
      },
    },
    { id: 'map', kind: 'map', config: { fields: invertFieldMap(resource) } },
  ];

  if (resource.hooks?.transform) {
    nodes.push({ id: 'transform', kind: 'transform', config: { mode: 'native', hook: 'transform' } });
  }
  if (resource.hooks?.beforeUpsert) {
    nodes.push({ id: 'beforeUpsert', kind: 'transform', config: { mode: 'native', hook: 'beforeUpsert' } });
  }

  nodes.push({
    id: 'destination',
    kind: 'destination',
    config: { kind: 'd1', table: resource.name, mode: resource.defaultMode },
  });

  const edges: FlowEdge[] = [];
  for (let i = 0; i < nodes.length - 1; i++) {
    edges.push({ from: nodes[i].id, to: nodes[i + 1].id });
  }

  return {
    id: `${integrationId}:${resource.name}`,
    integrationId,
    trigger: triggerOf(resource),
    nodes,
    edges,
  };
}

export function compileDescriptorToFlows(descriptor: IntegrationDescriptor): Flow[] {
  return descriptor.resources.map((r) => compileResourceToFlow(descriptor.id, r));
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/flow/compile.test.ts`
Expected: PASS (all 9 tests).

- [ ] **Step 5: Commit**

```bash
git add src/flow/compile.ts src/flow/compile.test.ts
git commit -m "feat(flow): add descriptor-to-flow compiler"
```

---

### Task 3: Graph executor — structural validation + topological sort

**Files:**
- Create: `src/flow/execute.ts`
- Test: `src/flow/execute.test.ts` (this task adds the structural-error and topo-sort tests; Task 4 appends node-execution tests to the same file)

**Interfaces:**
- Consumes: all types from `./types`; `IntegrationError`, `NotImplementedError` from `../errors`.
- Produces: `executeFlow(flow: Flow, deps: ExecuteDeps): Promise<ExecuteResult>`. This task implements topo-sort + structural validation; node execution is stubbed to throw so Task 4 fills it in.

- [ ] **Step 1: Write the failing test**

```ts
// src/flow/execute.test.ts
import { describe, it, expect } from 'vitest';
import { executeFlow } from './execute';
import type { Flow, ExecuteDeps } from './types';

const noopDeps = (): ExecuteDeps => ({
  transport: { fetchAll: async () => [] },
  db: { prepare: () => ({ bind: () => ({ run: async () => {} }), run: async () => {} }) } as unknown as ExecuteDeps['db'],
  hooks: {},
  now: () => 1000,
  genId: () => 'gen-id',
});

function flow(over: Partial<Flow> = {}): Flow {
  return {
    id: 'i:r',
    integrationId: 'i',
    trigger: { kind: 'manual' },
    nodes: [
      { id: 'source', kind: 'source', config: { transport: { method: 'GET', path: '/r' }, idField: 'id' } },
      { id: 'destination', kind: 'destination', config: { kind: 'd1', table: 'r', mode: 'stored' } },
    ],
    edges: [{ from: 'source', to: 'destination' }],
    ...over,
  };
}

describe('executeFlow structural validation', () => {
  it('throws on a cycle before any I/O', async () => {
    const f = flow({
      edges: [
        { from: 'source', to: 'destination' },
        { from: 'destination', to: 'source' },
      ],
    });
    await expect(executeFlow(f, noopDeps())).rejects.toThrow(/cycle/i);
  });

  it('throws when an edge references an unknown node', async () => {
    const f = flow({ edges: [{ from: 'source', to: 'ghost' }] });
    await expect(executeFlow(f, noopDeps())).rejects.toThrow(/unknown node/i);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/flow/execute.test.ts`
Expected: FAIL — `Cannot find module './execute'`.

- [ ] **Step 3: Write minimal implementation**

```ts
// src/flow/execute.ts
import { IntegrationError, NotImplementedError } from '../errors';
import type {
  Flow, FlowNode, ExecuteDeps, ExecuteResult, Row,
  SourceConfig, MapConfig, TransformConfig, FilterConfig, DestinationConfig,
} from './types';

/** Kahn's algorithm. Throws IntegrationError on cycle or unknown node reference. */
function topoSort(flow: Flow): FlowNode[] {
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

export async function executeFlow(flow: Flow, deps: ExecuteDeps): Promise<ExecuteResult> {
  const ordered = topoSort(flow); // structural validation happens before any I/O
  const errors: ExecuteResult['errors'] = [];
  let recordsIn = 0;
  let recordsOut = 0;

  // Node execution is implemented in Task 4. For now, signal incomplete wiring.
  void ordered;
  void deps;
  void recordsIn;
  void recordsOut;
  void errors;
  throw new NotImplementedError('node execution not implemented (Task 4)');
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/flow/execute.test.ts`
Expected: PASS (both structural tests — they assert cycle/unknown-node throws, which happen in `topoSort` before the NotImplemented throw).

- [ ] **Step 5: Commit**

```bash
git add src/flow/execute.ts src/flow/execute.test.ts
git commit -m "feat(flow): add executor skeleton with topological sort and structural validation"
```

---

### Task 4: Graph executor — node execution

**Files:**
- Modify: `src/flow/execute.ts` (replace the Task-3 stub body with real node execution)
- Test: `src/flow/execute.test.ts` (append node-execution tests)

**Interfaces:**
- Consumes: the topo-sort + types from Task 3.
- Produces: fully-working `executeFlow` for slice-1 node kinds (source, map, native transform/filter, d1 destination, unconditional route); snippet/conditional paths throw `NotImplementedError`.

- [ ] **Step 1: Write the failing tests (append to `src/flow/execute.test.ts`)**

```ts
// --- appended to src/flow/execute.test.ts ---
import type { FlowNode } from './types';

// A minimal in-memory db spy that records upserts.
function dbSpy() {
  const upserts: { sql: string; values: unknown[] }[] = [];
  const db = {
    prepare(sql: string) {
      return {
        bind(...values: unknown[]) {
          return { run: async () => { upserts.push({ sql, values }); } };
        },
        run: async () => {},
      };
    },
  };
  return { db: db as unknown as ExecuteDeps['db'], upserts };
}

function linearFlow(extra: FlowNode[] = []): Flow {
  const nodes: FlowNode[] = [
    { id: 'source', kind: 'source', config: { transport: { method: 'GET', path: '/r' }, idField: 'id' } },
    { id: 'map', kind: 'map', config: { fields: { first_name: 'first_name', last_name: 'last_name' } } },
    ...extra,
    { id: 'destination', kind: 'destination', config: { kind: 'd1', table: 'employees', mode: 'stored' } },
  ];
  const edges = [];
  for (let i = 0; i < nodes.length - 1; i++) edges.push({ from: nodes[i].id, to: nodes[i + 1].id });
  return { id: 'i:employees', integrationId: 'i', trigger: { kind: 'manual' }, nodes, edges };
}

describe('executeFlow node execution', () => {
  it('runs source -> map -> destination and upserts mapped rows', async () => {
    const { db, upserts } = dbSpy();
    const deps: ExecuteDeps = {
      transport: { fetchAll: async () => [{ id: 1, first_name: 'Ada', last_name: 'Lovelace' }] },
      db, hooks: {}, now: () => 5000, genId: () => 'gid',
    };
    const result = await executeFlow(linearFlow(), deps);
    expect(result.recordsIn).toBe(1);
    expect(result.recordsOut).toBe(1);
    expect(result.errors).toEqual([]);
    expect(upserts).toHaveLength(1);
    // quoted identifiers + remote_id + raw_json + synced_at present
    expect(upserts[0].sql).toMatch(/INSERT INTO "employees"/);
    expect(upserts[0].sql).toMatch(/"remote_id"/);
    expect(upserts[0].sql).toMatch(/"raw_json"/);
    expect(upserts[0].sql).toMatch(/"synced_at"/);
    // values: id, remote_id, first_name, last_name, raw_json, synced_at
    expect(upserts[0].values).toEqual([
      'gid', '1', 'Ada', 'Lovelace', JSON.stringify({ id: 1, first_name: 'Ada', last_name: 'Lovelace' }), 5000,
    ]);
  });

  it('maps undefined remote values to null', async () => {
    const { db, upserts } = dbSpy();
    const deps: ExecuteDeps = {
      transport: { fetchAll: async () => [{ id: 2, first_name: 'Grace' }] }, // last_name missing
      db, hooks: {}, now: () => 1, genId: () => 'g',
    };
    await executeFlow(linearFlow(), deps);
    // last_name value is null
    expect(upserts[0].values).toContain(null);
  });

  it('runs a native transform node by calling the registered hook', async () => {
    const { db, upserts } = dbSpy();
    const transformNode: FlowNode = { id: 'transform', kind: 'transform', config: { mode: 'native', hook: 'transform' } };
    const deps: ExecuteDeps = {
      transport: { fetchAll: async () => [{ id: 1, first_name: 'Ada', last_name: 'Lovelace' }] },
      db,
      hooks: { transform: (current: Record<string, unknown>) => ({ ...current, full_name: `${current.first_name} ${current.last_name}` }) },
      now: () => 1, genId: () => 'g',
    };
    await executeFlow(linearFlow([transformNode]), deps);
    // full_name derived by the hook appears in the upsert values
    expect(upserts[0].values).toContain('Ada Lovelace');
  });

  it('throws IntegrationError for an unknown native hook name', async () => {
    const { db } = dbSpy();
    const transformNode: FlowNode = { id: 'transform', kind: 'transform', config: { mode: 'native', hook: 'missing' } };
    const deps: ExecuteDeps = {
      transport: { fetchAll: async () => [{ id: 1, first_name: 'A' }] },
      db, hooks: {}, now: () => 1, genId: () => 'g',
    };
    await expect(executeFlow(linearFlow([transformNode]), deps)).rejects.toThrow(/unknown hook/i);
  });

  it('drops rows failing a native filter and keeps the rest', async () => {
    const { db, upserts } = dbSpy();
    const filterNode: FlowNode = { id: 'flt', kind: 'filter', config: { mode: 'native', hook: 'onlyAda' } };
    const deps: ExecuteDeps = {
      transport: { fetchAll: async () => [{ id: 1, first_name: 'Ada' }, { id: 2, first_name: 'Bob' }] },
      db,
      hooks: { onlyAda: (current: Record<string, unknown>) => current.first_name === 'Ada' },
      now: () => 1, genId: () => 'g',
    };
    const result = await executeFlow(linearFlow([filterNode]), deps);
    expect(result.recordsIn).toBe(2);
    expect(result.recordsOut).toBe(1);
    expect(upserts).toHaveLength(1);
  });

  it('collects per-record errors and still upserts good rows', async () => {
    const { db, upserts } = dbSpy();
    const transformNode: FlowNode = { id: 'transform', kind: 'transform', config: { mode: 'native', hook: 'boomOnBob' } };
    const deps: ExecuteDeps = {
      transport: { fetchAll: async () => [{ id: 1, first_name: 'Ada' }, { id: 2, first_name: 'Bob' }] },
      db,
      hooks: { boomOnBob: (current: Record<string, unknown>) => { if (current.first_name === 'Bob') throw new Error('boom'); return current; } },
      now: () => 1, genId: () => 'g',
    };
    const result = await executeFlow(linearFlow([transformNode]), deps);
    expect(result.recordsOut).toBe(1);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toMatchObject({ nodeId: 'transform', remoteId: '2', message: 'boom' });
    expect(upserts).toHaveLength(1);
  });

  it('throws NotImplementedError for a snippet transform when evalSnippet is absent', async () => {
    const { db } = dbSpy();
    const transformNode: FlowNode = { id: 'transform', kind: 'transform', config: { mode: 'snippet', snippet: 'x' } };
    const deps: ExecuteDeps = {
      transport: { fetchAll: async () => [{ id: 1 }] }, db, hooks: {}, now: () => 1, genId: () => 'g',
    };
    await expect(executeFlow(linearFlow([transformNode]), deps)).rejects.toThrow(NotImplementedError);
  });

  it('throws NotImplementedError for a conditional route edge', async () => {
    const { db } = dbSpy();
    const nodes: FlowNode[] = [
      { id: 'source', kind: 'source', config: { transport: { method: 'GET', path: '/r' }, idField: 'id' } },
      { id: 'route', kind: 'route', config: {} },
      { id: 'destination', kind: 'destination', config: { kind: 'd1', table: 'r', mode: 'stored' } },
    ];
    const f: Flow = {
      id: 'i:r', integrationId: 'i', trigger: { kind: 'manual' }, nodes,
      edges: [{ from: 'source', to: 'route' }, { from: 'route', to: 'destination', when: 'x > 1' }],
    };
    const deps: ExecuteDeps = { transport: { fetchAll: async () => [{ id: 1 }] }, db, hooks: {}, now: () => 1, genId: () => 'g' };
    await expect(executeFlow(f, deps)).rejects.toThrow(NotImplementedError);
  });
});
```

Also import `NotImplementedError` at the top of the test file:
```ts
import { NotImplementedError } from '../errors';
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/flow/execute.test.ts`
Expected: FAIL — the new tests hit the `NotImplementedError('node execution not implemented (Task 4)')` stub (wrong error/behavior), and structural tests still pass.

- [ ] **Step 3: Replace the stub body in `src/flow/execute.ts`**

Replace everything from `export async function executeFlow` to end of file with:

```ts
export async function executeFlow(flow: Flow, deps: ExecuteDeps): Promise<ExecuteResult> {
  const ordered = topoSort(flow); // structural validation before any I/O

  // Pre-validate route edges: conditional routing is a sub-project 5 feature.
  for (const e of flow.edges) {
    if (e.when !== undefined) {
      throw new NotImplementedError('conditional routing requires sub-project 5');
    }
  }

  const errors: ExecuteResult['errors'] = [];
  let recordsIn = 0;
  let recordsOut = 0;

  // Slice-1 graphs are linear; walk the topological order, threading a record stream.
  let stream: Row[] = [];

  for (const node of ordered) {
    switch (node.kind) {
      case 'source': {
        const cfg = node.config as SourceConfig;
        const raws = await deps.transport.fetchAll({
          // executeFlow receives a Flow, not a ResourceDescriptor; the transport's
          // fetchAll only reads .transport/.idField-ish fields. Pass a minimal shape.
          name: (flow.nodes.find((n) => n.kind === 'destination')?.config as DestinationConfig | undefined)?.table ?? flow.id,
          transport: cfg.transport,
          idField: cfg.idField,
          fieldMap: {},
          supportedModes: ['stored'],
          defaultMode: 'stored',
        } as unknown as Parameters<ExecuteDeps['transport']['fetchAll']>[0]);
        recordsIn = raws.length;
        stream = raws.map((raw) => ({ remoteId: String(raw[cfg.idField]), raw, current: raw }));
        break;
      }
      case 'map': {
        const cfg = node.config as MapConfig;
        stream = stream.map((row) => {
          const current: Record<string, unknown> = {};
          for (const [localCol, remoteKey] of Object.entries(cfg.fields)) {
            const v = row.raw[remoteKey];
            current[localCol] = v === undefined ? null : v;
          }
          return { ...row, current };
        });
        break;
      }
      case 'transform': {
        const cfg = node.config as TransformConfig;
        const next: Row[] = [];
        for (const row of stream) {
          try {
            if (cfg.mode === 'snippet') {
              if (!deps.evalSnippet) {
                throw new NotImplementedError('snippet transforms require the sandbox (sub-project 2)');
              }
              next.push({ ...row, current: deps.evalSnippet(cfg.snippet, row) as Record<string, unknown> });
            } else {
              const fn = deps.hooks[cfg.hook];
              if (!fn) throw new IntegrationError(`unknown hook: ${cfg.hook}`, 400);
              next.push({ ...row, current: fn(row.current, row.raw) as Record<string, unknown> });
            }
          } catch (e) {
            if (e instanceof NotImplementedError) throw e; // structural, not per-record
            errors.push({ nodeId: node.id, remoteId: row.remoteId, message: e instanceof Error ? e.message : String(e) });
          }
        }
        stream = next;
        break;
      }
      case 'filter': {
        const cfg = node.config as FilterConfig;
        const next: Row[] = [];
        for (const row of stream) {
          try {
            if (cfg.mode === 'snippet') {
              if (!deps.evalSnippet) {
                throw new NotImplementedError('snippet filters require the sandbox (sub-project 2)');
              }
              if (deps.evalSnippet(cfg.snippet, row)) next.push(row);
            } else {
              const fn = deps.hooks[cfg.hook];
              if (!fn) throw new IntegrationError(`unknown hook: ${cfg.hook}`, 400);
              if (fn(row.current, row.raw)) next.push(row);
            }
          } catch (e) {
            if (e instanceof NotImplementedError) throw e;
            errors.push({ nodeId: node.id, remoteId: row.remoteId, message: e instanceof Error ? e.message : String(e) });
          }
        }
        stream = next;
        break;
      }
      case 'route': {
        // Unconditional pass-through only in slice 1 (conditional edges already rejected above).
        break;
      }
      case 'destination': {
        const cfg = node.config as DestinationConfig;
        const ts = deps.now();
        for (const row of stream) {
          try {
            const cols = Object.keys(row.current);
            const allCols = ['id', 'remote_id', ...cols, 'raw_json', 'synced_at'];
            const quoted = allCols.map((c) => `"${c}"`);
            const placeholders = allCols.map(() => '?').join(', ');
            const updates = [...cols, 'raw_json', 'synced_at'].map((c) => `"${c}" = excluded."${c}"`).join(', ');
            const values = [deps.genId(), row.remoteId, ...cols.map((c) => row.current[c]), JSON.stringify(row.raw), ts];
            await deps.db
              .prepare(
                `INSERT INTO "${cfg.table}" (${quoted.join(', ')}) VALUES (${placeholders})
                 ON CONFLICT("remote_id") DO UPDATE SET ${updates}`,
              )
              .bind(...values)
              .run();
            recordsOut++;
          } catch (e) {
            errors.push({ nodeId: node.id, remoteId: row.remoteId, message: e instanceof Error ? e.message : String(e) });
          }
        }
        break;
      }
    }
  }

  return { flowId: flow.id, recordsIn, recordsOut, errors };
}
```

Note: the source node constructs a minimal `ResourceDescriptor`-shaped object for `transport.fetchAll`, because the existing `Transport.fetchAll(resource)` reads `resource.transport`/`resource.idField` (and the http transport uses `transport.path`/`method`/`pagination`). Confirm against `src/transport/http.ts` which fields `fetchAll` actually reads; pass exactly those. If `fetchAll` reads only `resource.transport`, the extra fields are harmless.

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run src/flow/execute.test.ts`
Expected: PASS (structural + all node-execution tests).

- [ ] **Step 5: Commit**

```bash
git add src/flow/execute.ts src/flow/execute.test.ts
git commit -m "feat(flow): implement graph executor node execution"
```

---

### Task 5: Rewire sync to the executor; delete `mapRows`

**Files:**
- Modify: `src/sync/index.ts` (rewrite `runResourceSync` internals; remove `mapRows` import)
- Delete: `src/sync/map.ts`
- Modify: `src/index.ts` (remove `mapRows`/`MappedRow` exports; add flow exports)
- Test: `src/flow/execute-integration.test.ts` (new — compile+execute against in-memory D1)

**Interfaces:**
- Consumes: `compileResourceToFlow` (Task 2), `executeFlow` (Task 4), existing `SyncDeps`/`SyncResult`/`writeSyncState`.
- Produces: `runResourceSync(resource, deps)` with **unchanged signature** but executor-backed internals. `runAllSync`, `runScheduled`, `dueResources`, and host call sites remain untouched.

- [ ] **Step 1: Write the failing integration test**

```ts
// src/flow/execute-integration.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import { compileResourceToFlow } from './compile';
import { executeFlow } from './execute';
import type { ExecuteDeps } from './types';
import type { ResourceDescriptor } from '../descriptor';
import { ensureResourceTables } from '../schema/ensure';
// Inspect src/test-helpers.ts for the exact in-memory adapter factory name and import it.
import { createMemoryAdapter } from '../test-helpers';

const resource: ResourceDescriptor = {
  name: 'employees',
  transport: { method: 'GET', path: '/employees' },
  idField: 'id',
  fieldMap: { id: 'unused', first_name: 'first_name', last_name: 'last_name' },
  supportedModes: ['stored'],
  defaultMode: 'stored',
};

describe('compile + execute against in-memory D1', () => {
  let db: ExecuteDeps['db'];

  beforeEach(async () => {
    db = createMemoryAdapter();
    await ensureResourceTables(db, {
      id: 'factorial',
      connection: { transport: 'http', baseUrl: 'x', auth: { strategy: 'apiKey' } },
      resources: [resource],
    });
  });

  it('upserts rows with remote_id, mapped columns, raw_json, synced_at', async () => {
    const flow = compileResourceToFlow('factorial', resource);
    const deps: ExecuteDeps = {
      transport: { fetchAll: async () => [{ id: 7, first_name: 'Ada', last_name: 'Lovelace' }] },
      db, hooks: {}, now: () => 9999, genId: () => 'row-1',
    };
    const result = await executeFlow(flow, deps);
    expect(result.recordsOut).toBe(1);

    const row = await db.prepare('SELECT * FROM "employees" WHERE "remote_id" = ?').bind('7').first<Record<string, unknown>>();
    expect(row).toMatchObject({ remote_id: '7', first_name: 'Ada', last_name: 'Lovelace', synced_at: 9999 });
    expect(JSON.parse(String(row!.raw_json))).toEqual({ id: 7, first_name: 'Ada', last_name: 'Lovelace' });
  });
});
```

If `src/test-helpers.ts` exports a differently-named factory (e.g. `makeTestDb`), use that name; the existing `src/schema/*.test.ts` files show the correct import.

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/flow/execute-integration.test.ts`
Expected: FAIL — wrong import name OR assertion mismatch until executor wiring confirmed. Fix the import to match `test-helpers.ts`, then it should pass against Task-4 code. If it passes immediately, that is acceptable (it is an integration check over already-built units).

- [ ] **Step 3: Rewrite `runResourceSync` internals in `src/sync/index.ts`**

Replace the file contents with:

```ts
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';
import type { IntegrationDescriptor, ResourceDescriptor } from '../descriptor';
import type { Transport } from '../transport';
import { compileResourceToFlow } from '../flow/compile';
import { executeFlow } from '../flow/execute';
import { bindHooks, type HookRegistry } from '../host/bind-hooks';
import { writeSyncState } from './sync-state';

export interface SyncDeps {
  db: DatabaseAdapter;
  transport: Transport;
  now: () => number;
  genId: () => string;
  hooks?: HookRegistry;
}

export interface SyncResult {
  resource: string;
  count: number;
}

export async function runResourceSync(
  resource: ResourceDescriptor,
  deps: SyncDeps,
): Promise<SyncResult> {
  const ts = deps.now();
  try {
    // The descriptor's hooks are already bound functions on resource.hooks
    // (bindHooks runs at worker construction). Native flow nodes look hooks up
    // by key from a registry, so expose the bound functions under their keys.
    const hooks: HookRegistry = deps.hooks ?? {};
    if (resource.hooks?.transform) hooks.transform = resource.hooks.transform;
    if (resource.hooks?.beforeUpsert) hooks.beforeUpsert = resource.hooks.beforeUpsert;

    const flow = compileResourceToFlow('integration', resource);
    const result = await executeFlow(flow, {
      transport: deps.transport,
      db: deps.db,
      hooks,
      now: deps.now,
      genId: deps.genId,
    });

    if (result.errors.length > 0) {
      // Surface the first per-record error as the sync error, matching prior
      // fail-the-resource behavior on a transform/upsert fault.
      throw new Error(result.errors[0].message);
    }

    await writeSyncState(deps.db, {
      resource: resource.name,
      lastSyncedAt: ts,
      lastStatus: 'ok',
      lastError: null,
      cursor: null,
    });
    return { resource: resource.name, count: result.recordsIn };
  } catch (e) {
    await writeSyncState(deps.db, {
      resource: resource.name,
      lastSyncedAt: ts,
      lastStatus: 'error',
      lastError: e instanceof Error ? e.message : String(e),
      cursor: null,
    });
    throw e;
  }
}

export async function runAllSync(
  descriptor: IntegrationDescriptor,
  deps: SyncDeps,
): Promise<SyncResult[]> {
  const results: SyncResult[] = [];
  for (const resource of descriptor.resources) {
    if (resource.defaultMode === 'stored' && resource.supportedModes.includes('stored')) {
      results.push(await runResourceSync(resource, deps));
    }
  }
  return results;
}

// re-export so existing importers of bindHooks types are unaffected
export { bindHooks };
```

Note on `hooks`: the resource passed to `runResourceSync` already has **bound function** hooks on `resource.hooks` (set by `bindHooks` at worker construction). The compiler emits native nodes keyed `'transform'`/`'beforeUpsert'`, so we register the bound functions under exactly those keys. `count` returns `result.recordsIn` to match the old behavior (old code returned `rows.length`).

- [ ] **Step 4: Delete `src/sync/map.ts` and update `src/index.ts`**

Delete the file:
```bash
git rm src/sync/map.ts
```

In `src/index.ts`, remove the two lines exporting `mapRows`/`MappedRow`:
```ts
// DELETE these:
export { mapRows } from './sync/map';
export type { MappedRow } from './sync/map';
```

Add flow exports (place near the sync exports):
```ts
export { compileDescriptorToFlows, compileResourceToFlow } from './flow/compile';
export { executeFlow } from './flow/execute';
export type {
  Flow, FlowNode, FlowEdge, NodeKind, NodeConfig, TriggerConfig,
  SourceConfig, MapConfig, TransformConfig, FilterConfig, RouteConfig, DestinationConfig,
  Row, ExecuteDeps, ExecuteResult,
} from './flow/types';
```

- [ ] **Step 5: Run the full suite + typecheck + build**

Run: `npx vitest run && npx tsc --noEmit && npm run build`
Expected: all tests PASS, no type errors, build succeeds. If `src/schedule/index.ts` or any other file still imports from `./map`, fix the import (it should not — only `src/sync/index.ts` imported `mapRows`).

- [ ] **Step 6: Commit**

```bash
git add src/sync/index.ts src/index.ts src/flow/execute-integration.test.ts
git commit -m "refactor(flow): route sync through the graph executor and remove mapRows"
```

---

### Task 6: Factorial regression gate

**Files:**
- Test: `src/flow/regression.test.ts` (new)

**Interfaces:**
- Consumes: `compileResourceToFlow`, `executeFlow`, the in-memory adapter, `ensureResourceTables`. This test reconstructs the OLD `mapRows`+upsert logic inline (the production `mapRows` is deleted) as the comparison oracle, then asserts the new path matches it.

This task proves byte-identical output and locks the guarantee as a golden-file comparison so the deleted path's behavior stays pinned.

- [ ] **Step 1: Write the regression test**

```ts
// src/flow/regression.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import { compileResourceToFlow } from './compile';
import { executeFlow } from './execute';
import type { ExecuteDeps } from './types';
import type { ResourceDescriptor } from '../descriptor';
import { ensureResourceTables } from '../schema/ensure';
import { createMemoryAdapter } from '../test-helpers'; // match test-helpers export name

// Factorial's employees resource, including the deriveFullName transform hook.
const deriveFullName = (raw: Record<string, unknown>) => ({
  ...raw,
  full_name: `${raw.first_name ?? ''} ${raw.last_name ?? ''}`.trim(),
});

const employees: ResourceDescriptor = {
  name: 'employees',
  transport: { method: 'GET', path: '/employees' },
  idField: 'id',
  fieldMap: { id: 'unused', first_name: 'first_name', last_name: 'last_name', full_name: 'full_name' },
  supportedModes: ['stored'],
  defaultMode: 'stored',
  hooks: { transform: deriveFullName },
};

const sourceRows = [
  { id: 1, first_name: 'Ada', last_name: 'Lovelace' },
  { id: 2, first_name: 'Grace', last_name: 'Hopper' },
  { id: 3, first_name: 'Alan', last_name: 'Turing' },
];

// OLD-path oracle: reproduces the deleted mapRows + upsert exactly (unquoted is fine;
// we compare ROW CONTENTS via SELECT, not SQL text).
async function oldPathUpsert(db: ExecuteDeps['db'], resource: ResourceDescriptor, rows: Record<string, unknown>[], ts: number, genId: () => string) {
  for (const raw of rows) {
    const transformed = resource.hooks?.transform ? resource.hooks.transform(raw) : raw;
    const mapped: Record<string, unknown> = {};
    for (const [remoteKey, localCol] of Object.entries(resource.fieldMap)) {
      if (remoteKey === resource.idField) continue;
      const v = (transformed as Record<string, unknown>)[remoteKey];
      mapped[localCol] = v === undefined ? null : v;
    }
    const cols = Object.keys(mapped);
    const allCols = ['id', 'remote_id', ...cols, 'raw_json', 'synced_at'];
    const placeholders = allCols.map(() => '?').join(', ');
    const updates = [...cols, 'raw_json', 'synced_at'].map((c) => `"${c}" = excluded."${c}"`).join(', ');
    const values = [genId(), String(raw[resource.idField]), ...cols.map((c) => mapped[c]), JSON.stringify(raw), ts];
    await db.prepare(`INSERT INTO "${resource.name}" (${allCols.map((c) => `"${c}"`).join(', ')}) VALUES (${placeholders}) ON CONFLICT("remote_id") DO UPDATE SET ${updates}`).bind(...values).run();
  }
}

async function dumpTable(db: ExecuteDeps['db']) {
  const res = await db.prepare('SELECT remote_id, first_name, last_name, full_name, raw_json, synced_at FROM "employees" ORDER BY remote_id').all<Record<string, unknown>>();
  return res.results;
}

describe('Factorial regression gate: new executor == old mapRows path', () => {
  it('produces identical table contents (including hook-derived full_name)', async () => {
    const ts = 4242;
    const genId = () => 'fixed-id';

    const oldDb = createMemoryAdapter();
    await ensureResourceTables(oldDb, { id: 'factorial', connection: { transport: 'http', baseUrl: 'x', auth: { strategy: 'apiKey' } }, resources: [employees] });
    await oldPathUpsert(oldDb, employees, sourceRows, ts, genId);
    const oldDump = await dumpTable(oldDb);

    const newDb = createMemoryAdapter();
    await ensureResourceTables(newDb, { id: 'factorial', connection: { transport: 'http', baseUrl: 'x', auth: { strategy: 'apiKey' } }, resources: [employees] });
    const flow = compileResourceToFlow('factorial', employees);
    const deps: ExecuteDeps = {
      transport: { fetchAll: async () => sourceRows },
      db: newDb,
      hooks: { transform: deriveFullName },
      now: () => ts, genId,
    };
    await executeFlow(flow, deps);
    const newDump = await dumpTable(newDb);

    expect(newDump).toEqual(oldDump);
    // Spot-check the hook-derived column to make the guarantee explicit.
    expect(newDump.find((r) => r.remote_id === '1')!.full_name).toBe('Ada Lovelace');
  });
});
```

- [ ] **Step 2: Run test to verify it fails (or passes) meaningfully**

Run: `npx vitest run src/flow/regression.test.ts`
Expected: PASS — both paths produce identical dumps. If it FAILS, the diff localizes the regression (column order, null handling, full_name). Fix the executor (Task 4) until identical; do not weaken the assertion.

- [ ] **Step 3: Run the entire suite with coverage**

Run: `npx vitest run --coverage`
Expected: all tests PASS; `src/flow/` lines ≥ 80%.

- [ ] **Step 4: Update README**

In `eldrin-integration/README.md`, add a short "Flow model" subsection under the architecture/sync section documenting: a flow is a graph compiled from the descriptor; `compileDescriptorToFlows`/`executeFlow` are the public entry points; transform/filter nodes are `native` (HookRegistry) in slice 1 with `snippet` (sandboxed) deferred; sync now runs through the executor. Keep it to ~10 lines, matching the README's existing tone.

- [ ] **Step 5: Commit**

```bash
git add src/flow/regression.test.ts README.md
git commit -m "test(flow): add Factorial regression gate proving executor parity with mapRows"
```

---

## Post-implementation: live verification (manual, not a task)

After all tasks pass and the SDK is rebuilt + the factorial preview restarted:
- Wipe Factorial's local D1, run a real `/api/sync`, confirm 38 employees / 8 projects with `full_name` populated — matching the pre-change live result.

## Notes for the executor

- **`Transport.fetchAll` shape:** Task 4's source node builds a minimal `ResourceDescriptor`-shaped object for `fetchAll`. Before finalizing, read `src/transport/http.ts` to confirm exactly which fields `fetchAll` reads (`resource.transport.method/path/pagination` at minimum) and pass exactly those. This is the one place the executor bridges to a descriptor-shaped API.
- **Hook registry keys:** the compiler emits `{ mode:'native', hook:'transform' }` / `'beforeUpsert'`. The sync wrapper (Task 5) registers the bound functions under those exact keys. Any divergence in key names breaks native execution — keep them identical.
