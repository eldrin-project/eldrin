# Sample Data, Draft Testing & Data-Flow Inspector — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a test/debug layer over the CPI flow platform — named HTTP-exchange samples per flow, mapping source-fields derived from a sample, draft test runs (sample + live/dry-run), and a per-node IN/OUT + per-connection trace inspector.

**Architecture:** SDK-first. The single `executeFlow` gains opt-in `trace` and `dryRun` deps (zero production overhead). A new `sample-store` + routes persist/capture/test. The core UI adds a third "Test" view, a sample manager, sample-derived mapping fields, and a trace inspector reusing the SP8 canvas selection model (extended for edges).

**Tech Stack:** TypeScript 5.8-5.9 strict, Vitest, Hono 4 (SDK worker), React 19 + React Router 7 + `@xyflow/react` 12 + Zustand 5 (core), Cloudflare D1 via `DatabaseAdapter` from `@eldrin-project/eldrin-app-core`, i18next.

## Global Constraints

- **Immutability:** never mutate rows/objects in place; trace collector clones at capture time (rows are reused/mutated as they walk). Spread for updates.
- **Cross-repo build seam:** the SDK is consumed via its built `dist/` (`tsup`). After SDK source changes: `npm run build` in `eldrin-integration`, THEN rebuild the consuming app (`eldrin-factorial`) before the running server sees it. Unit suites do NOT prove the bundle seam — live-verify.
- **Conventional commits**, attribution disabled. Feature branch per repo.
- **Admin-gating:** all new SDK routes use `resolveUserId` → 401, `isAdmin` → 403, exactly like existing routes in `create-worker.ts`.
- **Error envelope:** SDK routes return `c.json({ error: '<msg>' }, status)` on failure, `c.json({ ...data })` on success. Core wraps via `call<T>()` → `Result<T>`.
- **Tables are inline DDL** in `src/schema/tables.ts` (`SDK_TABLES` array) + idempotent creation in `src/schema/ensure.ts` — NOT timestamped migration files.
- **Production path unchanged:** `/api/sync` passes no `trace`/`dryRun` → existing 279 SDK tests MUST stay green at every commit.
- **Trace cap:** `maxRecords` default 50; beyond it, `truncated=true` and further records run untraced but still counted.

---

## File Structure

### eldrin-integration (SDK)
- Create `src/flow/trace.ts` — `TraceCollector` + trace types (`NodeTrace`/`EdgeTrace`/`RecordTrace`/`ExecuteTrace`).
- Modify `src/flow/types.ts` — add `trace?`/`dryRun?` to `ExecuteDeps`; export trace types via re-export.
- Modify `src/flow/exec/walk.ts` — thread optional collector through `walkRow`; capture node IN/OUT + edge crossings.
- Modify `src/flow/exec/sink.ts` — dry-run branch (count, skip write); accept collector for destination IN.
- Modify `src/flow/execute.ts` — build collector when `deps.trace`, attach `trace` to result, per-record begin/commit.
- Create `src/transport/fixture.ts` — `fixtureTransport(records)` implementing `Transport`.
- Create `src/flow/sample-types.ts` — `HttpExchange`, `FlowSample`.
- Create `src/flow/sample-store.ts` — `saveSample`/`readSample`/`listSamples`/`deleteSample`.
- Create `src/flow/sample-extract.ts` — `resolveRecords(body, arrayPath)`, `extractFields(entry)`.
- Modify `src/schema/tables.ts` — add `SAMPLES_DDL` to `SDK_TABLES`.
- Modify `src/host/create-worker.ts` — add `/samples` GET/PUT/DELETE, `/capture` POST, `/test` POST; add `captureExchange` helper.

### eldrin-core (UI)
- Modify `src/pages/integrations/integrations-api.ts` — add sample/test types + client fns.
- Create `src/pages/integrations/sample-extract.ts` — client mirror of array-path/field resolution (pure, unit-tested).
- Modify `src/pages/integrations/StructuralCanvas.tsx` — add `selectedEdgeId`/`onSelectEdge` + `onEdgeClick`.
- Create `src/pages/integrations/SamplePanel.tsx` — capture/paste/list + extraction controls.
- Create `src/pages/integrations/TracePanel.tsx` — pure presentational node/edge IN/OUT over a `RecordTrace`.
- Create `src/pages/integrations/TestPanel.tsx` — run controls, summary, record stepper, wires canvas selection → TracePanel.
- Modify `src/pages/integrations/FlowEditorShell.tsx` — add `'test'` view + toggle button; feed sample fields to Mapping.
- Modify `src/locales/en/integrations.json` — new keys.

---

# PHASE 1 — SDK trace + dry-run + fixtureTransport

Foundation. Pure SDK, heavily unit-tested. No routes, no UI.

### Task 1.1: Trace types + collector

**Files:**
- Create: `src/flow/trace.ts`
- Test: `src/flow/trace.test.ts`

**Interfaces:**
- Produces:
  ```ts
  export interface NodeTrace { nodeId: string; in: Row; out: Row | null; }
  export interface EdgeTrace { from: string; to: string; payload: Row; }
  export interface RecordTrace { recordKey: string; nodes: NodeTrace[]; edges: EdgeTrace[]; }
  export interface ExecuteTrace { records: RecordTrace[]; truncated: boolean; }
  export interface TraceCollector {
    beginRecord(recordKey: string): boolean;   // false ⇒ cap hit, caller should not trace this record
    node(nodeId: string, input: Row, output: Row | null): void;
    edge(from: string, to: string, payload: Row): void;
    commitRecord(): void;
    result(): ExecuteTrace;
  }
  export function createTraceCollector(maxRecords: number): TraceCollector;
  ```
- `Row` consumed from `./types`.

- [ ] **Step 1: Write the failing test**

```ts
// src/flow/trace.test.ts
import { describe, it, expect } from 'vitest';
import { createTraceCollector } from './trace';
import type { Row } from './types';

const row = (id: string, current: Record<string, unknown>): Row => ({ remoteId: id, raw: { ...current }, current });

describe('TraceCollector', () => {
  it('captures node IN/OUT and edges per record, cloning snapshots', () => {
    const c = createTraceCollector(50);
    expect(c.beginRecord('7')).toBe(true);
    const live = row('7', { a: 1 });
    c.node('map', live, { ...live, current: { a: 2 } });
    c.edge('map', 'destination', { ...live, current: { a: 2 } });
    // mutate the live row AFTER capture — snapshot must not change
    live.current.a = 999;
    c.commitRecord();
    const t = c.result();
    expect(t.records).toHaveLength(1);
    expect(t.records[0].recordKey).toBe('7');
    expect(t.records[0].nodes[0]).toEqual({ nodeId: 'map', in: { remoteId: '7', raw: { a: 1 }, current: { a: 1 } }, out: { remoteId: '7', raw: { a: 1 }, current: { a: 2 } } });
    expect(t.records[0].edges[0]).toEqual({ from: 'map', to: 'destination', payload: { remoteId: '7', raw: { a: 1 }, current: { a: 2 } } });
    expect(t.truncated).toBe(false);
  });

  it('records out:null for dropped rows', () => {
    const c = createTraceCollector(50);
    c.beginRecord('1');
    c.node('filter', row('1', { x: 1 }), null);
    c.commitRecord();
    expect(c.result().records[0].nodes[0].out).toBeNull();
  });

  it('truncates beyond maxRecords and sets truncated', () => {
    const c = createTraceCollector(1);
    expect(c.beginRecord('1')).toBe(true);
    c.commitRecord();
    expect(c.beginRecord('2')).toBe(false);
    expect(c.result().records).toHaveLength(1);
    expect(c.result().truncated).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd eldrin-integration && npx vitest run src/flow/trace.test.ts`
Expected: FAIL — `createTraceCollector` not exported / module not found.

- [ ] **Step 3: Write minimal implementation**

```ts
// src/flow/trace.ts
import type { Row } from './types';

export interface NodeTrace { nodeId: string; in: Row; out: Row | null; }
export interface EdgeTrace { from: string; to: string; payload: Row; }
export interface RecordTrace { recordKey: string; nodes: NodeTrace[]; edges: EdgeTrace[]; }
export interface ExecuteTrace { records: RecordTrace[]; truncated: boolean; }

export interface TraceCollector {
  beginRecord(recordKey: string): boolean;
  node(nodeId: string, input: Row, output: Row | null): void;
  edge(from: string, to: string, payload: Row): void;
  commitRecord(): void;
  result(): ExecuteTrace;
}

// Structural clone of a Row so trace snapshots never alias the live mutating row.
const cloneRow = (r: Row): Row => ({
  remoteId: r.remoteId,
  raw: structuredClone(r.raw),
  current: structuredClone(r.current),
});

export function createTraceCollector(maxRecords: number): TraceCollector {
  const records: RecordTrace[] = [];
  let truncated = false;
  let cur: RecordTrace | null = null;

  return {
    beginRecord(recordKey) {
      if (records.length >= maxRecords) { truncated = true; cur = null; return false; }
      cur = { recordKey, nodes: [], edges: [] };
      return true;
    },
    node(nodeId, input, output) {
      if (!cur) return;
      cur.nodes.push({ nodeId, in: cloneRow(input), out: output ? cloneRow(output) : null });
    },
    edge(from, to, payload) {
      if (!cur) return;
      cur.edges.push({ from, to, payload: cloneRow(payload) });
    },
    commitRecord() {
      if (cur) records.push(cur);
      cur = null;
    },
    result() { return { records, truncated }; },
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd eldrin-integration && npx vitest run src/flow/trace.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
cd eldrin-integration && git add src/flow/trace.ts src/flow/trace.test.ts && git commit -m "feat(flow): add trace collector for per-node IN/OUT + edge capture"
```

---

### Task 1.2: Thread trace + dryRun into ExecuteDeps

**Files:**
- Modify: `src/flow/types.ts` (the `ExecuteDeps` interface)

**Interfaces:**
- Produces: `ExecuteDeps.trace?: { enabled: true; maxRecords: number }` and `ExecuteDeps.dryRun?: boolean`.

- [ ] **Step 1: Add the optional fields**

In `src/flow/types.ts`, locate the `ExecuteDeps` interface and add two optional fields at the end:

```ts
export interface ExecuteDeps {
  transport: Transport;
  db: DatabaseAdapter;
  hooks: HookRegistry;
  now: () => number;
  genId: () => string;
  evalSnippet?: (code: string, input: SnippetInput) => unknown;
  evalWhen?: (expr: string, input: WhenInput) => boolean;
  trace?: { enabled: true; maxRecords: number };  // opt-in tracing; absent ⇒ no overhead
  dryRun?: boolean;                                // true ⇒ sinks count but skip writes
}
```

- [ ] **Step 2: Typecheck**

Run: `cd eldrin-integration && npx tsc --noEmit`
Expected: PASS (additive optional fields don't break callers).

- [ ] **Step 3: Commit**

```bash
cd eldrin-integration && git add src/flow/types.ts && git commit -m "feat(flow): add optional trace + dryRun to ExecuteDeps"
```

---

### Task 1.3: Dry-run sink (count, skip write)

**Files:**
- Modify: `src/flow/exec/sink.ts` (the `flush` closure)
- Test: `src/flow/exec/sink.test.ts` (create if absent; otherwise append)

**Interfaces:**
- Consumes: `ExecuteDeps.dryRun` (Task 1.2).
- Produces: unchanged `Sinks` interface; behavior differs only when `deps.dryRun === true`.

- [ ] **Step 1: Write the failing test**

```ts
// src/flow/exec/sink.test.ts
import { describe, it, expect, vi } from 'vitest';
import { createSinks } from './sink';
import * as batch from '../batch';
import type { FlowNode, ExecuteDeps, Row } from '../types';

const destNode = (id: string, table: string): FlowNode => ({ id, kind: 'destination', config: { kind: 'd1', table, mode: 'stored' } });
const row = (id: string): Row => ({ remoteId: id, raw: {}, current: {} });
const baseDeps = (over: Partial<ExecuteDeps>): ExecuteDeps => ({
  transport: { fetchAll: async () => [] }, db: {} as ExecuteDeps['db'], hooks: {},
  now: () => 1, genId: () => 'g', ...over,
});

describe('createSinks dryRun', () => {
  it('counts recordsOut but does NOT call flushBatch when dryRun', async () => {
    const spy = vi.spyOn(batch, 'flushBatch').mockResolvedValue(undefined);
    const sinks = createSinks([destNode('d', 'employees')], baseDeps({ dryRun: true }), 1, () => {});
    await sinks.push('d', row('1'));
    await sinks.flushAll();
    expect(spy).not.toHaveBeenCalled();
    expect(sinks.recordsOutByDest().d.recordsOut).toBe(1);
    spy.mockRestore();
  });

  it('calls flushBatch normally when not dryRun', async () => {
    const spy = vi.spyOn(batch, 'flushBatch').mockResolvedValue(undefined);
    const sinks = createSinks([destNode('d', 'employees')], baseDeps({}), 1, () => {});
    await sinks.push('d', row('1'));
    await sinks.flushAll();
    expect(spy).toHaveBeenCalledTimes(1);
    expect(sinks.recordsOutByDest().d.recordsOut).toBe(1);
    spy.mockRestore();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd eldrin-integration && npx vitest run src/flow/exec/sink.test.ts`
Expected: FAIL — first test fails because `flushBatch` IS called (dry-run not implemented).

- [ ] **Step 3: Implement the dry-run branch**

In `src/flow/exec/sink.ts`, modify the `flush` closure so dry-run counts without writing:

```ts
  const flush = async (destId: string) => {
    const sink = sinks.get(destId)!;
    if (sink.buffer.length === 0) return;
    const batch = sink.buffer;
    sink.buffer = [];
    if (deps.dryRun) { sink.recordsOut += batch.length; return; } // count, skip write
    try {
      await flushBatch(deps.db, sink.table, batch, deps.genId, ts);
      sink.recordsOut += batch.length;
    } catch (e) {
      for (const r of batch) collectError(destId, r.remoteId, e);
    }
  };
```

(`deps` is already a parameter of `createSinks`.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd eldrin-integration && npx vitest run src/flow/exec/sink.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Regression — full suite still green**

Run: `cd eldrin-integration && npx vitest run`
Expected: PASS — all existing tests + new ones.

- [ ] **Step 6: Commit**

```bash
cd eldrin-integration && git add src/flow/exec/sink.ts src/flow/exec/sink.test.ts && git commit -m "feat(flow): dry-run sink counts records without writing"
```

---

### Task 1.4: Capture node IN/OUT + edges in walkRow

**Files:**
- Modify: `src/flow/exec/walk.ts` (`WalkArgs` + `walkRow`)
- Test: `src/flow/exec/walk.test.ts` (create if absent; otherwise append)

**Interfaces:**
- Consumes: `TraceCollector` (Task 1.1).
- Produces: `WalkArgs` gains optional `collector?: TraceCollector`. When present, `walkRow` records each node's IN/OUT and each edge crossing (incl. route branch selection + the terminal destination edge).

- [ ] **Step 1: Write the failing test**

```ts
// src/flow/exec/walk.test.ts
import { describe, it, expect } from 'vitest';
import { walkRow } from './walk';
import { createTraceCollector } from '../trace';
import type { FlowNode, FlowEdge, Row, ExecuteDeps } from '../types';

function fixtureGraph() {
  const nodes: FlowNode[] = [
    { id: 'map', kind: 'map', config: { connections: [{ target: 'name', sources: ['first'] }] } },
    { id: 'destination', kind: 'destination', config: { kind: 'd1', table: 't', mode: 'stored' } },
  ];
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const outByNode = new Map<string, FlowEdge[]>([['map', [{ from: 'map', to: 'destination' }]]]);
  return { byId, outByNode };
}

const deps = (): ExecuteDeps => ({
  transport: { fetchAll: async () => [] }, db: {} as ExecuteDeps['db'], hooks: {},
  now: () => 1, genId: () => 'g',
});

describe('walkRow tracing', () => {
  it('records node IN/OUT and the edge to destination', async () => {
    const { byId, outByNode } = fixtureGraph();
    const collector = createTraceCollector(50);
    const sinks = { push: async () => {}, flush: async () => {}, flushAll: async () => {}, ids: () => ['destination'], recordsOutByDest: () => ({ destination: { table: 't', recordsOut: 0 } }) };
    const row: Row = { remoteId: '7', raw: { first: 'Ada' }, current: { first: 'Ada' } };
    collector.beginRecord('7');
    await walkRow({ startNodeId: 'map', row, byId, outByNode, deps: deps(), sinks, collectError: () => {}, onRoutedNowhere: () => {}, collector });
    collector.commitRecord();
    const rec = collector.result().records[0];
    expect(rec.nodes.map((n) => n.nodeId)).toEqual(['map']);
    expect(rec.nodes[0].in.current).toEqual({ first: 'Ada' });
    expect(rec.nodes[0].out!.current).toEqual({ name: 'Ada' });
    expect(rec.edges).toEqual([{ from: 'map', to: 'destination', payload: expect.objectContaining({ current: { name: 'Ada' } }) }]);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd eldrin-integration && npx vitest run src/flow/exec/walk.test.ts`
Expected: FAIL — `collector` not accepted / nothing recorded.

- [ ] **Step 3: Implement collector threading**

In `src/flow/exec/walk.ts`, add `collector?: TraceCollector` to `WalkArgs` (import the type from `../trace`), then record at the right points:

```ts
import type { TraceCollector } from '../trace';
// ...
export interface WalkArgs {
  startNodeId: string;
  row: Row;
  byId: Map<string, FlowNode>;
  outByNode: Map<string, FlowEdge[]>;
  deps: ExecuteDeps;
  sinks: Sinks;
  collectError: (nodeId: string, remoteId: string | undefined, e: unknown) => void;
  onRoutedNowhere: () => void;
  collector?: TraceCollector;
}

export async function walkRow(args: WalkArgs): Promise<void> {
  const { byId, outByNode, deps, sinks, collectError, onRoutedNowhere, collector } = args;
  let nodeId = args.startNodeId;
  let row: Row | null = args.row;

  while (row) {
    const node = byId.get(nodeId)!;

    if (node.kind === 'destination') {
      collector?.edge(nodeId, nodeId, row); // terminal: payload reaching the sink
      await sinks.push(nodeId, row);
      return;
    }

    if (node.kind === 'route') {
      const result = selectBranch(outByNode.get(nodeId) ?? [], row, deps);
      for (const { error } of result.edgeErrors) collectError(nodeId, row.remoteId, error);
      if (result.kind === 'matched') { collector?.edge(nodeId, result.to, row); nodeId = result.to; continue; }
      if (result.edgeErrors.length === 0) onRoutedNowhere();
      return;
    }

    const remoteId = row.remoteId;
    const input = row;
    let output: Row | null;
    try {
      output = applyNode(node, row, deps);
    } catch (e) {
      if (e instanceof NotImplementedError || e instanceof IntegrationError) throw e;
      collectError(node.id, remoteId, e);
      collector?.node(node.id, input, null);
      return;
    }
    collector?.node(node.id, input, output);
    row = output;
    if (!row) return;

    const outs = outByNode.get(nodeId) ?? [];
    if (outs.length === 0) return;
    collector?.edge(nodeId, outs[0].to, row);
    nodeId = outs[0].to;
  }
}
```

Note: the terminal destination `edge(nodeId, nodeId, row)` records the payload arriving at the sink; the inspector treats a self-edge on a destination as "input to destination." (Simpler than tracking the prior edge; the prior non-route edge was already recorded before the loop advanced.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd eldrin-integration && npx vitest run src/flow/exec/walk.test.ts`
Expected: PASS.

- [ ] **Step 5: Regression**

Run: `cd eldrin-integration && npx vitest run`
Expected: PASS — all green (collector is optional; untraced path identical).

- [ ] **Step 6: Commit**

```bash
cd eldrin-integration && git add src/flow/exec/walk.ts src/flow/exec/walk.test.ts && git commit -m "feat(flow): capture node IN/OUT + edge payloads in walkRow when tracing"
```

---

### Task 1.5: Wire collector into executeFlow + return trace

**Files:**
- Modify: `src/flow/execute.ts`
- Test: `src/flow/execute-trace.test.ts` (create)

**Interfaces:**
- Consumes: `createTraceCollector` (1.1), `deps.trace`/`deps.dryRun` (1.2), traced `walkRow` (1.4), dry-run sink (1.3).
- Produces: `executeFlow` return type becomes `Promise<ExecuteResult & { trace?: ExecuteTrace }>`. When `deps.trace` present, the resolved object includes `trace`.

- [ ] **Step 1: Write the failing test**

```ts
// src/flow/execute-trace.test.ts
import { describe, it, expect } from 'vitest';
import { executeFlow } from './execute';
import type { Flow, ExecuteDeps } from './types';

function flow(): Flow {
  return {
    id: 'acme:clients', integrationId: 'acme', trigger: { kind: 'manual' },
    nodes: [
      { id: 'source', kind: 'source', config: { transport: { method: 'GET', path: '/x' }, idField: 'id' } },
      { id: 'map', kind: 'map', config: { connections: [{ target: 'name', sources: ['first'] }] } },
      { id: 'destination', kind: 'destination', config: { kind: 'd1', table: 'clients', mode: 'stored' } },
    ],
    edges: [{ from: 'source', to: 'map' }, { from: 'map', to: 'destination' }],
  };
}

const deps = (): ExecuteDeps => ({
  transport: { fetchAll: async () => [{ id: 7, first: 'Ada' }, { id: 8, first: 'Grace' }] },
  db: {} as ExecuteDeps['db'], hooks: {}, now: () => 1, genId: () => 'g',
  trace: { enabled: true, maxRecords: 50 }, dryRun: true,
});

describe('executeFlow tracing', () => {
  it('returns a trace with one record per row and no writes (dryRun)', async () => {
    const result = await executeFlow(flow(), deps());
    expect(result.recordsIn).toBe(2);
    expect(result.recordsOut).toBe(2);           // counted under dryRun
    expect(result.trace).toBeDefined();
    expect(result.trace!.records.map((r) => r.recordKey)).toEqual(['7', '8']);
    expect(result.trace!.records[0].nodes[0].out!.current).toEqual({ name: 'Ada' });
  });

  it('omits trace when deps.trace absent', async () => {
    const d = deps(); delete (d as { trace?: unknown }).trace;
    const result = await executeFlow(flow(), d);
    expect(result.trace).toBeUndefined();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd eldrin-integration && npx vitest run src/flow/execute-trace.test.ts`
Expected: FAIL — `result.trace` is undefined / type error.

- [ ] **Step 3: Implement in execute.ts**

In `src/flow/execute.ts`: import `createTraceCollector` + `ExecuteTrace`; build a collector when `deps.trace`; wrap each row; attach trace to the return.

```ts
import { createTraceCollector } from './trace';
import type { ExecuteTrace } from './trace';
// ... change signature:
export async function executeFlow(flow: Flow, deps: ExecuteDeps): Promise<ExecuteResult & { trace?: ExecuteTrace }> {
  // ... unchanged setup through createSinks ...
  const collector = deps.trace ? createTraceCollector(deps.trace.maxRecords) : null;

  for await (const row of sourceStage()) {
    recordsIn++;
    const traced = collector?.beginRecord(row.remoteId) ?? false;
    await walkRow({ startNodeId: firstAfterSource, row, byId, outByNode, deps, sinks, collectError, onRoutedNowhere: () => { routedNowhere++; }, collector: traced ? collector! : undefined });
    if (traced) collector!.commitRecord();
  }
  await sinks.flushAll();

  const destinations = sinks.recordsOutByDest();
  let recordsOut = 0;
  for (const id of sinks.ids()) recordsOut += destinations[id].recordsOut;

  const base = { flowId: flow.id, recordsIn, recordsOut, errors, destinations, routedNowhere };
  return collector ? { ...base, trace: collector.result() } : base;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd eldrin-integration && npx vitest run src/flow/execute-trace.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Regression**

Run: `cd eldrin-integration && npx vitest run`
Expected: PASS — all green; production callers ignore `trace`.

- [ ] **Step 6: Commit**

```bash
cd eldrin-integration && git add src/flow/execute.ts src/flow/execute-trace.test.ts && git commit -m "feat(flow): executeFlow builds + returns ExecuteTrace when tracing enabled"
```

---

### Task 1.6: fixtureTransport

**Files:**
- Create: `src/transport/fixture.ts`
- Test: `src/transport/fixture.test.ts`

**Interfaces:**
- Produces: `export function fixtureTransport(records: Record<string, unknown>[]): Transport` — `fetchAll` returns the records as-is; no `fetchStream` (execute wraps fetchAll).

- [ ] **Step 1: Write the failing test**

```ts
// src/transport/fixture.test.ts
import { describe, it, expect } from 'vitest';
import { fixtureTransport } from './fixture';

describe('fixtureTransport', () => {
  it('fetchAll returns the provided records', async () => {
    const t = fixtureTransport([{ id: 1 }, { id: 2 }]);
    expect(await t.fetchAll({} as never)).toEqual([{ id: 1 }, { id: 2 }]);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd eldrin-integration && npx vitest run src/transport/fixture.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement**

```ts
// src/transport/fixture.ts
import type { Transport } from './index';

/** A Transport that yields a fixed set of records — used to run a flow against a stored sample. */
export function fixtureTransport(records: Record<string, unknown>[]): Transport {
  return { fetchAll: async () => records };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd eldrin-integration && npx vitest run src/transport/fixture.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd eldrin-integration && git add src/transport/fixture.ts src/transport/fixture.test.ts && git commit -m "feat(transport): add fixtureTransport for sample-driven runs"
```

---

### Task 1.7: Phase 1 gate — build the dist

- [ ] **Step 1: Full suite + build**

Run: `cd eldrin-integration && npx vitest run && npm run build`
Expected: all tests PASS; `tsup` build success.

- [ ] **Step 2: Commit (if build artifacts are tracked; otherwise skip)**

If `dist/` is gitignored, no commit. Note in the PR that Phase 1 is consumed by later phases via the rebuilt dist.

---

# PHASE 2 — SDK samples store + routes

### Task 2.1: Sample types

**Files:**
- Create: `src/flow/sample-types.ts`

**Interfaces:**
- Produces: `HttpExchange`, `FlowSample` (exact shapes from spec §2).

- [ ] **Step 1: Write the types (no test needed — pure type decls; covered by store/extract tests)**

```ts
// src/flow/sample-types.ts
export interface HttpExchange {
  request: {
    method: string;
    url: string;
    headers: Record<string, string>;
    cookies?: Record<string, string>;
    body?: unknown;
  };
  response: {
    status: number;
    headers: Record<string, string>;
    cookies?: Record<string, string>;
    body: unknown;
  };
  capturedAt: number;
  origin: 'live' | 'manual';
}

export interface FlowSample {
  flowId: string;
  key: string;          // 'source' | <nodeId>
  label?: string;
  exchange: HttpExchange;
  arrayPath: string;    // dot-path to records array within response.body; '' = root
  entryIndex: number;
}
```

- [ ] **Step 2: Typecheck + commit**

Run: `cd eldrin-integration && npx tsc --noEmit`
Expected: PASS.
```bash
cd eldrin-integration && git add src/flow/sample-types.ts && git commit -m "feat(flow): add sample types (HttpExchange, FlowSample)"
```

---

### Task 2.2: Samples table DDL

**Files:**
- Modify: `src/schema/tables.ts`

**Interfaces:**
- Produces: `SAMPLES_DDL` added to `SDK_TABLES`. Created idempotently by existing `ensureManagementTables` (no code change needed there — it iterates `SDK_TABLES`).

- [ ] **Step 1: Add the DDL**

In `src/schema/tables.ts`, after `FLOWS_DDL`:

```ts
export const SAMPLES_DDL =
  `CREATE TABLE IF NOT EXISTS _integration_flow_samples (` +
  `flow_id TEXT NOT NULL, key TEXT NOT NULL, data TEXT NOT NULL, ` +
  `updated_at INTEGER NOT NULL, ` +
  `PRIMARY KEY (flow_id, key))`;

export const SDK_TABLES: string[] = [
  SYNC_STATE_DDL,
  INTEGRATION_CONFIG_DDL,
  WEBHOOK_DELIVERIES_DDL,
  FLOWS_DDL,
  SAMPLES_DDL,
];
```

- [ ] **Step 2: Typecheck + commit**

Run: `cd eldrin-integration && npx tsc --noEmit`
Expected: PASS.
```bash
cd eldrin-integration && git add src/schema/tables.ts && git commit -m "feat(schema): add _integration_flow_samples table DDL"
```

---

### Task 2.3: sample-store CRUD

**Files:**
- Create: `src/flow/sample-store.ts`
- Test: `src/flow/sample-store.test.ts`

**Interfaces:**
- Consumes: `DatabaseAdapter` (from `@eldrin-project/eldrin-app-core`, same import as `store.ts`), `FlowSample` (2.1).
- Produces:
  ```ts
  export function saveSample(db, sample: FlowSample, now: () => number): Promise<void>;
  export function readSample(db, flowId: string, key: string): Promise<FlowSample | null>;
  export function listSamples(db, flowId: string): Promise<FlowSample[]>;
  export function deleteSample(db, flowId: string, key: string): Promise<boolean>;
  ```

- [ ] **Step 1: Write the failing test (use an in-memory DatabaseAdapter test double matching the .prepare().bind().run()/.first()/.all() API)**

```ts
// src/flow/sample-store.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import { saveSample, readSample, listSamples, deleteSample } from './sample-store';
import type { FlowSample } from './sample-types';
import { makeTestDb } from '../test-helpers'; // existing helper used by store.test.ts; if absent, see note

const sample = (key: string): FlowSample => ({
  flowId: 'acme:clients', key,
  exchange: { request: { method: 'GET', url: '/x', headers: {} }, response: { status: 200, headers: {}, body: [{ id: 1 }] }, capturedAt: 1, origin: 'manual' },
  arrayPath: '', entryIndex: 0,
});

describe('sample-store', () => {
  let db: ReturnType<typeof makeTestDb>;
  beforeEach(async () => { db = makeTestDb(); await db.exec?.(); });

  it('saves and reads back a sample', async () => {
    await saveSample(db, sample('source'), () => 5);
    const got = await readSample(db, 'acme:clients', 'source');
    expect(got).toEqual(sample('source'));
  });

  it('upserts on same (flowId,key)', async () => {
    await saveSample(db, sample('source'), () => 5);
    await saveSample(db, { ...sample('source'), entryIndex: 3 }, () => 6);
    const got = await readSample(db, 'acme:clients', 'source');
    expect(got!.entryIndex).toBe(3);
    expect((await listSamples(db, 'acme:clients'))).toHaveLength(1);
  });

  it('lists and deletes', async () => {
    await saveSample(db, sample('source'), () => 5);
    await saveSample(db, sample('enrich-1'), () => 5);
    expect(await listSamples(db, 'acme:clients')).toHaveLength(2);
    expect(await deleteSample(db, 'acme:clients', 'source')).toBe(true);
    expect(await listSamples(db, 'acme:clients')).toHaveLength(1);
  });

  it('returns null for missing', async () => {
    expect(await readSample(db, 'acme:clients', 'nope')).toBeNull();
  });
});
```

> **Note for implementer:** Look at how `src/flow/store.test.ts` constructs its test `DatabaseAdapter` (it must create one, since store.ts is unit-tested). Reuse that exact helper/pattern (`makeTestDb` is a placeholder name — match the real one). Ensure the samples table DDL (`SAMPLES_DDL`) is applied in the test setup the same way the flows table is.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd eldrin-integration && npx vitest run src/flow/sample-store.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement (mirror store.ts patterns for prepare/bind/run/first/all)**

```ts
// src/flow/sample-store.ts
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';
import type { FlowSample } from './sample-types';

const TABLE = '_integration_flow_samples';

export async function saveSample(db: DatabaseAdapter, sample: FlowSample, now: () => number): Promise<void> {
  await db.prepare(
    `INSERT INTO ${TABLE} (flow_id, key, data, updated_at) VALUES (?, ?, ?, ?) ` +
    `ON CONFLICT(flow_id, key) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`,
  ).bind(sample.flowId, sample.key, JSON.stringify(sample), now()).run();
}

export async function readSample(db: DatabaseAdapter, flowId: string, key: string): Promise<FlowSample | null> {
  const row = await db.prepare(`SELECT data FROM ${TABLE} WHERE flow_id = ? AND key = ?`).bind(flowId, key).first<{ data: string }>();
  return row ? (JSON.parse(row.data) as FlowSample) : null;
}

export async function listSamples(db: DatabaseAdapter, flowId: string): Promise<FlowSample[]> {
  const res = await db.prepare(`SELECT data FROM ${TABLE} WHERE flow_id = ? ORDER BY key`).bind(flowId).all<{ data: string }>();
  return (res.results ?? []).map((r) => JSON.parse(r.data) as FlowSample);
}

export async function deleteSample(db: DatabaseAdapter, flowId: string, key: string): Promise<boolean> {
  const res = await db.prepare(`DELETE FROM ${TABLE} WHERE flow_id = ? AND key = ?`).bind(flowId, key).run();
  return (res.meta?.changes ?? 0) > 0;
}
```

> **Implementer:** confirm the exact `.all()` result shape (`.results`) and `.run()` meta (`.meta.changes`) against how `store.ts` reads them — match it verbatim. The DatabaseAdapter wraps D1, which exposes `meta.changes` (confirmed in project notes).

- [ ] **Step 4: Run test to verify it passes**

Run: `cd eldrin-integration && npx vitest run src/flow/sample-store.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd eldrin-integration && git add src/flow/sample-store.ts src/flow/sample-store.test.ts && git commit -m "feat(flow): add sample-store CRUD over _integration_flow_samples"
```

---

### Task 2.4: sample-extract (array-path + field inference)

**Files:**
- Create: `src/flow/sample-extract.ts`
- Test: `src/flow/sample-extract.test.ts`

**Interfaces:**
- Produces:
  ```ts
  export function resolveRecords(body: unknown, arrayPath: string): Record<string, unknown>[];
  export function detectArrayPath(body: unknown): string;   // '' if body is the array; else first key whose value is an array, preferring data|items|results
  export function extractFields(entry: unknown): string[];   // dot-pathed keys of a record (one level of nesting)
  ```

- [ ] **Step 1: Write the failing test**

```ts
// src/flow/sample-extract.test.ts
import { describe, it, expect } from 'vitest';
import { resolveRecords, detectArrayPath, extractFields } from './sample-extract';

describe('sample-extract', () => {
  it('resolveRecords: root array', () => {
    expect(resolveRecords([{ a: 1 }], '')).toEqual([{ a: 1 }]);
  });
  it('resolveRecords: nested path', () => {
    expect(resolveRecords({ data: [{ a: 1 }] }, 'data')).toEqual([{ a: 1 }]);
  });
  it('resolveRecords: deep dotted path', () => {
    expect(resolveRecords({ result: { items: [{ a: 1 }] } }, 'result.items')).toEqual([{ a: 1 }]);
  });
  it('resolveRecords: missing path → empty', () => {
    expect(resolveRecords({ data: [] }, 'nope')).toEqual([]);
  });
  it('detectArrayPath: root array', () => {
    expect(detectArrayPath([{ a: 1 }])).toBe('');
  });
  it('detectArrayPath: prefers data over other keys', () => {
    expect(detectArrayPath({ meta: {}, data: [{ a: 1 }], other: [1] })).toBe('data');
  });
  it('extractFields: flat + one nesting level (dot)', () => {
    expect(extractFields({ id: 1, name: 'x', addr: { city: 'NYC' } }).sort()).toEqual(['addr.city', 'id', 'name'].sort());
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd eldrin-integration && npx vitest run src/flow/sample-extract.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement**

```ts
// src/flow/sample-extract.ts
const PREFERRED = ['data', 'items', 'results', 'records'];

export function resolveRecords(body: unknown, arrayPath: string): Record<string, unknown>[] {
  if (arrayPath === '') return Array.isArray(body) ? (body as Record<string, unknown>[]) : [];
  let cur: unknown = body;
  for (const seg of arrayPath.split('.')) {
    if (cur && typeof cur === 'object' && seg in (cur as Record<string, unknown>)) cur = (cur as Record<string, unknown>)[seg];
    else return [];
  }
  return Array.isArray(cur) ? (cur as Record<string, unknown>[]) : [];
}

export function detectArrayPath(body: unknown): string {
  if (Array.isArray(body)) return '';
  if (!body || typeof body !== 'object') return '';
  const obj = body as Record<string, unknown>;
  for (const k of PREFERRED) if (Array.isArray(obj[k])) return k;
  for (const k of Object.keys(obj)) if (Array.isArray(obj[k])) return k;
  return '';
}

export function extractFields(entry: unknown): string[] {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return [];
  const out: string[] = [];
  for (const [k, v] of Object.entries(entry as Record<string, unknown>)) {
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      for (const nk of Object.keys(v as Record<string, unknown>)) out.push(`${k}.${nk}`);
    } else {
      out.push(k);
    }
  }
  return out;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd eldrin-integration && npx vitest run src/flow/sample-extract.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd eldrin-integration && git add src/flow/sample-extract.ts src/flow/sample-extract.test.ts && git commit -m "feat(flow): add sample field extraction (array-path + dot-field inference)"
```

---

### Task 2.5: Sample CRUD routes (GET/PUT/DELETE)

**Files:**
- Modify: `src/host/create-worker.ts`
- Test: extend the existing worker route test (find it: a `create-worker.test.ts` or similar that exercises `/api/flows` routes with mocked headers).

**Interfaces:**
- Consumes: `saveSample`/`readSample`/`listSamples`/`deleteSample` (2.3), `FlowSample` (2.1), existing `resolveUserId`/`isAdmin`/`prepare`.
- Produces routes:
  - `GET /api/flows/:id/samples` → `c.json({ samples: FlowSample[] })`
  - `PUT /api/flows/:id/samples/:key` → body `{ sample: FlowSample }` → `c.json({ ok: true })`
  - `DELETE /api/flows/:id/samples/:key` → `c.json({ deleted: boolean })`

- [ ] **Step 1: Write the failing test (mirror existing worker test setup — admin headers, app.request)**

```ts
// in the existing worker route test file
it('PUT then GET samples round-trips (admin)', async () => {
  const app = makeApp(); // existing helper that builds the Hono app with test env
  const sample = { flowId: 'factorial:employees', key: 'source', exchange: { request: { method: 'GET', url: '/e', headers: {} }, response: { status: 200, headers: {}, body: [{ id: 1 }] }, capturedAt: 1, origin: 'manual' }, arrayPath: '', entryIndex: 0 };
  const put = await app.request('/api/flows/factorial:employees/samples/source', { method: 'PUT', headers: adminHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify({ sample }) });
  expect(put.status).toBe(200);
  const get = await app.request('/api/flows/factorial:employees/samples', { headers: adminHeaders() });
  const body = await get.json();
  expect(body.samples).toHaveLength(1);
  expect(body.samples[0].key).toBe('source');
});

it('samples routes are admin-gated (403 for non-admin)', async () => {
  const app = makeApp();
  const r = await app.request('/api/flows/x/samples', { headers: { 'X-Eldrin-User-Id': 'u1' } });
  expect(r.status).toBe(403);
});
```

> **Implementer:** match the exact test helpers (`makeApp`, `adminHeaders`) used by the existing worker route tests. If none exist, the existing `/api/flows` routes must be tested somewhere — find and reuse that harness.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd eldrin-integration && npx vitest run <worker-route-test-file>`
Expected: FAIL — 404 (routes not defined).

- [ ] **Step 3: Implement the three routes**

Add near the other `/api/flows/:id/*` routes in `create-worker.ts`, following the exact auth + envelope pattern:

```ts
app.get('/api/flows/:id/samples', async (c) => {
  const userId = resolveUserId(c);
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);
  if (!isAdmin(c)) return c.json({ error: 'Forbidden: admin role required' }, 403);
  const { db } = await prepare(c.env);
  const samples = await listSamples(db, c.req.param('id'));
  return c.json({ samples });
});

app.put('/api/flows/:id/samples/:key', async (c) => {
  const userId = resolveUserId(c);
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);
  if (!isAdmin(c)) return c.json({ error: 'Forbidden: admin role required' }, 403);
  const { db } = await prepare(c.env);
  const body = await c.req.json().catch(() => null);
  const sample = body?.sample;
  if (!sample || sample.flowId !== c.req.param('id') || sample.key !== c.req.param('key')) {
    return c.json({ error: 'Sample id/key mismatch or missing' }, 400);
  }
  await saveSample(db, sample, () => Date.now());
  return c.json({ ok: true });
});

app.delete('/api/flows/:id/samples/:key', async (c) => {
  const userId = resolveUserId(c);
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);
  if (!isAdmin(c)) return c.json({ error: 'Forbidden: admin role required' }, 403);
  const { db } = await prepare(c.env);
  const deleted = await deleteSample(db, c.req.param('id'), c.req.param('key'));
  return c.json({ deleted });
});
```

Add the imports for `listSamples`/`saveSample`/`deleteSample` at the top.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd eldrin-integration && npx vitest run <worker-route-test-file>`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd eldrin-integration && git add src/host/create-worker.ts <test-file> && git commit -m "feat(host): add /api/flows/:id/samples CRUD routes (admin-gated)"
```

---

### Task 2.6: /capture route

**Files:**
- Modify: `src/host/create-worker.ts` (route + a `captureExchange` helper)
- Test: extend worker route test

**Interfaces:**
- Consumes: existing transport build path (how `buildDeps`/`runAllSync` obtain a configured HTTP transport with auth + baseUrl), `resolveRecords`/`detectArrayPath` (2.4).
- Produces: `POST /api/flows/:id/capture` → performs the source resource's request via the configured HTTP transport, returns `c.json({ exchange: HttpExchange, suggestedArrayPath: string })`. Does NOT save.

> **Design note for implementer:** The existing `HttpTransport.fetchAll` doesn't expose the raw request/response envelope (just records). For `/capture` you need the full exchange (status, headers, body). Two acceptable approaches — pick the smaller:
> (a) Add an optional `captureExchange?(resource): Promise<HttpExchange>` to the `Transport` interface and implement it in `http.ts` by performing one request and recording method/url/headers/status/response-headers/body. Wire it via the same `auth.apply()` + `fetchImpl` path `fetchAll` uses.
> (b) If touching the Transport interface is too broad, write a focused `captureExchange(connection, auth, baseUrl, resource, fetchImpl)` helper in a new `src/transport/capture.ts` reusing `auth.apply()` and `fetchImpl`, returning the `HttpExchange`.
> Prefer (b) — it keeps `Transport` minimal and is independently testable. The route calls this helper for the flow's source node config.

- [ ] **Step 1: Write the failing test for the capture helper (unit, with a fake fetchImpl)**

```ts
// src/transport/capture.test.ts
import { describe, it, expect } from 'vitest';
import { captureExchange } from './capture';

describe('captureExchange', () => {
  it('records request + response into an HttpExchange', async () => {
    const fetchImpl = (async (url: string, init: RequestInit) => ({
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({ data: [{ id: 1 }] }),
      text: async () => '{"data":[{"id":1}]}',
    })) as unknown as typeof fetch;
    const auth = { apply: async (req: { headers: Record<string, string>; url: string }) => req };
    const ex = await captureExchange({ retry: undefined } as never, auth as never, 'https://api.example.com', { transport: { method: 'GET', path: '/employees' } } as never, fetchImpl);
    expect(ex.request.method).toBe('GET');
    expect(ex.request.url).toBe('https://api.example.com/employees');
    expect(ex.response.status).toBe(200);
    expect(ex.response.body).toEqual({ data: [{ id: 1 }] });
    expect(ex.origin).toBe('live');
  });
});
```

- [ ] **Step 2: Run test → fail**

Run: `cd eldrin-integration && npx vitest run src/transport/capture.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement capture helper**

```ts
// src/transport/capture.ts
import type { HttpExchange } from '../flow/sample-types';

const headersToObj = (h: Headers): Record<string, string> => {
  const o: Record<string, string> = {};
  h.forEach((v, k) => { o[k] = v; });
  return o;
};

export async function captureExchange(
  _connection: unknown,
  auth: { apply: (req: { headers: Record<string, string>; url: string }) => Promise<{ headers: Record<string, string>; url: string }> },
  baseUrl: string,
  resource: { transport: { method?: string; path: string } },
  fetchImpl: typeof fetch,
  now: () => number = () => Date.now(),
): Promise<HttpExchange> {
  const url = `${baseUrl}${resource.transport.path}`;
  const method = resource.transport.method ?? 'GET';
  const authed = await auth.apply({ headers: { Accept: 'application/json' }, url });
  const res = await fetchImpl(authed.url, { method, headers: authed.headers });
  const text = await res.text();
  let body: unknown;
  try { body = JSON.parse(text); } catch { body = text; }
  return {
    request: { method, url: authed.url, headers: authed.headers },
    response: { status: res.status, headers: headersToObj(res.headers), body },
    capturedAt: now(),
    origin: 'live',
  };
}
```

- [ ] **Step 4: Run test → pass**

Run: `cd eldrin-integration && npx vitest run src/transport/capture.test.ts`
Expected: PASS.

- [ ] **Step 5: Add the route**

In `create-worker.ts`, add `POST /api/flows/:id/capture`. Resolve the flow's source node, obtain the configured `auth`/`baseUrl`/`fetchImpl` the same way `buildDeps` does for sync, call `captureExchange`, suggest an array path:

```ts
app.post('/api/flows/:id/capture', async (c) => {
  const userId = resolveUserId(c);
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);
  if (!isAdmin(c)) return c.json({ error: 'Forbidden: admin role required' }, 403);
  try {
    const { db, effective } = await prepare(c.env);
    // resolve the source resource for this flow (reuse compiled/stored flow lookup like /fields)
    const compiled = compileDescriptorToFlows(effective);
    const stored = new Map((await listFlows(db)).map((s) => [s.id, s]));
    const match = compiled.find((f) => f.id === c.req.param('id'));
    if (!match) return c.json({ error: 'Flow not found' }, 404);
    const flow = stored.get(c.req.param('id'))?.flow ?? match;
    const sourceNode = flow.nodes.find((n) => n.kind === 'source');
    const resourceName = (sourceNode?.config as { idField?: string } | undefined) && flow.id;
    const resource = effective.resources.find((r) => match.id.endsWith(r.name)) ?? effective.resources[0];
    const { auth, baseUrl, fetchImpl } = resolveConnection(c.env, effective); // implementer: extract from buildDeps
    const exchange = await captureExchange(effective.connection, auth, baseUrl, resource, fetchImpl);
    const suggestedArrayPath = detectArrayPath(exchange.response.body);
    return c.json({ exchange, suggestedArrayPath });
  } catch (e) {
    const status = e instanceof IntegrationError ? e.status : 502;
    return c.json({ error: e instanceof Error ? e.message : 'Capture failed' }, status as 400 | 404 | 500 | 502);
  }
});
```

> **Implementer:** the exact way to get `auth`/`baseUrl`/`fetchImpl` lives inside `buildDeps`/the transport construction used by `runAllSync`. Factor a small `resolveConnection(env, effective)` if needed, or inline it. Map the flow id → resource the same way `/fields` does (it already maps a flow to its destination resource; the source resource is the integration resource the flow reads — for factorial, flow `factorial:employees` → resource `employees`). Verify the mapping against `compileDescriptorToFlows`.

- [ ] **Step 6: Add a route test (mock fetchImpl via env or a transport seam)**

Add a worker test that posts `/capture` and asserts `{ exchange, suggestedArrayPath }` shape and 403 for non-admin. Use whatever fetch-injection the existing transport tests use.

- [ ] **Step 7: Run + commit**

Run: `cd eldrin-integration && npx vitest run`
Expected: PASS.
```bash
cd eldrin-integration && git add src/transport/capture.ts src/transport/capture.test.ts src/host/create-worker.ts <test-file> && git commit -m "feat(host): add /capture route + captureExchange helper (live request → HttpExchange)"
```

---

### Task 2.7: /test route

**Files:**
- Modify: `src/host/create-worker.ts`
- Test: worker route test

**Interfaces:**
- Consumes: `readDraft`/`readFlowForEdit` (store), `validateFlow`, `executeFlow` (now trace-capable), `fixtureTransport` (1.6), `readSample` (2.3), `resolveRecords` (2.4), the live transport build (from 2.6).
- Produces: `POST /api/flows/:id/test`, body `{ mode: 'sample'|'live', trace: { maxRecords: number } }` → `c.json({ result: ExecuteResult, trace: ExecuteTrace, capturedExchange?: HttpExchange })`. Always reads the draft; always `dryRun: true`.

- [ ] **Step 1: Write the failing test**

```ts
it('POST /test sample-mode runs the draft against the stored sample, dry-run, returns trace', async () => {
  const app = makeApp();
  // seed a draft (use existing POST /api/flows/:id) + a source sample
  await app.request('/api/flows/factorial:employees', { method: 'POST', headers: adminHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify({ flow: validEmployeesFlow(), baseVersion: null }) });
  const sample = { flowId: 'factorial:employees', key: 'source', exchange: { request: { method: 'GET', url: '/e', headers: {} }, response: { status: 200, headers: {}, body: [{ id: 7, first_name: 'Ada' }] }, capturedAt: 1, origin: 'manual' }, arrayPath: '', entryIndex: 0 };
  await app.request('/api/flows/factorial:employees/samples/source', { method: 'PUT', headers: adminHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify({ sample }) });
  const r = await app.request('/api/flows/factorial:employees/test', { method: 'POST', headers: adminHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify({ mode: 'sample', trace: { maxRecords: 50 } }) });
  expect(r.status).toBe(200);
  const body = await r.json();
  expect(body.result.recordsIn).toBe(1);
  expect(body.trace.records).toHaveLength(1);
});

it('POST /test sample-mode 409 when no source sample', async () => {
  const app = makeApp();
  await app.request('/api/flows/factorial:employees', { method: 'POST', headers: adminHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify({ flow: validEmployeesFlow(), baseVersion: null }) });
  const r = await app.request('/api/flows/factorial:employees/test', { method: 'POST', headers: adminHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify({ mode: 'sample', trace: { maxRecords: 50 } }) });
  expect(r.status).toBe(409);
});
```

- [ ] **Step 2: Run test → fail**

Run: `cd eldrin-integration && npx vitest run <worker-route-test-file>`
Expected: FAIL — 404.

- [ ] **Step 3: Implement the route**

```ts
app.post('/api/flows/:id/test', async (c) => {
  const userId = resolveUserId(c);
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);
  if (!isAdmin(c)) return c.json({ error: 'Forbidden: admin role required' }, 403);
  try {
    const { db, effective } = await prepare(c.env);
    const id = c.req.param('id');
    const body = await c.req.json().catch(() => null);
    const mode = body?.mode === 'live' ? 'live' : 'sample';
    const maxRecords = Number(body?.trace?.maxRecords) || 50;

    const stored = (await readDraft(db, id)) ?? (await readFlowForEdit(db, id));
    if (!stored) return c.json({ error: 'No draft to test' }, 404);

    validateFlow(stored.flow, {
      hooks: boundHooks, hookSlots: new Set(['transform', 'beforeUpsert']),
      knownTables: new Set(effective.resources.map((r) => r.name)),
    });

    const { deps: liveDeps } = buildDeps(c.env as never, db);
    let transport = liveDeps.transport;
    let capturedExchange: HttpExchange | undefined;

    if (mode === 'sample') {
      const sample = await readSample(db, id, 'source');
      if (!sample) return c.json({ error: 'No source sample — capture or paste one first' }, 409);
      const records = resolveRecords(sample.exchange.response.body, sample.arrayPath);
      transport = fixtureTransport(records);
    }
    // live mode: keep liveDeps.transport (real fetch); optionally capture is a separate /capture call

    const result = await executeFlow(stored.flow, { ...liveDeps, transport, dryRun: true, trace: { enabled: true, maxRecords } });
    return c.json({ result, trace: result.trace, capturedExchange });
  } catch (e) {
    const status = e instanceof IntegrationError ? e.status : 500;
    return c.json({ error: e instanceof Error ? e.message : 'Test failed' }, status as 400 | 404 | 409 | 500);
  }
});
```

> **Implementer:** `buildDeps` is the existing helper that constructs `ExecuteDeps` for `/api/sync`. Reuse it so snippet/when evaluators + hooks + db are wired identically. The only overrides are `transport` (fixture in sample mode), `dryRun: true`, and `trace`.

- [ ] **Step 4: Run test → pass**

Run: `cd eldrin-integration && npx vitest run <worker-route-test-file>`
Expected: PASS.

- [ ] **Step 5: Regression + commit**

Run: `cd eldrin-integration && npx vitest run`
Expected: PASS.
```bash
cd eldrin-integration && git add src/host/create-worker.ts <test-file> && git commit -m "feat(host): add /test route — dry-run draft execution with trace (sample + live)"
```

---

### Task 2.8: Phase 2 gate — build dist + rebuild factorial + live smoke

- [ ] **Step 1: Build the SDK**

Run: `cd eldrin-integration && npx vitest run && npm run build`
Expected: PASS + build success.

- [ ] **Step 2: Rebuild the consumer**

Run: `cd eldrin-factorial && npm run build`
Expected: build success (picks up new SDK dist).

- [ ] **Step 3: Live smoke (curl the running factorial worker, admin headers)**

With the factorial dev worker running, capture + test:
```bash
# PUT a manual sample, then POST /test sample-mode — expect 200 with trace.records
```
Document the exact commands + responses in the PR. (Full browser verification happens in Phase 4.)

---

# PHASE 3 — Core: samples + mapping fields

### Task 3.1: API client types + functions

**Files:**
- Modify: `src/pages/integrations/integrations-api.ts`
- Test: `src/pages/integrations/integrations-api.test.ts` (extend)

**Interfaces:**
- Produces (matching the `call<T>()`/`Result<T>` style):
  ```ts
  export interface HttpExchange { /* mirror of SDK shape */ }
  export interface FlowSample { flowId: string; key: string; label?: string; exchange: HttpExchange; arrayPath: string; entryIndex: number; }
  export interface NodeTrace { nodeId: string; in: Row; out: Row | null; }
  export interface EdgeTrace { from: string; to: string; payload: Row; }
  export interface RecordTrace { recordKey: string; nodes: NodeTrace[]; edges: EdgeTrace[]; }
  export interface ExecuteTrace { records: RecordTrace[]; truncated: boolean; }
  export interface Row { remoteId: string; raw: Record<string, unknown>; current: Record<string, unknown>; }
  export interface ExecuteResult { flowId: string; recordsIn: number; recordsOut: number; errors: { nodeId: string; remoteId?: string; message: string }[]; destinations: Record<string, { table: string; recordsOut: number }>; routedNowhere: number; }
  export function fetchSamples(appId, flowId, authFetch): Promise<Result<{ samples: FlowSample[] }>>;
  export function saveSample(appId, sample: FlowSample, authFetch): Promise<Result<{ ok: true }>>;
  export function deleteSample(appId, flowId, key, authFetch): Promise<Result<{ deleted: boolean }>>;
  export function captureSample(appId, flowId, authFetch): Promise<Result<{ exchange: HttpExchange; suggestedArrayPath: string }>>;
  export function testFlow(appId, flowId, mode: 'sample'|'live', maxRecords, authFetch): Promise<Result<{ result: ExecuteResult; trace: ExecuteTrace; capturedExchange?: HttpExchange }>>;
  ```

- [ ] **Step 1: Write the failing test (mirror existing res()/vi.fn() pattern)**

```ts
// append to integrations-api.test.ts
it('fetchSamples returns samples on 200', async () => {
  const authFetch = vi.fn(async () => res(200, { samples: [{ flowId: 'factorial:employees', key: 'source', exchange: {}, arrayPath: '', entryIndex: 0 }] }));
  const r = await fetchSamples('factorial', 'factorial:employees', authFetch);
  expect(authFetch).toHaveBeenCalledWith('factorial', '/api/flows/factorial%3Aemployees/samples');
  expect(r.ok && r.data.samples).toHaveLength(1);
});

it('testFlow posts mode + maxRecords', async () => {
  const authFetch = vi.fn(async () => res(200, { result: { recordsIn: 1 }, trace: { records: [], truncated: false } }));
  const r = await testFlow('factorial', 'factorial:employees', 'sample', 50, authFetch);
  expect(authFetch).toHaveBeenCalledWith('factorial', '/api/flows/factorial%3Aemployees/test', expect.objectContaining({ method: 'POST' }));
  expect(r.ok).toBe(true);
});
```

- [ ] **Step 2: Run → fail.** `cd eldrin-core && npx vitest run src/pages/integrations/integrations-api.test.ts` → FAIL (not exported).

- [ ] **Step 3: Implement** the types + functions in `integrations-api.ts`, mirroring `fetchFlowFields`/`publishFlow` exactly (use `encodeURIComponent`, `call<T>()`, JSON body for POST/PUT).

```ts
export function fetchSamples(appId: string, flowId: string, authFetch: AuthFetch) {
  return call<{ samples: FlowSample[] }>(authFetch(appId, `/api/flows/${encodeURIComponent(flowId)}/samples`));
}
export function saveSample(appId: string, sample: FlowSample, authFetch: AuthFetch) {
  return call<{ ok: true }>(authFetch(appId, `/api/flows/${encodeURIComponent(sample.flowId)}/samples/${encodeURIComponent(sample.key)}`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sample }),
  }));
}
export function deleteSample(appId: string, flowId: string, key: string, authFetch: AuthFetch) {
  return call<{ deleted: boolean }>(authFetch(appId, `/api/flows/${encodeURIComponent(flowId)}/samples/${encodeURIComponent(key)}`, { method: 'DELETE' }));
}
export function captureSample(appId: string, flowId: string, authFetch: AuthFetch) {
  return call<{ exchange: HttpExchange; suggestedArrayPath: string }>(authFetch(appId, `/api/flows/${encodeURIComponent(flowId)}/capture`, { method: 'POST' }));
}
export function testFlow(appId: string, flowId: string, mode: 'sample' | 'live', maxRecords: number, authFetch: AuthFetch) {
  return call<{ result: ExecuteResult; trace: ExecuteTrace; capturedExchange?: HttpExchange }>(authFetch(appId, `/api/flows/${encodeURIComponent(flowId)}/test`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode, trace: { maxRecords } }),
  }));
}
```
(Plus the interface declarations above.)

- [ ] **Step 4: Run → pass.** Same command → PASS.

- [ ] **Step 5: Commit**

```bash
cd eldrin-core && git add src/pages/integrations/integrations-api.ts src/pages/integrations/integrations-api.test.ts && git commit -m "feat(integrations): add sample + test API client functions and types"
```

---

### Task 3.2: Client-side sample-extract (mirror)

**Files:**
- Create: `src/pages/integrations/sample-extract.ts`
- Test: `src/pages/integrations/sample-extract.test.ts`

**Interfaces:**
- Produces: `resolveRecords`, `detectArrayPath`, `extractFields` (same signatures/behavior as SDK Task 2.4 — the UI needs them locally to render fields without a round-trip).

- [ ] **Step 1–4:** Copy the SDK `sample-extract.ts` + its test verbatim into the core path (identical pure functions). Run `cd eldrin-core && npx vitest run src/pages/integrations/sample-extract.test.ts` → fail then pass.

> Rationale: these are tiny pure functions; duplicating avoids a cross-package import from core → SDK source. They're independently tested in both repos.

- [ ] **Step 5: Commit**

```bash
cd eldrin-core && git add src/pages/integrations/sample-extract.ts src/pages/integrations/sample-extract.test.ts && git commit -m "feat(integrations): client-side sample field extraction"
```

---

### Task 3.3: SamplePanel (capture / paste / extraction controls)

**Files:**
- Create: `src/pages/integrations/SamplePanel.tsx`
- Modify: `src/locales/en/integrations.json` (keys)
- Test: `src/pages/integrations/SamplePanel.test.tsx`

**Interfaces:**
- Consumes: `fetchSamples`/`saveSample`/`deleteSample`/`captureSample` (3.1), `resolveRecords`/`detectArrayPath`/`extractFields` (3.2), `FlowSample`/`HttpExchange`.
- Produces:
  ```ts
  export function SamplePanel({ appId, flowId, authFetch, onActiveSampleChange }: {
    appId: string; flowId: string;
    authFetch: AuthFetch;
    onActiveSampleChange: (sample: FlowSample | null) => void;  // lifts the 'source' sample up so Mapping re-derives fields
  }): JSX.Element;
  ```

- [ ] **Step 1: Add i18n keys** to `integrations.json`:

```json
"viewTest": "Test",
"sampleManager": "Samples",
"captureLive": "Capture live",
"pasteManual": "Paste manual",
"arrayPath": "Array path",
"entryIndex": "Entry",
"resolvedFields": "Fields",
"noSampleYet": "Capture or paste a sample to see real source fields.",
"saveSample": "Save sample",
"deleteSample": "Delete",
"pastePlaceholder": "Paste a JSON request/response exchange…",
"captureFailed": "Capture failed",
"dryRunNotice": "Dry run — no data was written.",
"runTest": "Run",
"sampleMode": "Sample",
"liveMode": "Live",
"maxRecords": "Max records",
"saveAsSample": "Save as source sample",
"traceIn": "IN",
"traceOut": "OUT",
"traceDropped": "filtered out",
"selectNodeOrEdge": "Select a node or connection to inspect its data.",
"recordStepper": "Record",
"testSummary": "Summary",
"truncatedNotice": "Trace truncated at the record cap."
```

- [ ] **Step 2: Write the failing test** (render with a mocked authFetch; assert empty-state prompt, then capture flow). Mirror the component-test pattern from existing core tests (vitest + a render helper — check what the repo uses: React Testing Library or a custom render; match it).

```tsx
// SamplePanel.test.tsx — minimal: empty state shows noSampleYet; capture calls authFetch /capture
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { SamplePanel } from './SamplePanel';

const res = (status: number, body: unknown): Response => ({ status, ok: status >= 200 && status < 300, json: async () => body } as Response);

describe('SamplePanel', () => {
  it('shows empty-state prompt when no samples', async () => {
    const authFetch = vi.fn(async () => res(200, { samples: [] }));
    render(<SamplePanel appId="factorial" flowId="factorial:employees" authFetch={authFetch} onActiveSampleChange={() => {}} />);
    await waitFor(() => expect(screen.getByText(/Capture or paste/i)).toBeInTheDocument());
  });

  it('capture calls /capture and shows resolved fields', async () => {
    const authFetch = vi.fn()
      .mockResolvedValueOnce(res(200, { samples: [] }))
      .mockResolvedValueOnce(res(200, { exchange: { request: {}, response: { status: 200, headers: {}, body: [{ id: 1, name: 'Ada' }] }, capturedAt: 1, origin: 'live' }, suggestedArrayPath: '' }));
    render(<SamplePanel appId="factorial" flowId="factorial:employees" authFetch={authFetch} onActiveSampleChange={() => {}} />);
    fireEvent.click(await screen.findByText(/Capture live/i));
    await waitFor(() => expect(screen.getByText('name')).toBeInTheDocument());
  });
});
```

> **Implementer:** confirm the repo has `@testing-library/react` (check package.json + existing `*.test.tsx`). If the repo tests components differently, match that. If no component-test infra exists, keep SamplePanel logic in a tiny pure helper and unit-test that instead, rendering minimal JSX.

- [ ] **Step 3: Run → fail.** `cd eldrin-core && npx vitest run src/pages/integrations/SamplePanel.test.tsx`

- [ ] **Step 4: Implement SamplePanel** — load samples on mount; Capture button → `captureSample` → preview + `detectArrayPath` default; Paste → textarea parsed into an `HttpExchange` (`origin:'manual'`); `arrayPath`/`entryIndex` inputs → live `resolveRecords`+`extractFields` preview; Save → `saveSample` then `onActiveSampleChange`; Delete → `deleteSample`. Keep under ~250 lines; extract a `SampleForm` sub-component if it grows.

- [ ] **Step 5: Run → pass.**

- [ ] **Step 6: Commit**

```bash
cd eldrin-core && git add src/pages/integrations/SamplePanel.tsx src/pages/integrations/SamplePanel.test.tsx src/locales/en/integrations.json && git commit -m "feat(integrations): SamplePanel — capture/paste samples + field extraction controls"
```

---

### Task 3.4: Feed sample fields into MappingCanvas

**Files:**
- Modify: `src/pages/integrations/FlowEditorShell.tsx`
- Test: covered by the live-verify in Phase 4; add a small unit test for the field-derivation helper if extracted.

**Interfaces:**
- Consumes: active `FlowSample` from SamplePanel, `resolveRecords`/`extractFields`.
- Produces: the `fields` passed to `<MappingCanvas>` uses sample-derived `sourceFields` when a `source` sample is active, else falls back to the fetched `fields.sourceFields`.

- [ ] **Step 1: Lift sample state in FlowEditorShell**

Add `const [sourceSample, setSourceSample] = useState<FlowSample | null>(null);`. Compute:

```ts
const sampleSourceFields = sourceSample
  ? extractFields(resolveRecords(sourceSample.exchange.response.body, sourceSample.arrayPath)[sourceSample.entryIndex] ?? {})
  : null;
const effectiveFields = sampleSourceFields
  ? { ...fields, sourceFields: sampleSourceFields }
  : fields;
```

Pass `effectiveFields` to `<MappingCanvas fields={effectiveFields} ... />`.

- [ ] **Step 2: Typecheck**

Run: `cd eldrin-core && npx tsc -b`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
cd eldrin-core && git add src/pages/integrations/FlowEditorShell.tsx && git commit -m "feat(integrations): mapping source fields derived from active sample"
```

---

# PHASE 4 — Core: Test view + inspector

### Task 4.1: Add edge selection to StructuralCanvas

**Files:**
- Modify: `src/pages/integrations/StructuralCanvas.tsx`
- Test: `src/pages/integrations/StructuralCanvas.test.tsx` (or extend graph-render test if selection is logic-extractable)

**Interfaces:**
- Produces: props gain `selectedEdgeId?: string | null` and `onSelectEdge?: (id: string | null) => void`; add `onEdgeClick` handler calling `onSelectEdge(e.id)`; clicking the pane clears both node + edge selection. Edge id format stays `${from}->${to}` (matches existing `onEdgesDelete` split on `->`).

- [ ] **Step 1: Write a failing test** asserting that providing `onSelectEdge` and clicking an edge invokes it. (If RTL can't easily click an SVG edge, extract the click→id mapping into a pure helper `edgeIdOf(edge)` and unit-test that, then wire the handler.)

- [ ] **Step 2–4:** Add the props + `onEdgeClick={(_, e) => onSelectEdge?.(e.id)}` and `onPaneClick={() => { onSelectNode(null); onSelectEdge?.(null); }}`. Run tests → green. Keep node-only callers working (new props optional).

- [ ] **Step 5: Commit**

```bash
cd eldrin-core && git add src/pages/integrations/StructuralCanvas.tsx src/pages/integrations/StructuralCanvas.test.tsx && git commit -m "feat(integrations): add edge selection to StructuralCanvas"
```

---

### Task 4.2: TracePanel (pure presentational)

**Files:**
- Create: `src/pages/integrations/TracePanel.tsx`
- Test: `src/pages/integrations/TracePanel.test.tsx`

**Interfaces:**
- Consumes: `RecordTrace`, selected node/edge ids.
- Produces:
  ```ts
  export function TracePanel({ record, selectedNodeId, selectedEdgeId }: {
    record: RecordTrace | null;
    selectedNodeId: string | null;
    selectedEdgeId: string | null;   // '${from}->${to}'
  }): JSX.Element;
  ```
  Shows: node selected → its `NodeTrace` IN/OUT (two JSON blocks; `out:null` → "filtered out"). Edge selected → matching `EdgeTrace.payload`. Neither → a prompt.

- [ ] **Step 1: Failing test** — render with a `RecordTrace` fixture; selecting a node shows IN+OUT JSON; selecting a dropped node shows "filtered out"; selecting an edge shows payload; nothing selected shows the prompt.

- [ ] **Step 2–4:** Implement (lookup `record.nodes.find(n => n.nodeId === selectedNodeId)`; for edge, parse `from->to` and `record.edges.find(...)`). Render JSON via `<pre>{JSON.stringify(x, null, 2)}</pre>`. Run → green.

- [ ] **Step 5: Commit**

```bash
cd eldrin-core && git add src/pages/integrations/TracePanel.tsx src/pages/integrations/TracePanel.test.tsx && git commit -m "feat(integrations): TracePanel renders node IN/OUT + edge payload"
```

---

### Task 4.3: TestPanel (run controls + summary + stepper, wires canvas → TracePanel)

**Files:**
- Create: `src/pages/integrations/TestPanel.tsx`
- Test: `src/pages/integrations/TestPanel.test.tsx`

**Interfaces:**
- Consumes: `testFlow` (3.1), `StructuralCanvas` (4.1, for node/edge selection over the flow), `TracePanel` (4.2), `saveSample` (3.1, for live "save as sample"), `FlowGraph`.
- Produces:
  ```ts
  export function TestPanel({ appId, flowId, flow, authFetch }: {
    appId: string; flowId: string; flow: FlowGraph; authFetch: AuthFetch;
  }): JSX.Element;
  ```
  Owns: `mode`, `maxRecords`, last `{result,trace,capturedExchange}`, `selectedRecordIdx`, `selectedNodeId`, `selectedEdgeId`. Renders run controls; on Run → `testFlow`; shows summary + always the `dryRunNotice`; record stepper over `trace.records`; `<StructuralCanvas>` (read-only selection) beside `<TracePanel record={trace.records[selectedRecordIdx]} .../>`; live + `capturedExchange` → "Save as source sample" button → `saveSample`.

- [ ] **Step 1: Failing test** — mock `authFetch` returning a `{result,trace}`; click Run; assert summary numbers + dryRunNotice render; selecting a record + node shows TracePanel content. (Reuse the RTL pattern.)

- [ ] **Step 2–4:** Implement. Keep `StructuralCanvas` in a non-editing posture (pass `onFlowChange` a no-op or the real one but the Test view doesn't save). Run → green.

- [ ] **Step 5: Commit**

```bash
cd eldrin-core && git add src/pages/integrations/TestPanel.tsx src/pages/integrations/TestPanel.test.tsx && git commit -m "feat(integrations): TestPanel — run draft, summary, record stepper, inspector"
```

---

### Task 4.4: Wire Test view into FlowEditorShell

**Files:**
- Modify: `src/pages/integrations/FlowEditorShell.tsx`

**Interfaces:**
- Consumes: `TestPanel` (4.3), `SamplePanel` (3.3).
- Produces: a third `'test'` value in the `view` union + a toggle button; the Test view renders `SamplePanel` (wired to `setSourceSample` from 3.4) + `TestPanel`.

- [ ] **Step 1: Extend the view union + toggle**

```ts
const [view, setView] = useState<'structure' | 'mapping' | 'test'>('structure');
```
Add a button to the toggle group:
```tsx
<button className={`rounded px-3 py-1 ${view === 'test' ? 'bg-muted font-medium' : ''}`} onClick={() => setView('test')}>{t('viewTest')}</button>
```

- [ ] **Step 2: Render the Test view**

```tsx
{view === 'test' && (
  <div className="space-y-4">
    <SamplePanel appId={appId} flowId={flowId} authFetch={getAuthFetch()} onActiveSampleChange={setSourceSample} />
    <TestPanel appId={appId} flowId={flowId} flow={flow} authFetch={getAuthFetch()} />
  </div>
)}
```

- [ ] **Step 3: Typecheck + build**

Run: `cd eldrin-core && npx tsc -b && npm run build`
Expected: PASS + build success.

- [ ] **Step 4: Lint**

Run: `cd eldrin-core && npx eslint src/pages/integrations/*.tsx src/pages/integrations/*.ts`
Expected: no NEW errors in the new/modified files.

- [ ] **Step 5: Commit**

```bash
cd eldrin-core && git add src/pages/integrations/FlowEditorShell.tsx && git commit -m "feat(integrations): add Test view (samples + run + inspector) to flow editor"
```

---

### Task 4.5: Final gate — full cross-repo live verification

- [ ] **Step 1: Build everything**

```bash
cd eldrin-integration && npx vitest run && npm run build
cd eldrin-factorial && npm run build
cd eldrin-core && npx vitest run && npm run build
```
Expected: all green.

- [ ] **Step 2: Live-verify in the browser (chrome-devtools)** with the dev stack running:
  1. Open a flow → Test view.
  2. **Capture** a real Factorial source sample; confirm preview + auto array-path + resolved fields.
  3. Switch to **Mapping**; confirm source column now shows the sample's real fields.
  4. Back to **Test**, **Sample mode**, **Run**; confirm summary, dry-run notice, record stepper.
  5. Select a **node** → IN/OUT; select a **connection** → payload.
  6. **Live mode**, **Run**; confirm real fetch, dry-run (no writes), "Save as source sample" works.

- [ ] **Step 3: Document the verification** (screenshots / notes) in the PR. Per project rule, unit green ≠ seam green — this step is the real gate.

---

## Self-Review

**Spec coverage:**
- §1 four capabilities → Phases 1–4. ✓
- §2 data model (`HttpExchange`/`FlowSample`/trace types/table) → 2.1, 2.2, 1.1. ✓
- §3 executor trace + dry-run + fixtureTransport → 1.1–1.6. ✓
- §4 store + routes (`/samples`,`/capture`,`/test`) + validation/errors → 2.3, 2.5–2.7. ✓
- §5 UI (api client, SamplePanel, mapping fields, Test view, TracePanel, edge selection) → 3.1–3.4, 4.1–4.4. ✓
- §6 testing (SDK unit, regression gate, core unit, live cross-repo) → embedded per task + 4.5. ✓
- §7 phasing → four phases. ✓
- §8 out-of-scope honored (no replay exec, no per-node enricher UI, full-trace via maxRecords param only, always dry-run). ✓

**Placeholder scan:** No "TBD"/"handle errors"/"similar to". Two spots flagged with explicit **Implementer notes** where exact reuse must be matched against existing code (`buildDeps`/`resolveConnection`, the worker test harness `makeApp`/`adminHeaders`, the store test DB helper, RTL availability) — these are "match the existing pattern" instructions, not placeholders, because the surrounding repo conventions must be the source of truth.

**Type consistency:** `FlowSample`/`HttpExchange`/`ExecuteTrace`/`RecordTrace`/`NodeTrace`/`EdgeTrace`/`Row`/`ExecuteResult` are defined once in the SDK (Phase 1–2) and mirrored verbatim in the core api client (3.1). Edge id format `${from}->${to}` is consistent between StructuralCanvas (existing `onEdgesDelete` split), 4.1, and TracePanel (4.2). `testFlow(mode,maxRecords)` matches the `/test` body `{ mode, trace:{maxRecords} }`. `saveSample` signature consistent across 2.3 (SDK) and 3.1 (core).

**Open risk:** Task 2.6 (`/capture`) requires mapping a flow id → its source resource and extracting `auth`/`baseUrl`/`fetchImpl` from `buildDeps`. This is the least-pinned part (the explorer didn't fully expose `buildDeps`' internals). The implementer should read `buildDeps` + `runAllSync` first and may need a small `resolveConnection` factor-out. Flagged in-task.
