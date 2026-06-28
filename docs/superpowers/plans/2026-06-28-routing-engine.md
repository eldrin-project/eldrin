# Routing Engine Implementation Plan (SP6)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the SDK executor + validator support `route` nodes with conditional `when` edges and branching to N destinations — a CPI content-based router runnable on the existing host, with no UI.

**Architecture:** Reuse the SP2 sandbox for a memoized boolean `when` evaluator. Relax `validateFlow` (destinations ≥1; route nodes need ≥2 conditioned outgoing edges; `when` only on route edges + compiles; reachability). Rewrite the executor's linear pipe into a per-row branching-DAG walk with one batched sink per destination, source-order preserved per sink, governed by the single-path invariant (each row takes exactly one path, visits no node twice).

**Tech Stack:** TypeScript + Vitest, Cloudflare Workers SDK (`eldrin-integration`).

## Global Constraints

- **SDK-only:** all changes in `/Users/tibor/projects/eldrin-backup/eldrin-integration`. No eldrin-core/factorial changes (the UI is SP8).
- **Non-branching regression-safety:** the executor rewrite MUST NOT change behavior for existing single-source/single-destination linear flows. The current `src/flow/execute.test.ts` suite is the gate — it must stay green.
- **`when` trust model:** `integration:admin`-authored only; same hardened sandbox (`new Function` + `SHADOWED` denylist + frozen null-proto inputs + compile-once memoization) and documented residual risk (no CPU/timeout guard, denylist not allowlist) as SP2 snippets. Reuse `src/flow/sandbox.ts`, don't reinvent.
- **First-match routing:** a route node evaluates its outgoing edges' `when` in declared edge order; the row advances down the FIRST matching edge. No match → drop + tally (`routedNowhere`), never error.
- **Single-path invariant:** because routing is first-match and non-route nodes have exactly one outgoing edge, every row traverses exactly one path source→one destination and visits no node twice. This is what terminates the walk and disambiguates reconvergence.
- **Source = 1, destinations ≥ 1;** each destination table must be in `knownTables` (validate-time).
- **Validate-time vs run-time:** uncompilable `when` → 400 at validate-time; runtime `when` throw → drop row from that branch + `collectError`, flow continues.
- **Source-order preserved per sink;** reuse existing `flushBatch` / `BATCH_SIZE` / ordered flush.
- **`ExecuteResult` additive:** keep `recordsOut` (now total across sinks); add `destinations: { [destNodeId]: { table: string; recordsOut: number } }` and `routedNowhere: number`. The only caller (`src/sync/index.ts`) reads `errors` + `recordsIn` only, so this is safe.
- Immutability; no `console.log`; conventional commits, attribution disabled. Coverage ≥ 80%. Tests: `cd eldrin-integration && npx vitest run`.

---

## File Structure

- `src/flow/sandbox.ts` (modify) — add `compileWhen` + `createWhenEvaluator` (boolean evaluator, `{current, raw}` surface) beside the existing snippet evaluator.
- `src/flow/sandbox.test.ts` (modify, or create if absent) — `when`-evaluator unit tests.
- `src/flow/types.ts` (modify) — add `WhenInput`; add `evalWhen?` to `ExecuteDeps`; extend `ExecuteResult` with `destinations` + `routedNowhere`.
- `src/flow/validate.ts` (modify) — destinations ≥1; route/when/reachability rules; compile each `when`.
- `src/flow/validate.test.ts` (modify) — the new validation cases.
- `src/flow/execute.ts` (modify) — rewrite middle+sink into a per-row DAG walk + multi-sink; remove the route/when `NotImplementedError` guards; populate the new result fields.
- `src/flow/execute.test.ts` (modify) — replace the two route/when NotImplementedError tests with passing routing tests; add reconverge/fan-out/first-match/no-match/order tests.
- `src/sync/index.ts` (modify) — thread `evalWhen` into the `executeFlow` deps.
- `src/host/create-worker.ts` (modify) — construct `createWhenEvaluator()` and add `evalWhen` to `buildDeps`.
- `src/index.ts` (modify) — export `createWhenEvaluator` (mirrors `createSnippetEvaluator` export) if the host needs it from the barrel.

---

## Reference: current code (do not re-derive)

**The sandbox to reuse** (`src/flow/sandbox.ts`):
```ts
const SHADOWED = ['fetch','caches','crypto','globalThis','self','Function','setTimeout','setInterval','setImmediate','queueMicrotask','WebSocket','importScripts','XMLHttpRequest','Request','Response','process','require','module','Deno','Bun'];
function freeze(o) { return Object.freeze(Object.assign(Object.create(null), o)); }
export function compileSnippet(code) {
  let fn;
  try { fn = new Function('sources','row','raw', ...SHADOWED, `"use strict"; return (${code});`); }
  catch (e) { throw new IntegrationError(`snippet failed to compile: ${...}`, 400); }
  const undefinedTail = SHADOWED.map(() => undefined);
  return (input) => fn(input.sources, freeze(input.row), freeze(input.raw), ...undefinedTail);
}
export function createSnippetEvaluator() {
  const cache = new Map();
  return (code, input) => { let c = cache.get(code); if (!c) { c = compileSnippet(code); cache.set(code, c); } return c(input); };
}
```

**Current `ExecuteDeps` / `ExecuteResult` / `Row`** (`src/flow/types.ts`):
```ts
export interface Row { remoteId: string; raw: Record<string, unknown>; current: Record<string, unknown>; }
export interface ExecuteDeps { transport: Transport; db: DatabaseAdapter; hooks: HookRegistry; now: () => number; genId: () => string; evalSnippet?: (code: string, input: SnippetInput) => unknown; }
export interface ExecuteResult { flowId: string; recordsIn: number; recordsOut: number; errors: { nodeId: string; remoteId?: string; message: string }[]; }
```

**Current executor stage bodies** (`src/flow/execute.ts:63-149`) — the map/transform/filter/route logic to reuse (refactored generator→single-row), the `flushBatch` sink with `BATCH_SIZE=100`, `collectError`, `topoSort` at the top, and the route/when `NotImplementedError` guards at lines 17-21 (to REMOVE). `route` is currently unconditional pass-through (line 110-111).

**`topoSort`** (`src/flow/graph.ts`) — Kahn's algorithm, throws `IntegrationError` on cycle/unknown-node. Already handles arbitrary DAGs (multiple outgoing edges). Reuse for validation + to build adjacency.

**Validator invariants today** (`src/flow/validate.ts:37-44`): `sources.length !== 1` fail; `dests.length !== 1` fail; each destination table in `knownTables`. `validateNodeConfig` handles map/transform/filter/destination; `route` has no checks.

**The only `executeFlow` caller** (`src/sync/index.ts:46-53`) passes `{transport, db, hooks, now, genId, evalSnippet}` and reads `result.errors` + `result.recordsIn`. Add `evalWhen: deps.evalWhen` to that deps object.

**Existing test helpers** (`src/flow/execute.test.ts`): `dbSpy()` returns `{ db, ... }`; `linearFlow(extraNodes)` and `mapFlow(connections, extra)` build chains with pairwise edges. The two route/when tests at lines 186-199 assert `NotImplementedError` — these get REPLACED in Task 5.

---

## Task 1: `when` evaluator in the sandbox

**Files:**
- Modify: `src/flow/sandbox.ts`
- Modify: `src/flow/types.ts` (add `WhenInput`)
- Test: `src/flow/sandbox.test.ts`

**Interfaces:**
- Consumes: `IntegrationError` (already imported in sandbox.ts); the `SHADOWED`/`freeze` machinery (file-local).
- Produces: `WhenInput { current: Record<string, unknown>; raw: Record<string, unknown> }`; `compileWhen(expr: string): (input: WhenInput) => boolean`; `createWhenEvaluator(): (expr: string, input: WhenInput) => boolean`. Tasks 2/3 consume `createWhenEvaluator`.

- [ ] **Step 1: Add the `WhenInput` type**

In `src/flow/types.ts`, after `SnippetInput`:
```ts
export interface WhenInput {
  current: Record<string, unknown>;
  raw: Record<string, unknown>;
}
```

- [ ] **Step 2: Write the failing tests**

In `src/flow/sandbox.test.ts` (create if it doesn't exist; if it exists, append):
```ts
import { describe, it, expect } from 'vitest';
import { createWhenEvaluator, compileWhen } from './sandbox';

describe('createWhenEvaluator', () => {
  it('evaluates a boolean condition over current', () => {
    const evalWhen = createWhenEvaluator();
    expect(evalWhen('current.active === true', { current: { active: true }, raw: {} })).toBe(true);
    expect(evalWhen('current.active === true', { current: { active: false }, raw: {} })).toBe(false);
  });

  it('coerces a truthy non-boolean result to boolean', () => {
    const evalWhen = createWhenEvaluator();
    expect(evalWhen('current.count', { current: { count: 5 }, raw: {} })).toBe(true);
    expect(evalWhen('current.count', { current: { count: 0 }, raw: {} })).toBe(false);
  });

  it('exposes raw as well as current', () => {
    const evalWhen = createWhenEvaluator();
    expect(evalWhen('raw.status === "x"', { current: {}, raw: { status: 'x' } })).toBe(true);
  });

  it('memoizes the compiled function per expression (same ref reused)', () => {
    const evalWhen = createWhenEvaluator();
    // Two evaluations of the same expr must not throw and must be consistent;
    // memoization is observable via no recompile cost — assert behavior stability.
    expect(evalWhen('current.n > 1', { current: { n: 2 }, raw: {} })).toBe(true);
    expect(evalWhen('current.n > 1', { current: { n: 0 }, raw: {} })).toBe(false);
  });

  it('shadows dangerous globals (fetch is undefined inside the expression)', () => {
    const evalWhen = createWhenEvaluator();
    expect(evalWhen('typeof fetch === "undefined"', { current: {}, raw: {} })).toBe(true);
  });

  it('throws a 400 IntegrationError on an uncompilable expression (via compileWhen)', () => {
    expect(() => compileWhen('current.')).toThrow(); // syntax error
  });
});
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd eldrin-integration && npx vitest run src/flow/sandbox.test.ts`
Expected: FAIL — `createWhenEvaluator`/`compileWhen` not exported.

- [ ] **Step 4: Implement in `src/flow/sandbox.ts`**

Add the import update + the two functions (reusing `SHADOWED`/`freeze`):
```ts
import type { SnippetInput, WhenInput } from './types';

export function compileWhen(expr: string): (input: WhenInput) => boolean {
  let fn: (...a: unknown[]) => unknown;
  try {
    // eslint-disable-next-line no-new-func
    fn = new Function('current', 'raw', ...SHADOWED, `"use strict"; return (${expr});`) as (...a: unknown[]) => unknown;
  } catch (e) {
    throw new IntegrationError(`when expression failed to compile: ${e instanceof Error ? e.message : String(e)}`, 400);
  }
  const undefinedTail = SHADOWED.map(() => undefined);
  return (input: WhenInput) => !!fn(freeze(input.current), freeze(input.raw), ...undefinedTail);
}

export function createWhenEvaluator(): (expr: string, input: WhenInput) => boolean {
  const cache = new Map<string, (input: WhenInput) => boolean>();
  return (expr: string, input: WhenInput) => {
    let compiled = cache.get(expr);
    if (!compiled) {
      compiled = compileWhen(expr);
      cache.set(expr, compiled);
    }
    return compiled(input);
  };
}
```
(Update the existing `import type { SnippetInput } from './types';` line to also import `WhenInput`.)

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd eldrin-integration && npx vitest run src/flow/sandbox.test.ts`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd eldrin-integration
git add src/flow/sandbox.ts src/flow/types.ts src/flow/sandbox.test.ts
git commit -m "feat(flow): add memoized boolean when-expression evaluator"
```

---

## Task 2: `validateFlow` — relax destinations + route/when/reachability rules

**Files:**
- Modify: `src/flow/validate.ts`
- Test: `src/flow/validate.test.ts`

**Interfaces:**
- Consumes: `topoSort` (already imported); `compileWhen` from `./sandbox` (Task 1); `FlowValidationContext` (existing: `{ hooks, hookSlots?, knownTables }`).
- Produces: the relaxed `validateFlow` — same signature `validateFlow(flow: Flow, ctx: FlowValidationContext): void`, throwing `IntegrationError(…, 400)`. No signature change.

**Rules to implement:**
- Destinations: change `dests.length !== 1` → `dests.length < 1` (message: `flow requires at least one destination node`). Source check unchanged (`=== 1`).
- `knownTables`: loop over ALL destination nodes; each table must be known.
- Route/when: build a set of route node ids. For each route node, require `>= 2` outgoing edges AND each of its outgoing edges has a non-empty `when`. For each edge with a `when`, require its `from` node is a route node. Each `when` must compile (call `compileWhen(edge.when)`; let its 400 propagate, but wrap with edge context).
- Reachability: from `topoSort`'s adjacency, BFS from the source — every node must be visited (forward-reachable). Then every node must reach some destination (a node with no path to any destination is a dead-end) — compute via reverse BFS from destinations.

- [ ] **Step 1: Write the failing tests**

In `src/flow/validate.test.ts` (reuse the existing `ctx` fixture style — `{ hooks: {...}, hookSlots: new Set([...]), knownTables: new Set([...]) }`):
```ts
import { compileWhen } from './sandbox'; // ensure import path resolves; not strictly needed in test

describe('validateFlow routing', () => {
  const baseCtx = { hooks: {}, hookSlots: new Set<string>(), knownTables: new Set(['a', 'b']) };
  const src = { id: 'source', kind: 'source' as const, config: { transport: { method: 'GET', path: '/r' }, idField: 'id' } };
  const dest = (id: string, table: string) => ({ id, kind: 'destination' as const, config: { kind: 'd1' as const, table, mode: 'stored' as const } });
  const route = { id: 'route', kind: 'route' as const, config: {} };

  it('accepts a flow with two destinations (fan-out)', () => {
    const flow = {
      id: 'i:r', integrationId: 'i', trigger: { kind: 'manual' as const },
      nodes: [src, route, dest('da', 'a'), dest('db', 'b')],
      edges: [
        { from: 'source', to: 'route' },
        { from: 'route', to: 'da', when: 'current.x === 1' },
        { from: 'route', to: 'db', when: 'current.x === 2' },
      ],
    };
    expect(() => validateFlow(flow, baseCtx)).not.toThrow();
  });

  it('rejects a route node whose outgoing edge lacks a when', () => {
    const flow = {
      id: 'i:r', integrationId: 'i', trigger: { kind: 'manual' as const },
      nodes: [src, route, dest('da', 'a'), dest('db', 'b')],
      edges: [
        { from: 'source', to: 'route' },
        { from: 'route', to: 'da', when: 'current.x === 1' },
        { from: 'route', to: 'db' }, // missing when
      ],
    };
    expect(() => validateFlow(flow, baseCtx)).toThrow(/when/i);
  });

  it('rejects a when on a non-route edge', () => {
    const flow = {
      id: 'i:r', integrationId: 'i', trigger: { kind: 'manual' as const },
      nodes: [src, dest('da', 'a')],
      edges: [{ from: 'source', to: 'da', when: 'current.x === 1' }], // when on a non-route source
    };
    expect(() => validateFlow(flow, baseCtx)).toThrow(/when/i);
  });

  it('rejects an uncompilable when expression with 400', () => {
    const flow = {
      id: 'i:r', integrationId: 'i', trigger: { kind: 'manual' as const },
      nodes: [src, route, dest('da', 'a'), dest('db', 'b')],
      edges: [
        { from: 'source', to: 'route' },
        { from: 'route', to: 'da', when: 'current.' }, // syntax error
        { from: 'route', to: 'db', when: 'current.x === 2' },
      ],
    };
    expect(() => validateFlow(flow, baseCtx)).toThrow();
  });

  it('rejects an unreachable / dead-end node', () => {
    // 'orphan' transform reachable from source but reaching no destination
    const flow = {
      id: 'i:r', integrationId: 'i', trigger: { kind: 'manual' as const },
      nodes: [src, { id: 'orphan', kind: 'transform' as const, config: { mode: 'native' as const, hook: 'h' } }, dest('da', 'a')],
      edges: [{ from: 'source', to: 'da' }, { from: 'source', to: 'orphan' }], // orphan reaches no dest
    };
    const ctx = { ...baseCtx, hooks: { h: () => ({}) } };
    expect(() => validateFlow(flow, ctx)).toThrow(/reach/i);
  });

  it('rejects a route with fewer than two outgoing edges', () => {
    const flow = {
      id: 'i:r', integrationId: 'i', trigger: { kind: 'manual' as const },
      nodes: [src, route, dest('da', 'a')],
      edges: [{ from: 'source', to: 'route' }, { from: 'route', to: 'da', when: 'current.x === 1' }],
    };
    expect(() => validateFlow(flow, baseCtx)).toThrow(/route/i);
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd eldrin-integration && npx vitest run src/flow/validate.test.ts`
Expected: FAIL — fan-out rejected (current `!== 1`), route/when/reachability not enforced.

- [ ] **Step 3: Implement the relaxation + new rules**

In `src/flow/validate.ts`:
1. Add `import { compileWhen } from './sandbox';`.
2. Change the destinations check:
```ts
if (dests.length < 1) fail(`flow requires at least one destination node`);
```
3. Change the known-table check to loop all destinations:
```ts
for (const d of dests) {
  const dc = d.config as DestinationConfig;
  if (!ctx.knownTables.has(dc.table)) fail(`destination table '${dc.table}' not in known tables`);
}
```
4. Add a routing-validation block after the source/destination counts (uses `flow.edges` + a route-id set):
```ts
// Routing: route nodes + when edges
const routeIds = new Set(flow.nodes.filter((n) => n.kind === 'route').map((n) => n.id));
const outByNode = new Map<string, typeof flow.edges>();
for (const e of flow.edges) {
  if (!outByNode.has(e.from)) outByNode.set(e.from, []);
  outByNode.get(e.from)!.push(e);
}
for (const id of routeIds) {
  const outs = outByNode.get(id) ?? [];
  if (outs.length < 2) fail(`route node ${id} requires at least two outgoing edges`);
  for (const e of outs) {
    if (!e.when || e.when.trim() === '') fail(`route node ${id}: outgoing edge to ${e.to} requires a 'when' condition`);
  }
}
for (const e of flow.edges) {
  if (e.when !== undefined && e.when !== '') {
    if (!routeIds.has(e.from)) fail(`edge ${e.from} -> ${e.to}: 'when' is only allowed on edges leaving a route node`);
    compileWhen(e.when); // throws IntegrationError(400) on parse failure
  }
}
```
5. Add reachability (after `topoSort(flow)`), using forward BFS from source and reverse BFS from destinations:
```ts
// Reachability: every node reachable from source AND reaching some destination
const fwd = new Map<string, string[]>(flow.nodes.map((n) => [n.id, []]));
const rev = new Map<string, string[]>(flow.nodes.map((n) => [n.id, []]));
for (const e of flow.edges) { fwd.get(e.from)!.push(e.to); rev.get(e.to)!.push(e.from); }
const reachFrom = (start: string[], adj: Map<string, string[]>) => {
  const seen = new Set(start); const q = [...start];
  while (q.length) { const id = q.shift()!; for (const nx of adj.get(id) ?? []) if (!seen.has(nx)) { seen.add(nx); q.push(nx); } }
  return seen;
};
const fromSource = reachFrom([sources[0].id], fwd);
const toDest = reachFrom(dests.map((d) => d.id), rev);
for (const n of flow.nodes) {
  if (!fromSource.has(n.id)) fail(`node ${n.id} is not reachable from the source`);
  if (!toDest.has(n.id)) fail(`node ${n.id} does not reach any destination`);
}
```
(`sources` and `dests` are the existing arrays computed at lines 37-38.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd eldrin-integration && npx vitest run src/flow/validate.test.ts`
Expected: PASS (the new routing block + the existing validation tests).

- [ ] **Step 5: Commit**

```bash
cd eldrin-integration
git add src/flow/validate.ts src/flow/validate.test.ts
git commit -m "feat(flow): validate routing — >=1 dest, route/when rules, reachability"
```

---

## Task 3: `ExecuteResult` + `ExecuteDeps` type extensions

**Files:**
- Modify: `src/flow/types.ts`

**Interfaces:**
- Consumes: `WhenInput` (Task 1).
- Produces: `ExecuteDeps.evalWhen?`; `ExecuteResult.destinations` + `ExecuteResult.routedNowhere`. Tasks 4/5 + `sync/index.ts` consume these.

- [ ] **Step 1: Extend the types**

In `src/flow/types.ts`:
```ts
export interface ExecuteDeps {
  transport: Transport;
  db: DatabaseAdapter;
  hooks: HookRegistry;
  now: () => number;
  genId: () => string;
  evalSnippet?: (code: string, input: SnippetInput) => unknown;
  evalWhen?: (expr: string, input: WhenInput) => boolean;
}

export interface ExecuteResult {
  flowId: string;
  recordsIn: number;
  recordsOut: number;
  errors: { nodeId: string; remoteId?: string; message: string }[];
  destinations: Record<string, { table: string; recordsOut: number }>;
  routedNowhere: number;
}
```

- [ ] **Step 2: Typecheck to surface the now-required fields**

Run: `cd eldrin-integration && npx tsc -b --noEmit`
Expected: FAIL — `execute.ts` returns an `ExecuteResult` without the two new required fields. (That's expected; Task 4 fills them. Confirm the ONLY errors are in `execute.ts`'s return; if other files error on the new required fields, note them — only the executor constructs `ExecuteResult`.)

- [ ] **Step 3: Commit**

```bash
cd eldrin-integration
git add src/flow/types.ts
git commit -m "feat(flow): extend ExecuteDeps/ExecuteResult for routing (evalWhen, destinations, routedNowhere)"
```

(Commit even though tsc fails — this type-only task is intentionally completed by Task 4. The reviewer is told to expect the transient tsc error scoped to `execute.ts`.)

---

## Task 4: Executor rewrite — per-row DAG walk + multi-sink

**Files:**
- Modify: `src/flow/execute.ts`
- Test: `src/flow/execute.test.ts` (regression only in this task — see Step 5)

**Interfaces:**
- Consumes: `topoSort`, `flushBatch`, `BUILTINS`, the existing stage logic; `ExecuteDeps.evalWhen` + the new `ExecuteResult` fields (Task 3); `WhenInput` (Task 1).
- Produces: the rewritten `executeFlow(flow, deps): Promise<ExecuteResult>` — same signature, now branching-capable, returning the populated `destinations` + `routedNowhere`.

**The rewrite (replace lines ~17-149).** Keep: `topoSort` (build adjacency + node lookup from it / from edges), the hook pre-validation, `collectError`, the source generator, the per-node stage BODIES (map/transform/filter), `flushBatch`/`BATCH_SIZE`. Replace: the `NotImplementedError` route/when guards (remove), the linear `for (const node of middle) stream = …` pipe, and the single sink.

**Algorithm:**
```ts
export async function executeFlow(flow: Flow, deps: ExecuteDeps): Promise<ExecuteResult> {
  topoSort(flow); // structural validation (cycle/unknown-node) before any I/O

  // hook pre-validation (unchanged) — keep the existing loop over transform/filter native hooks

  const byId = new Map(flow.nodes.map((n) => [n.id, n]));
  const outByNode = new Map<string, Flow['edges']>();
  for (const e of flow.edges) {
    if (!outByNode.has(e.from)) outByNode.set(e.from, []);
    outByNode.get(e.from)!.push(e);
  }

  const errors: ExecuteResult['errors'] = [];
  const collectError = (nodeId, remoteId, e) => errors.push({ nodeId, remoteId, message: e instanceof Error ? e.message : String(e) });
  const counters = { recordsIn: 0 };
  let routedNowhere = 0;

  const sourceNode = flow.nodes.find((n) => n.kind === 'source')!;
  const ts = deps.now();

  // One batched sink per destination node.
  const sinks = new Map<string, { table: string; buffer: Row[]; recordsOut: number }>();
  for (const n of flow.nodes) if (n.kind === 'destination') {
    sinks.set(n.id, { table: (n.config as DestinationConfig).table, buffer: [], recordsOut: 0 });
  }
  const flushSink = async (destId: string) => {
    const sink = sinks.get(destId)!;
    if (sink.buffer.length === 0) return;
    const batch = sink.buffer; sink.buffer = [];
    try { await flushBatch(deps.db, sink.table, batch, deps.genId, ts); sink.recordsOut += batch.length; }
    catch (e) { for (const row of batch) collectError(destId, row.remoteId, e); }
  };

  // Apply a single non-route node to one row → 0-or-1 row (faithful refactor of the
  // current generator bodies from yield-form to return-form). Throws propagate to walk().
  function applyNode(node: FlowNode, row: Row): Row | null {
    if (node.kind === 'map') {
      const cfg = node.config as MapConfig;
      const current: Record<string, unknown> = {};
      for (const conn of cfg.connections) {
        const resolved = conn.sources.map((sname) => row.current[sname]);
        let value: unknown;
        if (!conn.transform) {
          value = resolved[0] === undefined ? null : resolved[0];
        } else if (conn.transform.kind === 'builtin') {
          const fn = BUILTINS[conn.transform.fn];
          if (!fn) throw new IntegrationError(`unknown builtin: ${conn.transform.fn}`, 400);
          value = fn(resolved, conn.transform.args ?? []);
        } else {
          if (!deps.evalSnippet) throw new NotImplementedError('snippet transforms require the sandbox');
          value = deps.evalSnippet(conn.transform.code, { sources: resolved, row: row.current, raw: row.raw });
        }
        current[conn.target] = value;
      }
      return { ...row, current };
    }
    if (node.kind === 'transform') {
      const cfg = node.config as TransformConfig;
      if (cfg.mode === 'snippet') {
        if (!deps.evalSnippet) throw new NotImplementedError('snippet transforms require the sandbox (sub-project 2)');
        return { ...row, current: deps.evalSnippet(cfg.snippet, { sources: [], row: row.current, raw: row.raw }) as Record<string, unknown> };
      }
      const fn = deps.hooks[cfg.hook]!;
      return { ...row, current: fn(row.current, row.raw) as Record<string, unknown> };
    }
    if (node.kind === 'filter') {
      const cfg = node.config as FilterConfig;
      if (cfg.mode === 'snippet') {
        if (!deps.evalSnippet) throw new NotImplementedError('snippet filters require the sandbox (sub-project 2)');
        return deps.evalSnippet(cfg.snippet, { sources: [], row: row.current, raw: row.raw }) ? row : null;
      }
      const fn = deps.hooks[cfg.hook]!;
      return fn(row.current, row.raw) ? row : null;
    }
    return row; // unreachable for source/destination/route (handled in walk)
  }

  // Walk one row from a given node to its terminal sink (single-path invariant: no node visited twice).
  async function walk(startNodeId: string, startRow: Row): Promise<void> {
    let nodeId = startNodeId; let row: Row | null = startRow;
    while (row) {
      const node = byId.get(nodeId)!;
      if (node.kind === 'destination') {
        const sink = sinks.get(nodeId)!;
        sink.buffer.push(row);
        if (sink.buffer.length >= BATCH_SIZE) await flushSink(nodeId);
        return;
      }
      if (node.kind === 'route') {
        const outs = outByNode.get(nodeId) ?? [];
        let matched: string | null = null;
        for (const e of outs) {
          try {
            if (deps.evalWhen!(e.when!, { current: row.current, raw: row.raw })) { matched = e.to; break; }
          } catch (err) { collectError(nodeId, row.remoteId, err); matched = null; break; }
        }
        if (matched === null) { routedNowhere++; return; }
        nodeId = matched; continue;
      }
      // transform / map / filter
      try { row = applyNode(node, row); }
      catch (e) {
        if (e instanceof NotImplementedError || e instanceof IntegrationError) throw e;
        collectError(node.id, row.remoteId, e); return; // non-structural → drop
      }
      if (!row) return; // filter dropped it
      const outs = outByNode.get(nodeId) ?? [];
      if (outs.length === 0) return; // shouldn't happen (validated reachability), defensive
      nodeId = outs[0].to; // non-route nodes have exactly one outgoing edge
    }
  }

  // Source generator (unchanged), then walk each row to completion before pulling the next (source-order per sink).
  for await (const row of sourceStage()) { counters.recordsIn++; await walk(firstAfterSource, row); }
  for (const destId of sinks.keys()) await flushSink(destId);

  const destinations: ExecuteResult['destinations'] = {};
  let recordsOut = 0;
  for (const [id, s] of sinks) { destinations[id] = { table: s.table, recordsOut: s.recordsOut }; recordsOut += s.recordsOut; }
  return { flowId: flow.id, recordsIn: counters.recordsIn, recordsOut, errors, destinations, routedNowhere };
}
```
Notes for the implementer:
- `firstAfterSource` = the single `outByNode.get(sourceNode.id)![0].to` (source has exactly one outgoing edge; validated).
- The source generator (`sourceStage`) body is UNCHANGED — lift it verbatim from the current file; in the loop, increment `counters.recordsIn` exactly as today (the current code increments inside `sourceStage`; keep it there and don't double-count — pick ONE location and match the current semantics, which counts every row yielded by the source).
- `applyNode` is a faithful refactor of the current generator bodies: the `map` body (lines 67-91), the `transform` body (92-100), the `filter` body (101-109). Move the per-row `try/catch` into `walk` (as shown) so non-structural errors drop the row and structural errors (`NotImplementedError`/`IntegrationError`) rethrow — matching today's behavior.
- Remove the `NotImplementedError` guards for `when` edges (old lines 17-21).
- Keep the `dcfg.ordered === false` NotImplementedError guard semantics per-destination (if any destination has `ordered: false`, throw — reserved), checked when building sinks.

- [ ] **Step 1: (no new test yet — regression-first) Run the EXISTING suite to capture the baseline**

Run: `cd eldrin-integration && npx vitest run src/flow/execute.test.ts`
Expected: the two route/when tests (lines 186-199) currently PASS (asserting NotImplementedError). After the rewrite they will FAIL (routing now works) — Task 5 replaces them. All OTHER tests (linear flows, map, transform, filter, ordering, D1 batching) MUST stay green through the rewrite.

- [ ] **Step 2: Perform the rewrite**

Apply the algorithm above to `src/flow/execute.ts`. Preserve every non-routing behavior.

- [ ] **Step 3: Run the existing suite minus the two route tests**

Run: `cd eldrin-integration && npx vitest run src/flow/execute.test.ts -t "linear|map|transform|filter|order|batch|destination"` (or run the full file and confirm only the two route NotImplementedError tests fail)
Expected: every non-route test PASSES. The two route/when NotImplementedError tests now FAIL (routing implemented) — that's expected and fixed in Task 5.

- [ ] **Step 4: Typecheck**

Run: `cd eldrin-integration && npx tsc -b --noEmit`
Expected: clean (the `ExecuteResult` now returns `destinations` + `routedNowhere`, resolving Task 3's transient error).

- [ ] **Step 5: Commit**

```bash
cd eldrin-integration
git add src/flow/execute.ts
git commit -m "feat(flow): rewrite executor as per-row branching DAG walk with multi-sink"
```

---

## Task 5: Wire `evalWhen` into deps + end-to-end routing tests

**Files:**
- Modify: `src/sync/index.ts` (thread `evalWhen`)
- Modify: `src/host/create-worker.ts` (construct `createWhenEvaluator`, add to `buildDeps`)
- Modify: `src/index.ts` (export `createWhenEvaluator` if needed by host)
- Test: `src/flow/execute.test.ts` (replace the two route tests + add routing tests)

**Interfaces:**
- Consumes: `createWhenEvaluator` (Task 1), the rewritten executor (Task 4), `evalWhen` dep (Task 3).
- Produces: a fully wired routing path; `executeFlow` invoked with `evalWhen` in production.

- [ ] **Step 1: Replace the two route/when NotImplementedError tests with passing routing tests**

In `src/flow/execute.test.ts`, DELETE the test at lines 186-199 (`'throws NotImplementedError for a conditional route edge'`) and the snippet-route NotImplementedError test if present, and add (reuse `dbSpy()`; every routing test passes `evalWhen: createWhenEvaluator()` in deps):
```ts
import { createWhenEvaluator } from './sandbox';

describe('executeFlow routing', () => {
  const src = { id: 'source', kind: 'source' as const, config: { transport: { method: 'GET', path: '/r' }, idField: 'id' } };
  const route = { id: 'route', kind: 'route' as const, config: {} };
  const dest = (id: string, table: string) => ({ id, kind: 'destination' as const, config: { kind: 'd1' as const, table, mode: 'stored' as const } });
  const baseDeps = (db) => ({ transport: { fetchAll: async () => [{ id: 1, x: 1 }, { id: 2, x: 2 }, { id: 3, x: 9 }] }, db, hooks: {}, now: () => 1, genId: () => 'g', evalWhen: createWhenEvaluator() });

  it('fans out to two destinations by first-match when', async () => {
    const { db, writes } = dbSpy(); // assume dbSpy exposes captured writes per table; adapt to the real helper
    const flow = {
      id: 'i:r', integrationId: 'i', trigger: { kind: 'manual' as const },
      nodes: [src, route, dest('da', 'a'), dest('db', 'b')],
      edges: [
        { from: 'source', to: 'route' },
        { from: 'route', to: 'da', when: 'current.x === 1' },
        { from: 'route', to: 'db', when: 'current.x === 2' },
      ],
    };
    const r = await executeFlow(flow, baseDeps(db));
    expect(r.destinations.da.recordsOut).toBe(1); // x===1
    expect(r.destinations.db.recordsOut).toBe(1); // x===2
    expect(r.routedNowhere).toBe(1);              // x===9 matched nothing
    expect(r.recordsOut).toBe(2);
  });

  it('reconverges two branches to one destination', async () => {
    const { db } = dbSpy();
    const mapNode = (id: string) => ({ id, kind: 'map' as const, config: { connections: [{ target: 'x', sources: ['x'] }] } });
    const flow = {
      id: 'i:r', integrationId: 'i', trigger: { kind: 'manual' as const },
      nodes: [src, route, mapNode('mx'), mapNode('my'), dest('d', 'a')],
      edges: [
        { from: 'source', to: 'route' },
        { from: 'route', to: 'mx', when: 'current.x === 1' },
        { from: 'route', to: 'my', when: 'current.x === 2' },
        { from: 'mx', to: 'd' },
        { from: 'my', to: 'd' },
      ],
    };
    const r = await executeFlow(flow, baseDeps(db));
    expect(r.destinations.d.recordsOut).toBe(2); // x:1 via mx, x:2 via my, both → d
    expect(r.routedNowhere).toBe(1);
  });

  it('drops a row when a when throws at runtime, flow continues', async () => {
    const { db } = dbSpy();
    const flow = {
      id: 'i:r', integrationId: 'i', trigger: { kind: 'manual' as const },
      nodes: [src, route, dest('da', 'a'), dest('db', 'b')],
      edges: [
        { from: 'source', to: 'route' },
        { from: 'route', to: 'da', when: 'current.missing.deep === 1' }, // throws on x where missing is undefined
        { from: 'route', to: 'db', when: 'current.x === 2' },
      ],
    };
    const r = await executeFlow(flow, baseDeps(db));
    // first edge throws → collectError + that row drops from the branch; second edge never evaluated for that row
    expect(r.errors.length).toBeGreaterThan(0);
  });
});
```
(Adapt `dbSpy`'s capture API to the real helper — read the top of `execute.test.ts` for how writes are asserted today; the assertions above describe intent, match them to the helper's actual surface.)

- [ ] **Step 2: Run to verify the new tests fail without wiring (they should already pass against Task 4's executor since deps carry evalWhen)**

Run: `cd eldrin-integration && npx vitest run src/flow/execute.test.ts`
Expected: the new routing tests PASS (Task 4's executor handles them, deps include `evalWhen`). If a test fails because `evalWhen` is undefined in deps, that's the wiring gap Step 3 fixes for production — the tests pass their own `evalWhen`.

- [ ] **Step 3: Wire `evalWhen` into the production deps**

In `src/sync/index.ts` (the `executeFlow` call ~line 46-53), add `evalWhen: deps.evalWhen,` to the deps object. In `src/flow/types.ts`'s `SyncDeps` (if `evalSnippet` is on it, add `evalWhen?` alongside — check the SyncDeps shape and mirror evalSnippet exactly). In `src/host/create-worker.ts`: after `const evalSnippet = createSnippetEvaluator();` (line ~86) add `const evalWhen = createWhenEvaluator();` (import it from the flow barrel/sandbox), and add `evalWhen` to the `buildDeps` return (line ~96) next to `evalSnippet`.

- [ ] **Step 4: Export if needed + typecheck + full suite**

If `create-worker.ts` imports `createWhenEvaluator` from `../index` or `../flow/sandbox`, ensure the path resolves; add an export to `src/index.ts` mirroring `createSnippetEvaluator` if that's the established import path.
Run: `cd eldrin-integration && npx tsc -b --noEmit && npx vitest run`
Expected: tsc clean; full suite PASS (was 228; now 228 + the new sandbox/validate/execute routing tests, minus the 2 deleted NotImplementedError tests).

- [ ] **Step 5: Commit**

```bash
cd eldrin-integration
git add src/sync/index.ts src/host/create-worker.ts src/index.ts src/flow/types.ts src/flow/execute.test.ts
git commit -m "feat(flow): wire evalWhen into deps; end-to-end routing tests"
```

---

## After all tasks

- Final whole-branch review (most-capable model) of the SDK diff — focus on the executor rewrite preserving non-branching behavior, the single-path invariant holding, the `when` sandbox reuse, and the validation rules.
- Then `superpowers:finishing-a-development-branch` (single repo, eldrin-integration).
- No live-verify drag/UI step (SDK-only, no UI in SP6) — but DO rebuild the SDK dist (`npm run build`) so the routing engine is available to dependents, per the SP5 stale-dist lesson. A focused live check: seed a branching flow via `/api/flows` and run a sync, confirming rows route to the right tables (optional, since there's no UI to draw one yet — SP8).
