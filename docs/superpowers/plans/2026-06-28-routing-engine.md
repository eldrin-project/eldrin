# Routing Engine Implementation Plan (SP6)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the SDK executor + validator support `route` nodes with conditional `when` edges and branching to N destinations — a CPI content-based router runnable on the existing host, with no UI.

**Architecture:** Reuse the SP2 sandbox for a memoized boolean `when` evaluator. Relax `validateFlow` (destinations ≥1; route nodes need ≥2 conditioned outgoing edges; `when` only on route edges + compiles; reachability). Decompose the executor into focused `src/flow/exec/` modules — `stages.ts` (per-row map/transform/filter), `router.ts` (first-match `when`), `sink.ts` (per-destination batched buffers), `walk.ts` (per-row DAG walk) — with `execute.ts` a thin orchestrator. The walk follows the single-path invariant (each row takes exactly one path, visits no node twice), branching to one batched sink per destination with source-order preserved per sink.

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
- **Lightweight components, not monoliths:** the executor is split into `src/flow/exec/` single-responsibility modules (`stages.ts`, `router.ts`, `sink.ts`, `walk.ts`), each ~40-90 lines with its own test file; `execute.ts` becomes a thin orchestrator. Do NOT build one large `execute.ts`. Mirrors the existing `src/flow/transformers/` folder.
- Immutability; no `console.log`; conventional commits, attribution disabled. Coverage ≥ 80%. Tests: `cd eldrin-integration && npx vitest run`.

---

## File Structure

**Component decomposition (CRITICAL — many small focused files, NOT a monolithic `execute.ts`):** the executor is split into a `src/flow/exec/` folder of single-responsibility modules (~40-90 lines each), mirroring the existing `src/flow/transformers/` folder pattern. `execute.ts` becomes a thin orchestrator. Each module has its own focused test file. This is a hard requirement of this plan — do not collapse these back into one file.

- `src/flow/sandbox.ts` (modify) — add `compileWhen` + `createWhenEvaluator` (boolean evaluator, `{current, raw}` surface) beside the existing snippet evaluator. (Stays here — small; it's the sandbox's natural home next to `compileSnippet`.)
- `src/flow/sandbox.test.ts` (modify, or create if absent) — `when`-evaluator unit tests.
- `src/flow/types.ts` (modify) — add `WhenInput`; add `evalWhen?` to `ExecuteDeps`; extend `ExecuteResult` with `destinations` + `routedNowhere`.
- `src/flow/validate.ts` (modify) — destinations ≥1; route/when/reachability rules; compile each `when`.
- `src/flow/validate.test.ts` (modify) — the new validation cases.
- **`src/flow/exec/stages.ts` (new)** — `applyNode(node, row, deps): Row | null` — the map/transform/filter per-row stage bodies (refactored from `execute.ts`'s generator bodies). One responsibility: apply a single non-route/non-sink node to one row.
- **`src/flow/exec/stages.test.ts` (new)** — unit tests for `applyNode` (map projects connections; transform applies hook/snippet; filter keeps/drops; builtin/snippet error propagation).
- **`src/flow/exec/router.ts` (new)** — `selectBranch(routeNode, outgoingEdges, row, deps): { to: string } | { droppedError: unknown } | null` — first-match `when` evaluation for a route node. Returns the matched edge target, a runtime-error signal, or null (no match). One responsibility: route decision.
- **`src/flow/exec/router.test.ts` (new)** — first-match order; no-match → null; `when`-throws → error signal.
- **`src/flow/exec/sink.ts` (new)** — `createSinks(nodes, deps, ts, collectError)` returning a `Map<destId, Sink>` plus `push(destId, row)` and `flush(destId)`/`flushAll()` — the per-destination batched buffer + ordered `flushBatch`. One responsibility: destination sinks.
- **`src/flow/exec/sink.test.ts` (new)** — buffers to BATCH_SIZE then flushes; ordered per sink; flush error → collectError per row.
- **`src/flow/exec/walk.ts` (new)** — `walkRow(startNodeId, row, graph, deps, sinks, collectError, counters): Promise<void>` — the per-row DAG walk tying stages + router + sinks together under the single-path invariant. One responsibility: advance one row source→sink.
- **`src/flow/exec/walk.test.ts` (new)** — reconverge, fan-out, single-path (no node visited twice), drop on filter/route-no-match.
- `src/flow/execute.ts` (modify → thin orchestrator, ~40 lines) — `topoSort` validation, hook pre-validation, build adjacency (`graph`), build sinks, run the source generator, `walkRow` each row, flush all sinks, assemble `ExecuteResult`. Imports from `exec/`. Removes the route/when `NotImplementedError` guards.
- `src/flow/execute.test.ts` (modify) — keep as the END-TO-END / regression suite: the existing linear/map/transform/filter/order/batch tests stay (regression gate); replace the two route/when NotImplementedError tests with end-to-end routing tests (reconverge/fan-out/first-match/no-match/`routedNowhere`/per-destination result). Component-level edge cases live in the per-module tests above.
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
Expected: FAIL — `execute.ts` returns an `ExecuteResult` without the two new required fields. (That's expected; Task 4e fills them. Confirm the ONLY errors are in `execute.ts`'s return; if other files error on the new required fields, note them — only the executor constructs `ExecuteResult`.)

- [ ] **Step 3: Commit**

```bash
cd eldrin-integration
git add src/flow/types.ts
git commit -m "feat(flow): extend ExecuteDeps/ExecuteResult for routing (evalWhen, destinations, routedNowhere)"
```

(Commit even though tsc fails — this type-only task is intentionally completed by Task 4e. The reviewer is told to expect the transient tsc error scoped to `execute.ts`. Note: Tasks 4a-4d create NEW `exec/` modules that don't construct `ExecuteResult`, so they typecheck clean independently; only `execute.ts` carries the transient error until 4e.)

---

## Task 4a: `exec/stages.ts` — per-row stage bodies (`applyNode`)

**Files:**
- Create: `src/flow/exec/stages.ts`
- Test: `src/flow/exec/stages.test.ts`

**Interfaces:**
- Consumes: `BUILTINS` from `../transformers`; `IntegrationError`, `NotImplementedError` from `../../errors`; `Row, FlowNode, MapConfig, TransformConfig, FilterConfig, ExecuteDeps` from `../types`.
- Produces: `applyNode(node: FlowNode, row: Row, deps: ExecuteDeps): Row | null` — applies one map/transform/filter node to one row; returns the new row, or `null` if a filter drops it. Throws on builtin/snippet/hook errors (caller decides drop-vs-abort). Consumed by `walk.ts` (Task 4d).

- [ ] **Step 1: Write the failing tests**

```ts
import { describe, it, expect } from 'vitest';
import { applyNode } from './stages';
import type { Row, FlowNode, ExecuteDeps } from '../types';

const row = (current: Record<string, unknown>): Row => ({ remoteId: '1', raw: { ...current }, current });
const deps = (over: Partial<ExecuteDeps> = {}): ExecuteDeps =>
  ({ transport: { fetchAll: async () => [] }, db: {} as any, hooks: {}, now: () => 1, genId: () => 'g', ...over });

describe('applyNode', () => {
  it('map: projects connections (passthrough + builtin)', () => {
    const node: FlowNode = { id: 'm', kind: 'map', config: { connections: [
      { target: 'a', sources: ['x'] },
      { target: 'b', sources: ['x', 'y'], transform: { kind: 'builtin', fn: 'concat', args: ['-'] } },
    ] } };
    const out = applyNode(node, row({ x: 'P', y: 'Q' }), deps());
    expect(out!.current).toEqual({ a: 'P', b: 'P-Q' });
  });

  it('map: missing source → null (passthrough)', () => {
    const node: FlowNode = { id: 'm', kind: 'map', config: { connections: [{ target: 'a', sources: ['missing'] }] } };
    expect(applyNode(node, row({ x: 1 }), deps()).current).toEqual({ a: null });
  });

  it('transform native hook replaces current', () => {
    const node: FlowNode = { id: 't', kind: 'transform', config: { mode: 'native', hook: 'h' } };
    const out = applyNode(node, row({ n: 1 }), deps({ hooks: { h: (c: any) => ({ n: c.n + 1 }) } }));
    expect(out!.current).toEqual({ n: 2 });
  });

  it('filter native hook keeps or drops', () => {
    const node: FlowNode = { id: 'f', kind: 'filter', config: { mode: 'native', hook: 'keep' } };
    const d = deps({ hooks: { keep: (c: any) => c.ok === true } });
    expect(applyNode(node, row({ ok: true }), d)).not.toBeNull();
    expect(applyNode(node, row({ ok: false }), d)).toBeNull();
  });

  it('map: unknown builtin throws IntegrationError', () => {
    const node: FlowNode = { id: 'm', kind: 'map', config: { connections: [{ target: 'a', sources: ['x'], transform: { kind: 'builtin', fn: 'nope' } }] } };
    expect(() => applyNode(node, row({ x: 1 }), deps())).toThrow();
  });
});
```

- [ ] **Step 2: Run to verify fail**

Run: `cd eldrin-integration && npx vitest run src/flow/exec/stages.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `src/flow/exec/stages.ts`**

```ts
import { IntegrationError, NotImplementedError } from '../../errors';
import { BUILTINS } from '../transformers';
import type { Row, FlowNode, MapConfig, TransformConfig, FilterConfig, ExecuteDeps } from '../types';

/** Apply one map/transform/filter node to a single row. Returns the new row, or null if a filter drops it.
 *  Throws on builtin/snippet/hook faults — the caller (walk) decides drop-vs-abort. */
export function applyNode(node: FlowNode, row: Row, deps: ExecuteDeps): Row | null {
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
```

- [ ] **Step 4: Run to verify pass**

Run: `cd eldrin-integration && npx vitest run src/flow/exec/stages.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd eldrin-integration
git add src/flow/exec/stages.ts src/flow/exec/stages.test.ts
git commit -m "feat(flow): add exec/stages applyNode (map/transform/filter per-row)"
```

---

## Task 4b: `exec/router.ts` — first-match route decision

**Files:**
- Create: `src/flow/exec/router.ts`
- Test: `src/flow/exec/router.test.ts`

**Interfaces:**
- Consumes: `Row, FlowEdge, ExecuteDeps` from `../types`.
- Produces: `selectBranch(outgoing: FlowEdge[], row: Row, deps: ExecuteDeps): RouteResult` where `type RouteResult = { kind: 'matched'; to: string } | { kind: 'error'; error: unknown } | { kind: 'none' }`. First-match over `outgoing` (declared order); `when` throw → `{kind:'error'}` (stop evaluating further edges); no match → `{kind:'none'}`. Consumed by `walk.ts` (Task 4d). Export `RouteResult`.

- [ ] **Step 1: Write the failing tests**

```ts
import { describe, it, expect } from 'vitest';
import { selectBranch } from './router';
import { createWhenEvaluator } from '../sandbox';
import type { Row, FlowEdge, ExecuteDeps } from '../types';

const row = (current: Record<string, unknown>): Row => ({ remoteId: '1', raw: {}, current });
const deps = (): ExecuteDeps => ({ transport: { fetchAll: async () => [] }, db: {} as any, hooks: {}, now: () => 1, genId: () => 'g', evalWhen: createWhenEvaluator() });
const edges = (...es: FlowEdge[]) => es;

describe('selectBranch', () => {
  it('returns the first matching edge (declared order)', () => {
    const r = selectBranch(edges(
      { from: 'r', to: 'a', when: 'current.x === 1' },
      { from: 'r', to: 'b', when: 'current.x >= 1' }, // also matches, but second
    ), row({ x: 1 }), deps());
    expect(r).toEqual({ kind: 'matched', to: 'a' });
  });

  it('returns none when no edge matches', () => {
    const r = selectBranch(edges({ from: 'r', to: 'a', when: 'current.x === 9' }), row({ x: 1 }), deps());
    expect(r).toEqual({ kind: 'none' });
  });

  it('returns error when a when throws (stops there)', () => {
    const r = selectBranch(edges({ from: 'r', to: 'a', when: 'current.missing.deep === 1' }), row({ x: 1 }), deps());
    expect(r.kind).toBe('error');
  });
});
```

- [ ] **Step 2: Run to verify fail**

Run: `cd eldrin-integration && npx vitest run src/flow/exec/router.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `src/flow/exec/router.ts`**

```ts
import type { Row, FlowEdge, ExecuteDeps } from '../types';

export type RouteResult = { kind: 'matched'; to: string } | { kind: 'error'; error: unknown } | { kind: 'none' };

/** First-match content router: evaluate each outgoing edge's `when` in declared order;
 *  return the first match, or an error signal if a `when` throws, or none if nothing matched. */
export function selectBranch(outgoing: FlowEdge[], row: Row, deps: ExecuteDeps): RouteResult {
  for (const e of outgoing) {
    try {
      if (deps.evalWhen!(e.when!, { current: row.current, raw: row.raw })) return { kind: 'matched', to: e.to };
    } catch (error) {
      return { kind: 'error', error };
    }
  }
  return { kind: 'none' };
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd eldrin-integration && npx vitest run src/flow/exec/router.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd eldrin-integration
git add src/flow/exec/router.ts src/flow/exec/router.test.ts
git commit -m "feat(flow): add exec/router first-match branch selection"
```

---

## Task 4c: `exec/sink.ts` — per-destination batched sinks

**Files:**
- Create: `src/flow/exec/sink.ts`
- Test: `src/flow/exec/sink.test.ts`

**Interfaces:**
- Consumes: `flushBatch` from `../batch`; `Row, FlowNode, DestinationConfig, ExecuteDeps` from `../types`; `NotImplementedError` from `../../errors`.
- Produces: `createSinks(nodes: FlowNode[], deps: ExecuteDeps, ts: number, collectError: (nodeId: string, remoteId: string | undefined, e: unknown) => void): Sinks` where `Sinks = { ids(): string[]; push(destId, row): Promise<void>; flush(destId): Promise<void>; flushAll(): Promise<void>; recordsOutByDest(): Record<string, { table: string; recordsOut: number }> }`. `push` buffers and flushes at `BATCH_SIZE`. Throws `NotImplementedError` at construction if any destination has `ordered: false` (reserved). `BATCH_SIZE = 100` lives here (the flush cadence constant moves with the sink). Consumed by `walk.ts` (4d) + `execute.ts` (4e). Export `Sinks`, `BATCH_SIZE`.

- [ ] **Step 1: Write the failing tests**

```ts
import { describe, it, expect, vi } from 'vitest';
import { createSinks, BATCH_SIZE } from './sink';
import type { FlowNode, Row, ExecuteDeps } from '../types';

const dest = (id: string, table: string, extra = {}): FlowNode => ({ id, kind: 'destination', config: { kind: 'd1', table, mode: 'stored', ...extra } });
const row = (rid: string): Row => ({ remoteId: rid, raw: {}, current: {} });

function deps(): { deps: ExecuteDeps; flushed: Row[][] } {
  const flushed: Row[][] = [];
  const db = {} as any;
  const d: ExecuteDeps = { transport: { fetchAll: async () => [] }, db, hooks: {}, now: () => 1, genId: () => 'g' };
  return { deps: d, flushed };
}

describe('createSinks', () => {
  it('buffers then flushes at BATCH_SIZE, preserving order, counting recordsOut', async () => {
    // Spy flushBatch via the db: createSinks calls flushBatch(db, table, batch, genId, ts).
    // Use a real db spy that records batches; assert ordering + counts.
    const flushedTables: { table: string; ids: string[] }[] = [];
    const db = { prepare: () => ({ bind: () => ({ run: async () => ({}) }) }) } as any;
    // Easiest: stub flushBatch by injecting through module mock OR assert via recordsOut.
    const errors: any[] = [];
    const sinks = createSinks([dest('d', 't')], { ...deps().deps, db }, 1, (id, r, e) => errors.push({ id, e }));
    for (let i = 0; i < BATCH_SIZE + 5; i++) await sinks.push('d', row(String(i)));
    await sinks.flushAll();
    expect(sinks.recordsOutByDest().d.recordsOut).toBe(BATCH_SIZE + 5);
    expect(sinks.recordsOutByDest().d.table).toBe('t');
  });

  it('throws NotImplementedError for an ordered:false destination', () => {
    expect(() => createSinks([dest('d', 't', { ordered: false })], deps().deps, 1, () => {})).toThrow();
  });

  it('records a flush error per row via collectError', async () => {
    const db = { prepare: () => { throw new Error('DB down'); } } as any;
    const errs: any[] = [];
    const sinks = createSinks([dest('d', 't')], { ...deps().deps, db }, 1, (id, r, e) => errs.push({ id, r, e }));
    await sinks.push('d', row('1'));
    await sinks.flushAll();
    expect(errs.length).toBe(1);
    expect(errs[0].id).toBe('d');
  });
});
```
(Note for implementer: if asserting `flushBatch` behavior is awkward without a DB, use `vi.mock('../batch', …)` to stub `flushBatch` and assert it's called with `(db, table, batch, genId, ts)` and batches preserve order. Match the real `dbSpy`/mock style used elsewhere in the suite.)

- [ ] **Step 2: Run to verify fail**

Run: `cd eldrin-integration && npx vitest run src/flow/exec/sink.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `src/flow/exec/sink.ts`**

```ts
import { flushBatch } from '../batch';
import { NotImplementedError } from '../../errors';
import type { Row, FlowNode, DestinationConfig, ExecuteDeps } from '../types';

// Flush cadence: rows buffered per destination before flushBatch. flushBatch internally
// sub-chunks each buffer to respect D1's 100-bound-parameter cap.
export const BATCH_SIZE = 100;

export interface Sinks {
  ids(): string[];
  push(destId: string, row: Row): Promise<void>;
  flush(destId: string): Promise<void>;
  flushAll(): Promise<void>;
  recordsOutByDest(): Record<string, { table: string; recordsOut: number }>;
}

interface Sink { table: string; buffer: Row[]; recordsOut: number; }

export function createSinks(
  nodes: FlowNode[],
  deps: ExecuteDeps,
  ts: number,
  collectError: (nodeId: string, remoteId: string | undefined, e: unknown) => void,
): Sinks {
  const sinks = new Map<string, Sink>();
  for (const n of nodes) {
    if (n.kind !== 'destination') continue;
    const cfg = n.config as DestinationConfig;
    if (cfg.ordered === false) throw new NotImplementedError('unordered destination flush is reserved');
    sinks.set(n.id, { table: cfg.table, buffer: [], recordsOut: 0 });
  }

  const flush = async (destId: string) => {
    const sink = sinks.get(destId)!;
    if (sink.buffer.length === 0) return;
    const batch = sink.buffer;
    sink.buffer = [];
    try {
      await flushBatch(deps.db, sink.table, batch, deps.genId, ts);
      sink.recordsOut += batch.length;
    } catch (e) {
      for (const row of batch) collectError(destId, row.remoteId, e);
    }
  };

  return {
    ids: () => [...sinks.keys()],
    push: async (destId, row) => {
      const sink = sinks.get(destId)!;
      sink.buffer.push(row);
      if (sink.buffer.length >= BATCH_SIZE) await flush(destId);
    },
    flush,
    flushAll: async () => { for (const id of sinks.keys()) await flush(id); },
    recordsOutByDest: () => {
      const out: Record<string, { table: string; recordsOut: number }> = {};
      for (const [id, s] of sinks) out[id] = { table: s.table, recordsOut: s.recordsOut };
      return out;
    },
  };
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd eldrin-integration && npx vitest run src/flow/exec/sink.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd eldrin-integration
git add src/flow/exec/sink.ts src/flow/exec/sink.test.ts
git commit -m "feat(flow): add exec/sink per-destination batched buffers"
```

---

## Task 4d: `exec/walk.ts` — per-row DAG walk

**Files:**
- Create: `src/flow/exec/walk.ts`
- Test: `src/flow/exec/walk.test.ts`

**Interfaces:**
- Consumes: `applyNode` (4a), `selectBranch` (4b), `Sinks` (4c); `Row, FlowNode, FlowEdge, ExecuteDeps` from `../types`; `IntegrationError, NotImplementedError` from `../../errors`.
- Produces: `walkRow(args): Promise<void>` where `args = { startNodeId, row, byId: Map<string, FlowNode>, outByNode: Map<string, FlowEdge[]>, deps, sinks: Sinks, collectError, onRoutedNowhere: () => void }`. Walks one row source-side→sink under the single-path invariant. Consumed by `execute.ts` (4e).

- [ ] **Step 1: Write the failing tests**

```ts
import { describe, it, expect } from 'vitest';
import { walkRow } from './walk';
import { createSinks } from './sink';
import { createWhenEvaluator } from '../sandbox';
import type { FlowNode, FlowEdge, Row, ExecuteDeps } from '../types';

function harness(nodes: FlowNode[], edges: FlowEdge[]) {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const outByNode = new Map<string, FlowEdge[]>();
  for (const e of edges) { if (!outByNode.has(e.from)) outByNode.set(e.from, []); outByNode.get(e.from)!.push(e); }
  const errors: any[] = [];
  const collectError = (id: string, r: string | undefined, e: unknown) => errors.push({ id, e });
  const deps: ExecuteDeps = { transport: { fetchAll: async () => [] }, db: { prepare: () => ({ bind: () => ({ run: async () => ({}) }) }) } as any, hooks: {}, now: () => 1, genId: () => 'g', evalWhen: createWhenEvaluator() };
  const sinks = createSinks(nodes, deps, 1, collectError);
  let routedNowhere = 0;
  const run = (row: Row, start: string) => walkRow({ startNodeId: start, row, byId, outByNode, deps, sinks, collectError, onRoutedNowhere: () => routedNowhere++ });
  return { sinks, errors, run, routed: () => routedNowhere };
}
const row = (c: Record<string, unknown>): Row => ({ remoteId: '1', raw: {}, current: c });
const route: FlowNode = { id: 'r', kind: 'route', config: {} };
const dest = (id: string, t: string): FlowNode => ({ id, kind: 'destination', config: { kind: 'd1', table: t, mode: 'stored' } });

describe('walkRow', () => {
  it('fans out by first-match to the right sink', async () => {
    const h = harness([route, dest('da', 'a'), dest('db', 'b')], [
      { from: 'r', to: 'da', when: 'current.x === 1' },
      { from: 'r', to: 'db', when: 'current.x === 2' },
    ]);
    await h.run(row({ x: 1 }), 'r'); await h.run(row({ x: 2 }), 'r'); await h.run(row({ x: 9 }), 'r');
    await h.sinks.flushAll();
    expect(h.sinks.recordsOutByDest().da.recordsOut).toBe(1);
    expect(h.sinks.recordsOutByDest().db.recordsOut).toBe(1);
    expect(h.routed()).toBe(1);
  });

  it('reconverges two branches to one destination', async () => {
    const mp = (id: string): FlowNode => ({ id, kind: 'map', config: { connections: [{ target: 'x', sources: ['x'] }] } });
    const h = harness([route, mp('mx'), mp('my'), dest('d', 'a')], [
      { from: 'r', to: 'mx', when: 'current.x === 1' },
      { from: 'r', to: 'my', when: 'current.x === 2' },
      { from: 'mx', to: 'd' }, { from: 'my', to: 'd' },
    ]);
    await h.run(row({ x: 1 }), 'r'); await h.run(row({ x: 2 }), 'r');
    await h.sinks.flushAll();
    expect(h.sinks.recordsOutByDest().d.recordsOut).toBe(2);
  });

  it('drops the row + records error when a when throws', async () => {
    const h = harness([route, dest('da', 'a'), dest('db', 'b')], [
      { from: 'r', to: 'da', when: 'current.missing.deep === 1' },
      { from: 'r', to: 'db', when: 'current.x === 2' },
    ]);
    await h.run(row({ x: 2 }), 'r');
    await h.sinks.flushAll();
    expect(h.errors.length).toBe(1);
    expect(h.sinks.recordsOutByDest().da.recordsOut).toBe(0);
  });
});
```

- [ ] **Step 2: Run to verify fail**

Run: `cd eldrin-integration && npx vitest run src/flow/exec/walk.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `src/flow/exec/walk.ts`**

```ts
import { IntegrationError, NotImplementedError } from '../../errors';
import { applyNode } from './stages';
import { selectBranch } from './router';
import type { Sinks } from './sink';
import type { Row, FlowNode, FlowEdge, ExecuteDeps } from '../types';

export interface WalkArgs {
  startNodeId: string;
  row: Row;
  byId: Map<string, FlowNode>;
  outByNode: Map<string, FlowEdge[]>;
  deps: ExecuteDeps;
  sinks: Sinks;
  collectError: (nodeId: string, remoteId: string | undefined, e: unknown) => void;
  onRoutedNowhere: () => void;
}

/** Walk a single row from startNodeId to its terminal sink. Single-path invariant:
 *  first-match routing + single outgoing edge on non-route nodes ⇒ the row takes exactly
 *  one path and visits no node twice, so the loop terminates. */
export async function walkRow(args: WalkArgs): Promise<void> {
  const { byId, outByNode, deps, sinks, collectError, onRoutedNowhere } = args;
  let nodeId = args.startNodeId;
  let row: Row | null = args.row;

  while (row) {
    const node = byId.get(nodeId)!;

    if (node.kind === 'destination') {
      await sinks.push(nodeId, row);
      return;
    }

    if (node.kind === 'route') {
      const result = selectBranch(outByNode.get(nodeId) ?? [], row, deps);
      if (result.kind === 'matched') { nodeId = result.to; continue; }
      if (result.kind === 'error') { collectError(nodeId, row.remoteId, result.error); return; }
      onRoutedNowhere(); // kind === 'none'
      return;
    }

    // transform / map / filter
    try {
      row = applyNode(node, row, deps);
    } catch (e) {
      if (e instanceof NotImplementedError || e instanceof IntegrationError) throw e; // structural → abort
      collectError(node.id, row.remoteId, e);
      return; // non-structural → drop this row
    }
    if (!row) return; // filter dropped it

    const outs = outByNode.get(nodeId) ?? [];
    if (outs.length === 0) return; // defensive (validated reachability guarantees a path)
    nodeId = outs[0].to; // non-route nodes have exactly one outgoing edge
  }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd eldrin-integration && npx vitest run src/flow/exec/walk.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd eldrin-integration
git add src/flow/exec/walk.ts src/flow/exec/walk.test.ts
git commit -m "feat(flow): add exec/walk per-row DAG walk (single-path invariant)"
```

---

## Task 4e: `execute.ts` — thin orchestrator

**Files:**
- Modify: `src/flow/execute.ts`
- Test: `src/flow/execute.test.ts` (regression gate — see Step 1)

**Interfaces:**
- Consumes: `topoSort` (`./graph`), `createSinks` (`./exec/sink`), `walkRow` (`./exec/walk`); `ExecuteDeps.evalWhen` + new `ExecuteResult` fields (Task 3).
- Produces: `executeFlow(flow, deps): Promise<ExecuteResult>` — same signature, branching-capable, returning populated `destinations` + `routedNowhere`. The body is a thin orchestrator that delegates to `exec/`.

**The rewrite.** Keep: `topoSort` (structural validation), the hook pre-validation loop, `collectError`, the source generator (`sourceStage`, lift verbatim — counts `recordsIn` exactly as today). Replace: the `NotImplementedError` route/when guards (REMOVE — old lines 17-21), the `stageFor`/linear-pipe assembly + single sink → adjacency build + `createSinks` + per-row `walkRow`. `BATCH_SIZE` now lives in `exec/sink.ts` (remove the local const).

```ts
import { IntegrationError } from '../errors';
import { topoSort } from './graph';
import { createSinks } from './exec/sink';
import { walkRow } from './exec/walk';
import type { Flow, FlowNode, FlowEdge, ExecuteDeps, ExecuteResult, Row, SourceConfig, TransformConfig, FilterConfig } from './types';

export async function executeFlow(flow: Flow, deps: ExecuteDeps): Promise<ExecuteResult> {
  topoSort(flow); // cycle / unknown-node validation before any I/O

  // Hook pre-validation (unchanged): unknown native hook names are structural errors.
  for (const node of flow.nodes) {
    if (node.kind === 'transform' || node.kind === 'filter') {
      const cfg = node.config as TransformConfig | FilterConfig;
      if (cfg && cfg.mode === 'native' && !deps.hooks[cfg.hook]) {
        throw new IntegrationError(`unknown hook: ${cfg.hook}`, 400);
      }
    }
  }

  const byId = new Map(flow.nodes.map((n) => [n.id, n]));
  const outByNode = new Map<string, FlowEdge[]>();
  for (const e of flow.edges) {
    if (!outByNode.has(e.from)) outByNode.set(e.from, []);
    outByNode.get(e.from)!.push(e);
  }

  const errors: ExecuteResult['errors'] = [];
  const collectError = (nodeId: string, remoteId: string | undefined, e: unknown) =>
    errors.push({ nodeId, remoteId, message: e instanceof Error ? e.message : String(e) });

  const ts = deps.now();
  const sinks = createSinks(flow.nodes, deps, ts, collectError);

  let recordsIn = 0;
  let routedNowhere = 0;
  const sourceNode = flow.nodes.find((n) => n.kind === 'source')!;
  const firstAfterSource = (outByNode.get(sourceNode.id) ?? [])[0]!.to;

  // --- source generator (lifted verbatim from the prior executor) ---
  async function* sourceStage(): AsyncIterable<Row> {
    const cfg = sourceNode.config as SourceConfig;
    const res = {
      name: flow.id, transport: cfg.transport, idField: cfg.idField,
      fieldMap: {}, supportedModes: ['stored'], defaultMode: 'stored',
    } as unknown as Parameters<NonNullable<ExecuteDeps['transport']['fetchStream']>>[0];
    const iter: AsyncIterable<Record<string, unknown>> = deps.transport.fetchStream
      ? deps.transport.fetchStream(res)
      : (async function* () { for (const r of await deps.transport.fetchAll(res)) yield r; })();
    for await (const raw of iter) {
      yield { remoteId: String(raw[cfg.idField]), raw, current: raw };
    }
  }

  for await (const row of sourceStage()) {
    recordsIn++;
    await walkRow({ startNodeId: firstAfterSource, row, byId, outByNode, deps, sinks, collectError, onRoutedNowhere: () => { routedNowhere++; } });
  }
  await sinks.flushAll();

  const destinations = sinks.recordsOutByDest();
  let recordsOut = 0;
  for (const id of sinks.ids()) recordsOut += destinations[id].recordsOut;

  return { flowId: flow.id, recordsIn, recordsOut, errors, destinations, routedNowhere };
}
```
(Verify the `sourceStage` body matches the current file's exactly — copy it; the only change vs. today is that `recordsIn` is incremented in the consuming loop, not inside the generator. Pick the single location that preserves today's count semantics: count every row the source yields. If today's code increments inside the generator, keep it there and drop the loop increment — do NOT double-count.)

- [ ] **Step 1: Capture the regression baseline**

Run: `cd eldrin-integration && npx vitest run src/flow/execute.test.ts`
Expected: all current tests PASS (the two route/when NotImplementedError tests still assert NotImplementedError — they'll be replaced in Task 5). Note the count.

- [ ] **Step 2: Perform the orchestrator rewrite**

Apply the above to `src/flow/execute.ts`. Delete the local `BATCH_SIZE`, `stageFor`, `applyNode`-equivalent generator bodies, the linear pipe, and the route/when guards — those now live in `exec/`.

- [ ] **Step 3: Run the existing suite — non-route tests must stay green**

Run: `cd eldrin-integration && npx vitest run src/flow/execute.test.ts`
Expected: every non-route test (linear, map, transform, filter, order, batch, destination) PASSES. The two route/when NotImplementedError tests now FAIL (routing implemented) — expected; Task 5 replaces them. If ANY non-route test fails, the rewrite changed behavior — fix before proceeding.

- [ ] **Step 4: Typecheck + full suite**

Run: `cd eldrin-integration && npx tsc -b --noEmit && npx vitest run`
Expected: tsc clean (resolves Task 3's transient `ExecuteResult` error). Full suite: only the two route/when NotImplementedError tests fail (replaced in Task 5); everything else green.

- [ ] **Step 5: Commit**

```bash
cd eldrin-integration
git add src/flow/execute.ts
git commit -m "feat(flow): make execute.ts a thin orchestrator over exec/ modules"
```

---

## Task 5: Wire `evalWhen` into deps + end-to-end routing tests

**Files:**
- Modify: `src/sync/index.ts` (thread `evalWhen`)
- Modify: `src/host/create-worker.ts` (construct `createWhenEvaluator`, add to `buildDeps`)
- Modify: `src/index.ts` (export `createWhenEvaluator` if needed by host)
- Test: `src/flow/execute.test.ts` (replace the two route tests + add routing tests)

**Interfaces:**
- Consumes: `createWhenEvaluator` (Task 1), the rewritten executor (Tasks 4a-4e), `evalWhen` dep (Task 3).
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

- [ ] **Step 2: Run to verify the new tests pass against the Task 4e executor (deps carry evalWhen)**

Run: `cd eldrin-integration && npx vitest run src/flow/execute.test.ts`
Expected: the new routing tests PASS (the Task 4e orchestrator handles them, deps include `evalWhen`). If a test fails because `evalWhen` is undefined in deps, that's the wiring gap Step 3 fixes for production — the tests pass their own `evalWhen`.

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
