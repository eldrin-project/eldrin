# Flow Graph Model & Executor — Design Spec

**Date:** 2026-06-28
**Status:** Approved for planning
**Sub-project:** 1 of 5 (CPI-style integration flow platform)
**Scope:** SDK only (`@eldrin-project/eldrin-integration`). No UI, no flow-authoring persistence.

---

## Context & Motivation

Eldrin's integration SDK currently models an integration as an `IntegrationDescriptor`
(a connection + a list of resources), executed by a **hardcoded three-stage pipeline**
in `src/sync/map.ts` (`transform` hook → `fieldMap` → `beforeUpsert` hook) followed by a
D1 upsert. This is effectively a single, fixed integration-flow shape: "poll an HTTP
source → flat-map fields → upsert one D1 table."

The end goal is a system similar to **SAP Cloud Integration (CPI)**: a studio where an
admin authors integration *flows* — sources, triggers, field mappings with transformers,
destinations, routing, and events. CPI models a flow (iflow) as a graph of typed
processing steps between a sender and a receiver. Eldrin's current model cannot express
this: the pipeline is fixed, branching is impossible, and transformations exist only as
compiled-in code hooks.

This sub-project lays the **foundation**: a graph-based flow model and a single executor
that runs it, plus a compiler that lowers the existing descriptor into the new model so
the live Factorial integration keeps working unchanged on the new engine.

### The full decomposition (context, not scope)

The CPI-style platform is decomposed into five shippable sub-projects:

| # | Sub-project | Deliverable | Depends on |
|---|---|---|---|
| **1** | **Flow graph model + executor (this spec)** | `Flow` type, graph executor, descriptor→flow compiler | — |
| 2 | Sandboxed transform runtime | `new Function` snippet sandbox; snippet `transform`/`filter` nodes wired into executor | 1 |
| 3 | Flow persistence + CRUD API | Store flows as data in D1, versioned; admin-gated host routes | 1, 2 |
| 4 | Flow authoring UI — list + step editor | Shell "Integrations" side-nav section; linear step editor | 3 |
| 5 | Visual graph canvas + routing | CPI-style canvas: branching, routers, multicast, multiple destinations | 4 |

**This spec covers sub-project 1 only.** The others are listed so model decisions made
here (node kinds, edge conditions, native vs. snippet transforms) are understood as
forward-looking, not over-built.

---

## Locked Architectural Decisions

These were settled during brainstorming and bind the whole platform, not just slice 1:

1. **Graph/DAG flow model.** A flow is a directed acyclic graph of typed nodes connected
   by optionally-conditional edges. This subsumes linear pipelines (a chain is a DAG with
   no branches) and gives CPI parity (routers, multicast, multiple destinations) without
   reshaping the model later.

2. **Sandboxed-JS transformers (`new Function`), treated as trusted-admin code.** Authored
   transform/filter snippets will (in sub-project 2) execute as real JS via `new Function`
   with an aggressively shadowed global scope and per-row try/catch. This is **not** a true
   security sandbox — see "Security Boundary" below. Only `integration:admin` may author
   snippets. **No snippet execution exists in slice 1.**

3. **Descriptor compiles into a flow.** The `IntegrationDescriptor` remains an authoring
   shorthand. At load time each resource is compiled into a canonical flow graph. There is
   **one** executor; the descriptor is sugar that lowers into it. No dual runtime.

4. **UI placement (future):** a top-level "Integrations" side-nav section (admin-gated),
   not a Settings tab. Affects sub-projects 4–5 only; recorded here for coherence.

---

## Security Boundary (recorded; enforced in sub-project 2)

Slice 1 contains **no snippet evaluation**, so it introduces no new execution surface.
This section documents the boundary the platform commits to, because the model in slice 1
(the `mode: 'snippet'` variants) anticipates it.

`new Function` in a Cloudflare Worker is **not a security boundary by itself**:

- It can reach any global not explicitly shadowed (`fetch`, `caches`, `crypto`, `Date`).
  Sub-project 2 must shadow every dangerous global to `undefined` in the function's
  parameter list. Even then, prototype-chain escapes (`row.constructor.constructor`) are a
  known bypass and must be mitigated (e.g. null-prototype input objects, frozen scope).
- There is **no synchronous CPU/timeout interrupt** inside a single request. A `while(true)`
  snippet hangs until the Worker wall-clock limit kills the whole invocation. Mitigation is
  operational (Worker CPU limits) + authoring-time linting, not a runtime sandbox.
- Snippets run **per record**, on every synced row — a per-row failure mode and cost.

**Commitment:** snippets are **trusted-admin-authored** (only `integration:admin` writes
them), evaluated with aggressive scope shadowing and per-row try/catch error capture, and
stored as flow data. If non-admins are ever allowed to author transforms, the platform
revisits with a restricted expression DSL instead of `new Function`.

---

## Architecture

A flow is plain serializable data — a set of typed nodes and edges, no functions. One
**executor** (`executeFlow`) topologically walks any flow's graph, threading a stream of
records from a source node, through processing nodes, to one or more destination nodes.

The existing `IntegrationDescriptor` is no longer executed directly. A **compiler**
(`compileDescriptorToFlows`) lowers each resource into one `Flow` at load time, so
hand-authored descriptors and (future) UI-authored flows share the exact same execution
path. The old `src/sync/map.ts` (`mapRows`) and `runResourceSync` pipeline is **replaced
outright** — not kept in parallel.

Slice 1 is **pure SDK**, fully unit-testable, with no persistence-authoring and no UI. It
must produce byte-identical sync results for Factorial (the regression gate).

### Node-kind execution staging

The model carries all six node kinds from day one so it is never reshaped. The executor
grows into them across sub-projects:

| Node kind | Model (slice 1) | Executor (slice 1) | Full execution |
|---|---|---|---|
| `source` | ✅ | ✅ fetch via transport | slice 1 |
| `map` | ✅ | ✅ field binding | slice 1 |
| `transform` (`mode:'native'`) | ✅ | ✅ HookRegistry call | slice 1 |
| `transform` (`mode:'snippet'`) | ✅ | ❌ throws `NotImplementedError` | sub-project 2 |
| `filter` (`mode:'native'`) | ✅ | ✅ HookRegistry call | slice 1 |
| `filter` (`mode:'snippet'`) | ✅ | ❌ throws `NotImplementedError` | sub-project 2 |
| `destination` (`kind:'d1'`) | ✅ | ✅ D1 upsert | slice 1 |
| `route` (unconditional edges) | ✅ | ✅ pass-through fan-out | slice 1 |
| `route` (conditional edges) | ✅ | ❌ throws `NotImplementedError` | sub-project 5 |

---

## The Flow Type Model

Lives in `src/flow/types.ts`. Reuses existing descriptor types
(`HttpResourceTransport`, `PaginationKind`, `StorageMode`) from `src/descriptor/index.ts`.

```ts
export type NodeKind = 'source' | 'map' | 'transform' | 'filter' | 'route' | 'destination';

export interface FlowNode {
  id: string;                      // unique within the flow
  kind: NodeKind;
  config: NodeConfig;              // discriminated by kind
}

export interface FlowEdge {
  from: string;                    // node id
  to: string;                      // node id
  when?: string;                   // optional condition (a snippet); absent = unconditional
}

export interface Flow {
  id: string;                      // e.g. "factorial:employees"
  integrationId: string;           // e.g. "factorial"
  trigger: TriggerConfig;          // cron | webhook | manual
  nodes: FlowNode[];
  edges: FlowEdge[];
}

export type TriggerConfig =
  | { kind: 'cron'; expr: string }
  | { kind: 'webhook'; event: string }
  | { kind: 'manual' };

export type NodeConfig =
  | SourceConfig | MapConfig | TransformConfig
  | FilterConfig | RouteConfig | DestinationConfig;

export interface SourceConfig {
  transport: HttpResourceTransport;   // reuse existing descriptor type
  idField: string;
  pagination?: PaginationKind;
}

export interface MapConfig {
  fields: Record<string, string>;     // localColumn -> remoteKey  (inverse of descriptor fieldMap)
}

export type TransformConfig =
  | { mode: 'native'; hook: string }      // slice 1: HookRegistry lookup
  | { mode: 'snippet'; snippet: string }; // sub-project 2: sandboxed JS

export type FilterConfig =
  | { mode: 'native'; hook: string }      // slice 1: HookRegistry lookup, returns boolean
  | { mode: 'snippet'; snippet: string }; // sub-project 2: sandboxed JS, returns boolean

export interface RouteConfig {
  // branch selection lives on outgoing edges' `when`; no extra config in slice 1
}

export interface DestinationConfig {
  kind: 'd1';                          // only d1 in slice 1; discriminant exists for future kinds
  table: string;
  mode: StorageMode;                   // stored | live | cached
}
```

### Model decisions

1. **`MapConfig.fields` is `localColumn → remoteKey`** — the inverse of the descriptor's
   `fieldMap` (`remoteKey → localColumn`). The destination table's columns are the stable
   thing a UI author edits ("for column X, where does the value come from?"), and this
   direction makes a single local column sourcing from a nested/expression remote path
   natural later. The compiler inverts the descriptor's fieldMap when lowering.

2. **Edge conditions are snippets on `edge.when`**, not config on the route node. A `route`
   node is a fan-out point; branch logic lives on its outgoing edges ("this path is taken
   when `<expr>` is truthy"). This makes router and multicast the same primitive: multicast
   = multiple unconditional edges; router = conditional edges plus a default. (Conditional
   edges are model-only in slice 1; execution lands in sub-project 5.)

3. **`Flow` is per-resource**, id `"<integrationId>:<resourceName>"`. Factorial's four
   resources compile to four flows. Per-resource keeps each flow a single
   source→destination lineage — cleaner to execute, monitor, and reason about. A future
   "integration" is just a named group of flows.

4. **`transform`/`filter` are discriminated unions on `mode`** — `native` (a hook name
   resolved from the existing `HookRegistry`, trusted compiled-in code) vs. `snippet`
   (sandboxed authored JS). This cleanly separates trusted code hooks from authored
   snippets. Slice 1 runs only `native`; `snippet` is model-present, execution-deferred.

---

## The Graph Executor

Lives in `src/flow/execute.ts`. One function runs any flow graph; it replaces `mapRows` /
`runResourceSync` as the runtime.

```ts
export interface ExecuteDeps {
  transport: Transport;              // existing — fetches from the source
  db: DatabaseAdapter;               // existing — destination writes
  hooks: HookRegistry;               // existing — resolves native transform/filter nodes
  evalSnippet?: (snippet: string, row: Row) => unknown;  // injected in sub-project 2; absent in slice 1
}

export interface ExecuteResult {
  flowId: string;
  recordsIn: number;                // rows emitted by the source node
  recordsOut: number;               // rows that reached a destination (after filters/errors)
  errors: { nodeId: string; remoteId?: string; message: string }[];
}

export async function executeFlow(flow: Flow, deps: ExecuteDeps): Promise<ExecuteResult>;
```

A `Row` is the working record envelope threaded through the graph:

```ts
export interface Row {
  remoteId: string;                       // String(raw[source.idField])
  raw: Record<string, unknown>;           // original source payload (immutable)
  current: Record<string, unknown>;       // working payload, replaced by each node
}
```

### Execution model — record-stream-per-node walk

1. **Topological sort** the nodes (Kahn's algorithm). If a cycle is detected, throw
   `IntegrationError('flow has a cycle', 400)` **before any I/O**. The DAG invariant is
   enforced at execution entry. A node id referenced by an edge but absent from `nodes`
   throws `IntegrationError('edge references unknown node', 400)`.

2. The **source** node fetches rows via `deps.transport` and produces the initial record
   stream: each row becomes `{ remoteId: String(raw[idField]), raw, current: raw }`.

3. Walk nodes in topological order. Each node kind is a `Row[] → Row[]` function:
   - **map** → set `current` to a new object built from `config.fields`
     (`current[localCol] = raw[remoteKey]`, `undefined → null`). The idField entry is not
     present in `fields` (it is the fixed `remote_id`).
   - **transform** →
     - `mode:'native'`: `current = deps.hooks[config.hook](current, raw)`. If the hook name
       is not in the registry, throw `IntegrationError('unknown hook: <name>', 400)`.
     - `mode:'snippet'`: if `deps.evalSnippet` is absent, throw
       `NotImplementedError('snippet transforms require the sandbox (sub-project 2)')`;
       otherwise `current = evalSnippet(config.snippet, row)`.
   - **filter** →
     - `mode:'native'`: drop rows where `deps.hooks[config.hook](current, raw)` is falsy.
     - `mode:'snippet'`: same `NotImplementedError` guard as transform when `evalSnippet`
       absent.
   - **route** → fan rows onto outgoing edges. Slice 1 traverses **unconditional** edges
     only; if any outgoing edge has a `when`, throw
     `NotImplementedError('conditional routing requires sub-project 5')`.
   - **destination** → upsert each row's `current` into `config.table` keyed by `remote_id`,
     reusing the existing repository upsert, respecting `config.mode`. Increments
     `recordsOut`.

4. **Per-record errors are caught and collected** into `result.errors`
   (`{ nodeId, remoteId, message }`) and never abort the flow — one bad row does not sink
   the sync. **Structural errors** (cycle, unknown node, unknown hook, NotImplemented) are
   thrown and abort, because they are authoring/configuration faults, not data faults.

### Executor decisions

1. **Record-stream-per-node** (each node is a `Row[] → Row[]` step) rather than
   record-at-a-time-through-the-whole-graph. Slice 1's compiled graphs are linear
   (source→map→[transform]→dest), so this makes each node a clean, independently unit-
   testable function. When branching arrives (sub-project 5), a `route` node splits the
   stream; the model already supports it. Trade-off: a record is not "done" until all nodes
   process — fine for batch sync, which is the only trigger mode here.

2. **`evalSnippet` is an injected, slice-1-absent dependency.** The executor knows the
   transform/filter node *kinds* and how to thread records through them, but snippet
   evaluation is injected in sub-project 2. This keeps the sandbox entirely out of slice 1.
   `hooks` (the existing `HookRegistry`) **is** present in slice 1 and is what makes native
   nodes — and therefore Factorial — run.

---

## The Descriptor → Flow Compiler

Lives in `src/flow/compile.ts`. Lowers an `IntegrationDescriptor` into flows — the seam
that runs the old authoring format on the new engine.

```ts
export function compileDescriptorToFlows(descriptor: IntegrationDescriptor): Flow[];
```

For each `ResourceDescriptor`, emit exactly one `Flow` with id
`"<descriptor.id>:<resource.name>"` and `integrationId: descriptor.id`:

- **trigger** ← `resource.refresh.schedule` present → `{ kind:'cron', expr }`; else
  `resource.webhook` present → `{ kind:'webhook', event: resource.webhook.event }`; else
  `{ kind:'manual' }`.
- **source node** (`id: 'source'`) ← `{ transport: resource.transport,
  idField: resource.idField, pagination: resource.transport.pagination }`.
- **map node** (`id: 'map'`) ← `fields` built by **inverting** `resource.fieldMap`:
  for each `[remoteKey, localCol]`, if `remoteKey === resource.idField` skip it (maps to
  the fixed `remote_id`), else set `fields[localCol] = remoteKey`.
- **transform node** (`id: 'transform'`) ← emitted **only if** `resource.hooks?.transform`
  exists → `{ mode:'native', hook:'transform' }`. (The hook key is the descriptor's hook
  name; the registry resolves `'transform'` to the registered function — e.g. Factorial
  registers `deriveFullName` under the `transform` key.)
- **beforeUpsert node** (`id: 'beforeUpsert'`) ← emitted **only if**
  `resource.hooks?.beforeUpsert` exists → `{ mode:'native', hook:'beforeUpsert' }`, placed
  after the transform node.
- **destination node** (`id: 'destination'`) ← `{ kind:'d1', table: resource.name,
  mode: resource.defaultMode }`.
- **edges** ← a linear chain connecting the emitted nodes in order:
  source → map → [transform] → [beforeUpsert] → destination. Edges connect only nodes that
  were emitted (skipped hook nodes are bridged over).

### Where it plugs in

`prepare()` in `src/host/create-worker.ts` currently does
`runMigrations → ensureManagementTables → seedConfigFromDescriptor → loadEffectiveConfig →
ensureResourceTables`. That lifecycle is **unchanged** (destination tables still derive
from fieldMap via `ensureResourceTables`).

What changes is the **sync path**: where the worker previously called
`runAllSync`/`runResourceSync` (which used `mapRows`), it now calls
`compileDescriptorToFlows(effective)` and then `executeFlow(flow, deps)` per flow. The old
`mapRows` and `runResourceSync` code is **deleted**.

The `HookRegistry` already threaded into `createIntegrationWorker` (via
`options.hooks`, e.g. `{ deriveFullName }`) is passed to the executor as `deps.hooks`. The
compiler emits native nodes keyed by the descriptor's hook keys (`'transform'`,
`'beforeUpsert'`); how Factorial registers hooks does not change.

---

## Testing

Vitest, using the existing in-memory better-sqlite3 adapter from `src/test-helpers.ts`.
Coverage target ≥ 80% (per project testing rules), reached naturally by node-kind-by-node-
kind executor tests plus compiler tests.

### Unit tests

**`src/flow/compile.test.ts`** — descriptor → flow:
- fieldMap inversion is correct (`remoteKey→localCol` becomes `localCol→remoteKey`)
- idField entry is skipped in `map.fields`
- `transform` node emitted only when `hooks.transform` present; `beforeUpsert` node only
  when `hooks.beforeUpsert` present
- trigger derivation: cron (schedule present), webhook (webhook present), manual (neither)
- one flow per resource; flow id is `"<id>:<resource>"`
- edges form a linear chain over only the emitted nodes (skipped hook nodes bridged)

**`src/flow/execute.test.ts`** — executor in isolation, per node kind:
- source→map→destination happy path produces expected upserts
- topological sort orders a shuffled node list correctly
- **cycle detection throws** `IntegrationError` before any I/O
- edge referencing an unknown node throws `IntegrationError`
- per-record error capture: one bad row is collected in `result.errors`; other rows still
  reach the destination; `recordsOut` reflects only successful rows
- native transform node calls the registered hook and replaces `current`
- unknown native hook name throws `IntegrationError`
- snippet transform node throws `NotImplementedError` when `evalSnippet` absent
- snippet filter node throws `NotImplementedError` when `evalSnippet` absent
- route node with a conditional outgoing edge throws `NotImplementedError`
- route node with unconditional edges passes rows through

**`src/flow/execute-integration.test.ts`** — full compile + execute against in-memory D1:
- descriptor in → rows upserted with correct columns + `remote_id` + `raw_json` +
  `synced_at`

### The regression gate (safety net for "replace outright")

**`src/flow/regression.test.ts`** — proves the new executor produces results identical to
the old `mapRows` path for Factorial's actual descriptor, so the old path can be deleted
with confidence:

- Load Factorial's real `integration.config.json` and register its `deriveFullName` hook
- Run a fixed set of mock source rows through **both** the old `mapRows`/`runResourceSync`
  path **and** the new `compileDescriptorToFlows` + `executeFlow` path
- Assert resulting D1 table contents are identical: same columns, same values, same row
  count — **including the hook-derived `full_name`**

This test is authored against the old path **before it is deleted**, runs green on both,
and is the gate that authorizes deletion. After the old path is removed, it is repurposed
to assert the new path's output against a captured fixture (golden file), keeping the
guarantee without a dead code path to compare against.

### Live verification (manual, post-merge)

As done for prior passes: wipe Factorial's D1, run a real sync through the new executor,
confirm 38 employees / 8 projects with `full_name` populated — matching the pre-change
live result.

---

## Out of Scope (slice 1)

- Snippet evaluation / the `new Function` sandbox (sub-project 2)
- Flow persistence, versioning, CRUD API (sub-project 3)
- Any UI (sub-projects 4–5)
- Conditional routing execution, multicast, multiple destinations (sub-project 5)
- New transport/auth/destination kinds (only existing http transport + d1 destination)
- Webhook ingestion pipeline (still scaffolded in the SDK)

## Public API additions (slice 1)

New exports from `src/index.ts`:

```ts
export { compileDescriptorToFlows } from './flow/compile';
export { executeFlow } from './flow/execute';
export type {
  Flow, FlowNode, FlowEdge, NodeKind, NodeConfig, TriggerConfig,
  SourceConfig, MapConfig, TransformConfig, FilterConfig, RouteConfig, DestinationConfig,
  Row, ExecuteDeps, ExecuteResult,
} from './flow/types';
```

Removed exports (old pipeline, deleted): `mapRows`, `MappedRow` (from `src/sync/map.ts`),
and `runResourceSync` if no longer referenced after the executor replaces it
(`runAllSync` may be retained as a thin wrapper that compiles + executes, or also removed —
the plan decides based on call sites).
