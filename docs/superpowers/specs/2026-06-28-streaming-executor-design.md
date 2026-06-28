# Streaming Executor & Batched Sink — Design Spec

**Date:** 2026-06-28
**Status:** Approved for planning
**Sub-project:** 1.5 of 5 (CPI-style integration flow platform) — sequenced between sub-project 1 (executor) and sub-project 2 (mapping engine)
**Scope:** SDK only (`@eldrin-project/eldrin-integration`). No UI.
**Builds on:** Sub-project 1 (flow graph model & executor) — spec `2026-06-28-flow-graph-model-design.md`.

---

## Context & Motivation

SAP CPI is a UI over Apache Camel. Camel's two biggest large-dataset levers are **streaming
mode** (process a route row-by-row, never holding the whole dataset) and the
**aggregator-before-sink** pattern (collect rows into batches before a database write).
Our Pass-4 executor does neither: the source node materializes the full dataset
(`stream = raws.map(...)`), then *every* node re-materializes it (`stream = stream.map(...)`),
and the destination writes **one `INSERT … ON CONFLICT` per row**. For a data-heavy
integration this means N full in-memory copies of the dataset (one per node, plus per-row
`{...row, current}` spreads) and N D1 round-trips — the dominant real-world cost.

This sub-project re-shapes the executor to a **lazy async-generator pipeline** (each row
pulled end-to-end through the node chain, ~one row in flight) with a **batching sink** that
accumulates rows and flushes multi-row upserts in source order. It is sequenced **before**
the mapping engine (sub-project 2) so that engine is built on the streaming shape once,
rather than built on the batch shape and rewritten.

### Roadmap re-sequencing

| # | Sub-project | Status |
|---|---|---|
| 1 | Flow graph model + executor | DONE (Pass 4) |
| **1.5** | **Streaming executor + batched sink (this spec)** | this spec |
| 2 | Field-mapping engine + transformer runtime | spec'd (`2026-06-28-mapping-engine-transformers-design.md`) — rebases on 1.5 |
| 3 | Flow persistence + CRUD API | future |
| 4 | Flow authoring UI | future |
| 5 | Visual graph canvas + mapping | future |

**Scope split (important):** this pass keeps the **node set and graph shape identical** to
Pass 4 (`source → [transform] → map → [beforeUpsert] → destination`, linear). It changes only
*how* rows flow (async generators instead of arrays) and *how* the sink writes (batched
instead of per-row). The mapping-engine reshape (connections) and the snippet sandbox remain
sub-project 2, now built on top of this. Sub-project 2's plan must be rebased onto the
streaming node signatures before execution.

---

## Locked Decisions (from brainstorming)

1. **Streaming primitive: async-generator pipeline.** Each node is a stage
   `(input: AsyncIterable<Row>) => AsyncIterable<Row>`; the executor composes stages and the
   destination pulls rows through lazily. Naturally lazy, composes for future fan-out, ready
   for a paginating transport.

2. **Batching sink, ordered-by-default.** The destination is a *consumer* (not a stage): it
   pulls rows, buffers up to `BATCH_SIZE` (fixed 100), and flushes ONE multi-row
   `INSERT … VALUES (…),(…) ON CONFLICT(remote_id) DO UPDATE` per batch, flushed
   **sequentially in source order**. `DestinationConfig.ordered?: boolean` defaults true;
   `ordered:false` (parallel/unordered flush) is reserved → `NotImplementedError`.

3. **Source-side streaming seam.** `Transport` gains optional
   `fetchStream?(resource): AsyncIterable<Record<string,unknown>>`. The source stage uses it
   if present, else wraps the existing `fetchAll` array into an async iterable. `http` keeps
   only `fetchAll` this pass; the fully-bounded page-yielding fetch is a later transport-only
   change. **Honest cap recorded:** with today's `fetchAll`, the source array is still fully
   materialized before streaming begins — the downstream pipeline + sink are bounded, the
   fetch is not yet.

4. **`executeFlow` public signature unchanged** — `(flow, deps) => Promise<ExecuteResult>`;
   `ExecuteDeps`/`ExecuteResult` unchanged. Streaming is internal; `runResourceSync` and host
   call sites are untouched.

---

## Architecture

The executor changes from **batch-materialize-per-node** to a **lazy async-generator
pipeline** terminated by a **batching sink**:

- `topoSort` (structural validation: cycle, unknown node, conditional-edge and unknown-hook
  pre-validation) is **unchanged** and still runs before any I/O.
- The **source** node becomes an origin generator yielding `Row`s one at a time.
- **map / transform / filter / route** nodes become generator **stages**
  (`AsyncIterable<Row> → AsyncIterable<Row>`), composed in topological order.
- The **destination** is the terminal **consumer** that pulls rows, buffers, and flushes
  batched upserts in source order.

Memory is bounded to the in-flight row plus one write-batch (≤ `BATCH_SIZE` rows),
independent of dataset size; per-node array copies are eliminated; N per-row writes collapse
to ⌈N / `BATCH_SIZE`⌉ batched upserts. The Pass-4 regression gate stays the safety net:
byte-identical Factorial output, produced via streaming + batched writes.

---

## Streaming Pipeline & Node Model

`src/flow/execute.ts`. Each node kind maps to an async-generator stage; the executor nests
them and drives the pull from the destination consumer.

```ts
// A node stage transforms a lazy row stream into another lazy row stream.
type NodeStage = (input: AsyncIterable<Row>) => AsyncIterable<Row>;

export async function executeFlow(flow: Flow, deps: ExecuteDeps): Promise<ExecuteResult> {
  const ordered = topoSort(flow);                  // unchanged: structural validation before any I/O
  // ...pre-validate conditional route edges + native hook refs (unchanged from Pass 4)...

  const errors: ExecuteResult['errors'] = [];
  const collectError = (nodeId: string, remoteId: string | undefined, e: unknown) =>
    errors.push({ nodeId, remoteId, message: e instanceof Error ? e.message : String(e) });

  const counters = { recordsIn: 0 };
  const sourceNode = ordered.find((n) => n.kind === 'source')!;
  const destNode = ordered.find((n) => n.kind === 'destination')!;
  const middle = ordered.filter((n) => n.kind !== 'source' && n.kind !== 'destination');

  let stream: AsyncIterable<Row> = sourceStage(sourceNode, deps, counters);
  for (const node of middle) stream = stageFor(node, deps, collectError)(stream);

  const { recordsOut } = await runDestination(destNode, stream, deps, collectError);
  return { flowId: flow.id, recordsIn: counters.recordsIn, recordsOut, errors };
}
```

### Node-kind → stage mapping

- **source** → origin generator. Uses `deps.transport.fetchStream(res)` if present, else
  wraps `await deps.transport.fetchAll(res)` into `async function*`. For each raw record,
  increments `counters.recordsIn` and yields `{ remoteId: String(raw[idField]), raw, current: raw }`.
- **map / transform / filter** → `async function*(input) { for await (const row of input) { … } }`.
  - map / transform: compute the new `current`, `yield { ...row, current }`.
  - filter: `yield row` only when kept; dropped rows are simply not yielded.
  - Per-row errors are caught **inside the loop**: on a non-structural error, `collectError`
    and skip the row (do not yield). **Structural errors** (`IntegrationError`,
    `NotImplementedError`) are re-thrown out of the generator → propagates → aborts the pull.
- **route** → `async function*(input) { yield* input; }` (unconditional pass-through;
  conditional edges already rejected up front, sub-project 5).
- **destination** → NOT a stage; the terminal consumer (next section).

### Decisions

1. **`recordsIn` is a live counter**, incremented by the source stage as it yields — not
   `array.length`. Same final value, computed incrementally, ready for `fetchStream`.

2. **Per-row error capture moves inside each generator** (`for await … of` + try/catch in the
   generator body). The structural-vs-per-row split is unchanged: re-throw
   `IntegrationError`/`NotImplementedError`, collect everything else. The `errors` array and
   `collectError` are closed over by all stages.

3. **Destination is a consumer, not a stage.** Stages are pure `stream → stream`; the
   destination drives the pipeline by pulling, buffering into batches, and flushing. This is
   the Camel aggregator shape and is why streaming + batching coexist without conflict.

---

## The Batching Sink

`src/flow/execute.ts` (or an extracted `src/flow/sink.ts` — implementer's choice per file-size
judgment). The destination pulls rows, buffers up to `BATCH_SIZE`, flushes multi-row upserts
in source order.

```ts
const BATCH_SIZE = 100;  // ~100 rows × ~6 cols ≈ 600 bound params — safe under D1's bind-parameter cap

async function runDestination(
  node: FlowNode, stream: AsyncIterable<Row>, deps: ExecuteDeps,
  collectError: (nodeId: string, remoteId: string | undefined, e: unknown) => void,
): Promise<{ recordsOut: number }> {
  const cfg = node.config as DestinationConfig;
  if (cfg.ordered === false) throw new NotImplementedError('unordered destination flush is reserved');
  const ts = deps.now();
  let buffer: Row[] = [];
  let recordsOut = 0;

  const flush = async () => {
    if (buffer.length === 0) return;
    try {
      await flushBatch(deps.db, cfg.table, buffer, deps.genId, ts);
      recordsOut += buffer.length;
    } catch (e) {
      for (const row of buffer) collectError(node.id, row.remoteId, e); // batch failure → one error per row
    }
    buffer = [];
  };

  for await (const row of stream) {
    buffer.push(row);
    if (buffer.length >= BATCH_SIZE) await flush();   // sequential flush preserves source order
  }
  await flush();                                       // remainder
  return { recordsOut };
}
```

### `flushBatch` — one ordered multi-row upsert

Builds a single `INSERT INTO "<table>" (<quoted cols>) VALUES (…),(…),… ON CONFLICT("remote_id")
DO UPDATE SET …` with all rows' value tuples bound in **buffer (source) order**. Identifiers
double-quoted; values parameterized. Each row's value tuple is
`[genId(), remoteId, ...mappedColValues, JSON.stringify(raw), ts]`, matching the Pass-4
per-row column layout (`id, remote_id, <cols>, raw_json, synced_at`).

The column set is **derived from the first row's `current` keys** for the batch. If a later
row in the buffer has a **divergent** key set, that row is **split into its own single-row
flush** (correctness over batching for the odd row) rather than corrupting the batch's bind
layout. In slice-1 flows every row has the same columns, so the split path is a safety net.

### Decisions

1. **Per-batch column set from the first row, single-row-split fallback on divergence.** Safe
   for uniform slice-1 flows; the split keeps correctness if a future dynamic mapping yields
   heterogeneous rows.

2. **Batch-level write failure → one error per row in the batch, flow continues.** No
   row-by-row retry to isolate a poison row this pass (deferred resilience follow-up). Honest
   trade-off: one bad row fails its whole batch's writes.

3. **`BATCH_SIZE = 100`, fixed constant** (not configurable; `ordered` is the only destination
   knob). Documented against D1's bind-parameter limit.

---

## Type & Interface Changes

`src/flow/types.ts`:
- `DestinationConfig` gains `ordered?: boolean` (default true; `false` reserved →
  `NotImplementedError`). New shape:
  ```ts
  export interface DestinationConfig { kind: 'd1'; table: string; mode: StorageMode; ordered?: boolean; }
  ```
- `Row`, `ExecuteDeps`, `ExecuteResult` unchanged.

`src/transport/index.ts`:
- `Transport` gains an optional streaming method:
  ```ts
  export interface Transport {
    fetchAll(resource: ResourceDescriptor): Promise<Record<string, unknown>[]>;
    fetchStream?(resource: ResourceDescriptor): AsyncIterable<Record<string, unknown>>;
  }
  ```
  `http` implements only `fetchAll` this pass. The source stage prefers `fetchStream` when
  present.

No change to `executeFlow`'s signature, `runResourceSync`, the host, or the compiler.

---

## Testing

Vitest, in-memory better-sqlite3 adapter (`makeTestDb`). Coverage ≥ 80%.

- **`src/flow/execute.test.ts`** (rewrite node-execution assertions for generators):
  - source→map→destination happy path produces correct upserts.
  - **Batched-write assertion:** a `dbSpy` recording `prepare` calls — N rows produce
    ⌈N/100⌉ INSERT statements (e.g. 250 rows → 3), each a multi-row `VALUES (…),(…)` with
    bound params in source order.
  - **Laziness assertion:** instrument the source generator with a yield counter; assert that
    at the moment of the first `flush`, the source has yielded exactly `BATCH_SIZE` rows
    (not the whole dataset) — proving incremental pull, not drain-then-write.
  - **Ordering assertion:** sequential `remote_id`s appear in the batched INSERTs in source
    order across batch boundaries.
  - filter drops rows (not yielded); per-row transform/filter runtime error collected while
    other rows flow; cycle / unknown-node / unknown-hook / snippet-`NotImplementedError`
    structural throws still abort; `ordered:false` destination throws `NotImplementedError`.
- **`src/flow/batch.test.ts`** (or co-located) for `flushBatch`: multi-row SQL shape (quoted
  identifiers, K value tuples, ON CONFLICT clause); single-row-split fallback on divergent
  columns; batch-failure records one error per row.
- **`src/flow/regression.test.ts`** — still byte-identical: Factorial rows through the
  streaming executor + batched sink produce the same D1 table contents (columns, values, row
  count, hook-derived `full_name`) as the Pass-4 baseline. The oracle is unchanged; update
  only any dbSpy/per-row-write counting in the harness — the **DB dump equality must not
  change**.
- **`src/flow/execute-integration.test.ts`** — full compile+execute against in-memory D1:
  rows land correctly via the real multi-row INSERT.
- `tsc --noEmit` + `npm run build` clean (no better-sqlite3 in bundle).
- **Factorial `host-sync.test.ts`** green against the rebuilt SDK (cross-repo proof:
  `full_name` derives AND batched writes land correctly).

---

## Public API

No new exports required (streaming is internal; `DestinationConfig`/`Transport` are already
exported types, now with an added optional field/method). If `flushBatch` is extracted to its
own module it stays internal (not exported from `src/index.ts`).

## Out of Scope (this pass)

- `fetchStream` *implementation* for the http transport (page-yielding lazy fetch) — interface
  added, http still uses `fetchAll`; fully-bounded fetch is a later transport-only change.
- Row-by-row retry to isolate a poison row in a failed batch (deferred resilience follow-up).
- Configurable `BATCH_SIZE`; parallel/unordered flush (`ordered:false`) — reserved.
- Parallelism / thread-pool processing (Camel's parallel split) — least applicable to a
  single-threaded Worker; not pursued.
- The mapping engine (connections + transformers + sandbox) — sub-project 2, rebased onto this
  streaming shape.
