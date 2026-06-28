# Streaming Executor & Batched Sink Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Re-shape the flow executor in `@eldrin-project/eldrin-integration` from batch-materialize-per-node to a lazy async-generator pipeline with a batching, order-preserving D1 sink.

**Architecture:** Each node becomes an async-generator stage (`AsyncIterable<Row> → AsyncIterable<Row>`); the executor composes them and a destination *consumer* pulls rows, buffers up to `BATCH_SIZE`, and flushes one multi-row `INSERT…ON CONFLICT` per batch in source order. Node set and graph shape are unchanged from Pass 4; only how rows flow and how the sink writes change. The Pass-4 regression gate stays the byte-identical safety net.

**Tech Stack:** TypeScript 5.9 (strict), Vitest, in-memory better-sqlite3 adapter (`makeTestDb`).

## Global Constraints

- **SDK only.** All changes in `/Users/tibor/projects/eldrin-backup/eldrin-integration`. No UI.
- **Node set & graph shape unchanged** from Pass 4: `source → [transform] → map → [beforeUpsert] → destination`, linear. Only the *mechanism* (generators, batched writes) changes. Do NOT add the connection model / transformers / sandbox — that is sub-project 2.
- **Streaming primitive:** each middle node is `(input: AsyncIterable<Row>) => AsyncIterable<Row>` (an async generator). Rows are pulled lazily; ~one row in flight.
- **`recordsIn` is a live counter** incremented by the source stage as it yields — not `array.length`.
- **Per-row error capture inside the generator:** non-structural errors → `collectError` + skip row (don't yield); structural errors (`IntegrationError`, `NotImplementedError`) → re-thrown (abort the pull).
- **Destination is a CONSUMER, not a stage:** it pulls rows, buffers up to `BATCH_SIZE` (fixed 100), flushes one multi-row upsert per batch, **sequentially in source order**.
- **`DestinationConfig.ordered?: boolean`** default true; `ordered === false` throws `NotImplementedError('unordered destination flush is reserved')`.
- **Batched upsert SQL:** double-quoted identifiers, parameterized; per-row value tuple `[genId(), remoteId, ...mappedColValues, JSON.stringify(raw), ts]` (same column layout as Pass 4: `id, remote_id, <cols>, raw_json, synced_at`); `ON CONFLICT("remote_id") DO UPDATE SET "<col>" = excluded."<col>"` for each mapped col + raw_json + synced_at.
- **Per-batch column set from the first row's `current` keys**; a row whose keys diverge is split into its own single-row flush.
- **Batch write failure → one error per row in the batch** (via `collectError`), flow continues; no row-by-row retry this pass.
- **`Transport` gains optional `fetchStream?(resource): AsyncIterable<Record<string,unknown>>`;** the source stage uses it if present, else wraps `fetchAll`'s array. `http` keeps only `fetchAll`.
- **`executeFlow` signature unchanged:** `(flow, deps) => Promise<ExecuteResult>`; `ExecuteDeps`/`ExecuteResult` unchanged. `runResourceSync`, host, compiler untouched.
- **Regression preservation:** Factorial rows through the new path produce byte-identical D1 table contents (columns, values, row count, hook-derived `full_name`) vs. the Pass-4 baseline.
- **Immutability** (build new row objects; never mutate `row.raw`/`row.current`); no `console.log`; conventional commits, attribution disabled. Coverage ≥ 80%.
- Run tests from `/Users/tibor/projects/eldrin-backup/eldrin-integration` with `npx vitest run`.

---

## File Structure

- `src/flow/types.ts` (modify) — add `ordered?: boolean` to `DestinationConfig`.
- `src/transport/index.ts` (modify) — add optional `fetchStream?` to `Transport`.
- `src/flow/execute.ts` (rewrite the execution body) — async-generator stages + batching-sink consumer; `topoSort` and pre-validation unchanged.
- `src/flow/batch.ts` (new) — `flushBatch(db, table, rows, genId, ts)` builder + executor for one multi-row upsert (extracted for focus + unit testing).
- `src/flow/batch.test.ts` (new) — `flushBatch` SQL-shape + divergent-column-split + failure tests.
- `src/flow/execute.test.ts` (modify) — rewrite node-execution assertions for streaming + batched writes; add laziness + ordering assertions.
- `src/flow/regression.test.ts` (modify only if its harness counts per-row writes) — DB-dump equality unchanged.
- `src/flow/execute-integration.test.ts` (verify) — real D1 multi-row INSERT lands rows.

---

## Reference: current code (do not re-derive)

`src/flow/types.ts` `DestinationConfig`: `{ kind: 'd1'; table: string; mode: StorageMode }` (add `ordered?: boolean`).
`Row = { remoteId: string; raw: Record<string,unknown>; current: Record<string,unknown> }`.
`ExecuteDeps`: `{ transport: Transport; db: DatabaseAdapter; hooks: HookRegistry; now: () => number; genId: () => string; evalSnippet?: ... }`.
`ExecuteResult`: `{ flowId: string; recordsIn: number; recordsOut: number; errors: {nodeId; remoteId?; message}[] }`.
`src/transport/index.ts` `Transport`: `{ fetchAll(resource): Promise<Record<string,unknown>[]> }`.
`src/errors.ts`: `IntegrationError(message, status)`, `NotImplementedError(message)`.

**Current `executeFlow` body (Pass 4, to be replaced)** — for reference, the existing structure: `topoSort` → pre-validate conditional edges → pre-validate native hook refs → `let stream: Row[]` → `for (const node of ordered) switch(node.kind)` with `source` (fetchAll → `stream = raws.map`), `map` (`stream = stream.map`, projects `row.current[remoteKey]`), `transform`/`filter` (per-row loop, native hook or snippet, structural re-throw), `route` (no-op), `destination` (per-row `INSERT…ON CONFLICT`). **The `topoSort` function, the conditional-edge pre-validation, and the native-hook pre-validation are KEPT VERBATIM. The map/transform/filter projection LOGIC is kept (same field projection, same hook calls, same snippet-envelope from SP2 if present) — only the array-iteration shell becomes a generator. The destination per-row write becomes the batching consumer.**

`src/flow/execute.test.ts` already has a `dbSpy()` returning `{ db, upserts }` where `upserts: { sql, values }[]` records each `bind(...).run()`. Reuse it; for batched writes a single `prepare(...).bind(...all values...).run()` yields ONE `upserts` entry per batch.

`src/flow/regression.test.ts` uses `makeTestDb([])`, an `oldPathUpsert` oracle (per-row), `dumpTable`, `makeCounter()` for genId, and `expect(newDump).toEqual(oldDump)`. The oracle + dumpTable are unchanged.

Test adapter `makeTestDb(ddl: string[])` from `src/test-helpers.ts`; `ensureResourceTables(db, descriptor)` from `src/schema/ensure`.

---

### Task 1: Type + transport interface changes

**Files:**
- Modify: `src/flow/types.ts`
- Modify: `src/transport/index.ts`
- Test: `src/flow/types.test.ts` (extend)

**Interfaces:**
- Consumes: nothing new.
- Produces: `DestinationConfig.ordered?: boolean`; `Transport.fetchStream?`. Consumed by Tasks 2–3.

- [ ] **Step 1: Write the failing test (append to `src/flow/types.test.ts`)**

```ts
import type { DestinationConfig } from './types';
import type { Transport } from '../transport';

describe('streaming type additions', () => {
  it('DestinationConfig accepts an optional ordered flag', () => {
    const a: DestinationConfig = { kind: 'd1', table: 't', mode: 'stored' };
    const b: DestinationConfig = { kind: 'd1', table: 't', mode: 'stored', ordered: true };
    const c: DestinationConfig = { kind: 'd1', table: 't', mode: 'stored', ordered: false };
    expect([a.ordered, b.ordered, c.ordered]).toEqual([undefined, true, false]);
  });
  it('Transport allows an optional fetchStream', () => {
    const t: Transport = {
      fetchAll: async () => [],
      fetchStream: async function* () { yield { id: 1 }; },
    };
    expect(typeof t.fetchStream).toBe('function');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/flow/types.test.ts`
Expected: FAIL — `ordered` not on `DestinationConfig` / `fetchStream` not on `Transport`.

- [ ] **Step 3: Edit the types**

In `src/flow/types.ts`, replace the `DestinationConfig` interface:

```ts
export interface DestinationConfig {
  kind: 'd1';
  table: string;
  mode: StorageMode;
  ordered?: boolean; // default true; false (parallel/unordered flush) reserved → NotImplementedError
}
```

In `src/transport/index.ts`, extend the `Transport` interface:

```ts
export interface Transport {
  fetchAll(resource: ResourceDescriptor): Promise<Record<string, unknown>[]>;
  fetchStream?(resource: ResourceDescriptor): AsyncIterable<Record<string, unknown>>;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/flow/types.test.ts`
Expected: PASS. (`tsc --noEmit` may fail until execute.ts is rewritten in Task 4 — not a gate for this task.)

- [ ] **Step 5: Commit**

```bash
git add src/flow/types.ts src/transport/index.ts src/flow/types.test.ts
git commit -m "feat(flow): add ordered destination flag and optional fetchStream transport method"
```

---

### Task 2: The batched-upsert builder (`flushBatch`)

**Files:**
- Create: `src/flow/batch.ts`
- Test: `src/flow/batch.test.ts`

**Interfaces:**
- Consumes: `Row` from `./types`; `DatabaseAdapter` from `@eldrin-project/eldrin-app-core`.
- Produces: `flushBatch(db: DatabaseAdapter, table: string, rows: Row[], genId: () => string, ts: number): Promise<void>` — executes one or more multi-row upserts (one per contiguous same-columns run; a divergent row gets its own single-row flush). Consumed by Task 3's sink.

- [ ] **Step 1: Write the failing test**

```ts
// src/flow/batch.test.ts
import { describe, it, expect } from 'vitest';
import { flushBatch } from './batch';
import type { Row } from './types';
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';

function dbSpy() {
  const calls: { sql: string; values: unknown[] }[] = [];
  const db = { prepare(sql: string) { return { bind(...values: unknown[]) { return { run: async () => { calls.push({ sql, values }); } }; }, run: async () => {} }; } };
  return { db: db as unknown as DatabaseAdapter, calls };
}
const row = (remoteId: string, current: Record<string, unknown>, raw: Record<string, unknown> = {}): Row => ({ remoteId, raw, current });

describe('flushBatch', () => {
  it('writes a single multi-row INSERT for uniform-column rows', async () => {
    const { db, calls } = dbSpy();
    let n = 0; const genId = () => `g${++n}`;
    await flushBatch(db, 'employees', [
      row('1', { full_name: 'Ada', email: 'a@x' }, { id: 1 }),
      row('2', { full_name: 'Bob', email: 'b@x' }, { id: 2 }),
    ], genId, 1000);
    expect(calls).toHaveLength(1);
    const { sql, values } = calls[0];
    expect(sql).toMatch(/INSERT INTO "employees"/);
    expect(sql).toMatch(/"full_name"/);
    expect(sql).toMatch(/ON CONFLICT\("remote_id"\)/);
    // two value tuples: each [id, remote_id, full_name, email, raw_json, synced_at] = 6 → 12 bound values
    expect(values).toHaveLength(12);
    expect(values.slice(0, 6)).toEqual(['g1', '1', 'Ada', 'a@x', JSON.stringify({ id: 1 }), 1000]);
    expect(values.slice(6)).toEqual(['g2', '2', 'Bob', 'b@x', JSON.stringify({ id: 2 }), 1000]);
  });

  it('VALUES has one tuple group per row', async () => {
    const { db, calls } = dbSpy();
    await flushBatch(db, 't', [row('1', { a: 1 }), row('2', { a: 2 }), row('3', { a: 3 })], () => 'g', 1);
    // 3 rows → 3 placeholder groups "(?, ?, ?, ?)" (id, remote_id, a, raw_json, synced_at = 5 each)
    const groups = calls[0].sql.match(/\([?, ]+\)/g) ?? [];
    expect(groups.length).toBeGreaterThanOrEqual(3); // at least the 3 VALUES groups (ON CONFLICT has no paren group of ?)
  });

  it('splits a divergent-column row into its own single-row flush', async () => {
    const { db, calls } = dbSpy();
    await flushBatch(db, 't', [
      row('1', { a: 1, b: 2 }),
      row('2', { a: 3, b: 4 }),
      row('3', { a: 5 }),            // diverges (missing b)
    ], () => 'g', 1);
    // first two rows batch together; the third flushes alone → 2 prepare calls
    expect(calls).toHaveLength(2);
    expect(calls[0].values).toHaveLength(2 * 5); // a,b → [id,remote_id,a,b,raw_json,synced_at]=6? recompute below
  });
});
```

Note: the third test's exact value-count depends on column layout; the implementer should assert the *call count* (2) firmly and adjust the value-length assertion to the actual column math (`{a,b}` → 6 cols/row; `{a}` → 5 cols/row). Keep the call-count assertion as the behavioral anchor.

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/flow/batch.test.ts`
Expected: FAIL — `Cannot find module './batch'`.

- [ ] **Step 3: Write `src/flow/batch.ts`**

```ts
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';
import type { Row } from './types';

function sameColumns(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** Execute one multi-row upsert for a run of rows sharing the same `current` column set. */
async function flushRun(db: DatabaseAdapter, table: string, rows: Row[], cols: string[], genId: () => string, ts: number): Promise<void> {
  const allCols = ['id', 'remote_id', ...cols, 'raw_json', 'synced_at'];
  const quoted = allCols.map((c) => `"${c}"`);
  const tuple = `(${allCols.map(() => '?').join(', ')})`;
  const valuesSql = rows.map(() => tuple).join(', ');
  const updates = [...cols, 'raw_json', 'synced_at'].map((c) => `"${c}" = excluded."${c}"`).join(', ');
  const values: unknown[] = [];
  for (const row of rows) {
    values.push(genId(), row.remoteId, ...cols.map((c) => row.current[c]), JSON.stringify(row.raw), ts);
  }
  await db
    .prepare(`INSERT INTO "${table}" (${quoted.join(', ')}) VALUES ${valuesSql} ON CONFLICT("remote_id") DO UPDATE SET ${updates}`)
    .bind(...values)
    .run();
}

/**
 * Flush a buffer of rows as batched multi-row upserts, preserving order.
 * Rows are grouped into contiguous runs sharing the same `current` column set;
 * a row whose columns diverge from the current run starts a new run (so a single
 * divergent row becomes its own single-row flush). Identifiers double-quoted; params bound.
 */
export async function flushBatch(db: DatabaseAdapter, table: string, rows: Row[], genId: () => string, ts: number): Promise<void> {
  if (rows.length === 0) return;
  let runStart = 0;
  let runCols = Object.keys(rows[0].current);
  for (let i = 1; i <= rows.length; i++) {
    const cols = i < rows.length ? Object.keys(rows[i].current) : [];
    if (i === rows.length || !sameColumns(cols, runCols)) {
      await flushRun(db, table, rows.slice(runStart, i), runCols, genId, ts);
      runStart = i;
      runCols = cols;
    }
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/flow/batch.test.ts`
Expected: PASS (adjust the divergent-row value-length assertion to the real column math as noted; call-count must be 2).

- [ ] **Step 5: Commit**

```bash
git add src/flow/batch.ts src/flow/batch.test.ts
git commit -m "feat(flow): add batched multi-row upsert builder with divergent-column split"
```

---

### Task 3: Rewrite the executor as a streaming pipeline + batching sink

**Files:**
- Modify: `src/flow/execute.ts`
- Test: `src/flow/execute.test.ts` (rewrite node-execution assertions)

**Interfaces:**
- Consumes: `flushBatch` (Task 2); `ordered`/`fetchStream` (Task 1); existing `topoSort` + pre-validation.
- Produces: streaming `executeFlow` (same signature) with a batching sink.

- [ ] **Step 1: Rewrite/extend the tests in `src/flow/execute.test.ts`**

Keep the existing structural tests (cycle, unknown-node, unknown-hook, snippet-NotImplemented). Replace the per-row-write assertions with batched-write + laziness + ordering assertions. The existing `dbSpy()` records `{ sql, values }` per `bind().run()`; a batched flush is ONE entry.

```ts
// helper already present: dbSpy() → { db, upserts }
// linearFlow(extra?) builds source→map→[extra]→destination; if it builds a flat-fields map,
// keep its map shape (Pass-4 fields form) — this pass does NOT change MapConfig.

describe('streaming executor + batched sink', () => {
  it('writes N rows as ceil(N/100) batched INSERTs in source order', async () => {
    const { db, upserts } = dbSpy();
    const rows = Array.from({ length: 250 }, (_, i) => ({ id: i + 1, email: `u${i + 1}@x` }));
    const deps: ExecuteDeps = {
      transport: { fetchAll: async () => rows },
      db, hooks: {}, now: () => 7, genId: (() => { let n = 0; return () => `g${++n}`; })(),
    };
    const result = await executeFlow(linearFlowEmailOnly(), deps); // map: { email: 'email' }
    expect(result.recordsIn).toBe(250);
    expect(result.recordsOut).toBe(250);
    expect(upserts).toHaveLength(3); // 100 + 100 + 50
    // source order preserved: first batch's first remote_id is '1', last batch contains '250'
    expect(upserts[0].values[1]).toBe('1');                    // [id, remote_id, ...]
    expect(upserts[2].values).toContain('250');
  });

  it('pulls lazily — at first flush the source has yielded exactly BATCH_SIZE rows', async () => {
    const { db, upserts } = dbSpy();
    let yielded = 0;
    let yieldedAtFirstFlush = -1;
    const source = async function* () {
      for (let i = 1; i <= 250; i++) { yielded++; yield { id: i, email: `u${i}` }; }
    };
    const deps: ExecuteDeps = {
      transport: { fetchAll: async () => { throw new Error('should use fetchStream'); }, fetchStream: source },
      db: { prepare: (sql: string) => ({ bind: (...v: unknown[]) => ({ run: async () => { if (yieldedAtFirstFlush < 0) yieldedAtFirstFlush = yielded; upserts.push({ sql, values: v }); } }) , run: async () => {} }) } as unknown as ExecuteDeps['db'],
      hooks: {}, now: () => 1, genId: () => 'g',
    };
    await executeFlow(linearFlowEmailOnly(), deps);
    // At the first flush the source has yielded ~BATCH_SIZE rows (allow ±1 for
    // async-generator read-ahead), NOT the whole 250 — proves incremental pull.
    expect(yieldedAtFirstFlush).toBeGreaterThanOrEqual(100);
    expect(yieldedAtFirstFlush).toBeLessThanOrEqual(101);
  });

  it('rejects ordered:false destination with NotImplementedError', async () => {
    const { db } = dbSpy();
    const flow = linearFlowEmailOnly();
    (flow.nodes.find((n) => n.kind === 'destination')!.config as any).ordered = false;
    const deps: ExecuteDeps = { transport: { fetchAll: async () => [{ id: 1, email: 'a' }] }, db, hooks: {}, now: () => 1, genId: () => 'g' };
    await expect(executeFlow(flow, deps)).rejects.toThrow(NotImplementedError);
  });

  it('collects a per-row transform error while other rows still reach the sink', async () => {
    const { db, upserts } = dbSpy();
    const transformNode: FlowNode = { id: 'transform', kind: 'transform', config: { mode: 'native', hook: 'boomOnTwo' } };
    const deps: ExecuteDeps = {
      transport: { fetchAll: async () => [{ id: 1, email: 'a' }, { id: 2, email: 'b' }] },
      db, hooks: { boomOnTwo: (cur: Record<string, unknown>, raw: Record<string, unknown>) => { if (raw.id === 2) throw new Error('boom'); return cur; } },
      now: () => 1, genId: () => 'g',
    };
    const result = await executeFlow(linearFlowEmailOnly([transformNode]), deps);
    expect(result.recordsOut).toBe(1);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toMatchObject({ nodeId: 'transform', remoteId: '2', message: 'boom' });
  });
});
```

Add a `linearFlowEmailOnly(extra=[])` helper to the test file building `source → map({fields:{email:'email'}}) → [extra] → destination({kind:'d1',table:'t',mode:'stored'})` with linear edges. (Map stays Pass-4 `fields` form — this pass does not touch MapConfig.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/flow/execute.test.ts`
Expected: FAIL — current executor writes per-row (250 upserts, not 3); no `fetchStream` use; `ordered` unhandled.

- [ ] **Step 3: Rewrite the execution body in `src/flow/execute.ts`**

Keep `topoSort`, the conditional-edge pre-validation, and the native-hook pre-validation **verbatim**. Replace everything from `const errors` / `let stream: Row[]` through the end of `executeFlow` with the streaming pipeline:

```ts
import { flushBatch } from './batch';
// ...existing imports (IntegrationError, NotImplementedError, types)...

const BATCH_SIZE = 100; // ~100 rows × ~6 cols ≈ 600 bound params — safe under D1's bind cap

export async function executeFlow(flow: Flow, deps: ExecuteDeps): Promise<ExecuteResult> {
  const ordered = topoSort(flow);
  // ...KEEP: conditional-edge pre-validation + native-hook pre-validation exactly as-is...

  const errors: ExecuteResult['errors'] = [];
  const collectError = (nodeId: string, remoteId: string | undefined, e: unknown) =>
    errors.push({ nodeId, remoteId, message: e instanceof Error ? e.message : String(e) });

  const counters = { recordsIn: 0 };
  const sourceNode = ordered.find((n) => n.kind === 'source')!;
  const destNode = ordered.find((n) => n.kind === 'destination')!;
  const middle = ordered.filter((n) => n.kind !== 'source' && n.kind !== 'destination');

  // --- source: origin generator ---
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
      counters.recordsIn++;
      yield { remoteId: String(raw[cfg.idField]), raw, current: raw };
    }
  }

  // --- middle stage factory ---
  function stageFor(node: FlowNode): (input: AsyncIterable<Row>) => AsyncIterable<Row> {
    return async function* (input: AsyncIterable<Row>): AsyncIterable<Row> {
      for await (const row of input) {
        try {
          if (node.kind === 'map') {
            const cfg = node.config as MapConfig;
            const current: Record<string, unknown> = {};
            for (const [localCol, remoteKey] of Object.entries(cfg.fields)) {
              const v = row.current[remoteKey];
              current[localCol] = v === undefined ? null : v;
            }
            yield { ...row, current };
          } else if (node.kind === 'transform') {
            const cfg = node.config as TransformConfig;
            if (cfg.mode === 'snippet') {
              if (!deps.evalSnippet) throw new NotImplementedError('snippet transforms require the sandbox (sub-project 2)');
              yield { ...row, current: deps.evalSnippet(cfg.snippet, row) as Record<string, unknown> };
            } else {
              const fn = deps.hooks[cfg.hook]!;
              yield { ...row, current: fn(row.current, row.raw) as Record<string, unknown> };
            }
          } else if (node.kind === 'filter') {
            const cfg = node.config as FilterConfig;
            if (cfg.mode === 'snippet') {
              if (!deps.evalSnippet) throw new NotImplementedError('snippet filters require the sandbox (sub-project 2)');
              if (deps.evalSnippet(cfg.snippet, row)) yield row;
            } else {
              const fn = deps.hooks[cfg.hook]!;
              if (fn(row.current, row.raw)) yield row;
            }
          } else { // route: unconditional pass-through
            yield row;
          }
        } catch (e) {
          if (e instanceof NotImplementedError || e instanceof IntegrationError) throw e; // structural
          collectError(node.id, row.remoteId, e);
          // non-structural → skip this row (do not yield)
        }
      }
    };
  }

  let stream: AsyncIterable<Row> = sourceStage();
  for (const node of middle) stream = stageFor(node)(stream);

  // --- destination consumer: buffer + batched flush in source order ---
  const dcfg = destNode.config as DestinationConfig;
  if (dcfg.ordered === false) throw new NotImplementedError('unordered destination flush is reserved');
  const ts = deps.now();
  let buffer: Row[] = [];
  let recordsOut = 0;
  const flush = async () => {
    if (buffer.length === 0) return;
    const batch = buffer;
    buffer = [];
    try {
      await flushBatch(deps.db, dcfg.table, batch, deps.genId, ts);
      recordsOut += batch.length;
    } catch (e) {
      for (const row of batch) collectError(destNode.id, row.remoteId, e);
    }
  };
  for await (const row of stream) {
    buffer.push(row);
    if (buffer.length >= BATCH_SIZE) await flush();
  }
  await flush();

  return { flowId: flow.id, recordsIn: counters.recordsIn, recordsOut, errors };
}
```

Notes for the implementer:
- The `evalSnippet(cfg.snippet, row)` call keeps the **Pass-4 signature** `(snippet, row)`. (Sub-project 2 re-types it; this pass leaves it as-is — do not adopt the SP2 envelope here.)
- The map node still reads the Pass-4 `cfg.fields` record (do NOT switch to connections — that is SP2).
- Structural errors thrown inside a generator propagate out of the `for await` that drives it (the destination's pull loop), aborting `executeFlow` — preserving Pass-4 abort semantics.

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run src/flow/execute.test.ts && npx tsc --noEmit`
Expected: PASS (structural tests + batched/laziness/ordering/per-row-error tests); tsc clean.

- [ ] **Step 5: Commit**

```bash
git add src/flow/execute.ts src/flow/execute.test.ts
git commit -m "refactor(flow): stream rows through async-generator stages with a batching sink"
```

---

### Task 4: Regression gate + integration + coverage + Factorial

**Files:**
- Modify (if needed): `src/flow/regression.test.ts`
- Verify: `src/flow/execute-integration.test.ts`
- Modify: `README.md`

**Interfaces:**
- Consumes: all prior tasks.
- Produces: verified byte-identical parity, docs.

- [ ] **Step 1: Run the regression gate**

Run: `npx vitest run src/flow/regression.test.ts`
Expected: PASS unchanged — the new path writes via batched upserts, but the resulting D1 table contents are identical to the per-row oracle's. If it FAILS, inspect the dump diff. The oracle (`oldPathUpsert`), `dumpTable`, and `expect(newDump).toEqual(oldDump)` must NOT be weakened; only fix the new-path invocation if the test constructs deps that lack a field the streaming path needs (it should not — `ExecuteDeps` is unchanged). Report the result.

- [ ] **Step 2: Run the full suite with coverage**

Run: `npx vitest run --coverage`
Expected: all PASS; `src/flow/` (incl. `batch.ts`) line coverage ≥ 80%.

- [ ] **Step 3: Typecheck + build**

Run: `npx tsc --noEmit && npm run build`
Expected: clean; no better-sqlite3 in the bundle.

- [ ] **Step 4: Verify Factorial against the rebuilt SDK**

Run:
```bash
npm run build
cd /Users/tibor/projects/eldrin-backup/eldrin-factorial && npx vitest run worker/__tests__/host-sync.test.ts
```
Expected: PASS — `full_name` still derived ('Grace Hopper'); rows land via batched writes. Report the output (this is the cross-repo proof that streaming + batching preserve behavior).

- [ ] **Step 5: Update README**

In `eldrin-integration/README.md`, extend the "Flow model" subsection: the executor streams rows through async-generator stages (one row in flight, not the whole dataset) and the destination writes batched multi-row upserts (default 100/batch) in source order; note `DestinationConfig.ordered` (default true; unordered reserved) and the optional `Transport.fetchStream` seam (http still uses fetchAll this pass). ~10 lines, existing tone. Do NOT claim the fetch path is fully streamed (it isn't yet).

- [ ] **Step 6: Commit**

```bash
git add src/flow/regression.test.ts README.md
git commit -m "test(flow): verify streaming+batched parity; document streaming executor"
```

---

## Post-implementation: live verification (manual, not a task)

After all tasks pass and the SDK is rebuilt + the factorial preview restarted: wipe Factorial's D1, run a real `/api/sync`, confirm 38 employees / 8 projects with `full_name` populated (now written via batched upserts). The host-sync test already proves this in-process.

## Notes

- **Do NOT pull in sub-project 2 work** (connections, transformers, sandbox). This pass changes only the execution *mechanism*. The map node keeps the Pass-4 `fields` record; `evalSnippet` keeps the Pass-4 `(snippet, row)` signature.
- **`topoSort` and both pre-validation loops are kept verbatim** — only the post-validation execution body is rewritten.
- **Generators propagate structural throws to the driving consumer** — a `throw` inside a stage surfaces at the destination's `for await`, aborting `executeFlow`. This preserves Pass-4 abort semantics for cycles, snippet-without-sandbox, unknown hooks.
