# Routing Engine — Design Spec (SP6)

**Status:** approved (design), ready for implementation plan
**Date:** 2026-06-28
**Sub-project:** SP6 — first slice of the "full structural editing + conditional routing" arc for the CPI-style integration flow platform
**Repo:** `eldrin-integration` (SDK only — no UI)

---

## Decomposition context

Full structural editing + conditional routing is ~3 sub-projects, sequenced SDK-first (the runtime must support what later UI lets users draw):
- **SP6 (this spec)** — SDK routing engine: executor evaluates `route` nodes + `when`-edges + branching; `validateFlow` allows branching topologies. Runnable + tested.
- **SP7 (deferred)** — structural persistence: a path beyond `applyDraft` that saves whole node/edge graphs, optimistic-locked.
- **SP8 (deferred)** — the outer flow-graph canvas (eldrin-core): add/remove/reorder/branch nodes, edit configs, drill into the SP5 mapping canvas.

## 1. Scope & What Changes

SP6 is **SDK-only** (`eldrin-integration`). It implements the deferred "sub-project 5 routing" so `route` nodes with conditional `when` edges and branching to N destinations become runnable. No UI.

Three changes, all in `eldrin-integration`:
1. **`validateFlow`** (`src/flow/validate.ts`) — relax "exactly one destination" → "≥1 destination"; add route/`when` semantics (route nodes have ≥2 conditioned outgoing edges; `when` only on route edges; `when` compiles at validate-time; reachability).
2. **The executor** (`src/flow/execute.ts`) — replace the linear-pipe assembly with a per-row branching-DAG walk: first-match routing at route nodes, one batched sink per destination, source-order preserved per sink.
3. **A `when`-expression evaluator** — a sandboxed boolean predicate evaluator reusing the SP2 snippet-sandbox hardening (`when` is `integration:admin`-authored code).

## 2. Execution Model: Linear Pipe → Branching DAG

Today (`execute.ts:122-123`) the executor is a single linear pipe: `source → middle[0] → … → one sink`; every row flows through every middle node in topo order. Branching breaks this — a row at a route node goes down one branch, and different rows reach different destinations.

**New model — per-row graph walk with multiple sinks:**
- **Build once:** `topoSort` for validation + acyclicity (unchanged); build adjacency (`nodeId → outgoing edges`) and `nodeId → node` lookup.
- **One sink per destination node:** `Map<destNodeId, Buffer>`, each with its own batched `flushBatch` (reuse existing batching, `BATCH_SIZE`, ordered flush).
- **Per row, walk from the source:** at each node:
  - `transform`/`map`/`filter` — apply the stage (existing `stageFor` logic, refactored generator-pipe → single-row 0-or-1-row), advance along its single outgoing edge.
  - `route` — evaluate each outgoing edge's `when` in declared edge order; advance down the **first matching** edge (CPI first-match). No match → row dropped (tallied, not errored).
  - `destination` — push into that destination's buffer; flush at `BATCH_SIZE`.
- **Reconverge** (two branches' edges → same downstream node) and **fan-out** (different rows → different destinations) both fall out of following edges naturally.

**Single-path invariant (the linchpin):** because routing is first-match (a row takes exactly ONE outgoing edge at each route node) and non-route nodes have exactly one outgoing edge, every row traverses exactly one path from source to a single destination. A row therefore cannot visit any node twice — even in a diamond where two branches reconverge, the row arrived via one branch and continues along one edge. This is what makes the walk terminate, keeps reconvergence unambiguous (a reconverging node just processes rows arriving from whichever branch each took), and means each row lands in exactly one sink.

**Source-order preservation:** rows pulled from the source in order; each row walked to completion (or buffered) before the next is pulled → each destination buffer fills in source order, preserving the ordered-flush guarantee per sink.

**Reuse:** the stage *bodies* (map/transform/filter/route logic, `execute.ts:67-112`) are reused, refactored from generator-pipe to single-row form. Source stage + error-collection unchanged. The middle+sink section (~122-148) is the rewrite.

## 3. The `when` Expression Evaluator

Each route node's outgoing edge carries `when?: string` — a boolean expression per row (`current.active === true`, `current.status === 'inactive'`, `Number(current.headcount) > 100`). Admin-authored predicate code → same trust model + hardening as the SP2 snippet sandbox.

**Reuse the SP2 sandbox in boolean context:**
- New dep `deps.evalWhen?(expr: string, ctx: { current, raw }): boolean`, implemented with the same hardened `new Function` factory as `evalSnippet` (shadowed globals, frozen null-proto inputs, compile-once memoization), coercing result via `!!`.
- Surface: `current` (row's mapped state at that point) + `raw` (original source record). No `sources` — a route condition is about the whole row.
- **Compile-once memoization** keyed on the expression string — conditions run per row across thousands of rows; caching the compiled fn matters (performance-first goal).

**Semantics:**
- `when` throws at runtime → non-structural row error (`collectError`, row dropped from that branch), consistent with transform/filter error handling (`execute.ts:113-117`); does NOT abort the flow.
- `when` syntactically invalid → caught at **validate-time** (`validateFlow` compiles each `when` once, 400 if it won't parse) — a broken condition can't be saved, mirroring builtin/hook reference validation.

**Residual risk (documented, same as SP2):** no CPU/timeout guard, denylist not allowlist — acceptable because `when` is `integration:admin`-authored, the same trust boundary as snippets. Carry the SP2 documented-risk note forward.

## 4. Validation Changes (`validateFlow`)

Today (`validate.ts:37-44`): exactly-one-source AND exactly-one-destination; no route/`when` rules.

**Relaxed:**
- **Destinations `=== 1` → `>= 1`** (line 40). Source stays `=== 1` (singular origin generator).

**New route/`when` rules:**
- **Every `route` node has ≥2 outgoing edges, and every outgoing edge of a route node carries a `when`** (a conditionless route is a structural error — use a plain pass-through node for that). A `when` on an edge whose source is NOT a route node is rejected (conditions belong only on route branches; matches the `RouteConfig` "branch logic lives on outgoing edge.when" marker).
- **Each `when` compiles** — `validateFlow` compiles every `when` once (same sandbox-compile as validate-time snippet checks), 400 with node/edge context if it won't parse.
- **Reachability** — every node reachable from the source AND every node reaches some destination (no orphan branches, no dead-ends). `topoSort` already gives acyclicity + edge integrity; this adds forward-reachability from source + backward-reachability to a destination.

**Unchanged:** node-config checks (map connections, transform/filter hooks, destination kind/table), `knownTables` (now applied to EACH destination), duplicate-id, unknown-kind.

**Executor guards removed:** the `NotImplementedError` guards for `route`/`when` (`execute.ts:17-21`) are removed — SP6 implements them.

## 5. Data Flow, Edge Cases & Testing

```
Flow {nodes, edges with when} ─validateFlow─▶ (relaxed: ≥1 dest, route rules, when compiles)
                              ─executeFlow──▶ per-row DAG walk:
   source → … → route (first-match when) → … → destination[k] sink (batched, ordered)
                              ─▶ ExecuteResult { recordsIn, recordsOut, errors, destinations, routedNowhere }
```

**`ExecuteResult` change (additive):** keep `recordsOut` (total across sinks); add `destinations: { [destNodeId]: { table: string; recordsOut: number } }` and `routedNowhere: number`. Existing single-destination callers/tests keep working.

**Edge cases (each gets a test):**
- **No-match at a route** → row dropped, not an error; counted in `routedNowhere` (no silent caps).
- **First-match wins** → a row matching two branches goes down the first edge only (declared order).
- **Reconverge** → two branches → same node; it processes rows from both; shared destination buffers in source order.
- **Fan-out** → different rows → different destination buffers; each flushes independently.
- **`when` throws at runtime** → row dropped from that branch + `collectError`, flow continues.
- **Empty branch result** → destination receiving no rows flushes nothing (recordsOut 0), not an error.
- **Order** → per-row walk-to-completion preserves source order per sink (ordered-id fixture).

**Testing** (TDD, 80%+, Vitest; existing `execute.test.ts` has route/when fixtures stubbed at lines 195-212):
1. **`when`-evaluator unit:** boolean coercion, `{current, raw}` surface, memoization (same compiled fn for repeated expr), runtime-throw isolation.
2. **`validateFlow` unit:** ≥1 destination accepted; route-without-when rejected; `when`-on-non-route-edge rejected; uncompilable `when` → 400; unreachable branch → 400; multi-destination known-table check.
3. **`executeFlow` integration:** reconverge (one dest, two branches); fan-out (two dests); first-match; no-match `routedNowhere` tally; runtime-throw drop; per-sink source-order; per-destination `ExecuteResult` breakdown.
4. **Regression:** every existing single-source/single-destination linear flow executes identically (the executor rewrite must not change non-branching behavior) — the existing `execute.test.ts` suite is the gate.

**Task breakdown** (detailed in the plan):
1. `when`-evaluator + `deps.evalWhen` wiring (reuse SP2 sandbox factory).
2. `validateFlow` relaxation + route/when/reachability rules.
3. Executor rewrite to per-row DAG walk + multi-sink (the core).
4. `ExecuteResult` per-destination breakdown + `routedNowhere`.
5. Remove `NotImplementedError` route/when guards + end-to-end branching tests.

## Global Constraints (carried from the platform spec)

- **SDK-only:** all changes in `/Users/tibor/projects/eldrin-backup/eldrin-integration`. No eldrin-core/factorial changes (the UI that draws these graphs is SP8).
- **Non-branching regression-safety:** the executor rewrite MUST NOT change behavior for existing single-source/single-destination linear flows. The current `execute.test.ts` suite is the gate.
- **`when` trust model:** `integration:admin`-authored only; same hardened sandbox + documented residual risk as SP2 snippets (no CPU/timeout guard, denylist). Reuse, don't reinvent.
- **First-match routing:** declared edge order; no-match → drop + tally (`routedNowhere`), never error.
- **Source = 1, destinations ≥ 1;** each destination table in `knownTables`.
- **Validate-time vs run-time:** uncompilable `when` → 400 at validate; runtime `when` throw → drop row + `collectError`, flow continues.
- **Source-order preserved per sink;** reuse existing `flushBatch`/`BATCH_SIZE`/ordered-flush.
- **`ExecuteResult` additive:** keep `recordsOut`; add `destinations` + `routedNowhere`.
- Immutability; no `console.log`; conventional commits, attribution disabled. Coverage ≥ 80%. Tests: `cd eldrin-integration && npx vitest run`.
