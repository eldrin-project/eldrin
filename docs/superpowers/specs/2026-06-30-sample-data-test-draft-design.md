# Sample Data, Draft Testing & Data-Flow Inspector — Design

**Date:** 2026-06-30
**Status:** Approved (design) — pending implementation plan
**Repos:** `eldrin-integration` (SDK), `eldrin-factorial` (demo connector, consumer), `eldrin-core` (shell UI)
**Relates to:** SP7 draft/published lifecycle, SP8 outer flow-graph canvas, [future-flow-elements roadmap](./2026-06-29-future-flow-elements.md) ("Test the draft", "Content Enricher / async I/O")

---

## 1. Overview & Motivation

Today the mapping canvas derives source fields only from the flow's own structure
(`map` node `connections[].sources`) — there is no way to see the *real* shape of
source data, no way to run an unpublished draft, and no visibility into what each
node received or emitted. Drafts never execute (SP7), so a draft is currently
un-testable before publishing.

This feature adds a **test/debug layer** over the existing platform with four
cohesive capabilities:

1. **Samples** — a flow owns named HTTP-exchange samples (full request+response
   envelopes), keyed by role (`source`, and later enricher node ids). Created by
   *capturing a live call* or *pasting a manual exchange*.
2. **Field extraction from samples** — mapping source fields are derived from a
   sample's response body (array-path + entry index), replacing the
   self-referential `connections[].sources`.
3. **Draft test runs** — execute a *draft* in two modes: **sample mode** (input =
   stored samples, external calls stubbed) and **live mode** (real `Transport`
   fetch, **dry-run sink = no writes**, with an opt-in to save the captured
   exchange as a sample).
4. **Trace inspector** — a test run produces a structured execution trace.
   Selecting a node shows IN/OUT; selecting an edge shows what crossed it.
   Per-record stepping + aggregate summary, with a configurable trace depth.

**Layering:** SDK-first (executor trace mode, sample store, test/capture routes),
then core UI (sample manager, field-extraction in MappingCanvas, test panel +
inspector). The cross-repo build seam (`eldrin-integration` dist → `eldrin-factorial`
→ `eldrin-core`) is live-verified per the project's hard-won rule — unit suites
prove units, not the bundle seam.

---

## 2. Data Model

### `HttpExchange` — the sample envelope

A complete, replay-ready record of one call. Stores everything a request might
carry (incl. cookies) and the full response — rich enough to troubleshoot a
failed request and to support a future replay feature.

```ts
interface HttpExchange {
  request: {
    method: string;
    url: string;                       // full URL incl. query
    headers: Record<string, string>;
    cookies?: Record<string, string>;
    body?: unknown;                    // parsed JSON or raw string
  };
  response: {
    status: number;
    headers: Record<string, string>;
    cookies?: Record<string, string>;
    body: unknown;                     // parsed JSON (the data) or raw string
  };
  capturedAt: number;                  // ms epoch (deps.now())
  origin: 'live' | 'manual';           // how it was obtained
}
```

### `FlowSample` — named, role-keyed

```ts
interface FlowSample {
  flowId: string;
  key: string;            // 'source' | <nodeId> (future enrichers)
  label?: string;         // human name, optional
  exchange: HttpExchange;
  // field-extraction config, persisted so mapping is reproducible:
  arrayPath: string;      // dot-path to records array within response.body; '' = root
  entryIndex: number;     // which entry feeds field inference / per-record stepping
}
```

`arrayPath`/`entryIndex` live on the sample so the mapping editor and test runs
agree on "which record." Headers/cookies are stored for processing access and
future replay; `body` is what field-extraction reads.

### Storage

New D1 table in the SDK store, alongside `_integration_flows`:

```
_integration_flow_samples
  flow_id    TEXT
  key        TEXT
  data       TEXT     -- JSON of FlowSample
  updated_at INTEGER
  PRIMARY KEY (flow_id, key)
```

One mutable row per `(flowId, key)` — re-saving the `source` sample overwrites it
(mirrors SP7's single-mutable-draft pattern). Idempotent migration creates the
table; no backfill.

### Trace types (executor output)

```ts
interface NodeTrace { nodeId: string; in: Row; out: Row | null; } // null = dropped/filtered
interface EdgeTrace { from: string; to: string; payload: Row; }
interface RecordTrace { recordKey: string; nodes: NodeTrace[]; edges: EdgeTrace[]; }
interface ExecuteTrace { records: RecordTrace[]; truncated: boolean; } // truncated = hit the cap
```

`recordKey` is the row's `remoteId` (the executor already assigns this in the
source stage: `remoteId: String(raw[cfg.idField])`), so a traced record is
identifiable back to its source entry.

`ExecuteTrace` rides alongside `ExecuteResult` (additive — production callers ignore it).

---

## 3. Executor Trace Mode (SDK)

### Change to `executeFlow`

Trace and dry-run are **opt-in via deps**, both off by default — zero production
overhead:

```ts
interface ExecuteDeps {
  // ...existing...
  trace?: { enabled: true; maxRecords: number };   // absent = no tracing
  dryRun?: boolean;                                 // true = sink discards writes
}

async function executeFlow(flow, deps): Promise<ExecuteResult & { trace?: ExecuteTrace }>
```

### Capturing the trace

The per-row `walk` (`src/flow/exec/walk.ts`) already visits each node once under
the single-path invariant. Thread an optional **collector** through the walk:

- Before applying a node: record `in` (a structural **clone** of the row).
- After applying: record `out` (clone), or `null` if the node dropped/filtered
  the row.
- When following an edge to the next node (including a route branch selection):
  record an `EdgeTrace` with the payload that crossed.
- Each record's `NodeTrace[]`/`EdgeTrace[]` accumulate into one `RecordTrace`,
  appended to `ExecuteTrace.records` until `maxRecords` is hit, then
  `truncated = true` and further records run untraced (still counted in
  `ExecuteResult`).

**Immutability:** the collector clones rows at capture time, so trace snapshots
never alias the live mutating row (the row object is reused/mutated as it walks).

### Dry-run sink

`src/flow/exec/sink.ts` batches writes per destination. Under `dryRun` the sink
**counts** (so `ExecuteResult.destinations`/`recordsOut` stay accurate) but
**skips the DB write** — one branch at the write call, everything else identical.
The trace reflects true routing/transform behavior without mutating tables.

### Sample-mode input: `fixtureTransport`

Sample-mode runs read from a sample instead of the network via a tiny
`fixtureTransport(records)` implementing the existing `Transport` interface
(`fetchAll` returns the records sliced from the sample's `arrayPath`). No executor
change — it already accepts any `Transport` via deps. Live mode passes the real
HTTP transport + `dryRun: true`. **One executor, one set of semantics.**

### Safety

Production path (`/api/sync`) passes no `trace`, no `dryRun` → byte-for-byte
today's behavior, guarded by the existing 279 tests staying green.

---

## 4. SDK Store & API Routes

### Store methods (`src/flow/sample-store.ts` — new, mirrors `store.ts`)

```ts
saveSample(flowId, sample: FlowSample): Promise<void>   // upsert (flowId,key)
readSample(flowId, key): Promise<FlowSample | null>
listSamples(flowId): Promise<FlowSample[]>
deleteSample(flowId, key): Promise<void>
```

Pure data access over `_integration_flow_samples`; JSON in `data`. Own file for
cohesion — `store.ts` stays flow-lifecycle only.

### HTTP routes (`create-worker.ts`, admin-gated like the rest)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/flows/:id/samples` | list samples (metadata + extraction config; bodies included) |
| `PUT` | `/api/flows/:id/samples/:key` | save/replace a sample (manual paste *or* persist a captured one) |
| `DELETE` | `/api/flows/:id/samples/:key` | delete a sample |
| `POST` | `/api/flows/:id/capture` | make a live call, return the `HttpExchange` (does NOT auto-save) |
| `POST` | `/api/flows/:id/test` | run the draft, return `ExecuteResult + ExecuteTrace` |

### `/capture` semantics

Performs the source resource's request via the existing HTTP transport/auth,
captures the full request+response into an `HttpExchange` (`origin:'live'`), and
**returns it** for the user to preview and optionally save (`PUT`). Saving is
opt-in, never automatic.

### `/test` request body

```ts
{
  mode: 'sample' | 'live';
  trace: { maxRecords: number };   // default 50; bump for "full trace" later
}
```

- **sample mode**: load the `source` sample → `fixtureTransport(recordsAt(arrayPath))`
  → `executeFlow(draft, { transport: fixture, trace, dryRun: true })`. Stubs are
  role-keyed, so future enricher samples slot in.
- **live mode**: real transport + `dryRun: true` + `trace`. Response also carries
  the captured source `HttpExchange` so the UI can offer "save as sample."
- Always reads the **draft** (`readDraft` ?? `readFlowForEdit`) — never the
  published version, never writes.

### Validation & error handling (boundary discipline)

- `/test` validates the draft via existing `validateFlow` first → 400 with issues
  if invalid (can't test a broken graph).
- `/capture` & `/test` live errors (auth/network/timeout) → structured error
  envelope `{ ok:false, error }`, surfaced in the UI — never swallowed.
- Missing `source` sample in sample mode → 409 with a clear "capture or paste a
  sample first" message.
- `:key`, `arrayPath`, `entryIndex`, request body validated (Zod) at the boundary.

All additive; no existing routes change.

---

## 5. Core UI (eldrin-core)

The flow editor is its own full-page route (`/integrations/:appId/flows/:flowId`,
committed separately). Add a **third view** alongside Structure / Mapping:
**Test**. The Mapping view changes its source-field source.

### API client (`integrations-api.ts`)

`fetchSamples`, `saveSample`, `deleteSample`, `captureSample`, `testFlow` — thin
`Result<T>` wrappers matching existing style.

### 5a — Sample manager (`SamplePanel.tsx`)

Lists the flow's samples by key (in the Test view + reachable from Mapping). Per
sample:

- **Capture live** → calls `/capture`, shows a preview (status, headers, body);
  **Save** persists it.
- **Paste manual** → form/textarea to paste a request+response exchange
  (`origin:'manual'`); parsed & validated, then saved.
- **Field-extraction controls** — `arrayPath` input (with auto-detected default)
  + `entryIndex` stepper, showing the resolved record's keys live.

### 5b — Mapping source fields from the sample

`MappingCanvas` source fields switch from `connections[].sources` to **keys of the
selected sample's resolved entry** (dot-pathed for nested):

- `source` sample exists → source column = real fields from it.
- none → fall back to today's structural fields + an inline "Capture or paste a
  sample to see real source fields" prompt.
- Source side only; target fields (destination schema) unchanged.

### 5c — Test view (`TestPanel.tsx` + `TracePanel.tsx`)

- **Run controls**: mode toggle **Sample | Live**, a `maxRecords` field (default
  50; the door to "full trace"), **Run** button.
- After a run:
  - **Summary**: recordsIn/out, per-destination counts, routedNowhere, errors
    (from `ExecuteResult`). A persistent **"dry-run — no data written"** notice.
  - **Record stepper**: pick/step through traced records (defaults to the
    sample's `entryIndex`).
  - **Inspector wiring**: reuse `StructuralCanvas`'s existing node/edge selection.
    Node → `NodeTrace` IN/OUT (two JSON views; dropped → "filtered out"). Edge →
    `EdgeTrace` payload. Reuses SP8's selection model rather than a new canvas.
  - **Live mode extra**: if the run captured a source exchange, a **"Save as
    source sample"** button (opt-in persistence).

### State & isolation

`TestPanel` owns run state (last result/trace, selected record); `TracePanel` is
pure-presentational over a `RecordTrace`. `SamplePanel` owns sample CRUD and lifts
"active sample changed" so Mapping re-derives fields. No changes to
`flow-graph-model`/`draft-graph-model` (the editable documents) — testing is a
read-only overlay.

### i18n

New keys in `integrations.json` (capture, paste, arrayPath, entryIndex, run,
sampleMode, liveMode, IN, OUT, dryRunNotice, saveAsSample, noSampleYet, etc.).

---

## 6. Testing Strategy

TDD throughout (write the failing test first), per project rules.

### SDK unit (Vitest) — bulk of correctness

- `sample-store`: upsert/read/list/delete; `(flowId,key)` isolation; JSON round-trip.
- **trace collector**: IN/OUT per node for transform/filter/route; dropped row →
  `out:null`; edge payloads correct incl. route-branch selection; `maxRecords`
  truncation sets `truncated`; **clones don't alias** the mutating row.
- **dry-run sink**: zero writes, correct counts/destinations.
- `fixtureTransport`: slices records at `arrayPath`.
- **regression gate**: existing 279 tests stay green with no `trace`/`dryRun` →
  proves the production path unchanged.
- routes: `/samples` CRUD, `/capture` shape, `/test` sample+live, validation
  400/409, error envelopes.
- field-extraction helper: `arrayPath` resolution (root, nested, missing),
  `entryIndex` bounds, nested-key (dot) inference.

### Core unit

API client `Result` wrappers; `TracePanel` rendering over a `RecordTrace` fixture
(node IN/OUT, edge payload, dropped state); Mapping field-derivation from a sample
vs. fallback.

### Live cross-repo verification (non-negotiable)

Rebuild `eldrin-integration` dist → rebuild `eldrin-factorial` → exercise in the
browser via chrome-devtools: capture a real Factorial sample, see real source
fields in mapping, run a sample-mode test, step a record, select a node (IN/OUT)
and an edge, then a live-mode dry-run. Unit green ≠ seam green.

---

## 7. Implementation Phasing

Each phase is independently shippable & verifiable. Feature branch per repo,
conventional commits, attribution off, live-verify the seam before moving on.

1. **SDK trace + dry-run** — executor trace mode, dry-run sink, `fixtureTransport`.
   Pure SDK, heavily unit-tested. Foundation.
2. **SDK samples + routes** — sample-store, migration, `/samples` `/capture` `/test`.
3. **Core: samples + mapping fields** — SamplePanel, capture/paste, field
   extraction wired into MappingCanvas.
4. **Core: Test view + inspector** — TestPanel/TracePanel, node/edge IN/OUT,
   record stepper, live-mode save-as-sample.

---

## 8. Out of Scope (YAGNI — door left open)

- **Replay-request execution** — samples are replay-*ready* (full request stored),
  but replaying is a later feature.
- **Per-node enricher samples** beyond the role-keying model — the key supports
  node ids; enricher UX lands with the enricher sub-project.
- **Full-trace-all-records UI** — the `maxRecords` param exists and the trace API
  supports it; the UI toggle is later.
- **Writing during a test** — test runs are always dry-run.

---

## 9. Decisions Captured

| Decision | Choice |
|---|---|
| Trace mechanism | Optional trace mode in the single executor (not a separate simulator, not UI reconstruction) |
| Sample shape | Full HTTP exchange (request incl. cookies + response), for troubleshooting & future replay |
| Sample binding | Named samples per flow, keyed by role (`source` / node id) |
| Live mode | Real fetch + trace, **dry-run (no writes)**, opt-in save of the captured request |
| Field extraction | Path-to-array + entry index (handles nested envelopes; auto-detected default, user-overridable) |
| Trace scope | Per-record stepping + aggregate summary; trace depth configurable (full-trace door open) |
