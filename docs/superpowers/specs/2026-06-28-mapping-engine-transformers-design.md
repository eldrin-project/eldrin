# Field-Mapping Engine & Sandboxed Transformer Runtime — Design Spec

**Date:** 2026-06-28
**Status:** Approved for planning
**Sub-project:** 2 of 5 (CPI-style integration flow platform)
**Scope:** SDK only (`@eldrin-project/eldrin-integration`). No UI.
**Builds on:** Sub-project 1 (flow graph model & executor) — spec `2026-06-28-flow-graph-model-design.md`.

---

## Context & Motivation

Sub-project 1 replaced the SDK's hardcoded sync pipeline with a graph executor. Its `map`
node does flat field renames (`localColumn → remoteKey`), and transformation logic exists
only as compiled-in code hooks. The executor was built with a seam for snippet evaluation
(`ExecuteDeps.evalSnippet?`), and `transform`/`filter` nodes carry a `mode: 'snippet'`
variant that currently throws `NotImplementedError`.

The end goal mirrors **SAP CPI's graphical message mapping**: a source tree and a target
tree with **connections** drawn between fields. A connection can feed one target field
from one or more source fields, and carries either a **standard platform transformer**
(concat, formatDate, ifThenElse, …) or a **custom code snippet**. The drag-and-drop canvas
is a later sub-project; this sub-project builds the **runtime and data model that canvas
will drive**.

This reframes the work from "a bare per-node snippet sandbox" into a **field-level mapping
engine**: the unit that holds transformation logic is the *connection* (per target field),
not the node. The `map` node becomes the mapping engine; each target field is a connection.

### The full decomposition (context, not scope)

| # | Sub-project | Deliverable | Status |
|---|---|---|---|
| 1 | Flow graph model + executor | `Flow` type, executor, descriptor→flow compiler | DONE (Pass 4) |
| **2** | **Field-mapping engine + transformer runtime (this spec)** | Connection model, builtin library, snippet sandbox | this spec |
| 3 | Flow persistence + CRUD API | Store flows as data in D1, versioned; admin-gated routes | future |
| 4 | Flow authoring UI — list + step editor | Shell "Integrations" side-nav section | future |
| 5 | Visual graph canvas + mapping | CPI-style canvas: drag-drop field connections, routing | future |

**This spec covers sub-project 2 only.** The drag-and-drop mapping canvas is sub-project 5;
this slice produces the data model and runtime it edits.

---

## Locked Decisions (from brainstorming)

1. **Field-level mapping model.** The `map` node is reshaped into a list of *connections*.
   Each connection = `{ target, sources: string[], transform? }`. This is the CPI
   per-connection model; the canvas later edits this data.

2. **`MapConfig` connections replace the flat `fieldMap`.** `MapConfig` becomes
   `{ connections: Connection[] }`. The descriptor's flat `fieldMap` is lowered by the
   compiler into 1:1 pass-through connections — the flat form is authoring sugar. One model;
   Factorial keeps working through the compiler; the Pass-4 regression gate still guards
   byte-identical output.

3. **Transformer reference is a tagged union:** `{ kind:'builtin', fn, args? } |
   { kind:'snippet', code }`. Absent = pass-through of `sources[0]`. Both variants ship in
   this slice. The evaluator dispatches on `kind`; the future UI renders a dropdown
   (builtin) or code box (snippet) off `kind`.

4. **Built-in library: core set (~11 functions)** — `concat`, `substring`, `upperCase`,
   `lowerCase`, `trim`, `replace`, `ifThenElse`, `equals`, `formatDate`, `coalesce`,
   `constant`. Covers Factorial and common SaaS mappings; anything else is a custom snippet.

5. **Snippet sandbox: shadowed `new Function` + null-proto frozen inputs + per-row guard,
   treated as trusted-admin code.** Only `integration:admin` authors snippets. Not a true
   security boundary — see "Security Boundary" below.

6. **Error split:** snippet *compile* errors (syntax) abort the flow (authoring fault,
   `IntegrationError`); snippet/builtin *runtime* errors are caught per-row into
   `result.errors` (data fault, flow continues). Mirrors Pass 1's structural-vs-per-record
   split.

---

## Security Boundary (enforced in this slice)

Custom snippets execute as `new Function` per record inside the Cloudflare Worker. This is
**not a security boundary by itself**; the hardening below reduces but does not eliminate
risk, and authoring is restricted to `integration:admin`.

**Hardening applied:**
- **Scope shadowing (denylist):** every dangerous global is a parameter name bound to
  `undefined`, so e.g. `fetch(...)` inside a snippet is `undefined(...)` → throws.
  `"use strict"` blocks implicit global creation and `with`.
- **Null-prototype frozen inputs:** `sources`/`row`/`raw` are passed as
  `Object.freeze(Object.assign(Object.create(null), …))` to blunt prototype-chain escapes
  (`row.constructor.constructor`) and prevent snippet mutation of the working payload.
- **Compile once per flow run:** snippets are memoized by code string, so `new Function`
  runs once per distinct snippet, not per row.
- **Per-row try/catch:** a snippet that throws on a row is captured into `result.errors`;
  the flow continues.

**Residual risks (documented, not solved here):**
- **No CPU/timeout guard.** A `while(true)` snippet hangs until the Worker wall-clock limit
  kills the invocation. Mitigation is operational (Worker CPU limits), not a runtime
  interrupt.
- **Shadowing is a denylist, not an allowlist.** A global not listed is reachable. Mitigated
  by `"use strict"`, frozen null-proto inputs, and admin-only authoring.
- **Static authoring-time linting** (rejecting `constructor`/`import`/loops before storing a
  snippet) is a **deferred defense-in-depth follow-up**, not in this slice. Token blocklists
  are bypassable (belt, not armor) and risk false-rejecting legitimate code.

**Commitment:** if non-admins are ever allowed to author snippets, the platform revisits
with a restricted expression DSL instead of `new Function`.

---

## Architecture

The `map` node becomes a **field-mapping engine**. Each target field is a *connection* fed
by one or more source fields, optionally through a transformer (a vetted built-in or a
custom snippet). Pure SDK, no UI; the future canvas (sub-project 5) is a thin editor over
this data model.

New/changed units:
- **`MapConfig` reshape** (`src/flow/types.ts`) — `{ connections: Connection[] }` replacing
  `fields: Record<string,string>`.
- **Transformer library** (`src/flow/transformers/`) — the ~11 built-ins, each a pure
  `(sources, args) => value` function in a registry.
- **Snippet sandbox** (`src/flow/sandbox.ts`) — the hardened `new Function` evaluator; this
  *is* the `evalSnippet` dependency the executor already has a seam for.
- **Executor map-node rewrite** (`src/flow/execute.ts`) — applies connections.
- **Compiler change** (`src/flow/compile.ts`) — flat `fieldMap` lowers to 1:1 connections.
- **Host wiring** (`src/host/create-worker.ts`) — injects the sandbox-backed `evalSnippet`.

The Pass-4 regression gate stays the safety net: Factorial's flat fieldMap → 1:1 connections
→ byte-identical output (including hook-derived `full_name`).

---

## The Connection & Transformer Data Model

Lives in `src/flow/types.ts`.

```ts
export interface Connection {
  target: string;                 // local column name (destination field)
  sources: string[];              // source field names, read from the row's current payload
  transform?: TransformerRef;     // absent = pass-through of sources[0]
}

export type TransformerRef =
  | { kind: 'builtin'; fn: string; args?: unknown[] }   // fn is a library key; args are literal params
  | { kind: 'snippet'; code: string };                  // custom JS over `sources`

export interface MapConfig {
  connections: Connection[];      // replaces the old `fields: Record<string,string>`
}
```

### Evaluation contract (how a connection produces its target value)

1. Resolve `sources` → an array of values read from the row's working payload (`current`),
   in order. `sources: ['first_name','last_name']` → `[current.first_name, current.last_name]`.
2. Dispatch on `transform`:
   - **absent** → pass-through: target value is `sources[0]`; `undefined → null`.
   - **`builtin`** → `BUILTINS[fn](resolvedSources, args ?? [])`.
   - **`snippet`** → `evalSnippet(code, { sources: resolvedSources, row, raw })`.
3. Assign the result to `current[target]`.

### Decisions

1. **Sources read from `current`, not `raw`.** Connections operate on the row's working
   payload (after the Pass-4 fix, `current` is `raw` initially, or the post-transform-node
   payload if a node-level `transform` ran before `map`). Source field *names* are the keys
   present in `current` at that point.

2. **Built-in signature is uniform: `(sources: unknown[], args: unknown[]) => unknown`.**
   Every built-in takes the resolved source values and the literal args. Uniform shape =
   trivial registry dispatch and a uniform UI later.

3. **Snippet receives `{ sources, row, raw }`** — `sources` is the resolved-values array
   (primary input); `row` (full current payload) and `raw` (original record) are the escape
   hatch for snippets needing sibling fields. All three are passed frozen and null-proto.

---

## The Built-in Transformer Library

Lives in `src/flow/transformers/`. One registry; each built-in a pure function with the
uniform signature.

```ts
export type BuiltinFn = (sources: unknown[], args: unknown[]) => unknown;
export const BUILTINS: Record<string, BuiltinFn>;
```

| `fn` | sources | args | result |
|---|---|---|---|
| `concat` | N values | `[sep?]` | each part stringified (null/undefined → `''`), joined by `sep ?? ''` |
| `substring` | 1 value | `[start, end?]` | `String(sources[0]).slice(start, end)`; null source → `null` |
| `upperCase` | 1 | — | `String(sources[0]).toUpperCase()`; null source → `null` |
| `lowerCase` | 1 | — | `String(sources[0]).toLowerCase()`; null source → `null` |
| `trim` | 1 | — | `String(sources[0]).trim()`; null source → `null` |
| `replace` | 1 | `[search, replacement]` | `String(sources[0]).replaceAll(search, replacement)`; null source → `null` |
| `ifThenElse` | 1 (condition) | `[thenVal, elseVal]` | `sources[0] ? thenVal : elseVal` |
| `equals` | 2 | — | `sources[0] === sources[1]` |
| `formatDate` | 1 | `[pattern]` | parse `sources[0]` as Date → format per pattern; invalid/unparseable → `null` |
| `coalesce` | N | — | first non-null/undefined source, else `null` |
| `constant` | — (ignored) | `[value]` | `value` |

### Decisions

1. **Null-preserving, not null-stringifying.** Each string built-in guards
   `if (sources[0] == null) return null;` before coercing — a missing source stays `null`
   rather than leaking the literal `"null"` into a column. `concat` is the exception: it
   stringifies each part but maps null/undefined parts to `''` (not `"null"`).

2. **`formatDate` minimal pattern set.** Workers have no guaranteed `Intl` for arbitrary
   patterns, so `formatDate` hand-formats from a parsed `Date` using a minimal token set:
   `YYYY`, `MM`, `DD`, `HH`, `mm`, `ss` (zero-padded). Tokens outside the set pass through
   literally. Covers `YYYY-MM-DD` and `YYYY-MM-DD HH:mm:ss` (Factorial's dates). An
   invalid/unparseable input → `null`. No external dependency; deterministic.

   **Deferred extension (revisit per use case):** locales, timezones, and richer patterns
   are out of scope; when a real integration needs them we extend `formatDate` or add a
   dedicated date built-in. Recorded here as a known revisit point.

---

## The Snippet Sandbox (`evalSnippet`)

Lives in `src/flow/sandbox.ts`. This is the `evalSnippet` dependency the executor already
has a seam for (`ExecuteDeps.evalSnippet?`).

**Interface change to the Pass-4 seam:** Pass 1 typed
`ExecuteDeps.evalSnippet?: (snippet: string, row: Row) => unknown`. This slice **re-types**
it to `(code: string, input: SnippetInput) => unknown` (the second argument becomes the
`{ sources, row, raw }` envelope, not a bare `Row`), to carry the resolved connection
sources. The transform/filter *node* snippet branches (which currently call
`evalSnippet(cfg.snippet, row)`) must be updated to pass a `SnippetInput` envelope too — for
a node-level snippet there are no connection sources, so pass `{ sources: [], row: row.current, raw: row.raw }`
(frozen). This keeps a single `evalSnippet` signature across map-connection snippets and
node-level transform/filter snippets.

```ts
export interface SnippetInput {
  sources: unknown[];                 // resolved connection source values
  row: Record<string, unknown>;       // full current payload (frozen, null-proto)
  raw: Record<string, unknown>;       // original source record (frozen, null-proto)
}

// Compiles a snippet ONCE; returns a reusable evaluator. Compilation (syntax) errors throw here.
export function compileSnippet(code: string): (input: SnippetInput) => unknown;

// The executor-facing dep: memoizes compiled fns by code string within a flow run.
export function createSnippetEvaluator(): (code: string, input: SnippetInput) => unknown;
```

### Implementation

```ts
const SHADOWED = [
  'fetch','caches','crypto','globalThis','self','Function','eval',
  'setTimeout','setInterval','setImmediate','queueMicrotask',
  'WebSocket','importScripts','XMLHttpRequest','Request','Response',
  'process','require','module','Deno','Bun',
];

function compileSnippet(code: string): (input: SnippetInput) => unknown {
  let fn: Function;
  try {
    fn = new Function('sources', 'row', 'raw', ...SHADOWED, `"use strict"; return (${code});`);
  } catch (e) {
    throw new IntegrationError(`snippet failed to compile: ${e instanceof Error ? e.message : String(e)}`, 400);
  }
  return (input: SnippetInput) =>
    fn(input.sources, input.row, input.raw, ...SHADOWED.map(() => undefined));
}
```

- **Expression form** (`return (${code})`) matches the per-connection contract — a snippet
  is an expression over `sources` (e.g. `sources[0] + ' (' + sources[1] + ')'`), consistent
  with built-ins. (`'import'` is a reserved word and cannot be a parameter name, so it is
  not in `SHADOWED`; `"use strict"` plus the expression form already blocks `import`
  statements.)
- **`createSnippetEvaluator`** returns a closure holding a `Map<string, compiled>` so each
  distinct snippet compiles once per flow run. A compile error throws on first encounter
  (before any row is processed for that snippet).
- **Per-row try/catch** lives in the executor (already present on transform/filter nodes;
  added to the map node) — a snippet that throws on a row → `{ nodeId, remoteId, message }`
  in `result.errors`, flow continues.

### Error handling (decision)

- **Compile error (syntax)** → `IntegrationError` thrown → flow aborts, `last_status='error'`.
  An authoring fault, surfaced loud and early (mirrors the unknown-hook structural error
  from Pass 4). Because compilation is memoized, the throw happens once, not per row.
- **Runtime error (snippet throws on a row's data)** → caught per-row into `result.errors`;
  the row is skipped, the flow continues. A data fault, degraded gracefully.

---

## Executor Map-Node Rewrite

`src/flow/execute.ts` — the `map` case changes from flat-projection to connection-application:

```ts
case 'map': {
  const cfg = node.config as MapConfig;
  const next: Row[] = [];
  for (const row of stream) {
    try {
      const current: Record<string, unknown> = {};
      for (const conn of cfg.connections) {
        const resolved = conn.sources.map((s) => row.current[s]);
        let value: unknown;
        if (!conn.transform) {
          value = resolved[0] === undefined ? null : resolved[0];
        } else if (conn.transform.kind === 'builtin') {
          const fn = BUILTINS[conn.transform.fn];
          if (!fn) throw new IntegrationError(`unknown builtin: ${conn.transform.fn}`, 400);
          value = fn(resolved, conn.transform.args ?? []);
        } else {
          if (!deps.evalSnippet) {
            throw new NotImplementedError('snippet transforms require the sandbox');
          }
          value = deps.evalSnippet(conn.transform.code, {
            sources: resolved,
            row: freeze(row.current),
            raw: freeze(row.raw),
          });
        }
        current[conn.target] = value;
      }
      next.push({ ...row, current });
    } catch (e) {
      if (e instanceof NotImplementedError || e instanceof IntegrationError) throw e; // structural
      errors.push({ nodeId: node.id, remoteId: row.remoteId, message: e instanceof Error ? e.message : String(e) });
    }
  }
  stream = next;
  break;
}
```

- **Structural errors abort** (unknown builtin, snippet-without-evalSnippet, snippet compile
  error — all `IntegrationError`/`NotImplementedError`, re-thrown out of the per-row catch).
- **Runtime errors per-row** (builtin or snippet throws on a row's data) → collected, flow
  continues — consistent with transform/filter node behavior.
- `freeze(x)` = `Object.freeze(Object.assign(Object.create(null), x))`.

Note: a row whose map node throws a runtime error is dropped from the stream (`next` does
not receive it), matching the "skip the bad row" semantics; `recordsOut` reflects only rows
that reach the destination.

---

## Compiler Change

`src/flow/compile.ts` — `invertFieldMap` now emits **1:1 connections** instead of a flat
record. For each `[remoteKey, localCol]` in the descriptor `fieldMap` where
`remoteKey !== idField`:

```ts
connections.push({ target: localCol, sources: [remoteKey] }); // no transform = pass-through
```

The map node config becomes `{ connections }`. Factorial's flat fieldMap → a list of
pass-through connections → byte-identical output. The idField entry is still skipped (it is
the fixed `remote_id`, handled by source/destination, not a connection).

---

## Host Wiring

`src/host/create-worker.ts` — construct `createSnippetEvaluator()` once at worker
construction and pass it as `evalSnippet` in the `ExecuteDeps` the host builds for sync
(and any other executor invocation). This is the single change that flips `kind:'snippet'`
connections from `NotImplementedError` to live execution. The sync wrapper in
`src/sync/index.ts` threads `evalSnippet` through to `executeFlow` alongside `hooks`.

---

## Testing

Vitest, in-memory better-sqlite3 adapter (`makeTestDb`). Coverage ≥ 80%.

- **`src/flow/transformers/builtins.test.ts`** — each of the 11 built-ins: happy path;
  null-source handling (null-preserving for string fns; `concat` null→`''`); arg variations
  (`concat` separator; `substring` start/end; `replace` search/replacement; `ifThenElse`
  both branches; `equals` true/false; `formatDate` `YYYY-MM-DD` + `YYYY-MM-DD HH:mm:ss` +
  invalid→null; `coalesce` fall-through to first non-null and all-null→null; `constant`
  ignores sources).
- **`src/flow/sandbox.test.ts`** — snippet happy path (expression over `sources`);
  **shadowing works** (`fetch`/`crypto`/`globalThis` resolve to `undefined`, calling them
  throws and is surfaced to the caller); prototype-escape attempt
  (`row.constructor.constructor`) does not yield a usable `Function` / throws; frozen inputs
  cannot be mutated by a snippet; `createSnippetEvaluator` compiles a given code string once
  (memoization observable, e.g. via a spy or identity check); compile error throws
  `IntegrationError`; a runtime throw propagates to the caller (for the executor's per-row
  capture).
- **`src/flow/execute.test.ts`** (extend) — map node: pass-through connection; builtin
  connection; snippet connection (with an injected `evalSnippet`); multi-source connection
  (e.g. `concat`); unknown-builtin throws `IntegrationError`; snippet connection without
  `evalSnippet` throws `NotImplementedError`; per-row builtin/snippet runtime error
  collected into `result.errors` while other rows still reach the destination.
- **`src/flow/compile.test.ts`** (extend) — flat `fieldMap` → 1:1 pass-through connections;
  idField still skipped; the connections are `{ target, sources:[remoteKey] }` with no
  transform.
- **Regression gate** (`src/flow/regression.test.ts`) — still green: Factorial's
  connections-form map produces byte-identical output to the Pass-4 baseline, including the
  hook-derived `full_name`. (Update the test's expected map shape from flat to connections
  if it constructs one directly; the asserted DB dump is unchanged.)
- `tsc --noEmit` + `npm run build` clean (no better-sqlite3 in bundle); Factorial
  `host-sync.test.ts` green against the rebuilt SDK.

---

## Public API Additions

New exports from `src/index.ts`:

```ts
export { BUILTINS, type BuiltinFn } from './flow/transformers';
export { compileSnippet, createSnippetEvaluator, type SnippetInput } from './flow/sandbox';
export type { Connection, TransformerRef } from './flow/types'; // MapConfig already exported, reshaped
```

## Out of Scope (this slice)

- The visual drag-and-drop mapping canvas (sub-project 5).
- Flow persistence / CRUD API (sub-project 3).
- Static authoring-time snippet linting (deferred defense-in-depth follow-up).
- `formatDate` locales/timezones/rich patterns (revisit per use case).
- Arithmetic/boolean-logic/type-coercion built-ins beyond the core set (custom snippet
  covers them until a real integration needs a built-in).
- A `filter`-node connection model — filters remain whole-row (`mode:'native'|'snippet'`);
  the connection model applies to the `map` node only.
