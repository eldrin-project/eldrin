# Field-Mapping Engine & Transformer Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the flow executor's `map` node into a CPI-style field-mapping engine — each target field a *connection* fed by N sources through a built-in transformer or a sandboxed custom snippet — in `@eldrin-project/eldrin-integration`.

**Architecture:** Reshape `MapConfig` from a flat `fields` record into `{ connections: Connection[] }`. Add a built-in transformer library (`src/flow/transformers/`) and a hardened `new Function` snippet sandbox (`src/flow/sandbox.ts`, the `evalSnippet` dep the executor already has a seam for). Rewrite the executor map node to apply connections; lower the descriptor's flat fieldMap into 1:1 connections in the compiler; inject the sandbox-backed `evalSnippet` through the host. The Pass-4 regression gate stays the safety net (Factorial → byte-identical output).

**Tech Stack:** TypeScript 5.9 (strict), Vitest, in-memory better-sqlite3 adapter (`makeTestDb` from `src/test-helpers.ts`).

## Global Constraints

- **SDK only.** All changes in `/Users/tibor/projects/eldrin-backup/eldrin-integration`. No UI, no flow persistence.
- **Immutability.** Never mutate `row.raw` or `row.current`; build new objects. Snippet inputs are frozen null-proto objects.
- **No `console.log`** in production code.
- **`MapConfig` reshape:** `{ connections: Connection[] }` REPLACES `fields: Record<string,string>`. A pass-through connection = `{ target, sources:[remoteKey] }` with no `transform`.
- **`Connection` ≠ `ConnectionConfig`:** the descriptor already exports `ConnectionConfig` (transport+auth). The new flow type is `Connection` (a field mapping). Do not confuse or merge them.
- **Transformer ref tagged union:** `{ kind:'builtin'; fn:string; args?:unknown[] } | { kind:'snippet'; code:string }`. Absent `transform` = pass-through of `sources[0]` (`undefined → null`).
- **Built-in signature uniform:** `(sources: unknown[], args: unknown[]) => unknown`.
- **Built-ins null-preserving:** string fns return `null` when `sources[0] == null` (not `"null"`); `concat` maps null/undefined parts to `''`.
- **Snippet sandbox:** shadowed `new Function` + null-proto frozen inputs + compile-once memoization + per-row try/catch in executor. Snippet input envelope is `{ sources, row, raw }`.
- **`ExecuteDeps.evalSnippet` RE-TYPED** from `(snippet: string, row: Row) => unknown` to `(code: string, input: SnippetInput) => unknown`. The transform/filter NODE snippet branches must adapt to pass a `SnippetInput` envelope (`{ sources: [], row: row.current, raw: row.raw }`, frozen).
- **Error split:** snippet *compile* errors throw `IntegrationError` (abort flow); builtin/snippet *runtime* errors caught per-row into `result.errors` (flow continues). Structural errors (`IntegrationError`/`NotImplementedError`) re-thrown out of the map node's per-row catch.
- **Regression preservation:** Factorial's connections-form map produces byte-identical D1 output to the Pass-4 baseline, including hook-derived `full_name`.
- **Coverage ≥ 80%.** Conventional commits, attribution disabled.
- Run tests from `/Users/tibor/projects/eldrin-backup/eldrin-integration` with `npx vitest run`.

---

## File Structure

- `src/flow/types.ts` (modify) — add `Connection`, `TransformerRef`, `SnippetInput`; reshape `MapConfig`; re-type `ExecuteDeps.evalSnippet`.
- `src/flow/transformers/index.ts` (new) — `BUILTINS` registry + `BuiltinFn` type + the 11 functions.
- `src/flow/transformers/index.test.ts` (new) — built-in unit tests.
- `src/flow/sandbox.ts` (new) — `compileSnippet`, `createSnippetEvaluator`, `SnippetInput`.
- `src/flow/sandbox.test.ts` (new) — sandbox unit tests.
- `src/flow/execute.ts` (modify) — rewrite map node to apply connections; adapt transform/filter snippet branches to `SnippetInput`.
- `src/flow/execute.test.ts` (modify) — extend with connection map-node tests.
- `src/flow/compile.ts` (modify) — `invertFieldMap` emits connections.
- `src/flow/compile.test.ts` (modify) — update fieldMap-inversion assertion to connections form.
- `src/flow/regression.test.ts` (modify if it constructs a flat map directly) — connections form; DB dump assertion unchanged.
- `src/sync/index.ts` (modify) — thread `evalSnippet` from `SyncDeps` into the `ExecuteDeps` passed to `executeFlow`.
- `src/host/create-worker.ts` (modify) — construct `createSnippetEvaluator()` once; pass through `buildDeps` → `SyncDeps.evalSnippet`.
- `src/index.ts` (modify) — export `BUILTINS`, `BuiltinFn`, `compileSnippet`, `createSnippetEvaluator`, `SnippetInput`, `Connection`, `TransformerRef`.

---

## Reference: current signatures (do not re-derive)

`src/flow/types.ts` current `MapConfig`: `{ fields: Record<string, string> }` (localCol→remoteKey).
`ExecuteDeps.evalSnippet?: (snippet: string, row: Row) => unknown` (to be re-typed).
`Row = { remoteId: string; raw: Record<string,unknown>; current: Record<string,unknown> }`.
`src/errors.ts`: `IntegrationError(message, status)`, `NotImplementedError(message)`.
`src/flow/compile.ts` `invertFieldMap(resource): Record<string,string>` (skips idField; `fields[localCol]=remoteKey`); map node emitted as `{ id:'map', kind:'map', config:{ fields: invertFieldMap(resource) } }`.
`src/sync/index.ts` `runResourceSync` builds `ExecuteDeps` inline at ~line 36 with `{ transport, db, hooks, now, genId }`; `SyncDeps` has optional `hooks?: HookRegistry`.
`src/host/create-worker.ts` `buildDeps(env, db)` returns `{ deps: SyncDeps, transport }`.
Test adapter: `makeTestDb(ddl: string[])` from `src/test-helpers.ts` (see existing `src/flow/*.test.ts` for usage; `ensureResourceTables(db, descriptor)` from `src/schema/ensure` creates resource tables).

---

### Task 1: Connection & transformer types; re-type evalSnippet

**Files:**
- Modify: `src/flow/types.ts`
- Test: `src/flow/types.test.ts` (extend)

**Interfaces:**
- Consumes: nothing new.
- Produces: `Connection`, `TransformerRef`, `SnippetInput`, reshaped `MapConfig`, re-typed `ExecuteDeps.evalSnippet`. Imported by Tasks 2–7.

- [ ] **Step 1: Write the failing test (append to `src/flow/types.test.ts`)**

```ts
import type { Connection, TransformerRef, SnippetInput, MapConfig } from './types';

describe('connection types', () => {
  it('constructs connection values: pass-through, builtin, snippet', () => {
    const passthrough: Connection = { target: 'email', sources: ['email'] };
    const builtin: Connection = { target: 'full_name', sources: ['first_name', 'last_name'], transform: { kind: 'builtin', fn: 'concat', args: [' '] } };
    const snippet: Connection = { target: 'label', sources: ['name'], transform: { kind: 'snippet', code: "sources[0] + '!'" } };
    const cfg: MapConfig = { connections: [passthrough, builtin, snippet] };
    expect(cfg.connections).toHaveLength(3);
    const ref: TransformerRef = builtin.transform!;
    expect(ref.kind).toBe('builtin');
    const input: SnippetInput = { sources: ['x'], row: { a: 1 }, raw: { a: 1 } };
    expect(input.sources[0]).toBe('x');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/flow/types.test.ts`
Expected: FAIL — `Connection`/`TransformerRef`/`SnippetInput` not exported.

- [ ] **Step 3: Edit `src/flow/types.ts`**

Replace the `MapConfig` interface (lines 39-41) with:

```ts
export interface Connection {
  target: string;                 // local column name (destination field)
  sources: string[];              // source field names, read from the row's current payload
  transform?: TransformerRef;     // absent = pass-through of sources[0]
}

export type TransformerRef =
  | { kind: 'builtin'; fn: string; args?: unknown[] }
  | { kind: 'snippet'; code: string };

export interface MapConfig {
  connections: Connection[];      // replaces the old flat `fields` record
}

export interface SnippetInput {
  sources: unknown[];
  row: Record<string, unknown>;
  raw: Record<string, unknown>;
}
```

In `ExecuteDeps` (line 77), replace the `evalSnippet` line with:

```ts
  evalSnippet?: (code: string, input: SnippetInput) => unknown;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/flow/types.test.ts`
Expected: PASS. (`npx tsc --noEmit` will FAIL here because execute.ts still calls the old `evalSnippet(snippet, row)` shape and the old `MapConfig.fields` — that is fixed in Tasks 4 & 5. Do not run tsc as a gate for this task; the suite for this file passes.)

- [ ] **Step 5: Commit**

```bash
git add src/flow/types.ts src/flow/types.test.ts
git commit -m "feat(flow): add connection/transformer types and re-type evalSnippet"
```

---

### Task 2: Built-in transformer library

**Files:**
- Create: `src/flow/transformers/index.ts`
- Test: `src/flow/transformers/index.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces: `BUILTINS: Record<string, BuiltinFn>`, `type BuiltinFn = (sources: unknown[], args: unknown[]) => unknown`. Consumed by Task 4 (executor) and Task 7 (exports).

- [ ] **Step 1: Write the failing test**

```ts
// src/flow/transformers/index.test.ts
import { describe, it, expect } from 'vitest';
import { BUILTINS } from './index';

describe('builtin transformers', () => {
  it('concat joins stringified sources with separator, null parts become empty', () => {
    expect(BUILTINS.concat(['Ada', 'Lovelace'], [' '])).toBe('Ada Lovelace');
    expect(BUILTINS.concat(['a', 'b'], [])).toBe('ab');
    expect(BUILTINS.concat(['Ada', null, 'L'], [' '])).toBe('Ada  L');
  });
  it('substring slices', () => {
    expect(BUILTINS.substring(['hello'], [0, 3])).toBe('hel');
    expect(BUILTINS.substring(['hello'], [2])).toBe('llo');
    expect(BUILTINS.substring([null], [0, 3])).toBeNull();
  });
  it('upperCase/lowerCase/trim are null-preserving', () => {
    expect(BUILTINS.upperCase(['ab'], [])).toBe('AB');
    expect(BUILTINS.lowerCase(['AB'], [])).toBe('ab');
    expect(BUILTINS.trim(['  x  '], [])).toBe('x');
    expect(BUILTINS.upperCase([null], [])).toBeNull();
    expect(BUILTINS.trim([undefined], [])).toBeNull();
  });
  it('replace replaces all occurrences, null-preserving', () => {
    expect(BUILTINS.replace(['a-b-c'], ['-', '_'])).toBe('a_b_c');
    expect(BUILTINS.replace([null], ['-', '_'])).toBeNull();
  });
  it('ifThenElse selects branch by truthiness of sources[0]', () => {
    expect(BUILTINS.ifThenElse([true], ['Y', 'N'])).toBe('Y');
    expect(BUILTINS.ifThenElse([0], ['Y', 'N'])).toBe('N');
  });
  it('equals strict-compares two sources', () => {
    expect(BUILTINS.equals([1, 1], [])).toBe(true);
    expect(BUILTINS.equals([1, '1'], [])).toBe(false);
  });
  it('formatDate formats with minimal tokens; invalid -> null', () => {
    expect(BUILTINS.formatDate(['2026-06-28T09:05:03Z'], ['YYYY-MM-DD'])).toBe('2026-06-28');
    expect(BUILTINS.formatDate(['2026-06-28T09:05:03Z'], ['YYYY-MM-DD HH:mm:ss'])).toBe('2026-06-28 09:05:03');
    expect(BUILTINS.formatDate(['not-a-date'], ['YYYY-MM-DD'])).toBeNull();
    expect(BUILTINS.formatDate([null], ['YYYY-MM-DD'])).toBeNull();
  });
  it('coalesce returns first non-nullish, else null', () => {
    expect(BUILTINS.coalesce([null, undefined, 'x', 'y'], [])).toBe('x');
    expect(BUILTINS.coalesce([null, undefined], [])).toBeNull();
  });
  it('constant ignores sources and returns the arg', () => {
    expect(BUILTINS.constant(['ignored'], ['fixed'])).toBe('fixed');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/flow/transformers/index.test.ts`
Expected: FAIL — `Cannot find module './index'`.

- [ ] **Step 3: Write implementation**

```ts
// src/flow/transformers/index.ts
export type BuiltinFn = (sources: unknown[], args: unknown[]) => unknown;

const s = (v: unknown): string => String(v);
const isNullish = (v: unknown): boolean => v === null || v === undefined;

function pad(n: number, width: number): string {
  return String(n).padStart(width, '0');
}

function formatDate(sources: unknown[], args: unknown[]): unknown {
  if (isNullish(sources[0])) return null;
  const d = new Date(sources[0] as string | number);
  if (Number.isNaN(d.getTime())) return null;
  const pattern = (args[0] as string) ?? 'YYYY-MM-DD';
  return pattern
    .replace(/YYYY/g, pad(d.getUTCFullYear(), 4))
    .replace(/MM/g, pad(d.getUTCMonth() + 1, 2))
    .replace(/DD/g, pad(d.getUTCDate(), 2))
    .replace(/HH/g, pad(d.getUTCHours(), 2))
    .replace(/mm/g, pad(d.getUTCMinutes(), 2))
    .replace(/ss/g, pad(d.getUTCSeconds(), 2));
}

export const BUILTINS: Record<string, BuiltinFn> = {
  concat: (sources, args) => sources.map((v) => (isNullish(v) ? '' : s(v))).join((args[0] as string) ?? ''),
  substring: (sources, args) => (isNullish(sources[0]) ? null : s(sources[0]).slice(args[0] as number, args[1] as number | undefined)),
  upperCase: (sources) => (isNullish(sources[0]) ? null : s(sources[0]).toUpperCase()),
  lowerCase: (sources) => (isNullish(sources[0]) ? null : s(sources[0]).toLowerCase()),
  trim: (sources) => (isNullish(sources[0]) ? null : s(sources[0]).trim()),
  replace: (sources, args) => (isNullish(sources[0]) ? null : s(sources[0]).replaceAll(s(args[0]), s(args[1]))),
  ifThenElse: (sources, args) => (sources[0] ? args[0] : args[1]),
  equals: (sources) => sources[0] === sources[1],
  formatDate,
  coalesce: (sources) => {
    for (const v of sources) if (!isNullish(v)) return v;
    return null;
  },
  constant: (_sources, args) => args[0],
};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/flow/transformers/index.test.ts`
Expected: PASS (all 10 tests).

- [ ] **Step 5: Commit**

```bash
git add src/flow/transformers/index.ts src/flow/transformers/index.test.ts
git commit -m "feat(flow): add built-in transformer library"
```

---

### Task 3: Snippet sandbox

**Files:**
- Create: `src/flow/sandbox.ts`
- Test: `src/flow/sandbox.test.ts`

**Interfaces:**
- Consumes: `SnippetInput` from `./types` (Task 1); `IntegrationError` from `../errors`.
- Produces: `compileSnippet(code): (input: SnippetInput) => unknown`, `createSnippetEvaluator(): (code: string, input: SnippetInput) => unknown`. Consumed by Task 4 (executor uses the evaluator via `deps.evalSnippet`) and Task 6 (host constructs it).

- [ ] **Step 1: Write the failing test**

```ts
// src/flow/sandbox.test.ts
import { describe, it, expect, vi } from 'vitest';
import { compileSnippet, createSnippetEvaluator } from './sandbox';
import { IntegrationError } from '../errors';
import type { SnippetInput } from './types';

const input = (over: Partial<SnippetInput> = {}): SnippetInput => ({ sources: [], row: {}, raw: {}, ...over });

describe('snippet sandbox', () => {
  it('evaluates an expression over sources', () => {
    const fn = compileSnippet("sources[0] + ' ' + sources[1]");
    expect(fn(input({ sources: ['Ada', 'Lovelace'] }))).toBe('Ada Lovelace');
  });
  it('can read row and raw', () => {
    const fn = compileSnippet('row.a + raw.b');
    expect(fn(input({ row: { a: 1 }, raw: { b: 2 } }))).toBe(3);
  });
  it('shadows dangerous globals (fetch is undefined inside the snippet)', () => {
    const fn = compileSnippet('typeof fetch');
    expect(fn(input())).toBe('undefined');
  });
  it('calling a shadowed global throws (surfaced to caller)', () => {
    const fn = compileSnippet('fetch("x")');
    expect(() => fn(input())).toThrow();
  });
  it('throws IntegrationError on a syntax (compile) error', () => {
    expect(() => compileSnippet('sources[0] +')).toThrow(IntegrationError);
  });
  it('createSnippetEvaluator compiles a given code string once (memoized)', () => {
    const evaluator = createSnippetEvaluator();
    // Same code string twice; identity of the underlying compiled fn is hidden,
    // so assert behavior + that a second call with the same code still works without recompiling.
    // We prove memoization by spying on Function via a flaky-proof approach: count distinct results.
    expect(evaluator('sources[0]', input({ sources: [1] }))).toBe(1);
    expect(evaluator('sources[0]', input({ sources: [2] }))).toBe(2);
  });
  it('memoized evaluator surfaces a compile error once on first use', () => {
    const evaluator = createSnippetEvaluator();
    expect(() => evaluator('bad +', input())).toThrow(IntegrationError);
  });
});
```

Note on the memoization test: identity of the compiled function is internal. To make the memoization observable, implement `createSnippetEvaluator` so it caches by code string; the test above asserts correct repeated behavior. Additionally add this stronger memoization assertion using a global spy:

```ts
it('does not recompile the same code string (Function constructor called once)', () => {
  const evaluator = createSnippetEvaluator();
  const spy = vi.spyOn(globalThis, 'Function');
  evaluator('sources[0]', input({ sources: ['a'] }));
  const afterFirst = spy.mock.calls.length;
  evaluator('sources[0]', input({ sources: ['b'] }));
  expect(spy.mock.calls.length).toBe(afterFirst); // no new Function call for the same code
  spy.mockRestore();
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/flow/sandbox.test.ts`
Expected: FAIL — `Cannot find module './sandbox'`.

- [ ] **Step 3: Write implementation**

```ts
// src/flow/sandbox.ts
import { IntegrationError } from '../errors';
import type { SnippetInput } from './types';

// Denylist of dangerous globals shadowed to undefined inside every snippet.
// NOTE: 'import' is a reserved word and cannot be a parameter name; "use strict"
// + the expression form already block import statements, so it is omitted here.
const SHADOWED = [
  'fetch', 'caches', 'crypto', 'globalThis', 'self', 'Function', 'eval',
  'setTimeout', 'setInterval', 'setImmediate', 'queueMicrotask',
  'WebSocket', 'importScripts', 'XMLHttpRequest', 'Request', 'Response',
  'process', 'require', 'module', 'Deno', 'Bun',
];

function freeze(o: Record<string, unknown>): Record<string, unknown> {
  return Object.freeze(Object.assign(Object.create(null), o));
}

export function compileSnippet(code: string): (input: SnippetInput) => unknown {
  let fn: (...a: unknown[]) => unknown;
  try {
    // eslint-disable-next-line no-new-func
    fn = new Function('sources', 'row', 'raw', ...SHADOWED, `"use strict"; return (${code});`) as (...a: unknown[]) => unknown;
  } catch (e) {
    throw new IntegrationError(`snippet failed to compile: ${e instanceof Error ? e.message : String(e)}`, 400);
  }
  const undefinedTail = SHADOWED.map(() => undefined);
  return (input: SnippetInput) => fn(input.sources, freeze(input.row), freeze(input.raw), ...undefinedTail);
}

export function createSnippetEvaluator(): (code: string, input: SnippetInput) => unknown {
  const cache = new Map<string, (input: SnippetInput) => unknown>();
  return (code: string, input: SnippetInput) => {
    let compiled = cache.get(code);
    if (!compiled) {
      compiled = compileSnippet(code); // a compile error throws here, on first use
      cache.set(code, compiled);
    }
    return compiled(input);
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/flow/sandbox.test.ts`
Expected: PASS. If the `vi.spyOn(globalThis,'Function')` memoization test is flaky in the runtime (Function may not be spyable), keep the behavioral memoization test and remove the spy variant — note this in the report.

- [ ] **Step 5: Commit**

```bash
git add src/flow/sandbox.ts src/flow/sandbox.test.ts
git commit -m "feat(flow): add hardened snippet sandbox (new Function with shadowed globals)"
```

---

### Task 4: Executor map-node rewrite + snippet-branch adaptation

**Files:**
- Modify: `src/flow/execute.ts`
- Test: `src/flow/execute.test.ts` (extend)

**Interfaces:**
- Consumes: `MapConfig`/`Connection`/`SnippetInput` (Task 1); `BUILTINS` (Task 2); the `evalSnippet` dep shape (`(code, SnippetInput) => unknown`).
- Produces: a map node that applies connections; transform/filter snippet branches that pass `SnippetInput`.

- [ ] **Step 1: Write the failing tests (append to `src/flow/execute.test.ts`)**

```ts
// --- appended to src/flow/execute.test.ts ---
// Uses the existing dbSpy()/linearFlow helpers in this file. If linearFlow builds a
// map node from a flat `fields` record, add a connection-based variant:

function mapFlow(connections: import('./types').Connection[], extra: import('./types').FlowNode[] = []): Flow {
  const nodes: import('./types').FlowNode[] = [
    { id: 'source', kind: 'source', config: { transport: { method: 'GET', path: '/r' }, idField: 'id' } },
    { id: 'map', kind: 'map', config: { connections } },
    ...extra,
    { id: 'destination', kind: 'destination', config: { kind: 'd1', table: 'employees', mode: 'stored' } },
  ];
  const edges = [];
  for (let i = 0; i < nodes.length - 1; i++) edges.push({ from: nodes[i].id, to: nodes[i + 1].id });
  return { id: 'i:employees', integrationId: 'i', trigger: { kind: 'manual' }, nodes, edges };
}

describe('executeFlow map node connections', () => {
  it('pass-through connection copies source to target (undefined -> null)', async () => {
    const { db, upserts } = dbSpy();
    const deps: ExecuteDeps = {
      transport: { fetchAll: async () => [{ id: 1, email: 'a@x.io' }] },
      db, hooks: {}, now: () => 1, genId: () => 'g',
    };
    await executeFlow(mapFlow([{ target: 'email', sources: ['email'] }, { target: 'missing', sources: ['nope'] }]), deps);
    // email mapped, missing -> null
    expect(upserts[0].values).toContain('a@x.io');
    expect(upserts[0].values).toContain(null);
  });

  it('builtin connection applies the transformer (concat over two sources)', async () => {
    const { db, upserts } = dbSpy();
    const deps: ExecuteDeps = {
      transport: { fetchAll: async () => [{ id: 1, first_name: 'Ada', last_name: 'Lovelace' }] },
      db, hooks: {}, now: () => 1, genId: () => 'g',
    };
    await executeFlow(mapFlow([{ target: 'full_name', sources: ['first_name', 'last_name'], transform: { kind: 'builtin', fn: 'concat', args: [' '] } }]), deps);
    expect(upserts[0].values).toContain('Ada Lovelace');
  });

  it('unknown builtin throws IntegrationError (structural, aborts)', async () => {
    const { db } = dbSpy();
    const deps: ExecuteDeps = { transport: { fetchAll: async () => [{ id: 1 }] }, db, hooks: {}, now: () => 1, genId: () => 'g' };
    await expect(executeFlow(mapFlow([{ target: 't', sources: ['x'], transform: { kind: 'builtin', fn: 'nope' } }]), deps)).rejects.toThrow(/unknown builtin/i);
  });

  it('snippet connection runs via injected evalSnippet', async () => {
    const { db, upserts } = dbSpy();
    const deps: ExecuteDeps = {
      transport: { fetchAll: async () => [{ id: 1, name: 'X' }] },
      db, hooks: {}, now: () => 1, genId: () => 'g',
      evalSnippet: (code, inp) => `${inp.sources[0]}!`,
    };
    await executeFlow(mapFlow([{ target: 'label', sources: ['name'], transform: { kind: 'snippet', code: "sources[0]+'!'" } }]), deps);
    expect(upserts[0].values).toContain('X!');
  });

  it('snippet connection without evalSnippet throws NotImplementedError', async () => {
    const { db } = dbSpy();
    const deps: ExecuteDeps = { transport: { fetchAll: async () => [{ id: 1, name: 'X' }] }, db, hooks: {}, now: () => 1, genId: () => 'g' };
    await expect(executeFlow(mapFlow([{ target: 'label', sources: ['name'], transform: { kind: 'snippet', code: 'x' } }]), deps)).rejects.toThrow(NotImplementedError);
  });

  it('per-row builtin runtime error is collected; other rows still upsert', async () => {
    const { db, upserts } = dbSpy();
    const deps: ExecuteDeps = {
      transport: { fetchAll: async () => [{ id: 1, val: 'ok' }, { id: 2, val: 'boom' }] },
      db, hooks: {}, now: () => 1, genId: () => 'g',
      evalSnippet: (code, inp) => { if (inp.sources[0] === 'boom') throw new Error('kaboom'); return inp.sources[0]; },
    };
    const result = await executeFlow(mapFlow([{ target: 'val', sources: ['val'], transform: { kind: 'snippet', code: 'sources[0]' } }]), deps);
    expect(result.recordsOut).toBe(1);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toMatchObject({ nodeId: 'map', remoteId: '2', message: 'kaboom' });
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/flow/execute.test.ts`
Expected: FAIL — map node still reads `cfg.fields`; connection configs produce wrong output / errors.

- [ ] **Step 3: Rewrite the map node case in `src/flow/execute.ts`**

Update the import line (add `Connection` is not needed; `MapConfig` already imported) and add the BUILTINS import at top:

```ts
import { BUILTINS } from './transformers';
```

Replace the entire `case 'map': { ... break; }` block (lines 87-102) with:

```ts
      case 'map': {
        const cfg = node.config as MapConfig;
        const next: Row[] = [];
        for (const row of stream) {
          try {
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
                if (!deps.evalSnippet) {
                  throw new NotImplementedError('snippet transforms require the sandbox');
                }
                value = deps.evalSnippet(conn.transform.code, {
                  sources: resolved,
                  row: row.current,
                  raw: row.raw,
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

Then adapt the transform NODE snippet branch (line 114) and filter NODE snippet branch (line 138) to the new `evalSnippet` envelope signature. For transform (line 114):

```ts
              next.push({ ...row, current: deps.evalSnippet!(cfg.snippet, { sources: [], row: row.current, raw: row.raw }) as Record<string, unknown> });
```

For filter (line 138):

```ts
              if (deps.evalSnippet!(cfg.snippet, { sources: [], row: row.current, raw: row.raw })) next.push(row);
```

(The sandbox freezes `row`/`raw` internally, so passing `row.current`/`row.raw` here is correct — do not freeze at the call site.)

**Also align the transform and filter node per-row catches** so a snippet *compile* error (an `IntegrationError` thrown by the real `evalSnippet`) aborts the flow instead of being swallowed per-row. In BOTH the transform-node catch (currently `if (e instanceof NotImplementedError) throw e;`) and the filter-node catch, change the re-throw guard to also re-throw `IntegrationError`:

```ts
          } catch (e) {
            if (e instanceof NotImplementedError || e instanceof IntegrationError) throw e; // structural, not per-record
            errors.push({ nodeId: node.id, remoteId: row.remoteId, message: e instanceof Error ? e.message : String(e) });
          }
```

This matches the map node's catch and the spec's compile-error-aborts / runtime-error-per-row split. (A runtime error from a native hook is a plain `Error`, so it is still collected per-row; only structural `IntegrationError`/`NotImplementedError` abort.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run src/flow/execute.test.ts`
Expected: PASS (existing executor tests + the 6 new connection tests). Then `npx tsc --noEmit` — note it may still fail until compile.ts (Task 5) is updated, because the compiler still emits `{ fields }`. That's expected; the execute.test.ts suite passes.

- [ ] **Step 5: Commit**

```bash
git add src/flow/execute.ts src/flow/execute.test.ts
git commit -m "feat(flow): apply connections in map node and adapt snippet branches to SnippetInput"
```

---

### Task 5: Compiler emits connections

**Files:**
- Modify: `src/flow/compile.ts`
- Test: `src/flow/compile.test.ts` (update inversion assertion)

**Interfaces:**
- Consumes: `Connection`/`MapConfig` (Task 1).
- Produces: compiler that lowers the descriptor's flat fieldMap into 1:1 pass-through connections.

- [ ] **Step 1: Update the failing test in `src/flow/compile.test.ts`**

Replace the "inverts fieldMap into map.fields" test with the connections form:

```ts
  it('lowers fieldMap into 1:1 pass-through connections and skips the idField entry', () => {
    const flow = compileResourceToFlow('factorial', resource({
      idField: 'id',
      fieldMap: { id: 'emp_id', remote_first: 'first_name', remote_last: 'last_name' },
    }));
    const map = flow.nodes.find((n) => n.id === 'map')!;
    expect((map.config as { connections: unknown[] }).connections).toEqual([
      { target: 'first_name', sources: ['remote_first'] },
      { target: 'last_name', sources: ['remote_last'] },
    ]);
  });
```

(Direction note: descriptor fieldMap is `remoteKey → localCol`, so `remote_first → first_name`; the connection is `{ target: localCol, sources: [remoteKey] }` = `{ target:'first_name', sources:['remote_first'] }`. The `id → emp_id` entry is skipped because remoteKey `id` === idField.)

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/flow/compile.test.ts`
Expected: FAIL — compiler still emits `{ fields }`.

- [ ] **Step 3: Edit `src/flow/compile.ts`**

Replace `invertFieldMap` (lines 10-16) with a connections builder:

```ts
import type { Connection } from './types';

function fieldMapToConnections(resource: ResourceDescriptor): Connection[] {
  const connections: Connection[] = [];
  for (const [remoteKey, localCol] of Object.entries(resource.fieldMap)) {
    if (remoteKey === resource.idField) continue; // fixed remote_id column
    connections.push({ target: localCol, sources: [remoteKey] });
  }
  return connections;
}
```

Replace the map node emission (line 41) with:

```ts
  nodes.push({ id: 'map', kind: 'map', config: { connections: fieldMapToConnections(resource) } });
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/flow/compile.test.ts`
Expected: PASS (all compile tests).

- [ ] **Step 5: Commit**

```bash
git add src/flow/compile.ts src/flow/compile.test.ts
git commit -m "feat(flow): compile descriptor fieldMap into 1:1 connections"
```

---

### Task 6: Host wiring — inject the snippet evaluator

**Files:**
- Modify: `src/sync/index.ts`
- Modify: `src/host/create-worker.ts`
- Test: covered by the full suite + a host integration assertion (below)

**Interfaces:**
- Consumes: `createSnippetEvaluator` (Task 3); the re-typed `ExecuteDeps.evalSnippet`.
- Produces: `evalSnippet` threaded from worker construction → `SyncDeps` → `ExecuteDeps`.

- [ ] **Step 1: Write the failing test**

Add a test to `src/flow/execute-integration.test.ts` proving the real sandbox runs a snippet connection end-to-end against the in-memory DB:

```ts
import { createSnippetEvaluator } from './sandbox';

it('runs a snippet-connection map end-to-end with the real sandbox', async () => {
  const db = makeTestDb([]);
  const resource = {
    name: 'people', transport: { method: 'GET', path: '/people' }, idField: 'id',
    fieldMap: { id: 'unused', label: 'label' }, supportedModes: ['stored'], defaultMode: 'stored',
  } as const;
  await ensureResourceTables(db as any, { id: 'i', connection: { transport: 'http', baseUrl: 'x', auth: { strategy: 'apiKey' } }, resources: [resource as any] });
  // Build a flow with a snippet connection by hand (compiler emits pass-through; we override map)
  const { compileResourceToFlow } = await import('./compile');
  const flow = compileResourceToFlow('i', resource as any);
  const map = flow.nodes.find((n) => n.id === 'map')!;
  (map.config as any).connections = [{ target: 'label', sources: ['name'], transform: { kind: 'snippet', code: "sources[0].toUpperCase()" } }];
  const { executeFlow } = await import('./execute');
  const result = await executeFlow(flow, {
    transport: { fetchAll: async () => [{ id: 1, name: 'ada' }] },
    db: db as any, hooks: {}, now: () => 1, genId: () => 'g',
    evalSnippet: createSnippetEvaluator(),
  });
  expect(result.recordsOut).toBe(1);
  const row = await (db as any).prepare('SELECT label FROM "people" WHERE remote_id = ?').bind('1').first();
  expect(row.label).toBe('ADA');
});
```

- [ ] **Step 2: Run test to verify it fails or passes**

Run: `npx vitest run src/flow/execute-integration.test.ts`
Expected: PASS once Tasks 1-4 are in (it exercises built units with the real evaluator). If it fails, the message localizes the issue. This test does not depend on the host wiring below — it proves the evaluator + executor integrate; the host wiring (Steps 3-4) makes the WORKER pass it automatically.

- [ ] **Step 3: Thread `evalSnippet` through `src/sync/index.ts`**

In `SyncDeps` add `evalSnippet?`:

```ts
export interface SyncDeps {
  db: DatabaseAdapter;
  transport: Transport;
  now: () => number;
  genId: () => string;
  hooks?: HookRegistry;
  evalSnippet?: (code: string, input: import('../flow/types').SnippetInput) => unknown;
}
```

In `runResourceSync`, pass it into the `executeFlow` deps (the object built ~line 36):

```ts
    const result = await executeFlow(flow, {
      transport: deps.transport,
      db: deps.db,
      hooks,
      now: deps.now,
      genId: deps.genId,
      evalSnippet: deps.evalSnippet,
    });
```

- [ ] **Step 4: Construct the evaluator in `src/host/create-worker.ts`**

Add the import:

```ts
import { createSnippetEvaluator } from '../flow/sandbox';
```

Construct it once at worker scope (near where `seed` is built, ~line 73):

```ts
  const evalSnippet = createSnippetEvaluator();
```

In `buildDeps`, include it in the returned `SyncDeps`:

```ts
    // inside the returned deps object:
    evalSnippet,
```

(Find the `buildDeps` return; add `evalSnippet` to the `deps` object alongside `db`, `transport`, `now`, `genId`, `hooks`.)

- [ ] **Step 5: Run the full suite + typecheck + build**

Run: `npx vitest run && npx tsc --noEmit && npm run build`
Expected: all tests PASS, no type errors, build succeeds (no better-sqlite3 in bundle).

- [ ] **Step 6: Commit**

```bash
git add src/sync/index.ts src/host/create-worker.ts src/flow/execute-integration.test.ts
git commit -m "feat(flow): wire the snippet evaluator through the host into sync"
```

---

### Task 7: Exports, regression gate, coverage, README

**Files:**
- Modify: `src/index.ts`
- Modify (if needed): `src/flow/regression.test.ts`
- Modify: `README.md`

**Interfaces:**
- Consumes: all prior tasks.
- Produces: public API exports; verified regression parity; docs.

- [ ] **Step 1: Update `src/index.ts` exports**

Add to the flow exports block (near line 29-35):

```ts
export { BUILTINS, type BuiltinFn } from './flow/transformers';
export { compileSnippet, createSnippetEvaluator, type SnippetInput } from './flow/sandbox';
export type { Connection, TransformerRef } from './flow/types';
```

(`MapConfig` is already exported from the `./flow/types` type block — it is now the reshaped version automatically; no change needed there.)

- [ ] **Step 2: Verify/fix the regression gate**

Run: `npx vitest run src/flow/regression.test.ts`
Expected: PASS. If it FAILS because the test constructs a map node with the old `{ fields }` shape, update that construction to `{ connections: [...] }` (1:1 pass-through connections mirroring the fixture's fieldMap; for the `full_name` derived column, the regression fixture's transform NODE still derives it — keep the transform node, the connections are the pass-through projections). The asserted DB dump (the parity comparison) must NOT change. If the test passes unchanged, do nothing.

- [ ] **Step 3: Run the full suite with coverage**

Run: `npx vitest run --coverage`
Expected: all PASS; `src/flow/` (incl. `transformers/` and `sandbox.ts`) line coverage ≥ 80%.

- [ ] **Step 4: Verify Factorial still works against the rebuilt SDK**

Run:
```bash
npm run build
cd /Users/tibor/projects/eldrin-backup/eldrin-factorial && npx vitest run worker/__tests__/host-sync.test.ts
```
Expected: PASS — `full_name` still derived ('Grace Hopper'); the connections-form map produces identical output. Report the result.

- [ ] **Step 5: Update README**

In `eldrin-integration/README.md`, extend the "Flow model" subsection: the `map` node is now a list of *connections* (target ← sources via a built-in transformer or a custom snippet); list the built-in library names; note that custom snippets run in a hardened `new Function` sandbox (shadowed globals, frozen inputs, admin-authored) with the documented residual limits (no CPU/timeout guard); the descriptor's flat fieldMap compiles into 1:1 pass-through connections. ~12 lines, matching existing tone. Do NOT claim a CPU/timeout sandbox exists.

- [ ] **Step 6: Commit**

```bash
git add src/index.ts src/flow/regression.test.ts README.md
git commit -m "feat(flow): export mapping engine API; verify regression parity; document"
```

---

## Post-implementation: live verification (manual, not a task)

After all tasks pass and the SDK is rebuilt: add a snippet or builtin connection to Factorial's `integration.config.json` (e.g. a `formatDate` on a timeoff date, or a snippet), restart the preview, and confirm the transformed column renders. (Optional — the host-sync test already proves the engine end-to-end.)

## Notes

- **`Connection` vs `ConnectionConfig`:** the descriptor's `ConnectionConfig` (transport+auth) is unrelated to the flow `Connection` (a field mapping). Keep them distinct; do not import one where the other is meant.
- **Sandbox call site does not freeze:** `compileSnippet`'s returned evaluator freezes `row`/`raw` internally. The executor passes `row.current`/`row.raw` raw; do not double-freeze.
- **`evalSnippet` envelope is uniform:** map-connection snippets pass real `sources`; transform/filter NODE snippets pass `sources: []` (no connection sources at the node level). Same signature everywhere.
