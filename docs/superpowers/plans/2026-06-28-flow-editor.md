# Flow Editor (form-based) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Integrations studio writable — an admin edits a flow's map connections + trigger and saves via `POST /api/flows/:id` with optimistic lock — plus the five SDK/manifest prerequisites the editor needs.

**Architecture:** Five small prereqs first: `validateFlow` accepts compiler hook slots; `GET /api/flows/effective` (compiled+stored overlay); `BUILTIN_SPECS` + `GET /api/flows/builtin-specs`; Factorial manifest declares `/api/flows` routes. Then the eldrin-core editor: pure `toFlowDraft`/`applyDraft` + `saveFlow` (unit-tested), a revised effective-flow list, and a thin `FlowEditor` (trigger form + connection rows with typed builtin args from fetched specs), with 200/400/409 save handling.

**Tech Stack:** SDK: TypeScript + Vitest. Shell: React 19 + React Router 7 + shadcn/ui + Tailwind 4 + react-i18next; Vitest + Playwright.

## Global Constraints

- **Two repos, sequenced:** Tasks 1-4 in `/Users/tibor/projects/eldrin-backup/eldrin-integration` (SDK) + `/Users/tibor/projects/eldrin-backup/eldrin-factorial` (manifest); Tasks 5-9 in `/Users/tibor/projects/eldrin-backup/eldrin-core` (shell). SDK ships first (UI depends on all of it).
- **Editable scope:** the map node's connections + the flow trigger ONLY. Source/native-transform/destination nodes + edges are read-only and preserved verbatim.
- **`validateFlow` hook fix:** a native transform/filter hook name is valid if it's in `ctx.hooks` (registry fn name) OR in `ctx.hookSlots` (descriptor slots). The route passes `hookSlots: new Set(['transform','beforeUpsert'])` (fixed; the only slots the compiler emits).
- **`GET /api/flows/effective`:** admin-gated (resolveUserId→401, isAdmin→403); returns `[{ flow, version:number|null, stored:boolean }]` (compiled overlaid by stored). MUST register BEFORE `/api/flows/:id` (Hono ordering — else `:id` captures `effective`).
- **`BUILTIN_SPECS`:** one entry per `BUILTINS` key; `BuiltinArg = { name:string; type:'string'|'number'; optional?:boolean }`. `GET /api/flows/builtin-specs` returns it, admin-gated, registered before `/api/flows/:id`.
- **Manifest routes (factorial):** declare GET `/api/flows`, `/api/flows/effective`, `/api/flows/builtin-specs`, `/api/flows/:id` as `flows:read`; POST + DELETE `/api/flows/:id` as `flows:admin`.
- **`applyDraft` preserves non-map structure verbatim** — deep-copy original, replace only `map.config.connections` + `flow.trigger`. Never regenerate source/transform/destination/edges.
- **Save UX:** POST `{flow, baseVersion}`; 200 → "Saved (v{N+1})" + bump baseVersion in state; 400 → inline validation message (keep edits); 409 → "Changed elsewhere — Reload". Respect the optimistic lock (always send baseVersion).
- **Create override:** seed editor with the compiled-default flow (from `/effective`, `stored:false`), save with `baseVersion:null` → version 1.
- **Cross-repo:** shell does NOT import the SDK; mirror only the `BuiltinArg` TYPE locally; spec VALUES come from the `/builtin-specs` endpoint at runtime. Reuse SP4a's `authFetch` injection, `Result<T>`, proxy path.
- **No `@testing-library/react`** (SP4a standing decision); pure-logic Vitest units + one Playwright smoke. Immutability; no `console.log`; conventional commits, attribution disabled. Coverage ≥ 80% on the pure units.
- SDK tests: `cd eldrin-integration && npx vitest run`. Shell tests: `cd eldrin-core && npx vitest run`.

---

## File Structure

**eldrin-integration:**
- `src/flow/validate.ts` (modify) — `hookSlots` in `FlowValidationContext` + the native-hook check.
- `src/flow/validate.test.ts` (modify) — slot-name acceptance tests.
- `src/flow/transformers/specs.ts` (new) — `BuiltinArg`, `BUILTIN_SPECS`.
- `src/flow/transformers/specs.test.ts` (new) — specs-match-builtins.
- `src/host/create-worker.ts` (modify) — pass `hookSlots`; add `/api/flows/effective` + `/api/flows/builtin-specs` routes (before `:id`); import `compileDescriptorToFlows`, `BUILTIN_SPECS`.
- `src/host/create-worker.test.ts` (modify) — effective + builtin-specs route tests.
- `src/index.ts` (modify) — export `BUILTIN_SPECS`, `BuiltinArg`.

**eldrin-factorial:**
- `public/eldrin-app.manifest.json` (modify) — declare `/api/flows` routes.

**eldrin-core:**
- `src/pages/integrations/integrations-api.ts` (modify) — `EffectiveFlow`, `BuiltinArg`, `fetchEffectiveFlows`, `fetchBuiltinSpecs`.
- `src/pages/integrations/integrations-api.test.ts` (modify) — parse tests.
- `src/pages/integrations/flow-edit-model.ts` (new) + `.test.ts` — `toFlowDraft`/`applyDraft`.
- `src/pages/integrations/save-flow.ts` (new) + `.test.ts` — `saveFlow`.
- `src/pages/integrations/IntegrationList.tsx` (modify) — read `/effective`; edit/create-override.
- `src/pages/integrations/FlowEditor.tsx` (new) — trigger form + connection rows + save.
- `src/pages/integrations/ConnectionRowEditor.tsx` (new) — one connection row.
- `src/locales/en/integrations.json` (modify) — editor strings.
- `e2e/flow-editor.spec.ts` (new) — Playwright smoke.

---

## Reference: current code (do not re-derive)

**SDK** `src/flow/validate.ts:9` `FlowValidationContext { hooks: HookRegistry; knownTables: Set<string> }`; line 58 native-hook check `if (!ctx.hooks[cfg.hook]) fail(...)`; `validateConnection` (line 74) handles builtin/snippet. `src/flow/transformers/index.ts`: `BUILTINS: Record<string, BuiltinFn>` (keys: concat, substring, upperCase, lowerCase, trim, replace, ifThenElse, equals, formatDate, coalesce, constant). `create-worker.ts:22` imports `{ readFlow, listFlows, writeFlow, deleteFlow }` from `../flow/store`; flows routes at 158 (`GET /api/flows`), 167 (`GET /api/flows/:id`), 176 (`POST`), 194 (`DELETE`); `compileDescriptorToFlows` is from `../flow/compile` (NOT yet imported here). Admin gate pattern: `const userId = resolveUserId(c); if (!userId) return c.json({error:'Unauthorized'},401); if (!isAdmin(c)) return c.json({error:'Forbidden: admin role required'},403);`. The POST handler validates with `validateFlow(body.flow, { hooks: boundHooks, knownTables: new Set(effective.resources.map(r=>r.name)) })` — add `hookSlots` there too.

**Shell** `src/pages/integrations/integrations-api.ts`: already exports `Result<T>`, `AuthFetch`, `FlowSummary`, `FlowGraph`, `StoredFlow`, `flowsUrl`, `fetchFlows`, `fetchFlow`, and an internal `call<T>(p)` helper. `IntegrationList.tsx`: `IntegrationCard({id,label})` uses `fetchFlows(id, getAuthFetch())` → `FlowSummary[]`, `getAuthFetch()` reads `window.__ELDRIN__.authenticatedFetch`. `FlowGraph` shape: `{ id, integrationId, trigger: {kind:'cron',expr}|{kind:'webhook',event}|{kind:'manual'}, nodes: {id,kind,config}[], edges:{from,to,when?}[] }`. Map node config: `{ connections: {target, sources:string[], transform?: {kind:'builtin',fn,args?}|{kind:'snippet',code}}[] }`.

**Factorial manifest** `public/eldrin-app.manifest.json` `api.routes` is an array of `{method,path,permission}`; append to it.

---

### Task 1: SDK — `validateFlow` accepts compiler hook slots

**Repo:** `/Users/tibor/projects/eldrin-backup/eldrin-integration`

**Files:**
- Modify: `src/flow/validate.ts`
- Test: `src/flow/validate.test.ts`

**Interfaces:**
- Produces: `FlowValidationContext` with optional `hookSlots?: Set<string>`; native-hook check accepts registry name OR slot.

- [ ] **Step 1: Write the failing test (append to `src/flow/validate.test.ts`)**

```ts
describe('validateFlow native hook slot acceptance', () => {
  function flowWithNativeHook(hookName: string): Flow {
    return {
      id: 'i:r', integrationId: 'i', trigger: { kind: 'manual' },
      nodes: [
        { id: 'source', kind: 'source', config: { transport: { method: 'GET', path: '/r' }, idField: 'id' } as never },
        { id: 't', kind: 'transform', config: { mode: 'native', hook: hookName } as never },
        { id: 'map', kind: 'map', config: { connections: [{ target: 'email', sources: ['email'] }] } as never },
        { id: 'destination', kind: 'destination', config: { kind: 'd1', table: 'employees', mode: 'stored' } as never },
      ],
      edges: [{ from: 'source', to: 't' }, { from: 't', to: 'map' }, { from: 'map', to: 'destination' }],
    };
  }
  const ctx = { hooks: { deriveFullName: () => ({}) }, hookSlots: new Set(['transform', 'beforeUpsert']), knownTables: new Set(['employees']) };

  it('accepts a native hook by descriptor slot name (transform)', () => {
    expect(() => validateFlow(flowWithNativeHook('transform'), ctx)).not.toThrow();
  });
  it('accepts a native hook by registry function name (deriveFullName)', () => {
    expect(() => validateFlow(flowWithNativeHook('deriveFullName'), ctx)).not.toThrow();
  });
  it('rejects a native hook in neither registry nor slots', () => {
    expect(() => validateFlow(flowWithNativeHook('nope'), ctx)).toThrow(/hook 'nope' not found/i);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/flow/validate.test.ts`
Expected: FAIL — the slot-name test throws (current check only consults `ctx.hooks`).

- [ ] **Step 3: Edit `src/flow/validate.ts`**

In `FlowValidationContext` (line ~9) add the optional field:

```ts
export interface FlowValidationContext {
  hooks: HookRegistry;
  hookSlots?: Set<string>;       // descriptor slots, e.g. 'transform', 'beforeUpsert'
  knownTables: Set<string>;
}
```

Replace the native-hook check (line ~58) with:

```ts
        const known = !!ctx.hooks[cfg.hook] || (ctx.hookSlots?.has(cfg.hook) ?? false);
        if (!known) fail(`${node.kind} node ${node.id}: hook '${cfg.hook}' not found in registry`);
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/flow/validate.test.ts`
Expected: PASS (existing + 3 new).

- [ ] **Step 5: Commit**

```bash
git add src/flow/validate.ts src/flow/validate.test.ts
git commit -m "feat(flow): validateFlow accepts native hook by descriptor slot or registry name"
```

---

### Task 2: SDK — `BUILTIN_SPECS` + specs test

**Repo:** `/Users/tibor/projects/eldrin-backup/eldrin-integration`

**Files:**
- Create: `src/flow/transformers/specs.ts`
- Test: `src/flow/transformers/specs.test.ts`
- Modify: `src/index.ts`

**Interfaces:**
- Produces: `BuiltinArg`, `BUILTIN_SPECS`. Consumed by Task 3 (route) and Task 5 (UI types mirror).

- [ ] **Step 1: Write the failing test**

```ts
// src/flow/transformers/specs.test.ts
import { describe, it, expect } from 'vitest';
import { BUILTIN_SPECS } from './specs';
import { BUILTINS } from './index';

describe('BUILTIN_SPECS', () => {
  it('has exactly one entry per builtin (lockstep with BUILTINS)', () => {
    expect(Object.keys(BUILTIN_SPECS).sort()).toEqual(Object.keys(BUILTINS).sort());
  });
  it('declares typed args for the arg-taking builtins', () => {
    expect(BUILTIN_SPECS.concat).toEqual([{ name: 'separator', type: 'string' }]);
    expect(BUILTIN_SPECS.formatDate).toEqual([{ name: 'pattern', type: 'string' }]);
    expect(BUILTIN_SPECS.upperCase).toEqual([]);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/flow/transformers/specs.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Write `src/flow/transformers/specs.ts`**

```ts
export interface BuiltinArg {
  name: string;
  type: 'string' | 'number';
  optional?: boolean;
}

export const BUILTIN_SPECS: Record<string, BuiltinArg[]> = {
  concat: [{ name: 'separator', type: 'string' }],
  substring: [{ name: 'start', type: 'number' }, { name: 'end', type: 'number', optional: true }],
  upperCase: [],
  lowerCase: [],
  trim: [],
  replace: [{ name: 'search', type: 'string' }, { name: 'replacement', type: 'string' }],
  ifThenElse: [{ name: 'then', type: 'string' }, { name: 'else', type: 'string' }],
  equals: [],
  formatDate: [{ name: 'pattern', type: 'string' }],
  coalesce: [],
  constant: [{ name: 'value', type: 'string' }],
};
```

Export from `src/index.ts` (near the transformers export):

```ts
export { BUILTIN_SPECS, type BuiltinArg } from './flow/transformers/specs';
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/flow/transformers/specs.test.ts && npx tsc --noEmit`
Expected: PASS; tsc clean.

- [ ] **Step 5: Commit**

```bash
git add src/flow/transformers/specs.ts src/flow/transformers/specs.test.ts src/index.ts
git commit -m "feat(flow): add BUILTIN_SPECS arg schema for the editor"
```

---

### Task 3: SDK — `/api/flows/effective` + `/api/flows/builtin-specs` routes

**Repo:** `/Users/tibor/projects/eldrin-backup/eldrin-integration`

**Files:**
- Modify: `src/host/create-worker.ts`
- Test: `src/host/create-worker.test.ts`

**Interfaces:**
- Consumes: `compileDescriptorToFlows`, `listFlows`, `BUILTIN_SPECS`.
- Produces: two admin-gated GET routes; `validateFlow` call gains `hookSlots`.

- [ ] **Step 1: Write the failing route tests (append to `src/host/create-worker.test.ts`)**

Reuse the existing `/api/flows` test harness (worker construction + admin/non-admin request builders). Add:

```ts
describe('/api/flows/effective + /api/flows/builtin-specs', () => {
  it('GET /api/flows/effective as admin returns tagged effective set', async () => {
    // admin request → 200; body is an array; each item has { flow, version, stored }.
    // With no stored flows: every item stored:false, version:null.
  });
  it('GET /api/flows/effective as non-admin → 403', async () => {});
  it('GET /api/flows/effective is not captured by /api/flows/:id', async () => {
    // assert the response is the effective array, NOT a "flow not found" 404 for id="effective".
  });
  it('GET /api/flows/builtin-specs as admin returns the spec map', async () => {
    // 200; body.concat === [{name:'separator',type:'string'}]; admin-gated.
  });
  it('GET /api/flows/builtin-specs as non-admin → 403', async () => {});
});
```

Fill these in fully using the file's existing flows-route harness + admin/non-admin JWT builders.

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/host/create-worker.test.ts`
Expected: FAIL — routes 404 / not present.

- [ ] **Step 3: Edit `src/host/create-worker.ts`**

Add imports:

```ts
import { compileDescriptorToFlows } from '../flow/compile';
import { BUILTIN_SPECS } from '../flow/transformers/specs';
```

Register the two routes IMMEDIATELY BEFORE `app.get('/api/flows/:id', ...)` (line ~167), so the specific paths win over the `:id` wildcard:

```ts
app.get('/api/flows/effective', async (c) => {
  const userId = resolveUserId(c);
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);
  if (!isAdmin(c)) return c.json({ error: 'Forbidden: admin role required' }, 403);
  const { db, effective } = await prepare(c.env);
  const compiled = compileDescriptorToFlows(effective);
  const stored = new Map((await listFlows(db)).map((s) => [s.id, s]));
  const out = compiled.map((flow) => {
    const s = stored.get(flow.id);
    return { flow: s ? s.flow : flow, version: s ? s.version : null, stored: !!s };
  });
  return c.json(out);
});

app.get('/api/flows/builtin-specs', async (c) => {
  const userId = resolveUserId(c);
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);
  if (!isAdmin(c)) return c.json({ error: 'Forbidden: admin role required' }, 403);
  return c.json(BUILTIN_SPECS);
});
```

In the existing `POST /api/flows/:id` handler, add `hookSlots` to the `validateFlow` call:

```ts
    validateFlow(body.flow, {
      hooks: boundHooks,
      hookSlots: new Set(['transform', 'beforeUpsert']),
      knownTables: new Set(effective.resources.map((r) => r.name)),
    });
```

- [ ] **Step 4: Run the full SDK suite + typecheck + build**

Run: `npx vitest run && npx tsc --noEmit && npm run build`
Expected: all PASS (incl. the 5 new route tests + existing flows tests); tsc clean; build clean (no better-sqlite3 in bundle).

- [ ] **Step 5: Commit**

```bash
git add src/host/create-worker.ts src/host/create-worker.test.ts
git commit -m "feat(host): add /api/flows/effective + /api/flows/builtin-specs admin routes"
```

---

### Task 4: Factorial — declare `/api/flows` routes in the manifest

**Repo:** `/Users/tibor/projects/eldrin-backup/eldrin-factorial`

**Files:**
- Modify: `public/eldrin-app.manifest.json`

**Interfaces:**
- Produces: the proxy permission declarations for the flows routes.

- [ ] **Step 1: Edit `public/eldrin-app.manifest.json`**

In `api.routes`, append after the existing `schema:prune` entry (keep valid JSON — add the comma):

```jsonc
      { "method": "GET",    "path": "/api/flows",               "permission": "flows:read" },
      { "method": "GET",    "path": "/api/flows/effective",     "permission": "flows:read" },
      { "method": "GET",    "path": "/api/flows/builtin-specs", "permission": "flows:read" },
      { "method": "GET",    "path": "/api/flows/:id",           "permission": "flows:read" },
      { "method": "POST",   "path": "/api/flows/:id",           "permission": "flows:admin" },
      { "method": "DELETE", "path": "/api/flows/:id",           "permission": "flows:admin" }
```

- [ ] **Step 2: Validate the JSON**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-factorial && node -e "JSON.parse(require('fs').readFileSync('public/eldrin-app.manifest.json','utf8')); console.log('valid JSON')"`
Expected: `valid JSON`.

- [ ] **Step 3: Confirm the routes are present**

Run: `node -e "const m=JSON.parse(require('fs').readFileSync('public/eldrin-app.manifest.json','utf8')); console.log(m.api.routes.filter(r=>r.path.startsWith('/api/flows')).length)"`
Expected: `6`.

- [ ] **Step 4: Commit**

```bash
git add public/eldrin-app.manifest.json
git commit -m "feat(manifest): declare /api/flows routes (flows:read/flows:admin)"
```

---

### Task 5: Shell — effective/specs API fns + types

**Repo:** `/Users/tibor/projects/eldrin-backup/eldrin-core`

**Files:**
- Modify: `src/pages/integrations/integrations-api.ts`
- Test: `src/pages/integrations/integrations-api.test.ts`

**Interfaces:**
- Consumes: existing `Result`, `AuthFetch`, `FlowGraph`, `call` helper.
- Produces: `EffectiveFlow`, `BuiltinArg`, `fetchEffectiveFlows`, `fetchBuiltinSpecs`. Consumed by Tasks 6-8.

- [ ] **Step 1: Write the failing tests (append to `src/pages/integrations/integrations-api.test.ts`)**

```ts
import { fetchEffectiveFlows, fetchBuiltinSpecs } from './integrations-api';

const res2 = (status: number, body: unknown): Response =>
  ({ status, ok: status >= 200 && status < 300, json: async () => body } as Response);

describe('effective + builtin-specs API', () => {
  it('fetchEffectiveFlows parses the tagged set on 200', async () => {
    const item = { flow: { id: 'i:r', integrationId: 'i', trigger: { kind: 'manual' }, nodes: [], edges: [] }, version: null, stored: false };
    const authFetch = vi.fn(async () => res2(200, [item]));
    const r = await fetchEffectiveFlows('factorial', authFetch);
    expect(authFetch).toHaveBeenCalledWith('factorial', '/api/flows/effective');
    expect(r).toEqual({ ok: true, data: [item] });
  });
  it('fetchBuiltinSpecs parses the spec map on 200', async () => {
    const specs = { concat: [{ name: 'separator', type: 'string' }], upperCase: [] };
    const authFetch = vi.fn(async () => res2(200, specs));
    const r = await fetchBuiltinSpecs('factorial', authFetch);
    expect(authFetch).toHaveBeenCalledWith('factorial', '/api/flows/builtin-specs');
    expect(r).toEqual({ ok: true, data: specs });
  });
  it('fetchEffectiveFlows maps 403 to a forbidden Result', async () => {
    const authFetch = vi.fn(async () => res2(403, { error: 'Forbidden: admin role required' }));
    const r = await fetchEffectiveFlows('factorial', authFetch);
    expect(r).toEqual({ ok: false, status: 403, error: 'Forbidden: admin role required' });
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-core && npx vitest run src/pages/integrations/integrations-api.test.ts`
Expected: FAIL — `fetchEffectiveFlows`/`fetchBuiltinSpecs` not exported.

- [ ] **Step 3: Edit `src/pages/integrations/integrations-api.ts`**

Add types + fns (the file already has `Result`, `AuthFetch`, `FlowGraph`, and the internal `call` helper):

```ts
export interface BuiltinArg {
  name: string;
  type: 'string' | 'number';
  optional?: boolean;
}

export interface EffectiveFlow {
  flow: FlowGraph;
  version: number | null;
  stored: boolean;
}

export function fetchEffectiveFlows(appId: string, authFetch: AuthFetch): Promise<Result<EffectiveFlow[]>> {
  return call<EffectiveFlow[]>(authFetch(appId, '/api/flows/effective'));
}

export function fetchBuiltinSpecs(appId: string, authFetch: AuthFetch): Promise<Result<Record<string, BuiltinArg[]>>> {
  return call<Record<string, BuiltinArg[]>>(authFetch(appId, '/api/flows/builtin-specs'));
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `npx vitest run src/pages/integrations/integrations-api.test.ts && npx tsc --noEmit`
Expected: PASS; tsc clean.

- [ ] **Step 5: Commit**

```bash
git add src/pages/integrations/integrations-api.ts src/pages/integrations/integrations-api.test.ts
git commit -m "feat(integrations): add effective-flows + builtin-specs API fns"
```

---

### Task 6: Shell — flow ↔ draft model (pure)

**Repo:** `/Users/tibor/projects/eldrin-backup/eldrin-core`

**Files:**
- Create: `src/pages/integrations/flow-edit-model.ts`
- Test: `src/pages/integrations/flow-edit-model.test.ts`

**Interfaces:**
- Consumes: `FlowGraph`, `BuiltinArg` from `./integrations-api`.
- Produces: `ConnectionDraft`, `FlowDraft`, `toFlowDraft`, `applyDraft`. Consumed by Task 8 (FlowEditor).

- [ ] **Step 1: Write the failing test**

```ts
// src/pages/integrations/flow-edit-model.test.ts
import { describe, it, expect } from 'vitest';
import { toFlowDraft, applyDraft } from './flow-edit-model';
import type { FlowGraph, BuiltinArg } from './integrations-api';

const specs: Record<string, BuiltinArg[]> = {
  concat: [{ name: 'separator', type: 'string' }],
  substring: [{ name: 'start', type: 'number' }, { name: 'end', type: 'number', optional: true }],
  upperCase: [],
};

function flow(): FlowGraph {
  return {
    id: 'factorial:employees', integrationId: 'factorial', trigger: { kind: 'cron', expr: '0 * * * *' },
    nodes: [
      { id: 'source', kind: 'source', config: { transport: { method: 'GET', path: '/e' }, idField: 'id' } },
      { id: 'transform', kind: 'transform', config: { mode: 'native', hook: 'transform' } },
      { id: 'map', kind: 'map', config: { connections: [
        { target: 'email', sources: ['email'] },
        { target: 'name', sources: ['first', 'last'], transform: { kind: 'builtin', fn: 'concat', args: [' '] } },
        { target: 'note', sources: ['desc'], transform: { kind: 'snippet', code: 'x' } },
      ] } },
      { id: 'destination', kind: 'destination', config: { kind: 'd1', table: 'employees', mode: 'stored' } },
    ],
    edges: [{ from: 'source', to: 'transform' }, { from: 'transform', to: 'map' }, { from: 'map', to: 'destination' }],
  };
}

describe('toFlowDraft', () => {
  it('extracts trigger and un-discriminates connections', () => {
    const d = toFlowDraft(flow(), specs);
    expect(d.trigger).toEqual({ kind: 'cron', expr: '0 * * * *' });
    expect(d.connections[0]).toEqual({ target: 'email', sources: ['email'], transformKind: 'passthrough' });
    expect(d.connections[1]).toEqual({ target: 'name', sources: ['first', 'last'], transformKind: 'builtin', builtinFn: 'concat', builtinArgs: { separator: ' ' } });
    expect(d.connections[2]).toEqual({ target: 'note', sources: ['desc'], transformKind: 'snippet', snippet: 'x' });
  });
});

describe('applyDraft', () => {
  it('round-trips an unchanged flow (idempotent)', () => {
    const orig = flow();
    const r = applyDraft(orig, toFlowDraft(orig, specs), specs);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.flow).toEqual(orig);
  });
  it('preserves source/transform/destination + edges, replaces only connections + trigger', () => {
    const orig = flow();
    const draft = toFlowDraft(orig, specs);
    draft.trigger = { kind: 'manual' };
    draft.connections = [{ target: 'email', sources: ['email'], transformKind: 'passthrough' }];
    const r = applyDraft(orig, draft, specs);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.flow.trigger).toEqual({ kind: 'manual' });
    expect(r.flow.nodes.find((n) => n.id === 'source')).toEqual(orig.nodes.find((n) => n.id === 'source'));
    expect(r.flow.nodes.find((n) => n.id === 'transform')).toEqual(orig.nodes.find((n) => n.id === 'transform'));
    expect(r.flow.nodes.find((n) => n.id === 'destination')).toEqual(orig.nodes.find((n) => n.id === 'destination'));
    expect(r.flow.edges).toEqual(orig.edges);
    const map = r.flow.nodes.find((n) => n.id === 'map')!;
    expect((map.config as { connections: unknown[] }).connections).toEqual([{ target: 'email', sources: ['email'] }]);
  });
  it('coerces a number builtin arg per spec', () => {
    const orig = flow();
    const draft = toFlowDraft(orig, specs);
    draft.connections = [{ target: 'x', sources: ['y'], transformKind: 'builtin', builtinFn: 'substring', builtinArgs: { start: '2', end: '5' } }];
    const r = applyDraft(orig, draft, specs);
    expect(r.ok).toBe(true);
    if (r.ok) {
      const map = r.flow.nodes.find((n) => n.id === 'map')!;
      const conn = (map.config as { connections: { transform: { args: unknown[] } }[] }).connections[0];
      expect(conn.transform.args).toEqual([2, 5]);
    }
  });
  it('errors on a required number arg that is not a number', () => {
    const orig = flow();
    const draft = toFlowDraft(orig, specs);
    draft.connections = [{ target: 'x', sources: ['y'], transformKind: 'builtin', builtinFn: 'substring', builtinArgs: { start: 'nope' } }];
    const r = applyDraft(orig, draft, specs);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/start/i);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `npx vitest run src/pages/integrations/flow-edit-model.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Write `src/pages/integrations/flow-edit-model.ts`**

```ts
import type { FlowGraph, BuiltinArg } from './integrations-api';

export interface ConnectionDraft {
  target: string;
  sources: string[];
  transformKind: 'passthrough' | 'builtin' | 'snippet';
  builtinFn?: string;
  builtinArgs?: Record<string, string>;
  snippet?: string;
}
export interface FlowDraft {
  trigger: FlowGraph['trigger'];
  connections: ConnectionDraft[];
}

type Specs = Record<string, BuiltinArg[]>;

interface RawConn {
  target: string;
  sources: string[];
  transform?: { kind: 'builtin'; fn: string; args?: unknown[] } | { kind: 'snippet'; code: string };
}

function mapNode(flow: FlowGraph) {
  return flow.nodes.find((n) => n.kind === 'map');
}

export function toFlowDraft(flow: FlowGraph, specs: Specs): FlowDraft {
  const m = mapNode(flow);
  const conns = (m ? ((m.config as { connections?: RawConn[] }).connections ?? []) : []);
  const connections: ConnectionDraft[] = conns.map((c) => {
    if (!c.transform) return { target: c.target, sources: c.sources, transformKind: 'passthrough' };
    if (c.transform.kind === 'snippet') return { target: c.target, sources: c.sources, transformKind: 'snippet', snippet: c.transform.code };
    const spec = specs[c.transform.fn] ?? [];
    const args = c.transform.args ?? [];
    const builtinArgs: Record<string, string> = {};
    spec.forEach((a, i) => { if (args[i] !== undefined) builtinArgs[a.name] = String(args[i]); });
    return { target: c.target, sources: c.sources, transformKind: 'builtin', builtinFn: c.transform.fn, builtinArgs };
  });
  return { trigger: flow.trigger, connections };
}

export function applyDraft(
  original: FlowGraph,
  draft: FlowDraft,
  specs: Specs,
): { ok: true; flow: FlowGraph } | { ok: false; error: string } {
  const built: RawConn[] = [];
  for (const c of draft.connections) {
    if (c.transformKind === 'passthrough') {
      built.push({ target: c.target, sources: c.sources });
    } else if (c.transformKind === 'snippet') {
      built.push({ target: c.target, sources: c.sources, transform: { kind: 'snippet', code: c.snippet ?? '' } });
    } else {
      const fn = c.builtinFn ?? '';
      const spec = specs[fn] ?? [];
      const args: unknown[] = [];
      for (const a of spec) {
        const raw = c.builtinArgs?.[a.name];
        if (raw === undefined || raw === '') {
          if (a.optional) continue;
          return { ok: false, error: `connection '${c.target}': builtin '${fn}' requires arg '${a.name}'` };
        }
        if (a.type === 'number') {
          const n = Number(raw);
          if (Number.isNaN(n)) return { ok: false, error: `connection '${c.target}': arg '${a.name}' must be a number` };
          args.push(n);
        } else {
          args.push(raw);
        }
      }
      built.push({ target: c.target, sources: c.sources, transform: { kind: 'builtin', fn, ...(args.length ? { args } : {}) } });
    }
  }
  // Deep-copy original; replace only the map node's connections + the trigger.
  const flow: FlowGraph = JSON.parse(JSON.stringify(original));
  const m = mapNode(flow);
  if (m) (m.config as { connections: RawConn[] }).connections = built;
  flow.trigger = draft.trigger;
  return { ok: true, flow };
}
```

Note: `toFlowDraft` takes `(flow, specs)` — the test calls it with specs in the round-trip; ensure the signature is `toFlowDraft(flow: FlowGraph, specs: Specs)`. (The first test calls `toFlowDraft(flow(), specs)`.)

- [ ] **Step 4: Run to verify it passes**

Run: `npx vitest run src/pages/integrations/flow-edit-model.test.ts && npx tsc --noEmit`
Expected: PASS (all cases); tsc clean.

- [ ] **Step 5: Commit**

```bash
git add src/pages/integrations/flow-edit-model.ts src/pages/integrations/flow-edit-model.test.ts
git commit -m "feat(integrations): add flow<->draft edit model (pure)"
```

---

### Task 7: Shell — saveFlow (pure)

**Repo:** `/Users/tibor/projects/eldrin-backup/eldrin-core`

**Files:**
- Create: `src/pages/integrations/save-flow.ts`
- Test: `src/pages/integrations/save-flow.test.ts`

**Interfaces:**
- Consumes: `Result`, `AuthFetch`, `FlowGraph` from `./integrations-api`.
- Produces: `saveFlow(appId, flow, baseVersion, authFetch): Promise<Result<{ version: number }>>`. Consumed by Task 8.

- [ ] **Step 1: Write the failing test**

```ts
// src/pages/integrations/save-flow.test.ts
import { describe, it, expect, vi } from 'vitest';
import { saveFlow } from './save-flow';
import type { FlowGraph } from './integrations-api';

const flow: FlowGraph = { id: 'factorial:employees', integrationId: 'factorial', trigger: { kind: 'manual' }, nodes: [], edges: [] };
const res = (status: number, body: unknown): Response => ({ status, ok: status >= 200 && status < 300, json: async () => body } as Response);

describe('saveFlow', () => {
  it('POSTs {flow, baseVersion} and returns the new version on 200', async () => {
    const authFetch = vi.fn(async () => res(200, { flow, version: 2 }));
    const r = await saveFlow('factorial', flow, 1, authFetch);
    expect(authFetch).toHaveBeenCalledWith('factorial', '/api/flows/factorial:employees', expect.objectContaining({ method: 'POST' }));
    const body = JSON.parse((authFetch.mock.calls[0][2] as RequestInit).body as string);
    expect(body).toEqual({ flow, baseVersion: 1 });
    expect(r).toEqual({ ok: true, data: { version: 2 } });
  });
  it('maps 400 validation error', async () => {
    const authFetch = vi.fn(async () => res(400, { error: 'unknown builtin: nope' }));
    const r = await saveFlow('factorial', flow, 1, authFetch);
    expect(r).toEqual({ ok: false, status: 400, error: 'unknown builtin: nope' });
  });
  it('maps 409 conflict', async () => {
    const authFetch = vi.fn(async () => res(409, { error: 'version conflict' }));
    const r = await saveFlow('factorial', flow, 1, authFetch);
    expect(r).toEqual({ ok: false, status: 409, error: 'version conflict' });
  });
  it('sends baseVersion null for create', async () => {
    const authFetch = vi.fn(async () => res(200, { flow, version: 1 }));
    await saveFlow('factorial', flow, null, authFetch);
    const body = JSON.parse((authFetch.mock.calls[0][2] as RequestInit).body as string);
    expect(body.baseVersion).toBeNull();
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `npx vitest run src/pages/integrations/save-flow.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Write `src/pages/integrations/save-flow.ts`**

```ts
import type { Result, AuthFetch, FlowGraph } from './integrations-api';

export async function saveFlow(
  appId: string,
  flow: FlowGraph,
  baseVersion: number | null,
  authFetch: AuthFetch,
): Promise<Result<{ version: number }>> {
  try {
    const res = await authFetch(appId, `/api/flows/${encodeURIComponent(flow.id)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ flow, baseVersion }),
    });
    const body = await res.json().catch(() => undefined);
    if (res.ok) return { ok: true, data: { version: (body as { version: number }).version } };
    const error = (body && (body as { error?: string }).error) || `Request failed with status ${res.status}`;
    return { ok: false, status: res.status, error };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `npx vitest run src/pages/integrations/save-flow.test.ts && npx tsc --noEmit`
Expected: PASS (4 tests); tsc clean.

- [ ] **Step 5: Commit**

```bash
git add src/pages/integrations/save-flow.ts src/pages/integrations/save-flow.test.ts
git commit -m "feat(integrations): add saveFlow (POST with optimistic baseVersion)"
```

---

### Task 8: Shell — FlowEditor + ConnectionRowEditor + revised list

**Repo:** `/Users/tibor/projects/eldrin-backup/eldrin-core`

**Files:**
- Create: `src/pages/integrations/ConnectionRowEditor.tsx`
- Create: `src/pages/integrations/FlowEditor.tsx`
- Modify: `src/pages/integrations/IntegrationList.tsx`
- Modify: `src/locales/en/integrations.json`

**Interfaces:**
- Consumes: `fetchEffectiveFlows`, `fetchBuiltinSpecs`, `EffectiveFlow`, `BuiltinArg`, `FlowGraph` (Task 5); `toFlowDraft`, `applyDraft`, `ConnectionDraft`, `FlowDraft` (Task 6); `saveFlow` (Task 7); `toFlowViewModel` + `FlowDetail` (SP4a, for the read-only View).

These are thin components (not unit-tested per the no-component-test-stack constraint; covered by the logic units + the Task 9 Playwright smoke). Follow SP4a's component patterns (Card, useState/useEffect, the `getAuthFetch()` helper).

- [ ] **Step 1: Add editor i18n strings to `src/locales/en/integrations.json`**

```json
{
  "edit": "Edit",
  "createOverride": "Create override",
  "default": "default",
  "cancel": "Cancel",
  "save": "Save",
  "saved": "Saved (v{{version}})",
  "conflict": "This flow was changed elsewhere. Reload to get the latest (your edits will be lost).",
  "reload": "Reload",
  "addConnection": "Add connection",
  "target": "Target",
  "sources": "Sources",
  "transformer": "Transformer",
  "passthrough": "pass-through",
  "builtin": "builtin",
  "snippet": "snippet",
  "triggerKind": "Trigger"
}
```

(Merge into the existing `integrations.json` object — keep the SP4a keys.)

- [ ] **Step 2: Write `src/pages/integrations/ConnectionRowEditor.tsx`**

```tsx
import { useTranslation } from 'react-i18next';
import { X } from 'lucide-react';
import type { ConnectionDraft } from './flow-edit-model';
import type { BuiltinArg } from './integrations-api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

export function ConnectionRowEditor({
  conn, specs, onChange, onRemove,
}: {
  conn: ConnectionDraft;
  specs: Record<string, BuiltinArg[]>;
  onChange: (next: ConnectionDraft) => void;
  onRemove: () => void;
}) {
  const { t } = useTranslation('integrations');
  const set = (patch: Partial<ConnectionDraft>) => onChange({ ...conn, ...patch });
  return (
    <div className="flex flex-wrap items-start gap-2 border-t py-2">
      <Input className="w-32 font-mono" value={conn.target} onChange={(e) => set({ target: e.target.value })} placeholder={t('target')} />
      <Input className="w-48 font-mono" value={conn.sources.join(', ')} onChange={(e) => set({ sources: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) })} placeholder={t('sources')} />
      <select className="h-9 rounded-md border bg-background px-2 text-sm" value={conn.transformKind} onChange={(e) => set({ transformKind: e.target.value as ConnectionDraft['transformKind'] })}>
        <option value="passthrough">{t('passthrough')}</option>
        <option value="builtin">{t('builtin')}</option>
        <option value="snippet">{t('snippet')}</option>
      </select>
      {conn.transformKind === 'builtin' && (
        <>
          <select className="h-9 rounded-md border bg-background px-2 text-sm" value={conn.builtinFn ?? ''} onChange={(e) => set({ builtinFn: e.target.value, builtinArgs: {} })}>
            <option value="">—</option>
            {Object.keys(specs).map((fn) => <option key={fn} value={fn}>{fn}</option>)}
          </select>
          {(specs[conn.builtinFn ?? ''] ?? []).map((a) => (
            <Input key={a.name} className="w-28" placeholder={a.name + (a.optional ? '?' : '')} value={conn.builtinArgs?.[a.name] ?? ''}
              onChange={(e) => set({ builtinArgs: { ...conn.builtinArgs, [a.name]: e.target.value } })} />
          ))}
        </>
      )}
      {conn.transformKind === 'snippet' && (
        <Input className="w-64 font-mono text-xs" value={conn.snippet ?? ''} onChange={(e) => set({ snippet: e.target.value })} placeholder="sources[0]..." />
      )}
      <Button variant="ghost" size="icon" onClick={onRemove} aria-label="remove"><X size={14} /></Button>
    </div>
  );
}
```

- [ ] **Step 3: Write `src/pages/integrations/FlowEditor.tsx`**

```tsx
import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { toFlowDraft, applyDraft, type ConnectionDraft } from './flow-edit-model';
import { saveFlow } from './save-flow';
import { fetchBuiltinSpecs, type FlowGraph, type BuiltinArg } from './integrations-api';
import { ConnectionRowEditor } from './ConnectionRowEditor';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

type AuthFetchGlobal = (appId: string, input: string, init?: RequestInit) => Promise<Response>;
function getAuthFetch(): AuthFetchGlobal {
  return (window as unknown as { __ELDRIN__: { authenticatedFetch: AuthFetchGlobal } }).__ELDRIN__.authenticatedFetch;
}

export function FlowEditor({ appId, flow, baseVersion, onClose, onSaved }: {
  appId: string; flow: FlowGraph; baseVersion: number | null; onClose: () => void; onSaved: () => void;
}) {
  const { t } = useTranslation('integrations');
  const [specs, setSpecs] = useState<Record<string, BuiltinArg[]>>({});
  const [draft, setDraft] = useState(() => toFlowDraft(flow, {}));
  const [version, setVersion] = useState(baseVersion);
  const [status, setStatus] = useState<{ kind: 'idle' | 'saved' | 'error' | 'conflict'; msg?: string }>({ kind: 'idle' });

  useEffect(() => {
    fetchBuiltinSpecs(appId, getAuthFetch()).then((r) => {
      if (r.ok) { setSpecs(r.data); setDraft(toFlowDraft(flow, r.data)); }
    });
  }, [appId, flow]);

  const save = async () => {
    const applied = applyDraft(flow, draft, specs);
    if (!applied.ok) { setStatus({ kind: 'error', msg: applied.error }); return; }
    const r = await saveFlow(appId, applied.flow, version, getAuthFetch());
    if (r.ok) { setStatus({ kind: 'saved', msg: t('saved', { version: r.data.version }) }); setVersion(r.data.version); onSaved(); }
    else if (r.status === 409) setStatus({ kind: 'conflict' });
    else setStatus({ kind: 'error', msg: r.error });
  };

  const setConn = (i: number, next: ConnectionDraft) => setDraft((d) => ({ ...d, connections: d.connections.map((c, j) => (j === i ? next : c)) }));
  const addConn = () => setDraft((d) => ({ ...d, connections: [...d.connections, { target: '', sources: [], transformKind: 'passthrough' }] }));
  const removeConn = (i: number) => setDraft((d) => ({ ...d, connections: d.connections.filter((_, j) => j !== i) }));

  return (
    <div className="mt-2 rounded-md border p-3">
      <div className="mb-3 flex items-center gap-2">
        <span className="text-sm font-medium">{t('triggerKind')}:</span>
        <select className="h-9 rounded-md border bg-background px-2 text-sm" value={draft.trigger.kind}
          onChange={(e) => {
            const kind = e.target.value as 'cron' | 'manual' | 'webhook';
            setDraft((d) => ({ ...d, trigger: kind === 'cron' ? { kind, expr: '' } : kind === 'webhook' ? { kind, event: '' } : { kind } }));
          }}>
          <option value="cron">cron</option><option value="manual">manual</option><option value="webhook">webhook</option>
        </select>
        {draft.trigger.kind === 'cron' && <Input className="w-40 font-mono" value={draft.trigger.expr} onChange={(e) => setDraft((d) => ({ ...d, trigger: { kind: 'cron', expr: e.target.value } }))} />}
        {draft.trigger.kind === 'webhook' && <Input className="w-40" value={draft.trigger.event} onChange={(e) => setDraft((d) => ({ ...d, trigger: { kind: 'webhook', event: e.target.value } }))} />}
      </div>
      {draft.connections.map((c, i) => (
        <ConnectionRowEditor key={i} conn={c} specs={specs} onChange={(next) => setConn(i, next)} onRemove={() => removeConn(i)} />
      ))}
      <Button variant="link" size="sm" onClick={addConn}>+ {t('addConnection')}</Button>
      <div className="mt-3 flex items-center gap-3">
        <Button size="sm" onClick={save}>{t('save')}</Button>
        <Button variant="ghost" size="sm" onClick={onClose}>{t('cancel')}</Button>
        {status.kind === 'saved' && <span className="text-sm text-green-600">{status.msg}</span>}
        {status.kind === 'error' && <span className="text-sm text-destructive">{status.msg}</span>}
        {status.kind === 'conflict' && <span className="text-sm text-destructive">{t('conflict')} <Button variant="link" size="sm" onClick={onClose}>{t('reload')}</Button></span>}
      </div>
    </div>
  );
}
```

- [ ] **Step 4: Revise `src/pages/integrations/IntegrationList.tsx`**

Change `IntegrationCard` to fetch `fetchEffectiveFlows` instead of `fetchFlows`, render each `EffectiveFlow` with Edit (stored) / Create override (not stored), and open `FlowEditor` inline (alongside the existing read-only View via `FlowDetail`). Replace the import + the fetch + the row rendering:

```tsx
import { fetchEffectiveFlows, fetchFlow, type EffectiveFlow } from './integrations-api';
import { FlowEditor } from './FlowEditor';
// ... in IntegrationCard:
const [items, setItems] = useState<EffectiveFlow[]>([]);
const [editing, setEditing] = useState<string | null>(null);
// load(): const r = await fetchEffectiveFlows(id, getAuthFetch()); if (r.ok) setItems(r.data); ...
// render each item:
//   <span className="font-mono">{item.flow.id}</span>
//   {item.stored ? <span>v{item.version}</span> : <span>{t('default')}</span>}
//   <Button variant="link" size="sm" onClick={() => setEditing(editing === item.flow.id ? null : item.flow.id)}>{item.stored ? t('edit') : t('createOverride')}</Button>
//   {editing === item.flow.id && <FlowEditor appId={id} flow={item.flow} baseVersion={item.stored ? item.version : null} onClose={() => setEditing(null)} onSaved={load} />}
```

Keep the loading/error/forbidden/empty states. (The empty-state for `fetchEffectiveFlows` differs: effective is never empty if the descriptor has resources, so the "noFlows" copy now rarely shows — that's fine.)

- [ ] **Step 5: Typecheck + build + full shell suite**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-core && npx tsc --noEmit && npx vitest run && npm run build`
Expected: tsc clean; the logic-unit tests (Tasks 5-7) pass; build succeeds.

- [ ] **Step 6: Commit**

```bash
git add src/pages/integrations/ConnectionRowEditor.tsx src/pages/integrations/FlowEditor.tsx src/pages/integrations/IntegrationList.tsx src/locales/en/integrations.json
git commit -m "feat(integrations): add form-based flow editor (connections + trigger)"
```

---

### Task 9: Shell — Playwright smoke

**Repo:** `/Users/tibor/projects/eldrin-backup/eldrin-core`

**Files:**
- Create: `e2e/flow-editor.spec.ts`

- [ ] **Step 1: Write the smoke (reuse the repo's e2e auth helper)**

```ts
// e2e/flow-editor.spec.ts
import { test, expect } from '@playwright/test';
import { loginAsAdmin } from './helpers/auth';

test('admin can open the flow editor and save', async ({ page }) => {
  await loginAsAdmin(page);
  await page.getByRole('link', { name: /integrations/i }).click();
  await expect(page).toHaveURL(/\/integrations$/);
  // Open editor on the first flow (Edit or Create override).
  await page.getByRole('button', { name: /edit|create override/i }).first().click();
  // Save (no edits → re-save current flow); expect a Saved status.
  await page.getByRole('button', { name: /^save$/i }).click();
  await expect(page.getByText(/saved \(v\d+\)/i)).toBeVisible();
});
```

If the repo has no admin e2e fixture (browsers/servers unavailable in CI), mark `test.skip` with a comment that it needs the admin storageState + running shell/factorial, consistent with SP4a. Report which.

- [ ] **Step 2: Run (or confirm skip)**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-core && npx playwright test e2e/flow-editor.spec.ts`
Expected: PASS if browsers + dev servers are available; otherwise SKIP with the documented reason (the spec must typecheck either way).

- [ ] **Step 3: Commit**

```bash
git add e2e/flow-editor.spec.ts
git commit -m "test(integrations): add Playwright smoke for the flow editor"
```

---

## Post-implementation: live verification (manual, not a task)

After SDK + manifest changes are built and both servers restarted: as admin, open Integrations → a flow shows Edit (if stored) or Create override (if default) → open the editor → change a connection's transformer (e.g. pass-through → concat with a separator) → Save → see "Saved (v{N})" and the version bump. Confirm a 409 by editing the same flow in two tabs. Confirm a 400 by entering an unknown builtin (shouldn't be possible via the dropdown, but a snippet with a syntax error surfaces the server message).

## Notes

- **SDK ships first** — Tasks 1-4 land before the UI; the editor's effective-list + save + specs all depend on them.
- **Route ordering** — `/api/flows/effective` and `/api/flows/builtin-specs` MUST register before `/api/flows/:id` (Task 3).
- **`applyDraft` is the safety boundary** — it deep-copies the original and swaps only connections + trigger; never regenerates structure. The test asserting source/transform/destination/edges are preserved byte-for-byte is the guard.
- **Cross-repo types** — the shell mirrors only the `BuiltinArg` type; spec values come from the endpoint at runtime.
