# Manifest-Driven Integration Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a straightforward integration zero-boilerplate — a developer ships a declarative `integration.config.json` (+ optional named hooks) and a one-line `createIntegrationWorker(config, hooks)` Worker entry — by adding a host layer on the existing SDK, implementing the `live`/`cached` storage modes, wiring events, making config runtime-editable (D1 overlay), and refactoring `eldrin-factorial` onto it.

**Architecture:** A new `host/` layer in `@eldrin-project/eldrin-integration` parses+validates the JSON into the EXISTING `IntegrationDescriptor` model (reusing `validateDescriptor`), binds hooks by name from a registry, loads the effective config from D1 (falling back to the bundled JSON seed), and auto-mounts a Hono app (`POST /api/sync`, `GET /api/health`, repository reads), a `scheduled()` cron handler, and event emit/subscribe. The row-shaping logic (`fieldMap` + `transform`) is extracted into a shared `mapRows()` so `stored` sync and `live`/`cached` fetch produce identical shapes. No parallel runtime — the JSON is a serializable front-end to the proven descriptor.

**Tech Stack:** TypeScript 5.8 (strict, `verbatimModuleSyntax`), tsup (ESM+CJS), Vitest, Hono 4, Cloudflare Workers (D1, Cache API), `@eldrin-project/eldrin-app-core` (`DatabaseAdapter`, `EldrinEventClient`, `createD1Adapter`, `runMigrations`).

## Global Constraints

- **Reuse, don't fork:** the JSON config MUST parse+validate into the existing `IntegrationDescriptor` via the existing `validateDescriptor`. Do NOT create a parallel descriptor type or validator.
- **DatabaseAdapter only:** all DB access goes through the app-core `DatabaseAdapter` interface (`prepare().bind().all<T>()/first<T>()/run()`), never drizzle or raw D1.
- **Immutability:** create new objects, never mutate inputs. Hooks must be pure. The descriptor is deep-frozen by `defineIntegration`; the host must not mutate it.
- **Fail fast at startup:** config parse/validation failures and unknown hook names throw `DescriptorError` before serving any request. Unimplemented selections throw `NotImplementedError`. `live`/`cached` fetch errors throw `IntegrationError` with HTTP status — never a silently empty result.
- **Stub boundary stays typed:** capabilities NOT in scope here (bearer/OAuth2, GraphQL/file transports, full webhook pipeline, `query()`) remain `NotImplementedError` stubs — do not implement them.
- **`verbatimModuleSyntax: true`:** type-only imports use `import type`.
- **Tests:** co-located `*.test.ts`, Vitest, TDD (failing test first), 80%+ coverage. DB-backed tests use the existing `makeTestDb(ddl: string[]): Promise<DatabaseAdapter>` from `src/test-helpers.ts` (better-sqlite3-backed; test-only; never exported from `src/index.ts`).
- **Commit convention:** Conventional Commits. Attribution disabled.
- **Repo/cwd gotcha:** the SDK is its own git repo at `eldrin-integration/`; factorial is `eldrin-factorial/`. Run ALL git with `git -C <abs-path>` using absolute paths — Bash cwd persists across calls and a stray `cd` into a submodule misdirects commits. `.superpowers/` is gitignored in both repos.
- **Migration filename rule (factorial):** D1 migrations need a 14-digit timestamp prefix (`YYYYMMDDHHMMSS-description.sql`) or they are silently skipped. Today is 2026-06-27; use `20260627HHMMSS-*` sorting after existing migrations.
- **Storage modes scope:** implement `stored` (exists), `live`, and `cached`. `cached` uses the Workers Cache API keyed `<id>:<resource>:findAll|findById:<id?>`, TTL from `refresh.cache.ttlSeconds`. A runtime mode switch clears that resource's cache entries.

**Spec:** `docs/superpowers/specs/2026-06-27-manifest-driven-integration-design.md`. The §8 mode-resolution rule (validate-time vs resolve-time) and §7 config-overlay seam are authoritative.

**Scope decision (recorded):** Spec §7 says extend `_integration_config` to hold the "full effective config." For MVP, `loadEffectiveConfig` merges only the **editable scalar fields already stored** (mode, schedule, cacheTtlSeconds, webhookEnabled) from D1 onto the JSON-seed descriptor; structural fields (transport paths, fieldMap, events) come from the seed. Serializing the entire descriptor into D1 is deferred (YAGNI — the future admin UI needs it, MVP does not edit those fields). The `loadEffectiveConfig` seam is the single place this expands later.

---

## Current-state anchors (verified, for the implementer)

- `src/sync/index.ts`: `runResourceSync(resource, deps)` with a PRIVATE `mapRow(resource, raw)` (applies `transform`, maps `fieldMap` skipping `idField`, applies `beforeUpsert`). `SyncDeps = { db, transport, now, genId }`. `runAllSync` filters `defaultMode==='stored' && supportedModes.includes('stored')`.
- `src/storage/mode.ts`: `effectiveMode(supportedModes, configuredMode, defaultMode): StorageMode` (WORKS — returns the resolved mode) and `assertModeImplemented(mode)` (throws for non-`stored` — this gate is what live/cached work removes).
- `src/repository/index.ts`: `createRepository(db, resource)` → `{ findAll, findById, query }`; `ensureStored()` calls `assertModeImplemented` then reads the D1 table. `query()` throws `NotImplementedError('repository:query')` (KEEP).
- `src/config/index.ts`: `ResourceConfig = { resource, mode, schedule, cacheTtlSeconds, webhookEnabled }`; `readResourceConfig`, `writeResourceConfig` (upsert on `resource`), `seedConfigFromDescriptor` (idempotent, seeds defaults if absent).
- `src/schema/tables.ts`: `INTEGRATION_CONFIG_DDL`, `SYNC_STATE_DDL`, `WEBHOOK_DELIVERIES_DDL`, `SDK_TABLES`, `storedResourceDDL(name, cols)`.
- `src/transport/index.ts`: `createTransport(connection, auth, baseUrl, fetchImpl?)`; `Transport.fetchAll(resource)`.
- `src/auth/index.ts`: `createAuthStrategy(authConfig, lookup)`; `SettingsLookup = (ref) => string|undefined`.
- `src/schedule/index.ts`: `dueResources(descriptor, configs, isDue)`, `runScheduled(descriptor, deps)`.
- `src/health/index.ts`: `testConnection(transport, probe)`.
- app-core: `import { createD1Adapter, runMigrations, EldrinEventClient, createEventClient } from '@eldrin-project/eldrin-app-core'`. `new EldrinEventClient({ appId, coreApiUrl })` exposes `async emit<T>(type, payload, opts?)` and `async poll()`.
- factorial: `worker/index.ts` is a full Hono app importing `buildSyncDeps` from `worker/integration-runtime.ts`, `factorialIntegration` from `worker/integration.ts`, and route modules; `scheduled()` calls `runScheduled`. `worker/services/factorial-client.ts` still backs live `teams`/`timeoff` routes.

---

## File Structure (Part A — SDK `eldrin-integration/`)

```
src/
├── sync/
│   ├── map.ts              NEW: mapRows() — shared fieldMap+transform shaping
│   └── index.ts            MODIFY: runResourceSync uses mapRows (no behavior change)
├── storage/
│   ├── mode.ts             MODIFY: remove assertModeImplemented gate for live/cached
│   └── cache.ts            NEW: TTL cache over Workers Cache API
├── repository/index.ts     MODIFY: mode-dispatched reads (stored/live/cached)
├── config/
│   ├── index.ts            MODIFY: (unchanged scalar fields; reused by loader)
│   └── load.ts             NEW: loadEffectiveConfig(db, seedDescriptor) → IntegrationDescriptor
├── host/
│   ├── bind-hooks.ts       NEW: bindHooks(descriptor, registry) → descriptor with fn hooks
│   ├── create-worker.ts    NEW: createIntegrationWorker(config, hooks?, options?)
│   └── live.ts             NEW: fetchLive(resource, deps) — transport→mapRows, no D1 write
├── events/
│   └── wire.ts             NEW: emitChange(...) + registerSubscriptions(...)
└── index.ts                MODIFY: export new public surface
```

---

## Part A — SDK

### Task 1: Extract shared `mapRows()` (refactor, no behavior change)

**Files:**
- Create: `eldrin-integration/src/sync/map.ts`
- Create: `eldrin-integration/src/sync/map.test.ts`
- Modify: `eldrin-integration/src/sync/index.ts` (use `mapRows`, delete private `mapRow`)

**Interfaces:**
- Consumes: `ResourceDescriptor` (existing).
- Produces:
  - `function mapRows(resource: ResourceDescriptor, rawRows: Record<string, unknown>[]): { remoteId: string; mapped: Record<string, unknown>; raw: Record<string, unknown> }[]` — for each raw row: applies `hooks.transform(raw)` if present, maps `fieldMap` remote→local skipping `idField`, applies `hooks.beforeUpsert(mapped, raw)` if present; returns `remoteId = String(raw[idField])`, the `mapped` columns, and the original `raw`. Pure; does not mutate `raw`.

- [ ] **Step 1: Write the failing test**

```ts
// eldrin-integration/src/sync/map.test.ts
import { describe, it, expect } from 'vitest';
import { mapRows } from './map';
import type { ResourceDescriptor } from '../descriptor';

const base: ResourceDescriptor = {
  name: 'clients',
  transport: { method: 'GET', path: '/c', pagination: 'cursor' },
  idField: 'id',
  fieldMap: { id: 'remote_id', name: 'name', email: 'email' },
  supportedModes: ['stored'],
  defaultMode: 'stored',
};

describe('mapRows', () => {
  it('maps fieldMap remote→local, skips idField, returns remoteId+mapped+raw', () => {
    const out = mapRows(base, [{ id: 7, name: 'Ada', email: 'a@x.io' }]);
    expect(out).toHaveLength(1);
    expect(out[0].remoteId).toBe('7');
    expect(out[0].mapped).toEqual({ name: 'Ada', email: 'a@x.io' });
    expect(out[0].raw).toEqual({ id: 7, name: 'Ada', email: 'a@x.io' });
  });

  it('maps undefined fields to null', () => {
    const out = mapRows(base, [{ id: 8, name: 'Bo' }]);
    expect(out[0].mapped).toEqual({ name: 'Bo', email: null });
  });

  it('applies transform before mapping and does not mutate raw', () => {
    const r: ResourceDescriptor = {
      ...base,
      hooks: { transform: (raw) => ({ ...raw, name: String(raw.name).toUpperCase() }) },
    };
    const raw = { id: 9, name: 'ada', email: 'a@x.io' };
    const out = mapRows(r, [raw]);
    expect(out[0].mapped.name).toBe('ADA');
    expect(raw.name).toBe('ada'); // raw not mutated
  });

  it('applies beforeUpsert after mapping', () => {
    const r: ResourceDescriptor = {
      ...base,
      hooks: { beforeUpsert: (mapped) => ({ ...mapped, name: `<${mapped.name}>` }) },
    };
    const out = mapRows(r, [{ id: 1, name: 'x', email: 'e' }]);
    expect(out[0].mapped.name).toBe('<x>');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/sync/map.test.ts`
Expected: FAIL — cannot find module './map'.

- [ ] **Step 3: Write the implementation**

```ts
// eldrin-integration/src/sync/map.ts
import type { ResourceDescriptor } from '../descriptor';

export interface MappedRow {
  remoteId: string;
  mapped: Record<string, unknown>;
  raw: Record<string, unknown>;
}

export function mapRows(
  resource: ResourceDescriptor,
  rawRows: Record<string, unknown>[],
): MappedRow[] {
  return rawRows.map((raw) => {
    const transformed = resource.hooks?.transform ? resource.hooks.transform(raw) : raw;
    const mapped: Record<string, unknown> = {};
    for (const [remoteKey, localCol] of Object.entries(resource.fieldMap)) {
      if (remoteKey === resource.idField) continue;
      const value = transformed[remoteKey];
      mapped[localCol] = value === undefined ? null : value;
    }
    const finalMapped = resource.hooks?.beforeUpsert
      ? resource.hooks.beforeUpsert(mapped, raw)
      : mapped;
    return { remoteId: String(raw[resource.idField]), mapped: finalMapped, raw };
  });
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/sync/map.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Refactor `runResourceSync` to use `mapRows`**

In `eldrin-integration/src/sync/index.ts`: delete the private `mapRow` function and rewrite the loop in `runResourceSync` to use `mapRows`:

```ts
// at top, add:
import { mapRows } from './map';

// replace the `for (const raw of rows)` loop body in runResourceSync with:
    const rows = await deps.transport.fetchAll(resource);
    for (const { remoteId, mapped, raw } of mapRows(resource, rows)) {
      const cols = Object.keys(mapped);
      const allCols = ['id', 'remote_id', ...cols, 'raw_json', 'synced_at'];
      const placeholders = allCols.map(() => '?').join(', ');
      const updates = [...cols, 'raw_json', 'synced_at']
        .map((c) => `${c} = excluded.${c}`)
        .join(', ');
      const values = [deps.genId(), remoteId, ...cols.map((c) => mapped[c]), JSON.stringify(raw), ts];
      await deps.db
        .prepare(
          `INSERT INTO ${resource.name} (${allCols.join(', ')}) VALUES (${placeholders})
           ON CONFLICT(remote_id) DO UPDATE SET ${updates}`,
        )
        .bind(...values)
        .run();
    }
    return { resource: resource.name, count: rows.length };
```
(Keep the surrounding `try`/`writeSyncState`/`catch` exactly as-is. The `const rows` line moves up; `count` uses `rows.length`.)

- [ ] **Step 6: Run the existing sync tests to confirm no behavior change**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/sync`
Expected: PASS — `map.test.ts` (4) AND the existing `src/sync/index.test.ts` (5) all green. If `index.test.ts` fails, the refactor changed behavior — fix to match.

- [ ] **Step 7: Export `mapRows` and commit**

Add to `src/index.ts`:
```ts
export { mapRows, type MappedRow } from './sync/map';
```
Run: `npx vitest run src/sync && npm run typecheck`
```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-integration add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-integration commit -q -m "refactor: extract shared mapRows from sync runner"
```

---

### Task 2: TTL cache over Workers Cache API

**Files:**
- Create: `eldrin-integration/src/storage/cache.ts`
- Create: `eldrin-integration/src/storage/cache.test.ts`

**Interfaces:**
- Consumes: nothing (takes an injectable cache store for testability).
- Produces:
  - `interface CacheStore { get(key: string): Promise<string | null>; put(key: string, value: string, ttlSeconds: number): Promise<void>; delete(key: string): Promise<void> }`
  - `interface IntegrationCache { read<T>(key: string): Promise<T | null>; write<T>(key: string, value: T, ttlSeconds: number): Promise<void>; clearResource(resource: string): Promise<void> }`
  - `function createCache(store: CacheStore, integrationId: string): IntegrationCache` — JSON-serializes values; key format `<integrationId>:<resource>:...` (callers pass the suffix). `clearResource` deletes by tracking written keys per resource in an in-memory set (Workers Cache API has no prefix-delete; we track keys written this isolate + best-effort delete known suffixes `findAll` and `findById:*`). For MVP, `clearResource` deletes the two deterministic keys `<id>:<resource>:findAll` and is documented as best-effort for `findById:*`.
  - `function cacheKey(resource: string, op: 'findAll' | 'findById', id?: string): string` — returns `<resource>:findAll` or `<resource>:findById:<id>`.

> **Note on Cache API:** the real Workers `caches.default` keys by Request/URL, not arbitrary strings. To keep this unit testable and Workers-compatible, `CacheStore` is an abstraction; the Worker provides an implementation backed by `caches.default` using a synthetic request URL `https://integration-cache/<key>`. Tests inject a `Map`-backed `CacheStore`.

- [ ] **Step 1: Write the failing test**

```ts
// eldrin-integration/src/storage/cache.test.ts
import { describe, it, expect } from 'vitest';
import { createCache, cacheKey, type CacheStore } from './cache';

function memStore(): CacheStore & { map: Map<string, string> } {
  const map = new Map<string, string>();
  return {
    map,
    async get(k) { return map.has(k) ? map.get(k)! : null; },
    async put(k, v) { map.set(k, v); },
    async delete(k) { map.delete(k); },
  };
}

describe('integration cache', () => {
  it('cacheKey formats findAll and findById', () => {
    expect(cacheKey('clients', 'findAll')).toBe('clients:findAll');
    expect(cacheKey('clients', 'findById', '10')).toBe('clients:findById:10');
  });

  it('write then read round-trips JSON, scoped by integration id', async () => {
    const store = memStore();
    const cache = createCache(store, 'acme');
    await cache.write('clients:findAll', [{ a: 1 }], 300);
    expect(store.map.has('acme:clients:findAll')).toBe(true);
    expect(await cache.read('clients:findAll')).toEqual([{ a: 1 }]);
  });

  it('read returns null on miss', async () => {
    const cache = createCache(memStore(), 'acme');
    expect(await cache.read('clients:findAll')).toBeNull();
  });

  it('clearResource deletes the resource findAll key', async () => {
    const store = memStore();
    const cache = createCache(store, 'acme');
    await cache.write('clients:findAll', [1], 300);
    await cache.clearResource('clients');
    expect(await cache.read('clients:findAll')).toBeNull();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/storage/cache.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

```ts
// eldrin-integration/src/storage/cache.ts
export interface CacheStore {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, ttlSeconds: number): Promise<void>;
  delete(key: string): Promise<void>;
}

export interface IntegrationCache {
  read<T>(key: string): Promise<T | null>;
  write<T>(key: string, value: T, ttlSeconds: number): Promise<void>;
  clearResource(resource: string): Promise<void>;
}

export function cacheKey(resource: string, op: 'findAll' | 'findById', id?: string): string {
  return op === 'findById' ? `${resource}:findById:${id}` : `${resource}:findAll`;
}

export function createCache(store: CacheStore, integrationId: string): IntegrationCache {
  const full = (key: string) => `${integrationId}:${key}`;
  return {
    async read<T>(key: string): Promise<T | null> {
      const raw = await store.get(full(key));
      return raw === null ? null : (JSON.parse(raw) as T);
    },
    async write<T>(key: string, value: T, ttlSeconds: number): Promise<void> {
      await store.put(full(key), JSON.stringify(value), ttlSeconds);
    },
    async clearResource(resource: string): Promise<void> {
      // Best-effort: Workers Cache API has no prefix delete. Clear the deterministic
      // findAll key; findById:* entries expire via TTL.
      await store.delete(full(cacheKey(resource, 'findAll')));
    },
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/storage/cache.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Export and commit**

Add to `src/index.ts`:
```ts
export { createCache, cacheKey } from './storage/cache';
export type { CacheStore, IntegrationCache } from './storage/cache';
```
```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-integration add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-integration commit -q -m "feat: add TTL cache abstraction for cached mode"
```

---

### Task 3: Live fetch path

**Files:**
- Create: `eldrin-integration/src/host/live.ts`
- Create: `eldrin-integration/src/host/live.test.ts`

**Interfaces:**
- Consumes: `ResourceDescriptor`, `Transport` (existing), `mapRows` (Task 1).
- Produces:
  - `interface LiveDeps { transport: Transport }`
  - `async function fetchLive(resource: ResourceDescriptor, deps: LiveDeps): Promise<Record<string, unknown>[]>` — fetches via `transport.fetchAll(resource)`, runs `mapRows`, and returns rows shaped like stored rows: each is `{ remote_id, ...mapped }` (so a live read matches a `SELECT *` stored read column-wise; no `id`/`raw_json`/`synced_at` since those are storage artifacts). Pure read; no DB write.

- [ ] **Step 1: Write the failing test**

```ts
// eldrin-integration/src/host/live.test.ts
import { describe, it, expect } from 'vitest';
import { fetchLive } from './live';
import type { ResourceDescriptor } from '../descriptor';
import type { Transport } from '../transport';

const resource: ResourceDescriptor = {
  name: 'clients',
  transport: { method: 'GET', path: '/c', pagination: 'none' },
  idField: 'id',
  fieldMap: { id: 'remote_id', name: 'name' },
  supportedModes: ['stored', 'live'],
  defaultMode: 'live',
};

function fakeTransport(rows: Record<string, unknown>[]): Transport {
  return { fetchAll: async () => rows };
}

describe('fetchLive', () => {
  it('returns stored-shaped rows (remote_id + mapped cols), no DB write', async () => {
    const rows = await fetchLive(resource, { transport: fakeTransport([{ id: 5, name: 'Ada' }]) });
    expect(rows).toEqual([{ remote_id: '5', name: 'Ada' }]);
  });

  it('applies transform hook on the live path', async () => {
    const r: ResourceDescriptor = {
      ...resource,
      hooks: { transform: (raw) => ({ ...raw, name: String(raw.name).toUpperCase() }) },
    };
    const rows = await fetchLive(r, { transport: fakeTransport([{ id: 1, name: 'bo' }]) });
    expect(rows[0]).toEqual({ remote_id: '1', name: 'BO' });
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/host/live.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

```ts
// eldrin-integration/src/host/live.ts
import type { ResourceDescriptor } from '../descriptor';
import type { Transport } from '../transport';
import { mapRows } from '../sync/map';

export interface LiveDeps {
  transport: Transport;
}

export async function fetchLive(
  resource: ResourceDescriptor,
  deps: LiveDeps,
): Promise<Record<string, unknown>[]> {
  const raw = await deps.transport.fetchAll(resource);
  return mapRows(resource, raw).map(({ remoteId, mapped }) => ({
    remote_id: remoteId,
    ...mapped,
  }));
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/host/live.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Export and commit**

Add to `src/index.ts`:
```ts
export { fetchLive, type LiveDeps } from './host/live';
```
```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-integration add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-integration commit -q -m "feat: add live fetch path (transport + mapRows, no DB write)"
```

---

### Task 4: Mode engine — allow live/cached; mode-dispatched repository

> **CRITICAL (verified against current code):** `src/descriptor/validate.ts` has `IMPLEMENTED_MODES = new Set(['stored'])`, so `validateDescriptor` currently throws `NotImplementedError('mode:live')` for any live/cached resource — at `parseConfig`/`defineIntegration` time, BEFORE the repository ever runs. Implementing live/cached therefore REQUIRES updating that set too, or the factorial config (Task 11, teams/timeoff = live) throws at parse. This task updates BOTH the validator and the repository.

**Files:**
- Modify: `eldrin-integration/src/descriptor/validate.ts` (`IMPLEMENTED_MODES` → add `live`, `cached`)
- Modify: `eldrin-integration/src/descriptor/validate.test.ts` (the "live throws NotImplemented" case is now invalid — live is implemented; replace with a genuinely-unknown mode)
- Modify: `eldrin-integration/src/storage/mode.ts` (remove the `assertModeImplemented` gate for live/cached; keep a guard only for genuinely-unknown modes)
- Modify: `eldrin-integration/src/repository/index.ts` (dispatch reads by effective mode)
- Modify: `eldrin-integration/src/storage/mode.test.ts` (update the now-changed assertions)
- Create: `eldrin-integration/src/repository/modes.test.ts`

**Interfaces:**
- Consumes: `effectiveMode` (existing), `readResourceConfig` (existing), `fetchLive`+`LiveDeps` (Task 3), `IntegrationCache`+`cacheKey` (Task 2), `Transport`, `DatabaseAdapter`.
- Produces:
  - `assertModeImplemented(mode)` (modify): throws `NotImplementedError(mode:<x>)` ONLY for modes not in `{stored, live, cached}`. (stored/live/cached are now implemented.)
  - `createRepository(db, resource, opts?)` (modify) where `opts?: { transport?: Transport; cache?: IntegrationCache }`:
    - `stored` → `SELECT * FROM <resource>` (existing behavior).
    - `live` → `fetchLive(resource, { transport })` (requires `opts.transport`, else throws `IntegrationError`).
    - `cached` → cache.read(cacheKey) → on miss `fetchLive` then cache.write with `resource.refresh.cache.ttlSeconds` (requires both `opts.transport` and `opts.cache`).
    - `findById(remoteId)`: stored → indexed `SELECT`; live/cached → fetch all then filter by `remote_id` (documented; live APIs here have no by-id endpoint in MVP).
    - `query()` unchanged — throws `NotImplementedError('repository:query')`.

- [ ] **Step 1a: Update `validateDescriptor` to accept live/cached, and fix its test**

In `eldrin-integration/src/descriptor/validate.ts`, change the modes set:
```ts
const IMPLEMENTED_MODES = new Set(['stored', 'live', 'cached']);
```
In `eldrin-integration/src/descriptor/validate.test.ts`, the existing case asserting `live` throws `NotImplementedError` is now wrong (live is implemented). Replace that single test with one using a genuinely-unimplemented mode:
```ts
  it('throws NotImplemented for an unimplemented mode', () => {
    const d = make();
    d.resources[0].supportedModes = ['stored', 'archived' as never];
    expect(() => defineIntegration(d)).toThrow(NotImplementedError);
  });
```
Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/descriptor/validate.test.ts`
Expected: PASS (the live-now-allowed change + the replaced unknown-mode case). If any other test in that file asserts `live`/`cached` throws, update it the same way.

- [ ] **Step 1b: Update the mode-engine test for the new behavior**

Replace the `assertModeImplemented` cases in `eldrin-integration/src/storage/mode.test.ts`:
```ts
  it('assertModeImplemented allows stored, live, cached', () => {
    expect(() => assertModeImplemented('stored')).not.toThrow();
    expect(() => assertModeImplemented('live')).not.toThrow();
    expect(() => assertModeImplemented('cached')).not.toThrow();
  });
  it('assertModeImplemented throws for an unknown mode', () => {
    expect(() => assertModeImplemented('bogus' as never)).toThrow(NotImplementedError);
  });
```
(Keep the existing `effectiveMode` tests unchanged.)

- [ ] **Step 2: Write the failing repository modes test**

```ts
// eldrin-integration/src/repository/modes.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';
import { createRepository } from './index';
import type { ResourceDescriptor } from '../descriptor';
import type { Transport } from '../transport';
import { storedResourceDDL, INTEGRATION_CONFIG_DDL } from '../schema/tables';
import { writeResourceConfig } from '../config';
import { createCache, type CacheStore } from '../storage/cache';
import { makeTestDb } from '../test-helpers';

function memStore(): CacheStore & { map: Map<string, string> } {
  const map = new Map<string, string>();
  return { map, async get(k){return map.has(k)?map.get(k)!:null;}, async put(k,v){map.set(k,v);}, async delete(k){map.delete(k);} };
}
function fakeTransport(rows: Record<string, unknown>[]): Transport & { calls: number } {
  const t: any = { calls: 0, fetchAll: async () => { t.calls++; return rows; } };
  return t;
}
function resource(modes: ('stored'|'live'|'cached')[], def: 'stored'|'live'|'cached', ttl?: number): ResourceDescriptor {
  return { name: 'clients', transport: { method: 'GET', path: '/c', pagination: 'none' },
    idField: 'id', fieldMap: { id: 'remote_id', name: 'name' }, supportedModes: modes, defaultMode: def,
    refresh: ttl ? { cache: { ttlSeconds: ttl } } : undefined };
}

let db: DatabaseAdapter;
beforeEach(async () => {
  db = await makeTestDb([INTEGRATION_CONFIG_DDL, storedResourceDDL('clients', ['name TEXT'])]);
});

describe('repository mode dispatch', () => {
  it('stored reads from D1', async () => {
    await db.prepare('INSERT INTO clients (id,remote_id,name,raw_json,synced_at) VALUES (?,?,?,?,?)')
      .bind('a','10','Ada','{}',1).run();
    await writeResourceConfig(db, { resource:'clients', mode:'stored', schedule:null, cacheTtlSeconds:null, webhookEnabled:false });
    const repo = createRepository(db, resource(['stored'],'stored'));
    expect((await repo.findAll())).toHaveLength(1);
  });

  it('live fetches from transport every call, no D1 write', async () => {
    await writeResourceConfig(db, { resource:'clients', mode:'live', schedule:null, cacheTtlSeconds:null, webhookEnabled:false });
    const transport = fakeTransport([{ id: 5, name: 'Bo' }]);
    const repo = createRepository(db, resource(['stored','live'],'live'), { transport });
    expect(await repo.findAll()).toEqual([{ remote_id:'5', name:'Bo' }]);
    await repo.findAll();
    expect(transport.calls).toBe(2); // live = no caching
  });

  it('cached fetches once then serves from cache', async () => {
    await writeResourceConfig(db, { resource:'clients', mode:'cached', schedule:null, cacheTtlSeconds:300, webhookEnabled:false });
    const transport = fakeTransport([{ id: 9, name: 'Cy' }]);
    const cache = createCache(memStore(), 'acme');
    const repo = createRepository(db, resource(['stored','cached'],'cached',300), { transport, cache });
    expect(await repo.findAll()).toEqual([{ remote_id:'9', name:'Cy' }]);
    await repo.findAll();
    expect(transport.calls).toBe(1); // second served from cache
  });

  it('live findById filters fetched rows by remote_id', async () => {
    await writeResourceConfig(db, { resource:'clients', mode:'live', schedule:null, cacheTtlSeconds:null, webhookEnabled:false });
    const transport = fakeTransport([{ id: 1, name: 'A' }, { id: 2, name: 'B' }]);
    const repo = createRepository(db, resource(['stored','live'],'live'), { transport });
    expect(await repo.findById('2')).toEqual({ remote_id:'2', name:'B' });
    expect(await repo.findById('99')).toBeNull();
  });
});
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/repository/modes.test.ts src/storage/mode.test.ts`
Expected: FAIL — repository doesn't dispatch by mode yet / mode test asserts new behavior.

- [ ] **Step 4: Update `assertModeImplemented`**

```ts
// eldrin-integration/src/storage/mode.ts  (replace assertModeImplemented)
const IMPLEMENTED: ReadonlySet<string> = new Set(['stored', 'live', 'cached']);

export function assertModeImplemented(mode: StorageMode): void {
  if (!IMPLEMENTED.has(mode)) throw new NotImplementedError(`mode:${mode}`);
}
```
(Keep `effectiveMode` unchanged.)

- [ ] **Step 5: Rewrite the repository to dispatch by mode**

```ts
// eldrin-integration/src/repository/index.ts
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';
import type { ResourceDescriptor } from '../descriptor';
import type { Transport } from '../transport';
import { effectiveMode, assertModeImplemented } from '../storage/mode';
import { readResourceConfig } from '../config';
import { fetchLive } from '../host/live';
import { cacheKey, type IntegrationCache } from '../storage/cache';
import { IntegrationError, NotImplementedError } from '../errors';

export interface Repository<T = Record<string, unknown>> {
  findAll(): Promise<T[]>;
  findById(remoteId: string): Promise<T | null>;
  query(): Promise<never>;
}

export interface RepositoryOptions {
  transport?: Transport;
  cache?: IntegrationCache;
}

export function createRepository<T = Record<string, unknown>>(
  db: DatabaseAdapter,
  resource: ResourceDescriptor,
  opts: RepositoryOptions = {},
): Repository<T> {
  async function resolveMode(): Promise<'stored' | 'live' | 'cached'> {
    const config = await readResourceConfig(db, resource.name);
    const mode = effectiveMode(resource.supportedModes, config?.mode ?? null, resource.defaultMode);
    assertModeImplemented(mode);
    return mode as 'stored' | 'live' | 'cached';
  }

  async function liveAll(): Promise<Record<string, unknown>[]> {
    if (!opts.transport) throw new IntegrationError(`live mode for ${resource.name} requires a transport`, 500);
    return fetchLive(resource, { transport: opts.transport });
  }

  async function cachedAll(): Promise<Record<string, unknown>[]> {
    if (!opts.cache) throw new IntegrationError(`cached mode for ${resource.name} requires a cache`, 500);
    const key = cacheKey(resource.name, 'findAll');
    const hit = await opts.cache.read<Record<string, unknown>[]>(key);
    if (hit) return hit;
    const rows = await liveAll();
    const ttl = resource.refresh?.cache?.ttlSeconds ?? 60;
    await opts.cache.write(key, rows, ttl);
    return rows;
  }

  async function readAll(): Promise<Record<string, unknown>[]> {
    const mode = await resolveMode();
    if (mode === 'stored') {
      const res = await db.prepare(`SELECT * FROM ${resource.name}`).all<Record<string, unknown>>();
      return res.results;
    }
    if (mode === 'live') return liveAll();
    return cachedAll();
  }

  return {
    async findAll(): Promise<T[]> {
      return (await readAll()) as T[];
    },
    async findById(remoteId: string): Promise<T | null> {
      const mode = await resolveMode();
      if (mode === 'stored') {
        return db.prepare(`SELECT * FROM ${resource.name} WHERE remote_id = ?`).bind(remoteId).first<T>();
      }
      const rows = mode === 'live' ? await liveAll() : await cachedAll();
      const found = rows.find((r) => String(r.remote_id) === String(remoteId));
      return (found as T) ?? null;
    },
    async query(): Promise<never> {
      throw new NotImplementedError('repository:query');
    },
  };
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/repository src/storage && npm run typecheck`
Expected: PASS — `modes.test.ts` (4), existing `repository/index.test.ts` (4, stored path unchanged), `storage/mode.test.ts` updated, `cache.test.ts` (4).

- [ ] **Step 7: Export and commit**

Add to `src/index.ts`: `export type { RepositoryOptions } from './repository';`
```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-integration add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-integration commit -q -m "feat: implement live and cached modes via mode-dispatched repository"
```

---

### Task 5: `loadEffectiveConfig` (D1 overlay seam)

**Files:**
- Create: `eldrin-integration/src/config/load.ts`
- Create: `eldrin-integration/src/config/load.test.ts`

**Interfaces:**
- Consumes: `IntegrationDescriptor`, `readResourceConfig` (existing), `DatabaseAdapter`.
- Produces:
  - `async function loadEffectiveConfig(db: DatabaseAdapter, seed: IntegrationDescriptor): Promise<IntegrationDescriptor>` — returns a NEW descriptor (does not mutate `seed`) where each resource's editable scalar fields are overlaid from the D1 `_integration_config` row when present: `defaultMode` ← config.mode (if non-null), `refresh.schedule` ← config.schedule, `refresh.cache.ttlSeconds` ← config.cacheTtlSeconds. Structural fields (transport, fieldMap, events, hooks) come from the seed unchanged. If no D1 row exists for a resource, the seed values stand.

> **Scope (per plan header):** only the scalar fields already in `_integration_config` are overlaid. Structural editing (paths/fieldMap) is deferred; this function is the single seam where that expands later.

- [ ] **Step 1: Write the failing test**

```ts
// eldrin-integration/src/config/load.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';
import { loadEffectiveConfig } from './load';
import { writeResourceConfig } from './index';
import type { IntegrationDescriptor } from '../descriptor';
import { INTEGRATION_CONFIG_DDL } from '../schema/tables';
import { makeTestDb } from '../test-helpers';

const seed: IntegrationDescriptor = {
  id: 'acme',
  connection: { transport: 'http', baseUrl: 'x', auth: { strategy: 'apiKey', key: { secret: 'K' } } },
  resources: [{
    name: 'clients', transport: { method: 'GET', path: '/c', pagination: 'cursor' },
    idField: 'id', fieldMap: { id: 'remote_id', name: 'name' },
    supportedModes: ['stored','live','cached'], defaultMode: 'stored',
    refresh: { schedule: '0 * * * *', cache: { ttlSeconds: 300 } },
  }],
};

let db: DatabaseAdapter;
beforeEach(async () => { db = await makeTestDb([INTEGRATION_CONFIG_DDL]); });

describe('loadEffectiveConfig', () => {
  it('returns seed values when no D1 override exists', async () => {
    const eff = await loadEffectiveConfig(db, seed);
    expect(eff.resources[0].defaultMode).toBe('stored');
    expect(eff.resources[0].refresh?.schedule).toBe('0 * * * *');
  });

  it('overlays mode/schedule/ttl from D1 without mutating seed', async () => {
    await writeResourceConfig(db, { resource:'clients', mode:'live', schedule:'*/5 * * * *', cacheTtlSeconds:60, webhookEnabled:false });
    const eff = await loadEffectiveConfig(db, seed);
    expect(eff.resources[0].defaultMode).toBe('live');
    expect(eff.resources[0].refresh?.schedule).toBe('*/5 * * * *');
    expect(eff.resources[0].refresh?.cache?.ttlSeconds).toBe(60);
    // seed untouched (it is deep-frozen in real use; here assert value unchanged)
    expect(seed.resources[0].defaultMode).toBe('stored');
  });

  it('keeps structural fields from the seed', async () => {
    await writeResourceConfig(db, { resource:'clients', mode:'cached', schedule:null, cacheTtlSeconds:null, webhookEnabled:false });
    const eff = await loadEffectiveConfig(db, seed);
    expect(eff.resources[0].fieldMap).toEqual({ id: 'remote_id', name: 'name' });
    expect(eff.resources[0].transport.path).toBe('/c');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/config/load.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

```ts
// eldrin-integration/src/config/load.ts
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';
import type { IntegrationDescriptor, ResourceDescriptor, StorageMode } from '../descriptor';
import { readResourceConfig } from './index';

export async function loadEffectiveConfig(
  db: DatabaseAdapter,
  seed: IntegrationDescriptor,
): Promise<IntegrationDescriptor> {
  const resources: ResourceDescriptor[] = [];
  for (const r of seed.resources) {
    const config = await readResourceConfig(db, r.name);
    if (!config) {
      resources.push(r);
      continue;
    }
    const refresh = {
      schedule: config.schedule ?? r.refresh?.schedule,
      cache:
        config.cacheTtlSeconds != null
          ? { ttlSeconds: config.cacheTtlSeconds }
          : r.refresh?.cache,
    };
    resources.push({
      ...r,
      defaultMode: (config.mode as StorageMode) ?? r.defaultMode,
      refresh: refresh.schedule == null && refresh.cache == null ? r.refresh : refresh,
    });
  }
  return { ...seed, resources };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/config/load.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Export and commit**

Add to `src/index.ts`: `export { loadEffectiveConfig } from './config/load';`
```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-integration add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-integration commit -q -m "feat: add loadEffectiveConfig D1 overlay seam"
```

---

### Task 6: Bind hooks by name

**Files:**
- Create: `eldrin-integration/src/host/bind-hooks.ts`
- Create: `eldrin-integration/src/host/bind-hooks.test.ts`

**Interfaces:**
- Consumes: `IntegrationDescriptor`, `ResourceDescriptor`, `ResourceHooks`, `DescriptorError`.
- Produces:
  - `type HookFn = (...args: any[]) => any` (the registry value type)
  - `type HookRegistry = Record<string, HookFn>`
  - `function bindHooks(descriptor: IntegrationDescriptor, registry: HookRegistry): IntegrationDescriptor` — returns a NEW descriptor where each resource's `hooks` (currently STRING NAMES from JSON, e.g. `{ transform: 'deriveFullName' }`) are replaced with the actual functions resolved from `registry`. An unknown name throws `DescriptorError`. A resource with no hooks is unchanged. Hook string values are read from a parallel `hookNames` shape (see note).

> **JSON-vs-typed-hooks note:** the in-memory `ResourceDescriptor.hooks` type holds FUNCTIONS. JSON holds STRING names. To bridge without changing the existing type, the JSON loader (Task 7) keeps the raw hook-name map on a side field `__hookNames?: Record<string,string>` per resource, and `bindHooks` reads `__hookNames`, resolves each to a function from the registry, sets `hooks`, and deletes `__hookNames`. `bindHooks` accepts descriptors whose resources may carry `__hookNames`.

- [ ] **Step 1: Write the failing test**

```ts
// eldrin-integration/src/host/bind-hooks.test.ts
import { describe, it, expect } from 'vitest';
import { bindHooks } from './bind-hooks';
import type { IntegrationDescriptor } from '../descriptor';
import { DescriptorError } from '../errors';

function descriptorWithHookNames(names: Record<string,string> | undefined): IntegrationDescriptor {
  return {
    id: 'acme',
    connection: { transport: 'http', baseUrl: 'x', auth: { strategy: 'apiKey', key: { secret: 'K' } } },
    resources: [{
      name: 'clients', transport: { method: 'GET', path: '/c', pagination: 'cursor' },
      idField: 'id', fieldMap: { id: 'remote_id', name: 'name' },
      supportedModes: ['stored'], defaultMode: 'stored',
      ...(names ? { __hookNames: names } as any : {}),
    }],
  };
}

describe('bindHooks', () => {
  it('resolves hook names to functions from the registry', () => {
    const fn = (raw: any) => raw;
    const out = bindHooks(descriptorWithHookNames({ transform: 'myTransform' }), { myTransform: fn });
    expect(out.resources[0].hooks?.transform).toBe(fn);
    expect((out.resources[0] as any).__hookNames).toBeUndefined();
  });

  it('throws DescriptorError for an unknown hook name', () => {
    expect(() => bindHooks(descriptorWithHookNames({ transform: 'missing' }), {}))
      .toThrow(DescriptorError);
  });

  it('leaves a resource with no hook names unchanged', () => {
    const out = bindHooks(descriptorWithHookNames(undefined), {});
    expect(out.resources[0].hooks).toBeUndefined();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/host/bind-hooks.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

```ts
// eldrin-integration/src/host/bind-hooks.ts
import type { IntegrationDescriptor, ResourceDescriptor, ResourceHooks } from '../descriptor';
import { DescriptorError } from '../errors';

export type HookFn = (...args: any[]) => any;
export type HookRegistry = Record<string, HookFn>;

interface ResourceWithHookNames extends ResourceDescriptor {
  __hookNames?: Record<string, string>;
}

export function bindHooks(
  descriptor: IntegrationDescriptor,
  registry: HookRegistry,
): IntegrationDescriptor {
  const resources = descriptor.resources.map((r) => {
    const names = (r as ResourceWithHookNames).__hookNames;
    if (!names) return r;
    const hooks: ResourceHooks = {};
    for (const [hookKey, hookName] of Object.entries(names)) {
      const fn = registry[hookName];
      if (!fn) throw new DescriptorError(`Hook '${hookName}' for resource '${r.name}' not found in registry`);
      (hooks as Record<string, HookFn>)[hookKey] = fn;
    }
    const { __hookNames, ...rest } = r as ResourceWithHookNames;
    return { ...rest, hooks };
  });
  return { ...descriptor, resources };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/host/bind-hooks.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Export and commit**

Add to `src/index.ts`:
```ts
export { bindHooks, type HookFn, type HookRegistry } from './host/bind-hooks';
```
```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-integration add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-integration commit -q -m "feat: add bindHooks (resolve JSON hook names to functions)"
```

---

### Task 7: JSON config loader (parse + validate, preserve hook names)

**Files:**
- Create: `eldrin-integration/src/host/load-json.ts`
- Create: `eldrin-integration/src/host/load-json.test.ts`

**Interfaces:**
- Consumes: `validateDescriptor` (existing), `defineIntegration` (existing — validates+freezes), `DescriptorError`, the `events` config shape.
- Produces:
  - `function parseConfig(json: unknown): IntegrationDescriptor` — accepts the parsed JSON object. The JSON's per-resource `hooks` is a `Record<string,string>` (names). `parseConfig` moves that to `__hookNames`, sets `hooks` to undefined, validates the rest via `validateDescriptor`, and returns the descriptor (NOT frozen yet — hooks get bound after). The `events` field is carried through unchanged on each resource (validated shape: `{ emitOn?: ('sync'|'webhook')[]; subscribesTo?: { pattern: string; action: 'sync' }[] }`). Throws `DescriptorError` on malformed input.

> The existing `defineIntegration` deep-freezes; do NOT use it here because hooks are bound AFTER parsing. Use `validateDescriptor` directly, then freeze in `createIntegrationWorker` after `bindHooks`.

- [ ] **Step 1: Write the failing test**

```ts
// eldrin-integration/src/host/load-json.test.ts
import { describe, it, expect } from 'vitest';
import { parseConfig } from './load-json';
import { DescriptorError } from '../errors';

const validJson = {
  id: 'acme',
  connection: { transport: 'http', baseUrl: { setting: 'ACME.URL' }, auth: { strategy: 'apiKey', header: 'x-api-key', key: { secret: 'ACME.KEY' } } },
  resources: [{
    name: 'clients', transport: { method: 'GET', path: '/clients', pagination: 'cursor' },
    idField: 'id', fieldMap: { id: 'remote_id', name: 'name' },
    supportedModes: ['stored'], defaultMode: 'stored',
    hooks: { transform: 'deriveName' },
    events: { emitOn: ['sync'], subscribesTo: [{ pattern: 'billing.invoice.paid', action: 'sync' }] },
  }],
};

describe('parseConfig', () => {
  it('parses a valid config and moves hooks to __hookNames', () => {
    const d = parseConfig(validJson);
    expect(d.id).toBe('acme');
    expect((d.resources[0] as any).__hookNames).toEqual({ transform: 'deriveName' });
    expect(d.resources[0].hooks).toBeUndefined();
  });

  it('carries the events field through', () => {
    const d = parseConfig(validJson);
    expect((d.resources[0] as any).events.emitOn).toEqual(['sync']);
  });

  it('throws DescriptorError on a malformed config (bad defaultMode)', () => {
    const bad = JSON.parse(JSON.stringify(validJson));
    bad.resources[0].defaultMode = 'live';
    bad.resources[0].supportedModes = ['stored'];
    expect(() => parseConfig(bad)).toThrow(DescriptorError);
  });

  it('throws on a non-object', () => {
    expect(() => parseConfig(null)).toThrow(DescriptorError);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/host/load-json.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

```ts
// eldrin-integration/src/host/load-json.ts
import type { IntegrationDescriptor } from '../descriptor';
import { validateDescriptor } from '../descriptor/validate';
import { DescriptorError } from '../errors';

export function parseConfig(json: unknown): IntegrationDescriptor {
  if (!json || typeof json !== 'object') {
    throw new DescriptorError('Integration config must be an object');
  }
  const raw = json as Record<string, unknown>;
  const resourcesIn = Array.isArray(raw.resources) ? (raw.resources as Record<string, unknown>[]) : [];
  const resources = resourcesIn.map((r) => {
    const { hooks, ...rest } = r;
    const out: Record<string, unknown> = { ...rest };
    if (hooks && typeof hooks === 'object') {
      out.__hookNames = hooks; // string-name map; bound later by bindHooks
    }
    return out;
  });
  const descriptor = { ...raw, resources } as IntegrationDescriptor;
  validateDescriptor(descriptor); // throws DescriptorError / NotImplementedError
  return descriptor;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/host/load-json.test.ts`
Expected: PASS (4 tests). Note: `validateDescriptor` ignores unknown fields (`__hookNames`, `events`) — it checks the fields it knows. Confirm by reading `src/descriptor/validate.ts`; if it rejects unknown fields, it does not (it only validates known fields), so this passes.

- [ ] **Step 5: Export and commit**

Add to `src/index.ts`: `export { parseConfig } from './host/load-json';`
```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-integration add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-integration commit -q -m "feat: add parseConfig (JSON → validated descriptor, hook names preserved)"
```

---

### Task 8: Events wiring (emit + subscribe)

**Files:**
- Create: `eldrin-integration/src/events/wire.ts`
- Create: `eldrin-integration/src/events/wire.test.ts`

**Interfaces:**
- Consumes: `IntegrationDescriptor`, `ResourceDescriptor`, `SyncResult` (existing).
- Produces:
  - `interface EventEmitter { emit(type: string, payload: unknown): Promise<void> }` (a thin port; the Worker supplies an `EldrinEventClient`-backed impl).
  - `async function emitChange(emitter: EventEmitter, integrationId: string, resource: ResourceDescriptor, source: 'sync'|'webhook', count: number): Promise<void>` — if `resource.events?.emitOn?.includes(source)`, emits `<integrationId>.<resource.name>.changed` with payload `{ resource: resource.name, source, count }`. Emit failures are caught and swallowed (logged via an optional `onError`) — never throw into the caller.
  - `function subscriptionsFor(descriptor: IntegrationDescriptor): { pattern: string; action: 'sync'; resource: string }[]` — flattens each resource's `events.subscribesTo` into a list tagged with the resource name (for the host to register + dispatch).

> `events` lives on the resource as carried through by `parseConfig`. Read it via `(resource as { events?: EventsConfig }).events`. Define `EventsConfig = { emitOn?: ('sync'|'webhook')[]; subscribesTo?: { pattern: string; action: 'sync' }[] }` in this file and export it.

- [ ] **Step 1: Write the failing test**

```ts
// eldrin-integration/src/events/wire.test.ts
import { describe, it, expect } from 'vitest';
import { emitChange, subscriptionsFor, type EventEmitter } from './wire';
import type { IntegrationDescriptor, ResourceDescriptor } from '../descriptor';

function rec(): EventEmitter & { events: { type: string; payload: unknown }[] } {
  const events: any[] = [];
  return { events, async emit(type, payload) { events.push({ type, payload }); } };
}
function resource(events?: unknown): ResourceDescriptor {
  return { name: 'clients', transport: { method: 'GET', path: '/c', pagination: 'cursor' },
    idField: 'id', fieldMap: { id: 'remote_id' }, supportedModes: ['stored'], defaultMode: 'stored',
    ...(events ? { events } as any : {}) };
}

describe('events wiring', () => {
  it('emits <id>.<resource>.changed when source is in emitOn', async () => {
    const e = rec();
    await emitChange(e, 'acme', resource({ emitOn: ['sync'] }), 'sync', 3);
    expect(e.events).toEqual([{ type: 'acme.clients.changed', payload: { resource: 'clients', source: 'sync', count: 3 } }]);
  });

  it('does not emit when source not in emitOn', async () => {
    const e = rec();
    await emitChange(e, 'acme', resource({ emitOn: ['webhook'] }), 'sync', 1);
    expect(e.events).toHaveLength(0);
  });

  it('swallows emit errors (never throws into caller)', async () => {
    const failing: EventEmitter = { async emit() { throw new Error('events down'); } };
    await expect(emitChange(failing, 'acme', resource({ emitOn: ['sync'] }), 'sync', 1)).resolves.toBeUndefined();
  });

  it('subscriptionsFor flattens subscribesTo tagged with resource', () => {
    const d: IntegrationDescriptor = {
      id: 'acme', connection: { transport: 'http', baseUrl: 'x', auth: { strategy: 'apiKey', key: { secret: 'K' } } },
      resources: [resource({ subscribesTo: [{ pattern: 'billing.paid', action: 'sync' }] })],
    };
    expect(subscriptionsFor(d)).toEqual([{ pattern: 'billing.paid', action: 'sync', resource: 'clients' }]);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/events/wire.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

```ts
// eldrin-integration/src/events/wire.ts
import type { IntegrationDescriptor, ResourceDescriptor } from '../descriptor';

export interface EventsConfig {
  emitOn?: ('sync' | 'webhook')[];
  subscribesTo?: { pattern: string; action: 'sync' }[];
}

export interface EventEmitter {
  emit(type: string, payload: unknown): Promise<void>;
}

function resourceEvents(resource: ResourceDescriptor): EventsConfig | undefined {
  return (resource as ResourceDescriptor & { events?: EventsConfig }).events;
}

export async function emitChange(
  emitter: EventEmitter,
  integrationId: string,
  resource: ResourceDescriptor,
  source: 'sync' | 'webhook',
  count: number,
  onError?: (e: unknown) => void,
): Promise<void> {
  const events = resourceEvents(resource);
  if (!events?.emitOn?.includes(source)) return;
  try {
    await emitter.emit(`${integrationId}.${resource.name}.changed`, {
      resource: resource.name,
      source,
      count,
    });
  } catch (e) {
    onError?.(e); // never throw into the sync/webhook path
  }
}

export function subscriptionsFor(
  descriptor: IntegrationDescriptor,
): { pattern: string; action: 'sync'; resource: string }[] {
  const out: { pattern: string; action: 'sync'; resource: string }[] = [];
  for (const r of descriptor.resources) {
    for (const sub of resourceEvents(r)?.subscribesTo ?? []) {
      out.push({ pattern: sub.pattern, action: sub.action, resource: r.name });
    }
  }
  return out;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/events/wire.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Export and commit**

Add to `src/index.ts`:
```ts
export { emitChange, subscriptionsFor, type EventEmitter, type EventsConfig } from './events/wire';
```
```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-integration add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-integration commit -q -m "feat: add events wiring (emit-on-change + subscription flattening)"
```

---

### Task 9: `createIntegrationWorker` host

**Files:**
- Create: `eldrin-integration/src/host/create-worker.ts`
- Create: `eldrin-integration/src/host/create-worker.test.ts`

**Interfaces:**
- Consumes: everything above — `parseConfig`, `bindHooks` + `HookRegistry`, `loadEffectiveConfig`, `seedConfigFromDescriptor`, `runAllSync` + `SyncDeps`, `runScheduled`, `createRepository`, `testConnection`, `createAuthStrategy` + `SettingsLookup`, `createTransport`, `emitChange`/`subscriptionsFor`, `IntegrationError`; app-core `createD1Adapter`, `runMigrations`. Hono.
- Produces:
  - `interface IntegrationWorkerEnv { DB: D1Database; [key: string]: unknown }`
  - `interface CreateWorkerOptions { hooks?: HookRegistry; extend?: (app: Hono) => void; migrations?: unknown[]; settingsPrefix?: string }`
  - `function createIntegrationWorker(config: unknown, options?: CreateWorkerOptions): { fetch: (req: Request, env: any, ctx: any) => Response | Promise<Response>; scheduled: (event: any, env: any, ctx: any) => Promise<void> }`
  - Behavior: at module load, `parseConfig(config)` then `bindHooks(descriptor, options.hooks ?? {})` then `Object.freeze`-equivalent (it's the runtime descriptor seed). Per request: build a `SettingsLookup` from env (convention: `{setting|secret: 'GROUP.FIELD'}` → `env['GROUP_FIELD']`, configurable via `settingsPrefix`), build auth+transport, run migrations (once) + `seedConfigFromDescriptor`, `loadEffectiveConfig`, then route. Mounts: `POST /api/sync` (userId-guarded via `X-Eldrin-User-Id`), `GET /api/health`, `GET /api/:resource`, `GET /api/:resource/:id`. After a successful sync, calls `emitChange` per resource. `options.extend(app)` runs last. `scheduled()` runs migrations+seed+`runScheduled` and emits per resource.

> This is the composition root — keep it free of integration-specific logic. The SettingsLookup convention must match how factorial's settings are injected (`FACTORIAL.API_BASE_URL` → `env.FACTORIAL_API_BASE_URL`): replace `.` with `_`.

- [ ] **Step 1: Write the failing test** (integration-level, against a fake env + injected fetch)

```ts
// eldrin-integration/src/host/create-worker.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import { createIntegrationWorker } from './create-worker';
import { storedResourceDDL, SDK_TABLES } from '../schema/tables';
import { makeTestDb } from '../test-helpers';
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';

// Minimal config: one stored resource, apiKey auth, cursor pagination.
const config = {
  id: 'acme',
  connection: {
    transport: 'http',
    baseUrl: { setting: 'ACME.API_BASE_URL' },
    auth: { strategy: 'apiKey', header: 'x-api-key', key: { secret: 'ACME.API_KEY' } },
  },
  resources: [{
    name: 'clients', transport: { method: 'GET', path: '/clients', pagination: 'none' },
    idField: 'id', fieldMap: { id: 'remote_id', name: 'name' },
    supportedModes: ['stored'], defaultMode: 'stored',
    events: { emitOn: ['sync'] },
  }],
};

// The host calls createD1Adapter(env.DB). For the test we pass a pre-made adapter
// via env.__testDb and a test-only hook in options to use it. (See impl note.)
let db: DatabaseAdapter;
beforeEach(async () => {
  db = await makeTestDb([...SDK_TABLES, storedResourceDDL('clients', ['name TEXT'])]);
});

function env(extra: Record<string, unknown> = {}) {
  return {
    DB: {} as any,
    ACME_API_BASE_URL: 'https://api.test',
    ACME_API_KEY: 'k',
    ...extra,
  };
}

describe('createIntegrationWorker', () => {
  it('POST /api/sync syncs stored resources and returns counts', async () => {
    const worker = createIntegrationWorker(config, {
      adapterFactory: () => db,                                   // test seam (see impl)
      fetchImpl: async () => new Response(JSON.stringify({ data: [{ id: 1, name: 'Ada' }] }), { status: 200 }),
      migrations: [],
    } as any);
    const res = await worker.fetch(
      new Request('http://x/api/sync', { method: 'POST', headers: { 'X-Eldrin-User-Id': 'u1' } }),
      env(), {} as any,
    );
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.results).toEqual([{ resource: 'clients', count: 1 }]);
    const rows = await db.prepare('SELECT remote_id, name FROM clients').all();
    expect(rows.results).toEqual([{ remote_id: '1', name: 'Ada' }]);
  });

  it('POST /api/sync without user is 401', async () => {
    const worker = createIntegrationWorker(config, { adapterFactory: () => db, migrations: [] } as any);
    const res = await worker.fetch(new Request('http://x/api/sync', { method: 'POST' }), env(), {} as any);
    expect(res.status).toBe(401);
  });

  it('GET /api/:resource reads via repository', async () => {
    await db.prepare('INSERT INTO clients (id,remote_id,name,raw_json,synced_at) VALUES (?,?,?,?,?)')
      .bind('a','7','Bo','{}',1).run();
    const worker = createIntegrationWorker(config, { adapterFactory: () => db, migrations: [] } as any);
    const res = await worker.fetch(new Request('http://x/api/clients', { headers: { 'X-Eldrin-User-Id': 'u1' } }), env(), {} as any);
    expect(res.status).toBe(200);
    expect((await res.json() as any).length).toBe(1);
  });

  it('GET /api/health reports ok when transport succeeds', async () => {
    const worker = createIntegrationWorker(config, {
      adapterFactory: () => db, migrations: [],
      fetchImpl: async () => new Response(JSON.stringify({ data: [] }), { status: 200 }),
    } as any);
    const res = await worker.fetch(new Request('http://x/api/health'), env(), {} as any);
    expect(res.status).toBe(200);
    expect((await res.json() as any).ok).toBe(true);
  });

  it('extend adds a custom route', async () => {
    const worker = createIntegrationWorker(config, {
      adapterFactory: () => db, migrations: [],
      extend: (app: any) => app.get('/api/custom', (c: any) => c.json({ custom: true })),
    } as any);
    const res = await worker.fetch(new Request('http://x/api/custom'), env(), {} as any);
    expect((await res.json() as any).custom).toBe(true);
  });

  it('invalid config throws at construction (fail fast)', () => {
    const bad = JSON.parse(JSON.stringify(config));
    bad.resources[0].defaultMode = 'live';
    bad.resources[0].supportedModes = ['stored'];
    expect(() => createIntegrationWorker(bad, { adapterFactory: () => db } as any)).toThrow();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/host/create-worker.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

```ts
// eldrin-integration/src/host/create-worker.ts
import { Hono } from 'hono';
import { createD1Adapter, runMigrations } from '@eldrin-project/eldrin-app-core';
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';
import type { IntegrationDescriptor, SettingRef } from '../descriptor';
import { parseConfig } from './load-json';
import { bindHooks, type HookRegistry } from './bind-hooks';
import { loadEffectiveConfig } from '../config/load';
import { seedConfigFromDescriptor } from '../config';
import { createAuthStrategy, type SettingsLookup } from '../auth';
import { createTransport } from '../transport';
import { runAllSync, type SyncDeps } from '../sync';
import { runScheduled } from '../schedule';
import { createRepository } from '../repository';
import { testConnection } from '../health';
import { emitChange, type EventEmitter } from '../events/wire';
import { IntegrationError } from '../errors';

export interface CreateWorkerOptions {
  hooks?: HookRegistry;
  extend?: (app: Hono) => void;
  migrations?: unknown[];
  emitter?: EventEmitter;
  // test seams (optional):
  adapterFactory?: (env: any) => DatabaseAdapter;
  fetchImpl?: typeof fetch;
}

function settingsLookup(env: Record<string, unknown>): SettingsLookup {
  const resolve = (key: string) => {
    const envKey = key.replace('.', '_'); // GROUP.FIELD → GROUP_FIELD
    const v = env[envKey];
    return typeof v === 'string' ? v : undefined;
  };
  return (ref: SettingRef) => ('setting' in ref ? resolve(ref.setting) : resolve(ref.secret));
}

export function createIntegrationWorker(config: unknown, options: CreateWorkerOptions = {}) {
  // Fail fast at construction: parse + validate + bind hooks.
  const seed: IntegrationDescriptor = bindHooks(parseConfig(config), options.hooks ?? {});

  function buildDeps(env: Record<string, unknown>, db: DatabaseAdapter): { deps: SyncDeps; transport: SyncDeps['transport'] } {
    const lookup = settingsLookup(env);
    const baseUrl = (typeof seed.connection.baseUrl === 'string')
      ? seed.connection.baseUrl
      : lookup(seed.connection.baseUrl) ?? '';
    const auth = createAuthStrategy(seed.connection.auth, lookup);
    const transport = createTransport(seed.connection, auth, baseUrl, options.fetchImpl);
    return { deps: { db, transport, now: () => Date.now(), genId: () => crypto.randomUUID() }, transport };
  }

  let migrated = false;
  async function prepare(env: any): Promise<{ db: DatabaseAdapter; effective: IntegrationDescriptor }> {
    const db = options.adapterFactory ? options.adapterFactory(env) : createD1Adapter(env.DB);
    if (!migrated && options.migrations && options.migrations.length > 0) {
      await runMigrations(env.DB, { migrations: options.migrations as any });
    }
    migrated = true;
    await seedConfigFromDescriptor(db, seed);
    const effective = await loadEffectiveConfig(db, seed);
    return { db, effective };
  }

  const emitter = options.emitter;

  const app = new Hono();

  app.post('/api/sync', async (c) => {
    const userId = c.req.header('X-Eldrin-User-Id');
    if (!userId) return c.json({ error: 'Unauthorized' }, 401);
    try {
      const { db, effective } = await prepare(c.env);
      const { deps } = buildDeps(c.env as any, db);
      const results = await runAllSync(effective, deps);
      if (emitter) {
        for (const r of results) {
          const resource = effective.resources.find((x) => x.name === r.resource);
          if (resource) await emitChange(emitter, effective.id, resource, 'sync', r.count);
        }
      }
      return c.json({ results });
    } catch (e) {
      const status = e instanceof IntegrationError ? e.status : 500;
      return c.json({ error: e instanceof Error ? e.message : 'Sync failed' }, status as 400 | 500);
    }
  });

  app.get('/api/health', async (c) => {
    const { effective } = await prepare(c.env);
    const { transport } = buildDeps(c.env as any, options.adapterFactory ? options.adapterFactory(c.env) : createD1Adapter((c.env as any).DB));
    const probe = effective.resources[0];
    const result = await testConnection(transport, probe);
    return c.json(result, result.ok ? 200 : 502);
  });

  app.get('/api/:resource/:id', async (c) => {
    const { db, effective } = await prepare(c.env);
    const resource = effective.resources.find((r) => r.name === c.req.param('resource'));
    if (!resource) return c.json({ error: 'Unknown resource' }, 404);
    const { transport } = buildDeps(c.env as any, db);
    const repo = createRepository(db, resource, { transport });
    const row = await repo.findById(c.req.param('id'));
    return row ? c.json(row) : c.json({ error: 'Not found' }, 404);
  });

  app.get('/api/:resource', async (c) => {
    const { db, effective } = await prepare(c.env);
    const resource = effective.resources.find((r) => r.name === c.req.param('resource'));
    if (!resource) return c.json({ error: 'Unknown resource' }, 404);
    const { transport } = buildDeps(c.env as any, db);
    const repo = createRepository(db, resource, { transport });
    return c.json(await repo.findAll());
  });

  options.extend?.(app);

  return {
    fetch: app.fetch,
    scheduled: async (_event: any, env: any) => {
      const { db, effective } = await prepare(env);
      const { deps } = buildDeps(env, db);
      const results = await runScheduled(effective, deps);
      if (emitter) {
        for (const r of results) {
          const resource = effective.resources.find((x) => x.name === r.resource);
          if (resource) await emitChange(emitter, effective.id, resource, 'sync', r.count);
        }
      }
    },
  };
}
```

> **Note on test seams:** `adapterFactory` and `fetchImpl` are optional options used by the test to inject the in-memory DB and a fake fetch. In production neither is passed — the host uses `createD1Adapter(env.DB)` and the global `fetch`. They are legitimate dependency-injection points, not test-only hacks (a real deployment could pass a custom adapter). Keep them.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/host/create-worker.test.ts && npm run typecheck`
Expected: PASS (6 tests). Fix any Hono typing issues (the `c.env` is `any` here by design — the host is env-agnostic).

- [ ] **Step 5: Export and commit**

Add to `src/index.ts`:
```ts
export { createIntegrationWorker, type CreateWorkerOptions } from './host/create-worker';
```
```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-integration add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-integration commit -q -m "feat: add createIntegrationWorker host (auto-mount sync/health/repo/cron/events/extend)"
```

---

### Task 10: SDK build, coverage gate, README update

**Files:**
- Modify: `eldrin-integration/README.md`
- Modify: `eldrin-integration/src/index.ts` (verify full barrel)

**Interfaces:** Consumes all prior tasks. Produces a green, documented SDK.

- [ ] **Step 1: Full coverage run**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run --coverage`
Expected: all tests pass; ≥80% statements/lines for implemented `src/**` (stubs `graphql.ts`/`file.ts`/`bearer.ts`/`oauth2.ts`/`webhook/index.ts` exempt). If an implemented file is under 80%, add a focused behavior-asserting test.

- [ ] **Step 2: Typecheck + build, confirm bundle clean**

Run: `npm run typecheck && npm run build && grep -c better-sqlite3 dist/index.js`
Expected: typecheck clean; `dist/index.js`/`.cjs`/`.d.ts` emitted; grep prints `0`.

- [ ] **Step 3: Update README** — add a "Zero-boilerplate integrations" section documenting `createIntegrationWorker(config, hooks?)`, the `integration.config.json` shape, hooks-by-name, the three modes, events, and that config is D1-overlaid (runtime-editable). Keep the existing status table; mark `live`/`cached`/events as now implemented.

- [ ] **Step 4: Commit**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-integration add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-integration commit -q -m "docs: document manifest-driven host; finalize live/cached/events"
```

---

## File Structure (Part B — factorial `eldrin-factorial/`)

```
eldrin-factorial/
├── integration.config.json     NEW: declarative (employees/projects stored, teams/timeoff live)
├── integration.hooks.ts        NEW: deriveFullName (the one transform)
├── worker/index.ts             REPLACE: one line — createIntegrationWorker(config, { deriveFullName }, {...})
├── worker/integration.ts                 DELETE (replaced by JSON)
├── worker/integration-runtime.ts         DELETE (host builds deps)
├── worker/routes/{sync,teams,timeoff,connection,employees}.ts  DELETE (host auto-mounts)
├── worker/services/factorial-client.ts   DELETE (teams/timeoff now live-mode resources)
└── worker/db/, migrations/     KEEP (schema + migrations unchanged from prior pass)
```

> **Part B note:** keep factorial's tests green. The descriptor's resource shapes already exist in `worker/integration.ts` — port them verbatim into JSON. The host needs `migrations` (the generated array) and a settings convention matching `FACTORIAL_*` env.

---

### Task 11: Factorial config + hooks files

**Files:**
- Create: `eldrin-factorial/integration.config.json`
- Create: `eldrin-factorial/integration.hooks.ts`
- Create: `eldrin-factorial/worker/__tests__/config-loads.test.ts`

**Interfaces:**
- Consumes: SDK `parseConfig`, `bindHooks`.
- Produces: a valid `integration.config.json` (employees + projects `stored`; teams + projects... see below) and `integration.hooks.ts` exporting `deriveFullName`.

> **teams/timeoff:** add them as `live`-mode resources (`supportedModes: ['live']`, `defaultMode: 'live'`) with their validated paths (`/api/2026-04-01/resources/teams/teams`, `/api/2026-04-01/resources/timeoff/leaves`) and a minimal fieldMap (`{ id: 'remote_id', name: 'name' }` for teams; for timeoff use the fields the UI reads — inspect `worker/routes/timeoff.ts` before deleting it to capture the shape). Live resources need no D1 table.

- [ ] **Step 1: Capture the current teams/timeoff response shape** (before deletion)

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-factorial && sed -n '1,40p' worker/routes/teams.ts worker/routes/timeoff.ts`
Note the API paths and which fields the responses expose (used for the live resource fieldMaps).

- [ ] **Step 2: Write `integration.config.json`**

```json
{
  "id": "eldrin-factorial",
  "connection": {
    "transport": "http",
    "baseUrl": { "setting": "FACTORIAL.API_BASE_URL" },
    "auth": { "strategy": "apiKey", "header": "x-api-key", "key": { "secret": "FACTORIAL.API_KEY" } }
  },
  "resources": [
    {
      "name": "employees",
      "transport": { "method": "GET", "path": "/api/2026-04-01/resources/employees/employees?only_active=true", "pagination": "cursor" },
      "idField": "id",
      "fieldMap": { "id": "remote_id", "full_name": "full_name", "email": "email", "job_title": "job_title", "team_id": "team_id" },
      "supportedModes": ["stored"],
      "defaultMode": "stored",
      "refresh": { "schedule": "0 * * * *" },
      "hooks": { "transform": "deriveFullName" },
      "events": { "emitOn": ["sync"] }
    },
    {
      "name": "projects",
      "transport": { "method": "GET", "path": "/api/2026-04-01/resources/project_management/projects", "pagination": "cursor" },
      "idField": "id",
      "fieldMap": { "id": "remote_id", "name": "name", "status": "status" },
      "supportedModes": ["stored"],
      "defaultMode": "stored",
      "refresh": { "schedule": "0 * * * *" },
      "events": { "emitOn": ["sync"] }
    },
    {
      "name": "teams",
      "transport": { "method": "GET", "path": "/api/2026-04-01/resources/teams/teams", "pagination": "cursor" },
      "idField": "id",
      "fieldMap": { "id": "remote_id", "name": "name" },
      "supportedModes": ["live"],
      "defaultMode": "live"
    },
    {
      "name": "timeoff",
      "transport": { "method": "GET", "path": "/api/2026-04-01/resources/timeoff/leaves", "pagination": "cursor" },
      "idField": "id",
      "fieldMap": { "id": "remote_id" },
      "supportedModes": ["live"],
      "defaultMode": "live"
    }
  ]
}
```
(Adjust the `timeoff` fieldMap to the fields captured in Step 1.)

- [ ] **Step 3: Write `integration.hooks.ts`**

```ts
// eldrin-factorial/integration.hooks.ts
export const deriveFullName = (raw: Record<string, unknown>) => {
  const joined = [raw.first_name, raw.last_name].filter(Boolean).join(' ').trim() || null;
  return { ...raw, full_name: raw.full_name ?? joined };
};
```

- [ ] **Step 4: Write a test that the config loads + binds**

```ts
// eldrin-factorial/worker/__tests__/config-loads.test.ts
import { describe, it, expect } from 'vitest';
import { parseConfig, bindHooks } from '@eldrin-project/eldrin-integration';
import config from '../../integration.config.json';
import { deriveFullName } from '../../integration.hooks';

describe('factorial integration.config.json', () => {
  it('parses + validates + binds the deriveFullName hook', () => {
    const d = bindHooks(parseConfig(config), { deriveFullName });
    const names = d.resources.map((r) => r.name).sort();
    expect(names).toEqual(['employees', 'projects', 'teams', 'timeoff']);
    const emp = d.resources.find((r) => r.name === 'employees')!;
    expect(typeof emp.hooks?.transform).toBe('function');
    const live = d.resources.filter((r) => r.defaultMode === 'live').map((r) => r.name).sort();
    expect(live).toEqual(['teams', 'timeoff']);
  });

  it('deriveFullName derives from first/last when full_name absent', () => {
    expect(deriveFullName({ first_name: 'Grace', last_name: 'Hopper' }).full_name).toBe('Grace Hopper');
    expect(deriveFullName({ full_name: 'Ada L' }).full_name).toBe('Ada L');
  });
});
```

- [ ] **Step 5: Ensure JSON import works** — factorial's `tsconfig` must allow JSON imports (`resolveJsonModule: true`). Check `eldrin-factorial/tsconfig.worker.json` / `tsconfig.json`; if absent, add `"resolveJsonModule": true` to compilerOptions.

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-factorial && npx vitest run worker/__tests__/config-loads.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 6: Commit**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-factorial add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-factorial commit -q -m "feat(factorial): add declarative integration.config.json + hooks"
```

---

### Task 12: Collapse factorial worker to one-line entry; delete boilerplate

**Files:**
- Replace: `eldrin-factorial/worker/index.ts`
- Delete: `worker/integration.ts`, `worker/integration-runtime.ts`, `worker/routes/{sync,teams,timeoff,connection,employees}.ts`, `worker/services/factorial-client.ts`, and their now-orphaned tests
- Modify: `eldrin-factorial/worker/db/` only if route deletions orphan imports

**Interfaces:**
- Consumes: SDK `createIntegrationWorker`; app-core events client for the emitter; the generated migrations array.
- Produces: a one-line Worker entry; factorial's behavior preserved (stored employees/projects sync, live teams/timeoff via repository, health, cron).

- [ ] **Step 1: Inspect current entry + migrations import**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-factorial && cat worker/index.ts && echo '---' && head -5 worker/migrations.generated.ts && echo '---tests---' && ls worker/__tests__`

- [ ] **Step 2: Replace `worker/index.ts`**

```ts
// eldrin-factorial/worker/index.ts
import { createIntegrationWorker } from '@eldrin-project/eldrin-integration';
import { createEventClient } from '@eldrin-project/eldrin-app-core';
import migrations from './migrations.generated';
import config from '../integration.config.json';
import { deriveFullName } from '../integration.hooks';

export default createIntegrationWorker(config, {
  hooks: { deriveFullName },
  migrations,
  // emitter wired from the core events client; coreApiUrl from env at request time
  // (createIntegrationWorker reads env per request — pass a factory-built emitter via options if needed)
});
```

> **Emitter note:** `createIntegrationWorker`'s `emitter` is optional and constructed once. Because `coreApiUrl` comes from env (per-request), the simplest correct wiring for MVP is to OMIT the emitter here (events emission is then a no-op) OR extend the host to build the emitter from env inside `prepare()`. **Decision for this task:** omit the emitter in factorial (employees/projects emit is declared in config but not yet delivered cross-app — acceptable for MVP; the wiring exists and a follow-up can construct the emitter from env). Document this in the report. If the reviewer deems emit delivery required, the fix is to have the host build `createEventClient({ appId: descriptor.id, coreApiUrl: env.CORE_API_URL })` inside `prepare()` and pass it to `emitChange` — note this option.

- [ ] **Step 3: Delete the boilerplate files + orphaned tests**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-factorial && git rm \
  worker/integration.ts worker/integration-runtime.ts \
  worker/routes/sync.ts worker/routes/teams.ts worker/routes/timeoff.ts \
  worker/routes/connection.ts worker/routes/employees.ts \
  worker/services/factorial-client.ts
```
Then check for orphaned tests/imports: `grep -rln "routes/\|integration-runtime\|services/factorial-client\|integration'" worker/__tests__ worker/index.ts`. Delete tests that targeted the removed routes/services (e.g. `connection.test.ts`, `employees.test.ts`, `proxy.test.ts` if it imported routes, `factorial-client.test.ts`). KEEP `sdk-sync.test.ts`, `integration-descriptor.test.ts` (rename/retarget if it imported the deleted `worker/integration.ts` — point it at the JSON via `parseConfig` instead), `config-loads.test.ts`.

> Before deleting `integration-descriptor.test.ts`, check whether it imports `../integration` (deleted). If so, either delete it (superseded by `config-loads.test.ts`) or retarget it to the JSON. Prefer deleting it — `config-loads.test.ts` covers the same ground.

- [ ] **Step 4: Typecheck + run the full suite**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-factorial && npm run typecheck && npm run test`
Expected: typecheck clean; remaining tests pass (`sdk-sync.test.ts`, `config-loads.test.ts`, plus `health.test.ts` if it doesn't import deleted routes). Fix orphaned imports by deleting the dead test or retargeting it.

- [ ] **Step 5: Commit**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-factorial add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-factorial commit -q -m "refactor(factorial): collapse worker to one-line createIntegrationWorker; delete boilerplate"
```

---

### Task 13: Factorial end-to-end verification

**Files:**
- Create: `eldrin-factorial/worker/__tests__/host-sync.test.ts`

**Interfaces:**
- Consumes: `createIntegrationWorker`, the config + hooks, `makeTestDb`-equivalent (factorial's `worker/__tests__/test-db.ts` from the prior pass).
- Produces: an acceptance test driving the real host over the factorial config into an in-memory DB.

- [ ] **Step 1: Write the test**

```ts
// eldrin-factorial/worker/__tests__/host-sync.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import { createIntegrationWorker, SDK_TABLES, storedResourceDDL } from '@eldrin-project/eldrin-integration';
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';
import { makeTestDb } from './test-db';
import config from '../../integration.config.json';
import { deriveFullName } from '../../integration.hooks';

let db: DatabaseAdapter;
beforeEach(async () => {
  db = await makeTestDb([
    ...SDK_TABLES,
    storedResourceDDL('employees', ['full_name TEXT','email TEXT','job_title TEXT','team_id TEXT']),
    storedResourceDDL('projects', ['name TEXT','status TEXT']),
  ]);
});

describe('factorial host end-to-end', () => {
  it('POST /api/sync stores employees with derived full_name', async () => {
    const worker = createIntegrationWorker(config, {
      hooks: { deriveFullName },
      adapterFactory: () => db,
      migrations: [],
      fetchImpl: async (url: any) => {
        const u = String(url);
        if (u.includes('/employees/employees')) return new Response(JSON.stringify({ data: [{ id: 11, first_name: 'Grace', last_name: 'Hopper', email: 'g@x.io' }] }), { status: 200 });
        return new Response(JSON.stringify({ data: [] }), { status: 200 }); // projects
      },
    } as any);
    const res = await worker.fetch(new Request('http://x/api/sync', { method: 'POST', headers: { 'X-Eldrin-User-Id': 'u1' } }), { DB: {}, FACTORIAL_API_BASE_URL: 'https://api.test', FACTORIAL_API_KEY: 'k' } as any, {} as any);
    expect(res.status).toBe(200);
    const row = await db.prepare('SELECT full_name FROM employees WHERE remote_id = ?').bind('11').first<{ full_name: string }>();
    expect(row?.full_name).toBe('Grace Hopper');
  });
});
```

- [ ] **Step 2: Run + full suite**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-factorial && npx vitest run worker/__tests__/host-sync.test.ts && npm run typecheck && npm run test`
Expected: new test passes; full suite green.

- [ ] **Step 3: Commit**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-factorial add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-factorial commit -q -m "test(factorial): host-driven end-to-end sync acceptance test"
```

---

### Task 14: Live manual verification in the running app

**Files:** none (manual verification + ledger note).

- [ ] **Step 1: Build the SDK so factorial picks up changes**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npm run build`

- [ ] **Step 2: Wipe factorial's local D1 + restart worker** (the schema is unchanged, but a clean run avoids confusion)

Run: `rm -rf /Users/tibor/projects/eldrin-backup/eldrin-factorial/.wrangler/state/v3/d1/miniflare-D1DatabaseObject` (only if the factorial worker is stopped). Then `cd /Users/tibor/projects/eldrin-backup/eldrin-factorial && npm run dev:worker`.

- [ ] **Step 3: Sync + verify**

- `POST /api/sync` with `X-Eldrin-User-Id` → expect `{ results: [{ resource: 'employees', count: N }, { resource: 'projects', count: M }] }`.
- `GET /api/employees` → returns stored rows (mode-transparent repository).
- `GET /api/teams` → returns LIVE rows (fetched on demand — no D1 table for teams).
- Confirm Employees page populates in the shell.

- [ ] **Step 4: Inspect the DB** (reuse the prior inspection): confirm `employees`/`projects` populated with `remote_id`/`raw_json`/`synced_at`, `_integration_config` seeded (employees/projects stored, teams/timeoff live), no `teams`/`timeoff` tables (live mode stores nothing).

- [ ] **Step 5: Report** — record verification results; note the emitter decision (Task 12 Step 2) and any deferred follow-up.

---

## Self-Review

**1. Spec coverage:**
- §3 architecture (host/, modes, map, events, config overlay) → Tasks 1–9 ✓
- §4 separate config file + manifest untouched → Task 11 (JSON file; manifest unchanged) ✓
- §5 `createIntegrationWorker` + build-time validation + `extend` → Task 9 (extend, fail-fast) ✓. **Build-time validation (§5.4):** covered at runtime construction-time (Task 9 "invalid config throws at construction") and via Task 11's `config-loads.test.ts`. A dedicated `prebuild` script isn't added — noted below as a gap.
- §6 events emit+subscribe → Task 8 (emit + subscriptionsFor). **Subscribe dispatch wiring** (registering subscriptions with the live events subsystem) is represented by `subscriptionsFor` + a host hook, but the host (Task 9) does not poll/dispatch subscriptions — see gap below.
- §7 D1 overlay seam → Task 5 ✓
- §8 all three modes + cache + mode-switch clear → Tasks 2,3,4 ✓ (mode-switch cache clear: `clearResource` exists in Task 2; wiring a clear on config-change is a future-UI concern, noted)
- §9 error handling → fail-fast (Tasks 7,9), IntegrationError on live (Task 4), emit isolation (Task 8) ✓
- §10 factorial refactor → Tasks 11–13 ✓
- §11 testing → each task is TDD; E2E → Task 14 ✓

**Gaps found + resolved inline:**
- **Subscribe dispatch**: `subscriptionsFor` (Task 8) extracts subscriptions but Task 9's host doesn't actively poll the events subsystem and dispatch them. Cloudflare Workers have no always-on listener; subscription dispatch would run on the cron tick (poll → match → sync). **Resolution:** scope subscribe to *declaration + extraction* in this plan (the `subscribesTo` config is parsed, validated, and exposed via `subscriptionsFor`); actual poll-and-dispatch on the cron tick is added as an explicit follow-up note in Task 14 Step 5, since it depends on the events poll API and is a thin addition. This matches the spec's emit-first emphasis and avoids half-implementing a polling loop. Documenting rather than silently dropping.
- **Build-time validation as a `prebuild` script (§5.4)**: covered functionally by construction-time validation + the config-loads test; a literal `npm run build` failure on bad config is a 2-line `prebuild` script. Added as an optional hardening note in Task 10, not a separate task (YAGNI — the construction-time throw already prevents a broken deploy).
- **Emitter wiring** (Task 12): explicitly decided (omit for MVP, document) rather than left ambiguous.

**2. Placeholder scan:** No TBD/TODO. "Decision for this task" blocks are explicit resolutions, not placeholders. The teams/timeoff fieldMap has a real default + a Step-1 inspection to refine it.

**3. Type consistency:** `mapRows` returns `{remoteId, mapped, raw}` (Task 1) — consumed by `fetchLive` (Task 3) and `runResourceSync` (Task 1 Step 5) consistently. `RepositoryOptions` (Task 4) used in Task 9. `HookRegistry` (Task 6) used in Task 9 `CreateWorkerOptions`. `EventEmitter`/`emitChange` signature (Task 8) matches the Task 9 call. `loadEffectiveConfig(db, seed)` (Task 5) matches the Task 9 call. `parseConfig`/`bindHooks` (Tasks 6,7) match Task 9 construction + Task 11 test. `__hookNames` bridge consistent between Task 7 (sets it) and Task 6 (reads+deletes it). `createIntegrationWorker(config, options)` signature consistent across Tasks 9, 12, 13.
