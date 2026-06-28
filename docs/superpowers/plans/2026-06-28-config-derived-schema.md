# Config-Derived Schema (Auto-DDL) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Derive a stored integration's table schema from its descriptor at runtime — the host auto-creates tables + adds new fieldMap columns (non-destructive), and an admin-gated prune action removes orphaned SDK-owned columns/tables — so a stored integration needs zero hand-written migration files.

**Architecture:** Add `ensureSchema` (automatic, idempotent, additive) and `pruneSchema` (admin-triggered, destructive, dry-run-by-default) to the SDK's `src/schema/`. Wire `ensureSchema` into the host's `prepare()` (management tables before config seeding; resource tables after the effective-config overlay) and mount `POST /api/schema/prune`. Refactor `eldrin-factorial` to delete all migration artifacts and rely on auto-DDL.

**Tech Stack:** TypeScript 5.8 (strict, `verbatimModuleSyntax`), tsup (ESM+CJS), Vitest, Hono 4, Cloudflare Workers (D1), `@eldrin-project/eldrin-app-core` (`DatabaseAdapter`). DB-backed tests use the SDK's `makeTestDb` (better-sqlite3, test-only).

## Global Constraints

- **DatabaseAdapter only:** all DB access via `prepare(sql).bind(...).all<T>()/first<T>()/run()` or `exec(sql)`. Never drizzle or raw D1.
- **All stored columns are `TEXT`:** the sync runner stores every mapped value as-is and the existing factorial schema types every fieldMap column `TEXT`. ensureSchema types each derived column as `TEXT`. (The fixed columns are `id TEXT PRIMARY KEY, remote_id TEXT NOT NULL, raw_json TEXT, synced_at INTEGER NOT NULL` — produced by the existing `storedResourceDDL`.)
- **fieldMap → columns:** a resource's stored columns are the `fieldMap` LOCAL names (the values), EXCLUDING the entry whose remote key equals `idField` (that maps to the fixed `remote_id`, not a separate column). This matches the sync runner's `mapRows`, which skips the idField.
- **ensureSchema is non-destructive:** only `CREATE TABLE/INDEX IF NOT EXISTS` and `ALTER TABLE ADD COLUMN`. Never drop/rename/retype.
- **pruneSchema is destructive + gated:** dry-run by default; only touches SDK-owned schema (fixed columns + current fieldMap columns; tables with the SDK signature `remote_id`+`raw_json`+`synced_at`). Never automatic.
- **Stored-resource selection:** a resource participates in schema work when `supportedModes.includes('stored')`. A live-only resource (no `stored`) gets no table.
- **SDK-owned column set** for a stored table = `{ id, remote_id, raw_json, synced_at }` ∪ current fieldMap local columns (excluding idField).
- **Fail fast / no swallow:** ensureSchema errors throw `IntegrationError` with table/column context. pruneSchema records undroppable items in a `skipped[]` and continues; only an unexpected adapter error aborts.
- **SQL identifiers come only from the descriptor** (`resource.name`, fieldMap local names) + the fixed SDK set — never from API data.
- **`verbatimModuleSyntax: true`:** `import type` for type-only imports.
- **Tests:** co-located `*.test.ts`, Vitest, TDD (failing test first), 80%+. DB tests use `makeTestDb(ddl: string[]): Promise<DatabaseAdapter>` from `src/test-helpers.ts`.
- **Commit convention:** Conventional Commits. Attribution disabled.
- **Repo/cwd gotcha:** SDK is `eldrin-integration/` (own git repo), factorial is `eldrin-factorial/`. Run ALL git with `git -C <abs-path>` (absolute). `.superpowers/` is gitignored in both.

**Spec:** `docs/superpowers/specs/2026-06-28-config-derived-schema-design.md`. §5 (prepare() ordering) and §3 (ensure/prune logic) are authoritative.

---

## Current-state anchors (verified)

- `src/schema/tables.ts` exports: `SYNC_STATE_DDL`, `INTEGRATION_CONFIG_DDL`, `WEBHOOK_DELIVERIES_DDL`, `SDK_TABLES` (array of the 3), `storedResourceDDL(tableName, columns: string[])` → `"CREATE TABLE IF NOT EXISTS <t> (id TEXT PRIMARY KEY, remote_id TEXT NOT NULL<, cols>, raw_json TEXT, synced_at INTEGER NOT NULL); CREATE UNIQUE INDEX IF NOT EXISTS idx_<t>_remote_id ON <t> (remote_id)"`. `columns` are full SQL defs like `"full_name TEXT"`.
- `DatabaseAdapter`: `prepare(sql).bind(...).all<T>()/first<T>()/run()`, `exec(sql)`. SQLite `PRAGMA table_info(<t>)` returns rows `{ cid, name, type, notnull, dflt_value, pk }`. `sqlite_master` lists tables: `SELECT name FROM sqlite_master WHERE type='table'`.
- `IntegrationDescriptor` / `ResourceDescriptor` from `src/descriptor` — `resource.name`, `resource.idField`, `resource.fieldMap` (`Record<remoteKey, localCol>`), `resource.supportedModes`, `resource.defaultMode`.
- Host `prepare()` (`src/host/create-worker.ts`) currently: optional `runMigrations` → `seedConfigFromDescriptor(db, seed)` → `effective = loadEffectiveConfig(db, seed)` → returns `{db, effective}`. Every route calls `prepare()` before serving.
- `seedConfigFromDescriptor` writes `_integration_config` rows — so `_integration_config` must exist before it runs.
- `IntegrationError` from `src/errors` (`new IntegrationError(message, status?)`, default 500).
- factorial: `migrations/` (2 .sql), `worker/migrations.generated.ts`, `scripts/generate-migrations.ts`; `package.json` scripts `generate:migrations`, and `dev`/`dev:worker`/`build` are prefixed with `npm run generate:migrations &&`. `worker/index.ts` passes `{ hooks, migrations }` to `createIntegrationWorker`.

---

## Part A — SDK (`eldrin-integration/`)

### Task 1: `ensureSchema` — create tables + additive ALTER

**Files:**
- Create: `eldrin-integration/src/schema/ensure.ts`
- Create: `eldrin-integration/src/schema/ensure.test.ts`

**Interfaces:**
- Consumes: `DatabaseAdapter` (app-core), `IntegrationDescriptor`/`ResourceDescriptor` (`../descriptor`), `storedResourceDDL`/`SDK_TABLES` (`./tables`), `IntegrationError` (`../errors`).
- Produces:
  - `function storedColumnsOf(resource: ResourceDescriptor): string[]` — the fieldMap LOCAL column names excluding the idField's mapping. (e.g. for employees → `['full_name','email','job_title','team_id']`.)
  - `async function ensureManagementTables(db: DatabaseAdapter): Promise<void>` — runs each `SDK_TABLES` statement (split on `;`). Must run BEFORE seeding config.
  - `async function ensureResourceTables(db: DatabaseAdapter, descriptor: IntegrationDescriptor): Promise<void>` — for each resource with `supportedModes.includes('stored')`: run `storedResourceDDL(name, cols.map(c => `${c} TEXT`))` (split on `;`); then `PRAGMA table_info` and `ALTER TABLE <name> ADD COLUMN <col> TEXT` for each stored column missing from the table.
  - `async function ensureSchema(db: DatabaseAdapter, descriptor: IntegrationDescriptor): Promise<void>` — convenience = `ensureManagementTables` then `ensureResourceTables` (used by tests + any caller that wants both at once; the host calls the two phases separately for ordering).

- [ ] **Step 1: Write the failing test**

```ts
// eldrin-integration/src/schema/ensure.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';
import { ensureSchema, ensureManagementTables, ensureResourceTables, storedColumnsOf } from './ensure';
import type { IntegrationDescriptor, ResourceDescriptor } from '../descriptor';
import { makeTestDb } from '../test-helpers';

function resource(over: Partial<ResourceDescriptor> = {}): ResourceDescriptor {
  return {
    name: 'clients',
    transport: { method: 'GET', path: '/c', pagination: 'cursor' },
    idField: 'id',
    fieldMap: { id: 'remote_id', name: 'name', email: 'email' },
    supportedModes: ['stored'],
    defaultMode: 'stored',
    ...over,
  };
}
function descriptor(resources: ResourceDescriptor[]): IntegrationDescriptor {
  return { id: 'acme', connection: { transport: 'http', baseUrl: 'x', auth: { strategy: 'apiKey', key: { secret: 'K' } } }, resources };
}

async function columns(db: DatabaseAdapter, table: string): Promise<string[]> {
  const res = await db.prepare(`PRAGMA table_info(${table})`).all<{ name: string }>();
  return res.results.map((r) => r.name);
}
async function tableExists(db: DatabaseAdapter, table: string): Promise<boolean> {
  const row = await db.prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name = ?`).bind(table).first<{ name: string }>();
  return !!row;
}

let db: DatabaseAdapter;
beforeEach(async () => { db = await makeTestDb([]); }); // empty DB — schema created by ensureSchema

describe('storedColumnsOf', () => {
  it('returns fieldMap local columns excluding the idField mapping', () => {
    expect(storedColumnsOf(resource())).toEqual(['name', 'email']);
  });
});

describe('ensureManagementTables', () => {
  it('creates the three _integration_* tables', async () => {
    await ensureManagementTables(db);
    expect(await tableExists(db, '_integration_sync_state')).toBe(true);
    expect(await tableExists(db, '_integration_config')).toBe(true);
    expect(await tableExists(db, '_integration_webhook_deliveries')).toBe(true);
  });
});

describe('ensureResourceTables', () => {
  it('creates a stored resource table with fixed + fieldMap columns', async () => {
    await ensureResourceTables(db, descriptor([resource()]));
    expect(await columns(db, 'clients')).toEqual(['id', 'remote_id', 'name', 'email', 'raw_json', 'synced_at']);
  });

  it('is idempotent (re-run does not error or duplicate)', async () => {
    await ensureResourceTables(db, descriptor([resource()]));
    await ensureResourceTables(db, descriptor([resource()]));
    expect(await columns(db, 'clients')).toEqual(['id', 'remote_id', 'name', 'email', 'raw_json', 'synced_at']);
  });

  it('adds a new fieldMap column on re-run (additive ALTER)', async () => {
    await ensureResourceTables(db, descriptor([resource()]));
    const grown = resource({ fieldMap: { id: 'remote_id', name: 'name', email: 'email', phone: 'phone' } });
    await ensureResourceTables(db, descriptor([grown]));
    expect(await columns(db, 'clients')).toContain('phone');
  });

  it('does not create a table for a live-only resource', async () => {
    const live = resource({ name: 'teams', supportedModes: ['live'], defaultMode: 'live' });
    await ensureResourceTables(db, descriptor([live]));
    expect(await tableExists(db, 'teams')).toBe(false);
  });
});

describe('ensureSchema', () => {
  it('runs management + resource tables together', async () => {
    await ensureSchema(db, descriptor([resource()]));
    expect(await tableExists(db, '_integration_config')).toBe(true);
    expect(await tableExists(db, 'clients')).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/schema/ensure.test.ts`
Expected: FAIL — cannot find module './ensure'.

- [ ] **Step 3: Write the implementation**

```ts
// eldrin-integration/src/schema/ensure.ts
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';
import type { IntegrationDescriptor, ResourceDescriptor } from '../descriptor';
import { storedResourceDDL, SDK_TABLES } from './tables';
import { IntegrationError } from '../errors';

/** Run a possibly-multi-statement DDL string (split on ';') against the adapter. */
async function runDdl(db: DatabaseAdapter, ddl: string): Promise<void> {
  for (const part of ddl.split(';').map((s) => s.trim()).filter(Boolean)) {
    await db.prepare(part).run();
  }
}

/** Local column names for a stored resource: fieldMap values minus the idField mapping. */
export function storedColumnsOf(resource: ResourceDescriptor): string[] {
  const cols: string[] = [];
  for (const [remoteKey, localCol] of Object.entries(resource.fieldMap)) {
    if (remoteKey === resource.idField) continue; // maps to fixed remote_id
    cols.push(localCol);
  }
  return cols;
}

function isStored(resource: ResourceDescriptor): boolean {
  return resource.supportedModes.includes('stored');
}

export async function ensureManagementTables(db: DatabaseAdapter): Promise<void> {
  try {
    for (const ddl of SDK_TABLES) await runDdl(db, ddl);
  } catch (e) {
    throw new IntegrationError(
      `Failed creating integration management tables: ${e instanceof Error ? e.message : String(e)}`,
    );
  }
}

async function existingColumns(db: DatabaseAdapter, table: string): Promise<Set<string>> {
  const res = await db.prepare(`PRAGMA table_info(${table})`).all<{ name: string }>();
  return new Set(res.results.map((r) => r.name));
}

export async function ensureResourceTables(
  db: DatabaseAdapter,
  descriptor: IntegrationDescriptor,
): Promise<void> {
  for (const resource of descriptor.resources) {
    if (!isStored(resource)) continue;
    const cols = storedColumnsOf(resource);
    try {
      await runDdl(db, storedResourceDDL(resource.name, cols.map((c) => `${c} TEXT`)));
      const present = await existingColumns(db, resource.name);
      for (const col of cols) {
        if (!present.has(col)) {
          await db.prepare(`ALTER TABLE ${resource.name} ADD COLUMN ${col} TEXT`).run();
        }
      }
    } catch (e) {
      throw new IntegrationError(
        `Failed ensuring schema for resource '${resource.name}': ${e instanceof Error ? e.message : String(e)}`,
      );
    }
  }
}

export async function ensureSchema(
  db: DatabaseAdapter,
  descriptor: IntegrationDescriptor,
): Promise<void> {
  await ensureManagementTables(db);
  await ensureResourceTables(db, descriptor);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/schema/ensure.test.ts`
Expected: PASS (storedColumnsOf 1, ensureManagementTables 1, ensureResourceTables 4, ensureSchema 1 = 7 tests).

- [ ] **Step 5: Export and commit**

Add to `src/index.ts`:
```ts
export { ensureSchema, ensureManagementTables, ensureResourceTables, storedColumnsOf } from './schema/ensure';
```
Run: `npm run typecheck`
```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-integration add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-integration commit -q -m "feat: add ensureSchema (config-derived table create + additive ALTER)"
```

---

### Task 2: `pruneSchema` — detect + drop orphaned SDK-owned schema

**Files:**
- Create: `eldrin-integration/src/schema/prune.ts`
- Create: `eldrin-integration/src/schema/prune.test.ts`

**Interfaces:**
- Consumes: `DatabaseAdapter`, `IntegrationDescriptor`/`ResourceDescriptor`, `storedColumnsOf` (Task 1), `IntegrationError`.
- Produces:
  - `interface PruneReport { orphanedColumns: { table: string; column: string }[]; orphanedTables: string[]; skipped: { kind: 'column' | 'table'; name: string; reason: string }[]; dropped: boolean }`
  - `async function pruneSchema(db: DatabaseAdapter, descriptor: IntegrationDescriptor, opts?: { dryRun?: boolean }): Promise<PruneReport>` — `dryRun` defaults to `true`.
  - Fixed owned columns: `FIXED_COLUMNS = ['id', 'remote_id', 'raw_json', 'synced_at']`.
  - Detection:
    - Orphaned columns: for each stored resource's table that EXISTS, owned set = `FIXED_COLUMNS ∪ storedColumnsOf(resource)`; any actual column not in that set is orphaned.
    - Orphaned tables: a user table (from `sqlite_master`, excluding `sqlite_*`, `_eldrin_migrations`, `_cf_*`, and the three `_integration_*` tables) that is NOT a current stored resource's table AND has the SDK signature (its columns include `remote_id`, `raw_json`, `synced_at`) is an orphaned stored table.
  - Execute (when `!dryRun`): `ALTER TABLE <t> DROP COLUMN <c>` for orphaned columns; `DROP TABLE <t>` for orphaned tables. On a per-item failure, push to `skipped` with the error message; do not abort. Set `dropped = true`.

- [ ] **Step 1: Write the failing test**

```ts
// eldrin-integration/src/schema/prune.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';
import { pruneSchema } from './prune';
import { ensureSchema } from './ensure';
import type { IntegrationDescriptor, ResourceDescriptor } from '../descriptor';
import { makeTestDb } from '../test-helpers';

function resource(over: Partial<ResourceDescriptor> = {}): ResourceDescriptor {
  return { name: 'clients', transport: { method: 'GET', path: '/c', pagination: 'cursor' },
    idField: 'id', fieldMap: { id: 'remote_id', name: 'name', email: 'email' },
    supportedModes: ['stored'], defaultMode: 'stored', ...over };
}
function descriptor(resources: ResourceDescriptor[]): IntegrationDescriptor {
  return { id: 'acme', connection: { transport: 'http', baseUrl: 'x', auth: { strategy: 'apiKey', key: { secret: 'K' } } }, resources };
}
async function columns(db: DatabaseAdapter, t: string): Promise<string[]> {
  const r = await db.prepare(`PRAGMA table_info(${t})`).all<{ name: string }>();
  return r.results.map((x) => x.name);
}
async function tableExists(db: DatabaseAdapter, t: string): Promise<boolean> {
  return !!(await db.prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`).bind(t).first());
}

let db: DatabaseAdapter;
beforeEach(async () => { db = await makeTestDb([]); });

describe('pruneSchema', () => {
  it('dry-run reports an orphaned column (removed fieldMap entry) without dropping', async () => {
    await ensureSchema(db, descriptor([resource()]));            // clients has name,email
    const shrunk = resource({ fieldMap: { id: 'remote_id', name: 'name' } }); // email removed
    const report = await pruneSchema(db, descriptor([shrunk]));  // dryRun default
    expect(report.dropped).toBe(false);
    expect(report.orphanedColumns).toEqual([{ table: 'clients', column: 'email' }]);
    expect(await columns(db, 'clients')).toContain('email');     // NOT dropped
  });

  it('execute drops the orphaned column', async () => {
    await ensureSchema(db, descriptor([resource()]));
    const shrunk = resource({ fieldMap: { id: 'remote_id', name: 'name' } });
    const report = await pruneSchema(db, descriptor([shrunk]), { dryRun: false });
    expect(report.dropped).toBe(true);
    expect(await columns(db, 'clients')).not.toContain('email');
  });

  it('never reports/drops the fixed columns', async () => {
    await ensureSchema(db, descriptor([resource()]));
    const report = await pruneSchema(db, descriptor([resource()]));
    const orphanCols = report.orphanedColumns.map((c) => c.column);
    for (const fixed of ['id', 'remote_id', 'raw_json', 'synced_at']) expect(orphanCols).not.toContain(fixed);
    expect(report.orphanedColumns).toEqual([]); // up-to-date schema → nothing orphaned
  });

  it('reports an orphaned table (resource removed from config) and drops on execute', async () => {
    await ensureSchema(db, descriptor([resource({ name: 'clients' }), resource({ name: 'projects', fieldMap: { id: 'remote_id', title: 'title' } })]));
    const report = await pruneSchema(db, descriptor([resource({ name: 'clients' })]), { dryRun: false }); // projects removed
    expect(report.orphanedTables).toContain('projects');
    expect(await tableExists(db, 'projects')).toBe(false);
    expect(await tableExists(db, 'clients')).toBe(true);
  });

  it('does not treat a non-SDK-shaped table as orphaned', async () => {
    await ensureSchema(db, descriptor([resource()]));
    await db.prepare(`CREATE TABLE app_settings (k TEXT PRIMARY KEY, v TEXT)`).run(); // no remote_id/raw_json/synced_at
    const report = await pruneSchema(db, descriptor([resource()]), { dryRun: false });
    expect(report.orphanedTables).not.toContain('app_settings');
    expect(await tableExists(db, 'app_settings')).toBe(true);
  });

  it('never drops the _integration_* management tables', async () => {
    await ensureSchema(db, descriptor([resource()]));
    const report = await pruneSchema(db, descriptor([resource()]), { dryRun: false });
    expect(report.orphanedTables).not.toContain('_integration_config');
    expect(await tableExists(db, '_integration_config')).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/schema/prune.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

```ts
// eldrin-integration/src/schema/prune.ts
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';
import type { IntegrationDescriptor, ResourceDescriptor } from '../descriptor';
import { storedColumnsOf } from './ensure';

export interface PruneReport {
  orphanedColumns: { table: string; column: string }[];
  orphanedTables: string[];
  skipped: { kind: 'column' | 'table'; name: string; reason: string }[];
  dropped: boolean;
}

const FIXED_COLUMNS = ['id', 'remote_id', 'raw_json', 'synced_at'];
const SIGNATURE = ['remote_id', 'raw_json', 'synced_at'];
const MANAGEMENT_TABLES = new Set(['_integration_sync_state', '_integration_config', '_integration_webhook_deliveries']);

function isStored(r: ResourceDescriptor): boolean {
  return r.supportedModes.includes('stored');
}

async function tableColumns(db: DatabaseAdapter, table: string): Promise<string[]> {
  const res = await db.prepare(`PRAGMA table_info(${table})`).all<{ name: string }>();
  return res.results.map((r) => r.name);
}

async function userTables(db: DatabaseAdapter): Promise<string[]> {
  const res = await db
    .prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
    .all<{ name: string }>();
  return res.results.map((r) => r.name);
}

export async function pruneSchema(
  db: DatabaseAdapter,
  descriptor: IntegrationDescriptor,
  opts: { dryRun?: boolean } = {},
): Promise<PruneReport> {
  const dryRun = opts.dryRun ?? true;
  const report: PruneReport = { orphanedColumns: [], orphanedTables: [], skipped: [], dropped: false };

  const storedResources = descriptor.resources.filter(isStored);
  const storedTableNames = new Set(storedResources.map((r) => r.name));

  // Orphaned columns: extra columns on a current stored table.
  for (const resource of storedResources) {
    const cols = await tableColumns(db, resource.name);
    if (cols.length === 0) continue; // table doesn't exist yet
    const owned = new Set([...FIXED_COLUMNS, ...storedColumnsOf(resource)]);
    for (const col of cols) {
      if (!owned.has(col)) report.orphanedColumns.push({ table: resource.name, column: col });
    }
  }

  // Orphaned tables: SDK-shaped tables that are not a current stored resource and not management tables.
  for (const table of await userTables(db)) {
    if (MANAGEMENT_TABLES.has(table)) continue;
    if (table === '_eldrin_migrations' || table.startsWith('_cf_')) continue;
    if (storedTableNames.has(table)) continue;
    const cols = await tableColumns(db, table);
    if (SIGNATURE.every((c) => cols.includes(c))) report.orphanedTables.push(table);
  }

  if (dryRun) return report;

  for (const { table, column } of report.orphanedColumns) {
    try {
      await db.prepare(`ALTER TABLE ${table} DROP COLUMN ${column}`).run();
    } catch (e) {
      report.skipped.push({ kind: 'column', name: `${table}.${column}`, reason: e instanceof Error ? e.message : String(e) });
    }
  }
  for (const table of report.orphanedTables) {
    try {
      await db.prepare(`DROP TABLE ${table}`).run();
    } catch (e) {
      report.skipped.push({ kind: 'table', name: table, reason: e instanceof Error ? e.message : String(e) });
    }
  }
  report.dropped = true;
  return report;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/schema/prune.test.ts`
Expected: PASS (6 tests).

> Note: better-sqlite3 supports `ALTER TABLE DROP COLUMN` (SQLite ≥ 3.35). If the test env's SQLite is older and the drop test fails with "near DROP", the adapter's SQLite is too old — report it; the prune logic is still correct and the skipped-path test covers the fallback. Do not weaken the test to hide a real drop.

- [ ] **Step 5: Export and commit**

Add to `src/index.ts`:
```ts
export { pruneSchema, type PruneReport } from './schema/prune';
```
Run: `npm run typecheck`
```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-integration add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-integration commit -q -m "feat: add pruneSchema (detect + drop orphaned SDK-owned schema, dry-run default)"
```

---

### Task 3: Wire `ensureSchema` into host `prepare()` + mount prune route

**Files:**
- Modify: `eldrin-integration/src/host/create-worker.ts`
- Modify: `eldrin-integration/src/host/create-worker.test.ts` (add schema-on-prepare + prune-route tests)

**Interfaces:**
- Consumes: `ensureManagementTables`, `ensureResourceTables` (Task 1); `pruneSchema` (Task 2); existing `seedConfigFromDescriptor`, `loadEffectiveConfig`, `runMigrations`.
- Produces: a `prepare()` that creates management tables before seeding and resource tables after the effective overlay; and a mounted `POST /api/schema/prune` route.

- [ ] **Step 1: Update `prepare()` ordering**

In `src/host/create-worker.ts`, add imports:
```ts
import { ensureManagementTables, ensureResourceTables } from '../schema/ensure';
import { pruneSchema } from '../schema/prune';
```
Replace the `prepare` body so the order is: migrations → **ensureManagementTables** → seed → loadEffective → **ensureResourceTables**:
```ts
  async function prepare(env: any): Promise<{ db: DatabaseAdapter; effective: IntegrationDescriptor }> {
    const db = options.adapterFactory ? options.adapterFactory(env) : createD1Adapter(env.DB);
    if (!migrated && options.migrations && options.migrations.length > 0) {
      await runMigrations(env.DB, { migrations: options.migrations as any });
      migrated = true;
    }
    await ensureManagementTables(db);                 // _integration_* must exist before seeding
    await seedConfigFromDescriptor(db, seed);
    const effective = await loadEffectiveConfig(db, seed);
    await ensureResourceTables(db, effective);        // stored tables from the effective descriptor
    return { db, effective };
  }
```

- [ ] **Step 2: Write the failing tests** (append to `src/host/create-worker.test.ts`)

```ts
// Append inside the existing describe block (reuse the existing test config + makeTestDb pattern).
// These assume the file already has: a `config` object with a stored resource, `makeTestDb`,
// and the worker.fetch(new Request(...), env) pattern with adapterFactory injecting `db`.

  it('auto-creates the stored schema on prepare with NO migrations', async () => {
    const db = await makeTestDb([]); // truly empty — no DDL pre-applied
    const worker = createIntegrationWorker(config, {
      adapterFactory: () => db,
      // no migrations passed
      fetchImpl: async () => new Response(JSON.stringify({ data: [{ id: 1, name: 'Ada' }] }), { status: 200 }),
    } as any);
    const res = await worker.fetch(
      new Request('http://x/api/sync', { method: 'POST', headers: { 'X-Eldrin-User-Id': 'u1' } }),
      { DB: {}, ACME_API_BASE_URL: 'https://api.test', ACME_API_KEY: 'k' } as any, {} as any,
    );
    expect(res.status).toBe(200);
    // table was auto-created and the sync wrote to it
    const rows = await db.prepare('SELECT remote_id FROM clients').all();
    expect(rows.results).toHaveLength(1);
    // management table exists too
    const cfg = await db.prepare(`SELECT name FROM sqlite_master WHERE name='_integration_config'`).first();
    expect(cfg).toBeTruthy();
  });

  it('POST /api/schema/prune dry-run returns a report without dropping; 401 without auth', async () => {
    const db = await makeTestDb([]);
    const worker = createIntegrationWorker(config, { adapterFactory: () => db } as any);
    const env = { DB: {}, ACME_API_BASE_URL: 'https://api.test', ACME_API_KEY: 'k' } as any;
    // no auth → 401
    const noAuth = await worker.fetch(new Request('http://x/api/schema/prune', { method: 'POST' }), env, {} as any);
    expect(noAuth.status).toBe(401);
    // dry-run (prepare() creates the schema first)
    const res = await worker.fetch(new Request('http://x/api/schema/prune', { method: 'POST', headers: { 'X-Eldrin-User-Id': 'u1' } }), env, {} as any);
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.dropped).toBe(false);
    expect(Array.isArray(body.orphanedColumns)).toBe(true);
  });
```

> Use the existing test file's `config` (the minimal stored-resource config already defined there). If its resource isn't named `clients`, adjust the `SELECT … FROM <name>` table name in the first test to match. Read the top of `create-worker.test.ts` for the exact config before writing.

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/host/create-worker.test.ts`
Expected: FAIL — `/api/schema/prune` not mounted (404, not 401/200); first test may already pass if ensureSchema wired in Step 1.

- [ ] **Step 4: Mount the prune route**

In `src/host/create-worker.ts`, AFTER the other `/api/*` routes and `options.extend?.(app)` but BEFORE the `app.get('*', ...)` asset fallback, add:
```ts
  app.post('/api/schema/prune', async (c) => {
    const userId = resolveUserId(c); // existing helper used by /api/sync
    if (!userId) return c.json({ error: 'Unauthorized' }, 401);
    const { db, effective } = await prepare(c.env);
    const confirm = c.req.query('confirm') === '1';
    const report = await pruneSchema(db, effective, { dryRun: !confirm });
    return c.json(report);
  });
```
(Use whatever the existing userId-resolution is named in this file — Task from a prior pass added `resolveUserId`; if the sync route inlines it, extract or reuse the same logic. Read the `/api/sync` handler for the exact call.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/host/create-worker.test.ts && npm run typecheck`
Expected: PASS (all existing host tests + the 2 new ones).

- [ ] **Step 6: Export + commit**

Run: `npm run build`
```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-integration add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-integration commit -q -m "feat: wire ensureSchema into prepare(); mount admin POST /api/schema/prune"
```

---

### Task 4: SDK coverage gate + README

**Files:**
- Modify: `eldrin-integration/README.md`

**Interfaces:** Consumes Tasks 1–3. Produces a green, documented SDK.

- [ ] **Step 1: Full coverage run**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run --coverage`
Expected: all tests pass; ≥80% statements/lines for `src/schema/ensure.ts` and `src/schema/prune.ts`. If under, add a focused behavior-asserting test (e.g. ensure error path throws IntegrationError; prune `skipped` path) — no coverage-padding.

- [ ] **Step 2: Typecheck + build**

Run: `npm run typecheck && npm run build && grep -c better-sqlite3 dist/index.js`
Expected: clean; dist emitted; grep prints `0`.

- [ ] **Step 3: Update README** — add a "Schema (no migrations needed)" section documenting: `ensureSchema` runs automatically on the host (creates stored tables from `fieldMap` + adds new columns); stored integrations ship NO migration files; hand-written migrations remain available for one-offs; `pruneSchema` + `POST /api/schema/prune` (admin, dry-run by default, `?confirm=1` to execute) removes orphaned SDK-owned columns/tables — the future config UI's "Delete orphaned columns/tables" action.

- [ ] **Step 4: Commit**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-integration add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-integration commit -q -m "docs: document config-derived schema (ensureSchema/pruneSchema) in SDK README"
```

---

## Part B — Factorial (`eldrin-factorial/`)

### Task 5: Remove factorial migration artifacts; rely on auto-DDL

**Files:**
- Delete: `eldrin-factorial/migrations/20260617000000-init.sql`, `eldrin-factorial/migrations/20260627000000-integration-tables.sql`, `eldrin-factorial/worker/migrations.generated.ts`, `eldrin-factorial/scripts/generate-migrations.ts`
- Modify: `eldrin-factorial/package.json` (scripts), `eldrin-factorial/worker/index.ts`

**Interfaces:**
- Consumes: the host's auto-DDL (Task 3) — `createIntegrationWorker` now derives the schema, so factorial needs no migrations.
- Produces: factorial with zero migration artifacts; `host-sync.test.ts` green; live app still syncs.

- [ ] **Step 1: Inspect the current worker entry + scripts** (so the edits are exact)

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-factorial && cat worker/index.ts && echo '---' && node -e "console.log(JSON.stringify(require('./package.json').scripts,null,1))"`

- [ ] **Step 2: Update `worker/index.ts`** — remove the migrations import + option:

```ts
// eldrin-factorial/worker/index.ts
import { createIntegrationWorker } from '@eldrin-project/eldrin-integration';
import config from '../integration.config.json';
import { deriveFullName } from '../integration.hooks';

export default createIntegrationWorker(config, {
  hooks: { deriveFullName },
});
```
(Removed: `import migrations from './migrations.generated'` and the `migrations` option.)

- [ ] **Step 3: Update `package.json` scripts** — remove `generate:migrations` and its prefix from `dev`/`dev:worker`/`build`:

```jsonc
// the three scripts become:
"dev": "vite",
"dev:worker": "wrangler dev",
"build": "tsc -b && vite build",
// and DELETE the "generate:migrations" script line entirely.
```
(Leave all other scripts unchanged.)

- [ ] **Step 4: Delete the migration files + script**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-factorial && git rm \
  migrations/20260617000000-init.sql \
  migrations/20260627000000-integration-tables.sql \
  worker/migrations.generated.ts \
  scripts/generate-migrations.ts
```
Then check the `migrations/` and `scripts/` dirs aren't otherwise needed: `ls migrations scripts 2>/dev/null` — if empty, they can be removed (git won't track empty dirs anyway). Confirm nothing else imports `migrations.generated`: `grep -rn "migrations.generated\|generate-migrations" worker src package.json wrangler.jsonc` → should be empty.

- [ ] **Step 5: Rebuild the SDK so factorial links the new auto-DDL host, then update the host-sync test**

The SDK must be built for factorial's `file:` dep to see `ensureSchema`-wired host:
```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npm run build
```
Then in `eldrin-factorial/worker/__tests__/host-sync.test.ts`: the test currently pre-creates tables via `makeTestDb([...SDK_TABLES, storedResourceDDL(...)])`. Change it to pass an EMPTY db (`makeTestDb([])`) so the test proves the host AUTO-CREATES the schema. Keep the rest (fake transport returning an employee, assert the row lands with derived full_name). Add an assertion that the `employees` table exists after the sync. Example edit to the `beforeEach`/test:
```ts
  db = await makeTestDb([]); // empty — host's ensureSchema must create the tables
```
(Remove the now-unused `SDK_TABLES`/`storedResourceDDL` imports if they become unused — or keep them only if still referenced.)

- [ ] **Step 6: Run factorial typecheck + full suite + build**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-factorial && npm run typecheck && npm run test && npm run build`
Expected: typecheck clean (no missing `migrations.generated` import); `host-sync.test.ts` + `config-loads.test.ts` green; build succeeds (no `generate:migrations` step).

- [ ] **Step 7: Commit**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-factorial add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-factorial commit -q -m "refactor(factorial): remove migrations; rely on host config-derived schema"
```

---

### Task 6: Live end-to-end verification (fresh DB → auto-schema → sync)

**Files:** none (manual verification + report).

- [ ] **Step 1: Wipe factorial's local D1** (only if the factorial dev server is stopped)

Run: `rm -rf /Users/tibor/projects/eldrin-backup/eldrin-factorial/.wrangler/state/v3/d1/miniflare-D1DatabaseObject`

- [ ] **Step 2: Start factorial** (`npm run preview` — builds + serves on 4011, now with no generate:migrations step)

- [ ] **Step 3: Sync + verify auto-created schema**

- `POST /api/sync` (with `X-Eldrin-User-Id` or Bearer JWT) → `{ results: [{ resource:'employees', count:N }, { resource:'projects', count:M }] }`.
- Inspect the fresh D1: confirm `employees`/`projects` tables exist with the fieldMap columns + the three `_integration_*` tables — all created with ZERO migration files in the repo.
- `POST /api/schema/prune` (dry-run) → returns a report (likely empty for a freshly-synced, in-config schema).

- [ ] **Step 4: Report** — record that the schema was auto-derived (no migrations dir), sync succeeded, and the prune endpoint responds. Note any deferred follow-up.

---

## Self-Review

**1. Spec coverage:**
- §3.1 ensureSchema (create + additive ALTER, stored-only, TEXT cols) → Task 1 ✓
- §3.2 pruneSchema (orphaned cols/tables, dry-run/execute, skipped, SDK-owned only, signature check) → Task 2 ✓
- §3.3 ownership caveat → handled by the signature check + dry-run default (Task 2); documented in README (Task 4) ✓
- §4 prune route (admin auth, dry-run default, confirm=1) → Task 3 ✓
- §5 prepare() ordering (management tables before seed; resource tables after loadEffective) → Task 3 Step 1 ✓
- §6 factorial cleanup (delete migrations/generate script, package.json scripts, worker/index.ts option) → Task 5 ✓
- §7 error handling (IntegrationError on ensure; skipped[] on prune) → Tasks 1, 2 ✓
- §8 testing → each task TDD; E2E → Task 6 ✓

**2. Placeholder scan:** No TBD/TODO. The "read the existing test config / read the /api/sync handler" steps (Task 3) are genuine reconnaissance against existing code the implementer must match (the host file's exact `config` var and userId helper), not placeholders — they have concrete fallback instructions.

**3. Type consistency:** `ensureSchema`/`ensureManagementTables`/`ensureResourceTables`/`storedColumnsOf` (Task 1) consumed by Task 2 (`storedColumnsOf`) and Task 3 (the two ensure phases). `pruneSchema`/`PruneReport` (Task 2) consumed by Task 3's route. `FIXED_COLUMNS`/`SIGNATURE` internal to prune. Column convention (`id, remote_id, <cols>, raw_json, synced_at`) consistent with `storedResourceDDL` (Task 1 uses it) and the prune owned-set (Task 2). The prepare() order matches the spec §5 resolution. `resolveUserId` reuse flagged with a read-the-file instruction since its exact name is from a prior pass.

**4. One gap fixed inline:** Task 3's prune route uses `resolveUserId(c)` — I confirmed a prior pass added userId-resolution to the sync route (X-Eldrin-User-Id or Bearer JWT). The step instructs the implementer to reuse the same helper/logic the `/api/sync` handler uses, reading the file for the exact name. This avoids inventing a new auth path.
