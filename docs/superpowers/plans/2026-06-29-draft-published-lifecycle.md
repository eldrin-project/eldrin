# Draft/Published Flow Lifecycle Implementation Plan (SP7)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give flows a draft/published lifecycle in the SDK — saves write an invisible draft, an explicit publish promotes it to the live version the executor runs — with full published history, rollback, and a forward migration of existing stored flows.

**Architecture:** `_integration_flows` becomes version-history rows (`PRIMARY KEY (id, version)` + `status`). An idempotent migration promotes existing old-schema rows to `published v1`. `store.ts` is rewritten into a draft/published API (`saveDraft`/`publishDraft`/`republish` + `readPublished`/`readDraft`/`listFlowVersions`/`listFlows`). The executor/sync reads `readPublished` (published, else compiled default). Routes split save (POST `:id` → draft) from publish (`POST :id/publish`), add `/republish`, `/published`, `/versions`, and overlay `/effective` with published.

**Tech Stack:** TypeScript + Vitest (real in-memory SQLite via `makeTestDb`), Cloudflare Workers SDK (`eldrin-integration`).

## Global Constraints

- **SDK-only:** all changes in `/Users/tibor/projects/eldrin-backup/eldrin-integration`. NO eldrin-core/factorial changes — `POST /api/flows/:id` stays backward-compatible (same body/validate/200-400-409), it just writes a draft now.
- **Drafts never execute:** `runResourceSync` reads `readPublished(db, id)` → published row, else compiled default. THE headline guarantee.
- **One draft + one published per id** (code-enforced): at most one `status='draft'` row (re-saves overwrite it, version-locked); at most one `status='published'` row (the live one; older publishes → `archived`). Rollback = `republish`.
- **Migration idempotent + deterministic:** probe via `PRAGMA table_info`; if no `status` column, rename old table → create new → copy rows in as `status='published'` (preserving id/integration_id/flow_json/version/created_at/updated_at) → drop old. No `Date.now()` (use existing row timestamps). Regression guard: executor output identical pre/post.
- **Validate on save AND publish:** save-draft runs `validateFlow`; publish RE-runs `validateFlow` against the current `knownTables`/hooks (a draft referencing a now-missing table fails at publish, not silently live).
- **`saveDraft` is create-or-continue** (backward-compat with the eldrin-core editor, which sends `baseVersion = published version` when editing a live flow): no draft exists → create one regardless of `baseVersion`; draft exists → re-save, locking on the draft version (non-null `baseVersion` must match → 409; null continues). This is what makes POST `:id` need zero editor changes.
- **Optimistic locking** via the existing `WHERE version = ?` guard, applied per operation (save locks on draft version; publish locks on the draft being promoted).
- **`/effective` = list of LIVE (published) flows**; the editor opens a specific flow via `GET /api/flows/:id` (draft-if-exists). `listFlows` entries expose `hasDraft` so the studio can show a "draft pending" indicator without leaking draft content.
- Immutability; no `console.log`; conventional commits, attribution disabled. Coverage ≥ 80%. Tests: `cd eldrin-integration && npx vitest run`.

---

## File Structure

- `src/schema/tables.ts` (modify) — new `FLOWS_DDL` (version-history: `PRIMARY KEY (id, version)` + `status`).
- `src/schema/ensure.ts` (modify) — add `migrateFlowsTable(db)` (idempotent, uses existing `existingColumns`); call it in `ensureManagementTables` BEFORE the `SDK_TABLES` loop, or alongside — see Task 1.
- `src/schema/ensure.test.ts` (modify/create) — migration unit tests.
- `src/flow/store.ts` (rewrite) — `StoredFlow` gains `status`; `saveDraft`, `publishDraft`, `republish`, `readPublished`, `readDraft`, `listFlowVersions`, `listFlows` (now one-entry-per-id + `hasDraft`), `deleteFlow`, `loadEffectiveFlows` (now published-overlay). Remove `readFlow`/`writeFlow` (replaced).
- `src/flow/store.test.ts` (rewrite) — draft/published unit tests.
- `src/sync/index.ts` (modify) — `readFlow` → `readPublished` (line 45).
- `src/sync/index.test.ts` or `src/flow/execute-integration.test.ts` (modify/add) — the "draft doesn't change sync output" integration test.
- `src/host/create-worker.ts` (modify) — POST `:id` → `saveDraft`; new `/publish`, `/republish`, `/published`, `/versions` routes; GET `:id` → draft-else-published + `status`; `/effective` published-overlay (via new `listFlows`); `/api/flows` list adds `hasDraft`.
- `src/host/create-worker.test.ts` (modify) — route tests for draft/publish/republish/versions/effective.
- `src/index.ts` (modify) — barrel exports: replace `readFlow, writeFlow` with `saveDraft, publishDraft, republish, readPublished, readDraft, listFlowVersions`.

---

## Reference: current code (do not re-derive)

**Current `store.ts`** (full file is being rewritten) — key existing pieces to preserve/adapt:
- `StoredFlow { id, integrationId, flow: Flow, version, createdAt, updatedAt }` → ADD `status: 'draft'|'published'|'archived'`.
- `toStored(row)` maps a `FlowRow` → `StoredFlow` via `JSON.parse(row.flow_json)`.
- `writeFlow` pattern: `baseVersion===null` → INSERT version 1 (409 if exists); else UPDATE with `WHERE id = ? AND version = ?` optimistic lock (404 if missing, 409 on version mismatch).
- `loadEffectiveFlows(db, descriptor)` = `compileDescriptorToFlows` + per-id stored override.

**Current `FLOWS_DDL`** (`src/schema/tables.ts`):
```ts
export const FLOWS_DDL =
  `CREATE TABLE IF NOT EXISTS _integration_flows (` +
  `id TEXT PRIMARY KEY, integration_id TEXT NOT NULL, flow_json TEXT NOT NULL, ` +
  `version INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`;
```

**`ensure.ts` existing helper to reuse:**
```ts
async function existingColumns(db: DatabaseAdapter, table: string): Promise<Set<string>> {
  const res = await db.prepare(`PRAGMA table_info("${table}")`).all<{ name: string }>();
  return new Set(res.results.map((r) => r.name));
}
```
`ensureManagementTables(db)` currently just runs `for (const ddl of SDK_TABLES) await runDdl(db, ddl)`.

**`sync/index.ts` execution read** (line 44-47): `const stored = await readFlow(deps.db, compiled.id); const flow = stored ? stored.flow : compiled;` → becomes `readPublished`.

**Route handlers** (`create-worker.ts`): `/api/flows` list (161-168), `/effective` (172-184), GET `:id` (~217), POST `:id` (~233, validates + `writeFlow`), DELETE `:id` (~250). All admin-gated (`resolveUserId`→401, `isAdmin`→403). `validateFlow(flow, { hooks: boundHooks, hookSlots: new Set(['transform','beforeUpsert']), knownTables: new Set(effective.resources.map(r => r.name)) })`.

**Test harness:** `makeTestDb(ddl: string[]): Promise<DatabaseAdapter>` (in-memory SQLite, runs each DDL string). `store.test.ts` uses `db = await makeTestDb([FLOWS_DDL])`. For migration tests, seed the OLD schema by passing the old DDL string literal and inserting rows.

---

## Task 1: Schema + idempotent migration

**Files:**
- Modify: `src/schema/tables.ts` (new `FLOWS_DDL`)
- Modify: `src/schema/ensure.ts` (add `migrateFlowsTable`, call it)
- Test: `src/schema/ensure.test.ts` (create if absent)

**Interfaces:**
- Consumes: `existingColumns` (file-local in ensure.ts), `runDdl` (file-local), `DatabaseAdapter`.
- Produces: new `FLOWS_DDL` (exported); `migrateFlowsTable(db: DatabaseAdapter): Promise<void>` (idempotent). `ensureManagementTables` calls `migrateFlowsTable` after creating tables. Tasks 2-5 rely on the new schema shape (`status` column, `(id, version)` PK).

- [ ] **Step 1: Write the new `FLOWS_DDL`**

In `src/schema/tables.ts`, replace `FLOWS_DDL`:
```ts
export const FLOWS_DDL =
  `CREATE TABLE IF NOT EXISTS _integration_flows (` +
  `id TEXT NOT NULL, integration_id TEXT NOT NULL, flow_json TEXT NOT NULL, ` +
  `version INTEGER NOT NULL, status TEXT NOT NULL, ` +
  `created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, ` +
  `PRIMARY KEY (id, version))`;
```

- [ ] **Step 2: Write the failing migration tests**

In `src/schema/ensure.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { makeTestDb } from '../test-helpers';
import { migrateFlowsTable } from './ensure';
import { FLOWS_DDL } from './tables';

const OLD_FLOWS_DDL =
  `CREATE TABLE IF NOT EXISTS _integration_flows (` +
  `id TEXT PRIMARY KEY, integration_id TEXT NOT NULL, flow_json TEXT NOT NULL, ` +
  `version INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`;

async function colsOf(db: any, table: string): Promise<Set<string>> {
  const res = await db.prepare(`PRAGMA table_info("${table}")`).all<{ name: string }>();
  return new Set(res.results.map((r: { name: string }) => r.name));
}

describe('migrateFlowsTable', () => {
  it('migrates an old-schema table: existing rows become status=published', async () => {
    const db = await makeTestDb([OLD_FLOWS_DDL]);
    await db.prepare(
      `INSERT INTO _integration_flows (id, integration_id, flow_json, version, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
    ).bind('factorial:employees', 'factorial', '{"id":"factorial:employees"}', 6, 100, 200).run();

    await migrateFlowsTable(db);

    expect(await colsOf(db, '_integration_flows')).toContain('status');
    const row = await db.prepare(`SELECT * FROM _integration_flows WHERE id = ?`).bind('factorial:employees').first<any>();
    expect(row.status).toBe('published');
    expect(row.version).toBe(6);
    expect(row.flow_json).toBe('{"id":"factorial:employees"}');
    expect(row.created_at).toBe(100);
  });

  it('is idempotent: running on a new-schema table is a no-op', async () => {
    const db = await makeTestDb([FLOWS_DDL]);
    await db.prepare(
      `INSERT INTO _integration_flows (id, integration_id, flow_json, version, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).bind('x', 'i', '{}', 1, 'draft', 1, 1).run();

    await migrateFlowsTable(db);

    const row = await db.prepare(`SELECT * FROM _integration_flows WHERE id = ?`).bind('x').first<any>();
    expect(row.status).toBe('draft'); // unchanged, not clobbered
  });

  it('is a no-op when the table does not exist yet', async () => {
    const db = await makeTestDb([]); // no flows table
    await expect(migrateFlowsTable(db)).resolves.toBeUndefined();
  });
});
```

- [ ] **Step 3: Run to verify fail**

Run: `cd eldrin-integration && npx vitest run src/schema/ensure.test.ts`
Expected: FAIL — `migrateFlowsTable` not exported.

- [ ] **Step 4: Implement `migrateFlowsTable` + wire into `ensureManagementTables`**

In `src/schema/ensure.ts`:
```ts
export async function migrateFlowsTable(db: DatabaseAdapter): Promise<void> {
  // Does the table exist at all?
  const tbl = await db
    .prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name='_integration_flows'`)
    .first<{ name: string }>();
  if (!tbl) return; // FLOWS_DDL (CREATE TABLE IF NOT EXISTS) will create the new shape

  const cols = await existingColumns(db, '_integration_flows');
  if (cols.has('status')) return; // already new schema — idempotent no-op

  // Old schema → migrate. Each existing stored flow IS the live one → status='published'.
  await db.prepare(`ALTER TABLE _integration_flows RENAME TO _integration_flows_old`).run();
  await db.prepare(
    `CREATE TABLE _integration_flows (` +
    `id TEXT NOT NULL, integration_id TEXT NOT NULL, flow_json TEXT NOT NULL, ` +
    `version INTEGER NOT NULL, status TEXT NOT NULL, ` +
    `created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, ` +
    `PRIMARY KEY (id, version))`,
  ).run();
  await db.prepare(
    `INSERT INTO _integration_flows (id, integration_id, flow_json, version, status, created_at, updated_at) ` +
    `SELECT id, integration_id, flow_json, version, 'published', created_at, updated_at FROM _integration_flows_old`,
  ).run();
  await db.prepare(`DROP TABLE _integration_flows_old`).run();
}
```
Then in `ensureManagementTables`, after the `SDK_TABLES` loop, add `await migrateFlowsTable(db);`:
```ts
export async function ensureManagementTables(db: DatabaseAdapter): Promise<void> {
  try {
    for (const ddl of SDK_TABLES) await runDdl(db, ddl);
    await migrateFlowsTable(db);
  } catch (e) {
    throw new IntegrationError(
      `Failed creating integration management tables: ${e instanceof Error ? e.message : String(e)}`,
    );
  }
}
```
(Order rationale: for a brand-new deployment, `FLOWS_DDL` creates the new-schema table and `migrateFlowsTable` no-ops [status already present]. For an existing old-schema deployment, `CREATE TABLE IF NOT EXISTS` no-ops [table exists] and `migrateFlowsTable` does the real migration. Both paths converge.)

- [ ] **Step 5: Run to verify pass**

Run: `cd eldrin-integration && npx vitest run src/schema/ensure.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
cd eldrin-integration
git add src/schema/tables.ts src/schema/ensure.ts src/schema/ensure.test.ts
git commit -m "feat(schema): version-history flows table + idempotent migration"
```

---

## Task 2: `store.ts` rewrite — draft/published API

**Files:**
- Rewrite: `src/flow/store.ts`
- Rewrite: `src/flow/store.test.ts`

**Interfaces:**
- Consumes: `DatabaseAdapter`, `IntegrationError`, `compileDescriptorToFlows`, `Flow`, `IntegrationDescriptor`.
- Produces (Tasks 3-5 + barrel consume):
  - `StoredFlow { id, integrationId, flow, version, status: 'draft'|'published'|'archived', createdAt, updatedAt }`
  - `readPublished(db, id): Promise<StoredFlow | null>` — latest `status='published'`.
  - `readDraft(db, id): Promise<StoredFlow | null>` — the `status='draft'` row.
  - `readFlowForEdit(db, id): Promise<StoredFlow | null>` — draft if exists, else published (the editor open path).
  - `listFlowVersions(db, id): Promise<StoredFlow[]>` — all rows for id, version desc.
  - `listFlows(db): Promise<{ flow: Flow; id: string; integrationId: string; version: number; status: string; updatedAt: number; hasDraft: boolean }[]>` — one entry per id (published if any, else draft), with `hasDraft`.
  - `saveDraft(db, flow, baseVersion, now): Promise<StoredFlow>` — upsert the single draft row.
  - `publishDraft(db, id, baseVersion, now): Promise<StoredFlow>` — promote draft → published, prior published → archived.
  - `republish(db, id, version, now): Promise<StoredFlow>` — make a historical version the live published.
  - `deleteFlow(db, id): Promise<boolean>` — remove all rows for id.
  - `loadEffectiveFlows(db, descriptor): Promise<Flow[]>` — compiled + published overrides.

**Semantics (exact) — `saveDraft` is "create-or-continue" to stay backward-compatible with the eldrin-core editor:**

> **Why this shape:** the existing eldrin-core editor opens a flow from `/effective` (which now returns the PUBLISHED version) and saves with `baseVersion = item.stored ? item.version : null` — i.e. the *published* version, not a draft version. If `saveDraft` required `baseVersion` to match an existing draft, the editor's first save on an already-published flow would 404. So `saveDraft` keys its lock on **whether a draft already exists**, not on the caller knowing the draft version. This delivers the spec's "POST `:id` needs zero editor changes."

- **No existing draft** for the id (regardless of `baseVersion` value — null OR a published version number the editor passed): CREATE a new draft at version = `(max version across all rows for id) + 1` (or 1 if none). The first save forks a fresh draft from the current state. (We do NOT 409 when `baseVersion` is non-null-but-no-draft, because that's exactly the editor-editing-a-published-flow case.)
- **Existing draft** for the id: this is a re-save. If `baseVersion` is non-null, it must match the current draft version (409 on mismatch — genuine concurrent-edit protection). If `baseVersion` is null, treat as "continue the draft" and lock on the current draft version implicitly (no 409). UPDATE the draft row's flow_json + bump version (`WHERE id=? AND version=? AND status='draft'`).
- Returns the draft `StoredFlow` (status `'draft'`).

This means: editor opens published v1 → saves (baseVersion 1, no draft yet) → creates draft v2. Saves again (the editor now holds version 2 from the response) → re-saves draft, bumps to v3. Concurrent editor with stale draft version → 409.
- `publishDraft`: read the draft (404 if none). If `baseVersion!=null` require `draft.version===baseVersion` (409 mismatch). In order: UPDATE any current `status='published'` row for id → `'archived'`; UPDATE the draft row → `'published'` (keep its version). Return the now-published flow.
- `republish`: read the row `(id, version)` (404 if missing). Archive the current published row; set the target row's status → `'published'` (a new row copy is NOT needed — flipping status is enough; but if the target is itself already published, no-op-ish). Return it.
- `readPublished`/`readDraft`: `SELECT ... WHERE id=? AND status=? ORDER BY version DESC LIMIT 1`.
- `listFlows`: group by id; pick published row if any else draft; set `hasDraft = exists a status='draft' row for id`.

- [ ] **Step 1: Write the failing tests** (rewrite `store.test.ts`)

```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { saveDraft, publishDraft, republish, readPublished, readDraft, readFlowForEdit, listFlowVersions, listFlows, deleteFlow, loadEffectiveFlows } from './store';
import { FLOWS_DDL } from '../schema/tables';
import { IntegrationError } from '../errors';
import { makeTestDb } from '../test-helpers';
import type { Flow } from './types';
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';

const flow = (id: string, marker = 'a'): Flow => ({
  id, integrationId: 'factorial', trigger: { kind: 'manual' },
  nodes: [
    { id: 'source', kind: 'source', config: { transport: { method: 'GET', path: '/' + marker }, idField: 'id' } as never },
    { id: 'destination', kind: 'destination', config: { kind: 'd1', table: 'x', mode: 'stored' } as never },
  ],
  edges: [{ from: 'source', to: 'destination' }],
});
let n = 0; const now = () => 1000 + n++;

describe('flow store — draft/published', () => {
  let db: DatabaseAdapter;
  beforeEach(async () => { db = await makeTestDb([FLOWS_DDL]); n = 0; });

  it('saveDraft creates the first draft (baseVersion null), invisible to readPublished', async () => {
    const d = await saveDraft(db, flow('f'), null, now);
    expect(d.status).toBe('draft');
    expect(d.version).toBe(1);
    expect(await readPublished(db, 'f')).toBeNull(); // not live
    expect((await readDraft(db, 'f'))!.version).toBe(1);
  });

  it('saveDraft with null CONTINUES an existing draft (does not fork a second)', async () => {
    await saveDraft(db, flow('f'), null, now);            // draft v1
    const d2 = await saveDraft(db, flow('f', 'b'), null, now); // null + existing draft → continue → v2
    expect(d2.version).toBe(2);
    expect((await listFlowVersions(db, 'f')).filter((r) => r.status === 'draft')).toHaveLength(1); // still ONE draft
  });

  it('saveDraft creates a draft even when baseVersion is a published version (editor-of-live-flow case)', async () => {
    await saveDraft(db, flow('f'), null, now); await publishDraft(db, 'f', 1, now); // published v1, no draft
    const d = await saveDraft(db, flow('f', 'b'), 1, now); // editor passes the PUBLISHED version 1, no draft exists → forks draft v2
    expect(d.status).toBe('draft');
    expect(d.version).toBe(2);
    expect((await readPublished(db, 'f'))!.version).toBe(1); // published untouched
  });

  it('re-save overwrites the draft, version bumps, optimistic-locked on a stale draft version', async () => {
    await saveDraft(db, flow('f'), null, now);             // v1
    const d2 = await saveDraft(db, flow('f', 'b'), 1, now); // matches draft v1 → v2
    expect(d2.version).toBe(2);
    expect((await readDraft(db, 'f'))!.flow.nodes[0].config).toMatchObject({ transport: { path: '/b' } });
    await expect(saveDraft(db, flow('f', 'c'), 1, now)).rejects.toThrow(/conflict/i); // stale base (draft is at v2, not 1)
  });

  it('publishDraft promotes the draft to published; draft is gone, published is live', async () => {
    await saveDraft(db, flow('f'), null, now); // draft v1
    const p = await publishDraft(db, 'f', 1, now);
    expect(p.status).toBe('published');
    expect((await readPublished(db, 'f'))!.version).toBe(1);
    expect(await readDraft(db, 'f')).toBeNull();
  });

  it('publishDraft 404s when there is no draft', async () => {
    await expect(publishDraft(db, 'f', null, now)).rejects.toThrow(IntegrationError);
  });

  it('a new draft after publish does not change the published flow', async () => {
    await saveDraft(db, flow('f'), null, now); await publishDraft(db, 'f', 1, now); // published v1
    await saveDraft(db, flow('f', 'b'), null, now); // new draft v2, published untouched
    expect((await readPublished(db, 'f'))!.flow.nodes[0].config).toMatchObject({ transport: { path: '/a' } });
    expect((await readDraft(db, 'f'))!.version).toBe(2);
  });

  it('publishing again archives the prior published', async () => {
    await saveDraft(db, flow('f'), null, now); await publishDraft(db, 'f', 1, now);       // pub v1
    await saveDraft(db, flow('f', 'b'), null, now); await publishDraft(db, 'f', 2, now);  // pub v2
    expect((await readPublished(db, 'f'))!.version).toBe(2);
    const versions = await listFlowVersions(db, 'f');
    expect(versions.find((v) => v.version === 1)!.status).toBe('archived');
  });

  it('republish restores an archived version as live', async () => {
    await saveDraft(db, flow('f'), null, now); await publishDraft(db, 'f', 1, now);
    await saveDraft(db, flow('f', 'b'), null, now); await publishDraft(db, 'f', 2, now);
    await republish(db, 'f', 1, now);
    expect((await readPublished(db, 'f'))!.version).toBe(1);
    expect((await listFlowVersions(db, 'f')).find((v) => v.version === 2)!.status).toBe('archived');
  });

  it('readFlowForEdit returns draft if present else published', async () => {
    await saveDraft(db, flow('f'), null, now); await publishDraft(db, 'f', 1, now);
    expect((await readFlowForEdit(db, 'f'))!.status).toBe('published'); // no draft → published
    await saveDraft(db, flow('f', 'b'), null, now);
    expect((await readFlowForEdit(db, 'f'))!.status).toBe('draft');     // draft now exists
  });

  it('listFlows: one entry per id, published flow + hasDraft flag', async () => {
    await saveDraft(db, flow('f'), null, now); await publishDraft(db, 'f', 1, now);
    await saveDraft(db, flow('f', 'b'), null, now); // open draft
    const list = await listFlows(db);
    const entry = list.find((e) => e.id === 'f')!;
    expect(entry.status).toBe('published');
    expect(entry.flow.nodes[0].config).toMatchObject({ transport: { path: '/a' } }); // published content
    expect(entry.hasDraft).toBe(true);
  });

  it('deleteFlow removes all rows for the id', async () => {
    await saveDraft(db, flow('f'), null, now); await publishDraft(db, 'f', 1, now);
    await saveDraft(db, flow('f', 'b'), null, now);
    expect(await deleteFlow(db, 'f')).toBe(true);
    expect(await listFlowVersions(db, 'f')).toEqual([]);
    expect(await readPublished(db, 'f')).toBeNull();
  });
});
```

- [ ] **Step 2: Run to verify fail**

Run: `cd eldrin-integration && npx vitest run src/flow/store.test.ts`
Expected: FAIL — new functions not exported.

- [ ] **Step 3: Rewrite `src/flow/store.ts`**

```ts
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';
import type { IntegrationDescriptor } from '../descriptor';
import { IntegrationError } from '../errors';
import { compileDescriptorToFlows } from './compile';
import type { Flow } from './types';

export type FlowStatus = 'draft' | 'published' | 'archived';

export interface StoredFlow {
  id: string;
  integrationId: string;
  flow: Flow;
  version: number;
  status: FlowStatus;
  createdAt: number;
  updatedAt: number;
}

interface FlowRow {
  id: string;
  integration_id: string;
  flow_json: string;
  version: number;
  status: FlowStatus;
  created_at: number;
  updated_at: number;
}

function toStored(row: FlowRow): StoredFlow {
  return {
    id: row.id,
    integrationId: row.integration_id,
    flow: JSON.parse(row.flow_json) as Flow,
    version: row.version,
    status: row.status,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

async function rowByStatus(db: DatabaseAdapter, id: string, status: FlowStatus): Promise<StoredFlow | null> {
  const row = await db
    .prepare(`SELECT * FROM _integration_flows WHERE id = ? AND status = ? ORDER BY version DESC LIMIT 1`)
    .bind(id, status).first<FlowRow>();
  return row ? toStored(row) : null;
}

export function readPublished(db: DatabaseAdapter, id: string): Promise<StoredFlow | null> {
  return rowByStatus(db, id, 'published');
}

export function readDraft(db: DatabaseAdapter, id: string): Promise<StoredFlow | null> {
  return rowByStatus(db, id, 'draft');
}

export async function readFlowForEdit(db: DatabaseAdapter, id: string): Promise<StoredFlow | null> {
  return (await readDraft(db, id)) ?? (await readPublished(db, id));
}

export async function listFlowVersions(db: DatabaseAdapter, id: string): Promise<StoredFlow[]> {
  const res = await db.prepare(`SELECT * FROM _integration_flows WHERE id = ? ORDER BY version DESC`).bind(id).all<FlowRow>();
  return res.results.map(toStored);
}

async function maxVersion(db: DatabaseAdapter, id: string): Promise<number> {
  const row = await db.prepare(`SELECT MAX(version) AS m FROM _integration_flows WHERE id = ?`).bind(id).first<{ m: number | null }>();
  return row?.m ?? 0;
}

export async function saveDraft(db: DatabaseAdapter, flow: Flow, baseVersion: number | null, now: () => number): Promise<StoredFlow> {
  const draft = await readDraft(db, flow.id);
  const ts = now();
  if (!draft) {
    // No draft yet → CREATE one, regardless of baseVersion (the editor passes the published
    // version here when editing a live flow; that must fork a fresh draft, not 404/409).
    const version = (await maxVersion(db, flow.id)) + 1;
    await db.prepare(
      `INSERT INTO _integration_flows (id, integration_id, flow_json, version, status, created_at, updated_at) VALUES (?, ?, ?, ?, 'draft', ?, ?)`,
    ).bind(flow.id, flow.integrationId, JSON.stringify(flow), version, ts, ts).run();
    return { id: flow.id, integrationId: flow.integrationId, flow, version, status: 'draft', createdAt: ts, updatedAt: ts };
  }
  // Existing draft → re-save. A non-null baseVersion must match the draft (concurrent-edit guard);
  // a null baseVersion means "continue this draft" and locks implicitly on the current draft version.
  if (baseVersion !== null && draft.version !== baseVersion) {
    throw new IntegrationError(`version conflict: ${flow.id} draft is at version ${draft.version}, not ${baseVersion}`, 409);
  }
  const nextVersion = draft.version + 1;
  await db.prepare(
    `UPDATE _integration_flows SET flow_json = ?, version = ?, updated_at = ? WHERE id = ? AND version = ? AND status = 'draft'`,
  ).bind(JSON.stringify(flow), nextVersion, ts, flow.id, draft.version).run();
  return { id: flow.id, integrationId: flow.integrationId, flow, version: nextVersion, status: 'draft', createdAt: draft.createdAt, updatedAt: ts };
}

export async function publishDraft(db: DatabaseAdapter, id: string, baseVersion: number | null, now: () => number): Promise<StoredFlow> {
  const draft = await readDraft(db, id);
  if (!draft) throw new IntegrationError(`no draft to publish: ${id}`, 404);
  if (baseVersion !== null && draft.version !== baseVersion) {
    throw new IntegrationError(`version conflict: ${id} draft is at version ${draft.version}, not ${baseVersion}`, 409);
  }
  const ts = now();
  await db.prepare(`UPDATE _integration_flows SET status = 'archived', updated_at = ? WHERE id = ? AND status = 'published'`).bind(ts, id).run();
  await db.prepare(`UPDATE _integration_flows SET status = 'published', updated_at = ? WHERE id = ? AND version = ? AND status = 'draft'`).bind(ts, id, draft.version).run();
  return { ...draft, status: 'published', updatedAt: ts };
}

export async function republish(db: DatabaseAdapter, id: string, version: number, now: () => number): Promise<StoredFlow> {
  const res = await db.prepare(`SELECT * FROM _integration_flows WHERE id = ? AND version = ?`).bind(id, version).first<FlowRow>();
  if (!res) throw new IntegrationError(`flow version not found: ${id} v${version}`, 404);
  const ts = now();
  await db.prepare(`UPDATE _integration_flows SET status = 'archived', updated_at = ? WHERE id = ? AND status = 'published' AND version != ?`).bind(ts, id, version).run();
  await db.prepare(`UPDATE _integration_flows SET status = 'published', updated_at = ? WHERE id = ? AND version = ?`).bind(ts, id, version).run();
  return { ...toStored(res), status: 'published', updatedAt: ts };
}

export async function deleteFlow(db: DatabaseAdapter, id: string): Promise<boolean> {
  const any = await db.prepare(`SELECT 1 AS x FROM _integration_flows WHERE id = ? LIMIT 1`).bind(id).first<{ x: number }>();
  if (!any) return false;
  await db.prepare(`DELETE FROM _integration_flows WHERE id = ?`).bind(id).run();
  return true;
}

export interface FlowListEntry {
  id: string;
  integrationId: string;
  flow: Flow;
  version: number;
  status: FlowStatus;
  updatedAt: number;
  hasDraft: boolean;
}

export async function listFlows(db: DatabaseAdapter): Promise<FlowListEntry[]> {
  const res = await db.prepare(`SELECT * FROM _integration_flows ORDER BY id, version DESC`).all<FlowRow>();
  const byId = new Map<string, { rows: FlowRow[] }>();
  for (const r of res.results) {
    if (!byId.has(r.id)) byId.set(r.id, { rows: [] });
    byId.get(r.id)!.rows.push(r);
  }
  const out: FlowListEntry[] = [];
  for (const [id, { rows }] of byId) {
    const published = rows.find((r) => r.status === 'published');
    const draft = rows.find((r) => r.status === 'draft');
    const chosen = published ?? draft ?? rows[0]; // rows is version-desc; fallback newest
    const s = toStored(chosen);
    out.push({ id, integrationId: s.integrationId, flow: s.flow, version: s.version, status: s.status, updatedAt: s.updatedAt, hasDraft: !!draft });
  }
  return out;
}

/** Compiled defaults with PUBLISHED overrides applied per flow id (what runs). */
export async function loadEffectiveFlows(db: DatabaseAdapter, descriptor: IntegrationDescriptor): Promise<Flow[]> {
  const compiled = compileDescriptorToFlows(descriptor);
  const out: Flow[] = [];
  for (const def of compiled) {
    const published = await readPublished(db, def.id);
    out.push(published ? published.flow : def);
  }
  return out;
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd eldrin-integration && npx vitest run src/flow/store.test.ts`
Expected: PASS (all draft/published tests).

- [ ] **Step 5: Typecheck (other files still reference old names — expect errors)**

Run: `cd eldrin-integration && npx tsc -b --noEmit`
Expected: FAIL — `create-worker.ts`, `sync/index.ts`, `index.ts` still import `readFlow`/`writeFlow`. These are resolved in Tasks 3-5. Confirm the ONLY errors are missing `readFlow`/`writeFlow` imports in those three files.

- [ ] **Step 6: Commit**

```bash
cd eldrin-integration
git add src/flow/store.ts src/flow/store.test.ts
git commit -m "feat(flow): rewrite store as draft/published version-history API"
```

---

## Task 3: Executor reads published (the headline guarantee)

**Files:**
- Modify: `src/sync/index.ts` (line ~8 import, ~45 read)
- Test: `src/flow/execute-integration.test.ts` (add the draft-invisible-to-sync test) — or `src/sync/index.test.ts` if it exists; check and use the existing sync-integration test file.

**Interfaces:**
- Consumes: `readPublished` (Task 2).
- Produces: `runResourceSync` runs the published flow, else compiled default. No signature change.

- [ ] **Step 1: Write the failing integration test**

The sync integration test is `src/sync/index.test.ts`. It uses `runResourceSync(resource, deps(transport))` where `deps = (t) => ({ db, transport: t, now: () => 1000, genId: ... })`, `db = await makeTestDb([SYNC_STATE_DDL, FLOWS_DDL, storedResourceDDL('clients', ['name TEXT','email TEXT'])])`, a `resource` describing `clients`, and a `fakeTransport([rows])` helper. The compiled flow id is `<integrationId>:clients` (deps need `integrationId` — check how the existing tests get the compiled id; `runResourceSync` uses `deps.integrationId ?? 'integration'`, so the compiled id is `integration:clients` unless deps set integrationId). Add a test proving a draft is invisible to sync.

A draft's content that would be *observable* if it ran: change the map so a column gets a different value (e.g. drop the `email` mapping so email is null), or change `mode`. Simplest observable difference: a draft whose map omits the `name` connection → if the draft ran, `name` would be null. Assert it's NOT null after a draft save (compiled default ran), then IS null after publish.

```ts
it('a saved-but-unpublished draft does not change what sync runs; publishing does', async () => {
  const { saveDraft, publishDraft } = await import('../flow/store');
  const { compileResourceToFlow } = await import('../flow/compile');
  const flowId = compileResourceToFlow('integration', resource).id; // matches runResourceSync's deps.integrationId ?? 'integration'

  // 1. Baseline: no stored flow → compiled default runs, maps name through.
  await runResourceSync(resource, deps(fakeTransport([{ id: 1, name: 'Ada', email: 'a@x.io' }])));
  let row = await db.prepare(`SELECT name FROM clients WHERE remote_id = ?`).bind('1').first<{ name: string }>();
  expect(row!.name).toBe('Ada');

  // 2. Save a DRAFT whose map omits 'name' (would null it if it ran). Do NOT publish.
  const compiled = compileResourceToFlow('integration', resource);
  const draftFlow = { ...compiled, nodes: compiled.nodes.map((nd) =>
    nd.kind === 'map' ? { ...nd, config: { connections: (nd.config as any).connections.filter((c: any) => c.target !== 'name') } } : nd) };
  await saveDraft(db, draftFlow as any, null, () => 1000);

  // 3. Re-sync → still the compiled default (draft invisible): name still maps.
  await runResourceSync(resource, deps(fakeTransport([{ id: 2, name: 'Grace', email: 'g@x.io' }])));
  row = await db.prepare(`SELECT name FROM clients WHERE remote_id = ?`).bind('2').first<{ name: string }>();
  expect(row!.name).toBe('Grace'); // draft did NOT take effect

  // 4. Publish the draft → now sync uses it: name is dropped (null).
  await publishDraft(db, flowId, 1, () => 1000);
  await runResourceSync(resource, deps(fakeTransport([{ id: 3, name: 'Linus', email: 'l@x.io' }])));
  row = await db.prepare(`SELECT name FROM clients WHERE remote_id = ?`).bind('3').first<{ name: string | null }>();
  expect(row!.name).toBeNull(); // published draft took effect
});
```
(Adapt `compileResourceToFlow`'s import path / the `name`-connection shape to the real compiled flow — read `src/flow/compile.ts` to confirm the map connection target names for `clients`. If the compiled map uses different column names, pick a column the compiled flow DOES map and omit it in the draft.)

- [ ] **Step 2: Run to verify fail**

Run: `cd eldrin-integration && npx vitest run <the sync integration test file>`
Expected: FAIL — `runResourceSync` still reads `readFlow` (which no longer exists → import error), or runs the draft.

- [ ] **Step 3: Implement the read switch**

In `src/sync/index.ts`: change the import (line 8) `import { readFlow } from '../flow/store';` → `import { readPublished } from '../flow/store';`. Change the read (line 45) `const stored = await readFlow(deps.db, compiled.id);` → `const stored = await readPublished(deps.db, compiled.id);`. The next line `const flow = stored ? stored.flow : compiled;` is unchanged (published-else-compiled).

- [ ] **Step 4: Run to verify pass**

Run: `cd eldrin-integration && npx vitest run <the sync integration test file>`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd eldrin-integration
git add src/sync/index.ts <the sync integration test file>
git commit -m "feat(sync): executor reads the published flow (drafts never execute)"
```

---

## Task 4: Write routes — save-draft, publish, republish

**Files:**
- Modify: `src/host/create-worker.ts` (POST `:id` → `saveDraft`; new `/publish`, `/republish`)
- Test: `src/host/create-worker.test.ts`

**Interfaces:**
- Consumes: `saveDraft`, `publishDraft`, `republish` (Task 2); existing `validateFlow`, `prepare`, `boundHooks`, `resolveUserId`, `isAdmin`, `IntegrationError`.
- Produces: `POST /api/flows/:id` (draft), `POST /api/flows/:id/publish`, `POST /api/flows/:id/republish` — all admin-gated.

- [ ] **Step 1: Write the failing route tests**

In `src/host/create-worker.test.ts`, INSIDE the existing `describe('/api/flows routes', …)` block (so you reuse its `adminJwt`/`nonAdminJwt`/`flowsEnv`/`validFlow`/`worker`/`flowsDb` from `beforeEach`). The request idiom is `worker.fetch(new Request(url, {method, headers, body}), flowsEnv, {} as any)`. Add a helper + tests:
```ts
const POST = (path: string, jwt: string | null, body: unknown) =>
  worker.fetch(new Request('http://x' + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(jwt ? { Authorization: 'Bearer ' + jwt } : {}) },
    body: JSON.stringify(body),
  }), flowsEnv, {} as any);
const GET = (path: string, jwt = adminJwt) =>
  worker.fetch(new Request('http://x' + path, { headers: { Authorization: 'Bearer ' + jwt } }), flowsEnv, {} as any);

it('POST /api/flows/:id saves a DRAFT and does not publish', async () => {
  const res = await POST('/api/flows/acme:clients', adminJwt, { flow: validFlow });
  expect(res.status).toBe(200);
  const body = await res.json() as any;
  expect(body.status).toBe('draft');
  // not live yet:
  const pub = await GET('/api/flows/acme:clients/published');
  expect(pub.status).toBe(404);
});

it('POST /api/flows/:id/publish promotes the draft → published', async () => {
  await POST('/api/flows/acme:clients', adminJwt, { flow: validFlow });        // draft v1
  const res = await POST('/api/flows/acme:clients/publish', adminJwt, { baseVersion: 1 });
  expect(res.status).toBe(200);
  expect((await res.json() as any).status).toBe('published');
  expect((await GET('/api/flows/acme:clients/published')).status).toBe(200);
});

it('publish 404s with no draft', async () => {
  const res = await POST('/api/flows/acme:clients/publish', adminJwt, { baseVersion: 1 });
  expect(res.status).toBe(404);
});

it('publish re-validates against live knownTables (unknown destination table → 400)', async () => {
  // Insert a draft DIRECTLY via the store whose destination table is NOT a known resource,
  // bypassing the save-time validation, to prove publish independently re-validates.
  const { saveDraft } = await import('../flow/store');
  const badFlow = { ...validFlow, nodes: validFlow.nodes.map((n) => n.id === 'destination'
    ? { ...n, config: { kind: 'd1', table: 'ghost_table', mode: 'stored' } } : n) };
  await saveDraft(flowsDb, badFlow as any, null, () => 1);
  const res = await POST('/api/flows/acme:clients/publish', adminJwt, { baseVersion: 1 });
  expect(res.status).toBe(400); // validateFlow rejects unknown destination table at publish
});

it('POST /api/flows/:id/republish restores a prior version', async () => {
  await POST('/api/flows/acme:clients', adminJwt, { flow: validFlow });                    // draft v1
  await POST('/api/flows/acme:clients/publish', adminJwt, { baseVersion: 1 });             // pub v1
  const v2 = { ...validFlow, trigger: { kind: 'cron', expr: '0 * * * *' } };
  await POST('/api/flows/acme:clients', adminJwt, { flow: v2 });                           // draft v2
  await POST('/api/flows/acme:clients/publish', adminJwt, { baseVersion: 2 });             // pub v2
  const res = await POST('/api/flows/acme:clients/republish', adminJwt, { version: 1 });
  expect(res.status).toBe(200);
  const pub = await (await GET('/api/flows/acme:clients/published')).json() as any;
  expect(pub.version).toBe(1);
});

it('publish + republish require admin (401 no auth, 403 non-admin)', async () => {
  expect((await POST('/api/flows/acme:clients/publish', null, {})).status).toBe(401);
  expect((await POST('/api/flows/acme:clients/publish', nonAdminJwt, {})).status).toBe(403);
  expect((await POST('/api/flows/acme:clients/republish', null, { version: 1 })).status).toBe(401);
});
```

- [ ] **Step 2: Run to verify fail**

Run: `cd eldrin-integration && npx vitest run src/host/create-worker.test.ts`
Expected: FAIL — POST still calls `writeFlow` (gone), new routes 404.

- [ ] **Step 3: Implement the routes**

Update the import (line ~22): `import { saveDraft, publishDraft, republish, readPublished, readDraft, readFlowForEdit, listFlows, listFlowVersions, deleteFlow } from '../flow/store';`.

Change `POST /api/flows/:id` to call `saveDraft` (validation unchanged):
```ts
const stored = await saveDraft(db, body.flow, body.baseVersion ?? null, () => Date.now());
return c.json({ flow: stored.flow, version: stored.version, status: stored.status });
```

Add BEFORE `/api/flows/:id` (the GET) — but POST routes don't collide with the GET `:id`; register the publish/republish POSTs near the POST `:id`. They use distinct paths so ordering vs GET `:id` is not an issue, but keep them grouped:
```ts
app.post('/api/flows/:id/publish', async (c) => {
  const userId = resolveUserId(c);
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);
  if (!isAdmin(c)) return c.json({ error: 'Forbidden: admin role required' }, 403);
  const { db, effective } = await prepare(c.env);
  const id = c.req.param('id');
  const body = await c.req.json().catch(() => null);
  try {
    const draft = await readDraft(db, id);
    if (!draft) return c.json({ error: 'No draft to publish' }, 404);
    validateFlow(draft.flow, { hooks: boundHooks, hookSlots: new Set(['transform', 'beforeUpsert']), knownTables: new Set(effective.resources.map((r) => r.name)) });
    const stored = await publishDraft(db, id, body?.baseVersion ?? null, () => Date.now());
    return c.json({ flow: stored.flow, version: stored.version, status: stored.status });
  } catch (e) {
    const status = e instanceof IntegrationError ? e.status : 500;
    return c.json({ error: e instanceof Error ? e.message : 'Publish failed' }, status as 400 | 404 | 409 | 500);
  }
});

app.post('/api/flows/:id/republish', async (c) => {
  const userId = resolveUserId(c);
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);
  if (!isAdmin(c)) return c.json({ error: 'Forbidden: admin role required' }, 403);
  const { db } = await prepare(c.env);
  const body = await c.req.json().catch(() => null);
  if (typeof body?.version !== 'number') return c.json({ error: 'Missing version in body' }, 400);
  try {
    const stored = await republish(db, c.req.param('id'), body.version, () => Date.now());
    return c.json({ flow: stored.flow, version: stored.version, status: stored.status });
  } catch (e) {
    const status = e instanceof IntegrationError ? e.status : 500;
    return c.json({ error: e instanceof Error ? e.message : 'Republish failed' }, status as 400 | 404 | 409 | 500);
  }
});
```
**IMPORTANT Hono ordering:** `/api/flows/:id/publish` and `/api/flows/:id/republish` are POSTs; they must be registered so a POST to `/api/flows/x/publish` matches the publish route, not POST `/api/flows/:id`. Since `:id` would capture `x` and then `/publish` is an extra segment, `POST /api/flows/:id` (no trailing segment) does NOT match `/api/flows/x/publish` — distinct paths. Register publish/republish anywhere among the POSTs; no collision. (Verify with the test.)

- [ ] **Step 4: Run to verify pass**

Run: `cd eldrin-integration && npx vitest run src/host/create-worker.test.ts`
Expected: PASS (new route tests; existing POST-now-saves-draft adapted).

- [ ] **Step 5: Commit**

```bash
cd eldrin-integration
git add src/host/create-worker.ts src/host/create-worker.test.ts
git commit -m "feat(host): POST /flows/:id saves draft; add /publish + /republish routes"
```

---

## Task 5: Read routes + effective overlay + barrel exports

**Files:**
- Modify: `src/host/create-worker.ts` (GET `:id` → draft-else-published + status; `/published`; `/versions`; `/effective` published-overlay; `/api/flows` list + `hasDraft`)
- Modify: `src/index.ts` (barrel)
- Test: `src/host/create-worker.test.ts`

**Interfaces:**
- Consumes: `readFlowForEdit`, `readPublished`, `listFlowVersions`, `listFlows` (Task 2).
- Produces: `GET /api/flows/:id` (draft-else-published + status), `GET /api/flows/:id/published`, `GET /api/flows/:id/versions`, `/effective` overlays published, `/api/flows` list gains `hasDraft`. Barrel re-exports the new store API.

- [ ] **Step 1: Write the failing route tests**

In `create-worker.test.ts`, inside the same `/api/flows routes` describe (reusing `POST`/`GET` helpers from Task 4, `validFlow`, `worker`, `flowsEnv`):
```ts
it('GET /api/flows/:id returns the draft if one exists (else published) with status', async () => {
  await POST('/api/flows/acme:clients', adminJwt, { flow: validFlow });        // draft v1
  await POST('/api/flows/acme:clients/publish', adminJwt, { baseVersion: 1 }); // pub v1, no draft
  expect((await (await GET('/api/flows/acme:clients')).json() as any).status).toBe('published');
  const v2 = { ...validFlow, trigger: { kind: 'cron', expr: '5 * * * *' } };
  await POST('/api/flows/acme:clients', adminJwt, { flow: v2 });               // draft v2
  expect((await (await GET('/api/flows/acme:clients')).json() as any).status).toBe('draft');
});

it('GET /api/flows/:id/published returns the live flow', async () => {
  await POST('/api/flows/acme:clients', adminJwt, { flow: validFlow });
  await POST('/api/flows/acme:clients/publish', adminJwt, { baseVersion: 1 });
  const res = await GET('/api/flows/acme:clients/published');
  expect(res.status).toBe(200);
  expect((await res.json() as any).status).toBe('published');
});

it('GET /api/flows/:id/versions lists history newest-first', async () => {
  await POST('/api/flows/acme:clients', adminJwt, { flow: validFlow });
  await POST('/api/flows/acme:clients/publish', adminJwt, { baseVersion: 1 });
  await POST('/api/flows/acme:clients', adminJwt, { flow: validFlow });        // draft v2
  const versions = await (await GET('/api/flows/acme:clients/versions')).json() as any[];
  expect(versions.map((v) => v.version)).toEqual([2, 1]);
  expect(versions.find((v) => v.version === 1).status).toBe('published');
});

it('GET /api/flows/effective overlays PUBLISHED, not the draft, and flags hasDraft', async () => {
  await POST('/api/flows/acme:clients', adminJwt, { flow: validFlow });        // path /clients
  await POST('/api/flows/acme:clients/publish', adminJwt, { baseVersion: 1 }); // pub
  const v2 = { ...validFlow, trigger: { kind: 'cron', expr: '9 * * * *' } };
  await POST('/api/flows/acme:clients', adminJwt, { flow: v2 });               // unpublished draft
  const eff = await (await GET('/api/flows/effective')).json() as any[];
  const entry = eff.find((e) => e.flow.id === 'acme:clients');
  expect(entry.flow.trigger.kind).toBe('manual');  // published v1, NOT the cron draft
  expect(entry.hasDraft).toBe(true);
});

it('GET /api/flows list includes hasDraft + status', async () => {
  await POST('/api/flows/acme:clients', adminJwt, { flow: validFlow });
  const list = await (await GET('/api/flows')).json() as any[];
  const entry = list.find((e) => e.id === 'acme:clients');
  expect(entry.hasDraft).toBe(true);
  expect(entry.status).toBe('draft');
});
```

- [ ] **Step 2: Run to verify fail**

Run: `cd eldrin-integration && npx vitest run src/host/create-worker.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement**

`GET /api/flows/:id` → `readFlowForEdit`:
```ts
const stored = await readFlowForEdit(db, c.req.param('id'));
return stored ? c.json(stored) : c.json({ error: 'Flow not found' }, 404);
```
(`stored` now includes `status` since `StoredFlow` carries it.)

Add `/published` and `/versions` BEFORE `/api/flows/:id` (Hono ordering — specific paths first), next to `/fields`:
```ts
app.get('/api/flows/:id/published', async (c) => {
  const userId = resolveUserId(c);
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);
  if (!isAdmin(c)) return c.json({ error: 'Forbidden: admin role required' }, 403);
  const { db } = await prepare(c.env);
  const stored = await readPublished(db, c.req.param('id'));
  return stored ? c.json(stored) : c.json({ error: 'No published flow' }, 404);
});

app.get('/api/flows/:id/versions', async (c) => {
  const userId = resolveUserId(c);
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);
  if (!isAdmin(c)) return c.json({ error: 'Forbidden: admin role required' }, 403);
  const { db } = await prepare(c.env);
  return c.json(await listFlowVersions(db, c.req.param('id')));
});
```

`/effective` overlay — the new `listFlows` returns published-or-draft entries; but `/effective` must overlay PUBLISHED. Use `readPublished` per compiled flow (mirrors `loadEffectiveFlows`):
```ts
app.get('/api/flows/effective', async (c) => {
  const userId = resolveUserId(c);
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);
  if (!isAdmin(c)) return c.json({ error: 'Forbidden: admin role required' }, 403);
  const { db, effective } = await prepare(c.env);
  const compiled = compileDescriptorToFlows(effective);
  const list = await listFlows(db);
  const byId = new Map(list.map((e) => [e.id, e]));
  const out = await Promise.all(compiled.map(async (flow) => {
    const published = await readPublished(db, flow.id);
    const entry = byId.get(flow.id);
    return { flow: published ? published.flow : flow, version: published ? published.version : null, stored: !!published, hasDraft: entry?.hasDraft ?? false };
  }));
  return c.json(out);
});
```

`/api/flows` list — surface `hasDraft`:
```ts
const flows = await listFlows(db);
return c.json(flows.map((f) => ({ id: f.id, integrationId: f.integrationId, version: f.version, status: f.status, hasDraft: f.hasDraft, updatedAt: f.updatedAt })));
```

`src/index.ts` barrel: replace the old store export line with:
```ts
export { saveDraft, publishDraft, republish, readPublished, readDraft, readFlowForEdit, listFlowVersions, listFlows, deleteFlow, loadEffectiveFlows, type StoredFlow, type FlowStatus, type FlowListEntry } from './flow/store';
```

- [ ] **Step 4: Run to verify pass + full suite + tsc**

Run: `cd eldrin-integration && npx vitest run && npx tsc -b --noEmit`
Expected: full suite PASS (all draft/published tests + the existing suite adapted), tsc CLEAN (all `readFlow`/`writeFlow` references resolved).

- [ ] **Step 5: Commit**

```bash
cd eldrin-integration
git add src/host/create-worker.ts src/index.ts src/host/create-worker.test.ts
git commit -m "feat(host): draft/published read routes + effective published-overlay + barrel"
```

---

## After all tasks

- Final whole-branch review (most-capable model): focus on the migration (idempotent + preserves live flows), the one-draft/one-published invariants holding across save/publish/republish sequences, drafts never executing (the sync read), and `/effective` showing published.
- Then `superpowers:finishing-a-development-branch` (single repo, eldrin-integration).
- Rebuild the SDK dist (`npm run build`) per the SP5 stale-dist lesson so dependents get the new store API.
- A focused live check (optional, no UI yet for publish): via `/api/flows` curl — save a draft, confirm `/effective` unchanged, publish, confirm `/effective` changed.
