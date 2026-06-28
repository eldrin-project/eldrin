# Config-Derived Schema (Auto-DDL) for Stored Integrations — Technical Design

**Date:** 2026-06-28
**Status:** Approved (design); ready for implementation planning
**Builds on:**
- `docs/superpowers/specs/2026-06-27-integration-extension-design.md` (the `@eldrin-project/eldrin-integration` SDK)
- `docs/superpowers/specs/2026-06-27-manifest-driven-integration-design.md` (the `createIntegrationWorker` host + declarative config)

---

## 1. Summary

For a `stored` integration resource, the table schema is **fully derivable from the descriptor**: the resource `name` is the table, and the `fieldMap` local column names are the columns. The SDK already ships `storedResourceDDL(tableName, columns)` which builds exactly this SQL. Today, factorial nonetheless hand-writes migration files that duplicate this information.

This design makes the SDK host **derive and reconcile the stored-table schema from config at runtime**, eliminating hand-written migration files for the common case. A no-business-logic stored integration ships **zero migration files**.

Two clearly separated mechanisms:

- **`ensureSchema`** — runs automatically in the host's `prepare()`, idempotent and **non-destructive**: create tables that don't exist, and add `fieldMap` columns that are missing (additive `ALTER`). Adding a field to config "just works."
- **`pruneSchema`** — the destructive reconcile, **never automatic**: detects and (on explicit confirmation) removes **orphaned SDK-owned** columns and whole tables (a `fieldMap` entry removed, or a `stored` resource removed from config). Exposed via an admin-permissioned route `POST /api/schema/prune` with a default dry-run/report mode. The future configuration UI's "Delete orphaned columns/tables" action calls this endpoint.

The platform's checksum-tracked migration system (`_eldrin_migrations`) stays available for genuine one-off hand-written changes, but is no longer required for stored-table creation. `eldrin-factorial` is refactored to remove its migration files entirely, proving the zero-migration capability end-to-end.

---

## 2. Goals & Non-Goals

### Goals

- `ensureSchema(db, descriptor)`: automatic, idempotent, non-destructive — `CREATE TABLE IF NOT EXISTS` for each `stored` resource (columns from `fieldMap`) + the SDK management tables, plus additive `ALTER TABLE ADD COLUMN` for `fieldMap` columns missing from an existing table.
- `pruneSchema(db, descriptor, { dryRun })`: detect orphaned SDK-owned columns and tables; report them (dry-run, the default); drop them only on explicit confirmation. Touches **only** SDK-owned schema.
- An admin-permissioned route `POST /api/schema/prune` (default dry-run; `?confirm=1` to execute) that the future config UI calls.
- Wire `ensureSchema` into the host's `prepare()`, before `seedConfigFromDescriptor`.
- Refactor `eldrin-factorial` to remove all migration artifacts and rely on auto-DDL.
- SDK README documents both mechanisms and the "no migrations needed for stored integrations" model.

### Non-Goals (explicitly out of scope)

- **The configuration UI** that triggers prune — deferred (a separate later project). This design builds the *capability* (the function + the route + dry-run report); only the UI is deferred.
- **Automatic destructive reconcile** — drops are never automatic; they require the admin-triggered route with confirmation.
- **Column rename / retype detection** — `ensureSchema` only adds columns. Renames/retypes are not derivable from config (a removed name + an added name are indistinguishable from a rename) and remain the domain of a hand-written migration.
- **Exact ownership metadata** — MVP derives ownership from config (fixed columns + current fieldMap) rather than recording SDK-created columns in a metadata table. See §3.3 for the caveat and the dry-run mitigation. A metadata table is a possible future enhancement.
- Changing the platform migration system (`_eldrin_migrations`, `runMigrations`) — it stays as-is for hand-written one-offs.

---

## 3. Architecture

```
@eldrin-project/eldrin-integration
└── src/schema/
    ├── tables.ts        EXISTING: storedResourceDDL, SDK_TABLES, *_DDL constants
    ├── ensure.ts        NEW: ensureSchema(db, descriptor) — create + additive ALTER
    └── prune.ts         NEW: pruneSchema(db, descriptor, opts) — detect + drop orphans
└── src/host/
    └── create-worker.ts MODIFY: call ensureSchema in prepare(); mount POST /api/schema/prune
```

Host runtime flow:

```
prepare(env):
  runMigrations(env.DB, {migrations})   ← only if hand-written migrations are passed (exceptions)
  ensureSchema(db, effectiveDescriptor) ← NEW: create + additive ALTER (automatic, safe)
  seedConfigFromDescriptor(db, seed)    ← existing
  loadEffectiveConfig(db, seed)         ← existing

POST /api/schema/prune[?confirm=1]  →  pruneSchema(db, descriptor, {dryRun: !confirm})
```

**Design for isolation:** `ensureSchema` (additive, safe) and `pruneSchema` (destructive, gated) are separate units with separate files and separate tests. The host composes them; the schema logic lives in `src/schema/`. Both operate purely on the app-core `DatabaseAdapter` (`prepare().bind().all()/run()`) and the in-memory descriptor — no drizzle, no filesystem.

### 3.1 `ensureSchema(db, descriptor)` — automatic, non-destructive

```
for each resource where supportedModes.includes('stored') OR defaultMode === 'stored':
  cols = fieldMap local column names, EXCLUDING the idField's mapping (that is remote_id)
  run storedResourceDDL(resource.name, cols)        // CREATE TABLE/INDEX IF NOT EXISTS
  existing = column names from PRAGMA table_info(resource.name)
  for each col in cols where col NOT in existing:
    ALTER TABLE resource.name ADD COLUMN col          // nullable; per-column, no-op if present
run each SDK_TABLES statement                          // CREATE IF NOT EXISTS
```

- Idempotent: re-running on an up-to-date DB does nothing observable.
- Additive only: never drops, renames, or retypes.
- Errors throw `IntegrationError` with context; never swallowed.
- A `live`/`cached`-only resource creates **no** table.

> **Stored-resource selection:** a resource participates in `ensureSchema` when `stored` is among its modes (it may be stored). This matches how `runResourceSync`/`runAllSync` already gate on `stored`. A purely `live` resource (e.g. factorial's teams/timeoff) is skipped — no table.

### 3.2 `pruneSchema(db, descriptor, { dryRun })` — destructive, gated

Returns a report:
```ts
interface PruneReport {
  orphanedColumns: { table: string; column: string }[];
  orphanedTables: string[];
  skipped: { kind: 'column' | 'table'; name: string; reason: string }[];
  dropped: boolean;            // false for dry-run; true after executing drops
}
```

Logic:
- **Orphaned columns:** for each SDK-owned stored table, the owned column set = `{ id, remote_id, raw_json, synced_at }` ∪ current `fieldMap` columns. Any column in the DB table not in that set is orphaned.
- **Orphaned tables:** a user table that is NOT a current stored resource's table and NOT an `_integration_*` management table, AND that has the SDK signature shape (`remote_id` + `raw_json` + `synced_at` columns present), is an orphaned stored table (its resource was removed from config).
- **Dry-run (default):** compute and return the report; execute nothing.
- **Execute (`dryRun: false`):** `ALTER TABLE … DROP COLUMN` for orphaned columns; `DROP TABLE` for orphaned tables; SDK-owned only. A column/table that cannot be dropped (e.g. SQLite restriction, indexed column) is recorded in `skipped` with a reason rather than failing the whole operation. Set `dropped: true`.

### 3.3 Ownership caveat (honest)

Ownership is derived from config, not recorded. A *manually-added* column on an SDK table is indistinguishable from a *removed-fieldMap* column — both appear "extra." MVP treats any extra column on an SDK-shaped table as orphaned. This is acceptable because:
1. Drops are **admin-triggered and confirmed**, never automatic.
2. The **dry-run report lists every column/table it would drop**, so the admin reviews before confirming (`?confirm=1`).
3. Hand-editing SDK sync tables is already off-pattern.

A future enhancement may record SDK-created columns in a metadata table for exact ownership; out of scope here.

---

## 4. The Prune Route

`POST /api/schema/prune` mounted by `createIntegrationWorker`:

- **Auth:** userId resolved like `/api/sync` (X-Eldrin-User-Id or Bearer JWT `sub`); 401 if absent.
- **Permission:** admin-only. Declared in the manifest's route permissions so the shell's policy engine gates it; the route itself is not in `publicRoutes`.
- **Default dry-run:** without `?confirm=1`, returns the `PruneReport` with `dropped: false` — a safe preview.
- **Execute:** `?confirm=1` runs the drops and returns the report with `dropped: true`.
- **Errors:** `IntegrationError.status` mapping, consistent with the other host routes.

The future configuration UI's "Delete orphaned columns/tables" action calls this endpoint (dry-run to show the admin what would be removed, then confirm to execute).

---

## 5. Host Integration

In `prepare()` (`src/host/create-worker.ts`), the exact order is:
1. `runMigrations(env.DB, { migrations })` — only when `options.migrations` is non-empty (hand-written exceptions).
2. `seedConfigFromDescriptor(db, seed)` — writes `_integration_config` rows from the bundled seed if absent. (Operates on the config table only; does not touch resource tables.)
3. `effective = loadEffectiveConfig(db, seed)` — produces the effective descriptor with any runtime config overlay applied.
4. `await ensureSchema(db, effective)` — **unconditional**, runs against the **effective** descriptor so the stored resources (and their current fieldMap columns) reflect runtime config.

`ensureSchema` must run before any `/api/sync` or repository read touches a table — placing it last in `prepare()` (which every route calls before serving) guarantees that. `seedConfigFromDescriptor` seeds `_integration_config`, which `ensureSchema` also (idempotently) creates via `SDK_TABLES`; seeding tolerates the table already existing (`INSERT … ON CONFLICT`), so the seed-before-ensureSchema order is safe — but note `ensureSchema` is what guarantees `_integration_config` exists for `seedConfigFromDescriptor` on a truly fresh DB. **Therefore the management-table creation must happen before seeding.** Resolution: `ensureSchema` is split so the SDK management tables (`SDK_TABLES`) are created first (before seeding), and the per-resource stored tables + additive ALTER run after `loadEffectiveConfig`. Concretely: (a) create `SDK_TABLES` → (b) `seedConfigFromDescriptor` → (c) `loadEffectiveConfig` → (d) `ensureSchema` for the stored resource tables. The plan implements `ensureSchema` to accept the work in these two phases (or exposes a small `ensureManagementTables` + `ensureResourceTables` pair) so ordering is unambiguous and a fresh DB is handled correctly.

An integration that ships hand-written migrations still gets both paths: migrations first (for the one-off), then `ensureSchema` (idempotent — harmlessly confirms the derived schema). The two coexist without conflict because `ensureSchema` is `IF NOT EXISTS` + additive.

---

## 6. Factorial Cleanup (proving zero-migration)

- **Delete:** `eldrin-factorial/migrations/` (both `.sql` files), `worker/migrations.generated.ts`, `scripts/generate-migrations.ts`.
- **`package.json`:** remove the `generate:migrations` script; remove its prefix from `dev`/`dev:worker`/`build` scripts.
- **`worker/index.ts`:** remove the `migrations` import and the `migrations` option from `createIntegrationWorker(config, { hooks })`. The host's `ensureSchema` derives `employees`/`projects` tables + SDK management tables from the config.
- **Net:** factorial's `worker/` contains `index.ts` (one-liner) + `__tests__/` only — no migration artifacts.
- The historical `factorial_id → remote_id` rename is moot: fresh D1s (we wipe + recreate for testing) never had `factorial_id`. There is no production DB with `factorial_id` data to preserve.

---

## 7. Error Handling & Boundaries

- `ensureSchema` failures throw `IntegrationError` with the failing table/column in the message; never swallowed. A failure aborts `prepare()` (the integration can't serve correctly without its schema) — surfaced as a 500 on the triggering request.
- `pruneSchema` is resilient: an undroppable column/table is recorded in `skipped` and the operation continues; only an unexpected adapter error aborts.
- All schema SQL uses identifiers sourced from the descriptor (`resource.name`, `fieldMap` local column names — trusted) and the fixed SDK column set. No external/API data ever reaches a schema identifier. (Same trust model as the existing sync runner / repository.)
- `verbatimModuleSyntax`, strict TS, `DatabaseAdapter`-only, immutability — consistent with the rest of the SDK.

---

## 8. Testing Strategy

TDD, 80%+ coverage. Unit + integration + acceptance + E2E.

### Unit — `ensureSchema` (real SQLite via `makeTestDb`)
- Creates a stored resource's table with the fieldMap columns + `remote_id` unique index.
- Re-run on an up-to-date DB is a no-op (no error, no duplicate).
- Adding a fieldMap column then re-running ADDs the column (`PRAGMA table_info` shows it).
- Creates the three `_integration_*` management tables.
- A `live`-only resource creates NO table.

### Unit — `pruneSchema`
- Dry-run reports an orphaned column (fieldMap entry removed) WITHOUT dropping it; `dropped:false`.
- Dry-run reports an orphaned table (resource removed) without dropping.
- Execute (`dryRun:false`) drops only the orphaned SDK-owned column/table; `dropped:true`.
- Fixed columns (`id`/`remote_id`/`raw_json`/`synced_at`) are never reported/dropped.
- A non-SDK-shaped user table (lacking remote_id/raw_json/synced_at) is never a drop candidate.
- An undroppable column is recorded in `skipped`, operation still succeeds.

### Integration — host
- `prepare()` on a fresh in-memory DB (no migrations passed) auto-creates the schema; a subsequent stored `/api/sync` upserts successfully.
- `POST /api/schema/prune` (dry-run) returns a report; `?confirm=1` executes and reports `dropped:true`.
- `/api/schema/prune` without auth → 401.

### Factorial acceptance
- `host-sync.test.ts` passes with NO migrations array — proving the table is auto-derived. Add an assertion that the `employees`/`projects` tables exist with the fieldMap columns after `prepare()`.
- `config-loads.test.ts` stays green.

### E2E (manual, already exercised)
- Wipe D1 → restart factorial → first request auto-creates schema → sync → 38 employees / 8 projects, with **zero migration files** in the repo.

---

## 9. Implementation Order (suggested)

1. `ensureSchema` (`src/schema/ensure.ts`) + unit tests (create + additive ALTER).
2. `pruneSchema` (`src/schema/prune.ts`) + unit tests (detect + dry-run + execute + skipped).
3. Wire `ensureSchema` into host `prepare()`; mount `POST /api/schema/prune` (admin, dry-run default) + host integration tests.
4. SDK build, coverage gate, README update (document ensureSchema/pruneSchema/route + "no migrations for stored integrations").
5. Factorial cleanup: delete migrations + generate script, update package.json scripts, drop the `migrations` option from `worker/index.ts`; keep `host-sync.test.ts` green (+ schema-exists assertion).
6. E2E re-verify in the running app (wipe D1, restart, sync) — zero migration files.
