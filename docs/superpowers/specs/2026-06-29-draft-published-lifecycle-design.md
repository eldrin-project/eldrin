# Draft/Published Flow Lifecycle — Design Spec (SP7)

**Status:** approved (design), ready for implementation plan
**Date:** 2026-06-29
**Sub-project:** SP7 — draft/published lifecycle for the CPI-style integration flow platform
**Repo:** `eldrin-integration` (SDK only — no UI)

---

## Context & motivating finding

The original SP7 framing was "structural persistence." Ground-truth investigation found the SDK **already persists arbitrary node/edge graphs**: `POST /api/flows/:id` accepts any `Flow`, runs the full `validateFlow` (now routing-aware after SP6), version-locks, and stores the whole flow as JSON (`store.ts` `writeFlow` → `JSON.stringify(flow)`). The only thing blocking structural saves is eldrin-core's `applyDraft` (a client-side editing-model concern, deferred to SP8).

So SP7 is **rescoped** to a user-requested enhancement with clear standalone SDK value: a **draft/published lifecycle**. Saves write to a draft that never affects execution; an explicit **publish** promotes the draft to the live version the executor runs. (A future mechanism to *test* a draft before publishing is anticipated but out of scope here.)

**SP8 (still deferred)** — the outer flow-graph canvas + the structure-aware client editing model that produces structural edits.

## Decisions locked during brainstorming

- **Version-history rows** (not two-columns, not a separate table): each flow id has multiple rows in `_integration_flows`, distinguished by `version` + `status`.
- **One mutable draft + published history:** at most ONE open `draft` row per id (re-saves overwrite it, version-locked); `published` rows form immutable history; rollback = re-publish an old version.
- **Executor reads latest published, else compiled default:** drafts NEVER execute; a never-published flow runs the compiled descriptor default (today's fallback behavior preserved).

## 1. Storage Schema & Migration

**New `_integration_flows`** (version-history rows):
```
_integration_flows (
  id TEXT,                 -- flow id (no longer unique alone)
  integration_id TEXT,
  flow_json TEXT,
  version INTEGER,         -- monotonic per id
  status TEXT,             -- 'draft' | 'published' | 'archived'
  created_at INTEGER,
  updated_at INTEGER,
  PRIMARY KEY (id, version)
)
```
Code-enforced invariants: **at most one `draft` row per id**; **at most one `published` row per id** (older publishes → `archived` on the next publish/republish).

**Migration (the risky part).** The SDK has no filesystem; tables come from `SDK_TABLES` DDL run at bootstrap via `CREATE TABLE IF NOT EXISTS` — a no-op if the table already exists under the OLD schema (`id PRIMARY KEY`, no `status`). So changing `FLOWS_DDL` alone won't migrate existing rows. An explicit, idempotent migration step (in `ensureManagementTables` or a dedicated `migrateFlowsTable`):
1. `PRAGMA table_info(_integration_flows)` — if no `status` column, it's the old schema.
2. If old: rename → `_integration_flows_old`; create the new table; copy every old row in as **`status='published'`** (today's stored flow IS the live one) preserving `id/integration_id/flow_json/version/created_at/updated_at`; drop the old table.
3. Idempotent: if `status` already exists, no-op.

Deterministic (no `Date.now()` — uses existing row timestamps). **Regression guard: executor output identical before/after migration.** Rationale: a real flow (employees @ v6 from live tests) is stored — recreating the table would silently drop it.

## 2. Persistence API (`store.ts` rewrite)

`StoredFlow` gains `status: 'draft' | 'published' | 'archived'`.

**Reads:**
- `readPublished(db, id): StoredFlow | null` — latest `status='published'` row. **The executor/sync reads this.**
- `readDraft(db, id): StoredFlow | null` — the open `status='draft'` row, if any.
- `listFlowVersions(db, id): StoredFlow[]` — full history for an id (rollback UI later).
- `listFlows(db): StoredFlow[]` — one entry per id (latest published, else the draft if never published) — preserves what `/api/flows` + `/effective` list today. Each entry also exposes whether an unpublished draft exists for that id (e.g. a `hasDraft: boolean` / `draftVersion?: number` alongside the published flow), so the studio can show a "draft pending" indicator WITHOUT leaking draft content into the list. (The entry's `flow`/`version`/`status` describe the LIVE/published flow; `hasDraft` is the only draft signal exposed here.)

**Writes (all optimistic-locked via the existing `WHERE version = ?` guard):**
- `saveDraft(db, flow, baseVersion, ts): StoredFlow` — upsert the single draft row. `baseVersion=null` → create draft at the next version above any existing rows for the id; `baseVersion=N` → lock against the current draft's version (409 on mismatch). Re-saves overwrite the draft, bumping version. **Never touches published/archived rows.**
- `publishDraft(db, id, baseVersion, ts): StoredFlow` — promote the open draft to `published`; demote the prior `published` (if any) to `archived`. Locked on the draft version. 404 if no draft. Returns the now-published flow; no draft remains until the next edit.
- `republish(db, id, version, ts): StoredFlow` — rollback: take an existing published-history row by `version`, make it the live `published` (archiving the current live one).
- `deleteFlow(db, id)` — removes ALL rows for an id (revert to compiled default). Preserved.

**Key property:** `saveDraft` and `publishDraft` are SEPARATE operations — saving is cheap/frequent/invisible-to-execution; publishing is the deliberate promotion.

## 3. Route Changes (API surface)

All admin-gated (`resolveUserId`→401, `isAdmin`→403); specific paths registered BEFORE `/api/flows/:id` (Hono ordering).

**Write routes:**
- `POST /api/flows/:id` — **now saves a DRAFT** (`saveDraft`). Same body `{flow, baseVersion}`, same `validateFlow` gate, same 200/400/409 semantics. **Backward-compatible: the eldrin-core editor needs ZERO changes** — its saves simply become drafts.
- `POST /api/flows/:id/publish` — promote the draft (`publishDraft`). Body `{baseVersion}` (draft version being published). Re-runs `validateFlow` against LIVE context. 200 → `{flow, version, status:'published'}`; 409 if the draft moved; 404 if no draft.
- `POST /api/flows/:id/republish` — rollback (`republish`). Body `{version}` (historical published version to restore).

**Read routes:**
- `GET /api/flows/:id` — returns the **draft if one exists, else the published** (editor opens what you're working on) + a `status` field. **This is the editor's OPEN path** — opening a specific flow loads the in-progress draft so re-edits continue it rather than forking a new draft from published.
- `GET /api/flows/:id/published` — the live version explicitly.
- `GET /api/flows/:id/versions` — history list (rollback UI).
- `GET /api/flows/effective` — **overlays the PUBLISHED flow** per id (what runs); drafts don't appear in effective. **This is the studio LIST path only** (it shows what's live). To avoid the editor opening the published flow and silently forking over an existing draft, the editor opens via `GET /api/flows/:id` (above), NOT from the `/effective` payload. The `/effective` entry carries enough to flag an unpublished draft (see `listFlows` below) so the list can show a "draft pending" indicator without exposing the draft content.

**Reconciliation (avoids a real interaction bug):** `/effective` = list of LIVE flows; `GET /api/flows/:id` = editor open (draft-if-exists). The current eldrin-core editor mounts its editor from the list but fetches builtin-specs/fields on open — it will additionally fetch `GET /api/flows/:id` for the editable flow (a one-line change deferred to SP8/its own follow-up; until then the editor edits the published flow as today, which still works because save→draft is non-destructive to published). SP7 keeps the routes correct; wiring the editor's open-the-draft path is an eldrin-core change tracked for SP8.

**Executor/sync read:** `runResourceSync` switches `readFlow` → `readPublished` (published, else compiled default). One-line change — the whole point.

## 4. Validation, Edge Cases & the Publish Gate

**Validation — both, with intent:**
- **On save-draft:** run `validateFlow` (as today). A draft that won't validate can't be saved — keeps stored drafts always-sound + gives the editor immediate feedback. (A future WIP-invalid-draft mode is YAGNI.)
- **On publish:** re-run `validateFlow` against the CURRENT `knownTables`/hooks. The descriptor can change between save and publish (a referenced destination table might vanish); publishing a flow referencing a now-missing table must fail at publish, not silently go live.

**Edge cases (each a test):**
- Publish with no draft → 404.
- Save creates the first draft when only compiled-default exists → `baseVersion:null` → draft v1; executor still runs compiled default until publish.
- Publish the first draft → published v1; no prior to archive.
- Re-save a draft → overwrites the draft, version bumps; published untouched (assert published output identical before/after).
- Optimistic-lock conflict on save → stale `baseVersion` → 409.
- Optimistic-lock conflict on publish → draft changed between load and publish → 409.
- Republish an archived version → it becomes live; the previously-live one archives.
- Delete a flow with history → all rows removed; reverts to compiled default.
- Migration → existing old-schema stored flow becomes published v1; executor output identical pre/post.

**Concurrency:** D1 is single-writer per database; the optimistic-lock version check carries forward to `saveDraft`/`publishDraft`, so the one-draft/one-published invariants hold without extra locking.

## 5. Data Flow & Testing

```
editor save    → POST /api/flows/:id           → validateFlow → saveDraft (draft row, version-locked)   [INVISIBLE to execution]
editor publish → POST /api/flows/:id/publish    → validateFlow(live ctx) → publishDraft (draft→published, prior→archived)
sync/executor  → readPublished(id)              → published row, else compiled default                  [runs the LIVE flow]
rollback       → POST /api/flows/:id/republish  → republish (archived→published)
```

**Testing** (TDD, 80%+, SDK Vitest; existing `store.test.ts` is the base):
1. **`store.ts` unit (core):** `saveDraft` create/overwrite/version-lock; `publishDraft` promote+archive-prior, 404-no-draft, version-lock; `republish` restore; `readPublished`/`readDraft`/`listFlowVersions`/`listFlows` return the right rows; one-draft/one-published invariants across sequences.
2. **Migration unit:** seed an old-schema table → migrate → assert new schema, rows became `published`, `readPublished` returns them, idempotent on re-run.
3. **Route unit (`create-worker.test.ts`):** POST `:id` writes a draft (published unchanged); `/publish` promotes; `/effective` shows published not draft; `/versions` lists history; publish re-validates (draft referencing unknown table → fails at publish); admin-gated (401/403).
4. **Executor-source integration:** `runResourceSync` runs published else compiled default; a saved-but-unpublished draft does NOT change sync output (headline guarantee — sync result identical before/after a draft save, then changes after publish).
5. **Regression:** existing flow-persistence tests adapt to draft/published vocabulary; migration regression guard (output identical pre/post).

**Task breakdown** (detailed in the plan):
1. Schema + idempotent migration in `tables.ts`/`ensure.ts`.
2. `store.ts` rewrite (`saveDraft`/`publishDraft`/`republish` + reads).
3. Executor-source switch to `readPublished` + sync integration test.
4. Write routes: save-draft (POST `:id`), `/publish`, `/republish`.
5. Read routes: `/published`, `/versions`, `/effective` published-overlay, `status` on `GET :id`.

## Global Constraints (carried from the platform spec)

- **SDK-only:** all changes in `/Users/tibor/projects/eldrin-backup/eldrin-integration`. The eldrin-core editor needs NO changes (POST `:id` stays backward-compatible — saves become drafts).
- **Drafts never execute:** the executor/sync reads `readPublished` → published, else compiled default. This is the headline guarantee.
- **One draft + one published per id** (code-enforced); published history is immutable; rollback = `republish`.
- **Migration is idempotent + deterministic** (no `Date.now()`; existing timestamps), promotes existing stored flows to `published v1`; executor output identical pre/post (regression guard).
- **Validate on save AND publish;** publish re-validates against live `knownTables`/hooks.
- **Optimistic locking** via the existing `WHERE version = ?` guard, per operation.
- **Backward-compatible POST `:id`:** same body/validate/200-400-409; it just writes a draft now.
- Immutability; no `console.log`; conventional commits, attribution disabled. Coverage ≥ 80%. Tests: `cd eldrin-integration && npx vitest run`.
