# Calendar 4d Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the six hardening gaps deliberately deferred when Calendar Slice 4c shipped: sweep-race window, drizzle schema FK honesty, ASSETS deploy binding, multi-item Graph notification batches, proactive delta-window re-anchor, and the eldrin-email rotated-refresh-token defect found during the co-tenancy re-check.

**Architecture:** All calendar work lands in the `eldrin-calendar` submodule (worker sync core, schema, one new migration, wrangler config). The co-tenancy item produced a confirmed cross-app defect in `eldrin-email` (rotated Microsoft refresh tokens are discarded) fixed there. `eldrin-crm` and `eldrin-email` get the same one-line ASSETS binding fix as calendar. Parent repo gitlinks bump at the end.

**Tech Stack:** Cloudflare Workers, Hono 4, Drizzle ORM (D1/SQLite), Vitest (tests run real SQL migrations via better-sqlite3 with `PRAGMA foreign_keys = ON`), wrangler + @cloudflare/vite-plugin.

## Global Constraints

- Migration filenames MUST be 14-digit timestamps: `YYYYMMDDHHMMSS-description.sql` (shorter names are silently skipped by the migration runner).
- Conventional commits: `type(scope): description`. No AI attribution.
- Immutability: never mutate objects in place; build new objects (spread) — matches existing worker code style.
- Tests: run `npx vitest run` inside the submodule; the full suite must be green before each commit. eldrin-calendar baseline: 278 tests passing (main @ 7c08de3).
- Submodule workflow: work on a feature branch inside each submodule; the parent repo gitlink bump is a separate final task. NEVER run parent-repo git commands while the shell cwd is inside a submodule.
- REPO LAYOUT (verified): `eldrin-calendar` and `eldrin-crm` are SUBMODULES (own git repos, feature branches inside them). `eldrin-email` is PARENT-TRACKED (plain directory of the parent repo — it has NO `.git`): all eldrin-email changes are committed in the PARENT repo on its current branch (`feature/eldrin-factorial`), with `fix(email): ...` commit scopes. Do NOT run `git checkout`/`git branch` inside eldrin-email.
- `now()` and `generateId()` come from `worker/utils.ts` in eldrin-calendar (`Date.now()` / `crypto.randomUUID()`). Fake timers (`vi.useFakeTimers()` + `vi.setSystemTime()`) control `now()` in tests.

## Verified Baseline Facts (read before implementing)

- `migrations/20260709000000-calendar-core.sql:26` already declares `recurring_event_id TEXT REFERENCES events(id) ON DELETE CASCADE` — the DATABASE is correct; only `worker/db/schema.ts:42` omits the FK. No new migration is needed for Task 2.
- `worker/__tests__/test-db.ts` runs the real SQL migrations with `PRAGMA foreign_keys = ON`, so cascade behavior is honestly testable.
- All three apps (`eldrin-calendar`, `eldrin-crm`, `eldrin-email`) call `c.env.ASSETS.fetch(...)` in their `worker/index.ts` fallback route, and NONE of their `wrangler.jsonc` `assets` blocks declare `"binding": "ASSETS"` — confirmed missing in the built `dist/*/wrangler.json` of all three. In a real `wrangler deploy`, `env.ASSETS` is `undefined` and every non-API route 500s.
- `eldrin-email/worker/services/oauth-outlook.ts:100-131` (`refreshOutlookToken`) parses only `access_token`/`expires_in` from the Microsoft token response and DISCARDS the rotated `refresh_token`. `eldrin-email/worker/services/providers/index.ts` (`getAccessToken`) persists only the new access token. Microsoft rotates refresh tokens (live-verified in 4c: the account bricks in ~1h if the new token is not persisted). eldrin-calendar's `worker/services/accounts.ts:40-51` already handles this correctly and is the reference pattern.
- Graph webhook batches: `eldrin-calendar/worker/routes/sync.ts:178-201` loops `body.value` but (a) returns 403 immediately on the first bad `clientState`, skipping later valid items, and (b) schedules duplicate syncs when one batch repeats a `subscriptionId`.

---

### Task 1: Branch setup + sweep-race guard (eldrin-calendar)

The reconciliation sweep in `syncCalendar` deletes local rows whose `externalId` is missing from the provider's present-ids snapshot. That snapshot is taken during `provider.listChanges()`. An event created locally (and written through to Graph) while `listChanges` is running post-dates the snapshot, so the sweep wrongly deletes it (it self-heals next sync, but the local row id churns — bad for CRM references). Guard: skip rows touched after the change fetch began.

**Files:**
- Modify: `eldrin-calendar/worker/services/sync.ts:201-229`
- Test: `eldrin-calendar/worker/__tests__/sync-service.test.ts`

**Interfaces:**
- Consumes: existing `syncCalendar(db, env, provider, cal)` and `ChangeSet.presentExternalIds`.
- Produces: no signature changes. Introduces local variable `changesStartedAt` inside `syncCalendar` that Task 5 also uses — implement Task 1 before Task 5.

- [ ] **Step 1: Create the feature branch**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-calendar
git checkout main && git pull
git checkout -b feature/calendar-4d-hardening
```

- [ ] **Step 2: Write the failing test**

Append to the `describe('syncCalendar', ...)` block in `worker/__tests__/sync-service.test.ts` (it already has `db`, `calRow()`, `translatedEvent`, `T0`, `HOUR`, `WEEK`, and the `CalendarProvider` type imported):

```ts
  it('sweep skips rows touched after the change fetch began (write-through race)', async () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(T0);
      // Stale row: predates the sweep, absent remotely — MUST be swept.
      await db.insert(events).values({
        id: 'stale', calendarId: 'cal-g', title: 'Stale', description: null, location: null,
        startAt: T0, endAt: T0 + HOUR, allDay: false, timezone: 'UTC',
        recurrenceRule: null, recurringEventId: null, originalStartTime: null,
        status: 'confirmed', externalId: 'ext-stale', createdBy: 'u1',
        createdAt: T0 - WEEK, updatedAt: T0 - WEEK,
      });
      const provider = {
        // Simulates a concurrent local create + write-through DURING the
        // provider fetch: the row exists locally with an externalId, but the
        // provider's present-ids snapshot predates it.
        listChanges: vi.fn(async () => {
          vi.setSystemTime(T0 + 5000);
          await db.insert(events).values({
            id: 'racer', calendarId: 'cal-g', title: 'Just created', description: null, location: null,
            startAt: T0, endAt: T0 + HOUR, allDay: false, timezone: 'UTC',
            recurrenceRule: null, recurringEventId: null, originalStartTime: null,
            status: 'confirmed', externalId: 'ext-racer', createdBy: 'u1',
            createdAt: T0 + 5000, updatedAt: T0 + 5000,
          });
          return {
            events: [], nextSyncToken: 'tok-sweep', fullResyncRequired: false,
            presentExternalIds: [],
          };
        }),
      } as unknown as CalendarProvider;

      const result = await syncCalendar(db, env, provider, await calRow());
      expect(result.error).toBeNull();
      expect(result.removed).toBe(1); // stale swept, racer spared
      const remaining = await db.select().from(events);
      expect(remaining.map((r) => r.id)).toEqual(['racer']);
    } finally {
      vi.useRealTimers();
    }
  });
```

- [ ] **Step 3: Run the test to verify it fails**

```bash
npx vitest run worker/__tests__/sync-service.test.ts
```

Expected: the new test FAILS — `remaining` is `[]` because the racer row is swept too.

- [ ] **Step 4: Implement the guard in `worker/services/sync.ts`**

In `syncCalendar`, capture the fetch start time and use it in the sweep. Change the top of the `try` block:

```ts
  try {
    const changesStartedAt = now();
    let changes = await provider.listChanges(cal.externalId!, cal.syncToken ?? null);
```

And change the sweep loop (currently `sync.ts:223-228`) to:

```ts
      for (const row of locals) {
        if (present.has(row.externalId!)) continue;
        // Race guard (4d): a row created/updated after the change fetch began
        // post-dates the provider's present-ids snapshot — a concurrent local
        // create + write-through would be wrongly deleted. Defer it; a truly
        // deleted event's tombstone arrives in the next delta and re-triggers
        // the sweep.
        if (row.updatedAt >= changesStartedAt) continue;
        await db.delete(events).where(eq(events.id, row.id));
        swept++;
        fireAndForget(emitCalendarEventDeleted(env, row.id, 'all'));
      }
```

- [ ] **Step 5: Run the full suite**

```bash
npx vitest run
```

Expected: all tests pass (279 total: 278 baseline + 1 new).

- [ ] **Step 6: Commit**

```bash
git add worker/services/sync.ts worker/__tests__/sync-service.test.ts
git commit -m "fix(sync): guard reconciliation sweep against concurrent-create race"
```

---

### Task 2: Drizzle schema honesty — recurringEventId self-FK (eldrin-calendar)

The SQL migration already declares the FK cascade; only `schema.ts` lies about it. The sync core's comment ("exception rows die via FK cascade") depends on this. Make the drizzle schema declare what the database enforces, and pin the cascade with a test.

**Files:**
- Modify: `eldrin-calendar/worker/db/schema.ts:1,42`
- Test: `eldrin-calendar/worker/__tests__/schema.test.ts`

**Interfaces:**
- Consumes: nothing new.
- Produces: no type changes (`EventRow` shape is unchanged — `.references()` affects only DDL metadata). NO new migration: the database already has this FK.

- [ ] **Step 1: Write the cascade test**

Append to `worker/__tests__/schema.test.ts` (check its existing imports; it uses `createTestDb`. Add `events` to the drizzle imports and `eq` from `drizzle-orm` if not present):

```ts
  it('deleting a recurring master cascades to its exception rows', async () => {
    const db = createTestDb();
    await db.insert(calendars).values({
      id: 'c1', name: 'Cal', color: '#111111', ownerId: 'u1', isDefault: false,
      createdAt: 1, updatedAt: 1,
    });
    const base = {
      calendarId: 'c1', description: null, location: null,
      startAt: 1000, endAt: 2000, allDay: false, timezone: 'UTC',
      originalStartTime: null, status: 'confirmed', externalId: null,
      createdBy: 'u1', createdAt: 1, updatedAt: 1,
    };
    await db.insert(events).values({
      ...base, id: 'master', title: 'Master',
      recurrenceRule: 'FREQ=DAILY', recurringEventId: null,
    });
    await db.insert(events).values({
      ...base, id: 'exception', title: 'Moved instance',
      recurrenceRule: null, recurringEventId: 'master', originalStartTime: 1000,
    });

    await db.delete(events).where(eq(events.id, 'master'));

    const remaining = await db.select().from(events);
    expect(remaining).toHaveLength(0); // exception cascaded away with its master
  });
```

- [ ] **Step 2: Run it — expect PASS (the SQL migration already enforces the FK)**

```bash
npx vitest run worker/__tests__/schema.test.ts
```

Expected: PASS. This test pins the migration behavior; the schema.ts change below is compile-time honesty.

- [ ] **Step 3: Declare the self-FK in `worker/db/schema.ts`**

Drizzle self-references need an explicit return-type annotation. Change the import line (line 1) to:

```ts
import { sqliteTable, text, integer, index, uniqueIndex, type AnySQLiteColumn } from 'drizzle-orm/sqlite-core';
```

Change line 42 from `recurringEventId: text('recurring_event_id'),` to:

```ts
    recurringEventId: text('recurring_event_id')
      .references((): AnySQLiteColumn => events.id, { onDelete: 'cascade' }),
```

- [ ] **Step 4: Typecheck + full suite**

```bash
npx tsc -b && npx vitest run
```

Expected: clean typecheck, all tests pass (280).

- [ ] **Step 5: Commit**

```bash
git add worker/db/schema.ts worker/__tests__/schema.test.ts
git commit -m "fix(db): declare recurring_event_id self-FK in drizzle schema (matches migration DDL)"
```

---

### Task 3: Graph notify batch hardening + tests (eldrin-calendar)

One Graph webhook POST can carry several notifications. The current handler (`worker/routes/sync.ts:178-201`) aborts the whole batch with 403 on the first bad `clientState` (skipping later valid items) and schedules duplicate syncs when a batch repeats a `subscriptionId`. Harden: validate each item independently, dedupe subscription ids, schedule valid syncs, and still return 403 if any forged item was seen.

**Files:**
- Modify: `eldrin-calendar/worker/routes/sync.ts:178-201`
- Test: `eldrin-calendar/worker/__tests__/graph-notify.test.ts`

**Interfaces:**
- Consumes: `channelTokenFor(calendarId, secret)` from `../services/sync`, `syncCalendar`, `providerForCalendar` (all already imported in the route file).
- Produces: unchanged route contract: 200 handshake echo, 202 accepted, 403 when any item carried a forged clientState (valid items in the same batch are still processed).

- [ ] **Step 1: Write the failing tests**

Append inside `describe('POST /api/sync/notify/graph', ...)` in `worker/__tests__/graph-notify.test.ts`. A second calendar is needed; insert it per-test:

```ts
  const secondCalendar = {
    id: 'cal-ms2', name: 'MS 2', color: '#556677', ownerId: 'u1', isDefault: false,
    provider: 'microsoft', externalId: 'mscal-ext-2', accountId: 'acc-ms',
    watchChannelId: 'sub-2', watchResourceId: 'graph-subscription', createdAt: 1, updatedAt: 1,
  };

  it('processes every item in a multi-notification batch (one sync per calendar)', async () => {
    await db.insert(calendars).values(secondCalendar);
    const t1 = await channelTokenFor('cal-ms', 'test-secret');
    const t2 = await channelTokenFor('cal-ms2', 'test-secret');
    const res = await app.request('/api/sync/notify/graph', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ value: [
        { subscriptionId: 'sub-1', clientState: t1, changeType: 'updated' },
        { subscriptionId: 'sub-2', clientState: t2, changeType: 'created' },
      ] }),
    }, mockEnv, mockExecutionCtx);
    expect(res.status).toBe(202);
    expect(waited.length).toBe(2);
  });

  it('dedupes repeated subscriptionIds within one batch', async () => {
    const t1 = await channelTokenFor('cal-ms', 'test-secret');
    const res = await app.request('/api/sync/notify/graph', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ value: [
        { subscriptionId: 'sub-1', clientState: t1, changeType: 'updated' },
        { subscriptionId: 'sub-1', clientState: t1, changeType: 'updated' },
      ] }),
    }, mockEnv, mockExecutionCtx);
    expect(res.status).toBe(202);
    expect(waited.length).toBe(1);
  });

  it('a forged item does not block valid items in the same batch', async () => {
    await db.insert(calendars).values(secondCalendar);
    const t1 = await channelTokenFor('cal-ms', 'test-secret');
    const res = await app.request('/api/sync/notify/graph', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ value: [
        { subscriptionId: 'sub-1', clientState: t1, changeType: 'updated' },
        { subscriptionId: 'sub-2', clientState: 'forged', changeType: 'updated' },
      ] }),
    }, mockEnv, mockExecutionCtx);
    expect(res.status).toBe(403); // forged item still reported
    expect(waited.length).toBe(1); // but the valid item's sync was scheduled
  });
```

- [ ] **Step 2: Run to verify failures**

```bash
npx vitest run worker/__tests__/graph-notify.test.ts
```

Expected: multi-batch test PASSES already (loop exists); dedupe test FAILS (`waited.length` is 2); forged-item test FAILS (`waited.length` is 0). Confirm exactly this pattern before proceeding.

- [ ] **Step 3: Rewrite the handler body in `worker/routes/sync.ts`**

Replace the `for` loop and return of the `/api/sync/notify/graph` handler (keep the handshake and JSON-parse guards above it unchanged):

```ts
  // One Graph POST can batch several notifications, including repeats of the
  // same subscription. Validate each item independently — dedupe so one busy
  // calendar doesn't fan out duplicate syncs, and never let one forged item
  // block the valid ones (Graph would retry the whole batch).
  const seen = new Set<string>();
  let sawInvalidState = false;
  for (const n of body.value ?? []) {
    if (!n.subscriptionId || seen.has(n.subscriptionId)) continue;
    seen.add(n.subscriptionId);
    const [cal] = await db.select().from(calendars).where(eq(calendars.watchChannelId, n.subscriptionId));
    if (!cal) continue; // stale subscription for a removed calendar
    const expected = await channelTokenFor(cal.id, c.env.JWT_SECRET);
    if (n.clientState !== expected) {
      sawInvalidState = true;
      continue;
    }
    c.executionCtx.waitUntil((async () => {
      await syncCalendar(db, c.env, await providerForCalendar(db, c.env, cal), cal);
    })());
  }
  if (sawInvalidState) return c.json({ error: 'Invalid clientState' }, 403);
  return c.json({ ok: true }, 202);
```

- [ ] **Step 4: Run the full suite**

```bash
npx vitest run
```

Expected: all pass (283). The pre-existing `403s a clientState mismatch` test still passes (single forged item → 0 syncs, 403).

- [ ] **Step 5: Commit**

```bash
git add worker/routes/sync.ts worker/__tests__/graph-notify.test.ts
git commit -m "fix(sync): validate Graph notification batches per-item and dedupe subscriptions"
```

---

### Task 4: Delta-window proactive re-anchor (eldrin-calendar)

Graph's `calendarView` delta window is fixed at anchor time (−6mo/+18mo, `outlook.ts:23-24`). A long-lived deployment's forward horizon erodes; today we only recover when Graph rejects the token (`SyncStateNotFound` → destructive full resync that churns local ids). Instead: track when the window was anchored and, past 90 days, drain the old token normally then take one fresh null-token scan — idempotent upserts preserve local ids, and no rows are deleted (deletions were already handled by the drain). Google tokens are not windowed; Microsoft only.

**Files:**
- Create: `eldrin-calendar/migrations/20260710090000-sync-anchor.sql`
- Modify: `eldrin-calendar/worker/db/schema.ts:14` (calendars table), `eldrin-calendar/worker/services/sync.ts` (syncCalendar)
- Test: `eldrin-calendar/worker/__tests__/sync-service.test.ts`

**Interfaces:**
- Consumes: `changesStartedAt` variable introduced in Task 1; `CalendarRow` gains nullable `syncAnchoredAt: number | null`.
- Produces: `calendars.sync_anchored_at INTEGER` column; constants `REANCHOR_AFTER_MS` (90 days) and `REANCHOR_PROVIDERS` (`{'microsoft'}`) in `sync.ts`. `syncCalendar` signature unchanged.

- [ ] **Step 1: Create the migration**

Create `migrations/20260710090000-sync-anchor.sql` (14-digit name — mandatory):

```sql
-- 4d: when the provider sync token's delta window was anchored. Graph's
-- calendarView window is fixed at anchor time (-6mo/+18mo); calendars
-- re-anchor proactively after 90 days instead of waiting for SyncStateNotFound.
ALTER TABLE calendars ADD COLUMN sync_anchored_at INTEGER;
```

- [ ] **Step 2: Add the column to `worker/db/schema.ts`**

In the `calendars` table, directly after `syncToken`:

```ts
    syncAnchoredAt: integer('sync_anchored_at', { mode: 'number' }),
```

- [ ] **Step 3: Write the failing tests**

Append to `describe('syncCalendar', ...)` in `worker/__tests__/sync-service.test.ts`:

```ts
  describe('delta-window re-anchor (4d)', () => {
    const DAY = 24 * HOUR;
    const MS_CAL = {
      id: 'cal-ms', name: 'Outlook', color: '#334455', ownerId: 'u1', isDefault: false,
      provider: 'microsoft', externalId: 'ms-ext', accountId: 'acc2',
    };
    async function msRow() {
      const [row] = await db.select().from(calendars).where(eq(calendars.id, 'cal-ms'));
      return row;
    }

    it('re-anchors a Microsoft calendar whose window anchor is stale', async () => {
      vi.useFakeTimers();
      try {
        vi.setSystemTime(T0);
        await db.insert(calendars).values({
          ...MS_CAL, syncToken: 'delta-old', syncAnchoredAt: T0 - 91 * DAY,
          createdAt: 1, updatedAt: 1,
        });
        const { provider, calls } = fakeProvider([
          // Drain of the old token.
          { events: [translatedEvent({ externalId: 'e1', title: 'A' })], nextSyncToken: 'delta-drained', fullResyncRequired: false },
          // Fresh anchor scan (null token) — overlaps e1, adds e2.
          { events: [translatedEvent({ externalId: 'e1', title: 'A' }), translatedEvent({ externalId: 'e2', title: 'B' })], nextSyncToken: 'delta-fresh', fullResyncRequired: false },
        ]);
        const result = await syncCalendar(db, env, provider, await msRow());
        expect(result.error).toBeNull();
        expect(calls).toEqual(['delta-old', null]);
        const rows = await db.select().from(events);
        expect(rows).toHaveLength(2); // idempotent overlap, no duplicates
        const cal = await msRow();
        expect(cal.syncToken).toBe('delta-fresh');
        expect(cal.syncAnchoredAt).toBe(T0);
      } finally {
        vi.useRealTimers();
      }
    });

    it('does not re-anchor a fresh Microsoft window', async () => {
      vi.useFakeTimers();
      try {
        vi.setSystemTime(T0);
        await db.insert(calendars).values({
          ...MS_CAL, syncToken: 'delta-old', syncAnchoredAt: T0 - DAY,
          createdAt: 1, updatedAt: 1,
        });
        const { provider, calls } = fakeProvider([
          { events: [], nextSyncToken: 'delta-next', fullResyncRequired: false },
        ]);
        await syncCalendar(db, env, provider, await msRow());
        expect(calls).toEqual(['delta-old']);
        expect((await msRow()).syncAnchoredAt).toBe(T0 - DAY); // untouched
      } finally {
        vi.useRealTimers();
      }
    });

    it('never re-anchors Google calendars (tokens are not windowed)', async () => {
      // cal-g from the outer beforeEach; give it an ancient anchor + a token.
      await db.update(calendars)
        .set({ syncToken: 'g-tok', syncAnchoredAt: 1 })
        .where(eq(calendars.id, 'cal-g'));
      const { provider, calls } = fakeProvider([
        { events: [], nextSyncToken: 'g-tok-2', fullResyncRequired: false },
      ]);
      await syncCalendar(db, env, provider, await calRow());
      expect(calls).toEqual(['g-tok']);
    });

    it('stamps syncAnchoredAt on the initial (null-token) sync', async () => {
      const { provider } = fakeProvider([
        { events: [], nextSyncToken: 't1', fullResyncRequired: false },
      ]);
      await syncCalendar(db, env, provider, await calRow());
      expect((await calRow()).syncAnchoredAt).toBeGreaterThan(0);
    });
  });
```

- [ ] **Step 4: Run to verify failures**

```bash
npx vitest run worker/__tests__/sync-service.test.ts
```

Expected: the two re-anchor/stamp tests FAIL (`calls` has one element / `syncAnchoredAt` is null); the two negative tests may already pass — confirm which, then proceed.

- [ ] **Step 5: Implement in `worker/services/sync.ts`**

Add constants near `SYNC_ERROR_MAX_LEN`:

```ts
const DAY_MS = 86400000;
/**
 * Graph's calendarView delta window is FIXED at anchor time (-6mo/+18mo,
 * outlook.ts). Re-anchor after 90 days so the forward horizon never erodes
 * below ~15 months. Google sync tokens are not windowed — never re-anchored.
 */
const REANCHOR_AFTER_MS = 90 * DAY_MS;
const REANCHOR_PROVIDERS: ReadonlySet<string> = new Set(['microsoft']);
```

Rework the `try` block of `syncCalendar` (this builds on Task 1's `changesStartedAt`):

```ts
  try {
    const changesStartedAt = now();
    let anchoredAt = cal.syncAnchoredAt ?? null;
    if (!cal.syncToken) anchoredAt = changesStartedAt; // initial sync IS an anchor
    let changes = await provider.listChanges(cal.externalId!, cal.syncToken ?? null);
    if (changes.fullResyncRequired) {
      await db.delete(events).where(eq(events.calendarId, cal.id));
      anchoredAt = now();
      changes = await provider.listChanges(cal.externalId!, null);
    }
    let { applied, removed } = await applyChanges(db, env, cal, changes.events);

    // ... existing sweep block with Task 1's race guard, unchanged ...

    let nextSyncToken = changes.nextSyncToken ?? cal.syncToken;

    // Proactive re-anchor (4d): the incremental drain above brought us fully
    // up to date, so a fresh null-token scan can adopt a new window without
    // deleting anything — upserts are idempotent by externalId, local ids
    // are preserved (unlike the destructive fullResyncRequired path).
    if (
      REANCHOR_PROVIDERS.has(cal.provider) && cal.syncToken &&
      (anchoredAt === null || now() - anchoredAt > REANCHOR_AFTER_MS)
    ) {
      const anchor = await provider.listChanges(cal.externalId!, null);
      if (!anchor.fullResyncRequired) {
        const extra = await applyChanges(db, env, cal, anchor.events);
        applied += extra.applied;
        removed += extra.removed;
        if (anchor.nextSyncToken) {
          nextSyncToken = anchor.nextSyncToken;
          anchoredAt = now();
        }
      }
    }

    await db.update(calendars).set({
      syncToken: nextSyncToken,
      syncAnchoredAt: anchoredAt,
      lastSyncedAt: now(),
      syncStatus: 'ok',
      syncError: null,
      updatedAt: now(),
    }).where(eq(calendars.id, cal.id));
    return { calendarId: cal.id, applied, removed: removed + swept, error: null };
```

Note: `applied`/`removed` change from `const` destructuring to `let` — keep the `swept` accounting exactly as it is today.

- [ ] **Step 6: Run the full suite + typecheck**

```bash
npx tsc -b && npx vitest run
```

Expected: all pass (287).

- [ ] **Step 7: Commit**

```bash
git add migrations/20260710090000-sync-anchor.sql worker/db/schema.ts worker/services/sync.ts worker/__tests__/sync-service.test.ts
git commit -m "feat(sync): proactively re-anchor Graph delta windows after 90 days"
```

---

### Task 5: ASSETS binding in deploy config (eldrin-calendar, eldrin-crm, eldrin-email)

All three workers serve their SPA via `c.env.ASSETS.fetch(...)`, but no `wrangler.jsonc` declares `"binding": "ASSETS"` — in a real `wrangler deploy` the binding doesn't exist and every non-API route crashes (this forced hand-patching `dist/*/wrangler.json` during 4c live cron testing). One line per app.

**Files:**
- Modify: `eldrin-calendar/wrangler.jsonc:7`, `eldrin-crm/wrangler.jsonc` (assets block), `eldrin-email/wrangler.jsonc` (assets block)

**Interfaces:**
- Consumes: nothing.
- Produces: `env.ASSETS` defined in deployed workers. Dev behavior unchanged (the vite plugin already provides assets in dev).

- [ ] **Step 1: Edit all three `wrangler.jsonc` assets blocks**

In each of the three repos, change:

```jsonc
  "assets": { "directory": "./dist", "not_found_handling": "single-page-application" },
```

to:

```jsonc
  "assets": { "directory": "./dist", "binding": "ASSETS", "not_found_handling": "single-page-application" },
```

(eldrin-crm and eldrin-email format the block across multiple lines — add the `"binding": "ASSETS",` line inside it; do not reformat.)

- [ ] **Step 2: Verify the built deploy config carries the binding (calendar)**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-calendar
npm run build
node -e "const c=require('./dist/eldrin_calendar/wrangler.json'); if(c.assets.binding!=='ASSETS'){console.error('MISSING BINDING');process.exit(1)}; console.log('assets.binding OK')"
npx wrangler deploy --dry-run -c dist/eldrin_calendar/wrangler.json
```

Expected: `assets.binding OK` and a successful dry-run ending in `--dry-run: exiting now.` with `env.ASSETS (assets)` listed under bindings.

- [ ] **Step 3: Repeat the build + node check for crm and email**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-crm && npm run build && node -e "const c=require('./dist/eldrin_crm/wrangler.json'); if(c.assets.binding!=='ASSETS')process.exit(1); console.log('crm OK')"
cd /Users/tibor/projects/eldrin-backup/eldrin-email && npm run build && node -e "const c=require('./dist/eldrin_email/wrangler.json'); if(c.assets.binding!=='ASSETS')process.exit(1); console.log('email OK')"
```

Expected: `crm OK`, `email OK`.

- [ ] **Step 4: Commit in each submodule**

eldrin-calendar (on the existing `feature/calendar-4d-hardening` branch):

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-calendar
git add wrangler.jsonc
git commit -m "fix(deploy): declare ASSETS binding so deployed worker can serve the SPA"
```

eldrin-crm — create a small fix branch from main in the submodule:

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-crm
git checkout main && git pull && git checkout -b fix/assets-binding
git add wrangler.jsonc
git commit -m "fix(deploy): declare ASSETS binding so deployed worker can serve the SPA"
```

eldrin-email is PARENT-TRACKED — commit in the parent repo (cwd = parent root, not eldrin-email):

```bash
cd /Users/tibor/projects/eldrin-backup
git add eldrin-email/wrangler.jsonc
git commit -m "fix(email): declare ASSETS binding so deployed worker can serve the SPA"
```

---

### Task 6: Persist rotated Microsoft refresh tokens (eldrin-email)

Confirmed defect: `refreshOutlookToken` discards the `refresh_token` Microsoft returns on rotation, and `getAccessToken` persists only the new access token. Per the live-verified 4c lesson, the old refresh token dies after rotation and the mailbox bricks (~1h). Mirror eldrin-calendar's fix (`eldrin-calendar/worker/services/accounts.ts:40-51`).

**Files:**
- Modify: `eldrin-email/worker/services/oauth-outlook.ts:100-131`, `eldrin-email/worker/services/providers/types.ts` (EmailProvider.refreshAccessToken return type), `eldrin-email/worker/services/providers/outlook.ts` (refreshAccessToken passthrough type), `eldrin-email/worker/services/providers/index.ts` (getAccessToken persistence)
- Test: create `eldrin-email/worker/__tests__/token-rotation.test.ts`

**Interfaces:**
- Consumes: existing `encryptToken/decryptToken(value, secret)` from `../crypto`; `connectedMailboxes` schema fields `accessTokenEncrypted`, `refreshTokenEncrypted`, `tokenExpiresAt`.
- Produces: `refreshOutlookToken` and `EmailProvider.refreshAccessToken` now return `{ accessToken: string; expiresIn: number; newRefreshToken?: string }`. GmailProvider is unaffected (field optional; Google does not rotate).

- [ ] **Step 1: Write the failing tests**

Create `worker/__tests__/token-rotation.test.ts`:

```ts
import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockDecryptToken = vi.fn();
const mockEncryptToken = vi.fn();
vi.mock('../services/crypto', () => ({
  decryptToken: (...args: unknown[]) => mockDecryptToken(...args),
  encryptToken: (...args: unknown[]) => mockEncryptToken(...args),
}));

import { getAccessToken } from '../services/providers/index';
import { refreshOutlookToken } from '../services/oauth-outlook';
import type { Database } from '../db';
import type { EmailProvider } from '../services/providers/types';

function mailboxRow(overrides: Record<string, unknown> = {}) {
  return {
    id: 'mb1', provider: 'outlook',
    accessTokenEncrypted: 'enc:old-at', refreshTokenEncrypted: 'enc:old-rt',
    tokenExpiresAt: 0, // expired — forces a refresh
    ...overrides,
  } as never;
}

describe('rotated Microsoft refresh token persistence', () => {
  const updates: Record<string, unknown>[] = [];
  const db = {
    update: () => ({
      set: (vals: Record<string, unknown>) => ({
        where: async () => { updates.push(vals); },
      }),
    }),
  } as unknown as Database;
  const env = {
    JWT_SECRET: 's', MICROSOFT_CLIENT_ID: 'cid', MICROSOFT_CLIENT_SECRET: 'cs',
    GOOGLE_CLIENT_ID: 'g', GOOGLE_CLIENT_SECRET: 'gs',
  } as Env;

  beforeEach(() => {
    updates.length = 0;
    vi.clearAllMocks();
    mockDecryptToken.mockImplementation(async (v: string) => v.replace(/^enc:/, ''));
    mockEncryptToken.mockImplementation(async (v: string) => `enc:${v}`);
  });

  it('persists the rotated refresh token when the provider returns one', async () => {
    const provider = {
      refreshAccessToken: vi.fn(async () => ({
        accessToken: 'new-at', expiresIn: 3600, newRefreshToken: 'new-rt',
      })),
    } as unknown as EmailProvider;
    const token = await getAccessToken(db, mailboxRow(), env, provider);
    expect(token).toBe('new-at');
    expect(updates).toHaveLength(1);
    expect(updates[0].accessTokenEncrypted).toBe('enc:new-at');
    expect(updates[0].refreshTokenEncrypted).toBe('enc:new-rt');
  });

  it('leaves the stored refresh token alone when none is returned (Gmail path)', async () => {
    const provider = {
      refreshAccessToken: vi.fn(async () => ({ accessToken: 'new-at', expiresIn: 3600 })),
    } as unknown as EmailProvider;
    await getAccessToken(db, mailboxRow({ provider: 'gmail', GOOGLE: true }), env, provider);
    expect(updates).toHaveLength(1);
    expect(updates[0].refreshTokenEncrypted).toBeUndefined();
  });
});

describe('refreshOutlookToken response parsing', () => {
  it('surfaces the rotated refresh_token from the Microsoft response', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      access_token: 'at2', expires_in: 3600, refresh_token: 'rt2',
    }), { status: 200 })));
    try {
      const out = await refreshOutlookToken('rt1', 'cid', 'cs');
      expect(out.accessToken).toBe('at2');
      expect(out.newRefreshToken).toBe('rt2');
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
```

- [ ] **Step 2: Run to verify failures**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-email
npx vitest run worker/__tests__/token-rotation.test.ts
```

Expected: FAIL — `newRefreshToken` is undefined (not parsed) and `updates[0].refreshTokenEncrypted` is undefined in the rotation test.

- [ ] **Step 3: Implement**

`worker/services/oauth-outlook.ts` — change `refreshOutlookToken`'s return type and body:

```ts
export async function refreshOutlookToken(
  refreshToken: string,
  clientId: string,
  clientSecret: string,
): Promise<{ accessToken: string; expiresIn: number; newRefreshToken?: string }> {
  // ... fetch unchanged ...

  const data = await res.json() as {
    access_token: string;
    expires_in: number;
    refresh_token?: string; // Microsoft ROTATES refresh tokens (AAD v2)
  };

  return {
    accessToken: data.access_token,
    expiresIn: data.expires_in,
    ...(data.refresh_token ? { newRefreshToken: data.refresh_token } : {}),
  };
}
```

`worker/services/providers/types.ts` — update the `EmailProvider.refreshAccessToken` return type to `Promise<{ accessToken: string; expiresIn: number; newRefreshToken?: string }>`.

`worker/services/providers/outlook.ts` — update `OutlookProvider.refreshAccessToken`'s declared return type to match (the body already just returns `refreshOutlookToken(...)`).

`worker/services/providers/index.ts` — in `getAccessToken`, extend the persistence update:

```ts
  const newEncrypted = await encryptToken(refreshed.accessToken, env.JWT_SECRET);
  const timestamp = now();

  await db.update(connectedMailboxes)
    .set({
      accessTokenEncrypted: newEncrypted,
      // Microsoft rotates refresh tokens — persist the replacement or the
      // mailbox bricks on the next refresh (live-verified in calendar 4c).
      ...(refreshed.newRefreshToken
        ? { refreshTokenEncrypted: await encryptToken(refreshed.newRefreshToken, env.JWT_SECRET) }
        : {}),
      tokenExpiresAt: timestamp + refreshed.expiresIn * 1000,
      updatedAt: timestamp,
    })
    .where(eq(connectedMailboxes.id, mailbox.id));

  return refreshed.accessToken;
```

- [ ] **Step 4: Typecheck + full email suite**

```bash
npx tsc -b 2>/dev/null || npm run typecheck; npx vitest run
```

Expected: clean typecheck (use whichever typecheck script `package.json` defines), all email tests pass including the 3 new ones.

- [ ] **Step 5: Commit (in the PARENT repo — eldrin-email is parent-tracked)**

```bash
cd /Users/tibor/projects/eldrin-backup
git add eldrin-email/worker/services/oauth-outlook.ts eldrin-email/worker/services/providers/types.ts eldrin-email/worker/services/providers/outlook.ts eldrin-email/worker/services/providers/index.ts eldrin-email/worker/__tests__/token-rotation.test.ts
git commit -m "fix(email): persist rotated Microsoft refresh tokens (prevents mailbox bricking)"
```

---

### Task 7: OAuth co-tenancy validation runbook (parent repo docs)

eldrin-email and eldrin-calendar share the same Google Cloud Console client AND the same Entra app registration (separate redirect URIs/scopes were added per app). Document the tenancy rules and a live checklist proving that the same provider account linked in BOTH apps keeps working — especially across Microsoft refresh-token rotation now that both apps persist rotations.

**Files:**
- Create: `docs/superpowers/specs/2026-07-10-oauth-co-tenancy-validation.md` (parent repo)

**Interfaces:**
- Consumes: Task 6 must be implemented and its dev server restarted before the live run.
- Produces: a runbook with recorded results; the live half REQUIRES the user's own browser session (Google blocks OAuth consent in automated Chrome — 4c lesson).

- [ ] **Step 1: Write the runbook**

Create the file with this content:

```markdown
# OAuth Co-Tenancy Validation — eldrin-email × eldrin-calendar

**Why:** Both apps share one Google Cloud Console client and one Entra app
registration (distinct redirect URIs and scopes per app). Each app stores its
own token grant, so refresh activity in one must never invalidate the other.
Risk focus: Microsoft rotates refresh tokens on every refresh.

## Tenancy rules (documented facts)

- Shared Google client: eldrin-email (gmail scopes) + eldrin-calendar
  (calendar scopes, redirect `http://localhost:4012/api/oauth/google/callback`).
- Shared Entra app: eldrin-email (Mail scopes) + eldrin-calendar
  (Calendars.ReadWrite, redirect `http://localhost:4012/api/oauth/microsoft/callback`).
- Token grants are per-app-per-flow: each app runs its own consent and stores
  its own refresh token. Rotating one grant's refresh token MUST NOT
  invalidate the other grant (same client id, separate token chains).
- Both apps persist rotated MS refresh tokens (calendar since 4c;
  email since fix/email-4d-hardening).

## Live checklist (user-driven browser; do NOT automate the consents)

- [ ] 1. Task 6 merged; email + calendar dev servers restarted.
- [ ] 2. Link the SAME Microsoft account in eldrin-email (mailbox) AND
        eldrin-calendar (connected account).
- [ ] 3. Force refresh in calendar: `POST /api/sync/run` (or Sync now in
        Settings). Confirm account stays `active`.
- [ ] 4. Force refresh in email: trigger a mailbox sync. Confirm mailbox
        syncStatus is not `error`.
- [ ] 5. Wait ≥65 minutes (past access-token expiry, at least one rotation
        in each app), then repeat steps 3–4. BOTH must still succeed.
- [ ] 6. Same-account Google sanity pass: steps 2–5 with one Google account
        in both apps (no rotation expected; both must stay `active`).

## Results

| Date | Provider | Result | Notes |
|------|----------|--------|-------|
|      |          |        |       |
```

- [ ] **Step 2: Commit (parent repo — ensure cwd is the parent, NOT a submodule)**

```bash
cd /Users/tibor/projects/eldrin-backup
git add docs/superpowers/specs/2026-07-10-oauth-co-tenancy-validation.md
git commit -m "docs(oauth): co-tenancy validation runbook for shared Google/Entra clients"
```

- [ ] **Step 3: Schedule the live run with the user**

The checklist's live half needs the user's browser for OAuth consents and a >65-minute soak. Surface it at review time; do not block the rest of the plan on it.

---

### Task 8: Merge, push, and parent gitlink bump

- [ ] **Step 1: Final verification in each submodule**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-calendar && npx tsc -b && npx vitest run
cd /Users/tibor/projects/eldrin-backup/eldrin-email && npx vitest run
cd /Users/tibor/projects/eldrin-backup/eldrin-crm && npx vitest run
```

Expected: all green (calendar 287; email/crm suites fully passing).

- [ ] **Step 2: Merge each submodule feature branch to main and push (after user review; eldrin-email needs no merge — its changes are parent commits)**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-calendar
git checkout main && git merge --no-ff feature/calendar-4d-hardening && git push

cd /Users/tibor/projects/eldrin-backup/eldrin-crm
git checkout main && git merge --no-ff fix/assets-binding && git push
```

- [ ] **Step 3: Bump parent gitlinks (single parent commit, cwd = parent repo)**

```bash
cd /Users/tibor/projects/eldrin-backup
git add eldrin-calendar eldrin-crm
git commit -m "chore: bump eldrin-calendar and eldrin-crm submodules — 4d hardening (sweep race, re-anchor, batch notify, ASSETS binding)"
git push
```

- [ ] **Step 4: Live smoke check**

Restart the calendar dev server (`npm run dev`, port 4012) and the email dev server, open the shell at `http://localhost:4000`, and confirm: Calendar renders and `Sync now` succeeds against the linked accounts; Email inbox loads. Then hand the co-tenancy runbook (Task 7) to the user for the soak test.

---

## Self-Review Notes

- Item 1 (sweep race) → Task 1. Item 2 (schema honesty) → Task 2. Item 3 (ASSETS) → Task 5 (all three apps). Item 4 (batch test) → Task 3 (tests + real handler fixes the tests exposed). Item 5 (re-anchor) → Task 4. Item 6 (co-tenancy) → Tasks 6 + 7 (concrete defect fix + runbook). CalDAV: explicitly deferred.
- Task 4 builds on Task 1's `changesStartedAt` — keep the order.
- Test-count expectations (279/280/283/287) assume the plan's exact test additions; if a suite count differs, verify no test was skipped rather than adjusting blindly.
