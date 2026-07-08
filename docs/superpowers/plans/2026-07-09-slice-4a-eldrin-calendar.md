# Slice 4a — eldrin-calendar Standalone App Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the standalone `eldrin-calendar` marketplace app (local calendars + events with full recurrence, FullCalendar UI, `calendar.event.*` platform events) and make eldrin-crm its first consumer (Meeting-activity mirror + Upcoming Meetings dashboard widget).

**Architecture:** New full-stack Eldrin extension app (React 19 single-spa frontend + Hono/Drizzle/D1 worker) storing recurrence Google-style (master rows with RRULE + exception rows) and expanding occurrences **server-side** so every consumer reads concrete occurrences from one endpoint. CRM consumes via the platform event bus (mirror) and via the core cross-app proxy with the service secret (widget).

**Tech Stack:** React 19, Vite 6, single-spa 6, Tailwind 4 + daisyUI 5, `@fullcalendar/react` 6 (MIT plugins only), `rrule` 2.7, Hono 4, Drizzle ORM, Cloudflare Workers + D1, Vitest + better-sqlite3.

**Spec:** `docs/superpowers/specs/2026-07-09-eldrin-calendar-design.md` (decisions D1–D10). This plan implements Slice 4a only — NO provider sync, NO OAuth, NO cron.

## Global Constraints

- **FullCalendar MIT plugins ONLY**: `@fullcalendar/react`, `@fullcalendar/core`, `@fullcalendar/daygrid`, `@fullcalendar/timegrid`, `@fullcalendar/list`, `@fullcalendar/interaction`, all `^6.1.21`. NEVER add premium packages (anything named timeline/resource/scheduler/premium-common). No `@fullcalendar/rrule` either — expansion is server-side (spec D7).
- **Recurrence lib**: `rrule@^2.7.1`. Timezone conversion via `Intl.DateTimeFormat` helpers (Task 4) — do NOT add date-fns-tz/luxon/moment.
- **App identity**: manifest `id: "eldrin-calendar"`, entry `/eldrin-calendar.js`, styles `/eldrin-calendar.css`, dev port **4012** (4009=crm, 4010=email, 4011=factorial are taken), developer_id `eldrin.io`.
- **Env vars**: core URL from `env.ELDRIN_CORE_URL` with fallback `'http://localhost:4000'`; service secret IS `env.JWT_SECRET`, sent/checked via the `X-Eldrin-App-Secret` header. `.dev.vars` `JWT_SECRET` must be byte-identical to `eldrin-core`'s — copy the value from `eldrin-crm/.dev.vars`. NEVER commit `.dev.vars` (gitignored) and never paste the secret into committed files.
- **Cross-app proxy URL shape**: `{CORE_URL}/api/app/{appId}{path}` — e.g. CRM reaches the calendar at `http://localhost:4000/api/app/eldrin-calendar/events?...`. A valid `X-Eldrin-App-Secret` bypasses per-route permission checks in core.
- **Validation caps (exact)**: title ≤200 chars, description ≤2000, location ≤500, calendar name ≤100, `endAt > startAt`, expansion range ≤ 400 days, ≤ 1000 occurrences per response, attendee email RFC-basic + lowercased.
- **Instance id format**: expanded recurring occurrences get `id = `\`${masterId}_${basicIso}\`` where basicIso is the occurrence's ORIGINAL start in UTC basic ISO, e.g. `20260708T090000Z` (no hyphens/colons). Singles/masters keep their row uuid.
- **Event payloads (exact, spec §7)**: `calendar.event.created` `{eventId, calendarId, title, startAt, endAt, allDay, timezone, location, recurrenceRule, attendees: [{email, name}]}`; `calendar.event.updated` same + `scope`; `calendar.event.deleted` `{eventId, scope}`. A `following` split emits `updated` (old master) + `created` (new master). `single`-scope edits emit `updated` with the MASTER's eventId.
- **Migrations**: filenames MUST start with a 14-digit timestamp (`20260709000000-...`); `worker/migrations.generated.ts` is gitignored — regenerate with `npm run generate:migrations`, never commit it.
- **Theming**: daisyUI themes are `data-theme="eldrin"` (light) and `data-theme="eldrin-dark"` (dark) — NOT `.dark` and NOT `data-theme="dark"`. Dark-specific CSS is scoped `[data-theme='eldrin-dark']`.
- **CRM constants**: Meeting activity type id is the literal `'type-meeting'`; mirror dedup key is `sourceMessageId = `\`calendar:${eventId}\``; calendar app id constant `'eldrin-calendar'`.
- **Conventions**: immutable data patterns (no in-place mutation of fetched rows — build new objects); conventional commits; every worker change lands with tests (`npx vitest run`) and `npx tsc -b` green; frontend has NO unit-test harness (matches CRM) — typecheck + build are its gates.
- **Working directories**: eldrin-calendar tasks run in `/Users/tibor/projects/eldrin-backup/eldrin-calendar`; CRM tasks (12–14) run in `/Users/tibor/projects/eldrin-backup/eldrin-crm` on branch `feature/slice-4a-calendar-integration`. Beware: `cd` persists between Bash calls — use absolute paths or `git -C`.

## File Structure

**New repo `eldrin-calendar/`** (Tasks 1–11):
```
package.json, vite.config.ts, vitest.config.ts, wrangler.jsonc, tsconfig*.json,
index.html, .dev.vars (gitignored), .gitignore, scripts/generate-migrations.ts
public/eldrin-app.manifest.json
migrations/20260709000000-calendar-core.sql
worker/index.ts                      — bootstrap: migrations, permission middleware, Hono mount
worker/db/schema.ts                  — calendars, events, eventAttendees
worker/db/index.ts                   — createDb + Database type
worker/utils.ts                      — generateId, now
worker/services/zoned-time.ts        — Intl-based wall-time ⇄ UTC conversion (Task 4)
worker/services/expansion.ts         — occurrence expansion engine (Task 4)
worker/services/validation.ts        — input validators (Task 5)
worker/services/event-emitter.ts     — calendar.event.* emits (Task 6)
worker/services/event-edits.ts       — single/all/following edit + delete semantics (Task 7)
worker/routes/calendars.ts           — calendars CRUD (Task 3)
worker/routes/events.ts              — GET expanded + POST/PATCH/DELETE (Tasks 5–8)
worker/__tests__/test-db.ts          — better-sqlite3 harness (copied pattern)
worker/__tests__/*.test.ts           — per-task test files
src/index.css                        — Quiet Ledger tokens + --fc-* mapping
src/main.tsx, src/eldrin-calendar.tsx, src/root.component.tsx
src/api.ts                           — typed API client
src/components/CalendarSidebar.tsx   — calendar list/toggles/create
src/components/CalendarCanvas.tsx    — FullCalendar wrapper
src/components/EventModal.tsx        — create/edit modal
src/components/ScopeDialog.tsx       — this/following/all chooser
```

**eldrin-crm changes** (Tasks 12–14):
```
worker/services/calendar-mirror.ts       — mirror service (new)
worker/routes/events.ts                  — calendar.event.* cases (modify)
worker/services/upcoming-meetings.ts     — cross-app fetch service (new)
worker/routes/reports.ts                 — GET /api/reports/upcoming-meetings (modify)
public/eldrin-app.manifest.json          — new reports route entry (modify)
src/api.ts                               — types + getUpcomingMeetings (modify)
src/components/reports/UpcomingMeetingsWidget.tsx  — widget (new)
src/pages/reports/Dashboard.tsx          — slot widget (modify)
worker/__tests__/calendar-mirror.test.ts, upcoming-meetings.test.ts (new)
```

**Reference files an implementer may read (do not modify):**
- Template: `eldrin-templates/templates/cloudflare-react-sqlite/` (worker bootstrap, generate-migrations, single-spa entry)
- Patterns: `eldrin-crm/worker/index.ts`, `eldrin-crm/worker/__tests__/test-db.ts`, `eldrin-crm/worker/routes/reports.ts`, `eldrin-crm/src/components/reports/GoneQuietWidget.tsx`, `eldrin-crm/src/index.css`, `eldrin-crm/vite.config.ts`
- Cross-app seam: `eldrin-workflows/worker/engine/steps/call-app-api.ts`

---

### Task 1: Scaffold the eldrin-calendar app

**Files:**
- Create: entire `eldrin-calendar/` repo skeleton (list below)
- Test: `worker/__tests__/health.test.ts`

**Interfaces:**
- Produces: running dev server on 4012; `worker/index.ts` exporting the fetch handler with a mounted Hono app; `worker/utils.ts` with `generateId(): string` and `now(): number`; manifest v1. Later tasks add routers via `app.route('', xxxRoutes)` in `worker/index.ts`.

- [ ] **Step 1: Create the repo**

```bash
mkdir -p /Users/tibor/projects/eldrin-backup/eldrin-calendar
cd /Users/tibor/projects/eldrin-backup/eldrin-calendar
git init -b main
```

- [ ] **Step 2: Copy invariant files from the template and CRM**

Copy verbatim (then adapt only where stated):

```bash
T=/Users/tibor/projects/eldrin-backup/eldrin-templates/templates/cloudflare-react-sqlite
C=/Users/tibor/projects/eldrin-backup/eldrin-crm
cp $T/scripts/generate-migrations.ts scripts/generate-migrations.ts   # no placeholders — verbatim
cp $T/.gitignore .gitignore
cp $C/tsconfig.json $C/tsconfig.app.json $C/tsconfig.node.json $C/tsconfig.worker.json .
cp $C/vitest.config.ts vitest.config.ts                               # environment:'node', include worker/**/*.test.ts
cp $C/src/single-spa-react.d.ts src/single-spa-react.d.ts 2>/dev/null || cp $T/src/single-spa-react.d.ts src/single-spa-react.d.ts
cp $C/shims/better-sqlite3.js shims/better-sqlite3.js                 # create shims/ dir first if needed
grep -q "migrations.generated" .gitignore || echo "worker/migrations.generated.ts" >> .gitignore
echo ".dev.vars" >> .gitignore
```

Create `.dev.vars` with a single line `JWT_SECRET=<value>` where `<value>` is copied from `/Users/tibor/projects/eldrin-backup/eldrin-crm/.dev.vars` (must match eldrin-core). Do not commit it.

- [ ] **Step 3: Write `package.json`**

```json
{
  "name": "eldrin-calendar",
  "private": true,
  "version": "0.0.1",
  "type": "module",
  "scripts": {
    "generate:migrations": "tsx scripts/generate-migrations.ts",
    "dev": "npm run generate:migrations && vite",
    "build": "npm run generate:migrations && tsc -b && vite build",
    "typecheck": "tsc -b",
    "test": "vitest run",
    "deploy": "npm run build && wrangler deploy",
    "cf-typegen": "wrangler types"
  },
  "dependencies": {
    "@eldrin-project/eldrin-app-core": "file:../eldrin-app-core",
    "@eldrin-project/eldrin-app-react": "^0.0.2",
    "@fullcalendar/core": "^6.1.21",
    "@fullcalendar/daygrid": "^6.1.21",
    "@fullcalendar/interaction": "^6.1.21",
    "@fullcalendar/list": "^6.1.21",
    "@fullcalendar/react": "^6.1.21",
    "@fullcalendar/timegrid": "^6.1.21",
    "drizzle-orm": "^0.45.1",
    "hono": "^4.6.0",
    "react": "^19.1.1",
    "react-dom": "^19.1.1",
    "rrule": "^2.7.1",
    "single-spa-react": "^6.0.2"
  },
  "devDependencies": {
    "@cloudflare/vite-plugin": "^1.18.0",
    "@tailwindcss/vite": "^4.1.18",
    "@types/better-sqlite3": "^7.6.13",
    "@types/react": "^19.1.0",
    "@types/react-dom": "^19.1.0",
    "@vitejs/plugin-react": "^4.3.4",
    "better-sqlite3": "^12.11.1",
    "daisyui": "^5.0.0",
    "tailwindcss": "^4.1.18",
    "tsx": "^4.7.0",
    "typescript": "~5.9.3",
    "vitest": "^2.0.0",
    "wrangler": "^4.16.0"
  }
}
```

Reconcile devDependency versions against `eldrin-crm/package.json` if `npm install` complains — CRM is the source of truth for shared tooling versions.

- [ ] **Step 4: Write `wrangler.jsonc`**

```jsonc
{
  "$schema": "node_modules/wrangler/config-schema.json",
  "name": "eldrin-calendar",
  "main": "worker/index.ts",
  "compatibility_date": "2025-01-01",
  "compatibility_flags": ["nodejs_compat"],
  "assets": { "directory": "./dist", "not_found_handling": "single-page-application" },
  "d1_databases": [
    { "binding": "DB", "database_name": "eldrin-calendar-db", "database_id": "local" }
  ]
}
```

- [ ] **Step 5: Write `vite.config.ts`**

Copy `eldrin-crm/vite.config.ts` and adapt: port `4012`, lib entry `'./src/eldrin-calendar.tsx'`, lib name `'eldrinCalendar'`, fileName `'eldrin-calendar'`, and inside its `devShellCompat()` plugin replace every `eldrin-crm` filename with `eldrin-calendar` (the plugin rewrites `/eldrin-calendar.js` → `/src/eldrin-calendar.tsx` and serves `/eldrin-calendar.css` from `/src/index.css` in dev). Keep `server: { port: 4012, strictPort: true, cors: true }` and the `better-sqlite3` shim alias.

- [ ] **Step 6: Write `public/eldrin-app.manifest.json`**

```json
{
  "id": "eldrin-calendar",
  "name": "Calendar",
  "version": "0.0.1",
  "entry": "/eldrin-calendar.js",
  "styles": "/eldrin-calendar.css",
  "developer_id": "eldrin.io",
  "developer": { "id": "eldrin.io", "name": "Eldrin Team" },
  "compatibility": { "core": ">=0.1.0" },
  "permissions": [
    { "resource": "calendar", "actions": ["read", "create", "update", "delete"] }
  ],
  "groups": [
    { "id": "admin", "name": "Admin", "permissions": ["calendar:*"] },
    { "id": "user", "name": "User", "permissions": ["calendar:*"] },
    { "id": "viewer", "name": "Viewer", "permissions": ["calendar:read"] }
  ],
  "api": {
    "defaultPolicy": "deny",
    "publicRoutes": ["/health"],
    "routes": [
      { "method": "GET", "path": "/calendars", "permission": "calendar:read" },
      { "method": "POST", "path": "/calendars", "permission": "calendar:create" },
      { "method": "PATCH", "path": "/calendars/:id", "permission": "calendar:update" },
      { "method": "DELETE", "path": "/calendars/:id", "permission": "calendar:delete" },
      { "method": "GET", "path": "/events", "permission": "calendar:read" },
      { "method": "POST", "path": "/events", "permission": "calendar:create" },
      { "method": "GET", "path": "/events/:id", "permission": "calendar:read" },
      { "method": "PATCH", "path": "/events/:id", "permission": "calendar:update" },
      { "method": "DELETE", "path": "/events/:id", "permission": "calendar:delete" }
    ]
  },
  "database": { "name": "eldrin-calendar", "migrationsPath": "migrations", "handledBy": "worker" },
  "ui": { "sideNav": [ { "label": "Calendar", "icon": "calendar", "path": "/eldrin-calendar" } ] },
  "events": {
    "emits": [
      { "type": "calendar.event.created", "description": "A calendar event (single or recurring master) was created", "payload": { "eventId": "string", "calendarId": "string", "title": "string", "startAt": "number", "endAt": "number", "allDay": "boolean", "timezone": "string", "location": "string|null", "recurrenceRule": "string|null", "attendees": "array" } },
      { "type": "calendar.event.updated", "description": "A calendar event was updated (scope single|following|all)", "payload": { "eventId": "string", "scope": "string" } },
      { "type": "calendar.event.deleted", "description": "A calendar event was deleted (scope single|following|all)", "payload": { "eventId": "string", "scope": "string" } }
    ],
    "subscribes": []
  }
}
```

Note: manifest `api.routes` in THIS repo's convention must match how core stores them. eldrin-crm's manifest uses paths WITH the `/api` prefix (`"path": "/api/contacts"`) while the template omits it — **follow eldrin-crm** (it is the proven, registered app): prefix all route paths above with `/api` (i.e. `"/api/calendars"`, `"/api/events/:id"`, …) and use publicRoutes `["/api/health"]`. Check `eldrin-crm/public/eldrin-app.manifest.json` `api` block and mirror its exact style.

- [ ] **Step 7: Write the worker bootstrap**

`worker/utils.ts`:
```ts
export function generateId(): string {
  return crypto.randomUUID();
}

export function now(): number {
  return Date.now();
}
```

`worker/db/index.ts`:
```ts
import { drizzle } from 'drizzle-orm/d1';
import * as schema from './schema';

export function createDb(d1: D1Database) {
  return drizzle(d1, { schema });
}

export type Database = ReturnType<typeof createDb>;
export * from './schema';
```

`worker/db/schema.ts` — placeholder module for Task 1 only (Task 2 replaces it):
```ts
// Schema lands in Task 2.
export {};
```

`worker/index.ts` — copy `eldrin-crm/worker/index.ts` and adapt: app id `'eldrin-calendar'`, strip all CRM route imports/mounts, keep the structure (permission middleware from `@eldrin-project/eldrin-app-core` with the manifest, one-time `runMigrations` with `./migrations.generated`, Hono app with a `c.set('db', createDb(env.DB))` middleware, `env.ASSETS.fetch` fallback for non-API paths). Mount a single route for now:

```ts
app.get('/api/health', (c) => c.json({ status: 'ok', app: 'eldrin-calendar' }));
```

Later tasks add `app.route('', calendarRoutes)` / `app.route('', eventRoutes)` here.

- [ ] **Step 8: Minimal frontend so `vite build` passes**

`index.html`: copy from CRM, retitle "Eldrin Calendar", entry `/src/main.tsx`.

`src/index.css`: copy `eldrin-crm/src/index.css` WHOLE (tailwind + daisyUI plugin blocks + `eldrin`/`eldrin-dark` theme definitions + tokens), then rename the CRM-specific utility classes you keep (`crm-eyebrow` → `cal-eyebrow`, `crm-section-title` → `cal-section-title`, `crm-num` → `cal-num`) and DELETE the CRM component-specific rules you don't need (badges, kanban, etc. — keep the file lean, under ~200 lines). FullCalendar `--fc-*` mapping is Task 9.

`src/root.component.tsx`:
```tsx
export interface RootProps {
  manifest?: { baseUrl?: string };
}

export function Root({ manifest }: RootProps) {
  const apiBase = manifest?.baseUrl || '';
  return (
    <div className="p-4">
      <h1 className="cal-eyebrow">Calendar</h1>
      <p className="text-sm text-base-content/50">Coming in Task 9. API base: {apiBase || '(standalone)'}</p>
    </div>
  );
}
```

`src/eldrin-calendar.tsx` — copy the template's `src/eldrin-{{appNameKebab}}.tsx.template` resolving: container id `'single-spa-application:eldrin-calendar'`, error text `'Error loading Calendar app'`.

`src/main.tsx` — copy the template's `src/main.tsx.template` (standalone dev entry rendering `<Root />`), resolving names the same way.

- [ ] **Step 9: Write the failing health test**

`worker/__tests__/health.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';

// Import nothing from index.ts (it pulls in migrations.generated + manifest);
// assert the health handler shape by mounting an identical route.
describe('scaffold sanity', () => {
  it('health route returns ok', async () => {
    const app = new Hono();
    app.get('/api/health', (c) => c.json({ status: 'ok', app: 'eldrin-calendar' }));
    const res = await app.request('/api/health');
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: 'ok', app: 'eldrin-calendar' });
  });
});
```

- [ ] **Step 10: Install and verify everything runs**

```bash
npm install
npm run generate:migrations   # creates worker/migrations.generated.ts (empty list — no migrations yet)
npx vitest run                # 1 test passes
npx tsc -b                    # clean
npm run build                 # vite build succeeds
```

Expected: all green. If `generate:migrations` fails on an empty `migrations/` dir, create the dir (`mkdir -p migrations`) — the real migration lands in Task 2.

- [ ] **Step 11: Commit**

```bash
git add -A
git commit -m "feat: scaffold eldrin-calendar app (worker bootstrap, manifest, single-spa entry, port 4012)"
```

---

### Task 2: D1 schema, migration, and test harness

**Files:**
- Create: `migrations/20260709000000-calendar-core.sql`, `worker/__tests__/test-db.ts`
- Modify: `worker/db/schema.ts` (replace the placeholder)
- Test: `worker/__tests__/schema.test.ts`

**Interfaces:**
- Produces: Drizzle tables `calendars`, `events`, `eventAttendees` (exact columns below); `createTestDb(): Database` for all later worker tests. Row types: `typeof calendars.$inferSelect` etc.

- [ ] **Step 1: Write the migration**

`migrations/20260709000000-calendar-core.sql`:
```sql
-- Calendars, events (master/single/exception rows), attendees. Spec §5.
CREATE TABLE calendars (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  color TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  is_default INTEGER NOT NULL DEFAULT 0,
  provider TEXT NOT NULL DEFAULT 'local',
  external_id TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX idx_calendars_owner ON calendars(owner_id);

CREATE TABLE events (
  id TEXT PRIMARY KEY,
  calendar_id TEXT NOT NULL REFERENCES calendars(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT,
  location TEXT,
  start_at INTEGER NOT NULL,
  end_at INTEGER NOT NULL,
  all_day INTEGER NOT NULL DEFAULT 0,
  timezone TEXT NOT NULL,
  recurrence_rule TEXT,
  recurring_event_id TEXT REFERENCES events(id) ON DELETE CASCADE,
  original_start_time INTEGER,
  status TEXT NOT NULL DEFAULT 'confirmed',
  external_id TEXT,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX idx_events_calendar ON events(calendar_id);
CREATE INDEX idx_events_start ON events(start_at);
CREATE INDEX idx_events_recurring ON events(recurring_event_id);
CREATE UNIQUE INDEX idx_events_external ON events(calendar_id, external_id)
  WHERE external_id IS NOT NULL;

CREATE TABLE event_attendees (
  id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  display_name TEXT
);
CREATE INDEX idx_attendees_event ON event_attendees(event_id);
CREATE UNIQUE INDEX idx_attendees_unique ON event_attendees(event_id, email);
```

- [ ] **Step 2: Write the Drizzle schema**

Replace `worker/db/schema.ts`:
```ts
import { sqliteTable, text, integer, index, uniqueIndex } from 'drizzle-orm/sqlite-core';

export const calendars = sqliteTable(
  'calendars',
  {
    id: text('id').primaryKey(),
    name: text('name').notNull(),
    color: text('color').notNull(),
    ownerId: text('owner_id').notNull(),
    isDefault: integer('is_default', { mode: 'boolean' }).notNull().default(false),
    provider: text('provider').notNull().default('local'),
    externalId: text('external_id'),
    createdAt: integer('created_at', { mode: 'number' }).notNull(),
    updatedAt: integer('updated_at', { mode: 'number' }).notNull(),
  },
  (t) => [index('idx_calendars_owner').on(t.ownerId)],
);

export const events = sqliteTable(
  'events',
  {
    id: text('id').primaryKey(),
    calendarId: text('calendar_id')
      .notNull()
      .references(() => calendars.id, { onDelete: 'cascade' }),
    title: text('title').notNull(),
    description: text('description'),
    location: text('location'),
    startAt: integer('start_at', { mode: 'number' }).notNull(),
    endAt: integer('end_at', { mode: 'number' }).notNull(),
    allDay: integer('all_day', { mode: 'boolean' }).notNull().default(false),
    timezone: text('timezone').notNull(),
    recurrenceRule: text('recurrence_rule'),
    recurringEventId: text('recurring_event_id'),
    originalStartTime: integer('original_start_time', { mode: 'number' }),
    status: text('status').notNull().default('confirmed'),
    externalId: text('external_id'),
    createdBy: text('created_by').notNull(),
    createdAt: integer('created_at', { mode: 'number' }).notNull(),
    updatedAt: integer('updated_at', { mode: 'number' }).notNull(),
  },
  (t) => [
    index('idx_events_calendar').on(t.calendarId),
    index('idx_events_start').on(t.startAt),
    index('idx_events_recurring').on(t.recurringEventId),
  ],
);

export const eventAttendees = sqliteTable(
  'event_attendees',
  {
    id: text('id').primaryKey(),
    eventId: text('event_id')
      .notNull()
      .references(() => events.id, { onDelete: 'cascade' }),
    email: text('email').notNull(),
    displayName: text('display_name'),
  },
  (t) => [
    index('idx_attendees_event').on(t.eventId),
    uniqueIndex('idx_attendees_unique').on(t.eventId, t.email),
  ],
);

export type CalendarRow = typeof calendars.$inferSelect;
export type EventRow = typeof events.$inferSelect;
export type AttendeeRow = typeof eventAttendees.$inferSelect;
```

(Note: the self-referencing FK on `recurring_event_id` lives only in the SQL — drizzle self-references cause TS circularity; the SQL enforces it.)

- [ ] **Step 3: Write the test harness**

`worker/__tests__/test-db.ts` — copy `eldrin-crm/worker/__tests__/test-db.ts` verbatim; it already points `MIGRATIONS_DIR` at `../../migrations` and imports `../db/schema` + `type Database` from `../db`, both of which exist here. Add one line after opening the DB so cascades work in tests:
```ts
  sqlite.exec('PRAGMA foreign_keys = ON;');
```

- [ ] **Step 4: Write the failing schema test**

`worker/__tests__/schema.test.ts`:
```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { createTestDb } from './test-db';
import type { Database } from '../db';
import { calendars, events, eventAttendees } from '../db';
import { eq } from 'drizzle-orm';

const T0 = 1700000000000;

describe('calendar schema', () => {
  let db: Database;
  beforeEach(() => {
    db = createTestDb();
  });

  async function seedCalendar(id = 'cal1') {
    await db.insert(calendars).values({
      id, name: 'My Calendar', color: '#3b82f6', ownerId: 'u1',
      isDefault: true, createdAt: T0, updatedAt: T0,
    });
  }

  it('round-trips a calendar with defaults', async () => {
    await seedCalendar();
    const [row] = await db.select().from(calendars);
    expect(row.provider).toBe('local');
    expect(row.externalId).toBeNull();
    expect(row.isDefault).toBe(true);
  });

  it('cascades events and attendees when a calendar is deleted', async () => {
    await seedCalendar();
    await db.insert(events).values({
      id: 'ev1', calendarId: 'cal1', title: 'Standup', startAt: T0, endAt: T0 + 3600000,
      timezone: 'Europe/Budapest', createdBy: 'u1', createdAt: T0, updatedAt: T0,
    });
    await db.insert(eventAttendees).values({ id: 'at1', eventId: 'ev1', email: 'a@b.co' });
    await db.delete(calendars).where(eq(calendars.id, 'cal1'));
    expect(await db.select().from(events)).toHaveLength(0);
    expect(await db.select().from(eventAttendees)).toHaveLength(0);
  });

  it('rejects duplicate external ids within a calendar but allows null duplicates', async () => {
    await seedCalendar();
    const base = {
      calendarId: 'cal1', title: 'X', startAt: T0, endAt: T0 + 1000,
      timezone: 'UTC', createdBy: 'u1', createdAt: T0, updatedAt: T0,
    };
    await db.insert(events).values({ ...base, id: 'e1', externalId: 'ext-1' });
    await expect(
      db.insert(events).values({ ...base, id: 'e2', externalId: 'ext-1' }),
    ).rejects.toThrow(/unique/i);
    await db.insert(events).values({ ...base, id: 'e3' });
    await db.insert(events).values({ ...base, id: 'e4' });
    expect(await db.select().from(events)).toHaveLength(3);
  });

  it('cascades exception rows when the master is deleted', async () => {
    await seedCalendar();
    await db.insert(events).values({
      id: 'master', calendarId: 'cal1', title: 'Weekly', startAt: T0, endAt: T0 + 3600000,
      timezone: 'UTC', recurrenceRule: 'FREQ=WEEKLY', createdBy: 'u1', createdAt: T0, updatedAt: T0,
    });
    await db.insert(events).values({
      id: 'exc', calendarId: 'cal1', title: 'Weekly (moved)', startAt: T0 + 90000000,
      endAt: T0 + 93600000, timezone: 'UTC', recurringEventId: 'master',
      originalStartTime: T0 + 86400000, createdBy: 'u1', createdAt: T0, updatedAt: T0,
    });
    await db.delete(events).where(eq(events.id, 'master'));
    expect(await db.select().from(events)).toHaveLength(0);
  });
});
```

- [ ] **Step 5: Run tests — expect FAIL** (`schema.ts` placeholder has no tables)

Run: `npx vitest run worker/__tests__/schema.test.ts`
Expected: FAIL (module has no export `calendars`) before Step 2 is applied; after applying Steps 1–3, re-run.

- [ ] **Step 6: Run tests — expect PASS**

```bash
npm run generate:migrations
npx vitest run
npx tsc -b
```
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add migrations worker/db/schema.ts worker/__tests__/test-db.ts worker/__tests__/schema.test.ts
git commit -m "feat: calendar D1 schema (calendars, events master/exception, attendees) + test harness"
```

---

### Task 3: Calendars CRUD routes with lazy default seed

**Files:**
- Create: `worker/routes/calendars.ts`
- Modify: `worker/index.ts` (mount `app.route('', calendarRoutes)`)
- Test: `worker/__tests__/calendars-routes.test.ts`

**Interfaces:**
- Consumes: `createDb`/`Database`, `calendars` table, `generateId`/`now` from Task 1–2.
- Produces: `calendarRoutes` (Hono router); `requestUserId(c): string` helper (exported from this file, reused by Task 5's events routes); default-calendar constants `DEFAULT_CALENDAR_NAME = 'My Calendar'`, `DEFAULT_CALENDAR_COLOR = '#4f6df5'`.

- [ ] **Step 1: Write the failing tests**

`worker/__tests__/calendars-routes.test.ts`:
```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { Hono } from 'hono';
import { createTestDb } from './test-db';
import type { Database } from '../db';
import { calendars } from '../db';
import { calendarRoutes } from '../routes/calendars';

const mockEnv = { JWT_SECRET: 'test-secret' } as Env;
const USER = { 'x-eldrin-user-id': 'u1' };

function createApp(db: Database) {
  const app = new Hono<{ Bindings: Env; Variables: { db: Database } }>();
  app.use('*', async (c, next) => {
    c.set('db', db);
    await next();
  });
  app.route('', calendarRoutes);
  return app;
}

function req(app: ReturnType<typeof createApp>, path: string, init?: RequestInit) {
  return app.request(path, { ...init, headers: { 'Content-Type': 'application/json', ...USER, ...(init?.headers as Record<string, string>) } }, mockEnv);
}

describe('calendar routes', () => {
  let db: Database;
  let app: ReturnType<typeof createApp>;
  beforeEach(() => {
    db = createTestDb();
    app = createApp(db);
  });

  it('GET /api/calendars lazily seeds a default calendar for the user', async () => {
    const res = await req(app, '/api/calendars');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.calendars).toHaveLength(1);
    expect(body.calendars[0]).toMatchObject({
      name: 'My Calendar', isDefault: true, provider: 'local', ownerId: 'u1',
    });
    // Second call does not seed again
    const res2 = await req(app, '/api/calendars');
    expect((await res2.json()).calendars).toHaveLength(1);
  });

  it('scopes calendars by owner', async () => {
    await req(app, '/api/calendars'); // seeds for u1
    const res = await app.request('/api/calendars', { headers: { 'x-eldrin-user-id': 'u2' } }, mockEnv);
    const body = await res.json();
    expect(body.calendars).toHaveLength(1);
    expect(body.calendars[0].ownerId).toBe('u2'); // u2 got their own seed, not u1's
  });

  it('POST creates, PATCH renames/recolors, validates caps', async () => {
    const created = await req(app, '/api/calendars', {
      method: 'POST', body: JSON.stringify({ name: 'Work', color: '#16a34a' }),
    });
    expect(created.status).toBe(201);
    const { calendar } = await created.json();
    const patched = await req(app, `/api/calendars/${calendar.id}`, {
      method: 'PATCH', body: JSON.stringify({ name: 'Work Cal' }),
    });
    expect((await patched.json()).calendar.name).toBe('Work Cal');

    const tooLong = await req(app, '/api/calendars', {
      method: 'POST', body: JSON.stringify({ name: 'x'.repeat(101), color: '#fff' }),
    });
    expect(tooLong.status).toBe(400);
    const badColor = await req(app, '/api/calendars', {
      method: 'POST', body: JSON.stringify({ name: 'ok', color: 'red' }),
    });
    expect(badColor.status).toBe(400);
  });

  it('DELETE removes a non-default calendar, 409s on the default, 404s on unknown', async () => {
    await req(app, '/api/calendars');
    const [def] = await db.select().from(calendars);
    const extra = await req(app, '/api/calendars', {
      method: 'POST', body: JSON.stringify({ name: 'Temp', color: '#000000' }),
    });
    const { calendar } = await extra.json();
    expect((await req(app, `/api/calendars/${calendar.id}`, { method: 'DELETE' })).status).toBe(200);
    expect((await req(app, `/api/calendars/${def.id}`, { method: 'DELETE' })).status).toBe(409);
    expect((await req(app, '/api/calendars/nope', { method: 'DELETE' })).status).toBe(404);
  });

  it("cannot touch another user's calendar", async () => {
    await req(app, '/api/calendars');
    const [def] = await db.select().from(calendars);
    const res = await app.request(`/api/calendars/${def.id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', 'x-eldrin-user-id': 'u2' },
      body: JSON.stringify({ name: 'hijack' }),
    }, mockEnv);
    expect(res.status).toBe(404);
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run worker/__tests__/calendars-routes.test.ts`
Expected: FAIL — `Cannot find module '../routes/calendars'`.

- [ ] **Step 3: Implement `worker/routes/calendars.ts`**

```ts
import { Hono } from 'hono';
import type { Context } from 'hono';
import { and, eq } from 'drizzle-orm';
import type { Database } from '../db';
import { calendars } from '../db';
import { generateId, now } from '../utils';

type Variables = { db: Database };

export const DEFAULT_CALENDAR_NAME = 'My Calendar';
export const DEFAULT_CALENDAR_COLOR = '#4f6df5';
const NAME_MAX = 100;
const HEX_COLOR_RE = /^#[0-9a-fA-F]{6}$/;

/** Resolve the acting user from proxy-injected headers (dev fallback). */
export function requestUserId(c: Context): string {
  return c.req.header('x-eldrin-user-id') || c.req.header('x-user-id') || 'dev-user';
}

/** Seed the user's default calendar if they have none yet. */
export async function ensureDefaultCalendar(db: Database, ownerId: string): Promise<void> {
  const existing = await db.select({ id: calendars.id }).from(calendars)
    .where(eq(calendars.ownerId, ownerId)).limit(1);
  if (existing.length > 0) return;
  const ts = now();
  await db.insert(calendars).values({
    id: generateId(), name: DEFAULT_CALENDAR_NAME, color: DEFAULT_CALENDAR_COLOR,
    ownerId, isDefault: true, createdAt: ts, updatedAt: ts,
  });
}

function validateCalendarInput(body: Record<string, unknown>, partial: boolean): string | null {
  if (!partial || body.name !== undefined) {
    if (typeof body.name !== 'string' || body.name.trim().length === 0) return 'name is required';
    if (body.name.length > NAME_MAX) return `name must be at most ${NAME_MAX} characters`;
  }
  if (!partial || body.color !== undefined) {
    if (typeof body.color !== 'string' || !HEX_COLOR_RE.test(body.color)) {
      return 'color must be a #rrggbb hex value';
    }
  }
  return null;
}

export const calendarRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

calendarRoutes.get('/api/calendars', async (c) => {
  const db = c.get('db');
  const ownerId = requestUserId(c);
  await ensureDefaultCalendar(db, ownerId);
  const rows = await db.select().from(calendars).where(eq(calendars.ownerId, ownerId));
  return c.json({ calendars: rows });
});

calendarRoutes.post('/api/calendars', async (c) => {
  const db = c.get('db');
  const ownerId = requestUserId(c);
  let body: Record<string, unknown>;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }
  const problem = validateCalendarInput(body, false);
  if (problem) return c.json({ error: problem }, 400);
  const ts = now();
  const calendar = {
    id: generateId(), name: (body.name as string).trim(), color: body.color as string,
    ownerId, isDefault: false, provider: 'local', externalId: null,
    createdAt: ts, updatedAt: ts,
  };
  await db.insert(calendars).values(calendar);
  return c.json({ calendar }, 201);
});

calendarRoutes.patch('/api/calendars/:id', async (c) => {
  const db = c.get('db');
  const ownerId = requestUserId(c);
  const id = c.req.param('id');
  let body: Record<string, unknown>;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }
  const problem = validateCalendarInput(body, true);
  if (problem) return c.json({ error: problem }, 400);
  const [existing] = await db.select().from(calendars)
    .where(and(eq(calendars.id, id), eq(calendars.ownerId, ownerId)));
  if (!existing) return c.json({ error: 'Calendar not found' }, 404);
  const updated = {
    ...existing,
    name: body.name !== undefined ? (body.name as string).trim() : existing.name,
    color: body.color !== undefined ? (body.color as string) : existing.color,
    updatedAt: now(),
  };
  await db.update(calendars).set({
    name: updated.name, color: updated.color, updatedAt: updated.updatedAt,
  }).where(eq(calendars.id, id));
  return c.json({ calendar: updated });
});

calendarRoutes.delete('/api/calendars/:id', async (c) => {
  const db = c.get('db');
  const ownerId = requestUserId(c);
  const id = c.req.param('id');
  const [existing] = await db.select().from(calendars)
    .where(and(eq(calendars.id, id), eq(calendars.ownerId, ownerId)));
  if (!existing) return c.json({ error: 'Calendar not found' }, 404);
  if (existing.isDefault) return c.json({ error: 'The default calendar cannot be deleted' }, 409);
  await db.delete(calendars).where(eq(calendars.id, id));
  return c.json({ deleted: true });
});
```

Mount in `worker/index.ts`: `import { calendarRoutes } from './routes/calendars';` + `app.route('', calendarRoutes);`

- [ ] **Step 4: Run tests — expect PASS**

Run: `npx vitest run && npx tsc -b`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add worker/routes/calendars.ts worker/index.ts worker/__tests__/calendars-routes.test.ts
git commit -m "feat: calendars CRUD with lazy per-user default seed and owner scoping"
```

---

### Task 4: Timezone helpers + occurrence expansion engine

The heart of the app (spec D7/§6). Pure functions first; the route wires up in Task 5.

**Files:**
- Create: `worker/services/zoned-time.ts`, `worker/services/expansion.ts`
- Test: `worker/__tests__/zoned-time.test.ts`, `worker/__tests__/expansion.test.ts`

**Interfaces:**
- Consumes: `EventRow`, `calendars`/`events`/`eventAttendees` tables.
- Produces (exact — later tasks import these):
  - `wallMsInZone(utcMs: number, tz: string): number` — wall-clock fields of a UTC instant in `tz`, encoded as a fake-UTC ms value.
  - `zonedWallToUtcMs(wallMs: number, tz: string): number` — inverse (real UTC instant of a wall-clock time).
  - `isValidTimezone(tz: string): boolean`
  - `toBasicIso(utcMs: number): string` — `20260708T090000Z` format.
  - `buildRule(row: EventRow): RRule` — parsed RRULE with fake-UTC dtstart.
  - `MAX_RANGE_DAYS = 400`, `MAX_OCCURRENCES = 1000`, `class ExpansionLimitError extends Error`
  - `interface Occurrence { id: string; seriesId: string | null; originalStartTime: number | null; calendarId: string; title: string; description: string | null; location: string | null; startAt: number; endAt: number; allDay: boolean; timezone: string; isRecurring: boolean; }`
  - `expandRows(rows: EventRow[], rangeStartMs: number, rangeEndMs: number): Occurrence[]` — pure.
  - `listOccurrences(db: Database, args: { ownerId: string; startMs: number; endMs: number; calendarIds?: string[] }): Promise<{ occurrences: OccurrenceView[] }>` where `OccurrenceView = Occurrence & { color: string; attendees: { email: string; displayName: string | null }[] }`.

**Why fake-UTC:** `rrule` computes in UTC. To recur on *wall-clock* time ("every Monday 09:00 in Europe/Budapest" across DST), we convert the master's real start to its wall-clock representation, run rrule on that, then convert each occurrence's wall-clock back to a real UTC instant with `zonedWallToUtcMs`. Do NOT use rrule's `tzid` option (its fake-UTC output is system-timezone-relative — broken on servers).

- [ ] **Step 1: Write the failing timezone tests**

`worker/__tests__/zoned-time.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { wallMsInZone, zonedWallToUtcMs, isValidTimezone, toBasicIso } from '../services/zoned-time';

describe('zoned-time', () => {
  it('round-trips a CET instant (winter, +1)', () => {
    const utc = Date.UTC(2026, 0, 12, 8, 0, 0); // 2026-01-12 08:00Z = 09:00 Budapest
    const wall = wallMsInZone(utc, 'Europe/Budapest');
    expect(new Date(wall).toISOString()).toBe('2026-01-12T09:00:00.000Z'); // fake-UTC carries wall fields
    expect(zonedWallToUtcMs(wall, 'Europe/Budapest')).toBe(utc);
  });

  it('round-trips a CEST instant (summer, +2)', () => {
    const utc = Date.UTC(2026, 6, 6, 7, 0, 0); // 2026-07-06 07:00Z = 09:00 Budapest
    const wall = wallMsInZone(utc, 'Europe/Budapest');
    expect(new Date(wall).toISOString()).toBe('2026-07-06T09:00:00.000Z');
    expect(zonedWallToUtcMs(wall, 'Europe/Budapest')).toBe(utc);
  });

  it('handles UTC and validates timezones', () => {
    const utc = Date.UTC(2026, 3, 1, 12, 30, 15);
    expect(wallMsInZone(utc, 'UTC')).toBe(utc);
    expect(zonedWallToUtcMs(utc, 'UTC')).toBe(utc);
    expect(isValidTimezone('Europe/Budapest')).toBe(true);
    expect(isValidTimezone('Not/AZone')).toBe(false);
    expect(isValidTimezone('')).toBe(false);
  });

  it('formats basic ISO', () => {
    expect(toBasicIso(Date.UTC(2026, 6, 8, 9, 0, 0))).toBe('20260708T090000Z');
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run worker/__tests__/zoned-time.test.ts` — Expected: FAIL (module not found).

- [ ] **Step 3: Implement `worker/services/zoned-time.ts`**

```ts
/**
 * Wall-clock ⇄ UTC conversion via Intl (no external tz library).
 * "Fake-UTC" = a ms value whose UTC fields equal the wall-clock fields in a zone.
 */

const formatterCache = new Map<string, Intl.DateTimeFormat>();

function formatterFor(tz: string): Intl.DateTimeFormat {
  const cached = formatterCache.get(tz);
  if (cached) return cached;
  const fmt = new Intl.DateTimeFormat('en-US', {
    timeZone: tz, hour12: false,
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
  formatterCache.set(tz, fmt);
  return fmt;
}

export function isValidTimezone(tz: string): boolean {
  if (typeof tz !== 'string' || tz.length === 0) return false;
  try {
    formatterFor(tz);
    return true;
  } catch {
    return false;
  }
}

/** Wall-clock fields of `utcMs` in `tz`, encoded as fake-UTC ms. */
export function wallMsInZone(utcMs: number, tz: string): number {
  const parts = formatterFor(tz).formatToParts(new Date(utcMs));
  const num = (type: string): number =>
    Number(parts.find((p) => p.type === type)?.value ?? 0);
  // Intl may render midnight as hour "24"
  const hour = num('hour') % 24;
  return Date.UTC(num('year'), num('month') - 1, num('day'), hour, num('minute'), num('second'));
}

/** Real UTC instant whose wall clock in `tz` equals the fake-UTC `wallMs`. */
export function zonedWallToUtcMs(wallMs: number, tz: string): number {
  let utc = wallMs;
  for (let i = 0; i < 3; i += 1) {
    const next = wallMs - (wallMsInZone(utc, tz) - utc);
    if (next === utc) break;
    utc = next;
  }
  return utc;
}

/** 20260708T090000Z */
export function toBasicIso(utcMs: number): string {
  return new Date(utcMs).toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
}
```

- [ ] **Step 4: Run — expect PASS**, then commit

```bash
npx vitest run worker/__tests__/zoned-time.test.ts
git add worker/services/zoned-time.ts worker/__tests__/zoned-time.test.ts
git commit -m "feat: Intl-based wall-clock timezone conversion helpers"
```

- [ ] **Step 5: Write the failing expansion tests**

`worker/__tests__/expansion.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import type { EventRow } from '../db';
import { expandRows, ExpansionLimitError, listOccurrences } from '../services/expansion';
import { createTestDb } from './test-db';
import { calendars, events, eventAttendees } from '../db';

const TZ = 'Europe/Budapest';
// Monday 2026-03-23 09:00 Budapest (CET, +1) == 08:00Z. EU DST starts 2026-03-29.
const MASTER_START = Date.UTC(2026, 2, 23, 8, 0, 0);
const HOUR = 3600000;

function master(overrides: Partial<EventRow> = {}): EventRow {
  return {
    id: 'm1', calendarId: 'cal1', title: 'Weekly sync', description: null, location: null,
    startAt: MASTER_START, endAt: MASTER_START + HOUR, allDay: false, timezone: TZ,
    recurrenceRule: 'FREQ=WEEKLY', recurringEventId: null, originalStartTime: null,
    status: 'confirmed', externalId: null, createdBy: 'u1', createdAt: 1, updatedAt: 1,
    ...overrides,
  } as EventRow;
}

describe('expandRows', () => {
  const rangeStart = Date.UTC(2026, 2, 20);
  const rangeEnd = Date.UTC(2026, 3, 20);

  it('keeps wall-clock time across the DST boundary', () => {
    const occ = expandRows([master()], rangeStart, rangeEnd);
    expect(occ.map((o) => new Date(o.startAt).toISOString())).toEqual([
      '2026-03-23T08:00:00.000Z', // CET +1 → 09:00 wall
      '2026-03-30T07:00:00.000Z', // CEST +2 → still 09:00 wall
      '2026-04-06T07:00:00.000Z',
      '2026-04-13T07:00:00.000Z',
    ]);
    expect(occ[0].id).toBe('m1_20260323T080000Z');
    expect(occ[0].seriesId).toBe('m1');
    expect(occ[0].originalStartTime).toBe(MASTER_START);
    expect(occ[0].isRecurring).toBe(true);
    expect(occ.every((o) => o.endAt - o.startAt === HOUR)).toBe(true);
  });

  it('honors COUNT', () => {
    const occ = expandRows([master({ recurrenceRule: 'FREQ=WEEKLY;COUNT=2' })], rangeStart, rangeEnd);
    expect(occ).toHaveLength(2);
  });

  it('passes singles through and filters by range intersection', () => {
    const single = master({ id: 's1', recurrenceRule: null, startAt: rangeStart - HOUR, endAt: rangeStart + HOUR });
    const outside = master({ id: 's2', recurrenceRule: null, startAt: rangeEnd + HOUR, endAt: rangeEnd + 2 * HOUR });
    const occ = expandRows([single, outside], rangeStart, rangeEnd);
    expect(occ.map((o) => o.id)).toEqual(['s1']); // overlapping counts, fully-after does not
    expect(occ[0].seriesId).toBeNull();
  });

  it('applies a moved exception (replaces the generated occurrence)', () => {
    const secondOcc = Date.UTC(2026, 2, 30, 7, 0, 0);
    const exception = master({
      id: 'x1', recurrenceRule: null, recurringEventId: 'm1',
      originalStartTime: secondOcc, startAt: secondOcc + 2 * HOUR, endAt: secondOcc + 3 * HOUR,
      title: 'Weekly sync (moved)',
    });
    const occ = expandRows([master(), exception], rangeStart, rangeEnd);
    const moved = occ.find((o) => o.id === 'x1');
    expect(moved).toMatchObject({ title: 'Weekly sync (moved)', startAt: secondOcc + 2 * HOUR, seriesId: 'm1' });
    // the generated slot it replaced is gone
    expect(occ.filter((o) => o.originalStartTime === secondOcc)).toHaveLength(1);
    expect(occ).toHaveLength(4);
  });

  it('drops a cancelled exception occurrence', () => {
    const secondOcc = Date.UTC(2026, 2, 30, 7, 0, 0);
    const cancelled = master({
      id: 'x2', recurrenceRule: null, recurringEventId: 'm1',
      originalStartTime: secondOcc, startAt: secondOcc, endAt: secondOcc + HOUR, status: 'cancelled',
    });
    const occ = expandRows([master(), cancelled], rangeStart, rangeEnd);
    expect(occ).toHaveLength(3);
    expect(occ.find((o) => o.startAt === secondOcc)).toBeUndefined();
  });

  it('includes a moved exception whose new time is in range but original was not', () => {
    // moved from before the range into it
    const origOcc = Date.UTC(2026, 2, 16, 8, 0, 0); // before rangeStart's week
    const exception = master({
      id: 'x3', recurrenceRule: null, recurringEventId: 'm1',
      originalStartTime: origOcc, startAt: rangeStart + HOUR, endAt: rangeStart + 2 * HOUR,
    });
    const occ = expandRows([master(), exception], rangeStart, rangeEnd);
    expect(occ.some((o) => o.id === 'x3')).toBe(true);
  });

  it('throws ExpansionLimitError past MAX_OCCURRENCES', () => {
    const minutely = master({ recurrenceRule: 'FREQ=MINUTELY' });
    expect(() => expandRows([minutely], MASTER_START, MASTER_START + 2 * 86400000))
      .toThrow(ExpansionLimitError);
  });
});

describe('listOccurrences', () => {
  it('scopes to owner calendars, honors calendarIds filter, attaches color and attendees', async () => {
    const db = createTestDb();
    const T = MASTER_START;
    await db.insert(calendars).values([
      { id: 'cal1', name: 'Mine', color: '#111111', ownerId: 'u1', isDefault: true, createdAt: 1, updatedAt: 1 },
      { id: 'cal2', name: 'Work', color: '#222222', ownerId: 'u1', isDefault: false, createdAt: 1, updatedAt: 1 },
      { id: 'other', name: 'Not mine', color: '#333333', ownerId: 'u2', isDefault: true, createdAt: 1, updatedAt: 1 },
    ]);
    await db.insert(events).values([
      { id: 'e1', calendarId: 'cal1', title: 'A', startAt: T, endAt: T + HOUR, timezone: 'UTC', createdBy: 'u1', createdAt: 1, updatedAt: 1 },
      { id: 'e2', calendarId: 'cal2', title: 'B', startAt: T, endAt: T + HOUR, timezone: 'UTC', createdBy: 'u1', createdAt: 1, updatedAt: 1 },
      { id: 'e3', calendarId: 'other', title: 'C', startAt: T, endAt: T + HOUR, timezone: 'UTC', createdBy: 'u2', createdAt: 1, updatedAt: 1 },
    ]);
    await db.insert(eventAttendees).values({ id: 'a1', eventId: 'e1', email: 'dana@globex.example', displayName: 'Dana' });

    const all = await listOccurrences(db, { ownerId: 'u1', startMs: T - HOUR, endMs: T + 2 * HOUR });
    expect(all.occurrences.map((o) => o.id).sort()).toEqual(['e1', 'e2']);
    const e1 = all.occurrences.find((o) => o.id === 'e1')!;
    expect(e1.color).toBe('#111111');
    expect(e1.attendees).toEqual([{ email: 'dana@globex.example', displayName: 'Dana' }]);

    const filtered = await listOccurrences(db, { ownerId: 'u1', startMs: T - HOUR, endMs: T + 2 * HOUR, calendarIds: ['cal2'] });
    expect(filtered.occurrences.map((o) => o.id)).toEqual(['e2']);
  });

  it('expanded instances inherit the master attendees', async () => {
    const db = createTestDb();
    await db.insert(calendars).values({ id: 'cal1', name: 'Mine', color: '#111111', ownerId: 'u1', isDefault: true, createdAt: 1, updatedAt: 1 });
    await db.insert(events).values({
      id: 'm1', calendarId: 'cal1', title: 'Weekly', startAt: MASTER_START, endAt: MASTER_START + HOUR,
      timezone: TZ, recurrenceRule: 'FREQ=WEEKLY;COUNT=3', createdBy: 'u1', createdAt: 1, updatedAt: 1,
    });
    await db.insert(eventAttendees).values({ id: 'a1', eventId: 'm1', email: 'dana@globex.example', displayName: null });
    const res = await listOccurrences(db, { ownerId: 'u1', startMs: MASTER_START - HOUR, endMs: MASTER_START + 30 * 86400000 });
    expect(res.occurrences).toHaveLength(3);
    expect(res.occurrences.every((o) => o.attendees.length === 1)).toBe(true);
  });
});
```

- [ ] **Step 6: Run to verify failure**

Run: `npx vitest run worker/__tests__/expansion.test.ts` — Expected: FAIL (module not found).

- [ ] **Step 7: Implement `worker/services/expansion.ts`**

```ts
import { RRule } from 'rrule';
import { inArray } from 'drizzle-orm';
import type { Database, EventRow } from '../db';
import { calendars, events, eventAttendees } from '../db';
import { wallMsInZone, zonedWallToUtcMs, toBasicIso } from './zoned-time';

export const MAX_RANGE_DAYS = 400;
export const MAX_OCCURRENCES = 1000;

export class ExpansionLimitError extends Error {
  constructor() {
    super(`Expansion exceeds ${MAX_OCCURRENCES} occurrences — narrow the range`);
  }
}

export interface Occurrence {
  id: string;
  seriesId: string | null;
  originalStartTime: number | null;
  calendarId: string;
  title: string;
  description: string | null;
  location: string | null;
  startAt: number;
  endAt: number;
  allDay: boolean;
  timezone: string;
  isRecurring: boolean;
}

export interface OccurrenceView extends Occurrence {
  color: string;
  attendees: { email: string; displayName: string | null }[];
}

/** RRULE with the master's wall-clock start as fake-UTC dtstart. */
export function buildRule(row: EventRow): RRule {
  const options = RRule.parseString(row.recurrenceRule ?? '');
  options.dtstart = new Date(wallMsInZone(row.startAt, row.timezone));
  return new RRule(options);
}

function intersects(startAt: number, endAt: number, rangeStart: number, rangeEnd: number): boolean {
  return startAt < rangeEnd && endAt > rangeStart;
}

function occurrenceFromRow(row: EventRow, seriesId: string | null): Occurrence {
  return {
    id: row.id,
    seriesId,
    originalStartTime: row.originalStartTime,
    calendarId: row.calendarId,
    title: row.title,
    description: row.description,
    location: row.location,
    startAt: row.startAt,
    endAt: row.endAt,
    allDay: row.allDay,
    timezone: row.timezone,
    isRecurring: seriesId !== null,
  };
}

/** Pure expansion: masters → generated occurrences, exceptions applied, singles passed through. */
export function expandRows(rows: EventRow[], rangeStartMs: number, rangeEndMs: number): Occurrence[] {
  const masters = rows.filter((r) => r.recurrenceRule && !r.recurringEventId);
  const exceptions = rows.filter((r) => r.recurringEventId);
  const singles = rows.filter((r) => !r.recurrenceRule && !r.recurringEventId);

  const exceptionsByMaster = new Map<string, Map<number, EventRow>>();
  for (const exc of exceptions) {
    const forMaster = exceptionsByMaster.get(exc.recurringEventId!) ?? new Map<number, EventRow>();
    if (exc.originalStartTime !== null) forMaster.set(exc.originalStartTime, exc);
    exceptionsByMaster.set(exc.recurringEventId!, forMaster);
  }

  const out: Occurrence[] = [];

  for (const single of singles) {
    if (single.status !== 'cancelled' && intersects(single.startAt, single.endAt, rangeStartMs, rangeEndMs)) {
      out.push(occurrenceFromRow(single, null));
    }
  }

  for (const m of masters) {
    const duration = m.endAt - m.startAt;
    const rule = buildRule(m);
    const consumed = new Set<number>();
    const excMap = exceptionsByMaster.get(m.id) ?? new Map<number, EventRow>();
    // Pad the window by the duration so occurrences straddling rangeStart are found.
    const fakeStart = new Date(wallMsInZone(rangeStartMs - duration, m.timezone));
    const fakeEnd = new Date(wallMsInZone(rangeEndMs, m.timezone));
    const fakes = rule.between(fakeStart, fakeEnd, true);
    if (fakes.length > MAX_OCCURRENCES) throw new ExpansionLimitError();
    for (const fake of fakes) {
      const origStart = zonedWallToUtcMs(fake.getTime(), m.timezone);
      const exc = excMap.get(origStart);
      if (exc) {
        consumed.add(origStart);
        if (exc.status !== 'cancelled' && intersects(exc.startAt, exc.endAt, rangeStartMs, rangeEndMs)) {
          out.push(occurrenceFromRow(exc, m.id));
        }
        continue;
      }
      const occEnd = origStart + duration;
      if (!intersects(origStart, occEnd, rangeStartMs, rangeEndMs)) continue;
      out.push({
        ...occurrenceFromRow({ ...m, startAt: origStart, endAt: occEnd } as EventRow, m.id),
        id: `${m.id}_${toBasicIso(origStart)}`,
        originalStartTime: origStart,
      });
    }
    // Moved exceptions whose ORIGINAL slot fell outside the scanned window still show
    // when their new time intersects the range.
    for (const [origStart, exc] of excMap) {
      if (consumed.has(origStart)) continue;
      if (exc.status !== 'cancelled' && intersects(exc.startAt, exc.endAt, rangeStartMs, rangeEndMs)) {
        out.push(occurrenceFromRow(exc, m.id));
      }
    }
  }

  if (out.length > MAX_OCCURRENCES) throw new ExpansionLimitError();
  return out.sort((a, b) => a.startAt - b.startAt || a.id.localeCompare(b.id));
}

/** Query + expand + enrich for one owner. */
export async function listOccurrences(
  db: Database,
  args: { ownerId: string; startMs: number; endMs: number; calendarIds?: string[] },
): Promise<{ occurrences: OccurrenceView[] }> {
  const ownedRows = await db.select().from(calendars);
  const owned = ownedRows.filter(
    (c) => c.ownerId === args.ownerId && (!args.calendarIds || args.calendarIds.includes(c.id)),
  );
  if (owned.length === 0) return { occurrences: [] };
  const calIds = owned.map((c) => c.id);
  const colorByCal = new Map(owned.map((c) => [c.id, c.color]));

  const rows = await db.select().from(events).where(inArray(events.calendarId, calIds));
  const inScope = rows.filter(
    (r) => r.recurringEventId !== null || r.recurrenceRule !== null || intersects(r.startAt, r.endAt, args.startMs, args.endMs),
  );

  const occurrences = expandRows(inScope, args.startMs, args.endMs);

  // Attendees: fetch for every source row involved; instances inherit the master's.
  const sourceIds = [...new Set(occurrences.map((o) => o.seriesId && o.id.includes('_') ? o.seriesId : o.id))];
  const attendeeRows = sourceIds.length
    ? await db.select().from(eventAttendees).where(inArray(eventAttendees.eventId, sourceIds))
    : [];
  const attendeesByEvent = new Map<string, { email: string; displayName: string | null }[]>();
  for (const a of attendeeRows) {
    const list = attendeesByEvent.get(a.eventId) ?? [];
    attendeesByEvent.set(a.eventId, [...list, { email: a.email, displayName: a.displayName }]);
  }

  return {
    occurrences: occurrences.map((o) => {
      const sourceId = o.seriesId && o.id.includes('_') ? o.seriesId : o.id;
      return {
        ...o,
        color: colorByCal.get(o.calendarId) ?? '#4f6df5',
        attendees: attendeesByEvent.get(sourceId) ?? [],
      };
    }),
  };
}
```

Note on attendee inheritance: generated instance ids contain `_` (uuid + `_` + basic ISO; uuids never contain `_`), so `id.includes('_')` distinguishes instances from row-backed occurrences. Exception rows fetch their own attendee rows — Task 7's single-scope edit does not copy attendees, so exceptions show the master's attendees ONLY if you copy them; simpler and spec-compliant: exceptions render with their own (usually empty) attendee list in 4a. Do not "fix" this by joining master attendees for exceptions.

- [ ] **Step 8: Run — expect PASS**

Run: `npx vitest run && npx tsc -b` — Expected: all green.

- [ ] **Step 9: Commit**

```bash
git add worker/services/zoned-time.ts worker/services/expansion.ts worker/__tests__/expansion.test.ts
git commit -m "feat: server-side occurrence expansion engine (RRULE + exceptions, DST-correct)"
```

---

### Task 5: Input validation + GET /api/events (expansion endpoint)

**Files:**
- Create: `worker/services/validation.ts`, `worker/routes/events.ts`
- Modify: `worker/services/expansion.ts` (allow `ownerId: string | null` — null = all calendars, for service callers), `worker/index.ts` (mount `eventRoutes`)
- Test: `worker/__tests__/events-read-route.test.ts`

**Interfaces:**
- Consumes: `listOccurrences`, `MAX_RANGE_DAYS`, `ExpansionLimitError`, `requestUserId`, `ensureDefaultCalendar`.
- Produces: `eventRoutes` (Hono router; Tasks 6–8 add write handlers to this SAME file/router); from `validation.ts`:
  - `isValidServiceSecret(configuredSecret: string | undefined, header: string | undefined): boolean` (copy of CRM's — passes when secret unset)
  - `TITLE_MAX = 200`, `DESCRIPTION_MAX = 2000`, `LOCATION_MAX = 500`
  - `validateEventInput(body: Record<string, unknown>, opts: { partial: boolean }): { error: string } | { error: null; value: CleanEventInput }` with `interface CleanEventInput { title?: string; description?: string | null; location?: string | null; startAt?: number; endAt?: number; allDay?: boolean; timezone?: string; recurrenceRule?: string | null; attendees?: { email: string; displayName: string | null }[] }`

- [ ] **Step 1: Write `worker/services/validation.ts`**

```ts
import { RRule } from 'rrule';
import { isValidTimezone } from './zoned-time';

export const TITLE_MAX = 200;
export const DESCRIPTION_MAX = 2000;
export const LOCATION_MAX = 500;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** Same semantics as eldrin-crm: when no secret is configured (standalone dev), allow. */
export function isValidServiceSecret(
  configuredSecret: string | undefined,
  header: string | undefined,
): boolean {
  if (!configuredSecret) return true;
  return header === configuredSecret;
}

export interface CleanEventInput {
  title?: string;
  description?: string | null;
  location?: string | null;
  startAt?: number;
  endAt?: number;
  allDay?: boolean;
  timezone?: string;
  recurrenceRule?: string | null;
  attendees?: { email: string; displayName: string | null }[];
}

function checkText(v: unknown, label: string, max: number, required: boolean): string | null {
  if (v === undefined || v === null) return required ? `${label} is required` : null;
  if (typeof v !== 'string') return `${label} must be a string`;
  if (required && v.trim().length === 0) return `${label} is required`;
  if (v.length > max) return `${label} must be at most ${max} characters`;
  return null;
}

export function validateEventInput(
  body: Record<string, unknown>,
  opts: { partial: boolean },
): { error: string } | { error: null; value: CleanEventInput } {
  const value: CleanEventInput = {};
  const want = (k: string) => !opts.partial || body[k] !== undefined;

  if (want('title')) {
    const err = checkText(body.title, 'title', TITLE_MAX, true);
    if (err) return { error: err };
    value.title = (body.title as string).trim();
  }
  if (body.description !== undefined) {
    const err = checkText(body.description, 'description', DESCRIPTION_MAX, false);
    if (err) return { error: err };
    value.description = (body.description as string | null) ?? null;
  }
  if (body.location !== undefined) {
    const err = checkText(body.location, 'location', LOCATION_MAX, false);
    if (err) return { error: err };
    value.location = (body.location as string | null) ?? null;
  }
  if (want('startAt')) {
    if (typeof body.startAt !== 'number' || !Number.isFinite(body.startAt)) return { error: 'startAt must be a number (epoch ms)' };
    value.startAt = body.startAt;
  }
  if (want('endAt')) {
    if (typeof body.endAt !== 'number' || !Number.isFinite(body.endAt)) return { error: 'endAt must be a number (epoch ms)' };
    value.endAt = body.endAt;
  }
  if (value.startAt !== undefined && value.endAt !== undefined && value.endAt <= value.startAt) {
    return { error: 'endAt must be after startAt' };
  }
  if (body.allDay !== undefined) {
    if (typeof body.allDay !== 'boolean') return { error: 'allDay must be a boolean' };
    value.allDay = body.allDay;
  }
  if (want('timezone')) {
    if (typeof body.timezone !== 'string' || !isValidTimezone(body.timezone)) return { error: 'timezone must be a valid IANA timezone' };
    value.timezone = body.timezone;
  }
  if (body.recurrenceRule !== undefined) {
    if (body.recurrenceRule === null) {
      value.recurrenceRule = null;
    } else if (typeof body.recurrenceRule !== 'string') {
      return { error: 'recurrenceRule must be a string or null' };
    } else {
      try {
        RRule.parseString(body.recurrenceRule);
      } catch (e) {
        return { error: `recurrenceRule is not a valid RRULE: ${e instanceof Error ? e.message : 'parse error'}` };
      }
      value.recurrenceRule = body.recurrenceRule;
    }
  }
  if (body.attendees !== undefined) {
    if (!Array.isArray(body.attendees)) return { error: 'attendees must be an array' };
    const seen = new Set<string>();
    const cleaned: { email: string; displayName: string | null }[] = [];
    for (const raw of body.attendees) {
      const rec = raw as Record<string, unknown>;
      if (typeof rec?.email !== 'string' || !EMAIL_RE.test(rec.email)) return { error: 'attendees[].email must be a valid email address' };
      const email = rec.email.toLowerCase();
      if (seen.has(email)) continue;
      seen.add(email);
      cleaned.push({ email, displayName: typeof rec.displayName === 'string' ? rec.displayName.slice(0, 200) : null });
    }
    value.attendees = cleaned;
  }
  return { error: null, value };
}
```

- [ ] **Step 2: Adjust `listOccurrences` for service callers**

In `worker/services/expansion.ts`, change the signature to `args: { ownerId: string | null; ... }` and the owner filter line to:
```ts
  const owned = ownedRows.filter(
    (c) =>
      (args.ownerId === null || c.ownerId === args.ownerId) &&
      (!args.calendarIds || args.calendarIds.includes(c.id)),
  );
```

- [ ] **Step 3: Write the failing route tests**

`worker/__tests__/events-read-route.test.ts`:
```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { Hono } from 'hono';
import { createTestDb } from './test-db';
import type { Database } from '../db';
import { calendars, events } from '../db';
import { eventRoutes } from '../routes/events';

const SECRET = 'test-secret';
const mockEnv = { JWT_SECRET: SECRET } as Env;
const T0 = Date.UTC(2026, 6, 6, 8, 0, 0);
const HOUR = 3600000;

function createApp(db: Database) {
  const app = new Hono<{ Bindings: Env; Variables: { db: Database } }>();
  app.use('*', async (c, next) => {
    c.set('db', db);
    await next();
  });
  app.route('', eventRoutes);
  return app;
}

async function seed(db: Database) {
  await db.insert(calendars).values([
    { id: 'cal1', name: 'Mine', color: '#111111', ownerId: 'u1', isDefault: true, createdAt: 1, updatedAt: 1 },
    { id: 'cal2', name: 'Theirs', color: '#222222', ownerId: 'u2', isDefault: true, createdAt: 1, updatedAt: 1 },
  ]);
  await db.insert(events).values([
    { id: 'e1', calendarId: 'cal1', title: 'Mine', startAt: T0, endAt: T0 + HOUR, timezone: 'UTC', createdBy: 'u1', createdAt: 1, updatedAt: 1 },
    { id: 'e2', calendarId: 'cal2', title: 'Theirs', startAt: T0, endAt: T0 + HOUR, timezone: 'UTC', createdBy: 'u2', createdAt: 1, updatedAt: 1 },
  ]);
}

describe('GET /api/events', () => {
  let db: Database;
  let app: ReturnType<typeof createApp>;
  beforeEach(async () => {
    db = createTestDb();
    app = createApp(db);
    await seed(db);
  });

  it('returns the requesting user’s expanded occurrences', async () => {
    const res = await app.request(
      `/api/events?start=${T0 - HOUR}&end=${T0 + 2 * HOUR}`,
      { headers: { 'x-eldrin-user-id': 'u1' } }, mockEnv,
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.occurrences.map((o: { id: string }) => o.id)).toEqual(['e1']);
  });

  it('rejects missing/invalid/oversized ranges', async () => {
    const bad = ['?start=abc&end=1', `?start=${T0}&end=${T0}`, `?start=${T0}&end=${T0 + 401 * 86400000}`, ''];
    for (const qs of bad) {
      const res = await app.request(`/api/events${qs}`, { headers: { 'x-eldrin-user-id': 'u1' } }, mockEnv);
      expect(res.status, qs).toBe(400);
    }
  });

  it('filters by calendarIds', async () => {
    const res = await app.request(
      `/api/events?start=${T0 - HOUR}&end=${T0 + HOUR}&calendarIds=nope`,
      { headers: { 'x-eldrin-user-id': 'u1' } }, mockEnv,
    );
    expect((await res.json()).occurrences).toEqual([]);
  });

  it('service-secret caller with no user header sees all calendars', async () => {
    const res = await app.request(
      `/api/events?start=${T0 - HOUR}&end=${T0 + HOUR}`,
      { headers: { 'X-Eldrin-App-Secret': SECRET } }, mockEnv,
    );
    const body = await res.json();
    expect(body.occurrences.map((o: { id: string }) => o.id).sort()).toEqual(['e1', 'e2']);
  });

  it('anonymous caller without a valid secret is rejected', async () => {
    const res = await app.request(`/api/events?start=${T0 - HOUR}&end=${T0 + HOUR}`, {}, mockEnv);
    expect(res.status).toBe(401);
  });
});
```

- [ ] **Step 4: Run to verify failure** — `npx vitest run worker/__tests__/events-read-route.test.ts` → FAIL (module not found).

- [ ] **Step 5: Implement the read route in `worker/routes/events.ts`**

```ts
import { Hono } from 'hono';
import type { Database } from '../db';
import { listOccurrences, ExpansionLimitError, MAX_RANGE_DAYS } from '../services/expansion';
import { isValidServiceSecret } from '../services/validation';
import { ensureDefaultCalendar } from './calendars';

type Variables = { db: Database };

export const eventRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

const DAY_MS = 86400000;

eventRoutes.get('/api/events', async (c) => {
  const db = c.get('db');
  const start = Number(c.req.query('start'));
  const end = Number(c.req.query('end'));
  if (!Number.isFinite(start) || !Number.isFinite(end)) {
    return c.json({ error: 'start and end (epoch ms) are required' }, 400);
  }
  if (end <= start) return c.json({ error: 'end must be after start' }, 400);
  if (end - start > MAX_RANGE_DAYS * DAY_MS) {
    return c.json({ error: `Range must be at most ${MAX_RANGE_DAYS} days` }, 400);
  }
  const calendarIdsRaw = c.req.query('calendarIds');
  const calendarIds = calendarIdsRaw ? calendarIdsRaw.split(',').filter(Boolean) : undefined;

  // Owner resolution: user header wins; otherwise a valid service secret may read
  // across all calendars (spec §9 — CRM widget path). Anything else is rejected.
  const userId = c.req.header('x-eldrin-user-id') || c.req.header('x-user-id');
  let ownerId: string | null;
  if (userId) {
    ownerId = userId;
    await ensureDefaultCalendar(db, userId);
  } else if (
    c.req.header('X-Eldrin-App-Secret') !== undefined &&
    isValidServiceSecret(c.env.JWT_SECRET, c.req.header('X-Eldrin-App-Secret'))
  ) {
    ownerId = c.req.query('ownerId') || null;
  } else {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  try {
    const result = await listOccurrences(db, { ownerId, startMs: start, endMs: end, calendarIds });
    return c.json(result);
  } catch (error) {
    if (error instanceof ExpansionLimitError) return c.json({ error: error.message }, 400);
    throw error;
  }
});
```

Mount in `worker/index.ts`: `app.route('', eventRoutes);`

- [ ] **Step 6: Run — expect PASS** (`npx vitest run && npx tsc -b`), fix until green.

- [ ] **Step 7: Commit**

```bash
git add worker/services/validation.ts worker/services/expansion.ts worker/routes/events.ts worker/index.ts worker/__tests__/events-read-route.test.ts
git commit -m "feat: expanded-occurrences read endpoint with range guards and service-secret access"
```

---

### Task 6: Platform event emitter + POST /api/events

**Files:**
- Create: `worker/services/event-emitter.ts`
- Modify: `worker/routes/events.ts` (add POST + GET-by-id)
- Test: `worker/__tests__/events-write-route.test.ts`

**Interfaces:**
- Consumes: `validateEventInput`, tables, `requestUserId`.
- Produces (used by Tasks 7–8): from `event-emitter.ts` —
  - `interface CalendarEventPayload { eventId: string; calendarId: string; title: string; startAt: number; endAt: number; allDay: boolean; timezone: string; location: string | null; recurrenceRule: string | null; attendees: { email: string; name: string | null }[] }`
  - `buildEventPayload(row: EventRow, attendees: { email: string; displayName: string | null }[]): CalendarEventPayload`
  - `emitCalendarEventCreated(env: Env, payload: CalendarEventPayload): Promise<void>`
  - `emitCalendarEventUpdated(env: Env, payload: CalendarEventPayload, scope: string): Promise<void>`
  - `emitCalendarEventDeleted(env: Env, eventId: string, scope: string): Promise<void>`

- [ ] **Step 1: Write `worker/services/event-emitter.ts`** (modeled on `eldrin-crm/worker/services/event-emitter.ts` — read it first and mirror its client construction exactly)

```ts
import { createEventClient } from '@eldrin-project/eldrin-app-core';
import type { EventRow } from '../db';

const APP_ID = 'eldrin-calendar';

export interface CalendarEventPayload {
  eventId: string;
  calendarId: string;
  title: string;
  startAt: number;
  endAt: number;
  allDay: boolean;
  timezone: string;
  location: string | null;
  recurrenceRule: string | null;
  attendees: { email: string; name: string | null }[];
}

export function buildEventPayload(
  row: EventRow,
  attendees: { email: string; displayName: string | null }[],
): CalendarEventPayload {
  return {
    eventId: row.id,
    calendarId: row.calendarId,
    title: row.title,
    startAt: row.startAt,
    endAt: row.endAt,
    allDay: row.allDay,
    timezone: row.timezone,
    location: row.location,
    recurrenceRule: row.recurrenceRule,
    attendees: attendees.map((a) => ({ email: a.email, name: a.displayName })),
  };
}

function client(env: Env) {
  return createEventClient(env as unknown as Record<string, unknown>, APP_ID);
}

export async function emitCalendarEventCreated(env: Env, payload: CalendarEventPayload): Promise<void> {
  try {
    await client(env).emit('calendar.event.created', payload as unknown as Record<string, unknown>);
  } catch (error) {
    console.error('[calendar] emit calendar.event.created failed:', error);
  }
}

export async function emitCalendarEventUpdated(env: Env, payload: CalendarEventPayload, scope: string): Promise<void> {
  try {
    await client(env).emit('calendar.event.updated', { ...payload, scope } as unknown as Record<string, unknown>);
  } catch (error) {
    console.error('[calendar] emit calendar.event.updated failed:', error);
  }
}

export async function emitCalendarEventDeleted(env: Env, eventId: string, scope: string): Promise<void> {
  try {
    await client(env).emit('calendar.event.deleted', { eventId, scope });
  } catch (error) {
    console.error('[calendar] emit calendar.event.deleted failed:', error);
  }
}
```

If `createEventClient`'s emit signature differs (check `eldrin-app-core/src/events/client.ts`), adapt the call but keep this module's exported signatures fixed.

- [ ] **Step 2: Write the failing write-route tests**

`worker/__tests__/events-write-route.test.ts`:
```ts
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Hono } from 'hono';
import { createTestDb } from './test-db';
import type { Database } from '../db';
import { calendars, events, eventAttendees } from '../db';
import { eventRoutes } from '../routes/events';
import * as emitter from '../services/event-emitter';

vi.mock('../services/event-emitter', async (importOriginal) => {
  const mod = await importOriginal<typeof import('../services/event-emitter')>();
  return {
    ...mod,
    emitCalendarEventCreated: vi.fn().mockResolvedValue(undefined),
    emitCalendarEventUpdated: vi.fn().mockResolvedValue(undefined),
    emitCalendarEventDeleted: vi.fn().mockResolvedValue(undefined),
  };
});

const mockEnv = { JWT_SECRET: 'test-secret' } as Env;
const waited: Promise<unknown>[] = [];
const mockExecutionCtx = {
  waitUntil: (p: Promise<unknown>) => { waited.push(p); },
  passThroughOnException: () => {},
  props: {},
} as unknown as ExecutionContext;

const T0 = Date.UTC(2026, 6, 6, 8, 0, 0);
const HOUR = 3600000;

function createApp(db: Database) {
  const app = new Hono<{ Bindings: Env; Variables: { db: Database } }>();
  app.use('*', async (c, next) => {
    c.set('db', db);
    await next();
  });
  app.route('', eventRoutes);
  return app;
}

function post(app: ReturnType<typeof createApp>, body: unknown) {
  return app.request('/api/events', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-eldrin-user-id': 'u1' },
    body: JSON.stringify(body),
  }, mockEnv, mockExecutionCtx);
}

describe('POST /api/events', () => {
  let db: Database;
  let app: ReturnType<typeof createApp>;
  beforeEach(async () => {
    db = createTestDb();
    app = createApp(db);
    waited.length = 0;
    vi.clearAllMocks();
    await db.insert(calendars).values({ id: 'cal1', name: 'Mine', color: '#111111', ownerId: 'u1', isDefault: true, createdAt: 1, updatedAt: 1 });
  });

  const valid = {
    calendarId: 'cal1', title: 'Kickoff', startAt: T0, endAt: T0 + HOUR,
    timezone: 'Europe/Budapest',
    attendees: [{ email: 'Dana@Globex.example', displayName: 'Dana' }],
  };

  it('creates a single event, lowercases attendee emails, emits created', async () => {
    const res = await post(app, valid);
    expect(res.status).toBe(201);
    const { event } = await res.json();
    expect(event.title).toBe('Kickoff');
    const rows = await db.select().from(eventAttendees);
    expect(rows[0].email).toBe('dana@globex.example');
    await Promise.all(waited);
    expect(emitter.emitCalendarEventCreated).toHaveBeenCalledTimes(1);
    const payload = vi.mocked(emitter.emitCalendarEventCreated).mock.calls[0][1];
    expect(payload).toMatchObject({
      eventId: event.id, calendarId: 'cal1', title: 'Kickoff', startAt: T0, endAt: T0 + HOUR,
      allDay: false, timezone: 'Europe/Budapest', recurrenceRule: null,
      attendees: [{ email: 'dana@globex.example', name: 'Dana' }],
    });
  });

  it('creates a recurring master with a valid RRULE', async () => {
    const res = await post(app, { ...valid, recurrenceRule: 'FREQ=WEEKLY;BYDAY=MO' });
    expect(res.status).toBe(201);
    const [row] = await db.select().from(events);
    expect(row.recurrenceRule).toBe('FREQ=WEEKLY;BYDAY=MO');
  });

  it('rejects bad input', async () => {
    const cases = [
      { ...valid, title: 'x'.repeat(201) },
      { ...valid, endAt: T0 },
      { ...valid, timezone: 'Nope/Nope' },
      { ...valid, recurrenceRule: 'FREQ=NONSENSE' },
      { ...valid, attendees: [{ email: 'not-an-email' }] },
      { ...valid, calendarId: 'not-yours' },
    ];
    for (const body of cases) {
      const res = await post(app, body);
      expect([400, 404], JSON.stringify(body).slice(0, 60)).toContain(res.status);
    }
    expect(emitter.emitCalendarEventCreated).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 3: Run to verify failure** — POST route missing → 404 responses → tests FAIL.

- [ ] **Step 4: Implement POST + GET-by-id in `worker/routes/events.ts`**

Add imports: `and, eq` from drizzle-orm; `calendars, events, eventAttendees` and `EventRow` from `../db`; `generateId, now` from `../utils`; `validateEventInput` from `../services/validation`; `requestUserId` from `./calendars`; `buildEventPayload, emitCalendarEventCreated` from `../services/event-emitter`. Then:

```ts
/** Load a calendar owned by the user (404 otherwise). */
async function ownedCalendar(db: Database, ownerId: string, calendarId: string) {
  const [cal] = await db.select().from(calendars)
    .where(and(eq(calendars.id, calendarId), eq(calendars.ownerId, ownerId)));
  return cal ?? null;
}

eventRoutes.post('/api/events', async (c) => {
  const db = c.get('db');
  const ownerId = requestUserId(c);
  let body: Record<string, unknown>;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }
  if (typeof body.calendarId !== 'string') return c.json({ error: 'calendarId is required' }, 400);
  const checked = validateEventInput(body, { partial: false });
  if (checked.error) return c.json({ error: checked.error }, 400);
  const input = checked.value;
  if (!(await ownedCalendar(db, ownerId, body.calendarId))) {
    return c.json({ error: 'Calendar not found' }, 404);
  }

  const ts = now();
  const row = {
    id: generateId(), calendarId: body.calendarId,
    title: input.title!, description: input.description ?? null, location: input.location ?? null,
    startAt: input.startAt!, endAt: input.endAt!, allDay: input.allDay ?? false,
    timezone: input.timezone!, recurrenceRule: input.recurrenceRule ?? null,
    recurringEventId: null, originalStartTime: null, status: 'confirmed',
    externalId: null, createdBy: ownerId, createdAt: ts, updatedAt: ts,
  };
  await db.insert(events).values(row);
  const attendees = input.attendees ?? [];
  if (attendees.length > 0) {
    await db.insert(eventAttendees).values(
      attendees.map((a) => ({ id: generateId(), eventId: row.id, email: a.email, displayName: a.displayName })),
    );
  }
  c.executionCtx.waitUntil(
    emitCalendarEventCreated(c.env, buildEventPayload(row as EventRow, attendees)),
  );
  return c.json({ event: row, attendees }, 201);
});

eventRoutes.get('/api/events/:id', async (c) => {
  const db = c.get('db');
  const ownerId = requestUserId(c);
  const id = c.req.param('id');
  const [row] = await db.select().from(events).where(eq(events.id, id));
  if (!row || !(await ownedCalendar(db, ownerId, row.calendarId))) {
    return c.json({ error: 'Event not found' }, 404);
  }
  const attendees = await db.select().from(eventAttendees).where(eq(eventAttendees.eventId, id));
  return c.json({ event: row, attendees });
});
```

- [ ] **Step 5: Run — expect PASS** (`npx vitest run && npx tsc -b`).

- [ ] **Step 6: Commit**

```bash
git add worker/services/event-emitter.ts worker/routes/events.ts worker/__tests__/events-write-route.test.ts
git commit -m "feat: event creation with attendees + calendar.event.created emission"
```

---

### Task 7: Edit semantics — scope single / all / following

**Files:**
- Create: `worker/services/event-edits.ts`
- Modify: `worker/routes/events.ts` (PATCH handler)
- Test: `worker/__tests__/event-edits.test.ts`, extend `worker/__tests__/events-write-route.test.ts` (PATCH cases)

**Interfaces:**
- Consumes: `buildRule`, `wallMsInZone`, `zonedWallToUtcMs`, `CleanEventInput`, emitter.
- Produces (route + Task 8 use these):
  - `occurrenceExists(master: EventRow, originalStartTime: number): boolean` — the RRULE actually generates that slot (and no cancelled check here; pure rule check).
  - `editSingleOccurrence(db, master: EventRow, originalStartTime: number, patch: CleanEventInput): Promise<EventRow>` — upsert exception row.
  - `editAllInSeries(db, master: EventRow, patch: CleanEventInput): Promise<EventRow>`
  - `splitSeries(db, master: EventRow, originalStartTime: number, patch: CleanEventInput): Promise<{ oldMaster: EventRow; newMaster: EventRow }>`
  - `ruleToString(options: Partial<Options>): string` — bare `FREQ=...` string, never includes DTSTART.

**Semantics (spec §6):**
- `single` → exception row with the patched fields; unpatched fields copy from the master AT THAT OCCURRENCE (start/end shifted to the occurrence slot). `recurrenceRule` and `attendees` patches are rejected for this scope (400 at the route).
- `all` → patch the master row; exceptions keep their overrides. `startAt`/`endAt` patches move the SERIES ANCHOR (dtstart) — allowed.
- `following` → truncate the master's rule with `UNTIL` one second before the target occurrence (in fake-UTC wall space — our internal convention; provider adapters translate in 4b); create a new master starting at the target occurrence (with patch applied); re-point exceptions with `originalStartTime >= target` to the new master; copy master attendees to the new master. If the original rule used `COUNT`, the new master's COUNT = original − occurrences before the split; the old master swaps COUNT for UNTIL.

- [ ] **Step 1: Write the failing service tests**

`worker/__tests__/event-edits.test.ts`:
```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { createTestDb } from './test-db';
import type { Database, EventRow } from '../db';
import { calendars, events, eventAttendees } from '../db';
import { eq } from 'drizzle-orm';
import { occurrenceExists, editSingleOccurrence, editAllInSeries, splitSeries } from '../services/event-edits';
import { expandRows } from '../services/expansion';

const TZ = 'Europe/Budapest';
const MASTER_START = Date.UTC(2026, 2, 23, 8, 0, 0); // Mon 09:00 Budapest (CET)
const HOUR = 3600000;
const WEEK = 7 * 86400000;
const OCC2 = Date.UTC(2026, 2, 30, 7, 0, 0); // second occurrence (CEST)
const OCC3 = Date.UTC(2026, 3, 6, 7, 0, 0);

describe('event-edits', () => {
  let db: Database;
  let master: EventRow;

  beforeEach(async () => {
    db = createTestDb();
    await db.insert(calendars).values({ id: 'cal1', name: 'M', color: '#111111', ownerId: 'u1', isDefault: true, createdAt: 1, updatedAt: 1 });
    const row = {
      id: 'm1', calendarId: 'cal1', title: 'Weekly', description: null, location: null,
      startAt: MASTER_START, endAt: MASTER_START + HOUR, allDay: false, timezone: TZ,
      recurrenceRule: 'FREQ=WEEKLY;COUNT=6', recurringEventId: null, originalStartTime: null,
      status: 'confirmed', externalId: null, createdBy: 'u1', createdAt: 1, updatedAt: 1,
    };
    await db.insert(events).values(row);
    await db.insert(eventAttendees).values({ id: 'a1', eventId: 'm1', email: 'dana@globex.example', displayName: null });
    master = row as EventRow;
  });

  it('occurrenceExists is true only for generated slots', () => {
    expect(occurrenceExists(master, MASTER_START)).toBe(true);
    expect(occurrenceExists(master, OCC2)).toBe(true);
    expect(occurrenceExists(master, OCC2 + 1)).toBe(false);
  });

  it('editSingleOccurrence creates then updates ONE exception row', async () => {
    const exc = await editSingleOccurrence(db, master, OCC2, { title: 'Moved', startAt: OCC2 + 2 * HOUR, endAt: OCC2 + 3 * HOUR });
    expect(exc).toMatchObject({ recurringEventId: 'm1', originalStartTime: OCC2, title: 'Moved', startAt: OCC2 + 2 * HOUR });
    const again = await editSingleOccurrence(db, master, OCC2, { title: 'Moved again' });
    expect(again.id).toBe(exc.id); // upsert, not a second row
    expect(again.title).toBe('Moved again');
    expect((await db.select().from(events))).toHaveLength(2);
  });

  it('editAllInSeries patches the master, keeps exceptions', async () => {
    await editSingleOccurrence(db, master, OCC2, { title: 'Special' });
    const updated = await editAllInSeries(db, master, { title: 'Weekly v2' });
    expect(updated.title).toBe('Weekly v2');
    const rows = await db.select().from(events);
    expect(rows.find((r) => r.recurringEventId === 'm1')!.title).toBe('Special');
  });

  it('splitSeries truncates the head, creates the tail, re-points later exceptions, copies attendees', async () => {
    await editSingleOccurrence(db, master, OCC3, { title: 'Late exception' });
    const { oldMaster, newMaster } = await splitSeries(db, master, OCC2, { title: 'New era' });

    // Head now generates only occurrence 1
    const headOcc = expandRows([oldMaster], MASTER_START - HOUR, MASTER_START + 10 * WEEK);
    expect(headOcc).toHaveLength(1);

    // Tail: COUNT=6 minus 1 consumed = 5, starting at OCC2, patched title
    expect(newMaster.startAt).toBe(OCC2);
    expect(newMaster.title).toBe('New era');
    expect(newMaster.recurrenceRule).toContain('COUNT=5');
    const tailOcc = expandRows([newMaster], MASTER_START, MASTER_START + 20 * WEEK);
    expect(tailOcc).toHaveLength(5);

    // Later exception re-pointed to tail
    const excRows = (await db.select().from(events)).filter((r) => r.recurringEventId);
    expect(excRows).toHaveLength(1);
    expect(excRows[0].recurringEventId).toBe(newMaster.id);

    // Attendees copied to the tail
    const tailAttendees = await db.select().from(eventAttendees).where(eq(eventAttendees.eventId, newMaster.id));
    expect(tailAttendees.map((a) => a.email)).toEqual(['dana@globex.example']);
  });

  it('splitSeries with UNTIL keeps UNTIL on the tail', async () => {
    const untilRule = 'FREQ=WEEKLY;UNTIL=20260601T000000Z';
    await db.update(events).set({ recurrenceRule: untilRule }).where(eq(events.id, 'm1'));
    const fresh = { ...master, recurrenceRule: untilRule } as EventRow;
    const { newMaster } = await splitSeries(db, fresh, OCC2, {});
    expect(newMaster.recurrenceRule).toContain('UNTIL=');
    expect(newMaster.recurrenceRule).not.toContain('COUNT=');
  });
});
```

- [ ] **Step 2: Run to verify failure** — module not found.

- [ ] **Step 3: Implement `worker/services/event-edits.ts`**

```ts
import { RRule, type Options } from 'rrule';
import { and, eq, gte } from 'drizzle-orm';
import type { Database, EventRow } from '../db';
import { events, eventAttendees } from '../db';
import { buildRule } from './expansion';
import { wallMsInZone, zonedWallToUtcMs } from './zoned-time';
import type { CleanEventInput } from './validation';
import { generateId, now } from '../utils';

/** Bare RRULE string (no DTSTART line, no RRULE: prefix). */
export function ruleToString(options: Partial<Options>): string {
  const clean = { ...options, dtstart: null };
  return RRule.optionsToString(clean as Options)
    .split('\n')
    .filter((line) => line.startsWith('RRULE:'))
    .map((line) => line.replace(/^RRULE:/, ''))
    .join('');
}

/** Does the master's rule generate an occurrence exactly at originalStartTime? */
export function occurrenceExists(master: EventRow, originalStartTime: number): boolean {
  const rule = buildRule(master);
  const fake = wallMsInZone(originalStartTime, master.timezone);
  const hits = rule.between(new Date(fake - 1), new Date(fake + 1), true);
  return hits.some((d) => zonedWallToUtcMs(d.getTime(), master.timezone) === originalStartTime);
}

function applyPatch(base: EventRow, patch: CleanEventInput, ts: number): EventRow {
  return {
    ...base,
    title: patch.title ?? base.title,
    description: patch.description !== undefined ? patch.description : base.description,
    location: patch.location !== undefined ? patch.location : base.location,
    startAt: patch.startAt ?? base.startAt,
    endAt: patch.endAt ?? base.endAt,
    allDay: patch.allDay ?? base.allDay,
    timezone: patch.timezone ?? base.timezone,
    updatedAt: ts,
  };
}

export async function editSingleOccurrence(
  db: Database,
  master: EventRow,
  originalStartTime: number,
  patch: CleanEventInput,
): Promise<EventRow> {
  const ts = now();
  const [existing] = await db.select().from(events).where(and(
    eq(events.recurringEventId, master.id),
    eq(events.originalStartTime, originalStartTime),
  ));
  if (existing) {
    const updated = applyPatch(existing, patch, ts);
    await db.update(events).set({
      title: updated.title, description: updated.description, location: updated.location,
      startAt: updated.startAt, endAt: updated.endAt, allDay: updated.allDay,
      timezone: updated.timezone, status: 'confirmed', updatedAt: ts,
    }).where(eq(events.id, existing.id));
    return updated;
  }
  const duration = master.endAt - master.startAt;
  const slot: EventRow = {
    ...master,
    id: generateId(),
    recurrenceRule: null,
    recurringEventId: master.id,
    originalStartTime,
    startAt: originalStartTime,
    endAt: originalStartTime + duration,
    createdAt: ts,
    updatedAt: ts,
  };
  const exception = applyPatch(slot, patch, ts);
  await db.insert(events).values(exception);
  return exception;
}

export async function editAllInSeries(
  db: Database,
  master: EventRow,
  patch: CleanEventInput,
): Promise<EventRow> {
  const ts = now();
  const updated = {
    ...applyPatch(master, patch, ts),
    recurrenceRule: patch.recurrenceRule !== undefined ? patch.recurrenceRule : master.recurrenceRule,
  };
  await db.update(events).set({
    title: updated.title, description: updated.description, location: updated.location,
    startAt: updated.startAt, endAt: updated.endAt, allDay: updated.allDay,
    timezone: updated.timezone, recurrenceRule: updated.recurrenceRule, updatedAt: ts,
  }).where(eq(events.id, master.id));
  return updated;
}

export async function splitSeries(
  db: Database,
  master: EventRow,
  originalStartTime: number,
  patch: CleanEventInput,
): Promise<{ oldMaster: EventRow; newMaster: EventRow }> {
  const ts = now();
  const options = RRule.parseString(master.recurrenceRule ?? '');
  const fakeSplit = wallMsInZone(originalStartTime, master.timezone);

  // Head: everything strictly before the split.
  const headOptions: Partial<Options> = { ...options, until: new Date(fakeSplit - 1000), count: null };
  const headRule = ruleToString(headOptions);

  // Tail: remaining COUNT (if COUNT-based) or the original UNTIL.
  let tailOptions: Partial<Options> = { ...options };
  if (options.count) {
    const rule = buildRule(master);
    const consumed = rule.between(new Date(wallMsInZone(master.startAt, master.timezone) - 1), new Date(fakeSplit - 1), true).length;
    tailOptions = { ...options, count: Math.max(1, options.count - consumed) };
  }
  const tailRule = ruleToString(tailOptions);

  const duration = master.endAt - master.startAt;
  const tailBase: EventRow = {
    ...master,
    id: generateId(),
    startAt: originalStartTime,
    endAt: originalStartTime + duration,
    recurrenceRule: tailRule,
    createdAt: ts,
    updatedAt: ts,
  };
  const newMaster = { ...applyPatch(tailBase, patch, ts), recurrenceRule: tailRule };
  const oldMaster = { ...master, recurrenceRule: headRule, updatedAt: ts };

  await db.insert(events).values(newMaster);
  await db.update(events).set({ recurrenceRule: headRule, updatedAt: ts }).where(eq(events.id, master.id));
  await db.update(events).set({ recurringEventId: newMaster.id }).where(and(
    eq(events.recurringEventId, master.id),
    gte(events.originalStartTime, originalStartTime),
  ));

  const masterAttendees = await db.select().from(eventAttendees).where(eq(eventAttendees.eventId, master.id));
  if (masterAttendees.length > 0) {
    await db.insert(eventAttendees).values(
      masterAttendees.map((a) => ({ id: generateId(), eventId: newMaster.id, email: a.email, displayName: a.displayName })),
    );
  }
  return { oldMaster, newMaster };
}
```

- [ ] **Step 4: Run service tests — expect PASS.** Iterate on rrule quirks until green (`npx vitest run worker/__tests__/event-edits.test.ts`).

- [ ] **Step 5: Add the PATCH route** to `worker/routes/events.ts`:

```ts
eventRoutes.patch('/api/events/:id', async (c) => {
  const db = c.get('db');
  const ownerId = requestUserId(c);
  const id = c.req.param('id');
  const scope = (c.req.query('scope') ?? 'all') as 'single' | 'following' | 'all';
  if (!['single', 'following', 'all'].includes(scope)) return c.json({ error: 'scope must be single|following|all' }, 400);

  let body: Record<string, unknown>;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }
  const checked = validateEventInput(body, { partial: true });
  if (checked.error) return c.json({ error: checked.error }, 400);
  const patch = checked.value;

  const [row] = await db.select().from(events).where(eq(events.id, id));
  if (!row || !(await ownedCalendar(db, ownerId, row.calendarId))) return c.json({ error: 'Event not found' }, 404);

  const finish = async (subject: EventRow, emitScope: string) => {
    const attendees = await db.select().from(eventAttendees).where(eq(eventAttendees.eventId, subject.id));
    c.executionCtx.waitUntil(emitCalendarEventUpdated(
      c.env,
      buildEventPayload(subject, attendees.map((a) => ({ email: a.email, displayName: a.displayName }))),
      emitScope,
    ));
    return c.json({ event: subject });
  };

  // Exception row: always a direct single edit; emitted against the MASTER id.
  if (row.recurringEventId) {
    const ts = now();
    const updated = { ...row, ...patchFields(row, patch), updatedAt: ts };
    await db.update(events).set(setClause(updated)).where(eq(events.id, row.id));
    const [masterRow] = await db.select().from(events).where(eq(events.id, row.recurringEventId));
    return finish({ ...(masterRow ?? updated) } as EventRow, 'single');
  }

  // Single (non-recurring) event.
  if (!row.recurrenceRule) {
    if (patch.attendees) await replaceAttendees(db, row.id, patch.attendees);
    const ts = now();
    const updated = { ...row, ...patchFields(row, patch), updatedAt: ts };
    await db.update(events).set(setClause(updated)).where(eq(events.id, row.id));
    return finish(updated as EventRow, 'all');
  }

  // Master row.
  if (scope === 'all') {
    if (patch.attendees) await replaceAttendees(db, row.id, patch.attendees);
    const updated = await editAllInSeries(db, row, patch);
    return finish(updated, 'all');
  }
  const originalStartTime = Number(body.originalStartTime);
  if (!Number.isFinite(originalStartTime)) return c.json({ error: 'originalStartTime is required for this scope' }, 400);
  if (!occurrenceExists(row, originalStartTime)) return c.json({ error: 'No occurrence at originalStartTime' }, 404);
  if (patch.attendees || patch.recurrenceRule !== undefined) {
    if (scope === 'single') return c.json({ error: 'attendees/recurrenceRule cannot be changed for a single occurrence' }, 400);
  }
  if (scope === 'single') {
    await editSingleOccurrence(db, row, originalStartTime, patch);
    return finish(row, 'single'); // series-level payload, master id (spec §7)
  }
  const { oldMaster, newMaster } = await splitSeries(db, row, originalStartTime, patch);
  const newAttendees = await db.select().from(eventAttendees).where(eq(eventAttendees.eventId, newMaster.id));
  c.executionCtx.waitUntil(emitCalendarEventCreated(
    c.env,
    buildEventPayload(newMaster, newAttendees.map((a) => ({ email: a.email, displayName: a.displayName }))),
  ));
  return finish(oldMaster, 'following');
});
```

With small private helpers in the same file:
```ts
function patchFields(base: EventRow, patch: CleanEventInput): Partial<EventRow> {
  return {
    title: patch.title ?? base.title,
    description: patch.description !== undefined ? patch.description : base.description,
    location: patch.location !== undefined ? patch.location : base.location,
    startAt: patch.startAt ?? base.startAt,
    endAt: patch.endAt ?? base.endAt,
    allDay: patch.allDay ?? base.allDay,
    timezone: patch.timezone ?? base.timezone,
  };
}

function setClause(row: EventRow) {
  const { id: _id, createdAt: _c, ...rest } = row;
  return rest;
}

async function replaceAttendees(db: Database, eventId: string, attendees: { email: string; displayName: string | null }[]) {
  await db.delete(eventAttendees).where(eq(eventAttendees.eventId, eventId));
  if (attendees.length > 0) {
    await db.insert(eventAttendees).values(
      attendees.map((a) => ({ id: generateId(), eventId, email: a.email, displayName: a.displayName })),
    );
  }
}
```

Cross-field validation the route must also enforce (add before dispatching on row kind): if BOTH `patch.startAt`/`patch.endAt` are absent but one is present, compare the present one against the row's other bound and 400 on inversion (`patch.startAt >= row.endAt` etc.).

- [ ] **Step 6: Extend `events-write-route.test.ts` with PATCH cases** — cover: patch single event title (200, emit updated scope=all); scope=single on master creates exception + emit updated with MASTER eventId and scope 'single'; scope=following returns old master + emits updated(following) AND created(new master); scope=single without `originalStartTime` → 400; `originalStartTime` not on the rule → 404; attendees patch with scope=single → 400; unknown id → 404; other user's event → 404. Follow the existing test file's helpers; assert emitter mocks like Task 6.

- [ ] **Step 7: Run everything — expect PASS** (`npx vitest run && npx tsc -b`).

- [ ] **Step 8: Commit**

```bash
git add worker/services/event-edits.ts worker/routes/events.ts worker/__tests__/event-edits.test.ts worker/__tests__/events-write-route.test.ts
git commit -m "feat: recurring-event edit semantics (single exception, all, following series split)"
```

---

### Task 8: Delete semantics — scope single / all / following

**Files:**
- Modify: `worker/routes/events.ts` (DELETE handler), `worker/services/event-edits.ts` (add `cancelOccurrence`, `truncateSeries`)
- Test: extend `worker/__tests__/event-edits.test.ts` + `worker/__tests__/events-write-route.test.ts`

**Interfaces:**
- Produces: `cancelOccurrence(db, master: EventRow, originalStartTime: number): Promise<void>` (upsert a `status='cancelled'` exception); `truncateSeries(db, master: EventRow, originalStartTime: number): Promise<EventRow>` (UNTIL cut + delete exceptions at/after; returns updated master).

- [ ] **Step 1: Write failing tests** — in `event-edits.test.ts`: `cancelOccurrence` removes that slot from expansion (and overwrites an existing moved exception at the same slot to cancelled); `truncateSeries` leaves only earlier occurrences and drops later exception rows. In `events-write-route.test.ts`: DELETE single event → row gone + emit deleted scope=all; DELETE master scope=all → master + exceptions + attendees gone + emit deleted scope=all; scope=single → occurrence cancelled + emit deleted scope=single (eventId = master id); scope=following → later occurrences gone + emit deleted scope=following; missing `originalStartTime` where required → 400; deleting an exception row id → that occurrence cancelled + emit deleted scope=single.

Representative service test to include:
```ts
it('cancelOccurrence hides the slot; truncateSeries cuts the tail', async () => {
  await cancelOccurrence(db, master, OCC2);
  let occ = expandRows(await allRows(db), MASTER_START - HOUR, MASTER_START + 10 * WEEK);
  expect(occ.map((o) => o.startAt)).not.toContain(OCC2);
  expect(occ).toHaveLength(5); // COUNT=6 minus 1 cancelled

  const updated = await truncateSeries(db, { ...master }, OCC3);
  occ = expandRows(await allRows(db, updated), MASTER_START - HOUR, MASTER_START + 20 * WEEK);
  expect(occ.every((o) => o.startAt < OCC3)).toBe(true);
});
```
(with a tiny local `allRows` helper selecting all event rows and substituting the updated master).

- [ ] **Step 2: Implement the service functions** in `event-edits.ts`:

```ts
export async function cancelOccurrence(db: Database, master: EventRow, originalStartTime: number): Promise<void> {
  const ts = now();
  const [existing] = await db.select().from(events).where(and(
    eq(events.recurringEventId, master.id),
    eq(events.originalStartTime, originalStartTime),
  ));
  if (existing) {
    await db.update(events).set({ status: 'cancelled', updatedAt: ts }).where(eq(events.id, existing.id));
    return;
  }
  const duration = master.endAt - master.startAt;
  await db.insert(events).values({
    ...master, id: generateId(), recurrenceRule: null, recurringEventId: master.id,
    originalStartTime, startAt: originalStartTime, endAt: originalStartTime + duration,
    status: 'cancelled', createdAt: ts, updatedAt: ts,
  });
}

export async function truncateSeries(db: Database, master: EventRow, originalStartTime: number): Promise<EventRow> {
  const ts = now();
  const options = RRule.parseString(master.recurrenceRule ?? '');
  const fakeSplit = wallMsInZone(originalStartTime, master.timezone);
  const headRule = ruleToString({ ...options, until: new Date(fakeSplit - 1000), count: null });
  await db.update(events).set({ recurrenceRule: headRule, updatedAt: ts }).where(eq(events.id, master.id));
  await db.delete(events).where(and(
    eq(events.recurringEventId, master.id),
    gte(events.originalStartTime, originalStartTime),
  ));
  return { ...master, recurrenceRule: headRule, updatedAt: ts };
}
```

- [ ] **Step 3: Implement the DELETE route**:

```ts
eventRoutes.delete('/api/events/:id', async (c) => {
  const db = c.get('db');
  const ownerId = requestUserId(c);
  const id = c.req.param('id');
  const scope = (c.req.query('scope') ?? 'all') as 'single' | 'following' | 'all';
  if (!['single', 'following', 'all'].includes(scope)) return c.json({ error: 'scope must be single|following|all' }, 400);

  const [row] = await db.select().from(events).where(eq(events.id, id));
  if (!row || !(await ownedCalendar(db, ownerId, row.calendarId))) return c.json({ error: 'Event not found' }, 404);

  const emitDeleted = (eventId: string, emitScope: string) =>
    c.executionCtx.waitUntil(emitCalendarEventDeleted(c.env, eventId, emitScope));

  // Deleting an exception row = cancelling that occurrence.
  if (row.recurringEventId) {
    await db.update(events).set({ status: 'cancelled', updatedAt: now() }).where(eq(events.id, row.id));
    emitDeleted(row.recurringEventId, 'single');
    return c.json({ deleted: true, scope: 'single' });
  }

  if (!row.recurrenceRule || scope === 'all') {
    await db.delete(events).where(eq(events.id, row.id)); // cascades exceptions + attendees
    emitDeleted(row.id, 'all');
    return c.json({ deleted: true, scope: 'all' });
  }

  const originalStartTime = Number(c.req.query('originalStartTime'));
  if (!Number.isFinite(originalStartTime)) return c.json({ error: 'originalStartTime is required for this scope' }, 400);
  if (!occurrenceExists(row, originalStartTime)) return c.json({ error: 'No occurrence at originalStartTime' }, 404);

  if (scope === 'single') {
    await cancelOccurrence(db, row, originalStartTime);
    emitDeleted(row.id, 'single');
    return c.json({ deleted: true, scope: 'single' });
  }
  await truncateSeries(db, row, originalStartTime);
  emitDeleted(row.id, 'following');
  return c.json({ deleted: true, scope: 'following' });
});
```

- [ ] **Step 4: Run — expect PASS** (`npx vitest run && npx tsc -b`). Then commit:

```bash
git add worker/services/event-edits.ts worker/routes/events.ts worker/__tests__
git commit -m "feat: event deletion with single/following/all scopes + calendar.event.deleted emission"
```

---

### Task 9: Frontend foundation — API client, sidebar, FullCalendar canvas, theming

No unit-test harness for the frontend (matches CRM). Gates: `npx tsc -b` + `npm run build` + a manual standalone smoke test.

**Files:**
- Create: `src/api.ts`, `src/components/CalendarSidebar.tsx`, `src/components/CalendarCanvas.tsx`
- Modify: `src/root.component.tsx` (replace stub), `src/index.css` (add `--fc-*` mapping)

**Interfaces:**
- Produces: everything Tasks 10–11 build on —
  - `src/api.ts` types `Calendar`, `Occurrence`, `EventDetail`, `Attendee` and helpers `listCalendars`, `createCalendar`, `deleteCalendar`, `listEvents`, `createEvent`, `patchEvent`, `deleteEvent` (signatures below).
  - `CalendarCanvas` props: `{ occurrences: Occurrence[]; onRangeChange: (startMs: number, endMs: number) => void; onSelectSlot: (startMs: number, endMs: number, allDay: boolean) => void; onSelectEvent: (occ: Occurrence) => void; onMoveResize: (occ: Occurrence, newStartMs: number, newEndMs: number, revert: () => void) => void; }`
  - `Root` holds state: `calendars`, `enabledIds: Set<string>`, `occurrences`, `range`, `modal` (Task 10 fills the modal).

- [ ] **Step 1: Write `src/api.ts`** (mirror `eldrin-crm/src/api.ts` conventions: `type Headers = Record<string, string>`, `apiUrl(base, path)` prefixes `/api`, shared `request<T>` that throws `Error(body.error)` on non-OK)

```ts
type Headers = Record<string, string>;

export interface Calendar {
  id: string; name: string; color: string; ownerId: string;
  isDefault: boolean; provider: string; externalId: string | null;
  createdAt: number; updatedAt: number;
}

export interface Attendee { email: string; displayName: string | null }

export interface Occurrence {
  id: string; seriesId: string | null; originalStartTime: number | null;
  calendarId: string; title: string; description: string | null; location: string | null;
  startAt: number; endAt: number; allDay: boolean; timezone: string;
  isRecurring: boolean; color: string; attendees: Attendee[];
}

export interface EventDetail {
  id: string; calendarId: string; title: string; description: string | null; location: string | null;
  startAt: number; endAt: number; allDay: boolean; timezone: string;
  recurrenceRule: string | null; recurringEventId: string | null; originalStartTime: number | null;
}

export interface EventInputBody {
  calendarId: string; title: string; description?: string | null; location?: string | null;
  startAt: number; endAt: number; allDay?: boolean; timezone: string;
  recurrenceRule?: string | null; attendees?: Attendee[];
}

export type EditScope = 'single' | 'following' | 'all';

function apiUrl(base: string, path: string): string {
  return `${base}/api${path}`;
}

async function request<T>(url: string, headers: Headers, init?: RequestInit): Promise<T> {
  const res = await fetch(url, { ...init, headers: { 'Content-Type': 'application/json', ...headers, ...(init?.headers as Headers) } });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error((body as { error?: string }).error || `Request failed: ${res.status}`);
  }
  return res.json();
}

export const listCalendars = (base: string, h: Headers) =>
  request<{ calendars: Calendar[] }>(apiUrl(base, '/calendars'), h);

export const createCalendar = (base: string, h: Headers, input: { name: string; color: string }) =>
  request<{ calendar: Calendar }>(apiUrl(base, '/calendars'), h, { method: 'POST', body: JSON.stringify(input) });

export const deleteCalendar = (base: string, h: Headers, id: string) =>
  request<{ deleted: boolean }>(apiUrl(base, `/calendars/${id}`), h, { method: 'DELETE' });

export const listEvents = (base: string, h: Headers, startMs: number, endMs: number, calendarIds?: string[]) => {
  const qs = new URLSearchParams({ start: String(startMs), end: String(endMs) });
  if (calendarIds && calendarIds.length > 0) qs.set('calendarIds', calendarIds.join(','));
  return request<{ occurrences: Occurrence[] }>(apiUrl(base, `/events?${qs}`), h);
};

export const createEvent = (base: string, h: Headers, input: EventInputBody) =>
  request<{ event: EventDetail }>(apiUrl(base, '/events'), h, { method: 'POST', body: JSON.stringify(input) });

export const getEvent = (base: string, h: Headers, id: string) =>
  request<{ event: EventDetail; attendees: Attendee[] }>(apiUrl(base, `/events/${id}`), h);

export const patchEvent = (
  base: string, h: Headers, id: string,
  patch: Partial<EventInputBody> & { originalStartTime?: number }, scope?: EditScope,
) =>
  request<{ event: EventDetail }>(
    apiUrl(base, `/events/${id}${scope ? `?scope=${scope}` : ''}`), h,
    { method: 'PATCH', body: JSON.stringify(patch) },
  );

export const deleteEvent = (base: string, h: Headers, id: string, scope?: EditScope, originalStartTime?: number) => {
  const qs = new URLSearchParams();
  if (scope) qs.set('scope', scope);
  if (originalStartTime !== undefined) qs.set('originalStartTime', String(originalStartTime));
  const suffix = qs.toString() ? `?${qs}` : '';
  return request<{ deleted: boolean }>(apiUrl(base, `/events/${id}${suffix}`), h, { method: 'DELETE' });
};
```

- [ ] **Step 2: Write `src/components/CalendarSidebar.tsx`**

```tsx
import { useState } from 'react';
import type { Calendar } from '../api';

interface CalendarSidebarProps {
  calendars: Calendar[];
  enabledIds: Set<string>;
  onToggle: (id: string) => void;
  onCreate: (name: string, color: string) => Promise<void>;
  onDelete: (id: string) => Promise<void>;
}

const PALETTE = ['#4f6df5', '#16a34a', '#f59e0b', '#dc2626', '#8b5cf6', '#0d9488'];

export function CalendarSidebar({ calendars, enabledIds, onToggle, onCreate, onDelete }: CalendarSidebarProps) {
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState('');
  const [color, setColor] = useState(PALETTE[0]);
  const [busy, setBusy] = useState(false);

  async function submit() {
    if (!name.trim() || busy) return;
    setBusy(true);
    try {
      await onCreate(name.trim(), color);
      setName('');
      setAdding(false);
    } finally {
      setBusy(false);
    }
  }

  return (
    <aside className="w-56 shrink-0 space-y-3">
      <h2 className="cal-eyebrow">Calendars</h2>
      <ul className="space-y-1">
        {calendars.map((cal) => (
          <li key={cal.id} className="flex items-center gap-2 text-sm group">
            <input
              type="checkbox"
              className="checkbox checkbox-xs"
              checked={enabledIds.has(cal.id)}
              onChange={() => onToggle(cal.id)}
            />
            <span className="w-3 h-3 rounded-full shrink-0" style={{ backgroundColor: cal.color }} />
            <span className="truncate flex-1">{cal.name}</span>
            {!cal.isDefault && (
              <button
                className="btn btn-ghost btn-xs opacity-0 group-hover:opacity-100"
                aria-label={`Delete ${cal.name}`}
                onClick={() => onDelete(cal.id)}
              >
                ✕
              </button>
            )}
          </li>
        ))}
      </ul>
      {adding ? (
        <div className="space-y-2">
          <input
            className="input input-bordered input-sm w-full"
            placeholder="Calendar name"
            value={name}
            maxLength={100}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && submit()}
          />
          <div className="flex gap-1">
            {PALETTE.map((p) => (
              <button
                key={p}
                className={`w-5 h-5 rounded-full border-2 ${color === p ? 'border-base-content' : 'border-transparent'}`}
                style={{ backgroundColor: p }}
                aria-label={p}
                onClick={() => setColor(p)}
              />
            ))}
          </div>
          <div className="flex gap-2">
            <button className="btn btn-primary btn-xs" disabled={busy} onClick={submit}>Add</button>
            <button className="btn btn-ghost btn-xs" onClick={() => setAdding(false)}>Cancel</button>
          </div>
        </div>
      ) : (
        <button className="btn btn-ghost btn-xs" onClick={() => setAdding(true)}>+ New calendar</button>
      )}
    </aside>
  );
}
```

- [ ] **Step 3: Write `src/components/CalendarCanvas.tsx`**

```tsx
import FullCalendar from '@fullcalendar/react';
import dayGridPlugin from '@fullcalendar/daygrid';
import timeGridPlugin from '@fullcalendar/timegrid';
import listPlugin from '@fullcalendar/list';
import interactionPlugin from '@fullcalendar/interaction';
import type { DateSelectArg, EventClickArg, EventDropArg, DatesSetArg } from '@fullcalendar/core';
import type { EventResizeDoneArg } from '@fullcalendar/interaction';
import type { Occurrence } from '../api';

interface CalendarCanvasProps {
  occurrences: Occurrence[];
  onRangeChange: (startMs: number, endMs: number) => void;
  onSelectSlot: (startMs: number, endMs: number, allDay: boolean) => void;
  onSelectEvent: (occ: Occurrence) => void;
  onMoveResize: (occ: Occurrence, newStartMs: number, newEndMs: number, revert: () => void) => void;
}

export function CalendarCanvas({ occurrences, onRangeChange, onSelectSlot, onSelectEvent, onMoveResize }: CalendarCanvasProps) {
  const events = occurrences.map((o) => ({
    id: o.id,
    title: o.title,
    start: new Date(o.startAt),
    end: new Date(o.endAt),
    allDay: o.allDay,
    backgroundColor: o.color,
    borderColor: o.color,
    extendedProps: { occ: o },
  }));

  function handleDropOrResize(arg: EventDropArg | EventResizeDoneArg) {
    const occ = arg.event.extendedProps.occ as Occurrence;
    const start = arg.event.start?.getTime();
    const end = arg.event.end?.getTime() ?? (start !== undefined ? start + (occ.endAt - occ.startAt) : undefined);
    if (start === undefined || end === undefined) {
      arg.revert();
      return;
    }
    onMoveResize(occ, start, end, arg.revert);
  }

  return (
    <div className="cal-root flex-1 min-w-0">
      <FullCalendar
        plugins={[dayGridPlugin, timeGridPlugin, listPlugin, interactionPlugin]}
        initialView="dayGridMonth"
        headerToolbar={{
          left: 'prev,next today',
          center: 'title',
          right: 'dayGridMonth,timeGridWeek,timeGridDay,listWeek',
        }}
        events={events}
        selectable
        selectMirror
        editable
        dayMaxEventRows
        height="auto"
        datesSet={(arg: DatesSetArg) => onRangeChange(arg.start.getTime(), arg.end.getTime())}
        select={(arg: DateSelectArg) => onSelectSlot(arg.start.getTime(), arg.end.getTime(), arg.allDay)}
        eventClick={(arg: EventClickArg) => onSelectEvent(arg.event.extendedProps.occ as Occurrence)}
        eventDrop={handleDropOrResize}
        eventResize={handleDropOrResize}
      />
    </div>
  );
}
```

- [ ] **Step 4: Rewrite `src/root.component.tsx`**

```tsx
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useAuthHeaders } from '@eldrin-project/eldrin-app-react';
import * as api from './api';
import type { Calendar, Occurrence } from './api';
import { CalendarSidebar } from './components/CalendarSidebar';
import { CalendarCanvas } from './components/CalendarCanvas';

export interface RootProps {
  manifest?: { baseUrl?: string };
}

export function Root({ manifest }: RootProps) {
  const apiBase = manifest?.baseUrl || '';
  const authHeaders = useAuthHeaders();
  const headersRef = useRef(authHeaders);
  headersRef.current = authHeaders;

  const [calendars, setCalendars] = useState<Calendar[]>([]);
  const [enabledIds, setEnabledIds] = useState<Set<string>>(new Set());
  const [occurrences, setOccurrences] = useState<Occurrence[]>([]);
  const [range, setRange] = useState<{ start: number; end: number } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadCalendars = useCallback(async () => {
    const res = await api.listCalendars(apiBase, headersRef.current);
    setCalendars(res.calendars);
    // First load enables everything; afterwards keep only ids that still exist and were enabled.
    setEnabledIds((prev) =>
      prev.size === 0
        ? new Set(res.calendars.map((c) => c.id))
        : new Set(res.calendars.filter((c) => prev.has(c.id)).map((c) => c.id)),
    );
    return res.calendars;
  }, [apiBase]);

  const refreshEvents = useCallback(async () => {
    if (!range) return;
    try {
      const ids = [...enabledIds];
      const res = await api.listEvents(apiBase, headersRef.current, range.start, range.end, ids);
      setOccurrences(ids.length === 0 ? [] : res.occurrences);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load events');
    }
  }, [apiBase, range, enabledIds]);

  useEffect(() => { loadCalendars().catch((e) => setError(e.message)); }, [loadCalendars]);
  useEffect(() => { refreshEvents(); }, [refreshEvents]);

  const handleToggle = (id: string) =>
    setEnabledIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });

  const handleCreateCalendar = async (name: string, color: string) => {
    await api.createCalendar(apiBase, headersRef.current, { name, color });
    const cals = await loadCalendars();
    setEnabledIds(new Set(cals.map((c) => c.id)));
  };

  const handleDeleteCalendar = async (id: string) => {
    await api.deleteCalendar(apiBase, headersRef.current, id);
    await loadCalendars();
    await refreshEvents();
  };

  // Tasks 10–11 replace these stubs with the modal + scope dialog:
  const handleSelectSlot = (_s: number, _e: number, _allDay: boolean) => {};
  const handleSelectEvent = (_occ: Occurrence) => {};
  const handleMoveResize = (_occ: Occurrence, _s: number, _e: number, revert: () => void) => revert();

  return (
    <div className="p-4 flex gap-6">
      <CalendarSidebar
        calendars={calendars}
        enabledIds={enabledIds}
        onToggle={handleToggle}
        onCreate={handleCreateCalendar}
        onDelete={handleDeleteCalendar}
      />
      <div className="flex-1 min-w-0">
        {error && <div className="alert alert-error text-sm mb-3">{error}</div>}
        <CalendarCanvas
          occurrences={occurrences}
          onRangeChange={(start, end) => setRange({ start, end })}
          onSelectSlot={handleSelectSlot}
          onSelectEvent={handleSelectEvent}
          onMoveResize={handleMoveResize}
        />
      </div>
    </div>
  );
}
```

Note the `setEnabledIds` block in `loadCalendars` above is intentionally the simplest correct behavior: on first load enable everything; after that, keep only ids that still exist and were enabled. If the double-loop version above reads confused when you implement it, replace with exactly:
```ts
setEnabledIds((prev) =>
  prev.size === 0
    ? new Set(res.calendars.map((c) => c.id))
    : new Set(res.calendars.filter((c) => prev.has(c.id)).map((c) => c.id)),
);
```

- [ ] **Step 5: Add FullCalendar theming to `src/index.css`**

```css
/* ─── FullCalendar ⇄ daisyUI token mapping ─────────────────────────────── */
.cal-root {
  --fc-border-color: var(--color-base-300);
  --fc-page-bg-color: var(--color-base-100);
  --fc-neutral-bg-color: var(--color-base-200);
  --fc-neutral-text-color: var(--color-base-content);
  --fc-today-bg-color: color-mix(in oklab, var(--color-primary) 8%, transparent);
  --fc-event-border-color: transparent;
  --fc-event-text-color: #ffffff;
  --fc-button-bg-color: var(--color-base-200);
  --fc-button-text-color: var(--color-base-content);
  --fc-button-border-color: var(--color-base-300);
  --fc-button-hover-bg-color: var(--color-base-300);
  --fc-button-hover-border-color: var(--color-base-300);
  --fc-button-active-bg-color: var(--color-primary);
  --fc-button-active-border-color: var(--color-primary);
  --fc-list-event-hover-bg-color: var(--color-base-200);
  --fc-highlight-color: color-mix(in oklab, var(--color-primary) 15%, transparent);
}
.cal-root .fc { font-size: 0.875rem; }
.cal-root .fc .fc-toolbar-title { font-size: 1.05rem; font-weight: 600; }
.cal-root .fc .fc-button { text-transform: none; box-shadow: none; }
.cal-root .fc .fc-button:focus { box-shadow: none; }

[data-theme='eldrin-dark'] .cal-root {
  --fc-today-bg-color: color-mix(in oklab, var(--color-primary) 14%, transparent);
}
```

The daisyUI `--color-*` variables flip automatically between the `eldrin` and `eldrin-dark` themes, so only genuinely dark-specific tweaks belong under `[data-theme='eldrin-dark']`.

- [ ] **Step 6: Verify**

```bash
npx tsc -b && npm run build
npm run dev   # open http://localhost:4012 — sidebar shows "My Calendar", month grid renders, view switcher works
```
Expected: builds clean; standalone page renders the themed calendar (no events yet). Stop the dev server after checking.

- [ ] **Step 7: Commit**

```bash
git add src/
git commit -m "feat: calendar UI foundation (sidebar, FullCalendar canvas, Quiet Ledger theming)"
```

---

### Task 10: Event modal (create + edit) with recurrence presets and attendees

**Files:**
- Create: `src/components/EventModal.tsx`
- Modify: `src/root.component.tsx` (wire `handleSelectSlot`/`handleSelectEvent` for create + non-recurring edit)

**Interfaces:**
- Produces: `EventModal` props —
  `{ mode: 'create' | 'edit'; calendars: Calendar[]; initial: { calendarId: string; title: string; description: string; location: string; startAt: number; endAt: number; allDay: boolean; recurrenceRule: string | null; attendees: Attendee[] }; busy: boolean; error: string | null; onSave: (body: EventInputBody) => void; onDelete?: () => void; onClose: () => void; }`
- Consumes: Task 9 API client. Recurring-event edit routing (scope dialog) is Task 11; in this task, clicking a RECURRING occurrence opens the modal read-populated but Save uses `scope` handling only for non-recurring events (recurring save/delete buttons stay disabled with a "next task" tooltip removed in Task 11).

- [ ] **Step 1: Write `src/components/EventModal.tsx`**

```tsx
import { useMemo, useState } from 'react';
import type { Attendee, Calendar, EventInputBody } from '../api';

export interface EventModalInitial {
  calendarId: string; title: string; description: string; location: string;
  startAt: number; endAt: number; allDay: boolean;
  recurrenceRule: string | null; attendees: Attendee[];
}

interface EventModalProps {
  mode: 'create' | 'edit';
  calendars: Calendar[];
  initial: EventModalInitial;
  busy: boolean;
  error: string | null;
  disableSeriesFields?: boolean; // true when editing via scope=single (Task 11)
  onSave: (body: EventInputBody) => void;
  onDelete?: () => void;
  onClose: () => void;
}

const WEEKDAYS = ['SU', 'MO', 'TU', 'WE', 'TH', 'FR', 'SA'];

function toLocalInput(ms: number): string {
  const d = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function presetFor(rule: string | null): string {
  if (!rule) return 'none';
  if (/^FREQ=DAILY(;|$)/.test(rule)) return 'daily';
  if (/^FREQ=WEEKLY;BYDAY=[A-Z]{2}$/.test(rule)) return 'weekly';
  if (/^FREQ=MONTHLY;BYMONTHDAY=\d+$/.test(rule)) return 'monthly';
  return 'custom';
}

export function EventModal({ mode, calendars, initial, busy, error, disableSeriesFields, onSave, onDelete, onClose }: EventModalProps) {
  const [calendarId, setCalendarId] = useState(initial.calendarId);
  const [title, setTitle] = useState(initial.title);
  const [description, setDescription] = useState(initial.description);
  const [location, setLocation] = useState(initial.location);
  const [start, setStart] = useState(toLocalInput(initial.startAt));
  const [end, setEnd] = useState(toLocalInput(initial.endAt));
  const [allDay, setAllDay] = useState(initial.allDay);
  const [preset, setPreset] = useState(presetFor(initial.recurrenceRule));
  const [customRule, setCustomRule] = useState(preset === 'custom' ? (initial.recurrenceRule ?? '') : '');
  const [attendees, setAttendees] = useState<Attendee[]>(initial.attendees);
  const [attendeeInput, setAttendeeInput] = useState('');

  const timezone = useMemo(() => Intl.DateTimeFormat().resolvedOptions().timeZone, []);

  function computedRule(startMs: number): string | null {
    const d = new Date(startMs);
    switch (preset) {
      case 'daily': return 'FREQ=DAILY';
      case 'weekly': return `FREQ=WEEKLY;BYDAY=${WEEKDAYS[d.getDay()]}`;
      case 'monthly': return `FREQ=MONTHLY;BYMONTHDAY=${d.getDate()}`;
      case 'custom': return customRule.trim() || null;
      default: return null;
    }
  }

  function addAttendee() {
    const email = attendeeInput.trim().toLowerCase();
    if (!email || attendees.some((a) => a.email === email)) return;
    setAttendees([...attendees, { email, displayName: null }]);
    setAttendeeInput('');
  }

  function save() {
    const startMs = new Date(start).getTime();
    const endMs = new Date(end).getTime();
    onSave({
      calendarId, title: title.trim(),
      description: description.trim() || null,
      location: location.trim() || null,
      startAt: startMs, endAt: endMs, allDay, timezone,
      recurrenceRule: disableSeriesFields ? undefined : computedRule(startMs),
      attendees: disableSeriesFields ? undefined : attendees,
    } as EventInputBody);
  }

  return (
    <dialog className="modal modal-open">
      <div className="modal-box max-w-lg space-y-3">
        <h3 className="cal-eyebrow">{mode === 'create' ? 'New event' : 'Edit event'}</h3>
        {error && <div className="alert alert-error text-sm py-2">{error}</div>}

        <input className="input input-bordered w-full" placeholder="Title" value={title}
          maxLength={200} onChange={(e) => setTitle(e.target.value)} />

        <div className="flex gap-2 items-center">
          <select className="select select-bordered select-sm flex-1" value={calendarId}
            onChange={(e) => setCalendarId(e.target.value)} disabled={mode === 'edit'}>
            {calendars.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
          <label className="label cursor-pointer gap-2 text-sm">
            <input type="checkbox" className="checkbox checkbox-xs" checked={allDay}
              onChange={(e) => setAllDay(e.target.checked)} />
            All day
          </label>
        </div>

        <div className="grid grid-cols-2 gap-2">
          <label className="form-control text-xs">
            Start
            <input type="datetime-local" className="input input-bordered input-sm" value={start}
              onChange={(e) => setStart(e.target.value)} />
          </label>
          <label className="form-control text-xs">
            End
            <input type="datetime-local" className="input input-bordered input-sm" value={end}
              onChange={(e) => setEnd(e.target.value)} />
          </label>
        </div>

        <input className="input input-bordered input-sm w-full" placeholder="Location" value={location}
          maxLength={500} onChange={(e) => setLocation(e.target.value)} />
        <textarea className="textarea textarea-bordered w-full" placeholder="Description" value={description}
          maxLength={2000} rows={2} onChange={(e) => setDescription(e.target.value)} />

        {!disableSeriesFields && (
          <div className="flex gap-2 items-center">
            <span className="text-xs text-base-content/60 shrink-0">Repeats</span>
            <select className="select select-bordered select-sm" value={preset} onChange={(e) => setPreset(e.target.value)}>
              <option value="none">Never</option>
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
              <option value="monthly">Monthly</option>
              <option value="custom">Custom RRULE…</option>
            </select>
            {preset === 'custom' && (
              <input className="input input-bordered input-sm flex-1 font-mono text-xs"
                placeholder="FREQ=WEEKLY;BYDAY=MO,WE" value={customRule}
                onChange={(e) => setCustomRule(e.target.value)} />
            )}
          </div>
        )}

        {!disableSeriesFields && (
          <div>
            <div className="flex gap-2">
              <input className="input input-bordered input-sm flex-1" placeholder="Attendee email"
                value={attendeeInput} onChange={(e) => setAttendeeInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && addAttendee()} />
              <button className="btn btn-ghost btn-sm" onClick={addAttendee}>Add</button>
            </div>
            {attendees.length > 0 && (
              <div className="flex flex-wrap gap-1 mt-2">
                {attendees.map((a) => (
                  <span key={a.email} className="badge badge-outline gap-1">
                    {a.email}
                    <button aria-label={`Remove ${a.email}`}
                      onClick={() => setAttendees(attendees.filter((x) => x.email !== a.email))}>✕</button>
                  </span>
                ))}
              </div>
            )}
          </div>
        )}

        <div className="modal-action justify-between">
          <div>
            {mode === 'edit' && onDelete && (
              <button className="btn btn-error btn-outline btn-sm" disabled={busy} onClick={onDelete}>Delete</button>
            )}
          </div>
          <div className="flex gap-2">
            <button className="btn btn-ghost btn-sm" onClick={onClose}>Cancel</button>
            <button className="btn btn-primary btn-sm" disabled={busy || !title.trim()} onClick={save}>
              {busy ? 'Saving…' : 'Save'}
            </button>
          </div>
        </div>
      </div>
      <div className="modal-backdrop" onClick={onClose} />
    </dialog>
  );
}
```

- [ ] **Step 2: Wire create + non-recurring edit in `root.component.tsx`**

Add state and handlers (recurring flows come in Task 11):

```tsx
type ModalState =
  | { kind: 'create'; startAt: number; endAt: number; allDay: boolean }
  | { kind: 'edit'; occ: Occurrence }
  | null;

const [modal, setModal] = useState<ModalState>(null);
const [modalBusy, setModalBusy] = useState(false);
const [modalError, setModalError] = useState<string | null>(null);

const handleSelectSlot = (startAt: number, endAt: number, allDay: boolean) =>
  setModal({ kind: 'create', startAt, endAt, allDay });

// IMPORTANT: occurrences do NOT carry the series RRULE. For recurring events,
// fetch the master first so the modal can show (and preserve!) the rule —
// otherwise a scope=all save would silently wipe the recurrence.
const handleSelectEvent = async (occ: Occurrence) => {
  if (occ.seriesId) {
    try {
      const { event } = await api.getEvent(apiBase, headersRef.current, occ.seriesId);
      setModal({ kind: 'edit', occ, seriesRule: event.recurrenceRule });
      return;
    } catch {
      /* fall through with rule unknown */
    }
  }
  setModal({ kind: 'edit', occ, seriesRule: null });
};
```
(Extend `ModalState`'s edit variant to `{ kind: 'edit'; occ: Occurrence; seriesRule: string | null }` and pass `recurrenceRule: modal.seriesRule` in the edit `initial` instead of the hardcoded `null`.)
```tsx

async function saveModal(body: api.EventInputBody) {
  if (!modal) return;
  setModalBusy(true);
  setModalError(null);
  try {
    if (modal.kind === 'create') {
      await api.createEvent(apiBase, headersRef.current, body);
    } else {
      const occ = modal.occ;
      const targetId = occ.seriesId && occ.id.includes('_') ? occ.seriesId : occ.id;
      // Non-recurring only in this task; recurring goes through the scope dialog (Task 11).
      await api.patchEvent(apiBase, headersRef.current, targetId, body);
    }
    setModal(null);
    await refreshEvents();
  } catch (e) {
    setModalError(e instanceof Error ? e.message : 'Save failed');
  } finally {
    setModalBusy(false);
  }
}

async function deleteFromModal() {
  if (!modal || modal.kind !== 'edit') return;
  setModalBusy(true);
  try {
    await api.deleteEvent(apiBase, headersRef.current, modal.occ.id);
    setModal(null);
    await refreshEvents();
  } catch (e) {
    setModalError(e instanceof Error ? e.message : 'Delete failed');
  } finally {
    setModalBusy(false);
  }
}
```

Render below the canvas:
```tsx
{modal && (
  <EventModal
    mode={modal.kind}
    calendars={calendars}
    busy={modalBusy}
    error={modalError}
    initial={
      modal.kind === 'create'
        ? { calendarId: calendars.find((c) => c.isDefault)?.id ?? calendars[0]?.id ?? '',
            title: '', description: '', location: '', startAt: modal.startAt, endAt: modal.endAt,
            allDay: modal.allDay, recurrenceRule: null, attendees: [] }
        : { calendarId: modal.occ.calendarId, title: modal.occ.title,
            description: modal.occ.description ?? '', location: modal.occ.location ?? '',
            startAt: modal.occ.startAt, endAt: modal.occ.endAt, allDay: modal.occ.allDay,
            recurrenceRule: null, attendees: modal.occ.attendees }
    }
    onSave={saveModal}
    onDelete={modal.kind === 'edit' ? deleteFromModal : undefined}
    onClose={() => { setModal(null); setModalError(null); }}
  />
)}
```

- [ ] **Step 3: Verify** — `npx tsc -b && npm run build`; `npm run dev`: drag-select a slot → modal opens → create an event with a weekly preset → it renders on the grid and repeats across weeks; click it → edit modal opens.

- [ ] **Step 4: Commit**

```bash
git add src/
git commit -m "feat: event modal with recurrence presets and attendee chips"
```

---

### Task 11: Scope dialog + recurring edit/delete + drag-and-drop

**Files:**
- Create: `src/components/ScopeDialog.tsx`
- Modify: `src/root.component.tsx` (route recurring saves/deletes/drags through the dialog)

**Interfaces:**
- Produces: `ScopeDialog` props `{ title: string; onPick: (scope: 'single' | 'following' | 'all') => void; onClose: () => void }`.

- [ ] **Step 1: Write `src/components/ScopeDialog.tsx`**

```tsx
import type { EditScope } from '../api';

interface ScopeDialogProps {
  title: string;
  onPick: (scope: EditScope) => void;
  onClose: () => void;
}

export function ScopeDialog({ title, onPick, onClose }: ScopeDialogProps) {
  return (
    <dialog className="modal modal-open">
      <div className="modal-box max-w-sm space-y-3">
        <h3 className="cal-eyebrow">{title}</h3>
        <div className="flex flex-col gap-2">
          <button className="btn btn-sm" onClick={() => onPick('single')}>This event</button>
          <button className="btn btn-sm" onClick={() => onPick('following')}>This and following events</button>
          <button className="btn btn-sm" onClick={() => onPick('all')}>All events</button>
        </div>
        <div className="modal-action">
          <button className="btn btn-ghost btn-sm" onClick={onClose}>Cancel</button>
        </div>
      </div>
      <div className="modal-backdrop" onClick={onClose} />
    </dialog>
  );
}
```

- [ ] **Step 2: Route recurring operations through the dialog in `root.component.tsx`**

Add state `const [scopeAsk, setScopeAsk] = useState<{ title: string; run: (scope: api.EditScope) => Promise<void>; cleanup?: () => void } | null>(null);` and helpers:

```tsx
/** PATCH an occurrence with the right target id + scope params. */
async function patchOccurrence(occ: Occurrence, body: Partial<api.EventInputBody>, scope: api.EditScope) {
  const isGenerated = occ.seriesId !== null && occ.id.includes('_');
  const targetId = isGenerated ? occ.seriesId! : occ.id;
  const payload = isGenerated && scope !== 'all'
    ? { ...body, originalStartTime: occ.originalStartTime ?? undefined }
    : body;
  await api.patchEvent(apiBase, headersRef.current, targetId, payload, isGenerated ? scope : undefined);
}

async function deleteOccurrence(occ: Occurrence, scope: api.EditScope) {
  const isGenerated = occ.seriesId !== null && occ.id.includes('_');
  const targetId = isGenerated ? occ.seriesId! : occ.id;
  await api.deleteEvent(
    apiBase, headersRef.current, targetId,
    isGenerated ? scope : undefined,
    isGenerated && scope !== 'all' ? (occ.originalStartTime ?? undefined) : undefined,
  );
}
```

Change `saveModal` (edit branch): when `modal.occ.isRecurring`, do NOT call the API directly — instead:
```tsx
setScopeAsk({
  title: 'Change recurring event',
  run: async (scope) => {
    // single-scope edits cannot carry series fields — strip them
    const patch = scope === 'single'
      ? { ...body, recurrenceRule: undefined, attendees: undefined }
      : body;
    await patchOccurrence(modal.occ, patch, scope);
    setScopeAsk(null);
    setModal(null);
    await refreshEvents();
  },
});
```
Change `deleteFromModal` the same way (`deleteOccurrence(modal.occ, scope)` with title `'Delete recurring event'`). Non-recurring events keep the direct path.

Replace `handleMoveResize`:
```tsx
const handleMoveResize = (occ: Occurrence, newStart: number, newEnd: number, revert: () => void) => {
  const body = { startAt: newStart, endAt: newEnd };
  const apply = async (scope: api.EditScope) => {
    try {
      await patchOccurrence(occ, body, scope);
      await refreshEvents();
    } catch (e) {
      revert();
      setError(e instanceof Error ? e.message : 'Move failed');
    }
  };
  if (!occ.isRecurring) {
    void apply('all');
    return;
  }
  setScopeAsk({
    title: 'Move recurring event',
    run: async (scope) => { setScopeAsk(null); await apply(scope); },
    cleanup: revert,
  });
};
```
Render the dialog:
```tsx
{scopeAsk && (
  <ScopeDialog
    title={scopeAsk.title}
    onPick={(scope) => { void scopeAsk.run(scope); }}
    onClose={() => { scopeAsk.cleanup?.(); setScopeAsk(null); }}
  />
)}
```
One subtlety: a drag with scope `following`/`all` moves the series ANCHOR — the backend applies `startAt` to the master/new-master, which is exactly Google's behavior for "all"/"following" drags.

- [ ] **Step 3: Verify** — `npx tsc -b && npm run build`; `npm run dev`: create a weekly event; drag one occurrence → dialog appears; "This event" moves only that one; edit → "All events" retitles every occurrence; delete → "This and following" truncates the series. Cancelling the dialog reverts the drag.

- [ ] **Step 4: Commit**

```bash
git add src/
git commit -m "feat: recurring-event scope dialog wired to edit, delete, and drag interactions"
```

---

### Task 12: CRM mirror — calendar.event.* → Meeting activities

Runs in `/Users/tibor/projects/eldrin-backup/eldrin-crm`. First step creates the CRM feature branch.

**Files:**
- Create: `worker/services/calendar-mirror.ts`, `worker/__tests__/calendar-mirror.test.ts`
- Modify: `worker/routes/events.ts` (add `calendar.event.*` cases to the existing `switch (envelope.type)`)

**Interfaces:**
- Consumes (all existing CRM code): `matchEmailsToContacts(db, rawAddresses: string[]): Promise<{ contactId: string; email: string }[]>` from `worker/services/email-linking.ts`; `activities` table; `generateId`, `now` from `../utils`; the webhook's envelope parsing + ack conventions (`{ received: true, handled: true, ... }`).
- Produces:
  - `interface CalendarEventMirrorPayload { eventId: string; title: string; startAt: number; endAt: number; allDay: boolean; timezone: string; location: string | null; recurrenceRule: string | null; attendees: { email: string; name: string | null }[] }`
  - `asCalendarEventPayload(payload: Record<string, unknown>): CalendarEventMirrorPayload | null` — shape guard.
  - `mirrorCalendarEvent(db: Database, payload: CalendarEventMirrorPayload): Promise<{ contactsMatched: number; created: number; updated: number }>`
  - `removeMirroredActivities(db: Database, eventId: string): Promise<number>`
  - Dedup key: `sourceMessageId = 'calendar:' + eventId` (one activity per contact per calendar event).
  - CRM's manifest already subscribes with `{ "pattern": "*", "delivery": "push" }` — NO manifest change needed for the mirror.

- [ ] **Step 1: Create the CRM branch**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-crm
git checkout main && git pull
git checkout -b feature/slice-4a-calendar-integration
npx vitest run   # confirm baseline green before touching anything
```

- [ ] **Step 2: Write the failing mirror tests**

`worker/__tests__/calendar-mirror.test.ts` (use `createTestDb` + seed a contact with a `contactEmails` row — copy the seeding style from `worker/__tests__/email-linking.test.ts`):
```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { createTestDb } from './test-db';
import type { Database } from '../db';
import { contacts, contactEmails, activities } from '../db';
import { asCalendarEventPayload, mirrorCalendarEvent, removeMirroredActivities } from '../services/calendar-mirror';

const T0 = 1700000000000;

describe('calendar mirror', () => {
  let db: Database;
  beforeEach(async () => {
    db = createTestDb();
    await db.insert(contacts).values({ id: 'ct1', firstName: 'Dana', lastName: 'Buyer', createdBy: 'system', createdAt: T0, updatedAt: T0 });
    await db.insert(contactEmails).values({ id: 'ce1', contactId: 'ct1', email: 'dana@globex.example', isPrimary: true, createdAt: T0 });
  });

  const payload = {
    eventId: 'ev-1', title: 'ERP kickoff', startAt: T0 + 86400000, endAt: T0 + 86400000 + 3600000,
    allDay: false, timezone: 'Europe/Budapest', location: 'Zoom',
    recurrenceRule: null as string | null,
    attendees: [{ email: 'dana@globex.example', name: 'Dana' }, { email: 'nobody@example.com', name: null }],
  };

  it('guards malformed payloads', () => {
    expect(asCalendarEventPayload({})).toBeNull();
    expect(asCalendarEventPayload({ eventId: 'x', title: 't', startAt: 'NaN' })).toBeNull();
    expect(asCalendarEventPayload(payload as unknown as Record<string, unknown>)).not.toBeNull();
  });

  it('creates one Meeting activity per matched contact', async () => {
    const res = await mirrorCalendarEvent(db, payload);
    expect(res).toEqual({ contactsMatched: 1, created: 1, updated: 0 });
    const [act] = await db.select().from(activities);
    expect(act).toMatchObject({
      typeId: 'type-meeting', title: 'ERP kickoff', dueDate: payload.startAt,
      durationMinutes: 60, relatedRecordId: 'ct1', relatedRecordType: 'contact',
      sourceMessageId: 'calendar:ev-1', createdBy: 'system', isRecurring: false,
    });
    expect(JSON.parse(act.metadata!)).toMatchObject({ calendarEventId: 'ev-1', location: 'Zoom' });
  });

  it('is idempotent and updates on redelivery', async () => {
    await mirrorCalendarEvent(db, payload);
    const res = await mirrorCalendarEvent(db, { ...payload, title: 'ERP kickoff v2', startAt: payload.startAt + 3600000, endAt: payload.endAt + 3600000 });
    expect(res).toEqual({ contactsMatched: 1, created: 0, updated: 1 });
    const rows = await db.select().from(activities);
    expect(rows).toHaveLength(1);
    expect(rows[0].title).toBe('ERP kickoff v2');
    expect(rows[0].dueDate).toBe(payload.startAt + 3600000);
  });

  it('records recurrence flags for recurring events', async () => {
    await mirrorCalendarEvent(db, { ...payload, recurrenceRule: 'FREQ=WEEKLY' });
    const [act] = await db.select().from(activities);
    expect(act.isRecurring).toBe(true);
    expect(act.recurrenceRule).toBe('FREQ=WEEKLY');
  });

  it('skips when no attendee matches', async () => {
    const res = await mirrorCalendarEvent(db, { ...payload, attendees: [{ email: 'nobody@example.com', name: null }] });
    expect(res).toEqual({ contactsMatched: 0, created: 0, updated: 0 });
    expect(await db.select().from(activities)).toHaveLength(0);
  });

  it('removeMirroredActivities soft-deletes all rows for the event', async () => {
    await mirrorCalendarEvent(db, payload);
    const n = await removeMirroredActivities(db, 'ev-1');
    expect(n).toBe(1);
    const [act] = await db.select().from(activities);
    expect(act.isDeleted).toBe(true);
  });
});
```
(Adjust the `contactEmails` seed columns to the actual schema — check `worker/db/schema.ts`; if `isPrimary`/`createdAt` differ, use the real column names.)

- [ ] **Step 3: Run to verify failure** — `npx vitest run worker/__tests__/calendar-mirror.test.ts` → module not found.

- [ ] **Step 4: Implement `worker/services/calendar-mirror.ts`**

```ts
import { and, eq } from 'drizzle-orm';
import type { Database } from '../db';
import { activities } from '../db';
import { matchEmailsToContacts } from './email-linking';
import { generateId, now } from '../utils';

export const MEETING_ACTIVITY_TYPE_ID = 'type-meeting';

export interface CalendarEventMirrorPayload {
  eventId: string;
  title: string;
  startAt: number;
  endAt: number;
  allDay: boolean;
  timezone: string;
  location: string | null;
  recurrenceRule: string | null;
  attendees: { email: string; name: string | null }[];
}

export function asCalendarEventPayload(payload: Record<string, unknown>): CalendarEventMirrorPayload | null {
  if (typeof payload.eventId !== 'string' || payload.eventId.length === 0) return null;
  if (typeof payload.title !== 'string') return null;
  if (typeof payload.startAt !== 'number' || typeof payload.endAt !== 'number') return null;
  const attendees = Array.isArray(payload.attendees)
    ? payload.attendees
        .filter((a): a is Record<string, unknown> => typeof a === 'object' && a !== null)
        .filter((a) => typeof a.email === 'string')
        .map((a) => ({ email: a.email as string, name: typeof a.name === 'string' ? a.name : null }))
    : [];
  return {
    eventId: payload.eventId,
    title: payload.title,
    startAt: payload.startAt,
    endAt: payload.endAt,
    allDay: payload.allDay === true,
    timezone: typeof payload.timezone === 'string' ? payload.timezone : 'UTC',
    location: typeof payload.location === 'string' ? payload.location : null,
    recurrenceRule: typeof payload.recurrenceRule === 'string' ? payload.recurrenceRule : null,
    attendees,
  };
}

/** Series-level mirror: one Meeting activity per matched contact per calendar event. */
export async function mirrorCalendarEvent(
  db: Database,
  payload: CalendarEventMirrorPayload,
): Promise<{ contactsMatched: number; created: number; updated: number }> {
  const matched = await matchEmailsToContacts(db, payload.attendees.map((a) => a.email));
  let created = 0;
  let updated = 0;
  const sourceMessageId = `calendar:${payload.eventId}`;
  const ts = now();
  const durationMinutes = Math.max(1, Math.round((payload.endAt - payload.startAt) / 60000));
  const metadata = JSON.stringify({
    calendarEventId: payload.eventId, location: payload.location, timezone: payload.timezone, allDay: payload.allDay,
  });

  for (const { contactId } of matched) {
    const [existing] = await db.select().from(activities).where(and(
      eq(activities.sourceMessageId, sourceMessageId),
      eq(activities.relatedRecordId, contactId),
      eq(activities.isDeleted, false),
    ));
    const fields = {
      title: payload.title,
      dueDate: payload.startAt,
      durationMinutes,
      isRecurring: payload.recurrenceRule !== null,
      recurrenceRule: payload.recurrenceRule,
      metadata,
      updatedAt: ts,
    };
    if (existing) {
      await db.update(activities).set(fields).where(eq(activities.id, existing.id));
      updated += 1;
    } else {
      await db.insert(activities).values({
        id: generateId(),
        typeId: MEETING_ACTIVITY_TYPE_ID,
        description: null,
        dueTime: null,
        priority: 'medium',
        status: 'pending',
        outcome: null,
        nextSteps: null,
        assigneeId: null,
        relatedRecordId: contactId,
        relatedRecordType: 'contact',
        parentActivityId: null,
        createdBy: 'system',
        createdAt: ts,
        completedAt: null,
        sourceMessageId,
        ...fields,
      });
      created += 1;
    }
  }
  return { contactsMatched: matched.length, created, updated };
}

/** Soft-delete every mirrored activity for a calendar event. Returns affected count. */
export async function removeMirroredActivities(db: Database, eventId: string): Promise<number> {
  const sourceMessageId = `calendar:${eventId}`;
  const rows = await db.select({ id: activities.id }).from(activities).where(and(
    eq(activities.sourceMessageId, sourceMessageId),
    eq(activities.isDeleted, false),
  ));
  for (const row of rows) {
    await db.update(activities).set({ isDeleted: true, updatedAt: now() }).where(eq(activities.id, row.id));
  }
  return rows.length;
}
```

- [ ] **Step 5: Run mirror tests — expect PASS.**

- [ ] **Step 6: Add the webhook cases** in `worker/routes/events.ts`, inside the existing `switch (envelope.type)` right before `default:`:

```ts
      case 'calendar.event.created':
      case 'calendar.event.updated': {
        const parsed = asCalendarEventPayload(envelope.payload);
        if (!parsed) return c.json({ error: 'Invalid calendar event payload' }, 400);
        const result = await mirrorCalendarEvent(db, parsed);
        return c.json({ received: true, handled: true, ...result });
      }
      case 'calendar.event.deleted': {
        const eventId = envelope.payload.eventId;
        const scope = envelope.payload.scope;
        if (typeof eventId !== 'string' || eventId.length === 0) {
          return c.json({ error: 'Invalid calendar event payload' }, 400);
        }
        // Series-level mirror: only a whole-event deletion removes activities.
        if (scope !== undefined && scope !== 'all') {
          return c.json({ received: true, handled: false });
        }
        const removed = await removeMirroredActivities(db, eventId);
        return c.json({ received: true, handled: true, removed });
      }
```
Import `asCalendarEventPayload, mirrorCalendarEvent, removeMirroredActivities` from `../services/calendar-mirror`.

- [ ] **Step 7: Extend `worker/__tests__/events-route.test.ts`** with webhook-level cases following its existing `post(app, body)` helper: `calendar.event.created` with a matching attendee → 200 `{handled: true, created: 1}` and an activity row exists; `calendar.event.deleted` scope `'single'` → `{handled: false}` and the activity survives; scope `'all'` → activity soft-deleted; malformed payload → 400.

- [ ] **Step 8: Run the FULL CRM suite — expect PASS** (`npx vitest run && npx tsc -b`; baseline was 166 tests, all must stay green).

- [ ] **Step 9: Commit**

```bash
git add worker/services/calendar-mirror.ts worker/routes/events.ts worker/__tests__/calendar-mirror.test.ts worker/__tests__/events-route.test.ts
git commit -m "feat: mirror calendar.event.* into Meeting activities via attendee-contact matching"
```

---

### Task 13: CRM upcoming-meetings endpoint (cross-app fetch)

**Files:**
- Create: `worker/services/upcoming-meetings.ts`, `worker/__tests__/upcoming-meetings.test.ts`
- Modify: `worker/routes/reports.ts`, `public/eldrin-app.manifest.json` (one new route entry)

**Interfaces:**
- Consumes: `matchEmailsToContacts`, `clampInt` pattern from `reports.ts`, env `ELDRIN_CORE_URL` (fallback `'http://localhost:4000'`) + `JWT_SECRET`.
- Produces:
  - `interface UpcomingMeeting { id: string; title: string; startAt: number; endAt: number; allDay: boolean; location: string | null; contacts: { id: string; name: string }[] }`
  - `getUpcomingMeetings(db: Database, env: Env, args: { days: number; nowMs: number; fetchImpl?: typeof fetch }): Promise<{ calendarAvailable: boolean; meetings: UpcomingMeeting[]; days: number }>`
  - Route: `GET /api/reports/upcoming-meetings?days=7` (days clamped [1, 31], default 7), permission `reports:read`.

- [ ] **Step 1: Write the failing tests**

`worker/__tests__/upcoming-meetings.test.ts`:
```ts
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createTestDb } from './test-db';
import type { Database } from '../db';
import { contacts, contactEmails } from '../db';
import { getUpcomingMeetings } from '../services/upcoming-meetings';

const T0 = 1700000000000;
const mockEnv = { JWT_SECRET: 'svc-secret', ELDRIN_CORE_URL: 'http://core.test' } as Env;

describe('getUpcomingMeetings', () => {
  let db: Database;
  beforeEach(async () => {
    db = createTestDb();
    await db.insert(contacts).values({ id: 'ct1', firstName: 'Dana', lastName: 'Buyer', createdBy: 'system', createdAt: T0, updatedAt: T0 });
    await db.insert(contactEmails).values({ id: 'ce1', contactId: 'ct1', email: 'dana@globex.example', isPrimary: true, createdAt: T0 });
  });

  it('fetches occurrences through the core proxy with the service secret and annotates contacts', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      occurrences: [
        { id: 'o1', title: 'Kickoff', startAt: T0 + 1000, endAt: T0 + 2000, allDay: false, location: null,
          attendees: [{ email: 'dana@globex.example', displayName: 'Dana' }] },
        { id: 'o2', title: 'Solo', startAt: T0 + 3000, endAt: T0 + 4000, allDay: false, location: 'HQ', attendees: [] },
      ],
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }));

    const res = await getUpcomingMeetings(db, mockEnv, { days: 7, nowMs: T0, fetchImpl });
    expect(res.calendarAvailable).toBe(true);
    expect(res.meetings).toHaveLength(2);
    expect(res.meetings[0].contacts).toEqual([{ id: 'ct1', name: 'Dana Buyer' }]);
    expect(res.meetings[1].contacts).toEqual([]);

    const [url, init] = fetchImpl.mock.calls[0];
    expect(String(url)).toBe(`http://core.test/api/app/eldrin-calendar/events?start=${T0}&end=${T0 + 7 * 86400000}`);
    expect((init.headers as Record<string, string>)['X-Eldrin-App-Secret']).toBe('svc-secret');
  });

  it('reports calendarAvailable=false on failure without throwing', async () => {
    for (const impl of [
      vi.fn().mockResolvedValue(new Response('nope', { status: 502 })),
      vi.fn().mockRejectedValue(new Error('network down')),
    ]) {
      const res = await getUpcomingMeetings(db, mockEnv, { days: 7, nowMs: T0, fetchImpl: impl });
      expect(res).toEqual({ calendarAvailable: false, meetings: [], days: 7 });
    }
  });
});
```

- [ ] **Step 2: Run to verify failure** — module not found.

- [ ] **Step 3: Implement `worker/services/upcoming-meetings.ts`**

```ts
import type { Database } from '../db';
import { matchEmailsToContacts } from './email-linking';
import { contacts } from '../db';
import { inArray } from 'drizzle-orm';

const CALENDAR_APP_ID = 'eldrin-calendar';
const DAY_MS = 86400000;
const FETCH_TIMEOUT_MS = 10000;

export interface UpcomingMeeting {
  id: string;
  title: string;
  startAt: number;
  endAt: number;
  allDay: boolean;
  location: string | null;
  contacts: { id: string; name: string }[];
}

interface RawOccurrence {
  id: string; title: string; startAt: number; endAt: number; allDay: boolean;
  location: string | null; attendees?: { email: string; displayName: string | null }[];
}

export async function getUpcomingMeetings(
  db: Database,
  env: Env,
  args: { days: number; nowMs: number; fetchImpl?: typeof fetch },
): Promise<{ calendarAvailable: boolean; meetings: UpcomingMeeting[]; days: number }> {
  const doFetch = args.fetchImpl ?? fetch;
  const coreUrl = ((env as { ELDRIN_CORE_URL?: string }).ELDRIN_CORE_URL || 'http://localhost:4000').replace(/\/+$/, '');
  const unavailable = { calendarAvailable: false, meetings: [], days: args.days };

  let occurrences: RawOccurrence[];
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    const res = await doFetch(
      `${coreUrl}/api/app/${CALENDAR_APP_ID}/events?start=${args.nowMs}&end=${args.nowMs + args.days * DAY_MS}`,
      { headers: { 'X-Eldrin-App-Secret': env.JWT_SECRET ?? '' }, signal: controller.signal },
    );
    clearTimeout(timer);
    if (!res.ok) return unavailable;
    const body = (await res.json()) as { occurrences?: RawOccurrence[] };
    occurrences = Array.isArray(body.occurrences) ? body.occurrences : [];
  } catch (error) {
    console.error('[crm] upcoming-meetings calendar fetch failed:', error);
    return unavailable;
  }

  // Match every attendee email in one pass, then annotate per occurrence.
  const allEmails = [...new Set(occurrences.flatMap((o) => (o.attendees ?? []).map((a) => a.email)))];
  const matched = allEmails.length > 0 ? await matchEmailsToContacts(db, allEmails) : [];
  const contactIdByEmail = new Map(matched.map((m) => [m.email.toLowerCase(), m.contactId]));
  const ids = [...new Set(matched.map((m) => m.contactId))];
  const nameRows = ids.length > 0
    ? await db.select({ id: contacts.id, firstName: contacts.firstName, lastName: contacts.lastName })
        .from(contacts).where(inArray(contacts.id, ids))
    : [];
  const nameById = new Map(nameRows.map((r) => [r.id, `${r.firstName} ${r.lastName ?? ''}`.trim()]));

  const meetings = occurrences
    .map((o) => {
      const seen = new Set<string>();
      const linked: { id: string; name: string }[] = [];
      for (const a of o.attendees ?? []) {
        const contactId = contactIdByEmail.get(a.email.toLowerCase());
        if (contactId && !seen.has(contactId)) {
          seen.add(contactId);
          linked.push({ id: contactId, name: nameById.get(contactId) ?? 'Unknown contact' });
        }
      }
      return {
        id: o.id, title: o.title, startAt: o.startAt, endAt: o.endAt,
        allDay: o.allDay === true, location: o.location ?? null, contacts: linked,
      };
    })
    .sort((a, b) => a.startAt - b.startAt);

  return { calendarAvailable: true, meetings, days: args.days };
}
```

- [ ] **Step 4: Add the route** in `worker/routes/reports.ts` (below gone-quiet, same style; add `import { getUpcomingMeetings } from '../services/upcoming-meetings';` at the top):

```ts
// ── Upcoming meetings (Slice 4a — cross-app read from eldrin-calendar) ──────

reportRoutes.get('/api/reports/upcoming-meetings', async (c) => {
  const db = c.get('db');
  const days = clampInt(c.req.query('days'), 7, 1, 31);
  const result = await getUpcomingMeetings(db, c.env, { days, nowMs: now() });
  return c.json(result);
});
```

- [ ] **Step 5: Add the manifest route entry** in `public/eldrin-app.manifest.json` next to the gone-quiet entry:

```json
      {
        "method": "GET",
        "path": "/api/reports/upcoming-meetings",
        "permission": "reports:read"
      },
```

- [ ] **Step 6: Run the FULL CRM suite + typecheck — expect PASS.**

- [ ] **Step 7: Commit**

```bash
git add worker/services/upcoming-meetings.ts worker/routes/reports.ts worker/__tests__/upcoming-meetings.test.ts public/eldrin-app.manifest.json
git commit -m "feat: upcoming-meetings report via core cross-app proxy with graceful degradation"
```

---

### Task 14: CRM UpcomingMeetingsWidget on the Dashboard

**Files:**
- Create: `src/components/reports/UpcomingMeetingsWidget.tsx`
- Modify: `src/api.ts` (types + helper), `src/pages/reports/Dashboard.tsx` (slot the widget)

**Interfaces:**
- Consumes: Task 13's endpoint; CRM's `api.ts` conventions (`request`, `apiUrl`); Dashboard props `{ apiBase, onNavigate }`.

- [ ] **Step 1: Add to `src/api.ts`** (next to the GoneQuiet types):

```ts
export interface UpcomingMeetingContact { id: string; name: string }

export interface UpcomingMeeting {
  id: string;
  title: string;
  startAt: number;
  endAt: number;
  allDay: boolean;
  location: string | null;
  contacts: UpcomingMeetingContact[];
}

export async function getUpcomingMeetings(
  base: string,
  headers: Headers,
  days: number,
): Promise<{ calendarAvailable: boolean; meetings: UpcomingMeeting[]; days: number }> {
  return request(apiUrl(base, `/reports/upcoming-meetings?days=${days}`), headers);
}
```

- [ ] **Step 2: Write `src/components/reports/UpcomingMeetingsWidget.tsx`** (mirrors GoneQuietWidget structure — self-fetching daisyUI card):

```tsx
import { useState, useEffect, useCallback, useRef } from 'react';
import { useAuthHeaders } from '@eldrin-project/eldrin-app-react';
import type { UpcomingMeeting } from '../../api';
import * as api from '../../api';

const PERIODS = [7, 14, 31] as const;

interface UpcomingMeetingsWidgetProps {
  apiBase: string;
  onNavigate?: (path: string) => void;
}

function dayLabel(ms: number): string {
  return new Intl.DateTimeFormat(undefined, { weekday: 'short', month: 'short', day: 'numeric' }).format(new Date(ms));
}

function timeLabel(m: UpcomingMeeting): string {
  if (m.allDay) return 'All day';
  const fmt = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' });
  return `${fmt.format(new Date(m.startAt))}–${fmt.format(new Date(m.endAt))}`;
}

/** Upcoming meetings from the eldrin-calendar app (Slice 4a) — cross-app read. */
export function UpcomingMeetingsWidget({ apiBase, onNavigate }: UpcomingMeetingsWidgetProps) {
  const authHeaders = useAuthHeaders();
  const headersRef = useRef(authHeaders);
  headersRef.current = authHeaders;

  const [days, setDays] = useState<number>(7);
  const [meetings, setMeetings] = useState<UpcomingMeeting[]>([]);
  const [available, setAvailable] = useState(true);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.getUpcomingMeetings(apiBase, headersRef.current, days);
      setMeetings(res.meetings);
      setAvailable(res.calendarAvailable);
    } finally {
      setLoading(false);
    }
  }, [apiBase, days]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const byDay = meetings.reduce<Map<string, UpcomingMeeting[]>>((acc, m) => {
    const key = dayLabel(m.startAt);
    acc.set(key, [...(acc.get(key) ?? []), m]);
    return acc;
  }, new Map());

  return (
    <div className="card bg-base-100 border border-base-300">
      <div className="card-body p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="crm-eyebrow">Upcoming Meetings</h3>
          <select
            className="select select-bordered select-xs"
            value={days}
            onChange={(e) => setDays(Number(e.target.value))}
          >
            {PERIODS.map((p) => (
              <option key={p} value={p}>{p} days</option>
            ))}
          </select>
        </div>
        {loading ? (
          <div className="skeleton h-24 w-full" />
        ) : !available ? (
          <p className="text-sm text-base-content/40 text-center py-8">
            Calendar app not connected.
          </p>
        ) : meetings.length === 0 ? (
          <p className="text-sm text-base-content/40 text-center py-8">
            No meetings in the next {days} days.
          </p>
        ) : (
          <div className="space-y-3">
            {[...byDay.entries()].map(([label, dayMeetings]) => (
              <div key={label}>
                <div className="crm-section-title mb-1">{label}</div>
                <ul className="space-y-1">
                  {dayMeetings.map((m) => (
                    <li key={m.id} className="flex items-center justify-between gap-2 text-sm">
                      <span className="truncate flex-1">
                        {m.title}
                        {m.contacts.length > 0 && (
                          <span className="text-base-content/50">
                            {' · '}
                            {m.contacts.map((ct, i) => (
                              <span key={ct.id}>
                                {i > 0 && ', '}
                                {onNavigate ? (
                                  <button
                                    className="link link-hover"
                                    onClick={() => onNavigate(`/eldrin-crm/contacts/${ct.id}`)}
                                  >
                                    {ct.name}
                                  </button>
                                ) : (
                                  ct.name
                                )}
                              </span>
                            ))}
                          </span>
                        )}
                      </span>
                      <span className="crm-num text-xs text-base-content/50 shrink-0">{timeLabel(m)}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
```

- [ ] **Step 3: Slot into the Dashboard** — in `src/pages/reports/Dashboard.tsx`, import the widget and add it inside the existing `grid grid-cols-1 lg:grid-cols-2 gap-6` block right after `<GoneQuietWidget ... />`:

```tsx
        <UpcomingMeetingsWidget apiBase={apiBase} onNavigate={onNavigate} />
```

- [ ] **Step 4: Verify + commit**

```bash
npx tsc -b && npm run build && npx vitest run
git add src/api.ts src/components/reports/UpcomingMeetingsWidget.tsx src/pages/reports/Dashboard.tsx
git commit -m "feat: Upcoming Meetings dashboard widget backed by eldrin-calendar"
```

---

### Task 15: Dev registration + end-to-end live validation

No new code — wiring and verification. Needs eldrin-core (port 4000), eldrin-calendar (4012), and eldrin-crm (4009) dev servers running.

- [ ] **Step 1: Start the stack**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-core && npm run dev &   # port 4000
cd /Users/tibor/projects/eldrin-backup/eldrin-calendar && npm run dev &  # port 4012
cd /Users/tibor/projects/eldrin-backup/eldrin-crm && npm run dev &    # port 4009
```

- [ ] **Step 2: Register the calendar app with core**

Login for a JWT (dev admin: `admin@eldrin.local` / `admin123`), then:
```bash
TOKEN=$(curl -s -X POST http://localhost:4000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@eldrin.local","password":"admin123"}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
curl -s -X POST http://localhost:4000/api/apps \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"app_url":"http://localhost:4012"}'
```
Expected: `201` with the app + manifest echoed. (409 "App already exists" is fine on re-runs; use `POST /api/apps/eldrin-calendar/sync-permissions` after manifest changes.) If the login response shape differs, extract the token field the core actually returns.

- [ ] **Step 3: Validate in the browser** (chrome-devtools MCP; login to the shell at http://localhost:4000)

1. "Calendar" appears in the side nav; the app loads with "My Calendar" seeded.
2. Create a single event with a CRM-known attendee email (e.g. the contact emails seeded by CRM dev data) → event renders.
3. Create a weekly recurring event → occurrences repeat across weeks; month/week/day/list views all render.
4. Drag one occurrence → scope dialog → "This event" → only that occurrence moves; reload to confirm persistence.
5. Edit series with "All events" → every occurrence updates. Delete with "This and following" → tail truncated.
6. CRM Dashboard → Upcoming Meetings widget lists the events; contact names link to contact pages.
7. CRM contact timeline (for the matched attendee) shows a Meeting activity; delete the calendar event (All) → activity disappears from the timeline (soft-deleted).
8. Toggle dark mode → calendar grid, modal, and widgets all readable in `eldrin-dark`.
9. Stop the eldrin-calendar dev server → CRM widget shows "Calendar app not connected." (no error toast); restart it.

Record findings; fix anything broken before proceeding.

- [ ] **Step 4: Parent repo gitlink**

After the eldrin-calendar repo has a GitHub remote (ask the human partner if it should be created under their org, or keep it local-only for now):
```bash
cd /Users/tibor/projects/eldrin-backup
git submodule add <remote-url> eldrin-calendar   # ONLY once a remote exists; otherwise defer
```
If no remote yet: leave the directory untracked and note it in the final report — do NOT `git add eldrin-calendar` as a plain directory.

- [ ] **Step 5: Final commits + suites**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-calendar && npx vitest run && npx tsc -b
cd /Users/tibor/projects/eldrin-backup/eldrin-crm && npx vitest run && npx tsc -b
```
Both green → the branch pair is ready for the finishing workflow (merge/PR decision is the human's).

---

## Self-Review Notes (author)

- Spec coverage: D1–D9 all mapped (D10 is 4b-only). §5 schema → Task 2; §6 API → Tasks 3, 5–8; §7 events → Tasks 6–8; §8 UI → Tasks 9–11; §9 CRM → Tasks 12–14; §10 validation → Tasks 3/5; §11 testing → per-task + Task 15.
- The `UNTIL` values we write live in fake-UTC wall space (internal convention, consistent with `buildRule`); spec §12 already flags that provider adapters translate in 4b.
- Known simplifications (spec-sanctioned): exceptions don't carry copied attendees (Task 4 note); mirror is series-level (spec §9); `calendar.event.updated` for single-scope edits carries the master's CURRENT series payload, not the exception's fields.





