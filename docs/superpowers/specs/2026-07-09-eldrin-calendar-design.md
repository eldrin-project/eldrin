# eldrin-calendar — Slice 4a Design (Standalone Calendar App Foundation)

**Date:** 2026-07-09
**Status:** Approved (brainstormed + section-by-section user approval)
**Predecessor:** CRM Phase 10 Slice 3b (merged 2026-07-08). Slice 4 decision of 2026-07-03: calendar is a **standalone marketplace app**, not an eldrin-email extension.

## 1. Context & Goal

Build the foundation of `eldrin-calendar`: a new standalone Eldrin extension app with local calendar/event management, a FullCalendar-based UI, and platform events that other apps consume. CRM is the first consumer (activity mirror + dashboard widget). Provider sync (Google first, then Outlook) is **Slice 4b** — this slice ships working software without any external provider.

## 2. Decisions

- **D1 — Standalone app** (user, 2026-07-03): own repo, manifest, D1 database, events, UI. Any app can integrate; CRM is merely the first consumer.
- **D2 — UI component = FullCalendar** (user, 2026-07-08): `@fullcalendar/react` with **MIT core plugins only** — `daygrid`, `timegrid`, `list`, `interaction`. No premium plugins ever (resource-timeline is paid). Chosen over React Big Calendar (no recurrence support) and Schedule-X (v4 paywalls drag/drop/resize).
- **D3 — Foundation first** (user, 2026-07-08): Slice 4a = local CRUD + UI + events + CRM consumption. Google sync = Slice 4b, own spec.
- **D4 — CRM consumes via BOTH mirror and widget** (user, 2026-07-08): event-bus mirror into Meeting activities AND an upcoming-meetings dashboard widget.
- **D5 — Full recurrence with exceptions** (user, 2026-07-08): edit-this-occurrence, this-and-following, and all-events semantics from day one, matching the provider model.
- **D6 — Multiple calendars** (user, 2026-07-08): calendars table with colors + sidebar visibility toggles; default calendar seeded lazily per user.
- **D7 — Server-side expansion, provider-shaped storage** (user, 2026-07-08): recurring events stored as master + exception rows; the worker expands RRULEs for a requested range; every consumer (own UI, CRM widget) reads expanded occurrences from one endpoint.
- **D8 — Provider-neutral internal model** (user, 2026-07-09): internal standard is **iCalendar RFC 5545 semantics** (RRULE + master/exception). Google is near-native; Microsoft Graph's structured recurrence converts deterministically to/from RRULE and its seriesMaster/occurrence/exception types map onto our rows; CalDAV is native. Provider integrations are **adapter modules** added in later slices; core CRUD/expansion/UI never know the provider. Schema carries `provider` + `external_id` columns from day one.
- **D9 — Local-first, standalone by default** (user, 2026-07-09): the calendar is fully functional with zero external providers. `provider='local'` calendars are first-class forever, not a fallback; no feature in any slice may require a connected provider account. Provider sync is purely additive.
- **D10 — Webhook-driven incremental sync** (user, 2026-07-09): provider sync (4b+) uses **push notifications as the trigger and sync tokens as the payload** — Google watch channels → `events.list` with `syncToken`; Microsoft Graph change-notification subscriptions (validation handshake + `clientState`) → delta query with `deltaToken`. Notifications carry no event data by design; each one triggers an incremental fetch. Channels/subscriptions expire (Google ~days, Graph ~3 days for calendars) → a renewal job keeps them alive, and a **low-frequency reconciliation poll** remains as safety net (also the only path in dev, where localhost cannot receive provider webhooks). No brute-force polling as the primary mechanism.

## 3. Scope

**In (4a):**
- New `eldrin-calendar` app: scaffold, manifest, D1 schema, migrations, worker API, single-spa React UI.
- Calendars CRUD (multiple calendars, colors, default calendar).
- Events CRUD incl. full recurrence (RRULE, exceptions, series split), attendees (email + display name).
- Server-side occurrence expansion endpoint.
- Platform events: `calendar.event.created` / `updated` / `deleted`.
- CRM: mirror handler (Meeting activities) + `UpcomingMeetingsWidget` + `/api/reports/upcoming-meetings` cross-app endpoint.

**Out (later slices):**
- Provider sync (Google 4b, Outlook 4c+): OAuth, token encryption, webhook-triggered incremental sync per D10 (watch channels / Graph subscriptions + sync/delta tokens, renewal job, reconciliation-poll fallback), `connected_accounts` table (modeled on eldrin-email's `connected_mailboxes`, whose provider enum already proves the multi-provider linked-account pattern).
- Attendee RSVP/response status, invitations, notifications, reminders.
- Free/busy, availability, scheduling links.
- Per-occurrence mirror granularity in CRM (mirror is series-level; see §9).

## 4. Architecture

```
eldrin-calendar (port 4012, own D1)
├── src/            React 19 + single-spa entry, FullCalendar UI, daisyUI "Quiet Ledger"
└── worker/         Hono 4 + Drizzle over D1
    ├── db/schema.ts
    ├── services/   recurrence expansion, event-emitter
    └── routes/     calendars, events, health, events-webhook (future consume)

eldrin-crm (existing)
├── worker/routes/events.ts        + calendar.event.* mirror branch
├── worker/routes/reports.ts       + GET /api/reports/upcoming-meetings (cross-app fetch)
└── src/components/reports/UpcomingMeetingsWidget.tsx
```

- Scaffold **structure** from `eldrin-templates/templates/cloudflare-react-sqlite` (manifest, worker bootstrap with `runMigrations` + `createPermissionMiddleware` + `createEventClient`, migrations generator, single-spa entry, `.dev.vars` with shared `JWT_SECRET`). Adopt **eldrin-crm's** daisyUI 5 Quiet Ledger design system and vitest + better-sqlite3 worker test harness instead of the template's shadcn components.
- New git repo, gitlinked as a parent-repo submodule like eldrin-crm/eldrin-email.
- Dev registration: run on 4012, `POST /api/apps` to eldrin-core (port 4000) with the app URL; core reads `/eldrin-app.manifest.json` and syncs permissions/routes.
- Migration filenames use the mandatory 14-digit timestamp prefix; `worker/migrations.generated.ts` stays gitignored and is regenerated via `npm run generate:migrations`.

## 5. Data Model (D1, Drizzle)

### `calendars`
| column | type | notes |
|---|---|---|
| id | text PK | uuid |
| name | text NOT NULL | ≤100 chars |
| color | text NOT NULL | hex, drives FullCalendar event color |
| owner_id | text NOT NULL | platform userId |
| is_default | integer NOT NULL default 0 | one per owner; lazily seeded "My Calendar" on first API access |
| provider | text NOT NULL default 'local' | 'local' now; 'google'/'outlook' in later slices |
| external_id | text NULL | provider calendar id (null for local) |
| created_at / updated_at | integer NOT NULL | epoch ms |

Index: `owner_id`.

### `events`
| column | type | notes |
|---|---|---|
| id | text PK | uuid |
| calendar_id | text NOT NULL FK → calendars.id ON DELETE CASCADE | |
| title | text NOT NULL | ≤200 chars |
| description | text NULL | ≤2000 chars |
| location | text NULL | ≤500 chars |
| start_at / end_at | integer NOT NULL | epoch ms UTC; `end_at > start_at` (all-day: end exclusive) |
| all_day | integer NOT NULL default 0 | |
| timezone | text NOT NULL | IANA name; RRULE expansion runs in this zone (DST-correct) |
| recurrence_rule | text NULL | RFC 5545 RRULE string; only on masters |
| recurring_event_id | text NULL FK → events.id ON DELETE CASCADE | set only on exception rows |
| original_start_time | integer NULL | epoch ms; the occurrence this exception replaces |
| status | text NOT NULL default 'confirmed' | 'confirmed' \| 'cancelled' (cancelled = deleted single occurrence) |
| external_id | text NULL | provider event id; unique per calendar when set |
| created_by | text NOT NULL | userId |
| created_at / updated_at | integer NOT NULL | epoch ms |

Indexes: `calendar_id`, `start_at`, `recurring_event_id`. Partial unique index `(calendar_id, external_id)` where `external_id` is not null.

Invariants:
- A row is a **master** (recurrence_rule set, recurring_event_id null), a **single event** (both null), or an **exception** (recurring_event_id + original_start_time set, recurrence_rule null).
- Exceptions never nest (an exception's recurring_event_id always points at a master).

### `event_attendees`
| column | type | notes |
|---|---|---|
| id | text PK | uuid |
| event_id | text NOT NULL FK → events.id ON DELETE CASCADE | |
| email | text NOT NULL | validated, lowercased |
| display_name | text NULL | |

Index: `event_id`. Unique `(event_id, email)`. No response/RSVP column in 4a.

## 6. API Surface

All routes behind `createPermissionMiddleware` per the manifest; platform envelope responses; permissions `calendar:read` / `calendar:write`.

- `GET /api/calendars` — owner's calendars (seeds default on first call).
- `POST /api/calendars` — `{name, color}`.
- `PATCH /api/calendars/:id` — name/color; 404 unknown.
- `DELETE /api/calendars/:id` — 409 if `is_default`; cascades events.
- `GET /api/events?start=<ms>&end=<ms>&calendarIds=a,b` — **expansion endpoint**. Returns concrete occurrences intersecting the range: singles pass through; masters expand via the `rrule` package in the event's timezone; exception rows replace (moved) or remove (cancelled) their occurrence. Occurrence shape: `{id, seriesId, originalStartTime, calendarId, title, startAt, endAt, allDay, timezone, location, description, attendees, isRecurring, color}` where `id = masterId` for singles and `` `${masterId}_${originalStartBasicISO}` `` for expanded instances (Google-style instance ids; basic ISO format `20260708T090000Z` — no colons/hyphens in the suffix). Guards: `end > start`, range ≤ 400 days, ≤ 1000 occurrences per response (400 error when exceeded).
- `GET /api/events/:id` — raw row (master/single/exception).
- `POST /api/events` — `{calendarId, title, startAt, endAt, allDay, timezone, location?, description?, attendees?, recurrenceRule?}`. RRULE validated by parsing; attendee emails validated; caps as in §5.
- `PATCH /api/events/:id?scope=single|following|all` (+ body `originalStartTime` when scope targets an occurrence of a series):
  - `single` → upsert exception row for that occurrence with the patched fields.
  - `all` → patch the master; existing exceptions keep their overrides.
  - `following` → **series split**: master RRULE gets `UNTIL` immediately before the target occurrence; new master created at the occurrence with patched fields + remaining rule; exceptions at/after the split re-point to the new master.
  - Non-recurring events accept only implicit/`all` scope.
- `DELETE /api/events/:id?scope=single|following|all` (+ `originalStartTime`):
  - `single` → insert `status='cancelled'` exception row.
  - `following` → truncate master RRULE with `UNTIL`; drop exceptions at/after the cut.
  - `all` → delete master (cascade removes exceptions + attendees).
- Errors: 400 validation (field-specific messages, RRULE parser message surfaced), 404 unknown id/occurrence, 409 default-calendar delete.

## 7. Platform Events (manifest `events.emits`)

| type | payload |
|---|---|
| `calendar.event.created` | `{eventId, calendarId, title, startAt, endAt, allDay, timezone, location, recurrenceRule, attendees: [{email, name}]}` |
| `calendar.event.updated` | same + `scope` |
| `calendar.event.deleted` | `{eventId, scope}` |

- Emitted for masters/singles on CRUD. `scope=single` exception edits emit `updated` with the **master's** eventId (mirror is series-level). A `following` split emits `updated` for the truncated old master and `created` for the new master.
- Emission via `createEventClient` inside `executionCtx.waitUntil`; failures logged, never block the response.

## 8. Frontend UI (eldrin-calendar)

- **FullCalendar** `@fullcalendar/react` + `@fullcalendar/daygrid` + `timegrid` + `list` + `interaction`. Server-expanded occurrences → no rrule plugin client-side.
- Layout: left sidebar (calendar list with color dots, visibility checkboxes, inline "+ New calendar" with name + color picker) + canvas with Month/Week/Day/List switcher, today/prev/next.
- FullCalendar `events` fed by a fetch function keyed on visible range + enabled calendarIds (re-fetch on view navigation and calendar toggles).
- **Event modal** (daisyUI): title, calendar select, start/end datetime, all-day toggle, location, description, attendee email chips, recurrence select — None / Daily / Weekly on <weekday> / Monthly on day <n> / Custom RRULE (raw string input, validated server-side). Timezone defaults from the browser (`Intl.DateTimeFormat().resolvedOptions().timeZone`).
- Editing a series occurrence (modal save, delete, drag-move, resize) → **scope dialog**: "This event / This and following / All events". Drag/resize applies optimistic update with rollback on API error + toast.
- Theming: map `--fc-*` CSS custom properties to daisyUI tokens (`--color-base-100/200/300`, content colors); dark overrides scoped to `[data-theme="dark"]` (NOT a `.dark` class). Event background = calendar color.
- Side-nav entry in manifest `ui.sideNav`: label "Calendar", path `/`.

## 9. CRM Integration (changes in eldrin-crm)

### Mirror (event-bus)
- Manifest `events.subscribes` += `{pattern: "calendar.event.*", delivery: "push"}`.
- Webhook handler branch in `worker/routes/events.ts`:
  - Match `attendees[].email` against contacts (same matching as email capture).
  - For each matched contact: create/update a **Meeting** activity — `typeId` = seeded Meeting type, `title`, `dueDate = startAt`, `durationMinutes = (endAt-startAt)/60000`, `isRecurring`/`recurrenceRule`, `relatedRecordId/Type = contact`, dedup key `metadata.calendarEventId = eventId` (one activity per contact per calendar event).
  - `calendar.event.updated` → update the mirrored activities' fields.
  - `calendar.event.deleted` (scope `all`) → delete mirrored activities.
  - Series-level granularity: per-occurrence exceptions do NOT alter the mirror (documented limitation, revisit in 4b).
  - No matched attendees → ack + skip. All failures ack 200 + `console.error` (never retry-storm core). Per-event try/catch so one bad payload can't poison a batch.

### Widget (cross-app read)
- `GET /api/reports/upcoming-meetings` (permission `reports:read`) in `worker/routes/reports.ts`:
  - Calls eldrin-calendar `GET /api/events?start=now&end=now+7d` **through the core proxy with `X-Eldrin-App-Secret`** (the same cross-app seam Slice 3's `call_app_api` proved; exact proxy URL shape pinned during planning).
  - Annotates occurrences with matched contact ids/names (attendee email → contact lookup).
  - Calendar app unreachable/not installed → `{calendarAvailable: false, meetings: []}` (200, not an error).
- `src/components/reports/UpcomingMeetingsWidget.tsx` — PipelineFunnel-style self-fetching card on the Dashboard: next-7-days list (day header, time, title, matched contact links via `onNavigate` with `/eldrin-crm` prefix); `calendarAvailable: false` → quiet "Calendar app not connected" note.

## 10. Error Handling & Validation

- All user input validated at the worker boundary: title ≤200, description ≤2000, location ≤500, calendar name ≤100, valid IANA timezone (checked via `Intl` or accepted-list fallback), `end > start`, RRULE must parse, attendee emails RFC-basic-validated + lowercased, range/occurrence caps (§6).
- Platform envelope `{success, data, error}` per existing app convention; field-specific 400 messages; no internals leaked.
- Event emission and mirror handling are fire-and-forget with logging (see §7, §9).

## 11. Testing (worker vitest + better-sqlite3 in-memory, CRM-style harness)

- **Expansion service:** daily/weekly/monthly RRULEs; DST boundary (e.g., Europe/Budapest spring-forward weekly 9:00); COUNT/UNTIL rules; moved exception replaces occurrence; cancelled exception removes it; range intersection edges; occurrence cap.
- **Event routes:** CRUD; all three PATCH scopes (exception upsert, master patch, series split incl. exception re-pointing); all three DELETE scopes; validation failures; occurrence-id/originalStartTime handling; instance-id format.
- **Calendar routes:** CRUD, default-calendar lazy seed, default-delete 409, cascade.
- **CRM mirror:** match/no-match, per-contact activity creation, dedup on repeat delivery, update propagation, delete-all removal, malformed payload ack.
- **CRM upcoming-meetings:** mocked cross-app fetch — happy path with contact annotation, unreachable → `calendarAvailable: false`.
- No frontend unit harness (matches CRM). Final task: live browser validation — full flow incl. recurring edit scopes, drag/resize, calendar toggles, CRM widget + mirrored activity on contact timeline, light + dark themes.

## 12. Risks & Mitigations

- **Series-split correctness** (following-scope) is the subtlest logic → dedicated service function with exhaustive unit tests before any route wiring.
- **FullCalendar theming vs Quiet Ledger:** `--fc-*` variable mapping is documented FullCalendar API; fallback is scoped CSS overrides on `.fc-*` classes. Validate visually in both themes early.
- **Cross-app proxy URL shape** for the CRM widget is assumed from the Slice 3 seam; pin the exact path during planning (read `eldrin-core/core/routes/apps.ts` proxy handler) before tasking.
- **Instance-id parsing:** `${masterId}_${ISO}` ids must round-trip; keep masterId a uuid (no underscores? uuids contain hyphens only — safe) and split on the LAST underscore defensively.
- **Timezone edge cases:** all expansion tests pin explicit zones; server never uses its own local zone.

## 13. Slice 4b Preview (context only, not in scope)

Per D9, everything below is additive — local calendars remain fully functional without it.

- `connected_accounts` table (per eldrin-email `connected_mailboxes`: encrypted tokens via JWT_SECRET-keyed AES, provider enum, sync cursor/status) + OAuth connect/callback routes (public in manifest, settings.groups GOOGLE CLIENT_ID/SECRET pattern).
- **Sync architecture per D10 — webhook-triggered incremental sync:**
  - Public, secret-validated notification endpoint per provider (e.g. `POST /api/sync/notify/google` verifying the channel token; Graph endpoint additionally answers the validation-token handshake and checks `clientState`).
  - Notification → enqueue incremental fetch (`events.list` + `syncToken` for Google; delta query + `deltaToken` for Graph) inside `waitUntil`; upsert through the provider adapter into the RFC 5545 model keyed by `(calendar_id, external_id)`.
  - Expired/invalidated sync token (Google 410 GONE) → full resync of that calendar.
  - **Renewal job** (wrangler cron `scheduled` handler): re-arm watch channels / Graph subscriptions before expiry; same cron does a low-frequency reconciliation poll as fallback — and is the sole sync path in dev, where provider webhooks cannot reach localhost.
- Google adapter (`worker/services/providers/google.ts`) first; Outlook adapter (Microsoft Graph, `providers/outlook.ts`) follows as 4c behind the same adapter interface (translate ⇄ RFC 5545, list-changes, watch/renew, write-back).
- Two-way write-back of local edits to the owning provider; per-occurrence CRM mirror granularity revisit; attendee RSVP status.
