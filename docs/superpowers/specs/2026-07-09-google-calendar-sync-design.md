# eldrin-calendar — Slice 4b Design (Google Calendar Sync)

**Date:** 2026-07-09
**Status:** Approved (brainstormed; approach + scope confirmed by user)
**Predecessor:** Slice 4a (eldrin-calendar foundation, shipped 2026-07-09, main @ fc10910; spec `2026-07-09-eldrin-calendar-design.md`). Inherits decisions D8 (RFC 5545 internal model), D9 (local-first), D10 (webhook-driven incremental sync).

## 1. Context & Goal

Add two-way Google Calendar sync to `eldrin-calendar`. A user connects their Google account, picks which of its calendars to sync, and those calendars appear alongside local ones: Google changes flow in (webhook-triggered in prod, poll/manual in dev), and local edits to Google-backed events write through to Google. Per D9, everything here is additive — local calendars are untouched and remain first-class.

## 2. Decisions

- **D11 — Two-way sync** (user, 2026-07-09): Google → Eldrin import AND Eldrin → Google write-back in this slice. No read-only intermediate state.
- **D12 — User selects calendars** (user, 2026-07-09): after OAuth, the app lists the account's Google calendars and the user toggles which sync (primary pre-checked). Each enabled one becomes a `calendars` row with `provider='google'`.
- **D13 — Write-through write-back** (user, 2026-07-09): edits to Google-backed events call the Google API synchronously in the request path, then persist Google's authoritative response locally. Google failure → the edit fails visibly (502 + message), no local change, no divergence. No outbox/queue. Incoming upserts are idempotent by `(calendar_id, external_id)`, so the echo of our own write is a no-op.
- **D14 — Real-account dev validation** (user, 2026-07-09): browser validation (Chrome DevTools MCP) runs against a real Google account using the existing Cloud Console OAuth client (the one in `eldrin-email/.dev.vars`), extended with Calendar API + scopes and a `localhost:4012` redirect URI. Automated tests stub the Google API at fetch level.
- **D15 — Conflict policy: Google is authoritative for Google calendars** (derived from D13): incoming sync always wins for remote changes; write-through means outgoing changes are already Google state by the time they land locally. Both-sides-edited resolves as last-write-wins through the normal incremental fetch.

## 3. Scope

**In (4b):**
- `connected_accounts` table + AES-GCM token encryption (eldrin-email `crypto.ts` pattern, keyed off `JWT_SECRET`).
- Google OAuth connect/callback routes; manifest `settings.groups` GOOGLE CLIENT_ID/CLIENT_SECRET (same shape as eldrin-email).
- Google calendar listing + per-calendar sync enable/disable.
- Google adapter: event translation both directions (RFC 5545 ⇄ Google event JSON), incremental sync via `syncToken`, full resync on `410 GONE`.
- Incoming sync triggers: webhook notification endpoint (built + tested; channel registration behind config, off in dev), wrangler cron reconciliation poll, manual `POST /api/sync/run`.
- Write-through create/update/delete for events on `provider='google'` calendars, including recurring-event scopes (single occurrence, this-and-following, all).
- UI: Accounts/Sync settings view (connect, status, calendar toggles, Sync now, disconnect); synced calendars in the sidebar.
- Platform events (`calendar.event.created/updated/deleted`) emitted for synced changes so the CRM mirror keeps working.

**Out (later):**
- Outlook / Microsoft Graph adapter (4c) — but the adapter interface is shaped for it.
- Attendee RSVP status, invitations, notifications.
- Google watch-channel registration in production deployment docs / renewal tuning beyond the basic cron re-arm.
- Multiple Google accounts per user is supported by the schema (unique per account email) but the UI targets one account; multi-account polish is later.

## 4. Data Model

New table (one migration, `20260709150000-google-sync.sql` — 14-digit timestamp name, per platform rule):

```
connected_accounts
  id                text pk
  user_id           text notnull            -- eldrin user who connected
  provider          text notnull            -- 'google' (enum grows in 4c)
  email             text notnull            -- provider account email
  access_token_enc  text notnull            -- AES-GCM, JWT_SECRET-derived key
  refresh_token_enc text notnull
  token_expires_at  integer notnull         -- ms epoch
  status            text notnull default 'active'   -- active | error | revoked
  last_error        text
  created_at / updated_at  integer notnull
  unique(user_id, provider, email)
```

`calendars` gains sync bookkeeping (columns, not a new table, since sync state is per-calendar):

```
ALTER TABLE calendars ADD COLUMN account_id text;        -- fk → connected_accounts
ALTER TABLE calendars ADD COLUMN sync_token text;        -- Google nextSyncToken
ALTER TABLE calendars ADD COLUMN last_synced_at integer; -- ms epoch
ALTER TABLE calendars ADD COLUMN sync_status text;       -- ok | syncing | error (null for local)
ALTER TABLE calendars ADD COLUMN sync_error text;
```

`events.externalId` (exists since 4a) stores the Google event id; recurring exception rows store Google's instance id and map `recurringEventId`/`originalStartTime` directly (Google's model matches ours by construction, D8).

## 5. Worker Architecture

New modules (all under `eldrin-calendar/worker/`):

- `services/crypto.ts` — port of eldrin-email's AES-GCM encrypt/decrypt (JWT_SECRET-derived key).
- `services/oauth-google.ts` — port of eldrin-email's `oauth-gmail.ts` with scopes `calendar`, `calendar.events`, `userinfo.email`; `access_type=offline&prompt=consent`; state = signed nonce carrying userId.
- `services/providers/types.ts` — provider adapter interface: `listCalendars`, `listChanges(cal, syncToken?) → {upserts, deletes, nextSyncToken}`, `createEvent`, `updateEvent`, `deleteEvent`, `watch`/`stopWatch` (translate ⇄ RFC 5545 rows at this boundary; nothing above it knows Google shapes).
- `services/providers/google.ts` — the Google implementation over `fetch` to `www.googleapis.com/calendar/v3`: token refresh-on-401 via connected_accounts, pagination, `syncToken` handling, `410 GONE → full resync` signal, event translation (see §6).
- `services/sync.ts` — orchestration: `syncCalendar(calId)` (incremental or full), `syncAccount(accountId)`, initial import on enable; sets `sync_status`, emits platform events for changed rows, wraps everything in try/catch with `sync_error` persistence (no silent swallowing).
- `services/write-through.ts` — called by the existing event routes when the target calendar has `provider='google'`: maps the 4a edit scopes to Google (single → `events.patch` on instance id; this-and-following → UNTIL-split master + new master, mirroring 4a's local split; all → patch master; delete analogous), persists Google's response locally, returns the same shapes the local path returns.
- `routes/oauth.ts` — `GET /api/oauth/google/connect` (redirect), `GET /api/oauth/google/callback` (public route; exchanges code, encrypts tokens, upserts account, redirects back to the app's settings view).
- `routes/sync.ts` — `GET /api/accounts` (status), `DELETE /api/accounts/:id` (revoke + disconnect), `GET /api/accounts/:id/google-calendars` (live list w/ already-synced flags), `PUT /api/accounts/:id/calendars` (enable/disable set; enable creates the local calendar + kicks initial sync via `waitUntil`; disable confirms + deletes mirror rows), `POST /api/sync/run` (manual sync-now), `POST /api/sync/notify/google` (public; validates `X-Goog-Channel-Token` against an HMAC of the calendar id keyed by `JWT_SECRET` — set as the channel token at `watch` registration — then `waitUntil`s incremental sync).
- `index.ts` — add `scheduled` handler (wrangler cron `*/5 * * * *`): reconciliation poll over all `provider='google'` calendars + re-arm watch channels nearing expiry (no-op when webhooks disabled).

Manifest changes: `publicRoutes` += `/api/oauth/google/callback`, `/api/sync/notify/google`; new `settings.groups` GOOGLE block (CLIENT_ID config, CLIENT_SECRET secret) — identical shape to eldrin-email's. Dev uses `.dev.vars` (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `JWT_SECRET`).

## 6. Event Translation (the subtle part)

Bidirectional mapping in `providers/google.ts`, isolated and exhaustively unit-tested **before** any route wiring (same discipline as 4a's series-split):

- **Times:** Google `start/end.dateTime + timeZone` ⇄ `startAt/endAt` ms + `timezone`; all-day `start/end.date` ⇄ `allDay=true` (note Google all-day `end.date` is exclusive; ours is inclusive-by-duration — convert explicitly).
- **Recurrence:** Google `recurrence: ["RRULE:..."]` ⇄ `recurrenceRule` (strip/add the `RRULE:` prefix; EXDATE/RDATE lines out of scope — dropped with a logged warning, revisit if hit).
- **Exceptions:** Google instances with `recurringEventId` + `originalStartTime` ⇄ our exception rows; `status='cancelled'` instance ⇄ our cancelled exception row; cancelled master → delete series.
- **Fields:** summary⇄title, description, location, attendees (email + displayName; responseStatus ignored this slice).
- Unmappable inbound events (e.g. no start) are skipped with a warning, never crash the sync batch.

## 7. UI

- **Accounts view** (`/eldrin-calendar/settings` route in the app router + sidebar "Settings" link): connect-Google button (full-page redirect to `/api/oauth/google/connect`), account card (email, status, last sync, error if any), Google-calendar checkbox list, "Sync now" button, disconnect (confirm dialog; deletes synced calendars + events).
- **Sidebar:** synced calendars appear in a "Google" group with the same color/visibility/edit affordances as local ones (color + name edits stay local-only; Google is not written for calendar metadata).
- **Event modal:** unchanged UX on Google calendars — write-through is invisible on success; on failure the modal shows the error and keeps state (no partial save).
- Errors surface via the app's existing toast/error patterns; sync failures show on the account card, not as global noise.

## 8. Testing & Validation

- **Unit (Vitest, Google stubbed at fetch level):** translation round-trips (singles, all-day incl. exclusive-end, recurring masters, moved/cancelled exceptions, timezones), syncToken flow incl. `410` full-resync, token refresh-on-401, write-through scope mapping (single/following/all × create/update/delete), write-through failure leaves D1 untouched, notification endpoint auth (bad channel token → 403), crypto round-trip. Target: sustain the repo's 80%+ coverage bar; TDD per task.
- **Browser validation (Chrome DevTools MCP, real account per D14):** connect flow through real Google consent → callback lands on settings with account visible; pick a test calendar → initial import renders on the grid; create/edit/delete an event on the Google calendar in Eldrin → verify in Google via API read; change an event in Google (via API call) → "Sync now" pulls it in; disconnect removes the synced calendars. Also verify local calendars behave identically throughout (D9 regression).
- **Setup prerequisites (user-visible, documented in the plan):** enable Google Calendar API on the existing Cloud Console project; add scopes to the consent screen; add `http://localhost:4012/api/oauth/google/callback` to redirect URIs; copy client id/secret into `eldrin-calendar/.dev.vars`.

## 9. Risks

- **Recurrence translation** is the highest-risk logic → isolated module, tests first, route wiring only after green.
- **Google all-day exclusive end date** is a classic off-by-one → explicit tests both directions.
- **This-and-following write-through** requires a Google-side split (UNTIL-patch old master + insert new master) that must stay consistent with 4a's local split semantics → reuse the local split computation, translate its two outputs.
- **OAuth redirect mismatch** (Cloud Console allowlist) blocks validation → verify redirect URI setup as step 0 of browser validation.
- **Cron in dev:** `wrangler dev` supports `--test-scheduled`/`curl /__scheduled` but the manual "Sync now" button is the primary dev trigger; cron correctness is unit-tested.
