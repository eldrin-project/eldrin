# eldrin-calendar — Slice 4c Design (Outlook/Microsoft Graph Sync + 4b Hardening)

**Date:** 2026-07-09
**Status:** Approved (brainstormed; approach + scope confirmed by user)
**Predecessor:** Slice 4b (Google sync, shipped 2026-07-09, eldrin-calendar main @ 64bfe74, 173 tests; spec `2026-07-09-google-calendar-sync-design.md`). Inherits D8 (RFC 5545 internal model), D9 (local-first), D10 (webhook-driven incremental sync), D11–D15 (two-way, user-selected calendars, write-through, real-account validation, provider-authoritative).

## 1. Context & Goal

Add two-way Outlook (Microsoft Graph) calendar sync behind the SAME `CalendarProvider` adapter interface 4b built — proving the multi-provider seam — and close 4b's deferred hardening items. A user connects a Microsoft account next to their Google one; Outlook calendars sync with full feature parity (selection, incremental pull, write-through incl. recurring scopes). Validation additionally live-tests the webhook push path for BOTH providers via an ngrok tunnel.

## 2. Decisions

- **D16 — Graph incremental sync = calendarView delta + master reconstruction** (user, 2026-07-09): Graph's only true delta is on `calendarView` (windowed). We use it as the change signal: `@removed` tombstones drive deletes; items with `type: seriesMaster | exception | singleInstance` upsert into the existing master+exception model; plain `type: occurrence` items are SKIPPED (derivable from their master — when an occurrence changes, Graph also emits its master or marks it an exception). Delta window: **-6 months to +18 months** from initial sync, stored `deltaToken` in `calendars.sync_token`; window re-anchoring = full resync when the window's far edge is closer than 6 months (checked during cron reconciliation) or on delta-token rejection (HTTP 410 `SyncStateNotFound`).
- **D17 — Recurrence: deterministic patternedRecurrence ⇄ RRULE for the mappable subset** (user, 2026-07-09): daily/weekly/absoluteMonthly/relativeMonthly/absoluteYearly/relativeYearly patterns with interval, daysOfWeek, dayOfMonth, index(weekIndex→BYSETPOS), month; range endDate→UNTIL / numbered→COUNT / noEnd. **Outbound** RRULEs Graph cannot express → `ProviderApiError(400)` surfaced as 502 "This recurrence is not supported by Outlook calendars" (request aborted, D13 semantics — no local write). **Inbound** unmappable recurrence → skip event with console.warn (4b convention, spec 4b §6).
- **D18 — Graph times normalized to UTC at the wire** (2026-07-09): all Graph reads send `Prefer: outlook.timezone="UTC"`; `start`/`end.dateTime` parse as real-UTC ms; the row's `timezone` comes from the event's `originalStartTimeZone` (fallback UTC). Outbound sends `dateTime` formatted in the event's IANA zone with `timeZone: <iana>` (Graph accepts IANA names). The 4b wall⇄UTC RRULE lesson applies: local wall-space UNTIL converts to a real date for Graph's `range.endDate` (and reverse) inside graph-translate — the conversion lives at the translation boundary, mirroring `ruleWallToUtc`/`ruleUtcToWall`.
- **D19 — returnTo hardening = origin allowlist** (user, 2026-07-09; closes 4b deferral): `isSafeReturnTo` additionally requires the returnTo **origin** to be in an allowlist: the request's own origin, `env.ELDRIN_CORE_URL` (fallback `http://localhost:4000`), and `env.PUBLIC_URL` when set. Applies to the existing Google flow AND the new Microsoft flow (shared helper).
- **D20 — Webhook live validation via ngrok, both providers** (user, 2026-07-09): validation arms a real Google watch channel AND a real Graph subscription against an ngrok HTTPS tunnel to :4012 (`PUBLIC_URL`=tunnel URL, `WEBHOOKS_ENABLED=true` in `.dev.vars` for the test), and verifies a real push notification triggers incremental sync for each. Graph's subscription-creation validation handshake (echo `validationToken` as text/plain 200) makes this the only way to even create a subscription.

## 3. Scope

**In (4c):**
- `oauth-outlook.ts` port (eldrin-email pattern) with scopes `offline_access Calendars.ReadWrite User.Read`; connect/callback routes `/api/oauth/microsoft/*` mirroring the Google ones (shared state/`connect-token` helpers extracted, not duplicated); manifest `settings.groups` MICROSOFT block; `provider='microsoft'` rows in `connected_accounts` (multi-provider enum was designed in from 4a/4b — no migration needed for accounts; see §4 for the one schema addition).
- `providers/graph-translate.ts` (pure: Graph event JSON ⇄ TranslatedEvent; patternedRecurrence ⇄ RRULE; UNTIL/endDate wall⇄real conversion) + `providers/outlook.ts` (fetch client implementing `CalendarProvider`: listCalendars, listChanges via calendarView delta, create/update/delete, getInstanceExternalId via `/events/{master}/instances`, watch/stopWatch via Graph subscriptions).
- Sync + write-through work UNCHANGED above the adapter (that's the parity proof); `providerForAccount`/`providerForCalendar` dispatch on `account.provider`.
- `POST /api/sync/notify/graph` (public): validationToken handshake, clientState check (HMAC via `channelTokenFor`), waitUntil incremental sync. `renewWatches` arms/renews Graph subscriptions (≤3-day lifetime) alongside Google channels.
- UI: "Connect Microsoft" button; provider-labeled sidebar groups and account cards (email + provider badge); calendar-selection list works identically per account.
- Hardening: D19 returnTo allowlist; exception-row PATCH persists the resolved instance externalId (4b final-review deferral — `routes/events.ts` exception branch threads `pushEditOccurrence`'s return value into the local update); non-UTC inbound all-day translation test (Google + Graph).
- Validation: real Microsoft account (D14 pattern) + D20 ngrok webhook test for both providers.

**Out (later):**
- CalDAV or other providers; attendee RSVP; shared-mailbox calendars; Graph application-permission (app-only) mode — everything stays delegated.
- Outlook category/color mapping (calendar color from Graph's `hexColor` when present, else default).

## 4. Data Model

**No new tables and no migration in this slice** — all TEXT columns from 4b absorb the Graph values. `connected_accounts.provider` gains the value `'microsoft'`. Graph mapping onto existing columns: `calendars.external_id` = Graph calendar id; `calendars.sync_token` = the FULL `@odata.deltaLink` URL (it embeds window + token, so continuing the delta is one GET); `watch_channel_id` = Graph subscription id; `watch_resource_id` = the literal `'graph-subscription'` (Graph's unsubscribe needs only the subscription id — the column is meaningless for this provider but non-null marks an armed watch); `watch_expires_at` = subscription expiry ms. `events.external_id` = Graph event id (masters, exceptions, singles).

## 5. Worker Architecture

- `services/oauth-microsoft.ts` — port of eldrin-email's `oauth-outlook.ts`: `getMicrosoftAuthUrl`, `exchangeMicrosoftCode`, `refreshMicrosoftToken`, `getMicrosoftUserInfo` (Graph `/me`: `mail ?? userPrincipalName`), `revokeMicrosoftToken` (no-op — MS has no revoke endpoint; best-effort comment).
- `routes/oauth.ts` — refactor: extract shared `connect-token`/state/redirect helpers; add `GET /api/oauth/microsoft/connect` + `GET /api/oauth/microsoft/callback` (public routes `/oauth/microsoft/connect`, `/oauth/microsoft/callback`); both flows use the D19 allowlist.
- `services/accounts.ts` — `freshAccessToken` branches on `account.provider` for the refresh call; `providerForAccount` returns `createGoogleProvider` or `createOutlookProvider`.
- `services/providers/graph-translate.ts` — pure translation:
  - `graphEventToTranslated(e, calTz): TranslatedEvent | null` — skips `type:'occurrence'`; `@removed` handled by the client (emitted as cancelled TranslatedEvents with just externalId); exception items carry `seriesMasterId` → `recurringExternalId` and Graph's `originalStart`/(fallback `originalStartTimeZone`+occurrence id timestamp) → `originalStartTime`.
  - `patternToRrule(rec: PatternedRecurrence, timezone): string | null` (null = unmappable → skip) and `rruleToPattern(rrule, startAtWallDate, timezone): PatternedRecurrence | null` (null = unsupported → ProviderApiError 400 at the client layer).
  - `outboundToGraphBody(e: OutboundEvent)` — subject/body/location/start/end (IANA tz)/recurrence/attendees.
- `services/providers/outlook.ts` — `createOutlookProvider(getToken)`:
  - `listCalendars` → `GET /me/calendars?$select=id,name,hexColor,isDefaultCalendar` (paged).
  - `listChanges(calExtId, syncToken)` → if token: GET the stored deltaLink; else initial `GET /me/calendars/{id}/calendarView/delta?startDateTime={now-6mo}&endDateTime={now+18mo}` (paged via `@odata.nextLink`, finish at `@odata.deltaLink`). For each changed series-related item, LAZILY fetch the seriesMaster (`GET /me/events/{seriesMasterId}?$select=...`) once per batch to translate its recurrence. Delta-token rejection (410 or `SyncStateNotFound`) → `fullResyncRequired: true`.
  - `createEvent/updateEvent/deleteEvent` → `POST/PATCH/DELETE /me/calendars/{id}/events[/{eventId}]` (delete tolerates 404).
  - `getInstanceExternalId(master, originalStartUtcMs)` → `GET /me/events/{master}/instances?startDateTime&endDateTime` (±1 day window around the occurrence), match by `originalStart`/start.
  - `watch` → `POST /subscriptions` `{changeType:"created,updated,deleted", resource:"/me/calendars/{id}/events", notificationUrl, clientState: token, expirationDateTime: now+4170min}`; `stopWatch` → `DELETE /subscriptions/{id}`.
  - Same retry-once-on-401, `ProviderApiError(status)`, pagination discipline as the Google client.
- `routes/sync.ts` — add `POST /api/sync/notify/graph` (public): if `?validationToken=` present → 200 text/plain echo (subscription handshake); else parse notification array, for each check `clientState === channelTokenFor(cal.id, JWT_SECRET)` (403 on mismatch), look up calendar by `watch_channel_id === subscriptionId`, waitUntil incremental sync. Unknown subscription → 202 no-op.
- `services/sync.ts` — `renewWatches` becomes provider-aware (the provider's own `watch` is already dispatched via `providerForCalendar`; only the address differs: `/api/sync/notify/google` vs `/api/sync/notify/graph` chosen by `account.provider`). Sync/upsert core untouched.
- `routes/events.ts` — hardening: exception-row branch persists `pushEditOccurrence`'s returned instance id (mirrors the single-scope path).
- Manifest: publicRoutes += `/oauth/microsoft/connect`, `/oauth/microsoft/callback`, `/sync/notify/graph`; api.routes: the existing connect-token route becomes provider-parameterized — ONE route `POST /api/oauth/:provider/connect-token` replaces `POST /api/oauth/google/connect-token` (manifest entry updated; the SettingsView is the only consumer and migrates in the same task); settings.groups += MICROSOFT (CLIENT_ID config, CLIENT_SECRET secret). Env += `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET` (dev values copied from eldrin-email/.dev.vars).

## 6. UI

- Settings: "Connect Microsoft" button beside "Connect Google"; account cards show a provider badge; the per-account calendar-list endpoint is RENAMED to `GET /api/accounts/:id/provider-calendars` (no alias — SettingsView is the only consumer and migrates in the same task; manifest api.routes entry updated).
- Sidebar: group synced calendars by provider with headings "Google" / "Outlook"; identical affordances.
- Event modal/scopes: zero changes (adapter parity).

## 7. Testing & Validation

- **Unit (fetch-stubbed Graph):** graph-translate round-trips — every mappable pattern type both directions, UNTIL/endDate wall⇄real conversion (positive + negative offset zones), unmappable-outbound → error, unmappable-inbound → skip; occurrence-skip logic; delta paging incl. `@removed` and `SyncStateNotFound` → full resync; subscription handshake (validationToken echo) + clientState 403; write-through scope mapping against the Graph client; provider dispatch in accounts.ts; D19 allowlist (own origin OK, core URL OK, evil.com → 400) for both providers' flows; exception-row externalId persistence; non-UTC inbound all-day (both translators). 4b's 173 tests stay green (D9 + Google regression).
- **Live validation (real Microsoft account + Graph ground-truth reads via the stored token):** connect → consent → calendar selection → initial import; write-through create/edit/delete; recurring round-trip (weekly create, single-occurrence move verified via `/instances`, following-truncate verified against `range.endDate`, scope=all delete); inbound pull via Sync now; Google-side regression smoke (one create/delete on GTF).
- **D20 webhook test (ngrok, both providers):** user opens `ngrok http 4012`; set `PUBLIC_URL=<tunnel>`, `WEBHOOKS_ENABLED=true` in `.dev.vars`; restart; trigger `renewWatches` (via `curl /__scheduled` with `--test-scheduled` or a temporary manual trigger); verify Google channel + Graph subscription rows armed; make a change in each provider's web UI; verify the notification arrives (worker logs) and the change lands locally WITHOUT pressing Sync now. Then revert `.dev.vars` (webhooks off) and stop channels best-effort.
- **User prerequisites (manual, before validation):** Entra app (same as eldrin-email): add delegated `Calendars.ReadWrite` permission; add redirect URI `http://localhost:4012/api/oauth/microsoft/callback` (type Web); copy client id/secret into eldrin-calendar `.dev.vars`. ngrok installed/authed for D20.

## 8. Risks

- **patternedRecurrence ⇄ RRULE** is the 4c analogue of 4b's translation risk → isolated pure module, exhaustive tests FIRST (both directions, all six pattern types, boundary UNTIL/endDate semantics — Graph's `endDate` is inclusive and date-only in `recurrenceTimeZone`).
- **calendarView delta occurrence-noise:** initial delta returns every occurrence in the window; the client must skip `type:'occurrence'` cheaply and dedupe master fetches per batch, or initial import of a busy calendar makes hundreds of master GETs. Batch-level `Map<seriesMasterId, master>` cache required.
- **Graph delta ordering is not guaranteed** (master may arrive after its exceptions): the sync core's two-pass parents-then-exceptions logic (4b Task 5) already handles this — verify with a test.
- **Subscription lifetime ≤ ~3 days** and creation REQUIRES a reachable notificationUrl: `renewWatches` must skip Graph subscriptions cleanly when webhooks are disabled (existing gate covers it).
- **Token semantics differ:** MS refresh tokens rotate on use (the refresh response contains a NEW refresh_token that MUST be persisted) — unlike Google. `freshAccessToken`'s microsoft branch persists both tokens.
- **eldrin-email consent overlap:** connecting the same MS account for mail and calendar are separate consents/apps records; no interference expected (different scopes), but validation should confirm eldrin-email's mailbox still works after the calendar consent (same Entra app).
