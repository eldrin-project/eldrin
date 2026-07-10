# CRM ↔ Email + Calendar: Assigned-Mailbox Integration — Design

**Date:** 2026-07-10
**Status:** Approved (user, 2026-07-10)
**Repos:** eldrin-crm (bulk), eldrin-email (additive payload fields), eldrin-calendar (no changes)

## 1. Problem

CRM↔email is deep in both directions (auto-capture + activity logging inbound via the event bus; send + templates outbound via the core proxy). CRM↔calendar is one-directional: `calendar.event.*` events mirror into Meeting activities and a dashboard widget reads upcoming occurrences, but **CRM cannot create calendar events** — the "Log meeting" quick-action is a local CRM activity only, so nothing syncs to Google/Outlook and no invite reaches attendees.

The user's model: **each contact/lead has an assigned mailbox** (the identity that owns the relationship). That assignment drives both the email FROM account and the calendar that receives scheduled meetings.

## 2. Current-state facts (verified 2026-07-10)

- eldrin-email `POST /api/email/send` (emails.ts:365) and `POST /api/email/send-template` (integration.ts:37) already accept optional `mailboxId`. CRM never passes it.
- eldrin-email `GET /api/mailboxes` (mailbox.ts:314) lists the user's connected mailboxes.
- `EmailReceivedPayload` (event-emitter.ts:32-45) does NOT carry the receiving mailbox's identity — gap for auto-assign.
- eldrin-calendar `POST /api/events` (routes/events.ts:89) is ownership-checked, accepts attendees; write-through pushes to Google/Outlook BEFORE the D1 write (provider sends invites); `calendar.event.created` is emitted after.
- eldrin-calendar `requestUserId` (routes/calendars.ts:24) resolves the auth context OR `x-eldrin-user-id` header — service-secret proxy calls can act for a named user (pattern already used by CRM's upcoming-meetings service).
- eldrin-calendar `GET /api/accounts` returns connected accounts with their calendars, scoped to the acting user.
- CRM mirror (`calendar-mirror.ts`) creates one `type-meeting` activity per matched contact, idempotent on `sourceMessageId = 'calendar:'+eventId`; metadata JSON holds calendar fields. Mirror currently links contacts only (not deals) and overwrites the activity wholesale on update.

## 3. Decisions

- **D0 — Standalone-first (governing principle).** CRM has NO hard dependency on eldrin-email or eldrin-calendar. Every integration feature in this spec is progressive enhancement: it appears only when the other app is installed/enabled (availability checks via the core app registry, the existing `detectEmailApp` pattern plus a new `detectCalendarApp`) and its absence never errors, blocks, or degrades core CRM flows. Concretely: no email app → mailbox selector, FROM pass-through, and auto-assign simply don't happen (columns stay null); no calendar app → the "Schedule meeting" button is hidden and the existing local Quick-log meeting remains the path (it is never removed); webhook handlers for absent apps just never fire. The same holds at runtime: a mid-flight proxy failure degrades per D7 rather than breaking the page. This principle governs every decision below and is the platform norm for all extensions: standalone by default, better together when available.

- **D1 — Assignment lives on the record.** `contacts` and `leads` gain `assigned_mailbox_id TEXT` and `assigned_mailbox_email TEXT` (nullable). Id is the email-app API key; email address is the join key to calendar connected accounts and the display value. Both stored to avoid a proxy lookup on every render.
- **D2 — Auto-assign on capture, fill-empty-only.** eldrin-email adds `mailboxId` + `mailboxEmail` to `EmailReceivedPayload` (additive; consumers ignoring them are unaffected). CRM capture sets the assignment on contact/lead creation and backfills existing records only when both columns are null. Never overwrites a manual assignment.
- **D3 — Manual override UI.** Contact/Lead detail pages get a "Mailbox" selector fed by `GET /api/mailboxes` via the `useEmailApp` proxy hook, including an "Unassigned" option. Hidden when the email app is unavailable (same `isAvailable` gating as SendEmailButton).
- **D4 — Email FROM.** `SendEmailButton` (and template send) passes the record's `assignedMailboxId` as `mailboxId`. Unassigned → omit the field (email app's existing default-mailbox behavior).
- **D5 — Schedule meeting is a synchronous proxy write, not a bus command.** Interactive scheduling needs immediate success/failure and the created event id; the event bus stays the mirror-back channel only. The "Schedule meeting" button renders only when `detectCalendarApp` confirms the calendar app is available (D0); otherwise the local Quick-log meeting button stands alone, unchanged.
- **D6 — Target-calendar resolution.** CRM worker endpoint `POST /api/meetings/schedule`:
  1. Proxy `GET eldrin-calendar /api/accounts` as the acting user (`X-Eldrin-App-Secret` + `x-eldrin-user-id`).
  2. Match account where `account.email === contact.assignedMailboxEmail` (case-insensitive).
  3. Target: if the account has exactly one synced calendar, use it; if several, treat as ambiguous (D7 picker) — the local calendar rows do not reliably carry the provider's primary flag, so no primary heuristic.
  4. Proxy `POST /api/events` with `calendarId`, title, start/end, timezone, location, attendees.
- **D7 — Graceful degradation, never block.** No assignment, no matching account, ambiguity, or calendar app unavailable → the dialog surfaces a calendar picker (all the acting user's calendars, default preselected) with a hint explaining why. Proxy failure on submit → error shown in the dialog; no partial CRM state is written (the Meeting activity only ever arrives via mirror-back).
- **D8 — Mirror-back is the CRM record of truth.** The schedule endpoint does NOT write a CRM activity. The existing `calendar.event.created` mirror creates the Meeting activity (idempotent), keeping one creation path.
- **D9 — Deal linking in the mirror.** `mirrorCalendarEvent` also links each matched contact's OPEN deals (status not won/lost) to the Meeting activity via the existing polymorphic related-record mechanism. Applies to all mirrored meetings (scheduled from CRM or created directly in Calendar/Google/Outlook).
- **D10 — User-owned fields survive mirror updates.** No new columns: activities already carry `description` (serves as agenda), `outcome`, and `nextSteps`, and the generic activity edit UI already edits them. The mirror's update path already writes only calendar-sourced fields (title/dueDate/duration/recurrence/metadata) — D10 pins this contract with tests so a future mirror change cannot clobber user edits, and the timeline (D11) exposes the meeting activity's edit affordance.
- **D11 — Richer timeline rendering.** Timeline entries for `type-meeting` render start–end time, location, attendee chips (with matched-contact links), and — for mirrored meetings only — an "Open in Calendar" link to the Calendar app root (`/eldrin-calendar`), shown only when the calendar app is available (D0). Local quick-logged meetings (no calendar metadata) render with the same treatment minus the link and attendee chips — the renderer keys on what the activity's metadata actually contains, not on app availability. No event deep-link — the calendar router has no event/date query param today and adding one is out of scope.
- **D12 — Widget mailbox annotation.** Upcoming Meetings widget annotates each occurrence with the calendar name + account email it belongs to (data already present in the accounts/calendars payload; no new proxy call).

## 4. Data flow

**Auto-assign:** provider sync → eldrin-email emits `email.received` {…, mailboxId, mailboxEmail} → core bus → CRM webhook → capture sets assignment (fill-empty-only) → contact/lead carries identity.

**Send:** SendEmailButton → `POST /api/app/eldrin-email/api/email/send` {…, mailboxId: assignedMailboxId} → email app sends from that mailbox.

**Schedule:** dialog → CRM `POST /api/meetings/schedule` → resolve target calendar (D6) → proxy `POST eldrin-calendar /api/events` → write-through pushes to Google/Outlook (invites sent) → D1 write → `calendar.event.created` → CRM mirror creates Meeting activity linked to contacts + open deals (D9) → timeline shows it (D11).

## 5. Error handling

- Schedule endpoint validates inputs (title, start < end, ≥1 attendee or none-allowed, known contact) and returns 400 with field errors; dialog renders them inline.
- Calendar proxy 4xx/5xx → 502 from CRM endpoint with the calendar error message (bounded), dialog shows it; nothing persisted in CRM.
- Accounts-resolution failure (proxy down) → same degradation as D7 ambiguity: dialog falls back to picker mode on open; if it fails at submit time, error + retry.
- Email-app-unavailable: selector and mailboxId pass-through hidden/omitted (existing `detectEmailApp` gating).
- Mirror update with user fields: whitelist test pins that agenda/outcome survive `calendar.event.updated`.

## 6. Testing

- **CRM unit:** migration/schema; capture auto-assign (new record, fill-empty backfill, no-overwrite); schedule endpoint (happy path, each D7 fallback, validation errors, proxy failure — calendar proxied via mocked fetch); mirror deal-linking; mirror whitelist (agenda/outcome preserved); widget annotation mapping; **standalone degradation (D0):** schedule button absent when calendar app unavailable, mailbox selector absent when email app unavailable, contact/deal pages and quick-log fully functional with both apps absent.
- **eldrin-email unit:** payload builder includes mailboxId/mailboxEmail; existing consumers unaffected (additive).
- **Live browser validation (mandatory, chrome-devtools):** assign mailbox on a contact → schedule a meeting → verify the event appears in eldrin-calendar UI on the right calendar, syncs to the provider (Google/Outlook ground-truth read), and the Meeting activity mirrors back onto the contact + deal timeline with agenda editable across a calendar-side update. Cross-app proxy seams are not provable by unit tests.

## 7. Out of scope

- Email↔calendar direct integration (meeting invites parsed from emails) — separate project.
- Rescheduling/canceling calendar events from CRM (open the event in Calendar instead; the mirror keeps CRM current).
- Free/busy or availability lookup in the dialog.
- Assignment on companies (contacts/leads only).
- CalDAV (calendar backlog, own slice).

## 8. Repo change summary

| Repo | Changes |
|------|---------|
| eldrin-crm | Migration (4 columns), capture auto-assign, mailbox selector UI, SendEmailButton mailboxId, schedule endpoint + dialog, mirror deal-linking + field whitelist + agenda/outcome, timeline rendering, widget annotation |
| eldrin-email | `EmailReceivedPayload` + emit site: add `mailboxId`, `mailboxEmail` (additive) |
| eldrin-calendar | None |
