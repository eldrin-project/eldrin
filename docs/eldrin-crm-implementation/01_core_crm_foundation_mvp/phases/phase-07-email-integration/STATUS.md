# Phase 7: Email Integration (via eldrin-email Extension App)

## Status: in_progress
## Started: 2026-07-02
## Completed: -

> **RESTRUCTURED** — This phase now integrates with the standalone `eldrin-email` extension app
> instead of building email infrastructure directly in the CRM.
> See: `docs/eldrin_email_client/` for the email app plan.

## Progress:
- [x] Step 7.1: Handle email events from eldrin-email (received, sent, opened, clicked)
- [x] Step 7.2: Add "Send Email" button to record detail pages
- [x] Step 7.3: Add template-based sending via email app API
- [x] Step 7.4: Show email history on record timelines
- [x] Step 7.5: Create email-linking service (match emails to contacts/companies/deals)
- [x] Step 7.6: Handle graceful degradation (when email app not installed)
- [x] Step 7.7: Declare CRM events in manifest
- [ ] Step 7.8: Seed CRM-specific email templates (requires a running eldrin-email instance — do during live validation)

## Prerequisites:
- `eldrin-email` Phase 8 (Cross-App Integration API) must be complete — **verified complete 2026-07-02** (send/send-template/history routes + email.received/sent emitters exist)

## Notes:
- Implemented 2026-07-02 on branch `feature/phase-07-email-integration` (not yet committed).
- Backend: `worker/routes/events.ts` (webhook, accepts BOTH the live core envelope `{deliveryId, event:{…}}` and flat `{type, payload}`), `worker/services/email-linking.ts` (matching + idempotent activity logging), `worker/services/event-emitter.ts` (CRM event emission), migration `20260216700000-email-activities.sql` (adds `activities.source_message_id` + `metadata`, unique per message+record).
- Manifest: `/api/_events/webhook` added to `publicRoutes` (core pushes carry no auth); `events.emits` declares contact.created/updated, deal.created, deal.stage_changed, lead.converted.
- Frontend: `src/hooks/useEmailApp.ts`, `src/components/email/{SendEmailButton,TemplateSelector,EmailTimeline}.tsx`, integrated into Contact/Company/Deal/Lead detail pages; all email UI hidden when eldrin-email is absent.
- Tests: first CRM test suite added — `worker/__tests__/` (21 tests, vitest + better-sqlite3 running the real migrations). `npx tsc -b` clean, `npm run build` green.
- ✅ **Live validation 2026-07-02** (core:4000 + email:4010 + crm:4009, Chrome DevTools): `email.received` emitted as eldrin-email → core bus → push to CRM webhook → email activity created on matching contact (visible in Activities UI); redelivery of the same messageId proven idempotent (1 activity); Send Email button + compose modal render on ContactDetail with templates loaded from eldrin-email through the shell proxy; Emails history section shows correct empty state.
- Fixes made during validation: eldrin-core proxy double-`/api` bug (`core/routes/apps.ts` — `/api/app/{id}/api/x` produced `{app_url}/api/api/x`); CRM manifest `publicRoutes` entry must be `/_events/webhook` (SDK matcher prepends the `/api` prefix); `useEmailApp` now matches core's snake_case `app_id`.
- ⚠️ Still open: (1) app→core event **emission** is blocked by core's auth middleware — CRM's `contact.created` emit gets 401 because the SDK event client sends only `X-Eldrin-App-Id` with no JWT; needs a platform decision on service auth (shared secret / minted app token / header allowlist). (2) eldrin-email/eldrin-workflows webhook handlers still parse only the flat `{type, payload}` envelope, not the live `{deliveryId, event:{…}}` shape. (3) ContactDetail "Activity Timeline" is audit-trail-based and does not display activity records (captured emails show on the Activities page instead).
- Remaining before DONE.md: template seeding (7.8), send-email round trip with a real mailbox, resolve the emission auth decision.
