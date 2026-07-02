# Phase 7: Email Integration (via eldrin-email Extension App)

## Status: complete
## Started: 2026-07-02
## Completed: 2026-07-02

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
- [x] Step 7.8: Seed CRM-specific email templates (4 templates created in eldrin-email, 2026-07-02)

## Prerequisites:
- `eldrin-email` Phase 8 (Cross-App Integration API) must be complete — **verified complete 2026-07-02** (send/send-template/history routes + email.received/sent emitters exist)

## Notes:
- Implemented 2026-07-02 on branch `feature/phase-07-email-integration` (committed: ee11ed1, 0dc9ad4).
- Backend: `worker/routes/events.ts` (webhook, accepts BOTH the live core envelope `{deliveryId, event:{…}}` and flat `{type, payload}`), `worker/services/email-linking.ts` (matching + idempotent activity logging), `worker/services/event-emitter.ts` (CRM event emission), migration `20260216700000-email-activities.sql` (adds `activities.source_message_id` + `metadata`, unique per message+record).
- Manifest: `/api/_events/webhook` added to `publicRoutes` (core pushes carry no auth); `events.emits` declares contact.created/updated, deal.created, deal.stage_changed, lead.converted.
- Frontend: `src/hooks/useEmailApp.ts`, `src/components/email/{SendEmailButton,TemplateSelector,EmailTimeline}.tsx`, integrated into Contact/Company/Deal/Lead detail pages; all email UI hidden when eldrin-email is absent.
- Tests: first CRM test suite added — `worker/__tests__/` (21 tests, vitest + better-sqlite3 running the real migrations). `npx tsc -b` clean, `npm run build` green.
- ✅ **Live validation 2026-07-02** (core:4000 + email:4010 + crm:4009, Chrome DevTools): `email.received` emitted as eldrin-email → core bus → push to CRM webhook → email activity created on matching contact (visible in Activities UI); redelivery of the same messageId proven idempotent (1 activity); Send Email button + compose modal render on ContactDetail with templates loaded from eldrin-email through the shell proxy; Emails history section shows correct empty state.
- Fixes made during validation: eldrin-core proxy double-`/api` bug (`core/routes/apps.ts` — `/api/app/{id}/api/x` produced `{app_url}/api/api/x`); CRM manifest `publicRoutes` entry must be `/_events/webhook` (SDK matcher prepends the `/api` prefix); `useEmailApp` now matches core's snake_case `app_id`.
- Resolved later the same day: emission auth (shared-secret service auth across SDK/core/apps) and the flat-envelope parsing in eldrin-email/eldrin-workflows. Remaining product gap: ContactDetail "Activity Timeline" is audit-trail-based and does not display activity records (captured emails show on the Activities page and in the Emails history section).
- ✅ DONE 2026-07-02: templates seeded, real send round trip validated (outbound activity + Emails history on contact), emission auth resolved via shared-secret service auth. See DONE.md.
