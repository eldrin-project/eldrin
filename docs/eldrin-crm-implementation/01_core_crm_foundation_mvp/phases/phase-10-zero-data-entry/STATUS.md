# Phase 10: Zero-Data Entry

## Status: in_progress
## Started: 2026-07-02
## Completed: -

> **UPDATED** — OAuth, mailbox connections, and email sync moved to `eldrin-email` extension app.
> This phase now focuses on the CRM intelligence layer.
> See: `docs/eldrin_email_client/` for the email app plan.

## Progress:
- [x] Step 10.1: Create auto-capture database migration — implemented as `migrations/20260216800000-auto-capture.sql`. Deliberately minimal slice: `contacts` gained `is_auto_created`, `capture_confidence`, `capture_source` instead of the planned `auto_captured_emails` / `auto_created_contacts` / `enrichment_cache` side tables. Email dedup already lives on `activities.source_message_id`; enrichment cache deferred with enrichment itself.
- [x] Step 10.2: Add Drizzle schema — contacts auto-capture columns + `idx_contacts_auto_created`.
- [x] Step 10.3: Implement auto-linking on email events — `worker/services/auto-capture.ts` (`captureInboundSender`) runs before the Phase-07 linking pass in the event webhook. Auto-creates a provisional contact from the FROM address of inbound mail only (never from `to`; self-addressed mail skipped as owner guard), name from display name with local-part fallback, links to an existing company by domain (no company auto-creation), confidence formula 0.3 base + 0.4 display-name + 0.2 company-match. Review flag cleared via `PATCH /api/contacts/:id { isAutoCreated: false }`.
- [x] Step 10.4: Implement signature parsing — `worker/services/signature-parser.ts` (pure functions): phones (international), job title (line heuristics near sender name, `Title | Company` / `at` / comma forms), social URLs (LinkedIn/Twitter-X/GitHub). Applied fill-empty-only to both matched and auto-created sender contacts; phones deduped by normalized number. NOTE: the `email.received` payload only carries `snippet` (no body), so parsing quality is limited until the email app exposes bodies; postal-address extraction deferred as unreliable on snippets.
- [ ] Step 10.5: Implement company auto-enrichment — DEFERRED (external enrichment APIs out of scope for this slice)
- [ ] Step 10.6: Implement calendar sync — DEFERRED (out of scope for this slice)
- [ ] Step 10.7: Implement ghost activity detection — DEFERRED
- [~] Step 10.8: Build auto-capture review page — minimal slice only: `GET /api/contacts?filter=auto-created`, `GET /api/contacts/auto-created-count`, "Auto-captured" badge on ContactList rows and ContactDetail header, Confirm action on ContactDetail. Dedicated review page (approve/edit/reject, bulk) deferred.
- [~] Step 10.9: Build confidence indicators — `capture_confidence` stored and shown in the badge tooltip; full completeness/freshness indicator component deferred.
- [ ] Step 10.10: Add ghost records dashboard widget — DEFERRED

## Additional in this slice (product gap fix):
- `GET /api/contacts/:id/timeline` now merges captured activities (email etc., `relatedRecordType='contact'`, not deleted) with audit entries, sorted desc, with a `type` discriminator; `Timeline` component renders activity entries (title + direction badge + snippet).

## Prerequisites:
- CRM Phase 7 (Email Integration via eldrin-email) must be complete ✓
- `eldrin-email` Phases 2-3 (mailbox sync) must be operational

## Notes:
Removed steps: OAuth flows (10.3-10.4), mailbox management (10.5), email sync (10.6),
cron trigger (10.11), mailbox UI (10.12) — all now in eldrin-email.
