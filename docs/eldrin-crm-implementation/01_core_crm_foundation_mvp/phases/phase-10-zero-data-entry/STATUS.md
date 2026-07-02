# Phase 10: Zero-Data Entry

## Status: not_started
## Started: -
## Completed: -

> **UPDATED** — OAuth, mailbox connections, and email sync moved to `eldrin-email` extension app.
> This phase now focuses on the CRM intelligence layer.
> See: `docs/eldrin_email_client/` for the email app plan.

## Progress:
- [ ] Step 10.1: Create auto-capture database migration
- [ ] Step 10.2: Add Drizzle schema
- [ ] Step 10.3: Implement auto-linking on email events (extend Phase 7 handlers)
- [ ] Step 10.4: Implement signature parsing
- [ ] Step 10.5: Implement company auto-enrichment
- [ ] Step 10.6: Implement calendar sync
- [ ] Step 10.7: Implement ghost activity detection
- [ ] Step 10.8: Build auto-capture review page
- [ ] Step 10.9: Build confidence indicators
- [ ] Step 10.10: Add ghost records dashboard widget

## Prerequisites:
- CRM Phase 7 (Email Integration via eldrin-email) must be complete
- `eldrin-email` Phases 2-3 (mailbox sync) must be operational

## Notes:
Removed steps: OAuth flows (10.3-10.4), mailbox management (10.5), email sync (10.6),
cron trigger (10.11), mailbox UI (10.12) — all now in eldrin-email.
