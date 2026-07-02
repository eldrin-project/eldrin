# Phase 7: Email Integration (via eldrin-email Extension App)

## Status: not_started
## Started: -
## Completed: -

> **RESTRUCTURED** — This phase now integrates with the standalone `eldrin-email` extension app
> instead of building email infrastructure directly in the CRM.
> See: `docs/eldrin_email_client/` for the email app plan.

## Progress:
- [ ] Step 7.1: Handle email events from eldrin-email (received, sent, opened, clicked)
- [ ] Step 7.2: Add "Send Email" button to record detail pages
- [ ] Step 7.3: Add template-based sending via email app API
- [ ] Step 7.4: Show email history on record timelines
- [ ] Step 7.5: Create email-linking service (match emails to contacts/companies/deals)
- [ ] Step 7.6: Handle graceful degradation (when email app not installed)
- [ ] Step 7.7: Declare CRM events in manifest
- [ ] Step 7.8: Seed CRM-specific email templates

## Prerequisites:
- `eldrin-email` Phase 8 (Cross-App Integration API) must be complete

## Notes:
