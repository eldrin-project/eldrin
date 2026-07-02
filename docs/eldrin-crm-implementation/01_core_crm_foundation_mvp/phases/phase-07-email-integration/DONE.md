# Sub-Phase 07: Email Integration — DONE

Completed: 2026-07-02

## Summary

The CRM integrates with the standalone `eldrin-email` app: inbound/outbound
emails are captured as activities on matching records via platform events
(idempotent by message + record), email can be sent from Contact/Company/
Deal/Lead detail pages through the cross-app API (freeform or template),
real email history renders on the contact page, all email UI degrades
gracefully when the email app is absent, and the CRM emits its own
lifecycle events (contact.created/updated, deal.created/stage_changed,
lead.converted) for other apps. Four CRM templates seeded in eldrin-email.

Delivered alongside (platform work this phase forced): shared-secret
service auth (`X-Eldrin-App-Secret`) across SDK/core/apps, the core proxy
double-`/api` fix, core subscriber-dedup fix, live-envelope parsing in the
email and workflows webhooks, and the workflows `send_email` step +
`waitUntil` executor fix — the CRM → workflows → email automation loop is
live.

## Verification

- `npx tsc -b` — clean (eldrin-crm, eldrin-email, eldrin-workflows, core, SDK)
- `npx vitest run` — eldrin-crm 23/23, eldrin-email 76/76, eldrin-app-core 90/90, eldrin-core 571/571
- Live (core:4000 + email:4010 + crm:4009 + workflows:4008, Chrome DevTools):
  - `email.received` → activity on matching contact; redelivery idempotent
  - **Real send round trip**: email sent from the contact page via the
    `tibor.kiray@devista.io` mailbox to `tibor.kiray@gmail.com`; `email.sent`
    → outbound activity logged on the contact (provenance); the sent email
    renders in the contact's Emails section
  - Send Email modal loads live templates through the shell proxy
  - `contact.created` → triggered an eldrin-workflows run whose `send_email`
    step emitted `email.send.requested`, delivered to eldrin-email
  - Webhooks and emit endpoints reject missing/wrong service secret (401)

## Known follow-ups

- Two stale Gmail mailboxes (`tibor.kiray@gmail.com`, `eldrin.project@gmail.com`)
  return `invalid_grant` on token refresh — reconnect or remove them; consider
  marking `syncStatus='error'` on invalid_grant so the send fallback skips them.
- ContactDetail "Activity Timeline" is audit-based and doesn't render activity
  records (captured emails appear on the Activities page and in the Emails
  history section).
