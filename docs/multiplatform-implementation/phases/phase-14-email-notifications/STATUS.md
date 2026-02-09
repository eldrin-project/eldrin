# Phase 14: Email & Notification Service

## Status: done
## Started: 2026-02-09
## Completed: 2026-02-09

## Progress:
- [x] Step 14.1: Create email provider interface (`core/notifications/email/interface.ts`)
- [x] Step 14.2: Implement Console, SendGrid, SMTP adapters
- [x] Step 14.3: Create template engine with 6 built-in templates
- [x] Step 14.4: Create factory (`createEmailProvider`)
- [x] Step 14.5: Wire into app.ts and users.ts (approve/reject send emails)
- [x] Step 14.6: Write tests (25 new tests, 229 total)
- [ ] Step 14.7: SES adapter — DEFERRED to Phase 4 (Signature V4 complexity)
- [ ] Step 14.8: Azure Communication Services adapter — DEFERRED to Phase 4 (HMAC auth)

## Notes:
- MVP scope: Console + SendGrid + SMTP adapters
- SES and Azure deferred due to authentication complexity (SigV4, HMAC)
- SMTP uses dynamic `import('node:net')` — fails gracefully on Workers
- Email sending is fire-and-forget — failures logged but don't block HTTP response
- 6 templates: welcome, approval-request, approval-granted, rejection, password-reset, identity-linked
