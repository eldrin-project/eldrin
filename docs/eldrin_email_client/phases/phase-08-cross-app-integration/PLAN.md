# Phase 8: Cross-App Integration API

## Overview

Expose the APIs and event contracts that allow other Eldrin apps (CRM, Invoicing, Workflows) to send emails, fetch email history, and use templates. Also implement the event webhook handler so `eldrin-email` can react to events from other apps (e.g., `email.send.requested`).

This is the phase that makes `eldrin-email` a platform service rather than just a standalone app.

Covers REQ-EM-6.05 through REQ-EM-6.10.

## Dependencies

- **Phase 5** — Send functionality
- **Phase 6** — Templates
- **Phase 7** — Tracking (optional, for tracked sends via API)

## Steps

### 8.1 Create integration routes

Create `worker/routes/integration.ts`:

- `POST /api/email/send` — cross-app send API
  - Body: `{ to, cc?, bcc?, subject, bodyHtml, bodyText?, relatedApp?, relatedRecordId?, enableTracking? }`
  - Uses the requesting user's connected mailbox (or a configured default mailbox)
  - Sends email, stores record, optionally injects tracking
  - Emits `email.sent` event with `relatedApp` and `relatedRecordId` in payload
  - Called by CRM via: `POST /api/app/eldrin-email/api/email/send`

- `POST /api/email/send-template` — send using a template
  - Body: `{ templateId, to, cc?, bcc?, mergeContext, relatedApp?, relatedRecordId? }`
  - Fetches template, resolves merge fields, sends
  - Emits `email.sent` event

- `GET /api/email/history` — email history for an email address
  - Query params: `contactEmail` (required), `page`, `limit`
  - Returns: list of emails where `from_address` or `to_addresses` match the given email
  - Used by CRM to show email history on contact detail page

- `GET /api/email/history/record` — email history for a related record
  - Query params: `relatedApp`, `relatedRecordId`, `page`, `limit`
  - Returns emails linked to a specific record (e.g., all emails tagged to a deal)

### 8.2 Implement event webhook handler

Create/update `worker/routes/events.ts`:

- `POST /api/_events/webhook` — receive platform events
  - Handle `email.send.requested`:
    - Payload: `{ to, subject, bodyHtml, templateId?, mergeContext?, relatedApp, relatedRecordId }`
    - Send email on behalf of the event source app
    - Fire-and-forget: acknowledge event, send asynchronously
  - Handle `user.deleted`:
    - Clean up all mailbox connections and tokens for the deleted user
    - Delete associated synced emails

### 8.3 Document cross-app API contract

Create `docs/API.md` in the email app repo:

- Endpoint reference with request/response schemas
- Authentication: requests go through platform proxy (Authorization header injected)
- Event catalog: all emitted events with payload schemas
- Integration examples for CRM use cases

### 8.4 Add CRM-friendly response enrichments

Enhance `GET /api/email/history` response to include:
- Thread grouping (emails in the same thread shown together)
- Tracking data: open/click counts per email (if tracking was enabled)
- Direction indicator: inbound/outbound

### 8.5 Register commands for global search

Register `eldrin-email` commands with the platform command palette:
- "Compose email" → opens composer
- "Search emails" → navigates to inbox with search focused
- "Email templates" → navigates to template list
- Use `window.__ELDRIN__.registerCommands()` pattern from eldrin-workflows

## Test Gate

```bash
cd eldrin-email && npm run build
cd eldrin-email && npm run test
```

- `POST /api/email/send` sends email when called via platform proxy
- `POST /api/email/send-template` resolves merge fields and sends
- `GET /api/email/history?contactEmail=...` returns matching emails
- `email.send.requested` event triggers email send
- `user.deleted` event cleans up mailbox data
- Command palette shows email commands

## Files Created

| File | Purpose |
|------|---------|
| `worker/routes/integration.ts` | Cross-app send, send-template, history API |
| `worker/routes/events.ts` | Event webhook handler |
| `docs/API.md` | Integration API documentation |

## Files Modified

| File | Change |
|------|--------|
| `worker/index.ts` | Register integration and event routes |
| `src/index.ts` | Register command palette commands |

## Finalize

- [ ] Manual validation: CRM can send email through integration API
- [ ] Manual validation: email history returns correct results for a contact email
- [ ] Manual validation: `email.send.requested` event triggers send
- [ ] Commit: `feat(email): add cross-app integration API and event handlers`
- [ ] Update STATUS.md → complete, create DONE.md
