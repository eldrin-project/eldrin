# Phase 7: Email Integration (via eldrin-email Extension App)

> **RESTRUCTURED** — Email infrastructure has been extracted into the standalone `eldrin-email` extension app.
> See: `docs/eldrin_email_client/` for the full email app plan.
> The CRM integrates with `eldrin-email` through platform events and cross-app API — it does not build its own email infrastructure.

## Overview

The CRM's email integration is a thin layer that consumes events and APIs from the `eldrin-email` extension app. When a user sends or receives email through `eldrin-email`, the CRM reacts by:

1. **Matching** email addresses against CRM contacts
2. **Logging** email activities on contact/deal/lead timelines
3. **Sending** email from within record detail pages via the email app API
4. **Using templates** with CRM-specific merge fields (contact name, deal value, etc.)

This approach means:
- **No email infrastructure in the CRM** — OAuth, sync, SMTP, tracking all live in `eldrin-email`
- **Optional dependency** — CRM works without `eldrin-email` (email features hidden gracefully)
- **Shared infrastructure** — other Eldrin apps (Invoicing, Workflows) use the same email service

Covers requirements REQ-1.6.01 through REQ-1.6.06.

## Dependencies

- **Phase 02** — Contacts (email-to-contact matching)
- **Phase 04** — Deals (linking emails to deals)
- **Phase 05** — Activities (logging email activities)
- **External** — `eldrin-email` extension app (at minimum Phase 8: Cross-App Integration API)

## Steps

### 7.1 Handle email events from eldrin-email

Create or update CRM event webhook handler (`worker/routes/events.ts`):

Handle `email.received`:
1. Extract `from` and `to` addresses from event payload
2. Match against `contact_emails` table
3. If match: create activity (type `email`) on the contact
4. If contact has linked company/deal: associate activity with those records
5. Store `messageId` on activity for dedup and cross-reference

Handle `email.sent`:
1. If `relatedApp === 'eldrin-crm'`: create activity on the `relatedRecordId`
2. Otherwise: match `to` addresses against contacts and link

Handle `email.opened`:
1. Find activity by `messageId`
2. Update activity metadata (open count/timestamp)

Handle `email.clicked`:
1. Find activity by `messageId`
2. Update activity metadata (click info)

### 7.2 Add "Send Email" button to record detail pages

On ContactDetail, CompanyDetail, DealDetail, LeadDetail:

- "Send Email" button calls:
  ```
  POST /api/app/eldrin-email/api/email/send
  { to, subject, bodyHtml, relatedApp: "eldrin-crm", relatedRecordId }
  ```
- Opens a lightweight compose form or redirects to email app's composer
- If `eldrin-email` not installed: button hidden

### 7.3 Add template-based sending

- "Use Template" dropdown fetches templates: `GET /api/app/eldrin-email/api/templates`
- On selection, sends with merge context:
  ```
  POST /api/app/eldrin-email/api/email/send-template
  { templateId, to, mergeContext: { "contact.firstName": ..., "deal.name": ... }, relatedApp: "eldrin-crm", relatedRecordId }
  ```

### 7.4 Show email history on record timelines

Fetch email history from email app:
```
GET /api/app/eldrin-email/api/email/history?contactEmail={email}
```

Display in timeline:
- Email entries: subject, from/to, date, snippet
- Open/click tracking badges
- Click to expand full email preview
- Thread grouping for conversations

### 7.5 Create email-linking service

Create `worker/services/email-linking.ts`:

- `matchEmailToContact(db, emailAddress)` — find contact by email in `contact_emails`
- `matchEmailToCompany(db, emailDomain)` — find company by domain
- `findRelatedDeals(db, contactId)` — find active deals for a contact
- `createEmailActivity(db, params)` — create activity record from email event

### 7.6 Handle graceful degradation

Create `src/hooks/useEmailApp.ts`:

- Check if `eldrin-email` is installed: `GET /api/apps` and look for it
- Cache result in Zustand store
- Export `isEmailAppAvailable`, `sendEmail()`, `sendTemplate()`, `getEmailHistory()`
- Conditionally render email UI based on availability

### 7.7 Declare CRM events in manifest

Update `public/eldrin-app.manifest.json` to add `events.emits`:
```json
{
  "events": {
    "emits": [
      { "type": "contact.created", "payload": { "contactId": "string", "email": "string" } },
      { "type": "contact.updated", "payload": { "contactId": "string" } },
      { "type": "deal.created", "payload": { "dealId": "string", "contactIds": "string[]" } },
      { "type": "deal.stage_changed", "payload": { "dealId": "string", "fromStage": "string", "toStage": "string" } },
      { "type": "lead.converted", "payload": { "leadId": "string", "contactId": "string", "dealId": "string?" } }
    ],
    "subscribes": [
      { "pattern": "email.*", "delivery": "push" },
      { "pattern": "*", "delivery": "push" }
    ]
  }
}
```

### 7.8 Seed CRM-specific email templates

If `eldrin-email` is available, create CRM-oriented templates via API:
- "New Lead Follow-up" — `{{contact.firstName}}`, personal welcome
- "Deal Proposal" — `{{deal.name}}`, `{{deal.value}}`
- "Meeting Follow-up" — thank you after meeting
- "Re-engagement" — for stale contacts

## Test Gate

```bash
cd eldrin-crm && npm run build   # Zero TypeScript errors
cd eldrin-crm && npm run test    # Event handler and integration tests pass
```

Acceptance criteria:
1. `email.received` event creates activity on matching contact's timeline
2. "Send Email" from contact detail calls email app API successfully
3. Template-based sending resolves CRM merge fields
4. Email history displays on contact timeline (fetched from email app)
5. Email features hidden when eldrin-email is not installed
6. CRM manifest declares its own events for other apps to subscribe to

## Files Created

| File | Purpose |
|------|---------|
| `worker/routes/events.ts` | Email event handlers (received, sent, opened, clicked) |
| `worker/services/email-linking.ts` | Match emails to CRM contacts/companies/deals |
| `src/components/email/SendEmailButton.tsx` | Cross-app send button |
| `src/components/email/TemplateSelector.tsx` | Template picker from email app |
| `src/components/email/EmailTimeline.tsx` | Email history display |
| `src/hooks/useEmailApp.ts` | Email app availability + API helpers |

## Files Modified

| File | Change |
|------|--------|
| `worker/index.ts` | Register event webhook route |
| `public/eldrin-app.manifest.json` | Add `events.emits` declarations |
| `src/pages/contacts/ContactDetail.tsx` | Add send email button + email timeline |
| `src/pages/companies/CompanyDetail.tsx` | Add send email button + email timeline |
| `src/pages/deals/DealDetail.tsx` | Add send email button + email timeline |
| `src/pages/leads/LeadDetail.tsx` | Add send email button |

## Finalize

- [ ] Manual validation: email event creates activity on contact
- [ ] Manual validation: send email from contact detail via email app API
- [ ] Manual validation: template sending resolves CRM merge fields
- [ ] Manual validation: email history shows on contact timeline
- [ ] Manual validation: graceful degradation when email app not installed
- [ ] Commit: `feat(crm): integrate with eldrin-email extension app for email capabilities`
- [ ] Update `STATUS.md` → complete, create `DONE.md`
