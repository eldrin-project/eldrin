# Phase 10: Zero-Data Entry

> **UPDATED** — OAuth, mailbox connections, and email sync are now handled by the `eldrin-email` extension app.
> This phase focuses on the CRM-specific intelligence layer: auto-linking, signature parsing, enrichment, and ghost detection.
> See: `docs/eldrin_email_client/` for the email app plan.

## Overview

**DIFFERENTIATOR.** The CRM that fills itself. This phase builds the intelligence layer on top of `eldrin-email` events: when emails arrive, the CRM automatically matches them to contacts, parses signatures for missing data, enriches company records, creates provisional contacts for unknown senders, syncs calendar events as activities, and surfaces "ghost" records with no recent activity.

**What moved to `eldrin-email`:**
- OAuth 2.0 flows for Gmail and Outlook
- Encrypted token storage
- Background email sync engine
- Mailbox connection UI

**What stays in the CRM:**
- Auto-linking emails to CRM records (contacts, companies, deals)
- Auto-creating provisional contacts for unknown senders
- Email signature parsing (phone, title, address extraction)
- Company auto-enrichment from domain data
- Calendar event sync (with CRM-specific activity creation)
- Ghost activity detection
- Review UI for auto-created data

Covers requirements REQ-1.10.01 through REQ-1.10.13.

## Dependencies

- **Phase 02** — Contacts and companies (records to link and auto-create)
- **Phase 04** — Deals (link emails to deal context)
- **Phase 05** — Activities (create email and meeting activities)
- **Phase 07** — Email integration (event handlers, email-linking service)
- **External** — `eldrin-email` extension app (Phases 2-3: mailbox sync operational)

## Steps

### 10.1 Create auto-capture database migration

Create `migrations/008-auto-capture.sql` with the following tables:

**`auto_captured_emails`**:
- `id` TEXT PRIMARY KEY
- `email_message_id` TEXT UNIQUE NOT NULL — from `email.received` event payload
- `from_address` TEXT NOT NULL
- `from_name` TEXT
- `to_addresses` TEXT NOT NULL (JSON array)
- `subject` TEXT
- `direction` TEXT NOT NULL (inbound/outbound)
- `linked_contact_id` TEXT (FK to contacts, nullable)
- `linked_company_id` TEXT (FK to companies, nullable)
- `linked_deal_id` TEXT (FK to deals, nullable)
- `confidence_score` REAL NOT NULL DEFAULT 0
- `is_reviewed` INTEGER NOT NULL DEFAULT 0
- `created_at` INTEGER NOT NULL

**`auto_created_contacts`**:
- `id` TEXT PRIMARY KEY
- `contact_id` TEXT NOT NULL (FK to contacts)
- `source_email_message_id` TEXT NOT NULL
- `auto_fields` TEXT NOT NULL (JSON: which fields were auto-populated)
- `is_reviewed` INTEGER NOT NULL DEFAULT 0
- `created_at` INTEGER NOT NULL

**`enrichment_cache`**:
- `id` TEXT PRIMARY KEY
- `domain` TEXT UNIQUE NOT NULL
- `data` TEXT NOT NULL (JSON: company name, industry, size, location, logo, website)
- `fetched_at` INTEGER NOT NULL
- `expires_at` INTEGER NOT NULL

Indexes: `auto_captured_emails(email_message_id)`, `auto_captured_emails(linked_contact_id)`, `auto_created_contacts(contact_id)`, `enrichment_cache(domain)`.

### 10.2 Add Drizzle schema

Add auto-capture tables to `worker/db/schema.ts`.

### 10.3 Implement auto-linking on email events

Extend the `email.received` handler from Phase 7:

1. On each `email.received` event:
   - Match sender against `contact_emails` table
   - If match: link with high confidence (1.0)
   - If no match by email, check domain against `companies.domain`
   - If domain match: link to company with medium confidence (0.6)
   - Store in `auto_captured_emails` with confidence score

2. Auto-create provisional contact for unknown senders:
   - Parse display name into first/last name
   - Extract domain → find or create company
   - Create contact with `source = 'auto-capture'`
   - Record in `auto_created_contacts` with `auto_fields`
   - Mark `is_reviewed = false`
   - Confidence: 0.3 (needs review)

### 10.4 Implement signature parsing

Create `worker/services/signature-parser.ts`:

- `parseSignature(emailBody: string)` — extract structured data:
  1. Detect signature delimiter: `--`, `---`, `___`, `Sent from`, etc.
  2. Extract phone numbers: international regex patterns
  3. Extract job title: `Title | Company`, `Title at Company`
  4. Extract address: multi-line street + city + state
  5. Extract social URLs: LinkedIn, Twitter/X

- `updateContactFromSignature(db, contactId, signatureData)`:
  - Only overwrite empty fields (never replace manually entered data)
  - Log auto-populated fields in `auto_created_contacts.auto_fields`

- Triggered when processing `email.received` events — fetch email body from email app:
  ```
  GET /api/app/eldrin-email/api/email/history?contactEmail={from}
  ```
  (Use the most recent email's body for signature parsing)

### 10.5 Implement company auto-enrichment

Create `worker/services/enrichment.ts`:

- `enrichCompany(db, domain)`:
  1. Check `enrichment_cache` — return if cached and not expired
  2. Call enrichment API (Clearbit, or basic domain lookup fallback)
  3. Extract: company name, industry, size, location, logo URL
  4. Cache with 30-day TTL
  5. Update company record (only overwrite empty fields)

- Triggered when auto-creating a company from an email domain

### 10.6 Implement calendar sync

Create `worker/services/calendar-sync.ts`:

> Note: Calendar data comes from the email app's connected mailboxes.
> The CRM calls the email app's calendar API (if available) or processes
> calendar-related events.

- `processCalendarEvent(db, event)`:
  - Match attendee emails to CRM contacts
  - If match: create activity of type `meeting`
  - Set: title, start/end time, duration, location, attendees
  - Link to matching contacts and their companies/deals
  - Dedup by event ID

### 10.7 Implement ghost activity detection

Create `worker/services/ghost-detection.ts`:

- `detectGhostRecords(db, thresholdDays)`:
  - Contacts with no activities in the last N days
  - Deals with no stage changes or activities in the last N days
  - Return: record type, name, last activity date, days since last activity

- `getGhostSummary(db)`:
  - Counts for 30/60/90 day thresholds
  - Exposed via `GET /api/reports/ghost-records?threshold_days=30`

### 10.8 Build auto-capture review page

Create `src/pages/settings/AutoCaptureReview.tsx`:

Tab 1 — Auto-created contacts:
- List with source email, parsed name, confidence score
- Actions: Approve (keep), Edit (fix details), Reject (delete)
- Auto-populated fields highlighted differently
- Bulk approve for high-confidence records

Tab 2 — Auto-linked emails needing review:
- Emails with low confidence scores
- Show suggested link, allow override
- Filter by date range, confidence threshold

### 10.9 Build confidence indicators

Create `src/components/shared/ConfidenceIndicator.tsx`:

- Completeness score: % of fields filled
- Auto vs. manual badges on record detail pages
- Freshness: last update/activity date
- Color coding: green (>80%), yellow (50-80%), red (<50%)
- Tooltip with missing field list

### 10.10 Add ghost records dashboard widget

Update `src/pages/reports/Dashboard.tsx`:
- "Attention needed" widget showing ghost record counts
- Click through to ghost records list
- 30/60/90 day breakdowns

## Test Gate

```bash
cd eldrin-crm && npm run build
cd eldrin-crm && npm run test
```

Acceptance criteria:
1. `email.received` event auto-links to matching contact with high confidence
2. Unknown sender auto-creates provisional contact with parsed name
3. Signature parsing extracts phone number and job title
4. Company enrichment populates fields from domain data
5. Ghost detection surfaces inactive contacts/deals
6. Auto-capture review page: approve, edit, reject
7. Confidence indicators show data completeness

## Files Created

| File | Purpose |
|------|---------|
| `migrations/008-auto-capture.sql` | Auto-capture tables |
| `worker/services/signature-parser.ts` | Email signature parsing |
| `worker/services/enrichment.ts` | Company auto-enrichment |
| `worker/services/calendar-sync.ts` | Calendar event processing |
| `worker/services/ghost-detection.ts` | Inactive record detection |
| `src/pages/settings/AutoCaptureReview.tsx` | Review auto-created data |
| `src/components/shared/ConfidenceIndicator.tsx` | Data quality indicator |

## Files Modified

| File | Change |
|------|--------|
| `worker/db/schema.ts` | Add auto-capture tables |
| `worker/routes/events.ts` | Extend email event handlers for auto-linking |
| `worker/index.ts` | Register review routes |
| `src/root.component.tsx` | Add auto-capture review route |
| `src/pages/contacts/ContactDetail.tsx` | Show confidence indicators |
| `src/pages/companies/CompanyDetail.tsx` | Show enrichment data |
| `src/pages/reports/Dashboard.tsx` | Add ghost records widget |

## Finalize

- [ ] Manual validation: email event auto-links to contact
- [ ] Manual validation: unknown sender creates provisional contact
- [ ] Manual validation: signature parsing extracts phone and title
- [ ] Manual validation: company enrichment works
- [ ] Manual validation: ghost detection surfaces inactive records
- [ ] Manual validation: review page approve/edit/reject works
- [ ] Commit: `feat(crm): add zero-data entry with auto-linking, signature parsing, and enrichment`
- [ ] Update `STATUS.md` → complete, create `DONE.md`
