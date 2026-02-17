# Phase 7: Email Tracking

## Overview

Add open and click tracking to sent emails. A transparent tracking pixel is injected before sending, and all links are wrapped through a click tracker. Tracking events emit platform events (`email.opened`, `email.clicked`) that other apps can react to.

Covers REQ-EM-5.01 through REQ-EM-5.04, REQ-EM-6.03, REQ-EM-6.04.

## Dependencies

- **Phase 5** — Email sending (inject tracking before send)

## Steps

### 7.1 Create tracking migration

Create `migrations/004-tracking.sql`:

**`email_tracking`**:
- `id` TEXT PRIMARY KEY
- `email_id` TEXT NOT NULL (FK to emails)
- `tracking_id` TEXT UNIQUE NOT NULL — public identifier for tracking URLs
- `open_count` INTEGER NOT NULL DEFAULT 0
- `click_count` INTEGER NOT NULL DEFAULT 0
- `first_opened_at` INTEGER
- `last_opened_at` INTEGER
- `created_at` INTEGER NOT NULL

**`tracking_events`**:
- `id` TEXT PRIMARY KEY
- `tracking_id` TEXT NOT NULL (FK to email_tracking)
- `event_type` TEXT NOT NULL (open/click)
- `url` TEXT — clicked URL (null for opens)
- `user_agent` TEXT
- `ip_address` TEXT
- `created_at` INTEGER NOT NULL

Indexes: `email_tracking(email_id)`, `email_tracking(tracking_id)`, `tracking_events(tracking_id)`.

### 7.2 Add Drizzle schema

Add tracking tables to `worker/db/schema.ts`.

### 7.3 Implement tracking injection service

Create `worker/services/tracking.ts`:

- `generateTrackingId()` — crypto.randomUUID() or ULID
- `injectTrackingPixel(html, trackingId, baseUrl)` — append `<img src="{baseUrl}/api/track/{trackingId}/pixel.gif" ...>` before `</body>`
- `wrapLinksWithTracking(html, trackingId, baseUrl)` — replace all `<a href="...">` with `{baseUrl}/api/track/{trackingId}/click?url={encodedOriginalUrl}`
- `prepareTrackedEmail(html, emailId, baseUrl)` — creates tracking record, injects pixel and wraps links, returns modified HTML

### 7.4 Create tracking endpoints

Create `worker/routes/tracking.ts`:

- `GET /api/track/:trackingId/pixel.gif` — **public** (no auth)
  - Return 1x1 transparent GIF (hardcoded binary)
  - Record open event (non-blocking `waitUntil`)
  - Increment `open_count`, update `first_opened_at` / `last_opened_at`
  - Emit `email.opened` platform event
  - Set `Cache-Control: no-store` to prevent caching
- `GET /api/track/:trackingId/click` — **public** (no auth)
  - Query param: `url` — the original destination
  - Validate URL (prevent open redirect attacks: allowlist domains or require https)
  - Record click event
  - Increment `click_count`
  - Emit `email.clicked` platform event
  - Return 302 redirect to original URL

### 7.5 Integrate tracking with email send

Modify `POST /api/email/send`:
- Before calling Gmail API, run `prepareTrackedEmail()` on the HTML body
- Store tracking_id association with the sent email
- Optionally: allow sender to opt out of tracking per email

### 7.6 Add tracking dashboard to sent view

Update sent email detail view:
- Show open count and click count badges
- Expandable tracking timeline: list of open/click events with timestamps
- "Opened" / "Not opened" status indicator in sent list

## Test Gate

```bash
cd eldrin-email && npm run build
cd eldrin-email && npm run test
```

- Send tracked email → pixel and links injected in HTML
- Load pixel URL → records open event, increments count
- Click tracked link → redirects to original URL, records click
- `email.opened` and `email.clicked` events emitted
- Sent list shows open/click indicators

## Files Created

| File | Purpose |
|------|---------|
| `migrations/004-tracking.sql` | Tracking tables |
| `worker/services/tracking.ts` | Pixel injection, link wrapping |
| `worker/routes/tracking.ts` | Public tracking endpoints |

## Files Modified

| File | Change |
|------|--------|
| `worker/db/schema.ts` | Add tracking tables |
| `worker/index.ts` | Register tracking routes |
| `worker/routes/emails.ts` | Inject tracking on send |
| `src/pages/sent/SentList.tsx` | Show tracking indicators |

## Finalize

- [ ] Manual validation: pixel.gif fires, click redirects
- [ ] Manual validation: events emitted to platform
- [ ] Manual validation: open redirect prevention works
- [ ] Commit: `feat(email): add open and click tracking with events`
- [ ] Update STATUS.md → complete, create DONE.md
