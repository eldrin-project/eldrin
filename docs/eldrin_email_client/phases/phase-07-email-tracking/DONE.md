# Phase 7: Email Tracking — DONE

Completed: 2026-02-17

## What was built

### Backend (Hono worker)
- **Migration** `006-tracking.sql` — `email_tracking` and `tracking_events` tables with indexes
- **Drizzle schema** — `emailTracking` and `trackingEvents` table definitions in `worker/db/schema.ts`
- **Tracking injection service** (`worker/services/tracking.ts`) — `injectTrackingPixel()`, `wrapLinksWithTracking()`, `prepareTrackedEmail()`
- **Public tracking endpoints** (`worker/routes/tracking.ts`) — pixel.gif (1x1 transparent GIF) and click redirect with open redirect prevention
- **Send integration** — tracking pixel and link wrapping injected automatically before Gmail API call

### Frontend (React)
- **SentList.tsx** — open count (Eye icon, green) and click count (MousePointerClick icon, blue) indicators per sent email
- **Types** — `SentEmailRow` extended with `openCount`, `clickCount`, `firstOpenedAt`

### Key design decisions
- Tracking endpoints are **public** (no auth) — loaded by recipient email clients
- Event recording is **non-blocking** via `c.executionCtx.waitUntil()` — response returns instantly
- Open redirect prevention: only `http://` and `https://` URLs allowed for click redirect (blocks `javascript:`, `data:`, `mailto:` schemes)
- Tracking pixel served with `Cache-Control: no-store` to prevent email client caching
- `CF-Connecting-IP` header captured for IP address (Cloudflare-specific)
- Tracking injection wraps gracefully — if it fails, email sends without tracking

## Files created
| File | Purpose |
|------|---------|
| `migrations/006-tracking.sql` | Tracking tables + indexes |
| `worker/services/tracking.ts` | Pixel injection, link wrapping, tracked email preparation |
| `worker/routes/tracking.ts` | Public pixel.gif and click redirect endpoints |

## Files modified
| File | Change |
|------|--------|
| `worker/db/schema.ts` | Added `emailTracking` and `trackingEvents` tables |
| `worker/index.ts` | Registered `trackingRoutes` |
| `worker/routes/emails.ts` | Inject tracking on send, LEFT JOIN tracking data in sent list |
| `src/types/email.ts` | Added tracking fields to `SentEmailRow` |
| `src/pages/sent/SentList.tsx` | Added open/click tracking indicator badges |
