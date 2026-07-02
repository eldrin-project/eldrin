# Phase 8: Cross-App Integration API — DONE

Completed: 2026-02-17

## What was built

### Backend

**Migration `007-integration.sql`** — Adds `related_app` and `related_record_id` columns to the emails table with a composite index.

**Extended `POST /api/email/send`** — Accepts optional `relatedApp` and `relatedRecordId` fields for cross-app provenance tracking. Both the immediate send and scheduled send paths store these fields.

**`worker/routes/integration.ts`** — Three new endpoints:
- `POST /api/email/send-template` — Fetches template, resolves merge fields against provided context, sends via Gmail API. Auto-selects first active mailbox when `mailboxId` is omitted. Increments template usage count.
- `GET /api/email/history` — Returns paginated email history for a contact email address. Matches emails where the contact appears in `from_address` or `to_addresses`. Includes tracking data (openCount, clickCount) via LEFT JOIN.
- `GET /api/email/history/record` — Returns paginated email history for a specific related record (e.g., all emails linked to a CRM deal).

**`worker/routes/events.ts`** — Platform event webhook handler replacing the Phase 4 stub:
- `email.send.requested` — Sends email asynchronously (via `waitUntil`). Supports template resolution with merge fields. Stores cross-app provenance.
- `user.deleted` — Cascading cleanup: tracking events → tracking records → threads → templates → mailboxes.

### Frontend

**`src/lib/commands.ts`** — Command palette registration for the platform Cmd+K palette. Six commands: Go to Inbox, Go to Sent, Email Templates, Email Settings, Compose Email, Search Emails.

**`src/eldrin-email.tsx`** — Modified to call `registerEmailCommands()` on mount and `unregisterEmailCommands()` on unmount, following the CRM app pattern.

### Documentation

**`docs/API.md`** — Complete cross-app integration API reference with endpoint schemas, event catalog, and integration examples for CRM/Workflows use cases.

## Files created
| File | Purpose |
|------|---------|
| `migrations/007-integration.sql` | Add relatedApp/relatedRecordId columns to emails |
| `worker/routes/integration.ts` | send-template, history, history/record endpoints |
| `worker/routes/events.ts` | Platform event webhook handler |
| `src/lib/commands.ts` | Command palette registration |
| `docs/API.md` | Cross-app integration API documentation |

## Files modified
| File | Change |
|------|--------|
| `worker/db/schema.ts` | Added relatedApp, relatedRecordId columns + index to emails table |
| `worker/index.ts` | Registered integrationRoutes and eventRoutes, removed inline stub |
| `worker/routes/emails.ts` | Extended send body type + stored relatedApp/relatedRecordId |
| `src/eldrin-email.tsx` | Added command palette lifecycle hooks (mount/unmount) |
