# Phase 2: Mailbox Connection (Gmail) — DONE

## Completed: 2026-02-17

## What was built

### Database
- `migrations/001-mailboxes.sql` — `connected_mailboxes` table with encrypted token columns, sync settings
- `worker/db/schema.ts` — Drizzle ORM schema with indexes on user_id, provider+email (unique), sync_status

### Backend Services
- `worker/services/crypto.ts` — AES-GCM token encryption/decryption via HKDF from JWT_SECRET
- `worker/services/oauth-gmail.ts` — Gmail OAuth 2.0: auth URL, code exchange, token refresh, user info, revocation
- `worker/utils.ts` — `generateId()` + `now()` helpers

### API Routes (`worker/routes/mailbox.ts`)
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/mailbox/connect/gmail` | Redirect to Google OAuth consent |
| GET | `/api/mailbox/callback/gmail` | Handle OAuth callback, encrypt tokens, store mailbox |
| GET | `/api/mailboxes` | List user's connected mailboxes |
| DELETE | `/api/mailboxes/:id` | Disconnect (revoke token, delete record) |
| PATCH | `/api/mailboxes/:id` | Update settings (sync_depth) |
| POST | `/api/mailboxes/:id/pause` | Pause sync |
| POST | `/api/mailboxes/:id/resume` | Resume sync |

### Frontend
- `src/types/mailbox.ts` — Mailbox and SyncDepth types
- `src/api.ts` — Typed API layer with fetch wrapper + OAuth popup helper
- `src/pages/settings/MailboxSettings.tsx` — Full settings UI:
  - "Connect Gmail" button (opens OAuth popup)
  - "Connect Outlook" button (disabled, "Soon" badge)
  - Connected mailbox cards with status indicator, last sync time, sync depth
  - Actions: sync depth selector, pause/resume toggle, disconnect with confirmation
  - Empty state when no mailboxes connected
  - postMessage listener for OAuth popup completion

### Configuration
- `worker-configuration.d.ts` — Added GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET env vars

### Tests (19 passing)
- `crypto.test.ts` (6) — Round-trip, random IV, wrong-key rejection, malformed data, long tokens, special chars
- `oauth-gmail.test.ts` (9) — Auth URL params, code exchange, missing refresh token, HTTP errors, token refresh, user info, revocation
- `health.test.ts` (4) — Manifest validation from Phase 1

## Test gate
- `npm run build` — zero TypeScript errors
- `npm run test` — 19 tests passing
