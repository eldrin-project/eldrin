# Phase 2: Mailbox Connection (Gmail)

## Overview

Implement Gmail OAuth 2.0 connection flow, encrypted token storage, and the mailbox settings UI. Users can connect their Gmail account, see its sync status, and disconnect it. This phase establishes the provider pattern that Phase 9 (Outlook) will extend.

Covers REQ-EM-1.01, REQ-EM-1.03, REQ-EM-1.09, REQ-EM-7.01, REQ-EM-7.02.

## Dependencies

- **Phase 1** — Project scaffolding (Hono app, DB layer, frontend)

## Steps

### 2.1 Create mailbox database migration

Create `migrations/001-mailboxes.sql`:

**`connected_mailboxes`**:
- `id` TEXT PRIMARY KEY
- `user_id` TEXT NOT NULL
- `provider` TEXT NOT NULL (gmail/outlook/imap)
- `email_address` TEXT NOT NULL
- `display_name` TEXT
- `access_token_encrypted` TEXT NOT NULL
- `refresh_token_encrypted` TEXT NOT NULL
- `token_expires_at` INTEGER NOT NULL
- `last_sync_at` INTEGER
- `sync_status` TEXT NOT NULL DEFAULT 'active' (active/paused/error)
- `sync_depth` TEXT NOT NULL DEFAULT 'metadata' — controls local storage: 'full' | 'metadata' | 'thread_only'
- `sync_cursor` TEXT — provider-specific cursor for incremental sync
- `error_message` TEXT
- `created_at` INTEGER NOT NULL
- `updated_at` INTEGER NOT NULL

Indexes: `(user_id)`, `(provider, email_address)` UNIQUE, `(sync_status)`.

### 2.2 Add Drizzle schema

Add mailbox table to `worker/db/schema.ts`.

### 2.3 Implement Gmail OAuth service

Create `worker/services/oauth-gmail.ts`:

- `getGmailAuthUrl(redirectUri, state)` — Google OAuth consent URL with scopes: `gmail.readonly`, `gmail.send`, `gmail.compose`
- `exchangeGmailCode(code, redirectUri)` — exchange authorization code for tokens
- `refreshGmailToken(refreshToken)` — refresh expired access token
- Token encryption: AES-GCM with HKDF from env `JWT_SECRET` (salt: `'eldrin-email-oauth'`)
- `encryptToken(token, secret)` / `decryptToken(encrypted, secret)` helpers

### 2.4 Create mailbox routes

Create `worker/routes/mailbox.ts`:

- `GET /api/mailbox/connect/gmail` — redirect to Google OAuth consent
- `GET /api/mailbox/callback/gmail` — handle callback, exchange code, encrypt tokens, store mailbox
- `GET /api/mailboxes` — list user's connected mailboxes
- `DELETE /api/mailboxes/:id` — disconnect: revoke token, delete record
- `PATCH /api/mailboxes/:id` — update mailbox settings (sync_depth)
- `POST /api/mailboxes/:id/pause` — set sync_status to `paused`
- `POST /api/mailboxes/:id/resume` — set sync_status to `active`

### 2.5 Build mailbox settings UI

Create `src/pages/settings/MailboxSettings.tsx`:

- "Connect Gmail" button with Google logo
- "Connect Outlook" button (disabled, "Coming soon")
- List of connected mailboxes: email, provider icon, sync status badge, last sync time
- Per-mailbox actions: Pause/Resume toggle, Disconnect (with confirmation dialog)
- Sync depth selector per mailbox: dropdown with three options:
  - **Full** — "Store complete emails locally (fastest browsing, uses more storage)"
  - **Metadata only** (default) — "Store headers and snippets, fetch body on demand"
  - **Thread summary** — "Store minimal thread data, fetch everything on demand (smallest storage)"
  - Changing sync depth takes effect on next sync (does not retroactively delete stored bodies)
- Status indicators: green dot (active), yellow (paused), red (error + message)
- Empty state: illustration + "Connect your email to get started"

### 2.6 Emit mailbox events

After connecting/disconnecting, emit platform events:
- `email.mailbox.connected` — via `POST /api/events/emit`
- `email.mailbox.disconnected`
- `email.mailbox.error` (on sync failures, emitted in Phase 3)

## Test Gate

```bash
cd eldrin-email && npm run build
cd eldrin-email && npm run test    # OAuth flow tests (mocked Google API)
```

- OAuth flow: clicking "Connect Gmail" redirects to Google, callback stores encrypted tokens
- Mailbox list shows connected account with status
- Disconnect revokes token and removes record
- Pause/resume toggles sync_status
- Tokens are encrypted at rest (verify encrypted column is not plaintext)

## Files Created

| File | Purpose |
|------|---------|
| `migrations/001-mailboxes.sql` | Mailbox table |
| `worker/services/oauth-gmail.ts` | Gmail OAuth 2.0 + token encryption |
| `worker/routes/mailbox.ts` | OAuth flows, mailbox CRUD |
| `src/pages/settings/MailboxSettings.tsx` | Mailbox settings UI |

## Files Modified

| File | Change |
|------|--------|
| `worker/db/schema.ts` | Add mailbox table |
| `worker/index.ts` | Register mailbox routes |
| `src/root.component.tsx` | Add settings route |

## Finalize

- [ ] Manual validation: connect Gmail, see mailbox in list, disconnect
- [ ] Manual validation: tokens are encrypted in D1 (not plaintext)
- [ ] Commit: `feat(email): add Gmail OAuth mailbox connection`
- [ ] Update STATUS.md → complete, create DONE.md
