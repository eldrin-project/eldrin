# Phase 9: Outlook / Microsoft 365 Support

## Overview

Add Microsoft 365 / Outlook support by implementing the Microsoft Graph OAuth 2.0 flow and extending the sync and send services with a provider abstraction. After this phase, users can connect either Gmail or Outlook — the email app handles both transparently.

Covers REQ-EM-1.02.

## Dependencies

- **Phase 2** — Mailbox connection pattern (Gmail)
- **Phase 3** — Sync engine
- **Phase 5** — Send service

## Steps

### 9.1 Create provider abstraction

Refactor sync and send services into a provider interface:

Create `worker/services/providers/types.ts`:
```typescript
interface EmailProvider {
  listMessages(accessToken: string, since: number, cursor?: string): Promise<MessageListResult>;
  getMessage(accessToken: string, messageId: string): Promise<ParsedEmail>;
  sendMessage(accessToken: string, message: ComposeMessage): Promise<SendResult>;
  refreshToken(refreshToken: string): Promise<TokenResult>;
}
```

Create `worker/services/providers/gmail.ts` — extract existing Gmail logic into provider interface.

### 9.2 Implement Outlook OAuth service

Create `worker/services/oauth-outlook.ts`:

- `getOutlookAuthUrl(redirectUri, state)` — Microsoft identity platform OAuth URL
  - Scopes: `Mail.Read`, `Mail.Send`, `Mail.ReadWrite`, `offline_access`
- `exchangeOutlookCode(code, redirectUri)` — exchange code for tokens
- `refreshOutlookToken(refreshToken)` — refresh expired token
- Same AES-GCM encryption as Gmail tokens

### 9.3 Add Outlook routes

Add to `worker/routes/mailbox.ts`:
- `GET /api/mailbox/connect/outlook` — redirect to Microsoft OAuth
- `GET /api/mailbox/callback/outlook` — handle callback, store encrypted tokens

### 9.4 Implement Outlook provider

Create `worker/services/providers/outlook.ts`:

- `listMessages()` — Microsoft Graph `messages` endpoint with `$filter`, `$orderby`, `$select`
- `getMessage()` — Graph `messages/{id}` with body content
- `sendMessage()` — Graph `sendMail` endpoint
- `refreshToken()` — Microsoft token endpoint
- Handle Outlook-specific parsing (MIME differences, thread detection via `conversationId`)

### 9.5 Update sync engine for provider abstraction

Modify `email-sync.ts`:
- Detect provider from mailbox record
- Instantiate correct provider: `getProvider(mailbox.provider)`
- Sync logic is provider-agnostic (uses `EmailProvider` interface)

### 9.6 Enable Outlook button in settings UI

Update `MailboxSettings.tsx`:
- Remove "Coming soon" from Outlook button
- Outlook connect flow works identically to Gmail

## Test Gate

```bash
cd eldrin-email && npm run build
cd eldrin-email && npm run test
```

- Connect Outlook account via OAuth
- Sync fetches Outlook emails
- Send email via Outlook
- Reply/forward works with Outlook threads
- Provider abstraction: Gmail still works after refactor

## Files Created

| File | Purpose |
|------|---------|
| `worker/services/providers/types.ts` | Provider interface definition |
| `worker/services/providers/gmail.ts` | Gmail provider (refactored) |
| `worker/services/providers/outlook.ts` | Outlook / Microsoft Graph provider |
| `worker/services/oauth-outlook.ts` | Outlook OAuth 2.0 service |

## Files Modified

| File | Change |
|------|--------|
| `worker/routes/mailbox.ts` | Add Outlook OAuth routes |
| `worker/services/email-sync.ts` | Use provider abstraction |
| `worker/services/gmail-client.ts` | Refactor into providers/gmail.ts |
| `src/pages/settings/MailboxSettings.tsx` | Enable Outlook button |

## Finalize

- [ ] Manual validation: connect Outlook, sync emails, send email
- [ ] Manual validation: Gmail still works after refactor
- [ ] Commit: `feat(email): add Outlook/Microsoft 365 support with provider abstraction`
- [ ] Update STATUS.md → complete, create DONE.md
