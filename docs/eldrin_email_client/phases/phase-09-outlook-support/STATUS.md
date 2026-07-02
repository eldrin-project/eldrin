# Phase 9: Outlook / Microsoft 365 Support

## Status: complete
## Started: 2026-02-17
## Completed: 2026-02-17

## Progress:
- [x] Step 9.1: Create provider abstraction
- [x] Step 9.2: Implement Outlook OAuth service
- [x] Step 9.3: Add Outlook routes
- [x] Step 9.4: Implement Outlook provider
- [x] Step 9.5: Update sync engine for provider abstraction
- [x] Step 9.6: Enable Outlook button in settings UI

## Notes:

### Implementation Details

Provider abstraction (`worker/services/providers/`):
- `types.ts` — `EmailProvider` interface, `MessageRef`, `SendResult`, `IncrementalSyncResult`, `ProviderApiError`
- `gmail.ts` — `GmailProvider` wrapping existing gmail-client.ts + oauth-gmail.ts
- `outlook.ts` — `OutlookProvider` using Microsoft Graph v1.0 API
- `index.ts` — `getProvider()` factory, `getAccessToken()` shared utility, `getOAuthConfig()`

Outlook specifics:
- Microsoft Graph delta sync (`/me/messages/delta`) with `@odata.deltaLink` as cursor
- Draft-then-send pattern for `sendMessage` (Graph `sendMail` doesn't return message ID)
- `conversationId` mapped to `providerThreadId`

Refactored files (all now use provider abstraction instead of direct Gmail calls):
- `email-sync.ts`, `body-fetch.ts`, `scheduled-send.ts`
- `routes/emails.ts`, `routes/events.ts`, `routes/integration.ts`

Frontend:
- Outlook button enabled in MailboxSettings.tsx
- `connectOutlook()` added to api.ts (shared `connectProvider()` helper)
- Provider-agnostic toast messages

Env vars added: `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET`
