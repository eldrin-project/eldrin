# Phase 9: Outlook / Microsoft 365 Support — DONE

## Summary

Added Microsoft 365 / Outlook support via a provider abstraction layer. Gmail and Outlook now share the same sync, body-fetch, send, and scheduled-send pipelines. All existing Gmail functionality is preserved — the provider is selected at runtime based on the `mailbox.provider` column.

## Files Created

| File | Purpose |
|------|---------|
| `worker/services/providers/types.ts` | `EmailProvider` interface, `MessageRef`, `SendResult`, `ProviderApiError` |
| `worker/services/providers/gmail.ts` | `GmailProvider` — wraps `gmail-client.ts` + `oauth-gmail.ts` |
| `worker/services/providers/outlook.ts` | `OutlookProvider` — Microsoft Graph v1.0 API |
| `worker/services/providers/index.ts` | `getProvider()` factory, shared `getAccessToken()`, `getOAuthConfig()` |
| `worker/services/oauth-outlook.ts` | Microsoft identity platform OAuth 2.0 (authorize, exchange, refresh, user info) |

## Files Modified

| File | Change |
|------|--------|
| `worker/services/email-sync.ts` | Uses provider abstraction for sync (was Gmail-only) |
| `worker/services/body-fetch.ts` | Uses provider abstraction for body fetch (was Gmail-only) |
| `worker/services/scheduled-send.ts` | Uses provider abstraction for scheduled sends (was Gmail-only) |
| `worker/routes/emails.ts` | Send route uses provider abstraction |
| `worker/routes/events.ts` | Event webhook send uses provider abstraction |
| `worker/routes/integration.ts` | Integration API send uses provider abstraction |
| `worker/routes/mailbox.ts` | Added Outlook connect/callback OAuth routes |
| `worker-configuration.d.ts` | Added `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET` |
| `src/api.ts` | Added `connectOutlook()`, extracted shared `connectProvider()` |
| `src/pages/settings/MailboxSettings.tsx` | Enabled Outlook button, provider-agnostic messaging |

## Verification

- `npx tsc --noEmit` — passes
- `npx vite build` — passes (both SSR and client bundles)
- No remaining direct Gmail imports in business logic routes (confirmed via grep)
