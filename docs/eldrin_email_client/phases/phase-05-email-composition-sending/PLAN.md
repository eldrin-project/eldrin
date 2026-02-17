# Phase 5: Email Composition & Sending

## Overview

Build the TipTap-powered email composer and implement sending via Gmail API. Users can compose new emails, reply within threads, forward messages, and optionally schedule sends. Sent emails appear in the sent folder and emit `email.sent` events.

Covers REQ-EM-3.01 through REQ-EM-3.06, REQ-EM-6.02.

## Dependencies

- **Phase 3** — Email sync (to store sent emails)
- **Phase 4** — Thread view (reply/forward context)

## Steps

### 5.1 Create send email route

Add to `worker/routes/emails.ts`:

- `POST /api/email/send` — send an email via connected mailbox
  - Body: `{ mailboxId, to, cc?, bcc?, subject, bodyHtml, bodyText?, inReplyTo?, threadId?, scheduledAt? }`
  - Decrypt mailbox tokens, call Gmail API `messages.send`
  - Store in `emails` table with direction `outbound`
  - Update or create thread
  - Emit `email.sent` platform event
  - If `scheduledAt` provided: store with status `scheduled`, don't send yet

### 5.2 Implement Gmail send client

Add to `worker/services/gmail-client.ts`:

- `sendMessage(accessToken, message)` — Gmail `messages.send` API
  - Build RFC 2822 message (from, to, cc, bcc, subject, body MIME parts)
  - Handle HTML + plaintext multipart
- `replyToMessage(accessToken, threadId, inReplyTo, message)` — reply preserving thread
- Base64url encode the raw message for Gmail API

### 5.3 Implement scheduled send handler

Create `worker/services/scheduled-send.ts`:

- Query emails where `status = 'scheduled'` and `scheduled_at <= now()`
- Send each via Gmail API
- Update status to `sent`, set `sent_at`
- Add to cron handler in `worker/cron.ts` (check every minute or on each 15-min cycle)

### 5.4 Build ComposeModal component

Create `src/pages/compose/ComposeModal.tsx`:

- Modal/drawer that overlays current page
- To, CC, BCC input fields with email validation (pill-style multi-input)
- Subject line
- TipTap rich text editor with toolbar: bold, italic, underline, link, bullet list, numbered list
- Send button + dropdown: "Send now" / "Schedule for later"
- Schedule date/time picker (shown when "Schedule" selected)
- Discard button with confirmation

### 5.5 Implement reply and forward

Extend ThreadView and ComposeModal:

- "Reply" button: open ComposeModal with `to` prefilled (original sender), `subject` prefixed with "Re:", `inReplyTo` set, quoted body
- "Reply All": same but include all original recipients in `to`/`cc`
- "Forward": open ComposeModal with empty `to`, `subject` prefixed with "Fwd:", original body included

### 5.6 Add compose trigger to inbox

- Floating "Compose" button on InboxList page
- Opens ComposeModal for new email composition
- After send: close modal, refresh inbox/sent list

## Test Gate

```bash
cd eldrin-email && npm run build
cd eldrin-email && npm run test
```

- Compose and send an email → appears in Gmail's Sent folder
- Reply within a thread → preserves thread
- Forward an email → new thread with forwarded content
- Scheduled email stored with correct timestamp, sent when due
- `email.sent` event emitted after sending

## Files Created

| File | Purpose |
|------|---------|
| `src/pages/compose/ComposeModal.tsx` | TipTap email composer |
| `worker/services/scheduled-send.ts` | Scheduled send processor |

## Files Modified

| File | Change |
|------|--------|
| `worker/routes/emails.ts` | Add send endpoint |
| `worker/services/gmail-client.ts` | Add sendMessage, replyToMessage |
| `worker/cron.ts` | Add scheduled send check |
| `src/pages/inbox/ThreadView.tsx` | Add reply/forward buttons |
| `src/pages/inbox/InboxList.tsx` | Add compose button |
| `package.json` | Add TipTap dependencies |

## Finalize

- [ ] Manual validation: compose and send email, verify in Gmail sent folder
- [ ] Manual validation: reply preserves thread
- [ ] Manual validation: schedule send works
- [ ] Commit: `feat(email): add email composer with send, reply, and scheduling`
- [ ] Update STATUS.md → complete, create DONE.md
