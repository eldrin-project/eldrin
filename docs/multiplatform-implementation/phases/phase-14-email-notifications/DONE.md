# Phase 14: Email & Notification Service — DONE

## Summary
Added a pluggable email provider system with Console (dev), SendGrid (all runtimes), and SMTP (Node.js/Bun) adapters. Includes a simple `{{variable}}` template engine with 6 built-in templates for user lifecycle events. Integrated into user approval/rejection workflow with fire-and-forget semantics.

## Files Created (8 source + 5 test)

### Source
| File | Purpose | Lines |
|------|---------|-------|
| `core/notifications/email/interface.ts` | EmailProvider, EmailMessage, EmailSendResult types | ~30 |
| `core/notifications/email/adapters/console.ts` | Console adapter (dev/test) | ~22 |
| `core/notifications/email/adapters/sendgrid.ts` | SendGrid REST API adapter (all runtimes) | ~55 |
| `core/notifications/email/adapters/smtp.ts` | SMTP adapter via TCP sockets (Node.js/Bun only) | ~120 |
| `core/notifications/email/templates.ts` | Template engine + 6 built-in templates | ~115 |
| `core/notifications/email/factory.ts` | createEmailProvider(secrets) factory | ~35 |
| `core/notifications/email/index.ts` | Barrel exports | ~15 |
| `core/notifications/index.ts` | Top-level barrel | ~2 |

### Tests
| File | Tests |
|------|-------|
| `core/notifications/email/adapters/console.test.ts` | 3 |
| `core/notifications/email/adapters/sendgrid.test.ts` | 4 |
| `core/notifications/email/adapters/smtp.test.ts` | 3 |
| `core/notifications/email/templates.test.ts` | 9 |
| `core/notifications/email/factory.test.ts` | 6 |
| **Total new** | **25** |

## Files Modified
| File | Change |
|------|--------|
| `core/app.ts` | Added `email?: { provider?: EmailProvider }` to CreateAppOptions, pass to approve/reject |
| `core/routes/users.ts` | handleApproveUser/handleRejectUser accept optional EmailProvider, send notification |
| `core/routes/index.ts` | Added EmailProvider, createEmailProvider exports |

## Test Results
```
Test Files  31 passed (31)
     Tests  229 passed (229)
  Duration  777ms
```

## Phase Gate
- [x] All 229 unit tests pass
- [x] TypeScript compiles with zero errors
- [x] Console adapter logs email details
- [x] SendGrid adapter sends via REST API with proper auth
- [x] SMTP adapter builds correct MIME message
- [x] Template engine replaces variables, leaves unknown placeholders
- [x] All 6 built-in templates render correctly
- [x] Factory creates correct adapter from env config
- [x] handleApproveUser sends approval email when provider present
- [x] handleRejectUser sends rejection email when provider present
- [x] Email failures don't block HTTP response (fire-and-forget)
