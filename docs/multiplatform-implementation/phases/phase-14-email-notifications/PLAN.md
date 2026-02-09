# Phase 14: Email & Notification Service

## Overview

Pluggable email sending with multiple backends (SMTP, SES, SendGrid, Azure Communication Services) and a simple template engine.

## Dependencies

- Phase 2 (unified Hono app)
- Phase 10 (background jobs — email sent via task queue)

## Steps

### 14.1 Email provider interface — `core/notifications/email/interface.ts`

`EmailProvider`: `send(message)` → `{ messageId }`. `EmailMessage`: to, subject, html, text, from, replyTo.

### 14.2 Provider implementations

| File | Backend | Est. lines |
|------|---------|-----------|
| `core/notifications/email/adapters/smtp.ts` | SMTP (nodemailer-compatible) | ~60 |
| `core/notifications/email/adapters/ses.ts` | AWS SES | ~50 |
| `core/notifications/email/adapters/sendgrid.ts` | SendGrid REST API | ~40 |
| `core/notifications/email/adapters/azure-comm.ts` | Azure Communication Services | ~50 |
| `core/notifications/email/adapters/console.ts` | Console logger (dev) | ~15 |

### 14.3 Template engine — `core/notifications/email/templates.ts`

Simple Mustache-style rendering. Built-in templates: welcome, approval-request, approval-granted, password-reset, identity-linked.

### 14.4 Configuration

```
EMAIL_PROVIDER=ses|sendgrid|smtp|azure-comm|console
EMAIL_FROM=noreply@example.com
SMTP_HOST=, SMTP_PORT=, SENDGRID_API_KEY=, etc.
```

### 14.5 Tests

| Test file | Cases |
|-----------|-------|
| `core/notifications/email/adapters/console.test.ts` | ~3 |
| `core/notifications/email/adapters/ses.test.ts` | ~4 (mocked) |
| `core/notifications/email/adapters/sendgrid.test.ts` | ~3 (mocked) |
| `core/notifications/email/templates.test.ts` | ~5 |

## Test Gate

```bash
cd eldrin-core && npx vitest run -- core/notifications/   # ~15 tests
```


## Commit

After all tests pass, commit the changes to the relevant submodule(s) using conventional commits format, then update the parent repo submodule reference.
