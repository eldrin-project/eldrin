# Phase 10: IMAP/SMTP Support (Could)

## Overview

Add generic IMAP/SMTP support for users with self-hosted mail servers or providers not covered by Gmail/Outlook OAuth. Users provide IMAP/SMTP server details and credentials. This is a "Could" priority — implement only if there's demand.

Covers REQ-EM-1.06.

## Dependencies

- **Phase 9** — Provider abstraction (IMAP becomes another provider)

## Steps

### 10.1 Create IMAP connection form

Add IMAP connection option to MailboxSettings:
- Server hostname, port, encryption (TLS/STARTTLS/none)
- Username and password (encrypted at rest)
- SMTP server settings for sending
- Test connection button

### 10.2 Implement IMAP provider

Create `worker/services/providers/imap.ts`:

- IMAP client for Workers runtime (may need a WebSocket-based proxy or edge-compatible library)
- `listMessages()` — IMAP SEARCH/FETCH since date
- `getMessage()` — IMAP FETCH with BODY
- Email parsing: MIME multipart handling

### 10.3 Implement SMTP send

Create `worker/services/providers/smtp.ts`:

- SMTP client for Workers runtime
- Build MIME message
- TLS support

### 10.4 Handle runtime limitations

Cloudflare Workers have no raw TCP socket support. Options:
- Use a proxy service (e.g., Cloudflare Email Workers, or an external IMAP-to-REST bridge)
- For non-Cloudflare deployments (Node.js): use `nodemailer` or `imapflow` directly
- Document the limitation in the manifest: IMAP/SMTP only available on standalone/container deployments

## Test Gate

```bash
cd eldrin-email && npm run build
cd eldrin-email && npm run test
```

- Connect IMAP account, sync emails
- Send email via SMTP
- Provider abstraction handles IMAP alongside Gmail/Outlook

## Notes

This phase has significant runtime challenges on Cloudflare Workers due to TCP socket restrictions. Consider deferring until multi-cloud deployment (Node.js/Bun) is the primary target, or implement via Cloudflare Email Workers for the CF deployment.

## Finalize

- [ ] Manual validation: IMAP connect, sync, send
- [ ] Document runtime requirements/limitations
- [ ] Commit: `feat(email): add IMAP/SMTP support for self-hosted mail`
- [ ] Update STATUS.md → complete, create DONE.md
