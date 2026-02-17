# Phase 10: IMAP/SMTP Support

## Status: not_started
## Started: -
## Completed: -

## Progress:
- [ ] Step 10.1: Create IMAP connection form
- [ ] Step 10.2: Implement IMAP provider
- [ ] Step 10.3: Implement SMTP send
- [ ] Step 10.4: Handle runtime limitations

## Notes:
This is a "Could" priority phase. Defer unless there is demand.
Cloudflare Workers lack raw TCP sockets — IMAP/SMTP may only work on Node.js/Bun deployments.
