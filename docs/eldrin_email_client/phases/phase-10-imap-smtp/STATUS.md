# Phase 10: IMAP/SMTP Support

## Status: skipped
## Started: -
## Completed: -

## Progress:
- [ ] Step 10.1: Create IMAP connection form
- [ ] Step 10.2: Implement IMAP provider
- [ ] Step 10.3: Implement SMTP send
- [ ] Step 10.4: Handle runtime limitations

## Notes:
Skipped — Cloudflare Workers does not reliably support TCP sockets needed for IMAP/SMTP.

The `nodejs_compat` polyfills provide `node:net`/`node:tls` but they're backed by Workers' `connect()` API, which has different semantics than Node.js `net.Socket`. IMAP libraries like `imapflow` are unlikely to work. Additionally, Workers' 30s execution time limit is insufficient for syncing many messages over IMAP.

This was a "Could" priority. Revisit if the primary deployment target moves to Node.js/Bun (standalone/container), where full TCP socket support is available.
