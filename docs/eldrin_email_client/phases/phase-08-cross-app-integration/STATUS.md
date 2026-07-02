# Phase 8: Cross-App Integration API

## Status: complete
## Started: 2026-02-17
## Completed: 2026-02-17

## Progress:
- [x] Step 8.1: Create integration routes (send-template, history, history/record)
- [x] Step 8.2: Implement event webhook handler (email.send.requested, user.deleted)
- [x] Step 8.3: Document cross-app API contract (docs/API.md)
- [x] Step 8.4: Add CRM-friendly response enrichments (tracking data, direction, relatedApp in history)
- [x] Step 8.5: Register commands for global search (Cmd+K palette)

## Notes:
- Migration 007 adds `related_app` and `related_record_id` columns to emails table
- Existing `POST /api/email/send` extended with `relatedApp`/`relatedRecordId` optional fields
- `send-template` auto-selects first active mailbox when `mailboxId` not specified
- Event handler uses `waitUntil()` for async processing after immediate acknowledgment
- `user.deleted` handler cascades: tracking events → tracking records → threads → templates → mailboxes
- Command palette registers 6 commands: inbox, sent, templates, settings, compose, search
- Single-spa lifecycle mount/unmount hooks follow CRM app pattern
