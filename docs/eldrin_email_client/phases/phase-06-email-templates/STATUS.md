# Phase 6: Email Templates

## Status: complete
## Started: 2026-02-17
## Completed: 2026-02-17

## Progress:
- [x] Step 6.1: Create template migration (005-email-templates.sql)
- [x] Step 6.2: Add Drizzle schema (emailTemplates in schema.ts)
- [x] Step 6.3: Create template routes (worker/routes/templates.ts — CRUD + preview + usage)
- [x] Step 6.4: Implement merge field service (worker/services/merge-fields.ts)
- [x] Step 6.5: Integrate templates with composer (template selector + merge field toolbar)
- [x] Step 6.6: Build template management page (TemplateList.tsx + TemplateEditor.tsx)
- [x] Step 6.7: Increment usage count on send (via selectedTemplateId in ComposeModal)

## Notes:
- Migration numbered 005 (not 003 as originally planned — 003 and 004 were added by phases 3-5)
- Merge field syntax: `{{dotted.path}}` e.g. `{{contact.firstName}}`
- Four field groups: Contact, Company, Deal, User
- Preview uses sandboxed iframe (same pattern as ThreadView email body rendering)
- Template selector only appears in "new message" compose mode (not reply/forward)
- Usage count incremented client-side after successful send (fire-and-forget)
