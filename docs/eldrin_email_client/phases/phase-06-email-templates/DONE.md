# Phase 6: Email Templates — DONE

Completed: 2026-02-17

## What was built

### Backend (Hono worker)
- **Migration** `005-email-templates.sql` — `email_templates` table with indexes on owner_id, is_shared, category
- **Drizzle schema** — `emailTemplates` table definition in `worker/db/schema.ts`
- **Merge field service** (`worker/services/merge-fields.ts`) — `extractMergeFields()`, `resolveMergeFields()`, `getSampleContext()`
- **Template routes** (`worker/routes/templates.ts`) — GET list, GET by id, POST create, PATCH update, DELETE, POST preview, POST usage increment

### Frontend (React)
- **Types** (`src/types/template.ts`) — TemplateSummary, TemplateDetail, CreateTemplateParams, UpdateTemplateParams
- **API client** (`src/api.ts`) — listTemplates, getTemplate, createTemplate, updateTemplate, deleteTemplate, previewTemplate, incrementTemplateUsage
- **TemplateList** (`src/pages/templates/TemplateList.tsx`) — Full-height sticky layout, search, create/edit/delete with confirmation dialog
- **TemplateEditor** (`src/pages/templates/TemplateEditor.tsx`) — Name/subject/category/shared fields, TipTap rich text editor with merge field dropdown, preview panel (sandboxed iframe)
- **ComposeModal** integration — Template selector dropdown (new message mode), merge field insertion toolbar button, usage count increment on send

### Key design decisions
- Merge fields use `{{dotted.path}}` syntax matching CRM/deal/contact/user object structure
- Templates are user-scoped by default, optional `isShared` flag makes them visible to all
- Only template owner can edit/delete
- Preview resolves merge fields server-side with sample data, renders in sandboxed iframe
- Template selector only shows in "new message" mode (not reply/forward) to avoid clobbering quoted content

## Files created
| File | Purpose |
|------|---------|
| `migrations/005-email-templates.sql` | Template table + indexes |
| `worker/services/merge-fields.ts` | Merge field extraction and resolution |
| `worker/routes/templates.ts` | Template CRUD + preview + usage API |
| `src/types/template.ts` | Frontend type definitions |
| `src/pages/templates/TemplateEditor.tsx` | Template editor with TipTap + merge fields |

## Files modified
| File | Change |
|------|--------|
| `worker/db/schema.ts` | Added `emailTemplates` table |
| `worker/index.ts` | Registered `templateRoutes` |
| `src/api.ts` | Added 7 template API functions |
| `src/pages/templates/TemplateList.tsx` | Replaced stub with full implementation |
| `src/pages/compose/ComposeModal.tsx` | Added template selector, merge field toolbar, usage tracking |
| `src/root.component.tsx` | Pass `apiBase` to TemplateList |
