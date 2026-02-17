# Phase 6: Email Templates

## Overview

Implement email template management with merge field support. Users create reusable templates with `{{variable}}` placeholders that are resolved at send time. Templates can be personal or shared with the team. Other apps (CRM, Invoicing) can fetch and use these templates through the cross-app API.

Covers REQ-EM-4.01 through REQ-EM-4.05, REQ-EM-6.07.

## Dependencies

- **Phase 5** — Email composition (templates integrate with the composer)

## Steps

### 6.1 Create template migration

Create `migrations/003-templates.sql`:

**`email_templates`**:
- `id` TEXT PRIMARY KEY
- `name` TEXT NOT NULL
- `subject` TEXT NOT NULL
- `body_html` TEXT NOT NULL
- `body_text` TEXT
- `merge_fields` TEXT — JSON array of field names detected in template
- `category` TEXT — optional grouping tag
- `is_shared` INTEGER NOT NULL DEFAULT 0
- `usage_count` INTEGER NOT NULL DEFAULT 0
- `owner_id` TEXT NOT NULL
- `created_by` TEXT NOT NULL
- `created_at` INTEGER NOT NULL
- `updated_at` INTEGER NOT NULL

Indexes: `(owner_id)`, `(is_shared)`, `(category)`.

### 6.2 Add Drizzle schema

Add email_templates table to `worker/db/schema.ts`.

### 6.3 Create template routes

Create `worker/routes/templates.ts`:

- `GET /api/templates` — list templates (user's own + shared), optional `?category=` filter
- `GET /api/templates/:id` — get single template
- `POST /api/templates` — create template, auto-detect merge fields from body
- `PATCH /api/templates/:id` — update (owner or admin only)
- `DELETE /api/templates/:id` — delete (owner or admin only)

### 6.4 Implement merge field service

Create `worker/services/merge-fields.ts`:

- `extractMergeFields(html)` — regex to find all `{{...}}` placeholders, return list
- `resolveMergeFields(html, context)` — replace `{{field.name}}` with values from context object
  - Supported fields: `{{contact.firstName}}`, `{{contact.lastName}}`, `{{contact.email}}`, `{{company.name}}`, `{{deal.name}}`, `{{deal.value}}`, `{{user.name}}`, `{{user.email}}`, custom fields
  - Unresolved fields: replace with empty string
- `getSampleContext()` — return sample data for template preview

### 6.5 Integrate templates with composer

Update `ComposeModal.tsx`:
- Template selector dropdown at top of composer
- Selecting a template populates subject and body
- "Insert merge field" button/dropdown in toolbar — inserts `{{...}}` at cursor
- Preview mode: resolve merge fields with sample data

### 6.6 Build template management page

Create `src/pages/templates/TemplateList.tsx`:
- Table: name, subject preview, shared badge, usage count, owner, actions
- Create button → opens editor
- Click row → opens editor
- Delete with confirmation

Create `src/pages/templates/TemplateEditor.tsx`:
- Name input
- Subject input (supports merge fields)
- TipTap body editor
- Merge field insertion toolbar
- Shared toggle (checkbox)
- Category input
- Live preview tab: shows template with sample merge field values
- Save / Cancel buttons

### 6.7 Increment usage count on send

When sending an email with `templateId`, increment `usage_count` on the template.

## Test Gate

```bash
cd eldrin-email && npm run build
cd eldrin-email && npm run test
```

- Create template with merge fields → fields auto-detected
- Use template in composer → subject and body populated
- Preview mode shows resolved merge fields with sample data
- Shared template visible to other users
- Template API accessible by other apps (`GET /api/templates`)

## Files Created

| File | Purpose |
|------|---------|
| `migrations/003-templates.sql` | Email templates table |
| `worker/routes/templates.ts` | Template CRUD endpoints |
| `worker/services/merge-fields.ts` | Merge field extraction and resolution |
| `src/pages/templates/TemplateList.tsx` | Template list page |
| `src/pages/templates/TemplateEditor.tsx` | Template editor page |

## Files Modified

| File | Change |
|------|--------|
| `worker/db/schema.ts` | Add email_templates table |
| `worker/index.ts` | Register template routes |
| `src/pages/compose/ComposeModal.tsx` | Add template selector and merge field insertion |
| `src/root.component.tsx` | Add template editor route |

## Finalize

- [ ] Manual validation: create template, use in composer, merge fields resolve
- [ ] Manual validation: shared templates visible to other users
- [ ] Commit: `feat(email): add email templates with merge field support`
- [ ] Update STATUS.md → complete, create DONE.md
