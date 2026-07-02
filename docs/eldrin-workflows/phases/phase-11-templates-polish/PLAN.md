# Phase 11: Templates & Polish

## Overview

Add pre-built workflow templates that users can clone to get started quickly, plus UX improvements across the entire app. This is the final polish phase that makes the app feel production-ready.

Detailed plan will be written when implementation begins.

## Dependencies

- Phase 7 (frontend editor — templates need the editor for customization)
- Phase 10 (advanced features — templates showcase advanced step types)

## Key Deliverables

### Built-in templates

From requirements:

| Template | Trigger | Steps |
|----------|---------|-------|
| Welcome email | `user.created` | send_email |
| Admin notification | `user.created` where role=admin | http_request (Slack) |
| Cleanup old data | cron daily | call_app_api |
| Invoice follow-up | `invoice.overdue` | delay 3d → send_email |
| App install report | `app.installed` | http_request (analytics) + send_email (admin) |

### Template gallery UI
- **Templates page** (`/workflows/templates`) — card grid of available templates
- Each card: name, description, trigger type icon, step count, "Use Template" button
- "Use Template" → clones to editor pre-filled, user customizes and saves

### Template API
- `GET /templates` — list available templates
- Templates stored as static JSON (bundled, not in DB)
- Extensible: future versions could allow user-created templates

### UX polish
- Loading skeletons for all list pages
- Error states with retry buttons
- Empty states with call-to-action
- Confirmation dialogs for destructive actions (delete workflow, cancel run)
- Workflow duplicate action (copy existing workflow)
- Improved search/filter (by trigger type, status, date range)
- Toast notifications for all mutations (Sonner)
- Keyboard shortcuts (Ctrl+S to save in editor)

## Test Gate

- Template gallery loads with 5 templates
- "Use Template" opens editor pre-filled with template definition
- Customizing and saving creates a new workflow
- All pages show appropriate loading/error/empty states
- Delete/cancel show confirmation before executing
- Duplicate creates a copy with "(Copy)" suffix

## Finalize

- [ ] Commit: `feat: add workflow templates and UX polish`
- [ ] Update `STATUS.md` → complete, create `DONE.md`
