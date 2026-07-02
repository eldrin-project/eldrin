# Phase 9: System & UX Foundations

## Overview

Build the cross-cutting capabilities that support the entire CRM application: global search across all entities, in-app notifications with badge counts, a browsable audit trail with field-level change history, soft delete with a recycle bin (30-day retention), saved views for entity lists, and integration with the platform Cmd+K command palette. These features operate across all entity types and provide the polish expected from a production-quality application.

Covers requirements REQ-1.9.01 through REQ-1.9.08.

## Dependencies

- **Phase 02** — Contacts and companies exist for search, audit trail, and recycle bin
- **Phase 03** — Leads exist for search, audit trail, and recycle bin
- **Phase 04** — Deals exist for search, audit trail, and recycle bin

## Steps

### 9.1 Create system database migration

Create `migrations/007-system.sql` with the following tables:

**`notifications`**:
- `id` TEXT PRIMARY KEY (ULID)
- `user_id` TEXT NOT NULL
- `title` TEXT NOT NULL
- `body` TEXT
- `type` TEXT NOT NULL DEFAULT 'info' (info/warning/success/error)
- `related_record_id` TEXT
- `related_record_type` TEXT (contact/company/lead/deal/activity)
- `is_read` INTEGER NOT NULL DEFAULT 0
- `created_at` INTEGER NOT NULL

**`recycle_bin`**:
- `id` TEXT PRIMARY KEY (ULID)
- `record_id` TEXT NOT NULL
- `record_type` TEXT NOT NULL (contact/company/lead/deal/activity)
- `record_data` TEXT NOT NULL (JSON snapshot of the full record at deletion time)
- `deleted_by` TEXT NOT NULL
- `deleted_at` INTEGER NOT NULL
- `expires_at` INTEGER NOT NULL (deleted_at + 30 days in epoch seconds)

**`saved_views`**:
- `id` TEXT PRIMARY KEY (ULID)
- `user_id` TEXT NOT NULL
- `entity_type` TEXT NOT NULL (contacts/companies/leads/deals/activities)
- `name` TEXT NOT NULL
- `columns` TEXT NOT NULL (JSON array of visible column names)
- `filters` TEXT NOT NULL (JSON object of active filter criteria)
- `sort` TEXT NOT NULL (JSON object: `{ field, direction }`)
- `is_default` INTEGER NOT NULL DEFAULT 0
- `created_at` INTEGER NOT NULL
- `updated_at` INTEGER NOT NULL

Add indexes on `notifications(user_id, is_read)`, `recycle_bin(record_type, expires_at)`, `saved_views(user_id, entity_type)`.

### 9.2 Add Drizzle schema

Create `worker/db/schema-system.ts` with Drizzle table definitions matching the migration. Re-export from `worker/db/schema.ts`.

### 9.3 Create global search endpoint

Create `worker/routes/search.ts`:

- `GET /api/search?q=term` — full-text search across all CRM entities
  - Search contacts by first_name, last_name, email
  - Search companies by name, domain
  - Search leads by name, email, company
  - Search deals by name
  - Search activities by subject
  - Return grouped results: `{ contacts: [...], companies: [...], leads: [...], deals: [...], activities: [...] }`
  - Each result includes: id, display name, type label, link path
  - Limit to 5 results per entity type (25 total max)
  - Use SQL LIKE queries with `%term%` (SQLite does not support full-text by default; upgrade to FTS5 in a future phase if needed)

### 9.4 Register CRM commands with platform Cmd+K

Create `src/lib/commands.ts`:

- Call `window.__ELDRIN__.registerCommands()` with a CRM command provider
- Register quick navigation commands:
  - "Go to Contacts" → `/eldrin-crm/contacts`
  - "Go to Companies" → `/eldrin-crm/companies`
  - "Go to Leads" → `/eldrin-crm/leads`
  - "Go to Deals" → `/eldrin-crm/deals`
  - "Go to Activities" → `/eldrin-crm/activities`
  - "Go to Reports" → `/eldrin-crm/reports`
- Register search command with drill-down:
  - "Search CRM..." → opens search input → calls `/api/search` → shows results → click navigates to record
- Register quick action commands:
  - "Create Contact" → opens contact form
  - "Create Deal" → opens deal form
  - "Create Lead" → opens lead form
  - "Log Activity" → opens activity form
- Unregister on app unmount (handled by `unregisterApp` in the SDK)

### 9.5 Create notification routes

Create `worker/routes/notifications.ts`:

- `GET /api/notifications` — list notifications for the current user, paginated, newest first
- `GET /api/notifications/unread-count` — return `{ count: N }`
- `PATCH /api/notifications/:id/read` — mark single notification as read
- `POST /api/notifications/read-all` — mark all notifications as read for the current user

### 9.6 Implement notification service

Create `worker/services/notifications.ts`:

- `createNotification(db, { userId, title, body, type, relatedRecordId, relatedRecordType })` — insert notification record
- Trigger notifications on key CRM events:
  - Task assigned to a user → notify the assignee
  - Deal stage changed → notify deal owner
  - Lead assigned to a user → notify the assignee
  - Activity overdue → notify the owner (checked on API request, not real-time)
  - Import completed → notify the user who started it
- `getUnreadCount(db, userId)` — count query for badge display

### 9.7 Enhance audit trail with browsable UI

Extend the audit logging from Phase 02:

- `GET /api/audit?record_id=X&record_type=Y` — get field-level change history for a specific record
  - Return list of audit entries: timestamp, user, action, field changes
  - Field changes: `{ field: string, old_value: any, new_value: any }[]`
- Ensure all CRUD operations across contacts, companies, leads, deals, and activities log field-level changes (old value vs. new value) in the audit table
- `GET /api/audit?entity_type=X` — browse all changes for an entity type (admin view), paginated

### 9.8 Implement soft delete and recycle bin

Modify delete handlers across all entity types to use soft delete:

- On delete request: instead of hard delete, copy full record data (JSON) to `recycle_bin` table, then hard delete from the entity table (keeps queries simple, no `is_deleted` filter everywhere)
- Set `expires_at` to 30 days from deletion

Create `worker/routes/recycle-bin.ts`:

- `GET /api/recycle-bin` — list deleted records, paginated, newest first
  - Filter by `record_type` query param
  - Return: id, record_type, display name (extracted from record_data), deleted_by, deleted_at, days until expiry
- `POST /api/recycle-bin/:id/restore` — restore a record
  - Read record_data from recycle bin
  - Re-insert into the original entity table
  - Delete from recycle_bin
  - Return the restored record
- Scheduled cleanup: on any recycle bin API call, also purge expired records (where `expires_at < now`)

### 9.9 Build notification center component

Create `src/components/shared/NotificationCenter.tsx`:

- Dropdown panel triggered from CRM header area (bell icon)
- Unread badge count (red dot with number)
- List of notifications: icon by type (info/warning/success/error), title, body preview, time ago
- Click notification: mark as read, navigate to related record
- "Mark all as read" button
- Empty state: "No notifications"
- Poll for unread count every 60 seconds (or on window focus)

### 9.10 Build recycle bin page

Create `src/pages/settings/RecycleBin.tsx`:

- Table: record type icon, record name, deleted by (user name), deleted at (relative time), days until permanent deletion
- Filter by record type (tabs or dropdown)
- Restore button per row (with confirmation)
- Bulk restore (checkbox selection)
- Empty state: "Recycle bin is empty"
- Warning banner: "Records are permanently deleted after 30 days"

### 9.11 Build audit trail viewer component

Create `src/components/shared/AuditTrail.tsx`:

- Embedded on record detail pages (contacts, companies, leads, deals)
- Timeline format: newest change at top
- Each entry shows: user avatar/name, action (created/updated/deleted), timestamp
- For updates: expandable field change list showing old value → new value (with diff highlighting)
- Pagination: "Load more" button for long histories
- Filter by user or date range (optional)

### 9.12 Build saved views manager

Create `src/components/shared/SavedViews.tsx`:

- Dropdown above entity list tables
- "Save current view" — captures current columns, filters, and sort settings
- "Load view" — dropdown of saved views for this entity type
- "Set as default" — loads this view automatically on page visit
- "Delete view" — remove a saved view
- "Reset to default" — clear all customizations

Create routes in `worker/routes/saved-views.ts`:
- `GET /api/saved-views?entity_type=X` — list views for current user and entity
- `POST /api/saved-views` — create view
- `PATCH /api/saved-views/:id` — update view
- `DELETE /api/saved-views/:id` — delete view

## Test Gate

```bash
cd eldrin-crm && npm run build   # Zero TypeScript errors
cd eldrin-crm && npm run test    # System service tests pass
```

Acceptance criteria:
1. Global search returns results across contacts, companies, leads, deals, and activities
2. Cmd+K integration: CRM navigation commands and search drill-down work from the platform palette
3. Notifications appear on key events (task assigned, deal stage changed, lead assigned)
4. Unread notification count displays correctly, marking as read updates the badge
5. Audit trail on a record detail page shows field-level change history with old/new values
6. Soft delete moves record to recycle bin, record no longer appears in entity lists
7. Restore from recycle bin re-creates the record, it appears back in entity lists
8. Saved views: save a filter+column configuration, reload page, apply saved view, data matches
9. Dark mode: all system components render correctly

## Files Created

| File | Purpose |
|------|---------|
| `migrations/007-system.sql` | Notifications, recycle bin, and saved views tables |
| `worker/db/schema-system.ts` | Drizzle schema for system tables |
| `worker/routes/search.ts` | Global search endpoint across all entities |
| `worker/routes/notifications.ts` | Notification CRUD and unread count endpoints |
| `worker/routes/recycle-bin.ts` | Soft delete recycle bin list, restore, and cleanup |
| `worker/routes/saved-views.ts` | Saved view CRUD endpoints |
| `worker/services/notifications.ts` | Notification creation service for CRM events |
| `src/lib/commands.ts` | Cmd+K command registration for platform palette |
| `src/components/shared/NotificationCenter.tsx` | Notification dropdown with badge count |
| `src/pages/settings/RecycleBin.tsx` | Recycle bin management page |
| `src/components/shared/AuditTrail.tsx` | Field-level change history timeline component |
| `src/components/shared/SavedViews.tsx` | Saved view manager dropdown for entity lists |

## Files Modified

| File | Change |
|------|--------|
| `worker/db/schema.ts` | Re-export system schema tables |
| `worker/index.ts` | Register search, notification, recycle-bin, and saved-views routes |
| `src/root.component.tsx` | Add recycle bin settings route, integrate notification center |
| `src/eldrin-crm.tsx` | Register Cmd+K commands on mount, unregister on unmount |
| `worker/routes/contacts.ts` | Soft delete: move to recycle bin instead of hard delete |
| `worker/routes/companies.ts` | Soft delete: move to recycle bin instead of hard delete |
| `worker/routes/leads.ts` | Soft delete: move to recycle bin instead of hard delete |
| `worker/routes/deals.ts` | Soft delete: move to recycle bin instead of hard delete |
| `worker/routes/activities.ts` | Soft delete: move to recycle bin instead of hard delete |
| `src/pages/contacts/ContactList.tsx` | Add saved views dropdown |
| `src/pages/companies/CompanyList.tsx` | Add saved views dropdown |
| `src/pages/leads/LeadList.tsx` | Add saved views dropdown |
| `src/pages/deals/DealList.tsx` | Add saved views dropdown |

## Finalize

- [ ] Manual validation: global search finds records across all entity types
- [ ] Manual validation: Cmd+K palette shows CRM commands and search drill-down
- [ ] Manual validation: notifications fire on task assignment, deal stage change, lead assignment
- [ ] Manual validation: delete a contact, verify it appears in recycle bin, restore it, verify it returns to contact list
- [ ] Manual validation: audit trail on a contact shows field changes with old/new values
- [ ] Manual validation: save a view with filters and columns, reload page, apply view, verify state
- [ ] Commit: `feat(crm): add global search, notifications, audit trail, recycle bin, and saved views`
- [ ] Update `STATUS.md` → complete, create `DONE.md`
