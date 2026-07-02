# Phase 5: Activity & Task Management

## Overview

Log and schedule all sales activities — calls, emails, meetings, tasks, and notes — linked to contacts, companies, deals, and leads. Covers REQ-1.4.01 through REQ-1.4.08. Activities are the heartbeat of the CRM: they drive the timeline on every record, feed into deal stage requirements, and provide the data for sales activity reporting.

This phase includes a calendar view, quick-log forms for calls and meetings, recurring tasks, and a reminder system with in-app notifications.

## Dependencies

- Phase 2 (contacts and companies for linking activities to records)
- Phase 4 (deals for linking activities — deal stage requirements reference activity types)

## Steps

### 5.1 Create database migration for activities

Create **`migrations/004-activities.sql`**:

```sql
-- Activity types (system defaults + custom)
CREATE TABLE activity_types (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  icon TEXT,
  color TEXT,
  is_system INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

-- Seed default activity types
INSERT INTO activity_types (id, name, icon, color, is_system, created_at) VALUES
  ('type-call', 'Call', 'phone', '#3b82f6', 1, 0),
  ('type-email', 'Email', 'mail', '#8b5cf6', 1, 0),
  ('type-meeting', 'Meeting', 'calendar', '#f59e0b', 1, 0),
  ('type-task', 'Task', 'check-square', '#22c55e', 1, 0),
  ('type-note', 'Note', 'file-text', '#6b7280', 1, 0),
  ('type-lunch', 'Lunch', 'utensils', '#f97316', 1, 0);

-- Core activity record
CREATE TABLE activities (
  id TEXT PRIMARY KEY,
  type_id TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  due_date INTEGER,
  due_time TEXT,
  duration_minutes INTEGER,
  priority TEXT NOT NULL DEFAULT 'medium',
  status TEXT NOT NULL DEFAULT 'pending',
  outcome TEXT,
  next_steps TEXT,
  assignee_id TEXT,
  related_record_id TEXT,
  related_record_type TEXT,
  is_recurring INTEGER NOT NULL DEFAULT 0,
  recurrence_rule TEXT,
  parent_activity_id TEXT,
  is_deleted INTEGER NOT NULL DEFAULT 0,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  completed_at INTEGER,
  FOREIGN KEY (type_id) REFERENCES activity_types(id) ON DELETE RESTRICT,
  FOREIGN KEY (parent_activity_id) REFERENCES activities(id) ON DELETE SET NULL
);

CREATE INDEX idx_activities_type ON activities(type_id);
CREATE INDEX idx_activities_assignee ON activities(assignee_id);
CREATE INDEX idx_activities_due_date ON activities(due_date);
CREATE INDEX idx_activities_status ON activities(status);
CREATE INDEX idx_activities_priority ON activities(priority);
CREATE INDEX idx_activities_related ON activities(related_record_id, related_record_type);
CREATE INDEX idx_activities_is_deleted ON activities(is_deleted);
CREATE INDEX idx_activities_parent ON activities(parent_activity_id);

-- Activity reminders
CREATE TABLE activity_reminders (
  id TEXT PRIMARY KEY,
  activity_id TEXT NOT NULL,
  remind_at INTEGER NOT NULL,
  type TEXT NOT NULL DEFAULT 'in_app',
  is_sent INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (activity_id) REFERENCES activities(id) ON DELETE CASCADE
);

CREATE INDEX idx_reminders_activity ON activity_reminders(activity_id);
CREATE INDEX idx_reminders_remind_at ON activity_reminders(remind_at);
CREATE INDEX idx_reminders_is_sent ON activity_reminders(is_sent);
```

**Priority values**: `low`, `medium`, `high`, `urgent`

**Status values**: `pending`, `completed`, `cancelled`

**Related record types**: `contact`, `company`, `deal`, `lead`

**Recurrence rule** (JSON in `recurrence_rule`):
```json
{
  "frequency": "daily" | "weekly" | "monthly",
  "interval": 1,
  "daysOfWeek": [1, 3, 5],
  "endDate": 1700000000000,
  "maxOccurrences": 10
}
```

### 5.2 Add Drizzle schema for activity tables

Update **`worker/db/schema.ts`** with Drizzle definitions for `activityTypes`, `activities`, `activityReminders`.

Seed default activity types via the migration SQL (not Drizzle seed).

Key points:
- `activities.due_date` is `INTEGER` (Unix ms) — date only, no time zone
- `activities.due_time` is `TEXT` (e.g., `"14:30"`) — local time, optional
- `activities.recurrence_rule` is `TEXT` (JSON) — null for non-recurring
- `activities.related_record_type` is polymorphic — not a FK, resolved in application code
- `activity_reminders.type` is `in_app` or `email`

### 5.3 Create activity CRUD routes

Create **`worker/routes/activities.ts`** as a Hono sub-app:

```
GET    /api/activities              — paginated list with filters
POST   /api/activities              — create activity
GET    /api/activities/:id          — get activity with reminders
PATCH  /api/activities/:id          — update activity
DELETE /api/activities/:id          — soft delete
PATCH  /api/activities/:id/complete — mark as completed (sets completed_at, triggers recurrence)
PATCH  /api/activities/:id/cancel   — mark as cancelled
```

**List endpoint features**:
- Pagination: `?page=1&limit=25`
- Filter by type: `?type_id=type-call`
- Filter by status: `?status=pending`
- Filter by assignee: `?assignee_id=X`
- Filter by priority: `?priority=high,urgent`
- Filter by date range: `?due_after=X&due_before=Y`
- Filter by related record: `?related_record_id=X&related_record_type=contact`
- Sort: `?sort=due_date&order=asc` (default)
- Preset filters: `?preset=my_tasks` (assignee = current user), `?preset=overdue` (due_date < now AND status = pending)

**Sub-resource routes**:
```
POST   /api/activities/:id/reminders      — add reminder
DELETE /api/activities/:id/reminders/:rid  — remove reminder
GET    /api/activity-types                 — list all activity types
POST   /api/activity-types                 — create custom activity type
```

### 5.4 Create calendar data endpoint

Add **`GET /api/activities/calendar`**:

```
GET /api/activities/calendar?start=1700000000000&end=1703000000000&assignee_id=X
```

Returns activities grouped by date for calendar rendering:

```typescript
interface CalendarResponse {
  days: Record<string, Activity[]>;  // key: "YYYY-MM-DD"
  summary: {
    totalActivities: number;
    completedCount: number;
    pendingCount: number;
    overdueCount: number;
  };
}
```

### 5.5 Implement quick-log endpoints

Add simplified creation endpoints for common activity types:

**`POST /api/activities/quick-log/call`**:
```typescript
{
  "contactId": "...",         // or companyId, dealId
  "recordType": "contact",
  "duration_minutes": 15,
  "outcome": "Discussed pricing, interested in Pro plan",
  "next_steps": "Send proposal by Friday",
  "completed": true           // auto-mark as completed
}
```

**`POST /api/activities/quick-log/meeting`**:
```typescript
{
  "contactId": "...",
  "recordType": "deal",
  "title": "Demo presentation",
  "duration_minutes": 60,
  "outcome": "Positive reception, need technical review",
  "next_steps": "Schedule technical deep-dive",
  "completed": true
}
```

These create a full activity record with sensible defaults (type pre-set, title auto-generated if not provided, status set to completed).

### 5.6 Implement recurring task service

Create **`worker/services/recurring-tasks.ts`**:

```typescript
interface RecurrenceResult {
  nextActivityId: string | null;
  nextDueDate: number | null;
}

async function handleRecurrenceOnComplete(
  db: Database,
  activity: Activity,
  userId: string,
): Promise<RecurrenceResult>
```

When a recurring activity is marked as completed:
1. Check `recurrence_rule` is present and valid
2. Calculate next due date based on frequency, interval, and days of week
3. Check end conditions: `endDate` not exceeded, `maxOccurrences` not reached (count siblings with same `parent_activity_id`)
4. If valid: create new activity copying all fields except status (→ pending), due_date (→ next date), completed_at (→ null), set `parent_activity_id` to the original activity
5. Copy reminders from the completed activity to the new one (adjusted to new due date)
6. Return the new activity ID and due date

### 5.7 Implement reminder service

Create **`worker/services/reminders.ts`**:

```typescript
interface ReminderCheck {
  dueReminders: Array<{
    reminder: ActivityReminder;
    activity: Activity;
  }>;
}

async function checkDueReminders(db: Database): Promise<ReminderCheck>
async function markReminderSent(db: Database, reminderId: string): Promise<void>
```

Reminder check runs on a periodic basis (called from a cron trigger or on relevant API requests):
1. Query `activity_reminders` where `remind_at <= now` AND `is_sent = 0`
2. For each: load the associated activity
3. Generate in-app notification (structure for shell notification system)
4. Mark `is_sent = 1`

**In-app notification format** (compatible with shell notification system):
```typescript
{
  type: 'activity_reminder',
  title: 'Reminder: Call with Jane Doe',
  body: 'Due in 15 minutes',
  actionUrl: '/eldrin-crm/activities/{id}',
  userId: activity.assignee_id,
}
```

### 5.8 Implement daily digest endpoint

Add **`GET /api/activities/digest`** — returns today's activity summary for the current user:

```typescript
interface DailyDigest {
  overdue: Activity[];       // due_date < today AND status = pending
  dueToday: Activity[];      // due_date = today AND status = pending
  upcoming: Activity[];      // due_date = tomorrow or next 3 days
  completedToday: Activity[]; // completed_at = today
  stats: {
    overdueCount: number;
    dueTodayCount: number;
    completedTodayCount: number;
  };
}
```

This endpoint powers both the activity dashboard widget and the email digest (future email integration).

### 5.9 Build activity list page

Create **`src/pages/activities/ActivityList.tsx`**:

- Tab navigation: My Tasks | All Activities | Overdue
- DataTable columns: Title, Type (icon + name), Related Record (link), Priority (color badge), Due Date, Assignee, Status
- Overdue highlighting: red text/background for past-due pending activities
- Priority badges: urgent (red), high (orange), medium (blue), low (gray)
- Quick complete: checkbox in row to mark as completed without opening detail
- Bulk actions: change assignee, change priority, mark completed, delete
- New activity button → creation form with type selector

### 5.10 Build calendar view

Create **`src/pages/activities/CalendarView.tsx`**:

- Toggle between Day, Week, and Month views
- Custom CSS grid layout (no external calendar library dependency)
- Day view: hourly slots with activities placed by due_time
- Week view: 7-day grid with activities as colored blocks per type
- Month view: date grid with activity count dots, click to expand day
- Color-coded by activity type (matches `activity_types.color`)
- Click activity → opens detail/edit inline or navigates to detail page
- Click empty slot → quick-create activity for that date/time
- Today highlighted, overdue days marked

### 5.11 Build quick-log forms

Create quick-log components for the two most common activity types:

**`src/components/activities/QuickLogCall.tsx`**:
- Minimal form: related record (contact/company/deal search), duration (preset buttons: 5m, 15m, 30m, 1h), outcome textarea, next steps textarea
- Auto-sets type to Call, status to completed
- Can be opened from contact detail, deal detail, or activity list

**`src/components/activities/QuickLogMeeting.tsx`**:
- Minimal form: title, related record, duration (preset: 30m, 1h, 2h), outcome textarea, next steps textarea
- Auto-sets type to Meeting, status to completed

Both forms:
- Compact modal/drawer layout
- On submit: call quick-log endpoint, show success toast, refresh parent view
- "Log & Create Follow-up" button: logs current activity and opens new task creation pre-filled with next steps

## Test Gate

```bash
cd eldrin-crm && npm run build   # Clean build with activity schema types
cd eldrin-crm && npm run dev     # Dev server + migrations create activity tables
```

Acceptance criteria:
1. Activity types: 6 system defaults seeded (Call, Email, Meeting, Task, Note, Lunch)
2. Activity CRUD: create with type, due date, priority, assignee, related record
3. Task completion: mark as completed, sets `completed_at`
4. Recurring tasks: completing a recurring task auto-creates the next instance
5. Calendar view: activities displayed on correct dates, color-coded by type
6. Overdue highlighting: past-due pending activities shown in red
7. Quick-log call: minimal form creates completed call activity
8. Quick-log meeting: minimal form creates completed meeting activity
9. Reminders: creating a reminder, checking due reminders
10. Daily digest: overdue + due today + completed today for current user
11. Activity timeline appears on contact, company, and deal detail pages

## Files Created

| File | Purpose |
|------|---------|
| `migrations/004-activities.sql` | Schema for activity types, activities, reminders |
| `worker/routes/activities.ts` | Activity CRUD + calendar + quick-log + digest endpoints |
| `worker/services/recurring-tasks.ts` | Recurrence handling on task completion |
| `worker/services/reminders.ts` | Due reminder check and notification generation |
| `src/pages/activities/ActivityList.tsx` | Activity list with tabs, priority badges, quick complete |
| `src/pages/activities/CalendarView.tsx` | Day/Week/Month calendar grid |
| `src/components/activities/QuickLogCall.tsx` | Minimal call logging form |
| `src/components/activities/QuickLogMeeting.tsx` | Minimal meeting logging form |
| `src/components/activities/ActivityForm.tsx` | Full activity creation/edit form |
| `src/stores/activityStore.ts` | Zustand store for activity list state and filters |
| `src/types/activity.ts` | Activity TypeScript types |

## Files Modified

| File | Change |
|------|--------|
| `worker/db/schema.ts` | Add activity_types, activities, activity_reminders tables |
| `worker/index.ts` | Register activity route group |
| `src/root.component.tsx` | Add routing for activity list and calendar pages |
| `src/api.ts` | Add activity API client functions |
| `src/pages/contacts/ContactDetail.tsx` | Integrate activity timeline and quick-log buttons |
| `src/pages/companies/CompanyDetail.tsx` | Integrate activity timeline and quick-log buttons |
| `src/pages/deals/DealDetail.tsx` | Integrate activity timeline and quick-log buttons |

## Finalize

- [ ] Manual validation: create activities of different types, verify on calendar view
- [ ] Manual validation: complete a recurring task, verify next instance is created
- [ ] Manual validation: quick-log a call from a contact detail page, verify it appears in timeline
- [ ] Manual validation: verify overdue activities highlighted in list and calendar
- [ ] Commit: `feat: add activity and task management with calendar, quick-log, and reminders`
- [ ] Update `STATUS.md` → complete, create `DONE.md`
