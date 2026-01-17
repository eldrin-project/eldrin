# Future Improvements

A collection of features and improvements to implement in upcoming development cycles.

---

## 1. App Lifecycle - Automatic Subscription Registration

**Priority:** High
**Related:** Event Communication System

Currently, event subscriptions must be manually registered via `/api/events/sync-subscriptions` or direct database inserts. This should be automated as part of the app enable/disable lifecycle.

### Proposed Implementation

```
┌─────────────────────────────────────────────────────────────┐
│  POST /api/apps/enable                                      │
│  1. Set platform_apps.enabled = 1                           │
│  2. Fetch app manifest                                      │
│  3. Register event_subscriptions from manifest.events       │
│  4. Return success                                          │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  POST /api/apps/disable                                     │
│  1. Set platform_apps.enabled = 0                           │
│  2. Disable event_subscriptions (enabled = 0)               │
│  3. Return success                                          │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  POST /api/apps/refresh (or on app update)                  │
│  1. Fetch latest manifest                                   │
│  2. Re-sync event_subscriptions                             │
│  3. Return success                                          │
└─────────────────────────────────────────────────────────────┘
```

### Files to Modify

- `eldrin-core/worker/index.ts` - Add enable/disable/refresh endpoints
- Consider: App installation flow in admin UI

### Current Workaround

Use the temporary `/api/events/sync-subscriptions` endpoint:
```bash
curl -X POST http://localhost:4000/api/events/sync-subscriptions \
  -H "Content-Type: application/json" \
  -d '{"appId": "invoicing"}'
```

Or manually insert into database:
```sql
INSERT INTO event_subscriptions
  (subscriber_app, event_pattern, delivery_mode, enabled, created_at, updated_at)
VALUES
  ('invoicing', 'todo.*', 'push', 1, 1735395966000, 1735395966000);
```

---
