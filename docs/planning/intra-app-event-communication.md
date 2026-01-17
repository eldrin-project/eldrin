# Server-Side Intra-App Event Communication System

## Overview

A server-side pub/sub event system enabling Eldrin apps to communicate via events. Apps declare events they emit and subscribe to in their manifest. The platform handles event routing, delivery (poll or push), and access control.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Eldrin Core Worker                               │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                   Event Bus Service                           │  │
│  │  POST /api/events/emit         - Apps emit events             │  │
│  │  GET  /api/events/poll         - Apps poll pending events     │  │
│  │  POST /api/events/ack          - Acknowledge processed event  │  │
│  │  GET  /api/events/types        - List registered event types  │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                              │                                       │
│  ┌───────────────────────────┴───────────────────────────────────┐  │
│  │               D1 Database (eldrin-platform)                   │  │
│  │  - events               (persisted event log)                 │  │
│  │  - event_subscriptions  (app subscriptions from manifest)     │  │
│  │  - event_deliveries     (pending/delivered per subscriber)    │  │
│  │  - dead_letter_events   (failed after max retries)            │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
         │                              │
         │ Push (webhook)               │ Poll
         ▼                              ▼
┌─────────────────┐          ┌─────────────────┐
│   Invoicing     │          │      CRM        │
│   emits:        │          │   subscribes:   │
│   invoice.*     │─────────▶│   invoice.*     │
│   client.*      │          │   (poll mode)   │
└─────────────────┘          └─────────────────┘
```

---

## Database Schema

### Migration: `20251228000001-create-event-tables.sql`

```sql
-- Event log
CREATE TABLE events (
  id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  source_app TEXT NOT NULL,
  payload TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  idempotency_key TEXT,
  created_at INTEGER NOT NULL,
  UNIQUE(source_app, idempotency_key)
);
CREATE INDEX idx_events_type ON events(event_type);
CREATE INDEX idx_events_created ON events(created_at);

-- Subscriptions (from manifest)
CREATE TABLE event_subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  subscriber_app TEXT NOT NULL,
  event_pattern TEXT NOT NULL,
  delivery_mode TEXT NOT NULL DEFAULT 'poll',  -- 'poll' or 'push'
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  UNIQUE(subscriber_app, event_pattern)
);

-- Delivery tracking
CREATE TABLE event_deliveries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL REFERENCES events(id),
  subscriber_app TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',  -- pending, delivered, failed
  delivery_mode TEXT NOT NULL DEFAULT 'poll',
  attempts INTEGER NOT NULL DEFAULT 0,
  last_attempt_at INTEGER,
  delivered_at INTEGER,
  error_message TEXT,
  created_at INTEGER NOT NULL,
  UNIQUE(event_id, subscriber_app)
);
CREATE INDEX idx_deliveries_pending ON event_deliveries(subscriber_app, status);

-- Dead letter queue
CREATE TABLE dead_letter_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL,
  subscriber_app TEXT NOT NULL,
  event_type TEXT NOT NULL,
  payload TEXT NOT NULL,
  error_message TEXT,
  attempts INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
```

---

## Manifest Extension

### File: `eldrin-app.manifest.json`

```json
{
  "id": "invoicing",
  "name": "Invoicing",
  "version": "0.0.3",
  "events": {
    "emits": [
      {
        "type": "invoice.created",
        "description": "Fired when a new invoice is created",
        "payload": {
          "invoiceId": "string",
          "customerId": "string",
          "total": "number"
        }
      },
      { "type": "invoice.paid" },
      { "type": "client.created" }
    ],
    "subscribes": [
      {
        "pattern": "catalog.product.*",
        "delivery": "poll",
        "description": "Sync product changes"
      }
    ]
  }
}
```

### TypeScript Types

```typescript
// In eldrin-core/src/types/manifest.ts
interface EventDeclaration {
  type: string;
  description?: string;
  payload?: Record<string, string>;
}

interface SubscriptionDeclaration {
  pattern: string;
  delivery: 'poll' | 'push';
  description?: string;
}

interface EventsConfig {
  emits?: EventDeclaration[];
  subscribes?: SubscriptionDeclaration[];
}

interface AppManifest {
  // ... existing fields
  events?: EventsConfig;
}
```

---

## Event SDK (eldrin-app-core)

### New Files

| File | Purpose |
|------|---------|
| `src/events/types.ts` | TypeScript types for events |
| `src/events/client.ts` | Event client for app workers |
| `src/events/index.ts` | Public exports |

### Client API

```typescript
// Usage in app worker
import { createEventClient } from '@eldrin-project/eldrin-app-core';

const events = createEventClient(env, 'invoicing');

// Emit event
await events.emit('invoice.created', {
  invoiceId: 'inv_123',
  customerId: 'cust_456',
  total: 1500
}, { idempotencyKey: 'invoice-created-inv_123' });

// Poll for events (for apps using poll mode)
const pending = await events.poll(10);
for (const delivery of pending) {
  await processEvent(delivery.event);
  await events.ack(delivery.id);
}
```

---

## Core Worker API Routes

### Add to `eldrin-core/worker/index.ts`

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/events/emit` | POST | Emit event (validates app can emit this type) |
| `/api/events/poll` | GET | Get pending events for app |
| `/api/events/ack` | POST | Mark event as delivered |
| `/api/events/types` | GET | List all registered event types |

### Event Flow

1. **Emit**: App POSTs to `/api/events/emit`
2. **Validate**: Core checks app's manifest allows emitting this event type
3. **Store**: Event persisted to `events` table
4. **Fan-out**: Create `event_deliveries` for each matching subscriber
5. **Deliver**:
   - **Poll**: Subscriber fetches via `/api/events/poll`
   - **Push**: Core POSTs to subscriber's `/api/_events/receive` endpoint

### Access Control

- Apps can **only emit** event types declared in their `events.emits`
- Apps can **only receive** events matching patterns in their `events.subscribes`
- Subscriptions are registered when app is enabled (from manifest)

---

## Files to Create/Modify

### New Files

| Path | Description |
|------|-------------|
| `eldrin-core/worker/events/emit.ts` | Handle event emission |
| `eldrin-core/worker/events/poll.ts` | Handle event polling |
| `eldrin-core/worker/events/ack.ts` | Handle acknowledgment |
| `eldrin-core/worker/events/push.ts` | Push delivery to webhooks |
| `eldrin-core/worker/events/types.ts` | Shared types |
| `eldrin-core/migrations/20251228000001-create-event-tables.sql` | DB schema |
| `eldrin-app-core/src/events/types.ts` | Event type definitions |
| `eldrin-app-core/src/events/client.ts` | Event client class |
| `eldrin-app-core/src/events/index.ts` | Public exports |

### Files to Modify

| Path | Changes |
|------|---------|
| `eldrin-core/worker/index.ts` | Add event API routes |
| `eldrin-core/src/types/manifest.ts` | Add `events` field to AppManifest |
| `eldrin-core/src/services/manifestLoader.ts` | Parse events config, register subscriptions |
| `eldrin-app-core/src/index.ts` | Export event client |
| `eldrin-invoicing/worker/index.ts` | Example: emit events |
| `eldrin-invoicing/public/eldrin-app.manifest.json` | Add events config |

---

## Implementation Phases

### Phase 1: Database & Types
1. Create migration for event tables
2. Add `EventsConfig` to `AppManifest` type
3. Define event SDK types

### Phase 2: Core Event Service
1. Implement `/api/events/emit` with validation
2. Implement `/api/events/poll` for subscribers
3. Implement `/api/events/ack` for delivery confirmation
4. Add subscription registration on app enable

### Phase 3: SDK Client
1. Create `EldrinEventClient` class
2. Implement `emit()`, `poll()`, `ack()` methods
3. Export from `eldrin-app-core`

### Phase 4: Push Delivery
1. Implement push delivery worker
2. Add retry logic with exponential backoff
3. Move to dead letter after max attempts

### Phase 5: Example Integration
1. Update invoicing manifest with events
2. Add event emission to invoicing worker
3. Create example subscriber in CRM app

---

## Reliability Features

- **At-least-once delivery**: Events persisted before delivery
- **Idempotency**: Optional key prevents duplicate events
- **Retry logic**: Failed push deliveries retry with backoff
- **Dead letter queue**: Failed events after 5 attempts
- **Checksum/versioning**: Event payloads are versioned

---

## Cloudflare Workers Considerations

- **30s timeout**: Batch polling limited to 20 events
- **No persistent connections**: Poll-based or fire-and-forget push
- **D1 transactions**: Each event emission is atomic
- **Service bindings**: Future optimization for direct worker calls
