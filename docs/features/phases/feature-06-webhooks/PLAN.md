# Feature 6: Webhooks

## Overview

External systems register webhook URLs to receive event callbacks when things happen in Eldrin (user created, app installed, etc.). HMAC-signed payloads for verification, retry with exponential backoff, delivery logs. Builds on existing event pub/sub system and background job queue.

## Dependencies

None (builds on existing event pub/sub and task queue).

## Key Pieces

### Database
- New `webhooks` table: id, url, events (JSON array), secret, is_active, created_by, created_at
- New `webhook_deliveries` table: id, webhook_id, event_type, payload, status, status_code, response_time_ms, attempts, next_retry_at, created_at

### Backend
- CRUD: `GET/POST/PATCH/DELETE /api/webhooks`
- `GET /api/webhooks/:id/deliveries` — delivery log
- `POST /api/webhooks/:id/test` — send test payload
- Webhook delivery job: POST to URL with HMAC-SHA256 signature in `X-Eldrin-Signature` header
- Retry: 3 attempts with exponential backoff (1min, 5min, 30min)
- Integration: hook into event pub/sub to trigger webhook deliveries

### Frontend
- Settings page: webhook configuration (URL, event selection, secret display)
- Delivery log table with status, timing, retry info

## Test Gate

```bash
cd eldrin-core && npx tsc -b && npx vitest run
```

1. Create webhook with event filter
2. Trigger event → webhook delivery attempted
3. Verify HMAC signature on receiving end
4. Failed delivery retries with backoff
5. Delivery log shows history

## Detailed plan will be written when implementation begins.
