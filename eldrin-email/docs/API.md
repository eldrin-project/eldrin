# Eldrin Email — Cross-App Integration API

This document describes the APIs available to other Eldrin apps (CRM, Invoicing, Workflows) for sending emails, querying history, and reacting to email events.

## Authentication

All API requests go through the Eldrin platform proxy. The proxy verifies the user's JWT and injects the `X-Eldrin-User-Id` header. No additional authentication is required from the calling app.

```
POST /api/app/eldrin-email/api/email/send
Authorization: Bearer <platform-jwt>
```

## Endpoints

### POST /api/email/send

Send an email from the user's connected mailbox.

**Request body:**

```json
{
  "mailboxId": "uuid",
  "to": ["recipient@example.com"],
  "cc": ["cc@example.com"],
  "bcc": ["bcc@example.com"],
  "subject": "Hello",
  "bodyHtml": "<p>Hello world</p>",
  "bodyText": "Hello world",
  "inReplyTo": "<message-id>",
  "threadId": "uuid",
  "scheduledAt": 1700000000000,
  "relatedApp": "eldrin-crm",
  "relatedRecordId": "deal-123"
}
```

**Response:**

```json
{ "id": "uuid", "status": "sent", "threadId": "uuid" }
```

### POST /api/email/send-template

Send an email using a template with merge field resolution.

**Request body:**

```json
{
  "templateId": "uuid",
  "to": ["jane@example.com"],
  "cc": ["cc@example.com"],
  "bcc": ["bcc@example.com"],
  "mergeContext": {
    "contact": { "firstName": "Jane", "lastName": "Smith" },
    "deal": { "name": "Enterprise License", "value": "$25,000" }
  },
  "mailboxId": "uuid",
  "relatedApp": "eldrin-crm",
  "relatedRecordId": "deal-123"
}
```

- `mailboxId` is optional — if omitted, the user's first active mailbox is used.
- `mergeContext` maps to template merge fields (e.g., `{{contact.firstName}}`).

**Response:**

```json
{ "id": "uuid", "status": "sent", "threadId": "uuid", "templateId": "uuid" }
```

### GET /api/email/history

Get email history for a contact email address. Used by CRM to show email timeline on contact detail pages.

**Query params:**

| Param | Required | Description |
|-------|----------|-------------|
| `contactEmail` | Yes | Email address to search for |
| `page` | No | Page number (default: 1) |
| `limit` | No | Items per page (default: 25, max: 100) |

**Response:**

```json
{
  "data": [
    {
      "id": "uuid",
      "threadId": "uuid",
      "fromAddress": "user@company.com",
      "fromName": "User Name",
      "toAddresses": ["jane@example.com"],
      "subject": "Re: Proposal",
      "snippet": "Thanks for the proposal...",
      "direction": "outbound",
      "sentAt": 1700000000000,
      "receivedAt": 1700000000000,
      "relatedApp": "eldrin-crm",
      "relatedRecordId": "deal-123",
      "openCount": 3,
      "clickCount": 1
    }
  ],
  "pagination": { "page": 1, "limit": 25, "total": 42, "pages": 2 }
}
```

### GET /api/email/history/record

Get email history linked to a specific record (e.g., all emails tagged to a CRM deal).

**Query params:**

| Param | Required | Description |
|-------|----------|-------------|
| `relatedApp` | Yes | App ID (e.g., `eldrin-crm`) |
| `relatedRecordId` | Yes | Record ID (e.g., deal UUID) |
| `page` | No | Page number (default: 1) |
| `limit` | No | Items per page (default: 25, max: 100) |

**Response:** Same shape as `/api/email/history`.

## Events

### Emitted Events

| Event | Description | Payload |
|-------|-------------|---------|
| `email.sent` | Email sent through platform | `{ messageId, from, to, subject, templateId?, relatedApp?, relatedRecordId? }` |
| `email.received` | New email synced from provider | `{ messageId, threadId, from, to, subject, snippet, receivedAt }` |
| `email.opened` | Tracking pixel loaded by recipient | `{ messageId, recipientEmail, openedAt }` |
| `email.clicked` | Tracked link clicked by recipient | `{ messageId, recipientEmail, url, clickedAt }` |
| `email.bounced` | Email delivery failure | `{ messageId, recipientEmail, bounceType, reason }` |

### Subscribed Events

| Event | Handler |
|-------|---------|
| `email.send.requested` | Sends an email on behalf of the requesting app. Payload: `{ to, subject?, bodyHtml?, templateId?, mergeContext?, relatedApp, relatedRecordId }` |
| `user.deleted` | Cleans up all mailbox connections, synced emails, templates, and tracking data for the deleted user |

## Integration Examples

### CRM: Send email from contact page

```typescript
// Send a direct email
await fetch('/api/app/eldrin-email/api/email/send', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
  body: JSON.stringify({
    to: ['jane@example.com'],
    subject: 'Follow-up: Enterprise License',
    bodyHtml: '<p>Hi Jane, ...</p>',
    relatedApp: 'eldrin-crm',
    relatedRecordId: 'deal-abc123',
  }),
});
```

### CRM: Send using a template

```typescript
await fetch('/api/app/eldrin-email/api/email/send-template', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
  body: JSON.stringify({
    templateId: 'template-uuid',
    to: ['jane@example.com'],
    mergeContext: {
      contact: { firstName: 'Jane', lastName: 'Smith', company: 'Acme Corp' },
      deal: { name: 'Enterprise License', value: '$25,000' },
    },
    relatedApp: 'eldrin-crm',
    relatedRecordId: 'deal-abc123',
  }),
});
```

### CRM: Show email history on contact page

```typescript
const response = await fetch(
  '/api/app/eldrin-email/api/email/history?contactEmail=jane@example.com',
  { headers: { Authorization: `Bearer ${jwt}` } },
);
const { data, pagination } = await response.json();
```

### Workflows: Send email via event

```typescript
// Emit an event — the email app handles it asynchronously
await emitEvent('email.send.requested', {
  to: ['customer@example.com'],
  templateId: 'welcome-template-id',
  mergeContext: { contact: { firstName: 'Alice' } },
  relatedApp: 'eldrin-workflows',
  relatedRecordId: 'workflow-run-xyz',
});
```
