# Eldrin Email Client — Master Implementation Plan

## Overview

`eldrin-email` is a standalone Eldrin extension app that provides unified email capabilities to the platform. It manages mailbox connections (Gmail, Outlook, IMAP), email sync, composition, templates, and tracking — exposing everything through platform events and cross-app APIs.

**Repository:** `eldrin-email` (new submodule under `/Users/tibor/projects/eldrin/`)
**Stack:** Hono backend, React frontend, D1/Drizzle, single-spa, daisyUI 5
**Pattern:** Follows `eldrin-workflows` extension app architecture

---

## Architecture

```
eldrin-email/
├── public/
│   └── eldrin-app.manifest.json    # App manifest with events, permissions, API routes
├── migrations/
│   ├── 001-mailboxes.sql           # Connected mailboxes, OAuth tokens
│   ├── 002-emails.sql              # Synced emails, threads
│   ├── 003-templates.sql           # Email templates with merge fields
│   └── 004-tracking.sql            # Open/click tracking events
├── worker/
│   ├── index.ts                    # Hono app entry (Cloudflare Worker)
│   ├── db/
│   │   ├── schema.ts              # Drizzle schema (all tables)
│   │   └── index.ts               # DB factory
│   ├── routes/
│   │   ├── mailbox.ts             # OAuth flows, mailbox CRUD
│   │   ├── emails.ts              # Inbox, send, reply, forward
│   │   ├── templates.ts           # Template CRUD
│   │   ├── tracking.ts            # Open pixel, click redirect
│   │   ├── integration.ts         # Cross-app API (send-template, history)
│   │   └── events.ts              # Webhook handler for incoming events
│   ├── services/
│   │   ├── oauth-gmail.ts         # Gmail OAuth 2.0 + API client
│   │   ├── oauth-outlook.ts       # Microsoft Graph OAuth 2.0 + API client
│   │   ├── email-sync.ts          # Background sync engine
│   │   ├── email-send.ts          # Send via provider API
│   │   ├── merge-fields.ts        # Template merge field resolution
│   │   └── tracking.ts            # Pixel injection, link wrapping
│   └── cron.ts                    # Scheduled sync trigger
├── src/
│   ├── root.component.tsx         # Router
│   ├── pages/
│   │   ├── inbox/
│   │   │   ├── InboxList.tsx      # Email list
│   │   │   └── ThreadView.tsx     # Conversation thread
│   │   ├── sent/SentList.tsx
│   │   ├── compose/
│   │   │   └── ComposeModal.tsx   # TipTap email composer
│   │   ├── templates/
│   │   │   ├── TemplateList.tsx
│   │   │   └── TemplateEditor.tsx
│   │   └── settings/
│   │       └── MailboxSettings.tsx # Connect/disconnect mailboxes
│   └── components/
│       └── shared/                 # Reusable UI bits
├── scripts/
│   └── generate-migrations.ts
├── package.json
├── tsconfig.json
├── vite.config.ts
└── wrangler.jsonc
```

---

## Event-Driven Integration Model

### How the CRM consumes email events

```
┌─────────────┐    email.received    ┌──────────────┐
│ eldrin-email│ ──────────────────→  │  eldrin-core │ (platform event bus)
│   (sync)    │    email.sent        │  POST /emit  │
└─────────────┘ ──────────────────→  └──────┬───────┘
                                            │ push delivery
                                            ▼
                                     ┌──────────────┐
                                     │  eldrin-crm  │
                                     │ /api/_events/│
                                     │   webhook    │
                                     └──────┬───────┘
                                            │
                                     Match sender email
                                     against contact_emails
                                            │
                                     Create activity on
                                     matching contact
```

### How the CRM sends email through the email app

```
┌──────────────┐  POST /api/app/eldrin-email/api/email/send   ┌─────────────┐
│  eldrin-crm   │ ──────────────────────────────────────────→ │ eldrin-email│
│ (contact      │  { to, subject, body, relatedApp,           │ (send via   │
│  detail page) │    relatedRecordId, templateId? }           │  Gmail API) │
└──────────────┘                                              └──────┬──────┘
                                                                     │
                                                               email.sent event
                                                                     │
                                                               CRM logs activity
```

---

## Phases

### Phase 1: Project Scaffolding
Set up the `eldrin-email` repository with Hono, Drizzle, Vite, single-spa, daisyUI theme sync, and app manifest. Mirror `eldrin-workflows` boilerplate.

### Phase 2: Mailbox Connection (Gmail)
OAuth 2.0 flow for Gmail, encrypted token storage, mailbox CRUD, settings UI.

### Phase 3: Email Sync Engine
Background cron sync, message parsing, deduplication, inbox storage.

### Phase 4: Inbox & Thread UI
Inbox list page, thread/conversation view, read/unread, search.

### Phase 5: Email Composition & Sending
TipTap composer, send via Gmail API, reply/forward, scheduling.

### Phase 6: Email Templates
Template CRUD, merge field resolution, preview, shared templates.

### Phase 7: Email Tracking
Open pixel injection, click link wrapping, tracking dashboard.

### Phase 8: Cross-App Integration API
`POST /send`, `POST /send-template`, `GET /history`, event emission, webhook handler for `email.send.requested`.

### Phase 9: Outlook / Microsoft 365 Support
OAuth 2.0 for Microsoft Graph, provider abstraction layer, sync + send parity.

### Phase 10: IMAP/SMTP Support (Could)
Generic IMAP connection for self-hosted mail servers.

---

## Implementation Order

```
Phase 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → (10)
```

Phases 1–8 deliver a complete Gmail-based email client with cross-app integration.
Phase 9 adds Outlook support.
Phase 10 is optional (IMAP/SMTP for self-hosted).

---

## App Manifest (Target)

```json
{
  "id": "eldrin-email",
  "name": "Email",
  "version": "0.0.1",
  "entry": "/eldrin-email.js",
  "styles": "/eldrin-email.css",
  "developer_id": "eldrin.io",
  "developer": { "id": "eldrin.io", "name": "Eldrin Team" },
  "compatibility": { "core": ">=0.1.0" },
  "permissions": [
    { "resource": "mailboxes", "actions": ["read", "create", "delete"] },
    { "resource": "emails", "actions": ["read", "send", "archive", "delete"] },
    { "resource": "templates", "actions": ["read", "create", "update", "delete"] },
    { "resource": "tracking", "actions": ["read"] }
  ],
  "groups": [
    {
      "id": "admin",
      "name": "Admin",
      "permissions": ["*:*"]
    },
    {
      "id": "user",
      "name": "User",
      "permissions": [
        "mailboxes:read", "mailboxes:create", "mailboxes:delete",
        "emails:read", "emails:send",
        "templates:read", "templates:create", "templates:update",
        "tracking:read"
      ]
    },
    {
      "id": "viewer",
      "name": "Viewer",
      "permissions": ["emails:read", "templates:read"]
    }
  ],
  "api": {
    "defaultPolicy": "deny",
    "publicRoutes": ["/health", "/track/*"],
    "routes": [
      { "method": "GET", "path": "/inbox", "permission": "emails:read" },
      { "method": "GET", "path": "/inbox/:threadId", "permission": "emails:read" },
      { "method": "GET", "path": "/sent", "permission": "emails:read" },
      { "method": "POST", "path": "/email/send", "permission": "emails:send" },
      { "method": "POST", "path": "/email/send-template", "permission": "emails:send" },
      { "method": "GET", "path": "/email/history", "permission": "emails:read" },
      { "method": "GET", "path": "/templates", "permission": "templates:read" },
      { "method": "POST", "path": "/templates", "permission": "templates:create" },
      { "method": "PATCH", "path": "/templates/:id", "permission": "templates:update" },
      { "method": "DELETE", "path": "/templates/:id", "permission": "templates:delete" },
      { "method": "GET", "path": "/mailboxes", "permission": "mailboxes:read" },
      { "method": "DELETE", "path": "/mailboxes/:id", "permission": "mailboxes:delete" }
    ]
  },
  "database": {
    "name": "eldrin-email",
    "migrationsPath": "migrations",
    "handledBy": "worker"
  },
  "ui": {
    "sideNav": [
      { "label": "Inbox", "icon": "inbox", "path": "/eldrin-email/inbox" },
      { "label": "Sent", "icon": "send", "path": "/eldrin-email/sent" },
      { "label": "Templates", "icon": "file-text", "path": "/eldrin-email/templates" }
    ]
  },
  "events": {
    "emits": [
      { "type": "email.received", "description": "New email synced from provider", "payload": { "messageId": "string", "threadId": "string", "from": "string", "fromName": "string", "to": "string[]", "subject": "string", "snippet": "string", "receivedAt": "number" } },
      { "type": "email.sent", "description": "Email sent through platform", "payload": { "messageId": "string", "from": "string", "to": "string[]", "subject": "string", "templateId": "string?", "relatedApp": "string?", "relatedRecordId": "string?" } },
      { "type": "email.opened", "description": "Tracking pixel loaded", "payload": { "messageId": "string", "recipientEmail": "string", "openedAt": "number" } },
      { "type": "email.clicked", "description": "Tracked link clicked", "payload": { "messageId": "string", "recipientEmail": "string", "url": "string", "clickedAt": "number" } },
      { "type": "email.bounced", "description": "Delivery failure detected", "payload": { "messageId": "string", "recipientEmail": "string", "bounceType": "string", "reason": "string" } },
      { "type": "email.mailbox.connected", "description": "New mailbox connected", "payload": { "mailboxId": "string", "provider": "string", "emailAddress": "string", "userId": "string" } },
      { "type": "email.mailbox.disconnected", "description": "Mailbox disconnected", "payload": { "mailboxId": "string", "provider": "string", "emailAddress": "string" } },
      { "type": "email.mailbox.error", "description": "Sync error occurred", "payload": { "mailboxId": "string", "provider": "string", "errorMessage": "string" } }
    ],
    "subscribes": [
      { "pattern": "email.send.requested", "delivery": "push" },
      { "pattern": "user.deleted", "delivery": "push" }
    ]
  }
}
```

---

## Key Design Decisions

### 1. Sending via provider API (not SMTP)
Email is sent through Gmail API / Microsoft Graph rather than raw SMTP. This means the email appears in the user's "Sent" folder in their actual mail client, maintaining a single source of truth.

### 2. Configurable sync depth
Each mailbox has a `sync_depth` setting (`full` | `metadata` | `thread_only`) that controls how much data is stored locally in D1:

- **`full`** — store everything (body_html, body_text, headers, thread metadata). Instant thread rendering, but D1 grows fast.
- **`metadata`** (default) — store thread + per-message envelope (from, to, subject, date, snippet) but skip body content. Body is fetched on demand from the provider API when the user opens a thread (~200-300ms). Best balance of storage and UX.
- **`thread_only`** — store only `email_threads` rows (subject, participants, last message date, count). Both the message list and body are fetched on demand. Smallest footprint.

The setting is per-mailbox (column on `connected_mailboxes`), configurable from the mailbox settings UI, and defaults to `metadata`. Platform events (`email.received`) are emitted regardless of sync depth — they use the envelope data that is always stored.

### 3. Token encryption matches platform pattern
OAuth tokens are encrypted with AES-GCM using HKDF-derived key from the platform's `JWT_SECRET` (salt: `'eldrin-email-oauth'`). Same pattern as TOTP secret encryption in eldrin-core.

### 4. Tracking endpoints are public
`/track/:trackingId/pixel.gif` and `/track/:trackingId/click` must be publicly accessible (loaded in recipient's email client, outside the platform). Listed in `api.publicRoutes`.

### 5. Cross-app API via platform proxy
Other apps call `POST /api/app/eldrin-email/api/email/send` through the platform proxy. The platform injects the Authorization header, and `eldrin-email` validates the calling app's permissions.

### 6. On-demand body fetch for non-full sync depths
When `sync_depth` is `metadata` or `thread_only`, the thread view API (`GET /api/inbox/:threadId`) transparently fetches message bodies from the provider API, caching the result for the duration of the request. The cross-app history API (`GET /api/email/history`) similarly fetches bodies on demand when a consumer requests `?includeBody=true`. This keeps the architecture consistent — callers don't need to know the sync depth.

---

## Dependencies

| Dependency | Reason |
|------------|--------|
| `eldrin-core >= 0.1.0` | Platform event system, cross-app proxy, auth |
| `@eldrin-project/eldrin-app-core` | SDK (createApp, migrations, database adapter) |
| `@eldrin-project/eldrin-app-react` | React lifecycle (single-spa wrapper) |
| `@tiptap/react` + `@tiptap/starter-kit` | Rich text email composer |
| `hono` | Backend framework |
| `drizzle-orm` | Database ORM |

---

## Relation to CRM

The CRM's Phase 7 (Email Integration) and Phase 10 (Zero-Data Entry) both depend on `eldrin-email`:

- **CRM Phase 7** becomes a thin integration layer: subscribe to email events, call email API for sending, display email history on contact/deal timelines. No email infrastructure in the CRM itself.
- **CRM Phase 10** uses `email.received` events to trigger auto-capture: contact matching, signature parsing, company enrichment. The OAuth and sync complexity lives in `eldrin-email`.

See updated CRM phase plans for details.
