# Eldrin Email Client — Requirements

## 1. Product Vision

A standalone Eldrin extension app that provides unified email capabilities to the entire platform. Rather than each app (CRM, Invoicing, Support) building its own email integration, `eldrin-email` centralizes mailbox connections, email sending/receiving, templates, and tracking — exposing functionality through platform events and a cross-app API.

**Core principles:**
- **Shared infrastructure** — one OAuth connection serves all apps
- **Event-driven** — apps react to `email.*` events rather than polling or building custom sync
- **Composable** — apps embed the email composer via cross-app API, not by duplicating UI
- **Optional dependency** — apps can function without `eldrin-email` installed; they degrade gracefully

---

## 2. Capabilities

### 2.1 Mailbox Connection & Sync

| ID | Priority | Requirement |
|----|----------|-------------|
| REQ-EM-1.01 | **Must** | Connect Gmail accounts via OAuth 2.0 (scopes: `gmail.readonly`, `gmail.send`, `gmail.compose`) |
| REQ-EM-1.02 | **Must** | Connect Outlook/Microsoft 365 accounts via OAuth 2.0 (scopes: `Mail.Read`, `Mail.Send`, `Mail.ReadWrite`) |
| REQ-EM-1.03 | **Must** | Encrypt access and refresh tokens at rest (AES-GCM, HKDF from platform secret) |
| REQ-EM-1.04 | **Must** | Background sync: fetch new emails every 15 minutes via cron trigger |
| REQ-EM-1.05 | **Must** | Deduplicate by RFC 2822 Message-ID header |
| REQ-EM-1.06 | **Should** | Connect generic IMAP/SMTP accounts (for self-hosted mail servers) |
| REQ-EM-1.07 | **Should** | Manual "Sync now" button for immediate refresh |
| REQ-EM-1.08 | **Could** | Connect multiple mailboxes per user |
| REQ-EM-1.09 | **Must** | Configurable sync depth per mailbox: `full` (store body + metadata), `metadata` (store envelope + snippet, fetch body on demand), or `thread_only` (store thread-level summary, fetch messages on demand). Default: `metadata`. |
| REQ-EM-1.10 | **Must** | On-demand body fetch: when sync depth is `metadata` or `thread_only`, fetch email body from provider API when user opens a thread or when requested via cross-app API. |

### 2.2 Inbox & Email UI

| ID | Priority | Requirement |
|----|----------|-------------|
| REQ-EM-2.01 | **Must** | Inbox view: paginated list with sender, subject, snippet, date, read/unread status |
| REQ-EM-2.02 | **Must** | Thread/conversation view: group messages by thread ID |
| REQ-EM-2.03 | **Must** | Sent mail view |
| REQ-EM-2.04 | **Must** | Search emails by sender, subject, body text |
| REQ-EM-2.05 | **Should** | Labels/folders (synced from provider or custom) |
| REQ-EM-2.06 | **Should** | Archive and trash actions |
| REQ-EM-2.07 | **Could** | Drafts folder (synced) |

### 2.3 Email Composition & Sending

| ID | Priority | Requirement |
|----|----------|-------------|
| REQ-EM-3.01 | **Must** | Rich text email composer (TipTap) with formatting toolbar |
| REQ-EM-3.02 | **Must** | Send email via connected mailbox (Gmail API / Microsoft Graph) |
| REQ-EM-3.03 | **Must** | Reply and Reply All within thread view |
| REQ-EM-3.04 | **Must** | Forward email |
| REQ-EM-3.05 | **Should** | File attachments (stored in R2, attached via provider API) |
| REQ-EM-3.06 | **Should** | Email scheduling: compose now, send at a future date/time |
| REQ-EM-3.07 | **Could** | Inline images in email body |

### 2.4 Email Templates

| ID | Priority | Requirement |
|----|----------|-------------|
| REQ-EM-4.01 | **Must** | Create, edit, delete email templates with name, subject, and body |
| REQ-EM-4.02 | **Must** | Merge fields: `{{variable}}` placeholders resolved at send time |
| REQ-EM-4.03 | **Must** | Template preview with sample data |
| REQ-EM-4.04 | **Should** | Shared team templates with permission controls (personal vs. shared) |
| REQ-EM-4.05 | **Should** | Template categories/tags for organization |
| REQ-EM-4.06 | **Could** | Template analytics: usage count, open/click rates per template |

### 2.5 Email Tracking

| ID | Priority | Requirement |
|----|----------|-------------|
| REQ-EM-5.01 | **Should** | Open tracking via invisible pixel injection |
| REQ-EM-5.02 | **Should** | Click tracking via link wrapping |
| REQ-EM-5.03 | **Should** | Per-email tracking dashboard: opens, clicks, timestamps |
| REQ-EM-5.04 | **Could** | Real-time notification to sender when email is opened |

### 2.6 Cross-App Integration (Events & API)

| ID | Priority | Requirement |
|----|----------|-------------|
| REQ-EM-6.01 | **Must** | Emit `email.received` event when a new email is synced (payload: messageId, from, to, subject, threadId) |
| REQ-EM-6.02 | **Must** | Emit `email.sent` event when an email is sent (payload: messageId, from, to, subject, templateId?) |
| REQ-EM-6.03 | **Must** | Emit `email.opened` event when tracking pixel fires (payload: messageId, recipientEmail) |
| REQ-EM-6.04 | **Must** | Emit `email.clicked` event when a tracked link is clicked (payload: messageId, url) |
| REQ-EM-6.05 | **Must** | Expose `POST /api/email/send` API for other apps to send email through connected mailboxes |
| REQ-EM-6.06 | **Must** | Expose `POST /api/email/send-template` API — accepts templateId + merge field context, resolves and sends |
| REQ-EM-6.07 | **Must** | Expose `GET /api/email/templates` API for other apps to list available templates |
| REQ-EM-6.08 | **Should** | Expose `GET /api/email/history?contactEmail=...` API — returns email history for a given email address (used by CRM contact detail) |
| REQ-EM-6.09 | **Should** | Accept `email.send.requested` event from other apps (fire-and-forget send) |
| REQ-EM-6.10 | **Could** | Expose embeddable email composer that other apps can open via `window.__ELDRIN__` |

### 2.7 Settings & Administration

| ID | Priority | Requirement |
|----|----------|-------------|
| REQ-EM-7.01 | **Must** | User-facing mailbox settings: connect, disconnect, view sync status |
| REQ-EM-7.02 | **Must** | Admin view: all connected mailboxes across users, force disconnect |
| REQ-EM-7.03 | **Should** | Email signature management (per-mailbox signature appended to outbound) |
| REQ-EM-7.04 | **Could** | BCC-to-CRM address generation for manual email logging from external clients |

---

## 3. Event Catalog

Events emitted by `eldrin-email` that other apps can subscribe to:

| Event Type | Trigger | Payload |
|------------|---------|---------|
| `email.received` | New email synced from provider | `{ messageId, threadId, from, fromName, to, subject, snippet, receivedAt }` |
| `email.sent` | Email sent through platform | `{ messageId, from, to, subject, templateId?, relatedApp?, relatedRecordId? }` |
| `email.opened` | Tracking pixel loaded | `{ messageId, recipientEmail, openedAt, userAgent? }` |
| `email.clicked` | Tracked link clicked | `{ messageId, recipientEmail, url, clickedAt }` |
| `email.bounced` | Delivery failure detected | `{ messageId, recipientEmail, bounceType, reason }` |
| `email.mailbox.connected` | New mailbox connected | `{ mailboxId, provider, emailAddress, userId }` |
| `email.mailbox.disconnected` | Mailbox removed | `{ mailboxId, provider, emailAddress, userId }` |
| `email.mailbox.error` | Sync error (token expired, etc.) | `{ mailboxId, provider, errorMessage }` |

Events consumed by `eldrin-email`:

| Event Pattern | Source | Reaction |
|---------------|--------|----------|
| `email.send.requested` | Any app | Send email with provided parameters |
| `user.deleted` | Platform | Clean up mailbox connections and tokens |

---

## 4. CRM Integration Points

When `eldrin-email` is installed alongside `eldrin-crm`:

1. **Contact timeline** — CRM subscribes to `email.received` / `email.sent`, matches sender/recipient against `contact_emails`, creates activity on matching contact
2. **Send from record** — CRM calls `POST /api/app/eldrin-email/api/email/send` with `relatedApp: 'eldrin-crm'` and `relatedRecordId` to send email from within a contact/deal view
3. **Email history on contact detail** — CRM calls `GET /api/app/eldrin-email/api/email/history?contactEmail=...` to show email thread history
4. **Template usage** — CRM fetches templates from email app for merge-field emails (deal follow-ups, lead nurture sequences)
5. **Zero-data entry** — CRM processes `email.received` events to auto-create contacts, parse signatures, and enrich company data

---

## 5. Requirement Summary

| Category | Must | Should | Could | Total |
|----------|------|--------|-------|-------|
| 2.1 Mailbox Connection & Sync | 7 | 2 | 1 | 10 |
| 2.2 Inbox & Email UI | 4 | 2 | 1 | 7 |
| 2.3 Composition & Sending | 4 | 2 | 1 | 7 |
| 2.4 Templates | 3 | 2 | 1 | 6 |
| 2.5 Tracking | 0 | 3 | 1 | 4 |
| 2.6 Cross-App Integration | 7 | 2 | 1 | 10 |
| 2.7 Settings & Admin | 2 | 1 | 1 | 4 |
| **Total** | **27** | **14** | **7** | **48** |
