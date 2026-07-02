# Phase 11: Buyer-Side Deal Rooms

## Overview

**DIFFERENTIATOR.** Shared digital workspaces where buyers and sellers collaborate on each deal. A deal room is a branded, externally accessible page linked to a deal record. Buyers authenticate via magic links (no CRM account needed) and can view documents, complete mutual action plan items, and exchange messages. Sellers see engagement analytics on the deal record (who visited, what they viewed, time spent). The buyer-facing frontend is a standalone page served directly by the worker, not a single-spa micro-app.

Covers requirements REQ-1.11.01 through REQ-1.11.13.

## Dependencies

- **Phase 04** — Deals (each room is linked to a deal)

## Steps

### 11.1 Create deal rooms database migration

Create `migrations/009-deal-rooms.sql` with the following tables:

**`deal_rooms`**:
- `id` TEXT PRIMARY KEY (ULID)
- `deal_id` TEXT UNIQUE NOT NULL (FK to deals)
- `title` TEXT NOT NULL
- `welcome_message` TEXT
- `branding` TEXT (JSON: `{ logo_url, primary_color, company_name }`)
- `is_active` INTEGER NOT NULL DEFAULT 1
- `created_by` TEXT NOT NULL
- `created_at` INTEGER NOT NULL
- `updated_at` INTEGER NOT NULL

**`deal_room_invitations`**:
- `id` TEXT PRIMARY KEY (ULID)
- `room_id` TEXT NOT NULL (FK to deal_rooms)
- `email` TEXT NOT NULL
- `name` TEXT NOT NULL
- `role` TEXT NOT NULL (buyer/seller)
- `token_hash` TEXT UNIQUE NOT NULL
- `expires_at` INTEGER NOT NULL
- `accepted_at` INTEGER
- `created_at` INTEGER NOT NULL

**`deal_room_sessions`**:
- `id` TEXT PRIMARY KEY (ULID)
- `room_id` TEXT NOT NULL (FK to deal_rooms)
- `invitation_id` TEXT NOT NULL (FK to deal_room_invitations)
- `session_token_hash` TEXT UNIQUE NOT NULL
- `expires_at` INTEGER NOT NULL
- `created_at` INTEGER NOT NULL

**`deal_room_action_items`**:
- `id` TEXT PRIMARY KEY (ULID)
- `room_id` TEXT NOT NULL (FK to deal_rooms)
- `title` TEXT NOT NULL
- `description` TEXT
- `owner_email` TEXT
- `owner_side` TEXT NOT NULL (buyer/seller)
- `due_date` INTEGER
- `is_completed` INTEGER NOT NULL DEFAULT 0
- `completed_at` INTEGER
- `position` INTEGER NOT NULL DEFAULT 0
- `created_by` TEXT NOT NULL
- `created_at` INTEGER NOT NULL
- `updated_at` INTEGER NOT NULL

**`deal_room_documents`**:
- `id` TEXT PRIMARY KEY (ULID)
- `room_id` TEXT NOT NULL (FK to deal_rooms)
- `name` TEXT NOT NULL
- `file_url` TEXT NOT NULL
- `file_size` INTEGER NOT NULL DEFAULT 0
- `uploaded_by` TEXT NOT NULL
- `uploaded_at` INTEGER NOT NULL
- `view_count` INTEGER NOT NULL DEFAULT 0
- `download_count` INTEGER NOT NULL DEFAULT 0

**`deal_room_messages`**:
- `id` TEXT PRIMARY KEY (ULID)
- `room_id` TEXT NOT NULL (FK to deal_rooms)
- `sender_email` TEXT NOT NULL
- `sender_name` TEXT NOT NULL
- `body` TEXT NOT NULL
- `created_at` INTEGER NOT NULL

**`deal_room_analytics`**:
- `id` TEXT PRIMARY KEY (ULID)
- `room_id` TEXT NOT NULL (FK to deal_rooms)
- `visitor_email` TEXT NOT NULL
- `event_type` TEXT NOT NULL (room_view/section_view/document_view/document_download/action_item_complete)
- `section` TEXT (nullable: overview/action_plan/documents/messages)
- `document_id` TEXT (FK to deal_room_documents, nullable)
- `duration_seconds` INTEGER DEFAULT 0
- `created_at` INTEGER NOT NULL

Add indexes on `deal_rooms(deal_id)`, `deal_room_invitations(room_id, token_hash)`, `deal_room_sessions(session_token_hash)`, `deal_room_action_items(room_id, position)`, `deal_room_documents(room_id)`, `deal_room_messages(room_id)`, `deal_room_analytics(room_id, visitor_email)`.

### 11.2 Add Drizzle schema

Create `worker/db/schema-deal-rooms.ts` with Drizzle table definitions matching the migration. Re-export from `worker/db/schema.ts`.

### 11.3 Create deal room management routes (CRM-side)

Create `worker/routes/deal-rooms.ts` (all endpoints require CRM auth):

- `POST /api/deal-rooms` — create a room linked to a deal
  - Body: `{ dealId, title, welcomeMessage?, branding? }`
  - Validates deal exists and no room exists yet for this deal
  - Returns created room
- `GET /api/deal-rooms/:id` — get room with all content (action items, documents, messages, invitations)
- `PATCH /api/deal-rooms/:id` — update room settings (title, welcome message, branding, is_active)
- `POST /api/deal-rooms/:id/invite` — send invitation to a buyer or seller
  - Body: `{ email, name, role }`
  - Generate random token, hash with SHA-256, store hash in invitation
  - Send email with magic link: `/rooms/:roomId/auth?token=RAW_TOKEN`
  - Set expiry: 30 days from creation
- `DELETE /api/deal-rooms/:id/invitations/:invId` — revoke an invitation (and its active sessions)
- `GET /api/deal-rooms/:id/analytics` — aggregated engagement data:
  - Per visitor: visit count, last visit, total time, documents viewed, action items completed
  - Overall: total visits, unique visitors, most viewed document, action plan completion percentage
- `POST /api/deal-rooms/:id/action-items` — add action item (seller-side)
- `POST /api/deal-rooms/:id/documents` — upload document (with file via multipart)
- `POST /api/deal-rooms/:id/messages` — post message (seller-side)

### 11.4 Create deal room public routes (buyer-facing)

Create `worker/routes/deal-room-public.ts` (no CRM auth, session cookie auth only):

- `GET /rooms/:roomId/auth` — magic link verification
  - Query param: `token` (raw token)
  - Hash the token, look up in `deal_room_invitations`
  - Validate: token exists, not expired, room is active
  - Mark invitation as accepted (`accepted_at`)
  - Create session: generate session token, hash, store in `deal_room_sessions` with 7-day expiry
  - Set `HttpOnly` session cookie scoped to `/rooms/:roomId/`
  - Redirect to `/rooms/:roomId`
- `GET /rooms/:roomId` — render the deal room page
  - Validate session cookie
  - Return the buyer-facing HTML (either server-rendered or SPA bundle)
- `GET /rooms/:roomId/api/content` — get room content for the buyer view
  - Returns: title, welcome message, branding, action items, documents (metadata), messages
- `GET /rooms/:roomId/api/action-items` — list action items
- `PATCH /rooms/:roomId/api/action-items/:itemId` — update action item (check off, buyer-side only for buyer-owned items)
- `GET /rooms/:roomId/api/documents` — list documents
- `GET /rooms/:roomId/api/documents/:docId/download` — tracked download
  - Increment `download_count` on the document
  - Record analytics event (document_download)
  - Return file or redirect to file URL
- `GET /rooms/:roomId/api/messages` — list messages (paginated, newest first)
- `POST /rooms/:roomId/api/messages` — post message (buyer-side)
  - Body: `{ body }`
  - Sender info from session (invitation email and name)

### 11.5 Implement magic link auth

Create `worker/services/deal-room-auth.ts`:

- `generateInvitationToken()` — generate 32 random bytes, encode as URL-safe base64
- `hashToken(token: string)` — SHA-256 hash using Web Crypto API
- `createSession(db, roomId, invitationId)` — generate session token, hash, store, return raw token for cookie
- `validateSession(db, roomId, sessionTokenHash)` — look up session, check expiry, return invitation details
- `extractSessionFromCookie(cookieHeader, roomId)` — parse cookie, extract session token for this room
- Session cookie settings: `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/rooms/:roomId/`, `Max-Age=604800` (7 days)

### 11.6 Implement engagement tracking middleware

Create `worker/middleware/deal-room-tracking.ts`:

- Middleware applied to all buyer-facing routes
- On each request: record an analytics event in `deal_room_analytics`:
  - `room_view` — on page load
  - `section_view` — when navigating to a section (inferred from route or explicit tracking call)
  - `document_view` — when document metadata is accessed
  - `document_download` — on download
  - `action_item_complete` — when an item is checked off
- Extract visitor email from session
- Non-blocking: fire-and-forget insert (do not slow down the response)

### 11.7 Implement deal room notification service

Create `worker/services/deal-room-notifications.ts`:

- Notify deal owner (CRM user) when:
  - A buyer first visits the room
  - A buyer views a specific document
  - A buyer completes an action item
  - A buyer posts a message
- Use the notification system from Phase 09 (`createNotification`)
- Include: visitor name, action description, link to deal room analytics

### 11.8 Build deal room creation UI on deal detail page

Create `src/components/deals/DealRoomPanel.tsx`:

- Shown on the deal detail page as a collapsible panel or tab
- If no room exists: "Create Deal Room" button with configuration form:
  - Title (default: deal name)
  - Welcome message (rich text, optional)
  - Branding: company logo URL, primary color picker, company name
- If room exists:
  - Room status: active/inactive toggle
  - Invitation management: send new invitation (email, name, role), list existing invitations with accepted status, revoke button
  - Quick stats: total visits, unique visitors, last visitor, action plan progress
  - Link to full analytics view
  - "Copy room link" button for sharing without email

### 11.9 Build buyer-facing deal room frontend

Create `src/pages/deal-rooms/DealRoom.tsx`:

This is a **standalone page** — it is NOT mounted via single-spa. It is a separate HTML page served directly by the worker for the `/rooms/:roomId` route. It should be a clean, branded experience with no shell sidebar, no platform navigation, just the deal room content.

Layout:
- Header: seller's company logo (from branding), room title, buyer's name (from session)
- Navigation: section tabs — Overview, Action Plan, Documents, Messages
- Footer: "Powered by Eldrin" (subtle)

**Overview section**: Welcome message, stakeholder map (list of all invited participants with name, email, role)

**Action Plan section**: Shared checklist of action items. Buyer can check off their items. Due dates shown with urgency colors. Progress bar at top showing X of Y items completed.

**Documents section**: List of documents with name, size, upload date. Download button (tracked). View count displayed for seller's documents.

**Messages section**: Threaded message list. Compose box at bottom. Sender name and avatar. Timestamp for each message. Auto-scroll to newest.

Styling:
- Use seller's `primary_color` from branding for accents
- Clean, modern design (daisyUI base but with custom theme override from branding)
- Responsive: works on mobile (buyers may view on phone)

### 11.10 Build mutual action plan component

Create `src/components/deal-rooms/ActionPlan.tsx`:

- Used in both the CRM view (seller-side) and the buyer-facing room
- Shared checklist with items that can be owned by buyer or seller side
- Each item: checkbox, title, description (expandable), owner (name + side badge), due date, completed status
- Drag-and-drop reordering (seller-side only, using @hello-pangea/dnd)
- Add new item form: title, description, owner side (buyer/seller), owner email (from invitations), due date
- Progress bar: X of Y items completed (separate bars for buyer-side and seller-side items)
- Overdue items highlighted in red

### 11.11 Build deal room templates

Create `src/pages/settings/DealRoomTemplates.tsx`:

- Pre-configured room layouts that can be applied when creating a new room
- Each template defines: default welcome message, default action items (titles, descriptions, owner sides), section visibility
- Template CRUD: create, edit, delete, duplicate
- "Apply template" option in the room creation flow
- Store templates in a `deal_room_templates` table (add to migration):

**`deal_room_templates`** (add to 009-deal-rooms.sql):
- `id` TEXT PRIMARY KEY (ULID)
- `name` TEXT NOT NULL
- `welcome_message` TEXT
- `default_action_items` TEXT (JSON array of `{ title, description, owner_side, position }`)
- `created_by` TEXT NOT NULL
- `created_at` INTEGER NOT NULL
- `updated_at` INTEGER NOT NULL

### 11.12 Add engagement summary widget on deal detail page

Create `src/components/deals/DealRoomEngagement.tsx`:

- Compact widget embedded in the deal detail page (alongside the DealRoomPanel)
- Key metrics: last visit (time ago), total visits, unique visitors, documents viewed, documents downloaded, action items completed (X of Y), overall engagement score
- Mini timeline: last 5 buyer activities (visited, viewed document X, completed action item Y)
- Link to full analytics page
- Visual health indicator: green (high engagement), yellow (moderate), red (low/no engagement)

## Test Gate

```bash
cd eldrin-crm && npm run build   # Zero TypeScript errors
cd eldrin-crm && npm run test    # Deal room service tests pass
```

Acceptance criteria:
1. Create a deal room linked to a deal with title, welcome message, and branding
2. Send invitation email with magic link to a buyer
3. Buyer opens magic link, authenticates, sees branded room with all sections
4. Mutual action plan: seller adds items, buyer checks off their items, progress updates on both sides
5. Documents: seller uploads, buyer downloads, download count increments
6. Messages: both sides can post, messages appear in order
7. Engagement analytics: deal owner sees who visited, what they viewed, time spent
8. Deal room notifications: seller gets notified when buyer visits, views document, completes action item
9. Branding: room displays seller's logo and primary color
10. Room templates: create template, apply to new room, action items pre-populated
11. Buyer-facing page is responsive and works on mobile
12. Session management: cookie scoped to room, 7-day expiry, re-auth on expiry

## Files Created

| File | Purpose |
|------|---------|
| `migrations/009-deal-rooms.sql` | Deal rooms, invitations, sessions, action items, documents, messages, analytics, templates |
| `worker/db/schema-deal-rooms.ts` | Drizzle schema for deal room tables |
| `worker/routes/deal-rooms.ts` | CRM-side deal room management endpoints |
| `worker/routes/deal-room-public.ts` | Buyer-facing public routes with session auth |
| `worker/services/deal-room-auth.ts` | Magic link token generation, session management |
| `worker/middleware/deal-room-tracking.ts` | Engagement tracking middleware for buyer actions |
| `worker/services/deal-room-notifications.ts` | Notification triggers for buyer engagement events |
| `src/components/deals/DealRoomPanel.tsx` | Room creation and management UI on deal detail page |
| `src/pages/deal-rooms/DealRoom.tsx` | Buyer-facing standalone deal room page |
| `src/components/deal-rooms/ActionPlan.tsx` | Mutual action plan shared checklist component |
| `src/pages/settings/DealRoomTemplates.tsx` | Room template management page |
| `src/components/deals/DealRoomEngagement.tsx` | Engagement summary widget for deal detail page |

## Files Modified

| File | Change |
|------|--------|
| `worker/db/schema.ts` | Re-export deal room schema tables |
| `worker/index.ts` | Register deal room management and public routes |
| `src/root.component.tsx` | Add deal room template settings route |
| `src/pages/deals/DealDetail.tsx` | Embed DealRoomPanel and DealRoomEngagement components |
| `index.html` | Add separate entry point for buyer-facing room (or use worker-rendered HTML) |

## Finalize

- [ ] Manual validation: create deal room, send invitation, buyer authenticates via magic link
- [ ] Manual validation: mutual action plan works from both buyer and seller sides
- [ ] Manual validation: document upload and tracked download work correctly
- [ ] Manual validation: messaging works bidirectionally
- [ ] Manual validation: engagement analytics accurately reflect buyer activity
- [ ] Manual validation: notifications fire when buyer engages with the room
- [ ] Manual validation: branding (logo, color) applies correctly to buyer-facing page
- [ ] Manual validation: buyer-facing page is responsive on mobile viewport
- [ ] Commit: `feat(crm): add buyer-side deal rooms with mutual action plans and engagement tracking`
- [ ] Update `STATUS.md` → complete, create `DONE.md`
