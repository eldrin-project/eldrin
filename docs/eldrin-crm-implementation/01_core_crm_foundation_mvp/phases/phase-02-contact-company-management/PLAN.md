# Phase 2: Contact & Company Management

## Overview

Build the foundational data model and full CRUD for contacts and companies. Covers REQ-1.1.01 through REQ-1.1.12. This is the core of the CRM — every other module (leads, deals, activities) links back to contacts and companies. Includes multi-value fields (emails, phones, social profiles), company-contact relationships with roles, parent-child company hierarchies, duplicate detection, full-text search, tag management, audit trail, and activity timeline.

## Dependencies

- Phase 1 (project scaffolding — repo, deps, configs, Hono skeleton, Drizzle factory exist)

## Steps

### 2.1 Create database migration for contacts and companies

Create **`migrations/001-contacts-companies.sql`** with all foundational tables:

```sql
-- Core contact record
CREATE TABLE contacts (
  id TEXT PRIMARY KEY,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  job_title TEXT,
  department TEXT,
  address_line1 TEXT,
  address_line2 TEXT,
  city TEXT,
  state TEXT,
  postal_code TEXT,
  country TEXT,
  avatar_url TEXT,
  source TEXT,
  notes TEXT,
  owner_id TEXT,
  is_deleted INTEGER NOT NULL DEFAULT 0,
  deleted_at INTEGER,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX idx_contacts_name ON contacts(last_name, first_name);
CREATE INDEX idx_contacts_owner ON contacts(owner_id);
CREATE INDEX idx_contacts_is_deleted ON contacts(is_deleted);

-- Multi-value email addresses
CREATE TABLE contact_emails (
  id TEXT PRIMARY KEY,
  contact_id TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  is_primary INTEGER NOT NULL DEFAULT 0,
  label TEXT,
  FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
);

CREATE INDEX idx_contact_emails_contact ON contact_emails(contact_id);
CREATE INDEX idx_contact_emails_email ON contact_emails(email);

-- Multi-value phone numbers
CREATE TABLE contact_phones (
  id TEXT PRIMARY KEY,
  contact_id TEXT NOT NULL,
  phone TEXT NOT NULL,
  is_primary INTEGER NOT NULL DEFAULT 0,
  label TEXT,
  FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
);

CREATE INDEX idx_contact_phones_contact ON contact_phones(contact_id);

-- Social profile links
CREATE TABLE contact_social_profiles (
  id TEXT PRIMARY KEY,
  contact_id TEXT NOT NULL,
  platform TEXT NOT NULL,
  url TEXT NOT NULL,
  FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
);

CREATE INDEX idx_contact_social_contact ON contact_social_profiles(contact_id);

-- Core company record
CREATE TABLE companies (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  domain TEXT,
  industry TEXT,
  size TEXT,
  revenue_range TEXT,
  phone TEXT,
  website TEXT,
  address_line1 TEXT,
  address_line2 TEXT,
  city TEXT,
  state TEXT,
  postal_code TEXT,
  country TEXT,
  logo_url TEXT,
  parent_company_id TEXT,
  notes TEXT,
  owner_id TEXT,
  is_deleted INTEGER NOT NULL DEFAULT 0,
  deleted_at INTEGER,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY (parent_company_id) REFERENCES companies(id) ON DELETE SET NULL
);

CREATE INDEX idx_companies_name ON companies(name);
CREATE INDEX idx_companies_domain ON companies(domain);
CREATE INDEX idx_companies_owner ON companies(owner_id);
CREATE INDEX idx_companies_parent ON companies(parent_company_id);
CREATE INDEX idx_companies_is_deleted ON companies(is_deleted);

-- Many-to-many: contact <-> company with role
CREATE TABLE contact_company_relations (
  id TEXT PRIMARY KEY,
  contact_id TEXT NOT NULL,
  company_id TEXT NOT NULL,
  role TEXT,
  is_primary INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE,
  FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE,
  UNIQUE (contact_id, company_id)
);

CREATE INDEX idx_ccr_contact ON contact_company_relations(contact_id);
CREATE INDEX idx_ccr_company ON contact_company_relations(company_id);

-- Tags (shared across record types)
CREATE TABLE tags (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  color TEXT,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

-- Polymorphic tag assignments
CREATE TABLE record_tags (
  record_id TEXT NOT NULL,
  record_type TEXT NOT NULL,
  tag_id TEXT NOT NULL,
  PRIMARY KEY (record_id, record_type, tag_id),
  FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
);

CREATE INDEX idx_record_tags_record ON record_tags(record_id, record_type);
CREATE INDEX idx_record_tags_tag ON record_tags(tag_id);

-- Field-level audit trail
CREATE TABLE audit_trail (
  id TEXT PRIMARY KEY,
  record_id TEXT NOT NULL,
  record_type TEXT NOT NULL,
  field_name TEXT NOT NULL,
  old_value TEXT,
  new_value TEXT,
  changed_by TEXT NOT NULL,
  changed_at INTEGER NOT NULL
);

CREATE INDEX idx_audit_record ON audit_trail(record_id, record_type);
CREATE INDEX idx_audit_changed_at ON audit_trail(changed_at);
```

### 2.2 Add Drizzle schema definitions

Update **`worker/db/schema.ts`** with Drizzle table definitions matching the migration SQL. Use `sqliteTable` from `drizzle-orm/sqlite-core`. Define all columns, indexes, foreign keys, and unique constraints.

Export all tables: `contacts`, `contactEmails`, `contactPhones`, `contactSocialProfiles`, `companies`, `contactCompanyRelations`, `tags`, `recordTags`, `auditTrail`.

Type notes:
- `INTEGER` with `mode: 'boolean'` for `is_deleted`, `is_primary`
- `INTEGER` with `mode: 'number'` for timestamps (Unix ms)
- All IDs are `TEXT` (UUID generated in app code)

### 2.3 Create contact CRUD routes

Create **`worker/routes/contacts.ts`** as a Hono sub-app:

```
GET    /api/contacts          — paginated list with filters
POST   /api/contacts          — create contact
GET    /api/contacts/:id      — get contact with emails, phones, companies, tags
PATCH  /api/contacts/:id      — update contact (triggers audit trail)
DELETE /api/contacts/:id      — soft delete (set is_deleted=1, deleted_at=now)
```

**List endpoint features**:
- Pagination: `?page=1&limit=25` with total count in response
- Sort: `?sort=last_name&order=asc`
- Filter: `?search=john&owner_id=X&tag=hot-lead&source=website`
- Saved views: filter presets stored client-side (Zustand)

**Sub-resource routes**:
```
POST   /api/contacts/:id/emails        — add email
DELETE /api/contacts/:id/emails/:eid   — remove email
POST   /api/contacts/:id/phones        — add phone
DELETE /api/contacts/:id/phones/:pid   — remove phone
POST   /api/contacts/:id/companies     — link to company with role
DELETE /api/contacts/:id/companies/:cid — unlink from company
GET    /api/contacts/:id/timeline      — activity timeline (aggregates audit + activities)
```

### 2.4 Create company CRUD routes

Create **`worker/routes/companies.ts`** as a Hono sub-app:

```
GET    /api/companies          — paginated list with filters
POST   /api/companies          — create company
GET    /api/companies/:id      — get company with contacts, tags, children
PATCH  /api/companies/:id      — update company (triggers audit trail)
DELETE /api/companies/:id      — soft delete
GET    /api/companies/:id/contacts   — list contacts at this company
GET    /api/companies/:id/children   — list subsidiary companies
```

**List endpoint features**:
- Same pagination, sort, filter pattern as contacts
- Filter by: `?search=acme&industry=Technology&size=51-200&owner_id=X`

### 2.5 Create tag management routes

Create **`worker/routes/tags.ts`** as a Hono sub-app:

```
GET    /api/tags               — list all tags
POST   /api/tags               — create tag
PATCH  /api/tags/:id           — update tag (name, color)
DELETE /api/tags/:id           — delete tag (cascades to record_tags)
POST   /api/tags/assign        — assign tag to record { record_id, record_type, tag_id }
DELETE /api/tags/unassign      — remove tag from record
```

### 2.6 Implement duplicate detection service

Create **`worker/services/duplicate-detection.ts`**:

Detection strategies with confidence scores:
- **Email match** (confidence: 0.95) — exact match on `contact_emails.email`
- **Phone match** (confidence: 0.85) — normalized phone comparison
- **Domain match** (confidence: 0.70) — company domain matches contact email domain
- **Name + company fuzzy match** (confidence: 0.60) — same first+last name at same company

```typescript
interface DuplicateCandidate {
  id: string;
  type: 'contact' | 'company';
  matchField: string;
  matchValue: string;
  confidence: number;
}

async function detectDuplicates(
  db: Database,
  record: Partial<Contact>,
): Promise<DuplicateCandidate[]>
```

Called during `POST /api/contacts` — returns duplicates in response if found (does not block creation, warns the user).

### 2.7 Implement full-text search service

Create **`worker/services/search.ts`**:

- **Simple search**: `LIKE '%term%'` across name, email, phone, company name fields. Suitable for D1/SQLite.
- **Advanced filter builder**: AND/OR condition groups with `{ field, operator, value }` where operators include `equals`, `contains`, `starts_with`, `gt`, `lt`, `in`, `is_empty`, `is_not_empty`.
- Returns a Drizzle `where` clause builder that composes filters.

```typescript
interface FilterCondition {
  field: string;
  operator: 'equals' | 'contains' | 'starts_with' | 'gt' | 'lt' | 'in' | 'is_empty' | 'is_not_empty';
  value: string | number | string[];
}

interface FilterGroup {
  logic: 'AND' | 'OR';
  conditions: (FilterCondition | FilterGroup)[];
}

function buildWhereClause(filters: FilterGroup): SQL
```

### 2.8 Implement audit trail middleware

Create **`worker/middleware/audit.ts`**:

- Wrap PATCH handlers: read old record before update, compare changed fields, insert rows into `audit_trail` for each changed field.
- Captures `changed_by` from the authenticated user context.
- Utility function `recordAuditChanges(db, recordId, recordType, oldRecord, newRecord, userId)`.

```typescript
async function recordAuditChanges(
  db: Database,
  recordId: string,
  recordType: 'contact' | 'company',
  oldRecord: Record<string, unknown>,
  newRecord: Record<string, unknown>,
  changedBy: string,
): Promise<void>
```

### 2.9 Build contact list page

Create **`src/pages/contacts/ContactList.tsx`**:

- DataTable with columns: Name (avatar + full name), Email (primary), Phone (primary), Company (primary), Owner, Tags, Last Updated
- Search bar with debounced input
- Filter builder sidebar (toggle open/close)
- Column configuration (show/hide columns)
- Saved views dropdown (store filter presets in Zustand)
- Bulk actions: assign owner, add tag, delete selected
- New contact button → creation form/modal

### 2.10 Build contact detail page

Create **`src/pages/contacts/ContactDetail.tsx`**:

- Header: avatar, full name, job title, company link
- Info card with inline edit (click field to edit, save on blur/enter)
- Emails section: list with primary badge, add/remove
- Phones section: list with primary badge, add/remove
- Social profiles section: platform icons with links
- Companies section: list with role badges, add/remove with role picker
- Tags section: tag chips with add/remove
- Activity timeline: chronological list of audit changes + activities (Phase 5)
- Related deals sidebar (populated in Phase 4)

### 2.11 Build company list page

Create **`src/pages/companies/CompanyList.tsx`**:

- DataTable with columns: Name (logo + name), Domain, Industry, Size, Contact Count, Owner, Tags
- Same search, filter, pagination pattern as ContactList
- Click row → CompanyDetail

### 2.12 Build company detail page

Create **`src/pages/companies/CompanyDetail.tsx`**:

- Header: logo, name, industry, website link
- Info card with inline edit
- Hierarchy section: parent company link + child companies list
- Contacts section: table of contacts at this company with roles
- Tags section
- Activity timeline
- Related deals sidebar (populated in Phase 4)

### 2.13 Build shared UI components

Create reusable components in **`src/components/`**:

- **DataTable** (`src/components/DataTable.tsx`) — sortable columns, row selection, pagination controls, loading skeleton
- **FilterBuilder** (`src/components/FilterBuilder.tsx`) — visual AND/OR condition builder, field selector, operator selector, value input
- **InlineEdit** (`src/components/InlineEdit.tsx`) — click-to-edit text/select fields with save/cancel
- **TagInput** (`src/components/TagInput.tsx`) — autocomplete tag selector with color chips
- **Avatar** (`src/components/Avatar.tsx`) — image with initials fallback
- **Timeline** (`src/components/Timeline.tsx`) — chronological event list with icons and timestamps
- **RecordLink** (`src/components/RecordLink.tsx`) — clickable link to contact/company/deal with preview tooltip

### 2.14 Create API client

Create **`src/api.ts`** with typed API functions:

```typescript
// Contacts
export async function listContacts(params: ContactListParams): Promise<PaginatedResponse<Contact>>
export async function getContact(id: string): Promise<ContactDetail>
export async function createContact(data: CreateContactInput): Promise<Contact>
export async function updateContact(id: string, data: UpdateContactInput): Promise<Contact>
export async function deleteContact(id: string): Promise<void>

// Companies
export async function listCompanies(params: CompanyListParams): Promise<PaginatedResponse<Company>>
export async function getCompany(id: string): Promise<CompanyDetail>
export async function createCompany(data: CreateCompanyInput): Promise<Company>
export async function updateCompany(id: string, data: UpdateCompanyInput): Promise<Company>
export async function deleteCompany(id: string): Promise<void>

// Tags
export async function listTags(): Promise<Tag[]>
export async function createTag(data: CreateTagInput): Promise<Tag>
export async function assignTag(recordId: string, recordType: string, tagId: string): Promise<void>
```

Uses `useAuthHeaders()` from SDK for authorization.

### 2.15 Wire up routes and test end-to-end

- Register contact, company, and tag route groups in `worker/index.ts`
- Update `src/root.component.tsx` routing to render ContactList, ContactDetail, CompanyList, CompanyDetail
- Create Zustand stores for contacts and companies (list state, filters, selected items)
- Verify full flow: create contact → add email/phone → link to company with role → add tags → edit inline → view audit trail

## Test Gate

```bash
cd eldrin-crm && npm run build   # Clean build with schema types
cd eldrin-crm && npm run dev     # Dev server + migrations create tables
```

Acceptance criteria:
1. Contact CRUD: create, read, update (inline edit), soft delete
2. Company CRUD: same pattern with parent-child hierarchy
3. Contact-company relationships with roles (e.g., "CTO at Acme Corp")
4. Multi-value emails and phones with primary designation
5. Duplicate detection returns candidates on contact creation
6. Full-text search across contacts and companies
7. Tag management: create, assign, filter by tag
8. Audit trail: field-level change history visible in timeline
9. Configurable list views with saved filter presets
10. Dark mode renders correctly across all pages

## Files Created

| File | Purpose |
|------|---------|
| `migrations/001-contacts-companies.sql` | Schema for contacts, companies, tags, audit trail |
| `worker/routes/contacts.ts` | Contact CRUD + sub-resource routes |
| `worker/routes/companies.ts` | Company CRUD routes |
| `worker/routes/tags.ts` | Tag management routes |
| `worker/services/duplicate-detection.ts` | Duplicate detection with confidence scores |
| `worker/services/search.ts` | Full-text search + advanced filter builder |
| `worker/middleware/audit.ts` | Field-level audit trail on updates |
| `src/pages/contacts/ContactList.tsx` | Contact list with DataTable, filters, bulk actions |
| `src/pages/contacts/ContactDetail.tsx` | Contact detail with inline edit, timeline |
| `src/pages/companies/CompanyList.tsx` | Company list page |
| `src/pages/companies/CompanyDetail.tsx` | Company detail with hierarchy, contacts |
| `src/components/DataTable.tsx` | Reusable sortable paginated table |
| `src/components/FilterBuilder.tsx` | Visual AND/OR filter condition builder |
| `src/components/InlineEdit.tsx` | Click-to-edit field component |
| `src/components/TagInput.tsx` | Autocomplete tag selector |
| `src/components/Avatar.tsx` | Avatar with initials fallback |
| `src/components/Timeline.tsx` | Chronological event list |
| `src/components/RecordLink.tsx` | Cross-entity link with preview |
| `src/api.ts` | Typed API client functions |
| `src/types/contact.ts` | Contact/Company TypeScript types |

## Files Modified

| File | Change |
|------|--------|
| `worker/db/schema.ts` | Add all table definitions (contacts, companies, tags, audit) |
| `worker/index.ts` | Register contact, company, tag route groups |
| `src/root.component.tsx` | Add routing for contact/company pages |

## Finalize

- [ ] Manual validation: create contacts and companies, verify relationships, tags, search, audit
- [ ] Manual validation: inline edit fields, verify audit trail captures changes
- [ ] Manual validation: duplicate detection warns on matching email
- [ ] Commit: `feat: add contact and company management with CRUD, search, tags, and audit trail`
- [ ] Update `STATUS.md` → complete, create `DONE.md`
