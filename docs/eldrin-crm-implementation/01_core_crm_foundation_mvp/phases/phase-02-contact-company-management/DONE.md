# Phase 2: Contact & Company Management — DONE

Completed: 2026-02-16

## Summary

Built full CRUD for contacts and companies with multi-value fields, relationships, tags, duplicate detection, full-text search, audit trail, and inline editing. Covers REQ-1.1.01 through REQ-1.1.12.

## What was built

### Backend (worker/)

- **Database migration** (`migrations/20260216000000-contacts-companies.sql`) — 9 tables with indexes, foreign keys, unique constraints
- **Drizzle schema** (`worker/db/schema.ts`) — All 9 tables with typed columns, modes (`boolean`, `number`), and references
- **Contact routes** (`worker/routes/contacts.ts`) — 12 endpoints: CRUD + emails, phones, company links, timeline
- **Company routes** (`worker/routes/companies.ts`) — 7 endpoints: CRUD + contacts list, children list
- **Tag routes** (`worker/routes/tags.ts`) — 6 endpoints: CRUD + assign/unassign polymorphic tags
- **Audit trail** (`worker/middleware/audit.ts`) — Field-level change tracking on PATCH operations
- **Duplicate detection** (`worker/services/duplicate-detection.ts`) — Email match (0.95), name match (0.60), domain match (0.90)
- **Search service** (`worker/services/search.ts`) — Nested AND/OR filter builder producing Drizzle SQL clauses
- **Utilities** (`worker/utils.ts`) — `generateId()` and `now()` helpers

### Frontend (src/)

- **Types** (`src/types/contact.ts`) — 25+ interfaces covering contacts, companies, tags, audit, filters, API inputs
- **API client** (`src/api.ts`) — 20+ typed functions for all CRUD + sub-resource operations
- **Contact list** (`src/pages/contacts/ContactList.tsx`) — DataTable with search, sort, pagination, row selection, bulk delete
- **Contact detail** (`src/pages/contacts/ContactDetail.tsx`) — Inline edit, emails/phones management, company links, tags, timeline
- **Contact form** (`src/pages/contacts/ContactForm.tsx`) — Modal for creating contacts with duplicate detection warnings
- **Company list** (`src/pages/companies/CompanyList.tsx`) — Same DataTable pattern with contact count, tags
- **Company detail** (`src/pages/companies/CompanyDetail.tsx`) — Inline edit, hierarchy, contacts, tags
- **Company form** (`src/pages/companies/CompanyForm.tsx`) — Modal for creating companies with duplicate detection
- **Shared components**: DataTable, Avatar, InlineEdit, TagInput, Timeline, RecordLink
- **Root component** updated with detail route parsing (`/contacts/:id`, `/companies/:id`)

## Verification

- `tsc -b` — clean (0 errors)
- `npm run build` — success (client 1,104KB + 69KB CSS)
- All externalization warnings are expected (eldrin-app-core multi-runtime adapters)

## Architecture Decisions

- **No Zustand stores**: Direct API calls from components (matching workflows pattern). Stores can be added later for complex cross-component state.
- **camelCase types**: Match Drizzle's JavaScript property names, not SQL column names
- **Self-referencing FK**: `companies.parentCompanyId` defined as plain `text()` in Drizzle (avoids circular type inference), FK enforced at SQL level
- **List enrichment**: Parallel batch queries for primary email/phone/company/tags per page of results
- **Polymorphic tags**: `record_tags` table with `record_type` discriminator — one tag system for all entity types
