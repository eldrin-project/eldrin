# Phase 3: Lead Management

## Overview

Capture, qualify, and convert leads into contacts and deals. Covers REQ-1.2.01 through REQ-1.2.08. Leads are the top of the sales funnel — they flow in from web forms, imports, and manual entry, get scored and assigned, then convert into contacts (and optionally deals) when qualified.

This phase introduces the lead lifecycle: New → Contacted → Qualified → Converted (or Unqualified). The conversion workflow is transactional — it creates a Contact, links or creates a Company, and optionally creates a Deal, all in a single operation that preserves the full lead history.

## Dependencies

- Phase 2 (contacts and companies exist — leads convert into these entities)

## Steps

### 3.1 Create database migration for leads

Create **`migrations/002-leads.sql`**:

```sql
-- Lead sources (system + custom)
CREATE TABLE lead_sources (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  is_system INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

-- Seed default lead sources
INSERT INTO lead_sources (id, name, is_system, created_at) VALUES
  ('src-website', 'Website', 1, 0),
  ('src-referral', 'Referral', 1, 0),
  ('src-linkedin', 'LinkedIn', 1, 0),
  ('src-cold-call', 'Cold Call', 1, 0),
  ('src-trade-show', 'Trade Show', 1, 0),
  ('src-partner', 'Partner', 1, 0),
  ('src-advertisement', 'Advertisement', 1, 0),
  ('src-other', 'Other', 1, 0);

-- Core lead record
CREATE TABLE leads (
  id TEXT PRIMARY KEY,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  email TEXT,
  phone TEXT,
  company_name TEXT,
  job_title TEXT,
  source TEXT,
  status TEXT NOT NULL DEFAULT 'New',
  score INTEGER NOT NULL DEFAULT 0,
  owner_id TEXT,
  converted_contact_id TEXT,
  converted_company_id TEXT,
  converted_deal_id TEXT,
  is_deleted INTEGER NOT NULL DEFAULT 0,
  deleted_at INTEGER,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY (converted_contact_id) REFERENCES contacts(id) ON DELETE SET NULL,
  FOREIGN KEY (converted_company_id) REFERENCES companies(id) ON DELETE SET NULL
);

CREATE INDEX idx_leads_status ON leads(status);
CREATE INDEX idx_leads_source ON leads(source);
CREATE INDEX idx_leads_owner ON leads(owner_id);
CREATE INDEX idx_leads_score ON leads(score);
CREATE INDEX idx_leads_is_deleted ON leads(is_deleted);
CREATE INDEX idx_leads_email ON leads(email);

-- Lead assignment rules
CREATE TABLE lead_assignment_rules (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  config TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);

-- Lead scoring rules
CREATE TABLE lead_scoring_rules (
  id TEXT PRIMARY KEY,
  field TEXT NOT NULL,
  operator TEXT NOT NULL,
  value TEXT NOT NULL,
  points INTEGER NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);
```

**Status values**: `New`, `Contacted`, `Qualified`, `Unqualified`, `Converted`

**Assignment rule types**: `round_robin`, `territory`, `manual`, `load_balanced`

### 3.2 Add Drizzle schema for lead tables

Update **`worker/db/schema.ts`** with Drizzle definitions for `leadSources`, `leads`, `leadAssignmentRules`, `leadScoringRules`.

Key points:
- `leads.status` is `TEXT` with application-level validation (not DB enum for SQLite portability)
- `leads.score` is `INTEGER` default 0
- Foreign keys to `contacts` and `companies` for conversion tracking
- `converted_deal_id` is `TEXT` without FK (deals table created in Phase 4 — will be linked via application logic)

### 3.3 Create lead CRUD routes

Create **`worker/routes/leads.ts`** as a Hono sub-app:

```
GET    /api/leads              — paginated list with filters
POST   /api/leads              — create lead (runs duplicate check + auto-assign)
GET    /api/leads/:id          — get lead with score breakdown
PATCH  /api/leads/:id          — update lead (triggers audit + score recalc)
DELETE /api/leads/:id          — soft delete
```

**List endpoint features**:
- Pagination: `?page=1&limit=25`
- Filter by status: `?status=New,Contacted` (comma-separated for multi-select)
- Filter by source: `?source=Website`
- Filter by owner: `?owner_id=X`
- Filter by score range: `?min_score=50&max_score=100`
- Sort: `?sort=score&order=desc` (default: newest first)

### 3.4 Implement lead status transitions with validation

Add status transition logic to the PATCH route:

Valid transitions:
- `New` → `Contacted`, `Unqualified`
- `Contacted` → `Qualified`, `Unqualified`
- `Qualified` → `Converted`, `Unqualified`
- `Unqualified` → `New` (reopen)
- Admin override: can skip states (e.g., `New` → `Qualified`)

Return 400 with descriptive error if invalid transition is attempted by non-admin.

### 3.5 Implement lead assignment service

Create **`worker/services/lead-assignment.ts`**:

```typescript
interface AssignmentResult {
  assignedTo: string;
  ruleName: string;
}

async function assignLead(db: Database, leadId: string): Promise<AssignmentResult | null>
```

**Round-robin**: Tracks last-assigned index in the rule config. On each assignment, increments index modulo team size. Wraps around when reaching the end.

```typescript
// round_robin config shape:
{
  "team": ["user-1", "user-2", "user-3"],
  "lastAssignedIndex": 1
}
```

**Load-balanced**: Queries current workload (count of active leads per user in team), assigns to user with fewest active leads.

**Territory**: Matches lead attributes (country, state, industry) against territory definitions.

**Manual**: No auto-assignment — returns null, owner set manually.

Only the first active rule of matching type is applied. If no active rules exist, returns null.

### 3.6 Implement lead conversion workflow

Create **`worker/services/lead-conversion.ts`**:

```typescript
interface ConversionInput {
  leadId: string;
  createDeal?: {
    name: string;
    value: number;
    pipelineId: string;
    stageId: string;
  };
  existingContactId?: string;   // Link to existing contact instead of creating new
  existingCompanyId?: string;   // Link to existing company instead of creating new
}

interface ConversionResult {
  contactId: string;
  companyId: string | null;
  dealId: string | null;
}

async function convertLead(
  db: Database,
  input: ConversionInput,
  userId: string,
): Promise<ConversionResult>
```

Conversion steps (all in one transaction):
1. Validate lead exists and status is `Qualified` (or admin override)
2. Create Contact from lead fields (or link to existing)
3. Create Company from `company_name` (or link to existing, or skip if no company)
4. Create contact-company relation
5. Optionally create Deal with provided pipeline/stage
6. Update lead: status → `Converted`, set `converted_contact_id`, `converted_company_id`, `converted_deal_id`
7. Copy lead tags to the new contact
8. Record audit trail entries

**Conversion endpoint**: `POST /api/leads/:id/convert`

### 3.7 Implement lead scoring engine

Create **`worker/services/lead-scoring.ts`**:

```typescript
interface ScoreBreakdown {
  total: number;
  rules: Array<{
    ruleId: string;
    field: string;
    points: number;
    matched: boolean;
  }>;
}

async function calculateScore(db: Database, lead: Lead): Promise<ScoreBreakdown>
async function recalculateScore(db: Database, leadId: string): Promise<number>
```

Default scoring rules (seeded or configurable):
- Source is "Referral": +20 points
- Source is "Website": +10 points
- Has email: +10 points
- Has phone: +5 points
- Has company name: +15 points
- Has job title: +10 points

Score recalculation triggers:
- On lead creation
- On lead update (if scored fields change)
- Manual recalculate-all endpoint: `POST /api/leads/recalculate-scores`

### 3.8 Create lead capture API endpoint

Add **`POST /api/leads/capture`** — public or API-key-authenticated endpoint for web form submissions:

```typescript
// Request body
{
  "first_name": "Jane",
  "last_name": "Doe",
  "email": "jane@example.com",
  "company_name": "Acme Corp",
  "source": "Website",
  "metadata": { "form_id": "contact-us", "page_url": "https://..." }
}
```

- Runs duplicate detection against existing leads and contacts
- Auto-assigns via assignment rules
- Calculates initial score
- Returns created lead with duplicate warnings if any

### 3.9 Build lead list page

Create **`src/pages/leads/LeadList.tsx`**:

- Status filter tabs: All | New | Contacted | Qualified | Unqualified | Converted
- DataTable columns: Name, Email, Company, Source, Score (with color-coded badge), Owner, Status, Created
- Score column: green for high (70+), yellow for medium (30-69), gray for low (0-29)
- Bulk actions: assign owner, change status, delete
- Quick filters: My Leads, Unassigned, High Score
- New lead button → creation form

### 3.10 Build lead detail page

Create **`src/pages/leads/LeadDetail.tsx`**:

- Header: name, company, source badge, score badge
- Status workflow visualisation: horizontal stepper showing New → Contacted → Qualified → Converted with current state highlighted
- Score breakdown: list of scoring rules with matched/unmatched indicators
- Lead info card with inline edit
- Activity timeline (audit trail)
- Conversion button (enabled when status is Qualified): opens ConversionWizard

### 3.11 Build lead conversion wizard

Create **`src/components/leads/ConversionWizard.tsx`**:

Multi-step modal wizard:
1. **Contact**: Pre-filled from lead data. Option to link to existing contact (search) or create new.
2. **Company**: Pre-filled from lead's company_name. Option to link to existing company (search) or create new or skip.
3. **Deal** (optional): Create a deal — name, value, pipeline, stage. Can skip this step.
4. **Review**: Summary of what will be created. Confirm button.

On confirm, calls `POST /api/leads/:id/convert` and navigates to the new contact detail page.

## Test Gate

```bash
cd eldrin-crm && npm run build   # Clean build with lead schema types
cd eldrin-crm && npm run dev     # Dev server + migrations create lead tables
```

Acceptance criteria:
1. Lead CRUD: create, list (with status/source filters), update, soft delete
2. Status transitions enforce valid flow (New → Contacted → Qualified → Converted)
3. Invalid transitions return 400 error
4. Lead source tracking with system defaults
5. Round-robin assignment distributes leads across team members
6. Lead scoring calculates and displays score with breakdown
7. Lead conversion creates Contact + Company + optional Deal in one transaction
8. Conversion preserves lead history (converted_contact_id, etc.)
9. Lead capture endpoint accepts web form submissions
10. Conversion wizard walks through multi-step flow

## Files Created

| File | Purpose |
|------|---------|
| `migrations/002-leads.sql` | Schema for leads, sources, assignment rules, scoring rules |
| `worker/routes/leads.ts` | Lead CRUD + capture + conversion endpoints |
| `worker/services/lead-assignment.ts` | Round-robin, load-balanced, territory assignment |
| `worker/services/lead-conversion.ts` | Transactional lead-to-contact/company/deal conversion |
| `worker/services/lead-scoring.ts` | Configurable scoring engine with rule evaluation |
| `src/pages/leads/LeadList.tsx` | Lead list with status tabs, score badges |
| `src/pages/leads/LeadDetail.tsx` | Lead detail with status stepper, score breakdown |
| `src/components/leads/ConversionWizard.tsx` | Multi-step conversion modal |
| `src/stores/leadStore.ts` | Zustand store for lead list state and filters |
| `src/types/lead.ts` | Lead TypeScript types |

## Files Modified

| File | Change |
|------|--------|
| `worker/db/schema.ts` | Add lead, lead_sources, assignment_rules, scoring_rules tables |
| `worker/index.ts` | Register lead route group |
| `src/root.component.tsx` | Add routing for lead pages |
| `src/api.ts` | Add lead API client functions |

## Finalize

- [ ] Manual validation: create leads, verify status transitions, score calculation
- [ ] Manual validation: convert a qualified lead, verify contact + company created
- [ ] Manual validation: lead capture endpoint accepts form data with source tracking
- [ ] Commit: `feat: add lead management with scoring, assignment, and conversion`
- [ ] Update `STATUS.md` → complete, create `DONE.md`
