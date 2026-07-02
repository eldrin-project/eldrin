# Phase 4: Deal & Pipeline Management

## Overview

Track revenue opportunities through customisable sales pipelines with a Kanban board interface. Covers REQ-1.3.01 through REQ-1.3.10. Deals represent potential revenue tied to contacts and companies. Each deal moves through pipeline stages (e.g., Prospecting → Qualification → Proposal → Negotiation → Closed Won) with configurable probabilities, activity requirements per stage, and close-out reason codes.

The Kanban board is the primary deal interface — drag-and-drop cards between columns. The list view provides a tabular alternative with inline editing and advanced filtering.

## Dependencies

- Phase 2 (contacts and companies — deals link to both via `deal_contacts`)
- Phase 3 (lead conversion creates deals — `converted_deal_id` FK)

## Steps

### 4.1 Create database migration for deals and pipelines

Create **`migrations/003-deals.sql`**:

```sql
-- Customisable sales pipelines
CREATE TABLE pipelines (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  is_default INTEGER NOT NULL DEFAULT 0,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- Stages within a pipeline (ordered)
CREATE TABLE pipeline_stages (
  id TEXT PRIMARY KEY,
  pipeline_id TEXT NOT NULL,
  name TEXT NOT NULL,
  position INTEGER NOT NULL,
  probability REAL NOT NULL DEFAULT 0,
  requirements TEXT,
  color TEXT,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (pipeline_id) REFERENCES pipelines(id) ON DELETE CASCADE
);

CREATE INDEX idx_stages_pipeline ON pipeline_stages(pipeline_id);
CREATE INDEX idx_stages_position ON pipeline_stages(pipeline_id, position);

-- Seed default pipeline with stages
INSERT INTO pipelines (id, name, is_default, is_active, created_by, created_at, updated_at)
VALUES ('pipeline-default', 'Sales Pipeline', 1, 1, 'system', 0, 0);

INSERT INTO pipeline_stages (id, pipeline_id, name, position, probability, color, created_at) VALUES
  ('stage-prospecting', 'pipeline-default', 'Prospecting', 0, 0.10, '#3b82f6', 0),
  ('stage-qualification', 'pipeline-default', 'Qualification', 1, 0.25, '#8b5cf6', 0),
  ('stage-proposal', 'pipeline-default', 'Proposal', 2, 0.50, '#f59e0b', 0),
  ('stage-negotiation', 'pipeline-default', 'Negotiation', 3, 0.75, '#f97316', 0),
  ('stage-closed-won', 'pipeline-default', 'Closed Won', 4, 1.00, '#22c55e', 0),
  ('stage-closed-lost', 'pipeline-default', 'Closed Lost', 5, 0.00, '#ef4444', 0);

-- Core deal record
CREATE TABLE deals (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  value REAL,
  currency TEXT NOT NULL DEFAULT 'USD',
  expected_close_date INTEGER,
  pipeline_id TEXT NOT NULL,
  stage_id TEXT NOT NULL,
  probability REAL,
  owner_id TEXT,
  is_deleted INTEGER NOT NULL DEFAULT 0,
  deleted_at INTEGER,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY (pipeline_id) REFERENCES pipelines(id) ON DELETE RESTRICT,
  FOREIGN KEY (stage_id) REFERENCES pipeline_stages(id) ON DELETE RESTRICT
);

CREATE INDEX idx_deals_pipeline ON deals(pipeline_id);
CREATE INDEX idx_deals_stage ON deals(stage_id);
CREATE INDEX idx_deals_owner ON deals(owner_id);
CREATE INDEX idx_deals_close_date ON deals(expected_close_date);
CREATE INDEX idx_deals_is_deleted ON deals(is_deleted);
CREATE INDEX idx_deals_value ON deals(value);

-- Many-to-many: deal <-> contact with stakeholder role
CREATE TABLE deal_contacts (
  id TEXT PRIMARY KEY,
  deal_id TEXT NOT NULL,
  contact_id TEXT NOT NULL,
  role TEXT,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (deal_id) REFERENCES deals(id) ON DELETE CASCADE,
  FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE,
  UNIQUE (deal_id, contact_id)
);

CREATE INDEX idx_deal_contacts_deal ON deal_contacts(deal_id);
CREATE INDEX idx_deal_contacts_contact ON deal_contacts(contact_id);

-- Stage transition history
CREATE TABLE deal_stage_history (
  id TEXT PRIMARY KEY,
  deal_id TEXT NOT NULL,
  from_stage_id TEXT,
  to_stage_id TEXT NOT NULL,
  changed_by TEXT NOT NULL,
  changed_at INTEGER NOT NULL,
  duration_seconds INTEGER,
  FOREIGN KEY (deal_id) REFERENCES deals(id) ON DELETE CASCADE,
  FOREIGN KEY (from_stage_id) REFERENCES pipeline_stages(id) ON DELETE SET NULL,
  FOREIGN KEY (to_stage_id) REFERENCES pipeline_stages(id) ON DELETE SET NULL
);

CREATE INDEX idx_stage_history_deal ON deal_stage_history(deal_id);
CREATE INDEX idx_stage_history_changed_at ON deal_stage_history(changed_at);

-- Close-out reason codes
CREATE TABLE close_reasons (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  reason TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1
);

-- Seed default close reasons
INSERT INTO close_reasons (id, type, reason, is_active) VALUES
  ('cr-won-competitive', 'won', 'Won against competitor', 1),
  ('cr-won-sole', 'won', 'Sole vendor selected', 1),
  ('cr-won-expansion', 'won', 'Expansion of existing account', 1),
  ('cr-lost-price', 'lost', 'Lost on price', 1),
  ('cr-lost-competitor', 'lost', 'Lost to competitor', 1),
  ('cr-lost-no-budget', 'lost', 'No budget', 1),
  ('cr-lost-no-decision', 'lost', 'No decision made', 1),
  ('cr-lost-timing', 'lost', 'Bad timing', 1),
  ('cr-abandoned-stale', 'abandoned', 'Deal went stale', 1),
  ('cr-abandoned-contact', 'abandoned', 'Lost contact with prospect', 1);
```

**Deal contact roles**: `Champion`, `Budget Holder`, `Technical Evaluator`, `Decision Maker`, `Influencer`, `End User`, `Other`

**Stage requirements** (JSON in `pipeline_stages.requirements`):
```json
{
  "requiredActivities": ["meeting", "proposal_sent"],
  "requiredFields": ["expected_close_date", "value"]
}
```

### 4.2 Add Drizzle schema for deal and pipeline tables

Update **`worker/db/schema.ts`** with Drizzle definitions for `pipelines`, `pipelineStages`, `deals`, `dealContacts`, `dealStageHistory`, `closeReasons`.

Key points:
- `deals.value` is `REAL` (nullable — some deals start without a value)
- `deals.probability` can override the stage default (nullable — falls back to stage probability)
- `pipeline_stages.requirements` is `TEXT` (JSON string) — parsed in application code
- `deal_stage_history.duration_seconds` is calculated at write time: diff between current `changed_at` and the previous stage entry's `changed_at`

### 4.3 Create pipeline configuration routes

Create **`worker/routes/pipelines.ts`** as a Hono sub-app:

```
GET    /api/pipelines                    — list all pipelines with stages
POST   /api/pipelines                    — create pipeline
GET    /api/pipelines/:id                — get pipeline with stages
PATCH  /api/pipelines/:id                — update pipeline name/active status
DELETE /api/pipelines/:id                — delete pipeline (only if no deals)
POST   /api/pipelines/:id/stages         — add stage
PATCH  /api/pipelines/:id/stages/:sid    — update stage (name, probability, requirements, color)
DELETE /api/pipelines/:id/stages/:sid    — remove stage (only if no deals in stage)
PUT    /api/pipelines/:id/stages/reorder — reorder stages (accepts array of stage IDs)
GET    /api/close-reasons                — list close reasons grouped by type
POST   /api/close-reasons                — create close reason
PATCH  /api/close-reasons/:id            — update close reason
```

### 4.4 Create deal CRUD routes

Create **`worker/routes/deals.ts`** as a Hono sub-app:

```
GET    /api/deals              — paginated list with filters
POST   /api/deals              — create deal
GET    /api/deals/:id          — get deal with contacts, stage history, tags
PATCH  /api/deals/:id          — update deal (triggers audit + stage history if stage changes)
DELETE /api/deals/:id          — soft delete
POST   /api/deals/:id/close    — close deal with reason code (won/lost/abandoned)
```

**List endpoint features**:
- Pagination: `?page=1&limit=25`
- Filter by pipeline: `?pipeline_id=X`
- Filter by stage: `?stage_id=X` or `?stages=stage-1,stage-2`
- Filter by owner: `?owner_id=X`
- Filter by value range: `?min_value=10000&max_value=50000`
- Filter by close date range: `?close_after=X&close_before=Y`
- Sort: `?sort=value&order=desc`

**Deal contact management**:
```
POST   /api/deals/:id/contacts          — add contact with role
PATCH  /api/deals/:id/contacts/:cid     — update contact role
DELETE /api/deals/:id/contacts/:cid     — remove contact from deal
GET    /api/deals/:id/history           — stage transition history
```

### 4.5 Implement stage progression service

Create **`worker/services/deal-stage.ts`**:

```typescript
interface StageChangeResult {
  success: boolean;
  error?: string;
  unmetRequirements?: string[];
}

async function changeDealStage(
  db: Database,
  dealId: string,
  newStageId: string,
  userId: string,
): Promise<StageChangeResult>
```

Stage change logic:
1. Load current deal and target stage
2. Validate target stage belongs to the same pipeline
3. Check stage requirements (required activities logged, required fields populated)
4. If requirements unmet, return error with list of unmet requirements (UI shows these to user)
5. If valid: update deal stage, set probability from stage default (unless manually overridden), insert `deal_stage_history` record with calculated duration
6. Record audit trail entry

**Close-out flow**: When moving to a "Closed" stage (Closed Won, Closed Lost, or custom closed stages), require a close reason:

```typescript
async function closeDeal(
  db: Database,
  dealId: string,
  closeType: 'won' | 'lost' | 'abandoned',
  reasonId: string,
  userId: string,
): Promise<void>
```

### 4.6 Implement Kanban data endpoint

Add **`GET /api/deals/kanban`**:

```
GET /api/deals/kanban?pipeline_id=X&owner_id=Y
```

Returns deals grouped by stage with position ordering:

```typescript
interface KanbanResponse {
  pipeline: Pipeline;
  columns: Array<{
    stage: PipelineStage;
    deals: Deal[];
    totalValue: number;
    weightedValue: number;  // sum(deal.value * stage.probability)
    count: number;
  }>;
  summary: {
    totalDeals: number;
    totalValue: number;
    weightedPipeline: number;
  };
}
```

### 4.7 Implement weighted pipeline calculation

Add pipeline summary calculation:

```typescript
async function calculatePipelineMetrics(
  db: Database,
  pipelineId: string,
  filters?: { ownerId?: string; closeDateRange?: [number, number] },
): Promise<PipelineMetrics>

interface PipelineMetrics {
  totalDeals: number;
  totalValue: number;
  weightedValue: number;        // sum of (deal value x probability)
  averageDealSize: number;
  averageSalesCycle: number;    // average days from creation to close
  winRate: number;              // closed-won / (closed-won + closed-lost)
  stageBreakdown: Array<{
    stage: PipelineStage;
    count: number;
    totalValue: number;
    weightedValue: number;
    avgDaysInStage: number;
  }>;
}
```

### 4.8 Implement deal rotting detection

Add rotting check to the Kanban and list endpoints:

```typescript
interface DealWithRotting extends Deal {
  isRotting: boolean;
  daysInCurrentStage: number;
  rottingThresholdDays: number;
}
```

Default thresholds (configurable per stage via `pipeline_stages.requirements`):
- Prospecting: 14 days
- Qualification: 21 days
- Proposal: 14 days
- Negotiation: 30 days

Rotting deals are flagged with a visual indicator (amber/red badge) in both Kanban and list views.

### 4.9 Build Kanban board page

Create **`src/pages/deals/DealKanban.tsx`**:

- Pipeline selector dropdown at the top
- Columns per stage, each showing: stage name, deal count, weighted total value
- Deal cards with: name, value, company, owner avatar, expected close date, rotting indicator
- `@hello-pangea/dnd` for drag-and-drop between columns
- On drop: call stage change endpoint — if requirements unmet, show toast with missing items and revert card position
- Column footer: "Add deal" button
- Filter bar: owner, value range, close date range

### 4.10 Build deal list page

Create **`src/pages/deals/DealList.tsx`**:

- Toggle between Kanban (default) and List view
- DataTable columns: Name, Value, Pipeline/Stage (badge), Probability %, Owner, Expected Close, Days in Stage, Rotting indicator
- Inline editing for value, expected close date, owner
- Saved filters
- Bulk actions: change stage, assign owner, delete

### 4.11 Build deal detail page

Create **`src/pages/deals/DealDetail.tsx`**:

- Header: deal name, value (large), stage badge with color
- Stage progress bar: visual pipeline showing current position
- Info card: value, currency, expected close date, probability, owner — inline editable
- Contacts section: list of associated contacts with stakeholder roles (Champion, Budget Holder, etc.), add/remove
- Stage history timeline: chronological list of stage changes with duration at each stage
- Tags section
- Activity timeline (populated in Phase 5)
- Close button (Won/Lost/Abandoned) in header

### 4.12 Build pipeline settings page

Create **`src/pages/settings/PipelineSettings.tsx`**:

- List of pipelines with active/inactive toggle
- Create new pipeline button
- For each pipeline: editable stage list
  - Drag to reorder stages
  - Edit stage: name, probability %, color picker, requirements
  - Add/remove stages
  - Mark default pipeline
- Close reasons management: grouped by type (Won/Lost/Abandoned), add/edit/deactivate

### 4.13 Build close-out dialog

Create **`src/components/deals/CloseOutDialog.tsx`**:

Modal dialog triggered from deal detail or Kanban when moving to a closed stage:

1. Select type: Won / Lost / Abandoned (tabs or radio buttons)
2. Select reason from filtered list (only reasons matching selected type)
3. Optional notes field
4. Confirm button

On confirm: calls `POST /api/deals/:id/close`, navigates back to pipeline or refreshes Kanban.

## Test Gate

```bash
cd eldrin-crm && npm run build   # Clean build with deal/pipeline schema types
cd eldrin-crm && npm run dev     # Dev server + migrations create deal tables
```

Acceptance criteria:
1. Default pipeline seeded with 6 stages and probabilities
2. Pipeline CRUD: create, edit stages, reorder, delete empty pipeline
3. Deal CRUD: create, update, soft delete
4. Kanban board: deals grouped by stage, drag-and-drop moves deals between stages
5. Stage change validates activity requirements, returns errors if unmet
6. Close-out flow: Won/Lost/Abandoned with required reason code
7. Weighted pipeline calculation: column totals = sum(value x probability)
8. Deal contacts with stakeholder roles (Champion, Budget Holder, etc.)
9. Stage history: chronological log of stage transitions with duration
10. Deal rotting: visual indicator on deals stalled beyond threshold
11. Close reasons management in settings

## Files Created

| File | Purpose |
|------|---------|
| `migrations/003-deals.sql` | Schema for pipelines, stages, deals, contacts, history, close reasons |
| `worker/routes/pipelines.ts` | Pipeline and stage configuration routes |
| `worker/routes/deals.ts` | Deal CRUD + close + Kanban + contact management |
| `worker/services/deal-stage.ts` | Stage progression, requirements validation, close-out |
| `src/pages/deals/DealKanban.tsx` | Kanban board with drag-and-drop |
| `src/pages/deals/DealList.tsx` | Deal list/table view |
| `src/pages/deals/DealDetail.tsx` | Deal detail with stage history, contacts |
| `src/pages/settings/PipelineSettings.tsx` | Pipeline and stage configuration UI |
| `src/components/deals/CloseOutDialog.tsx` | Won/Lost/Abandoned close-out modal |
| `src/components/deals/DealCard.tsx` | Kanban deal card component |
| `src/components/deals/StageProgressBar.tsx` | Visual pipeline stage indicator |
| `src/stores/dealStore.ts` | Zustand store for deal/pipeline state |
| `src/stores/pipelineStore.ts` | Zustand store for pipeline configuration |
| `src/types/deal.ts` | Deal/Pipeline TypeScript types |

## Files Modified

| File | Change |
|------|--------|
| `worker/db/schema.ts` | Add pipeline, stage, deal, deal_contacts, history, close_reasons tables |
| `worker/index.ts` | Register pipeline and deal route groups |
| `src/root.component.tsx` | Add routing for deal pages and pipeline settings |
| `src/api.ts` | Add deal and pipeline API client functions |

## Finalize

- [ ] Manual validation: create pipeline with custom stages, reorder stages
- [ ] Manual validation: create deals, drag between stages on Kanban, verify requirements check
- [ ] Manual validation: close deal as Won with reason, verify stage history
- [ ] Manual validation: verify weighted pipeline totals and deal rotting indicators
- [ ] Commit: `feat: add deal pipeline management with Kanban board and stage tracking`
- [ ] Update `STATUS.md` → complete, create `DONE.md`
