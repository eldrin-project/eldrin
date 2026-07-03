# Slice 3b — Ghost-Activity Detection + Deal Auto-Detection Suggestions

**Date:** 2026-07-03
**Status:** Draft — awaiting user review
**Scope:** eldrin-crm only (CRM-internal, no cross-repo changes)
**Requirements:** REQ-1.10.11 (ghost activity), REQ-1.10.08 (deal auto-detection)
**Parent spec:** `2026-07-03-ai-enhancement-workflows-design.md` (deferred item D2)

## Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | Deal-signal detection is a **CRM-internal keyword/pattern heuristic**, not an AI workflow extension. | Deterministic, testable, free, no LLM dependency, single repo. Matches the "CRM-internal, low-risk" framing of the deferral. |
| D2 | The `deal_suggestions` store records a `source` column (`'heuristic'` now). | A future AI workflow can feed the same store through the existing enhancement seam without schema changes. |
| D3 | Accepting a suggestion **opens the DealForm pre-populated** — it never auto-creates a deal. | The user always confirms; wrong suggestions cost one click to dismiss, never a wrong record. |
| D4 | Ghost activity is **computed on read** (no new tables, no cron). | The activities table already carries everything needed, indexed by `(relatedRecordId, relatedRecordType)`. A widget query at dashboard-load frequency is cheap at single-tenant scale. |
| D5 | Ghost ≠ rotting. Rotting (existing) = no **stage change**; ghost = no **captured activity at all** (and for deals, also no stage change). | The two signals answer different questions; both stay. |

## Assumptions (made while user was away — flag on review if wrong)

- Both features ship in this one slice.
- Ghost-activity covers **contacts and open deals** (not companies or leads) per REQ-1.10.11.
- Default quiet window 30 days; selector offers 14/30/60/90. No server-side config table (YAGNI — the selector is the "configurable period").
- Suggestion threshold: **≥ 2 distinct signal families** in one email body.

## 1. Ghost-activity detection ("Gone quiet")

### Backend

`GET /api/reports/gone-quiet?days=30&limit=25` (manifest permission `reports:read`), returning:

```json
{
  "contacts": [{ "id", "firstName", "lastName", "companyName", "lastTouchAt", "daysQuiet" }],
  "deals":    [{ "id", "name", "value", "stageName", "lastTouchAt", "daysQuiet" }],
  "days": 30
}
```

- **Contact last touch** = `MAX(COALESCE(a.completedAt, a.createdAt))` over non-deleted activities with `relatedRecordType='contact'`; falls back to the contact's `createdAt` when no activities exist (a never-touched contact IS ghost once older than the window).
- **Deal last touch** = greatest of: linked-activity timestamp (as above, `relatedRecordType='deal'`), latest `dealStageHistory.changedAt`, and the deal's `createdAt`. Only **open** deals (not won/lost/deleted).
- `days` clamped to [7, 365]; `limit` clamped to [1, 100]; ordered by `daysQuiet` descending.
- Implementation: `worker/services/ghost-activity.ts` (queries) + route registration in `worker/routes/reports.ts`.

### Frontend

`GoneQuietWidget` on the CRM dashboard (`src/pages/reports/Dashboard.tsx`), Quiet Ledger styling (`crm-card`, eyebrow title, `crm-num` figures):

- Period selector (14/30/60/90 days, default 30) — client state only.
- Two compact lists (Contacts / Deals): name → record link, muted "last touch" date, right-aligned "Nd quiet" figure.
- Empty state: "Nothing has gone quiet in the last N days."

## 2. Deal auto-detection (buying signals)

### Signal scanner — `worker/services/buying-signals.ts`

Pure function `detectBuyingSignals(bodyText: string): BuyingSignals`:

```ts
interface SignalHit { family: 'budget' | 'timeline' | 'stakeholder' | 'intent'; snippet: string }
interface BuyingSignals { hits: SignalHit[]; families: string[]; suggestedValue: number | null }
```

| Family | Patterns (case-insensitive; word-bounded) |
|---|---|
| budget | currency amounts (`$12,000`, `€50k`, `12.000 EUR`), `budget`, `pricing`, `cost estimate`, `price range` |
| timeline | `by (Q[1-4]\|end of \w+\|early/mid/late \w+)`, `deadline`, `go[- ]live`, `this/next quarter/month/year`, explicit dates near intent words |
| stakeholder | `looping in`, `cc'?ing`, `our (CTO\|CFO\|CEO\|VP\|head of ...)`, `decision[- ]maker`, `procurement` |
| intent | `RFP`, `RFI`, `request for proposal`, `proposal`, `quote\|quotation`, `evaluate\|evaluation`, `trial\|pilot\|POC`, `contract` |

Guards (each unit-tested):

- Input truncated to the first 4 000 chars (matches the captured `bodyText` cap).
- Quoted-reply lines (`>`-prefixed) and signature blocks (below the existing signature-parser delimiter heuristics) are excluded before scanning.
- Snippets capped at 120 chars, max 3 hits per family.
- `suggestedValue`: largest parsed currency amount, `null` when none; parsing rejects values > 10⁹.

### Suggestion store — new table `deal_suggestions`

Migration `migrations/YYYYMMDDHHMMSS-deal-suggestions.sql` (14-digit timestamp prefix is mandatory — the runner silently skips misnamed files) + Drizzle schema in `worker/db/schema.ts`, then `npm run generate:migrations`:

```
id TEXT PK · contact_id TEXT NOT NULL → contacts · company_id TEXT NULL → companies
source_message_id TEXT NULL · signals TEXT NOT NULL (JSON: SignalHit[])
suggested_name TEXT NOT NULL · suggested_value REAL NULL
status TEXT NOT NULL DEFAULT 'pending'  -- pending | accepted | dismissed
source TEXT NOT NULL DEFAULT 'heuristic'
created_at INTEGER NOT NULL · updated_at INTEGER NOT NULL
INDEX (status) · INDEX (contact_id)
```

### Capture-time hook (in `worker/services/auto-capture.ts`)

After the existing signature/enhancement handling, when `payload.bodyText` is present:

1. Run `detectBuyingSignals`. If `families.length < 2` → done.
2. Skip if the contact has any **open deal** (via `dealContacts` join) — the conversation is already tracked.
3. Skip (merge instead) if a `pending` suggestion exists for the contact: append new hits (deduped by snippet), update `suggested_value` if larger, bump `updatedAt`.
4. Otherwise insert a suggestion: `suggestedName` = `"{Company name} — {email subject}"` (fallback `"Deal with {contact name}"`), `suggestedValue` from the scanner, `sourceMessageId` from the payload.
5. A dismissed suggestion for the same `sourceMessageId` is never re-created; a dismissed suggestion for the contact from an *older* message does not block a new one from a *newer* message.

Failures in this hook are logged and swallowed — suggestion detection must never break email capture.

### API — `worker/routes/deal-suggestions.ts`

| Route | Permission | Behavior |
|---|---|---|
| `GET /api/deal-suggestions?status=pending` | `deals:read` | List, joined with contact/company display names. |
| `POST /api/deal-suggestions/:id/dismiss` | `deals:update` | `status='dismissed'`. 404 unknown, 409 non-pending. |
| `POST /api/deal-suggestions/:id/accept` | `deals:update` | `status='accepted'`. Returns the suggestion payload; the **client** then opens DealForm pre-populated. 409 non-pending. |

All three registered in the manifest `api.routes`.

### Frontend

- **`SuggestedDealsWidget`** on the CRM dashboard: signal-family chips (StatusBadge, info tone) per suggestion with matched snippets in a tooltip; Accept / Dismiss buttons.
- **Contact-detail banner** (`crm-card`, violet accent) when that contact has a pending suggestion — same chips + actions.
- **Accept flow:** call accept → open `DealForm` with new props `initialName`, `initialValue`, `initialContactId` (extending the existing `initialPipelineId/initialStageId` pattern). Submitting creates the deal through the existing deals API unchanged. Cancelling the form leaves the suggestion `accepted` (it stops being suggested; acceptable for this slice).
- Empty widget state: "No suggested deals. Signals from inbound email will appear here."

## 3. What this slice does NOT do

- No AI/LLM involvement (D1/D2 leave the seam open).
- No auto-created deals (D3).
- No ghost-activity notifications or emails — dashboard widget only.
- No company/lead ghost tracking.
- No new eldrin-workflows or eldrin-core changes.

## 4. Testing

- **Unit (worker):** scanner fixtures per family + combined; false-positive guards (signature block with phone numbers ≠ budget; quoted reply ignored); currency parsing edge cases; ghost-activity boundary (exactly N days, never-touched contact, deal with only stage history); suggestion dedup/merge/dismiss-then-new-message matrix.
- **Route tests:** list/accept/dismiss status transitions incl. 404/409; gone-quiet clamps.
- **UI:** browser-verified in light + dark (widgets, banner, accept→prefilled-form flow).
- Existing suites must stay green.

## 5. Risks

| Risk | Mitigation |
|---|---|
| Keyword false positives annoy users | ≥2-family threshold, reply/signature stripping, one-click dismiss that sticks per message. |
| Ghost query slow with large activity tables | Existing `(relatedRecordId, relatedRecordType)` index; LIMIT-bounded; measured in tests with seeded data. |
| Suggestion spam from long threads | One pending suggestion per contact; merge instead of insert; dismissed messages never re-suggest. |
