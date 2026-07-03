# Slice 3b — Ghost-Activity Detection + Deal Auto-Detection Suggestions

**Date:** 2026-07-03
**Status:** Draft — awaiting user review (v2: hybrid detection per user decision)
**Scope:** eldrin-crm (primary) + one new workflow template in eldrin-workflows
**Requirements:** REQ-1.10.11 (ghost activity), REQ-1.10.08 (deal auto-detection)
**Parent spec:** `2026-07-03-ai-enhancement-workflows-design.md` (deferred item D2)

## Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | **Hybrid detection (user decision):** a CRM-internal keyword heuristic is the trigger at capture time; an AI workflow **refines** suggestions asynchronously. | Heuristic gives a deterministic, always-working baseline; the LLM only runs on emails that already look deal-ish, so cost stays near zero. Rides the Slice 3 infrastructure unchanged. |
| D2 | AI refinement is **enhancement-only**: it improves name/value, adds a confidence assessment, and never creates, dismisses, or deletes suggestions. | Mirrors the Slice 3 fill-empty philosophy: the heuristic suggestion is already valid; AI failure or absence leaves a fully usable suggestion. A model must never silently discard a potential deal. |
| D3 | Accepting a suggestion **opens the DealForm pre-populated** — it never auto-creates a deal. | The user always confirms; wrong suggestions cost one click to dismiss, never a wrong record. |
| D4 | Ghost activity is **computed on read** (no new tables, no cron). | The activities table already carries everything needed, indexed by `(relatedRecordId, relatedRecordType)`. A widget query at dashboard-load frequency is cheap at single-tenant scale. |
| D5 | Ghost ≠ rotting. Rotting (existing) = no **stage change**; ghost = no **captured activity at all** (and for deals, also no stage change). | The two signals answer different questions; both stay. |
| D6 | Refinement durability copies the `ai_enhancement_status` contract: `ai_refinement_status` = `null` (heuristic didn't fire / below threshold) \| `'pending'` (armed) \| `'refined'` (applied). **Failures stay `pending`.** | Same source-of-truth pattern already live-validated in Slice 3; a future sweep can retry pending refinements. |

## Assumptions (flag on review if wrong)

- Both features ship in this one slice.
- Ghost-activity covers **contacts and open deals** (not companies or leads) per REQ-1.10.11.
- Default quiet window 30 days; selector offers 14/30/60/90. No server-side config table (YAGNI — the selector is the "configurable period").
- Suggestion threshold: **≥ 2 distinct signal families** in one email body.
- Dev validation of the AI leg uses the existing **mock provider** (canned output), same as Slice 3.

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
source TEXT NOT NULL DEFAULT 'heuristic'  -- 'heuristic' | 'heuristic+ai' (set on refinement)
ai_refinement_status TEXT NULL            -- null | 'pending' | 'refined' (D6; failures stay pending)
ai_confidence REAL NULL                   -- 0..1, set by refinement
ai_reasoning TEXT NULL                    -- one-line model rationale, shown in the UI tooltip
created_at INTEGER NOT NULL · updated_at INTEGER NOT NULL
INDEX (status) · INDEX (contact_id) · INDEX (ai_refinement_status)
```

### Capture-time hook (in `worker/services/auto-capture.ts`)

After the existing signature/enhancement handling, when `payload.bodyText` is present:

1. Run `detectBuyingSignals`. If `families.length < 2` → done.
2. Skip if the contact has any **open deal** (via `dealContacts` join) — the conversation is already tracked.
3. Skip (merge instead) if a `pending` suggestion exists for the contact: append new hits (deduped by snippet), update `suggested_value` if larger, bump `updatedAt`.
4. Otherwise insert a suggestion: `suggestedName` = `"{Company name} — {email subject}"` (fallback `"Deal with {contact name}"`), `suggestedValue` from the scanner, `sourceMessageId` from the payload, `ai_refinement_status='pending'`.
5. A dismissed suggestion for the same `sourceMessageId` is never re-created; a dismissed suggestion for the contact from an *older* message does not block a new one from a *newer* message.
6. Emit `deal.suggestion.created` (fire-and-forget via the existing event emitter, `waitUntil`) with `{ suggestionId, contactId, messageId }` — the trigger for the AI refinement workflow. Merges (step 3) re-emit and re-arm `ai_refinement_status='pending'` (new material to assess).

Failures in this hook are logged and swallowed — suggestion detection must never break email capture.

### AI refinement leg (hybrid, D1/D2/D6)

Rides the Slice 3 chain unchanged: CRM event → core event bus → eldrin-workflows → `call_app_api` back through the core proxy with the service secret.

**New workflow template** `workflows-templates/crm-refine-deal-suggestion.json` in eldrin-workflows (template only — no engine changes; imported via the existing bulk-import route):

1. Trigger: event `deal.suggestion.created`.
2. `call_app_api` GET `/api/enhancement/deal-suggestions/{{payload.suggestionId}}/material` → current suggestion + email `bodyText`.
3. `ai_extract` with JSON schema `{ isLikelyDeal: boolean, confidence: number, dealName: string, estimatedValue: number|null, reasoning: string }` over the material (providers: mock/openai/claude, exactly as Slice 3).
4. `call_app_api` POST `/api/enhancement/deal-suggestions/{{payload.suggestionId}}` with the extraction output.

**Two new service-secret-gated CRM endpoints** (same auth pattern as the existing `/api/enhancement/*` routes, registered as public in the manifest and guarded in-route):

| Route | Behavior |
|---|---|
| `GET /api/enhancement/deal-suggestions/:id/material` | Returns the suggestion row + the source message's `bodyText` (via `sourceMessageId` → activities metadata). 404 unknown/non-pending-refinement. |
| `POST /api/enhancement/deal-suggestions/:id` | Validates + caps the AI output (`confidence` clamped to [0,1], `dealName` ≤ 200 chars, `estimatedValue` rejected > 10⁹, `reasoning` ≤ 500 chars). Applies refinement: fill-empty on `suggested_value`; replace `suggested_name` only when the heuristic used the fallback name; always set `ai_confidence`, `ai_reasoning`, `source='heuristic+ai'`, `ai_refinement_status='refined'`. **Never changes `status`** — even `isLikelyDeal=false` only records low confidence (D2). |

If the workflow never runs (no LLM, event undelivered, run failed), `ai_refinement_status` stays `'pending'` and the heuristic suggestion remains fully functional — identical durability semantics to Slice 3's `ai_enhancement_status`.

### API — `worker/routes/deal-suggestions.ts`

| Route | Permission | Behavior |
|---|---|---|
| `GET /api/deal-suggestions?status=pending` | `deals:read` | List, joined with contact/company display names. |
| `POST /api/deal-suggestions/:id/dismiss` | `deals:update` | `status='dismissed'`. 404 unknown, 409 non-pending. |
| `POST /api/deal-suggestions/:id/accept` | `deals:update` | `status='accepted'`. Returns the suggestion payload; the **client** then opens DealForm pre-populated. 409 non-pending. |

All three registered in the manifest `api.routes`.

### Frontend

- **`SuggestedDealsWidget`** on the CRM dashboard: signal-family chips (StatusBadge, info tone) per suggestion with matched snippets in a tooltip; Accept / Dismiss buttons. When refined, a confidence indicator (e.g. "AI: 82%" violet chip, `ai_reasoning` in its tooltip); an unrefined suggestion shows no AI chip — absence of refinement is not an error state.
- **Contact-detail banner** (`crm-card`, violet accent) when that contact has a pending suggestion — same chips + actions.
- **Accept flow:** call accept → open `DealForm` with new props `initialName`, `initialValue`, `initialContactId` (extending the existing `initialPipelineId/initialStageId` pattern). Submitting creates the deal through the existing deals API unchanged. Cancelling the form leaves the suggestion `accepted` (it stops being suggested; acceptable for this slice).
- Empty widget state: "No suggested deals. Signals from inbound email will appear here."

## 3. What this slice does NOT do

- No auto-created deals; AI never dismisses or creates suggestions (D2/D3).
- No AI sweep/retry cron for pending refinements (the flag makes it possible later).
- No ghost-activity notifications or emails — dashboard widget only.
- No company/lead ghost tracking.
- No eldrin-workflows **engine** changes and no eldrin-core changes — the only cross-repo artifact is one JSON workflow template.

## 4. Testing

- **Unit (worker):** scanner fixtures per family + combined; false-positive guards (signature block with phone numbers ≠ budget; quoted reply ignored); currency parsing edge cases; ghost-activity boundary (exactly N days, never-touched contact, deal with only stage history); suggestion dedup/merge/dismiss-then-new-message matrix; refinement apply rules (fill-empty value, name only over fallback, status never changed, caps/clamps, wrong service secret → 401).
- **Route tests:** list/accept/dismiss status transitions incl. 404/409; gone-quiet clamps; material endpoint 404s.
- **Template test** (eldrin-workflows): import route accepts the new template; definition validates.
- **Live validation:** end-to-end with the mock provider (email → suggestion → event → workflow → refined), LLM-down path (refinement stays `pending`, suggestion still usable), plus UI in light + dark (widgets, banner, accept→prefilled-form flow).
- Existing suites must stay green.

## 5. Risks

| Risk | Mitigation |
|---|---|
| Keyword false positives annoy users | ≥2-family threshold, reply/signature stripping, one-click dismiss that sticks per message; AI confidence chip helps triage borderline ones. |
| Ghost query slow with large activity tables | Existing `(relatedRecordId, relatedRecordType)` index; LIMIT-bounded; measured in tests with seeded data. |
| Suggestion spam from long threads | One pending suggestion per contact; merge instead of insert; dismissed messages never re-suggest. |
| AI refinement chain fails silently | `ai_refinement_status` stays `pending` (durable, queryable); suggestion works without it; same contract already proven in Slice 3. |
| Prompt-injected email steers the model output | Refinement apply endpoint validates/caps every field, cannot change status, and runs behind the service secret — worst case is a bad name/confidence on a suggestion the user still manually reviews. |
