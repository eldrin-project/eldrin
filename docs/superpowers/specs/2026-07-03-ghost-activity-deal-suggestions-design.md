# Slice 3b — Ghost-Activity Detection + Deal Auto-Detection Suggestions

**Date:** 2026-07-03
**Status:** Draft — awaiting user review (v3: AI co-detector runs on ALL captured emails per user decision)
**Scope:** eldrin-crm (primary) + one new workflow template in eldrin-workflows
**Requirements:** REQ-1.10.11 (ghost activity), REQ-1.10.08 (deal auto-detection)
**Parent spec:** `2026-07-03-ai-enhancement-workflows-design.md` (deferred item D2)

## Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | **Hybrid detection with two parallel co-detectors (user decision):** a CRM-internal keyword heuristic runs synchronously at capture time, and an AI workflow runs asynchronously on **every** captured inbound email with body text — not only heuristic hits. | The heuristic gives an instant, deterministic, LLM-free baseline; the AI catches paraphrased signals the patterns miss. User explicitly chose full AI coverage over trigger-gated cost savings; cost = one LLM call per captured inbound email. |
| D2 | The AI assessment may **create** a suggestion (when `isLikelyDeal` and confidence ≥ 0.6 and no pending one exists) and may **refine** an existing pending one — but it never dismisses or deletes a suggestion, never changes `status`, and never auto-creates a deal. `isLikelyDeal=false` merely records low confidence on an existing suggestion. | A model may add candidates for human review but must never silently discard a potential deal; the human Accept/Dismiss stays the only status authority. |
| D3 | Accepting a suggestion **opens the DealForm pre-populated** — it never auto-creates a deal. | The user always confirms; wrong suggestions cost one click to dismiss, never a wrong record. |
| D4 | Ghost activity is **computed on read** (no new tables, no cron). | The activities table already carries everything needed, indexed by `(relatedRecordId, relatedRecordType)`. A widget query at dashboard-load frequency is cheap at single-tenant scale. |
| D5 | Ghost ≠ rotting. Rotting (existing) = no **stage change**; ghost = no **captured activity at all** (and for deals, also no stage change). | The two signals answer different questions; both stay. |
| D6 | Assessment durability copies the `ai_enhancement_status` contract: `ai_assessment_status` = `'pending'` (heuristic-created, AI hasn't assessed yet) \| `'assessed'` (AI applied; AI-created rows are born `'assessed'`). **Failures stay `pending`.** | Same source-of-truth pattern already live-validated in Slice 3; a future sweep can retry pending assessments. |
| D7 | The AI leg triggers on a **new event `deal.detection.requested`, emitted unconditionally** for every captured inbound email with body text — NOT by widening `email.extraction.requested`. | The existing extraction event is deliberately gated (human-created contacts are pull-only for contact-field writes; Slice 3 design). Deal detection has different semantics and must cover all emails, so it gets its own event rather than silently changing Slice 3's contract. |

## Assumptions (flag on review if wrong)

- Both features ship in this one slice.
- Ghost-activity covers **contacts and open deals** (not companies or leads) per REQ-1.10.11.
- Default quiet window 30 days; selector offers 14/30/60/90. No server-side config table (YAGNI — the selector is the "configurable period").
- Heuristic threshold: **≥ 2 distinct signal families** in one email body. AI-creation threshold: **confidence ≥ 0.6**.
- Dev validation of the AI leg uses the existing **mock provider** (canned output), same as Slice 3.
- Cost of one LLM call per captured inbound email is accepted (explicit user decision — full coverage over trigger-gating).

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
source TEXT NOT NULL DEFAULT 'heuristic'  -- 'heuristic' | 'ai' | 'heuristic+ai'
ai_assessment_status TEXT NOT NULL DEFAULT 'pending'  -- 'pending' | 'assessed' (D6; failures stay pending)
ai_confidence REAL NULL                   -- 0..1, set by assessment
ai_reasoning TEXT NULL                    -- one-line model rationale, shown in the UI tooltip
created_at INTEGER NOT NULL · updated_at INTEGER NOT NULL
INDEX (status) · INDEX (contact_id) · INDEX (ai_assessment_status)
```

### Capture-time hook

In the email-capture path (`worker/services/auto-capture.ts` + the emission point in `worker/routes/events.ts`, matching where `email.extraction.requested` is emitted today), after the existing signature/enhancement handling, when `payload.bodyText` is present:

1. Emit `deal.detection.requested` (fire-and-forget via the existing event emitter, `waitUntil`) with `{ messageId, contactId, from, subject, bodyText }` — **unconditionally** (D7), same payload shape as `email.extraction.requested`. This drives the AI co-detector on every email.
2. Run `detectBuyingSignals`. If `families.length < 2` → done (the AI leg may still create a suggestion later).
3. Skip if the contact has any **open deal** (via `dealContacts` join) — the conversation is already tracked.
4. Skip (merge instead) if a `pending` suggestion exists for the contact: append new hits (deduped by snippet), update `suggested_value` if larger, re-arm `ai_assessment_status='pending'`, bump `updatedAt`.
5. Otherwise insert a suggestion: `suggestedName` = `"{Company name} — {email subject}"` (fallback `"Deal with {contact name}"`), `suggestedValue` from the scanner, `sourceMessageId` from the payload, `source='heuristic'`, `ai_assessment_status='pending'`.
6. A dismissed suggestion for the same `sourceMessageId` is never re-created; a dismissed suggestion for the contact from an *older* message does not block a new one from a *newer* message.

Failures in this hook are logged and swallowed — suggestion detection must never break email capture.

### AI co-detector leg (D1/D2/D6/D7)

Rides the Slice 3 chain unchanged: CRM event → core event bus → eldrin-workflows → `call_app_api` back through the core proxy with the service secret.

**New workflow template** `workflows-templates/crm-detect-deal-signals.json` in eldrin-workflows (template only — no engine changes; imported via the existing bulk-import route). The existing "CRM: Extract email insights" template is untouched.

1. Trigger: event `deal.detection.requested`.
2. `ai_extract` over `{{payload.bodyText}}` (no material fetch needed — the body rides the event, exactly like the insights template) with JSON schema `{ isLikelyDeal: boolean, confidence: number, dealName: string, estimatedValue: number|null, reasoning: string }`, prompt instructing assessment of buying intent (budget, timeline, stakeholders, RFP/procurement language). Providers: mock/openai/claude, as Slice 3.
3. `call_app_api` POST `/api/enhancement/deal-suggestions/assess` with `{ messageId, contactId, assessment: {{steps.extract.output}}, source: "workflow:detect-deal-signals" }`.

**One new service-secret-gated CRM endpoint** (same auth pattern as the existing `/api/enhancement/*` routes: public in the manifest, guarded in-route):

`POST /api/enhancement/deal-suggestions/assess` — upsert semantics:

1. Validate + cap the attacker-influenced AI output: `confidence` clamped to [0,1], `dealName` ≤ 200 chars, `estimatedValue` rejected outside (0, 10⁹), `reasoning` ≤ 500 chars, `messageId`/`contactId` required and existing.
2. Guards (same as the heuristic): contact has an open deal → record nothing, ack. Message was already dismissed (`sourceMessageId` of a dismissed suggestion) → ack.
3. **Pending suggestion exists for the contact** → refine it: fill-empty on `suggested_value`; replace `suggested_name` only when the heuristic used the fallback name; set `ai_confidence`, `ai_reasoning`, `source='heuristic+ai'`, `ai_assessment_status='assessed'`. Applies even when `isLikelyDeal=false` (low confidence recorded, suggestion kept — D2).
4. **No pending suggestion** → create one only when `isLikelyDeal === true` AND `confidence ≥ 0.6` (named constant `AI_SUGGESTION_MIN_CONFIDENCE`): `source='ai'`, `ai_assessment_status='assessed'`, `signals='[]'`, name/value from the assessment (fallback name as in the heuristic path).
5. **Never changes `status`**; never deletes (D2).

If the workflow never runs (no LLM, event undelivered, run failed), heuristic-created suggestions stay `ai_assessment_status='pending'` and remain fully functional — identical durability semantics to Slice 3's `ai_enhancement_status`. Emails where neither detector fired simply produce nothing; the next email retriggers both paths.

### API — `worker/routes/deal-suggestions.ts`

| Route | Permission | Behavior |
|---|---|---|
| `GET /api/deal-suggestions?status=pending` | `deals:read` | List, joined with contact/company display names. |
| `POST /api/deal-suggestions/:id/dismiss` | `deals:update` | `status='dismissed'`. 404 unknown, 409 non-pending. |
| `POST /api/deal-suggestions/:id/accept` | `deals:update` | `status='accepted'`. Returns the suggestion payload; the **client** then opens DealForm pre-populated. 409 non-pending. |

All three registered in the manifest `api.routes`.

### Frontend

- **`SuggestedDealsWidget`** on the CRM dashboard: signal-family chips (StatusBadge, info tone) per suggestion with matched snippets in a tooltip (AI-created suggestions may have zero heuristic chips — that's normal); Accept / Dismiss buttons. When assessed, a confidence indicator (e.g. "AI: 82%" violet chip, `ai_reasoning` in its tooltip); an unassessed suggestion shows no AI chip — absence of assessment is not an error state.
- **Contact-detail banner** (`crm-card`, violet accent) when that contact has a pending suggestion — same chips + actions.
- **Accept flow:** call accept → open `DealForm` with new props `initialName`, `initialValue`, `initialContactId` (extending the existing `initialPipelineId/initialStageId` pattern). Submitting creates the deal through the existing deals API unchanged. Cancelling the form leaves the suggestion `accepted` (it stops being suggested; acceptable for this slice).
- Empty widget state: "No suggested deals. Signals from inbound email will appear here."

## 3. What this slice does NOT do

- No auto-created deals; AI never dismisses or creates suggestions (D2/D3).
- No AI sweep/retry cron for pending assessments (the flag makes it possible later).
- No ghost-activity notifications or emails — dashboard widget only.
- No company/lead ghost tracking.
- No eldrin-workflows **engine** changes and no eldrin-core changes — the only cross-repo artifact is one JSON workflow template.

## 4. Testing

- **Unit (worker):** scanner fixtures per family + combined; false-positive guards (signature block with phone numbers ≠ budget; quoted reply ignored); currency parsing edge cases; ghost-activity boundary (exactly N days, never-touched contact, deal with only stage history); suggestion dedup/merge/dismiss-then-new-message matrix; assess-endpoint matrix (refine existing incl. `isLikelyDeal=false`; create above/below confidence threshold; open-deal and dismissed-message guards; status never changed; caps/clamps; wrong service secret → 401); `deal.detection.requested` emitted unconditionally while `email.extraction.requested` stays gated.
- **Route tests:** list/accept/dismiss status transitions incl. 404/409; gone-quiet clamps.
- **Template test** (eldrin-workflows): import route accepts the new template; definition validates.
- **Live validation:** end-to-end with the mock provider — (a) heuristic+AI path: deal-ish email → instant suggestion → workflow assesses it; (b) AI-only path: email below heuristic threshold → workflow creates the suggestion; (c) LLM-down path: assessment stays `pending`, heuristic suggestion still usable. Plus UI in light + dark (widgets, banner, accept→prefilled-form flow).
- Existing suites must stay green.

## 5. Risks

| Risk | Mitigation |
|---|---|
| Keyword false positives annoy users | ≥2-family threshold, reply/signature stripping, one-click dismiss that sticks per message; AI confidence chip helps triage borderline ones. |
| Ghost query slow with large activity tables | Existing `(relatedRecordId, relatedRecordType)` index; LIMIT-bounded; measured in tests with seeded data. |
| Suggestion spam from long threads | One pending suggestion per contact; merge instead of insert; dismissed messages never re-suggest. |
| AI chain fails silently | `ai_assessment_status` stays `pending` on heuristic rows (durable, queryable); suggestions work without assessment; same contract already proven in Slice 3. |
| Prompt-injected email steers the model output | Assess endpoint validates/caps every field, cannot change status or dismiss, and runs behind the service secret — worst case is a bad name/confidence on a suggestion the user still manually reviews. |
| LLM cost/volume on busy mailboxes | Accepted by explicit user decision; single call per email, 4 000-char input cap; the event seam makes trigger-gating a one-line revert later if needed. |
