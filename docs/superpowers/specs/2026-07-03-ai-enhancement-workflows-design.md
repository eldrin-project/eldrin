# AI Enhancement via eldrin-workflows — Design

**Date:** 2026-07-03
**Status:** approved design, pending implementation plan
**Scope:** CRM Phase 10 Slice 3 (revised) — company enrichment + LLM email-insight extraction, built as workflow-engine improvements instead of a new extension app.

## Context

CRM Phase 10 ("Zero Data Entry") slices 1–2 shipped auto-capture: provisional contacts from inbound email, signature parsing, company-domain linking. Slice 3 adds the two "derive data from outside" capabilities:

1. **Company enrichment** — fill an auto-created company's fields (name, description, logo, …) from its domain.
2. **AI email-insight extraction** — run email body text through an LLM to extract what regex parsing cannot (job titles in prose, signature info the heuristics miss; later: footer images via vision).

## Decisions (brainstorm outcomes)

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | **No new extension.** Build inside eldrin-workflows + thin CRM additions. | eldrin-workflows is the platform's generic reaction layer; enrichment is "event in → fetch/derive → write back", exactly its shape. Its missing pieces (`call_app_api`, more steps) are already on the roadmap. Fallback if blocked: an `eldrin-crm-integrations` connector app (factorial-style). |
| D2 | Ghost-activity detection + deal auto-detection **split out** to a follow-up mini-slice. | CRM-internal, low-risk; different weight class. |
| D3 | Company enrichment default provider is **free metadata lookup** (homepage title/meta/OG parse), no API key. Commercial-provider seam stays open. | Works out of the box for every single-tenant deploy. |
| D4 | **Hybrid seam**: event-driven for auto-capture, plus a manual path ("Enhance now" = manual workflow run). | |
| D5 | `call_app_api` routes **through core's app proxy** (`/api/app/{appId}/…`), not direct worker-to-worker. | Less configuration (no per-app URL discovery); one place for service authz. |
| D6 | **Multiple AI providers**: `mock`, `openai` (OpenAI-compatible — also covers local Ollama/LM Studio/Gemma via base URL), `claude` (Anthropic Messages API). | Local LLM needs no separate provider — it speaks the OpenAI protocol. |
| D7 | **CRM orchestrates extraction**: CRM emits explicit `email.extraction.requested` events; the workflow reacts. The engine never subscribes to raw `email.received`. | CRM decides which emails are worth an LLM call and passes matched-record context. |
| D8 | **`ai_enhancement_status` flag on CRM records is the source of truth.** Set `pending` at capture, cleared only by a successful apply. Failures leave it pending. | Local LLM is not always available; the flag enables a pull-based local enhancer app and implicit retry. Nothing is ever lost to a transient failure. |
| D9 | The two shipped workflows are **JSON documents** imported into eldrin-workflows, not code. | Matches the "import/configure workflows other extensions use" platform vision. Manifest-declared workflow templates deferred to a future slice. |

## Architecture

Three existing repos change; no new repo.

```
eldrin-email ──email.received──▶ core bus ──▶ eldrin-crm webhook
                                                │ auto-capture (slices 1–2)
                                                │ + set ai_enhancement_status='pending'
                                                │ + emit company.created /
                                                │   email.extraction.requested
                                                ▼
                                            core bus
                                                │ (manifest subscription)
                                                ▼
                                        eldrin-workflows webhook
                                                │ trigger matching → run
                                                │ steps: http_request →
                                                │   html_extract | ai_extract →
                                                │   call_app_api
                                                ▼
                        core app proxy /api/app/eldrin-crm/api/…  (X-Eldrin-App-Secret)
                                                ▼
                                  eldrin-crm apply endpoints
                                  (fill-empty-only, flag → 'enhanced')
```

A future **local enhancer app** (out of scope this slice) pulls `GET /api/enhancement/pending` from the CRM, runs a local LLM, and POSTs to the same apply endpoints. The flag lifecycle + pull/apply API shipped now is its complete contract.

## Component design

### 1. eldrin-crm — flag lifecycle, events, endpoints, UI

**Schema (new migration):** `contacts` and `companies` gain:
- `ai_enhancement_status` TEXT, nullable — `null` (nothing to do) | `'pending'` | `'enhanced'`
- `ai_enhancement_updated_at` INTEGER, nullable
- partial index on each table where status = 'pending'

**Flag transitions:**
- → `pending`: set by auto-capture — on a contact when an inbound email with non-null `bodyText` is captured for it; on a company at provisional creation (D8 below adds company auto-creation). Re-arming: a *new* email for an already-`enhanced` contact resets it to `pending` (new material to process).
- → `enhanced`: set only by the apply endpoints on success.
- Failures (LLM down, workflow failed, timeout): no transition. `pending` persists; retry is implicit via the pull model or a manual re-run.

**Persist bodyText (bug-adjacent gap):** `email-linking.ts` currently stores only `snippet` in activity metadata and drops `bodyText` after signature parsing. Change: include `bodyText` in `EmailActivityMetadata` (≤4000 chars, already truncated by the emitter). Without this the pull model has no source material.

**Company auto-creation (scope addition, user-approved):** auto-capture creates a provisional company when an inbound sender's domain matches no existing company and is not a freemail domain (static blocklist: gmail.com, outlook.com, yahoo.com, etc. — a constant list, ~30 entries). Mirrors slice-1 contacts: `is_auto_created`, `capture_confidence`, badge + Confirm UX. Created with `name` = domain (placeholder until enrichment fills it), `ai_enhancement_status='pending'`.

**New emitted events (manifest `events.emits`):**
- `company.created {companyId, domain, isAutoCreated}` — emitted on any company creation (manual or auto); the shipped workflow's conditions filter on `isAutoCreated` if desired.
- `email.extraction.requested {messageId, contactId, from, bodyText}` — emitted during capture when the contact is auto-created OR capture confidence < 0.7, AND `bodyText` is non-null.

**New endpoints:**
- `POST /api/companies/:id/apply-enrichment` — body `{data: {name?, description?, logoUrl?, industry?, location?}, source}`. Fill-empty-only; bumps `capture_confidence`; sets flag `enhanced`; idempotent (re-applying the same data is a no-op). Auth: service secret (`X-Eldrin-App-Secret`) OR admin JWT.
- `POST /api/contacts/:id/apply-insights` — body `{messageId, insights: {jobTitle?, phones?, companyName?, social?, address?}, source}`. Same semantics; phones deduped by normalized number (reuse slice-1 logic); idempotent per `(contactId, messageId)`.
- `GET /api/enhancement/pending?type=contact|company&limit&offset` — service-secret or admin JWT. Returns pending records **with material**: contacts include the latest email activity's `bodyText` + `from`; companies include `domain`. This + the apply endpoints = the local-enhancer contract.

**Input validation:** apply endpoints validate bodies with zod schemas; unknown fields rejected; strings length-capped. LLM-derived data is external input — never trusted raw.

**UI:**
- "Pending AI enhancement" badge on ContactDetail/CompanyDetail when flag = `pending` (reuse the slice-1 auto-captured badge pattern).
- **Enhance now** button next to the badge: calls `POST /api/app/eldrin-workflows/api/workflows/:id/run` through the shell proxy, passing the same payload shape the event trigger would carry (`{companyId, domain, isAutoCreated}` / `{messageId, contactId, from, bodyText}`) so one definition serves both trigger paths (fire-and-forget; toast "Enhancement requested"). Workflow id resolved by listing workflows and matching the shipped names; button hidden when eldrin-workflows is not installed (same `useEmailApp`-style graceful degradation — a `useWorkflowsApp` hook).

### 2. eldrin-workflows — three new steps + AI provider registry

All steps follow the existing `StepRunner {type, execute(config, context)}` contract, registered in `registry.ts`. Config values support the existing `{{…}}` interpolation.

**`call_app_api`** — `worker/engine/steps/call-app-api.ts`
- Config: `{appId, method, path, body?, timeout?}`.
- Executes `fetch(`${env.CORE_URL}/api/app/${appId}${path}`)` with headers `X-Eldrin-App-Secret: env.JWT_SECRET`, JSON body.
- Output: `{statusCode, body}`; non-2xx → step fails (run failed, flag stays pending).
- `CORE_URL` from `.dev.vars`/settings (dev: `http://localhost:4000`).

**`html_extract`** — `worker/engine/steps/html-extract.ts`
- Config: `{html}` (interpolated from a prior `http_request` output).
- Pure function, no network: extracts `<title>`, `meta[name=description]`, `og:site_name`, `og:title`, `og:description`, `og:image` via regex-based parsing (no DOM in Workers; a small tolerant parser, not a dependency).
- Output: `{name?, description?, logoUrl?}` — og:site_name > og:title > `<title>` for name; og:image resolved against the fetched URL for logoUrl.
- Response-size cap: input truncated to 256 KB before parsing.

**`ai_extract`** — `worker/engine/steps/ai-extract.ts` + `worker/engine/ai/` (provider registry)
- Config: `{provider?, prompt, input, schema}` — `schema` is a JSON-schema-shaped object describing the expected output; `input` is the text to process (interpolated).
- Provider registry `worker/engine/ai/providers/`:
  - **`mock`** (default when `AI_PROVIDER` unset): deterministic — extracts via the same heuristics family as the CRM signature parser plus canned patterns; exists so the pipeline is fully testable/e2e-runnable with no LLM. Returns schema-shaped output.
  - **`openai`**: `POST {AI_OPENAI_BASE_URL}/chat/completions` with `AI_OPENAI_MODEL`, optional `Authorization: Bearer {AI_OPENAI_API_KEY}`, `response_format: {type: "json_object"}`, prompt instructing JSON-only output. Covers OpenAI itself AND local Ollama/LM Studio/Gemma (base URL `http://localhost:11434/v1`, no key).
  - **`claude`**: official `@anthropic-ai/sdk` (fetch-based, Workers-compatible), Messages API with structured outputs (`output_config: {format: {type: "json_schema", schema}}`) so the response is schema-enforced server-side. Model from `AI_CLAUDE_MODEL` (default `claude-opus-4-8`), key from `AI_CLAUDE_API_KEY`.
- Step-level provider override in config beats the env default (`AI_PROVIDER`).
- **Output validation:** every provider's output is validated against `schema` (zod-from-JSON-schema at the step layer) before the step succeeds. Invalid/unparseable output → step fails. Timeout 30 s.
- Settings (env/`.dev.vars`): `AI_PROVIDER`, `AI_OPENAI_BASE_URL/MODEL/API_KEY`, `AI_CLAUDE_MODEL/API_KEY`. Secrets never in config JSON or workflow definitions.

**Workflow import:** `POST /api/workflows/import` accepting the export shape `{name, description, definition}` (admin-gated, same auth as existing workflow CRUD); creates inactive workflows (admin reviews + activates). The two shipped definitions live in `workflows-templates/` in the repo as JSON files.

**Test infra (first in this repo):** vitest + the same better-sqlite3 harness the CRM uses. Unit tests for the three steps (mocked fetch/providers), provider registry, output validation, and one executor-level test running a full definition against stubbed steps.

### 3. eldrin-core — app proxy accepts the service secret

`core/routes/apps.ts` proxy (`/api/app/:appId/*`): today requires a user JWT. Add: if `X-Eldrin-App-Secret` is present and matches `JWT_SECRET` (same constant-time comparison helper as the event-bus endpoints), treat the caller as a trusted **service principal** — skip the user-JWT requirement and role/route checks, forward the request with the secret header attached (the receiving app's own service-secret check still applies). No other proxy behavior changes. This mirrors the emit/poll/ack/nack precedent from the Phase-07 platform work.

## The two shipped workflow definitions

**"CRM: Enrich new company"** (`workflows-templates/crm-enrich-company.json`)
```json
{
  "name": "CRM: Enrich new company",
  "definition": {
    "version": 1,
    "trigger": {"type": "event", "config": {"eventType": "company.created"}},
    "conditions": [{"field": "payload.isAutoCreated", "operator": "equals", "value": true}],
    "steps": [
      {"name": "fetch_site", "type": "http_request",
       "config": {"url": "https://{{payload.domain}}", "timeout": 5000}},
      {"name": "extract", "type": "html_extract",
       "config": {"html": "{{steps.fetch_site.output.body}}"}},
      {"name": "apply", "type": "call_app_api",
       "config": {"appId": "eldrin-crm", "method": "POST",
                  "path": "/api/companies/{{payload.companyId}}/apply-enrichment",
                  "body": {"data": "{{steps.extract.output}}", "source": "workflow:enrich-company"}}}
    ]
  }
}
```
No LLM involved — works day one with zero configuration.

**"CRM: Extract email insights"** (`workflows-templates/crm-extract-email-insights.json`)
```json
{
  "name": "CRM: Extract email insights",
  "definition": {
    "version": 1,
    "trigger": {"type": "event", "config": {"eventType": "email.extraction.requested"}},
    "steps": [
      {"name": "extract", "type": "ai_extract",
       "config": {"prompt": "Extract the sender's contact details from this email. Return ONLY fields you are confident about; omit anything uncertain.",
                  "input": "{{payload.bodyText}}",
                  "schema": {"type": "object", "properties": {"jobTitle": {"type": "string"},
                             "phones": {"type": "array", "items": {"type": "string"}},
                             "companyName": {"type": "string"},
                             "social": {"type": "object"}},
                             "additionalProperties": false}}},
      {"name": "apply", "type": "call_app_api",
       "config": {"appId": "eldrin-crm", "method": "POST",
                  "path": "/api/contacts/{{payload.contactId}}/apply-insights",
                  "body": {"messageId": "{{payload.messageId}}",
                           "insights": "{{steps.extract.output}}",
                           "source": "workflow:extract-email-insights"}}}
    ]
  }
}
```
Runs on `mock` until a real provider is configured — the seam, not the model, is what ships.

Note: object-valued interpolation (`"body": {...}` containing `{{steps.x.output}}` as a whole-object substitution) must be supported by `interpolateConfig`; if it is string-only today, extending it to whole-value substitution when a config value is exactly one `{{…}}` expression is part of the `call_app_api` work.

## Failure handling & degradation

- **eldrin-workflows not installed / workflows not imported:** CRM events go nowhere; capture works exactly as slices 1–2; flags stay `pending` and are visible in the pull endpoint. Nothing breaks.
- **LLM unavailable / provider error / invalid output:** `ai_extract` step fails → run recorded as failed (visible in run history) → no apply → flag stays `pending`. No retry loop in the engine this slice; retry = next triggering email, manual Enhance-now, or the local puller.
- **Domain fetch fails** (site down, timeout, non-HTML): `http_request`/`html_extract` fail the same way; company keeps its placeholder name and `pending` flag.
- **SSRF guard on the enrich workflow:** `http_request` already exists and takes arbitrary URLs (admin-authored workflows are trusted), but the *shipped* company workflow interpolates an email-derived domain. Guard in `captureInboundSender`: the domain written to `companies.domain` (and thus the event) must match a hostname regex (no ports, no IPs, no localhost/RFC-1918 names) — validated CRM-side before the company is created.
- **Apply endpoints are idempotent** — a redelivered event or duplicate run cannot double-write (fill-empty-only + per-message keys).

## Security

- Both apply endpoints + pull endpoint: service secret or admin JWT; 401 otherwise. Manifest `api.routes` updated with the new routes and permissions.
- Core proxy service-principal path: constant-time secret comparison; keeps the existing "swap to HMAC later" isolation pattern.
- LLM output is untrusted external input: schema-validated at the step layer AND zod-validated again at the CRM apply boundary (defense in depth — the two run in different trust domains).
- No secrets in workflow definitions, config JSON, or the repo (`.dev.vars` gitignored; `.dev.vars.example` updated with the new AI_* / CORE_URL keys, placeholder values only).

## Testing

- **eldrin-workflows (new suite):** step unit tests (call_app_api with mocked fetch incl. non-2xx; html_extract against fixture HTML pages incl. malformed; ai_extract per provider with canned responses incl. invalid-JSON and schema-violation cases); interpolation whole-object substitution; import route.
- **eldrin-crm (extend 72-test suite):** flag transitions (pending on capture, re-arm on new email, enhanced on apply, unchanged on failure paths); apply endpoints (fill-empty-only, idempotency, validation rejects, auth 401s); pull endpoint (material included, pagination); company auto-creation (freemail blocklist, domain validation); event emission conditions.
- **eldrin-core:** proxy service-principal tests (valid secret passes, wrong/missing falls through to JWT path).
- **Live validation (gate for DONE):** core + email + crm + workflows running; real inbound email from an unknown corporate domain → provisional company + pending flags → both workflows fire → mock-extracted insights + real homepage metadata applied → flags `enhanced`, badges clear; LLM-down simulation (point openai provider at a dead port) → run failed, flag stays pending, record appears in pull endpoint; Enhance-now button round trip; wrong service secret → 401 on apply + proxy. Chrome-devtools verified, per the established cross-repo seam discipline.

## Out of scope (recorded)

- Ghost-activity detection + deal auto-detection suggestions (next mini-slice).
- The local enhancer app itself (its API contract ships now).
- Footer-image OCR / vision extraction (needs full MIME access from eldrin-email; the `ai_extract` input shape can grow an `images` field later).
- Commercial enrichment provider implementation (seam only).
- Manifest-declared workflow templates / template registry (own slice).
- Enrichment result caching (event-driven once-per-company creation makes it low-value; revisit with the persistent-store primitive).
- Workflow-level retry/backoff policy (the pending flag covers durability this slice).

## References

- Roadmap: `docs/eldrin-crm-implementation/NEXT_STEPS.md` (steps 2–3), Phase 10 `PLAN.md`/`STATUS.md`.
- Engine: `eldrin-workflows/worker/engine/` (executor, registry, interpolation, steps).
- Auth precedent: shared-secret service auth (Phase-07 DONE.md), `eldrin-core/core/app.ts` `isValidServiceSecret`.
- Slice 1–2 capture: `eldrin-crm/worker/services/{auto-capture,signature-parser,email-linking}.ts`.
- CPI flow backlog tie-in: `docs/superpowers/specs/2026-06-29-future-flow-elements.md` Tier 1 (Content Enricher) — this slice builds the app-level enrichment loop; the flow-engine enrich node remains a separate future primitive.
