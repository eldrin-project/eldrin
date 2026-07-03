# Eldrin CRM — Next Steps

*Created: 2026-07-02. Owner: Tibor. This is the active short-term roadmap; the master plan remains `eldrin-crm-plan.md`.*

## Focus

**React only.** React 19 + single-spa + Hono workers is the production stack. The angular/vue/svelte apps and `eldrin-app-{angular,vue,svelte}` libraries are experiments — no further investment.

## Value proposition

Take the best of the big players, then beat them where they are structurally weak:

| Big-player baseline (match it) | Our edge (beat them) |
|---|---|
| Contacts/companies/leads/deals/activities/reports (Salesforce, HubSpot, Pipedrive) — **done in MVP** | **Zero Data Entry**: the CRM fills itself from email/calendar — foundational, not a bolt-on AI add-on (vs Einstein/Breeze) |
| Email send/templates/tracking (HubSpot) — **built in eldrin-email** | **Buyer-Side Deal Rooms** — already built; no major CRM has this natively |
| Workflow automation (Salesforce Flow, Zoho) — **engine 70% built in eldrin-workflows** | **Own your data**: single-tenant Cloudflare worker per customer — no per-seat SaaS pricing, full data ownership |
| | **Composable**: CRM, email, workflows, integrations are separate apps sharing one event bus — buy only what you need |

The differentiators only become real when auto-capture works end-to-end. That is the priority.

## Architecture (verified 2026-07-02)

- **eldrin-email** (mature): Gmail/Outlook OAuth sync, cross-app send API, `email.received/sent` events. The data-collection engine.
- **eldrin-core** event bus: registers manifest subscriptions, pushes to `POST {app}/api/_events/webhook`, cron-hooks API exists. (`worker/events/push.ts` targeting `/api/_events/receive` is dead legacy code — ignore or delete.)
- **eldrin-workflows**: real engine; `send_email`/`emit_event` steps stubbed; `call_app_api` missing. The reaction layer.
- **eldrin-integration**: declarative connector SDK (API-key + HTTP polling); reference: `eldrin-factorial`. The connector factory.
- **eldrin-crm**: MVP done (phases 01–06, 08, 09, 11). Phases 07 + 10 not started. Zero tests.

## Steps

### 0. Prove the event seam (runtime smoke test) — ~half a day
- [x] Run eldrin-core + eldrin-email + eldrin-crm locally; emit a test event; confirm push delivery to a subscriber, retries (401→retry→delivered observed) *(2026-07-02 — full flow validated: emit → bus → CRM webhook → activity on contact)*
- [x] Delete or quarantine legacy `eldrin-core/worker/events/` to remove the `/api/_events/receive` trap. *(2026-07-02 — deleted in eldrin-core `3a62c0c`)*
- [x] **RESOLVED (2026-07-02) — shared-secret service auth:** `X-Eldrin-App-Secret` header (= shared `JWT_SECRET`) both directions. SDK event client sends it on emit/poll/ack/nack (`eldrin-app-core/src/events/client.ts`, `buildAuthHeaders()`); core validates it on those four endpoints (`core/app.ts` `isValidServiceSecret`, falls through to JWT auth when absent) and attaches it on webhook pushes (`core/routes/events.ts` `buildPushAuthHeaders()`); CRM webhook enforces it when `JWT_SECRET` is set. Comparison isolated in per-repo helpers for a later HMAC swap. Live-validated: CRM `contact.created` emits cleanly; secured `email.received` push delivered to the enforcing webhook; wrong/missing secret → 401 on both sides. Remaining follow-up: eldrin-email + eldrin-workflows webhooks should also verify the header (fold into the envelope fix).

### 1. CRM Phase 07 — Email Integration (unblocked; plan exists)
Per `01_core_crm_foundation_mvp/phases/phase-07-email-integration/PLAN.md`:
- [x] 7.1 `worker/routes/events.ts`: handle `email.received/sent` → match `contact_emails` → log `email` activities (dedup by `messageId`) *(2026-07-02)*
- [x] 7.5 email-linking service (address → contact/company/deal) *(2026-07-02)*
- [x] 7.2/7.3 Send + template send from contact/deal via `POST /api/app/eldrin-email/api/email/send(-template)` *(2026-07-02)*
- [x] 7.4 email history tab (`GET …/email/history?contactEmail=`) *(2026-07-02)*
- [x] 7.6 graceful degradation when email app absent (`useEmailApp`) *(2026-07-02)*
- [x] 7.7 **declare + emit CRM events** (`contact.created/updated`, `deal.created/stage_changed`, `lead.converted`) *(2026-07-02)*
- [x] 7.8 seed CRM email templates (4 templates created in eldrin-email) *(2026-07-02)*
- [x] Tests for linking/dedup services (started the CRM test suite: 21 tests) *(2026-07-02)*
- [x] Live validation end-to-end + DONE.md *(2026-07-02 — real send round trip, idempotent redelivery, workflow-triggered send all verified; see phase-07 DONE.md)* — **Phase 07 COMPLETE**

### 2. CRM Phase 10 — Zero Data Entry (the differentiator)
- [x] **Slice 1 — auto-capture core** *(2026-07-02, commit f382022; live-validated)*: contact auto-creation from unknown inbound senders (name from display header, owner-guard, idempotent under redelivery), confidence heuristic (0.3–0.9) with badge + Confirm action, signature parser (phones/social extracted live; job title needs multi-line text), company-domain linking, merged audit+activity ContactDetail timeline (captured emails finally visible on the contact card). 59 CRM tests.
- [x] **Slice 2 — richer capture text** *(2026-07-03, commits 65c5bb1 email / 3b5ed0b crm; live-validated)*: `email.received` now carries `bodyText` (≤4000 chars, plain-text preferred, HTML-stripped fallback, null on metadata-depth sync) and the signature parser handles inline comma-separated signatures (closing-phrase detection, sender-name anchor, role-keyword-gated title). Live: unknown sender's inline signature yielded job title + phone + LinkedIn + company link at 90% confidence. Tests: email 86, crm 72.
- [x] **Slice 3 — AI enhancement via eldrin-workflows** *(2026-07-03; live-validated end-to-end)*: **built on eldrin-workflows, NOT a new eldrin-integration connector** (the workflows engine is the platform's generic reaction layer; enrichment is "event in → derive → write back"). Delivered: three generic workflow steps (`html_extract` homepage-metadata parser, `ai_extract` with mock/openai(local Ollama)/claude providers + JSON-schema validation, `call_app_api` service call through the core proxy), whole-value `{{expr}}` interpolation, the workflows repo's first test suite, a bulk idempotent workflow-import route + two shipped JSON templates ("CRM: Enrich new company", "CRM: Extract email insights"); eldrin-core app-proxy accepts `X-Eldrin-App-Secret` as a service principal; eldrin-crm `ai_enhancement_status` flag lifecycle (pending at capture / enhanced on apply / failures stay pending), provisional-company auto-creation (freemail + SSRF-guarded domains), `company.created` + `email.extraction.requested` events, service-secret-gated `/api/enhancement/{companies,contacts}/:id` apply + `/pending` + `/contacts/:id/enhancement-material` endpoints (the pull contract for a future local enhancer app), and UI badges + Enhance-now buttons. Spec/plan: `docs/superpowers/{specs,plans}/2026-07-03-ai-enhancement-workflows*`. Live: cloudflare.com email → provisional company enriched from homepage + contact title via mock LLM; LLM-down → flag stays pending; wrong secret → 401. **Deferred to a follow-up mini-slice: ghost-activity detection + deal auto-detection suggestions.** ~~Follow-up filed: core cron callback sends no service secret, so workflows' `/api/_events` `/_cron/callback` route stays public — have core sign cron callbacks, then gate it.~~ *(DONE 2026-07-03 — core signs cron callbacks with `X-Eldrin-App-Secret` (processCronHooks + all three provider schedulers), workflows gates `/_cron/callback` like its events webhook; unit-tested both sides + live-validated with a real cron workflow through core tick. Also fixed: local core D1 was missing the app-cron-hooks migration.)*
- [ ] **Slice 3b — ghost-activity detection + deal auto-detection** (split out of Slice 3; CRM-internal, low-risk).
- [ ] **Slice 4 — calendar sync: standalone `eldrin-calendar` extension app** *(DECISION 2026-07-03: NOT an eldrin-email extension — calendar becomes its own app so any app can integrate with it; CRM is the first consumer. It can still reuse the OAuth-mailbox pattern/accounts where sensible, but owns its own manifest, D1, events (e.g. `calendar.event.created`), and UI. Needs new Google scopes → re-consent.)* — write a small plan first.

### 3. Finish eldrin-workflows instead of building CRM Phase-2 automation
- [x] Webhook parses the live core envelope + verifies the service secret *(2026-07-02; live-validated — a CRM `contact.created` created a run with correct triggerData)*
- [x] **Executor reliability:** all `executeWorkflow` call sites (event webhook, cron callback, manual run) now run inside `executionCtx.waitUntil` *(2026-07-02; one legacy stuck run 710a72a6 remains in local D1)*
- [ ] Wire event emitter (`createEventClient`) — unstubs `emit_event` + workflow lifecycle events (secret + env plumbing now in place; `context.env` reaches step runners)
- [x] `send_email` step → emits `email.send.requested` *(2026-07-02; live-validated: contact.created → run completed → event delivered to eldrin-email through the secured bus; found+fixed core subscriber-dedup 500 on multi-pattern subscriptions)*
- [x] Implement `call_app_api` runner + permission middleware + test infra (repo has none) *(2026-07-03, Slice 3: call_app_api routes through the core proxy with the service secret; createPermissionMiddleware + manifest api.routes now gate the workflows API with a service-secret bypass; vitest bootstrapped)*
- [ ] Decision recorded: CRM REQ-2.1 is delivered by CRM events + eldrin-workflows, not a second engine

### 4. Hygiene (parallel, ongoing)
- [x] Rotate + purge committed secrets in `eldrin-email/.dev.vars` and `private/` *(2026-07-03 — audit (2026-07-02, see `eldrin-email/private/SECURITY-ROTATION.md`) found only JWT_SECRET was ever committed (eldrin-templates history); it is now ROTATED across all four `.dev.vars` and live-verified. Remaining manual: Google/Microsoft provider-side secret rotation (precautionary — never in git); optional eldrin-templates history rewrite (rotation already made the leaked value worthless).)*
- [x] Sync eldrin-email manifest `api.routes` with real routes *(2026-07-02, parent commit 949a521)*
- [ ] CRM test coverage: services first (linking, dedup, signature parsing, lead conversion)
- [x] **Envelope mismatch (found 2026-07-02):** ~~the `eldrin-email` and `eldrin-workflows` webhook handlers read a flat `{type, payload}`~~ *(RESOLVED 2026-07-02 — live-envelope parsing fixed in both apps; webhook auth resolved via `X-Eldrin-App-Secret` shared-secret service auth across SDK/core/apps. See phase-07 DONE.md.)*

## Order

`0 → 1 → 2` sequential (each builds on the last). `3` can start any time after 1's event emission lands. `4` interleaves.
