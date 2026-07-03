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
- [ ] 7.8 seed CRM email templates (needs running eldrin-email — do during live validation)
- [x] Tests for linking/dedup services (started the CRM test suite: 21 tests) *(2026-07-02)*
- [ ] Live validation end-to-end (step 0 smoke test + acceptance criteria), then DONE.md + commit

### 2. CRM Phase 10 — Zero Data Entry (the differentiator)
- [x] **Slice 1 — auto-capture core** *(2026-07-02, commit f382022; live-validated)*: contact auto-creation from unknown inbound senders (name from display header, owner-guard, idempotent under redelivery), confidence heuristic (0.3–0.9) with badge + Confirm action, signature parser (phones/social extracted live; job title needs multi-line text), company-domain linking, merged audit+activity ContactDetail timeline (captured emails finally visible on the contact card). 59 CRM tests.
- [x] **Slice 2 — richer capture text** *(2026-07-03, commits 65c5bb1 email / 3b5ed0b crm; live-validated)*: `email.received` now carries `bodyText` (≤4000 chars, plain-text preferred, HTML-stripped fallback, null on metadata-depth sync) and the signature parser handles inline comma-separated signatures (closing-phrase detection, sender-name anchor, role-keyword-gated title). Live: unknown sender's inline signature yielded job title + phone + LinkedIn + company link at 90% confidence. Tests: email 86, crm 72.
- [ ] **Slice 3 — enrichment** as an eldrin-integration connector (API-key REST fits the SDK; second real consumer after factorial) + ghost-activity detection + deal auto-detection suggestions.
- [ ] **Slice 4 — calendar sync: extend eldrin-email** (reuses OAuth mailboxes; needs new Google scopes → mailbox re-consent) — write a small plan first.

### 3. Finish eldrin-workflows instead of building CRM Phase-2 automation
- [x] Webhook parses the live core envelope + verifies the service secret *(2026-07-02; live-validated — a CRM `contact.created` created a run with correct triggerData)*
- [x] **Executor reliability:** all `executeWorkflow` call sites (event webhook, cron callback, manual run) now run inside `executionCtx.waitUntil` *(2026-07-02; one legacy stuck run 710a72a6 remains in local D1)*
- [ ] Wire event emitter (`createEventClient`) — unstubs `emit_event` + workflow lifecycle events (secret + env plumbing now in place; `context.env` reaches step runners)
- [x] `send_email` step → emits `email.send.requested` *(2026-07-02; live-validated: contact.created → run completed → event delivered to eldrin-email through the secured bus; found+fixed core subscriber-dedup 500 on multi-pattern subscriptions)*
- [ ] Implement `call_app_api` runner + permission middleware + test infra (repo has none)
- [ ] Decision recorded: CRM REQ-2.1 is delivered by CRM events + eldrin-workflows, not a second engine

### 4. Hygiene (parallel, ongoing)
- [ ] Rotate + purge committed secrets in `eldrin-email/.dev.vars` and `private/`
- [ ] Sync eldrin-email manifest `api.routes` with real routes
- [ ] CRM test coverage: services first (linking, dedup, signature parsing, lead conversion)
- [ ] **Envelope mismatch (found 2026-07-02):** the live core pushes `{deliveryId, event: {id, type, source, payload, version}}` (`eldrin-core/core/routes/events.ts:534`), but the `eldrin-email` and `eldrin-workflows` webhook handlers read a flat `{type, payload}` — they silently drop every real delivery. The CRM handler accepts both shapes; fix email + workflows the same way. Event pushes also carry **no auth**, so webhook endpoints are public — consider a shared-secret header in core.

## Order

`0 → 1 → 2` sequential (each builds on the last). `3` can start any time after 1's event emission lands. `4` interleaves.
