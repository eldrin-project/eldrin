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
- [ ] Delete or quarantine legacy `eldrin-core/worker/events/` to remove the `/api/_events/receive` trap.
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
- [ ] Auto-capture migration (`auto_captured_emails`, `auto_created_contacts`, `enrichment_cache`)
- [ ] Smart linking with confidence scores + review UI; provisional contact auto-creation; signature parser
- [ ] **Enrichment as an eldrin-integration connector** (API-key REST fits the SDK; second real consumer after factorial)
- [ ] **Calendar sync: extend eldrin-email** (reuses OAuth tokens/mailboxes; the SDK has no OAuth) — gap not covered by existing plans; write a small plan first

### 3. Finish eldrin-workflows instead of building CRM Phase-2 automation
- [ ] Wire event emitter (`createEventClient`) — unstubs `emit_event` + lifecycle events
- [ ] `send_email` step → emit `email.send.requested` (eldrin-email already subscribes)
- [ ] Implement `call_app_api` runner + permission middleware + tests
- [ ] Decision recorded: CRM REQ-2.1 is delivered by CRM events + eldrin-workflows, not a second engine

### 4. Hygiene (parallel, ongoing)
- [ ] Rotate + purge committed secrets in `eldrin-email/.dev.vars` and `private/`
- [ ] Sync eldrin-email manifest `api.routes` with real routes
- [ ] CRM test coverage: services first (linking, dedup, signature parsing, lead conversion)
- [ ] **Envelope mismatch (found 2026-07-02):** the live core pushes `{deliveryId, event: {id, type, source, payload, version}}` (`eldrin-core/core/routes/events.ts:534`), but the `eldrin-email` and `eldrin-workflows` webhook handlers read a flat `{type, payload}` — they silently drop every real delivery. The CRM handler accepts both shapes; fix email + workflows the same way. Event pushes also carry **no auth**, so webhook endpoints are public — consider a shared-secret header in core.

## Order

`0 → 1 → 2` sequential (each builds on the last). `3` can start any time after 1's event emission lands. `4` interleaves.
