# Enricher v1.1 Implementation Plan (sequential runs, main-domain fetch, automated senders)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the three v1.1 behaviors from `docs/superpowers/specs/2026-07-11-enricher-automated-sender-design.md`: sequential runs with live per-record output, registrable-domain-first fetching, and automated-sender retirement with a persisted CRM flag + manual override.

**Architecture:** CRM side first (migration + endpoint changes + re-arm route + UI), then enricher side (runner, fetch candidates, contact gates). The two sides meet at the existing enhancement contract, extended with `manual` (pending payload) and `automated` (apply payload).

**Tech Stack:** eldrin-crm: Hono 4 + Drizzle + Vitest (better-sqlite3 test DB). eldrin-enricher: Rust, `psl` crate added; wiremock tests.

## Global Constraints

- eldrin-crm work on branch `feature/enricher-automated-sender` from `main` (@ df8369f). Migration file needs a NEW 14-digit timestamp prefix > `20260710130000`; run `npm run generate:migrations` after adding it (`worker/migrations.generated.ts` is gitignored — never commit it).
- CRM columns: `is_automated_sender` integer `{mode:'boolean'}` nullable; `ai_enhancement_manual` integer `{mode:'boolean'}` notNull default false. camelCase TS ↔ snake_case SQL per schema.ts convention.
- Apply-contacts accepts optional top-level `automated: boolean` (ignore non-boolean); when present set `isAutomatedSender` and push `'automated-flag'` into `applied`; EVERY apply sets `aiEnhancementManual: false`. Pending contact items gain `manual: boolean`.
- `POST /api/contacts/:id/request-enhancement`: 404 unknown/deleted contact, 400 when `latestEmailMaterial` is null, else set `{aiEnhancementStatus:'pending', aiEnhancementManual:true, aiEnhancementUpdatedAt, updatedAt}` and return `{contact}`.
- Enricher: address-gate list exactly `["no-reply","noreply","do-not-reply","donotreply","mailer-daemon","postmaster","bounce","newsletter","notification","notify","marketing"]`, prefix-matched against the lowercased local part of `from`. `manual: true` bypasses BOTH gates. Retirement = apply with `automated: Some(true)` + empty insights (dry-run: log only). LLM classification always forwarded as `automated: Some(bool)` when present.
- Sequential loop replaces `buffered`; live line printed per outcome; end summary prints counts header. `RunSummary::render()` output format unchanged (existing tests must pass untouched).
- `candidate_urls`: registrable-domain triple first (via `psl::domain_str`), then original triple, deduped; unchanged when registrable == input or PSL returns none. Existing fetch/e2e tests must pass unchanged.
- Both repos: suites + typecheck/clippy/fmt clean at every commit. Conventional commits. eldrin-crm suite currently 22 enhancement tests / ~201 total; enricher 45 unit + 2 e2e.
- Bash cwd persists — use `git -C <abs path>`. Never commit the parent repo except the final gitlink/doc commit. Secrets never committed or echoed.

---

### Task 1 (CRM): Migration + schema columns

**Files:**
- Create: `eldrin-crm/migrations/20260711120000-automated-sender-flag.sql`
- Modify: `eldrin-crm/worker/db/schema.ts` (contacts table, after `aiEnhancementUpdatedAt` at ~line 42)
- Branch setup: `git -C eldrin-crm checkout main && git -C eldrin-crm checkout -b feature/enricher-automated-sender`

**Interfaces:**
- Produces: `contacts.isAutomatedSender: boolean|null`, `contacts.aiEnhancementManual: boolean` for Tasks 2-3.

- [ ] **Step 1: Create branch, write the migration**

```sql
-- Automated-sender flag + manual enhancement-request marker (enricher v1.1).
ALTER TABLE contacts ADD COLUMN is_automated_sender INTEGER;
ALTER TABLE contacts ADD COLUMN ai_enhancement_manual INTEGER NOT NULL DEFAULT 0;
```

- [ ] **Step 2: Add schema.ts columns** (contacts table, next to the other AI columns)

```ts
isAutomatedSender: integer('is_automated_sender', { mode: 'boolean' }),
aiEnhancementManual: integer('ai_enhancement_manual', { mode: 'boolean' })
  .notNull()
  .default(false),
```

- [ ] **Step 3: Regenerate migrations, run suite + typecheck**

Run: `cd eldrin-crm && npm run generate:migrations && npm run test && npm run typecheck`
Expected: all existing tests pass (createTestDb executes real migration files, so a broken migration fails loudly).

- [ ] **Step 4: Commit**

`git -C eldrin-crm add migrations/20260711120000-automated-sender-flag.sql worker/db/schema.ts && git -C eldrin-crm commit -m "feat(enhancement): automated-sender flag and manual-request columns"`

---

### Task 2 (CRM): Enhancement endpoint changes (pending `manual`, apply `automated`)

**Files:**
- Modify: `eldrin-crm/worker/routes/enhancement.ts` (apply-contacts handler ~120-174; pending handler ~193-235)
- Test: `eldrin-crm/worker/__tests__/enhancement-routes.test.ts` (TDD: add failing tests first)

**Interfaces:**
- Consumes: Task 1 columns.
- Produces (wire): pending contact items gain `manual: boolean`; apply-contacts body accepts `automated?: boolean`; `applied` gains `'automated-flag'` when automated present; every apply clears `aiEnhancementManual`.

- [ ] **Step 1: Write failing tests** (in the existing apply-contacts and pending describe blocks; follow the file's seed helpers)

```ts
it('records the automated flag and retires the contact', async () => {
  const id = await seedContactRow(db, { aiEnhancementStatus: 'pending' });
  const res = await app.request(`/api/enhancement/contacts/${id}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ messageId: 'm1', insights: {}, automated: true, source: 't' }),
  });
  expect(res.status).toBe(200);
  const body = await res.json();
  expect(body.applied).toContain('automated-flag');
  expect(body.contact.isAutomatedSender).toBe(true);
  expect(body.contact.aiEnhancementStatus).toBe('enhanced');
  expect(body.contact.aiEnhancementManual).toBe(false);
});

it('clears the manual marker on every apply and ignores non-boolean automated', async () => {
  const id = await seedContactRow(db, { aiEnhancementStatus: 'pending', aiEnhancementManual: true });
  const res = await app.request(`/api/enhancement/contacts/${id}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ messageId: 'm1', insights: { jobTitle: 'CTO' }, automated: 'yes', source: 't' }),
  });
  const body = await res.json();
  expect(body.contact.aiEnhancementManual).toBe(false);
  expect(body.contact.isAutomatedSender).toBeNull();
  expect(body.applied).not.toContain('automated-flag');
});

it('pending contact items expose the manual marker', async () => {
  await seedContactRow(db, { aiEnhancementStatus: 'pending', aiEnhancementManual: true });
  const res = await app.request('/api/enhancement/pending?type=contact');
  const body = await res.json();
  expect(body.items[0].manual).toBe(true);
});
```

(Adapt `seedContactRow` to accept the new optional fields if it doesn't already.)

- [ ] **Step 2: Run tests — expect the three new tests FAIL** (`npx vitest run worker/__tests__/enhancement-routes.test.ts`)

- [ ] **Step 3: Implement.** In apply-contacts, after body parse:

```ts
const automated = typeof body.automated === 'boolean' ? body.automated : null;
```

and in the `updates` block:

```ts
const updates: Record<string, unknown> = {
  aiEnhancementStatus: 'enhanced',
  aiEnhancementUpdatedAt: now(),
  aiEnhancementManual: false,
  updatedAt: now(),
};
if (automated !== null) {
  updates.isAutomatedSender = automated;
  applied.push('automated-flag');
}
```

(Note `applied` must be mutable/computed before this point; keep the existing `signature-fields` logic intact.) Extend the handler's body type with `automated?: unknown`. In the pending handler's contact loop add `manual: contact.aiEnhancementManual === true` to the pushed item.

- [ ] **Step 4: Run tests — all pass; run full suite + typecheck** (`npm run test && npm run typecheck`)

- [ ] **Step 5: Commit** — `feat(enhancement): manual marker in pending payload, automated flag on apply`

---

### Task 3 (CRM): Contact re-arm endpoint + api helper

**Files:**
- Modify: `eldrin-crm/worker/routes/contacts.ts` (next to the existing `GET /:id/enhancement-material` at ~297), `eldrin-crm/src/api.ts` (mirror `requestCompanyEnhancement` at ~340)
- Test: Create `eldrin-crm/worker/__tests__/contacts-request-enhancement.test.ts` (mirror `companies-request-enhancement.test.ts` structure)

**Interfaces:**
- Produces: `POST /api/contacts/:id/request-enhancement` → `{contact}` (arms pending + manual); `requestContactEnhancement(base, headers, id)` helper for Task 4.

- [ ] **Step 1: Write failing tests** — three cases: 404 unknown contact; 400 when no email material; 200 arms `{aiEnhancementStatus:'pending', aiEnhancementManual:true}` for a contact seeded with an email activity (copy the activity-seeding pattern from `enhancement-routes.test.ts`'s pending-contacts tests).

- [ ] **Step 2: Verify RED**, then implement:

```ts
// POST /api/contacts/:id/request-enhancement — arm a manual AI-enhancement pass.
// Mirrors companies.ts request-enhancement; 400 without email material because
// the enricher would have nothing to process.
contactsRoutes.post('/api/contacts/:id/request-enhancement', async (c) => {
  const db = c.get('db');
  const id = c.req.param('id');
  const [existing] = await db
    .select()
    .from(contacts)
    .where(and(eq(contacts.id, id), eq(contacts.isDeleted, false)));
  if (!existing) return c.json({ error: 'Contact not found' }, 404);

  const material = await latestEmailMaterial(db, id);
  if (!material) {
    return c.json({ error: 'No captured email material to enhance from' }, 400);
  }

  await db
    .update(contacts)
    .set({
      aiEnhancementStatus: 'pending',
      aiEnhancementManual: true,
      aiEnhancementUpdatedAt: now(),
      updatedAt: now(),
    })
    .where(eq(contacts.id, id));
  const [contact] = await db.select().from(contacts).where(eq(contacts.id, id));
  return c.json({ contact });
});
```

(import `latestEmailMaterial` from `./enhancement`). api.ts helper mirrors `requestCompanyEnhancement` verbatim with the contacts path.

- [ ] **Step 3: GREEN + full suite + typecheck**, **Step 4: Commit** — `feat(contacts): manual enhancement re-arm endpoint`

---

### Task 4 (CRM): ContactDetail re-arm wiring

**Files:**
- Modify: `eldrin-crm/src/pages/contacts/ContactDetail.tsx` (`handleEnhanceNow` ~168-188, button ~263-266)

Follow `CompanyDetail.tsx`'s pattern (handleEnhanceNow 127-157, button 214-226): (1) `handleEnhanceNow` calls the new `requestContactEnhancement` FIRST (arming pending + manual — surface a 400 "no material" as the existing error-toast pattern does), then keeps the current workflow-trigger logic (`getEnhancementMaterial` + run "CRM: Extract email insights") gated on `workflowsApp.isAvailable`; (2) the button becomes always-visible like CompanyDetail's, labelled "Enhance now" / "Re-enhance" by `aiEnhancementStatus`, no longer gated on `status === 'pending'` (keep the `Wand2` icon and disabled/busy state conventions of the file).

- [ ] **Step 1: Implement per the anchors above** (read both files first; reuse existing state/toast idioms — no new patterns)
- [ ] **Step 2: `npm run test && npm run typecheck`** (UI has no unit tests here; typecheck is the gate)
- [ ] **Step 3: Commit** — `feat(contacts): Enhance-now re-arms manual AI enhancement`

---

### Task 5 (enricher): Sequential runner + live per-record output

**Files:**
- Modify: `eldrin-enricher/src/report.rs`, `eldrin-enricher/src/runner.rs`, `eldrin-enricher/src/main.rs`

**Interfaces:**
- `report::outcome_line(outcome: &Outcome) -> String` (the existing per-outcome line, extracted; `render()` now maps over it — byte-identical output, existing tests unchanged)
- `RunSummary::render_header(&self) -> String` (the existing header line, extracted; used by main at end of run)
- `runner::run` drops `buffered`, processes items in a plain `for` loop, and calls `println!("{}", report::outcome_line(&outcome))` after each record completes (also in dry-run).
- main.rs: after `run` returns, print `summary.render_header()` instead of `summary.render()` (lines already streamed live).

- [ ] **Step 1: TDD on report refactor** — add tests: `outcome_line` returns the exact existing line strings (reuse the `sample()` fixtures); `render()` still equals header + joined lines (existing tests must pass unchanged). RED on missing fn, then implement extraction.
- [ ] **Step 2: Rewire runner** — replace the stream with:

```rust
let mut outcomes = Vec::with_capacity(items.len());
for item in items {
    let outcome = match item {
        PendingItem::Company(company) => enrich_company(&company, &deps, dry_run).await,
        PendingItem::Contact(contact) => enrich_contact(&contact, &deps, dry_run).await,
    };
    println!("{}", crate::report::outcome_line(&outcome));
    outcomes.push(outcome);
}
```

Remove the now-unused `futures` imports from runner (crate keeps the dependency only if still used elsewhere — if nothing else uses `futures`, remove it from Cargo.toml). e2e counts assertions unchanged.
- [ ] **Step 3: Full checks** (`cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test`), **Step 4: Commit** — `feat: sequential processing with live per-record output`

---

### Task 6 (enricher): Registrable-domain-first candidates

**Files:**
- Modify: `eldrin-enricher/Cargo.toml` (add `psl = "2"`), `eldrin-enricher/src/fetch.rs`

**Interfaces:**
- `candidate_urls` behavior per Global Constraints; new pure helper `registrable_domain(domain: &str) -> Option<String>` (strip port before PSL lookup, re-attach nothing — registrable host only).

- [ ] **Step 1: Failing tests**

```rust
#[test]
fn subdomain_tries_registrable_domain_first_then_original() {
    assert_eq!(
        candidate_urls("em1.cloudflare.com"),
        vec![
            "https://cloudflare.com", "https://www.cloudflare.com", "http://cloudflare.com",
            "https://em1.cloudflare.com", "https://www.em1.cloudflare.com", "http://em1.cloudflare.com",
        ]
    );
}

#[test]
fn multi_label_suffix_respected() {
    // Naive last-two-labels would wrongly yield "co.uk".
    assert_eq!(candidate_urls("mail.acme.co.uk")[0], "https://acme.co.uk");
}

#[test]
fn registrable_domain_equals_input_keeps_original_triple() {
    assert_eq!(
        candidate_urls("acme.com"),
        vec!["https://acme.com", "https://www.acme.com", "http://acme.com"]
    );
}

#[test]
fn non_psl_hosts_fall_back_to_original_triple() {
    assert_eq!(candidate_urls("127.0.0.1:8080")[0], "https://127.0.0.1:8080");
    assert_eq!(candidate_urls("127.0.0.1:8080").len(), 3);
}
```

- [ ] **Step 2: RED, then implement** — `registrable_domain` uses `psl::domain_str(host_without_port)`; `candidate_urls` builds `[registrable-triple if Some && != bare] + [original triple]`, deduped preserving order (a small `Vec::contains` filter is fine at n=6). All existing fetch + e2e tests must pass unchanged.
- [ ] **Step 3: Full checks**, **Step 4: Commit** — `feat: fetch registrable main domain before email subdomains`

---

### Task 7 (enricher): Automated-sender gates + manual override + apply flag

**Files:**
- Modify: `eldrin-enricher/src/eldrin.rs` (PendingContact + apply body/signature), `eldrin-enricher/src/enrich/contact.rs` (gates, schema, prompt), `eldrin-enricher/src/enrich/company.rs` + `eldrin-enricher/tests/e2e_run.rs` (only if the apply_contact signature change ripples — company is untouched functionally)

**Interfaces:**
- `PendingContact` gains `#[serde(default)] pub manual: bool`.
- `EldrinClient::apply_contact(&self, id: &str, message_id: &str, insights: &ContactInsights, automated: Option<bool>) -> Result<Vec<String>, EldrinError>` — `automated` serialized top-level, skipped when None.
- `contact.rs`: `pub fn is_automated_address(from: &str) -> bool` (lowercased local part, prefix match against the constant list); LLM extraction deserialized into `ContactExtraction { #[serde(flatten)] insights: ContactInsights, automated: Option<bool> }`; schema + prompt extended with the `automated` boolean ("true when the email is a bulk, marketing, notification, or otherwise automated message rather than a personal message written by an individual").
- Pipeline flow: material gate (unchanged) → if `!manual && is_automated_address(from)` → retire (apply `automated=Some(true)`, empty insights; dry-run: `WouldApply` with `{messageId, automated: true, insights: {}}`, no POST) → LLM extract → if `!manual && extraction.automated == Some(true)` → retire the same way → else apply insights with `automated: extraction.automated`.

- [ ] **Step 1: Failing tests** (contact.rs test module; follow existing harness):
  - `no_reply_address_is_retired_without_llm_call` — from `no-reply@acme.com`, only the apply endpoint is hit (mock asserts `body_partial_json({"automated": true, "insights": {}})`, `.expect(1)`); NO `/v1/chat/completions` request; outcome `Enhanced{applied:["automated-flag"]}`.
  - `llm_classified_automated_is_retired` — personal-looking address, mock LLM returns `{"automated": true, "jobTitle": "x"}` → apply body has `automated: true` and empty insights (jobTitle discarded).
  - `manual_bypasses_gates` — `manual: true` + `no-reply@` from + LLM returns `{"jobTitle":"CTO","automated":true}` → apply body carries `insights.jobTitle: "CTO"` AND `automated: true`.
  - `dry_run_retirement_posts_nothing` — no-reply address + dry_run → `WouldApply` payload `{messageId, automated: true, insights: {}}`, zero requests.
  - `is_automated_address` unit cases (matches `newsletter@`, `bounces@` via `bounce` prefix; does NOT match `jane@`, `info@`).
  - eldrin.rs test update: `apply_contact` test asserts `automated` absent from JSON when None (existing test updated for the new signature).
- [ ] **Step 2: RED, then implement** per the interfaces above. The retire path posts via `apply_contact(id, message_id, &ContactInsights::default(), Some(true))`.
- [ ] **Step 3: Full checks** (all suites; e2e untouched contacts have `manual` absent → default false), **Step 4: Commit** — `feat: retire automated senders with CRM flag, manual override bypass`

---

### Task 8: Finalize (suites, pushes, parent wiring, live verification)

- [ ] **Step 1:** Full verification both repos: enricher `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`; CRM `npm run test && npm run typecheck` on the feature branch.
- [ ] **Step 2:** Push enricher `main`; watch CI to green.
- [ ] **Step 3:** CRM: browser-verify the ContactDetail button against the running preview (arm → pending badge → button label flips), THEN (user approval already given for the feature; merge follows the repo's merge-to-main convention) `git -C eldrin-crm checkout main && git merge --no-ff feature/enricher-automated-sender && git push`.
- [ ] **Step 4:** Parent repo: stage `eldrin-crm` + `eldrin-enricher` gitlinks + the two new docs, one commit (`feat: enricher v1.1 — automated-sender handling across crm + enricher`), push (user pre-approved parent pushes this session).
- [ ] **Step 5:** Live smoke with the real stack: `cargo run --release -- run --dry-run --limit 5` — expect live per-record lines; if a no-reply contact is pending, expect the retirement dry-run line. Report output.
