# Enricher v1.2 Implementation Plan (failure backoff: 3 attempts, 7 days apart)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `docs/superpowers/specs/2026-07-11-enricher-failure-backoff-design.md` — failed records get a 7-day cooldown per attempt and park as `'failed'` after the 3rd attempt; re-arm resets everything; the enricher reports failures best-effort.

**Architecture:** CRM first (migration → failure endpoints + cooldown filter + resets), then enricher (client failure method + runner wiring). Meeting point: `POST /api/enhancement/{companies,contacts}/:id/failure`.

**Tech Stack:** unchanged (Hono/Drizzle/Vitest; Rust/wiremock).

## Global Constraints

- eldrin-crm on branch `feature/enricher-failure-backoff` from current `main` (@ bfe0713). Migration timestamp > `20260711120000`; run `npm run generate:migrations`; never commit `migrations.generated.ts`.
- Columns on BOTH contacts and companies: `ai_enhancement_attempts` integer notNull default 0; `ai_enhancement_error` text nullable. TS names `aiEnhancementAttempts`, `aiEnhancementError`.
- `ENHANCEMENT_RETRY_COOLDOWN_MS = 7 * 24 * 60 * 60 * 1000`, defined once in `worker/routes/enhancement.ts`, exported.
- Failure endpoints: service-secret gated like siblings; 404 unknown/deleted; body `{reason?, source?}` (reason cleaned/capped 500 via the file's `cleanString`); attempts += 1; error stored; timestamps bumped; incremented attempts >= 3 → status `'failed'`, else status forced to `'pending'` (idempotent for already-pending). Response `{<record>, attempts, status}`.
- Pending pull (both types): `status='pending' AND (attempts = 0 OR aiEnhancementUpdatedAt <= now() - ENHANCEMENT_RETRY_COOLDOWN_MS)`.
- Resets: both apply endpoints set `aiEnhancementAttempts: 0, aiEnhancementError: null`; both request-enhancement endpoints (companies.ts + contacts.ts) set the same plus status `'pending'` — including from `'failed'`.
- Enricher: `EldrinClient::report_failure(&self, record: &RecordRef, reason: &str) -> Result<(), EldrinError>` posting to `/api/enhancement/{companies|contacts}/:id/failure` with `{reason, source: SOURCE}` (kind → path segment: "company"→companies, "contact"→contacts). Runner calls it after printing a `Failed` outcome line, only when NOT dry-run; errors logged `tracing::warn!`, never fail the run.
- Suites green at every commit (CRM 207 + new; enricher 61 unit + 2 e2e + new). fmt/clippy/typecheck clean. Conventional commits. `git -C` always; parent repo untouched until final wiring.

---

### Task 1 (CRM): Migration + schema + failure endpoints + cooldown + resets

(One task: the columns, endpoints, filter, and resets form one reviewable unit — a reviewer cannot meaningfully approve the filter without the columns.)

**Files:**
- Create: `eldrin-crm/migrations/20260711150000-enhancement-failure-backoff.sql`
- Modify: `eldrin-crm/worker/db/schema.ts` (contacts ~line 43, companies ~line 132), `eldrin-crm/worker/routes/enhancement.ts` (failure endpoints + pending filter + apply resets + exported constant), `eldrin-crm/worker/routes/companies.ts` + `eldrin-crm/worker/routes/contacts.ts` (request-enhancement resets)
- Test: `eldrin-crm/worker/__tests__/enhancement-routes.test.ts` (+ the contacts/companies request-enhancement test files for reset coverage)

**Migration:**

```sql
-- Failure backoff for AI enhancement (enricher v1.2): attempt counter +
-- last-error, on both contacts and companies.
ALTER TABLE contacts ADD COLUMN ai_enhancement_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE contacts ADD COLUMN ai_enhancement_error TEXT;
ALTER TABLE companies ADD COLUMN ai_enhancement_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE companies ADD COLUMN ai_enhancement_error TEXT;
```

**TDD scenarios (write failing first; use the file's authenticated helpers and seed helpers, extending them for the new columns):**

1. `POST /api/enhancement/companies/:id/failure` with `{reason:"fetch: HTTP status 403", source:"t"}` on an attempts=0 pending company → 200 `{attempts:1, status:'pending'}`; row has error stored, `aiEnhancementUpdatedAt` bumped.
2. Third failure parks: seed attempts=2 pending → failure → `{attempts:3, status:'failed'}`; row status `'failed'`.
3. Contact failure endpoint mirrors (one happy-path test).
4. Cooldown filter: seed company A pending attempts=1 `aiEnhancementUpdatedAt = now()` (fresh failure) and company B pending attempts=1 `aiEnhancementUpdatedAt = now() - 8 days`; pending pull returns only B. A third company with attempts=0 always returned.
5. `failed` never pulled: seed status `'failed'` → pending pull excludes it regardless of age.
6. Apply resets: seed company attempts=2 + error, apply enrichment → row `attempts=0`, `aiEnhancementError` null.
7. Re-arm resets from failed: seed company status `'failed'` attempts=3 + error → `POST /api/companies/:id/request-enhancement` → status `'pending'`, attempts 0, error null. Same for the contact re-arm (contact needs email material seeded — reuse existing pattern).
8. Failure endpoint 404s on unknown id; missing body/reason tolerated (attempts still increment, error null).

**Implementation sketch (enhancement.ts):**

```ts
export const ENHANCEMENT_RETRY_COOLDOWN_MS = 7 * 24 * 60 * 60 * 1000;

function failureUpdates(existing: { aiEnhancementAttempts: number }, reason: string | null) {
  const attempts = (existing.aiEnhancementAttempts ?? 0) + 1;
  return {
    attempts,
    updates: {
      aiEnhancementAttempts: attempts,
      aiEnhancementError: reason,
      aiEnhancementStatus: attempts >= 3 ? 'failed' : 'pending',
      aiEnhancementUpdatedAt: now(),
      updatedAt: now(),
    },
  };
}
```

Two thin handlers (companies/contacts) share it; pending pull adds the cooldown predicate with drizzle `or(eq(...attempts, 0), lte(...aiEnhancementUpdatedAt, now() - ENHANCEMENT_RETRY_COOLDOWN_MS))` combined with the existing status/isDeleted conditions; apply handlers add `aiEnhancementAttempts: 0, aiEnhancementError: null` to their update sets; both request-enhancement handlers add the same trio (status/attempts/error).

- [ ] Branch `feature/enricher-failure-backoff` from main; migration + schema + `generate:migrations`
- [ ] Failing tests (RED) → implement → GREEN
- [ ] `npm run test && npm run typecheck` clean
- [ ] Commit: `feat(enhancement): failure backoff — 3 attempts, 7-day cooldown, failed state`

---

### Task 2 (enricher): report_failure client + runner wiring

**Files:**
- Modify: `eldrin-enricher/src/eldrin.rs` (new method + tests), `eldrin-enricher/src/runner.rs` (wiring), `eldrin-enricher/tests/e2e_run.rs` (failure-report mock for the e2e's failing companies — the e2e currently has 0 failed; leave counts as-is, add mocks only if a scenario needs them)

**Interfaces:**
- `EldrinClient::report_failure(&self, kind: &str, id: &str, reason: &str) -> Result<(), EldrinError>` — kind is `"company"` or `"contact"` (the `RecordRef.kind` values), mapped to the plural path segment; body `{"reason": reason, "source": "eldrin-enricher"}`; 2xx → Ok.
- Runner loop, after `println!` of the outcome line: if NOT dry_run and outcome is `Failed{record, reason}` → `if let Err(err) = eldrin.report_failure(record.kind, &record.id, reason).await { tracing::warn!("failure report for {} {} not recorded: {err}", record.kind, record.id); }`.

**TDD:**
- eldrin.rs: `report_failure` posts the contract body to `/api/app/eldrin-crm/api/enhancement/companies/co1/failure` with the secret header (wiremock `.expect(1)`, `body_partial_json({"reason":"fetch: HTTP status 403","source":"eldrin-enricher"})`); contact path variant; non-2xx surfaces `EldrinError::Api`.
- runner (e2e): extend `tests/e2e_run.rs` with a second scenario or extend `start_stack` — add one pending company with an unreachable domain (e.g. `nosuchhost.invalid`), mount `POST .../companies/<id>/failure` with `.expect(1)`; assert counts gain 1 failed and the mock is satisfied. Also assert dry-run posts NO failure (existing dry-run coverage pattern; a `.expect(0)` mock in a dry-run test or assert via received_requests).

- [ ] Failing tests (RED) → implement → GREEN
- [ ] `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test` clean
- [ ] Commit: `feat: report enrichment failures for CRM backoff tracking`

---

### Task 3: Finalize

- [ ] Full suites both repos; push enricher main; watch CI green
- [ ] CRM: merge `feature/enricher-failure-backoff` → main (`--no-ff`), push
- [ ] Parent: stage both gitlinks + the two docs, commit `feat: enricher v1.2 — failure backoff (3 attempts, 7-day cooldown)`, push (pre-approved)
- [ ] Live verify against the real stack: run `cargo run --release -- run --type company --limit 5` TWICE. First run: the 4 known-bad domains fail and get reported (attempts 1). Second run: they are NOT pulled (cooldown); fresh records (if any) fill the limit. Report both outputs.
