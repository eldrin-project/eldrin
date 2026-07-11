# Enricher v1.3 Implementation Plan (refill to requested count)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `docs/superpowers/specs/2026-07-11-enricher-refill-design.md` — the run loops, refilling from `/pending`, until it has `--limit` successful outcomes or the server yields nothing new.

**Tech Stack:** unchanged. Repo: `eldrin-enricher` only, on `main` (@ 6e024cf; 65 unit + 3 e2e green).

## Global Constraints

- Success = `Outcome::Enhanced` or `Outcome::WouldApply`. Skips/failures refill.
- Round pull size: `min(remaining + seen_pending, 100)` where `remaining = target - successes` and `seen_pending` = seen IDs that are presumably still pending (skipped, or any record in dry-run). Simplest sound over-approximation: `seen.len()` — failed-and-cooled records inflate the window harmlessly (they just don't come back). Use `seen.len()`.
- Termination: successes >= target, OR a round's pull contains zero unseen items. No other exit; no unbounded loops (each round either grows `seen` or terminates).
- Seen-set keys: the record id (String). Company and contact ids are UUIDs — no collision concern across types.
- Live per-record output, sequential processing, failure reporting (non-dry-run) all unchanged per record.
- `--limit` help updated: `Target number of successful enrichments per run (refills after failures; the server serves at most 100 records per pull).`
- fmt/clippy(-D warnings)/test clean at every commit. Conventional commits. `git -C` always; do NOT push (orchestrator finalizes).

---

### Task 1: Refill loop in `runner.rs` + e2e proof

**Files:**
- Modify: `eldrin-enricher/src/runner.rs` (the loop), `eldrin-enricher/src/main.rs` (help text)
- Test: `eldrin-enricher/tests/e2e_run.rs`

**Interfaces (consumed, all existing):** `EldrinClient::pull_pending(Option<&str>, u32, u32)`, `enrich_company`, `enrich_contact`, `report_failure`, `outcome_line`, `RunSummary`.

**Implementation sketch (replaces the single pull + loop in `run`):**

```rust
let mut outcomes = Vec::new();
let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
let target = options.limit as usize;
let mut successes = 0usize;

while successes < target {
    let window = (target - successes + seen.len()).min(100) as u32;
    let page = eldrin
        .pull_pending(options.record_type.as_query_param(), window, 0)
        .await
        .map_err(|err| RunError::Client(err.to_string()))?;
    let fresh: Vec<PendingItem> = page
        .into_iter()
        .filter(|item| {
            let id = match item {
                PendingItem::Company(c) => &c.id,
                PendingItem::Contact(c) => &c.id,
            };
            !seen.contains(id.as_str())
        })
        .collect();
    if fresh.is_empty() {
        tracing::info!("no more unseen pending records; stopping at {successes}/{target}");
        break;
    }
    for item in fresh {
        // insert into seen, process (existing match + println + failure report),
        // count Enhanced/WouldApply as success, push outcome,
        // and break the inner loop early once successes == target.
    }
}
```

(Keep the existing per-record body verbatim: match → outcome → `println!(outcome_line)` → non-dry-run Failed → `report_failure` warn-only → push. Increment `successes` on `Enhanced | WouldApply`. Break the inner loop when `successes == target` so a refill round doesn't overshoot.)

**TDD — e2e scenarios (RED first), in `tests/e2e_run.rs`:**

1. `refill_reaches_target_after_failures`: stack with 3 pending companies — co_bad1, co_bad2 (unreachable domains, each gets a `/failure` mock `.expect(1)`) and co_good (web mock + apply `.expect(1)`). BUT the pending mock must be stateful to prove refill: first pull (limit=1) returns [co_bad1]; second pull returns [co_bad1?—no: cooled] — simplest faithful simulation: use wiremock `Mock::given(...).and(query_param("limit","1")).up_to_n_times(1)` chains OR a single responder closure that returns a shrinking list based on request count. Recommended: a `Respond` closure over an `Arc<Mutex<Vec<...>>>`-free design is overkill — instead mount THREE mocks with `.up_to_n_times(1)` in mount order (wiremock matches most-recently-mounted first? NO — wiremock matches in mount order, first match wins, and `up_to_n_times` exhausts): pull#1 → `[co_bad1, co_good_hidden?]`... KEEP IT SIMPLE AND DETERMINISTIC: run with `--limit`=target 2, pending responder closure keyed on a request counter via `wiremock::Request` inspection is not available — so use the documented pattern: `ResponseTemplate` per call is not dynamic; therefore model the SERVER's real behavior statically: pull window formula gives: round 1: window=2 → respond [bad1, bad2] (mock A, `up_to_n_times(1)`); round 2 (successes 0, seen 2): window=4 → respond [good] (mock B, matches remaining traffic). Assert: counts = 1 enhanced 2 failed, failure mocks satisfied, apply `.expect(1)` satisfied, and at least 2 pending pulls occurred (received_requests count on the pending path >= 2).
   - Note for the implementer: verify wiremock's matching semantics (`up_to_n_times` + mount order) with a quick doc check; if order is unreliable, discriminate the rounds by `query_param("limit","2")` vs `query_param("limit","4")` — the window formula makes round limits distinct and deterministic (2 then 4). Prefer the query-param discrimination: it also pins the window formula.
2. `refill_stops_when_no_unseen`: pending always returns the same single no-domain company `[co_nodomain]` (skip outcome, stays pending). Target 3. Assert: run terminates (doesn't hang), counts = 1 skipped 0 enhanced, and exactly 2 pending pulls happened (round 1 processes it; round 2 sees only seen → stops). Use `.expect(2)` on the pending mock.
3. Existing e2e tests updated only where the pull now uses the window formula (first-round window == old limit when seen is empty — `query_param("limit","25")` assertions still hold for target 25; the full_run test's counts must stay the same, though it MAY now issue a second pull returning the already-seen items → make the pending mock tolerant: drop any `.expect(1)` on pending or set `.expect(1..)`; verify each apply/failure mock still `.expect(1)`).

- [ ] RED (new tests fail against single-pull runner) → implement → GREEN
- [ ] `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test`
- [ ] Commit: `feat: refill pulls until the requested number of successful enrichments`

---

### Task 2: Finalize (orchestrator)

- [ ] Push enricher main; CI green
- [ ] Parent: docs + gitlink commit `feat: enricher v1.3 — refill to requested count`, push
- [ ] Live verify: with fresh pending companies available, `run --type company --limit 3` — if any fail, observe extra pull rounds and a final `3 enhanced` (or exhaustion message). Report output.
