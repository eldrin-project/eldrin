# Enricher v1.3 — Refill to requested count (Design)

**Date:** 2026-07-11
**Status:** Approved (user, in-session)
**Extends:** the v1.0–v1.2 enricher specs
**Repo:** `eldrin-enricher` only (no CRM changes)

## Requirement (user)

`run --limit 5` with 3 failures should fetch 3 more, and if 1 of those fails,
1 more — the run should end with as many *successful* enrichments as requested
(or with the server exhausted).

## Decisions

| # | Decision | Choice |
|---|----------|--------|
| D1 | Target semantics | `--limit N` (default `run.limit`) = target number of SUCCESSFUL outcomes. Success = `Enhanced` (including automated-sender retirement) or, in dry-run, `WouldApply`. `Skipped` and `Failed` do not count and trigger refill. |
| D2 | Refill loop | Process in rounds. Each round: pull `min(target - successes + seen_still_pending, 100)` records, filter out already-seen IDs, process sequentially (live lines as before). Stop when successes ≥ target OR a pull yields zero unseen items (server exhausted / only unprocessable heads). |
| D3 | Why seen-set + growing window | Failed records cool down server-side and drop out of `pending` on the next pull, but skipped records (no-domain, no-material) and all dry-run records stay `pending` and would be re-pulled forever. The seen-set breaks the cycle; growing the pull window by the number of seen-but-still-pending records lets fresh items surface behind them (bounded by the server's limit cap of 100). |
| D4 | Known bound | If more than 100 unprocessable records sit at the head of the pending list, refill cannot see past them (server cap). Acceptable; noted in --limit help. |

## Out of scope

CRM changes; parallelism changes; per-type success quotas for `--type all`
(the target counts successes across both types combined).
