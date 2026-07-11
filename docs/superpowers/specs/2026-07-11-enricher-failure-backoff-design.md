# Enricher v1.2 — Failure backoff (3 attempts, 7 days apart) (Design)

**Date:** 2026-07-11
**Status:** Approved (user, in-session)
**Extends:** `2026-07-11-eldrin-enricher-design.md`, `2026-07-11-enricher-automated-sender-design.md`
**Repos:** `eldrin-crm` (feature branch → main) + `eldrin-enricher` (main)

## Problem

Failed records (dead domains, 403s, LLM errors) stay `pending` forever and are
re-pulled by every run, crowding out fresh work within `--limit` (user observed
4 of 5 slots consumed by the same permanent failures on consecutive runs).

## Requirement (user)

Mark failures so the next call skips them — but allow retries: **3 attempts
spaced 7 days apart**, then the record is parked until manually re-armed.

## Decisions

| # | Decision | Choice |
|---|----------|--------|
| D1 | State store | CRM-side (visible, durable, machine-independent). New columns on BOTH `contacts` and `companies`: `ai_enhancement_attempts` integer notNull default 0, `ai_enhancement_error` text nullable (last failure reason, capped 500). |
| D2 | Failure report | New service-secret-gated endpoints `POST /api/enhancement/companies/:id/failure` and `POST /api/enhancement/contacts/:id/failure`, body `{reason?, source?}`. Effect: `attempts += 1`, `aiEnhancementError = reason`, `aiEnhancementUpdatedAt = now`, `updatedAt = now`. When the incremented attempts ≥ 3 → `aiEnhancementStatus = 'failed'` (terminal until re-armed); else status stays `'pending'` (cooldown governs re-pull). Response `{contact|company, attempts, status}`. |
| D3 | Cooldown | Pending pull filters per type: `status = 'pending' AND (attempts = 0 OR aiEnhancementUpdatedAt <= now() - 7d)`. Constant `ENHANCEMENT_RETRY_COOLDOWN_MS = 7 * 24 * 60 * 60 * 1000` in the CRM (single definition, exported for tests). |
| D4 | Reset semantics | Successful apply (both types) resets `attempts = 0`, clears `aiEnhancementError`. Re-arm endpoints (`/api/companies/:id/request-enhancement`, `/api/contacts/:id/request-enhancement`) reset `attempts = 0`, clear the error, set status `'pending'` — a manual re-arm overrides both the cooldown and the terminal `failed` state (consistent with v1.1's manual-override philosophy). |
| D5 | Enricher reporting | On a `Failed` outcome in a real run, the enricher POSTs the failure (reason string = the outcome reason, e.g. `fetch: HTTP status 403`) best-effort: a failed failure-report is logged (warn) and never aborts the run. Dry-run reports nothing. |
| D6 | Status vocabulary | `ai_enhancement_status` gains `'failed'` as a fourth value (null \| pending \| enhanced \| failed). The pull endpoint never returns `failed` records. |

## Out of scope

UI surfacing of `failed`/attempts/error (the existing Enhance-now/Re-enhance
buttons already re-arm and thus un-park records); per-reason backoff tuning;
enricher-side retry flag (re-arm is the retry path).
