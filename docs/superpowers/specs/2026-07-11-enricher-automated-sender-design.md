# Enricher v1.1 — Sequential runs, main-domain fetch, automated-sender handling (Design)

**Date:** 2026-07-11
**Status:** Approved (user, in-session)
**Extends:** `2026-07-11-eldrin-enricher-design.md`
**Repos touched:** `eldrin-enricher` (main) + `eldrin-crm` (feature branch → main)

## Requirements (user)

1. Runs feel slow and opaque → process records **strictly sequentially** and emit a
   **live log line per record the moment it completes** (dry-run logs the would-apply
   payload). Note: applies were already immediate per record; the change is ordering +
   live visibility.
2. Captured company domains are often email-sending subdomains (`em1.cloudflare.com`)
   → fetch the **registrable main domain** (`cloudflare.com`) first.
3. Automated/marketing senders (`no-reply@...`) should be **skipped**, and:
   - **retired** so they stop being re-pulled (empty apply flips `aiEnhancementStatus`
     to `'enhanced'`),
   - **flagged** persistently in the CRM as automated senders,
   - a **manual enhancement request overrides** the automated decision: the record is
     processed fully and its extracted insights applied.

## Decisions

| # | Decision | Choice |
|---|----------|--------|
| D1 | Concurrency | Sequential loop replaces `buffered(fetch.concurrency)`; config key stays (unused by `run`) for the future `serve` mode. LLM semaphore unchanged. |
| D2 | Live output | `report::outcome_line(&Outcome)` printed to stdout as each record completes; end-of-run prints the counts header. `render()` (header + lines) unchanged for tests. |
| D3 | Main domain | `psl` crate (compiled Public Suffix List, offline). Candidates: registrable-domain triple (`https://`, `https://www.`, `http://`) first, then the original subdomain triple as fallback, deduped. Domains where registrable == input (or PSL has no answer, e.g. `127.0.0.1:port`) keep the existing triple — all current tests unaffected. |
| D4 | Automated detection | Two gates in the contact pipeline: (a) **address gate** — `from` local-part prefix-matches a conservative list (`no-reply`, `noreply`, `do-not-reply`, `donotreply`, `mailer-daemon`, `postmaster`, `bounce`, `newsletter`, `notification`, `notify`, `marketing`) → no LLM call; (b) **content gate** — `automated: boolean` field added to the extraction schema/prompt (same LLM call, no extra cost). |
| D5 | Retirement | Gated contacts are retired via `POST /api/enhancement/contacts/:id` with `automated: true` and empty insights → server sets the flag, marks `enhanced`, record stops re-pulling. Dry-run logs the payload and POSTs nothing. |
| D6 | CRM flag | New contacts columns: `is_automated_sender` (boolean, nullable = unknown) and `ai_enhancement_manual` (boolean, not null default false). Apply endpoint accepts optional top-level `automated: boolean` → sets `isAutomatedSender`, pushes `'automated-flag'` into `applied`; every apply clears `aiEnhancementManual` back to false. |
| D7 | Manual override | New `POST /api/contacts/:id/request-enhancement` (mirrors the company endpoint; 400 when the contact has no email material) sets `aiEnhancementStatus='pending'` + `aiEnhancementManual=true`. The pending payload exposes `manual: boolean` on contact items. The enricher **bypasses both gates** when `manual` is true: extracts and applies insights regardless, still reporting the LLM's `automated` classification so the flag stays honest. |
| D8 | UI | ContactDetail's "Enhance now" button re-arms via the new endpoint first (making the manual override reachable), then keeps its existing workflow trigger when the workflows app is available; button follows CompanyDetail's always-visible "Enhance now"/"Re-enhance" pattern. |

## Out of scope

Filtering automated senders at CRM auto-capture time (contacts are still created);
surfacing `isAutomatedSender` in list views/filters; company-side manual flag.
