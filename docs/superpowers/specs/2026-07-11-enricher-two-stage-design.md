# Enricher v1.4 — Two-stage enhancement: fast workflow pass + final AI pass (Design)

**Date:** 2026-07-11
**Status:** Approved (user, in-session)
**Extends:** the v1.0–v1.3 enricher specs + `2026-07-03-ai-enhancement-workflows-design.md`
**Repos:** `eldrin-crm` + `eldrin-workflows` (template JSONs); enricher unchanged

## Problem

The Enhance-now buttons arm a record `pending` and immediately run the CRM
enrichment workflow. The workflow's apply marks the record `enhanced`, consuming
the pending flag seconds before the local AI enricher can pull it — the two
consumers race and the (weaker, og-tags-only) workflow always wins.

## Requirement (user)

Keep the button-triggered workflow as a FAST first pass, but leave the AI
(local enricher) as a SECOND step — the workflow must not consume the record.

## Decisions

| # | Decision | Choice |
|---|----------|--------|
| D1 | Mechanism | Optional `final: boolean` (default `true`) on both apply endpoints (`/api/enhancement/companies/:id`, `/api/enhancement/contacts/:id`). Non-boolean → treated as `true` (backward compatible; the enricher and any unaware caller stay final). |
| D2 | Non-final apply semantics | Applies fill-empty field updates + `updatedAt` ONLY. Does NOT set `aiEnhancementStatus='enhanced'`, does NOT bump `aiEnhancementUpdatedAt` (cooldown clock untouched), does NOT reset `aiEnhancementAttempts`/`aiEnhancementError`, does NOT clear `aiEnhancementManual` (manual override must survive to the AI pass), does NOT bump `captureConfidence`, and ignores the `automated` flag (final-pass concern). Response unchanged shape (`{record, applied}`). |
| D3 | Which callers are non-final | The two CRM workflow templates (`crm-enrich-company.json`, `crm-extract-email-insights.json`) add `"final": false` to their call_app_api bodies — for BOTH companies and contacts (the same race exists on ContactDetail). `crm-detect-deal-signals` untouched (different endpoint, no status semantics). |
| D4 | Resulting flow | Button click → arm pending → workflow fast pass fills og-derived fields instantly, record stays `pending` → next local enricher run does the AI pass → final apply marks `enhanced` (and fill-empty means the AI pass only adds what the fast pass could not). |
| D5 | Dev deployment | Template JSON edits do not update already-imported workflow definitions; the local dev workflows D1 is updated in place (definition JSON row) as part of finalize. |

## Out of scope

Enricher changes (its applies default to final); UI changes; a "stage" audit
trail beyond the existing `source` strings.
