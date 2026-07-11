# Enricher v1.4 Implementation Plan (two-stage enhancement)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `docs/superpowers/specs/2026-07-11-enricher-two-stage-design.md` — `final: false` applies fill fields without consuming the pending flag; workflow templates become non-final.

## Global Constraints

- eldrin-crm on branch `feature/enricher-two-stage` from `main` (@ 56dad5a). eldrin-workflows: check out `main` first (currently detached HEAD), branch `feature/non-final-enrichment` — template-only change.
- `final` parsing: `body.final === false` → non-final; anything else (absent, true, non-boolean) → final. Applies to BOTH apply endpoints.
- Non-final apply MUST: apply the existing fill-empty field logic and `updatedAt`. MUST NOT: set status, bump `aiEnhancementUpdatedAt`, reset attempts/error, clear `aiEnhancementManual`, bump `captureConfidence`, or process `automated`. Response shape unchanged.
- Suites/typecheck clean at every commit; conventional commits; `git -C` always; no pushes until finalize.

---

### Task 1 (CRM): `final` flag on both apply endpoints

**Files:** Modify `eldrin-crm/worker/routes/enhancement.ts`; test `eldrin-crm/worker/__tests__/enhancement-routes.test.ts`.

**TDD scenarios (RED first):**
1. Company apply `final:false` with data: fields applied (fill-empty), response `applied` lists them, but row keeps `aiEnhancementStatus='pending'`, attempts/error untouched (seed attempts=1 + error to prove), `aiEnhancementUpdatedAt` unchanged (seed an old explicit value).
2. Contact apply `final:false` with insights + seeded `aiEnhancementManual=true`: signature fields applied, manual STILL true, status still `'pending'`.
3. Contact apply `final:false` with `automated:true`: `isAutomatedSender` NOT set, no `'automated-flag'` in applied.
4. `final:"nope"` (non-boolean) behaves exactly like final (status → enhanced).
5. Existing final-apply tests unchanged.

- [ ] RED → implement (both handlers branch on `const isFinal = body.final !== false;` and build their update sets accordingly) → GREEN
- [ ] `npm run test && npm run typecheck`
- [ ] Commit: `feat(enhancement): non-final applies preserve the pending flag for the AI pass`

### Task 2 (workflows): templates non-final

**Files:** Modify `eldrin-workflows/workflows-templates/crm-enrich-company.json` (+`"final": false` in the call_app_api body, next to `source`) and `crm-extract-email-insights.json` (same).

- [ ] Edit both JSONs; validate with `python3 -m json.tool`; run the workflows suite if one exists touching templates (`cd eldrin-workflows && npx vitest run` — report result either way)
- [ ] Commit: `feat(templates): CRM enrichment applies are non-final (AI pass follows)`

### Task 3: Finalize (orchestrator)

- [ ] CRM: merge → main, push. Workflows: merge → main, push.
- [ ] Update the two imported workflow definitions in the LOCAL dev workflows D1 in place (definition JSON rows) so the running instance uses `final: false`; restart/verify the workflows app if needed.
- [ ] Rebuild CRM preview on main.
- [ ] Parent: gitlinks + docs commit `feat: enricher v1.4 — two-stage enhancement (fast workflow pass + final AI pass)`, push.
- [ ] Live verify: re-arm LIH-like record via UI button (or DB) → workflow fast pass runs → record STILL pending → enricher run performs the AI pass → enhanced. Report the sequence.
