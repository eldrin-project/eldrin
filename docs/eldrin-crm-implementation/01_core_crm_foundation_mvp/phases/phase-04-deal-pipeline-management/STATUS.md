# Phase 4: Deal & Pipeline Management

## Status: complete
## Started: 2026-02-16
## Completed: 2026-02-16

## Progress:
- [x] Step 4.1: Create database migration for deals and pipelines
- [x] Step 4.2: Add Drizzle schema for deal and pipeline tables
- [x] Step 4.3: Create pipeline configuration routes
- [x] Step 4.4: Create deal CRUD routes
- [x] Step 4.5: Implement stage progression service
- [x] Step 4.6: Implement Kanban data endpoint
- [x] Step 4.7: Implement weighted pipeline calculation
- [x] Step 4.8: Implement deal rotting detection
- [x] Step 4.9: Build Kanban board page
- [x] Step 4.10: Build deal list page
- [x] Step 4.11: Build deal detail page
- [x] Step 4.12: Build pipeline settings page
- [x] Step 4.13: Build close-out dialog

## Notes:
- Reconciled 2026-07-02: this file previously read `not_started`, but the module is fully implemented in code (and the SP1 roll-up already listed it complete). Verified live in the shell — Deals kanban renders with seeded deals, weighted pipeline value, per-stage totals, and board/list toggle.
- Migration: `migrations/20260216200000-deals.sql`
- Backend: `worker/routes/deals.ts` (CRUD, `/api/deals/kanban`, `/api/deals/:id/history`, `/api/deals/:id/close`, deal-contact roles) + `worker/routes/pipelines.ts` (pipeline + stage config, stage reorder)
- Service: `worker/services/deal-stage.ts` (stage progression / probability)
- Frontend: `src/pages/deals/` — DealKanban (drag-and-drop via @hello-pangea/dnd), DealList, DealDetail, DealForm; close-out dialog with required reason codes
- Weighted pipeline value = Σ(deal value × stage probability); deal rotting shown as a visual cue past the stage threshold
- Deferred per spec: deal cloning (REQ-1.3.09, Could)
