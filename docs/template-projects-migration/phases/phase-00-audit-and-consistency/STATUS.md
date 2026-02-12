# Phase 0: Audit & Fix Single-spa Consistency

## Status: awaiting_validation
## Started: 2026-02-11
## Completed: -

## Progress:
- [x] Step 0.1: Rename Angular entry point (`main.single-spa.ts` → `eldrin-angular-todo.ts`)
- [x] Step 0.2: Document lifecycle combination patterns (Vue/Svelte entry points)
- [x] Step 0.3: Fix Svelte bugs (priority color, error codes, collapse)
- [x] Step 0.4: Align dependency versions (Tailwind 4.1.18, TypeScript 5.9.3, single-spa-vue 3.0.1)
- [x] Step 0.5: Error handling parity across all 4 apps
- [ ] Manual validation + commit

## Build Verification:
- [x] react-todo: `npm run build` ✓
- [x] vue-todo: `npm run build` ✓
- [x] svelte-todo: `npm run build` ✓
- [ ] angular-todo: pre-existing build failure (peer dep resolution in eldrin-app-angular, not caused by our changes)

## Notes:
- Angular build failure is a pre-existing issue with `@eldrin-project/eldrin-app-angular` peer dependency resolution — unrelated to Phase 0 changes
- single-spa 6.0.3 is already the latest version — no upgrade needed
- single-spa-svelte 3.0.0-beta.0 is the only Svelte 5 option (stable 2.1.1 is Svelte 4 only)
