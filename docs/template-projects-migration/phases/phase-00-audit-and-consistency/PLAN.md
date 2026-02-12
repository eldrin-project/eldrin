# Phase 0: Audit & Fix Single-spa Consistency

## Overview

Fix structural inconsistencies across all 4 extension todo apps before changing UI libraries. Ensures a clean baseline for the daisyUI migration.

## Dependencies

None.

## Steps

### 0.1 Rename Angular entry point

Angular uses `main.single-spa.ts`, others use `eldrin-{fw}-todo.{ext}`. Rename to `eldrin-angular-todo.ts` and update `angular.json` build target.

Files:
- `angular-todo/src/main.single-spa.ts` → `angular-todo/src/eldrin-angular-todo.ts`
- `angular-todo/angular.json` — update entry point reference

### 0.2 Document lifecycle combination patterns

React/Angular use explicit `combineLifecycles()`. Vue/Svelte handle it internally. Add clarifying comments in each entry point explaining why.

Files:
- `react-todo/src/eldrin-react-todo.tsx`
- `angular-todo/src/eldrin-angular-todo.ts`
- `vue-todo/src/eldrin-vue-todo.ts`
- `svelte-todo/src/eldrin-svelte-todo.ts`

### 0.3 Fix Svelte bugs

- `TodoForm.svelte` — hardcoded `amber-500` priority color → use dynamic PRIORITY_CONFIG
- `TodoList.svelte` — add missing error status codes (400, 429) to `getErrorMessage()`
- `TodoList.svelte` — fix collapse behavior to match other apps

### 0.4 Align dependency versions

- Tailwind CSS → align all to latest 4.x
- TypeScript → align all to latest 5.9.x
- single-spa-vue → bump 3.0.0 → 3.0.1

### 0.5 Error handling parity

Ensure all 4 apps handle: 400, 401, 403, 404, 409, 429, 500.

## Test Gate

```bash
cd react-todo && npm run build
cd angular-todo && npm run build
cd vue-todo && npm run build
cd svelte-todo && npm run build
```

## Finalize

- [ ] Manual validation: run all 4 apps, verify single-spa mounting, check entry points
- [ ] Commit: `chore: fix single-spa consistency across extension apps`
