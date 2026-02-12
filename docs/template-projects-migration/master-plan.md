# Template Projects Migration — Extension App Standardization

## Context

The 4 extension app templates (react-todo, angular-todo, vue-todo, svelte-todo) serve as reference implementations that become scaffolded templates in `eldrin-templates`. Two problems need solving:

1. **Single-spa integration inconsistencies** — Different entry point naming, lifecycle patterns, error handling gaps, and a beta dependency (single-spa-svelte) across the 4 apps
2. **UI library divergence** — Each app uses a different component library (shadcn/ui, Spartan UI, custom, bits-ui) despite sharing Tailwind CSS 4, creating visual inconsistency and 4x maintenance burden

**Decision**: Migrate all extension apps to **daisyUI 5** (CSS-only Tailwind plugin, 63 components, 34KB, zero JS). The shell (eldrin-core) stays on shadcn/ui — visual consistency via CSS variable theme mapping.

## Implementation Order

```
Phase 0 → 1 → 2 → 3 → 4 → 5 → 6 → 7
```

## Docs Structure

```
docs/template-projects-migration/
├── master-plan.md          ← this plan (copy from plan file when approved)
├── HOW_TO.md
└── phases/
    ├── phase-00-audit-and-consistency/    PLAN.md, STATUS.md
    ├── phase-01-shared-theme/            PLAN.md, STATUS.md
    ├── phase-02-migrate-react-todo/      PLAN.md, STATUS.md
    ├── phase-03-migrate-angular-todo/    PLAN.md, STATUS.md
    ├── phase-04-migrate-vue-todo/        PLAN.md, STATUS.md
    ├── phase-05-migrate-svelte-todo/     PLAN.md, STATUS.md
    ├── phase-06-update-eldrin-templates/ PLAN.md, STATUS.md
    └── phase-07-add-svelte-template/    PLAN.md, STATUS.md
```

---

## Phase 0: Audit & Fix Single-spa Consistency

**Goal**: Fix structural inconsistencies across all 4 todo apps before changing UI libraries. Ensures a clean baseline.

### Current single-spa versions (all latest)

| Package | In Project | Latest Stable | Action |
|---------|-----------|---------------|--------|
| single-spa | ^6.0.3 | 6.0.3 | None |
| single-spa-react | ^6.0.2 | 6.0.2 | None |
| single-spa-angular | ^9.2.0 | 9.2.0 | None |
| single-spa-vue | ^3.0.0 | 3.0.1 | Bump to 3.0.1 |
| single-spa-svelte | ^3.0.0-beta.0 | 3.0.0-beta.0 (beta) | Keep beta (only Svelte 5 option) |

### Inconsistencies to fix

**0.1 Entry point naming** — Angular uses `main.single-spa.ts`, others use `eldrin-{fw}-todo.{ext}`. Standardize Angular to `eldrin-angular-todo.ts` and update `angular.json` build target.

**0.2 Lifecycle combination pattern** — React/Angular use explicit `combineLifecycles()` from their `eldrin-app-*` adapters. Vue/Svelte skip this. Document the expected pattern per framework — this is intentional (Vue/Svelte adapters handle it internally), but should be documented in each entry point with a comment explaining why.

**0.3 Svelte bugs**:
- Hardcoded `amber-500` priority color in `TodoForm.svelte` → use dynamic PRIORITY_CONFIG like other apps
- Missing error status codes (400, 429) in `getErrorMessage()` → add to match React/Angular/Vue
- Collapse button behavior differs (context-dependent vs always-collapsible) → align with other apps

**0.4 Version alignment**:
- Tailwind CSS: 4.1.12 (Angular) vs 4.1.17-4.1.18 (others) → align to latest 4.x
- TypeScript: 5.8.3 (React/Vue) vs 5.9.2-5.9.3 (Angular/Svelte) → align to latest 5.9.x
- single-spa-vue: bump 3.0.0 → 3.0.1

**0.5 Error handling parity** — Ensure all 4 apps handle identical HTTP status codes: 400, 401, 403, 404, 409, 429, 500.

### Files modified
- `angular-todo/src/main.single-spa.ts` → rename to `eldrin-angular-todo.ts`
- `angular-todo/angular.json` — update entry point reference
- `svelte-todo/src/components/TodoForm.svelte` — fix hardcoded color
- `svelte-todo/src/components/TodoList.svelte` — add missing error codes, fix collapse
- `vue-todo/package.json` — bump single-spa-vue
- All 4 `package.json` — align Tailwind + TypeScript versions

### Test gate
```bash
# Each app must build and dev-serve without errors
cd react-todo && npm run build && npm run dev
cd angular-todo && npm run build && npm run dev
cd vue-todo && npm run build && npm run dev
cd svelte-todo && npm run build && npm run dev
```

### Finalize
- [ ] Manual validation: run all 4 apps, verify single-spa mounting works, check entry points
- [ ] Commit: `chore: fix single-spa consistency across extension apps`
- [ ] Update `STATUS.md` → complete, create `DONE.md`

---

## Phase 1: Create Shared daisyUI Theme

**Goal**: Create a daisyUI theme CSS file that maps to the shell's `:root` CSS variables, ensuring extension apps visually match the shell.

### Steps

**1.1** Audit the shell's CSS variables — read `eldrin-core/src/index.css` to catalog all `--color-*`, `--radius-*`, `--spacing-*` vars exposed on `:root`.

**1.2** Create `shared/eldrin-daisyui-theme.css` — maps daisyUI theme tokens to shell CSS vars:
```css
@plugin "daisyui" {
  themes: eldrin --default,
  themes: eldrin-dark
}

@plugin "daisyui/theme" {
  name: "eldrin";
  color-scheme: light;
  --color-primary: oklch(from var(--color-action-primary) l c h);
  --color-base-100: var(--color-bg-surface);
  --color-base-content: var(--color-text-primary);
  /* ... full mapping */
}
```

**1.3** Test theme in isolation — create a minimal HTML page importing daisyUI + theme CSS to verify colors match the shell.

### Files created
- `shared/eldrin-daisyui-theme.css`

### Test gate
- Visual comparison: daisyUI components render with shell colors
- Dark mode toggle switches correctly

### Finalize
- [ ] Manual validation: open test page, verify theme colors match shell in light + dark mode
- [ ] Commit: `feat: add shared daisyUI theme mapping for extension apps`
- [ ] Update `STATUS.md` → complete, create `DONE.md`

---

## Phase 2: Migrate react-todo

**Goal**: Reference implementation — first app migrated to daisyUI 5. Sets the pattern for phases 3-5.

### Steps

**2.1** Swap dependencies:
- Add: `daisyui@5`
- Remove: `@radix-ui/*`, `class-variance-authority`, `tw-animate-css`

**2.2** Delete: `src/components/ui/` (entire shadcn directory), `src/lib/utils.ts` (cn() helper)

**2.3** Update `src/index.css` — import daisyUI plugin + shared eldrin theme

**2.4** Replace component usage in all component files:
- `<Button variant="default">` → `<button className="btn btn-primary">`
- `<Checkbox>` → `<input type="checkbox" className="checkbox">`
- `<Select>` → `<select className="select">`
- `<Card>` → `<div className="card">`
- `<Badge>` → `<span className="badge">`
- `<Tabs>` → `<div role="tablist" className="tabs tabs-bordered">`
- Keep Sonner toasts (CSS-only, framework-agnostic)

**2.5** Verify: `npm run build && npm run dev` — visual match with shell

### Files modified
- `react-todo/package.json`
- `react-todo/src/index.css`
- `react-todo/src/components/TodoList.tsx`
- `react-todo/src/components/TodoForm.tsx`
- `react-todo/src/components/TodoItem.tsx`
- `react-todo/src/components/FilterBar.tsx`
- `react-todo/src/components/CategoryList.tsx`
- `react-todo/src/root.component.tsx`

### Files deleted
- `react-todo/src/components/ui/*` (14+ files)
- `react-todo/src/lib/utils.ts`

### Finalize
- [ ] Manual validation: `npm run dev`, verify all CRUD operations, filters, toasts, empty states
- [ ] Visual comparison with shell — colors, spacing, dark mode
- [ ] Commit: `feat: migrate react-todo to daisyUI 5`
- [ ] Update `STATUS.md` → complete, create `DONE.md`

---

## Phase 3: Migrate angular-todo

Same pattern as Phase 2, Angular-specific:

- Remove: `@spartan-ng/brain`, `@spartan-ng/helm`, `class-variance-authority`, `tw-animate-css`, CDK overlay CSS
- Delete: `src/app/components/ui/` (25+ Spartan files)
- Replace `hlmBtn`, `HlmCheckbox`, etc. directives → plain `class="btn"`, `class="checkbox"`
- Update `src/styles.css` with daisyUI + theme

### Finalize
- [ ] Manual validation: `npm run dev`, verify all CRUD operations, filters, toasts, empty states
- [ ] Visual comparison with react-todo — should look identical
- [ ] Commit: `feat: migrate angular-todo to daisyUI 5`
- [ ] Update `STATUS.md` → complete, create `DONE.md`

---

## Phase 4: Migrate vue-todo

Same pattern as Phase 2, Vue-specific:

- Remove: `class-variance-authority`, `tw-animate-css`
- Remove any custom shadcn-style components
- Replace component imports → daisyUI classes in `<template>` blocks
- Update `src/index.css` with daisyUI + theme

### Finalize
- [ ] Manual validation: `npm run dev`, verify all CRUD operations, filters, toasts, empty states
- [ ] Visual comparison with react-todo — should look identical
- [ ] Commit: `feat: migrate vue-todo to daisyUI 5`
- [ ] Update `STATUS.md` → complete, create `DONE.md`

---

## Phase 5: Migrate svelte-todo

Same pattern as Phase 2, Svelte-specific:

- Remove: `bits-ui`, `tailwind-variants`, `tw-animate-css`
- Delete: `src/lib/components/ui/`
- Replace component imports → daisyUI classes in `.svelte` files
- Update `src/routes/layout.css` with daisyUI + theme

### Finalize
- [ ] Manual validation: `npm run dev`, verify all CRUD operations, filters, toasts, empty states
- [ ] Visual comparison with react-todo — should look identical
- [ ] Commit: `feat: migrate svelte-todo to daisyUI 5`
- [ ] Update `STATUS.md` → complete, create `DONE.md`

---

## Phase 6: Update eldrin-templates

**Goal**: Propagate the daisyUI changes to the template scaffolding in `eldrin-templates`.

### Steps

**6.1** Update template `package.json.template` files — swap deps to daisyUI
**6.2** Replace `src/components/ui/` in templates with daisyUI class usage
**6.3** Remove `components.json` (shadcn config) from templates
**6.4** Add shared daisyUI theme CSS to each template
**6.5** Test scaffolding: `npx create-eldrin-project test-app` → verify output

### Files modified
- `eldrin-templates/templates/cloudflare-react-sqlite/package.json.template`
- `eldrin-templates/templates/cloudflare-vue-sqlite/package.json.template`
- `eldrin-templates/templates/cloudflare-angular-sqlite/package.json.template`
- Component files in each template
- `components.json` — delete from templates

### Finalize
- [ ] Manual validation: scaffold a test project with each framework, verify it builds and runs
- [ ] Commit: `feat: update eldrin-templates to use daisyUI 5`
- [ ] Update `STATUS.md` → complete, create `DONE.md`

---

## Phase 7: Add Svelte Template to eldrin-templates

**Goal**: Now that all frameworks use identical daisyUI classes, add a Svelte template.

### Steps

**7.1** Create `eldrin-templates/templates/cloudflare-svelte-sqlite/` based on svelte-todo
**7.2** Update `eldrin-templates/src/prompts.ts` to enable Svelte option
**7.3** Test: scaffold Svelte project, verify it builds and runs

### Finalize
- [ ] Manual validation: scaffold Svelte project, verify build + dev + single-spa mounting
- [ ] Commit: `feat: add Svelte template to eldrin-templates`
- [ ] Update `STATUS.md` → complete, create `DONE.md`

---

## Verification (Cross-phase)

```bash
# Per app (after their phase)
cd {app} && npm install && npm run build && npm run dev

# Cross-app visual comparison
# Open all 4 todo apps side by side — identical look
# Same HTML classes in devtools (class="btn btn-primary")

# Dark mode
# data-theme="dark" on shell switches all apps

# Templates
cd eldrin-templates && npm run build
npx create-eldrin-project test-react    # scaffold React
npx create-eldrin-project test-vue      # scaffold Vue
# Compare generated code — UI classes should be identical
```
