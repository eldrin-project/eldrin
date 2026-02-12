# Phase 3: Migrate angular-todo to daisyUI 5

## Overview

Same pattern as Phase 2, Angular-specific.

## Dependencies

Phase 2 (react-todo as reference).

## Steps

### 3.1 Swap dependencies
- Add: `daisyui@5`
- Remove: `@spartan-ng/brain`, `@spartan-ng/helm`, `class-variance-authority`, `tw-animate-css`

### 3.2 Delete Spartan UI artifacts
- `src/app/components/ui/` (25+ files)
- Remove CDK overlay CSS

### 3.3 Update CSS entry
- `src/styles.css` — import daisyUI + shared eldrin theme

### 3.4 Replace component usage
Replace `hlmBtn`, `HlmCheckbox`, etc. directives → plain `class="btn"`, `class="checkbox"`.

### 3.5 Verify build + dev

## Test Gate

```bash
cd angular-todo && npm run build && npm run dev
```

## Finalize

- [ ] Manual validation: all CRUD operations, filters, toasts, empty states
- [ ] Visual comparison with react-todo — should look identical
- [ ] Commit: `feat: migrate angular-todo to daisyUI 5`
