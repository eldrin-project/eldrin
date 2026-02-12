# Phase 2: Migrate react-todo to daisyUI 5

## Overview

Reference implementation — first app migrated. Sets the pattern for phases 3-5.

## Dependencies

Phase 1 (shared theme).

## Steps

### 2.1 Swap dependencies
- Add: `daisyui@5`
- Remove: `@radix-ui/*`, `class-variance-authority`, `tw-animate-css`

### 2.2 Delete shadcn artifacts
- `src/components/ui/` (entire directory)
- `src/lib/utils.ts` (cn() helper)

### 2.3 Update CSS entry
- `src/index.css` — import daisyUI plugin + shared eldrin theme

### 2.4 Replace component usage
All component files: Button → `btn`, Checkbox → `checkbox`, Select → `select`, Card → `card`, Badge → `badge`, Tabs → `tabs tabs-bordered`. Keep Sonner toasts.

### 2.5 Verify build + dev

## Test Gate

```bash
cd react-todo && npm run build && npm run dev
```

## Finalize

- [ ] Manual validation: all CRUD operations, filters, toasts, empty states
- [ ] Visual comparison with shell — colors, spacing, dark mode
- [ ] Commit: `feat: migrate react-todo to daisyUI 5`
