# Phase 5: Migrate svelte-todo to daisyUI 5

## Overview

Same pattern as Phase 2, Svelte-specific.

## Dependencies

Phase 2 (react-todo as reference).

## Steps

### 5.1 Swap dependencies
- Add: `daisyui@5`
- Remove: `bits-ui`, `tailwind-variants`, `tw-animate-css`

### 5.2 Delete bits-ui artifacts
- `src/lib/components/ui/`

### 5.3 Update CSS entry
- `src/routes/layout.css` — import daisyUI + shared eldrin theme

### 5.4 Replace component usage
Replace component imports → daisyUI classes in `.svelte` files.

### 5.5 Verify build + dev

## Test Gate

```bash
cd svelte-todo && npm run build && npm run dev
```

## Finalize

- [ ] Manual validation: all CRUD operations, filters, toasts, empty states
- [ ] Visual comparison with react-todo — should look identical
- [ ] Commit: `feat: migrate svelte-todo to daisyUI 5`
