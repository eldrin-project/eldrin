# Phase 4: Migrate vue-todo to daisyUI 5

## Overview

Same pattern as Phase 2, Vue-specific.

## Dependencies

Phase 2 (react-todo as reference).

## Steps

### 4.1 Swap dependencies
- Add: `daisyui@5`
- Remove: `class-variance-authority`, `tw-animate-css`

### 4.2 Remove custom shadcn-style components (if any)

### 4.3 Update CSS entry
- `src/index.css` — import daisyUI + shared eldrin theme

### 4.4 Replace component usage
Replace component imports → daisyUI classes in `<template>` blocks.

### 4.5 Verify build + dev

## Test Gate

```bash
cd vue-todo && npm run build && npm run dev
```

## Finalize

- [ ] Manual validation: all CRUD operations, filters, toasts, empty states
- [ ] Visual comparison with react-todo — should look identical
- [ ] Commit: `feat: migrate vue-todo to daisyUI 5`
