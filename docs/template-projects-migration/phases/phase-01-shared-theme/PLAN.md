# Phase 1: Create Shared daisyUI Theme

## Overview

Create a daisyUI theme CSS file that maps to the shell's `:root` CSS variables, ensuring extension apps visually match the shell.

## Dependencies

Phase 0 (clean baseline).

## Steps

### 1.1 Audit shell CSS variables

Read `eldrin-core/src/index.css` to catalog all `--color-*`, `--radius-*`, `--spacing-*` vars.

### 1.2 Create shared theme file

Create `shared/eldrin-daisyui-theme.css` mapping daisyUI tokens to shell CSS vars.

### 1.3 Test in isolation

Minimal HTML page importing daisyUI + theme CSS to verify color match.

## Test Gate

- Visual comparison: daisyUI components render with shell colors
- Dark mode toggle switches correctly

## Finalize

- [ ] Manual validation: verify theme colors match shell in light + dark mode
- [ ] Commit: `feat: add shared daisyUI theme mapping for extension apps`
