# Phase 1: Create Shared daisyUI Theme

## Status: complete
## Started: 2026-02-12
## Completed: 2026-02-12

## Progress:
- [x] Step 1.1: Audit shell CSS variables
- [x] Step 1.2: Create shared theme file
- [x] Step 1.3: Theme sync utility
- [ ] Manual validation (deferred to Phase 2 — requires daisyUI install + build)

## Notes:

### Architecture Decision: Scoped Themes

Named themes `"eldrin"` (light) and `"eldrin-dark"` (dark) instead of `"light"`/`"dark"`.

**Why**: The shell's `@theme inline` block registers `--color-primary`, `--color-secondary`,
and `--color-accent` on `:root`. daisyUI also uses these variable names. If daisyUI themes
were named "light"/"dark" and applied via `data-theme` on `<html>`, the daisyUI values
would override the shell's shadcn/ui tokens page-wide, breaking the shell's UI.

By scoping to `[data-theme="eldrin"]` on the extension app's wrapper `<div>`, CSS variable
cascade means daisyUI variables only apply inside the app — the shell remains unaffected.

### Theme Sync Pattern

Extension apps sync with the shell's dark mode via MutationObserver on `<html data-theme>`:
- Shell sets `data-theme="dark"` → app sets `data-theme="eldrin-dark"` on wrapper
- Shell sets `data-theme="light"` → app sets `data-theme="eldrin"` on wrapper

See `shared/theme-sync.ts` for the framework-agnostic utility.

### Color Mapping (Shell → daisyUI)

| daisyUI Token | Light Value | Dark Value | Shell Source |
|---|---|---|---|
| base-100 | #FFFFFF | #1C1917 | --color-bg-surface |
| base-200 | #F5F5F4 | #292524 | --color-bg-sunken / elevated |
| base-300 | #E7E5E4 | #44403C | --color-border-default |
| base-content | #1C1917 | #FAFAF9 | --color-text-primary |
| primary | #2563EB | #3B82F6 | --color-action-primary |
| secondary | #F5F5F4 | #292524 | --color-action-secondary |
| info | #06B6D4 | #06B6D4 | --color-status-info |
| success | #16A34A | #22C55E | --color-status-success |
| warning | #EAB308 | #EAB308 | --color-status-warning |
| error | #DC2626 | #EF4444 | --color-status-error |

### Files Created
- `shared/eldrin-daisyui-theme.css` — daisyUI plugin config + both theme definitions
- `shared/theme-sync.ts` — MutationObserver utility for dark mode sync
