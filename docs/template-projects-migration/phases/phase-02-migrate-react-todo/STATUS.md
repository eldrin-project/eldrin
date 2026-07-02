# Phase 2: Migrate react-todo to daisyUI 5

## Status: complete
## Started: 2026-02-12
## Completed: 2026-02-12

## Progress:
- [x] Step 2.1: Swap dependencies (added daisyui@5, removed 10 Radix/shadcn deps, -52 packages)
- [x] Step 2.2: Delete shadcn artifacts (12 ui/ components, lib/utils.ts, components.json)
- [x] Step 2.3: Update CSS entry (inlined daisyUI theme — @plugin resolves from CSS file location)
- [x] Step 2.4: Replace component usage (7 files rewritten to daisyUI classes)
- [x] Step 2.5: Verify build (`npm run build` passes — SSR + client bundles)
- [ ] Manual visual validation (pending: run dev server, test all CRUD, dark mode)

## Notes:
- `@import "../../shared/eldrin-daisyui-theme.css"` doesn't work — Tailwind @plugin directive
  resolves packages relative to the CSS file's directory, not the app's node_modules.
  Fix: inline theme in each app's index.css. shared/ file remains as canonical reference.
- Sonner toasts kept (CSS-only, portals to body) — theme prop synced via MutationObserver.
- tw-animate-css animations (fade-in, slide-in) removed — daisyUI has no equivalent entrance animations.
- cn() utility (clsx + tailwind-merge) removed — replaced with template literal ternaries.

## Files modified:
- `package.json` — +daisyui, -@radix-ui/*, -cva, -clsx, -next-themes, -tailwind-merge, -tw-animate-css
- `src/index.css` — full daisyUI theme inline (light + dark, 28 tokens each)
- `src/root.component.tsx` — theme sync + daisyUI tabs + direct Sonner import
- `src/components/TodoForm.tsx` — native elements + daisyUI classes
- `src/components/TodoItem.tsx` — native checkbox + daisyUI classes
- `src/components/FilterBar.tsx` — join button group + native select
- `src/components/TodoList.tsx` — daisyUI card/skeleton
- `src/components/CategoryList.tsx` — daisyUI classes

## Files deleted:
- `src/components/ui/` (12 files: badge, button, card, checkbox, input, select, skeleton, sonner, tabs, textarea, toggle, toggle-group)
- `src/lib/utils.ts`
- `components.json`
