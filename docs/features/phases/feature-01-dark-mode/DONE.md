# Feature 1: Dark Mode — DONE

## Completed: 2026-02-10

## What was done

### index.html — FOUC prevention script
- Added synchronous inline `<script>` before `<div id="root">`
- Reads `eldrin-theme` from localStorage, falls back to `prefers-color-scheme` media query
- Sets `data-theme` attribute on `<html>` before first paint

### src/stores/shellStore.ts — persistence + OS detection
- `getInitialTheme()` reads from localStorage → OS preference → defaults to 'light'
- `toggleTheme()` and `setTheme()` now persist to localStorage
- OS `prefers-color-scheme` change listener active only when no explicit user choice
- Storage key: `eldrin-theme`

## Verification
- `npx tsc -b` — passes
- `npx vitest run` — 318/318 tests pass
- Theme toggle persists across page reloads
- No flash of wrong theme (FOUC prevention)
- OS preference changes respected when no explicit choice

## Files changed
| File | Change |
|------|--------|
| `index.html` | Added inline FOUC prevention script |
| `src/stores/shellStore.ts` | Added localStorage persistence, OS preference detection, change listener |
