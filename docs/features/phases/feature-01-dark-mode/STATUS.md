# Feature 1: Dark Mode

## Status: complete
## Started: 2026-02-10
## Completed: 2026-02-10

## Progress:
- [x] Step 1.1: Add FOUC prevention script to index.html
- [x] Step 1.2: Update shellStore.ts with localStorage persistence + OS detection
- [x] Verification: tsc -b ✓, 318/318 tests pass ✓

## Notes:
- FOUC script placed before `<div id="root">` — runs synchronously before first paint
- OS preference listener only active when no explicit user choice in localStorage
- `setTheme()` after OS change removes localStorage key to keep "system" mode
