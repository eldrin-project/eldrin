# Feature 1: Dark Mode (Persistence + FOUC Prevention)

## Overview

The dark mode infrastructure is already built: CSS variables with light/dark themes in `src/index.css`, `data-theme` attribute switching, a toggle button in TopBar using Sun/Moon icons, and a Zustand store (`shellStore.ts`) with `toggleTheme()`. The only gap: theme resets on reload because there's no persistence or OS preference detection.

## Dependencies

None.

## Steps

### 1.1 Add FOUC prevention script to `index.html`

Add an inline `<script>` before `<div id="root">` that reads the theme from localStorage (or detects OS preference) and sets `data-theme` on `<html>` before React hydrates. This prevents a flash of the wrong theme on page load.

```html
<script>
  (function() {
    var s = localStorage.getItem('eldrin-theme');
    var p = window.matchMedia('(prefers-color-scheme: dark)').matches;
    var t = s || (p ? 'dark' : 'light');
    document.documentElement.setAttribute('data-theme', t);
  })();
</script>
```

### 1.2 Update `src/stores/shellStore.ts` with persistence

- Initialize `theme` from `localStorage.getItem('eldrin-theme')` or OS `prefers-color-scheme`
- On `toggleTheme()` / `setTheme()`: save to `localStorage` + set `data-theme` attribute
- Sync `data-theme` on initialization (in case inline script and React disagree)

## Test Gate

```bash
cd eldrin-core && npx tsc -b && npx vitest run
```

1. Toggle dark mode → persists after page reload
2. Clear localStorage → follows OS preference
3. No flash of wrong theme on load (FOUC prevention)
4. Existing unit tests still pass

## Files Modified

| File | Change |
|------|--------|
| `eldrin-core/index.html` | Add inline FOUC prevention script |
| `eldrin-core/src/stores/shellStore.ts` | Add localStorage persistence + OS detection |
