# eldrin-calendar UX Overhaul — Design (Slice 4a.1)

**Date:** 2026-07-09
**Status:** Approved (brainstormed + section-by-section user approval)
**Context:** Slice 4a shipped a functional calendar, but the month view is cramped: the shell caps apps at 1440px, the app adds its own padding and a fixed 224px sidebar, and the grid sizes to content instead of the viewport. Event entries are barely readable (FullCalendar dot style). Goal: use ALL available screen space and make the app look and feel polished ("perfect") — visual direction guided by the frontend-design skill within the Quiet Ledger system.

## 1. Decisions

- **U1 — Shell full-width flag** (user): new optional manifest field `ui.layout: "full-width"`. When the ACTIVE app declares it, eldrin-core's content wrapper (`Shell.tsx` `p-6 max-w-[1440px] mx-auto`) drops the max-width cap and outer padding for that app; all other apps render exactly as today (absent → `default`). Platform feature; calendar is the first adopter.
- **U2 — Collapsible sidebar** with mini month navigator (user): Google-Calendar-style panel, collapsible to zero via a toolbar hamburger; state persisted in localStorage.
- **U3 — Month events as colored block chips + "+N more" popover** (user): tinted-background chips replace dot events; overflow uses FullCalendar's day popover.
- **U4 — All four interaction upgrades** (user): event peek popover, "+ New event" button + empty-state hint, now indicator + business hours in week/day, keyboard shortcuts.
- **U5 — Custom app frame** (user): replace FullCalendar's built-in headerToolbar with one custom daisyUI toolbar row; app renders an edge-to-edge flex column filling the viewport below the shell topbar.

## 2. Scope

**In:** eldrin-core layout flag (+ manifest type + sync tolerance); eldrin-calendar frame/toolbar/sidebar/mini-nav rewrite; month/week/day/list visual redesign; peek popover; create button; empty-state hint; keyboard shortcuts; responsive drawer below `lg`.
**Out:** any backend/API change (none needed); marketplace/manifest schema versioning beyond the one optional field; mobile-first redesign (drawer fallback only); Google sync (4b).

## 3. eldrin-core: full-width layout flag

- Manifest: `ui.layout?: "default" | "full-width"` (optional, default `"default"`). Documented next to `ui.sideNav`.
- `Shell.tsx`: the active app's manifest is already available to the shell (appRegistry loads manifests). When the route's active app has `ui.layout === "full-width"`, the content wrapper renders `p-0 max-w-none` (no horizontal centering); otherwise the existing `p-6 max-w-[1440px] mx-auto` — the class set is chosen per active route/app, transitions cleanly on navigation.
- Non-app routes (core dashboard, settings) always use the default wrapper.
- Manifest validation/registration in core must tolerate (not strip) the new field; no DB column needed if the shell reads the loaded manifest at render time (preferred).
- Regression requirement: CRM and all other apps render byte-identically to today.

## 4. eldrin-calendar: app frame

```
Root (data-theme bridge, flex flex-col, height: calc(100dvh − var(--layout-topbar-height)), overflow-hidden)
├── Toolbar row (h-14, border-b, px-3):
│     [☰ sidebar toggle] [+ New event (btn-primary)]  [Today] [‹] [›]  {Month YYYY title}
│     ………………spacer………………  [Month | Week | Day | List]  (daisyUI join/segmented)
└── Body (flex-1 flex min-h-0)
      ├── Sidebar (w-[264px], collapsible → w-0, transition, border-r, overflow-y-auto)
      │     ├── MiniMonthNav (compact grid; ‹ › month paging; click day → main grid navigates;
      │     │    days in the main view's visible range highlighted; today = primary badge)
      │     ├── Calendar list (existing: color dot, visibility checkbox, hover actions
      │     │    rename/recolor/delete via inline popover; + New calendar form)
      │     └── (future 4b: connected accounts section)
      └── Grid area (flex-1 min-w-0) — FullCalendar height="100%", headerToolbar={false},
            view driven by toolbar state; datesSet keeps title + mini-nav in sync
```

- Sidebar collapsed state in `localStorage('eldrin-calendar:sidebar')`; default open on ≥lg, closed below. Below `lg` the sidebar renders as an overlay drawer (backdrop, closes on selection/Esc) instead of inline.
- The app manages NO page scroll; week/day views scroll internally (FullCalendar's own scroller), month never scrolls (rows flex to fit).
- Title format: "July 2026" (month), "Jul 13 – 19, 2026" (week), "Thursday, July 9, 2026" (day), "July 2026" (list) — from FullCalendar's `view.title`.

## 5. Visual design (frontend-design direction, Quiet Ledger)

**Month grid:**
- Event chips: `eventDisplay: 'block'`; chip = calendar color at ~16% via `color-mix(in oklab, <color> 16%, var(--color-base-100))` background, 3px solid left border in the full calendar color, text `var(--color-base-content)`, title weight 500, start time in tabular numerals at 70% opacity before the title. Radius 4px, 1px vertical gap. Hover: tint deepens to ~26%. No white-on-color text anywhere (theme-safe).
- All-day/multi-day events: solid spanning bar in the calendar color at ~28% tint with the same left accent; title once at span start.
- Day numbers: 0.8125rem, weight 500, top-right; **today** = filled `--color-primary` circle badge with primary-content number; adjacent-month days at 40% opacity; weekend columns tinted `color-mix(in oklab, var(--color-base-content) 3%, transparent)`.
- Weekday header row: `cal-eyebrow` treatment (uppercase, tracking, 0.6875rem, muted) — no heavy borders.
- `dayMaxEvents: true` (auto-fit per row height); "+N more" link styled as a quiet `link-hover` in primary; FullCalendar's `.fc-popover` restyled to a daisyUI card (border-base-300, shadow-sm, base-100 bg).
- Grid lines: hairline `--color-base-300` at 60% — lighter than stock.

**Week/day:**
- `nowIndicator: true` — line + arrow in `--color-error`; `scrollTime: '07:30'`.
- `businessHours: { daysOfWeek: [1-5], startTime: '08:00', endTime: '18:00' }` — non-business slots get a 3% content-tint wash so working hours read lighter.
- Timed event blocks use the same tint+accent chip language; 30-min slot hairlines at 40% of the hour-line strength; slot labels tabular numerals, muted.

**List:** day section headers as `cal-eyebrow`, event rows with color dot + title + humanized time, hover `bg-base-200`, no stock FC table borders.

**Toolbar:** `+ New event` = `btn-primary btn-sm` (the page's single strong accent); Today/arrows = `btn-ghost btn-sm`; view switcher = daisyUI `join` segmented control with the active segment `btn-active`; title `text-lg font-semibold tracking-tight`.

**Density tokens:** grid base font 0.9375rem; chip text 0.8125rem; all sizes via the `.cal-root` scope in `src/index.css` (existing `--fc-*` mapping extends; dark-specific overrides stay under `[data-theme='eldrin-dark']`).

## 6. Interactions

**Peek popover (replaces click→modal):**
- Click event → anchored floating card (~320px) near the chip (flip to stay in viewport): calendar dot + name (eyebrow), title (semibold), humanized time ("Fri, Jul 17 · 11:00 – 12:00" / "All day"), location with pin glyph, attendee chips, recurrence hint ("Repeats weekly") when the occurrence is recurring.
- Footer: **Edit** (`btn-sm`) → existing EventModal (unchanged flow incl. seriesRule fetch); **Delete** (`btn-ghost btn-sm text-error`) → existing scope-dialog flow for recurring, direct for single.
- Dismiss: Esc, outside click, or opening another peek. Only one open at a time.
- Drag/resize keep their current direct behavior (scope dialog for recurring).

**Create:**
- Toolbar `+ New event` → EventModal seeded at the **next round hour** (duration 1h) on today, or on the mini-nav-focused day if the user just clicked one. Month-view day-cell click/drag-select behavior unchanged.

**Empty state:** when the visible range returns zero occurrences (and calendars exist), a centered, non-blocking hint in the grid area: "Nothing scheduled — press N or click + New event". Disappears as soon as any event exists in range.

**Keyboard shortcuts** (document-level listener; suppressed when focus is in input/textarea/select/contenteditable or any modal/popover is open except Esc):
- `T` today · `←`/`→` prev/next period · `M`/`W`/`D`/`L` month/week/day/list · `N` or `C` new event · `Esc` close topmost (peek → scope dialog → modal → drawer).

## 7. File plan (eldrin-calendar)

- `src/root.component.tsx` — slims to state + composition: view/date state moves into the frame; keeps data fetching, modal/scope wiring, theme bridge.
- `src/components/CalendarToolbar.tsx` (new) — toolbar row.
- `src/components/CalendarSidebar.tsx` — rewrite: mini nav + list + collapse/drawer behavior.
- `src/components/MiniMonthNav.tsx` (new) — compact month grid.
- `src/components/CalendarCanvas.tsx` — headerToolbar off, height 100%, block display, chip renderers (`eventContent`), popover/nowIndicator/businessHours settings, exposes an API ref for toolbar navigation (`prev/next/today/changeView/gotoDate`).
- `src/components/EventPeek.tsx` (new) — anchored peek card.
- `src/components/EmptyHint.tsx` (new, tiny) — empty-range hint.
- `src/hooks/useKeyboardShortcuts.ts` (new) — shortcut wiring.
- `src/index.css` — extended `.cal-root` block (chips, popover, grid lines, week/day polish, toolbar tokens).
- `public/eldrin-app.manifest.json` — `ui.layout: "full-width"`.

eldrin-core: `src/layouts/Shell.tsx` (conditional wrapper classes), manifest type + any validation touchpoint; a unit test if the shell has a testable seam for it, otherwise live regression validation.

## 8. Testing & acceptance

- Gates per repo: `tsc -b` + build; eldrin-core's existing test suite stays green; eldrin-calendar worker suite (70) untouched/green.
- Live validation (both themes, wide ≥1900px and ~1280px viewports):
  1. Calendar fills the full window width and height below the topbar; no page scrollbar; month rows evenly fill.
  2. CRM (and core dashboard) still render with the 1440px cap — pixel-identical regression.
  3. Sidebar collapse/expand animates, persists across reload; drawer mode below lg.
  4. Mini nav: day click navigates, range highlight follows main view.
  5. Month chips readable (tint + accent + weight); "+N more" popover styled; today badge; weekend tint.
  6. Week/day: now line visible, auto-scroll ~07:30, business hours shading.
  7. Peek popover on click with Edit/Delete; Esc/outside dismiss; recurring delete → scope dialog.
  8. `T ← → M W D L N Esc` all work; typing in the modal never triggers them.
  9. Empty range shows the hint; creating an event removes it.
  10. Both themes clean (no stock-FullCalendar colors bleeding through).

## 9. Risks

- **Shell flag seam:** Shell.tsx must know the active app's manifest at render time — if the manifest isn't loaded yet (first paint), fall back to default wrapper for that frame (brief width jump acceptable, no layout crash).
- **FullCalendar imperative nav:** toolbar drives the grid via `calendarRef.getApi()` — the ref must survive view switches; keep one FullCalendar instance across views.
- **dayMaxEvents + height 100%:** verified combination (FC supports both), but chip min-height must stay ≥18px for readability — if a row gets too short on small screens, dayMaxEvents auto-reduces to keep chips legible.
- **Popover z-index vs shell topbar:** peek + FC popover render inside the app; ensure z-index below the shell's dropdowns but above the grid.
