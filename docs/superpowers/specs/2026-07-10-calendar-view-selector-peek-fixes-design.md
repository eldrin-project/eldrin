# eldrin-calendar: View Selector Redesign + Peek/Chip Fixes + Preview Regression — Design

**Date:** 2026-07-10
**Repos touched:** `eldrin-calendar` (main work), `eldrin-email` + `eldrin-crm` (one-line vite config fix)
**Validation:** Chrome DevTools MCP against the local shell (localhost:4000)

## Problems

1. **Event peek clips off-screen.** `EventPeek` renders every attendee as a badge with no
   height cap. A real Outlook meeting (10+ attendees) makes the card taller than the
   viewport; the vertical clamp pins it to the top and the rest — including the
   Delete/Edit buttons — is unreachable. There is also no final horizontal clamp (only a
   right→left flip), so the card can sit partially outside narrow viewports.
2. **Day/week chips spill their content.** In timegrid views `.cal-chip` switches to
   multi-line (time above wrapped title) but the absolutely-positioned
   `.fc-timegrid-event` does not clip, so short (30-min) events paint their title below
   the chip box, overlapping neighboring rows/columns.
3. **View selector is limited.** Four inline buttons (Month/Week/Day/List). Wanted:
   dropdown with five display intervals (Day, Three Day, Working Week, Week, Month) and
   an orthogonal display mode (Calendar vs List), where List renders the selected
   interval's events as a list.
4. **Email/CRM pages blank.** `eldrin-email` and `eldrin-crm` are served with
   `vite preview` (dist lib-mode builds). Vite lib builds intentionally keep
   `process.env.NODE_ENV` unreplaced (the React CJS entry shim references it), and the
   browser has no `process` → `application 'eldrin-email' died in
   LOADING_SOURCE_CODE: process is not defined`. Calendar only works because it runs
   full `vite` dev. The same dist is what `wrangler deploy` ships, so production is
   exposed too. Not caused by calendar code — surfaced by how the servers were started.

## Design

### 1. EventPeek: bounded card + attendee truncation

- Card: `max-height: min(70vh, viewport − 16px)`. Header block (calendar name, title,
  time, location) fixed; middle content scrolls (`overflow-y: auto`); Delete/Edit row
  pinned at the bottom, always reachable.
- Attendees: first **5** badges + `+N more` button that expands the full list inside the
  scrollable area (no nested popover). Collapses again whenever a new peek opens.
- Positioning: after the flip, hard-clamp `x` into `[8, viewport.width − card.width − 8]`;
  re-clamp both axes once the real height is measured.

### 2. Timegrid chip overflow (CSS only)

- `.cal-root .fc .fc-timegrid-event { overflow: hidden; }` — content can never paint
  outside the chip box.
- Short events: key off FullCalendar's own `fc-timegrid-event-short` class to render
  time + title on one ellipsized line instead of stacked lines.

### 3. View selector: one dropdown, interval × mode

- Replace the 4-button join with a single daisyUI dropdown labeled with the current
  interval (e.g. `Week ▾`). Menu = Calendar|List segmented toggle on top, then the five
  interval options as a radio-style list.
- State: `{ interval: 'day'|'threeDay'|'workWeek'|'week'|'month', mode: 'calendar'|'list' }`,
  persisted to localStorage, resolved to a FullCalendar view name:

  | interval | Calendar | List |
  |---|---|---|
  | Day | `timeGridDay` | `listDay` |
  | Three Day | `timeGridThreeDay` (custom, `duration:{days:3}`) | `listThreeDay` (custom) |
  | Working Week | `timeGridWorkWeek` (custom week, `weekends:false`) | `listWorkWeek` (custom, `weekends:false`) |
  | Week | `timeGridWeek` | `listWeek` |
  | Month | `dayGridMonth` | `listMonth` |

- List mode reuses FullCalendar's list plugin; existing `.fc-list` styling applies to
  all list variants. Custom views declared via the `views` option on `<FullCalendar>`.
- Keyboard shortcuts (`useKeyboardShortcuts`): `m`/`w`/`d` select the Month/Week/Day
  intervals (mode unchanged); `l` now **toggles** the display mode (calendar ⇄ list) for
  the current interval, replacing its old hardcoded jump to `listWeek`. `3` selects
  Three Day. Working Week gets no shortcut for now. `t`, arrows, `n`/`c`, `Escape`
  unchanged.

### 4. Preview/deploy regression fix

- Add `define: { 'process.env.NODE_ENV': JSON.stringify(mode === 'development' ? 'development' : 'production') }`
  to `vite.config.ts` in `eldrin-email`, `eldrin-crm`, and `eldrin-calendar` (parity +
  deploy safety). Rebuild, restart the preview servers, verify pages render.

## Testing

- Vitest: view-resolution mapping (interval × mode → FC view name, exhaustive), peek
  clamp math (pure function extracted for testability), attendee truncation logic.
- Live via Chrome DevTools MCP: peek on the many-attendee Outlook "Design review" event
  in Day/Week/Month; 30-min chip rendering in Day/Week; all 10 interval × mode
  combinations render and navigate (prev/next/today); Email and CRM pages render again.

## Out of scope

- No changes to sync, API, or worker code.
- No redesign of the list view's visual style beyond what the existing CSS provides.
