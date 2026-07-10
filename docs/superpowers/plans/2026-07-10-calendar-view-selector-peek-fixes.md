# Calendar View Selector + Peek/Chip Fixes + Preview Regression — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the event-peek popover clipping and timegrid chip overflow, replace the calendar view buttons with a single interval × mode dropdown (Day / Three Day / Working Week / Week / Month × Calendar / List), and fix the `process is not defined` crash that blanks the Email and CRM apps under `vite preview`.

**Architecture:** All calendar work lives in the `eldrin-calendar` submodule (React 19 + FullCalendar 6 + daisyUI 5, mounted into the eldrin-core shell via single-spa). View state becomes a pure `{interval, mode}` model resolved to FullCalendar view names by a new `src/view-config.ts`; peek positioning becomes a pure helper in `src/utils/peek-position.ts`. The regression fix is a one-line `define` addition to three `vite.config.ts` files (eldrin-email is parent-tracked; eldrin-crm and eldrin-calendar are submodules).

**Tech Stack:** React 19, FullCalendar 6 (`@fullcalendar/{daygrid,timegrid,list,interaction,react}`), daisyUI 5 (styles reach the shell via `@scope` wrapping), Vite 7 lib-mode builds, Vitest, Chrome DevTools MCP for live validation.

**Spec:** `docs/superpowers/specs/2026-07-10-calendar-view-selector-peek-fixes-design.md`

## Global Constraints

- Immutability everywhere; no mutation of props/state objects.
- Files < 800 lines; functions < 50 lines where practical.
- Vitest config of eldrin-calendar currently only includes `worker/**/*.test.ts`; Task 3 widens it to `src/**/*.test.ts` — UI-adjacent tests must be pure (environment stays `node`, no DOM).
- Commit format: `type(scope): description`, no attribution footer.
- Dark mode = `data-theme="eldrin-dark")` inside the app (mirrors shell `data-theme="dark"`); any new CSS must work in both themes (use daisyUI tokens, no hardcoded colors).
- Dev environment: shell at `http://localhost:4000` (login `admin@eldrin.local` / `admin123`, JWT lives in `sessionStorage['eldrin-token']`), calendar dev server on :4012 (`vite` dev), email preview on :4010, crm preview on :4009. Calendar page: `http://localhost:4000/eldrin-calendar`.
- Bash cwd persists between commands — always `cd` with absolute paths and verify `pwd` before `git` operations (submodule vs parent gotcha).

## Repo/branch map

| Repo | Path | Kind | Branch for this work |
|---|---|---|---|
| eldrin-calendar | `eldrin-calendar/` | submodule (on `main`) | `feature/view-selector-ux` |
| eldrin-crm | `eldrin-crm/` | submodule (on `main`) | `fix/vite-preview-node-env` → merge to `main` |
| eldrin-email | `eldrin-email/` | parent-tracked directory | parent branch `feature/eldrin-factorial` |
| parent | `/Users/tibor/projects/eldrin-backup` | orchestrator | `feature/eldrin-factorial` |

---

### Task 1: NODE_ENV define fix (eldrin-email, eldrin-crm, eldrin-calendar)

The dist lib-mode bundles keep `process.env.NODE_ENV` (React's CJS entry shim), and browsers have no `process`, so `vite preview` (and production deploys of the same dist) die with `process is not defined`. Add an explicit `define`.

**Files:**
- Modify: `eldrin-email/vite.config.ts:70` (the `export default defineConfig({...})`)
- Modify: `eldrin-crm/vite.config.ts:70` (same shape)
- Modify: `eldrin-calendar/vite.config.ts:70` (same shape)

**Interfaces:**
- Consumes: nothing.
- Produces: browser-safe dist bundles; no code-level interface.

- [ ] **Step 1: Create the CRM fix branch and the calendar feature branch**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-crm && git checkout -b fix/vite-preview-node-env
cd /Users/tibor/projects/eldrin-backup/eldrin-calendar && git checkout -b feature/view-selector-ux
```

- [ ] **Step 2: Edit all three vite configs**

In each of the three files, the config currently ends like this (ports/entry names differ per app):

```ts
export default defineConfig({
  plugins: [react(), cloudflare(), tailwindcss(), devShellCompat()],
  ...
});
```

Convert to the function form and add `define` as the first key. Example for eldrin-email (apply the identical transformation to eldrin-crm and eldrin-calendar — only the inner content already differs, do not touch it):

```ts
export default defineConfig(({ mode }) => ({
  // Lib-mode builds keep process.env.NODE_ENV unreplaced (React's CJS entry
  // shim reads it at runtime), but browsers have no `process` — the served
  // bundle dies in LOADING_SOURCE_CODE. Pin it at build time.
  define: {
    'process.env.NODE_ENV': JSON.stringify(mode === 'development' ? 'development' : 'production'),
  },
  plugins: [react(), cloudflare(), tailwindcss(), devShellCompat()],
  ...rest of the existing object unchanged...
}));
```

Note the closing `}));` replaces the old `});`.

- [ ] **Step 3: Rebuild email + crm and verify the references are gone**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-email && npm run build
cd /Users/tibor/projects/eldrin-backup/eldrin-crm && npm run build
grep -c "process\.env\.NODE_ENV" /Users/tibor/projects/eldrin-backup/eldrin-email/dist/client/eldrin-email.js /Users/tibor/projects/eldrin-backup/eldrin-crm/dist/client/eldrin-crm.js
```

Expected: `0` for both files (grep -c prints 0; exit code 1 is fine). Before the fix: 17 and 189.

- [ ] **Step 4: Restart the two preview servers**

Find and kill the old servers, then restart (background):

```bash
kill $(lsof -tiTCP:4009 -sTCP:LISTEN) $(lsof -tiTCP:4010 -sTCP:LISTEN)
cd /Users/tibor/projects/eldrin-backup/eldrin-crm && (npm run preview >/tmp/crm-preview.log 2>&1 &)
cd /Users/tibor/projects/eldrin-backup/eldrin-email && (npm run preview >/tmp/email-preview.log 2>&1 &)
```

Wait until `curl -s -o /dev/null -w '%{http_code}' http://localhost:4009/eldrin-crm.js` and the :4010 equivalent return 200 (the preview script re-runs the build first, allow ~60s).

- [ ] **Step 5: Verify in the browser (Chrome DevTools MCP)**

Navigate to `http://localhost:4000/eldrin-crm` and `http://localhost:4000/eldrin-email` (login if redirected). Expected: both pages render app UI (CRM dashboard, Email inbox), and `list_console_messages` shows **no** `died in status LOADING_SOURCE_CODE` error.

- [ ] **Step 6: Commit (three repos)**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-email && git status -s   # confirm only vite.config.ts (dist is gitignored)
cd /Users/tibor/projects/eldrin-backup && git add eldrin-email/vite.config.ts && git commit -m "fix(email): pin process.env.NODE_ENV in vite define — lib build crashed under preview/deploy (process is not defined)"
cd /Users/tibor/projects/eldrin-backup/eldrin-crm && git add vite.config.ts && git commit -m "fix: pin process.env.NODE_ENV in vite define — lib build crashed under preview/deploy (process is not defined)"
cd /Users/tibor/projects/eldrin-backup/eldrin-calendar && git add vite.config.ts && git commit -m "fix: pin process.env.NODE_ENV in vite define (parity with email/crm preview fix)"
```

(CRM merge to main + parent gitlink bumps happen in Task 8.)

---

### Task 2: Timegrid chip overflow (CSS only)

Short (≤30 min) events in Day/Week views paint their wrapped title below the chip box because `.fc-timegrid-event` doesn't clip and `.cal-chip` stacks time/title vertically.

**Files:**
- Modify: `eldrin-calendar/src/index.css` (the `.cal-chip` block, currently around lines 199–221)

**Interfaces:**
- Consumes: FullCalendar's own `fc-timegrid-event-short` class (added automatically to events too short for two lines).
- Produces: nothing code-level.

- [ ] **Step 1: Add the clip + short-event rules**

In `eldrin-calendar/src/index.css`, directly after the existing rule

```css
.cal-root .fc .fc-timegrid-event .cal-chip { white-space: normal; flex-direction: column; gap: 0; align-items: flex-start; }
```

add:

```css
/* Chips must never paint outside their slot box (short events used to spill
   their wrapped title over the rows below). */
.cal-root .fc .fc-timegrid-event { overflow: hidden; }
/* FC marks events too short for stacked lines with fc-timegrid-event-short:
   collapse back to a single ellipsized time+title line. */
.cal-root .fc .fc-timegrid-event.fc-timegrid-event-short .cal-chip {
  flex-direction: row;
  gap: 4px;
  align-items: baseline;
  white-space: nowrap;
}
.cal-root .fc .fc-timegrid-event.fc-timegrid-event-short .cal-chip-title {
  overflow: hidden;
  text-overflow: ellipsis;
}
```

- [ ] **Step 2: Verify live (Chrome DevTools MCP)**

On `http://localhost:4000/eldrin-calendar` switch to Week (`w`) and Day (`d`). Check the 09:30 "Daily Campion" / 11:30 "Veestacks - Daily Scrum" 30-minute chips: title must stay inside the chip (ellipsized), nothing painted over neighboring rows/columns. Screenshot Day + Week for the record.

- [ ] **Step 3: Commit**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-calendar && git add src/index.css && git commit -m "fix(ui): clip timegrid chips and single-line short events — titles spilled outside chip bounds"
```

---

### Task 3: Pure peek-positioning helper + vitest include widening

**Files:**
- Create: `eldrin-calendar/src/utils/peek-position.ts`
- Test: `eldrin-calendar/src/utils/peek-position.test.ts`
- Modify: `eldrin-calendar/vitest.config.ts`

**Interfaces:**
- Consumes: nothing.
- Produces: `placePeek(anchor: PeekAnchor, card: Size, viewport: Size, margin?: number): { x: number; y: number }` with `PeekAnchor = { x: number; y: number; w: number; h: number }` and `Size = { w: number; h: number }`. Task 4 imports `placePeek` and `PeekAnchor`.

- [ ] **Step 1: Widen the vitest include**

`eldrin-calendar/vitest.config.ts` — change `include`:

```ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['worker/**/*.test.ts', 'src/**/*.test.ts'],
  },
});
```

- [ ] **Step 2: Write the failing test**

`eldrin-calendar/src/utils/peek-position.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { placePeek } from './peek-position';

const CARD = { w: 320, h: 200 };
const VIEWPORT = { w: 1512, h: 806 };

describe('placePeek', () => {
  it('prefers the right side of the anchor', () => {
    const pos = placePeek({ x: 100, y: 100, w: 150, h: 24 }, CARD, VIEWPORT);
    expect(pos).toEqual({ x: 258, y: 100 }); // 100 + 150 + 8
  });

  it('flips to the left when the right side would overflow', () => {
    const pos = placePeek({ x: 1200, y: 100, w: 150, h: 24 }, CARD, VIEWPORT);
    expect(pos.x).toBe(1200 - 320 - 8);
  });

  it('hard-clamps x when even the flipped position is off-screen (full-width day chip)', () => {
    // Chip spans nearly the whole viewport: right overflows AND flip goes negative.
    const pos = placePeek({ x: 60, y: 100, w: 1400, h: 46 }, CARD, VIEWPORT);
    expect(pos.x).toBe(8);
  });

  it('clamps x to the right edge on very narrow viewports', () => {
    const pos = placePeek({ x: 10, y: 10, w: 30, h: 24 }, CARD, { w: 300, h: 806 });
    expect(pos.x).toBe(8); // right edge clamp: max(8, 300-320-8) = 8
  });

  it('shifts up when the card would overflow the bottom', () => {
    const pos = placePeek({ x: 100, y: 700, w: 150, h: 24 }, CARD, VIEWPORT);
    expect(pos.y).toBe(806 - 200 - 8);
  });

  it('pins to the top margin when the card is taller than the viewport', () => {
    const pos = placePeek({ x: 100, y: 300, w: 150, h: 24 }, { w: 320, h: 1200 }, VIEWPORT);
    expect(pos.y).toBe(8);
  });
});
```

- [ ] **Step 3: Run to verify failure**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-calendar && npx vitest run src/utils/peek-position.test.ts`
Expected: FAIL — `Cannot find module './peek-position'`.

- [ ] **Step 4: Implement**

`eldrin-calendar/src/utils/peek-position.ts`:

```ts
export interface PeekAnchor {
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface Size {
  w: number;
  h: number;
}

/**
 * Place the peek card next to its anchor chip, guaranteed inside the viewport.
 * Prefer the anchor's right side; flip left when that overflows; then hard-clamp
 * both axes to a `margin` inset. When the card is bigger than the viewport the
 * top/left edge wins (the card itself scrolls, see EventPeek).
 */
export function placePeek(anchor: PeekAnchor, card: Size, viewport: Size, margin = 8): { x: number; y: number } {
  let x = anchor.x + anchor.w + margin;
  if (x + card.w > viewport.w - margin) x = anchor.x - card.w - margin;
  x = Math.max(margin, Math.min(x, Math.max(margin, viewport.w - card.w - margin)));

  let y = anchor.y;
  if (y + card.h > viewport.h - margin) y = viewport.h - card.h - margin;
  y = Math.max(margin, y);

  return { x, y };
}
```

- [ ] **Step 5: Run tests**

Run: `npx vitest run src/utils/peek-position.test.ts` (from `eldrin-calendar/`)
Expected: 6 passed. Then `npx vitest run` — full suite (253+ worker tests) still green.

- [ ] **Step 6: Commit**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-calendar && git add src/utils/peek-position.ts src/utils/peek-position.test.ts vitest.config.ts && git commit -m "feat(ui): pure peek placement helper with hard x/y viewport clamping"
```

---

### Task 4: EventPeek — bounded, scrollable card with attendee truncation

**Files:**
- Modify: `eldrin-calendar/src/components/EventPeek.tsx` (full rewrite of the component body; the `humanTime`/`isSameLocalDay` helpers and formatters stay as they are)

**Interfaces:**
- Consumes: `placePeek`, `PeekAnchor` from `../utils/peek-position` (Task 3). Props stay `{ occ, calendarName, anchor, onEdit, onDelete, onClose }` — no caller changes in root.component.tsx.
- Produces: nothing new outward.

- [ ] **Step 1: Rewrite the component**

Replace the constants, state and JSX of `EventPeek` (keep imports of `Occurrence`, the `DAY_FMT`/`TIME_FMT` formatters and `humanTime`/`isSameLocalDay` unchanged; add the new imports):

```tsx
import { useLayoutEffect, useEffect, useRef, useState } from 'react';
import type { Occurrence } from '../api';
import { placePeek, type PeekAnchor } from '../utils/peek-position';

interface EventPeekProps {
  occ: Occurrence;
  calendarName: string;
  anchor: PeekAnchor;
  onEdit: () => void;
  onDelete: () => void;
  onClose: () => void;
}

const CARD_W = 320;
const CARD_H_GUESS = 210;
const MARGIN = 8;
/** Attendee badges shown before the "+N more" expander. */
const ATTENDEE_PREVIEW = 5;

// ... humanTime / formatters unchanged ...

export function EventPeek({ occ, calendarName, anchor, onEdit, onDelete, onClose }: EventPeekProps) {
  const ref = useRef<HTMLDivElement>(null);
  const [showAllAttendees, setShowAllAttendees] = useState(false);
  const [pos, setPos] = useState(() =>
    placePeek(anchor, { w: CARD_W, h: CARD_H_GUESS }, { w: window.innerWidth, h: window.innerHeight }, MARGIN),
  );

  // Re-clamp with the real card size — after mount and whenever the
  // attendee list expands/collapses (the card height changes).
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    setPos(placePeek(anchor, { w: r.width, h: r.height }, { w: window.innerWidth, h: window.innerHeight }, MARGIN));
  }, [anchor, showAllAttendees]);

  useEffect(() => {
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    document.addEventListener('mousedown', onDown);
    return () => document.removeEventListener('mousedown', onDown);
  }, [onClose]);

  const attendees = showAllAttendees ? occ.attendees : occ.attendees.slice(0, ATTENDEE_PREVIEW);
  const hiddenCount = occ.attendees.length - attendees.length;

  return (
    <div
      ref={ref}
      className="fixed z-30 w-80 card bg-base-100 border border-base-300 shadow-lg flex flex-col"
      style={{ left: pos.x, top: pos.y, maxHeight: `min(70vh, calc(100dvh - ${MARGIN * 2}px))` }}
      role="dialog"
      aria-label={occ.title}
    >
      <div className="card-body p-4 gap-2 min-h-0 flex flex-col">
        <div className="flex items-center gap-2 text-xs text-base-content/60 shrink-0">
          <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: occ.color }} />
          <span className="truncate">{calendarName}</span>
          {occ.isRecurring && <span className="badge badge-ghost badge-xs">Repeats</span>}
        </div>
        <h3 className="font-semibold leading-tight shrink-0">{occ.title}</h3>
        <p className="text-sm text-base-content/70 cal-num shrink-0">{humanTime(occ)}</p>
        <div className="min-h-0 overflow-y-auto flex flex-col gap-2">
          {occ.location && <p className="text-sm text-base-content/70">📍 {occ.location}</p>}
          {occ.attendees.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {attendees.map((a) => (
                <span key={a.email} className="badge badge-outline badge-sm max-w-full">
                  <span className="truncate">{a.displayName || a.email}</span>
                </span>
              ))}
              {hiddenCount > 0 && (
                <button className="badge badge-ghost badge-sm" onClick={() => setShowAllAttendees(true)}>
                  +{hiddenCount} more
                </button>
              )}
              {showAllAttendees && occ.attendees.length > ATTENDEE_PREVIEW && (
                <button className="badge badge-ghost badge-sm" onClick={() => setShowAllAttendees(false)}>
                  Show less
                </button>
              )}
            </div>
          )}
        </div>
        <div className="flex justify-end gap-2 mt-1 shrink-0">
          <button className="btn btn-ghost btn-sm text-error" onClick={onDelete}>Delete</button>
          <button className="btn btn-sm btn-primary" onClick={onEdit}>Edit</button>
        </div>
      </div>
    </div>
  );
}
```

Key points: the middle `div` is the only scrollable region (`min-h-0 overflow-y-auto`); header and Delete/Edit row are `shrink-0` so they never collapse or leave the card; `showAllAttendees` resets naturally because root remounts `EventPeek` per peek (`{peek && <EventPeek .../>}` keyed by state change — verify a new click produces a fresh component; if the same component instance is reused when clicking another chip while the peek is open, add `key={occ.id}` at the call site in `root.component.tsx:446`).

- [ ] **Step 2: Typecheck**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-calendar && npx tsc -b`
Expected: clean.

- [ ] **Step 3: Verify live (Chrome DevTools MCP)**

On `http://localhost:4000/eldrin-calendar`:
1. Day view (Jul 10), click the Outlook "Design review" chip (the one with 10+ attendees — it's on the Outlook "Calendar" account; if two chips share the name, the wide blue one). Expected: card fully inside viewport, 5 attendee badges + `+N more`, Delete/Edit visible.
2. Click `+N more` → full list appears, card grows but bottom edge stays ≥8px inside the viewport, inner area scrolls, "Show less" collapses.
3. Month view: click an event in the top-right corner cell (e.g. "Test sync" on Fri) and one in the bottom row — card never crosses any viewport edge.
4. Repeat one check with a small window: `resize_page` to 900×600, click any chip — card stays inside.
5. Resize back (e.g. 1512×806).

- [ ] **Step 4: Commit**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-calendar && git add src/components/EventPeek.tsx src/root.component.tsx && git commit -m "fix(ui): bounded scrollable event peek with attendee truncation (+N more) — card no longer clips off-screen"
```

(Include `src/root.component.tsx` only if the `key={occ.id}` addition was needed.)

---

### Task 5: View model — `view-config.ts` (interval × mode → FullCalendar view)

**Files:**
- Create: `eldrin-calendar/src/view-config.ts`
- Test: `eldrin-calendar/src/view-config.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces (used by Tasks 6–7):
  - `type DisplayInterval = 'day' | 'threeDay' | 'workWeek' | 'week' | 'month'`
  - `type DisplayMode = 'calendar' | 'list'`
  - `interface ViewSelection { interval: DisplayInterval; mode: DisplayMode }`
  - `const INTERVALS: ReadonlyArray<{ key: DisplayInterval; label: string }>` (order: Day, Three Day, Working Week, Week, Month)
  - `function resolveViewName(sel: ViewSelection): string`
  - `const CUSTOM_VIEWS: Record<string, object>` (passed to FullCalendar's `views` option)
  - `function parseViewSelection(raw: string | null): ViewSelection` (safe localStorage parse, falls back to `{ interval: 'month', mode: 'calendar' }`)
  - `const VIEW_STORAGE_KEY = 'eldrin-calendar:view'`

- [ ] **Step 1: Write the failing test**

`eldrin-calendar/src/view-config.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { CUSTOM_VIEWS, INTERVALS, parseViewSelection, resolveViewName } from './view-config';

describe('resolveViewName', () => {
  it.each([
    ['day', 'calendar', 'timeGridDay'],
    ['day', 'list', 'listDay'],
    ['threeDay', 'calendar', 'timeGridThreeDay'],
    ['threeDay', 'list', 'listThreeDay'],
    ['workWeek', 'calendar', 'timeGridWorkWeek'],
    ['workWeek', 'list', 'listWorkWeek'],
    ['week', 'calendar', 'timeGridWeek'],
    ['week', 'list', 'listWeek'],
    ['month', 'calendar', 'dayGridMonth'],
    ['month', 'list', 'listMonth'],
  ] as const)('%s + %s -> %s', (interval, mode, expected) => {
    expect(resolveViewName({ interval, mode })).toBe(expected);
  });
});

describe('CUSTOM_VIEWS', () => {
  it('declares exactly the four non-built-in views', () => {
    expect(Object.keys(CUSTOM_VIEWS).sort()).toEqual(
      ['listThreeDay', 'listWorkWeek', 'timeGridThreeDay', 'timeGridWorkWeek'],
    );
  });
  it('working week hides weekends', () => {
    expect(CUSTOM_VIEWS.timeGridWorkWeek).toMatchObject({ weekends: false });
    expect(CUSTOM_VIEWS.listWorkWeek).toMatchObject({ weekends: false });
  });
});

describe('parseViewSelection', () => {
  it('round-trips a valid selection', () => {
    expect(parseViewSelection(JSON.stringify({ interval: 'threeDay', mode: 'list' })))
      .toEqual({ interval: 'threeDay', mode: 'list' });
  });
  it.each([null, '', 'garbage', '{"interval":"decade","mode":"list"}', '{"interval":"day"}'])(
    'falls back to month/calendar for %s',
    (raw) => {
      expect(parseViewSelection(raw as string | null)).toEqual({ interval: 'month', mode: 'calendar' });
    },
  );
});

describe('INTERVALS', () => {
  it('is ordered Day, Three Day, Working Week, Week, Month', () => {
    expect(INTERVALS.map((i) => i.label)).toEqual(['Day', 'Three Day', 'Working Week', 'Week', 'Month']);
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-calendar && npx vitest run src/view-config.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement**

`eldrin-calendar/src/view-config.ts`:

```ts
/**
 * Display-interval × display-mode view model.
 * The toolbar picks a `ViewSelection`; FullCalendar consumes the resolved
 * view name plus the CUSTOM_VIEWS definitions for the non-built-in ones.
 */

export type DisplayInterval = 'day' | 'threeDay' | 'workWeek' | 'week' | 'month';
export type DisplayMode = 'calendar' | 'list';

export interface ViewSelection {
  interval: DisplayInterval;
  mode: DisplayMode;
}

export const INTERVALS: ReadonlyArray<{ key: DisplayInterval; label: string }> = [
  { key: 'day', label: 'Day' },
  { key: 'threeDay', label: 'Three Day' },
  { key: 'workWeek', label: 'Working Week' },
  { key: 'week', label: 'Week' },
  { key: 'month', label: 'Month' },
];

const VIEW_NAMES: Record<DisplayInterval, Record<DisplayMode, string>> = {
  day: { calendar: 'timeGridDay', list: 'listDay' },
  threeDay: { calendar: 'timeGridThreeDay', list: 'listThreeDay' },
  workWeek: { calendar: 'timeGridWorkWeek', list: 'listWorkWeek' },
  week: { calendar: 'timeGridWeek', list: 'listWeek' },
  month: { calendar: 'dayGridMonth', list: 'listMonth' },
};

export function resolveViewName(sel: ViewSelection): string {
  return VIEW_NAMES[sel.interval][sel.mode];
}

/** Views FullCalendar doesn't ship built in — passed via the `views` option. */
export const CUSTOM_VIEWS: Record<string, object> = {
  timeGridThreeDay: { type: 'timeGrid', duration: { days: 3 } },
  listThreeDay: { type: 'list', duration: { days: 3 } },
  timeGridWorkWeek: { type: 'timeGrid', duration: { weeks: 1 }, weekends: false },
  listWorkWeek: { type: 'list', duration: { weeks: 1 }, weekends: false },
};

export const VIEW_STORAGE_KEY = 'eldrin-calendar:view';

const DEFAULT_SELECTION: ViewSelection = { interval: 'month', mode: 'calendar' };

/** Safe parse for the persisted selection — any malformed value falls back. */
export function parseViewSelection(raw: string | null): ViewSelection {
  if (!raw) return DEFAULT_SELECTION;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (
      typeof parsed === 'object' && parsed !== null &&
      INTERVALS.some((i) => i.key === (parsed as ViewSelection).interval) &&
      ((parsed as ViewSelection).mode === 'calendar' || (parsed as ViewSelection).mode === 'list')
    ) {
      const { interval, mode } = parsed as ViewSelection;
      return { interval, mode };
    }
  } catch {
    /* fall through */
  }
  return DEFAULT_SELECTION;
}
```

- [ ] **Step 4: Run tests**

Run: `npx vitest run src/view-config.test.ts` (from `eldrin-calendar/`)
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-calendar && git add src/view-config.ts src/view-config.test.ts && git commit -m "feat(ui): interval x mode view model with custom three-day and working-week views"
```

---

### Task 6: Toolbar dropdown + root/canvas wiring

**Files:**
- Modify: `eldrin-calendar/src/components/CalendarToolbar.tsx` (replace the `VIEWS` join with the dropdown; delete the `VIEWS` const and `ViewType` type)
- Modify: `eldrin-calendar/src/components/CalendarCanvas.tsx` (add `views`/`initialView` wiring, fix the list-view check)
- Modify: `eldrin-calendar/src/root.component.tsx` (state `{interval, mode}`, persistence, handler changes)

**Interfaces:**
- Consumes: everything Task 5 produces.
- Produces:
  - `CalendarToolbar` props become `{ title, selection: ViewSelection, sidebarOpen, onToggleSidebar, onNewEvent, onToday, onPrev, onNext, onChangeInterval: (i: DisplayInterval) => void, onChangeMode: (m: DisplayMode) => void }`. `nextRoundHour` stays exported from CalendarToolbar.
  - `CalendarCanvas` gains prop `initialView: string`.
  - Task 7 relies on root handlers `applySelection(sel: ViewSelection)` (defined here).

- [ ] **Step 1: Rewrite CalendarToolbar**

Full new content for `eldrin-calendar/src/components/CalendarToolbar.tsx` (keep `nextRoundHour` as is; `VIEWS`/`ViewType` are deleted — Task 7 fixes the last importer, `root.component.tsx` is fixed in Step 3):

```tsx
import { useEffect, useRef, useState } from 'react';
import { INTERVALS, type DisplayInterval, type DisplayMode, type ViewSelection } from '../view-config';

/** Next full hour from `now`, 1h duration — seed for the New-event modal. */
export function nextRoundHour(now: Date = new Date()): { startAt: number; endAt: number } {
  const start = new Date(now);
  start.setMinutes(0, 0, 0);
  start.setHours(start.getHours() + 1);
  return { startAt: start.getTime(), endAt: start.getTime() + 3600000 };
}

interface CalendarToolbarProps {
  title: string;
  selection: ViewSelection;
  sidebarOpen: boolean;
  onToggleSidebar: () => void;
  onNewEvent: () => void;
  onToday: () => void;
  onPrev: () => void;
  onNext: () => void;
  onChangeInterval: (interval: DisplayInterval) => void;
  onChangeMode: (mode: DisplayMode) => void;
}

/** Interval picker + calendar/list mode toggle in a single dropdown. */
function ViewDropdown({ selection, onChangeInterval, onChangeMode }: Pick<CalendarToolbarProps, 'selection' | 'onChangeInterval' | 'onChangeMode'>) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const label = INTERVALS.find((i) => i.key === selection.interval)?.label ?? 'View';

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onDown);
    return () => document.removeEventListener('mousedown', onDown);
  }, [open]);

  return (
    <div className="relative" ref={ref}>
      <button
        className="btn btn-ghost btn-sm gap-1"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        {label}
        {selection.mode === 'list' && <span className="badge badge-ghost badge-xs">List</span>}
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
          <polyline points="6 9 12 15 18 9" />
        </svg>
      </button>
      {open && (
        <div className="absolute right-0 top-full mt-1 z-40 w-56 card bg-base-100 border border-base-300 shadow-lg p-2" role="menu">
          <div className="join w-full mb-2">
            <button
              className={`btn btn-sm join-item flex-1 ${selection.mode === 'calendar' ? 'btn-active' : 'btn-ghost'}`}
              onClick={() => { onChangeMode('calendar'); setOpen(false); }}
            >
              Calendar
            </button>
            <button
              className={`btn btn-sm join-item flex-1 ${selection.mode === 'list' ? 'btn-active' : 'btn-ghost'}`}
              onClick={() => { onChangeMode('list'); setOpen(false); }}
            >
              List
            </button>
          </div>
          <ul className="menu p-0">
            {INTERVALS.map((i) => (
              <li key={i.key}>
                <button
                  className={i.key === selection.interval ? 'active' : ''}
                  role="menuitemradio"
                  aria-checked={i.key === selection.interval}
                  onClick={() => { onChangeInterval(i.key); setOpen(false); }}
                >
                  {i.label}
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export function CalendarToolbar({
  title, selection, sidebarOpen,
  onToggleSidebar, onNewEvent, onToday, onPrev, onNext, onChangeInterval, onChangeMode,
}: CalendarToolbarProps) {
  return (
    <div className="h-14 shrink-0 flex items-center gap-2 px-3 border-b border-base-300 bg-base-100">
      <button
        className="btn btn-ghost btn-sm btn-square"
        aria-label={sidebarOpen ? 'Hide sidebar' : 'Show sidebar'}
        onClick={onToggleSidebar}
      >
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
          <line x1="4" y1="6" x2="20" y2="6" /><line x1="4" y1="12" x2="20" y2="12" /><line x1="4" y1="18" x2="20" y2="18" />
        </svg>
      </button>
      <button className="btn btn-primary btn-sm" onClick={onNewEvent}>+ New event</button>
      <div className="w-2" />
      <button className="btn btn-ghost btn-sm" onClick={onToday}>Today</button>
      <div className="join">
        <button className="btn btn-ghost btn-sm join-item" aria-label="Previous" onClick={onPrev}>‹</button>
        <button className="btn btn-ghost btn-sm join-item" aria-label="Next" onClick={onNext}>›</button>
      </div>
      <h2 className="text-lg font-semibold tracking-tight ml-2 truncate">{title}</h2>
      <div className="flex-1" />
      <ViewDropdown selection={selection} onChangeInterval={onChangeInterval} onChangeMode={onChangeMode} />
    </div>
  );
}
```

(A hand-rolled dropdown instead of daisyUI's focus-based `dropdown` class: click-outside and explicit open state behave predictably inside the shell's `@scope`d CSS.)

- [ ] **Step 2: Wire CalendarCanvas**

In `eldrin-calendar/src/components/CalendarCanvas.tsx`:

1. Import: `import { CUSTOM_VIEWS } from '../view-config';`
2. Add to `CalendarCanvasProps`: `initialView: string;` and destructure it in the component signature.
3. `renderEventContent` first line — the list-view check must cover **all** list views:

```tsx
  if (arg.view.type.startsWith('list')) return true; // default rendering, restyled via CSS
```

4. On the `<FullCalendar>` element replace `initialView="dayGridMonth"` with:

```tsx
        initialView={initialView}
        views={CUSTOM_VIEWS}
```

- [ ] **Step 3: Wire root.component.tsx**

In `eldrin-calendar/src/root.component.tsx`:

1. Replace the import of `ViewType`:

```tsx
import { CalendarToolbar, nextRoundHour } from './components/CalendarToolbar';
import {
  parseViewSelection, resolveViewName, VIEW_STORAGE_KEY,
  type DisplayInterval, type DisplayMode, type ViewSelection,
} from './view-config';
```

2. Add state + persistence next to the `sidebarOpen` state (after line ~73):

```tsx
  const [viewSel, setViewSel] = useState<ViewSelection>(() =>
    parseViewSelection(localStorage.getItem(VIEW_STORAGE_KEY)),
  );
  useEffect(() => {
    localStorage.setItem(VIEW_STORAGE_KEY, JSON.stringify(viewSel));
  }, [viewSel]);
```

3. Replace `handleChangeView` (line 342) with:

```tsx
  const applySelection = (sel: ViewSelection) => {
    setViewSel(sel);
    calApi()?.changeView(resolveViewName(sel));
  };
  const handleChangeInterval = (interval: DisplayInterval) => applySelection({ ...viewSel, interval });
  const handleChangeMode = (mode: DisplayMode) => applySelection({ ...viewSel, mode });
```

4. Update the `<CalendarToolbar>` call (replace `viewType`/`onChangeView` props):

```tsx
      <CalendarToolbar
        title={viewInfo?.title ?? ''}
        selection={viewSel}
        sidebarOpen={sidebarOpen}
        onToggleSidebar={() => setSidebarOpen((o) => !o)}
        onNewEvent={handleNewEvent}
        onToday={handleToday}
        onPrev={handlePrev}
        onNext={handleNext}
        onChangeInterval={handleChangeInterval}
        onChangeMode={handleChangeMode}
      />
```

5. Pass the initial view to the canvas (in the `<CalendarCanvas>` call):

```tsx
          <CalendarCanvas
            calendarRef={calendarRef}
            initialView={resolveViewName(parseViewSelection(localStorage.getItem(VIEW_STORAGE_KEY)))}
            ...existing props unchanged...
          />
```

(Read localStorage again rather than `viewSel` so the prop is stable — `initialView` only matters on first mount and must not re-render the canvas on every selection change; FullCalendar ignores later changes to it anyway.)

6. Temporary shortcut shim (Task 7 replaces it — the build must stay green): change the `onView` handler in `useKeyboardShortcuts` to:

```tsx
    onView: (view) => { if (!uiBlocked) calApi()?.changeView(view); },
```

- [ ] **Step 4: Typecheck + unit tests**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-calendar && npx tsc -b && npx vitest run`
Expected: clean, all tests pass.

- [ ] **Step 5: Verify live (Chrome DevTools MCP)**

On `http://localhost:4000/eldrin-calendar`:
1. Toolbar shows one dropdown button (current interval label) instead of four buttons.
2. Open it: Calendar|List toggle on top, five intervals below, current one highlighted.
3. Click through **all five intervals in Calendar mode**: Day (1 col), Three Day (3 cols), Working Week (Mon–Fri, 5 cols, no Sat/Sun), Week (7 cols), Month (grid). Title updates; prev/next moves by the right amount (3-day view advances 3 days).
4. Switch mode to List for at least Day, Working Week and Month: event list renders for exactly that range (Month list shows the whole month's events).
5. Reload the page: last selection (interval + mode) is restored.
6. Screenshot Working Week calendar + Month list for the record.

- [ ] **Step 6: Commit**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-calendar && git add src/components/CalendarToolbar.tsx src/components/CalendarCanvas.tsx src/root.component.tsx && git commit -m "feat(ui): single view dropdown — display interval (day/3-day/work-week/week/month) x display mode (calendar/list), persisted"
```

---

### Task 7: Keyboard shortcuts remap

**Files:**
- Modify: `eldrin-calendar/src/hooks/useKeyboardShortcuts.ts`
- Modify: `eldrin-calendar/src/root.component.tsx` (the `useKeyboardShortcuts({...})` call, lines ~350–364)

**Interfaces:**
- Consumes: `DisplayInterval` from `../view-config`; root's `applySelection` and `viewSel` (Task 6).
- Produces: `ShortcutHandlers` becomes `{ onToday, onPrev, onNext, onInterval: (interval: DisplayInterval) => void, onToggleMode: () => void, onNew, onEscape }`.

- [ ] **Step 1: Update the hook**

In `eldrin-calendar/src/hooks/useKeyboardShortcuts.ts` — replace the `onView` member and the view key cases:

```ts
import type { DisplayInterval } from '../view-config';

export interface ShortcutHandlers {
  onToday: () => void;
  onPrev: () => void;
  onNext: () => void;
  onInterval: (interval: DisplayInterval) => void;
  /** Toggle display mode calendar ⇄ list for the current interval. */
  onToggleMode: () => void;
  onNew: () => void;
  /** Close the topmost overlay; return true if something was closed. */
  onEscape: () => boolean;
}
```

and in the `switch`:

```ts
        case 'm': ref.current.onInterval('month'); break;
        case 'w': ref.current.onInterval('week'); break;
        case 'd': ref.current.onInterval('day'); break;
        case '3': ref.current.onInterval('threeDay'); break;
        case 'l': ref.current.onToggleMode(); break;
```

(everything else — `t`, arrows, `n`/`c`, Escape handling, `isTyping`, preventDefault comment — unchanged.)

- [ ] **Step 2: Update the root call site**

In `root.component.tsx`, replace the `onView` line inside `useKeyboardShortcuts({...})` (and remove the Task 6 shim):

```tsx
    onInterval: (interval) => { if (!uiBlocked) applySelection({ ...viewSel, interval }); },
    onToggleMode: () => {
      if (!uiBlocked) applySelection({ ...viewSel, mode: viewSel.mode === 'list' ? 'calendar' : 'list' });
    },
```

- [ ] **Step 3: Typecheck + tests**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-calendar && npx tsc -b && npx vitest run`
Expected: clean.

- [ ] **Step 4: Verify live (Chrome DevTools MCP)**

Focus the calendar page (click empty background first so no input has focus), then send keys via `press_key` / `evaluate_script` KeyboardEvent dispatch: `d` → Day, `3` → Three Day, `w` → Week, `m` → Month, `l` → list of the current interval, `l` again → back to calendar mode. Verify `t` and arrow keys still navigate.

- [ ] **Step 5: Commit**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-calendar && git add src/hooks/useKeyboardShortcuts.ts src/root.component.tsx && git commit -m "feat(ui): shortcut remap — m/w/d/3 pick interval, l toggles list mode"
```

---

### Task 8: Final validation, merges, parent bumps

**Files:**
- No new code. Git plumbing + full regression sweep.

- [ ] **Step 1: Full test + typecheck sweep in eldrin-calendar**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-calendar && npx vitest run && npx tsc -b && npm run build
```

Expected: all tests green (worker suite + new src tests), clean compile, successful build (build also proves the `define` change didn't break lib output).

- [ ] **Step 2: Full live sweep (Chrome DevTools MCP)**

On `http://localhost:4000` (re-login if needed):
1. `/eldrin-calendar`: all 10 interval × mode combos via the dropdown; peek on many-attendee event in Day + Week + Month; 30-min chips clipped correctly; `l`/`3`/`d`/`w`/`m` shortcuts; reload restores selection.
2. Dark mode: toggle the shell theme (moon icon in the top bar), spot-check the dropdown menu, peek card, and Working Week view for broken colors.
3. `/eldrin-email` and `/eldrin-crm`: pages render, console free of `LOADING_SOURCE_CODE` errors.

- [ ] **Step 3: Merge eldrin-calendar and eldrin-crm to main, push**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-calendar
git checkout main && git merge --no-ff feature/view-selector-ux -m "Merge feature/view-selector-ux: view dropdown (interval x mode), peek/chip fixes, NODE_ENV define"
git push && git branch -d feature/view-selector-ux

cd /Users/tibor/projects/eldrin-backup/eldrin-crm
git checkout main && git merge --no-ff fix/vite-preview-node-env -m "Merge fix/vite-preview-node-env: pin process.env.NODE_ENV in vite define"
git push && git branch -d fix/vite-preview-node-env
```

- [ ] **Step 4: Parent repo — gitlink bumps + email fix already committed**

```bash
cd /Users/tibor/projects/eldrin-backup
git add eldrin-calendar eldrin-crm
git commit -m "chore: bump eldrin-calendar (view dropdown + peek/chip fixes) and eldrin-crm (NODE_ENV define) submodules"
git push
```

(The eldrin-email vite.config fix was committed to the parent branch in Task 1; it rides along on the same push.)

- [ ] **Step 5: Report**

Summarize: what shipped, test counts, live-validation evidence (screenshots), and that email/crm render again.
