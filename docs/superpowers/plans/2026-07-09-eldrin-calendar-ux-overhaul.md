# eldrin-calendar UX Overhaul Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the calendar use the full viewport (shell full-width flag + viewport-filling frame) and redesign the grid/interactions to a polished, Google-Calendar-grade experience.

**Architecture:** eldrin-core gains an opt-in `ui.layout: "full-width"` manifest flag (pure resolver + Shell wrapper switch). eldrin-calendar replaces FullCalendar's header with a custom daisyUI toolbar, pins the app to `100dvh − topbar` with `height="100%"` grid, adds a collapsible sidebar with mini month navigator, re-renders month events as tinted chips via `eventContent`/`eventDidMount`, and adds a peek popover, keyboard shortcuts, create button, and empty-state hint.

**Tech Stack:** React 19, FullCalendar 6 (MIT plugins only), Tailwind 4 + daisyUI 5, zustand (core shell), Vitest (core unit test only — calendar frontend has no test harness).

**Spec:** `docs/superpowers/specs/2026-07-09-eldrin-calendar-ux-design.md` (U1–U5). Visual direction per the frontend-design skill, concretized in spec §5 — the token values there are binding.

## Global Constraints

- **Regression (U1, spec §3):** every app WITHOUT the flag renders byte-identically to today — the default wrapper stays exactly `p-6 max-w-[1440px] mx-auto`. Full-width wrapper is `w-full` (no padding, no max-width).
- **Flag name/values exact:** `ui.layout?: 'default' | 'full-width'`; absent → default. Route match for the active app is exact-or-`/`-boundary (`/eldrin-cal` must NOT match app id `eldrin-calendar`).
- **No new FullCalendar packages.** MIT plugins already installed (daygrid/timegrid/list/interaction) only. No premium, no rrule plugin.
- **Theme-safety:** no white-on-color text; chips = `color-mix(in oklab, <calendar color> 16%, var(--color-base-100))` bg + 3px left border in the full color + `var(--color-base-content)` text. All dark-specific CSS scoped `[data-theme='eldrin-dark']`.
- **Spec §5 tokens verbatim:** grid base font 0.9375rem; chip text 0.8125rem; hover tint 26%; all-day bar tint 28%; weekend tint = 3% content-mix; adjacent-month days 40% opacity; `scrollTime: '07:30'`; businessHours Mon–Fri 08:00–18:00; now indicator uses `--color-error`.
- **Keyboard map exact (spec §6):** `T` today · `←`/`→` prev/next · `M`/`W`/`D`/`L` views · `N`/`C` new event · `Esc` closes topmost (peek → scope dialog → modal → drawer). Suppressed while typing (input/textarea/select/contenteditable) — except Esc.
- **localStorage key:** `eldrin-calendar:sidebar` storing `'open' | 'closed'`.
- **Branches:** eldrin-core work on `feature/full-width-app-layout` (from main), eldrin-calendar work on `feature/ux-overhaul` (from main). Conventional commits.
- **Gates:** eldrin-core → `npm run test:run` + `npx tsc -b --noEmit 2>/dev/null || npm run build`; eldrin-calendar → `npx tsc -b && npm run build && npx vitest run` (worker suite stays 70/70; UI has no unit harness — Task 7 is the visual gate).
- **Working directories:** Task 1 in `/Users/tibor/projects/eldrin-backup/eldrin-core`; Tasks 2–6 in `/Users/tibor/projects/eldrin-backup/eldrin-calendar`. `cd` persists between Bash calls — prefer absolute paths / `git -C`.

## File Structure

**eldrin-core** (Task 1): `src/types/manifest.ts` (ui.layout field), `src/layouts/layout-mode.ts` (+ test — pure resolver; core's vitest is node-env, no jsdom, so Shell itself is validated live), `src/layouts/Shell.tsx` (conditional wrapper).

**eldrin-calendar** (Tasks 2–6):
```
public/eldrin-app.manifest.json      — ui.layout: "full-width"           (Task 2)
src/root.component.tsx               — frame, view state, peek wiring     (Tasks 2,3,5,6)
src/components/CalendarToolbar.tsx   — NEW toolbar row                    (Task 2)
src/components/CalendarCanvas.tsx    — ref API, height 100%, chips        (Tasks 2,4,5)
src/components/CalendarSidebar.tsx   — REWRITE: collapse/drawer + mini nav (Task 3)
src/components/MiniMonthNav.tsx      — NEW compact month grid             (Task 3)
src/components/EventPeek.tsx         — NEW anchored peek card             (Task 5)
src/hooks/useKeyboardShortcuts.ts    — NEW                                 (Task 6)
src/api.ts                           — + updateCalendar helper            (Task 3)
src/index.css                        — extended .cal-root design block    (Tasks 2,4)
src/main.tsx                         — standalone topbar-var fallback     (Task 2)
```

**Reference files (read, don't modify):** `eldrin-core/src/layouts/Shell.tsx` current state (wrapper at line 58), `eldrin-core/src/stores/appRegistry.ts` (AppRegistration.manifest), `eldrin-core/src/types/manifest.ts` (ui block at ~198), calendar's existing components.

---

### Task 1: eldrin-core — `ui.layout` flag + full-width Shell wrapper

**Files:**
- Modify: `src/types/manifest.ts` (ui block, ~line 198)
- Create: `src/layouts/layout-mode.ts`
- Test: `src/layouts/layout-mode.test.ts`
- Modify: `src/layouts/Shell.tsx`

**Interfaces:**
- Produces: `resolveLayoutMode(apps: Iterable<AppLayoutSource>, pathname: string): LayoutMode` where `type LayoutMode = 'default' | 'full-width'` and `interface AppLayoutSource { id: string; manifest?: { ui?: { layout?: string } } }`. Shell renders wrapper class `'w-full'` (full-width) vs `'p-6 max-w-[1440px] mx-auto'` (default).

- [ ] **Step 1: Branch**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-core
git checkout main && git pull && git checkout -b feature/full-width-app-layout
npm run test:run 2>&1 | tail -3   # baseline green before touching anything
```

- [ ] **Step 2: Write the failing test**

`src/layouts/layout-mode.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { resolveLayoutMode } from './layout-mode';

const app = (id: string, layout?: string) => ({
  id,
  manifest: layout ? { ui: { layout } } : { ui: {} },
});

describe('resolveLayoutMode', () => {
  it('returns full-width when the active app declares it', () => {
    const apps = [app('eldrin-crm'), app('eldrin-calendar', 'full-width')];
    expect(resolveLayoutMode(apps, '/eldrin-calendar')).toBe('full-width');
    expect(resolveLayoutMode(apps, '/eldrin-calendar/settings')).toBe('full-width');
  });

  it('returns default for apps without the flag and for unknown values', () => {
    const apps = [app('eldrin-crm'), app('eldrin-email', 'banana')];
    expect(resolveLayoutMode(apps, '/eldrin-crm')).toBe('default');
    expect(resolveLayoutMode(apps, '/eldrin-email')).toBe('default');
  });

  it('returns default for non-app routes and empty registry', () => {
    expect(resolveLayoutMode([app('eldrin-calendar', 'full-width')], '/settings')).toBe('default');
    expect(resolveLayoutMode([], '/eldrin-calendar')).toBe('default');
  });

  it('does not prefix-match across path segment boundaries', () => {
    const apps = [app('eldrin-cal', 'full-width')];
    expect(resolveLayoutMode(apps, '/eldrin-calendar')).toBe('default');
  });

  it('handles apps with no manifest at all', () => {
    expect(resolveLayoutMode([{ id: 'bare' }], '/bare')).toBe('default');
  });
});
```

- [ ] **Step 3: Run to verify failure**

Run: `npx vitest run src/layouts/layout-mode.test.ts`
Expected: FAIL — cannot find module './layout-mode'.

- [ ] **Step 4: Implement `src/layouts/layout-mode.ts`**

```ts
/**
 * Per-app content layout (spec: eldrin-calendar UX overhaul, U1).
 * An app opts into edge-to-edge rendering via manifest `ui.layout: "full-width"`;
 * everything else keeps the classic centered 1440px container.
 */

export type LayoutMode = 'default' | 'full-width';

export interface AppLayoutSource {
  id: string;
  manifest?: { ui?: { layout?: string } };
}

export function resolveLayoutMode(
  apps: Iterable<AppLayoutSource>,
  pathname: string,
): LayoutMode {
  for (const app of apps) {
    const base = `/${app.id}`;
    if (pathname === base || pathname.startsWith(`${base}/`)) {
      return app.manifest?.ui?.layout === 'full-width' ? 'full-width' : 'default';
    }
  }
  return 'default';
}
```

- [ ] **Step 5: Run to verify pass** — `npx vitest run src/layouts/layout-mode.test.ts` → 5 passed.

- [ ] **Step 6: Add the manifest type field**

In `src/types/manifest.ts`, inside the `ui?: { ... }` block (after `sideNav?: SideNavItem[];`):
```ts
    /** Content layout: 'full-width' drops the shell's 1440px cap + padding for this app. */
    layout?: 'default' | 'full-width';
```

- [ ] **Step 7: Wire Shell.tsx**

Add the import and compute the mode (after the existing `showAppContainer` memo):
```tsx
import { resolveLayoutMode } from './layout-mode';
```
```tsx
  const layoutMode = useMemo(
    () => resolveLayoutMode(apps.values(), location.pathname),
    [apps, location.pathname],
  );
```
Replace the content wrapper line `<div className="p-6 max-w-[1440px] mx-auto">` with:
```tsx
        <div className={layoutMode === 'full-width' ? 'w-full' : 'p-6 max-w-[1440px] mx-auto'}>
```
Nothing else in Shell.tsx changes. (While manifests are still loading, `apps` is empty → resolver returns `'default'` — the spec's accepted first-paint fallback.)

- [ ] **Step 8: Gates + commit**

```bash
npm run test:run 2>&1 | tail -3     # whole suite green (baseline + 5 new)
npm run build 2>&1 | tail -2        # build clean
git add src/types/manifest.ts src/layouts/layout-mode.ts src/layouts/layout-mode.test.ts src/layouts/Shell.tsx
git commit -m "feat: opt-in full-width app layout via manifest ui.layout flag"
```

---

### Task 2: eldrin-calendar — viewport frame + custom toolbar

**Files:**
- Modify: `public/eldrin-app.manifest.json`, `src/root.component.tsx`, `src/components/CalendarCanvas.tsx`, `src/index.css`, `src/main.tsx`
- Create: `src/components/CalendarToolbar.tsx`

**Interfaces:**
- Consumes: nothing new (Task 1 is a different repo; dev shell picks the flag up at runtime).
- Produces (later tasks rely on): `CalendarToolbar` props exactly as below; `CalendarCanvas` props gain `calendarRef: React.RefObject<FullCalendar | null>` and `onDatesSet(info: CanvasDatesInfo)` replaces `onRangeChange`, where `interface CanvasDatesInfo { startMs: number; endMs: number; title: string; viewType: string; anchorMs: number }` (anchorMs = `view.currentStart` — the mini-nav sync point). Root state: `viewInfo: CanvasDatesInfo | null`, `sidebarOpen: boolean`. Helper `nextRoundHour(now?: Date): { startAt: number; endAt: number }` exported from `src/components/CalendarToolbar.tsx`.

- [ ] **Step 1: Branch**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-calendar
git checkout main && git pull && git checkout -b feature/ux-overhaul
npx vitest run 2>&1 | tail -3   # 70/70 baseline
```

- [ ] **Step 2: Manifest flag**

In `public/eldrin-app.manifest.json`, change the `ui` block to:
```json
  "ui": {
    "layout": "full-width",
    "sideNav": [ { "label": "Calendar", "icon": "calendar", "path": "/eldrin-calendar" } ]
  },
```

- [ ] **Step 3: Write `src/components/CalendarToolbar.tsx`**

```tsx
export const VIEWS = [
  { type: 'dayGridMonth', label: 'Month', key: 'M' },
  { type: 'timeGridWeek', label: 'Week', key: 'W' },
  { type: 'timeGridDay', label: 'Day', key: 'D' },
  { type: 'listWeek', label: 'List', key: 'L' },
] as const;

export type ViewType = (typeof VIEWS)[number]['type'];

/** Next full hour from `now`, 1h duration — seed for the New-event modal. */
export function nextRoundHour(now: Date = new Date()): { startAt: number; endAt: number } {
  const start = new Date(now);
  start.setMinutes(0, 0, 0);
  start.setHours(start.getHours() + 1);
  return { startAt: start.getTime(), endAt: start.getTime() + 3600000 };
}

interface CalendarToolbarProps {
  title: string;
  viewType: string;
  sidebarOpen: boolean;
  onToggleSidebar: () => void;
  onNewEvent: () => void;
  onToday: () => void;
  onPrev: () => void;
  onNext: () => void;
  onChangeView: (view: ViewType) => void;
}

export function CalendarToolbar({
  title, viewType, sidebarOpen,
  onToggleSidebar, onNewEvent, onToday, onPrev, onNext, onChangeView,
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
      <div className="join">
        {VIEWS.map((v) => (
          <button
            key={v.type}
            className={`btn btn-sm join-item ${viewType === v.type ? 'btn-active' : 'btn-ghost'}`}
            onClick={() => onChangeView(v.type)}
          >
            {v.label}
          </button>
        ))}
      </div>
    </div>
  );
}
```

- [ ] **Step 4: Rework `src/components/CalendarCanvas.tsx`**

Full replacement (chip rendering lands in Task 4; this step is the structural change):
```tsx
import type { RefObject } from 'react';
import FullCalendar from '@fullcalendar/react';
import dayGridPlugin from '@fullcalendar/daygrid';
import timeGridPlugin from '@fullcalendar/timegrid';
import listPlugin from '@fullcalendar/list';
import interactionPlugin from '@fullcalendar/interaction';
import type { DateSelectArg, EventClickArg, EventDropArg, DatesSetArg } from '@fullcalendar/core';
import type { EventResizeDoneArg } from '@fullcalendar/interaction';
import type { Occurrence } from '../api';

export interface CanvasDatesInfo {
  startMs: number;
  endMs: number;
  title: string;
  viewType: string;
  anchorMs: number;
}

interface CalendarCanvasProps {
  calendarRef: RefObject<FullCalendar | null>;
  occurrences: Occurrence[];
  onDatesSet: (info: CanvasDatesInfo) => void;
  onSelectSlot: (startMs: number, endMs: number, allDay: boolean) => void;
  onSelectEvent: (occ: Occurrence, anchor: DOMRect) => void;
  onMoveResize: (occ: Occurrence, newStartMs: number, newEndMs: number, revert: () => void) => void;
}

export function CalendarCanvas({
  calendarRef, occurrences, onDatesSet, onSelectSlot, onSelectEvent, onMoveResize,
}: CalendarCanvasProps) {
  const events = occurrences.map((o) => ({
    id: o.id,
    title: o.title,
    start: new Date(o.startAt),
    end: new Date(o.endAt),
    allDay: o.allDay,
    extendedProps: { occ: o },
  }));

  function handleDropOrResize(arg: EventDropArg | EventResizeDoneArg) {
    const occ = arg.event.extendedProps.occ as Occurrence;
    const start = arg.event.start?.getTime();
    const end = arg.event.end?.getTime() ?? (start !== undefined ? start + (occ.endAt - occ.startAt) : undefined);
    if (start === undefined || end === undefined) {
      arg.revert();
      return;
    }
    onMoveResize(occ, start, end, arg.revert);
  }

  return (
    <div className="cal-root flex-1 min-w-0 min-h-0 px-3 pb-3">
      <FullCalendar
        ref={calendarRef}
        plugins={[dayGridPlugin, timeGridPlugin, listPlugin, interactionPlugin]}
        initialView="dayGridMonth"
        headerToolbar={false}
        firstDay={1}
        events={events}
        selectable
        selectMirror
        editable
        dayMaxEvents
        height="100%"
        nowIndicator
        scrollTime="07:30:00"
        businessHours={{ daysOfWeek: [1, 2, 3, 4, 5], startTime: '08:00', endTime: '18:00' }}
        eventDidMount={(info) => {
          const occ = info.event.extendedProps.occ as Occurrence | undefined;
          if (occ) info.el.style.setProperty('--chip', occ.color);
        }}
        datesSet={(arg: DatesSetArg) =>
          onDatesSet({
            startMs: arg.start.getTime(),
            endMs: arg.end.getTime(),
            title: arg.view.title,
            viewType: arg.view.type,
            anchorMs: arg.view.currentStart.getTime(),
          })
        }
        select={(arg: DateSelectArg) => onSelectSlot(arg.start.getTime(), arg.end.getTime(), arg.allDay)}
        eventClick={(arg: EventClickArg) =>
          onSelectEvent(arg.event.extendedProps.occ as Occurrence, arg.el.getBoundingClientRect())
        }
        eventDrop={handleDropOrResize}
        eventResize={handleDropOrResize}
      />
    </div>
  );
}
```
Note: `backgroundColor`/`borderColor` props are gone — Task 4's CSS owns chip appearance via `--chip`. Until Task 4 lands, events render in FullCalendar's default blue; that's expected mid-branch state.

- [ ] **Step 5: Rework `src/root.component.tsx` frame**

Keep ALL existing data/handler logic (loadCalendars, refreshEvents, resolveScopeTarget, patchOccurrence, deleteOccurrence, saveModal, deleteFromModal, theme bridge, modal/scopeAsk rendering) unchanged unless named here. Apply these changes:

1. New imports:
```tsx
import FullCalendar from '@fullcalendar/react';
import { CalendarToolbar, nextRoundHour, type ViewType } from './components/CalendarToolbar';
import type { CanvasDatesInfo } from './components/CalendarCanvas';
```
2. New state/refs (replace `const [range, setRange] = ...`):
```tsx
  const calendarRef = useRef<FullCalendar | null>(null);
  const [viewInfo, setViewInfo] = useState<CanvasDatesInfo | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(
    () => localStorage.getItem('eldrin-calendar:sidebar') !== 'closed',
  );
  useEffect(() => {
    localStorage.setItem('eldrin-calendar:sidebar', sidebarOpen ? 'open' : 'closed');
  }, [sidebarOpen]);
```
3. `refreshEvents` reads `viewInfo` instead of `range`:
```tsx
  const refreshEvents = useCallback(async () => {
    if (!viewInfo) return;
    try {
      const ids = [...enabledIds];
      const res = await api.listEvents(apiBase, headersRef.current, viewInfo.startMs, viewInfo.endMs, ids);
      setOccurrences(ids.length === 0 ? [] : res.occurrences);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load events');
    }
  }, [apiBase, viewInfo, enabledIds]);
```
4. Toolbar handlers (FullCalendar imperative API):
```tsx
  const calApi = () => calendarRef.current?.getApi();
  const handleToday = () => calApi()?.today();
  const handlePrev = () => calApi()?.prev();
  const handleNext = () => calApi()?.next();
  const handleChangeView = (view: ViewType) => calApi()?.changeView(view);
  const handleNewEvent = () => {
    const seed = nextRoundHour();
    handleSelectSlot(seed.startAt, seed.endAt, false);
  };
```
5. New render frame (replace the current outer `<div data-theme=... className="p-4 flex gap-6">` structure; modal/scopeAsk blocks stay as siblings inside the root div):
```tsx
  return (
    <div
      data-theme={daisyTheme}
      className="flex flex-col overflow-hidden bg-base-100"
      style={{ height: 'calc(100dvh - var(--layout-topbar-height, 0px))' }}
    >
      <CalendarToolbar
        title={viewInfo?.title ?? ''}
        viewType={viewInfo?.viewType ?? 'dayGridMonth'}
        sidebarOpen={sidebarOpen}
        onToggleSidebar={() => setSidebarOpen((o) => !o)}
        onNewEvent={handleNewEvent}
        onToday={handleToday}
        onPrev={handlePrev}
        onNext={handleNext}
        onChangeView={handleChangeView}
      />
      <div className="flex-1 flex min-h-0">
        {sidebarOpen && (
          <div className="w-[264px] shrink-0 border-r border-base-300 overflow-y-auto p-3">
            <CalendarSidebar
              calendars={calendars}
              enabledIds={enabledIds}
              onToggle={handleToggle}
              onCreate={handleCreateCalendar}
              onDelete={handleDeleteCalendar}
            />
          </div>
        )}
        <div className="flex-1 min-w-0 flex flex-col">
          {error && <div className="alert alert-error text-sm m-3 mb-0">{error}</div>}
          <CalendarCanvas
            calendarRef={calendarRef}
            occurrences={occurrences}
            onDatesSet={setViewInfo}
            onSelectSlot={handleSelectSlot}
            onSelectEvent={handleSelectEvent}
            onMoveResize={handleMoveResize}
          />
        </div>
      </div>
      {/* modal + scopeAsk blocks unchanged */}
    </div>
  );
```
`handleSelectEvent` gains the anchor param but ignores it until Task 5: `const handleSelectEvent = async (occ: Occurrence, _anchor?: DOMRect) => { ... }` (existing body unchanged). Task 3 replaces the inline sidebar wrapper with the rewritten component's own collapse/drawer handling — the temporary `{sidebarOpen && ...}` wrapper here is deliberate scaffolding.

6. In `src/main.tsx` (standalone dev only), set the topbar var to zero on a wrapper so the frame fills the whole window: wrap `<Root />` as
```tsx
<div style={{ ['--layout-topbar-height' as string]: '0px' }}>
  <Root />
</div>
```

7. In `src/index.css`, update the `.cal-root .fc` font-size line to `0.9375rem` (spec token; rest of the design block lands in Task 4).

- [ ] **Step 6: Gates**

```bash
npx tsc -b && npm run build 2>&1 | tail -2 && npx vitest run 2>&1 | tail -3
```
Expected: clean, 70/70. Quick standalone smoke: `npm run dev` → calendar fills the window height with the new toolbar; stop the server.

- [ ] **Step 7: Commit**

```bash
git add public/eldrin-app.manifest.json src/
git commit -m "feat: full-width viewport frame with custom toolbar (manifest flag, height 100%, imperative nav)"
```

---

### Task 3: Sidebar rewrite — collapse/drawer, mini month nav, calendar actions

**Files:**
- Create: `src/components/MiniMonthNav.tsx`
- Modify: `src/components/CalendarSidebar.tsx` (rewrite), `src/root.component.tsx` (sidebar wiring), `src/api.ts` (+updateCalendar)

**Interfaces:**
- Consumes: `viewInfo: CanvasDatesInfo | null`, `calApi()` navigation from Task 2.
- Produces:
  - `MiniMonthNav` props: `{ anchorMs: number; rangeStartMs: number; rangeEndMs: number; onSelectDay: (dayStartMs: number) => void }`
  - `CalendarSidebar` props: `{ open: boolean; isDrawer: boolean; onClose: () => void; calendars: Calendar[]; enabledIds: Set<string>; onToggle: (id: string) => void; onCreate: (name: string, color: string) => Promise<void>; onUpdate: (id: string, patch: { name?: string; color?: string }) => Promise<void>; onDelete: (id: string) => Promise<void>; miniNav: React.ReactNode }` — the sidebar owns its container (width transition inline, drawer overlay below lg).
  - `api.updateCalendar(base: string, h: Headers, id: string, patch: { name?: string; color?: string }): Promise<{ calendar: Calendar }>`

- [ ] **Step 1: Add the api helper** in `src/api.ts` next to `createCalendar`:

```ts
export const updateCalendar = (
  base: string, h: Headers, id: string, patch: { name?: string; color?: string },
) =>
  request<{ calendar: Calendar }>(apiUrl(base, `/calendars/${id}`), h, {
    method: 'PATCH', body: JSON.stringify(patch),
  });
```

- [ ] **Step 2: Write `src/components/MiniMonthNav.tsx`**

```tsx
import { useEffect, useState } from 'react';

interface MiniMonthNavProps {
  anchorMs: number;        // main view's currentStart — keeps mini nav in sync
  rangeStartMs: number;    // visible range of the main grid (highlight)
  rangeEndMs: number;
  onSelectDay: (dayStartMs: number) => void;
}

const WEEKDAYS = ['M', 'T', 'W', 'T', 'F', 'S', 'S']; // firstDay=1 (Monday), matches the grid

function monthStart(ms: number): Date {
  const d = new Date(ms);
  return new Date(d.getFullYear(), d.getMonth(), 1);
}

export function MiniMonthNav({ anchorMs, rangeStartMs, rangeEndMs, onSelectDay }: MiniMonthNavProps) {
  const [month, setMonth] = useState(() => monthStart(anchorMs));
  // Follow the main view when it navigates (but keep manual paging independent until then).
  useEffect(() => setMonth(monthStart(anchorMs)), [anchorMs]);

  const first = new Date(month);
  // Offset to the Monday on/before the 1st.
  const lead = (first.getDay() + 6) % 7;
  const gridStart = new Date(first);
  gridStart.setDate(1 - lead);

  const todayKey = new Date().toDateString();
  const cells = Array.from({ length: 42 }, (_, i) => {
    const d = new Date(gridStart);
    d.setDate(gridStart.getDate() + i);
    return d;
  });

  const label = month.toLocaleDateString(undefined, { month: 'long', year: 'numeric' });
  const page = (delta: number) =>
    setMonth((m) => new Date(m.getFullYear(), m.getMonth() + delta, 1));

  return (
    <div className="mb-4 select-none">
      <div className="flex items-center justify-between mb-1 px-1">
        <span className="text-sm font-medium">{label}</span>
        <span className="flex">
          <button className="btn btn-ghost btn-xs btn-square" aria-label="Previous month" onClick={() => page(-1)}>‹</button>
          <button className="btn btn-ghost btn-xs btn-square" aria-label="Next month" onClick={() => page(1)}>›</button>
        </span>
      </div>
      <div className="grid grid-cols-7 text-center">
        {WEEKDAYS.map((w, i) => (
          <span key={i} className="text-[0.625rem] text-base-content/40 font-medium py-1">{w}</span>
        ))}
        {cells.map((d) => {
          const ms = d.getTime();
          const inMonth = d.getMonth() === month.getMonth();
          const inRange = ms >= rangeStartMs && ms < rangeEndMs;
          const isToday = d.toDateString() === todayKey;
          return (
            <button
              key={ms}
              onClick={() => onSelectDay(ms)}
              className={[
                'h-6 w-6 mx-auto my-px rounded-full text-[0.6875rem] leading-6',
                isToday
                  ? 'bg-primary text-primary-content font-semibold'
                  : inRange
                    ? 'bg-primary/10 text-base-content'
                    : inMonth
                      ? 'text-base-content hover:bg-base-200'
                      : 'text-base-content/35 hover:bg-base-200',
              ].join(' ')}
            >
              {d.getDate()}
            </button>
          );
        })}
      </div>
    </div>
  );
}
```

- [ ] **Step 3: Rewrite `src/components/CalendarSidebar.tsx`**

```tsx
import { useState, type ReactNode } from 'react';
import type { Calendar } from '../api';

interface CalendarSidebarProps {
  open: boolean;
  isDrawer: boolean;
  onClose: () => void;
  calendars: Calendar[];
  enabledIds: Set<string>;
  onToggle: (id: string) => void;
  onCreate: (name: string, color: string) => Promise<void>;
  onUpdate: (id: string, patch: { name?: string; color?: string }) => Promise<void>;
  onDelete: (id: string) => Promise<void>;
  miniNav: ReactNode;
}

export const PALETTE = ['#4f6df5', '#16a34a', '#f59e0b', '#dc2626', '#8b5cf6', '#0d9488'];

function ColorDots({ value, onPick }: { value: string; onPick: (c: string) => void }) {
  return (
    <div className="flex gap-1">
      {PALETTE.map((p) => (
        <button
          key={p}
          className={`w-5 h-5 rounded-full border-2 ${value === p ? 'border-base-content' : 'border-transparent'}`}
          style={{ backgroundColor: p }}
          aria-label={p}
          onClick={() => onPick(p)}
        />
      ))}
    </div>
  );
}

/** One calendar row with hover actions; editing swaps to an inline form. */
function CalendarRow({
  cal, enabled, onToggle, onUpdate, onDelete,
}: {
  cal: Calendar;
  enabled: boolean;
  onToggle: () => void;
  onUpdate: (patch: { name?: string; color?: string }) => Promise<void>;
  onDelete: () => Promise<void>;
}) {
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(cal.name);
  const [color, setColor] = useState(cal.color);
  const [busy, setBusy] = useState(false);

  async function save() {
    if (!name.trim() || busy) return;
    setBusy(true);
    try {
      await onUpdate({ name: name.trim(), color });
      setEditing(false);
    } finally {
      setBusy(false);
    }
  }

  if (editing) {
    return (
      <li className="space-y-2 py-1">
        <input
          className="input input-bordered input-xs w-full"
          value={name}
          maxLength={100}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && save()}
        />
        <ColorDots value={color} onPick={setColor} />
        <div className="flex gap-2">
          <button className="btn btn-primary btn-xs" disabled={busy} onClick={save}>Save</button>
          <button className="btn btn-ghost btn-xs" onClick={() => setEditing(false)}>Cancel</button>
        </div>
      </li>
    );
  }

  return (
    <li className="flex items-center gap-2 text-sm group min-h-7">
      <input type="checkbox" className="checkbox checkbox-xs" checked={enabled} onChange={onToggle} />
      <span className="w-3 h-3 rounded-full shrink-0" style={{ backgroundColor: cal.color }} />
      <span className="truncate flex-1">{cal.name}</span>
      <span className="hidden group-hover:flex gap-0.5">
        <button className="btn btn-ghost btn-xs btn-square" aria-label={`Edit ${cal.name}`} onClick={() => setEditing(true)}>✎</button>
        {!cal.isDefault && (
          <button className="btn btn-ghost btn-xs btn-square" aria-label={`Delete ${cal.name}`} onClick={() => void onDelete()}>✕</button>
        )}
      </span>
    </li>
  );
}

export function CalendarSidebar({
  open, isDrawer, onClose, calendars, enabledIds,
  onToggle, onCreate, onUpdate, onDelete, miniNav,
}: CalendarSidebarProps) {
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState('');
  const [color, setColor] = useState(PALETTE[0]);
  const [busy, setBusy] = useState(false);

  async function submit() {
    if (!name.trim() || busy) return;
    setBusy(true);
    try {
      await onCreate(name.trim(), color);
      setName('');
      setAdding(false);
    } finally {
      setBusy(false);
    }
  }

  const panel = (
    <div className="w-[264px] h-full border-r border-base-300 overflow-y-auto p-3 bg-base-100">
      {miniNav}
      <h2 className="cal-eyebrow mb-2">Calendars</h2>
      <ul className="space-y-1">
        {calendars.map((cal) => (
          <CalendarRow
            key={cal.id}
            cal={cal}
            enabled={enabledIds.has(cal.id)}
            onToggle={() => onToggle(cal.id)}
            onUpdate={(patch) => onUpdate(cal.id, patch)}
            onDelete={() => onDelete(cal.id)}
          />
        ))}
      </ul>
      {adding ? (
        <div className="space-y-2 mt-2">
          <input
            className="input input-bordered input-sm w-full"
            placeholder="Calendar name"
            value={name}
            maxLength={100}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && submit()}
          />
          <ColorDots value={color} onPick={setColor} />
          <div className="flex gap-2">
            <button className="btn btn-primary btn-xs" disabled={busy} onClick={submit}>Add</button>
            <button className="btn btn-ghost btn-xs" onClick={() => setAdding(false)}>Cancel</button>
          </div>
        </div>
      ) : (
        <button className="btn btn-ghost btn-xs mt-2" onClick={() => setAdding(true)}>+ New calendar</button>
      )}
    </div>
  );

  if (isDrawer) {
    if (!open) return null;
    return (
      <div className="fixed inset-0 z-40" style={{ top: 'var(--layout-topbar-height, 0px)' }}>
        <div className="absolute inset-0 bg-black/30" onClick={onClose} />
        <div className="absolute left-0 top-0 bottom-0 shadow-xl">{panel}</div>
      </div>
    );
  }

  return (
    <div
      className="shrink-0 overflow-hidden transition-[width] duration-200 ease-out"
      style={{ width: open ? 264 : 0 }}
    >
      {panel}
    </div>
  );
}
```

- [ ] **Step 4: Wire in `src/root.component.tsx`**

1. Replace Task 2's temporary `{sidebarOpen && (<div className="w-[264px] ...">…</div>)}` wrapper with:
```tsx
        <CalendarSidebar
          open={sidebarOpen}
          isDrawer={isNarrow}
          onClose={() => setSidebarOpen(false)}
          calendars={calendars}
          enabledIds={enabledIds}
          onToggle={handleToggle}
          onCreate={handleCreateCalendar}
          onUpdate={handleUpdateCalendar}
          onDelete={handleDeleteCalendar}
          miniNav={
            viewInfo && (
              <MiniMonthNav
                anchorMs={viewInfo.anchorMs}
                rangeStartMs={viewInfo.startMs}
                rangeEndMs={viewInfo.endMs}
                onSelectDay={(ms) => {
                  calApi()?.gotoDate(new Date(ms));
                  if (isNarrow) setSidebarOpen(false);
                }}
              />
            )
          }
        />
```
2. Add the narrow-viewport hook + update handler:
```tsx
  const [isNarrow, setIsNarrow] = useState(() => !window.matchMedia('(min-width: 1024px)').matches);
  useEffect(() => {
    const mq = window.matchMedia('(min-width: 1024px)');
    const onChange = () => setIsNarrow(!mq.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);

  const handleUpdateCalendar = async (id: string, patch: { name?: string; color?: string }) => {
    await api.updateCalendar(apiBase, headersRef.current, id, patch);
    await loadCalendars();
    await refreshEvents(); // color changes affect chips
  };
```
3. Imports: `MiniMonthNav`; default sidebar state on narrow screens starts closed:
```tsx
  const [sidebarOpen, setSidebarOpen] = useState(() => {
    const stored = localStorage.getItem('eldrin-calendar:sidebar');
    if (stored) return stored !== 'closed';
    return window.matchMedia('(min-width: 1024px)').matches;
  });
```

- [ ] **Step 5: Gates + commit**

```bash
npx tsc -b && npm run build 2>&1 | tail -2 && npx vitest run 2>&1 | tail -3
git add src/
git commit -m "feat: collapsible sidebar with mini month navigator and calendar edit actions"
```
Standalone smoke: toggle collapse (animates, persists across reload), mini-nav day click moves the main grid.

---

### Task 4: Visual redesign — chips, popover, grid polish (all views)

**Files:**
- Modify: `src/components/CalendarCanvas.tsx` (eventContent renderer), `src/index.css` (the design block)

**Interfaces:**
- Consumes: `--chip` custom property set per event by Task 2's `eventDidMount`.
- Produces: final visual layer; no API changes.

Design authority: spec §5 (tokens are binding). For sensibility while adjusting details, read the frontend-design skill at `/Users/tibor/.claude/plugins/cache/claude-plugins-official/frontend-design/unknown/skills/frontend-design/SKILL.md` — but do NOT invent different tokens; the spec already made the choices.

- [ ] **Step 1: Add the chip content renderer** to `CalendarCanvas.tsx`

Add above the component:
```tsx
import type { EventContentArg } from '@fullcalendar/core';

/** Chip body: tabular time + weight-500 title (month/week); list view keeps FC's layout. */
function renderEventContent(arg: EventContentArg) {
  if (arg.view.type === 'listWeek') return true; // default rendering, restyled via CSS
  const occ = arg.event.extendedProps.occ as Occurrence | undefined;
  const showTime = !arg.event.allDay && arg.timeText;
  return (
    <div className="cal-chip" title={arg.event.title + (occ?.location ? ` · ${occ.location}` : '')}>
      {showTime && <span className="cal-chip-time">{arg.timeText}</span>}
      <span className="cal-chip-title">{arg.event.title}</span>
    </div>
  );
}
```
and pass to FullCalendar: `eventContent={renderEventContent}` plus `eventTimeFormat={{ hour: '2-digit', minute: '2-digit', hour12: false }}` and `displayEventEnd={false}`.

- [ ] **Step 2: Replace the `.cal-root` block in `src/index.css`**

Replace everything from `.cal-root {` through the current `[data-theme='eldrin-dark'] .cal-root { ... }` block with:

```css
/* ─── FullCalendar ⇄ Quiet Ledger (spec §5) ─────────────────────────────── */
.cal-root {
  --fc-border-color: color-mix(in oklab, var(--color-base-300) 60%, transparent);
  --fc-page-bg-color: var(--color-base-100);
  --fc-neutral-bg-color: var(--color-base-200);
  --fc-neutral-text-color: var(--color-base-content);
  --fc-today-bg-color: transparent; /* today is marked by the day-number badge instead */
  --fc-event-border-color: transparent;
  --fc-event-text-color: var(--color-base-content);
  --fc-list-event-hover-bg-color: var(--color-base-200);
  --fc-highlight-color: color-mix(in oklab, var(--color-primary) 15%, transparent);
  --fc-now-indicator-color: var(--color-error);
  --fc-non-business-color: color-mix(in oklab, var(--color-base-content) 3%, transparent);
  --fc-more-link-bg-color: transparent;
  --fc-more-link-text-color: var(--color-primary);
}
.cal-root .fc { font-size: 0.9375rem; }

/* Weekday header: eyebrow treatment */
.cal-root .fc .fc-col-header-cell-cushion {
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: color-mix(in oklab, var(--color-base-content) 55%, transparent);
  padding: 6px 4px;
}

/* Day numbers + today badge + adjacent-month dimming + weekend tint */
.cal-root .fc .fc-daygrid-day-number {
  font-size: 0.8125rem;
  font-weight: 500;
  padding: 4px 6px;
}
.cal-root .fc .fc-day-today .fc-daygrid-day-number {
  background: var(--color-primary);
  color: var(--color-primary-content);
  border-radius: 9999px;
  min-width: 1.5rem;
  height: 1.5rem;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 0 0.375rem;
  margin: 2px;
}
.cal-root .fc .fc-day-other .fc-daygrid-day-top { opacity: 0.4; }
.cal-root .fc .fc-daygrid-day.fc-day-sat,
.cal-root .fc .fc-daygrid-day.fc-day-sun {
  background: color-mix(in oklab, var(--color-base-content) 3%, transparent);
}

/* Event chips: tinted bg + 3px accent, theme-safe text */
.cal-root .fc .fc-daygrid-event,
.cal-root .fc .fc-timegrid-event {
  background: color-mix(in oklab, var(--chip, var(--color-primary)) 16%, var(--color-base-100));
  border: none;
  border-left: 3px solid var(--chip, var(--color-primary));
  border-radius: 4px;
  margin-bottom: 1px;
}
.cal-root .fc .fc-daygrid-event:hover,
.cal-root .fc .fc-timegrid-event:hover {
  background: color-mix(in oklab, var(--chip, var(--color-primary)) 26%, var(--color-base-100));
}
.cal-root .fc .fc-daygrid-block-event, /* all-day / multi-day bars */
.cal-root .fc .fc-daygrid-event.fc-event-start.fc-event-end.fc-daygrid-block-event {
  background: color-mix(in oklab, var(--chip, var(--color-primary)) 28%, var(--color-base-100));
}
.cal-chip {
  display: flex;
  gap: 4px;
  align-items: baseline;
  padding: 1px 4px;
  min-height: 18px;
  overflow: hidden;
  white-space: nowrap;
  font-size: 0.8125rem;
  color: var(--color-base-content);
}
.cal-chip-time {
  font-variant-numeric: tabular-nums;
  opacity: 0.7;
  font-size: 0.75rem;
  flex-shrink: 0;
}
.cal-chip-title { font-weight: 500; overflow: hidden; text-overflow: ellipsis; }
.cal-root .fc .fc-timegrid-event .cal-chip { white-space: normal; flex-direction: column; gap: 0; align-items: flex-start; }

/* "+N more" + day popover */
.cal-root .fc .fc-daygrid-more-link {
  font-size: 0.75rem;
  font-weight: 500;
  color: var(--color-primary);
}
.cal-root .fc .fc-daygrid-more-link:hover { text-decoration: underline; background: transparent; }
.cal-root .fc .fc-popover {
  background: var(--color-base-100);
  border: 1px solid var(--color-base-300);
  border-radius: 0.625rem;
  box-shadow: 0 4px 16px rgb(0 0 0 / 0.08);
}
.cal-root .fc .fc-popover-header {
  background: var(--color-base-200);
  border-radius: 0.625rem 0.625rem 0 0;
  font-size: 0.8125rem;
  font-weight: 600;
  padding: 6px 10px;
}

/* Week/day: slot labels + hairlines */
.cal-root .fc .fc-timegrid-slot-label-cushion {
  font-variant-numeric: tabular-nums;
  font-size: 0.75rem;
  color: color-mix(in oklab, var(--color-base-content) 55%, transparent);
}
.cal-root .fc .fc-timegrid-slot-minor {
  border-top-color: color-mix(in oklab, var(--color-base-300) 40%, transparent);
}

/* List view */
.cal-root .fc .fc-list { border: 1px solid var(--color-base-300); border-radius: 0.625rem; overflow: hidden; }
.cal-root .fc .fc-list-day-cushion {
  background: var(--color-base-200);
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: color-mix(in oklab, var(--color-base-content) 55%, transparent);
}
.cal-root .fc .fc-list-event td { font-size: 0.875rem; }
.cal-root .fc .fc-list-event-dot { border-color: var(--chip, var(--color-primary)); }

[data-theme='eldrin-dark'] .cal-root .fc .fc-popover { box-shadow: 0 4px 20px rgb(0 0 0 / 0.5); }
```

Note: chips inherit `--chip` from the harness element (`eventDidMount` sets it on `info.el`) — verify the selector applies to the element that carries the variable; if FullCalendar nests the harness differently in a view, move the `style.setProperty` target or selector accordingly and note it in the report.

- [ ] **Step 3: Gates + visual smoke + commit**

```bash
npx tsc -b && npm run build 2>&1 | tail -2 && npx vitest run 2>&1 | tail -3
```
Standalone smoke (`npm run dev`, then stop): month chips tinted with accent bar and readable title; today badge; weekend tint; week view shows now-line and business-hours shading.

```bash
git add src/
git commit -m "feat: Quiet Ledger grid redesign — tinted event chips, styled popover, week/day polish"
```

---

### Task 5: Event peek popover

**Files:**
- Create: `src/components/EventPeek.tsx`
- Modify: `src/root.component.tsx` (click → peek; Edit/Delete from peek)

**Interfaces:**
- Consumes: `onSelectEvent(occ, anchor: DOMRect)` from Task 2; existing `handleSelectEvent` (renamed to `openEditModal`), `deleteOccurrence`, `setScopeAsk`, `refreshEvents`.
- Produces: `EventPeek` props `{ occ: Occurrence; calendarName: string; anchor: { x: number; y: number; w: number; h: number }; onEdit: () => void; onDelete: () => void; onClose: () => void }`.

- [ ] **Step 1: Write `src/components/EventPeek.tsx`**

```tsx
import { useEffect, useRef, useState } from 'react';
import type { Occurrence } from '../api';

interface EventPeekProps {
  occ: Occurrence;
  calendarName: string;
  anchor: { x: number; y: number; w: number; h: number };
  onEdit: () => void;
  onDelete: () => void;
  onClose: () => void;
}

const CARD_W = 320;
const CARD_H_GUESS = 210;

function humanTime(occ: Occurrence): string {
  const day = new Intl.DateTimeFormat(undefined, {
    weekday: 'short', month: 'short', day: 'numeric',
  }).format(new Date(occ.startAt));
  if (occ.allDay) return `${day} · All day`;
  const t = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', hour12: false });
  return `${day} · ${t.format(new Date(occ.startAt))} – ${t.format(new Date(occ.endAt))}`;
}

export function EventPeek({ occ, calendarName, anchor, onEdit, onDelete, onClose }: EventPeekProps) {
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState(() => {
    // Prefer right of the chip; flip left / clamp vertically to stay in the viewport.
    let x = anchor.x + anchor.w + 8;
    if (x + CARD_W > window.innerWidth - 8) x = Math.max(8, anchor.x - CARD_W - 8);
    let y = anchor.y;
    if (y + CARD_H_GUESS > window.innerHeight - 8) y = Math.max(8, window.innerHeight - CARD_H_GUESS - 8);
    return { x, y };
  });

  useEffect(() => {
    // Re-clamp once real height is known.
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    if (r.bottom > window.innerHeight - 8) {
      setPos((p) => ({ ...p, y: Math.max(8, window.innerHeight - r.height - 8) }));
    }
  }, []);

  useEffect(() => {
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    document.addEventListener('mousedown', onDown);
    return () => document.removeEventListener('mousedown', onDown);
  }, [onClose]);

  return (
    <div
      ref={ref}
      className="fixed z-30 w-80 card bg-base-100 border border-base-300 shadow-lg"
      style={{ left: pos.x, top: pos.y }}
      role="dialog"
      aria-label={occ.title}
    >
      <div className="card-body p-4 gap-2">
        <div className="flex items-center gap-2 text-xs text-base-content/60">
          <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: occ.color }} />
          <span className="truncate">{calendarName}</span>
          {occ.isRecurring && <span className="badge badge-ghost badge-xs">Repeats</span>}
        </div>
        <h3 className="font-semibold leading-tight">{occ.title}</h3>
        <p className="text-sm text-base-content/70 cal-num">{humanTime(occ)}</p>
        {occ.location && <p className="text-sm text-base-content/70">📍 {occ.location}</p>}
        {occ.attendees.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {occ.attendees.map((a) => (
              <span key={a.email} className="badge badge-outline badge-sm">{a.displayName || a.email}</span>
            ))}
          </div>
        )}
        <div className="flex justify-end gap-2 mt-1">
          <button className="btn btn-ghost btn-sm text-error" onClick={onDelete}>Delete</button>
          <button className="btn btn-sm btn-primary" onClick={onEdit}>Edit</button>
        </div>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Wire in `src/root.component.tsx`**

1. State + import:
```tsx
import { EventPeek } from './components/EventPeek';
...
  const [peek, setPeek] = useState<{ occ: Occurrence; anchor: { x: number; y: number; w: number; h: number } } | null>(null);
```
2. Rename the existing `handleSelectEvent` to `openEditModal` (same body). New click handler:
```tsx
  const handleSelectEvent = (occ: Occurrence, anchor: DOMRect) => {
    setPeek({ occ, anchor: { x: anchor.x, y: anchor.y, w: anchor.width, h: anchor.height } });
  };
```
3. Peek delete mirrors `deleteFromModal`'s logic but from the peek:
```tsx
  const deleteFromPeek = () => {
    if (!peek) return;
    const occ = peek.occ;
    setPeek(null);
    if (occ.isRecurring) {
      setScopeAsk({
        title: 'Delete recurring event',
        run: async (scope) => {
          await deleteOccurrence(occ, scope);
          setScopeAsk(null);
          await refreshEvents();
        },
      });
      return;
    }
    void deleteOccurrence(occ, 'all').then(refreshEvents).catch((e) =>
      setError(e instanceof Error ? e.message : 'Delete failed'));
  };
```
4. Render (next to the modal blocks):
```tsx
      {peek && (
        <EventPeek
          occ={peek.occ}
          calendarName={calendars.find((c) => c.id === peek.occ.calendarId)?.name ?? ''}
          anchor={peek.anchor}
          onEdit={() => { const occ = peek.occ; setPeek(null); void openEditModal(occ); }}
          onDelete={deleteFromPeek}
          onClose={() => setPeek(null)}
        />
      )}
```
5. Close the peek on navigation: in the `onDatesSet` handler pass `(info) => { setViewInfo(info); setPeek(null); }`.

- [ ] **Step 3: Gates + commit**

```bash
npx tsc -b && npm run build 2>&1 | tail -2 && npx vitest run 2>&1 | tail -3
git add src/
git commit -m "feat: event peek popover with edit/delete actions"
```

---

### Task 6: Keyboard shortcuts + empty-state hint

**Files:**
- Create: `src/hooks/useKeyboardShortcuts.ts`
- Modify: `src/root.component.tsx`

**Interfaces:**
- Consumes: toolbar handlers, `setPeek`, `setScopeAsk`, `setModal`, `setSidebarOpen`, `isNarrow` from earlier tasks.
- Produces: `useKeyboardShortcuts(handlers: ShortcutHandlers): void` with
  `interface ShortcutHandlers { onToday(): void; onPrev(): void; onNext(): void; onView(view: 'dayGridMonth' | 'timeGridWeek' | 'timeGridDay' | 'listWeek'): void; onNew(): void; onEscape(): boolean }` — `onEscape` returns whether it consumed the key.

- [ ] **Step 1: Write `src/hooks/useKeyboardShortcuts.ts`**

```ts
import { useEffect, useRef } from 'react';

export interface ShortcutHandlers {
  onToday: () => void;
  onPrev: () => void;
  onNext: () => void;
  onView: (view: 'dayGridMonth' | 'timeGridWeek' | 'timeGridDay' | 'listWeek') => void;
  onNew: () => void;
  /** Close the topmost overlay; return true if something was closed. */
  onEscape: () => boolean;
}

function isTyping(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || target.isContentEditable;
}

/** Spec §6 keyboard map. Handlers are kept in a ref so the listener binds once. */
export function useKeyboardShortcuts(handlers: ShortcutHandlers): void {
  const ref = useRef(handlers);
  ref.current = handlers;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key === 'Escape') {
        if (ref.current.onEscape()) e.preventDefault();
        return;
      }
      if (isTyping(e.target)) return;
      switch (e.key.toLowerCase()) {
        case 't': ref.current.onToday(); break;
        case 'arrowleft': ref.current.onPrev(); break;
        case 'arrowright': ref.current.onNext(); break;
        case 'm': ref.current.onView('dayGridMonth'); break;
        case 'w': ref.current.onView('timeGridWeek'); break;
        case 'd': ref.current.onView('timeGridDay'); break;
        case 'l': ref.current.onView('listWeek'); break;
        case 'n':
        case 'c': ref.current.onNew(); break;
        default: return;
      }
      e.preventDefault();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, []);
}
```

- [ ] **Step 2: Wire in `src/root.component.tsx`**

```tsx
import { useKeyboardShortcuts } from './hooks/useKeyboardShortcuts';
...
  useKeyboardShortcuts({
    onToday: handleToday,
    onPrev: handlePrev,
    onNext: handleNext,
    onView: handleChangeView,
    onNew: handleNewEvent,
    onEscape: () => {
      // topmost first: peek → scope dialog → modal → drawer (spec §6)
      if (peek) { setPeek(null); return true; }
      if (scopeAsk) { scopeAsk.cleanup?.(); setScopeAsk(null); return true; }
      if (modal) { setModal(null); setModalError(null); return true; }
      if (isNarrow && sidebarOpen) { setSidebarOpen(false); return true; }
      return false;
    },
  });
```
Guard `onNew`/`onView`/nav shortcuts against firing while a modal is open (they'd act behind it): at the top of each of those handlers' shortcut paths, bail when `modal || scopeAsk`:
```tsx
  const uiBlocked = modal !== null || scopeAsk !== null;
  // in the useKeyboardShortcuts call, wrap: onToday: () => { if (!uiBlocked) handleToday(); }, …same for onPrev/onNext/onView/onNew.
```
(Write the five wrappers explicitly — do not pass unguarded handlers.)

- [ ] **Step 3: Empty-state hint**

In the grid-area wrapper (around `CalendarCanvas`), add a floating hint when the range is empty:
```tsx
        <div className="flex-1 min-w-0 flex flex-col relative">
          {error && <div className="alert alert-error text-sm m-3 mb-0">{error}</div>}
          {occurrences.length === 0 && calendars.length > 0 && viewInfo && (
            <div className="absolute inset-0 z-10 flex items-center justify-center pointer-events-none">
              <p className="text-sm text-base-content/40 bg-base-100/80 px-4 py-2 rounded-full">
                Nothing scheduled — press <kbd className="kbd kbd-xs">N</kbd> or click + New event
              </p>
            </div>
          )}
          <CalendarCanvas ... />
        </div>
```

- [ ] **Step 4: Gates + commit**

```bash
npx tsc -b && npm run build 2>&1 | tail -2 && npx vitest run 2>&1 | tail -3
git add src/
git commit -m "feat: keyboard shortcuts (T/arrows/MWDL/N/Esc) and empty-range hint"
```

---

### Task 7: Live validation (browser) — spec §8 acceptance

No new code except fixes. Needs eldrin-core on `feature/full-width-app-layout` and eldrin-calendar on `feature/ux-overhaul` running (`npm run dev` in eldrin-core:4000, eldrin-calendar:4012, eldrin-crm:4009 on main). Login admin@eldrin.local/admin123.

- [ ] **Step 1: Walk the checklist** (both themes; wide ~1900px AND ~1280px viewport):
  1. Calendar fills full width & height under the topbar; no page scrollbar; month rows evenly fill.
  2. CRM + core dashboard still render with the 1440px centered container (regression).
  3. Sidebar collapse animates + persists across reload; drawer below 1024px.
  4. Mini nav: day click navigates the grid; range highlight follows; ‹ › pages independently.
  5. Month chips: tint + accent + readable title; "+N more" popover styled; today badge; weekend tint; adjacent-month dimming.
  6. Week/day: now line, ~07:30 auto-scroll, business-hours shading.
  7. Peek popover: click chip → card with correct fields; Edit → modal; Delete on recurring → scope dialog; Esc/outside closes.
  8. Shortcuts: T ← → M W D L N work; typing in the modal doesn't trigger them; Esc closes topmost in order.
  9. Empty range shows the hint; creating an event removes it.
  10. Both themes clean (no stock FullCalendar colors).
- [ ] **Step 2: Fix everything found** (commit per fix, conventional messages), re-verify.
- [ ] **Step 3: Full gates on both repos** (`npm run test:run` in core; `npx tsc -b && npm run build && npx vitest run` in calendar). Branches ready for the finishing workflow (merge decision is the human's).

---

## Self-Review Notes (author)

- Spec coverage: §3→Task 1, §4→Tasks 2–3, §5→Task 4, §6→Tasks 5–6, §8→Task 7. All U1–U5 mapped.
- Deliberate additions beyond spec text: `firstDay={1}` (Monday start — matches the user's locale and the mini-nav header) and `displayEventEnd={false}` (chip shows start time only, per §5 "start time … before the title").
- Type consistency: `CanvasDatesInfo` defined once (Task 2), consumed in Tasks 3/5/6; `ViewType` from CalendarToolbar; `ShortcutHandlers.onView` union matches `VIEWS` types.
- Known seam risks repeated from spec §9: `--chip` variable placement on the FC harness element (Task 4 note) and first-paint default-layout flash in the shell (accepted).

