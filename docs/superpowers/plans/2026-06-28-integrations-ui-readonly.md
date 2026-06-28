# Read-Only Integrations Studio Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A read-only admin "Integrations" studio in the eldrin-core shell that lists installed integrations and their stored flows and renders a flow's graph — plus a prerequisite SDK fix so admin-gated calls work through the shell proxy.

**Architecture:** Two repos. First, an `eldrin-integration` fix: `isAdmin` honors the proxy-forwarded `X-Eldrin-User-Roles` header (else every `/api/flows` call through the shell proxy 403s). Then, an `eldrin-core` UI: pure-logic units (integration discovery, proxy API layer, flow view-model) unit-tested with Vitest, thin React components, an admin-gated nav item + `/integrations` route, and one Playwright smoke.

**Tech Stack:** SDK: TypeScript + Vitest. Shell: React 19 + React Router v7 + Zustand + shadcn/ui + Tailwind 4 + react-i18next; Vitest + Playwright.

## Global Constraints

- **Two repos, sequenced:** SDK fix in `/Users/tibor/projects/eldrin-backup/eldrin-integration` (Task 1, merge to SDK `main` mentally — but here it lands on a branch); then UI in `/Users/tibor/projects/eldrin-backup/eldrin-core` (Tasks 2-7).
- **Read-only.** NO create/update/delete, no connection editor, no canvas. Display only.
- **SDK `isAdmin` fix:** honor `X-Eldrin-User-Roles` header (comma-separated, trimmed, includes 'admin') OR the existing Bearer-JWT `platformRoles`. Add `X-Eldrin-User-Roles` to host CORS `allowHeaders`. Applies to all admin-gated routes (`/api/flows`, `/api/schema/prune`).
- **Integration discovery:** filter the shell app registry by `manifest.kind === 'integration'`; use `app.id` (proxy appId) + `app.label`.
- **API mechanism:** `window.__ELDRIN__.authenticatedFetch(appId, '/api/flows')` → proxy URL `/api/app/{appId}/api/flows` with Bearer token; the proxy forwards `X-Eldrin-User-Roles`. The API-logic functions take `authFetch` as an INJECTED parameter (mockable; never call `window` directly inside the pure functions).
- **`Result<T>` envelope:** `{ ok: true; data: T } | { ok: false; status?: number; error: string }` — API functions map 403/network/parse into this; components render forbidden/error states from it.
- **"No stored flows" copy is honest:** `/api/flows` returns only persisted flows; empty → "No stored flow overrides — this integration runs its default compiled flows" (NOT "no flows").
- **Admin gating, defense in depth:** nav item hidden unless `hasPlatformRole('admin')`; the `/integrations` page redirects non-admins (`<Navigate to="/" replace />`); the server `isAdmin` gate is the backstop.
- **Pure logic / thin components:** discovery, API, and view-model are pure functions (unit-tested); components are thin wrappers using the codebase's `useEffect`/`useState` pattern (NO react-query — it isn't in the repo).
- **No new test stack:** do NOT add `@testing-library/react`. Logic → Vitest units; UI wiring → one Playwright smoke.
- Immutability; no `console.log` in production code; conventional commits, attribution disabled. Coverage ≥ 80% on the three logic units.
- SDK tests: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run`. Shell tests: `cd /Users/tibor/projects/eldrin-backup/eldrin-core && npx vitest run`.

---

## File Structure

**eldrin-integration (Task 1):**
- `src/host/create-worker.ts` (modify) — `isAdmin` reads `X-Eldrin-User-Roles`; CORS `allowHeaders` += `X-Eldrin-User-Roles`.
- `src/host/create-worker.test.ts` (modify) — header-admin tests.

**eldrin-core (Tasks 2-7):**
- `src/pages/integrations/discovery.ts` + `.test.ts` (new) — registry → integration list.
- `src/pages/integrations/integrations-api.ts` + `.test.ts` (new) — proxy URL + fetch/parse → `Result`.
- `src/pages/integrations/flow-view-model.ts` + `.test.ts` (new) — flow JSON → view structure.
- `src/pages/integrations/IntegrationList.tsx` (new) — thin list component.
- `src/pages/integrations/FlowDetail.tsx` (new) — thin read-only viewer.
- `src/pages/Integrations.tsx` (new) — route target + admin guard.
- `src/components/SideNav.tsx` (modify) — admin "Integrations" nav item.
- `src/App.tsx` (modify) — `/integrations` route.
- `src/locales/en/integrations.json` (new) — i18n strings.
- `e2e/integrations.spec.ts` (new) — Playwright smoke.

---

## Reference: current code (do not re-derive)

**SDK** `src/host/create-worker.ts`: `isAdmin(c)` currently reads only the Bearer JWT `platformRoles`. `resolveUserId(c)` reads `X-Eldrin-User-Id` header OR JWT `sub`. CORS `allowHeaders: ['Content-Type', 'Authorization', 'X-Eldrin-User-Id']`. Admin routes call `if (!isAdmin(c)) return c.json({ error: 'Forbidden: admin role required' }, 403);`.

**Shell** `src/components/SideNav.tsx`: `NavItem { label; path; icon: React.ReactNode; badge?; children? }`. `mainItems`/`footerItems` are `useMemo`'d arrays; `appNavItems` derived from `useAppRegistry(state => state.apps)` (a `Map<string, AppRegistration>`). Render order in `<nav>`: main section, then `{appNavItems.length > 0 && (...)}` app section; `footerItems` in a separate bordered `<div>`. Section header markup: `<div className="py-2 px-3 text-xs font-semibold text-muted-foreground tracking-[0.05em] uppercase">{t('nav.X')}</div>`. `NavItemComponent` renders one item.

`src/stores/appRegistry.ts`: `AppRegistration { id; label; icon; basePath; nav; entryUrl?; appUrl?; proxyApiBase?; manifest? }`. `manifest.kind?: 'app' | 'integration'` (from `types/manifest.ts`). `window.__ELDRIN__.authenticatedFetch(appId, input, init?)` → `Promise<Response>`, builds `/api/app/{appId}/...` + Bearer token.

`src/stores/authStore.ts`: `useAuthStore` exposes `hasPlatformRole(role: string): boolean`. Import: `import { useAuthStore } from '../stores/authStore'` (adjust relative depth per file).

`src/App.tsx`: routes inside `<Shell>` at lines ~354-361, e.g. `<Route path="settings" element={<Settings />} />`. `Navigate` imported from `react-router-dom`.

Flow type (from the SDK, mirrored as a local TS type in the shell since the shell doesn't import the SDK): `Flow { id; integrationId; trigger: {kind:'cron',expr}|{kind:'webhook',event}|{kind:'manual'}; nodes: {id; kind; config}[]; edges: {from;to;when?}[] }`. Map node config: `{ connections: {target; sources:string[]; transform?: {kind:'builtin',fn,args?}|{kind:'snippet',code}}[] }`. Source config: `{ transport:{method,path}, idField }`. Destination config: `{ kind:'d1', table, mode }`.

---

### Task 1: SDK — `isAdmin` honors `X-Eldrin-User-Roles`

**Repo:** `/Users/tibor/projects/eldrin-backup/eldrin-integration`

**Files:**
- Modify: `src/host/create-worker.ts`
- Test: `src/host/create-worker.test.ts`

**Interfaces:**
- Produces: an `isAdmin` that returns true for a request carrying `X-Eldrin-User-Roles` containing `admin`, OR a Bearer JWT with `platformRoles` containing `admin`.

- [ ] **Step 1: Write the failing tests (append to `src/host/create-worker.test.ts`)**

Use the existing admin-route test helpers in that file (the prune/flows tests build a worker and call its fetch with crafted headers). Add tests against an admin-gated route (e.g. `GET /api/flows` or `POST /api/schema/prune` — whichever the file already exercises):

```ts
describe('isAdmin via X-Eldrin-User-Roles (proxy path)', () => {
  it('grants admin when X-Eldrin-User-Roles contains admin (no Bearer)', async () => {
    // build a request to an admin route with headers:
    //   X-Eldrin-User-Id: 'u'   (so resolveUserId passes)
    //   X-Eldrin-User-Roles: 'admin'
    // expect NOT 403 (200 or the route's success status)
  });
  it('denies when X-Eldrin-User-Roles has no admin', async () => {
    // X-Eldrin-User-Id: 'u', X-Eldrin-User-Roles: 'viewer,user'  → expect 403
  });
  it('still grants admin via Bearer JWT platformRoles (regression)', async () => {
    // Authorization: Bearer <jwt {sub:'u',platformRoles:['admin']}>  → not 403
  });
  it('denies when neither header roles nor JWT admin present', async () => {
    // X-Eldrin-User-Id: 'u' only → 403
  });
});
```

Fill these in fully using the file's existing request-builder + worker-construction helpers (read the existing prune/flows admin tests and mirror them). The `X-Eldrin-User-Roles: 'viewer,user'` case must assert 403; the header-admin case must assert non-403.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/host/create-worker.test.ts`
Expected: the two header-based tests FAIL (current `isAdmin` ignores the header → header-admin gets 403).

- [ ] **Step 3: Edit `isAdmin` and CORS in `src/host/create-worker.ts`**

Replace the `isAdmin` function with:

```ts
function isAdmin(c: { req: { header: (name: string) => string | undefined } }): boolean {
  // Proxy-forwarded roles: the shell's /api/app proxy authenticates the JWT, then forwards
  // identity as X-Eldrin-* headers — same trust model as resolveUserId's X-Eldrin-User-Id.
  const headerRoles = c.req.header('X-Eldrin-User-Roles');
  if (headerRoles && headerRoles.split(',').map((r) => r.trim()).includes('admin')) return true;
  // Direct Bearer JWT (curl / non-proxied callers).
  const auth = c.req.header('Authorization');
  if (auth?.startsWith('Bearer ')) {
    try {
      const payload = JSON.parse(atob(auth.slice(7).split('.')[1]));
      const roles = payload.platformRoles;
      if (Array.isArray(roles) && roles.includes('admin')) return true;
    } catch { /* invalid JWT — not admin */ }
  }
  return false;
}
```

In the host CORS config, add `'X-Eldrin-User-Roles'` to `allowHeaders`:

```ts
allowHeaders: ['Content-Type', 'Authorization', 'X-Eldrin-User-Id', 'X-Eldrin-User-Roles'],
```

- [ ] **Step 4: Run the full SDK suite + typecheck + build**

Run: `npx vitest run && npx tsc --noEmit && npm run build`
Expected: all PASS (incl. the 4 new tests + the existing admin-gate tests as regression); tsc clean; build clean (no better-sqlite3 in bundle).

- [ ] **Step 5: Commit**

```bash
git add src/host/create-worker.ts src/host/create-worker.test.ts
git commit -m "fix(host): isAdmin honors proxy-forwarded X-Eldrin-User-Roles header"
```

---

### Task 2: Shell — integration discovery (pure)

**Repo:** `/Users/tibor/projects/eldrin-backup/eldrin-core`

**Files:**
- Create: `src/pages/integrations/discovery.ts`
- Test: `src/pages/integrations/discovery.test.ts`

**Interfaces:**
- Produces: `IntegrationRef { id: string; label: string }`; `listIntegrations(apps: Map<string, AppRegistration>): IntegrationRef[]`. Consumed by Task 5 (IntegrationList).

- [ ] **Step 1: Write the failing test**

```ts
// src/pages/integrations/discovery.test.ts
import { describe, it, expect } from 'vitest';
import { listIntegrations } from './discovery';
import type { AppRegistration } from '../../stores/appRegistry';

function reg(id: string, kind?: 'app' | 'integration'): AppRegistration {
  return { id, label: id.toUpperCase(), icon: 'box', basePath: `/${id}`, nav: [], manifest: kind ? ({ kind } as never) : undefined };
}

describe('listIntegrations', () => {
  it('returns only apps whose manifest.kind === integration, as {id,label}', () => {
    const apps = new Map<string, AppRegistration>([
      ['factorial', reg('factorial', 'integration')],
      ['todo', reg('todo', 'app')],
      ['catalog', reg('catalog', 'integration')],
      ['nokind', reg('nokind')],
    ]);
    expect(listIntegrations(apps)).toEqual([
      { id: 'factorial', label: 'FACTORIAL' },
      { id: 'catalog', label: 'CATALOG' },
    ]);
  });
  it('returns empty array for an empty registry', () => {
    expect(listIntegrations(new Map())).toEqual([]);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-core && npx vitest run src/pages/integrations/discovery.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Write `src/pages/integrations/discovery.ts`**

```ts
import type { AppRegistration } from '../../stores/appRegistry';

export interface IntegrationRef {
  id: string;
  label: string;
}

export function listIntegrations(apps: Map<string, AppRegistration>): IntegrationRef[] {
  const out: IntegrationRef[] = [];
  for (const app of apps.values()) {
    if (app.manifest?.kind === 'integration') out.push({ id: app.id, label: app.label });
  }
  return out;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/pages/integrations/discovery.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/pages/integrations/discovery.ts src/pages/integrations/discovery.test.ts
git commit -m "feat(integrations): add integration discovery from app registry"
```

---

### Task 3: Shell — proxy API layer (pure, injected authFetch)

**Files:**
- Create: `src/pages/integrations/integrations-api.ts`
- Test: `src/pages/integrations/integrations-api.test.ts`

**Interfaces:**
- Produces: `Result<T>`, `AuthFetch`, `FlowSummary`, `StoredFlow`, `FlowGraph` (local Flow type), `flowsUrl(appId)`, `fetchFlows(appId, authFetch)`, `fetchFlow(appId, flowId, authFetch)`. Consumed by Task 5/6.

- [ ] **Step 1: Write the failing test**

```ts
// src/pages/integrations/integrations-api.test.ts
import { describe, it, expect, vi } from 'vitest';
import { flowsUrl, fetchFlows } from './integrations-api';

const res = (status: number, body: unknown): Response =>
  ({ status, ok: status >= 200 && status < 300, json: async () => body } as Response);

describe('integrations-api', () => {
  it('flowsUrl builds the proxy path', () => {
    expect(flowsUrl('factorial')).toBe('/api/app/factorial/api/flows');
  });

  it('fetchFlows returns parsed summaries on 200', async () => {
    const authFetch = vi.fn(async () => res(200, [{ id: 'factorial:employees', integrationId: 'factorial', version: 1, updatedAt: 5 }]));
    const r = await fetchFlows('factorial', authFetch);
    expect(authFetch).toHaveBeenCalledWith('factorial', '/api/flows');
    expect(r).toEqual({ ok: true, data: [{ id: 'factorial:employees', integrationId: 'factorial', version: 1, updatedAt: 5 }] });
  });

  it('fetchFlows maps 403 to a forbidden Result', async () => {
    const authFetch = vi.fn(async () => res(403, { error: 'Forbidden: admin role required' }));
    const r = await fetchFlows('factorial', authFetch);
    expect(r).toEqual({ ok: false, status: 403, error: 'Forbidden: admin role required' });
  });

  it('fetchFlows maps a thrown error to a Result', async () => {
    const authFetch = vi.fn(async () => { throw new Error('network down'); });
    const r = await fetchFlows('factorial', authFetch);
    expect(r).toEqual({ ok: false, error: 'network down' });
  });

  it('fetchFlows returns ok with empty array (no stored flows)', async () => {
    const authFetch = vi.fn(async () => res(200, []));
    const r = await fetchFlows('factorial', authFetch);
    expect(r).toEqual({ ok: true, data: [] });
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/pages/integrations/integrations-api.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Write `src/pages/integrations/integrations-api.ts`**

```ts
export type Result<T> = { ok: true; data: T } | { ok: false; status?: number; error: string };

export type AuthFetch = (appId: string, input: string, init?: RequestInit) => Promise<Response>;

export interface FlowSummary {
  id: string;
  integrationId: string;
  version: number;
  updatedAt: number;
}

export interface FlowGraph {
  id: string;
  integrationId: string;
  trigger: { kind: 'cron'; expr: string } | { kind: 'webhook'; event: string } | { kind: 'manual' };
  nodes: { id: string; kind: string; config: unknown }[];
  edges: { from: string; to: string; when?: string }[];
}

export interface StoredFlow {
  id: string;
  integrationId: string;
  flow: FlowGraph;
  version: number;
  createdAt: number;
  updatedAt: number;
}

export function flowsUrl(appId: string): string {
  return `/api/app/${appId}/api/flows`;
}

async function call<T>(p: Promise<Response>): Promise<Result<T>> {
  try {
    const res = await p;
    const body = await res.json().catch(() => undefined);
    if (res.ok) return { ok: true, data: body as T };
    const error = (body && (body as { error?: string }).error) || `Request failed with status ${res.status}`;
    return { ok: false, status: res.status, error };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

export function fetchFlows(appId: string, authFetch: AuthFetch): Promise<Result<FlowSummary[]>> {
  return call<FlowSummary[]>(authFetch(appId, '/api/flows'));
}

export function fetchFlow(appId: string, flowId: string, authFetch: AuthFetch): Promise<Result<StoredFlow>> {
  return call<StoredFlow>(authFetch(appId, `/api/flows/${encodeURIComponent(flowId)}`));
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/pages/integrations/integrations-api.test.ts`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/pages/integrations/integrations-api.ts src/pages/integrations/integrations-api.test.ts
git commit -m "feat(integrations): add proxy API layer with Result envelope"
```

---

### Task 4: Shell — flow view-model (pure)

**Files:**
- Create: `src/pages/integrations/flow-view-model.ts`
- Test: `src/pages/integrations/flow-view-model.test.ts`

**Interfaces:**
- Consumes: `FlowGraph` from `./integrations-api`.
- Produces: `FlowViewModel`, `toFlowViewModel(flow: FlowGraph): FlowViewModel`. Consumed by Task 6 (FlowDetail).

- [ ] **Step 1: Write the failing test**

```ts
// src/pages/integrations/flow-view-model.test.ts
import { describe, it, expect } from 'vitest';
import { toFlowViewModel } from './flow-view-model';
import type { FlowGraph } from './integrations-api';

const flow: FlowGraph = {
  id: 'factorial:employees', integrationId: 'factorial',
  trigger: { kind: 'cron', expr: '0 * * * *' },
  nodes: [
    { id: 'source', kind: 'source', config: { transport: { method: 'GET', path: '/employees' }, idField: 'id' } },
    { id: 'transform', kind: 'transform', config: { mode: 'native', hook: 'deriveFullName' } },
    { id: 'map', kind: 'map', config: { connections: [
      { target: 'email', sources: ['email'] },
      { target: 'full_name', sources: ['first_name', 'last_name'], transform: { kind: 'builtin', fn: 'concat', args: [' '] } },
      { target: 'notes', sources: ['description'], transform: { kind: 'snippet', code: "sources[0].toUpperCase()" } },
    ] } },
    { id: 'destination', kind: 'destination', config: { kind: 'd1', table: 'employees', mode: 'stored' } },
  ],
  edges: [{ from: 'source', to: 'transform' }, { from: 'transform', to: 'map' }, { from: 'map', to: 'destination' }],
};

describe('toFlowViewModel', () => {
  it('summarizes trigger as a human string', () => {
    expect(toFlowViewModel(flow).trigger).toBe('cron: 0 * * * *');
    expect(toFlowViewModel({ ...flow, trigger: { kind: 'manual' } }).trigger).toBe('manual');
    expect(toFlowViewModel({ ...flow, trigger: { kind: 'webhook', event: 'x.changed' } }).trigger).toBe('webhook: x.changed');
  });

  it('lists nodes in pipeline order with summaries', () => {
    const vm = toFlowViewModel(flow);
    expect(vm.nodes.map((n) => n.kind)).toEqual(['source', 'transform', 'map', 'destination']);
    expect(vm.nodes[0].summary).toContain('GET /employees');
    expect(vm.nodes[3].summary).toContain('employees');
  });

  it('extracts map connections with transformer labels', () => {
    const vm = toFlowViewModel(flow);
    expect(vm.connections).toEqual([
      { target: 'email', sources: ['email'], transform: 'pass-through' },
      { target: 'full_name', sources: ['first_name', 'last_name'], transform: 'concat' },
      { target: 'notes', sources: ['description'], transform: 'snippet', snippet: 'sources[0].toUpperCase()' },
    ]);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/pages/integrations/flow-view-model.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Write `src/pages/integrations/flow-view-model.ts`**

```ts
import type { FlowGraph } from './integrations-api';

export interface ConnectionView {
  target: string;
  sources: string[];
  transform: string;      // 'pass-through' | builtin fn name | 'snippet'
  snippet?: string;
}

export interface NodeView {
  id: string;
  kind: string;
  summary: string;
}

export interface FlowViewModel {
  id: string;
  trigger: string;
  nodes: NodeView[];
  connections: ConnectionView[];
}

function triggerSummary(t: FlowGraph['trigger']): string {
  if (t.kind === 'cron') return `cron: ${t.expr}`;
  if (t.kind === 'webhook') return `webhook: ${t.event}`;
  return 'manual';
}

function nodeSummary(node: { kind: string; config: unknown }): string {
  const cfg = node.config as Record<string, unknown>;
  if (node.kind === 'source') {
    const t = cfg.transport as { method?: string; path?: string } | undefined;
    return `${t?.method ?? ''} ${t?.path ?? ''}`.trim();
  }
  if (node.kind === 'destination') {
    return `d1: ${String(cfg.table ?? '')} (${String(cfg.mode ?? '')})`;
  }
  if (node.kind === 'transform' || node.kind === 'filter') {
    return cfg.mode === 'snippet' ? 'snippet' : `hook: ${String(cfg.hook ?? '')}`;
  }
  if (node.kind === 'map') {
    const conns = (cfg.connections as unknown[]) ?? [];
    return `${conns.length} connection${conns.length === 1 ? '' : 's'}`;
  }
  return node.kind;
}

function connectionViews(flow: FlowGraph): ConnectionView[] {
  const mapNode = flow.nodes.find((n) => n.kind === 'map');
  if (!mapNode) return [];
  const conns = ((mapNode.config as Record<string, unknown>).connections as {
    target: string; sources: string[]; transform?: { kind: 'builtin'; fn: string } | { kind: 'snippet'; code: string };
  }[]) ?? [];
  return conns.map((c) => {
    if (!c.transform) return { target: c.target, sources: c.sources, transform: 'pass-through' };
    if (c.transform.kind === 'builtin') return { target: c.target, sources: c.sources, transform: c.transform.fn };
    return { target: c.target, sources: c.sources, transform: 'snippet', snippet: c.transform.code };
  });
}

export function toFlowViewModel(flow: FlowGraph): FlowViewModel {
  return {
    id: flow.id,
    trigger: triggerSummary(flow.trigger),
    nodes: flow.nodes.map((n) => ({ id: n.id, kind: n.kind, summary: nodeSummary(n) })),
    connections: connectionViews(flow),
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/pages/integrations/flow-view-model.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/pages/integrations/flow-view-model.ts src/pages/integrations/flow-view-model.test.ts
git commit -m "feat(integrations): add flow view-model transform"
```

---

### Task 5: Shell — IntegrationList + FlowDetail components

**Files:**
- Create: `src/pages/integrations/IntegrationList.tsx`
- Create: `src/pages/integrations/FlowDetail.tsx`
- Create: `src/locales/en/integrations.json`

**Interfaces:**
- Consumes: `listIntegrations` (Task 2), `fetchFlows`/`fetchFlow`/`Result`/`FlowSummary`/`StoredFlow` (Task 3), `toFlowViewModel`/`FlowViewModel` (Task 4), `useAppRegistry`, `useAuthStore` (existing).
- Produces: the two components consumed by Task 6 (Integrations page).

These are thin presentational components (no new pure logic → covered by the Playwright smoke + the logic units, not unit-tested per the no-component-test-stack constraint). Follow the existing settings sub-page pattern (Card + useEffect/useState + loading/error).

- [ ] **Step 1: Write `src/locales/en/integrations.json`**

```json
{
  "title": "Integrations",
  "description": "Inspect installed integrations and their flows.",
  "empty": "No integrations installed.",
  "noFlows": "No stored flow overrides — this integration runs its default compiled flows.",
  "forbidden": "You need admin access to view integration flows.",
  "error": "Failed to load flows.",
  "retry": "Try again",
  "version": "v{{version}}",
  "viewFlow": "View",
  "connections": "Connections",
  "trigger": "Trigger"
}
```

- [ ] **Step 2: Write `src/pages/integrations/FlowDetail.tsx`**

```tsx
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ChevronRight } from 'lucide-react';
import type { FlowViewModel } from './flow-view-model';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export function FlowDetail({ vm }: { vm: FlowViewModel }) {
  const { t } = useTranslation('integrations');
  const [open, setOpen] = useState(true);
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{vm.id}</CardTitle>
        <p className="text-sm text-muted-foreground">{t('trigger')}: {vm.trigger}</p>
      </CardHeader>
      <CardContent>
        <ol className="space-y-2">
          {vm.nodes.map((n) => (
            <li key={n.id} className="flex items-center gap-2 text-sm">
              <span className="font-medium">{n.kind}</span>
              <span className="text-muted-foreground">{n.summary}</span>
            </li>
          ))}
        </ol>
        {vm.connections.length > 0 && (
          <div className="mt-4">
            <button className="flex items-center gap-1 text-sm font-medium" onClick={() => setOpen((o) => !o)}>
              <ChevronRight size={14} className={open ? 'rotate-90 transition-transform' : 'transition-transform'} />
              {t('connections')} ({vm.connections.length})
            </button>
            {open && (
              <table className="mt-2 w-full text-sm">
                <tbody>
                  {vm.connections.map((c) => (
                    <tr key={c.target} className="border-t">
                      <td className="py-1 pr-3 font-mono">{c.target}</td>
                      <td className="py-1 pr-3 text-muted-foreground">← {c.sources.join(', ')}</td>
                      <td className="py-1 pr-3">{c.transform}</td>
                      <td className="py-1 font-mono text-xs text-muted-foreground">{c.snippet ?? ''}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
```

- [ ] **Step 3: Write `src/pages/integrations/IntegrationList.tsx`**

```tsx
import { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { RefreshCw } from 'lucide-react';
import { useAppRegistry } from '../../stores/appRegistry';
import { listIntegrations } from './discovery';
import { fetchFlows, fetchFlow, type FlowSummary } from './integrations-api';
import { toFlowViewModel } from './flow-view-model';
import { FlowDetail } from './FlowDetail';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

type AuthFetchGlobal = (appId: string, input: string, init?: RequestInit) => Promise<Response>;
function getAuthFetch(): AuthFetchGlobal {
  return (window as unknown as { __ELDRIN__: { authenticatedFetch: AuthFetchGlobal } }).__ELDRIN__.authenticatedFetch;
}

export function IntegrationList() {
  const { t } = useTranslation('integrations');
  const apps = useAppRegistry((s) => s.apps);
  const integrations = listIntegrations(apps);

  if (integrations.length === 0) {
    return <p className="text-muted-foreground">{t('empty')}</p>;
  }
  return (
    <div className="space-y-6">
      {integrations.map((i) => (
        <IntegrationCard key={i.id} id={i.id} label={i.label} />
      ))}
    </div>
  );
}

function IntegrationCard({ id, label }: { id: string; label: string }) {
  const { t } = useTranslation('integrations');
  const [flows, setFlows] = useState<FlowSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [forbidden, setForbidden] = useState(false);
  const [openFlowId, setOpenFlowId] = useState<string | null>(null);
  const [openVm, setOpenVm] = useState<ReturnType<typeof toFlowViewModel> | null>(null);

  const load = useCallback(async () => {
    setLoading(true); setError(null); setForbidden(false);
    const r = await fetchFlows(id, getAuthFetch());
    if (r.ok) setFlows(r.data);
    else if (r.status === 403) setForbidden(true);
    else setError(r.error);
    setLoading(false);
  }, [id]);

  useEffect(() => { load(); }, [load]);

  const openFlow = useCallback(async (flowId: string) => {
    if (openFlowId === flowId) { setOpenFlowId(null); setOpenVm(null); return; }
    const r = await fetchFlow(id, flowId, getAuthFetch());
    if (r.ok) { setOpenFlowId(flowId); setOpenVm(toFlowViewModel(r.data.flow)); }
  }, [id, openFlowId]);

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-base">{label}</CardTitle>
        <Button variant="ghost" size="icon" onClick={load} disabled={loading} aria-label={t('retry')}>
          <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
        </Button>
      </CardHeader>
      <CardContent>
        {forbidden ? (
          <p className="text-destructive">{t('forbidden')}</p>
        ) : error ? (
          <div><p className="text-destructive mb-2">{t('error')}</p><Button variant="link" onClick={load}>{t('retry')}</Button></div>
        ) : loading ? (
          <p className="text-muted-foreground">…</p>
        ) : flows.length === 0 ? (
          <p className="text-muted-foreground">{t('noFlows')}</p>
        ) : (
          <div className="space-y-2">
            {flows.map((f) => (
              <div key={f.id}>
                <div className="flex items-center justify-between text-sm">
                  <span className="font-mono">{f.id}</span>
                  <span className="flex items-center gap-3">
                    <span className="text-muted-foreground">{t('version', { version: f.version })}</span>
                    <Button variant="link" size="sm" onClick={() => openFlow(f.id)}>{t('viewFlow')}</Button>
                  </span>
                </div>
                {openFlowId === f.id && openVm && <div className="mt-2"><FlowDetail vm={openVm} /></div>}
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
```

- [ ] **Step 4: Verify it compiles (typecheck)**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-core && npx tsc --noEmit`
Expected: clean (the components reference only existing exports + the new logic units). If `i18n` namespace loading needs registration, check how other namespaces (e.g. `settings`) are registered in the i18n init and mirror it (the brief for Task 6 covers route wiring; namespace registration lives wherever `i18next` is configured — search for `settings.json` usage).

- [ ] **Step 5: Commit**

```bash
git add src/pages/integrations/IntegrationList.tsx src/pages/integrations/FlowDetail.tsx src/locales/en/integrations.json
git commit -m "feat(integrations): add read-only integration list and flow detail components"
```

---

### Task 6: Shell — Integrations page, route, nav item

**Files:**
- Create: `src/pages/Integrations.tsx`
- Modify: `src/App.tsx`
- Modify: `src/components/SideNav.tsx`

**Interfaces:**
- Consumes: `IntegrationList` (Task 5), `useAuthStore.hasPlatformRole` (existing).

- [ ] **Step 1: Write `src/pages/Integrations.tsx`**

```tsx
import { Navigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useAuthStore } from '../stores/authStore';
import { IntegrationList } from './integrations/IntegrationList';

export function Integrations() {
  const { t } = useTranslation('integrations');
  const hasPlatformRole = useAuthStore((s) => s.hasPlatformRole);
  if (!hasPlatformRole('admin')) return <Navigate to="/" replace />;
  return (
    <div className="animate-fade-in">
      <header className="mb-6">
        <h1 className="text-2xl font-semibold text-foreground mb-1">{t('title')}</h1>
        <p className="text-base text-muted-foreground">{t('description')}</p>
      </header>
      <IntegrationList />
    </div>
  );
}
```

(If `useAuthStore` does not support selector form `useAuthStore((s) => s.hasPlatformRole)`, use `const { hasPlatformRole } = useAuthStore();` — match how other pages call it; the Explore reference shows `const { hasPlatformRole } = useAuthStore();`.)

- [ ] **Step 2: Add the route in `src/App.tsx`**

Add an import near the other page imports:
```ts
import { Integrations } from './pages/Integrations';
```
Add the route inside `<Shell>` next to the `settings` route (after line ~358):
```tsx
<Route path="integrations" element={<Integrations />} />
```

- [ ] **Step 3: Add the admin nav item in `src/components/SideNav.tsx`**

Add imports: `Workflow` from `lucide-react`, and `useAuthStore`:
```ts
import { Workflow } from 'lucide-react';
import { useAuthStore } from '../stores/authStore';
```
Inside `SideNav()`, after `appNavItems`, add an admin section:
```ts
const { hasPlatformRole } = useAuthStore();
const adminItems: NavItem[] = useMemo(() => (
  hasPlatformRole('admin')
    ? [{ label: t('nav.integrations'), path: '/integrations', icon: <Workflow size={20} /> }]
    : []
), [t, hasPlatformRole]);
```
Render it in the `<nav>` between the main section and the app section:
```tsx
{adminItems.length > 0 && (
  <div className="mb-4">
    {!sidenavCollapsed && (
      <div className="py-2 px-3 text-xs font-semibold text-muted-foreground tracking-[0.05em] uppercase">
        {t('nav.admin')}
      </div>
    )}
    {adminItems.map(item => (
      <NavItemComponent key={item.path} item={item} collapsed={sidenavCollapsed} />
    ))}
  </div>
)}
```
Add the i18n keys `nav.integrations` and `nav.admin` to `src/locales/en/common.json` (where the other `nav.*` keys live — find `nav.dashboard`/`nav.settings` and add alongside).

- [ ] **Step 4: Typecheck + build + full shell suite**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-core && npx tsc --noEmit && npx vitest run && npm run build`
Expected: tsc clean; the logic-unit tests (discovery/api/view-model) pass; build succeeds.

- [ ] **Step 5: Commit**

```bash
git add src/pages/Integrations.tsx src/App.tsx src/components/SideNav.tsx src/locales/en/common.json
git commit -m "feat(integrations): add admin Integrations page, route, and nav item"
```

---

### Task 7: Shell — Playwright smoke + i18n registration verify

**Files:**
- Create: `e2e/integrations.spec.ts`

**Interfaces:**
- Consumes: the running shell (admin login).

- [ ] **Step 1: Confirm the `integrations` i18n namespace loads**

Find the i18next configuration (search for where `settings.json` / namespaces are registered — likely `src/i18n.ts` or similar). Ensure the new `integrations` namespace is registered the same way `settings` is (add it to the resources/ns list). If namespaces are auto-loaded, no change needed. Verify by running the shell dev server and navigating to `/integrations` as admin — the title should read "Integrations", not a raw key.

- [ ] **Step 2: Write the Playwright smoke**

```ts
// e2e/integrations.spec.ts
import { test, expect } from '@playwright/test';

// Mirror the existing e2e auth setup in this repo (look at other specs in e2e/ for the
// login helper / storageState). This smoke logs in as an admin and asserts the nav + page.
test('admin sees Integrations nav and the integrations page renders', async ({ page }) => {
  // 1. Log in as an admin user (reuse the repo's existing e2e login helper / fixture).
  // 2. Expect the Integrations nav item to be visible.
  await expect(page.getByRole('link', { name: /integrations/i })).toBeVisible();
  // 3. Navigate to it.
  await page.getByRole('link', { name: /integrations/i }).click();
  await expect(page).toHaveURL(/\/integrations$/);
  // 4. The page heading renders (not a raw i18n key).
  await expect(page.getByRole('heading', { name: 'Integrations' })).toBeVisible();
});
```

Fill in the login step using the repo's existing e2e patterns (read other files in `e2e/` for the auth fixture/helper). If there is no admin e2e fixture, document that the smoke requires an admin storageState and wire it minimally; if e2e auth infra is absent, mark this test `test.skip` with a comment that it needs the admin fixture, and rely on the logic units — record this in the report.

- [ ] **Step 3: Run the smoke (or confirm skip)**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-core && npx playwright test e2e/integrations.spec.ts`
Expected: PASS if the admin fixture exists; otherwise SKIP with the documented reason. Report which.

- [ ] **Step 4: Commit**

```bash
git add e2e/integrations.spec.ts src/i18n.ts
git commit -m "test(integrations): add Playwright smoke for the integrations studio"
```

---

## Post-implementation: live verification (manual, not a task)

After the SDK fix is built and both repos' changes are in: start the shell (4000) + factorial preview (4011), log in as an admin, open Integrations → see Factorial → its stored flows (or the "runs default compiled flows" empty state if none stored), open a flow → see the node list + connection table. Then `curl` an admin request through the proxy (`/api/app/eldrin-factorial/api/flows` with the admin JWT) to confirm the `isAdmin` header fix returns 200, not 403.

## Notes

- **The SDK fix (Task 1) is the unblocker** — without it the UI's flow fetches 403. It is its own commit and can merge to SDK `main` independently.
- **`authFetch` injection** keeps `integrations-api.ts` pure/testable; the component supplies `window.__ELDRIN__.authenticatedFetch`. Do NOT call `window` inside the pure functions.
- **No `@testing-library/react`** — components are thin; the logic units carry the unit coverage and the Playwright smoke covers wiring.
- **i18n namespace:** the new `integrations` namespace must be registered wherever the existing `settings` namespace is; verify the page title renders real copy, not a raw key.
- **`hasPlatformRole` call form:** match the existing usage in the codebase (`const { hasPlatformRole } = useAuthStore();`) rather than guessing the selector form.
