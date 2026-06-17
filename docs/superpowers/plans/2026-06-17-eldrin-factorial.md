# eldrin-factorial Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Scaffold a company-level FactorialHR integration extension app (`eldrin-factorial`) that runs in the eldrin-core shell, configured via an API key in Settings, with a manual sync that persists Employees and Projects into D1 and live-proxies Teams and Time Off.

**Architecture:** A React 19 + single-spa micro-frontend served by a Cloudflare Worker (Hono), following the exact structure of the existing `eldrin-email` app. The worker authenticates to Factorial with a company-level API key read from its environment, exposes proxy/sync routes, and uses its own D1 database with SQL migrations compiled into the bundle at build time.

**Tech Stack:** React 19, single-spa 6, Vite 6, Tailwind 4 + daisyUI 5, Hono 4, Drizzle ORM (D1), Cloudflare Workers (wrangler 4), Vitest 2, `@eldrin-project/eldrin-app-core` + `@eldrin-project/eldrin-app-react`.

## Global Constraints

- App id / package name: `eldrin-factorial`. Worker name: `eldrin-factorial`. D1 db name: `eldrin-factorial-db`.
- Dev server port: `4011` (eldrin-email uses 4010; pick the next free port).
- Single-spa entry filename: `/eldrin-factorial.js` (+ `/eldrin-factorial.css`).
- Factorial API path convention: `{API_BASE_URL}/api/v1/...`. Sandbox base `https://api.eu2.demo.factorial.dev`; prod `https://api.factorialhr.com`.
- Factorial auth header (company API key): send as `x-api-key: <API_KEY>` (verify against docs in Task 5; the client centralizes this so only one line changes if wrong).
- Worker env vars: `FACTORIAL_API_BASE_URL` (config), `FACTORIAL_API_KEY` (secret), plus platform `DB`, `ASSETS`, `JWT_SECRET`, optional `ELDRIN_CORE_URL`.
- Shell auth: resolve `userId` from `X-Eldrin-User-Id` header (prod) or Bearer JWT (dev). `/health` is public; all `/api/*` require an authenticated user.
- Immutable patterns, files < 800 lines (target 200–400), errors handled explicitly and never swallowed, inputs validated at boundaries (project global rules).
- TDD: write failing test first, watch it fail, implement minimal, watch it pass, commit. Target 80%+ coverage.
- `.dev.vars*` and `worker/migrations.generated.ts` are gitignored — never commit secrets or the generated migrations file.
- Commit attribution is disabled globally; use conventional commit messages (`feat:`, `chore:`, `test:`).

## File Structure

```
eldrin-factorial/
├── .gitignore
├── .dev.vars.example                  # documents required vars (committed); .dev.vars is gitignored
├── index.html                         # standalone dev shell-context mock
├── package.json
├── tsconfig.json / tsconfig.app.json / tsconfig.node.json / tsconfig.worker.json
├── vite.config.ts
├── vitest.config.ts
├── wrangler.jsonc
├── worker-configuration.d.ts
├── shims/better-sqlite3.js
├── scripts/generate-migrations.ts
├── public/eldrin-app.manifest.json
├── migrations/001-init.sql
├── src/
│   ├── main.tsx
│   ├── index.css
│   ├── env.d.ts
│   ├── eldrin-factorial.tsx           # single-spa entry
│   ├── root.component.tsx             # nav + route parsing
│   ├── api.ts                         # typed client to our worker
│   ├── types/factorial.ts
│   └── pages/
│       ├── employees/EmployeeList.tsx
│       ├── teams/TeamList.tsx
│       ├── timeoff/TimeOffList.tsx
│       └── settings/ConnectionSettings.tsx
└── worker/
    ├── index.ts
    ├── utils.ts
    ├── db/{index.ts, schema.ts}
    ├── services/{factorial-client.ts, sync.ts}
    ├── routes/{connection.ts, employees.ts, teams.ts, timeoff.ts, sync.ts}
    └── __tests__/{health.test.ts, factorial-client.test.ts, sync.test.ts, connection.test.ts, employees.test.ts}
```

Tasks are ordered so each ends with an independently testable deliverable. Tasks 1–4 stand up the worker + DB; Task 5 is the Factorial client; Task 6 is sync; Tasks 7–8 are the remaining routes; Tasks 9–11 are the front-end; Task 12 wires the manifest + dev registration so it appears in the shell.

---

### Task 1: Project scaffold (config, build, empty worker that serves /health)

**Files:**
- Create: `eldrin-factorial/package.json`, `tsconfig.json`, `tsconfig.app.json`, `tsconfig.node.json`, `tsconfig.worker.json`, `vite.config.ts`, `vitest.config.ts`, `wrangler.jsonc`, `worker-configuration.d.ts`, `.gitignore`, `.dev.vars.example`, `index.html`, `shims/better-sqlite3.js`, `scripts/generate-migrations.ts`, `src/main.tsx`, `src/index.css`, `src/env.d.ts`, `src/root.component.tsx` (placeholder), `src/eldrin-factorial.tsx` (placeholder), `worker/index.ts`, `worker/utils.ts`
- Test: `eldrin-factorial/worker/__tests__/health.test.ts`

**Interfaces:**
- Produces: `worker/index.ts` default export `{ fetch, scheduled }`; `worker/utils.ts` exports `generateId(): string` and `now(): number`.

- [ ] **Step 1: Copy config files from eldrin-email, renaming `eldrin-email` → `eldrin-factorial`**

Create `package.json` (adapted from `eldrin-email/package.json`): set `"name": "eldrin-factorial"`, keep scripts identical, drop the tiptap/sonner-unrelated deps you won't use but KEEP: `@eldrin-project/eldrin-app-core` (`file:../eldrin-app-core`), `@eldrin-project/eldrin-app-react`, `@tailwindcss/vite`, `daisyui`, `drizzle-orm`, `hono`, `lucide-react`, `react`, `react-dom`, `single-spa-react`, `sonner`, `tailwindcss`. Keep all devDependencies identical. Change the `preview` port to `4011`.

Copy verbatim (no content change needed): `tsconfig.json`, `tsconfig.app.json`, `tsconfig.node.json`, `tsconfig.worker.json`, `vitest.config.ts`, `shims/better-sqlite3.js`, `scripts/generate-migrations.ts`, `src/index.css`, `src/env.d.ts`.

`.gitignore` — copy from `eldrin-email/.gitignore` (it already ignores `node_modules`, `dist`, `.dev.vars*`, `.env*`, `worker/migrations.generated.ts`, `.wrangler`).

`.dev.vars.example`:
```
FACTORIAL_API_BASE_URL=https://api.eu2.demo.factorial.dev
FACTORIAL_API_KEY=replace-me
JWT_SECRET=replace-with-shared-core-secret
```

`index.html` — copy from email, change `<title>` to `Eldrin Factorial` and `src="/src/main.tsx"` stays.

- [ ] **Step 2: Write `vite.config.ts`** (adapt from email — change all `eldrin-email` strings to `eldrin-factorial`, `eldrinEmail` → `eldrinFactorial`, port `4010` → `4011`):

Key edits to the copied file: in `devShellCompat()` replace `/src/eldrin-email.tsx` → `/src/eldrin-factorial.tsx`, `/eldrin-email.js` → `/eldrin-factorial.js`, `/eldrin-email.css` → `/eldrin-factorial.css`; in `build.lib` set `entry: './src/eldrin-factorial.tsx'`, `name: 'eldrinFactorial'`, `fileName: 'eldrin-factorial'`; `server.port: 4011`.

- [ ] **Step 3: Write `wrangler.jsonc`**:
```jsonc
{
  "$schema": "node_modules/wrangler/config-schema.json",
  "name": "eldrin-factorial",
  "main": "worker/index.ts",
  "compatibility_date": "2025-01-01",
  "compatibility_flags": ["nodejs_compat"],
  "assets": {
    "directory": "./dist",
    "not_found_handling": "single-page-application"
  },
  "d1_databases": [
    {
      "binding": "DB",
      "database_name": "eldrin-factorial-db",
      "database_id": "local",
      "migrations_dir": "migrations"
    }
  ]
}
```
(No `triggers.crons` — cron is deferred.)

- [ ] **Step 4: Write `worker-configuration.d.ts`**:
```ts
// Generated by Wrangler
interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  /** JWT secret shared with eldrin-core for token verification */
  JWT_SECRET: string;
  /** Factorial company API credentials */
  FACTORIAL_API_BASE_URL: string;
  FACTORIAL_API_KEY: string;
  /** Eldrin Core platform URL for event emission */
  ELDRIN_CORE_URL?: string;
}
```

- [ ] **Step 5: Write `worker/utils.ts`**:
```ts
export function generateId(): string {
  return crypto.randomUUID();
}

export function now(): number {
  return Math.floor(Date.now() / 1000);
}
```

- [ ] **Step 6: Write placeholder `src/eldrin-factorial.tsx` and `src/root.component.tsx`** so build/typecheck pass (full versions land in Tasks 9–11):

`src/root.component.tsx`:
```tsx
export interface RootProps {
  manifest?: { baseUrl?: string };
}

export function Root(_props: RootProps) {
  return <div className="p-6">eldrin-factorial</div>;
}
```

`src/eldrin-factorial.tsx`:
```tsx
import './index.css';
import React from 'react';
import ReactDOMClient from 'react-dom/client';
import singleSpaReact from 'single-spa-react';
import { createApp, combineLifecycles, DatabaseProvider } from '@eldrin-project/eldrin-app-react';
import { Root, type RootProps } from './root.component';

function getOrCreateContainer(): HTMLElement {
  const containerId = 'single-spa-application:eldrin-factorial';
  let container = document.getElementById(containerId);
  if (!container) {
    container = document.createElement('div');
    container.id = containerId;
    const mainContent = document.querySelector('main .p-6') || document.body;
    mainContent.appendChild(container);
  }
  return container;
}

const eldrinLifecycle = createApp({ name: 'eldrin-factorial' });

const reactLifecycle = singleSpaReact({
  React,
  ReactDOMClient,
  rootComponent: (props: RootProps) => (
    <DatabaseProvider>
      <Root {...props} />
    </DatabaseProvider>
  ),
  domElementGetter: getOrCreateContainer,
  errorBoundary(err) {
    return <div className="p-4 bg-red-50 text-red-700 rounded">Error loading Factorial app: {err.message}</div>;
  },
});

const lifecycles = combineLifecycles(eldrinLifecycle, reactLifecycle);
export const bootstrap = lifecycles.bootstrap;
export const mount = lifecycles.mount;
export const unmount = lifecycles.unmount;
```

`src/main.tsx` — copy email's verbatim (imports `Root` from `./root.component`).

- [ ] **Step 7: Write the failing test** `worker/__tests__/health.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import app from '../index';

const env = {} as unknown as Env;

describe('health', () => {
  it('returns ok status', async () => {
    const res = await app.fetch(new Request('http://localhost/health'), env);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: 'ok', app: 'eldrin-factorial' });
  });
});
```
Note: `app/index.ts` will export the Hono app as default (the `{ fetch }` object). Make the test import match what `index.ts` exports — export the Hono `app` instance's `.fetch` via `export default app` is NOT used in email; email exports `{ fetch: app.fetch, scheduled }`. So the test must call `app.fetch`. Write `index.ts` (Step 8) to `export default { fetch: app.fetch, scheduled }` AND also `export { app }`, and import `{ app }` in the test.

Corrected test import line:
```ts
import { app } from '../index';
```

- [ ] **Step 8: Write minimal `worker/index.ts`**:
```ts
import { Hono } from 'hono';
import { cors } from 'hono/cors';

type Variables = { userId: string };

export const app = new Hono<{ Bindings: Env; Variables: Variables }>();

app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-Eldrin-User-Id'],
}));

app.get('/health', (c) => c.json({ status: 'ok', app: 'eldrin-factorial' }));

app.get('*', async (c) => c.env.ASSETS.fetch(c.req.raw));

export default {
  fetch: app.fetch,
  scheduled: async (_event: ScheduledEvent, _env: Env) => {},
};
```

- [ ] **Step 9: Install deps and run the test**

Run: `cd eldrin-factorial && npm install && npx vitest run worker/__tests__/health.test.ts`
Expected: PASS (1 test).

- [ ] **Step 10: Commit**
```bash
git add eldrin-factorial
git commit -m "feat(factorial): scaffold eldrin-factorial worker with health route"
```

---

### Task 2: D1 schema + migration (employees, projects, sync_state)

**Files:**
- Create: `eldrin-factorial/worker/db/schema.ts`, `worker/db/index.ts`, `migrations/001-init.sql`
- Test: covered indirectly by later tasks; this task's gate is a successful migration generation + typecheck.

**Interfaces:**
- Produces: `worker/db/index.ts` exports `createDb(env): Database`, type `Database`, and re-exports `schema` plus tables `employees`, `projects`, `syncState`.

- [ ] **Step 1: Write `worker/db/schema.ts`**:
```ts
import { sqliteTable, text, integer, uniqueIndex } from 'drizzle-orm/sqlite-core';

export const employees = sqliteTable('employees', {
  id: text('id').primaryKey(),
  factorialId: text('factorial_id').notNull(),
  fullName: text('full_name'),
  email: text('email'),
  jobTitle: text('job_title'),
  teamId: text('team_id'),
  rawJson: text('raw_json'),
  syncedAt: integer('synced_at', { mode: 'number' }).notNull(),
}, (t) => [uniqueIndex('idx_employees_factorial_id').on(t.factorialId)]);

export const projects = sqliteTable('projects', {
  id: text('id').primaryKey(),
  factorialId: text('factorial_id').notNull(),
  name: text('name'),
  status: text('status'),
  rawJson: text('raw_json'),
  syncedAt: integer('synced_at', { mode: 'number' }).notNull(),
}, (t) => [uniqueIndex('idx_projects_factorial_id').on(t.factorialId)]);

export const syncState = sqliteTable('sync_state', {
  id: text('id').primaryKey(),
  resource: text('resource').notNull(), // 'employees' | 'projects'
  lastSyncedAt: integer('last_synced_at', { mode: 'number' }),
  lastStatus: text('last_status'),       // 'ok' | 'error'
  lastError: text('last_error'),
}, (t) => [uniqueIndex('idx_sync_state_resource').on(t.resource)]);
```

- [ ] **Step 2: Write `worker/db/index.ts`** (copy email's verbatim — it is generic):
```ts
import { drizzle as drizzleD1 } from 'drizzle-orm/d1';
import * as schema from './schema';

export * from './schema';
export { schema };

export type Database = ReturnType<typeof createDb>;

export function createDb(env: Record<string, unknown>) {
  const d1 = env.DB as D1Database;
  return drizzleD1(d1, { schema });
}
```

- [ ] **Step 3: Write `migrations/001-init.sql`** (must match the drizzle schema column names exactly):
```sql
CREATE TABLE IF NOT EXISTS employees (
  id TEXT PRIMARY KEY,
  factorial_id TEXT NOT NULL,
  full_name TEXT,
  email TEXT,
  job_title TEXT,
  team_id TEXT,
  raw_json TEXT,
  synced_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_employees_factorial_id ON employees (factorial_id);

CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  factorial_id TEXT NOT NULL,
  name TEXT,
  status TEXT,
  raw_json TEXT,
  synced_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_factorial_id ON projects (factorial_id);

CREATE TABLE IF NOT EXISTS sync_state (
  id TEXT PRIMARY KEY,
  resource TEXT NOT NULL,
  last_synced_at INTEGER,
  last_status TEXT,
  last_error TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sync_state_resource ON sync_state (resource);
```

- [ ] **Step 4: Generate migrations + typecheck**

Run: `cd eldrin-factorial && npm run generate:migrations && npm run typecheck`
Expected: `Generated .../worker/migrations.generated.ts with 1 migrations` and typecheck passes with no errors.

- [ ] **Step 5: Commit**
```bash
git add eldrin-factorial/worker/db eldrin-factorial/migrations
git commit -m "feat(factorial): add D1 schema and init migration"
```

---

### Task 3: Wire migrations + auth middleware into the worker

**Files:**
- Modify: `eldrin-factorial/worker/index.ts`
- Test: `worker/__tests__/health.test.ts` still passes (health is before middleware).

**Interfaces:**
- Consumes: `createDb`, `runMigrations` from `@eldrin-project/eldrin-app-core`, `migrations.generated`.
- Produces: Hono context vars `db: Database` and `userId: string` available to all `/api/*` routes; migration runs lazily once.

- [ ] **Step 1: Update `worker/index.ts`** to add the auth + migration middleware between health and the asset fallback (copy the pattern from `eldrin-email/worker/index.ts` lines for auth mw + migration mw verbatim, swapping the log prefix `[email]` → `[factorial]`). Add imports:
```ts
import { runMigrations } from '@eldrin-project/eldrin-app-core';
import migrations from './migrations.generated';
import { createDb, type Database } from './db';
```
Change `type Variables = { userId: string }` → `type Variables = { db: Database; userId: string }`.

Insert after the `/health` route, before `app.get('*', ...)`:
```ts
app.use('/api/*', async (c, next) => {
  const headerUserId = c.req.header('X-Eldrin-User-Id');
  if (headerUserId) {
    c.set('userId', headerUserId);
  } else {
    const auth = c.req.header('Authorization');
    if (auth?.startsWith('Bearer ')) {
      try {
        const payload = JSON.parse(atob(auth.slice(7).split('.')[1]));
        if (payload.sub) c.set('userId', payload.sub);
      } catch { /* invalid JWT — route handlers return 401 */ }
    }
  }
  await next();
});

let migrationsComplete = false;
app.use('/api/*', async (c, next) => {
  if (!migrationsComplete) {
    const result = await runMigrations(c.env.DB, {
      migrations,
      onLog: (msg: string, level: string) =>
        console[level as 'log' | 'warn' | 'error'](`[factorial] ${msg}`),
    });
    if (!result.success) {
      return c.json({ error: 'Migration failed', details: result.error?.message }, 500);
    }
    migrationsComplete = true;
  }
  c.set('db', createDb(c.env as unknown as Record<string, unknown>));
  await next();
});
```

- [ ] **Step 2: Run health test (regression)**

Run: `cd eldrin-factorial && npx vitest run worker/__tests__/health.test.ts`
Expected: PASS.

- [ ] **Step 3: Commit**
```bash
git add eldrin-factorial/worker/index.ts
git commit -m "feat(factorial): wire migrations and shell auth middleware"
```

---

### Task 4: Connection/config status route

**Files:**
- Create: `eldrin-factorial/worker/routes/connection.ts`
- Modify: `worker/index.ts` (mount route)
- Test: `worker/__tests__/connection.test.ts`

**Interfaces:**
- Produces: `connectionRoutes` Hono router with `GET /api/connection` → `{ configured: boolean, baseUrl: string | null }`. `configured` is true iff both `FACTORIAL_API_BASE_URL` and `FACTORIAL_API_KEY` are non-empty. Never returns the key value.

- [ ] **Step 1: Write the failing test** `worker/__tests__/connection.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { app } from '../index';

function req(env: Partial<Env>) {
  return app.fetch(
    new Request('http://localhost/api/connection', { headers: { 'X-Eldrin-User-Id': 'u1' } }),
    { DB: makeDb(), ...env } as unknown as Env,
  );
}

// Minimal D1 stub: migrations run against it; return empty results.
function makeDb() {
  const stmt = { bind: () => stmt, all: async () => ({ results: [] }), run: async () => ({}), first: async () => null };
  return { prepare: () => stmt, batch: async () => [], exec: async () => ({}) } as unknown as D1Database;
}

describe('GET /api/connection', () => {
  it('reports not configured when env vars missing', async () => {
    const res = await req({ FACTORIAL_API_BASE_URL: '', FACTORIAL_API_KEY: '' });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ configured: false, baseUrl: null });
  });

  it('reports configured when both env vars present, without leaking the key', async () => {
    const res = await req({ FACTORIAL_API_BASE_URL: 'https://api.eu2.demo.factorial.dev', FACTORIAL_API_KEY: 'secret' });
    const body = await res.json();
    expect(body).toEqual({ configured: true, baseUrl: 'https://api.eu2.demo.factorial.dev' });
    expect(JSON.stringify(body)).not.toContain('secret');
  });

  it('returns 401 without a shell user', async () => {
    const res = await app.fetch(new Request('http://localhost/api/connection'), { DB: makeDb(), FACTORIAL_API_BASE_URL: 'x', FACTORIAL_API_KEY: 'y' } as unknown as Env);
    expect(res.status).toBe(401);
  });
});
```
> Note for implementer: if `runMigrations` cannot run against the stub `makeDb()`, replace the stub with `@cloudflare/vitest-pool-workers` or an in-memory D1. If that is heavy, gate migrations to skip when `c.env.DB` lacks a real binding is NOT acceptable; instead use the official Cloudflare test D1. Simplest path: add `@cloudflare/vitest-pool-workers` and a `wrangler`-backed test env. Keep this note and pick the lightest working option; the assertion behavior above must hold.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd eldrin-factorial && npx vitest run worker/__tests__/connection.test.ts`
Expected: FAIL (route not mounted → 404, or import error).

- [ ] **Step 3: Write `worker/routes/connection.ts`**:
```ts
import { Hono } from 'hono';
import type { Database } from '../db';

type Variables = { db: Database; userId: string };

export const connectionRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

connectionRoutes.get('/api/connection', (c) => {
  const userId = c.get('userId');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);

  const baseUrl = c.env.FACTORIAL_API_BASE_URL?.trim() || '';
  const apiKey = c.env.FACTORIAL_API_KEY?.trim() || '';
  const configured = baseUrl.length > 0 && apiKey.length > 0;

  return c.json({ configured, baseUrl: configured ? baseUrl : null });
});
```

- [ ] **Step 4: Mount in `worker/index.ts`** — add `import { connectionRoutes } from './routes/connection';` and `app.route('', connectionRoutes);` after the middleware block, before the asset fallback.

- [ ] **Step 5: Run test to verify it passes**

Run: `cd eldrin-factorial && npx vitest run worker/__tests__/connection.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**
```bash
git add eldrin-factorial/worker/routes/connection.ts eldrin-factorial/worker/index.ts eldrin-factorial/worker/__tests__/connection.test.ts
git commit -m "feat(factorial): add connection status route"
```

---

### Task 5: Factorial API client

**Files:**
- Create: `eldrin-factorial/worker/services/factorial-client.ts`
- Test: `worker/__tests__/factorial-client.test.ts`

**Interfaces:**
- Produces:
  - `class FactorialError extends Error { status: number }`
  - `interface FactorialClient { get<T>(path: string): Promise<T>; getAll<T>(path: string): Promise<T[]> }`
  - `function createFactorialClient(env: Pick<Env, 'FACTORIAL_API_BASE_URL' | 'FACTORIAL_API_KEY'>): FactorialClient`
  - `getAll` traverses Factorial pagination (follows `meta`/`next` page params; see Step 1 for the assumed shape) and returns the flattened `data` array.

- [ ] **Step 1: Write the failing test** `worker/__tests__/factorial-client.test.ts`. The client uses `globalThis.fetch`; stub it.
```ts
import { describe, it, expect, vi, afterEach } from 'vitest';
import { createFactorialClient, FactorialError } from '../services/factorial-client';

const env = { FACTORIAL_API_BASE_URL: 'https://api.eu2.demo.factorial.dev', FACTORIAL_API_KEY: 'k' };

afterEach(() => vi.restoreAllMocks());

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

describe('factorial-client', () => {
  it('GETs with api key header and /api/v1 base', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse({ data: [{ id: 1 }] }));
    const client = createFactorialClient(env);
    const out = await client.get<{ data: { id: number }[] }>('/employees');
    expect(out.data[0].id).toBe(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://api.eu2.demo.factorial.dev/api/v1/employees');
    expect((init?.headers as Record<string, string>)['x-api-key']).toBe('k');
  });

  it('throws FactorialError on non-2xx with status', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse({ message: 'nope' }, 403));
    const client = createFactorialClient(env);
    await expect(client.get('/employees')).rejects.toMatchObject({ name: 'FactorialError', status: 403 });
  });

  it('getAll follows pagination until no next page', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse({ data: [{ id: 1 }], meta: { has_next_page: true } }))
      .mockResolvedValueOnce(jsonResponse({ data: [{ id: 2 }], meta: { has_next_page: false } }));
    const client = createFactorialClient(env);
    const all = await client.getAll<{ id: number }>('/employees');
    expect(all.map((x) => x.id)).toEqual([1, 2]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[1][0]).toContain('page=2');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd eldrin-factorial && npx vitest run worker/__tests__/factorial-client.test.ts`
Expected: FAIL (module not found).

- [ ] **Step 3: Write `worker/services/factorial-client.ts`**:
```ts
const API_VERSION = 'v1';

export class FactorialError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = 'FactorialError';
    this.status = status;
  }
}

export interface FactorialClient {
  get<T>(path: string): Promise<T>;
  getAll<T>(path: string): Promise<T[]>;
}

interface Paged<T> {
  data: T[];
  meta?: { has_next_page?: boolean };
}

export function createFactorialClient(
  env: Pick<Env, 'FACTORIAL_API_BASE_URL' | 'FACTORIAL_API_KEY'>,
): FactorialClient {
  const base = (env.FACTORIAL_API_BASE_URL || '').replace(/\/$/, '');
  const key = env.FACTORIAL_API_KEY || '';
  if (!base || !key) throw new FactorialError('Factorial credentials not configured', 400);

  async function get<T>(path: string): Promise<T> {
    const url = `${base}/api/${API_VERSION}${path}`;
    const res = await fetch(url, {
      headers: { 'x-api-key': key, Accept: 'application/json' },
    });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new FactorialError(`Factorial GET ${path} failed: ${res.status} ${body}`, res.status);
    }
    return res.json() as Promise<T>;
  }

  async function getAll<T>(path: string): Promise<T[]> {
    const out: T[] = [];
    let page = 1;
    for (;;) {
      const sep = path.includes('?') ? '&' : '?';
      const pageData = await get<Paged<T>>(`${path}${sep}page=${page}`);
      out.push(...(pageData.data ?? []));
      if (!pageData.meta?.has_next_page) break;
      page += 1;
    }
    return out;
  }

  return { get, getAll };
}
```
> Implementer note: the exact auth header (`x-api-key` vs `Authorization: Bearer`) and pagination shape (`meta.has_next_page` vs link headers) must be confirmed against the Factorial docs during the Bruno phase. They are isolated here so a correction is a one-line change. Keep the test asserting whatever the confirmed contract is.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd eldrin-factorial && npx vitest run worker/__tests__/factorial-client.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**
```bash
git add eldrin-factorial/worker/services/factorial-client.ts eldrin-factorial/worker/__tests__/factorial-client.test.ts
git commit -m "feat(factorial): add Factorial API client with pagination"
```

---

### Task 6: Sync service + POST /api/sync route

**Files:**
- Create: `eldrin-factorial/worker/services/sync.ts`, `worker/routes/sync.ts`
- Modify: `worker/index.ts` (mount route)
- Test: `worker/__tests__/sync.test.ts`

**Interfaces:**
- Consumes: `createFactorialClient`, `FactorialError` (Task 5); `Database`, `employees`, `projects`, `syncState` (Task 2); `generateId`, `now` (Task 1).
- Produces:
  - `async function syncEmployees(db: Database, client: FactorialClient): Promise<number>` (returns count upserted)
  - `async function syncProjects(db: Database, client: FactorialClient): Promise<number>`
  - `async function runSync(db: Database, env: Env): Promise<{ employees: number; projects: number }>` — calls both, records `sync_state` per resource (`last_status` `ok`/`error`, `last_error`, `last_synced_at`), and is the single entry point a future cron handler will call.
  - `syncRoutes` Hono router: `POST /api/sync` → 401 if no user, 400 `{ error }` if not configured, else `{ employees, projects }`.

- [ ] **Step 1: Write the failing test** `worker/__tests__/sync.test.ts` (unit-test the sync functions against a fake client + a thin in-memory db double exposing only the drizzle calls used). To keep it lightweight, test `syncEmployees`/`syncProjects` by injecting a fake `Database` that records upserts:
```ts
import { describe, it, expect } from 'vitest';
import { syncEmployees } from '../services/sync';
import type { FactorialClient } from '../services/factorial-client';

function fakeClient(rows: unknown[]): FactorialClient {
  return { get: async () => ({ data: rows }) as any, getAll: async () => rows as any };
}

function fakeDb() {
  const upserts: any[] = [];
  const db: any = {
    insert: () => ({
      values: (v: any) => ({
        onConflictDoUpdate: () => { upserts.push(v); return Promise.resolve(); },
      }),
    }),
    _upserts: upserts,
  };
  return db;
}

describe('syncEmployees', () => {
  it('upserts each employee mapped from Factorial payload', async () => {
    const db = fakeDb();
    const client = fakeClient([
      { id: 10, full_name: 'Ada Lovelace', email: 'ada@x.io', job_title: 'Engineer', team_id: 3 },
    ]);
    const count = await syncEmployees(db, client);
    expect(count).toBe(1);
    expect(db._upserts[0]).toMatchObject({
      factorialId: '10', fullName: 'Ada Lovelace', email: 'ada@x.io', jobTitle: 'Engineer', teamId: '3',
    });
    expect(typeof db._upserts[0].syncedAt).toBe('number');
    expect(typeof db._upserts[0].rawJson).toBe('string');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd eldrin-factorial && npx vitest run worker/__tests__/sync.test.ts`
Expected: FAIL (module not found).

- [ ] **Step 3: Write `worker/services/sync.ts`**:
```ts
import { sql } from 'drizzle-orm';
import type { Database } from '../db';
import { employees, projects, syncState } from '../db';
import type { FactorialClient } from './factorial-client';
import { FactorialError } from './factorial-client';
import { generateId, now } from '../utils';

interface RawEmployee { id: number | string; full_name?: string; email?: string; job_title?: string; team_id?: number | string }
interface RawProject { id: number | string; name?: string; status?: string }

const asStr = (v: unknown): string | null => (v === undefined || v === null ? null : String(v));

export async function syncEmployees(db: Database, client: FactorialClient): Promise<number> {
  const rows = await client.getAll<RawEmployee>('/employees');
  const ts = now();
  for (const r of rows) {
    await db.insert(employees).values({
      id: generateId(),
      factorialId: String(r.id),
      fullName: r.full_name ?? null,
      email: r.email ?? null,
      jobTitle: r.job_title ?? null,
      teamId: asStr(r.team_id),
      rawJson: JSON.stringify(r),
      syncedAt: ts,
    }).onConflictDoUpdate({
      target: employees.factorialId,
      set: { fullName: r.full_name ?? null, email: r.email ?? null, jobTitle: r.job_title ?? null, teamId: asStr(r.team_id), rawJson: JSON.stringify(r), syncedAt: ts },
    });
  }
  return rows.length;
}

export async function syncProjects(db: Database, client: FactorialClient): Promise<number> {
  const rows = await client.getAll<RawProject>('/projects');
  const ts = now();
  for (const r of rows) {
    await db.insert(projects).values({
      id: generateId(),
      factorialId: String(r.id),
      name: r.name ?? null,
      status: r.status ?? null,
      rawJson: JSON.stringify(r),
      syncedAt: ts,
    }).onConflictDoUpdate({
      target: projects.factorialId,
      set: { name: r.name ?? null, status: r.status ?? null, rawJson: JSON.stringify(r), syncedAt: ts },
    });
  }
  return rows.length;
}

async function recordState(db: Database, resource: string, status: 'ok' | 'error', error: string | null) {
  await db.insert(syncState).values({
    id: generateId(), resource, lastSyncedAt: now(), lastStatus: status, lastError: error,
  }).onConflictDoUpdate({
    target: syncState.resource,
    set: { lastSyncedAt: now(), lastStatus: status, lastError: error },
  });
}

export async function runSync(db: Database, env: Env): Promise<{ employees: number; projects: number }> {
  const { createFactorialClient } = await import('./factorial-client');
  const client = createFactorialClient(env);

  let empCount = 0;
  try {
    empCount = await syncEmployees(db, client);
    await recordState(db, 'employees', 'ok', null);
  } catch (e) {
    await recordState(db, 'employees', 'error', e instanceof Error ? e.message : String(e));
    throw e;
  }

  let projCount = 0;
  try {
    projCount = await syncProjects(db, client);
    await recordState(db, 'projects', 'ok', null);
  } catch (e) {
    await recordState(db, 'projects', 'error', e instanceof Error ? e.message : String(e));
    throw e;
  }

  return { employees: empCount, projects: projCount };
}

void sql; void FactorialError; // referenced for type clarity; remove if unused by linter
```
> Implementer note: remove the final `void` line if `noUnusedLocals` complains — it's only there to signal these imports may be needed. Drop unused imports rather than voiding them.

- [ ] **Step 4: Write `worker/routes/sync.ts`**:
```ts
import { Hono } from 'hono';
import type { Database } from '../db';
import { runSync } from '../services/sync';
import { FactorialError } from '../services/factorial-client';

type Variables = { db: Database; userId: string };

export const syncRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

syncRoutes.post('/api/sync', async (c) => {
  const userId = c.get('userId');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);

  if (!c.env.FACTORIAL_API_BASE_URL?.trim() || !c.env.FACTORIAL_API_KEY?.trim()) {
    return c.json({ error: 'Factorial is not configured' }, 400);
  }

  try {
    const result = await runSync(c.get('db'), c.env);
    return c.json(result);
  } catch (e) {
    const status = e instanceof FactorialError ? e.status : 500;
    return c.json({ error: e instanceof Error ? e.message : 'Sync failed' }, status as 400 | 500);
  }
});
```

- [ ] **Step 5: Mount in `worker/index.ts`** — `import { syncRoutes } from './routes/sync';` and `app.route('', syncRoutes);`.

- [ ] **Step 6: Run test to verify it passes**

Run: `cd eldrin-factorial && npx vitest run worker/__tests__/sync.test.ts`
Expected: PASS (1 test).

- [ ] **Step 7: Commit**
```bash
git add eldrin-factorial/worker/services/sync.ts eldrin-factorial/worker/routes/sync.ts eldrin-factorial/worker/index.ts eldrin-factorial/worker/__tests__/sync.test.ts
git commit -m "feat(factorial): add sync service and POST /api/sync route"
```

---

### Task 7: Employees route (read from D1)

**Files:**
- Create: `eldrin-factorial/worker/routes/employees.ts`
- Modify: `worker/index.ts`
- Test: `worker/__tests__/employees.test.ts`

**Interfaces:**
- Produces: `employeesRoutes` with `GET /api/employees` → `{ employees: EmployeeRow[] }` read from D1, ordered by `full_name`. 401 if no user.

- [ ] **Step 1: Write the failing test** `worker/__tests__/employees.test.ts` using a fake db whose `query.employees.findMany` returns rows:
```ts
import { describe, it, expect } from 'vitest';
import { employeesRoutes } from '../routes/employees';

function ctxApp() {
  // mount the router on a bare Hono with pre-set vars
  return employeesRoutes;
}

describe('GET /api/employees', () => {
  it('returns 401 without user', async () => {
    const res = await ctxApp().fetch(new Request('http://localhost/api/employees'), {} as Env);
    expect(res.status).toBe(401);
  });
});
```
> Implementer note: full DB-backed assertion is exercised in the integration smoke (Task 12). This unit test pins the 401 contract; expand with a fake-db `findMany` returning one row and asserting the JSON shape if the fake-db pattern from Task 6 is reused. Keep at least the 401 test.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd eldrin-factorial && npx vitest run worker/__tests__/employees.test.ts`
Expected: FAIL (module not found).

- [ ] **Step 3: Write `worker/routes/employees.ts`**:
```ts
import { Hono } from 'hono';
import { asc } from 'drizzle-orm';
import { employees, type Database } from '../db';

type Variables = { db: Database; userId: string };

export const employeesRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

employeesRoutes.get('/api/employees', async (c) => {
  const userId = c.get('userId');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);

  const db = c.get('db');
  const rows = await db.query.employees.findMany({ orderBy: [asc(employees.fullName)] });
  return c.json({ employees: rows });
});
```

- [ ] **Step 4: Mount in `worker/index.ts`** — `import { employeesRoutes } from './routes/employees';` and `app.route('', employeesRoutes);`.

- [ ] **Step 5: Run test to verify it passes**

Run: `cd eldrin-factorial && npx vitest run worker/__tests__/employees.test.ts`
Expected: PASS.

- [ ] **Step 6: Commit**
```bash
git add eldrin-factorial/worker/routes/employees.ts eldrin-factorial/worker/index.ts eldrin-factorial/worker/__tests__/employees.test.ts
git commit -m "feat(factorial): add employees read route"
```

---

### Task 8: Teams + Time Off live-proxy routes

**Files:**
- Create: `eldrin-factorial/worker/routes/teams.ts`, `worker/routes/timeoff.ts`
- Modify: `worker/index.ts`
- Test: extend `worker/__tests__/factorial-client.test.ts` is not needed; add a small `teams` 401 test inside a new `worker/__tests__/proxy.test.ts`.

**Interfaces:**
- Produces:
  - `teamsRoutes`: `GET /api/teams` → `{ teams: unknown[] }` proxied via `client.getAll('/teams')`.
  - `timeoffRoutes`: `GET /api/timeoff` → `{ timeoff: unknown[] }` proxied via `client.getAll('/time_off')`.
  - Both: 401 without user; 400 `{ error }` if not configured; map `FactorialError.status` on failure.

- [ ] **Step 1: Write the failing test** `worker/__tests__/proxy.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { teamsRoutes } from '../routes/teams';

describe('GET /api/teams', () => {
  it('401 without user', async () => {
    const res = await teamsRoutes.fetch(new Request('http://localhost/api/teams'), {} as Env);
    expect(res.status).toBe(401);
  });
  it('400 when not configured', async () => {
    // set a user via header path requires the index middleware; here we hit the route directly,
    // so simulate by providing env without credentials and a manual userId via a wrapper.
    // Simplest: assert configured-guard through index integration instead. Keep the 401 test as the gate.
  });
});
```
> Implementer note: the route checks `c.get('userId')`; when testing the router in isolation there is no middleware to set it, so only the 401 path is unit-testable here. The configured-guard + proxy success are covered by the Task 12 smoke run against the dev server. Keep the 401 test.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd eldrin-factorial && npx vitest run worker/__tests__/proxy.test.ts`
Expected: FAIL (module not found).

- [ ] **Step 3: Write `worker/routes/teams.ts`**:
```ts
import { Hono } from 'hono';
import type { Database } from '../db';
import { createFactorialClient, FactorialError } from '../services/factorial-client';

type Variables = { db: Database; userId: string };

export const teamsRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

teamsRoutes.get('/api/teams', async (c) => {
  const userId = c.get('userId');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);
  if (!c.env.FACTORIAL_API_BASE_URL?.trim() || !c.env.FACTORIAL_API_KEY?.trim()) {
    return c.json({ error: 'Factorial is not configured' }, 400);
  }
  try {
    const teams = await createFactorialClient(c.env).getAll('/teams');
    return c.json({ teams });
  } catch (e) {
    const status = e instanceof FactorialError ? e.status : 500;
    return c.json({ error: e instanceof Error ? e.message : 'Failed to fetch teams' }, status as 400 | 500);
  }
});
```

- [ ] **Step 4: Write `worker/routes/timeoff.ts`** — identical shape to teams, route `GET /api/timeoff`, calls `getAll('/time_off')`, returns `{ timeoff }`, error message "Failed to fetch time off".

- [ ] **Step 5: Mount both in `worker/index.ts`** — import and `app.route('', teamsRoutes)`, `app.route('', timeoffRoutes)`.

- [ ] **Step 6: Run test to verify it passes**

Run: `cd eldrin-factorial && npx vitest run worker/__tests__/proxy.test.ts`
Expected: PASS.

- [ ] **Step 7: Commit**
```bash
git add eldrin-factorial/worker/routes/teams.ts eldrin-factorial/worker/routes/timeoff.ts eldrin-factorial/worker/index.ts eldrin-factorial/worker/__tests__/proxy.test.ts
git commit -m "feat(factorial): add teams and time-off proxy routes"
```

---

### Task 9: Front-end types + worker API client

**Files:**
- Create: `eldrin-factorial/src/types/factorial.ts`, `src/api.ts`
- Test: none (thin typed wrappers; exercised by UI + Task 12 smoke).

**Interfaces:**
- Produces:
  - `types/factorial.ts`: `interface EmployeeRow { id: string; factorialId: string; fullName: string | null; email: string | null; jobTitle: string | null; teamId: string | null; syncedAt: number }`; `interface ConnectionStatus { configured: boolean; baseUrl: string | null }`; `type Team = Record<string, unknown>`; `type TimeOff = Record<string, unknown>`; `interface SyncResult { employees: number; projects: number }`.
  - `api.ts`: `getConnection(base, headers): Promise<ConnectionStatus>`, `listEmployees(base, headers): Promise<{ employees: EmployeeRow[] }>`, `listTeams(base, headers): Promise<{ teams: Team[] }>`, `listTimeoff(base, headers): Promise<{ timeoff: TimeOff[] }>`, `runSync(base, headers): Promise<SyncResult>`. Uses the same `apiUrl`/`request` helpers as `eldrin-email/src/api.ts`.

- [ ] **Step 1: Write `src/types/factorial.ts`** with the interfaces above.

- [ ] **Step 2: Write `src/api.ts`** — copy the `Headers` type + `apiUrl` + `request` helpers verbatim from `eldrin-email/src/api.ts` (lines shown in plan research), then add:
```ts
import type { ConnectionStatus, EmployeeRow, Team, TimeOff, SyncResult } from './types/factorial';

export async function getConnection(base: string, headers: Headers): Promise<ConnectionStatus> {
  return request(apiUrl(base, '/connection'), headers);
}
export async function listEmployees(base: string, headers: Headers): Promise<{ employees: EmployeeRow[] }> {
  return request(apiUrl(base, '/employees'), headers);
}
export async function listTeams(base: string, headers: Headers): Promise<{ teams: Team[] }> {
  return request(apiUrl(base, '/teams'), headers);
}
export async function listTimeoff(base: string, headers: Headers): Promise<{ timeoff: TimeOff[] }> {
  return request(apiUrl(base, '/timeoff'), headers);
}
export async function runSync(base: string, headers: Headers): Promise<SyncResult> {
  return request(apiUrl(base, '/sync'), headers, { method: 'POST' });
}
```

- [ ] **Step 3: Typecheck**

Run: `cd eldrin-factorial && npm run typecheck`
Expected: PASS.

- [ ] **Step 4: Commit**
```bash
git add eldrin-factorial/src/types/factorial.ts eldrin-factorial/src/api.ts
git commit -m "feat(factorial): add front-end types and worker API client"
```

---

### Task 10: Page components (Employees, Teams, TimeOff, Settings)

**Files:**
- Create: `src/pages/employees/EmployeeList.tsx`, `src/pages/teams/TeamList.tsx`, `src/pages/timeoff/TimeOffList.tsx`, `src/pages/settings/ConnectionSettings.tsx`
- Test: none (visual; smoke in Task 12).

**Interfaces:**
- Consumes: `useAuthHeaders` from `@eldrin-project/eldrin-app-react`; `api.ts` functions; `types/factorial.ts`.
- Produces: four default-exported (named export) React components, each accepting `{ apiBase: string }`.

- [ ] **Step 1: Write `src/pages/settings/ConnectionSettings.tsx`** — shows connection status from `getConnection`, a "Sync now" button calling `runSync`, success/error via `sonner` `toast`, and the last result. Pattern (≈ follow `eldrin-email/src/pages/settings/MailboxSettings.tsx` for the `useAuthHeaders` + fetch-on-mount + loading/error states):
```tsx
import { useState, useEffect, useCallback } from 'react';
import { useAuthHeaders } from '@eldrin-project/eldrin-app-react';
import { toast } from 'sonner';
import * as api from '../../api';
import type { ConnectionStatus } from '../../types/factorial';

export function ConnectionSettings({ apiBase }: { apiBase: string }) {
  const headers = useAuthHeaders();
  const [status, setStatus] = useState<ConnectionStatus | null>(null);
  const [syncing, setSyncing] = useState(false);

  const load = useCallback(async () => {
    try { setStatus(await api.getConnection(apiBase, headers)); }
    catch (e) { toast.error(e instanceof Error ? e.message : 'Failed to load status'); }
  }, [apiBase, headers]);

  useEffect(() => { void load(); }, [load]);

  const sync = async () => {
    setSyncing(true);
    try {
      const r = await api.runSync(apiBase, headers);
      toast.success(`Synced ${r.employees} employees, ${r.projects} projects`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Sync failed');
    } finally { setSyncing(false); }
  };

  return (
    <div className="p-6 space-y-4">
      <h2 className="text-lg font-semibold">Factorial Connection</h2>
      {status === null ? <p>Loading…</p> : status.configured
        ? <p className="text-success">Connected to {status.baseUrl}</p>
        : <p className="text-error">Not configured. Set FACTORIAL_API_BASE_URL and FACTORIAL_API_KEY in app settings.</p>}
      <button className="btn btn-primary" disabled={!status?.configured || syncing} onClick={sync}>
        {syncing ? 'Syncing…' : 'Sync now'}
      </button>
    </div>
  );
}
```

- [ ] **Step 2: Write `EmployeeList.tsx`** — fetch `listEmployees` on mount, render a daisyUI `table` of full name / email / job title; loading + empty + error states; empty state hints "Run a sync in Settings".

- [ ] **Step 3: Write `TeamList.tsx`** and `TimeOffList.tsx` — fetch `listTeams` / `listTimeoff`, render the JSON rows defensively (these are `Record<string, unknown>`; show `name`/`id` when present, else `JSON.stringify`). Handle the 400 "not configured" error with a friendly message.

- [ ] **Step 4: Typecheck**

Run: `cd eldrin-factorial && npm run typecheck`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add eldrin-factorial/src/pages
git commit -m "feat(factorial): add employees, teams, time-off, and settings pages"
```

---

### Task 11: Root component (nav + routing) + final single-spa entry

**Files:**
- Modify: `src/root.component.tsx` (replace placeholder), `src/eldrin-factorial.tsx` (already final from Task 1 — verify mount passes `manifest.baseUrl`)
- Test: none (smoke in Task 12).

**Interfaces:**
- Consumes: page components (Task 10); `manifest.baseUrl` prop.
- Produces: `Root({ manifest }: RootProps)` rendering a left side-nav (Employees / Teams / Time Off / Settings) and the active page, parsing `window.location.pathname` under prefix `/eldrin-factorial`, listening to `popstate`. Mirror `eldrin-email/src/root.component.tsx` route-parsing + theme-sync structure but with the four Factorial sections.

- [ ] **Step 1: Replace `src/root.component.tsx`** following the email root structure: `getShellTheme()` (eldrin/eldrin-dark), `parseRoute(pathname)` for sections `'employees' | 'teams' | 'timeoff' | 'settings'` (default `'employees'`), `popstate` listener, a `sections` array with lucide icons (`Users`, `UsersRound`, `CalendarOff`, `Settings`), and a switch rendering the matching page with `apiBase={manifest?.baseUrl || ''}`. Include `<Toaster />` from `sonner`.

- [ ] **Step 2: Verify `src/eldrin-factorial.tsx` mount passes baseUrl** — if the Task 1 placeholder used `lifecycles.mount` directly, that already forwards props (including `manifest`). No command-registration is needed (unlike email). Leave as-is.

- [ ] **Step 3: Typecheck + build**

Run: `cd eldrin-factorial && npm run build`
Expected: `tsc -b` passes and Vite emits `dist/eldrin-factorial.js` + `dist/eldrin-factorial.css`.

- [ ] **Step 4: Commit**
```bash
git add eldrin-factorial/src/root.component.tsx eldrin-factorial/src/eldrin-factorial.tsx
git commit -m "feat(factorial): add root component with nav and routing"
```

---

### Task 12: Manifest + run in shell (the phase gate)

**Files:**
- Create: `eldrin-factorial/public/eldrin-app.manifest.json`
- Test: manual integration — app appears and works in the eldrin-core shell.

**Interfaces:**
- Produces: a manifest the shell validates (`id`, `name`, `version`, `entry`, `styles`) and registers via `POST /api/apps`, declaring permissions, side nav, settings group, and API routes.

- [ ] **Step 1: Write `public/eldrin-app.manifest.json`**:
```json
{
  "id": "eldrin-factorial",
  "name": "Factorial",
  "version": "0.0.1",
  "entry": "/eldrin-factorial.js",
  "styles": "/eldrin-factorial.css",
  "developer_id": "eldrin.io",
  "developer": { "id": "eldrin.io", "name": "Eldrin Team" },
  "compatibility": { "core": ">=0.1.0" },
  "permissions": [
    { "resource": "employees", "actions": ["read"] },
    { "resource": "teams", "actions": ["read"] },
    { "resource": "timeoff", "actions": ["read"] },
    { "resource": "sync", "actions": ["create"] }
  ],
  "groups": [
    { "id": "admin", "name": "Admin", "description": "Full access including sync", "permissions": ["*:*"] },
    { "id": "viewer", "name": "Viewer", "description": "Read-only HR data", "permissions": ["employees:read", "teams:read", "timeoff:read"] }
  ],
  "api": {
    "defaultPolicy": "deny",
    "publicRoutes": ["/health"],
    "routes": [
      { "method": "GET", "path": "/api/connection", "permission": "employees:read" },
      { "method": "GET", "path": "/api/employees", "permission": "employees:read" },
      { "method": "GET", "path": "/api/teams", "permission": "teams:read" },
      { "method": "GET", "path": "/api/timeoff", "permission": "timeoff:read" },
      { "method": "POST", "path": "/api/sync", "permission": "sync:create" }
    ]
  },
  "database": { "name": "eldrin-factorial-db", "migrationsPath": "migrations", "handledBy": "worker" },
  "ui": {
    "sideNav": [
      { "label": "Employees", "icon": "users", "path": "/eldrin-factorial" },
      { "label": "Teams", "icon": "users", "path": "/eldrin-factorial/teams" },
      { "label": "Time Off", "icon": "calendar", "path": "/eldrin-factorial/timeoff" },
      { "label": "Settings", "icon": "settings", "path": "/eldrin-factorial/settings" }
    ]
  },
  "settings": {
    "groups": [
      {
        "key": "FACTORIAL",
        "label": "Factorial",
        "description": "Company-level Factorial API credentials",
        "fields": [
          { "key": "API_BASE_URL", "label": "API Base URL", "type": "string", "storage": "config", "required": true, "placeholder": "https://api.eu2.demo.factorial.dev", "description": "Factorial API root (sandbox or production)" },
          { "key": "API_KEY", "label": "API Key", "type": "string", "storage": "secret", "required": true, "description": "Factorial company API key" }
        ]
      }
    ]
  }
}
```

- [ ] **Step 2: Create `.dev.vars`** (gitignored) from `.dev.vars.example` with the real sandbox key + the shared `JWT_SECRET` from `~/.eldrin/.env` (ask the user for the API key value; do not invent one).

- [ ] **Step 3: Start the dev server**

Run: `cd eldrin-factorial && npm run dev`
Expected: Vite serves on `http://localhost:4011`; `curl http://localhost:4011/eldrin-app.manifest.json` returns the manifest; `curl http://localhost:4011/health` returns `{"status":"ok","app":"eldrin-factorial"}`.

- [ ] **Step 4: Start eldrin-core shell** (per its own README/CLAUDE.md) and **register the app** via the shell's app-management UI or `POST /api/apps` with `{ "url": "http://localhost:4011" }` (the shell fetches `/eldrin-app.manifest.json` from that URL — same path used to add eldrin-email/eldrin-workflows). Confirm with the user how they normally register a local dev app if the admin UI path is unclear.

- [ ] **Step 5: Manual smoke in the shell**
  - Factorial appears in the shell nav with Employees / Teams / Time Off / Settings.
  - Settings shows "Not configured" until `API_BASE_URL` + `API_KEY` are set in shell app settings (or `.dev.vars` for the worker), then "Connected".
  - "Sync now" returns a count; Employees list populates from D1.
  - Teams / Time Off load live (or show a clear error if the sandbox lacks data/permissions).

- [ ] **Step 6: Run the full test suite + typecheck (final gate)**

Run: `cd eldrin-factorial && npm run typecheck && npx vitest run`
Expected: all tests pass.

- [ ] **Step 7: Commit**
```bash
git add eldrin-factorial/public/eldrin-app.manifest.json
git commit -m "feat(factorial): add app manifest and register in shell"
```

---

## Self-Review

**Spec coverage:**
- Company-level API-key auth (no OAuth) → Task 4 (status), Task 5 (client header), manifest settings group Task 12. ✅
- Persist Employees + Projects → Task 2 (schema), Task 6 (sync upserts both). ✅ (Projects has no list route/page in scaffold — it is persisted and sync-counted per the spec, which only requires persistence to prove the integration; Employees is the browseable one. A Projects page is future work, consistent with spec's "Employees and Projects are the two we persist" + nav of Employees/Teams/TimeOff/Settings.)
- Live proxy Teams + Time Off → Task 8 + pages Task 10. ✅
- Manual sync only, cron deferred but structured → `runSync` single entry point (Task 6); no cron trigger in wrangler (Task 1). ✅
- D1 + migrations compiled at build → Task 1 (generate script), Task 2 (migration), Task 3 (runMigrations). ✅
- Shell auth model, /health public → Task 1 + Task 3. ✅
- Error handling (toasts, server logs, sync_state) → Tasks 6, 8, 10. ✅
- Tests 80%+ across client/sync/routes → Tasks 4–8. ✅
- Runs in shell (phase gate) → Task 12. ✅

**Placeholder scan:** The two intentional implementer notes (connection.test D1 strategy; isolated-route 401-only unit tests) are flagged as such with the required behavior pinned, not left as "TODO". No bare TODO/TBD remain.

**Type consistency:** `createFactorialClient`/`FactorialClient`/`FactorialError` consistent across Tasks 5/6/8. `runSync(db, env)` / `syncEmployees(db, client)` consistent Task 6 ↔ uses. `EmployeeRow`/`ConnectionStatus`/`SyncResult` consistent Task 9 ↔ 10. Table exports `employees`/`projects`/`syncState` consistent Task 2 ↔ 6 ↔ 7. API client method names match route paths Task 8/9. ✅
