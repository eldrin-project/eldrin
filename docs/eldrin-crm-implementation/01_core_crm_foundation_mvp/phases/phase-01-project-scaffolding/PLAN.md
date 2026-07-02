# Phase 1: Project Scaffolding & Dev Environment

## Overview

Scaffold the `eldrin-crm` repository with the standard Eldrin extension app structure. Same pattern as `eldrin-workflows` Phase 1: Hono backend skeleton, React micro-frontend that mounts in the shell, daisyUI 5 theming, Drizzle ORM setup, and a dev environment that works both standalone and shell-integrated.

The CRM is the largest Eldrin extension app planned, so the scaffolding includes a broader directory structure to accommodate contacts, companies, leads, deals, activities, reports, and settings from day one.

## Dependencies

None — this is the first phase.

## Steps

### 1.1 Create repository and directory structure

Create the `eldrin-crm` directory (will later become a submodule). Initialize with `npm init` and set up the full project structure.

```bash
mkdir eldrin-crm
cd eldrin-crm
npm init -y
```

Create directory structure:
```
eldrin-crm/
├── migrations/
├── public/
├── scripts/
├── src/
│   ├── components/
│   ├── pages/
│   ├── stores/
│   ├── hooks/
│   ├── lib/
│   └── types/
└── worker/
    ├── db/
    ├── routes/
    ├── services/
    └── middleware/
```

### 1.2 Install production dependencies

```bash
npm install hono \
  drizzle-orm \
  @eldrin-project/eldrin-app-core \
  @eldrin-project/eldrin-app-react \
  react react-dom \
  single-spa-react \
  tailwindcss @tailwindcss/vite daisyui \
  lucide-react \
  sonner \
  zustand \
  recharts \
  @hello-pangea/dnd
```

**Notes**:
- `zustand` — state management for CRM stores (contacts, deals, pipeline, filters)
- `recharts` — dashboard charts and pipeline reporting
- `@hello-pangea/dnd` — Kanban drag-and-drop for deal pipeline board

### 1.3 Install dev dependencies

```bash
npm install -D \
  @cloudflare/vite-plugin \
  @cloudflare/workers-types \
  @vitejs/plugin-react \
  @types/react @types/react-dom @types/node \
  typescript \
  vite \
  wrangler \
  tsx \
  drizzle-kit \
  vitest
```

### 1.4 Create TypeScript configs

**`tsconfig.json`** — project references (same pattern as react-todo and eldrin-workflows):
```json
{
  "files": [],
  "references": [
    { "path": "./tsconfig.app.json" },
    { "path": "./tsconfig.worker.json" },
    { "path": "./tsconfig.node.json" }
  ]
}
```

**`tsconfig.app.json`** — frontend (React, DOM, JSX):
- Target: ES2022
- Libs: ES2023, DOM, DOM.Iterable
- JSX: react-jsx
- Module: ESNext with bundler resolution
- Strict mode, path alias `@/*` → `./src/*`
- Include: `src/`

**`tsconfig.worker.json`** — Cloudflare Worker:
- Extends `tsconfig.node.json`
- Types: `@cloudflare/workers-types`
- Include: `worker/`, `worker-configuration.d.ts`

**`tsconfig.node.json`** — build scripts:
- Target: ES2022
- Module: ESNext with bundler resolution
- Include: `scripts/`

### 1.5 Create worker environment types

**`worker-configuration.d.ts`**:
```typescript
interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  JWT_SECRET: string;
  // Future: HYPERDRIVE, DATABASE_URL, TURSO_URL, etc.
}
```

### 1.6 Create Hono backend skeleton

**`worker/index.ts`** — Hono app with middleware, CORS, health endpoint, migration runner, and ASSETS fallback:

```typescript
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { runMigrations } from '@eldrin-project/eldrin-app-core';
import migrations from './migrations.generated';
import { createDb } from './db';

const app = new Hono<{ Bindings: Env }>();

// CORS
app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
}));

// Health check (public)
app.get('/health', (c) => c.json({ status: 'ok', app: 'eldrin-crm' }));

// Migration + DB middleware (all /api/* routes)
let migrationsComplete = false;

app.use('/api/*', async (c, next) => {
  if (!migrationsComplete) {
    const result = await runMigrations(c.env.DB, {
      migrations,
      onLog: (msg, level) => console[level](`[crm] ${msg}`),
    });
    if (!result.success) {
      return c.json({ error: 'Migration failed', details: result.error?.message }, 500);
    }
    migrationsComplete = true;
  }

  const db = createDb(c.env as unknown as Record<string, unknown>);
  c.set('db', db);
  await next();
});

// TODO: Contact routes (Phase 2)
// TODO: Company routes (Phase 2)
// TODO: Tag routes (Phase 2)
// TODO: Lead routes (Phase 3)
// TODO: Deal/Pipeline routes (Phase 4)
// TODO: Activity routes (Phase 5)

// Static asset fallback
app.get('*', async (c) => {
  return c.env.ASSETS.fetch(c.req.raw);
});

export default app;
```

### 1.7 Create Drizzle database factory

**`worker/db/index.ts`**:
```typescript
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

**`worker/db/schema.ts`** — empty placeholder (populated in Phase 2):
```typescript
// CRM database schema — tables added in subsequent phases
```

### 1.8 Create app manifest

**`public/eldrin-app.manifest.json`** — full CRM manifest with:

- `id`: `"eldrin-crm"`
- `name`: `"CRM"`
- `permissions`:
  - `contacts` — view, create, edit, delete
  - `companies` — view, create, edit, delete
  - `leads` — view, create, edit, delete, convert
  - `deals` — view, create, edit, delete, close
  - `activities` — view, create, edit, delete
  - `reports` — view, export
  - `email` — view, send, manage-templates
  - `import-export` — import, export
  - `deal-rooms` — view, create, manage
  - `settings` — manage
- `groups`:
  - `admin` — full access to all permissions
  - `sales-manager` — all CRUD + reports + settings
  - `sales-rep` — contacts/companies/leads/deals/activities CRUD, reports view
  - `viewer` — view-only across all modules
- `api.publicRoutes`: `["/health"]`
- `database`: `{ "name": "eldrin-crm", "migrationsPath": "migrations", "handledBy": "worker" }`
- `ui.sideNav`:
  - Dashboard (`/eldrin-crm`, icon: `layout-dashboard`)
  - Contacts (`/eldrin-crm/contacts`, icon: `users`)
  - Companies (`/eldrin-crm/companies`, icon: `building-2`)
  - Leads (`/eldrin-crm/leads`, icon: `target`)
  - Deals (`/eldrin-crm/deals`, icon: `handshake`)
  - Activities (`/eldrin-crm/activities`, icon: `calendar-check`)
  - Reports (`/eldrin-crm/reports`, icon: `bar-chart-3`)

### 1.9 Create Vite config

**`vite.config.ts`** — same structure as react-todo and eldrin-workflows:

- Plugins: react, cloudflare, tailwindcss, devShellCompat (custom)
- Build: library mode, ES format, entry `./src/eldrin-crm.tsx`
- Server: port 4009, strictPort, CORS
- `devShellCompat()` plugin: maps `/eldrin-crm.js` to entry, serves compiled CSS

### 1.10 Create Wrangler config

**`wrangler.jsonc`**:
```jsonc
{
  "name": "eldrin-crm",
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
      "database_name": "eldrin-crm-db",
      "database_id": "local"
    }
  ]
}
```

### 1.11 Create single-spa entry point

**`src/eldrin-crm.tsx`** — matches react-todo / eldrin-workflows pattern:

- Import `createApp`, `combineLifecycles`, `DatabaseProvider` from SDK
- Create Eldrin lifecycle with `createApp({ name: 'eldrin-crm' })`
- Create React lifecycle with `singleSpaReact()`
- Combine with `combineLifecycles()`
- Export `{ bootstrap, mount, unmount }`
- `domElementGetter`: creates/reuses container `single-spa-application:eldrin-crm`

### 1.12 Create root component

**`src/root.component.tsx`**:

- daisyUI theme sync via MutationObserver on `document.documentElement` `data-theme` attribute (same pattern as react-todo)
- Pathname-based routing for CRM sections
- Sidebar nav layout with icons matching the manifest sideNav
- Placeholder pages: "Dashboard — Coming soon", "Contacts — Coming soon", etc.

### 1.13 Create CSS with daisyUI theme

**`src/index.css`**:
- Import Tailwind base, components, utilities
- daisyUI theme definitions (`eldrin`, `eldrin-dark`) mapping to shell CSS variables
- Same pattern as react-todo and eldrin-workflows theme setup

### 1.14 Create migration generation script

**`scripts/generate-migrations.ts`** — same as react-todo and eldrin-workflows:
- Reads `.sql` files from `migrations/`
- Generates `worker/migrations.generated.ts`
- Sorts by filename (timestamp prefix ensures order)

### 1.15 Create standalone dev entry

**`src/main.tsx`** — standalone dev mode (not shell-integrated):
- Renders root component directly
- Imports `index.css`

**`index.html`** — dev server HTML template with root div and script tag

### 1.16 Add package.json scripts

```json
{
  "scripts": {
    "dev": "npm run generate:migrations && vite dev",
    "build": "npm run generate:migrations && tsc -b && vite build",
    "generate:migrations": "tsx scripts/generate-migrations.ts",
    "preview": "vite preview",
    "test": "vitest run",
    "typecheck": "tsc -b"
  }
}
```

## Test Gate

```bash
cd eldrin-crm && npm run build   # Clean build
cd eldrin-crm && npm run dev     # Dev server starts
curl http://localhost:4009/health  # Returns { status: "ok", app: "eldrin-crm" }
```

Acceptance criteria:
1. `npm run build` succeeds with zero TypeScript errors
2. Dev server starts on port 4009 and serves the standalone page
3. Health endpoint returns 200 with `{ status: "ok", app: "eldrin-crm" }`
4. Shell mounts the frontend when navigating to `/eldrin-crm`
5. daisyUI theme is applied (light + dark mode via `eldrin` / `eldrin-dark`)
6. Sidebar navigation renders all 7 sections with correct icons

## Files Created

| File | Purpose |
|------|---------|
| `package.json` | Dependencies and scripts |
| `tsconfig.json` | Project references |
| `tsconfig.app.json` | Frontend TypeScript config |
| `tsconfig.worker.json` | Worker TypeScript config |
| `tsconfig.node.json` | Build scripts TypeScript config |
| `worker-configuration.d.ts` | Cloudflare Worker env types |
| `vite.config.ts` | Vite build + dev config |
| `wrangler.jsonc` | Cloudflare Workers config |
| `worker/index.ts` | Hono backend app with CORS, health, migration middleware |
| `worker/db/index.ts` | Drizzle database factory + re-exports |
| `worker/db/schema.ts` | Empty schema placeholder |
| `src/eldrin-crm.tsx` | single-spa entry point |
| `src/root.component.tsx` | Main React component with theme sync + routing |
| `src/main.tsx` | Standalone dev entry |
| `src/index.css` | daisyUI theme styles |
| `index.html` | Dev server HTML |
| `public/eldrin-app.manifest.json` | App manifest with permissions, groups, sideNav |
| `public/_headers` | Cloudflare headers |
| `scripts/generate-migrations.ts` | Migration code generator |

## Finalize

- [ ] Manual validation: `npm run dev`, verify standalone page, health endpoint, build
- [ ] Manual validation: shell integration — navigate to `/eldrin-crm`, verify mount and sidebar
- [ ] Commit: `feat: scaffold eldrin-crm extension app`
- [ ] Update `STATUS.md` → complete, create `DONE.md`
