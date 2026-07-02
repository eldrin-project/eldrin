# Phase 1: Project Scaffolding & Dev Environment

## Overview

Create the `eldrin-workflows` repository with the standard Eldrin extension app structure. This phase produces a working app skeleton: Hono backend with a health endpoint, React micro-frontend that mounts in the shell, daisyUI theming, and a dev environment that works both standalone and shell-integrated.

**Key difference from react-todo**: Uses **Hono** for backend routing instead of a bare fetch handler. This is the new standard for Eldrin extension apps.

## Dependencies

None — this is the first phase.

## Steps

### 1.1 Create repository and initialize project

Create the `eldrin-workflows` directory (will later become a submodule). Initialize with `npm init` and set up the basic project structure.

```bash
mkdir eldrin-workflows
cd eldrin-workflows
npm init -y
```

Create directory structure:
```
eldrin-workflows/
├── migrations/
├── public/
├── scripts/
├── src/
│   ├── components/
│   └── pages/
└── worker/
    └── routes/
```

### 1.2 Install dependencies

**Production dependencies**:
```bash
npm install hono \
  drizzle-orm \
  @eldrin-project/eldrin-app-core \
  @eldrin-project/eldrin-app-react \
  react react-dom \
  single-spa-react \
  tailwindcss @tailwindcss/vite daisyui \
  lucide-react \
  sonner
```

**Dev dependencies**:
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
  drizzle-kit
```

### 1.3 Create TypeScript configs

**`tsconfig.json`** — project references (same pattern as react-todo):
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

### 1.4 Create worker environment types

**`worker-configuration.d.ts`**:
```typescript
interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  JWT_SECRET: string;
  // Future: HYPERDRIVE, DATABASE_URL, TURSO_URL, etc.
}
```

### 1.5 Create Hono backend skeleton

**`worker/index.ts`** — Hono app with middleware and health endpoint:

```typescript
import { Hono } from 'hono';
import { cors } from 'hono/cors';

const app = new Hono<{ Bindings: Env }>();

// CORS
app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
}));

// Health check (public)
app.get('/health', (c) => c.json({ status: 'ok', app: 'eldrin-workflows' }));

// TODO: Permission middleware (Phase 3)
// TODO: Workflow routes (Phase 3)
// TODO: Run routes (Phase 5)
// TODO: Event webhook (Phase 5)

// Static asset fallback
app.get('*', async (c) => {
  return c.env.ASSETS.fetch(c.req.raw);
});

export default app;
```

### 1.6 Create app manifest

**`public/eldrin-app.manifest.json`**:

Define the full manifest with:
- `id`: `"eldrin-workflows"`
- `name`: `"Workflows"`
- `permissions`: workflows (CRUD), workflow-runs (read, delete)
- `groups`: admin (full access), editor (create/manage workflows), viewer (read-only)
- `api.routes`: all endpoints from requirements
- `api.publicRoutes`: `["/health"]`
- `events.subscribes`: `[{ "pattern": "*", "delivery": "push" }]`
- `database`: `{ "name": "eldrin-workflows", "migrationsPath": "migrations", "handledBy": "worker" }`
- `ui.sideNav`: `[{ "label": "Workflows", "icon": "workflow", "path": "/eldrin-workflows/workflows" }]`

### 1.7 Create Vite config

**`vite.config.ts`** — same structure as react-todo:

- Plugins: react, cloudflare, tailwindcss, devShellCompat (custom)
- Build: library mode, ES format, entry `./src/eldrin-workflows.tsx`
- Server: dedicated port (e.g., 4008), strictPort, CORS
- `devShellCompat()` plugin: maps `/eldrin-workflows.js` → entry, serves compiled CSS

### 1.8 Create Wrangler config

**`wrangler.jsonc`**:
```jsonc
{
  "name": "eldrin-workflows",
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
      "database_name": "eldrin-workflows-db",
      "database_id": "local"
    }
  ]
}
```

### 1.9 Create single-spa entry point

**`src/eldrin-workflows.tsx`** — matches react-todo pattern:

- Import `createApp`, `combineLifecycles`, `DatabaseProvider` from SDK
- Create Eldrin lifecycle with `createApp({ name: 'eldrin-workflows' })`
- Create React lifecycle with `singleSpaReact()`
- Combine with `combineLifecycles()`
- Export `{ bootstrap, mount, unmount }`
- `domElementGetter`: creates/reuses container `single-spa-application:eldrin-workflows`

### 1.10 Create root component

**`src/root.component.tsx`**:

- daisyUI theme sync via MutationObserver (same as react-todo)
- Basic layout with router placeholder
- Placeholder content: "Workflows — Coming soon"

### 1.11 Create standalone dev entry

**`src/main.tsx`** — standalone dev mode (not shell-integrated):
- Renders root component directly
- Imports `index.css`

**`index.html`** — dev server HTML template

### 1.12 Create CSS with daisyUI theme

**`src/index.css`**:
- Import Tailwind
- daisyUI theme definitions (`eldrin`, `eldrin-dark`) mapping to shell CSS vars
- Same pattern as react-todo's theme setup

### 1.13 Create migration generation script

**`scripts/generate-migrations.ts`** — same as react-todo:
- Reads `.sql` files from `migrations/`
- Generates `worker/migrations.generated.ts`

### 1.14 Add package.json scripts

```json
{
  "scripts": {
    "dev": "npm run generate:migrations && vite dev",
    "build": "npm run generate:migrations && tsc -b && vite build",
    "generate:migrations": "tsx scripts/generate-migrations.ts",
    "preview": "vite preview",
    "typecheck": "tsc -b"
  }
}
```

### 1.15 Test dev environment

- Run `npm run dev` — verify it starts without errors
- Open standalone page — verify "Workflows — Coming soon" renders
- Hit `/health` — verify JSON response
- Build: `npm run build` — verify dist output

## Test Gate

```bash
cd eldrin-workflows && npm run build   # Clean build
cd eldrin-workflows && npm run dev     # Dev server starts
curl http://localhost:4008/health      # Returns { status: "ok" }
```

Acceptance criteria:
1. `npm run build` succeeds with zero TypeScript errors
2. Dev server starts and serves the standalone page
3. Health endpoint returns 200
4. daisyUI theme is applied (light + dark mode)

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
| `worker/index.ts` | Hono backend app |
| `src/eldrin-workflows.tsx` | single-spa entry point |
| `src/root.component.tsx` | Main React component |
| `src/main.tsx` | Standalone dev entry |
| `src/index.css` | daisyUI theme styles |
| `index.html` | Dev server HTML |
| `public/eldrin-app.manifest.json` | App manifest |
| `public/_headers` | Cloudflare headers |
| `scripts/generate-migrations.ts` | Migration code generator |

## Finalize

- [ ] Manual validation: `npm run dev`, verify standalone page, health endpoint, build
- [ ] Commit: `feat: scaffold eldrin-workflows extension app`
- [ ] Update `STATUS.md` → complete, create `DONE.md`
