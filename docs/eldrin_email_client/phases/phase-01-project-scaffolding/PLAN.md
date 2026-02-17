# Phase 1: Project Scaffolding

## Overview

Set up the `eldrin-email` repository with the same architecture as `eldrin-workflows`: Hono backend on Cloudflare Workers, React frontend with single-spa, daisyUI 5 theme sync, Drizzle ORM, and the Eldrin app SDK. At the end of this phase the app loads in the shell with an empty inbox placeholder.

## Dependencies

- None (first phase)

## Steps

### 1.1 Initialize repository and package.json

Create `eldrin-email/` with:
- `package.json` — dependencies matching eldrin-workflows (hono, drizzle-orm, @eldrin-project/eldrin-app-core, @eldrin-project/eldrin-app-react, react, react-dom, tailwindcss, daisyui, vite, wrangler, typescript, vitest)
- `tsconfig.json` — strict, ESM, `@` alias for `./src`
- `.gitignore` — node_modules, dist, .wrangler, .env*, worker/migrations.generated.ts

### 1.2 Configure Vite and Wrangler

- `vite.config.ts` — React plugin, Cloudflare plugin, external `react`/`react-dom` for single-spa, tailwind
- `wrangler.jsonc` — D1 binding (`eldrin-email-db`), assets, compatibility flags
- `tailwind.config.ts` — extend with daisyUI 5, eldrin theme

### 1.3 Create app manifest

`public/eldrin-app.manifest.json` — full manifest as defined in the master plan (events, permissions, groups, API routes, sideNav).

### 1.4 Set up worker entry point

`worker/index.ts`:
- Hono app with CORS middleware
- Migration middleware on `/api/*` (run migrations on first request)
- DB initialization via `c.set('db', ...)`
- Health check route
- Event webhook route (`/api/_events/webhook`)
- ASSETS fallback for frontend

### 1.5 Set up database layer

- `worker/db/schema.ts` — empty for now (tables added in later phases)
- `worker/db/index.ts` — Drizzle factory (same pattern as eldrin-workflows)
- `scripts/generate-migrations.ts` — migration bundler for Workers

### 1.6 Set up frontend entry point

- `src/index.ts` — `createApp()` + `singleSpaReact()` + `combineLifecycles()`
- `src/root.component.tsx` — theme sync (MutationObserver), basic router
- `src/index.css` — Tailwind directives + daisyUI theme
- `src/App.tsx` — layout shell with placeholder pages

### 1.7 Create placeholder pages

- `src/pages/inbox/InboxList.tsx` — "No emails yet" placeholder
- `src/pages/sent/SentList.tsx` — placeholder
- `src/pages/templates/TemplateList.tsx` — placeholder
- `src/pages/settings/MailboxSettings.tsx` — "Connect your mailbox" placeholder

## Test Gate

```bash
cd eldrin-email && npm run build   # Zero errors
cd eldrin-email && npm run test    # Placeholder test passes
```

- App loads in eldrin-core shell with sideNav items (Inbox, Sent, Templates)
- Theme sync works (dark/light mode)
- `/api/health` returns 200

## Files Created

| File | Purpose |
|------|---------|
| `package.json` | Dependencies and scripts |
| `tsconfig.json` | TypeScript config |
| `.gitignore` | Ignore patterns |
| `vite.config.ts` | Vite + Cloudflare + Tailwind |
| `wrangler.jsonc` | Worker config with D1 |
| `public/eldrin-app.manifest.json` | App manifest |
| `worker/index.ts` | Hono entry point |
| `worker/db/schema.ts` | Drizzle schema (empty) |
| `worker/db/index.ts` | DB factory |
| `scripts/generate-migrations.ts` | Migration bundler |
| `src/index.ts` | single-spa lifecycle |
| `src/root.component.tsx` | Router + theme sync |
| `src/index.css` | Tailwind + daisyUI |
| All placeholder pages | Empty page shells |

## Finalize

- [ ] App loads in shell and navigates between pages
- [ ] Theme sync works
- [ ] Health endpoint responds
- [ ] Commit: `feat(email): scaffold eldrin-email extension app`
- [ ] Update STATUS.md → complete, create DONE.md
