# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Eldrin is a modular business application platform built on Cloudflare Workers with a micro-frontend architecture. This is the **parent orchestrator repository** — it coordinates 14 Git submodules (each an independent GitHub repo) and contains example todo apps. Most development happens inside individual submodules, which have their own CLAUDE.md files.

Single-tenant model: each customer deploys their own Cloudflare Worker with apps loaded from a centralized marketplace.

## Commands

```bash
# Setup
npm run install:all              # Install all submodules + todo apps
npm run install:submodules       # Install only core submodules
npm run install:todos            # Install only todo app dependencies

# Dev servers (todo example apps)
npm run dev:react                # port 4004
npm run dev:angular              # port 4005
npm run dev:vue                  # port 4006
npm run dev:svelte               # port 4007

# Build
npm run build:all                # Build all todo apps
npm run build:react              # Build individual todo app

# Submodule management
npm run submodules:status        # Check submodule status
npm run submodules:update        # Update to latest remote commits
npm run submodules:sync          # Sync URLs and reinitialize

# Helper scripts
./scripts/init.sh                # Initialize fresh clone
./scripts/status.sh              # Detailed submodule status (--full, --fetch, --json)
./scripts/update-submodules.sh   # Update submodules (--remote, --checkout, --pull)

# Clean
npm run clean:all                # Remove all node_modules and dist
```

Individual submodules use their own commands (typically `npm run dev`, `npm run build`, `npm run test`). Navigate into the submodule directory first.

## Architecture

```
Customer Cloudflare Worker
├── Eldrin Shell (eldrin-core: React + Vite + single-spa)
│   ├── Auth, Navigation, Theming, Events, Licensing
│   └── single-spa mount points for micro-apps
├── Micro-apps (each has isolated D1 database)
│   ├── eldrin-invoicing (Hono backend)
│   ├── eldrin-catalog
│   └── eldrin-crm
└── Cloudflare D1 (SQLite) + R2 (Storage)
```

### Key Submodules

| Submodule | Purpose | Stack |
|-----------|---------|-------|
| `eldrin-core` | Shell app: auth, nav, app loading, licensing | React 19, Vite 7, Zustand 5, single-spa 6, Tailwind 4 |
| `eldrin-app-core` | SDK library (`@eldrin-project/eldrin-app-core`) | tsup (ESM+CJS), Vitest |
| `eldrin-invoicing` | Invoice/client management app | React Router, Hono 4 |
| `eldrin-catalog` | Product/service catalog | React, Cloudflare Workers |
| `eldrin-crm` | Customer relationship management | React, Cloudflare Workers |
| `eldrin-templates` | CLI scaffolding (`create-eldrin-project`) | tsup, Commander |
| `eldrin-docs` | Developer documentation | Astro/Starlight |

### How Apps Load

1. Shell fetches enabled apps from `/api/apps` (D1)
2. Loads `eldrin-app.manifest.json` for each app
3. Validates license (free apps skip this)
4. Registers with single-spa
5. Apps mount when their route activates

Apps access shell context via `window.__ELDRIN__` (customerId, userId, registerApp, etc.).

### SDK Core Concepts (eldrin-app-core)

- **createApp()** — Factory returning single-spa `{bootstrap, mount, unmount}`. Runs migrations during bootstrap.
- **Migration system** — SQL files named `YYYYMMDDHHMMSS-description.sql`, tracked with SHA-256 checksums in `_eldrin_migrations` table.
- **Vite plugin** — Virtual modules `virtual:eldrin/migrations` and `virtual:eldrin/seeds` embed SQL at build time (Workers have no filesystem).
- **useDatabase()** hook — React context for D1 access.

## Submodule Workflow

Submodules track **specific commits** (not branches). After clone, they're in detached HEAD state.

```bash
# Work in a submodule
cd eldrin-invoicing
git checkout main                    # Exit detached HEAD
git checkout -b feature/my-feature   # Or create feature branch
# ... make changes, commit, push ...

# Then update parent reference
cd ..
git add eldrin-invoicing
git commit -m "chore: update eldrin-invoicing submodule"
```

For multi-submodule changes, stage all updated submodules together in one parent commit.

## Commit Convention

[Conventional Commits](https://www.conventionalcommits.org/) format: `type(scope): description`

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`

Parent repo submodule updates: `chore: update eldrin-invoicing submodule`

## Tech Stack Summary

| Layer | Technology |
|-------|------------|
| Frontend | React 19, Vite 6-7, Tailwind CSS 4 |
| Micro-frontend | single-spa 6, Module Federation |
| State | Zustand 5 |
| Runtime | Cloudflare Workers |
| Database | D1 (SQLite), PostgreSQL via Hyperdrive |
| Storage | R2 |
| Testing | Vitest |
| TypeScript | 5.8-5.9 (strict mode) |

## Multi-Cloud Implementation Tracking

The multi-cloud transformation plan is tracked at:
- **Master plan**: `docs/multiplatform-implementation/eldrin-core-multi-cloud.md`
- **Phase folders**: `docs/multiplatform-implementation/phases/phase-NN-*/`
- **How-to guide**: `docs/multiplatform-implementation/HOW_TO.md`

### Finding the next task

1. Check `docs/multiplatform-implementation/phases/` for phase folders
2. Find the first phase where `STATUS.md` shows `Status: not_started` or `Status: in_progress`
3. Read that phase's `PLAN.md` for implementation details
4. Update `STATUS.md` as you work (check off steps, add notes)
5. Create `DONE.md` when all tests pass and the phase gate is met

Quick check:
```bash
grep -r "^## Status:" docs/multiplatform-implementation/phases/*/STATUS.md
```

### Implementation order (dependency-aware)

Phase 0 → 1 → Local Infra → 9 → 8 → 15 → 2 → 16 → 11 → 12 → 13 → 3 → 14 → 10 → 7 → 4 → 5 → 6 → 17 → 18

### Running tests

```bash
# eldrin-core unit tests
cd eldrin-core && npx vitest run

# eldrin-app-core unit tests (SDK)
cd eldrin-app-core && npx vitest run

# E2E tests
cd eldrin-core && npx playwright test

# Local infrastructure
cd eldrin-core && docker compose up -d
```

## Prerequisites

- Git 2.13+
- Node.js 20+
- npm
