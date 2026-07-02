# How To — Eldrin Multi-Cloud

Quick-reference instructions for common development tasks.

---

## Run the App Locally

### Standalone Bun Server (fastest for development)

```bash
cd eldrin-core
npm run server:dev       # Bun server on http://localhost:4000
```

Uses SQLite at `./data/eldrin.db`, auto-generates JWT secret on first run.

### Vite Dev Server (frontend only)

```bash
cd eldrin-core
npm run dev              # Vite dev server with HMR
```

### Wrangler (Cloudflare Workers local)

```bash
cd eldrin-core
npx wrangler dev         # Local Workers runtime with D1
```

---

## Run Tests

### Unit Tests — eldrin-core

```bash
cd eldrin-core
npx vitest run           # Run all unit tests once
npx vitest               # Watch mode
npx vitest run --coverage  # With coverage report
```

### Unit Tests — eldrin-app-core (SDK)

```bash
cd eldrin-app-core
npx vitest run           # Run all SDK tests once (84+ tests)
```

### E2E Tests — Playwright

```bash
cd eldrin-core
npx playwright test                          # Run all E2E tests
npx playwright test e2e/baseline.spec.ts     # Baseline regression only
npx playwright test --ui                     # Interactive UI mode
```

Requires the app to be running (auto-started via `webServer` config on port 4000).

### Run All Tests

```bash
# From parent repo
cd eldrin-app-core && npx vitest run && cd ../eldrin-core && npx vitest run && npx playwright test
```

---

## Start Local Infrastructure

```bash
cd eldrin-core
docker compose up -d                  # Start all services
docker compose up -d postgres redis   # Start specific services
docker compose down                   # Stop all
docker compose logs -f postgres       # Tail logs for a service
```

### Services Available

| Service | URL | Credentials |
|---------|-----|-------------|
| PostgreSQL | `localhost:5432` | `eldrin` / `eldrin_dev` / db: `eldrin` |
| Redis | `localhost:6379` | No auth |
| MinIO Console | `http://localhost:9001` | `minioadmin` / `minioadmin` |
| MinIO API | `http://localhost:9000` | (S3-compatible) |
| Mailpit UI | `http://localhost:8025` | No auth |
| Mailpit SMTP | `localhost:1025` | No auth |

### Run with PostgreSQL

```bash
# Start PostgreSQL
docker compose up -d postgres

# Set env vars (or copy .env.local)
export DATABASE_TYPE=postgres
export DATABASE_URL=postgres://eldrin:eldrin_dev@localhost:5432/eldrin

# Start app
npm run server:dev
```

### Run with Redis Cache

```bash
docker compose up -d redis
export CACHE_PROVIDER=redis
export REDIS_URL=redis://localhost:6379
npm run server:dev
```

### Test Email (Mailpit)

```bash
docker compose up -d mailpit
export EMAIL_PROVIDER=smtp
export SMTP_HOST=localhost
export SMTP_PORT=1025
npm run server:dev
# Open http://localhost:8025 to see captured emails
```

### Test Storage (MinIO)

```bash
docker compose up -d minio
export STORAGE_PROVIDER=s3
export STORAGE_BUCKET=eldrin-dev
export STORAGE_REGION=us-east-1
export AWS_ACCESS_KEY_ID=minioadmin
export AWS_SECRET_ACCESS_KEY=minioadmin
export S3_ENDPOINT=http://localhost:9000
npm run server:dev
# Open http://localhost:9001 for MinIO console
```

---

## Check Implementation Progress

### Quick Status

```bash
# See which phases are done
ls docs/multiplatform-implementation/phases/*/DONE.md 2>/dev/null

# See all phase statuses
grep -r "^## Status:" docs/multiplatform-implementation/phases/*/STATUS.md
```

### Phase Details

Each phase folder at `docs/multiplatform-implementation/phases/phase-NN-*/` contains:

| File | Purpose |
|------|---------|
| `PLAN.md` | Detailed implementation steps, file paths, test gates |
| `STATUS.md` | Progress tracking with checkboxes |
| `DONE.md` | Present only when phase is complete (with test results) |

### Implementation Order (dependency-aware)

```
Phase 0 → 1 → Local Infra → 9 → 8 → 15 → 2 → 16 → 11 → 12 → 13 → 3 → 14 → 10 → 7 → 4 → 5 → 6 → 17 → 18
```

---

## Add a New Phase

1. Create folder: `docs/multiplatform-implementation/phases/phase-NN-description/`
2. Create `PLAN.md` with: overview, dependencies, steps, test gate, files created/modified
3. Create `STATUS.md` with template:

```markdown
# Phase N: Title

## Status: not_started
## Started: -
## Completed: -

## Progress:
- [ ] Step N.1: Description
- [ ] Step N.2: Description

## Notes:
```

4. When complete, create `DONE.md`:

```markdown
# Phase N: Title — COMPLETE

Completed: YYYY-MM-DD
Test results: X/X unit tests, Y/Y E2E tests
```

---

## Master Plan Reference

The full multi-cloud implementation plan with all technical details:

`docs/multiplatform-implementation/eldrin-core-multi-cloud.md`
