# eldrin-factorial — Design Spec

**Date:** 2026-06-17
**Status:** Approved (scaffold phase)

## Purpose

A company-wide FactorialHR integration extension app for the Eldrin platform.

An administrator configures a Factorial **API key + base URL** once in the app's
Settings screen (no OAuth, no per-user authentication). A manual **Sync** pulls
**Employees** and **Projects** from Factorial into the app's own D1 database to prove
the integration end-to-end; **Teams** and **Time Off** are browsed as live proxies.

The persisted data is intended as a backing store that other Eldrin apps (e.g. a future
HR app) can read for reports. The architecture leaves room for write-back later (e.g.
timesheet creation persisting to Factorial). A scheduled cron sync is deliberately
deferred for the scaffold, but the sync logic is structured so a cron handler can call
it unchanged.

This app follows the same scaffolding pattern as `eldrin-email` and `eldrin-workflows`:
a React 19 + single-spa micro-frontend served by a Cloudflare Worker (Hono), with its
own D1 database and migrations, registered into the shell via its manifest.

## Scope (scaffold phase)

- **Auth to Factorial:** API key (company-level), configured in Settings. No OAuth.
- **UI:** side nav with Employees, Teams, Time Off, Settings.
  - Employees / Projects: read from D1 (persisted via sync).
  - Teams / Time Off: live proxy to Factorial.
  - Settings: shows configuration status + a **Sync now** button + last-synced timestamp.
- **Sync trigger:** manual button only. Cron deferred (logic structured to allow it later).
- **Persisted resources:** Employees and Projects (plus technical tables). Teams and
  Time Off are not persisted in the scaffold.

Out of scope for the scaffold (future work): cron-scheduled sync, write-back to Factorial
(timesheets etc.), persisting Teams/Time Off, reporting consumers in other apps, OAuth.

## Architecture

```
eldrin-factorial/
├── public/eldrin-app.manifest.json    # registered into shell via POST /api/apps
├── src/                               # micro-frontend (React 19 + single-spa + daisyUI)
│   ├── eldrin-factorial.tsx           # single-spa entry (createApp + singleSpaReact)
│   ├── root.component.tsx             # route parsing + nav
│   ├── api.ts                         # typed client to our worker
│   ├── index.css
│   ├── main.tsx                       # standalone dev entry
│   ├── types/factorial.ts             # Employee, Team, Project, TimeOff, ConnectionStatus
│   └── pages/
│       ├── employees/EmployeeList.tsx
│       ├── teams/TeamList.tsx
│       ├── timeoff/TimeOffList.tsx
│       └── settings/ConnectionSettings.tsx
├── worker/                            # Hono on Cloudflare Workers
│   ├── index.ts                       # auth mw, migrations, route mounting, static fallback
│   ├── db/{schema.ts,index.ts}        # drizzle schema + db factory
│   ├── routes/
│   │   ├── connection.ts              # GET config/health status
│   │   ├── employees.ts               # read from D1
│   │   ├── teams.ts                   # live proxy
│   │   ├── timeoff.ts                 # live proxy
│   │   └── sync.ts                    # POST /api/sync
│   └── services/
│       ├── factorial-client.ts        # base URL + API key header + version + pagination + error mapping
│       └── sync.ts                    # trigger-agnostic: pull → upsert employees + projects
├── migrations/001-init.sql
├── bruno/                             # Phase 2: converted + doc-validated Factorial collection
├── wrangler.jsonc
├── vite.config.ts
├── vitest.config.ts
├── tsconfig.*.json
├── package.json
├── worker-configuration.d.ts
└── .dev.vars.example
```

## Credentials — via manifest `settings`

Mirrors eldrin-email's settings groups. No `connections` table.

```jsonc
"settings": { "groups": [{
  "key": "FACTORIAL", "label": "Factorial",
  "description": "Company-level Factorial API credentials",
  "fields": [
    { "key": "API_BASE_URL", "type": "string", "storage": "config", "required": true,
      "placeholder": "https://api.eu2.demo.factorial.dev" },
    { "key": "API_KEY", "type": "string", "storage": "secret", "required": true }
  ]
}]}
```

The worker reads `FACTORIAL_API_BASE_URL` (config) and `FACTORIAL_API_KEY` (secret) from
its environment and sends the key on every Factorial call.

### Environments

- Sandbox API root: `https://api.eu2.demo.factorial.dev/`
- Production API root: `https://api.factorialhr.com/`
- OAuth app registration page (not used at runtime): `https://app.eu2.demo.factorial.dev/...`
- Factorial API path convention: `/api/v1/...` (per the Postman collection).

## Data model (D1, `migrations/001-init.sql`)

Company-scoped (no per-user partitioning) since credentials are company-level.

```sql
employees(
  id, factorial_id UNIQUE, full_name, email, job_title, team_id,
  raw_json,            -- full payload for forward-compat
  synced_at
)
projects(
  id, factorial_id UNIQUE, name, status,
  raw_json,
  synced_at
)
sync_state(
  id, resource,        -- 'employees' | 'projects'
  last_synced_at, last_status, last_error
)
```

## Auth model with the shell

Same as eldrin-email: `userId` resolved from `X-Eldrin-User-Id` (prod proxy) or Bearer
JWT (dev mode, cross-origin). All `/api/*` routes require an authenticated shell user;
`/health` is public. There is no Factorial-side callback (no OAuth), so no public OAuth
route is needed.

## Data flow

- **Configure:** admin sets `API_BASE_URL` + `API_KEY` in Settings → shell stores them →
  injected as worker env.
- **Sync (manual):** `POST /api/sync` → `factorial-client` pulls employees + projects
  (paginated, with API-key auth) → `sync.ts` upserts into D1 by `factorial_id` →
  updates `sync_state`. `sync.ts` is trigger-agnostic so a future cron calls the same
  functions.
- **Browse:** Employees / Projects read from D1; Teams / Time Off live-proxied through
  `factorial-client`.

## Factorial client & versioning

`factorial-client.ts` centralizes: base URL, API-key auth header, the `/api/v1` version
segment, pagination handling, and non-2xx → typed error mapping. One place to adjust when
validating the Postman/Bruno collection against the live docs.

## Error handling

Per project global rules:
- Validate inputs at the boundary; never trust external data (Factorial responses).
- Friendly UI errors via `sonner` toasts; detailed server-side logs; never swallow errors.
- Missing/invalid credentials → Settings shows "not configured" / "error" state.
- Sync failures recorded in `sync_state.last_status` / `last_error` and surfaced in UI.
- Factorial non-2xx surfaced with status + message.

## Testing (Vitest)

- `factorial-client`: auth header set, pagination traversal, non-2xx error mapping.
- `sync`: upsert idempotency (re-sync does not duplicate by `factorial_id`), `sync_state` updates.
- `connection`/health route: reports configured vs not-configured correctly.
- `employees` route: reads persisted D1 rows.
- Target: 80%+ coverage per project testing rules.

## Phase 2 (after scaffold runs in the shell)

Convert `~/Downloads/Factorial API.postman_collection.json` (82 requests across Ats /
Core / Time / Payroll) into a Bruno collection under `bruno/`, validated against the
Factorial API documentation. Environment variables: `baseUrl`, `prefix=/api`, API key.
