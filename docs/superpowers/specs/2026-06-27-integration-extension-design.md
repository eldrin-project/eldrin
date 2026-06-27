# Integration Extension Type — Technical Design

**Date:** 2026-06-27
**Status:** Approved (design); ready for implementation planning
**Scope:** Full technical design, grounded in the Eldrin platform (shell, adapters, the existing factorial extension). React only where UI is required.

---

## 1. Summary

Introduce a new **extension kind** on the Eldrin platform — the **integration extension** — whose purpose is to connect Eldrin to external systems (CRMs, HR systems, ERPs, file feeds, etc.). Unlike a normal app, an integration extension is **headless by default**: it may contribute no left-navigation UI. It is driven by **declarative resource descriptors** rather than hand-written API clients and sync code.

The design generalizes the patterns already proven in `eldrin-factorial` (typed HTTP client with API-key auth and cursor pagination, a sync service mapping remote resources into D1 with `rawJson` + `syncedAt`, sync-state tracking, manifest-declared routes/permissions/settings) into a reusable SDK: **`@eldrin-project/eldrin-integration`**.

The guiding philosophy is **"configure first, override when needed"** — comparable to Apache Camel's building-block approach. A developer should mostly write configuration (a descriptor) and only drop to imperative override hooks when a descriptor cannot express what they need.

`eldrin-factorial` is **rewritten on top of this SDK as part of this work**, serving as the reference integration and the acceptance test for the abstraction.

---

## 2. Goals & Non-Goals

### Goals

- A new `@eldrin-project/eldrin-integration` package providing the integration building blocks.
- A new manifest `kind: "integration"` recognized by the shell.
- Declarative resource descriptors that derive: HTTP/transport client, D1 schema/migrations (for stored resources), generic sync runner, repository, webhook routes, health check, and the admin-panel schema.
- Per-resource **storage modes** (`stored` / `live` / `cached`) with declared capability + admin override.
- Three refresh paths for stored data: **scheduled** (cron), **manual**, and **webhooks** (fully implemented).
- A **repository interface** that abstracts stored-vs-live-vs-cached for cross-app consumption.
- Outbound auth strategies: API key / static header, Bearer / static token, OAuth2 client-credentials, OAuth2 authorization-code.
- Transports: HTTP/REST (fully shipped), GraphQL, and File (R2/S3), behind an extensible `Transport` interface.
- Health / connection-test capability derived from the connection block.
- Admin UI: shell-generated management panel by default, with an opt-in custom React management page.
- Rewrite `eldrin-factorial` onto the SDK as the reference integration.

### Non-Goals (explicitly out of scope)

- **SQL-like cross-source query language** (`SELECT … FROM clients JOIN contacts …` spanning API + DB). This is framed as the future evolution of the repository layer; the repository's `query()` signature is shaped to be its eventual backend, but the query engine itself is not built here.
- Raw TCP / native FTP sockets (not supported by Cloudflare Workers). File transfer is via R2 / object storage only.
- SOAP transport (the `Transport` interface allows it later; not shipped now).

---

## 3. Architecture

```
Customer Cloudflare Worker
├── Eldrin Shell (eldrin-core)
│   ├── App management → renders generated integration admin panel
│   ├── AppSettingsForm (existing) → connection settings
│   ├── WebhookSettings (existing) → webhook management
│   └── Events subsystem (existing) → cross-app change notifications
│
├── Integration Extension (e.g. eldrin-factorial, eldrin-acme-crm)
│   ├── defineIntegration({ connection, resources[] })   ← single source of truth
│   ├── (optional) custom React management page (hidden route)
│   └── D1 database (stored resources, sync_state, integration_config, webhook_deliveries)
│
└── @eldrin-project/eldrin-integration  (new SDK package)
```

### 3.1 Package: `@eldrin-project/eldrin-integration`

Depends on `@eldrin-project/eldrin-app-core`. Built with **tsup** (ESM + CJS), subpath exports mirroring app-core's conventions. Reuses app-core's database abstraction (D1/Postgres/Turso/SQLite), migration system, settings accessor, middleware, and events client.

```
@eldrin-project/eldrin-integration
├── transport/      Transport interface + http (shipped), graphql, file (R2/S3)
├── auth/           apiKey | bearer | oauth2-client-credentials | oauth2-auth-code
├── descriptor/     defineIntegration({ connection, resources[] }) + schema validation
├── resource/       ResourceDescriptor model
├── sync/           generic sync runner (descriptor → D1 upsert → sync_state → event)
├── storage/        mode engine: stored (D1) | live (API) | cached (TTL)
├── repository/     createRepository(resource) → findAll/findById/query
├── webhook/        inbound route + signature verify + dedup + handler hooks
├── schedule/       cron-driven scheduled sync, admin-configurable interval
├── health/         connection-test capability → /api/health route + admin action
└── manifest/       emits the `integration` manifest block + generated admin schema
```

**Design for isolation:** each subsystem has one clear purpose, communicates through a defined interface, and is unit-testable in isolation. The descriptor is the only thing a consumer must understand to use the SDK.

---

## 4. Resource Descriptor Model

A developer defines the entire integration in one declarative call:

```ts
export default defineIntegration({
  id: 'eldrin-acme-crm',
  connection: {
    transport: 'http',
    baseUrl: { setting: 'ACME.API_BASE_URL' },        // pulled from manifest settings
    auth: {
      strategy: 'oauth2-client-credentials',
      clientId: { setting: 'ACME.CLIENT_ID' },
      clientSecret: { secret: 'ACME.CLIENT_SECRET' },
      tokenUrl: 'https://acme.com/oauth/token',
    },
    retry: { attempts: 3, backoff: 'exponential' },
  },
  resources: [
    {
      name: 'clients',
      transport: { method: 'GET', path: '/clients', pagination: 'cursor' },
      idField: 'id',
      fieldMap: { id: 'remoteId', name: 'name', email: 'email' },  // remote → local
      supportedModes: ['stored', 'live', 'cached'],
      defaultMode: 'stored',
      refresh: { schedule: '0 * * * *', cache: { ttlSeconds: 300 } },
      webhook: { event: 'client.updated', match: (b) => b.resource_id },
      hooks: { /* transform?, paginate?, beforeUpsert? — optional overrides */ },
    },
  ],
});
```

### 4.1 ResourceDescriptor fields

| Field | Purpose |
|-------|---------|
| `name` | Logical resource name; drives table name, route, repository key. |
| `transport` | Method/path/pagination (or transport-specific config for GraphQL/file). |
| `idField` | Remote primary key; upsert conflict target. |
| `fieldMap` | Remote→local field mapping. Unmapped raw payload preserved as `rawJson`. |
| `supportedModes` | Subset of `['stored','live','cached']` the resource permits. |
| `defaultMode` | Seeded into runtime config on install; must be in `supportedModes`. |
| `refresh` | `schedule` (cron), `cache.ttlSeconds`. |
| `webhook` | Event name + matcher to resolve affected record. |
| `hooks` | Optional override functions: `transform`, `paginate`, `beforeUpsert`. |

### 4.2 Override hooks (the escape hatch)

When a descriptor cannot express something, the developer supplies an override hook. This is the Camel-like "override default behavior when needed." If `eldrin-factorial` needs anything a descriptor can't express, it becomes an override hook — which validates the escape-hatch design.

---

## 5. Storage Modes

Per-resource storage mode follows **declared capability + admin override**.

| Mode | Behavior | Repository reads from |
|------|----------|----------------------|
| `stored` | Scheduled / manual / webhook sync into D1. | D1 table |
| `live` | Fetched on demand on every call. | API |
| `cached` | Live + TTL cache (Workers Cache API / KV). | Cache → API on miss |

- A resource declares `supportedModes`; the admin can switch the active mode **only among those**.
- If a resource omits `live`/`cached` (e.g. it must be joined in the DB), the shell greys those options out with a tooltip. This is the "extension may forbid live" case from the requirements.
- The **active mode is runtime config**, not manifest data, so switching modes never requires a redeploy.

**Mode is invisible to consumers.** `createRepository('clients')` returns `findAll / findById / query` and resolves stored-vs-live-vs-cached internally. For `live` resources, `query()` materializes the API result set in memory so a consumer (e.g. CRM joining contacts → clients) gets uniform results regardless of mode.

---

## 6. Refresh, Webhooks & Scheduling

All three refresh paths converge on the same generic sync runner: **transport fetch → map (`fieldMap`/`transform`) → `beforeUpsert` → upsert (keyed on `idField`, preserving `rawJson` + `syncedAt`) → update `sync_state` → emit change event.**

### 6.1 Scheduled

- Cloudflare Worker **cron triggers**. Each resource declares a default `schedule`; the admin overrides the interval per resource at runtime (stored as config).
- The cron handler iterates due resources and runs the sync runner.
- Per-resource `last_synced_at` drives incremental sync where the API supports `updated_since`.

### 6.2 Manual

- `POST /api/sync` (factorial already has this) and a "Sync now" button in the admin panel, per-resource or all.

### 6.3 Webhooks (fully implemented)

Inbound `POST /api/webhooks/:resource`. The SDK pipeline:

1. **Signature verification** — HMAC strategy declared in the descriptor.
2. **Dedup** — idempotency key / delivery-id stored in `webhook_deliveries`.
3. **Resolve affected record** — via the descriptor's `webhook.match`.
4. **Apply** — fetch-and-upsert, or apply payload directly.
5. **Emit event** — notify subscribing apps.

The shell's existing `WebhookSettings` UI registers/manages endpoints; the descriptor declares the `webhook` block per resource.

### 6.4 Sync state

`sync_state` tracks `resource, lastSyncedAt, lastStatus ('ok'|'error'), lastError, cursor` (generalizes factorial's existing `sync_state` table).

---

## 7. Cross-App Data Consumption

Two layers, matching the requirements:

### 7.1 In-process repository

Other apps import and call `createRepository('clients')` for typed `findAll / findById / query`, mode-transparent. This is the join surface (e.g. CRM contacts → integration clients). The repository follows the platform Repository Pattern.

- For `stored` resources, reads from D1.
- For `cached` resources, reads cache → API on miss.
- For `live` resources, fetches from the API and materializes results. The repository **emits an explicit warning when a `query()` join targets a live resource** — surfacing the "some reports need to join the clients table" caveat rather than failing silently.

### 7.2 Events

On every sync/webhook change the integration emits `integration.<id>.<resource>.changed` via the existing events subsystem; apps subscribe (poll or push) to react. Stored mode keeps cross-app joins cheap; live mode still works through the repository.

### 7.3 Future: cross-source query language

The SQL-like query language (`SELECT … FROM clients JOIN contacts …` spanning API + DB) is the **future evolution of the repository layer** — out of scope here, but `query()` is shaped to be its eventual backend.

---

## 8. Authentication Strategies

Credentials are stored via the existing settings `secret` storage and injected as proxy headers (`getAppSettings`). The SDK ships four strategies behind a common `AuthStrategy` interface:

| Strategy | Behavior |
|----------|----------|
| `apiKey` | Header or query-param key injection (factorial's `x-api-key`). |
| `bearer` | `Authorization: Bearer <token>`. |
| `oauth2-client-credentials` | Machine-to-machine: `client_id`/`secret` → token endpoint, auto-refresh, token caching. |
| `oauth2-auth-code` | User-delegated flow with redirect + refresh tokens (per-user consent). |

---

## 9. Transports

Behind an extensible `Transport` interface so additional transports (e.g. SOAP) can be added later without changing the descriptor model.

| Transport | Status | Notes |
|-----------|--------|-------|
| `http` (REST) | **Shipped** | JSON, declared pagination (cursor/offset/page), retries/backoff. |
| `graphql` | Shipped | Query/variables config; pagination via cursors. |
| `file` (R2/S3) | Shipped | File-based transfer over R2 / object storage (Workers-compatible). |

Raw TCP / native FTP are not possible on Workers and are excluded.

---

## 10. Manifest & Extension Kind

### 10.1 New manifest block

Extensions declare `"kind": "integration"` and an `integration` block.

```jsonc
{
  "kind": "integration",
  "integration": {
    "connection": { "transport": "http", "authStrategy": "oauth2-client-credentials" },
    "resources": [
      { "name": "clients", "supportedModes": ["stored","live","cached"],
        "defaultMode": "stored", "schedule": "0 * * * *", "webhook": true }
    ],
    "health": { "route": "/api/health" }
  }
}
```

`kind: "integration"` signals the shell to **accept an empty `ui.sideNav`** as valid — a headless integration is allowed. The developer **may still declare `sideNav` items to enforce a UI contribution** when the integration warrants one.

### 10.2 Immutable manifest + runtime config

The manifest stays **immutable** (build-time, checksummed). Everything an admin changes — active mode per resource, schedule overrides, cache TTL, webhook enable/disable — lives in a **runtime config store** (D1 table `integration_config`, keyed by resource), seeded from manifest defaults on install.

### 10.3 New / generalized D1 tables (SDK-managed)

- `sync_state` — per-resource sync status (generalized from factorial).
- `integration_config` — runtime admin overrides (mode, schedule, TTL, webhook enabled).
- `webhook_deliveries` — dedup/idempotency for inbound webhooks.
- Per stored-resource tables — derived from descriptor `fieldMap`, always including `rawJson` + `syncedAt`.

---

## 11. Health / Connection-Test

Derived from the connection block. The SDK auto-generates:

- A `/api/health` route per integration that performs a lightweight authenticated call to verify connectivity and credentials.
- A **"Test connection"** action in the admin panel.

(Factorial already has `GET /api/connection`; this generalizes it.)

---

## 12. Admin UI

**Both shell-generated default + opt-in custom.** React is the only UI surface in scope.

The SDK emits an **admin schema** derived from the descriptor; the shell renders a standard management panel under app management:

- **Connection** — settings fields (reuses existing `AppSettingsForm`) + a **Test connection** button hitting `/api/health`.
- **Resources** — per resource: a mode selector (only `supportedModes` enabled; others greyed with a tooltip), schedule/TTL inputs, "Sync now", and last-sync status from `sync_state`.
- **Webhooks** — reuses the shell's existing `WebhookSettings`.

An integration may **opt out** of the generated panel by registering its own React management page as a **hidden route** (not in `sideNav`) — the factorial-style custom Settings page, for richer UX.

---

## 13. Testing Strategy

TDD, 80%+ coverage. Unit + integration + E2E (per project rules).

### Unit
Each building block in isolation with mocked `fetch`/transport:
- Auth strategies (header injection, OAuth2 token fetch + refresh + caching).
- Transports (REST pagination, GraphQL, file/R2).
- `fieldMap` / `transform` mapping.
- Storage-mode engine (stored/live/cached resolution + TTL expiry).
- Webhook pipeline (signature verify, dedup, malformed-payload rejection).
- Schedule due-resource selection.

### Integration
End-to-end against a mocked external API into a real SQLite (app-core's `sqlite-node` test DB):
- Full sync → `sync_state` → repository read.
- Mode switch stored↔live yields identical repository results.
- Webhook delivery → upsert → event emitted.
- Cron trigger drives a sync.

### Boundary / validation
- Descriptors validated with a schema at `defineIntegration()` (fail fast: unsupported default mode, missing auth settings, live-only resource used in a join → explicit warning).
- Never trust external API responses; validate before upsert.

### E2E
Admin panel flow in eldrin-core (Playwright): test connection, switch a resource mode, trigger "Sync now", see status update.

---

## 14. Factorial Refactor (Reference Integration)

`eldrin-factorial` is **rewritten on top of the SDK as part of this work** — it is the proof the abstraction holds and the acceptance test for the SDK.

| Today (hand-written) | Becomes (declarative) |
|----------------------|------------------------|
| `factorial-client.ts` — `x-api-key`, cursor pagination | `auth: apiKey` + `transport: http, pagination: cursor` |
| `sync.ts` — employees/projects/teams/timeoff upserts with `rawJson`/`syncedAt` | resource descriptors with `fieldMap`s |
| `sync_state` table | SDK-managed `sync_state` |
| React pages (Employees/Teams/TimeOff/Settings) | opt-in custom management UI (hidden routes) |
| `GET /api/connection` | generated `/api/health` |
| `POST /api/sync` | generic manual-sync path |

Factorial's existing tests are kept green throughout and become the acceptance test for the SDK. Anything factorial needs that a descriptor can't express becomes an **override hook**, validating the escape-hatch design.

---

## 15. Implementation Order (suggested)

1. Scaffold `@eldrin-project/eldrin-integration` (tsup, exports, dep on app-core).
2. `Transport` interface + HTTP transport (REST, pagination, retry).
3. Auth strategies (apiKey, bearer, then OAuth2 variants).
4. Descriptor model + `defineIntegration()` + schema validation.
5. Sync runner + `sync_state` + derived schema/migrations.
6. Storage-mode engine (stored → live → cached) + repository.
7. Webhook pipeline + `webhook_deliveries`.
8. Scheduling (cron) + `integration_config` runtime overrides.
9. Health/connection-test.
10. Manifest `kind: "integration"` + generated admin schema; shell admin panel + headless handling.
11. GraphQL + file (R2/S3) transports.
12. Rewrite `eldrin-factorial` on the SDK; keep its tests green.
13. E2E admin flow in eldrin-core.
