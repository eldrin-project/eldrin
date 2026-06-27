# Manifest-Driven Integration Layer — Technical Design

**Date:** 2026-06-27
**Status:** Approved (design); ready for implementation planning
**Builds on:** `docs/superpowers/specs/2026-06-27-integration-extension-design.md` (the shipped `@eldrin-project/eldrin-integration` SDK) and its implementation (`docs/superpowers/plans/2026-06-27-integration-extension.md`).

---

## 1. Summary

Add a layer on top of the shipped integration SDK that makes a straightforward integration **zero-boilerplate**. A developer declares an integration in a JSON config file (and, only when business logic is needed, a hooks file), and a single host helper — `createIntegrationWorker(config, hooks?)` — auto-wires the sync route, health check, repository, scheduled cron, event emission/subscription, and config seeding.

Each integration remains its own Cloudflare Worker with its own D1 database and deploy — only the *boilerplate* disappears, not the isolation. The Worker entry collapses from three hand-written files (`integration-runtime.ts`, a sync route, a Hono app + scheduled handler) to a single line.

The JSON config does **not** introduce a parallel runtime. It is parsed and validated against the **existing** `IntegrationDescriptor` model (reusing `validateDescriptor`), hooks are bound by name, and the result is the exact in-memory descriptor the already-shipped sync runner, repository, scheduler, and health check consume. The JSON is a serializable front-end to the proven model.

This pass also **implements the `live` and `cached` storage modes** (currently typed stubs) and **wires events** (emit + subscribe) so that `mode` and `events` become real configuration a developer sets in the JSON.

`eldrin-factorial` is refactored onto this layer as the reference, proving zero-boilerplate end-to-end against a real integration.

---

## 2. Goals & Non-Goals

### Goals

- A new SDK export `createIntegrationWorker(config, hooks?)` returning a Cloudflare Worker `{ fetch, scheduled }` that auto-mounts everything from a config object.
- A declarative `integration.config.json` format that parses+validates into the existing `IntegrationDescriptor` model.
- An optional `integration.hooks.ts` of named functions, bound to the config by name via a hooks registry passed to the host.
- **Implement all three storage modes** (`stored`, `live`, `cached`) with transparent repository resolution.
- **Wire events**: per-resource `emitOn` (emit `<id>.<resource>.changed` after sync/webhook) and `subscribesTo` (external event → declared action).
- Config source-of-truth is **runtime-editable**: bundled JSON is a seed written into D1 on install; the host reads the effective config from D1 (falling back to the seed). This enables a future admin authoring UI with no redeploy.
- Build-time schema validation so a malformed config fails `npm run build`, not production.
- An `extend(app)` escape hatch so an integration can add custom routes without abandoning the auto-wiring.
- Refactor `eldrin-factorial` onto the new layer (config + one hook + one-line entry); fold its live `teams`/`timeoff` routes into `live`-mode resources.

### Non-Goals (explicitly out of scope — on the radar, not MVP)

- **Admin authoring UI** to add/edit endpoints, mappings, and modes for an existing integration. The design *enables* it (D1-backed runtime-editable config, sibling-fetchable config file, `kind: "integration"` marker for a future admin app section) but builds no UI in this pass.
- The deferred SDK capabilities that remain stubs and are not required by factorial: `bearer`/OAuth2 auth, GraphQL/file transports, the full webhook pipeline implementation, the cross-source `query()` engine. (`live`/`cached` modes and events ARE implemented here.)
- Putting any integration data into `eldrin-app.manifest.json` (see §4 — the config lives in its own file).

---

## 3. Architecture

```
eldrin-acme/  (a new integration — at most three authored files)
├── integration.config.json     declarative: connection, resources, modes, refresh, events
├── integration.hooks.ts        OPTIONAL: named functions (transform, beforeUpsert, ...)
├── worker/index.ts             ONE line: export default createIntegrationWorker(config, hooks)
├── public/eldrin-app.manifest.json   unchanged; app identity / permissions / UI only
└── migrations/…                generated from the config's resources

@eldrin-project/eldrin-integration  (SDK — new + reused pieces)
├── host/
│   ├── createIntegrationWorker.ts   NEW: parse → validate → bind hooks → mount Hono app + scheduled
│   ├── load-config.ts               NEW: loadEffectiveConfig(db, seedJson) → IntegrationDescriptor
│   └── bind-hooks.ts                NEW: attach hooks-by-name from a registry
├── storage/
│   ├── mode.ts                      EXTENDED: implement live + cached resolution
│   └── cache.ts                     NEW: TTL cache (Workers Cache API / KV)
├── sync/map.ts                      NEW: shared mapRows() (fieldMap + transform) used by sync AND live
├── events/wire.ts                   NEW: emit-on-change + subscribe→action wiring
├── repository/index.ts              EXTENDED: live/cached read paths
├── config/index.ts                  EXTENDED: store full effective config (not just mode/schedule)
└── (existing: descriptor, validate, auth, transport, sync runner, schedule, health, schema, errors)
```

Data flow:

```
integration.config.json ──parse──▶ validateDescriptor ──▶ IntegrationDescriptor
integration.hooks.ts ──bind by name──▶ hooks attached
                  │
   loadEffectiveConfig(db, seedJson): D1 overlay ▶ effective descriptor
                  │
   createIntegrationWorker(config, hooks) auto-mounts:
     POST /api/sync · GET /api/health · repository reads ·
     scheduled() cron · events emit/subscribe · seedConfigFromDescriptor · extend(app)
```

**Design for isolation:** each new unit has one responsibility and a defined interface — `loadEffectiveConfig` (config source resolution), `bindHooks` (name→function), `createIntegrationWorker` (composition only, no business logic), `mapRows` (shared shaping), the cache (TTL only), the events wiring (emit/subscribe only). The host composes them; it contains no integration-specific logic.

---

## 4. Config File & Manifest Separation

### 4.1 The config file is separate from the manifest

`eldrin-app.manifest.json` stays about **app identity, permissions, and UI**. It carries only a `kind: "integration"` marker (already added in the prior pass) for shell discovery. **No connection/resource/mode/event data goes in the manifest.**

The integration's declarative config lives in its own **`integration.config.json`** at the app root, fetchable by the shell as a sibling (`{baseUrl}/integration.config.json`) for its admin UI later.

### 4.2 `integration.config.json` schema

Pure declarative data. Validates against the existing `IntegrationDescriptor` plus the `events` addition.

```jsonc
{
  "id": "eldrin-acme",
  "connection": {
    "transport": "http",
    "baseUrl": { "setting": "ACME.API_BASE_URL" },
    "auth": { "strategy": "apiKey", "header": "x-api-key", "key": { "secret": "ACME.API_KEY" } },
    "retry": { "attempts": 3 }
  },
  "resources": [
    {
      "name": "clients",
      "transport": { "method": "GET", "path": "/clients", "pagination": "cursor" },
      "idField": "id",
      "fieldMap": { "id": "remote_id", "name": "name", "email": "email" },
      "supportedModes": ["stored", "live", "cached"],
      "defaultMode": "stored",
      "refresh": { "schedule": "0 * * * *", "cache": { "ttlSeconds": 300 } },
      "hooks": { "transform": "deriveDisplayName" },
      "events": {
        "emitOn": ["sync", "webhook"],
        "subscribesTo": [{ "pattern": "billing.invoice.paid", "action": "sync" }]
      }
    }
  ]
}
```

Notes:
- `hooks` values are **string names**, not functions (JSON can't hold functions). They resolve against the hooks registry passed to the host (§5.3).
- `events` is the new declarative dimension (§6).
- Credential references (`{ setting }` / `{ secret }`) are unchanged from the SDK — resolved at runtime from app settings, never stored as literals.

### 4.3 `integration.hooks.ts` (optional)

Pure named functions — unchanged from how hooks work today:

```ts
export const deriveDisplayName = (raw: Record<string, unknown>) => ({
  ...raw,
  name: raw.name ?? `${raw.first_name ?? ''} ${raw.last_name ?? ''}`.trim() || null,
});
```

A no-business-logic integration omits this file entirely.

---

## 5. The Host: `createIntegrationWorker`

### 5.1 Signature & entry

```ts
import { createIntegrationWorker } from '@eldrin-project/eldrin-integration';
import config from '../integration.config.json';
import * as hooks from '../integration.hooks';   // omit if no hooks

export default createIntegrationWorker(config, hooks);
```

```ts
function createIntegrationWorker(
  config: unknown,                                  // the parsed JSON
  hooks?: Record<string, HookFn>,                   // the named-hooks registry
  options?: { extend?: (app: Hono) => void },       // custom-route escape hatch
): { fetch: ExportedHandlerFetchHandler; scheduled: ExportedHandlerScheduledHandler };
```

### 5.2 Startup sequence (fail fast)

1. **Parse + validate** `config` against the `IntegrationDescriptor` shape via `validateDescriptor`. On failure → throw `DescriptorError` before serving any request.
2. **Bind hooks**: for each `hooks` name in the config, resolve it in the registry. An unknown name → `DescriptorError` (fail fast). A config referencing no hooks needs no registry.
3. **First request**: run migrations, then `seedConfigFromDescriptor` (writes the JSON seed into D1 if absent — see §7).
4. **Load effective config** from D1 (`loadEffectiveConfig`), producing the descriptor the runtime uses.

### 5.3 Auto-mounted surface

A Hono app with:
- `POST /api/sync` — manual sync (`runAllSync`), userId-guarded, "not configured" 400 guard, maps `IntegrationError.status`.
- `GET /api/health` — `testConnection` against a probe resource.
- Repository read routes per resource (`GET /api/:resource`, `GET /api/:resource/:id`) — mode-transparent.
- `scheduled()` — runs due resources (`runScheduled` honoring per-resource schedule; see §7).
- Events wiring (§6).
- `options.extend(app)` is invoked last, letting an integration add custom routes without losing the auto-mounted ones.

The host contains **only composition** — no integration-specific logic. All behavior comes from the descriptor + the existing SDK units.

### 5.4 Build-time validation

A small build step (or a `prebuild` script) runs the same JSON-schema/`validateDescriptor` check on `integration.config.json` so a malformed config fails `npm run build`, not runtime. Reuses the runtime validator to avoid drift.

---

## 6. Events

Wired through the existing shell events subsystem (`EldrinEventClient`).

### 6.1 Emit (`emitOn`)

After each sync or webhook upsert for a resource that declares `emitOn`, the host emits `<id>.<resource>.changed` (e.g. `eldrin-acme.clients.changed`). The payload carries the resource name and affected count — **not** the rows (consumers pull via the repository). `emitOn` values are `"sync"` and/or `"webhook"`.

### 6.2 Subscribe (`subscribesTo`)

Each `subscribesTo` entry declares a `pattern` and an `action`. The host registers the pattern with the events subsystem; on a matching delivery it runs the action. MVP action enum: `"sync"` (run that resource's sync). The action field is an enum now, designed to extend to a named hook (`action: "hook:myHandler"`) later without schema change.

### 6.3 Errors

Emission/subscription failures are logged with context and never crash the sync; a failed subscribed-action is recorded but does not throw into the events subsystem.

---

## 7. Runtime-Editable Config (enables the future admin UI)

**Source-of-truth: bundled JSON is a seed; D1 is the runtime source.**

- On install/first request, `seedConfigFromDescriptor` writes the bundled config into the `_integration_config` D1 table. This table is **extended** to hold the full effective config per resource (connection-level + resource-level: endpoint/path, fieldMap, mode, schedule, cache TTL, webhook enabled, events) — not just mode/schedule as today.
- The host loads the **effective** descriptor via `loadEffectiveConfig(db, seedJson)`: read from D1; if absent, fall back to the JSON seed (and seed it).
- MVP behavior is unchanged — D1 simply mirrors the JSON. But because the runtime reads from D1, a **future admin UI edits the D1 rows** (add an endpoint, change a mapping, switch a mode) and the host picks them up **with no redeploy**.

`loadEffectiveConfig` is a single, well-defined seam — the only place config source is resolved — so the future UI is a row-editing add-on, not a rewrite.

---

## 8. Storage Modes (all three implemented)

The repository resolves the effective mode per resource (from D1 config) and reads accordingly. Behavior is transparent to callers — `findAll` / `findById` / `query` return uniform results regardless of mode.

| Mode | `findAll` / `findById` read from | Wiring |
|------|----------------------------------|--------|
| `stored` | D1 table (existing) | scheduled / manual / webhook sync populates it |
| `live` | the API on every call | transport fetch → `mapRows()` applied in-memory; no D1 write |
| `cached` | Workers Cache API / KV → API on miss | TTL from `refresh.cache.ttlSeconds`; populated lazily; same `mapRows()` |

- **Shared shaping:** the row mapping (`fieldMap` + `transform` hook) is extracted from the sync runner into a shared `mapRows()` so stored-sync and live/cached fetch produce **identical** shapes. (This refactors the existing `mapRow` in the sync runner to call the shared unit — no behavior change for stored.)
- **Mode switching:** an admin changing a resource's mode (via D1 config / future UI) flips the read path with no code change. Resolution is two-layered and unambiguous: (a) at **validate** time, if `defaultMode` or any declared `supportedModes` entry is not a real mode, throw `DescriptorError` (fail fast). (b) at **resolve** time, the effective configured mode must be a member of `supportedModes`; if a D1 override names a mode outside `supportedModes`, the resolver ignores it and falls back to `defaultMode` (consistent with the existing `effectiveMode`). So: structurally-invalid modes fail the build; a runtime override that violates `supportedModes` degrades safely to the default rather than erroring a live request.
- **`cached` cache key:** `<id>:<resource>:findAll|findById:<id?>`; invalidated on TTL expiry. The cache is consulted only when the effective mode is `cached`. A `stored`-mode sync does not write the cache. Because a resource's mode can be switched at runtime (e.g. `cached` → `stored`), a mode change explicitly clears that resource's cache entries so a later switch back to `cached` cannot serve stale data.

---

## 9. Error Handling & Boundaries

Per the project's coding rules:
- Config parse/validation failures and unknown hook names throw `DescriptorError` at **startup**, before serving requests (fail fast).
- Unimplemented capability selections still throw `NotImplementedError` (the deferred stubs are unchanged).
- `live`/`cached` fetch errors surface as `IntegrationError` carrying the HTTP status — never a silently empty result.
- Every external API response is validated through the shared `mapRows()` path before storage or return; raw payload preserved as `raw_json` (stored mode).
- Event emit/subscribe failures are logged with context and isolated from the sync path.

---

## 10. Factorial Refactor (Reference Integration)

`eldrin-factorial` is refactored onto the new layer as the canonical zero-boilerplate example.

| Today (TS descriptor) | After (manifest-driven) |
|---|---|
| `worker/integration.ts` — `defineIntegration({...})` with inline transform | `integration.config.json` (declarative) + `integration.hooks.ts` (`deriveFullName`) |
| `worker/integration-runtime.ts` — `buildSyncDeps` | **deleted** — host builds deps from config |
| `worker/routes/sync.ts` — hand-written | **deleted** — host auto-mounts `POST /api/sync` |
| `worker/index.ts` — Hono app + scheduled handler | **one line**: `export default createIntegrationWorker(config, hooks)` |
| `worker/services/factorial-client.ts` + `teams`/`timeoff` routes (live) | `teams`/`timeoff` become `live`-mode resources in the config; standalone client retired |
| `GET /api/connection` | host-mounted `GET /api/health` |

- employees/projects stay `stored`; teams/timeoff become `live` (now that live mode is implemented), folding into the descriptor.
- This proves: a no-hook resource needs zero code; a hooked resource needs only the named function; live and stored modes coexist in one config.

**Acceptance baseline:** factorial's existing behavior is preserved — same synced data, same `remote_id` / `raw_json` / `synced_at` shape, the transform still derives `full_name`. The current local DB (38 employees, 8 projects, transform working, sync_state ok) is the regression baseline.

---

## 11. Testing Strategy

TDD, 80%+ coverage. Unit + integration + acceptance + E2E.

### Unit
- `loadEffectiveConfig`: JSON seed → D1 → effective descriptor; D1-present overrides seed; absent falls back and seeds.
- JSON parse → `validateDescriptor`: malformed config → `DescriptorError`; unimplemented selection → `NotImplementedError`.
- `bindHooks`: resolves names from registry; unknown name → `DescriptorError`; no-hooks config needs no registry.
- Mode engine: `stored`/`live`/`cached` read resolution; cache TTL hit/miss/expiry; mode outside `supportedModes` handling.
- `mapRows`: identical output for the same raw input across stored and live paths; `transform` + `fieldMap` applied; `raw_json` preserved.
- Events: emit payload shape (resource + count, no rows) on sync and webhook; subscribe pattern → `sync` action dispatch; emit/subscribe failure isolated.
- Build-time schema validation rejects a malformed config.

### Integration (real SQLite via the existing test helper)
- `createIntegrationWorker` end-to-end: config → mounted routes → `POST /api/sync` upserts → repository read.
- Mode switch `stored`↔`live`↔`cached` yields identical repository results for the same data.
- Emit fires after a sync; a subscribed event triggers a sync.
- `extend(app)` adds a custom route that responds, without breaking auto-mounted routes.
- `scheduled()` honors per-resource schedule via `dueResources`.

### Factorial acceptance
- Existing SDK-sync acceptance test stays green.
- New test: the JSON-config path reproduces the prior TS-descriptor results exactly (same employee/project mapping + transform output).

### E2E (shell)
- Load factorial via the new host, run "Sync now", confirm Employees populates (the manual test already performed, formalized).

---

## 12. Implementation Order (suggested)

1. `mapRows()` extraction (refactor sync runner to use it; no behavior change) — unblocks live/cached.
2. Storage-mode engine: implement `live`, then `cached` (+ cache unit); repository read paths.
3. `loadEffectiveConfig` + extend `_integration_config` to hold full effective config; `seedConfigFromDescriptor` writes the seed.
4. `bindHooks` (name → function registry).
5. `createIntegrationWorker` host: parse → validate → bind → mount routes + scheduled + `extend`.
6. Events wiring: emit-on-change, then subscribe→action.
7. Build-time config validation step.
8. Refactor `eldrin-factorial` onto the layer (config + hook + one-line entry; teams/timeoff → live); keep tests green.
9. E2E in the shell.

(The admin authoring UI is explicitly deferred — §2 Non-Goals — but every step above keeps its door open: D1-backed config, `loadEffectiveConfig` seam, sibling-fetchable config file, `kind: "integration"` marker.)
