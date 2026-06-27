# Integration Extension Type Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a new `@eldrin-project/eldrin-integration` SDK that lets a developer define an external-system integration with a declarative descriptor, and rewrite `eldrin-factorial` onto it as the reference integration.

**Architecture:** A framework-agnostic SDK package (mirroring `@eldrin-project/eldrin-app-core`'s tsup build) provides building blocks — transports, auth strategies, a descriptor model, a generic sync runner, a storage-mode engine, a repository, a health check, scheduling, and webhook scaffolding. The full abstraction is designed and typed; only the slice `eldrin-factorial` exercises is implemented (apiKey auth, HTTP GET + cursor transport, `stored` mode, manual + scheduled sync). Every unimplemented capability is a typed stub that throws a documented `NotImplemented` error.

**Tech Stack:** TypeScript 5.8 (strict), tsup (ESM+CJS), Vitest (globals, node env), Hono 4, drizzle-orm/d1, Cloudflare Workers. SDK depends on `@eldrin-project/eldrin-app-core` and operates on its `DatabaseAdapter` interface (not drizzle directly).

## Global Constraints

- **Package name:** `@eldrin-project/eldrin-integration`, version `0.0.1`, `"type": "module"`, `publishConfig.access = "public"`.
- **Build:** tsup, `format: ['esm','cjs']`, `dts: true`, `sourcemap: true`, `treeshake: true`, `minify: false`. Mirror app-core's `tsup.config.ts` shape.
- **Node engine:** `>=18.0.0`. TypeScript `^5.8.0`, strict mode.
- **Dependency:** `@eldrin-project/eldrin-app-core` via `file:../eldrin-app-core` (matches factorial's existing local-link convention).
- **Database access:** the SDK MUST use the app-core `DatabaseAdapter` interface (`prepare().bind().all()/first()/run()`), never drizzle or a raw D1 type directly. This keeps it D1/Postgres/SQLite-portable.
- **Stub boundary:** unimplemented capabilities throw `new NotImplementedError(capability)` — a typed, documented error. NEVER a silent no-op. (Defined in Task 2.)
- **Immutability:** create new objects, never mutate inputs (per coding-style rule). Descriptor inputs are treated as frozen.
- **Tests:** co-located `*.test.ts`, Vitest. TDD: failing test first. Target 80%+ coverage. SQLite-backed integration tests use app-core's SQLite adapter via `@eldrin-project/eldrin-app-core/database/sqlite`.
- **Commit convention:** Conventional Commits (`feat:`, `test:`, `chore:`, `refactor:`, `docs:`). Attribution disabled.
- **Repo/cwd gotcha:** The SDK lives in its own submodule repo `eldrin-integration/`. The factorial repo is `eldrin-factorial/`. Run all git commands with `git -C <repo-root>` using absolute paths — the Bash cwd persists across calls and a stray `cd` into one submodule misdirects commits to the wrong repo.

**Spec:** `docs/superpowers/specs/2026-06-27-integration-extension-design.md`. The §14a "Implemented vs. Scaffolded" matrix is the authoritative scope. This plan has two parts:
- **Part A (Tasks 1–14):** the SDK package.
- **Part B (Tasks 15–20):** the factorial rewrite + shell manifest support + E2E.

---

## File Structure (Part A — `eldrin-integration/`)

```
eldrin-integration/
├── package.json
├── tsup.config.ts
├── tsconfig.json
├── vitest.config.ts
├── src/
│   ├── index.ts                      Public barrel export
│   ├── errors.ts                     NotImplementedError, IntegrationError, DescriptorError
│   ├── transport/
│   │   ├── index.ts                  Transport interface + factory
│   │   ├── http.ts                   HTTP/REST: GET + cursor pagination + retry (IMPLEMENTED)
│   │   ├── graphql.ts                stub (NotImplemented)
│   │   └── file.ts                   stub (NotImplemented)
│   ├── auth/
│   │   ├── index.ts                  AuthStrategy interface + factory
│   │   ├── api-key.ts                header/query key injection (IMPLEMENTED)
│   │   ├── bearer.ts                 stub
│   │   └── oauth2.ts                 client-credentials + auth-code stubs
│   ├── descriptor/
│   │   ├── index.ts                  defineIntegration() + types
│   │   └── validate.ts               schema validation (fail fast)
│   ├── sync/
│   │   ├── index.ts                  runResourceSync(), runAllSync()
│   │   └── sync-state.ts             sync_state table read/write
│   ├── storage/
│   │   └── mode.ts                   resolveMode(): stored impl; live/cached stub
│   ├── repository/
│   │   └── index.ts                  createRepository(): findAll/findById (stored); query() stub
│   ├── webhook/
│   │   └── index.ts                  route shape + pipeline stub
│   ├── schedule/
│   │   └── index.ts                  dueResources() + runScheduled()
│   ├── health/
│   │   └── index.ts                  testConnection()
│   ├── config/
│   │   └── index.ts                  integration_config read/write (runtime overrides)
│   └── schema/
│       └── tables.ts                 SDK-managed table SQL (sync_state, integration_config, webhook_deliveries)
```

---

## Part A — The SDK

### Task 1: Scaffold the `eldrin-integration` package

**Files:**
- Create: `eldrin-integration/package.json`
- Create: `eldrin-integration/tsconfig.json`
- Create: `eldrin-integration/tsup.config.ts`
- Create: `eldrin-integration/vitest.config.ts`
- Create: `eldrin-integration/src/index.ts`
- Create: `eldrin-integration/.gitignore`

**Interfaces:**
- Consumes: nothing (first task).
- Produces: a buildable, testable empty package. `npm run build`, `npm run test`, `npm run typecheck` all succeed.

- [ ] **Step 1: Create the package directory and `package.json`**

```jsonc
// eldrin-integration/package.json
{
  "name": "@eldrin-project/eldrin-integration",
  "version": "0.0.1",
  "description": "Integration extension SDK for Eldrin — declarative connectors to external systems",
  "publishConfig": { "access": "public" },
  "type": "module",
  "main": "./dist/index.cjs",
  "module": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": {
      "import": { "types": "./dist/index.d.ts", "default": "./dist/index.js" },
      "require": { "types": "./dist/index.d.cts", "default": "./dist/index.cjs" }
    }
  },
  "files": ["dist"],
  "scripts": {
    "build": "tsup",
    "dev": "tsup --watch",
    "test": "vitest",
    "test:run": "vitest run",
    "typecheck": "tsc --noEmit",
    "prepublishOnly": "npm run build"
  },
  "license": "MIT",
  "author": "Eldrin Team",
  "engines": { "node": ">=18.0.0" },
  "dependencies": {
    "@eldrin-project/eldrin-app-core": "file:../eldrin-app-core"
  },
  "devDependencies": {
    "@cloudflare/workers-types": "^4.20251216.0",
    "@types/node": "^22.0.0",
    "@vitest/coverage-v8": "^2.0.0",
    "tsup": "^8.0.0",
    "typescript": "^5.8.0",
    "vitest": "^2.0.0"
  }
}
```

> **Note:** Task 8 may add `better-sqlite3` (+ `@types/better-sqlite3`) to devDependencies if app-core's node SQLite adapter requires it (confirmed in Task 8 Step 1). `@vitest/coverage-v8` is included now because Task 14/20 run `vitest run --coverage`.

- [ ] **Step 2: Create `tsconfig.json`**

```jsonc
// eldrin-integration/tsconfig.json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "lib": ["ES2022"],
    "types": ["@cloudflare/workers-types", "node"],
    "strict": true,
    "declaration": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "noEmit": true,
    "verbatimModuleSyntax": true
  },
  "include": ["src"]
}
```

- [ ] **Step 3: Create `tsup.config.ts`**

```ts
// eldrin-integration/tsup.config.ts
import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: { index: 'src/index.ts' },
    format: ['esm', 'cjs'],
    dts: true,
    clean: true,
    sourcemap: true,
    external: ['@eldrin-project/eldrin-app-core'],
    treeshake: true,
    minify: false,
  },
]);
```

- [ ] **Step 4: Create `vitest.config.ts`**

```ts
// eldrin-integration/vitest.config.ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['src/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.test.ts'],
    },
  },
});
```

- [ ] **Step 5: Create `.gitignore` and a placeholder `src/index.ts`**

```
// eldrin-integration/.gitignore
node_modules
dist
coverage
*.tsbuildinfo
```

```ts
// eldrin-integration/src/index.ts
// Public barrel — populated by later tasks.
export {};
```

- [ ] **Step 6: Install and verify the package builds and tests run**

Run:
```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npm install && npm run build && npm run typecheck && npm run test:run
```
Expected: install succeeds, `dist/index.js` + `dist/index.cjs` + `dist/index.d.ts` created, typecheck passes, vitest reports "no test files found" (exit 0 with `--passWithNoTests` not needed since vitest run exits 0 on no files in v2 — if it errors, add `"test:run": "vitest run --passWithNoTests"`).

- [ ] **Step 7: Initialize git and commit**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-integration && git init -q 2>/dev/null; git -C /Users/tibor/projects/eldrin-backup/eldrin-integration add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-integration commit -q -m "chore: scaffold eldrin-integration SDK package"
```

---

### Task 2: Error types

**Files:**
- Create: `eldrin-integration/src/errors.ts`
- Test: `eldrin-integration/src/errors.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `class IntegrationError extends Error { status: number; constructor(message: string, status?: number) }` — default status 500.
  - `class NotImplementedError extends IntegrationError { capability: string; constructor(capability: string) }` — message ```Capability not implemented: ${capability}```, status 501.
  - `class DescriptorError extends IntegrationError { constructor(message: string) }` — status 400.

- [ ] **Step 1: Write the failing test**

```ts
// eldrin-integration/src/errors.test.ts
import { describe, it, expect } from 'vitest';
import { IntegrationError, NotImplementedError, DescriptorError } from './errors';

describe('errors', () => {
  it('IntegrationError defaults to status 500', () => {
    const e = new IntegrationError('boom');
    expect(e.status).toBe(500);
    expect(e.name).toBe('IntegrationError');
    expect(e).toBeInstanceOf(Error);
  });

  it('NotImplementedError carries capability and status 501', () => {
    const e = new NotImplementedError('transport:graphql');
    expect(e.status).toBe(501);
    expect(e.capability).toBe('transport:graphql');
    expect(e.message).toContain('transport:graphql');
    expect(e).toBeInstanceOf(IntegrationError);
  });

  it('DescriptorError uses status 400', () => {
    const e = new DescriptorError('bad descriptor');
    expect(e.status).toBe(400);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/errors.test.ts`
Expected: FAIL — cannot find module './errors'.

- [ ] **Step 3: Write the implementation**

```ts
// eldrin-integration/src/errors.ts
export class IntegrationError extends Error {
  readonly status: number;
  constructor(message: string, status = 500) {
    super(message);
    this.name = 'IntegrationError';
    this.status = status;
  }
}

export class NotImplementedError extends IntegrationError {
  readonly capability: string;
  constructor(capability: string) {
    super(`Capability not implemented: ${capability}`, 501);
    this.name = 'NotImplementedError';
    this.capability = capability;
  }
}

export class DescriptorError extends IntegrationError {
  constructor(message: string) {
    super(message, 400);
    this.name = 'DescriptorError';
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/errors.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Export from barrel and commit**

Edit `src/index.ts` to add:
```ts
export { IntegrationError, NotImplementedError, DescriptorError } from './errors';
```

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-integration add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-integration commit -q -m "feat: add integration error types"
```

---

### Task 3: Descriptor types & `defineIntegration()`

**Files:**
- Create: `eldrin-integration/src/descriptor/index.ts`
- Test: `eldrin-integration/src/descriptor/index.test.ts`

**Interfaces:**
- Consumes: nothing (pure types + identity helper).
- Produces:
  - Types:
    ```ts
    type SettingRef = { setting: string } | { secret: string };
    type StorageMode = 'stored' | 'live' | 'cached';
    type PaginationKind = 'none' | 'cursor' | 'offset' | 'page';
    type TransportKind = 'http' | 'graphql' | 'file';
    type AuthStrategyKind = 'apiKey' | 'bearer' | 'oauth2-client-credentials' | 'oauth2-auth-code';

    interface HttpResourceTransport {
      method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
      path: string;
      pagination?: PaginationKind;
    }
    interface AuthConfig {
      strategy: AuthStrategyKind;
      // apiKey:
      header?: string; queryParam?: string; key?: SettingRef;
      // bearer:
      token?: SettingRef;
      // oauth2:
      clientId?: SettingRef; clientSecret?: SettingRef; tokenUrl?: string; authorizeUrl?: string; scopes?: string[];
    }
    interface ConnectionConfig {
      transport: TransportKind;
      baseUrl: SettingRef | string;
      auth: AuthConfig;
      retry?: { attempts: number; backoff?: 'fixed' | 'exponential' };
    }
    interface ResourceHooks {
      transform?: (raw: Record<string, unknown>) => Record<string, unknown>;
      paginate?: unknown; // reserved
      beforeUpsert?: (mapped: Record<string, unknown>, raw: Record<string, unknown>) => Record<string, unknown>;
    }
    interface ResourceDescriptor {
      name: string;
      transport: HttpResourceTransport;
      idField: string;
      fieldMap: Record<string, string>; // remote key -> local column
      supportedModes: StorageMode[];
      defaultMode: StorageMode;
      refresh?: { schedule?: string; cache?: { ttlSeconds: number } };
      webhook?: { event: string; match: (body: Record<string, unknown>) => string | number | undefined };
      hooks?: ResourceHooks;
    }
    interface IntegrationDescriptor {
      id: string;
      connection: ConnectionConfig;
      resources: ResourceDescriptor[];
    }
    ```
  - `function defineIntegration(descriptor: IntegrationDescriptor): IntegrationDescriptor` — returns a deep-frozen copy (immutability) after validation (validation wired in Task 4; for now just freeze + return).

- [ ] **Step 1: Write the failing test**

```ts
// eldrin-integration/src/descriptor/index.test.ts
import { describe, it, expect } from 'vitest';
import { defineIntegration } from './index';
import type { IntegrationDescriptor } from './index';

const base: IntegrationDescriptor = {
  id: 'eldrin-acme',
  connection: {
    transport: 'http',
    baseUrl: { setting: 'ACME.API_BASE_URL' },
    auth: { strategy: 'apiKey', header: 'x-api-key', key: { secret: 'ACME.API_KEY' } },
  },
  resources: [
    {
      name: 'clients',
      transport: { method: 'GET', path: '/clients', pagination: 'cursor' },
      idField: 'id',
      fieldMap: { id: 'remoteId', name: 'name' },
      supportedModes: ['stored'],
      defaultMode: 'stored',
    },
  ],
};

describe('defineIntegration', () => {
  it('returns a descriptor with the same shape', () => {
    const d = defineIntegration(base);
    expect(d.id).toBe('eldrin-acme');
    expect(d.resources[0].name).toBe('clients');
  });

  it('returns a frozen object (immutability)', () => {
    const d = defineIntegration(base);
    expect(Object.isFrozen(d)).toBe(true);
    expect(() => { (d as { id: string }).id = 'mutated'; }).toThrow();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/descriptor/index.test.ts`
Expected: FAIL — cannot find module './index'.

- [ ] **Step 3: Write the implementation**

```ts
// eldrin-integration/src/descriptor/index.ts
export type SettingRef = { setting: string } | { secret: string };
export type StorageMode = 'stored' | 'live' | 'cached';
export type PaginationKind = 'none' | 'cursor' | 'offset' | 'page';
export type TransportKind = 'http' | 'graphql' | 'file';
export type AuthStrategyKind = 'apiKey' | 'bearer' | 'oauth2-client-credentials' | 'oauth2-auth-code';

export interface HttpResourceTransport {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  path: string;
  pagination?: PaginationKind;
}

export interface AuthConfig {
  strategy: AuthStrategyKind;
  header?: string;
  queryParam?: string;
  key?: SettingRef;
  token?: SettingRef;
  clientId?: SettingRef;
  clientSecret?: SettingRef;
  tokenUrl?: string;
  authorizeUrl?: string;
  scopes?: string[];
}

export interface ConnectionConfig {
  transport: TransportKind;
  baseUrl: SettingRef | string;
  auth: AuthConfig;
  retry?: { attempts: number; backoff?: 'fixed' | 'exponential' };
}

export interface ResourceHooks {
  transform?: (raw: Record<string, unknown>) => Record<string, unknown>;
  paginate?: unknown;
  beforeUpsert?: (
    mapped: Record<string, unknown>,
    raw: Record<string, unknown>,
  ) => Record<string, unknown>;
}

export interface ResourceDescriptor {
  name: string;
  transport: HttpResourceTransport;
  idField: string;
  fieldMap: Record<string, string>;
  supportedModes: StorageMode[];
  defaultMode: StorageMode;
  refresh?: { schedule?: string; cache?: { ttlSeconds: number } };
  webhook?: {
    event: string;
    match: (body: Record<string, unknown>) => string | number | undefined;
  };
  hooks?: ResourceHooks;
}

export interface IntegrationDescriptor {
  id: string;
  connection: ConnectionConfig;
  resources: ResourceDescriptor[];
}

/**
 * Define an integration. Returns a deep-frozen descriptor.
 * Validation is applied in Task 4 (validateDescriptor wired here).
 */
export function defineIntegration(descriptor: IntegrationDescriptor): IntegrationDescriptor {
  return deepFreeze(descriptor);
}

function deepFreeze<T>(obj: T): T {
  if (obj && typeof obj === 'object') {
    for (const value of Object.values(obj as Record<string, unknown>)) {
      if (value && typeof value === 'object') deepFreeze(value);
    }
    return Object.freeze(obj);
  }
  return obj;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/descriptor/index.test.ts`
Expected: PASS (2 tests). Note: the freeze-throws assertion requires strict mode at runtime — Vitest runs ESM modules in strict mode, so assignment to a frozen prop throws `TypeError`.

- [ ] **Step 5: Export from barrel and commit**

Add to `src/index.ts`:
```ts
export { defineIntegration } from './descriptor';
export type {
  SettingRef, StorageMode, PaginationKind, TransportKind, AuthStrategyKind,
  HttpResourceTransport, AuthConfig, ConnectionConfig, ResourceHooks,
  ResourceDescriptor, IntegrationDescriptor,
} from './descriptor';
```

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-integration add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-integration commit -q -m "feat: add integration descriptor model and defineIntegration"
```

---

### Task 4: Descriptor validation (fail fast)

**Files:**
- Create: `eldrin-integration/src/descriptor/validate.ts`
- Modify: `eldrin-integration/src/descriptor/index.ts` (call `validateDescriptor` inside `defineIntegration` before freezing)
- Test: `eldrin-integration/src/descriptor/validate.test.ts`

**Interfaces:**
- Consumes: `IntegrationDescriptor`, `DescriptorError`, `NotImplementedError` (Task 2/3).
- Produces: `function validateDescriptor(d: IntegrationDescriptor): void` — throws `DescriptorError` on structural problems; throws `NotImplementedError` when the descriptor selects a capability not implemented in this pass.

  Implemented capabilities accepted: transport `http` with `method: 'GET'` and `pagination` in `{none, cursor}`; auth strategy `apiKey`; storage modes — `defaultMode` and every `supportedModes` entry must be `stored` (others are scaffolded). Anything else → `NotImplementedError` with a capability string like `transport:graphql`, `auth:bearer`, `mode:live`, `http:POST`, `pagination:offset`.

- [ ] **Step 1: Write the failing test**

```ts
// eldrin-integration/src/descriptor/validate.test.ts
import { describe, it, expect } from 'vitest';
import { defineIntegration } from './index';
import type { IntegrationDescriptor } from './index';
import { DescriptorError, NotImplementedError } from '../errors';

function make(overrides: Partial<IntegrationDescriptor> = {}): IntegrationDescriptor {
  return {
    id: 'eldrin-acme',
    connection: {
      transport: 'http',
      baseUrl: { setting: 'ACME.API_BASE_URL' },
      auth: { strategy: 'apiKey', header: 'x-api-key', key: { secret: 'ACME.API_KEY' } },
    },
    resources: [
      {
        name: 'clients',
        transport: { method: 'GET', path: '/clients', pagination: 'cursor' },
        idField: 'id',
        fieldMap: { id: 'remoteId' },
        supportedModes: ['stored'],
        defaultMode: 'stored',
      },
    ],
    ...overrides,
  };
}

describe('validateDescriptor (via defineIntegration)', () => {
  it('accepts a valid factorial-shaped descriptor', () => {
    expect(() => defineIntegration(make())).not.toThrow();
  });

  it('rejects empty id', () => {
    expect(() => defineIntegration(make({ id: '' }))).toThrow(DescriptorError);
  });

  it('rejects defaultMode not in supportedModes', () => {
    const d = make();
    d.resources[0].supportedModes = ['stored'];
    d.resources[0].defaultMode = 'live';
    expect(() => defineIntegration(d)).toThrow(DescriptorError);
  });

  it('rejects duplicate resource names', () => {
    const d = make();
    d.resources = [d.resources[0], { ...d.resources[0] }];
    expect(() => defineIntegration(d)).toThrow(DescriptorError);
  });

  it('throws NotImplemented for graphql transport', () => {
    expect(() => defineIntegration(make({
      connection: { ...make().connection, transport: 'graphql' },
    }))).toThrow(NotImplementedError);
  });

  it('throws NotImplemented for bearer auth', () => {
    const c = make().connection;
    expect(() => defineIntegration(make({
      connection: { ...c, auth: { strategy: 'bearer', token: { secret: 'X' } } },
    }))).toThrow(NotImplementedError);
  });

  it('throws NotImplemented for live mode', () => {
    const d = make();
    d.resources[0].supportedModes = ['stored', 'live'];
    expect(() => defineIntegration(d)).toThrow(NotImplementedError);
  });

  it('throws NotImplemented for non-GET method', () => {
    const d = make();
    d.resources[0].transport = { method: 'POST', path: '/clients' };
    expect(() => defineIntegration(d)).toThrow(NotImplementedError);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/descriptor/validate.test.ts`
Expected: FAIL — cannot find module './validate' / validation not wired.

- [ ] **Step 3: Write the implementation**

```ts
// eldrin-integration/src/descriptor/validate.ts
import { DescriptorError, NotImplementedError } from '../errors';
import type { IntegrationDescriptor, ResourceDescriptor } from './index';

const IMPLEMENTED_TRANSPORTS = new Set(['http']);
const IMPLEMENTED_AUTH = new Set(['apiKey']);
const IMPLEMENTED_MODES = new Set(['stored']);
const IMPLEMENTED_METHODS = new Set(['GET']);
const IMPLEMENTED_PAGINATION = new Set(['none', 'cursor', undefined]);

export function validateDescriptor(d: IntegrationDescriptor): void {
  if (!d.id || d.id.trim().length === 0) {
    throw new DescriptorError('Integration id is required');
  }
  if (!d.connection) throw new DescriptorError('connection is required');
  if (!IMPLEMENTED_TRANSPORTS.has(d.connection.transport)) {
    throw new NotImplementedError(`transport:${d.connection.transport}`);
  }
  if (!IMPLEMENTED_AUTH.has(d.connection.auth?.strategy)) {
    throw new NotImplementedError(`auth:${d.connection.auth?.strategy}`);
  }
  if (!Array.isArray(d.resources) || d.resources.length === 0) {
    throw new DescriptorError('At least one resource is required');
  }
  const seen = new Set<string>();
  for (const r of d.resources) {
    validateResource(r, seen);
  }
}

function validateResource(r: ResourceDescriptor, seen: Set<string>): void {
  if (!r.name) throw new DescriptorError('Resource name is required');
  if (seen.has(r.name)) throw new DescriptorError(`Duplicate resource name: ${r.name}`);
  seen.add(r.name);

  if (!r.idField) throw new DescriptorError(`Resource ${r.name} requires idField`);
  if (!r.fieldMap || Object.keys(r.fieldMap).length === 0) {
    throw new DescriptorError(`Resource ${r.name} requires a non-empty fieldMap`);
  }
  if (!r.supportedModes?.length) {
    throw new DescriptorError(`Resource ${r.name} requires supportedModes`);
  }
  if (!r.supportedModes.includes(r.defaultMode)) {
    throw new DescriptorError(
      `Resource ${r.name}: defaultMode '${r.defaultMode}' not in supportedModes`,
    );
  }
  for (const mode of r.supportedModes) {
    if (!IMPLEMENTED_MODES.has(mode)) throw new NotImplementedError(`mode:${mode}`);
  }
  if (!IMPLEMENTED_METHODS.has(r.transport.method)) {
    throw new NotImplementedError(`http:${r.transport.method}`);
  }
  if (!IMPLEMENTED_PAGINATION.has(r.transport.pagination)) {
    throw new NotImplementedError(`pagination:${r.transport.pagination}`);
  }
}
```

Modify `src/descriptor/index.ts` — import and call validation before freezing:
```ts
import { validateDescriptor } from './validate';
// ...
export function defineIntegration(descriptor: IntegrationDescriptor): IntegrationDescriptor {
  validateDescriptor(descriptor);
  return deepFreeze(descriptor);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/descriptor`
Expected: PASS (validate: 8 tests, index: 2 tests).

- [ ] **Step 5: Export and commit**

Add to `src/index.ts`: `export { validateDescriptor } from './descriptor/validate';`

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-integration add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-integration commit -q -m "feat: add descriptor validation with NotImplemented gating"
```

---

### Task 5: Auth strategies (apiKey implemented; bearer/oauth2 stubbed)

**Files:**
- Create: `eldrin-integration/src/auth/index.ts`
- Create: `eldrin-integration/src/auth/api-key.ts`
- Create: `eldrin-integration/src/auth/bearer.ts`
- Create: `eldrin-integration/src/auth/oauth2.ts`
- Test: `eldrin-integration/src/auth/api-key.test.ts`
- Test: `eldrin-integration/src/auth/stubs.test.ts`

**Interfaces:**
- Consumes: `AuthConfig`, `SettingRef` (Task 3); `NotImplementedError` (Task 2); app-core `AppSettings` (`getAppSettings`).
- Produces:
  - `interface AuthStrategy { apply(request: { headers: Record<string,string>; url: string }): Promise<{ headers: Record<string,string>; url: string }> }`
  - `function createAuthStrategy(auth: AuthConfig, settings: SettingsLookup): AuthStrategy` — returns apiKey impl; throws `NotImplementedError` for bearer/oauth2.
  - `type SettingsLookup = (ref: SettingRef) => string | undefined` — resolves a `{setting}` or `{secret}` ref to a value.

- [ ] **Step 1: Write the failing tests**

```ts
// eldrin-integration/src/auth/api-key.test.ts
import { describe, it, expect } from 'vitest';
import { createAuthStrategy } from './index';
import type { SettingsLookup } from './index';

const lookup: SettingsLookup = (ref) =>
  'setting' in ref ? { 'ACME.BASE': 'https://x' }[ref.setting] : { 'ACME.KEY': 'secret-123' }[ref.secret];

describe('apiKey auth strategy', () => {
  it('injects the key as a header', async () => {
    const s = createAuthStrategy(
      { strategy: 'apiKey', header: 'x-api-key', key: { secret: 'ACME.KEY' } },
      lookup,
    );
    const out = await s.apply({ headers: {}, url: 'https://x/clients' });
    expect(out.headers['x-api-key']).toBe('secret-123');
    expect(out.url).toBe('https://x/clients');
  });

  it('injects the key as a query param when queryParam is set', async () => {
    const s = createAuthStrategy(
      { strategy: 'apiKey', queryParam: 'api_key', key: { secret: 'ACME.KEY' } },
      lookup,
    );
    const out = await s.apply({ headers: {}, url: 'https://x/clients' });
    expect(out.url).toContain('api_key=secret-123');
  });

  it('throws when key resolves to undefined', async () => {
    const s = createAuthStrategy(
      { strategy: 'apiKey', header: 'x-api-key', key: { secret: 'MISSING' } },
      lookup,
    );
    await expect(s.apply({ headers: {}, url: 'https://x' })).rejects.toThrow();
  });
});
```

```ts
// eldrin-integration/src/auth/stubs.test.ts
import { describe, it, expect } from 'vitest';
import { createAuthStrategy } from './index';
import { NotImplementedError } from '../errors';

const lookup = () => 'x';

describe('scaffolded auth strategies throw NotImplemented', () => {
  it('bearer', () => {
    expect(() => createAuthStrategy({ strategy: 'bearer', token: { secret: 'T' } }, lookup))
      .toThrow(NotImplementedError);
  });
  it('oauth2-client-credentials', () => {
    expect(() => createAuthStrategy({ strategy: 'oauth2-client-credentials' }, lookup))
      .toThrow(NotImplementedError);
  });
  it('oauth2-auth-code', () => {
    expect(() => createAuthStrategy({ strategy: 'oauth2-auth-code' }, lookup))
      .toThrow(NotImplementedError);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/auth`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementations**

```ts
// eldrin-integration/src/auth/index.ts
import type { AuthConfig, SettingRef } from '../descriptor';
import { NotImplementedError } from '../errors';
import { createApiKeyStrategy } from './api-key';

export type SettingsLookup = (ref: SettingRef) => string | undefined;

export interface AuthRequest {
  headers: Record<string, string>;
  url: string;
}

export interface AuthStrategy {
  apply(request: AuthRequest): Promise<AuthRequest>;
}

export function createAuthStrategy(auth: AuthConfig, lookup: SettingsLookup): AuthStrategy {
  switch (auth.strategy) {
    case 'apiKey':
      return createApiKeyStrategy(auth, lookup);
    case 'bearer':
    case 'oauth2-client-credentials':
    case 'oauth2-auth-code':
      throw new NotImplementedError(`auth:${auth.strategy}`);
    default:
      throw new NotImplementedError(`auth:${String(auth.strategy)}`);
  }
}
```

```ts
// eldrin-integration/src/auth/api-key.ts
import type { AuthConfig } from '../descriptor';
import { IntegrationError } from '../errors';
import type { AuthStrategy, SettingsLookup } from './index';

export function createApiKeyStrategy(auth: AuthConfig, lookup: SettingsLookup): AuthStrategy {
  return {
    async apply(request) {
      if (!auth.key) throw new IntegrationError('apiKey auth requires a key ref', 400);
      const value = lookup(auth.key);
      if (!value) throw new IntegrationError('apiKey credential not configured', 400);

      if (auth.queryParam) {
        const sep = request.url.includes('?') ? '&' : '?';
        const url = `${request.url}${sep}${encodeURIComponent(auth.queryParam)}=${encodeURIComponent(value)}`;
        return { headers: { ...request.headers }, url };
      }
      const header = auth.header ?? 'Authorization';
      return { headers: { ...request.headers, [header]: value }, url: request.url };
    },
  };
}
```

```ts
// eldrin-integration/src/auth/bearer.ts
import { NotImplementedError } from '../errors';
// Scaffolded: implement when an integration needs bearer-token auth.
export function createBearerStrategy(): never {
  throw new NotImplementedError('auth:bearer');
}
```

```ts
// eldrin-integration/src/auth/oauth2.ts
import { NotImplementedError } from '../errors';
// Scaffolded: implement client-credentials / auth-code when an integration needs them.
export function createOAuth2ClientCredentialsStrategy(): never {
  throw new NotImplementedError('auth:oauth2-client-credentials');
}
export function createOAuth2AuthCodeStrategy(): never {
  throw new NotImplementedError('auth:oauth2-auth-code');
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/auth`
Expected: PASS (api-key: 3, stubs: 3).

- [ ] **Step 5: Export and commit**

Add to `src/index.ts`:
```ts
export { createAuthStrategy } from './auth';
export type { AuthStrategy, AuthRequest, SettingsLookup } from './auth';
```

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-integration add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-integration commit -q -m "feat: add auth strategies (apiKey impl, bearer/oauth2 scaffolded)"
```

---

### Task 6: HTTP transport (GET + cursor pagination + retry)

**Files:**
- Create: `eldrin-integration/src/transport/index.ts`
- Create: `eldrin-integration/src/transport/http.ts`
- Create: `eldrin-integration/src/transport/graphql.ts`
- Create: `eldrin-integration/src/transport/file.ts`
- Test: `eldrin-integration/src/transport/http.test.ts`
- Test: `eldrin-integration/src/transport/stubs.test.ts`

**Interfaces:**
- Consumes: `ConnectionConfig`, `HttpResourceTransport`, `ResourceDescriptor` (Task 3); `AuthStrategy` (Task 5); `NotImplementedError`, `IntegrationError` (Task 2).
- Produces:
  - `interface Transport { fetchAll(resource: ResourceDescriptor): Promise<Record<string, unknown>[]> }`
  - `function createTransport(connection: ConnectionConfig, auth: AuthStrategy, baseUrl: string, fetchImpl?: typeof fetch): Transport` — returns HTTP impl for `transport: 'http'`; throws `NotImplementedError` for graphql/file.
  - HTTP impl: builds `${baseUrl}${resource.transport.path}`, applies auth, GETs JSON. For `pagination: 'cursor'`, expects `{ data: T[], meta?: { has_next_page?: boolean; end_cursor?: string } }` and follows `after_id=<end_cursor>` until `has_next_page` is false (factorial's validated shape). For `pagination: 'none'`/undefined, returns `data` array or the raw array. Retries per `connection.retry` with exponential/fixed backoff (no real delay in tests — backoff base is injected; default 0 in tests via `fetchImpl`).

- [ ] **Step 1: Write the failing tests**

```ts
// eldrin-integration/src/transport/http.test.ts
import { describe, it, expect } from 'vitest';
import { createTransport } from './index';
import type { ConnectionConfig, ResourceDescriptor } from '../descriptor';
import type { AuthStrategy } from '../auth';

const passthroughAuth: AuthStrategy = { apply: async (r) => r };
const conn: ConnectionConfig = {
  transport: 'http',
  baseUrl: 'https://api.test',
  auth: { strategy: 'apiKey', header: 'x-api-key', key: { secret: 'K' } },
};

function resource(pagination: 'none' | 'cursor'): ResourceDescriptor {
  return {
    name: 'clients', transport: { method: 'GET', path: '/clients', pagination },
    idField: 'id', fieldMap: { id: 'remoteId' }, supportedModes: ['stored'], defaultMode: 'stored',
  };
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
}

describe('http transport', () => {
  it('fetches a single non-paginated page (data array)', async () => {
    const fetchImpl = async () => jsonResponse({ data: [{ id: 1 }, { id: 2 }] });
    const t = createTransport(conn, passthroughAuth, 'https://api.test', fetchImpl as typeof fetch);
    const rows = await t.fetchAll(resource('none'));
    expect(rows).toHaveLength(2);
    expect(rows[0]).toEqual({ id: 1 });
  });

  it('follows cursor pagination via meta.end_cursor', async () => {
    let call = 0;
    const fetchImpl = async (url: string | URL | Request) => {
      call++;
      const u = String(url);
      if (call === 1) {
        expect(u).toContain('/clients');
        return jsonResponse({ data: [{ id: 1 }], meta: { has_next_page: true, end_cursor: 'C1' } });
      }
      expect(u).toContain('after_id=C1');
      return jsonResponse({ data: [{ id: 2 }], meta: { has_next_page: false } });
    };
    const t = createTransport(conn, passthroughAuth, 'https://api.test', fetchImpl as unknown as typeof fetch);
    const rows = await t.fetchAll(resource('cursor'));
    expect(rows.map((r) => (r as { id: number }).id)).toEqual([1, 2]);
    expect(call).toBe(2);
  });

  it('retries on failure then throws after attempts exhausted', async () => {
    let call = 0;
    const fetchImpl = async () => { call++; return new Response('err', { status: 500 }); };
    const connRetry: ConnectionConfig = { ...conn, retry: { attempts: 3, backoff: 'fixed' } };
    const t = createTransport(connRetry, passthroughAuth, 'https://api.test', fetchImpl as typeof fetch);
    await expect(t.fetchAll(resource('none'))).rejects.toThrow();
    expect(call).toBe(3);
  });
});
```

```ts
// eldrin-integration/src/transport/stubs.test.ts
import { describe, it, expect } from 'vitest';
import { createTransport } from './index';
import type { ConnectionConfig } from '../descriptor';
import type { AuthStrategy } from '../auth';
import { NotImplementedError } from '../errors';

const auth: AuthStrategy = { apply: async (r) => r };

describe('scaffolded transports throw NotImplemented', () => {
  it('graphql', () => {
    const conn = { transport: 'graphql', baseUrl: 'x', auth: { strategy: 'apiKey' } } as unknown as ConnectionConfig;
    expect(() => createTransport(conn, auth, 'x')).toThrow(NotImplementedError);
  });
  it('file', () => {
    const conn = { transport: 'file', baseUrl: 'x', auth: { strategy: 'apiKey' } } as unknown as ConnectionConfig;
    expect(() => createTransport(conn, auth, 'x')).toThrow(NotImplementedError);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/transport`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementations**

```ts
// eldrin-integration/src/transport/index.ts
import type { ConnectionConfig, ResourceDescriptor } from '../descriptor';
import type { AuthStrategy } from '../auth';
import { NotImplementedError } from '../errors';
import { createHttpTransport } from './http';

export interface Transport {
  fetchAll(resource: ResourceDescriptor): Promise<Record<string, unknown>[]>;
}

export function createTransport(
  connection: ConnectionConfig,
  auth: AuthStrategy,
  baseUrl: string,
  fetchImpl: typeof fetch = fetch,
): Transport {
  switch (connection.transport) {
    case 'http':
      return createHttpTransport(connection, auth, baseUrl, fetchImpl);
    case 'graphql':
      throw new NotImplementedError('transport:graphql');
    case 'file':
      throw new NotImplementedError('transport:file');
    default:
      throw new NotImplementedError(`transport:${String(connection.transport)}`);
  }
}
```

```ts
// eldrin-integration/src/transport/http.ts
import type { ConnectionConfig, ResourceDescriptor } from '../descriptor';
import type { AuthStrategy } from '../auth';
import type { Transport } from './index';
import { IntegrationError } from '../errors';

interface Paged<T> {
  data: T[];
  meta?: { has_next_page?: boolean; end_cursor?: string };
}

export function createHttpTransport(
  connection: ConnectionConfig,
  auth: AuthStrategy,
  baseUrl: string,
  fetchImpl: typeof fetch,
): Transport {
  const base = baseUrl.replace(/\/$/, '');
  const attempts = connection.retry?.attempts ?? 1;

  async function getOnce(url: string): Promise<unknown> {
    const authed = await auth.apply({ headers: { Accept: 'application/json' }, url });
    const res = await fetchImpl(authed.url, { headers: authed.headers });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new IntegrationError(`GET ${url} failed: ${res.status} ${body}`, res.status);
    }
    return res.json();
  }

  async function getWithRetry(url: string): Promise<unknown> {
    let lastErr: unknown;
    for (let i = 0; i < attempts; i++) {
      try {
        return await getOnce(url);
      } catch (e) {
        lastErr = e;
      }
    }
    throw lastErr;
  }

  function extractArray(body: unknown): Record<string, unknown>[] {
    if (Array.isArray(body)) return body as Record<string, unknown>[];
    const data = (body as Paged<Record<string, unknown>>)?.data;
    return Array.isArray(data) ? data : [];
  }

  return {
    async fetchAll(resource: ResourceDescriptor) {
      const path = resource.transport.path;
      if (resource.transport.pagination === 'cursor') {
        const out: Record<string, unknown>[] = [];
        let afterId: string | undefined;
        for (;;) {
          const sep = path.includes('?') ? '&' : '?';
          const pagePath = afterId
            ? `${path}${sep}after_id=${encodeURIComponent(afterId)}`
            : path;
          const body = (await getWithRetry(`${base}${pagePath}`)) as Paged<Record<string, unknown>>;
          out.push(...extractArray(body));
          if (!body?.meta?.has_next_page || !body?.meta?.end_cursor) break;
          afterId = body.meta.end_cursor;
        }
        return out;
      }
      const body = await getWithRetry(`${base}${path}`);
      return extractArray(body);
    },
  };
}
```

```ts
// eldrin-integration/src/transport/graphql.ts
import { NotImplementedError } from '../errors';
// Scaffolded: implement GraphQL transport when an integration needs it.
export function createGraphqlTransport(): never {
  throw new NotImplementedError('transport:graphql');
}
```

```ts
// eldrin-integration/src/transport/file.ts
import { NotImplementedError } from '../errors';
// Scaffolded: implement R2/S3 file transport when an integration needs it.
export function createFileTransport(): never {
  throw new NotImplementedError('transport:file');
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/transport`
Expected: PASS (http: 3, stubs: 2).

- [ ] **Step 5: Export and commit**

Add to `src/index.ts`:
```ts
export { createTransport } from './transport';
export type { Transport } from './transport';
```

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-integration add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-integration commit -q -m "feat: add HTTP transport with cursor pagination and retry"
```

---

### Task 7: SDK-managed table SQL

**Files:**
- Create: `eldrin-integration/src/schema/tables.ts`
- Test: `eldrin-integration/src/schema/tables.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `const SYNC_STATE_DDL: string` — `CREATE TABLE IF NOT EXISTS _integration_sync_state (resource TEXT PRIMARY KEY, last_synced_at INTEGER, last_status TEXT, last_error TEXT, cursor TEXT)`.
  - `const INTEGRATION_CONFIG_DDL: string` — `CREATE TABLE IF NOT EXISTS _integration_config (resource TEXT PRIMARY KEY, mode TEXT, schedule TEXT, cache_ttl_seconds INTEGER, webhook_enabled INTEGER)`.
  - `const WEBHOOK_DELIVERIES_DDL: string` — `CREATE TABLE IF NOT EXISTS _integration_webhook_deliveries (delivery_id TEXT PRIMARY KEY, resource TEXT, received_at INTEGER)`.
  - `function storedResourceDDL(tableName: string, columns: string[]): string` — `CREATE TABLE IF NOT EXISTS <tableName> (id TEXT PRIMARY KEY, remote_id TEXT NOT NULL, <columns...>, raw_json TEXT, synced_at INTEGER NOT NULL)` plus a unique index on `remote_id`. Returns the full statement(s) joined by `;`.
  - `const SDK_TABLES: string[]` — `[SYNC_STATE_DDL, INTEGRATION_CONFIG_DDL, WEBHOOK_DELIVERIES_DDL]`.

- [ ] **Step 1: Write the failing test**

```ts
// eldrin-integration/src/schema/tables.test.ts
import { describe, it, expect } from 'vitest';
import { SYNC_STATE_DDL, INTEGRATION_CONFIG_DDL, WEBHOOK_DELIVERIES_DDL, storedResourceDDL, SDK_TABLES } from './tables';

describe('schema tables', () => {
  it('sync_state DDL is idempotent and keyed by resource', () => {
    expect(SYNC_STATE_DDL).toContain('CREATE TABLE IF NOT EXISTS _integration_sync_state');
    expect(SYNC_STATE_DDL).toContain('resource TEXT PRIMARY KEY');
  });

  it('config and webhook DDLs exist', () => {
    expect(INTEGRATION_CONFIG_DDL).toContain('_integration_config');
    expect(WEBHOOK_DELIVERIES_DDL).toContain('_integration_webhook_deliveries');
  });

  it('storedResourceDDL builds a table with remote_id, raw_json, synced_at and a unique index', () => {
    const ddl = storedResourceDDL('clients', ['name TEXT', 'email TEXT']);
    expect(ddl).toContain('CREATE TABLE IF NOT EXISTS clients');
    expect(ddl).toContain('remote_id TEXT NOT NULL');
    expect(ddl).toContain('name TEXT');
    expect(ddl).toContain('raw_json TEXT');
    expect(ddl).toContain('synced_at INTEGER NOT NULL');
    expect(ddl).toContain('CREATE UNIQUE INDEX IF NOT EXISTS');
  });

  it('SDK_TABLES contains the three management tables', () => {
    expect(SDK_TABLES).toHaveLength(3);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/schema/tables.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

```ts
// eldrin-integration/src/schema/tables.ts
export const SYNC_STATE_DDL =
  `CREATE TABLE IF NOT EXISTS _integration_sync_state (` +
  `resource TEXT PRIMARY KEY, last_synced_at INTEGER, last_status TEXT, ` +
  `last_error TEXT, cursor TEXT)`;

export const INTEGRATION_CONFIG_DDL =
  `CREATE TABLE IF NOT EXISTS _integration_config (` +
  `resource TEXT PRIMARY KEY, mode TEXT, schedule TEXT, ` +
  `cache_ttl_seconds INTEGER, webhook_enabled INTEGER)`;

export const WEBHOOK_DELIVERIES_DDL =
  `CREATE TABLE IF NOT EXISTS _integration_webhook_deliveries (` +
  `delivery_id TEXT PRIMARY KEY, resource TEXT, received_at INTEGER)`;

export const SDK_TABLES: string[] = [
  SYNC_STATE_DDL,
  INTEGRATION_CONFIG_DDL,
  WEBHOOK_DELIVERIES_DDL,
];

export function storedResourceDDL(tableName: string, columns: string[]): string {
  const cols = columns.length ? `, ${columns.join(', ')}` : '';
  const table =
    `CREATE TABLE IF NOT EXISTS ${tableName} (` +
    `id TEXT PRIMARY KEY, remote_id TEXT NOT NULL${cols}, ` +
    `raw_json TEXT, synced_at INTEGER NOT NULL)`;
  const index =
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_${tableName}_remote_id ` +
    `ON ${tableName} (remote_id)`;
  return `${table}; ${index}`;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/schema/tables.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Export and commit**

Add to `src/index.ts`:
```ts
export { SYNC_STATE_DDL, INTEGRATION_CONFIG_DDL, WEBHOOK_DELIVERIES_DDL, SDK_TABLES, storedResourceDDL } from './schema/tables';
```

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-integration add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-integration commit -q -m "feat: add SDK-managed table DDL helpers"
```

---

### Task 8: sync_state read/write

**Files:**
- Create: `eldrin-integration/src/sync/sync-state.ts`
- Test: `eldrin-integration/src/sync/sync-state.test.ts`

**Interfaces:**
- Consumes: app-core `DatabaseAdapter` (`createSQLiteAdapter` from `@eldrin-project/eldrin-app-core/database/sqlite` for tests); `SYNC_STATE_DDL` (Task 7).
- Produces:
  - `interface SyncStateRow { resource: string; lastSyncedAt: number | null; lastStatus: string | null; lastError: string | null; cursor: string | null }`
  - `async function readSyncState(db: DatabaseAdapter, resource: string): Promise<SyncStateRow | null>`
  - `async function writeSyncState(db: DatabaseAdapter, row: SyncStateRow): Promise<void>` — upsert keyed on `resource`.

  **Note on the test DB:** use app-core's SQLite adapter. The import path is `@eldrin-project/eldrin-app-core/database/sqlite` and the factory is `createSQLiteAdapter`. The adapter exposes `prepare(sql).bind(...).all()/first()/run()` and `exec(sql)` per the `DatabaseAdapter` interface. Before each test, create the adapter with an in-memory DB and run `SYNC_STATE_DDL`. If `createSQLiteAdapter` requires `bun:sqlite` and the test runner is node (not bun), fall back to `better-sqlite3`-backed adapter — verify which the project ships by checking `eldrin-app-core/src/database/sqlite-node.ts` exports during Step 1, and import the node variant (`createNodeSQLiteAdapter` or equivalent) used by app-core's own `sqlite-node.test.ts`.

- [ ] **Step 1: Inspect the app-core SQLite test adapter to use the exact same import**

Run:
```bash
sed -n '1,40p' /Users/tibor/projects/eldrin-backup/eldrin-app-core/src/database/sqlite-node.test.ts
```
Expected: shows the exact import + constructor used by app-core's own tests (e.g. `createNodeSQLiteAdapter()` from `./sqlite-node`). Use the **same** adapter and import style in this test. If it imports from a relative path inside app-core, the published equivalent is `@eldrin-project/eldrin-app-core/database/sqlite` — but for a node test prefer whatever app-core's own node test imports, adding a devDependency on `better-sqlite3` to `eldrin-integration/package.json` if app-core's node adapter needs it.

- [ ] **Step 2: Write the failing test**

```ts
// eldrin-integration/src/sync/sync-state.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';
import { SYNC_STATE_DDL } from '../schema/tables';
import { readSyncState, writeSyncState } from './sync-state';
import { makeTestDb } from '../test-helpers';

let db: DatabaseAdapter;
beforeEach(async () => {
  db = await makeTestDb([SYNC_STATE_DDL]);
});

describe('sync-state', () => {
  it('returns null when no row exists', async () => {
    expect(await readSyncState(db, 'clients')).toBeNull();
  });

  it('writes then reads a row', async () => {
    await writeSyncState(db, {
      resource: 'clients', lastSyncedAt: 100, lastStatus: 'ok', lastError: null, cursor: null,
    });
    const row = await readSyncState(db, 'clients');
    expect(row).toMatchObject({ resource: 'clients', lastSyncedAt: 100, lastStatus: 'ok' });
  });

  it('upserts on the same resource', async () => {
    await writeSyncState(db, { resource: 'clients', lastSyncedAt: 1, lastStatus: 'ok', lastError: null, cursor: null });
    await writeSyncState(db, { resource: 'clients', lastSyncedAt: 2, lastStatus: 'error', lastError: 'x', cursor: null });
    const row = await readSyncState(db, 'clients');
    expect(row?.lastSyncedAt).toBe(2);
    expect(row?.lastStatus).toBe('error');
  });
});
```

- [ ] **Step 3: Create the shared test helper**

```ts
// eldrin-integration/src/test-helpers.ts
// Test-only helper: builds an in-memory DatabaseAdapter and applies DDL.
// Uses the SAME node SQLite adapter that eldrin-app-core's own tests use
// (confirmed in Task 8 Step 1). Replace the import below to match.
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';
import { createNodeSQLiteAdapter } from '@eldrin-project/eldrin-app-core/database/sqlite';

export async function makeTestDb(ddl: string[]): Promise<DatabaseAdapter> {
  const db = createNodeSQLiteAdapter(':memory:');
  for (const statement of ddl) {
    for (const part of statement.split(';').map((s) => s.trim()).filter(Boolean)) {
      await db.prepare(part).run();
    }
  }
  return db;
}
```

> If Step 1 reveals a different adapter factory/signature (e.g. the node adapter is not exported from `/database/sqlite` but from `/node`, or is named differently), update this import and the `:memory:` argument accordingly, and add the matching devDependency. The helper's contract (`makeTestDb(ddl) → DatabaseAdapter`) stays the same so later tasks are unaffected.

- [ ] **Step 4: Run test to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/sync/sync-state.test.ts`
Expected: FAIL — `./sync-state` not found (helper now resolves).

- [ ] **Step 5: Write the implementation**

```ts
// eldrin-integration/src/sync/sync-state.ts
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';

export interface SyncStateRow {
  resource: string;
  lastSyncedAt: number | null;
  lastStatus: string | null;
  lastError: string | null;
  cursor: string | null;
}

interface RawRow {
  resource: string;
  last_synced_at: number | null;
  last_status: string | null;
  last_error: string | null;
  cursor: string | null;
}

export async function readSyncState(
  db: DatabaseAdapter,
  resource: string,
): Promise<SyncStateRow | null> {
  const row = await db
    .prepare('SELECT * FROM _integration_sync_state WHERE resource = ?')
    .bind(resource)
    .first<RawRow>();
  if (!row) return null;
  return {
    resource: row.resource,
    lastSyncedAt: row.last_synced_at,
    lastStatus: row.last_status,
    lastError: row.last_error,
    cursor: row.cursor,
  };
}

export async function writeSyncState(db: DatabaseAdapter, row: SyncStateRow): Promise<void> {
  await db
    .prepare(
      `INSERT INTO _integration_sync_state (resource, last_synced_at, last_status, last_error, cursor)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(resource) DO UPDATE SET
         last_synced_at = excluded.last_synced_at,
         last_status = excluded.last_status,
         last_error = excluded.last_error,
         cursor = excluded.cursor`,
    )
    .bind(row.resource, row.lastSyncedAt, row.lastStatus, row.lastError, row.cursor)
    .run();
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/sync/sync-state.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 7: Add `test-helpers.ts` to tsup/coverage excludes, export, commit**

Edit `vitest.config.ts` coverage exclude to add `'src/test-helpers.ts'`. Add to `src/index.ts`:
```ts
export { readSyncState, writeSyncState, type SyncStateRow } from './sync/sync-state';
```

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-integration add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-integration commit -q -m "feat: add sync_state read/write over DatabaseAdapter"
```

---

### Task 9: Generic sync runner

**Files:**
- Create: `eldrin-integration/src/sync/index.ts`
- Test: `eldrin-integration/src/sync/index.test.ts`

**Interfaces:**
- Consumes: `DatabaseAdapter`, `ResourceDescriptor`, `IntegrationDescriptor` (Task 3), `Transport` (Task 6), `writeSyncState` (Task 8), `storedResourceDDL` (Task 7).
- Produces:
  - `interface SyncDeps { db: DatabaseAdapter; transport: Transport; now: () => number; genId: () => string }`
  - `async function runResourceSync(resource: ResourceDescriptor, deps: SyncDeps): Promise<{ resource: string; count: number }>` — fetches via transport, maps each raw row through `fieldMap` (remote key → local snake_case column), applies `hooks.transform`/`hooks.beforeUpsert` if present, upserts into the resource's table (table name = `resource.name`) keyed on `remote_id`, sets `raw_json` + `synced_at`, then writes sync_state (`ok`, or `error` + rethrow on failure).
  - `async function runAllSync(descriptor: IntegrationDescriptor, deps: SyncDeps): Promise<{ resource: string; count: number }[]>` — runs each `stored`-mode resource.
  - The local column name for a `fieldMap` value is used verbatim (the descriptor author supplies snake_case column names matching the table DDL). `idField`'s mapped column is always `remote_id` regardless of fieldMap (the runner maps `raw[idField] → remote_id`).

- [ ] **Step 1: Write the failing test**

```ts
// eldrin-integration/src/sync/index.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';
import { runResourceSync } from './index';
import type { Transport } from '../transport';
import type { ResourceDescriptor } from '../descriptor';
import { storedResourceDDL, SYNC_STATE_DDL } from '../schema/tables';
import { readSyncState } from './sync-state';
import { makeTestDb } from '../test-helpers';

const resource: ResourceDescriptor = {
  name: 'clients',
  transport: { method: 'GET', path: '/clients', pagination: 'cursor' },
  idField: 'id',
  fieldMap: { id: 'remote_id', name: 'name', email: 'email' },
  supportedModes: ['stored'],
  defaultMode: 'stored',
};

function fakeTransport(rows: Record<string, unknown>[]): Transport {
  return { fetchAll: async () => rows };
}

let db: DatabaseAdapter;
let counter = 0;
const deps = (t: Transport) => ({ db, transport: t, now: () => 1000, genId: () => `id-${++counter}` });

beforeEach(async () => {
  counter = 0;
  db = await makeTestDb([SYNC_STATE_DDL, storedResourceDDL('clients', ['name TEXT', 'email TEXT'])]);
});

describe('runResourceSync', () => {
  it('upserts mapped rows and reports a count', async () => {
    const t = fakeTransport([
      { id: 10, name: 'Ada', email: 'ada@x.io' },
      { id: 11, name: 'Grace', email: 'grace@x.io' },
    ]);
    const result = await runResourceSync(resource, deps(t));
    expect(result).toEqual({ resource: 'clients', count: 2 });

    const stored = await db.prepare('SELECT remote_id, name, email, raw_json, synced_at FROM clients ORDER BY remote_id').all();
    expect(stored.results).toHaveLength(2);
    expect(stored.results[0]).toMatchObject({ remote_id: '10', name: 'Ada', email: 'ada@x.io', synced_at: 1000 });
    expect(typeof (stored.results[0] as { raw_json: string }).raw_json).toBe('string');
  });

  it('is idempotent on re-sync (upsert by remote_id)', async () => {
    const t = fakeTransport([{ id: 10, name: 'Ada', email: 'ada@x.io' }]);
    await runResourceSync(resource, deps(t));
    await runResourceSync(resource, deps(fakeTransport([{ id: 10, name: 'Ada Lovelace', email: 'ada@x.io' }])));
    const stored = await db.prepare('SELECT name FROM clients WHERE remote_id = ?').bind('10').all();
    expect(stored.results).toHaveLength(1);
    expect((stored.results[0] as { name: string }).name).toBe('Ada Lovelace');
  });

  it('records ok sync state', async () => {
    await runResourceSync(resource, deps(fakeTransport([{ id: 1, name: 'X', email: 'x@x.io' }])));
    const state = await readSyncState(db, 'clients');
    expect(state?.lastStatus).toBe('ok');
    expect(state?.lastSyncedAt).toBe(1000);
  });

  it('records error sync state and rethrows on transport failure', async () => {
    const failing: Transport = { fetchAll: async () => { throw new Error('api down'); } };
    await expect(runResourceSync(resource, deps(failing))).rejects.toThrow('api down');
    const state = await readSyncState(db, 'clients');
    expect(state?.lastStatus).toBe('error');
    expect(state?.lastError).toContain('api down');
  });

  it('applies beforeUpsert hook', async () => {
    const withHook: ResourceDescriptor = {
      ...resource,
      hooks: { beforeUpsert: (mapped) => ({ ...mapped, name: String(mapped.name).toUpperCase() }) },
    };
    await runResourceSync(withHook, deps(fakeTransport([{ id: 5, name: 'ada', email: 'a@x.io' }])));
    const row = await db.prepare('SELECT name FROM clients WHERE remote_id = ?').bind('5').first<{ name: string }>();
    expect(row?.name).toBe('ADA');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/sync/index.test.ts`
Expected: FAIL — `./index` runner not found.

- [ ] **Step 3: Write the implementation**

```ts
// eldrin-integration/src/sync/index.ts
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';
import type { IntegrationDescriptor, ResourceDescriptor } from '../descriptor';
import type { Transport } from '../transport';
import { writeSyncState } from './sync-state';

export interface SyncDeps {
  db: DatabaseAdapter;
  transport: Transport;
  now: () => number;
  genId: () => string;
}

export interface SyncResult {
  resource: string;
  count: number;
}

function mapRow(resource: ResourceDescriptor, raw: Record<string, unknown>): Record<string, unknown> {
  const transformed = resource.hooks?.transform ? resource.hooks.transform(raw) : raw;
  const mapped: Record<string, unknown> = {};
  for (const [remoteKey, localCol] of Object.entries(resource.fieldMap)) {
    if (remoteKey === resource.idField) continue; // id handled as remote_id
    const value = transformed[remoteKey];
    mapped[localCol] = value === undefined ? null : value;
  }
  return resource.hooks?.beforeUpsert ? resource.hooks.beforeUpsert(mapped, raw) : mapped;
}

export async function runResourceSync(
  resource: ResourceDescriptor,
  deps: SyncDeps,
): Promise<SyncResult> {
  const ts = deps.now();
  try {
    const rows = await deps.transport.fetchAll(resource);
    for (const raw of rows) {
      const remoteId = String(raw[resource.idField]);
      const mapped = mapRow(resource, raw);
      const cols = Object.keys(mapped);
      const allCols = ['id', 'remote_id', ...cols, 'raw_json', 'synced_at'];
      const placeholders = allCols.map(() => '?').join(', ');
      const updates = [...cols, 'raw_json', 'synced_at']
        .map((c) => `${c} = excluded.${c}`)
        .join(', ');
      const values = [
        deps.genId(),
        remoteId,
        ...cols.map((c) => mapped[c]),
        JSON.stringify(raw),
        ts,
      ];
      await deps.db
        .prepare(
          `INSERT INTO ${resource.name} (${allCols.join(', ')}) VALUES (${placeholders})
           ON CONFLICT(remote_id) DO UPDATE SET ${updates}`,
        )
        .bind(...values)
        .run();
    }
    await writeSyncState(deps.db, {
      resource: resource.name,
      lastSyncedAt: ts,
      lastStatus: 'ok',
      lastError: null,
      cursor: null,
    });
    return { resource: resource.name, count: rows.length };
  } catch (e) {
    await writeSyncState(deps.db, {
      resource: resource.name,
      lastSyncedAt: ts,
      lastStatus: 'error',
      lastError: e instanceof Error ? e.message : String(e),
      cursor: null,
    });
    throw e;
  }
}

export async function runAllSync(
  descriptor: IntegrationDescriptor,
  deps: SyncDeps,
): Promise<SyncResult[]> {
  const results: SyncResult[] = [];
  for (const resource of descriptor.resources) {
    if (resource.defaultMode === 'stored' && resource.supportedModes.includes('stored')) {
      results.push(await runResourceSync(resource, deps));
    }
  }
  return results;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/sync/index.test.ts`
Expected: PASS (5 tests).

- [ ] **Step 5: Export and commit**

Add to `src/index.ts`:
```ts
export { runResourceSync, runAllSync, type SyncDeps, type SyncResult } from './sync';
```

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-integration add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-integration commit -q -m "feat: add generic sync runner"
```

---

### Task 10: Storage-mode engine (stored impl; live/cached stub)

**Files:**
- Create: `eldrin-integration/src/storage/mode.ts`
- Test: `eldrin-integration/src/storage/mode.test.ts`

**Interfaces:**
- Consumes: `StorageMode`, `ResourceDescriptor` (Task 3); `NotImplementedError` (Task 2); `DatabaseAdapter` + `integration_config` (Task 11 provides the config reader — to avoid a forward dependency, `resolveActiveMode` takes the resolved mode string directly here, and Task 11/12 wire config in).
- Produces:
  - `function assertModeImplemented(mode: StorageMode): void` — throws `NotImplementedError('mode:live'|'mode:cached')` for non-stored.
  - `function effectiveMode(supportedModes: StorageMode[], configuredMode: string | null, defaultMode: StorageMode): StorageMode` — returns `configuredMode` if it's a valid member of `supportedModes`, else `defaultMode`. (Pure; no DB.)

- [ ] **Step 1: Write the failing test**

```ts
// eldrin-integration/src/storage/mode.test.ts
import { describe, it, expect } from 'vitest';
import { assertModeImplemented, effectiveMode } from './mode';
import { NotImplementedError } from '../errors';

describe('storage mode engine', () => {
  it('assertModeImplemented allows stored', () => {
    expect(() => assertModeImplemented('stored')).not.toThrow();
  });
  it('assertModeImplemented throws for live and cached', () => {
    expect(() => assertModeImplemented('live')).toThrow(NotImplementedError);
    expect(() => assertModeImplemented('cached')).toThrow(NotImplementedError);
  });
  it('effectiveMode uses configured when supported', () => {
    expect(effectiveMode(['stored', 'live'], 'live', 'stored')).toBe('live');
  });
  it('effectiveMode falls back to default when configured is unsupported or null', () => {
    expect(effectiveMode(['stored'], 'live', 'stored')).toBe('stored');
    expect(effectiveMode(['stored'], null, 'stored')).toBe('stored');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/storage/mode.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

```ts
// eldrin-integration/src/storage/mode.ts
import type { StorageMode } from '../descriptor';
import { NotImplementedError } from '../errors';

export function assertModeImplemented(mode: StorageMode): void {
  if (mode !== 'stored') throw new NotImplementedError(`mode:${mode}`);
}

export function effectiveMode(
  supportedModes: StorageMode[],
  configuredMode: string | null,
  defaultMode: StorageMode,
): StorageMode {
  if (configuredMode && (supportedModes as string[]).includes(configuredMode)) {
    return configuredMode as StorageMode;
  }
  return defaultMode;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/storage/mode.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Export and commit**

Add to `src/index.ts`: `export { assertModeImplemented, effectiveMode } from './storage/mode';`

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-integration add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-integration commit -q -m "feat: add storage-mode engine (stored impl, live/cached gated)"
```

---

### Task 11: Runtime config (integration_config) read/write

**Files:**
- Create: `eldrin-integration/src/config/index.ts`
- Test: `eldrin-integration/src/config/index.test.ts`

**Interfaces:**
- Consumes: `DatabaseAdapter`, `INTEGRATION_CONFIG_DDL` (Task 7), `IntegrationDescriptor` (Task 3), `makeTestDb` (test helper).
- Produces:
  - `interface ResourceConfig { resource: string; mode: string | null; schedule: string | null; cacheTtlSeconds: number | null; webhookEnabled: boolean }`
  - `async function readResourceConfig(db, resource): Promise<ResourceConfig | null>`
  - `async function writeResourceConfig(db, config: ResourceConfig): Promise<void>` — upsert keyed on resource.
  - `async function seedConfigFromDescriptor(db, descriptor): Promise<void>` — for each resource, insert a config row with `mode = defaultMode`, `schedule = refresh?.schedule ?? null`, `cacheTtlSeconds = refresh?.cache?.ttlSeconds ?? null`, `webhookEnabled = !!resource.webhook`, only if no row exists (idempotent install seed).

- [ ] **Step 1: Write the failing test**

```ts
// eldrin-integration/src/config/index.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';
import { INTEGRATION_CONFIG_DDL } from '../schema/tables';
import { readResourceConfig, writeResourceConfig, seedConfigFromDescriptor } from './index';
import type { IntegrationDescriptor } from '../descriptor';
import { makeTestDb } from '../test-helpers';

let db: DatabaseAdapter;
beforeEach(async () => { db = await makeTestDb([INTEGRATION_CONFIG_DDL]); });

const descriptor: IntegrationDescriptor = {
  id: 'x',
  connection: { transport: 'http', baseUrl: 'x', auth: { strategy: 'apiKey', key: { secret: 'K' } } },
  resources: [{
    name: 'clients', transport: { method: 'GET', path: '/c', pagination: 'cursor' },
    idField: 'id', fieldMap: { id: 'remote_id' }, supportedModes: ['stored'], defaultMode: 'stored',
    refresh: { schedule: '0 * * * *' },
  }],
};

describe('integration_config', () => {
  it('read returns null when absent', async () => {
    expect(await readResourceConfig(db, 'clients')).toBeNull();
  });
  it('write then read round-trips, webhookEnabled as boolean', async () => {
    await writeResourceConfig(db, { resource: 'clients', mode: 'stored', schedule: '0 * * * *', cacheTtlSeconds: null, webhookEnabled: true });
    const c = await readResourceConfig(db, 'clients');
    expect(c).toMatchObject({ resource: 'clients', mode: 'stored', schedule: '0 * * * *', webhookEnabled: true });
  });
  it('seedConfigFromDescriptor seeds defaults and is idempotent', async () => {
    await seedConfigFromDescriptor(db, descriptor);
    await seedConfigFromDescriptor(db, descriptor); // second call must not overwrite/duplicate
    const c = await readResourceConfig(db, 'clients');
    expect(c?.mode).toBe('stored');
    expect(c?.schedule).toBe('0 * * * *');
    const all = await db.prepare('SELECT COUNT(*) AS n FROM _integration_config').first<{ n: number }>();
    expect(all?.n).toBe(1);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/config/index.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

```ts
// eldrin-integration/src/config/index.ts
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';
import type { IntegrationDescriptor } from '../descriptor';

export interface ResourceConfig {
  resource: string;
  mode: string | null;
  schedule: string | null;
  cacheTtlSeconds: number | null;
  webhookEnabled: boolean;
}

interface RawConfig {
  resource: string;
  mode: string | null;
  schedule: string | null;
  cache_ttl_seconds: number | null;
  webhook_enabled: number | null;
}

export async function readResourceConfig(
  db: DatabaseAdapter,
  resource: string,
): Promise<ResourceConfig | null> {
  const row = await db
    .prepare('SELECT * FROM _integration_config WHERE resource = ?')
    .bind(resource)
    .first<RawConfig>();
  if (!row) return null;
  return {
    resource: row.resource,
    mode: row.mode,
    schedule: row.schedule,
    cacheTtlSeconds: row.cache_ttl_seconds,
    webhookEnabled: row.webhook_enabled === 1,
  };
}

export async function writeResourceConfig(db: DatabaseAdapter, config: ResourceConfig): Promise<void> {
  await db
    .prepare(
      `INSERT INTO _integration_config (resource, mode, schedule, cache_ttl_seconds, webhook_enabled)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(resource) DO UPDATE SET
         mode = excluded.mode, schedule = excluded.schedule,
         cache_ttl_seconds = excluded.cache_ttl_seconds, webhook_enabled = excluded.webhook_enabled`,
    )
    .bind(
      config.resource,
      config.mode,
      config.schedule,
      config.cacheTtlSeconds,
      config.webhookEnabled ? 1 : 0,
    )
    .run();
}

export async function seedConfigFromDescriptor(
  db: DatabaseAdapter,
  descriptor: IntegrationDescriptor,
): Promise<void> {
  for (const r of descriptor.resources) {
    const existing = await readResourceConfig(db, r.name);
    if (existing) continue;
    await writeResourceConfig(db, {
      resource: r.name,
      mode: r.defaultMode,
      schedule: r.refresh?.schedule ?? null,
      cacheTtlSeconds: r.refresh?.cache?.ttlSeconds ?? null,
      webhookEnabled: !!r.webhook,
    });
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/config/index.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Export and commit**

Add to `src/index.ts`:
```ts
export { readResourceConfig, writeResourceConfig, seedConfigFromDescriptor, type ResourceConfig } from './config';
```

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-integration add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-integration commit -q -m "feat: add runtime integration_config store with descriptor seeding"
```

---

### Task 12: Repository (stored findAll/findById; query/live stubbed)

**Files:**
- Create: `eldrin-integration/src/repository/index.ts`
- Test: `eldrin-integration/src/repository/index.test.ts`

**Interfaces:**
- Consumes: `DatabaseAdapter`, `ResourceDescriptor` (Task 3), `assertModeImplemented`/`effectiveMode` (Task 10), `readResourceConfig` (Task 11), `makeTestDb`.
- Produces:
  - `interface Repository<T = Record<string, unknown>> { findAll(): Promise<T[]>; findById(remoteId: string): Promise<T | null>; query(): Promise<never> }`
  - `function createRepository(db, resource): Repository` — resolves effective mode from config; for `stored`, `findAll`/`findById` read the resource table; `query()` always throws `NotImplementedError('repository:query')`. If effective mode resolves to `live`/`cached`, `findAll`/`findById` throw `NotImplementedError('mode:live'|'mode:cached')` via `assertModeImplemented`.

- [ ] **Step 1: Write the failing test**

```ts
// eldrin-integration/src/repository/index.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';
import { createRepository } from './index';
import type { ResourceDescriptor } from '../descriptor';
import { storedResourceDDL, INTEGRATION_CONFIG_DDL } from '../schema/tables';
import { seedConfigFromDescriptor } from '../config';
import { NotImplementedError } from '../errors';
import { makeTestDb } from '../test-helpers';

const resource: ResourceDescriptor = {
  name: 'clients', transport: { method: 'GET', path: '/c', pagination: 'cursor' },
  idField: 'id', fieldMap: { id: 'remote_id', name: 'name' }, supportedModes: ['stored'], defaultMode: 'stored',
};

let db: DatabaseAdapter;
beforeEach(async () => {
  db = await makeTestDb([INTEGRATION_CONFIG_DDL, storedResourceDDL('clients', ['name TEXT'])]);
  await db.prepare('INSERT INTO clients (id, remote_id, name, raw_json, synced_at) VALUES (?, ?, ?, ?, ?)')
    .bind('a', '10', 'Ada', '{}', 1).run();
  await seedConfigFromDescriptor(db, {
    id: 'x', connection: { transport: 'http', baseUrl: 'x', auth: { strategy: 'apiKey', key: { secret: 'K' } } },
    resources: [resource],
  });
});

describe('createRepository (stored)', () => {
  it('findAll returns stored rows', async () => {
    const repo = createRepository(db, resource);
    const rows = await repo.findAll();
    expect(rows).toHaveLength(1);
    expect((rows[0] as { name: string }).name).toBe('Ada');
  });
  it('findById returns one row by remote_id', async () => {
    const repo = createRepository(db, resource);
    const row = await repo.findById('10');
    expect((row as { name: string }).name).toBe('Ada');
  });
  it('findById returns null for unknown id', async () => {
    const repo = createRepository(db, resource);
    expect(await repo.findById('999')).toBeNull();
  });
  it('query() throws NotImplemented', async () => {
    const repo = createRepository(db, resource);
    await expect(repo.query()).rejects.toThrow(NotImplementedError);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/repository/index.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

```ts
// eldrin-integration/src/repository/index.ts
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';
import type { ResourceDescriptor } from '../descriptor';
import { assertModeImplemented, effectiveMode } from '../storage/mode';
import { readResourceConfig } from '../config';
import { NotImplementedError } from '../errors';

export interface Repository<T = Record<string, unknown>> {
  findAll(): Promise<T[]>;
  findById(remoteId: string): Promise<T | null>;
  query(): Promise<never>;
}

export function createRepository<T = Record<string, unknown>>(
  db: DatabaseAdapter,
  resource: ResourceDescriptor,
): Repository<T> {
  async function ensureStored(): Promise<void> {
    const config = await readResourceConfig(db, resource.name);
    const mode = effectiveMode(resource.supportedModes, config?.mode ?? null, resource.defaultMode);
    assertModeImplemented(mode); // throws for live/cached until implemented
  }

  return {
    async findAll(): Promise<T[]> {
      await ensureStored();
      const res = await db.prepare(`SELECT * FROM ${resource.name}`).all<T>();
      return res.results;
    },
    async findById(remoteId: string): Promise<T | null> {
      await ensureStored();
      return db
        .prepare(`SELECT * FROM ${resource.name} WHERE remote_id = ?`)
        .bind(remoteId)
        .first<T>();
    },
    async query(): Promise<never> {
      // Future: cross-source SQL-like query engine (spec §7.3). Scaffolded.
      throw new NotImplementedError('repository:query');
    },
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/repository/index.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Export and commit**

Add to `src/index.ts`:
```ts
export { createRepository, type Repository } from './repository';
```

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-integration add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-integration commit -q -m "feat: add repository over stored mode; query() scaffolded"
```

---

### Task 13: Scheduling + health + webhook scaffold

**Files:**
- Create: `eldrin-integration/src/schedule/index.ts`
- Create: `eldrin-integration/src/health/index.ts`
- Create: `eldrin-integration/src/webhook/index.ts`
- Test: `eldrin-integration/src/schedule/index.test.ts`
- Test: `eldrin-integration/src/health/index.test.ts`
- Test: `eldrin-integration/src/webhook/index.test.ts`

**Interfaces:**
- Consumes: `IntegrationDescriptor`, `ResourceDescriptor` (Task 3); `SyncDeps`, `runResourceSync` (Task 9); `Transport` (Task 6); `NotImplementedError` (Task 2); `readResourceConfig` (Task 11); `DatabaseAdapter`.
- Produces:
  - **schedule:** `function dueResources(descriptor, configs: Map<string,{schedule:string|null}>, isDue: (cron: string) => boolean): ResourceDescriptor[]` — returns stored resources whose configured (or descriptor) schedule `isDue`. (Cron parsing is injected as `isDue` so it's pure/testable; the Worker passes a real evaluator. For the first pass the Worker may simply run all stored resources on each cron tick — `isDue` defaults to `() => true`.)
    `async function runScheduled(descriptor, deps: SyncDeps): Promise<SyncResult[]>` — runs `runResourceSync` for every stored resource (the cron handler's entry point).
  - **health:** `async function testConnection(transport: Transport, probe: ResourceDescriptor): Promise<{ ok: boolean; error?: string }>` — calls `transport.fetchAll(probe)` (a lightweight first resource), returns `{ok:true}` or `{ok:false, error}`.
  - **webhook:** `async function handleWebhook(): Promise<never>` — throws `NotImplementedError('webhook:pipeline')`. `interface WebhookHandlerDeps { db: DatabaseAdapter; descriptor: IntegrationDescriptor }` exported as the designed shape for later implementation.

- [ ] **Step 1: Write the failing tests**

```ts
// eldrin-integration/src/schedule/index.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';
import { runScheduled, dueResources } from './index';
import type { IntegrationDescriptor } from '../descriptor';
import type { Transport } from '../transport';
import { storedResourceDDL, SYNC_STATE_DDL } from '../schema/tables';
import { makeTestDb } from '../test-helpers';

const descriptor: IntegrationDescriptor = {
  id: 'x',
  connection: { transport: 'http', baseUrl: 'x', auth: { strategy: 'apiKey', key: { secret: 'K' } } },
  resources: [{
    name: 'clients', transport: { method: 'GET', path: '/c', pagination: 'cursor' },
    idField: 'id', fieldMap: { id: 'remote_id', name: 'name' }, supportedModes: ['stored'], defaultMode: 'stored',
    refresh: { schedule: '0 * * * *' },
  }],
};

let db: DatabaseAdapter;
let counter = 0;
beforeEach(async () => {
  counter = 0;
  db = await makeTestDb([SYNC_STATE_DDL, storedResourceDDL('clients', ['name TEXT'])]);
});

describe('schedule', () => {
  it('dueResources returns resources whose schedule isDue', () => {
    const due = dueResources(descriptor, new Map([['clients', { schedule: '0 * * * *' }]]), () => true);
    expect(due.map((r) => r.name)).toEqual(['clients']);
    const none = dueResources(descriptor, new Map([['clients', { schedule: '0 * * * *' }]]), () => false);
    expect(none).toHaveLength(0);
  });

  it('runScheduled syncs all stored resources', async () => {
    const transport: Transport = { fetchAll: async () => [{ id: 1, name: 'A' }] };
    const results = await runScheduled(descriptor, {
      db, transport, now: () => 5, genId: () => `id-${++counter}`,
    });
    expect(results).toEqual([{ resource: 'clients', count: 1 }]);
  });
});
```

```ts
// eldrin-integration/src/health/index.test.ts
import { describe, it, expect } from 'vitest';
import { testConnection } from './index';
import type { Transport } from '../transport';
import type { ResourceDescriptor } from '../descriptor';

const probe: ResourceDescriptor = {
  name: 'clients', transport: { method: 'GET', path: '/c', pagination: 'none' },
  idField: 'id', fieldMap: { id: 'remote_id' }, supportedModes: ['stored'], defaultMode: 'stored',
};

describe('testConnection', () => {
  it('returns ok when transport succeeds', async () => {
    const t: Transport = { fetchAll: async () => [] };
    expect(await testConnection(t, probe)).toEqual({ ok: true });
  });
  it('returns error when transport throws', async () => {
    const t: Transport = { fetchAll: async () => { throw new Error('401 unauthorized'); } };
    const r = await testConnection(t, probe);
    expect(r.ok).toBe(false);
    expect(r.error).toContain('401');
  });
});
```

```ts
// eldrin-integration/src/webhook/index.test.ts
import { describe, it, expect } from 'vitest';
import { handleWebhook } from './index';
import { NotImplementedError } from '../errors';

describe('webhook (scaffolded)', () => {
  it('handleWebhook throws NotImplemented', async () => {
    await expect(handleWebhook()).rejects.toThrow(NotImplementedError);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/schedule src/health src/webhook`
Expected: FAIL — modules not found.

- [ ] **Step 3: Write the implementations**

```ts
// eldrin-integration/src/schedule/index.ts
import type { IntegrationDescriptor, ResourceDescriptor } from '../descriptor';
import { runResourceSync, type SyncDeps, type SyncResult } from '../sync';

export function dueResources(
  descriptor: IntegrationDescriptor,
  configs: Map<string, { schedule: string | null }>,
  isDue: (cron: string) => boolean = () => true,
): ResourceDescriptor[] {
  return descriptor.resources.filter((r) => {
    if (r.defaultMode !== 'stored') return false;
    const schedule = configs.get(r.name)?.schedule ?? r.refresh?.schedule ?? null;
    return schedule ? isDue(schedule) : false;
  });
}

export async function runScheduled(
  descriptor: IntegrationDescriptor,
  deps: SyncDeps,
): Promise<SyncResult[]> {
  const results: SyncResult[] = [];
  for (const r of descriptor.resources) {
    if (r.defaultMode === 'stored' && r.supportedModes.includes('stored')) {
      results.push(await runResourceSync(r, deps));
    }
  }
  return results;
}
```

```ts
// eldrin-integration/src/health/index.ts
import type { Transport } from '../transport';
import type { ResourceDescriptor } from '../descriptor';

export async function testConnection(
  transport: Transport,
  probe: ResourceDescriptor,
): Promise<{ ok: boolean; error?: string }> {
  try {
    await transport.fetchAll(probe);
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}
```

```ts
// eldrin-integration/src/webhook/index.ts
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';
import type { IntegrationDescriptor } from '../descriptor';
import { NotImplementedError } from '../errors';

// Designed shape for the inbound webhook pipeline (spec §6.3). Scaffolded:
// signature verification, dedup against _integration_webhook_deliveries,
// record resolution, upsert, and event emission are implemented when the
// first webhook-using integration arrives.
export interface WebhookHandlerDeps {
  db: DatabaseAdapter;
  descriptor: IntegrationDescriptor;
}

export async function handleWebhook(): Promise<never> {
  throw new NotImplementedError('webhook:pipeline');
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run src/schedule src/health src/webhook`
Expected: PASS (schedule: 2, health: 2, webhook: 1).

- [ ] **Step 5: Export and commit**

Add to `src/index.ts`:
```ts
export { dueResources, runScheduled } from './schedule';
export { testConnection } from './health';
export { handleWebhook, type WebhookHandlerDeps } from './webhook';
```

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-integration add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-integration commit -q -m "feat: add scheduling, health check, and webhook scaffold"
```

---

### Task 14: Full SDK build + coverage gate + register as submodule

**Files:**
- Modify: `eldrin-integration/src/index.ts` (verify complete barrel)
- Create: `eldrin-integration/README.md`
- Modify (parent): `.gitmodules`, parent repo index

**Interfaces:**
- Consumes: all prior tasks.
- Produces: a published-shape SDK; registered as a parent submodule like `eldrin-factorial`.

- [ ] **Step 1: Run the full test suite with coverage**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npx vitest run --coverage`
Expected: all tests pass; coverage ≥80% statements/lines for `src/**` excluding stubs and `test-helpers.ts`. If any implemented file is under 80%, add a focused test before proceeding.

- [ ] **Step 2: Full typecheck and build**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npm run typecheck && npm run build`
Expected: typecheck passes; `dist/index.js`, `dist/index.cjs`, `dist/index.d.ts` emitted.

- [ ] **Step 3: Write a short README**

```markdown
// eldrin-integration/README.md
# @eldrin-project/eldrin-integration

Integration extension SDK for Eldrin. Define a connector to an external system with a declarative descriptor; the SDK derives the HTTP client, sync runner, repository, scheduling, and health check.

## Status (factorial-driven first pass)

Implemented: `apiKey` auth, HTTP/REST GET + cursor pagination, `stored` storage mode, generic sync runner, repository (`findAll`/`findById`), scheduling, health check, runtime config.

Scaffolded (throws `NotImplementedError` until an integration needs it): `bearer`/OAuth2 auth, GraphQL/file transports, `live`/`cached` modes, `query()`, the webhook pipeline.

See `docs/superpowers/specs/2026-06-27-integration-extension-design.md` in the parent repo.

## Usage

```ts
import { defineIntegration } from '@eldrin-project/eldrin-integration';

export default defineIntegration({
  id: 'eldrin-acme',
  connection: { transport: 'http', baseUrl: { setting: 'ACME.API_BASE_URL' },
    auth: { strategy: 'apiKey', header: 'x-api-key', key: { secret: 'ACME.API_KEY' } } },
  resources: [{
    name: 'clients', transport: { method: 'GET', path: '/clients', pagination: 'cursor' },
    idField: 'id', fieldMap: { id: 'remote_id', name: 'name' },
    supportedModes: ['stored'], defaultMode: 'stored', refresh: { schedule: '0 * * * *' },
  }],
});
```
```

- [ ] **Step 4: Commit the SDK repo**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-integration add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-integration commit -q -m "docs: add eldrin-integration README; finalize first-pass SDK"
```

- [ ] **Step 5: Register as a parent submodule**

> Follow the same approach used for `eldrin-factorial`. The SDK currently lives as a local repo; if a remote exists, add it as a submodule URL. If no remote yet, leave it as a sibling local dependency (`file:../eldrin-integration`) and note in the parent commit that the submodule registration is pending a remote. Confirm with the user which (remote URL vs. local-only) before running `git submodule add`.

```bash
# Only if a remote exists (confirm URL with user first):
# git -C /Users/tibor/projects/eldrin-backup submodule add <remote-url> eldrin-integration
git -C /Users/tibor/projects/eldrin-backup add .gitmodules eldrin-integration 2>/dev/null; \
git -C /Users/tibor/projects/eldrin-backup status
```
Expected: parent shows `eldrin-integration` staged (as submodule or directory). Defer the parent commit until Part B so the SDK + factorial rewrite land together.

---

## File Structure (Part B — `eldrin-factorial/` rewrite + shell)

```
eldrin-factorial/
├── package.json                      add @eldrin-project/eldrin-integration dep
├── worker/
│   ├── integration.ts                NEW: defineIntegration() descriptor for Factorial
│   ├── index.ts                      MODIFY: wire SDK sync + cron + health via descriptor
│   ├── db/schema.ts                  MODIFY: tables match storedResourceDDL columns
│   ├── services/factorial-client.ts  DELETE (replaced by SDK transport)
│   ├── services/sync.ts              DELETE (replaced by SDK sync runner)
│   └── routes/sync.ts                MODIFY: call SDK runAllSync
└── public/eldrin-app.manifest.json   MODIFY: add "kind":"integration" + integration block

eldrin-core/  (shell)
├── src/types/manifest.ts             MODIFY: add kind + integration block types
└── src/pages/settings/...            MODIFY: accept empty sideNav for kind=integration
```

> **Part B note:** The factorial rewrite touches a live, tested extension. Each task keeps factorial's existing test suite green. Where the SDK's generic shape diverges from factorial's current hand-written behavior, prefer an SDK override hook over changing the SDK. Run factorial's full suite (`cd eldrin-factorial && npm run test`) after each task.

---

### Task 15: Add the SDK dependency and write the Factorial descriptor

**Files:**
- Modify: `eldrin-factorial/package.json` (add dependency)
- Create: `eldrin-factorial/worker/integration.ts`
- Test: `eldrin-factorial/worker/__tests__/integration-descriptor.test.ts`

**Interfaces:**
- Consumes: `defineIntegration`, `IntegrationDescriptor` from the SDK.
- Produces: `export const factorialIntegration: IntegrationDescriptor` — the declarative replacement for `factorial-client.ts` + `sync.ts`, covering employees and projects (the resources factorial syncs today), using `auth: apiKey` (`x-api-key`) and `transport: http, pagination: cursor`, with `fieldMap`s matching the existing employee/project columns.

- [ ] **Step 1: Add the dependency**

Edit `eldrin-factorial/package.json` dependencies, add:
```jsonc
"@eldrin-project/eldrin-integration": "file:../eldrin-integration",
```
Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-factorial && npm install`
Expected: installs the local SDK.

- [ ] **Step 2: Write the failing test**

```ts
// eldrin-factorial/worker/__tests__/integration-descriptor.test.ts
import { describe, it, expect } from 'vitest';
import { factorialIntegration } from '../integration';

describe('factorialIntegration descriptor', () => {
  it('uses apiKey auth with x-api-key header', () => {
    expect(factorialIntegration.connection.auth.strategy).toBe('apiKey');
    expect(factorialIntegration.connection.auth.header).toBe('x-api-key');
  });
  it('declares employees and projects as stored cursor-paginated resources', () => {
    const names = factorialIntegration.resources.map((r) => r.name).sort();
    expect(names).toEqual(['employees', 'projects']);
    for (const r of factorialIntegration.resources) {
      expect(r.transport.method).toBe('GET');
      expect(r.transport.pagination).toBe('cursor');
      expect(r.supportedModes).toContain('stored');
      expect(r.defaultMode).toBe('stored');
    }
  });
  it('maps employee fields used by the UI', () => {
    const emp = factorialIntegration.resources.find((r) => r.name === 'employees')!;
    expect(emp.fieldMap).toMatchObject({ id: 'remote_id', email: 'email' });
  });
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-factorial && npx vitest run worker/__tests__/integration-descriptor.test.ts`
Expected: FAIL — `../integration` not found.

- [ ] **Step 4: Write the descriptor**

```ts
// eldrin-factorial/worker/integration.ts
import { defineIntegration, type IntegrationDescriptor } from '@eldrin-project/eldrin-integration';

// Factorial's validated 2026-04-01 resource paths and field shapes,
// migrated from the former hand-written factorial-client.ts + sync.ts.
const API_BASE_PATH = '/api/2026-04-01/resources';

export const factorialIntegration: IntegrationDescriptor = defineIntegration({
  id: 'eldrin-factorial',
  connection: {
    transport: 'http',
    baseUrl: { setting: 'FACTORIAL.API_BASE_URL' },
    auth: { strategy: 'apiKey', header: 'x-api-key', key: { secret: 'FACTORIAL.API_KEY' } },
  },
  resources: [
    {
      name: 'employees',
      transport: { method: 'GET', path: `${API_BASE_PATH}/employees/employees?only_active=true`, pagination: 'cursor' },
      idField: 'id',
      fieldMap: { id: 'remote_id', full_name: 'full_name', email: 'email', job_title: 'job_title', team_id: 'team_id' },
      supportedModes: ['stored'],
      defaultMode: 'stored',
      refresh: { schedule: '0 * * * *' },
      hooks: {
        // full_name may be absent; derive from first/last like the old sync did.
        transform: (raw) => {
          const full = raw.full_name ??
            [raw.first_name, raw.last_name].filter(Boolean).join(' ').trim() || null;
          return { ...raw, full_name: full };
        },
      },
    },
    {
      name: 'projects',
      transport: { method: 'GET', path: `${API_BASE_PATH}/project_management/projects`, pagination: 'cursor' },
      idField: 'id',
      fieldMap: { id: 'remote_id', name: 'name', status: 'status' },
      supportedModes: ['stored'],
      defaultMode: 'stored',
      refresh: { schedule: '0 * * * *' },
    },
  ],
});
```

> **Note on baseUrl resolution:** the descriptor references settings (`FACTORIAL.API_BASE_URL`, `FACTORIAL.API_KEY`). In the Worker (Task 17) these resolve from `c.env.FACTORIAL_API_BASE_URL` / `FACTORIAL_API_KEY` via a `SettingsLookup`. The `${API_BASE_PATH}` prefix that `factorial-client.ts` used to add is now baked into each resource `path`.

- [ ] **Step 5: Run test to verify it passes**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-factorial && npx vitest run worker/__tests__/integration-descriptor.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-factorial add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-factorial commit -q -m "feat(factorial): add eldrin-integration dep and declarative descriptor"
```

---

### Task 16: Align factorial schema with the SDK stored-table shape

**Files:**
- Modify: `eldrin-factorial/worker/db/schema.ts`
- Modify: `eldrin-factorial/scripts/generate-migrations.ts` output OR add a new migration (whichever factorial uses — check before editing)
- Test: existing `eldrin-factorial/worker/__tests__/*` must stay green

**Interfaces:**
- Consumes: `storedResourceDDL` column convention (Task 7): `id TEXT PRIMARY KEY, remote_id TEXT NOT NULL UNIQUE, <cols>, raw_json TEXT, synced_at INTEGER NOT NULL`.
- Produces: `employees` and `projects` drizzle tables whose columns match the SDK runner's expectations (`remote_id` instead of `factorial_id`), plus the SDK management tables created via migration.

- [ ] **Step 1: Inspect factorial's migration generation**

Run:
```bash
sed -n '1,60p' /Users/tibor/projects/eldrin-backup/eldrin-factorial/scripts/generate-migrations.ts; ls /Users/tibor/projects/eldrin-backup/eldrin-factorial/migrations
```
Expected: shows how migrations are produced (from schema.ts or hand-written SQL) and the existing migration filename(s). Remember the **14-digit timestamp filename rule** — any new migration must be named `YYYYMMDDHHMMSS-description.sql` or it is silently skipped.

- [ ] **Step 2: Update `schema.ts`** so `employees`/`projects` use `remoteId: text('remote_id')` with a unique index, and add drizzle tables (or raw migration SQL) for `_integration_sync_state`, `_integration_config`, `_integration_webhook_deliveries` matching the SDK DDL exactly. Update the `idx_*_factorial_id` index name to `idx_*_remote_id`.

```ts
// eldrin-factorial/worker/db/schema.ts  (employees shown; mirror for projects)
import { sqliteTable, text, integer, uniqueIndex } from 'drizzle-orm/sqlite-core';

export const employees = sqliteTable('employees', {
  id: text('id').primaryKey(),
  remoteId: text('remote_id').notNull(),
  fullName: text('full_name'),
  email: text('email'),
  jobTitle: text('job_title'),
  teamId: text('team_id'),
  rawJson: text('raw_json'),
  syncedAt: integer('synced_at', { mode: 'number' }).notNull(),
}, (t) => [uniqueIndex('idx_employees_remote_id').on(t.remoteId)]);

export const projects = sqliteTable('projects', {
  id: text('id').primaryKey(),
  remoteId: text('remote_id').notNull(),
  name: text('name'),
  status: text('status'),
  rawJson: text('raw_json'),
  syncedAt: integer('synced_at', { mode: 'number' }).notNull(),
}, (t) => [uniqueIndex('idx_projects_remote_id').on(t.remoteId)]);
```

- [ ] **Step 3: Add a timestamped migration** for the renamed columns/indexes and the three SDK tables. Generate the migration via factorial's existing script if it derives from schema.ts; otherwise create `migrations/<14-digit-timestamp>-integration-tables.sql` by hand with `ALTER TABLE`/`CREATE TABLE IF NOT EXISTS` statements. Then regenerate `worker/migrations.generated.ts` (run `npm run generate:migrations`).

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-factorial && npm run generate:migrations`
Expected: `worker/migrations.generated.ts` includes the new migration.

- [ ] **Step 4: Update existing factorial tests** that reference `factorial_id` to use `remote_id` (the column rename). Search and update:

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-factorial && grep -rn "factorial_id\|factorialId" worker src`
Then update each occurrence in non-deleted files to `remote_id`/`remoteId`. (The `sync.ts`/`factorial-client.ts` references disappear when those files are deleted in Task 17 — for now, if tests import them, leave until Task 17.)

- [ ] **Step 5: Run factorial tests**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-factorial && npm run test`
Expected: tests that don't depend on the soon-deleted services pass; `sync.test.ts`/`factorial-client.test.ts` may still pass against the old services (deleted next task). If a schema test fails on the column rename, update its expectation to `remote_id`.

- [ ] **Step 6: Commit**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-factorial add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-factorial commit -q -m "refactor(factorial): align schema with SDK stored-table shape + add management tables"
```

---

### Task 17: Wire the Worker to the SDK; delete hand-written client/sync

**Files:**
- Modify: `eldrin-factorial/worker/index.ts` (cron `scheduled`, health, db wiring)
- Modify: `eldrin-factorial/worker/routes/sync.ts` (call SDK `runAllSync`)
- Modify: `eldrin-factorial/worker/routes/connection.ts` (use SDK `testConnection` for health) — or keep as-is if it only reports config presence
- Delete: `eldrin-factorial/worker/services/factorial-client.ts`
- Delete: `eldrin-factorial/worker/services/sync.ts`
- Delete: `eldrin-factorial/worker/__tests__/factorial-client.test.ts`, `worker/__tests__/sync.test.ts` (replaced by SDK tests + the new integration test in Task 18)

**Interfaces:**
- Consumes: `factorialIntegration` (Task 15); SDK `createAuthStrategy`, `createTransport`, `runAllSync`, `runScheduled`, `testConnection`, `seedConfigFromDescriptor`, `SyncDeps`; the app-core `DatabaseAdapter` (factorial currently uses drizzle-d1 — wrap `c.env.DB` with app-core's `createD1Adapter` for the SDK calls).
- Produces: a Worker where `POST /api/sync` and the cron `scheduled` handler both drive the SDK sync runner against Factorial's live API shape; `GET /api/connection` (or `/api/health`) uses the SDK health check.

- [ ] **Step 1: Build the SDK deps factory** — a small helper in `worker/index.ts` (or `worker/integration-runtime.ts`) that, given `env`, builds: a `SettingsLookup` mapping `{setting:'FACTORIAL.API_BASE_URL'}`→`env.FACTORIAL_API_BASE_URL` and `{secret:'FACTORIAL.API_KEY'}`→`env.FACTORIAL_API_KEY`; the auth strategy; the transport; and `SyncDeps` ( `db: createD1Adapter(env.DB)`, `transport`, `now: () => Date.now()`, `genId: () => crypto.randomUUID()` ).

```ts
// eldrin-factorial/worker/integration-runtime.ts
import { createD1Adapter } from '@eldrin-project/eldrin-app-core';
import {
  createAuthStrategy, createTransport, type SyncDeps, type SettingsLookup,
} from '@eldrin-project/eldrin-integration';
import { factorialIntegration } from './integration';

function lookup(env: Env): SettingsLookup {
  const map: Record<string, string | undefined> = {
    'FACTORIAL.API_BASE_URL': env.FACTORIAL_API_BASE_URL,
    'FACTORIAL.API_KEY': env.FACTORIAL_API_KEY,
  };
  return (ref) => ('setting' in ref ? map[ref.setting] : map[ref.secret]);
}

export function buildSyncDeps(env: Env): SyncDeps {
  const look = lookup(env);
  const baseUrl = look({ setting: 'FACTORIAL.API_BASE_URL' }) ?? '';
  const auth = createAuthStrategy(factorialIntegration.connection.auth, look);
  const transport = createTransport(factorialIntegration.connection, auth, baseUrl);
  return {
    db: createD1Adapter(env.DB),
    transport,
    now: () => Date.now(),
    genId: () => crypto.randomUUID(),
  };
}
```

- [ ] **Step 2: Update `routes/sync.ts`** to call `runAllSync(factorialIntegration, buildSyncDeps(c.env))` and seed config on first run:

```ts
// eldrin-factorial/worker/routes/sync.ts
import { Hono } from 'hono';
import { runAllSync, seedConfigFromDescriptor, IntegrationError } from '@eldrin-project/eldrin-integration';
import { createD1Adapter } from '@eldrin-project/eldrin-app-core';
import { factorialIntegration } from '../integration';
import { buildSyncDeps } from '../integration-runtime';

type Variables = { userId: string };
export const syncRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

syncRoutes.post('/api/sync', async (c) => {
  const userId = c.get('userId');
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);
  if (!c.env.FACTORIAL_API_BASE_URL?.trim() || !c.env.FACTORIAL_API_KEY?.trim()) {
    return c.json({ error: 'Factorial is not configured' }, 400);
  }
  try {
    await seedConfigFromDescriptor(createD1Adapter(c.env.DB), factorialIntegration);
    const results = await runAllSync(factorialIntegration, buildSyncDeps(c.env));
    return c.json({ results });
  } catch (e) {
    const status = e instanceof IntegrationError ? e.status : 500;
    return c.json({ error: e instanceof Error ? e.message : 'Sync failed' }, status as 400 | 500);
  }
});
```

- [ ] **Step 3: Update the cron handler** in `worker/index.ts` to run a scheduled sync:

```ts
// in eldrin-factorial/worker/index.ts
import { runScheduled, seedConfigFromDescriptor } from '@eldrin-project/eldrin-integration';
import { createD1Adapter } from '@eldrin-project/eldrin-app-core';
import { factorialIntegration } from './integration';
import { buildSyncDeps } from './integration-runtime';

export default {
  fetch: app.fetch,
  scheduled: async (_event: ScheduledEvent, env: Env) => {
    await seedConfigFromDescriptor(createD1Adapter(env.DB), factorialIntegration);
    await runScheduled(factorialIntegration, buildSyncDeps(env));
  },
};
```

- [ ] **Step 4: Delete the obsolete services and their tests**

Run:
```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-factorial && \
  git rm worker/services/factorial-client.ts worker/services/sync.ts \
         worker/__tests__/factorial-client.test.ts worker/__tests__/sync.test.ts
```
Then update any remaining imports of those files (e.g. `routes/employees.ts`, `routes/connection.ts`) — `grep -rn "services/sync\|services/factorial-client" worker` and replace usages (employees/teams/timeoff list routes now read from D1 directly via drizzle, unchanged; only the sync path moved to the SDK).

- [ ] **Step 5: Add a cron trigger to `wrangler.jsonc`** (if not present) so the scheduled handler fires:

Run: `grep -n "triggers\|crons" /Users/tibor/projects/eldrin-backup/eldrin-factorial/wrangler.jsonc`
If absent, add:
```jsonc
"triggers": { "crons": ["0 * * * *"] }
```

- [ ] **Step 6: Typecheck and run the full factorial suite**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-factorial && npm run typecheck && npm run test`
Expected: typecheck passes; remaining tests (connection, employees, teams, timeoff, proxy, health) pass. If a route test imported the deleted services, fix the import.

- [ ] **Step 7: Commit**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-factorial add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-factorial commit -q -m "refactor(factorial): drive sync via eldrin-integration SDK; remove hand-written client/sync"
```

---

### Task 18: Factorial SDK-backed sync integration test

**Files:**
- Create: `eldrin-factorial/worker/__tests__/sdk-sync.test.ts`

**Interfaces:**
- Consumes: `factorialIntegration` (Task 15), SDK `runResourceSync` + `makeTestDb` equivalent. Since `makeTestDb` is internal to the SDK, this test builds its own in-memory adapter the same way (or imports the SDK's exported DDL helpers and app-core's node SQLite adapter directly).
- Produces: an acceptance test proving the descriptor + SDK reproduce factorial's old `syncEmployees` behavior (the replacement for the deleted `sync.test.ts`).

- [ ] **Step 1: Write the test**

```ts
// eldrin-factorial/worker/__tests__/sdk-sync.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import { createNodeSQLiteAdapter } from '@eldrin-project/eldrin-app-core/database/sqlite';
import type { DatabaseAdapter } from '@eldrin-project/eldrin-app-core';
import {
  runResourceSync, storedResourceDDL, SYNC_STATE_DDL, type Transport,
} from '@eldrin-project/eldrin-integration';
import { factorialIntegration } from '../integration';

const employees = factorialIntegration.resources.find((r) => r.name === 'employees')!;

function fakeTransport(rows: Record<string, unknown>[]): Transport {
  return { fetchAll: async () => rows };
}

let db: DatabaseAdapter;
let counter = 0;
beforeEach(async () => {
  counter = 0;
  db = createNodeSQLiteAdapter(':memory:');
  for (const ddl of [SYNC_STATE_DDL, storedResourceDDL('employees', ['full_name TEXT', 'email TEXT', 'job_title TEXT', 'team_id TEXT'])]) {
    for (const part of ddl.split(';').map((s) => s.trim()).filter(Boolean)) await db.prepare(part).run();
  }
});

describe('factorial employees sync via SDK', () => {
  it('maps the validated Factorial employee payload into the employees table', async () => {
    const result = await runResourceSync(employees, {
      db, transport: fakeTransport([
        { id: 10, first_name: 'Ada', last_name: 'Lovelace', full_name: 'Ada Lovelace', email: 'ada@x.io' },
      ]),
      now: () => 1000, genId: () => `id-${++counter}`,
    });
    expect(result).toEqual({ resource: 'employees', count: 1 });
    const row = await db.prepare('SELECT remote_id, full_name, email FROM employees WHERE remote_id = ?').bind('10').first<{ remote_id: string; full_name: string; email: string }>();
    expect(row).toMatchObject({ remote_id: '10', full_name: 'Ada Lovelace', email: 'ada@x.io' });
  });

  it('derives full_name from first/last when absent (transform hook)', async () => {
    await runResourceSync(employees, {
      db, transport: fakeTransport([{ id: 11, first_name: 'Grace', last_name: 'Hopper', email: 'grace@x.io' }]),
      now: () => 1, genId: () => `id-${++counter}`,
    });
    const row = await db.prepare('SELECT full_name FROM employees WHERE remote_id = ?').bind('11').first<{ full_name: string }>();
    expect(row?.full_name).toBe('Grace Hopper');
  });
});
```

> If `createNodeSQLiteAdapter`'s name/signature differs (confirmed in Task 8 Step 1), match it here. The SDK must export `Transport`, `runResourceSync`, `storedResourceDDL`, `SYNC_STATE_DDL` (it does, per Tasks 6/7/9).

- [ ] **Step 2: Run the test**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-factorial && npx vitest run worker/__tests__/sdk-sync.test.ts`
Expected: PASS (2 tests). If the SDK isn't built/linked, run `npm install` in factorial first.

- [ ] **Step 3: Run the full factorial suite + typecheck**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-factorial && npm run typecheck && npm run test`
Expected: all green.

- [ ] **Step 4: Commit**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-factorial add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-factorial commit -q -m "test(factorial): add SDK-backed sync acceptance test"
```

---

### Task 19: Shell manifest support for `kind: "integration"`

**Files:**
- Modify: `eldrin-core/src/types/manifest.ts` (add `kind` + `integration` block types)
- Modify: `eldrin-factorial/public/eldrin-app.manifest.json` (add `kind` + `integration`)
- Test: `eldrin-core/src/types/manifest.test.ts` (create if absent) — type-level + a parse/validation test if the shell validates manifests at runtime

**Interfaces:**
- Consumes: existing `AppManifest` type.
- Produces:
  - `AppManifest.kind?: 'app' | 'integration'` (default `'app'` when absent).
  - `AppManifest.integration?: IntegrationManifestBlock` where:
    ```ts
    interface IntegrationManifestBlock {
      connection: { transport: string; authStrategy: string };
      resources: Array<{ name: string; supportedModes: string[]; defaultMode: string; schedule?: string; webhook?: boolean }>;
      health?: { route: string };
    }
    ```
  - Shell rule: when `kind === 'integration'`, an empty/absent `ui.sideNav` is **accepted as valid** (no warning). A developer MAY still declare `sideNav` items. (Spec §10.1.)

- [ ] **Step 1: Inspect how the shell validates/consumes the manifest**

Run:
```bash
grep -rn "sideNav\|kind\|AppManifest" /Users/tibor/projects/eldrin-backup/eldrin-core/src/types/manifest.ts | head; \
grep -rln "sideNav" /Users/tibor/projects/eldrin-backup/eldrin-core/src | head
```
Expected: identifies whether sideNav emptiness is currently warned/enforced anywhere (e.g. in `appRegistry.ts` or `SideNav.tsx`). This tells you where to add the `kind === 'integration'` exception.

- [ ] **Step 2: Write the failing test**

```ts
// eldrin-core/src/types/manifest.test.ts
import { describe, it, expect } from 'vitest';
import type { AppManifest } from './manifest';

describe('integration manifest kind', () => {
  it('accepts kind=integration with an integration block and no sideNav', () => {
    const m: AppManifest = {
      id: 'eldrin-factorial', name: 'Factorial', version: '0.0.1', entry: '/x.js',
      kind: 'integration',
      integration: {
        connection: { transport: 'http', authStrategy: 'apiKey' },
        resources: [{ name: 'employees', supportedModes: ['stored'], defaultMode: 'stored', schedule: '0 * * * *' }],
        health: { route: '/api/health' },
      },
    } as AppManifest;
    expect(m.kind).toBe('integration');
    expect(m.integration?.resources[0].defaultMode).toBe('stored');
  });
});
```

> If the shell has a runtime manifest validator (found in Step 1), add a test there asserting an integration manifest with empty `sideNav` passes validation without a warning. Use the exact validator function name discovered in Step 1.

- [ ] **Step 3: Run test to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-core && npx vitest run src/types/manifest.test.ts`
Expected: FAIL — `kind`/`integration` not on `AppManifest`.

- [ ] **Step 4: Extend `manifest.ts`**

Add to `eldrin-core/src/types/manifest.ts`:
```ts
export interface IntegrationResourceManifest {
  name: string;
  supportedModes: string[];
  defaultMode: string;
  schedule?: string;
  webhook?: boolean;
}

export interface IntegrationManifestBlock {
  connection: { transport: string; authStrategy: string };
  resources: IntegrationResourceManifest[];
  health?: { route: string };
}
```
And add to the `AppManifest` interface:
```ts
  kind?: 'app' | 'integration';
  integration?: IntegrationManifestBlock;
```

- [ ] **Step 5: Apply the `kind === 'integration'` sideNav exception** at the location found in Step 1 (e.g. wherever the shell warns on an app with no nav). Gate that warning behind `manifest.kind !== 'integration'`. If no such warning exists, no code change is needed beyond the types — note that in the commit.

- [ ] **Step 6: Update factorial's manifest**

Edit `eldrin-factorial/public/eldrin-app.manifest.json` — add at the top level:
```jsonc
"kind": "integration",
"integration": {
  "connection": { "transport": "http", "authStrategy": "apiKey" },
  "resources": [
    { "name": "employees", "supportedModes": ["stored"], "defaultMode": "stored", "schedule": "0 * * * *" },
    { "name": "projects", "supportedModes": ["stored"], "defaultMode": "stored", "schedule": "0 * * * *" }
  ],
  "health": { "route": "/api/connection" }
}
```
Factorial keeps its existing `ui.sideNav` (it has UI pages) — this validates the "developer MAY enforce a UI contribution" path.

- [ ] **Step 7: Run shell tests + typecheck**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-core && npx vitest run src/types/manifest.test.ts && npm run typecheck 2>/dev/null || npx tsc --noEmit`
Expected: PASS; typecheck clean.

- [ ] **Step 8: Commit (both repos)**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-core add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-core commit -q -m "feat(core): support manifest kind=integration with headless sideNav"
git -C /Users/tibor/projects/eldrin-backup/eldrin-factorial add -A && git -C /Users/tibor/projects/eldrin-backup/eldrin-factorial commit -q -m "feat(factorial): declare kind=integration in manifest"
```

---

### Task 20: End-to-end verification + parent submodule commit

**Files:**
- Modify (parent): submodule references for `eldrin-integration`, `eldrin-factorial`, `eldrin-core`
- Create: `eldrin-core/e2e/integration-admin.spec.ts` (only if the shell admin panel from spec §12 is implemented in this pass — see note)

**Interfaces:**
- Consumes: everything.
- Produces: green builds across the three repos and a single parent commit bundling the submodule updates.

> **Scope note on the admin panel:** Spec §12 describes a shell-generated admin panel (connection test, resources, sync-now, status). The descriptor → admin-schema generation and the shell React panel are a substantial UI surface. This plan implements the **manifest + headless handling** (Task 19) and the **backend** the panel would call (sync, health, config — Tasks 8–13, 17). Building the generated React admin panel + its Playwright E2E is deferred to a follow-up plan unless the user wants it now. Confirm with the user before adding Task 20's E2E spec; if deferred, Step 3 below is skipped.

- [ ] **Step 1: Build + test all three repos**

Run:
```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-integration && npm run build && npx vitest run --coverage
cd /Users/tibor/projects/eldrin-backup/eldrin-factorial && npm run typecheck && npm run test && npm run build
cd /Users/tibor/projects/eldrin-backup/eldrin-core && npx tsc --noEmit && npx vitest run
```
Expected: all green; factorial builds (the SDK is bundled via `file:` dep); SDK coverage ≥80%.

- [ ] **Step 2: Manual smoke (optional, recommended)** — run factorial's worker dev server and hit the sync + connection endpoints with the sandbox credentials, confirming employees populate the `employees` table with `remote_id`.

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-factorial && npm run dev:worker` (then `POST /api/sync` with a valid `X-Eldrin-User-Id` and configured `FACTORIAL_*` env). Expected: `{ results: [{ resource: 'employees', count: N }, ...] }`.

- [ ] **Step 3 (conditional): Admin-panel E2E** — only if the user opted to build the shell admin panel this pass. Otherwise skip. (Playwright spec: configure connection → Test connection → Sync now → status shows last sync.)

- [ ] **Step 4: Parent submodule commit**

```bash
git -C /Users/tibor/projects/eldrin-backup add eldrin-integration eldrin-factorial eldrin-core .gitmodules 2>/dev/null
git -C /Users/tibor/projects/eldrin-backup status
git -C /Users/tibor/projects/eldrin-backup commit -q -m "feat: add integration extension SDK and rewrite factorial onto it

- New @eldrin-project/eldrin-integration SDK (descriptor model, HTTP transport,
  apiKey auth, sync runner, repository, scheduling, health; OAuth2/GraphQL/file/
  live/cached/webhooks scaffolded as typed NotImplemented stubs)
- eldrin-factorial rewritten as the reference integration on the SDK
- eldrin-core manifest supports kind=integration (headless sideNav)"
```
Expected: a single parent commit referencing all updated submodules. Per the submodule workflow, this is the integration point.

- [ ] **Step 5: Report status** — summarize what's implemented vs. scaffolded (mirror spec §14a) and surface any deferred items (admin panel UI, webhook pipeline, second storage mode) for a follow-up plan.

---

## Notes for the implementer

- **Run order:** Tasks 1–14 (SDK) must precede 15–20 (factorial/shell). Within Part A, Tasks 2–13 are mostly independent after Tasks 1–3; do them in numeric order to keep barrel exports consistent.
- **The cwd gotcha is real** (see Global Constraints). Every git command in this plan uses `git -C <abs-path>` for exactly this reason — don't simplify them to bare `git`.
- **Stubs are tested.** Every `NotImplementedError` path has a test asserting it throws. When a future plan implements one, it replaces the stub test with behavioral tests (spec §13).
- **Adapter import is the one unknown.** Task 8 Step 1 pins down app-core's node SQLite adapter import; everything DB-related depends on getting that exact name/signature right. Do that step carefully before writing DB-backed tests.
