# Plan: Make eldrin-core Provider-Agnostic

## Context

eldrin-core is currently deployable only to Cloudflare Workers (via `worker/index.ts`) and as a standalone Bun binary (via `server/index.ts`). The goal is to make it deployable to **Cloudflare, AWS, Azure, and GCP** — both serverless and container targets — with a **unified, pluggable authentication system** supporting multiple identity providers simultaneously.

The codebase is already well-architected: `core/` contains all platform-agnostic business logic, and both entry points import the same route handlers. The main problems are: (1) **route duplication** between worker and server, (2) **auth is hardcoded to local email/password**, and (3) **Cloudflare-specific entry points and build**.

**Approach**: Unify on Hono as the single HTTP layer. Extract a shared `createApp()` factory. Add a pluggable auth provider system with account linking. Create thin provider adapters per cloud.

---

## Phase 0: Testing Foundation

eldrin-app-core already has Vitest (`vitest ^2.0.0`) with 3 co-located `.test.ts` files, `globals: true`, and `environment: 'node'`. eldrin-core has **zero** testing infrastructure. This phase sets up testing for eldrin-core and establishes shared patterns.

### 0.1 Add Vitest to eldrin-core

Install: `vitest`, `@vitest/coverage-v8`

Create `eldrin-core/vitest.config.ts`:
```typescript
export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['core/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['core/**/*.ts'],
      exclude: ['core/**/*.test.ts'],
    },
  },
});
```

Add scripts to `package.json`:
```json
"test": "vitest",
"test:run": "vitest run",
"test:coverage": "vitest run --coverage"
```

### 0.2 Create test utilities — `core/test-utils/`

**`core/test-utils/mock-db.ts`** (~80 lines) — In-memory `DatabaseAdapter` mock backed by a simple Map, supporting `prepare().bind().all/first/run()`. Sufficient for unit tests without real SQLite.

**`core/test-utils/mock-storage.ts`** (~40 lines) — In-memory `StorageAdapter` for testing file operations.

**`core/test-utils/mock-cache.ts`** (~30 lines) — In-memory `CacheAdapter` for testing cache behavior.

**`core/test-utils/mock-logger.ts`** (~20 lines) — Captures log entries for assertion.

**`core/test-utils/fixtures.ts`** (~60 lines) — Factory functions for test data:
- `createTestUser()` — returns a `UserRecord` with sensible defaults
- `createTestUserWithPermissions()` — returns `UserWithPermissions`
- `createTestJWTPayload()` — returns a valid `JWTPayload`
- `createTestApp()` — returns a `PlatformApp`

**`core/test-utils/hono-helpers.ts`** (~40 lines) — Helpers for testing Hono routes:
- `createTestApp(overrides?)` — returns a configured Hono app with mock db/services
- `makeAuthenticatedRequest(app, method, path, options?)` — adds valid JWT header

### 0.3 Phase gate tests

Every subsequent phase includes a **"Tests"** subsection. The rule: **all phase tests must pass before proceeding to the next phase.** Tests are run with `vitest run` and must exit 0.

### 0.4 Playwright E2E setup

Install: `@playwright/test`

Create `eldrin-core/playwright.config.ts`:
```typescript
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  webServer: {
    command: 'npm run dev',
    url: 'http://localhost:4000',
    reuseExistingServer: !process.env.CI,
  },
  use: {
    baseURL: 'http://localhost:4000',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
});
```

Add scripts to `package.json`:
```json
"e2e": "playwright test",
"e2e:ui": "playwright test --ui"
```

Create `e2e/` directory with test files organized by feature area.

### 0.5 E2E test utilities — `e2e/helpers/`

**`e2e/helpers/auth.ts`** (~30 lines):
- `loginAsAdmin(page)` — fills email/password form with default admin credentials, submits
- `loginAs(page, email, password)` — fills custom credentials
- `logout(page)` — clicks logout

**`e2e/helpers/api.ts`** (~20 lines):
- `apiLogin(request)` — gets auth token via API (for API-only tests)
- `authenticatedRequest(request, token)` — adds Authorization header

**`e2e/helpers/setup.ts`** (~20 lines):
- `resetDatabase()` — resets DB to clean state before test suite (calls API or shell)

### 0.6 Baseline E2E tests — `e2e/baseline.spec.ts`

These tests validate the app works before any changes. They serve as the regression baseline that must continue passing after every phase.

```typescript
// ~10 cases
- App loads at / (redirects to /login if not authenticated)
- Login page renders with email/password form
- Login with valid credentials → redirects to dashboard
- Login with invalid credentials → shows error message
- Dashboard loads after successful login
- Logout returns to login page
- Protected API routes return 401 without auth
- Health endpoint returns 200
- Static assets served correctly
- Page title is correct
```

### 0.7 Tests for Phase 0

```
core/test-utils/mock-db.test.ts        — verify mock DB supports prepare/bind/all/first/run
core/test-utils/fixtures.test.ts       — verify factory functions return valid shapes
core/test-utils/hono-helpers.test.ts   — verify test app creation and auth request helper
e2e/baseline.spec.ts                   — baseline E2E tests (10 cases)
```

**Gate**: `npm run test:run` passes with all test utility tests green. `npm run e2e` passes with baseline E2E tests green.

---

## Phase 1: SDK Fixes (eldrin-app-core)

Fix migration runner type signatures from `D1Database` to the existing `DatabaseAdapter` interface. Type-only change — runtime behavior is identical.

### 1.1 Fix `eldrin-app-core/src/migrations/runner.ts`

- **Line 41**: `db: D1Database` → `db: DatabaseAdapter`
- **Line 142**: `const batch: D1PreparedStatement[]` → `const batch: PreparedStatement[]`
- **Line 210** (`getMigrationStatus`): `db: D1Database` → `db: DatabaseAdapter`
- Add import: `import type { DatabaseAdapter, PreparedStatement } from '../database/interface';`

### 1.2 Fix `eldrin-app-core/src/migrations/rollback.ts`

- **Line 30**: `db: D1Database` → `db: DatabaseAdapter`
- **Line 121**: `const batch: D1PreparedStatement[]` → `const batch: PreparedStatement[]`
- Add import: `import type { DatabaseAdapter, PreparedStatement } from '../database/interface';`

### 1.3 Add Turso/libSQL adapter — `eldrin-app-core/src/database/turso.ts`

The existing SDK has D1 (Cloudflare), SQLite (Bun/local file), and PostgreSQL adapters. The SQLite adapter depends on `bun:sqlite` and a local file path — this cannot work in serverless environments (Lambda, Azure Functions, Cloud Functions) which have no persistent filesystem.

Turso (libSQL) is an SQLite-compatible database accessible over HTTP with a generous free tier (9GB storage, 500 databases). Adding a TursoAdapter gives every cloud provider a free/cheap SQLite option alongside paid PostgreSQL.

```typescript
export class TursoAdapter implements DatabaseAdapter {
  constructor(private url: string, private authToken: string);
  prepare(query: string): PreparedStatement;
  async exec(query: string): Promise<void>;
  async batch<T>(statements: PreparedStatement[]): Promise<DatabaseResults<T>[]>;
}

export function createTursoAdapter(url: string, authToken: string): DatabaseAdapter;
```

Implementation uses Turso's HTTP API (`POST /v2/pipeline`) — no native dependencies, works in Workers, Lambda, Azure Functions, Cloud Functions, Node, and Bun.

~80 lines. Follows the same pattern as `postgres.ts`:
- Converts `?` placeholders to positional format if needed
- Maps Turso's JSON response to `DatabaseResults<T>`
- Supports `batch()` for transactional multi-statement execution

### 1.4 Update database factory — `eldrin-app-core/src/database/factory.ts`

Add Turso to `createDatabaseAdapter()`:
```typescript
case 'turso':
  const { createTursoAdapter } = await import('./turso');
  return createTursoAdapter(config.url, config.authToken);
```

Add to `createDatabaseFromEnv()`:
```typescript
if (env.TURSO_URL && env.TURSO_AUTH_TOKEN) {
  return createTursoAdapter(env.TURSO_URL, env.TURSO_AUTH_TOKEN);
}
```

### 1.5 Database strategy per provider

Every provider gets two database options — cheap/free (SQLite-family) and scalable (PostgreSQL):

| Provider | Target | Free/Cheap (SQLite) | Paid/Scalable (PostgreSQL) |
|----------|--------|--------------------|-----------------------|
| Cloudflare | Workers | D1 (native, free tier: 5GB) | Hyperdrive + external PG |
| AWS | Lambda | SQLite on EFS mount ($0.30/GB/mo) or Turso | RDS PostgreSQL / Aurora Serverless |
| AWS | ECS Fargate | SQLite on EFS mount or Turso | RDS PostgreSQL |
| Azure | Functions | SQLite on Azure Files mount (SMB, $0.06/GB/mo) or Turso | Azure PostgreSQL Flexible Server |
| Azure | Container Apps | SQLite on Azure Files mount or Turso | Azure PostgreSQL Flexible Server |
| GCP | Cloud Functions (2nd gen) | SQLite on NFS via Filestore or Turso | Cloud SQL PostgreSQL |
| GCP | Cloud Run | SQLite on NFS via Filestore or GCS FUSE or Turso | Cloud SQL PostgreSQL |
| Standalone | Bun process | SQLite file (local, free) | External PostgreSQL |

**Mount options per cloud**:
- **AWS EFS**: Elastic File System, NFS v4.1, $0.30/GB/month. Lambda mounts via VPC + access point. ECS mounts via task definition.
- **Azure Files**: SMB/NFS file shares, $0.06/GB/month (Hot tier). Functions mount via `WEBSITE_CONTENTAZUREFILECONNECTIONSTRING`. Container Apps mount via volume config.
- **GCP Filestore**: Managed NFS, minimum 1TB Basic HDD (~$60/mo) or 10GB-100GB with **Zonal** tier. Cloud Run and Cloud Functions (2nd gen) mount via VPC connector + NFS volume. Alternative: GCS FUSE (object storage as filesystem) — cheaper but higher latency.
- **Turso**: Available on all providers as the zero-infrastructure option. Free tier: 9GB, 500 databases. No VPC or mount points needed.

**Note on SQLite adapters by runtime**:
- The existing `SQLiteAdapter` uses `bun:sqlite` — works in Bun (standalone, Bun-based containers)
- AWS Lambda runs on Node.js, not Bun. We need a **Node.js-compatible SQLite adapter** using `better-sqlite3` for EFS-mounted SQLite on Lambda
- Azure Functions and GCP Cloud Functions also run Node.js, so the same adapter applies if a filesystem mount is available
- Alternative: use `@libsql/client` which provides both local file mode (SQLite) and remote mode (Turso) from a single package — works in Node.js, Bun, and Workers

### 1.5b Add Node.js SQLite adapter — `eldrin-app-core/src/database/sqlite-node.ts`

For Lambda + EFS and other Node.js container environments:

```typescript
export class NodeSQLiteAdapter implements DatabaseAdapter {
  constructor(private db: BetterSqlite3.Database);
  // Same interface as SQLiteAdapter but uses better-sqlite3 instead of bun:sqlite
}

export function createNodeSQLiteAdapter(dbPath: string): DatabaseAdapter {
  const Database = require('better-sqlite3');
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  return new NodeSQLiteAdapter(db);
}
```

~60 lines. Add `better-sqlite3` as an optional peer dependency.

Update factory auto-detection:
```typescript
// If running in Bun → use bun:sqlite
// If running in Node.js → use better-sqlite3
// DATABASE_TYPE=sqlite auto-selects based on runtime
```

Selection: Determined by `DATABASE_TYPE` env var (`d1`, `sqlite`, `turso`, `postgres`) and auto-detected by the existing `createDatabaseFromEnv()` factory. The `sqlite` type auto-selects `bun:sqlite` or `better-sqlite3` based on the detected runtime.

### 1.6 Tests

Existing tests in eldrin-app-core must continue passing:
```
eldrin-app-core/src/migrations/sql-parser.test.ts   (17 cases)
eldrin-app-core/src/migrations/checksum.test.ts      (8 cases)
eldrin-app-core/src/middleware/matcher.test.ts        (20 cases)
```

New adapter tests:

**`eldrin-app-core/src/database/sqlite-node.test.ts`** (~6 cases):
- Creates database file at specified path
- WAL mode and foreign keys enabled
- `prepare().bind().all()` returns results
- `prepare().bind().first()` returns first row
- `prepare().bind().run()` executes write
- `batch()` executes multiple statements atomically

**`eldrin-app-core/src/database/turso.test.ts`** (~10 cases, mocked HTTP):
- `prepare().bind().all()` sends correct HTTP request to Turso pipeline API
- `prepare().bind().first()` returns first row
- `prepare().bind().run()` executes write and returns changes count
- `batch()` sends all statements in single pipeline request
- Handles Turso error responses (auth failure, DB not found)
- Placeholder binding works correctly
- Empty result set returns `{ results: [] }`
- Connection uses auth token in Authorization header
- URL validation (must be https libsql:// or https://)

**`eldrin-app-core/src/database/factory.test.ts`** (~7 cases):
- `DATABASE_TYPE=turso` + `TURSO_URL` + `TURSO_AUTH_TOKEN` creates TursoAdapter
- `DATABASE_TYPE=sqlite` + `DATABASE_PATH` in Bun creates SQLiteAdapter (bun:sqlite)
- `DATABASE_TYPE=sqlite` + `DATABASE_PATH` in Node creates NodeSQLiteAdapter (better-sqlite3)
- `DATABASE_TYPE=postgres` + `DATABASE_URL` creates PostgresAdapter
- Auto-detection from env bindings works
- Runtime detection correctly identifies Bun vs Node.js
- Missing required env vars throws descriptive error

**Gate**: `cd eldrin-app-core && npm run test:run` passes (45 existing + ~23 new = ~68 cases). `npm run typecheck` passes (verifies `D1Database` references are gone).

---

## Phase 2: Unified Hono App (`core/app.ts`)

Create a factory function returning a fully configured Hono app with all routes, eliminating the duplication between `worker/index.ts` (323 lines) and `server/index.ts` (451 lines).

### 2.1 Create `eldrin-core/core/app.ts`

```typescript
export type AppVariables = {
  db: DatabaseAdapter;
  jwtSecret: string;
  auth?: JWTPayload;
  deploymentMode: 'local' | 'cloud';
};
export type AppEnv = { Variables: AppVariables };

export function createApp(): Hono<AppEnv> { ... }
```

**Routes**: All ~35 routes from `worker/index.ts` with permission checks from the worker pattern (server was missing these — bug fix). Reference:
- `eldrin-core/worker/index.ts` — complete permission checks per route
- `eldrin-core/server/index.ts` — Hono route patterns
- `eldrin-core/core/routes/index.ts` — all handler exports

### 2.2 Update `eldrin-core/core/index.ts`

Add: `export { createApp, type AppVariables, type AppEnv } from './app';`

### 2.3 Tests — `core/app.test.ts`

```typescript
// Route registration tests (~15 cases)
- createApp() returns a Hono instance
- All expected routes are registered (GET /api/health, POST /api/auth/login, etc.)
- Public routes return 200 without auth (GET /api/health)
- Protected routes return 401 without auth token
- Protected routes return 200 with valid auth token
- Permission-guarded routes return 403 with insufficient permissions
- Route handlers receive db from context variables
- Unknown routes return 404

// Route parity tests (~5 cases)
- Every route in worker/index.ts has a corresponding route in createApp()
- Permission checks match between worker and unified app
```

**E2E regression**: `npm run e2e -- e2e/baseline.spec.ts` — all baseline tests still pass after route consolidation.

**Gate**: `npm run test:run -- core/app.test.ts` passes (20 unit tests). `npm run e2e -- e2e/baseline.spec.ts` passes (10 E2E).

---

## Phase 3: Pluggable Auth Provider System

### Current state

All auth is local: users in `users` table with PBKDF2 password hashes, HS256 JWT signed with local secret, RBAC from local tables. Key files:
- `core/auth/jwt.ts` — HS256 token creation/verification (Web Crypto)
- `core/auth/password.ts` — PBKDF2 hashing
- `core/auth/middleware.ts` — Bearer token extraction, `checkAuth()`
- `core/auth/permissions.ts` — RBAC calculation from DB (already uses `DatabaseAdapter`)
- `core/auth/types.ts` — `JWTPayload`, `UserWithPermissions`, etc.
- `core/routes/auth.ts` — login/logout/me handlers
- `src/stores/authStore.ts` — frontend auth state
- `src/pages/Login.tsx` — email/password form

### Design principles

1. **External IdPs handle authentication** (who are you?), Eldrin handles **authorization** (what can you do?)
2. **Multiple providers simultaneously** — login page shows all enabled options
3. **Account linking** — one user can have multiple linked identities (local + Entra + Google)
4. **JIT user creation with PENDING role** — new external users require admin approval before gaining access
5. **Both OIDC flows** — auth code (server-side) for full deployments, PKCE (client-side) for SPAs
6. **Eldrin JWT remains the internal token** — after IdP authentication, Eldrin issues its own JWT with embedded permissions

### 3.1 Auth provider interface — `core/auth/providers/interface.ts`

```typescript
export type AuthProviderType = 'local' | 'oidc' | 'entra' | 'google' | 'cognito';

export interface AuthProviderConfig {
  id: string;
  type: AuthProviderType;
  name: string;            // Display name ("Microsoft Entra", "Google", etc.)
  enabled: boolean;
  displayOrder: number;
  config: OIDCProviderConfig | LocalProviderConfig;
}

export interface OIDCProviderConfig {
  issuer: string;           // OIDC discovery URL
  clientId: string;
  clientSecret?: string;    // Required for auth code flow
  scopes: string[];         // Default: ['openid', 'profile', 'email']
  redirectUri: string;
  jwksUri?: string;         // Auto-discovered if not set
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
}

export interface LocalProviderConfig {
  // No additional config — uses DB users + JWT_SECRET
}

export interface AuthIdentity {
  subject: string;          // IdP unique identifier
  email: string;
  firstName?: string;
  lastName?: string;
  groups?: string[];        // IdP groups (for future role mapping)
  rawClaims: Record<string, unknown>;
}

export interface AuthProvider {
  type: AuthProviderType;

  /** Validate an ID token from this provider */
  validateToken(idToken: string): Promise<AuthIdentity | null>;

  /** Get authorization URL for auth code flow */
  getAuthorizationUrl?(state: string, nonce: string, redirectUri: string): string;

  /** Exchange auth code for tokens (server-side flow) */
  exchangeCode?(code: string, redirectUri: string): Promise<{ idToken: string; accessToken: string }>;

  /** Get login config for frontend */
  getLoginConfig(): { type: AuthProviderType; clientId?: string; issuer?: string; scopes?: string[] };
}
```

### 3.2 Provider implementations

**`core/auth/providers/local.ts`** — Wraps existing email/password logic. `validateToken` verifies HS256 JWT. Login is handled by existing `handleLogin` route.

**`core/auth/providers/oidc-base.ts`** (~150 lines) — Base OIDC provider:
- Fetches OIDC discovery document (`.well-known/openid-configuration`)
- Caches JWKS keys (with TTL refresh)
- Validates ID tokens using RS256/RS384/RS512 against JWKS
- Builds `AuthIdentity` from standard OIDC claims (`sub`, `email`, `name`, `given_name`, `family_name`)
- Implements `getAuthorizationUrl()` and `exchangeCode()`

**`core/auth/providers/entra.ts`** (~40 lines) — Extends OIDC base:
- Sets issuer to `https://login.microsoftonline.com/{tenantId}/v2.0`
- Maps Entra-specific claims (`preferred_username`, `groups` array)
- Supports both Entra External ID and workforce identity

**`core/auth/providers/google.ts`** (~30 lines) — Extends OIDC base:
- Sets issuer to `https://accounts.google.com`
- Maps Google-specific claims (`hd` for hosted domain)

**`core/auth/providers/cognito.ts`** (~30 lines) — Extends OIDC base:
- Sets issuer to `https://cognito-idp.{region}.amazonaws.com/{userPoolId}`
- Maps Cognito-specific claims (`cognito:groups`)

**`core/auth/providers/oidc-generic.ts`** (~10 lines) — Direct use of OIDC base, no custom claim mapping. Catch-all for Keycloak, Auth0, Okta, etc.

### 3.3 Provider registry — `core/auth/providers/registry.ts`

```typescript
export class AuthProviderRegistry {
  private providers: Map<string, AuthProvider> = new Map();

  /** Register a provider instance */
  register(id: string, provider: AuthProvider): void;

  /** Get provider by ID */
  get(id: string): AuthProvider | undefined;

  /** Get all enabled providers (for login page) */
  getEnabled(): Array<{ id: string; provider: AuthProvider }>;

  /** Initialize from database config */
  static async fromDatabase(db: DatabaseAdapter): Promise<AuthProviderRegistry>;
}
```

Initialized once at app startup. Reads `auth_providers` table, instantiates the correct provider class per row.

### 3.4 JWKS token validation — `core/auth/jwks.ts`

```typescript
/** Fetch and cache JWKS keys from an IdP */
export class JWKSClient {
  constructor(jwksUri: string, cacheTtlMs?: number);
  getSigningKey(kid: string): Promise<CryptoKey>;
}

/** Verify an RS256 JWT against JWKS */
export async function verifyJWKSToken(token: string, jwksClient: JWKSClient): Promise<Record<string, unknown> | null>;
```

Uses Web Crypto API (`crypto.subtle.importKey`, `crypto.subtle.verify`) — works in Workers, Node, Bun.

### 3.5 Account linking — `core/auth/account-linking.ts`

```typescript
/** Find or create user from external identity */
export async function resolveExternalIdentity(
  db: DatabaseAdapter,
  providerId: string,
  identity: AuthIdentity
): Promise<{ user: UserRecord; isNew: boolean; isPending: boolean }>;

/** Link an additional identity to existing user */
export async function linkIdentity(
  db: DatabaseAdapter,
  userId: string,
  providerId: string,
  identity: AuthIdentity
): Promise<void>;

/** Get all identities for a user */
export async function getUserIdentities(
  db: DatabaseAdapter,
  userId: string
): Promise<UserIdentityRecord[]>;

/** Unlink an identity */
export async function unlinkIdentity(
  db: DatabaseAdapter,
  userId: string,
  identityId: string
): Promise<void>;
```

**Account resolution logic**:
1. Look up by `(provider_id, subject)` in `user_identities` → existing linked user
2. If not found, look up by email in `users` table → auto-link if email matches
3. If not found, create new user with `status = 'pending'`, assign PENDING role
4. Return user + whether approval is needed

### 3.6 New database migration — `migrations/YYYYMMDD000001-create-auth-provider-tables.sql`

```sql
-- Auth provider configuration
CREATE TABLE IF NOT EXISTS auth_providers (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,             -- 'local', 'oidc', 'entra', 'google', 'cognito'
  name TEXT NOT NULL,             -- Display name
  config TEXT NOT NULL DEFAULT '{}', -- JSON config
  enabled INTEGER DEFAULT 1,
  display_order INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- User identity links (account linking)
CREATE TABLE IF NOT EXISTS user_identities (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider_id TEXT NOT NULL REFERENCES auth_providers(id),
  subject TEXT NOT NULL,          -- IdP unique identifier
  email TEXT,
  display_name TEXT,
  raw_claims TEXT,                -- JSON
  linked_at INTEGER NOT NULL,
  last_used_at INTEGER,
  UNIQUE(provider_id, subject)
);

-- Add status column to users table
ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active';
-- Possible values: 'active', 'pending', 'disabled'

-- Seed default local provider
INSERT INTO auth_providers (id, type, name, config, enabled, display_order, created_at, updated_at)
VALUES ('local', 'local', 'Email & Password', '{}', 1, 0, strftime('%s','now')*1000, strftime('%s','now')*1000);
```

### 3.7 New auth routes — `core/routes/auth-providers.ts`

| Route | Method | Auth | Purpose |
|-------|--------|------|---------|
| `/api/auth/providers` | GET | No | List enabled providers for login page |
| `/api/auth/providers/:id/authorize` | GET | No | Redirect to IdP (auth code flow) |
| `/api/auth/callback` | GET | No | OIDC callback — exchange code, resolve user, issue JWT |
| `/api/auth/token-exchange` | POST | No | Exchange IdP token for Eldrin JWT (PKCE flow) |
| `/api/auth/identities` | GET | Yes | Get current user's linked identities |
| `/api/auth/link` | POST | Yes | Link additional IdP to current user |
| `/api/auth/link/:identityId` | DELETE | Yes | Unlink an identity |

### 3.8 Modify existing auth routes — `core/routes/auth.ts`

- `handleLogin` — unchanged (local provider only)
- `handleAuthMe` — unchanged (works with any Eldrin JWT)
- `handleLogout` — unchanged

### 3.9 New user management routes — update `core/routes/users.ts`

| Route | Method | Permission | Purpose |
|-------|--------|------------|---------|
| `/api/users/pending` | GET | `users:read` | List users awaiting approval |
| `/api/users/:userId/approve` | POST | `users:write` | Approve pending user (sets status to active, assigns default role) |
| `/api/users/:userId/reject` | POST | `users:write` | Reject pending user (sets status to disabled) |

### 3.10 Modify auth middleware — `core/auth/middleware.ts`

The `checkAuth()` function currently only handles HS256 local JWTs. After this change:
1. All Eldrin internal JWTs remain HS256 (signed by `JWT_SECRET`)
2. The middleware verifies the **Eldrin JWT** (not the IdP token)
3. No middleware change needed — the OIDC flow exchanges IdP tokens for Eldrin JWTs at the `/callback` or `/token-exchange` endpoints

**Key insight**: The middleware doesn't need to change because by the time a request reaches a protected route, the client already has an Eldrin JWT (obtained via local login OR IdP flow → Eldrin JWT exchange).

### 3.11 Frontend changes

**`src/pages/Login.tsx`** — Replace hardcoded email/password form:
1. On mount, fetch `GET /api/auth/providers` to get enabled providers
2. Show "Sign in with {provider}" buttons for each OIDC provider
3. Show email/password form if local provider is enabled
4. OIDC buttons either redirect (auth code) or use popup (PKCE)

**`src/pages/AuthCallback.tsx`** (NEW) — OIDC callback handler:
1. Extracts `code` and `state` from URL params
2. Calls `GET /api/auth/callback?code=...&state=...`
3. Receives Eldrin JWT + user data
4. If user is pending → show "Awaiting approval" message
5. If approved → store token, redirect to dashboard

**`src/stores/authStore.ts`** — Extend with:
- `loginWithProvider(providerId: string)` — initiates OIDC flow
- `handleCallback(code: string, state: string)` — completes OIDC flow
- `exchangeToken(providerId: string, idToken: string)` — PKCE flow

**`src/pages/settings/AccountLinking.tsx`** (NEW) — Manage linked identities:
- Show current linked providers
- "Link {provider}" buttons for unlinked providers
- "Unlink" buttons (with guard: can't unlink last identity)

**`src/pages/settings/users/`** — Add pending user management:
- Show pending users tab/filter
- Approve/reject actions

### 3.12 Tests

**`core/auth/providers/registry.test.ts`** (~10 cases):
- Register and retrieve provider by ID
- `getEnabled()` returns only enabled providers in display order
- `get()` returns undefined for unknown provider ID
- `fromDatabase()` constructs providers from mock DB rows

**`core/auth/providers/local.test.ts`** (~8 cases):
- `validateToken()` accepts valid HS256 JWT
- `validateToken()` rejects expired JWT
- `validateToken()` rejects malformed token
- `getLoginConfig()` returns type 'local'

**`core/auth/providers/oidc-base.test.ts`** (~12 cases):
- `getAuthorizationUrl()` builds correct URL with state, nonce, scopes
- `exchangeCode()` sends correct POST to token endpoint (mock fetch)
- `validateToken()` verifies RS256 signature against JWKS (mock JWKS)
- `validateToken()` rejects expired ID token
- `validateToken()` rejects token with wrong audience
- `validateToken()` rejects token with wrong issuer
- OIDC discovery document is fetched and cached
- JWKS keys are cached and refreshed after TTL

**`core/auth/providers/entra.test.ts`** (~5 cases):
- Issuer URL constructed correctly from tenant ID
- Entra-specific claims mapped (`preferred_username`, `groups`)
- Both workforce and External ID tenant formats supported

**`core/auth/providers/google.test.ts`** (~3 cases):
- Issuer URL is `https://accounts.google.com`
- `hd` claim mapped for hosted domain

**`core/auth/providers/cognito.test.ts`** (~3 cases):
- Issuer URL constructed from region + user pool ID
- `cognito:groups` claim mapped

**`core/auth/jwks.test.ts`** (~8 cases):
- `JWKSClient` fetches keys from JWKS URI (mock fetch)
- `getSigningKey()` returns CryptoKey for known kid
- `getSigningKey()` throws for unknown kid
- Keys are cached until TTL expires
- Cache refresh fetches new keys
- `verifyJWKSToken()` verifies valid RS256 token
- `verifyJWKSToken()` rejects tampered token
- `verifyJWKSToken()` rejects token signed with wrong key

**`core/auth/account-linking.test.ts`** (~10 cases):
- `resolveExternalIdentity()` returns existing linked user
- `resolveExternalIdentity()` auto-links by email match
- `resolveExternalIdentity()` creates new pending user when no match
- New user gets status='pending' and empty permissions
- `linkIdentity()` creates user_identities record
- `linkIdentity()` rejects duplicate (same provider + subject)
- `unlinkIdentity()` removes identity record
- `unlinkIdentity()` rejects unlinking last identity
- `getUserIdentities()` returns all linked identities for user

**`core/routes/auth-providers.test.ts`** (~12 cases):
- `GET /api/auth/providers` returns list of enabled providers
- `GET /api/auth/providers` excludes disabled providers
- `GET /api/auth/providers/:id/authorize` redirects to IdP
- `GET /api/auth/callback` exchanges code and issues Eldrin JWT
- `GET /api/auth/callback` creates pending user for new external user
- `POST /api/auth/token-exchange` exchanges IdP token for Eldrin JWT
- `POST /api/auth/token-exchange` rejects invalid IdP token
- `GET /api/auth/identities` returns current user's linked identities (authed)
- `GET /api/auth/identities` returns 401 without auth
- `POST /api/auth/link` links new identity to current user
- `DELETE /api/auth/link/:id` unlinks identity
- `DELETE /api/auth/link/:id` rejects unlinking last identity

**`core/routes/users.test.ts`** (extend, ~6 cases):
- `GET /api/users/pending` returns only pending users
- `POST /api/users/:id/approve` sets status to active
- `POST /api/users/:id/approve` assigns default role
- `POST /api/users/:id/reject` sets status to disabled
- Approve/reject require `users:write` permission
- Approve/reject return 404 for non-existent user

**E2E tests — `e2e/auth/`**:

**`e2e/auth/local-login.spec.ts`** (~8 cases):
- Login page shows email/password form when local provider enabled
- Successful login with admin credentials → dashboard
- Failed login shows error message
- Empty email/password shows validation error
- Logout clears session, redirects to login
- Refreshing after login preserves session (sessionStorage token)
- Multiple failed attempts still allow eventual success
- Login redirect: accessing protected page while unauthenticated → login → original page

**`e2e/auth/providers.spec.ts`** (~6 cases):
- Login page fetches and displays enabled providers
- Provider buttons appear for each enabled OIDC provider
- Local provider shows email/password form
- Disabled providers are not shown
- Provider display order matches configuration
- Loading state shown while fetching providers

**`e2e/auth/pending-user.spec.ts`** (~5 cases):
- New external user (mocked OIDC) sees "Awaiting approval" message
- Pending user cannot access dashboard
- Admin sees pending user in user management
- Admin approves pending user → user can now log in
- Admin rejects pending user → user cannot log in

**`e2e/auth/account-linking.spec.ts`** (~4 cases):
- Authenticated user can view linked identities in settings
- "Link" button shown for unlinked providers
- "Unlink" button shown for linked providers
- Cannot unlink last identity (button disabled or shows warning)

**E2E regression**: `npm run e2e -- e2e/baseline.spec.ts` — all baseline tests still pass.

**Gate**: `npm run test:run -- core/auth/ core/routes/auth-providers.test.ts core/routes/users.test.ts` — all ~77 unit tests pass. `npm run e2e -- e2e/auth/` — all ~23 E2E auth tests pass. `npm run e2e -- e2e/baseline.spec.ts` — regression tests pass.

### 3.13 Auth provider configuration

Providers are configured via environment variables and/or `auth_providers` DB table:

```
# Enable Entra ID
AUTH_ENTRA_ENABLED=true
AUTH_ENTRA_TENANT_ID=your-tenant-id
AUTH_ENTRA_CLIENT_ID=your-client-id
AUTH_ENTRA_CLIENT_SECRET=your-client-secret

# Enable Google
AUTH_GOOGLE_ENABLED=true
AUTH_GOOGLE_CLIENT_ID=your-client-id
AUTH_GOOGLE_CLIENT_SECRET=your-client-secret

# Enable Cognito
AUTH_COGNITO_ENABLED=true
AUTH_COGNITO_USER_POOL_ID=your-pool-id
AUTH_COGNITO_REGION=us-east-1
AUTH_COGNITO_CLIENT_ID=your-client-id
```

On startup, the system reads env vars and upserts into `auth_providers` table. This allows both env-based config (12-factor) and DB-based config (admin UI in future).

---

## Phase 4: Cloud Provider Adapters

### 4.1 Create `eldrin-core/providers/cloudflare/index.ts` (~30 lines)

- Wrapper Hono app with `{ Bindings: CloudflareBindings }`
- Middleware: create D1Adapter from `c.env.DB`, set jwtSecret, deploymentMode
- Mount `createApp()` via `wrapper.route('/', coreApp)`
- Fallback: `c.env.ASSETS.fetch(c.req.raw)`

### 4.2 Move `wrangler.jsonc` to `providers/cloudflare/wrangler.jsonc`

### 4.3 Create `providers/aws/lambda.ts` (~25 lines)

- `hono/aws-lambda` adapter
- DB from `process.env.DATABASE_URL`
- `export const handler = handle(app)`

### 4.4 Create `providers/aws/ecs/entrypoint.ts` + `Dockerfile`

- `@hono/node-server` + `serveStatic`
- PostgreSQL or SQLite from env

### 4.5 Create `providers/azure/functions.ts` + `host.json`

- Azure Functions adapter
- Same DB pattern

### 4.6 Create `providers/azure/container/entrypoint.ts` + `Dockerfile`

### 4.7 Create `providers/gcp/cloud-functions.ts`

### 4.8 Create `providers/gcp/cloud-run/entrypoint.ts` + `Dockerfile` + `app.yaml`

### 4.9 Move standalone server to `providers/standalone/`

Files: `index.ts`, `config.ts`, `migrations.ts`, `embedded-assets.ts`

### 4.10 Tests

**`providers/cloudflare/index.test.ts`** (~6 cases):
- Wrapper app sets `db` variable from D1 binding
- Wrapper app sets `jwtSecret` from env
- Wrapper app sets `deploymentMode` to 'cloud'
- Wrapper app mounts core app routes
- API routes are accessible through wrapper
- Static asset fallback works

**`providers/aws/lambda.test.ts`** (~4 cases):
- Handler exports a valid Lambda handler function
- DB adapter created from environment variables
- Request/response mapping works (API Gateway event → Hono → Lambda response)
- Auth headers forwarded correctly

**`providers/standalone/index.test.ts`** (~4 cases):
- Server starts on configured port
- DB adapter created from config
- Migration runner executes on startup
- Graceful shutdown works

**Gate**: `npm run test:run -- providers/` — all ~14 provider adapter tests pass.

---

## Phase 5: Build System

### 5.1 Create `vite.config.base.ts`

Frontend-only: React + Tailwind, resolve aliases. No Cloudflare plugin.

### 5.2 Update `vite.config.ts`

Extends base, adds `cloudflare()` plugin. Backward compatible.

### 5.3 Update `package.json`

Add per-target build scripts:
```
build:frontend, build:cloudflare, build:aws-lambda, build:aws-ecs,
build:azure-func, build:gcp-cf, build:gcp-run, build:standalone
```

Add dev dependencies: `@hono/node-server`, `tsup`

### 5.4 Backward-compatibility shims

- `worker/index.ts` → re-export from `providers/cloudflare/`
- `server/index.ts` → re-export from `providers/standalone/`

### 5.5 Tests

Build verification tests (shell-based, run via `vitest` calling build scripts):

**`build.test.ts`** (~8 cases):
- `npm run build:frontend` produces `dist/` with index.html
- `npm run build:cloudflare` produces valid worker bundle
- `npm run build:aws-lambda` produces `dist/aws-lambda/index.js`
- `npm run build:standalone` produces executable binary
- Backward-compat shims: `worker/index.ts` re-exports resolve correctly
- Backward-compat shims: `server/index.ts` re-exports resolve correctly
- TypeScript compilation succeeds with no errors (`npm run typecheck`)
- No Cloudflare-specific imports in `core/` directory (grep validation)

**Gate**: `npm run test:run -- build.test.ts` passes. All target builds succeed.

---

## Phase 6: IaC Templates

Templates that provision **all** infrastructure services from Phases 4-18 per cloud provider. See the "IaC Template Coverage" section in Infrastructure Dependencies for full service lists.

| File | Format | Services Provisioned |
|------|--------|---------------------|
| `providers/aws/template.yaml` | SAM/CloudFormation | Lambda, API Gateway, RDS, S3, SQS, ElastiCache, Secrets Manager, SES, IAM, VPC |
| `providers/aws/ecs/template.yaml` | SAM/CloudFormation | ECS Fargate, ALB, RDS, S3, SQS, ElastiCache, Secrets Manager, ECR, VPC |
| `providers/azure/bicep/main.bicep` | Bicep | Functions/Container Apps, PostgreSQL, Blob Storage, Key Vault, Service Bus, Redis, Comm Services, App Insights |
| `providers/gcp/terraform/main.tf` | Terraform | Cloud Functions/Run, Cloud SQL, Cloud Storage, Secret Manager, Cloud Tasks, Memorystore, Artifact Registry, VPC |
| `providers/cloudflare/wrangler.jsonc` | Wrangler config | Workers, D1, R2, KV, Queues, secrets, custom domains |

### 6.1 Tests

**`iac.test.ts`** (~6 cases):
- SAM template validates (`sam validate`)
- Bicep template compiles (`az bicep build`)
- Terraform config validates (`terraform validate`)
- Wrangler config is valid JSON(C) and contains all required bindings
- All templates reference services matching the provider-service matrix
- No hardcoded credentials in any template

**Gate**: `npm run test:run -- iac.test.ts` passes.

---

## Phase 7: Storage Abstraction Layer

Abstract file/blob storage behind a unified interface so apps can store uploads, exports, and attachments on any cloud.

### 7.1 Storage interface — `core/storage/interface.ts`

```typescript
export interface StorageAdapter {
  put(key: string, data: ReadableStream | Uint8Array, opts?: PutOptions): Promise<StorageObject>;
  get(key: string): Promise<StorageObject | null>;
  delete(key: string): Promise<void>;
  list(prefix: string, opts?: ListOptions): Promise<StorageListResult>;
  getSignedUrl(key: string, expiresIn: number): Promise<string>;
}

export interface StorageObject {
  key: string;
  size: number;
  contentType: string;
  lastModified: number;
  body: ReadableStream;
}

export interface PutOptions {
  contentType?: string;
  metadata?: Record<string, string>;
}

export interface ListOptions {
  cursor?: string;
  limit?: number;
}

export interface StorageListResult {
  objects: Array<{ key: string; size: number; lastModified: number }>;
  cursor?: string;
  truncated: boolean;
}
```

### 7.2 Provider implementations

| File | Backend | Est. lines |
|------|---------|-----------|
| `core/storage/adapters/local.ts` | Local filesystem (Bun/Node `fs`) | ~80 |
| `core/storage/adapters/s3.ts` | AWS S3 (also MinIO-compatible) | ~100 |
| `core/storage/adapters/azure-blob.ts` | Azure Blob Storage | ~100 |
| `core/storage/adapters/gcs.ts` | Google Cloud Storage | ~100 |
| `core/storage/adapters/r2.ts` | Cloudflare R2 (S3-compatible subset) | ~60 |

All use native platform SDKs/APIs. The `s3.ts` adapter uses raw `fetch` with AWS Signature V4 (no SDK dependency) so it works in Workers.

### 7.3 Storage configuration

```
STORAGE_PROVIDER=s3|azure-blob|gcs|r2|local
STORAGE_BUCKET=my-eldrin-bucket
STORAGE_REGION=us-east-1
# Provider-specific keys as needed
```

### 7.4 Storage routes — `core/routes/storage.ts`

| Route | Method | Auth | Purpose |
|-------|--------|------|---------|
| `/api/storage/upload` | POST | Yes | Upload file (multipart) |
| `/api/storage/download/:key` | GET | Yes | Download file |
| `/api/storage/list` | GET | Yes | List files |
| `/api/storage/delete/:key` | DELETE | Yes | Delete file |
| `/api/storage/signed-url/:key` | GET | Yes | Get pre-signed download URL |

### 7.5 Tests

**`core/storage/adapters/local.test.ts`** (~8 cases):
- `put()` stores data, `get()` retrieves it
- `get()` returns null for non-existent key
- `delete()` removes stored object
- `list()` returns objects matching prefix
- `list()` supports cursor-based pagination
- `getSignedUrl()` generates URL with expiry
- Content type is preserved
- Metadata is preserved

**`core/storage/adapters/s3.test.ts`** (~6 cases, mocked fetch):
- `put()` sends correct S3 PUT with SigV4 auth
- `get()` sends correct S3 GET with SigV4 auth
- `delete()` sends correct S3 DELETE
- `list()` parses S3 ListObjectsV2 XML response
- `getSignedUrl()` generates valid pre-signed URL
- Handles S3 error responses (403, 404)

**`core/routes/storage.test.ts`** (~6 cases):
- `POST /api/storage/upload` stores file via adapter
- `GET /api/storage/download/:key` returns file contents
- `GET /api/storage/list` returns object list
- `DELETE /api/storage/delete/:key` removes file
- All routes require authentication
- Missing file returns 404

**E2E tests — `e2e/storage.spec.ts`** (~5 cases):
- Upload file via UI → file appears in file list
- Download previously uploaded file → correct content
- Delete file via UI → file removed from list
- Upload with auth expired → redirected to login
- Large file upload shows progress

**E2E regression**: `npm run e2e -- e2e/baseline.spec.ts` passes.

**Gate**: `npm run test:run -- core/storage/ core/routes/storage.test.ts` — all ~20 unit tests. `npm run e2e -- e2e/storage.spec.ts` — all ~5 E2E tests. Baseline regression passes.

### 7.6 Add `StorageAdapter` to `AppVariables`

```typescript
export type AppVariables = {
  db: DatabaseAdapter;
  storage: StorageAdapter;
  // ...
};
```

---

## Phase 8: Secret Management

Centralize secret retrieval so the app doesn't care where secrets come from — env vars, cloud vault, or config file.

### 8.1 Secret provider interface — `core/secrets/interface.ts`

```typescript
export interface SecretProvider {
  get(key: string): Promise<string | undefined>;
  getRequired(key: string): Promise<string>;  // throws if missing
}
```

### 8.2 Provider implementations

| File | Backend | Est. lines |
|------|---------|-----------|
| `core/secrets/adapters/env.ts` | `process.env` / Cloudflare `env` bindings | ~20 |
| `core/secrets/adapters/aws-secrets-manager.ts` | AWS Secrets Manager | ~50 |
| `core/secrets/adapters/azure-key-vault.ts` | Azure Key Vault | ~50 |
| `core/secrets/adapters/gcp-secret-manager.ts` | GCP Secret Manager | ~50 |

### 8.3 Composite provider — `core/secrets/composite.ts`

Chains providers with fallback: try cloud vault first, then env vars. Caches resolved values in-memory for the request lifecycle.

```typescript
export class CompositeSecretProvider implements SecretProvider {
  constructor(providers: SecretProvider[]);
  async get(key: string): Promise<string | undefined>;
}
```

### 8.4 Integration

Replace all `getJWTSecret(env)` and direct `process.env` reads with `secrets.getRequired('JWT_SECRET')`. The `SecretProvider` is set on `AppVariables` by each cloud adapter.

### 8.5 Tests

**`core/secrets/adapters/env.test.ts`** (~4 cases):
- `get()` returns value from env
- `get()` returns undefined for missing key
- `getRequired()` throws for missing key
- Works with both process.env and Cloudflare env bindings

**`core/secrets/composite.test.ts`** (~5 cases):
- First provider in chain takes priority
- Falls back to second provider if first returns undefined
- Caches resolved values within request lifecycle
- `getRequired()` throws if no provider has the key
- Empty chain returns undefined for all keys

**Gate**: `npm run test:run -- core/secrets/` — all ~9 secret management tests pass.

---

## Phase 9: Observability Stack

### 9.1 Structured logging — `core/observability/logger.ts`

```typescript
export interface Logger {
  info(message: string, context?: Record<string, unknown>): void;
  warn(message: string, context?: Record<string, unknown>): void;
  error(message: string, context?: Record<string, unknown>): void;
  debug(message: string, context?: Record<string, unknown>): void;
  child(context: Record<string, unknown>): Logger;
}
```

Default implementation outputs JSON lines to stdout. Each log entry includes: `timestamp`, `level`, `message`, `requestId`, `userId` (if authenticated), plus custom context.

Provider adapters can route logs to:
- **Cloudflare**: Workers Logpush / `console.log` (auto-collected)
- **AWS**: CloudWatch Logs (stdout from Lambda/ECS → CloudWatch)
- **Azure**: Application Insights (stdout + custom telemetry)
- **GCP**: Cloud Logging (stdout from Cloud Run/Functions → structured logs)

### 9.2 Metrics — `core/observability/metrics.ts`

```typescript
export interface MetricsCollector {
  increment(name: string, tags?: Record<string, string>): void;
  gauge(name: string, value: number, tags?: Record<string, string>): void;
  histogram(name: string, value: number, tags?: Record<string, string>): void;
  flush(): Promise<void>;
}
```

Built-in metrics: `http_requests_total`, `http_request_duration_ms`, `auth_login_total`, `auth_login_failed_total`, `db_query_duration_ms`.

Adapters: in-memory (for dev), CloudWatch Metrics, Azure Monitor, Cloud Monitoring, Prometheus-compatible endpoint.

### 9.3 OpenTelemetry tracing — `core/observability/tracing.ts`

Lightweight span interface compatible with OpenTelemetry:

```typescript
export interface Tracer {
  startSpan(name: string, attributes?: Record<string, string>): Span;
}

export interface Span {
  setAttribute(key: string, value: string | number): void;
  setStatus(code: 'OK' | 'ERROR', message?: string): void;
  end(): void;
}
```

Default implementation: no-op tracer (zero overhead). Can be swapped for `@opentelemetry/api` integration when full OTel is needed. Hono middleware auto-creates a request span with `http.method`, `http.route`, `http.status_code`.

### 9.4 Request-scoped context

Add `logger`, `metrics`, and `tracer` to `AppVariables`. Hono middleware creates per-request logger child with `requestId` (from `X-Request-ID` header or generated UUID).

### 9.5 Tests

**`core/observability/logger.test.ts`** (~8 cases):
- `info/warn/error/debug` produce JSON output with correct level
- Log entries include `timestamp` and `message`
- `child()` merges parent context into entries
- Request-scoped logger includes `requestId`
- Authenticated request logger includes `userId`
- Context fields are preserved across child loggers
- Debug level suppressed when log level > debug
- Large context objects are serialized without error

**`core/observability/metrics.test.ts`** (~5 cases):
- `increment()` increases counter by 1
- `gauge()` sets value
- `histogram()` records value
- Tags are attached to metrics
- `flush()` clears pending metrics

**`core/observability/middleware.test.ts`** (~5 cases):
- Middleware generates `requestId` if not in headers
- Middleware uses `X-Request-ID` header if present
- Request span created with `http.method` and `http.route`
- Response includes `X-Request-ID` header
- Request duration metric recorded

**Gate**: `npm run test:run -- core/observability/` — all ~18 observability tests pass.

---

## Phase 10: Background Jobs / Task Queue

### 10.1 Task queue interface — `core/jobs/interface.ts`

```typescript
export interface TaskQueue {
  enqueue<T>(task: TaskDefinition<T>): Promise<string>;  // returns task ID
  schedule<T>(task: TaskDefinition<T>, runAt: Date): Promise<string>;
}

export interface TaskDefinition<T = unknown> {
  type: string;        // e.g., 'email:send', 'webhook:deliver', 'report:generate'
  payload: T;
  maxRetries?: number;
  retryDelayMs?: number;
}

export interface TaskHandler<T = unknown> {
  type: string;
  handle(payload: T, context: TaskContext): Promise<void>;
}

export interface TaskContext {
  taskId: string;
  attempt: number;
  db: DatabaseAdapter;
  logger: Logger;
}
```

### 10.2 Provider implementations

| File | Backend | Est. lines |
|------|---------|-----------|
| `core/jobs/adapters/database.ts` | DB-backed polling queue (`task_queue` table) | ~120 |
| `core/jobs/adapters/sqs.ts` | AWS SQS | ~80 |
| `core/jobs/adapters/azure-service-bus.ts` | Azure Service Bus | ~80 |
| `core/jobs/adapters/cloud-tasks.ts` | GCP Cloud Tasks | ~80 |
| `core/jobs/adapters/cf-queues.ts` | Cloudflare Queues | ~60 |

The database adapter is the **universal fallback** — works everywhere, uses a `task_queue` table with polling. Good enough for low-to-medium volume. Cloud-native queues are used when available for better scalability.

### 10.3 Task handler registry — `core/jobs/registry.ts`

```typescript
export class TaskHandlerRegistry {
  register<T>(handler: TaskHandler<T>): void;
  handle(type: string, payload: unknown, context: TaskContext): Promise<void>;
}
```

### 10.4 Built-in task types

- `webhook:deliver` — Reliable webhook delivery with retries (replaces fire-and-forget)
- `email:send` — Send email via notification service
- `audit:cleanup` — Periodic cleanup of old audit entries
- `user:approval-reminder` — Remind admins of pending user approvals

### 10.5 Tests

**`core/jobs/adapters/database.test.ts`** (~10 cases):
- `enqueue()` inserts task with status 'pending'
- `schedule()` inserts task with future `run_at`
- Worker picks up pending tasks in `run_at` order
- Task handler receives correct payload and context
- Failed task is retried up to `maxRetries`
- Task exceeding retries moves to 'dead' status
- Concurrent workers don't process same task (locking)
- Completed task gets status 'completed' with `completed_at`
- Error message stored on failed task
- `TaskHandlerRegistry` routes to correct handler by type

**`core/jobs/registry.test.ts`** (~4 cases):
- Register handler for task type
- Handle dispatches to registered handler
- Unknown task type throws error
- Multiple handlers can be registered for different types

**Gate**: `npm run test:run -- core/jobs/` — all ~14 task queue tests pass.

### 10.6 Database migration — `migrations/YYYYMMDD-create-task-queue.sql`

```sql
CREATE TABLE IF NOT EXISTS task_queue (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  payload TEXT NOT NULL,      -- JSON
  status TEXT NOT NULL DEFAULT 'pending',  -- pending, processing, completed, failed, dead
  attempts INTEGER DEFAULT 0,
  max_retries INTEGER DEFAULT 3,
  run_at INTEGER NOT NULL,
  started_at INTEGER,
  completed_at INTEGER,
  error TEXT,
  created_at INTEGER NOT NULL
);

CREATE INDEX idx_task_queue_status_run_at ON task_queue(status, run_at);
```

---

## Phase 11: Rate Limiting & API Protection

### 11.1 Rate limiter interface — `core/security/rate-limiter.ts`

```typescript
export interface RateLimiter {
  /** Check if request is allowed. Returns remaining count or rejects. */
  check(key: string, limit: number, windowMs: number): Promise<RateLimitResult>;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;   // Unix timestamp
  retryAfter?: number; // seconds
}
```

### 11.2 Implementations

| File | Backend | Est. lines |
|------|---------|-----------|
| `core/security/rate-limiters/memory.ts` | In-memory sliding window (single-instance only) | ~50 |
| `core/security/rate-limiters/database.ts` | DB-backed (distributed, universal fallback) | ~60 |
| `core/security/rate-limiters/kv.ts` | Cloudflare KV / Redis-like | ~40 |

### 11.3 Hono middleware — `core/security/rate-limit-middleware.ts`

Applied to auth endpoints (`/api/auth/login`, `/api/auth/callback`, `/api/auth/token-exchange`) with aggressive limits (e.g., 10 attempts per minute per IP). Lighter limits on general API endpoints.

Returns standard `429 Too Many Requests` with `Retry-After` header.

### 11.4 IP extraction utility

Handles `X-Forwarded-For`, `CF-Connecting-IP`, `X-Real-IP` per cloud provider, with configurable trusted proxy depth.

### 11.5 Tests

**`core/security/rate-limiters/memory.test.ts`** (~6 cases):
- First request within limit → allowed, remaining decremented
- Requests exceeding limit → blocked with `allowed: false`
- Window expires → counter resets, requests allowed again
- Different keys are tracked independently
- `resetAt` is correctly calculated
- `retryAfter` is provided when blocked

**`core/security/rate-limiters/database.test.ts`** (~5 cases):
- Same behavior as memory tests but against mock DB
- Distributed: two "instances" share the same DB state
- Expired entries are cleaned up

**`core/security/rate-limit-middleware.test.ts`** (~5 cases):
- Auth endpoints limited to 10/min by default
- Returns 429 with Retry-After header when exceeded
- General API endpoints have higher limit
- IP extracted correctly from X-Forwarded-For
- Different IPs have independent counters

**`core/security/ip-extraction.test.ts`** (~4 cases):
- Extracts IP from CF-Connecting-IP (Cloudflare)
- Extracts IP from X-Forwarded-For with trusted proxy depth
- Falls back to X-Real-IP
- Falls back to remote address

**E2E tests — `e2e/security/rate-limiting.spec.ts`** (~3 cases):
- Rapid login attempts (>10/min) → 429 response shown to user
- After rate limit expires → login works again
- Rate limit error message displayed clearly in UI

**E2E regression**: `npm run e2e -- e2e/baseline.spec.ts` passes.

**Gate**: `npm run test:run -- core/security/` — all ~20 unit tests. `npm run e2e -- e2e/security/rate-limiting.spec.ts` — all ~3 E2E tests. Baseline regression passes.

---

## Phase 12: Session Revocation & Token Blacklist

### 12.1 Token revocation — `core/auth/token-revocation.ts`

```typescript
export interface TokenRevocationStore {
  /** Revoke a token by its JTI (JWT ID) */
  revoke(jti: string, expiresAt: number): Promise<void>;
  /** Check if a token is revoked */
  isRevoked(jti: string): Promise<boolean>;
  /** Revoke all tokens for a user (e.g., password change, account disable) */
  revokeAllForUser(userId: string): Promise<void>;
  /** Cleanup expired revocations */
  cleanup(): Promise<void>;
}
```

### 12.2 Implementation

**Database-backed** (universal): `revoked_tokens` table with `jti`, `user_id`, `revoked_at`, `expires_at`. Auto-cleanup via background task.

### 12.3 JWT changes

Add `jti` (JWT ID) claim to `JWTPayload` in `core/auth/types.ts`. Modify `createToken()` to generate unique `jti`. Modify middleware `checkAuth()` to check revocation store.

### 12.4 Integration points

- `handleLogout` → revoke current token
- User disable/delete → `revokeAllForUser()`
- Password change → `revokeAllForUser()` (force re-login)
- Admin "force logout" action → revoke specific token or all user tokens

### 12.5 Tests

**`core/auth/token-revocation.test.ts`** (~8 cases):
- `revoke()` stores jti in revoked_tokens table
- `isRevoked()` returns true for revoked jti
- `isRevoked()` returns false for non-revoked jti
- `revokeAllForUser()` revokes all tokens for a user
- `cleanup()` removes entries past their `expires_at`
- `cleanup()` preserves entries still within expiry
- Revoked token rejected by middleware `checkAuth()`
- Logout triggers token revocation

**Integration with auth middleware** (~3 cases):
- Request with revoked token returns 401
- Request with valid (non-revoked) token returns 200
- Password change revokes all user tokens, forcing re-login

**E2E tests — `e2e/auth/token-revocation.spec.ts`** (~4 cases):
- Logout → same token rejected on next API call
- Logout → refreshing page redirects to login
- Admin force-logout of another user → that user's next request fails
- Password change → user forced to re-login

**E2E regression**: `npm run e2e -- e2e/baseline.spec.ts` passes.

**Gate**: `npm run test:run -- core/auth/token-revocation.test.ts` — all ~11 unit tests. `npm run e2e -- e2e/auth/token-revocation.spec.ts` — all ~4 E2E tests. Baseline regression passes.

### 12.6 Migration — `migrations/YYYYMMDD-create-revoked-tokens.sql`

```sql
CREATE TABLE IF NOT EXISTS revoked_tokens (
  jti TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  revoked_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX idx_revoked_tokens_user ON revoked_tokens(user_id);
CREATE INDEX idx_revoked_tokens_expires ON revoked_tokens(expires_at);
```

---

## Phase 13: Audit Logging

### 13.1 Audit service — `core/audit/service.ts`

```typescript
export interface AuditEntry {
  action: string;         // e.g., 'user.login', 'user.approve', 'app.create', 'permission.grant'
  actorId: string;        // Who performed the action (user ID)
  targetType?: string;    // What was acted on ('user', 'app', 'role')
  targetId?: string;      // ID of the target
  metadata?: Record<string, unknown>;  // Additional context
  ipAddress?: string;
  userAgent?: string;
}

export async function recordAudit(db: DatabaseAdapter, entry: AuditEntry): Promise<void>;

export async function queryAuditLog(
  db: DatabaseAdapter,
  filters: AuditFilters
): Promise<{ entries: AuditRecord[]; total: number }>;

export interface AuditFilters {
  actorId?: string;
  action?: string;
  targetType?: string;
  targetId?: string;
  from?: number;       // timestamp
  to?: number;         // timestamp
  limit?: number;
  offset?: number;
}
```

### 13.2 Built-in audit actions

| Action | When |
|--------|------|
| `auth.login` | Successful login (local or OIDC) |
| `auth.login_failed` | Failed login attempt |
| `auth.logout` | User logout |
| `user.create` | User created (local or JIT) |
| `user.approve` | Pending user approved |
| `user.reject` | Pending user rejected |
| `user.disable` | User disabled |
| `user.update` | User profile updated |
| `user.password_change` | Password changed |
| `identity.link` | External identity linked |
| `identity.unlink` | External identity unlinked |
| `role.assign` | Role assigned to user |
| `role.revoke` | Role revoked from user |
| `permission.grant` | Permission granted |
| `permission.deny` | Permission denied |
| `app.create` | App registered |
| `app.update` | App updated |
| `app.delete` | App deleted |
| `config.update` | System configuration changed |

### 13.3 Audit routes — `core/routes/audit.ts`

| Route | Method | Permission | Purpose |
|-------|--------|------------|---------|
| `/api/audit` | GET | `audit:read` | Query audit log with filters |
| `/api/audit/export` | GET | `audit:read` | Export audit log as CSV/JSON |

### 13.4 Tests

**`core/audit/service.test.ts`** (~8 cases):
- `recordAudit()` inserts entry into audit_log table
- Entry includes all fields (action, actorId, targetType, targetId, metadata, ip, userAgent)
- `queryAuditLog()` filters by actorId
- `queryAuditLog()` filters by action
- `queryAuditLog()` filters by date range (from/to)
- `queryAuditLog()` supports pagination (limit/offset)
- `queryAuditLog()` returns total count
- Metadata stored as valid JSON, queryable after retrieval

**`core/routes/audit.test.ts`** (~5 cases):
- `GET /api/audit` returns audit entries with filters
- `GET /api/audit` requires `audit:read` permission
- `GET /api/audit` returns 403 without permission
- `GET /api/audit/export` returns CSV format
- `GET /api/audit/export` returns JSON format

**Integration** (~3 cases):
- Login produces `auth.login` audit entry
- User approval produces `user.approve` audit entry
- Failed login produces `auth.login_failed` audit entry

**E2E tests — `e2e/admin/audit-log.spec.ts`** (~5 cases):
- Admin can access audit log page
- Login events appear in audit log
- Audit log filters work (by action, user, date range)
- Audit log pagination works
- Non-admin user cannot access audit log (403 or redirect)

**E2E regression**: `npm run e2e -- e2e/baseline.spec.ts` passes.

**Gate**: `npm run test:run -- core/audit/ core/routes/audit.test.ts` — all ~16 unit tests. `npm run e2e -- e2e/admin/audit-log.spec.ts` — all ~5 E2E tests. Baseline regression passes.

### 13.5 Migration — `migrations/YYYYMMDD-create-audit-log.sql`

```sql
CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  action TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  metadata TEXT,           -- JSON
  ip_address TEXT,
  user_agent TEXT,
  created_at INTEGER NOT NULL
);

CREATE INDEX idx_audit_log_actor ON audit_log(actor_id);
CREATE INDEX idx_audit_log_action ON audit_log(action);
CREATE INDEX idx_audit_log_target ON audit_log(target_type, target_id);
CREATE INDEX idx_audit_log_created ON audit_log(created_at);
```

---

## Phase 14: Email & Notification Service

### 14.1 Email provider interface — `core/notifications/email/interface.ts`

```typescript
export interface EmailProvider {
  send(message: EmailMessage): Promise<{ messageId: string }>;
}

export interface EmailMessage {
  to: string | string[];
  subject: string;
  html?: string;
  text?: string;
  from?: string;           // Falls back to system default
  replyTo?: string;
}
```

### 14.2 Provider implementations

| File | Backend | Est. lines |
|------|---------|-----------|
| `core/notifications/email/adapters/smtp.ts` | SMTP (nodemailer-compatible, universal fallback) | ~60 |
| `core/notifications/email/adapters/ses.ts` | AWS SES | ~50 |
| `core/notifications/email/adapters/sendgrid.ts` | SendGrid (REST API) | ~40 |
| `core/notifications/email/adapters/azure-comm.ts` | Azure Communication Services | ~50 |
| `core/notifications/email/adapters/console.ts` | Console logger (dev mode) | ~15 |

### 14.3 Template engine — `core/notifications/email/templates.ts`

Simple Mustache-style template rendering (no external dependency). Templates stored as strings, supports variables like `{{firstName}}`, `{{approvalLink}}`.

Built-in templates:
- `welcome` — Welcome email for new users
- `approval-request` — Notify admin of pending user
- `approval-granted` — Notify user they've been approved
- `password-reset` — Password reset link
- `identity-linked` — Confirm identity linking

### 14.4 Tests

**`core/notifications/email/adapters/console.test.ts`** (~3 cases):
- `send()` logs email to console
- Returns messageId
- All fields (to, subject, html, text) captured

**`core/notifications/email/adapters/ses.test.ts`** (~4 cases, mocked fetch):
- `send()` calls SES SendEmail API with correct parameters
- Handles SES error responses
- Returns messageId from SES response
- Multiple recipients supported

**`core/notifications/email/adapters/sendgrid.test.ts`** (~3 cases, mocked fetch):
- `send()` calls SendGrid API with correct JSON body
- API key sent as Bearer token
- Handles error responses

**`core/notifications/email/templates.test.ts`** (~5 cases):
- `{{variable}}` replaced with value
- Missing variable replaced with empty string
- HTML special characters escaped
- Nested object access (`{{user.firstName}}`) supported
- Built-in templates render correctly (welcome, approval-request)

**Gate**: `npm run test:run -- core/notifications/` — all ~15 email/notification tests pass.

### 14.5 Configuration

```
EMAIL_PROVIDER=ses|sendgrid|smtp|azure-comm|console
EMAIL_FROM=noreply@example.com
# Provider-specific settings
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SENDGRID_API_KEY=...
```

---

## Phase 15: Cache Layer

### 15.1 Cache interface — `core/cache/interface.ts`

```typescript
export interface CacheAdapter {
  get<T>(key: string): Promise<T | null>;
  set<T>(key: string, value: T, ttlMs?: number): Promise<void>;
  delete(key: string): Promise<void>;
  has(key: string): Promise<boolean>;
}
```

### 15.2 Implementations

| File | Backend | Est. lines |
|------|---------|-----------|
| `core/cache/adapters/memory.ts` | In-memory Map with TTL (single-instance) | ~50 |
| `core/cache/adapters/kv.ts` | Cloudflare KV | ~30 |
| `core/cache/adapters/redis.ts` | Redis / ElastiCache / Azure Cache / Memorystore | ~40 |
| `core/cache/adapters/database.ts` | DB-backed (`cache_entries` table, universal fallback) | ~50 |

### 15.3 Use cases

- **JWKS caching**: Cache IdP signing keys (TTL: 1 hour)
- **OIDC discovery caching**: Cache `.well-known/openid-configuration` (TTL: 24 hours)
- **Auth provider config**: Cache `auth_providers` table (TTL: 5 minutes)
- **User permissions**: Cache calculated permissions per user (TTL: 1 minute, invalidated on change)
- **Rate limit counters**: Sliding window counters (when KV/Redis available)

### 15.4 Tests

**`core/cache/adapters/memory.test.ts`** (~7 cases):
- `set()` + `get()` round-trips value
- `get()` returns null for missing key
- `has()` returns true/false correctly
- `delete()` removes entry
- Entry expires after TTL
- Entry available before TTL
- Different keys are independent

**`core/cache/adapters/database.test.ts`** (~5 cases):
- Same round-trip behavior against mock DB
- Expired entries return null
- Cleanup removes expired entries from DB
- TTL stored as absolute timestamp

**Gate**: `npm run test:run -- core/cache/` — all ~12 cache tests pass.

### 15.5 Add to `AppVariables`

```typescript
export type AppVariables = {
  db: DatabaseAdapter;
  storage: StorageAdapter;
  cache: CacheAdapter;
  secrets: SecretProvider;
  logger: Logger;
  metrics: MetricsCollector;
  // ...
};
```

---

## Phase 16: CORS & Security Headers

### 16.1 Security headers middleware — `core/security/headers.ts`

Configurable middleware applied to all responses:

```typescript
export interface SecurityHeadersConfig {
  cors: {
    origins: string[];           // Allowed origins (not '*' in production)
    methods: string[];
    headers: string[];
    credentials: boolean;
    maxAge: number;
  };
  csp?: string;                   // Content-Security-Policy
  hsts?: { maxAge: number; includeSubDomains: boolean };
  xFrameOptions?: 'DENY' | 'SAMEORIGIN';
  xContentTypeOptions?: boolean;  // nosniff
  referrerPolicy?: string;
}
```

### 16.2 Default configuration

- **Development**: `origins: ['*']`, relaxed CSP
- **Production**: `origins` read from `ALLOWED_ORIGINS` env var (comma-separated), strict CSP, HSTS enabled

### 16.3 Tests

**`core/security/headers.test.ts`** (~8 cases):
- CORS: Allowed origin receives `Access-Control-Allow-Origin`
- CORS: Disallowed origin does NOT receive the header
- CORS: Preflight `OPTIONS` returns correct headers + 204
- CORS: Credentials flag reflected in `Access-Control-Allow-Credentials`
- CSP header set correctly
- HSTS header set with correct max-age
- X-Frame-Options set to configured value
- X-Content-Type-Options: nosniff always present
- Dev config: relaxed origins, no HSTS
- Prod config: strict origins, HSTS enabled

**E2E tests — `e2e/security/headers.spec.ts`** (~4 cases):
- Response headers include X-Content-Type-Options: nosniff
- Response headers include X-Frame-Options
- CORS preflight returns correct Access-Control headers
- HSTS header present in production mode

**E2E regression**: `npm run e2e -- e2e/baseline.spec.ts` passes.

**Gate**: `npm run test:run -- core/security/headers.test.ts` — all ~10 unit tests. `npm run e2e -- e2e/security/headers.spec.ts` — all ~4 E2E tests. Baseline regression passes.

### 16.4 Configuration

```
ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
CORS_CREDENTIALS=true
HSTS_MAX_AGE=31536000
```

---

## Phase 17: CI/CD Pipelines

### 17.1 GitHub Actions workflows

| File | Purpose |
|------|---------|
| `.github/workflows/ci.yml` | Lint + typecheck + test on PR |
| `.github/workflows/deploy-cloudflare.yml` | Deploy to Cloudflare Workers |
| `.github/workflows/deploy-aws-lambda.yml` | Build + deploy Lambda via SAM |
| `.github/workflows/deploy-aws-ecs.yml` | Build Docker + deploy to ECS/Fargate |
| `.github/workflows/deploy-azure-functions.yml` | Deploy to Azure Functions |
| `.github/workflows/deploy-azure-container.yml` | Build Docker + deploy to Azure Container Apps |
| `.github/workflows/deploy-gcp-functions.yml` | Deploy to Cloud Functions |
| `.github/workflows/deploy-gcp-run.yml` | Build Docker + deploy to Cloud Run |
| `.github/workflows/deploy-standalone.yml` | Build standalone binary + publish release |

### 17.2 Common patterns

- All workflows use reusable composite actions for shared steps (checkout, setup Node, install deps, build frontend)
- Environment-specific secrets via GitHub Environments
- Build matrix for provider-specific targets
- Artifact caching for node_modules and build outputs

### 17.3 Tests

**Workflow validation** (can be run locally with `act` or validated via YAML lint):

**`ci.test.ts`** (~4 cases):
- All workflow YAML files are valid (parseable)
- `ci.yml` runs test suite on PR triggers
- Deploy workflows trigger on push to main or manual dispatch
- All workflows reference correct build scripts from package.json

**Gate**: Workflow files are valid YAML. `npm run test:run -- ci.test.ts` validates structure.

---

## Phase 18: Provider Migration Tooling

### 18.1 Data export/import — `core/migration/`

```typescript
export interface ExportOptions {
  includeUsers: boolean;
  includeApps: boolean;
  includePermissions: boolean;
  includeAuditLog: boolean;
  format: 'json' | 'sql';
}

export async function exportData(db: DatabaseAdapter, options: ExportOptions): Promise<ReadableStream>;
export async function importData(db: DatabaseAdapter, data: ReadableStream, options: ImportOptions): Promise<ImportResult>;
```

### 18.2 CLI commands

Integrated into standalone server CLI:

```
eldrin export --output backup.json --include users,apps,permissions
eldrin import --input backup.json --dry-run
eldrin import --input backup.json --confirm
eldrin migrate-db --from sqlite --to postgresql --source ./data/eldrin.db --target postgres://...
```

### 18.3 Database migration utility — `core/migration/db-migrate.ts`

Transfers data between SQLite and PostgreSQL:
- Reads from source database adapter
- Transforms schema differences (e.g., `INTEGER` booleans in SQLite → `BOOLEAN` in PostgreSQL)
- Writes to target database adapter
- Validates row counts and data integrity post-migration

### 18.4 Tests

**`core/migration/export.test.ts`** (~6 cases):
- Exports users as JSON
- Exports apps as JSON
- Exports permissions with role assignments
- Exports audit log entries
- Export respects `includeUsers`, `includeApps` flags
- Empty database produces valid empty export

**`core/migration/import.test.ts`** (~6 cases):
- Imports users from JSON export
- Imports apps from JSON export
- Dry run reports changes without writing
- Duplicate detection (existing user by email)
- Import preserves relationships (user → roles, user → identities)
- Invalid format produces clear error

**`core/migration/db-migrate.test.ts`** (~5 cases):
- Migrates users between two mock DB adapters
- Boolean transformation (SQLite INTEGER → proper boolean)
- Row count validated post-migration
- Data integrity check (checksums match)
- Handles empty tables gracefully

**Gate**: `npm run test:run -- core/migration/` — all ~17 migration tests pass.

---

## Test Summary

### Unit Tests (Vitest)

| Phase | Test file(s) | Est. cases |
|-------|-------------|-----------|
| 0 — Testing Foundation | `core/test-utils/*.test.ts` | ~8 |
| 1 — SDK + DB Adapters | Existing + `turso.test.ts`, `sqlite-node.test.ts`, `factory.test.ts` | 45 + ~23 |
| 2 — Unified Hono App | `core/app.test.ts` | ~20 |
| 3 — Auth Providers | `core/auth/**/*.test.ts`, `core/routes/auth-providers.test.ts` | ~77 |
| 4 — Cloud Adapters | `providers/**/*.test.ts` | ~14 |
| 5 — Build System | `build.test.ts` | ~8 |
| 6 — IaC Templates | `iac.test.ts` | ~6 |
| 7 — Storage | `core/storage/**/*.test.ts`, `core/routes/storage.test.ts` | ~20 |
| 8 — Secrets | `core/secrets/**/*.test.ts` | ~9 |
| 9 — Observability | `core/observability/**/*.test.ts` | ~18 |
| 10 — Background Jobs | `core/jobs/**/*.test.ts` | ~14 |
| 11 — Rate Limiting | `core/security/**/*.test.ts` | ~20 |
| 12 — Token Revocation | `core/auth/token-revocation.test.ts` | ~11 |
| 13 — Audit Logging | `core/audit/**/*.test.ts`, `core/routes/audit.test.ts` | ~16 |
| 14 — Email/Notifications | `core/notifications/**/*.test.ts` | ~15 |
| 15 — Cache | `core/cache/**/*.test.ts` | ~12 |
| 16 — Security Headers | `core/security/headers.test.ts` | ~10 |
| 17 — CI/CD | `ci.test.ts` | ~4 |
| 18 — Migration Tooling | `core/migration/**/*.test.ts` | ~17 |
| **Unit subtotal** | | **~393** |

### E2E Tests (Playwright)

| Phase | Test file(s) | Est. cases |
|-------|-------------|-----------|
| 0 — Baseline | `e2e/baseline.spec.ts` | ~10 |
| 3 — Auth: Local Login | `e2e/auth/local-login.spec.ts` | ~8 |
| 3 — Auth: Providers | `e2e/auth/providers.spec.ts` | ~6 |
| 3 — Auth: Pending Users | `e2e/auth/pending-user.spec.ts` | ~5 |
| 3 — Auth: Account Linking | `e2e/auth/account-linking.spec.ts` | ~4 |
| 7 — Storage | `e2e/storage.spec.ts` | ~5 |
| 11 — Rate Limiting | `e2e/security/rate-limiting.spec.ts` | ~3 |
| 12 — Token Revocation | `e2e/auth/token-revocation.spec.ts` | ~4 |
| 13 — Audit Log | `e2e/admin/audit-log.spec.ts` | ~5 |
| 16 — Security Headers | `e2e/security/headers.spec.ts` | ~4 |
| **E2E subtotal** | | **~54** |

### Regression Strategy

Every phase gate includes: `npm run e2e -- e2e/baseline.spec.ts` to ensure no regressions in core flows. The baseline tests cover:
- App loading and navigation
- Login/logout flow
- Protected route access
- API authentication
- Static asset serving

As new E2E tests are added per phase, they accumulate into the full suite. Running `npm run e2e` executes all E2E tests — both baseline and feature-specific.

### Totals

| Type | Cases |
|------|-------|
| Unit (Vitest) | ~393 |
| E2E (Playwright) | ~54 |
| **Grand total** | **~447** |

**Full test gate**: `npm run test:run` (unit) AND `npm run e2e` (E2E) must both pass before the project is considered complete. Each phase gate is validated independently as work progresses.

---

## File Summary

### New files (~130)

**Core auth system (Phase 3):**
| File | Est. lines |
|------|-----------|
| `core/auth/providers/interface.ts` | ~80 |
| `core/auth/providers/registry.ts` | ~60 |
| `core/auth/providers/local.ts` | ~40 |
| `core/auth/providers/oidc-base.ts` | ~150 |
| `core/auth/providers/entra.ts` | ~40 |
| `core/auth/providers/google.ts` | ~30 |
| `core/auth/providers/cognito.ts` | ~30 |
| `core/auth/providers/oidc-generic.ts` | ~10 |
| `core/auth/jwks.ts` | ~100 |
| `core/auth/account-linking.ts` | ~120 |
| `core/auth/token-revocation.ts` | ~80 |
| `core/routes/auth-providers.ts` | ~200 |

**Unified app + cloud adapters (Phases 2, 4):**
| File | Est. lines |
|------|-----------|
| `core/app.ts` | ~280 |
| `providers/cloudflare/index.ts` | ~30 |
| `providers/aws/lambda.ts` | ~25 |
| `providers/aws/ecs/entrypoint.ts` + `Dockerfile` | ~50 |
| `providers/azure/functions.ts` | ~25 |
| `providers/azure/container/entrypoint.ts` + `Dockerfile` | ~50 |
| `providers/gcp/cloud-functions.ts` | ~25 |
| `providers/gcp/cloud-run/entrypoint.ts` + `Dockerfile` | ~50 |
| `providers/aws/template.yaml` | ~80 |
| `vite.config.base.ts` | ~20 |

**Storage (Phase 7):**
| File | Est. lines |
|------|-----------|
| `core/storage/interface.ts` | ~50 |
| `core/storage/adapters/local.ts` | ~80 |
| `core/storage/adapters/s3.ts` | ~100 |
| `core/storage/adapters/azure-blob.ts` | ~100 |
| `core/storage/adapters/gcs.ts` | ~100 |
| `core/storage/adapters/r2.ts` | ~60 |
| `core/routes/storage.ts` | ~100 |

**Secrets (Phase 8):**
| File | Est. lines |
|------|-----------|
| `core/secrets/interface.ts` | ~20 |
| `core/secrets/composite.ts` | ~40 |
| `core/secrets/adapters/env.ts` | ~20 |
| `core/secrets/adapters/aws-secrets-manager.ts` | ~50 |
| `core/secrets/adapters/azure-key-vault.ts` | ~50 |
| `core/secrets/adapters/gcp-secret-manager.ts` | ~50 |

**Observability (Phase 9):**
| File | Est. lines |
|------|-----------|
| `core/observability/logger.ts` | ~80 |
| `core/observability/metrics.ts` | ~60 |
| `core/observability/tracing.ts` | ~50 |
| `core/observability/middleware.ts` | ~40 |

**Background jobs (Phase 10):**
| File | Est. lines |
|------|-----------|
| `core/jobs/interface.ts` | ~50 |
| `core/jobs/registry.ts` | ~40 |
| `core/jobs/adapters/database.ts` | ~120 |
| `core/jobs/adapters/sqs.ts` | ~80 |
| `core/jobs/adapters/azure-service-bus.ts` | ~80 |
| `core/jobs/adapters/cloud-tasks.ts` | ~80 |
| `core/jobs/adapters/cf-queues.ts` | ~60 |

**Security (Phases 11, 16):**
| File | Est. lines |
|------|-----------|
| `core/security/rate-limiter.ts` | ~30 |
| `core/security/rate-limiters/memory.ts` | ~50 |
| `core/security/rate-limiters/database.ts` | ~60 |
| `core/security/rate-limiters/kv.ts` | ~40 |
| `core/security/rate-limit-middleware.ts` | ~50 |
| `core/security/headers.ts` | ~60 |

**Audit (Phase 13):**
| File | Est. lines |
|------|-----------|
| `core/audit/service.ts` | ~100 |
| `core/routes/audit.ts` | ~80 |

**Email/Notifications (Phase 14):**
| File | Est. lines |
|------|-----------|
| `core/notifications/email/interface.ts` | ~30 |
| `core/notifications/email/templates.ts` | ~80 |
| `core/notifications/email/adapters/smtp.ts` | ~60 |
| `core/notifications/email/adapters/ses.ts` | ~50 |
| `core/notifications/email/adapters/sendgrid.ts` | ~40 |
| `core/notifications/email/adapters/azure-comm.ts` | ~50 |
| `core/notifications/email/adapters/console.ts` | ~15 |

**Cache (Phase 15):**
| File | Est. lines |
|------|-----------|
| `core/cache/interface.ts` | ~20 |
| `core/cache/adapters/memory.ts` | ~50 |
| `core/cache/adapters/kv.ts` | ~30 |
| `core/cache/adapters/redis.ts` | ~40 |
| `core/cache/adapters/database.ts` | ~50 |

**Migration tooling (Phase 18):**
| File | Est. lines |
|------|-----------|
| `core/migration/export.ts` | ~80 |
| `core/migration/import.ts` | ~80 |
| `core/migration/db-migrate.ts` | ~120 |

**CI/CD (Phase 17):**
| File | Est. lines |
|------|-----------|
| `.github/workflows/ci.yml` | ~60 |
| `.github/workflows/deploy-cloudflare.yml` | ~40 |
| `.github/workflows/deploy-aws-lambda.yml` | ~50 |
| `.github/workflows/deploy-aws-ecs.yml` | ~60 |
| `.github/workflows/deploy-azure-functions.yml` | ~50 |
| `.github/workflows/deploy-azure-container.yml` | ~60 |
| `.github/workflows/deploy-gcp-functions.yml` | ~50 |
| `.github/workflows/deploy-gcp-run.yml` | ~60 |
| `.github/workflows/deploy-standalone.yml` | ~40 |

**Database migrations:**
| File | Est. lines |
|------|-----------|
| `migrations/YYYYMMDD-create-auth-provider-tables.sql` | ~30 |
| `migrations/YYYYMMDD-create-task-queue.sql` | ~20 |
| `migrations/YYYYMMDD-create-revoked-tokens.sql` | ~15 |
| `migrations/YYYYMMDD-create-audit-log.sql` | ~20 |

**Frontend:**
| File | Est. lines |
|------|-----------|
| `src/pages/AuthCallback.tsx` | ~60 |
| `src/pages/settings/AccountLinking.tsx` | ~100 |

**Testing foundation (Phase 0):**
| File | Est. lines |
|------|-----------|
| `vitest.config.ts` | ~20 |
| `playwright.config.ts` | ~25 |
| `core/test-utils/mock-db.ts` | ~80 |
| `core/test-utils/mock-storage.ts` | ~40 |
| `core/test-utils/mock-cache.ts` | ~30 |
| `core/test-utils/mock-logger.ts` | ~20 |
| `core/test-utils/fixtures.ts` | ~60 |
| `core/test-utils/hono-helpers.ts` | ~40 |
| `e2e/helpers/auth.ts` | ~30 |
| `e2e/helpers/api.ts` | ~20 |
| `e2e/helpers/setup.ts` | ~20 |

**Test files (~35 files, ~2500 lines total):**
| File | Est. cases |
|------|-----------|
| `core/test-utils/mock-db.test.ts` | ~4 |
| `core/test-utils/fixtures.test.ts` | ~3 |
| `core/test-utils/hono-helpers.test.ts` | ~3 |
| `core/app.test.ts` | ~20 |
| `core/auth/providers/registry.test.ts` | ~10 |
| `core/auth/providers/local.test.ts` | ~8 |
| `core/auth/providers/oidc-base.test.ts` | ~12 |
| `core/auth/providers/entra.test.ts` | ~5 |
| `core/auth/providers/google.test.ts` | ~3 |
| `core/auth/providers/cognito.test.ts` | ~3 |
| `core/auth/jwks.test.ts` | ~8 |
| `core/auth/account-linking.test.ts` | ~10 |
| `core/auth/token-revocation.test.ts` | ~11 |
| `core/routes/auth-providers.test.ts` | ~12 |
| `core/routes/users.test.ts` | ~6 |
| `core/routes/storage.test.ts` | ~6 |
| `core/routes/audit.test.ts` | ~5 |
| `core/storage/adapters/local.test.ts` | ~8 |
| `core/storage/adapters/s3.test.ts` | ~6 |
| `core/secrets/adapters/env.test.ts` | ~4 |
| `core/secrets/composite.test.ts` | ~5 |
| `core/observability/logger.test.ts` | ~8 |
| `core/observability/metrics.test.ts` | ~5 |
| `core/observability/middleware.test.ts` | ~5 |
| `core/jobs/adapters/database.test.ts` | ~10 |
| `core/jobs/registry.test.ts` | ~4 |
| `core/security/rate-limiters/memory.test.ts` | ~6 |
| `core/security/rate-limiters/database.test.ts` | ~5 |
| `core/security/rate-limit-middleware.test.ts` | ~5 |
| `core/security/ip-extraction.test.ts` | ~4 |
| `core/security/headers.test.ts` | ~10 |
| `core/audit/service.test.ts` | ~8 |
| `core/notifications/email/templates.test.ts` | ~5 |
| `core/notifications/email/adapters/*.test.ts` | ~10 |
| `core/cache/adapters/memory.test.ts` | ~7 |
| `core/cache/adapters/database.test.ts` | ~5 |
| `core/migration/export.test.ts` | ~6 |
| `core/migration/import.test.ts` | ~6 |
| `core/migration/db-migrate.test.ts` | ~5 |
| `providers/cloudflare/index.test.ts` | ~6 |
| `providers/aws/lambda.test.ts` | ~4 |
| `providers/standalone/index.test.ts` | ~4 |
| `build.test.ts` | ~8 |
| `ci.test.ts` | ~4 |

**E2E test files (Playwright):**
| File | Est. cases |
|------|-----------|
| `e2e/baseline.spec.ts` | ~10 |
| `e2e/auth/local-login.spec.ts` | ~8 |
| `e2e/auth/providers.spec.ts` | ~6 |
| `e2e/auth/pending-user.spec.ts` | ~5 |
| `e2e/auth/account-linking.spec.ts` | ~4 |
| `e2e/auth/token-revocation.spec.ts` | ~4 |
| `e2e/storage.spec.ts` | ~5 |
| `e2e/security/rate-limiting.spec.ts` | ~3 |
| `e2e/security/headers.spec.ts` | ~4 |
| `e2e/admin/audit-log.spec.ts` | ~5 |

**SDK (eldrin-app-core, Phase 1):**
| File | Est. lines |
|------|-----------|
| `eldrin-app-core/src/database/turso.ts` | ~80 |
| `eldrin-app-core/src/database/sqlite-node.ts` | ~60 |
| `eldrin-app-core/src/database/turso.test.ts` | ~60 |
| `eldrin-app-core/src/database/sqlite-node.test.ts` | ~40 |
| `eldrin-app-core/src/database/factory.test.ts` | ~40 |

### Modified files (~16)
| File | Change |
|------|--------|
| `eldrin-app-core/src/migrations/runner.ts` | `D1Database` → `DatabaseAdapter` |
| `eldrin-app-core/src/migrations/rollback.ts` | Same type fix |
| `eldrin-app-core/src/database/factory.ts` | Add Turso to factory + auto-detection |
| `eldrin-app-core/src/database/index.ts` | Export Turso adapter |
| `eldrin-core/core/index.ts` | Add `createApp` export |
| `eldrin-core/core/auth/index.ts` | Export new provider types, token revocation |
| `eldrin-core/core/auth/types.ts` | Add `jti` to `JWTPayload` |
| `eldrin-core/core/auth/jwt.ts` | Generate `jti` in `createToken()` |
| `eldrin-core/core/auth/middleware.ts` | Add revocation check in `checkAuth()` |
| `eldrin-core/core/routes/users.ts` | Add pending/approve/reject routes |
| `eldrin-core/core/routes/auth.ts` | Revoke token on logout |
| `eldrin-core/src/stores/authStore.ts` | Add OIDC login methods |
| `eldrin-core/src/pages/Login.tsx` | Show provider buttons |
| `eldrin-core/vite.config.ts` | Extract base config |
| `eldrin-core/package.json` | Build scripts, deps |
| `eldrin-core/worker/index.ts` | Re-export shim |
| `eldrin-core/server/index.ts` | Re-export shim |

### Moved files (4)
| From | To |
|------|-----|
| `server/index.ts` | `providers/standalone/index.ts` |
| `server/config.ts` | `providers/standalone/config.ts` |
| `server/migrations.ts` | `providers/standalone/migrations.ts` |
| `server/embedded-assets.ts` | `providers/standalone/embedded-assets.ts` |

---

## Infrastructure Dependencies

### Provider-Service Matrix

Each abstraction layer maps to specific cloud services. "—" means the universal/DB fallback is used.

| Service Layer | Cloudflare | AWS | Azure | GCP | Standalone |
|--------------|-----------|-----|-------|-----|-----------|
| **Compute** | Workers | Lambda / ECS Fargate | Functions / Container Apps | Cloud Functions / Cloud Run | Bun process |
| **Database (free)** | D1 (SQLite) | SQLite on EFS or Turso | SQLite on Azure Files or Turso | SQLite on Filestore/GCS FUSE or Turso | SQLite file |
| **Database (paid)** | Hyperdrive + external PG | RDS PostgreSQL / Aurora Serverless | PostgreSQL Flexible Server | Cloud SQL PostgreSQL | External PostgreSQL |
| **Storage** | R2 | S3 | Blob Storage | Cloud Storage | Local filesystem |
| **Secrets** | Environment bindings + Secrets | Secrets Manager | Key Vault | Secret Manager | `.env` file / process.env |
| **Cache** | KV | ElastiCache Redis | Azure Cache for Redis | Memorystore Redis | In-memory |
| **Task Queue** | Queues | SQS | Service Bus | Cloud Tasks | DB-backed polling |
| **Email** | — (use SendGrid) | SES | Communication Services | — (use SendGrid) | Console / SMTP |
| **Rate Limiting** | KV / Durable Objects | ElastiCache Redis | Azure Cache for Redis | Memorystore Redis | In-memory / DB |
| **Logging** | Workers Logpush (auto) | CloudWatch Logs (stdout) | Application Insights (stdout) | Cloud Logging (stdout) | stdout JSON |
| **Metrics** | Workers Analytics | CloudWatch Metrics | Azure Monitor | Cloud Monitoring | Prometheus endpoint |
| **Tracing** | — (no-op) | X-Ray (opt-in) | Application Insights | Cloud Trace | No-op / OTel |
| **Auth IdPs** | Any OIDC | Cognito + any OIDC | Entra ID + any OIDC | Google Identity + any OIDC | Any OIDC |
| **CI/CD** | Wrangler CLI | SAM CLI / CDK | Azure CLI / Bicep | gcloud CLI | Bun build |

### Per-Phase Infrastructure Requirements

#### Phase 2 — Unified Hono App
| Provider | Required Services | Configuration |
|----------|------------------|---------------|
| Cloudflare | D1 binding or Hyperdrive | `DB` binding (D1) or `DATABASE_URL` via Hyperdrive, `JWT_SECRET` |
| AWS/Azure/GCP (serverless) | Turso or PostgreSQL | `DATABASE_TYPE=turso` + `TURSO_URL` + `TURSO_AUTH_TOKEN`, or `DATABASE_TYPE=postgres` + `DATABASE_URL` |
| AWS/Azure/GCP (container) | SQLite file, Turso, or PostgreSQL | `DATABASE_TYPE=sqlite` + `DATABASE_PATH`, or Turso, or PostgreSQL |
| Standalone | SQLite file or PostgreSQL | `DATABASE_TYPE=sqlite` + `DATABASE_PATH=./data/eldrin.db`, or `DATABASE_URL` |

#### Phase 3 — Auth Providers
| Provider | Required Services | Configuration |
|----------|------------------|---------------|
| All | Database (auth tables) | Migration applied for `auth_providers`, `user_identities` tables |
| Cloudflare | — | OIDC providers configured via env bindings |
| AWS | Cognito (optional) | `AUTH_COGNITO_USER_POOL_ID`, `AUTH_COGNITO_REGION`, `AUTH_COGNITO_CLIENT_ID` |
| Azure | Entra ID (optional) | `AUTH_ENTRA_TENANT_ID`, `AUTH_ENTRA_CLIENT_ID`, `AUTH_ENTRA_CLIENT_SECRET` |
| GCP | Google Identity (optional) | `AUTH_GOOGLE_CLIENT_ID`, `AUTH_GOOGLE_CLIENT_SECRET` |

#### Phase 4 — Cloud Adapters
| Provider | Required Services | Provisioning |
|----------|------------------|-------------|
| Cloudflare | Workers, D1 or Hyperdrive + PG | `wrangler.jsonc` — D1 binding (free) or Hyperdrive binding (PG). `[vars]` for JWT_SECRET |
| AWS Lambda (free: EFS) | Lambda, API Gateway, EFS, VPC | SAM: `AWS::Serverless::Function` with EFS mount point, `AWS::EFS::FileSystem`, VPC, Security Groups. SQLite on `/mnt/efs/eldrin.db` |
| AWS Lambda (free: Turso) | Lambda, API Gateway, Turso | SAM: `AWS::Serverless::Function`, env vars: `TURSO_URL`, `TURSO_AUTH_TOKEN`. No VPC needed |
| AWS Lambda (paid) | Lambda, API Gateway, RDS, VPC | SAM: `AWS::Serverless::Function`, `AWS::RDS::DBInstance`, VPC, Security Groups |
| AWS ECS (free) | ECS Fargate, ALB, EFS, ECR | Dockerfile, task def with EFS volume mount for SQLite, or Turso env vars |
| AWS ECS (paid) | ECS Fargate, ALB, RDS, ECR | Dockerfile, task def, ALB target group, ECR repository |
| Azure Functions (free: Files) | Functions App, Azure Files share | `host.json`, Consumption plan, Azure Files mount (SMB), SQLite on `/mnt/azure/eldrin.db` |
| Azure Functions (free: Turso) | Functions App, Turso | `host.json`, Consumption plan, env vars: `TURSO_URL`, `TURSO_AUTH_TOKEN` |
| Azure Functions (paid) | Functions App, PostgreSQL Flexible Server | `host.json`, Premium plan, DB server, VNet integration |
| Azure Container (free) | Container Apps, Azure Files, ACR | Dockerfile, Azure Files volume mount for SQLite, or Turso env vars |
| Azure Container (paid) | Container Apps, PostgreSQL Flexible Server, ACR | Dockerfile, Container Apps Environment, ACR registry |
| GCP Cloud Functions (free: Filestore) | Cloud Functions (2nd gen), Filestore | Filestore instance, VPC connector, NFS mount. SQLite at `/mnt/filestore/eldrin.db` |
| GCP Cloud Functions (free: Turso) | Cloud Functions (2nd gen), Turso | `gcloud functions deploy`, env vars: `TURSO_URL`, `TURSO_AUTH_TOKEN`. No VPC needed |
| GCP Cloud Functions (paid) | Cloud Functions (2nd gen), Cloud SQL | Cloud SQL instance, VPC connector |
| GCP Cloud Run (free: Filestore) | Cloud Run, Filestore, Artifact Registry | Dockerfile, NFS volume mount, VPC connector |
| GCP Cloud Run (free: Turso) | Cloud Run, Turso, Artifact Registry | Dockerfile, Turso env vars. No VPC needed for DB |
| GCP Cloud Run (paid) | Cloud Run, Cloud SQL, Artifact Registry | Dockerfile, Cloud SQL connection |
| Standalone | Bun runtime | SQLite file (default) or external PostgreSQL. Config via `config.ts` |

#### Phase 7 — Storage
| Provider | Required Service | Provisioning |
|----------|-----------------|-------------|
| Cloudflare | R2 bucket | `wrangler.jsonc` — R2 binding: `[[r2_buckets]] binding = "STORAGE"` |
| AWS | S3 bucket | SAM: `AWS::S3::Bucket`, IAM policy for Lambda/ECS role |
| Azure | Blob Storage container | Storage Account + container, Managed Identity access |
| GCP | Cloud Storage bucket | `gsutil mb`, IAM service account with `storage.objectAdmin` |
| Standalone | Local directory | `STORAGE_PATH=./data/storage` |

#### Phase 8 — Secrets
| Provider | Required Service | Provisioning |
|----------|-----------------|-------------|
| Cloudflare | Wrangler secrets | `wrangler secret put JWT_SECRET`, accessed via `env.JWT_SECRET` |
| AWS | Secrets Manager | `AWS::SecretsManager::Secret`, IAM policy for Lambda/ECS role |
| Azure | Key Vault | Key Vault instance, Managed Identity with `Key Vault Secrets User` role |
| GCP | Secret Manager | `gcloud secrets create`, IAM binding for service account |
| Standalone | `.env` file | `process.env` via dotenv or Bun built-in |

#### Phase 9 — Observability
| Provider | Required Service | Provisioning |
|----------|-----------------|-------------|
| Cloudflare | Workers Logpush (auto), Workers Analytics Engine (optional) | Logpush destination (R2/S3/etc.), Analytics binding in wrangler.jsonc |
| AWS | CloudWatch Logs + Metrics | Auto for Lambda (stdout → CloudWatch). ECS: awslogs driver. X-Ray: opt-in via SAM |
| Azure | Application Insights | `APPLICATIONINSIGHTS_CONNECTION_STRING` env var, App Insights resource |
| GCP | Cloud Logging + Monitoring | Auto for Cloud Run/Functions (stdout → Cloud Logging). Cloud Trace: opt-in |
| Standalone | stdout | No external service needed. Optional: Prometheus scrape endpoint on `/metrics` |

#### Phase 10 — Background Jobs
| Provider | Required Service | Provisioning |
|----------|-----------------|-------------|
| Cloudflare | Queues | `wrangler.jsonc` — `[[queues.producers]]` + `[[queues.consumers]]` |
| AWS | SQS | SAM: `AWS::SQS::Queue`, Lambda event source mapping or ECS polling |
| Azure | Service Bus | Service Bus namespace + queue, connection string in env |
| GCP | Cloud Tasks | Cloud Tasks queue + IAM, HTTP target for task handler endpoint |
| Standalone | DB-backed (task_queue table) | Migration applied. Background worker polls via `setInterval` |

#### Phase 11 — Rate Limiting
| Provider | Required Service | Provisioning |
|----------|-----------------|-------------|
| Cloudflare | KV namespace | `wrangler.jsonc` — KV binding: `[[kv_namespaces]]` |
| AWS | ElastiCache Redis | VPC, subnet group, Redis cluster, security group |
| Azure | Azure Cache for Redis | Redis instance, connection string in env |
| GCP | Memorystore Redis | Memorystore instance, VPC connector |
| Standalone | In-memory (single instance) or DB | No external service. DB fallback for multi-instance |

#### Phase 12 — Token Revocation
| Provider | Required Service | Provisioning |
|----------|-----------------|-------------|
| All | Database (revoked_tokens table) | Migration applied. Optional: Redis for faster lookups (same as rate limiting) |

#### Phase 13 — Audit Logging
| Provider | Required Service | Provisioning |
|----------|-----------------|-------------|
| All | Database (audit_log table) | Migration applied. High-volume deployments may want to offload to dedicated store |

#### Phase 14 — Email
| Provider | Required Service | Provisioning |
|----------|-----------------|-------------|
| Cloudflare | SendGrid (external) | SendGrid API key in secrets |
| AWS | SES | Verified sender identity, SES out of sandbox (for production), IAM policy |
| Azure | Communication Services | Communication Services resource, email domain verified |
| GCP | SendGrid (external) | SendGrid API key in secrets |
| Standalone | SMTP or Console | SMTP server credentials or console output (dev) |

#### Phase 15 — Cache
| Provider | Required Service | Provisioning |
|----------|-----------------|-------------|
| Cloudflare | KV | Same KV namespace as rate limiting (separate key prefix) |
| AWS | ElastiCache Redis | Same as rate limiting (shared Redis) |
| Azure | Azure Cache for Redis | Same as rate limiting (shared Redis) |
| GCP | Memorystore Redis | Same as rate limiting (shared Redis) |
| Standalone | In-memory or DB | No external service |

### IaC Template Coverage

Each cloud provider's IaC template (Phase 6) must provision all services for all phases:

**`providers/aws/template.yaml`** (SAM) — **Parameterized** with `DatabaseType` parameter (`sqlite-efs`, `turso`, or `postgres`):
- Lambda function + API Gateway (always)
- **If sqlite-efs**: EFS file system + access point + mount target, VPC + subnets + security groups. Lambda gets EFS mount at `/mnt/efs`. Uses `better-sqlite3` Node.js adapter. Cost: ~$0.30/GB/month for EFS
- **If turso**: Turso URL + auth token in Secrets Manager (no VPC needed for DB). Cost: free tier up to 9GB
- **If postgres**: RDS PostgreSQL (or Aurora Serverless v2), VPC + subnets + security groups
- S3 bucket (storage)
- Secrets Manager secret (JWT_SECRET + auth provider configs)
- SQS queue (task queue)
- ElastiCache Redis (cache + rate limiting) — **optional**, omitted for free tier (uses DB fallback)
- SES identity (email, if used)
- IAM roles + policies
- CloudWatch alarms

**`providers/aws/ecs/template.yaml`** (SAM) — additional ECS resources:
- All of the above, plus:
- ECS Fargate cluster + service + task definition
- ALB + target group
- ECR repository
- **If sqlite**: EFS file system + mount target (persistent volume for SQLite)
- **If turso**: Turso env vars (no EFS needed)
- **If postgres**: RDS + VPC

**`providers/azure/bicep/main.bicep`** — **Parameterized** with `databaseType` (`sqlite-files`, `turso`, `postgres`):
- Functions App / Container Apps Environment (always)
- **If sqlite-files**: Azure Storage Account + File Share (SMB), mounted to Functions/Container Apps. SQLite at mount path. Cost: ~$0.06/GB/mo
- **If turso**: Turso URL + auth token in Key Vault (no VNet needed for DB)
- **If postgres**: PostgreSQL Flexible Server, VNet integration
- Blob Storage account + container (for file storage — separate from DB Files share)
- Key Vault
- Service Bus namespace + queue
- Azure Cache for Redis — **optional**, omitted for free tier
- Communication Services (email)
- Managed Identity + role assignments
- Application Insights

**`providers/gcp/terraform/main.tf`** — **Parameterized** with `database_type` variable (`sqlite-filestore`, `turso`, `postgres`):
- Cloud Functions / Cloud Run service (always)
- **If sqlite-filestore**: Filestore instance (Zonal tier, starting at 10GB), VPC connector, NFS volume mount. SQLite at `/mnt/filestore/eldrin.db`. Cost: from ~$0.20/GB/mo
- **If turso**: Turso URL + auth token in Secret Manager (no VPC connector needed for DB)
- **If postgres**: Cloud SQL PostgreSQL instance, VPC connector
- Cloud Storage bucket (for file storage — separate from DB)
- Secret Manager secrets
- Cloud Tasks queue
- Memorystore Redis instance — **optional**, omitted for free tier
- Artifact Registry (for Cloud Run)
- IAM service accounts + bindings
- Cloud Monitoring alert policies

**`providers/cloudflare/wrangler.jsonc`**:
- Workers script
- D1 database binding (free) — or Hyperdrive binding for external PG (paid)
- R2 bucket binding (storage)
- KV namespace binding (cache + rate limiting)
- Queues producer + consumer (task queue)
- Environment variables + secrets
- Custom domain / route

### Environment Variables Reference

All services are configured via environment variables. Each provider adapter reads these and initializes the correct adapters.

```
# === Core (required) ===
JWT_SECRET=                    # Secret for signing Eldrin JWTs
DATABASE_TYPE=                 # d1 | sqlite | turso | postgres (auto-detected if omitted)

# Database: SQLite (containers + standalone)
DATABASE_PATH=./data/eldrin.db # Path to SQLite file

# Database: Turso/libSQL (serverless-friendly SQLite, free tier)
TURSO_URL=                     # e.g., libsql://my-db-myorg.turso.io
TURSO_AUTH_TOKEN=              # Turso auth token

# Database: PostgreSQL (paid/scalable)
DATABASE_URL=                  # e.g., postgres://user:pass@host:5432/eldrin

# For Cloudflare: DB is a D1 binding (free) or Hyperdrive binding (PG), not env vars

# === Auth Providers (optional, enable per provider) ===
AUTH_ENTRA_ENABLED=true
AUTH_ENTRA_TENANT_ID=
AUTH_ENTRA_CLIENT_ID=
AUTH_ENTRA_CLIENT_SECRET=

AUTH_GOOGLE_ENABLED=true
AUTH_GOOGLE_CLIENT_ID=
AUTH_GOOGLE_CLIENT_SECRET=

AUTH_COGNITO_ENABLED=true
AUTH_COGNITO_USER_POOL_ID=
AUTH_COGNITO_REGION=
AUTH_COGNITO_CLIENT_ID=

AUTH_OIDC_ENABLED=true         # Generic OIDC
AUTH_OIDC_ISSUER=
AUTH_OIDC_CLIENT_ID=
AUTH_OIDC_CLIENT_SECRET=

# === Storage ===
STORAGE_PROVIDER=s3|azure-blob|gcs|r2|local
STORAGE_BUCKET=
STORAGE_REGION=
STORAGE_PATH=./data/storage    # Local only
AWS_ACCESS_KEY_ID=             # S3 (if not using IAM role)
AWS_SECRET_ACCESS_KEY=         # S3 (if not using IAM role)

# === Cache ===
CACHE_PROVIDER=memory|kv|redis|database
REDIS_URL=                     # Redis connection string

# === Task Queue ===
QUEUE_PROVIDER=database|sqs|azure-service-bus|cloud-tasks|cf-queues
SQS_QUEUE_URL=
AZURE_SERVICE_BUS_CONNECTION_STRING=
GCP_CLOUD_TASKS_QUEUE=

# === Email ===
EMAIL_PROVIDER=ses|sendgrid|smtp|azure-comm|console
EMAIL_FROM=noreply@example.com
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
SENDGRID_API_KEY=
AZURE_COMM_CONNECTION_STRING=

# === Security ===
ALLOWED_ORIGINS=https://app.example.com
CORS_CREDENTIALS=true
HSTS_MAX_AGE=31536000
RATE_LIMIT_PROVIDER=memory|database|kv|redis

# === Observability ===
LOG_LEVEL=info
METRICS_ENABLED=true
APPLICATIONINSIGHTS_CONNECTION_STRING=  # Azure only
```

---

## Implementation Order

Phases have dependencies — recommended execution order:

1. **Phase 1** (SDK fixes) — no dependencies, unblocks everything
2. **Phase 9** (Observability) — logger needed by nearly all other phases
3. **Phase 8** (Secrets) — needed before cloud adapters can configure themselves
4. **Phase 15** (Cache) — needed by auth providers, rate limiting
5. **Phase 2** (Unified Hono app) — core consolidation
6. **Phase 16** (CORS/Security headers) — middleware for the unified app
7. **Phase 11** (Rate limiting) — security before auth endpoints go live
8. **Phase 12** (Token revocation) — needed before expanding auth
9. **Phase 13** (Audit logging) — record auth events from Phase 3 onward
10. **Phase 3** (Auth providers) — depends on cache, secrets, audit, revocation
11. **Phase 14** (Email) — used by auth for approval notifications
12. **Phase 10** (Background jobs) — used by email, webhook delivery
13. **Phase 7** (Storage) — independent, can happen anytime after Phase 2
14. **Phase 4** (Cloud adapters) — depends on Phase 2 + all core services
15. **Phase 5** (Build system) — depends on Phase 4
16. **Phase 6** (IaC templates) — depends on Phase 4
17. **Phase 17** (CI/CD) — depends on Phase 5
18. **Phase 18** (Migration tooling) — can happen anytime after Phase 2

---

## Verification

### Build & Deploy
1. **SDK**: `cd eldrin-app-core && npm run typecheck` passes
2. **Cloudflare**: `npm run build:cloudflare` succeeds, `npm run dev` serves on port 4000
3. **Standalone**: `npm run build:standalone` produces working binary
4. **AWS Lambda**: `npm run build:aws-lambda` produces bundle in `dist/aws-lambda/`
5. **Docker builds**: All Dockerfiles build successfully
6. **Route parity**: All routes from worker/index.ts present in core/app.ts with permission checks
7. **Backward compat**: Re-export shims in `worker/` and `server/` resolve correctly

### Authentication & Security
8. **Auth providers**: `GET /api/auth/providers` returns enabled providers list
9. **Local login**: POST /api/auth/login still works (backward compatible)
10. **OIDC flow**: Configure test provider → authorize → callback → receive Eldrin JWT
11. **Account linking**: Login with local, then link Google → both identities in `/api/auth/identities`
12. **Pending user**: New external user gets PENDING status → admin approves → user becomes active
13. **Token revocation**: Logout revokes token, subsequent requests with same token get 401
14. **Rate limiting**: 11th login attempt within 1 minute returns 429 with Retry-After header
15. **CORS**: Cross-origin requests from allowed origin succeed, disallowed origin blocked
16. **Security headers**: Response includes HSTS, X-Content-Type-Options, CSP headers

### Infrastructure Services
17. **Storage**: Upload file via `/api/storage/upload`, download via `/api/storage/download/:key`
18. **Cache**: JWKS keys cached, second IdP token validation skips HTTP fetch
19. **Audit log**: Login produces audit entry, `GET /api/audit?action=auth.login` returns it
20. **Email**: User approval triggers email notification (console adapter in dev)
21. **Background jobs**: Enqueue webhook delivery task, verify delivery with retries
22. **Observability**: Structured JSON logs with requestId, metrics endpoint serves counters

### Migration
23. **Data export**: `eldrin export --output backup.json` produces valid backup
24. **Data import**: `eldrin import --input backup.json --dry-run` reports expected changes
25. **DB migration**: SQLite → PostgreSQL migration preserves all data
