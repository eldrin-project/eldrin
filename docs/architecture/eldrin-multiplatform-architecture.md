# Eldrin Multi-Platform Architecture Plan

## Vision

Create a platform-agnostic deployment system where:
- **Admin** selects provider (Cloudflare/AWS/Azure/GCP) and database (SQLite/PostgreSQL) for core
- **Developers** create apps with chosen frontend framework (React/Angular/Vue/Svelte)
- **Apps** inherit platform from core, user selects database

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         eldrin.config.ts                                 │
│              (Single unified configuration file)                         │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
            ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
            │ @eldrin/aws │ │@eldrin/azure│ │ @eldrin/gcp │
            └─────────────┘ └─────────────┘ └─────────────┘
                    │               │               │
                    └───────────────┼───────────────┘
                                    ▼
                    ┌─────────────────────────────────┐
                    │     @eldrin/eldrin-app-core     │
                    │   (Database + Runtime adapters) │
                    └─────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
            ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
            │ D1 Adapter  │ │  Postgres   │ │   MySQL     │
            │  (SQLite)   │ │  Adapter    │ │  Adapter    │
            └─────────────┘ └─────────────┘ └─────────────┘
```

---

## Package Structure

### New Packages to Create

| Package | Purpose |
|---------|---------|
| `@eldrin-project/eldrin-aws` | AWS Lambda + API Gateway + RDS adapters |
| `@eldrin-project/eldrin-azure` | Azure Functions + Azure SQL adapters |
| `@eldrin-project/eldrin-gcp` | GCP Cloud Functions + Cloud SQL adapters |
| `@eldrin-project/eldrin-config` | Unified config parser and provider-specific config generators |

### Existing Packages to Extend

| Package | Changes |
|---------|---------|
| `eldrin-app-core` | Add PostgreSQL adapter, runtime abstraction interface |
| `eldrin-templates` | Add templates for all provider/framework/database combinations |

---

## Phase 1: Database Abstraction

### 1.1 Add PostgreSQL Adapter to eldrin-app-core

**File:** `/eldrin-app-core/adapters/database/postgres.ts`

```typescript
export class PostgresAdapter implements DatabaseAdapter {
  constructor(private client: Client) {}

  prepare(query: string): PreparedStatement {
    // Convert ? placeholders to $1, $2, ...
    return new PostgresPreparedStatement(this.client, convertPlaceholders(query));
  }
}
```

### 1.2 Database Factory

**File:** `/eldrin-app-core/adapters/database/factory.ts`

```typescript
export type DatabaseType = 'd1' | 'postgres' | 'mysql';

export function createDatabaseAdapter(
  type: DatabaseType,
  connection: unknown
): DatabaseAdapter {
  switch (type) {
    case 'd1': return createD1Adapter(connection as D1Database);
    case 'postgres': return createPostgresAdapter(connection as string);
    case 'mysql': return createMySQLAdapter(connection as string);
  }
}
```

---

## Phase 2: Runtime Abstraction

### 2.1 Runtime Interface

**File:** `/eldrin-app-core/adapters/runtime/interface.ts`

```typescript
export interface RuntimeAdapter {
  /** Handle incoming HTTP request */
  handleRequest(handler: RequestHandler): void;

  /** Get environment variable */
  getEnv(key: string): string | undefined;

  /** Get database connection */
  getDatabase(): DatabaseAdapter;

  /** Serve static assets */
  serveAssets?(path: string): Promise<Response>;
}

export type RequestHandler = (
  request: Request,
  db: DatabaseAdapter,
  env: Record<string, string>
) => Promise<Response>;
```

### 2.2 Provider-Specific Runtime Adapters

Each provider package implements `RuntimeAdapter`:

**Cloudflare (existing in eldrin-app-core):**
```typescript
// Uses Cloudflare Workers fetch handler
export class CloudflareRuntime implements RuntimeAdapter { ... }
```

**AWS Lambda (@eldrin-project/eldrin-aws):**
```typescript
// Converts API Gateway events to Request/Response
export class AWSLambdaRuntime implements RuntimeAdapter { ... }
```

**Azure Functions (@eldrin-project/eldrin-azure):**
```typescript
// Converts Azure HTTP triggers to Request/Response
export class AzureFunctionsRuntime implements RuntimeAdapter { ... }
```

**GCP Cloud Functions (@eldrin-project/eldrin-gcp):**
```typescript
// Converts GCP HTTP functions to Request/Response
export class GCPCloudFunctionsRuntime implements RuntimeAdapter { ... }
```

---

## Phase 3: Unified Configuration

### 3.1 eldrin.config.ts Schema

**File:** `eldrin.config.ts` (in each project)

```typescript
import { defineConfig } from '@eldrin-project/eldrin-config';

export default defineConfig({
  // App metadata
  app: {
    name: 'my-todo-app',
    version: '1.0.0',
  },

  // Deployment provider
  provider: {
    type: 'cloudflare', // | 'aws' | 'azure' | 'gcp'

    // Provider-specific options
    cloudflare: {
      accountId: 'xxx',
      compatibilityDate: '2025-01-01',
    },
    aws: {
      region: 'us-east-1',
      runtime: 'nodejs20.x',
    },
    azure: {
      region: 'eastus',
      resourceGroup: 'eldrin-apps',
    },
    gcp: {
      project: 'my-project',
      region: 'us-central1',
    },
  },

  // Database configuration
  database: {
    type: 'sqlite', // | 'postgres'

    // Provider-specific database options
    d1: {
      databaseName: 'my-app-db',
    },
    postgres: {
      // For Cloudflare: Hyperdrive ID
      hyperdriveId: 'xxx',
      // For AWS/Azure/GCP: Connection string env var
      connectionStringEnvVar: 'DATABASE_URL',
    },
  },

  // Build configuration
  build: {
    outDir: 'dist',
    assets: 'dist/browser',
  },
});
```

### 3.2 Config Generator

**Package:** `@eldrin-project/eldrin-config`

Reads `eldrin.config.ts` and generates provider-specific configs:

| Provider | Generated File |
|----------|----------------|
| Cloudflare | `wrangler.jsonc` |
| AWS | `serverless.yml` or `template.yaml` (SAM) |
| Azure | `host.json` + `function.json` |
| GCP | `app.yaml` or Cloud Functions config |

---

## Phase 4: Provider Packages

### 4.1 @eldrin-project/eldrin-aws

```
eldrin-aws/
├── src/
│   ├── runtime/
│   │   └── lambda.ts         # Lambda runtime adapter
│   ├── database/
│   │   └── rds.ts            # RDS connection helper
│   ├── deploy/
│   │   └── sam-generator.ts  # SAM template generator
│   └── index.ts
├── package.json
└── README.md
```

**Key features:**
- API Gateway → Request/Response conversion
- RDS PostgreSQL/MySQL connection pooling
- SAM/Serverless Framework template generation
- S3 static asset serving

### 4.2 @eldrin-project/eldrin-azure

```
eldrin-azure/
├── src/
│   ├── runtime/
│   │   └── functions.ts      # Azure Functions adapter
│   ├── database/
│   │   └── azure-sql.ts      # Azure SQL connection
│   ├── deploy/
│   │   └── config-generator.ts
│   └── index.ts
```

**Key features:**
- HTTP trigger → Request/Response conversion
- Azure SQL Database connection
- Azure Functions config generation
- Blob Storage static asset serving

### 4.3 @eldrin-project/eldrin-gcp

```
eldrin-gcp/
├── src/
│   ├── runtime/
│   │   └── cloud-functions.ts # GCP Cloud Functions adapter
│   ├── database/
│   │   └── cloud-sql.ts       # Cloud SQL connection
│   ├── deploy/
│   │   └── config-generator.ts
│   └── index.ts
```

**Key features:**
- HTTP function → Request/Response conversion
- Cloud SQL PostgreSQL/MySQL connection
- App Engine / Cloud Functions config generation
- Cloud Storage static asset serving

---

## Phase 5: Template Expansion

### 5.1 Template Matrix

Current: 3 templates (Cloudflare only)
Target: **32 templates** (4 providers × 4 frameworks × 2 databases)

| Provider | Framework | Database | Template Name |
|----------|-----------|----------|---------------|
| Cloudflare | React | SQLite | `cloudflare-react-sqlite` |
| Cloudflare | React | PostgreSQL | `cloudflare-react-postgres` |
| Cloudflare | Angular | SQLite | `cloudflare-angular-sqlite` |
| Cloudflare | Angular | PostgreSQL | `cloudflare-angular-postgres` |
| Cloudflare | Vue | SQLite | `cloudflare-vue-sqlite` |
| Cloudflare | Vue | PostgreSQL | `cloudflare-vue-postgres` |
| Cloudflare | Svelte | SQLite | `cloudflare-svelte-sqlite` |
| Cloudflare | Svelte | PostgreSQL | `cloudflare-svelte-postgres` |
| AWS | React | SQLite | `aws-react-sqlite` |
| AWS | React | PostgreSQL | `aws-react-postgres` |
| ... | ... | ... | ... |

### 5.2 Template Structure (Provider-Specific)

**Cloudflare template:**
```
cloudflare-react-postgres/
├── worker/index.ts           # Cloudflare Worker
├── wrangler.jsonc.template   # Cloudflare config
├── eldrin.config.ts.template # Unified config
└── ...
```

**AWS template:**
```
aws-react-postgres/
├── lambda/index.ts           # Lambda handler
├── template.yaml.template    # SAM template
├── eldrin.config.ts.template # Unified config
└── ...
```

### 5.3 Shared Template Components

To reduce duplication, extract shared parts:

```
templates/
├── _shared/
│   ├── frontend/
│   │   ├── react/           # React app structure
│   │   ├── angular/         # Angular app structure
│   │   ├── vue/             # Vue app structure
│   │   └── svelte/          # Svelte app structure
│   ├── migrations/
│   │   ├── sqlite/          # SQLite migrations
│   │   └── postgres/        # PostgreSQL migrations
│   └── manifest/            # Shared manifest structure
├── cloudflare-react-sqlite/
│   └── ... (provider-specific files only)
└── aws-react-postgres/
    └── ... (provider-specific files only)
```

---

## Phase 6: CLI Updates

### 6.1 Enhanced Prompts

**File:** `/eldrin-templates/src/prompts.ts`

```typescript
const providerChoices = [
  { name: 'Cloudflare Workers', value: 'cloudflare' },
  { name: 'AWS Lambda', value: 'aws' },
  { name: 'Azure Functions', value: 'azure' },
  { name: 'Google Cloud Functions', value: 'gcp' },
];

const databaseChoices = [
  { name: 'SQLite (D1/Local)', value: 'sqlite' },
  { name: 'PostgreSQL', value: 'postgres' },
];
```

### 6.2 Config Generation

After scaffolding, generate provider-specific config:

```typescript
// Generate eldrin.config.ts
await generateEldrinConfig(options);

// Generate provider-specific deployment config
await generateProviderConfig(options.provider, options);
```

---

## Implementation Order

### Milestone 1: Database Foundation
1. Add PostgreSQL adapter to `eldrin-app-core`
2. Update `angular-todo` to use database abstraction (POC)
3. Test with Cloudflare Hyperdrive

### Milestone 2: Configuration System
4. Create `@eldrin-project/eldrin-config` package
5. Define `eldrin.config.ts` schema
6. Implement config generators for Cloudflare

### Milestone 3: AWS Support
7. Create `@eldrin-project/eldrin-aws` package
8. Implement Lambda runtime adapter
9. Add AWS templates to `eldrin-templates`
10. Test end-to-end AWS deployment

### Milestone 4: Azure Support
11. Create `@eldrin-project/eldrin-azure` package
12. Implement Azure Functions adapter
13. Add Azure templates

### Milestone 5: GCP Support
14. Create `@eldrin-project/eldrin-gcp` package
15. Implement Cloud Functions adapter
16. Add GCP templates

### Milestone 6: Template Completion
17. Complete all 32 template combinations
18. Update CLI with all options enabled
19. Documentation and testing

---

## Key Files to Create/Modify

### New Files

| File | Purpose |
|------|---------|
| `/eldrin-app-core/adapters/database/postgres.ts` | PostgreSQL adapter |
| `/eldrin-app-core/adapters/runtime/interface.ts` | Runtime abstraction |
| `/eldrin-config/src/index.ts` | Config package |
| `/eldrin-aws/src/index.ts` | AWS package |
| `/eldrin-azure/src/index.ts` | Azure package |
| `/eldrin-gcp/src/index.ts` | GCP package |

### Files to Modify

| File | Changes |
|------|---------|
| `/eldrin-app-core/adapters/database/index.ts` | Export PostgreSQL adapter |
| `/eldrin-templates/src/prompts.ts` | Enable all provider/database options |
| `/angular-todo/worker/index.ts` | Use database abstraction |

---

## Database Considerations

### SQLite Compatibility Across Providers

| Provider | SQLite Option |
|----------|---------------|
| Cloudflare | D1 (native) |
| AWS | Lambda + EFS-mounted SQLite |
| Azure | Functions + Azure Files SQLite |
| GCP | Cloud Functions + GCS-mounted SQLite |

### PostgreSQL Connectivity

| Provider | PostgreSQL Option |
|----------|-------------------|
| Cloudflare | Hyperdrive (connection pooling) |
| AWS | RDS PostgreSQL |
| Azure | Azure Database for PostgreSQL |
| GCP | Cloud SQL PostgreSQL |

---

## Risk Mitigation

1. **Cold start latency**: Use connection pooling (Hyperdrive, RDS Proxy)
2. **SQL dialect differences**: Stick to ANSI SQL, test migrations on both
3. **Template maintenance**: Use shared components to reduce duplication
4. **Breaking changes**: Version provider packages independently
