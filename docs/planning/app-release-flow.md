# Eldrin App Release Flow

This document describes the end-to-end process for releasing an Eldrin app to the marketplace, from development through distribution.

## Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           APP DEVELOPMENT                                   │
│  Developer builds app using @eldrin/eldrin-app-core SDK                            │
│  ├── src/           React components                                        │
│  ├── migrations/    SQL migration files                                     │
│  └── worker/        Cloudflare Worker (optional)                            │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           BUILD PHASE                                       │
│  npm run build:lib → produces single-spa compatible bundle                  │
│  npm run generate:migrations → embeds migrations for worker                 │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SUBMISSION PHASE                                  │
│  1. Create PR in eldrin-marketplace-dist                                    │
│  2. GitHub Actions validate manifest, checksums, security                   │
│  3. Review by Eldrin team                                                   │
│  4. Merge to main                                                           │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           DISTRIBUTION                                      │
│  Apps available via GitHub raw URLs:                                        │
│  https://raw.githubusercontent.com/.../eldrin.io/invoicing/v0.0.1/          │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           RUNTIME                                           │
│  eldrin-core (shell) loads manifest, validates license, runs migrations     │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Current Implementation Status

### Implemented Components

| Component | Location | Status |
|-----------|----------|--------|
| App SDK | `packages/app-core` | Complete |
| Migration Runner (SDK) | `packages/app-core/src/migrations/runner.ts` | Complete |
| Vite Plugin | `packages/app-core/src/vite.ts` | Complete |
| Sample App | `eldrin-invoicing` | Complete |
| Marketplace Dist Repo | `eldrin-marketplace-dist` | Structure exists |
| License Server | `eldrin-website/worker` | Implemented |
| Manifest Loader | `eldrin-core/src/services/manifestLoader.ts` | Implemented |
| Bundle Decryptor | `eldrin-core/src/services/bundleDecryptor.ts` | Implemented |
| Migration Runner (Shell) | `eldrin-core/src/services/migrationRunner.ts` | Implemented |

### Missing Components

| Component | Description | Priority |
|-----------|-------------|----------|
| GitHub Actions | Automated validation on PR | High |
| App Submission API | `/api/apps/submit` endpoint | Medium |
| Migration Export Script | Generate marketplace format | High |
| Encryption Script | Encrypt paid app bundles | Medium |

---

## Detailed Flow

### Step 1: App Development

Apps are built using `@eldrin/eldrin-app-core` SDK:

```typescript
// src/eldrin-invoicing.tsx
import singleSpaReact from 'single-spa-react';

const lifecycles = singleSpaReact({
  React,
  ReactDOMClient,
  rootComponent: Root,
  domElementGetter: () => document.getElementById('single-spa-application:invoicing')!,
});

export const { bootstrap, mount, unmount } = lifecycles;
```

### Step 2: Build

```bash
# Build single-spa library bundle
npm run build:lib  # Outputs: dist/eldrin-invoicing.js
```

The build process:
1. Runs `generate:migrations` to embed SQL files for the worker
2. Compiles TypeScript
3. Bundles with Vite in library mode

### Step 3: Prepare Marketplace Package

Create the following structure in `eldrin-marketplace-dist`:

```
eldrin-marketplace-dist/
└── {developer_id}/
    └── {app_name}/
        └── v{version}/
            ├── manifest.json           # App metadata
            ├── bundle.js               # Free apps
            ├── bundle.enc.js           # Paid apps (encrypted)
            ├── meta.json               # Encryption metadata
            └── migrations/
                ├── index.json          # Migration manifest
                └── *.sql               # SQL files
```

### Step 4: Submit via Marketplace API

Use the `eldrin-submit` CLI tool from `@eldrin/eldrin-app-core`:

```bash
# Set your developer credentials
export ELDRIN_API_KEY="your-api-key"
export ELDRIN_DEVELOPER_ID="eldrin.io"

# Submit the release
npx eldrin-submit -d ./dist/release/eldrin.io/invoicing/v0.0.1

# Or use the combined script in your app
npm run submit
```

The submission tool:
1. Authenticates with your developer API key
2. Uploads all release files to the marketplace API
3. Creates a release branch in `eldrin-marketplace-dist`
4. Opens a PR against the `test` branch

**Configuration options:**
- `--api-key` or `ELDRIN_API_KEY` - Your developer API key
- `--developer-id` or `ELDRIN_DEVELOPER_ID` - Your developer ID
- `--marketplace-url` - Custom marketplace URL (default: https://eldrin.io)
- `--description` - PR description
- `--dry-run` - Preview without submitting

**Config file (.eldrinrc.json):**
```json
{
  "developerId": "your-developer-id",
  "marketplaceUrl": "https://eldrin.io"
}
```

### Step 5: Review & Merge

1. Automated checks run on the PR
2. Eldrin team reviews the submission
3. Merge to `test` branch for testing
4. Promote to `main` for production

### Step 6: Runtime Loading

When a customer enables the app:

1. Shell fetches manifest from marketplace
2. Validates license (for paid apps)
3. Decrypts bundle (for paid apps)
4. Runs pending migrations
5. Registers with single-spa

---

## Aligned Decisions

The following decisions have been made to resolve discrepancies between code and documentation:

### 1. Migration File Naming Convention

**Decision**: Keep the timestamp format (`YYYYMMDDHHMMSS-description.sql`)

**Rationale**:
- Provides natural ordering without gaps
- Prevents ID conflicts in distributed development
- Already validated by `isValidMigrationFilename()` in app-core
- Currently used by eldrin-invoicing

**Example**:
```
migrations/
├── 20250120100000-create-invoices-table.sql
├── 20250120100100-create-line-items-table.sql
```

### 2. Migration Manifest Format

**Decision**: Option A - Transform at build time in `@eldrin/eldrin-app-core`

The app-core package will provide utilities to generate the marketplace migration format:

```typescript
// New export from @eldrin/eldrin-app-core
import { generateMigrationManifest } from '@eldrin/eldrin-app-core';

// Generates migrations/index.json for marketplace distribution
const manifest = await generateMigrationManifest({
  migrationsDir: './migrations',
  database: 'invoicing',
});
```

**Output format** (`migrations/index.json`):
```json
{
  "database": "invoicing",
  "migrations": [
    {
      "id": "20250120100000",
      "file": "20250120100000-create-invoices-table.sql",
      "checksum": "sha256:abc123..."
    }
  ]
}
```

### 3. Manifest Filename

**Decision**: Use `eldrin-app.manifest.json`

**Rationale**:
- Clearly identifies Eldrin-specific manifests
- Avoids confusion with npm's `package.json`
- Aligns with original documentation

**Action**: Rename existing `manifest.json` files in marketplace-dist.

### 4. Migration Execution Location

**Decision**: Each app handles its own migrations

**Rationale**:
- Apps know their own database schema best
- Worker-based apps already do this (eldrin-invoicing)
- Simpler architecture - shell doesn't need migration logic
- Better isolation and error handling per app

**Implementation**:
- App's Cloudflare Worker runs migrations on first request
- Shell does NOT run migrations - only loads the app bundle
- `eldrin-core/src/services/migrationRunner.ts` can be deprecated

**Manifest indication**:
```json
{
  "database": {
    "name": "invoicing",
    "migrationsPath": "migrations",
    "handledBy": "worker"
  }
}
```

### 5. Checksum Format

**Decision**: Use prefixed format (`sha256:...`)

**Rationale**:
- Explicit about algorithm used
- Future-proof for other hash algorithms
- Matches marketplace-dist documentation

**Action**: Update `@eldrin/eldrin-app-core` checksum functions to support prefixed output.

---

## Proposed Build Script for Release

Create `scripts/release.ts` in app projects:

```typescript
/**
 * Prepares app for marketplace submission
 *
 * Usage: npx tsx scripts/release.ts --version 0.0.1
 */

interface ReleaseConfig {
  developerId: string;
  appId: string;
  version: string;
  isPaid: boolean;
}

async function release(config: ReleaseConfig) {
  const outputDir = `dist/release/${config.developerId}/${config.appId}/v${config.version}`;

  // 1. Build library bundle
  await exec('npm run build:lib');

  // 2. Copy bundle
  await copyFile('dist/eldrin-invoicing.js', `${outputDir}/bundle.js`);

  // 3. Generate migration manifest
  const migrations = await readMigrations('./migrations');
  const manifest = {
    database: config.appId,
    migrations: await Promise.all(migrations.map(async (m) => ({
      id: extractId(m.name),
      file: m.name,
      checksum: `sha256:${await calculateChecksum(m.content)}`,
    }))),
  };
  await writeFile(`${outputDir}/migrations/index.json`, JSON.stringify(manifest, null, 2));

  // 4. Copy SQL files
  for (const m of migrations) {
    await copyFile(`migrations/${m.name}`, `${outputDir}/migrations/${m.name}`);
  }

  // 5. Copy manifest
  await copyFile('manifest.json', `${outputDir}/manifest.json`);

  // 6. Encrypt if paid (TODO)
  if (config.isPaid) {
    // await encryptBundle(...)
  }

  console.log(`Release package created at ${outputDir}`);
}
```

---

## GitHub Actions Workflow

Create `.github/workflows/app-submission.yml` in eldrin-marketplace-dist:

```yaml
name: App Submission Validation

on:
  pull_request:
    branches: [main]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Find changed apps
        id: changed
        run: |
          # Find added/modified manifest files
          MANIFESTS=$(git diff --name-only ${{ github.event.pull_request.base.sha }} | grep 'manifest.json' || true)
          echo "manifests=$MANIFESTS" >> $GITHUB_OUTPUT

      - name: Validate manifest schema
        run: |
          for manifest in ${{ steps.changed.outputs.manifests }}; do
            npx ajv validate -s schema/manifest.schema.json -d "$manifest"
          done

      - name: Verify migration checksums
        run: |
          for manifest in ${{ steps.changed.outputs.manifests }}; do
            dir=$(dirname "$manifest")
            if [ -f "$dir/migrations/index.json" ]; then
              node scripts/verify-checksums.js "$dir/migrations"
            fi
          done

      - name: Security scan
        run: |
          # Scan bundle.js for suspicious patterns
          node scripts/security-scan.js

      - name: Notify reviewers
        if: success()
        run: |
          gh pr comment ${{ github.event.pull_request.number }} \
            --body "Automated checks passed. Ready for review."
```

---

## Action Items

### Completed

1. ~~Add migration manifest generation to app-core~~: `generateMigrationManifest()` function added
2. ~~Update checksum format~~: Added `sha256:` prefix with `calculatePrefixedChecksum()`
3. ~~Rename manifest files~~: Changed to `eldrin-app.manifest.json` in marketplace-dist
4. ~~Deprecate shell migrationRunner~~: Marked deprecated in eldrin-core
5. ~~Create release script~~: Added to eldrin-invoicing as example
6. ~~App submission API~~: Added `/api/apps/submit` to eldrin-website
7. ~~Submission CLI~~: Added `eldrin-submit` to @eldrin/eldrin-app-core
8. ~~Database schema for developers~~: Added `developers`, `developer_api_keys`, `developer_invites`, and `app_submissions` tables
9. ~~Developer registration API~~: Added `/api/developers/register`, `/api/developers/:id`, `/api/developers/:id/keys` endpoints
10. ~~Admin invite API~~: Added `/api/admin/invites` endpoint

### Pending

1. **Encryption tooling**: Script to encrypt paid app bundles
2. **Rollback support**: Implement rollback for failed migrations
3. **Versioning**: Support for major version upgrades with breaking changes
4. **Create `test` branch**: Set up `test` branch in eldrin-marketplace-dist for PR targets
5. **Admin authentication**: Add proper admin authentication to `/api/admin/invites`

---

## File Reference

### SDK (packages/app-core)

| File | Purpose |
|------|---------|
| `src/index.ts` | Main exports |
| `src/vite.ts` | Vite plugin for virtual migration module |
| `src/migrations/runner.ts` | Migration execution |
| `src/migrations/checksum.ts` | SHA-256 checksum calculation |
| `src/migrations/sql-parser.ts` | SQL statement parsing |

### Sample App (eldrin-invoicing)

| File | Purpose |
|------|---------|
| `package.json` | Build scripts |
| `vite.config.ts` | Vite config with eldrinPlugin |
| `scripts/generate-migrations.ts` | Worker migration embedding |
| `worker/index.ts` | Cloudflare Worker entry |
| `worker/migrations.generated.ts` | Auto-generated migration data |
| `migrations/*.sql` | SQL migration files |

### Shell (eldrin-core)

| File | Purpose |
|------|---------|
| `src/services/manifestLoader.ts` | Fetch and validate manifests |
| `src/services/migrationRunner.ts` | Run migrations for marketplace apps |
| `src/services/licenseValidator.ts` | License validation |
| `src/services/bundleDecryptor.ts` | AES-GCM bundle decryption |

### Marketplace (eldrin-website)

| File | Purpose |
|------|---------|
| `worker/index.ts` | API routes |
| `worker/handlers/license.ts` | License validation handlers |
| `worker/handlers/seats.ts` | Seat management for per-user licenses |
| `worker/handlers/submission.ts` | App submission via GitHub API |
| `worker/handlers/developers.ts` | Developer registration and API key management |
| `worker/services/jwt.ts` | JWT signing/verification |
| `worker/services/encryption.ts` | Key management |
| `migrations/0002_create_developer_api_keys.sql` | Developer tables schema |

### Distribution (eldrin-marketplace-dist)

| File | Purpose |
|------|---------|
| `README.md` | Repository documentation |
| `{dev}/{app}/{ver}/eldrin-app.manifest.json` | App metadata |
| `{dev}/{app}/{ver}/bundle.js` | App bundle |
| `{dev}/{app}/{ver}/migrations/` | Migration files |

---

## Appendix: Manifest Schema

```typescript
interface AppManifest {
  id: string;                    // App identifier (e.g., "invoicing")
  name: string;                  // Display name
  version: string;               // SemVer (e.g., "0.0.1")
  description: string;           // Short description

  developer: {
    id: string;                  // Developer identifier
    name: string;                // Developer display name
  };

  compatibility: {
    core: string;                // SemVer range (e.g., ">=0.1.0")
  };

  entry: string;                 // Bundle filename (e.g., "bundle.js")
  encryptedEntry?: string;       // Encrypted bundle for paid apps

  pricing?: {
    model: 'free' | 'one-time' | 'subscription' | 'per-user';
    plans?: Array<{
      id: string;
      name: string;
      price: number;
      currency: string;
      interval?: 'month' | 'year';
      features: string[];
    }>;
  };

  database?: {
    name: string;                // Logical database name
    migrationsPath: string;      // Path to migrations folder
  };

  ui?: {
    sideNav?: Array<{
      label: string;
      icon: string;
      path: string;
      permission: string;
    }>;
    dashboardWidgets?: Array<{
      id: string;
      name: string;
      component: string;
      defaultSize: 'small' | 'medium' | 'large';
    }>;
  };

  assets?: {
    icon?: string;
  };
}
```
