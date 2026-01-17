# Eldrin Setup Wizard - Implementation Requirements

This document outlines the technical requirements for building the Setup Wizard application that facilitates platform deployment for end users.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [User Flows](#user-flows)
4. [Technical Requirements](#technical-requirements)
5. [API Specifications](#api-specifications)
6. [Security Requirements](#security-requirements)
7. [UI/UX Requirements](#uiux-requirements)
8. [Deployment](#deployment)

---

## Overview

### Purpose

The Setup Wizard is a standalone web application that guides users through deploying their own Eldrin platform instance to their Cloudflare account. It eliminates the need for technical expertise or command-line operations.

### Key Goals

1. **Zero CLI** - Users never need to open a terminal
2. **Guided Experience** - Step-by-step wizard with clear instructions
3. **Error Recovery** - Graceful handling of failures with retry options
4. **Security First** - Secure handling of API tokens and credentials

### Target Users

- Business owners with no technical background
- IT administrators with basic cloud knowledge
- Consultants deploying for clients

---

## Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         USER'S BROWSER                               │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                    SETUP WIZARD SPA                            │  │
│  │              (React + Tailwind + Vite)                         │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   │ HTTPS
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    ELDRIN SETUP API                                  │
│               (Cloudflare Workers)                                   │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐   │
│  │   Auth      │ │  Validator  │ │  Deployer   │ │  Progress   │   │
│  │  Service    │ │   Service   │ │   Service   │ │   Service   │   │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   │ Cloudflare API
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  USER'S CLOUDFLARE ACCOUNT                          │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐   │
│  │   Workers   │ │     D1      │ │     R2      │ │     KV      │   │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### Components

| Component | Technology | Purpose |
|-----------|------------|---------|
| Setup Wizard SPA | React, Tailwind, Vite | User interface |
| Setup API | Cloudflare Workers | Backend orchestration |
| Eldrin Registry | D1 + R2 | App manifests and bundles |
| Deployment Engine | Workers | Deploys to user's account |

---

## User Flows

### Main Flow

```
┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐
│ Welcome │────▶│ Connect │────▶│ Company │────▶│  Apps   │
│  Page   │     │Cloudflare│    │  Setup  │     │ Select  │
└─────────┘     └─────────┘     └─────────┘     └─────────┘
                                                     │
┌─────────┐     ┌─────────┐     ┌─────────┐         │
│ Success │◀────│ Deploy  │◀────│Integrate│◀────────┘
│  Page   │     │ Review  │     │  Setup  │
└─────────┘     └─────────┘     └─────────┘
```

### Flow States

```typescript
type WizardStep =
  | 'welcome'
  | 'cloudflare-connect'
  | 'company-info'
  | 'company-address'
  | 'platform-url'
  | 'app-selection'
  | 'users-roles'
  | 'integrations-email'
  | 'integrations-payments'
  | 'integrations-import'
  | 'review'
  | 'deploying'
  | 'success'
  | 'error';

interface WizardState {
  currentStep: WizardStep;
  completedSteps: WizardStep[];

  // Step 1: Cloudflare
  cloudflare: {
    apiToken: string;
    accountId: string;
    accountName: string;
    verified: boolean;
    permissions: {
      // Required
      d1: boolean;                  // D1
      workersKvStorage: boolean;    // Workers KV Storage
      workersR2Storage: boolean;    // Workers R2 Storage
      workersScripts: boolean;      // Workers Scripts
      cloudflarePages: boolean;     // Cloudflare Pages
      // Optional (Zone level)
      dns: boolean;                 // DNS (for custom domains)
    };
  };

  // Step 2: Company
  company: {
    name: string;
    industry: string;
    size: '1-10' | '11-50' | '51-200' | '200+';
    country: string;
    address: {
      street: string;
      city: string;
      state: string;
      zip: string;
    };
    taxId?: string;
  };

  // Step 3: Platform URL
  platform: {
    urlType: 'subdomain' | 'custom';
    subdomain?: string;
    customDomain?: string;
  };

  // Step 4: Apps
  apps: {
    selected: string[];
    dependencies: Record<string, string[]>;
  };

  // Step 5: Users
  users: {
    admin: {
      name: string;
      email: string;
      password: string;
    };
    invited: Array<{
      email: string;
      role: string;
    }>;
    roles: Array<{
      name: string;
      permissions: Record<string, string[]>;
    }>;
  };

  // Step 6: Integrations
  integrations: {
    email: {
      provider: 'eldrin' | 'sendgrid' | 'mailgun' | 'ses' | 'smtp';
      config?: Record<string, string>;
    };
    payments: {
      provider?: 'stripe' | 'paypal';
      connected: boolean;
    };
    imports: {
      products?: File;
      customers?: File;
      suppliers?: File;
    };
  };

  // Deployment
  deployment: {
    id?: string;
    status: 'pending' | 'in_progress' | 'completed' | 'failed';
    progress: number;
    currentTask: string;
    tasks: Array<{
      name: string;
      status: 'pending' | 'in_progress' | 'completed' | 'failed';
      error?: string;
    }>;
    platformUrl?: string;
  };
}
```

---

## Technical Requirements

### Frontend (Setup Wizard SPA)

#### Technology Stack

| Technology | Version | Purpose |
|------------|---------|---------|
| React | 19.x | UI framework |
| TypeScript | 5.x | Type safety |
| Tailwind CSS | 4.x | Styling |
| Vite | 7.x | Build tool |
| React Router | 7.x | Navigation |
| Zustand | 5.x | State management |
| React Hook Form | 7.x | Form handling |
| Zod | 3.x | Validation |

#### Key Features

1. **Multi-Step Wizard**
   - Progress indicator
   - Step validation before progression
   - Back/forward navigation
   - Step state persistence (localStorage)

2. **Form Handling**
   - Real-time validation
   - Clear error messages
   - Auto-save drafts
   - File upload (CSV imports)

3. **API Token Input**
   - Secure password-style input
   - Copy/paste support
   - Token validation feedback
   - Permission verification display

4. **App Selection**
   - Visual grid of apps
   - Dependency resolution
   - Search and filter
   - Category grouping

5. **Deployment Progress**
   - Real-time status updates (WebSocket or polling)
   - Task-by-task progress
   - Error display with retry option
   - Estimated time remaining

### Backend (Setup API)

#### Technology Stack

| Technology | Purpose |
|------------|---------|
| Cloudflare Workers | Serverless compute |
| Hono | Web framework |
| D1 | Wizard session storage |
| R2 | App bundle storage |
| Durable Objects | Deployment orchestration |

#### API Endpoints

```typescript
// Auth
POST   /api/auth/register     // Create wizard account
POST   /api/auth/login        // Login to existing session
POST   /api/auth/logout       // End session

// Cloudflare Verification
POST   /api/cloudflare/verify // Verify API token
GET    /api/cloudflare/zones  // List available zones (for custom domain)

// Apps
GET    /api/apps              // List all available apps
GET    /api/apps/:id          // Get app details
GET    /api/apps/:id/bundle   // Download app bundle

// Deployment
POST   /api/deployments       // Start deployment
GET    /api/deployments/:id   // Get deployment status
POST   /api/deployments/:id/retry // Retry failed deployment
DELETE /api/deployments/:id   // Cancel deployment

// Data Import
POST   /api/imports/validate  // Validate CSV file
POST   /api/imports/preview   // Preview import data

// Templates
GET    /api/templates/csv/:type // Download CSV template
```

### Deployment Engine

The Deployment Engine is a Durable Object that orchestrates the deployment process.

#### Deployment Tasks

```typescript
interface DeploymentTask {
  id: string;
  name: string;
  description: string;
  execute: (context: DeploymentContext) => Promise<void>;
  rollback?: (context: DeploymentContext) => Promise<void>;
}

const DEPLOYMENT_TASKS: DeploymentTask[] = [
  {
    id: 'create-d1-databases',
    name: 'Creating databases',
    description: 'Setting up D1 databases for each app',
    // Requires: D1 (Edit)
    execute: async (ctx) => {
      // Create D1 database for each selected app
      // API: POST /accounts/{account_id}/d1/database
      for (const app of ctx.apps) {
        await ctx.cloudflare.d1.create(`eldrin-${app.id}`);
      }
    },
  },
  {
    id: 'create-r2-buckets',
    name: 'Creating storage',
    description: 'Setting up R2 storage buckets',
    // Requires: Workers R2 Storage (Edit)
    execute: async (ctx) => {
      // API: POST /accounts/{account_id}/r2/buckets
      await ctx.cloudflare.r2.create('eldrin-assets');
      await ctx.cloudflare.r2.create('eldrin-uploads');
    },
  },
  {
    id: 'create-kv-namespaces',
    name: 'Creating KV storage',
    description: 'Setting up KV namespaces for sessions and cache',
    // Requires: Workers KV Storage (Edit)
    execute: async (ctx) => {
      // API: POST /accounts/{account_id}/storage/kv/namespaces
      await ctx.cloudflare.kv.create('eldrin-sessions');
      await ctx.cloudflare.kv.create('eldrin-cache');
    },
  },
  {
    id: 'deploy-shell',
    name: 'Deploying platform',
    description: 'Deploying Eldrin Shell worker',
    // Requires: Workers Scripts (Edit)
    execute: async (ctx) => {
      // API: PUT /accounts/{account_id}/workers/scripts/{script_name}
      const bundle = await ctx.registry.getBundle('eldrin-shell');
      await ctx.cloudflare.workers.deploy('eldrin', bundle, {
        bindings: ctx.bindings,
        routes: [ctx.platformUrl],
      });
    },
  },
  {
    id: 'deploy-apps',
    name: 'Deploying apps',
    description: 'Deploying selected applications',
    execute: async (ctx) => {
      for (const app of ctx.apps) {
        ctx.updateProgress(`Deploying ${app.name}...`);
        const bundle = await ctx.registry.getBundle(app.id);
        // Apps are bundled into the shell worker
        await ctx.shell.registerApp(app.id, bundle);
      }
    },
  },
  {
    id: 'run-migrations',
    name: 'Setting up data',
    description: 'Running database migrations',
    execute: async (ctx) => {
      for (const app of ctx.apps) {
        const migrations = await ctx.registry.getMigrations(app.id);
        await ctx.cloudflare.d1.migrate(`eldrin-${app.id}`, migrations);
      }
    },
  },
  {
    id: 'create-admin',
    name: 'Creating admin',
    description: 'Setting up administrator account',
    execute: async (ctx) => {
      await ctx.shell.createUser({
        email: ctx.admin.email,
        name: ctx.admin.name,
        password: ctx.admin.password,
        role: 'administrator',
      });
    },
  },
  {
    id: 'invite-users',
    name: 'Inviting users',
    description: 'Sending invitations to team members',
    execute: async (ctx) => {
      for (const user of ctx.invitedUsers) {
        await ctx.shell.inviteUser(user.email, user.role);
      }
    },
  },
  {
    id: 'import-data',
    name: 'Importing data',
    description: 'Importing uploaded data files',
    execute: async (ctx) => {
      if (ctx.imports.products) {
        await ctx.apps.catalog.importProducts(ctx.imports.products);
      }
      if (ctx.imports.customers) {
        await ctx.apps.crm.importContacts(ctx.imports.customers);
      }
      if (ctx.imports.suppliers) {
        await ctx.apps.purchasing?.importSuppliers(ctx.imports.suppliers);
      }
    },
  },
  {
    id: 'configure-integrations',
    name: 'Configuring integrations',
    description: 'Setting up email and payment integrations',
    execute: async (ctx) => {
      if (ctx.integrations.email) {
        await ctx.shell.configureEmail(ctx.integrations.email);
      }
      if (ctx.integrations.payments) {
        await ctx.shell.configurePayments(ctx.integrations.payments);
      }
    },
  },
  {
    id: 'verify-deployment',
    name: 'Verifying deployment',
    description: 'Running health checks',
    execute: async (ctx) => {
      const health = await fetch(`${ctx.platformUrl}/api/health`);
      if (!health.ok) {
        throw new Error('Platform health check failed');
      }
    },
  },
];
```

---

## API Specifications

### Cloudflare Verification

```typescript
// POST /api/cloudflare/verify
interface VerifyRequest {
  apiToken: string;
}

interface VerifyResponse {
  success: boolean;
  account?: {
    id: string;
    name: string;
  };
  permissions: {
    // Required permissions
    d1: boolean;                  // D1
    workersKvStorage: boolean;    // Workers KV Storage
    workersR2Storage: boolean;    // Workers R2 Storage
    workersScripts: boolean;      // Workers Scripts
    cloudflarePages: boolean;     // Cloudflare Pages
    // Optional permissions (Zone level)
    dns: boolean;                 // DNS (for custom domains)
  };
  missingPermissions: string[];   // List of missing required permissions
  error?: string;
}

// Permission names as they appear in Cloudflare dashboard
const CLOUDFLARE_PERMISSIONS = {
  // Account-level permissions (required)
  required: [
    'D1',
    'Workers KV Storage',
    'Workers R2 Storage',
    'Workers Scripts',
    'Cloudflare Pages',
  ],
  // Zone-level permissions (optional)
  optional: [
    'DNS',  // Zone-level permission for custom domains
  ],
} as const;
```

### Start Deployment

```typescript
// POST /api/deployments
interface DeploymentRequest {
  cloudflare: {
    apiToken: string;
    accountId: string;
  };
  company: {
    name: string;
    industry: string;
    size: string;
    country: string;
    address: Address;
    taxId?: string;
  };
  platform: {
    urlType: 'subdomain' | 'custom';
    subdomain?: string;
    customDomain?: string;
  };
  apps: string[];
  users: {
    admin: AdminUser;
    invited: InvitedUser[];
    roles: Role[];
  };
  integrations: {
    email: EmailConfig;
    payments?: PaymentsConfig;
  };
  imports?: {
    products?: string; // Pre-uploaded file ID
    customers?: string;
    suppliers?: string;
  };
}

interface DeploymentResponse {
  id: string;
  status: 'pending';
  estimatedDuration: number; // seconds
  websocketUrl: string; // For real-time updates
}
```

### Deployment Status

```typescript
// GET /api/deployments/:id
interface DeploymentStatus {
  id: string;
  status: 'pending' | 'in_progress' | 'completed' | 'failed';
  progress: number; // 0-100
  currentTask: string;
  tasks: Array<{
    id: string;
    name: string;
    status: 'pending' | 'in_progress' | 'completed' | 'failed';
    startedAt?: string;
    completedAt?: string;
    error?: string;
  }>;
  result?: {
    platformUrl: string;
    adminEmail: string;
  };
  error?: {
    task: string;
    message: string;
    canRetry: boolean;
  };
}
```

### WebSocket Updates

```typescript
// Connect to websocketUrl from deployment response
// Receive messages:

interface ProgressMessage {
  type: 'progress';
  taskId: string;
  status: 'started' | 'completed' | 'failed';
  progress: number;
  message?: string;
}

interface CompletedMessage {
  type: 'completed';
  platformUrl: string;
}

interface ErrorMessage {
  type: 'error';
  taskId: string;
  error: string;
  canRetry: boolean;
}
```

---

## Cloudflare Permissions Reference

### Required Permissions

These permissions must be present in the API token for deployment to succeed:

| Permission Name | Access Level | Used For | Cloudflare API Scope |
|-----------------|--------------|----------|---------------------|
| **D1** | Edit | Creating databases for each app | `account:d1:write` |
| **Workers KV Storage** | Edit | Session storage, caching | `account:workers_kv_storage:write` |
| **Workers R2 Storage** | Edit | File uploads, assets | `account:workers_r2_storage:write` |
| **Workers Scripts** | Edit | Deploying the Eldrin worker | `account:workers_scripts:write` |
| **Cloudflare Pages** | Edit | Hosting the frontend | `account:pages:write` |

### Optional Permissions (Zone Level)

| Permission Name | Access Level | Used For | Cloudflare API Scope |
|-----------------|--------------|----------|---------------------|
| **DNS** | Edit | Custom domain setup | `zone:dns:write` |

### Permission Verification

```typescript
async function verifyPermissions(apiToken: string): Promise<PermissionResult> {
  // 1. Verify token is valid
  const tokenVerify = await fetch(
    'https://api.cloudflare.com/client/v4/user/tokens/verify',
    { headers: { Authorization: `Bearer ${apiToken}` } }
  );

  if (!tokenVerify.ok) {
    return { valid: false, error: 'Invalid token' };
  }

  // 2. Get token details to check permissions
  const tokenDetails = await fetch(
    'https://api.cloudflare.com/client/v4/user/tokens',
    { headers: { Authorization: `Bearer ${apiToken}` } }
  );

  // 3. Check each required permission
  const permissions = await checkPermissions(apiToken);

  // Account-level permissions (required)
  const requiredPermissions = [
    'd1',
    'workersKvStorage',
    'workersR2Storage',
    'workersScripts',
    'cloudflarePages',
  ];

  // Zone-level permissions (optional)
  const optionalPermissions = ['dns'];

  const missing = requiredPermissions.filter(p => !permissions[p]);

  return {
    valid: missing.length === 0,
    permissions,
    missingPermissions: missing,
  };
}
```

---

## Security Requirements

### API Token Handling

1. **Never store tokens persistently**
   - Tokens exist only in memory during wizard session
   - Clear tokens on page unload/close
   - Use secure, httpOnly cookies for session management

2. **Token validation**
   - Validate token format before sending to Cloudflare
   - Verify minimum required permissions
   - Warn if token has excessive permissions

3. **Token transmission**
   - Always use HTTPS
   - Send tokens in request body, never URL
   - Implement request signing for deployment API calls

### Session Security

```typescript
interface SessionConfig {
  cookieName: 'eldrin_setup_session';
  maxAge: 3600; // 1 hour
  secure: true;
  httpOnly: true;
  sameSite: 'strict';
}
```

### Password Requirements

```typescript
interface PasswordPolicy {
  minLength: 8;
  requireUppercase: true;
  requireLowercase: true;
  requireNumber: true;
  requireSpecial: true;
}
```

### Rate Limiting

| Endpoint | Limit |
|----------|-------|
| `/api/auth/*` | 10 req/min |
| `/api/cloudflare/verify` | 5 req/min |
| `/api/deployments` | 3 req/hour |
| All other endpoints | 60 req/min |

---

## UI/UX Requirements

### Design System

Use the Eldrin "Refined Industrial" design system:

- **Typography**: JetBrains Mono (headings), IBM Plex Sans (body)
- **Colors**: Warm gray neutrals, deep blue primary (#2563EB)
- **Borders**: Sharp corners (2-4px radius)
- **Shadows**: Crisp offset shadows

### Progress Indicator

```
Step 1    Step 2    Step 3    Step 4    Step 5    Step 6
  ●─────────●─────────●─────────○─────────○─────────○
Connect   Company    Apps     Users   Integrate  Review
```

- Completed steps: Filled circle, clickable
- Current step: Filled circle, highlighted
- Future steps: Empty circle, not clickable

### Form Validation

| State | Visual |
|-------|--------|
| Empty | Default border |
| Valid | Green border, checkmark |
| Invalid | Red border, error message |
| Loading | Pulsing border |

### Error Handling

```
┌─────────────────────────────────────────────────────────────┐
│  ⚠️  Something went wrong                                    │
│                                                              │
│  We couldn't complete the deployment.                        │
│                                                              │
│  Error: Failed to create D1 database                        │
│  "Quota exceeded for D1 databases"                          │
│                                                              │
│  What you can do:                                           │
│  • Upgrade your Cloudflare plan for more D1 databases       │
│  • Delete unused databases in your Cloudflare dashboard     │
│  • Contact support if you need assistance                   │
│                                                              │
│  [ View Cloudflare Dashboard ]  [ Retry Deployment ]        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Responsive Design

| Breakpoint | Layout |
|------------|--------|
| < 640px | Single column, full width |
| 640-1024px | Centered container, comfortable padding |
| > 1024px | Max-width 1024px, centered |

### Accessibility

- WCAG 2.1 AA compliance
- Keyboard navigation support
- Screen reader friendly
- High contrast mode support
- Focus indicators on all interactive elements

---

## Deployment

### Setup Wizard Hosting

The Setup Wizard itself is deployed to Cloudflare:

| Resource | Purpose |
|----------|---------|
| `setup.eldrin.app` | Custom domain for wizard |
| Cloudflare Pages | Static site hosting |
| Cloudflare Workers | API backend |
| D1 | Session and wizard state |
| R2 | App bundles and templates |

### Environment Configuration

```typescript
interface EnvConfig {
  // Public (embedded in frontend)
  VITE_API_URL: string;           // https://api.setup.eldrin.app
  VITE_STRIPE_PUBLIC_KEY: string; // For payment integration

  // Private (Workers only)
  CLOUDFLARE_API_URL: string;     // https://api.cloudflare.com/client/v4
  SESSION_SECRET: string;          // For session encryption
  APP_REGISTRY_BUCKET: string;     // R2 bucket for app bundles
}
```

### CI/CD Pipeline

```yaml
# .github/workflows/deploy.yml
name: Deploy Setup Wizard

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install dependencies
        run: npm ci

      - name: Build frontend
        run: npm run build

      - name: Deploy to Cloudflare
        uses: cloudflare/wrangler-action@v3
        with:
          apiToken: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          command: deploy
```

---

## Testing Requirements

### Unit Tests

- Form validation logic
- State management
- API response handling
- Permission verification

### Integration Tests

- Full wizard flow (mocked Cloudflare API)
- Deployment orchestration
- Error recovery scenarios

### E2E Tests

- Complete deployment to test Cloudflare account
- Multi-user scenarios
- Browser compatibility (Chrome, Firefox, Safari, Edge)

---

## Milestones

### Phase 1: Core Wizard (MVP)
- [ ] Wizard UI framework
- [ ] Cloudflare token verification
- [ ] Basic company setup
- [ ] App selection (P0 apps only)
- [ ] Single admin user
- [ ] Basic deployment engine
- [ ] Subdomain URL only

### Phase 2: Full Features
- [ ] Custom domain support
- [ ] Multiple users and roles
- [ ] Email integration options
- [ ] Payment integration (Stripe)
- [ ] CSV data import
- [ ] All P0-P1 apps

### Phase 3: Polish
- [ ] Progress WebSocket
- [ ] Retry mechanism
- [ ] Rollback support
- [ ] Advanced app configuration
- [ ] Cost estimation
- [ ] All P2 apps

---

*Document Version: 1.0*
*Last Updated: December 2025*
