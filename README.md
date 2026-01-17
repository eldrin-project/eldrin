# Eldrin

A modular business application platform built on Cloudflare Workers with a micro-frontend architecture.

## Overview

Eldrin is a single-tenant platform that enables businesses to deploy customizable business applications (Invoicing, CRM, Catalog, etc.) on their own Cloudflare Workers infrastructure. Each customer owns their worker and data, with apps loaded from a centralized marketplace.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              CUSTOMER CLOUDFLARE WORKER                      │
│  ┌────────────────────────────────────────────────────────┐ │
│  │           ELDRIN SHELL (React + Vite + single-spa)     │ │
│  │  Auth │ Navigation │ Orchestrator │ Theming │ Events   │ │
│  └────────────────────────────────────────────────────────┘ │
│       │           │            │            │               │
│  ┌────┴───┐  ┌────┴───┐  ┌────┴───┐  ┌────┴───┐           │
│  │Catalog │  │Invoice │  │  CRM   │  │  ...   │           │
│  │  App   │  │  App   │  │  App   │  │  Apps  │           │
│  └────┬───┘  └────┬───┘  └────┬───┘  └────┬───┘           │
└───────│───────────│───────────│───────────│────────────────┘
        ▼           ▼           ▼           ▼
   [D1 + R2]   [D1 + R2]   [D1 + R2]   [D1 + R2]
```

### Key Technologies

| Layer | Technology |
|-------|------------|
| Frontend | React + Vite |
| Micro-frontend | single-spa + Module Federation |
| State Management | Zustand |
| Runtime | Cloudflare Workers |
| Database | Cloudflare D1 (SQLite) |
| Storage | Cloudflare R2 |
| Authentication | Custom JWT |

## Repository Structure

This is a **parent repository** that orchestrates multiple components via Git submodules.

### Core Components

| Directory | Description | Repository |
|-----------|-------------|------------|
| [`eldrin-core`](./eldrin-core) | Core platform shell, authentication, navigation, and orchestration | [eldrin-project/eldrin-core](https://github.com/eldrin-project/eldrin-core) |
| [`eldrin-app-core`](./eldrin-app-core) | Framework-agnostic library for building Eldrin apps | [eldrin-project/eldrin-app-core](https://github.com/eldrin-project/eldrin-app-core) |

### Business Apps (Modules)

| Directory | Description | Repository |
|-----------|-------------|------------|
| [`eldrin-invoicing`](./eldrin-invoicing) | Invoice and client management app | [eldrin-project/eldrin-invoicing](https://github.com/eldrin-project/eldrin-invoicing) |
| [`eldrin-catalog`](./eldrin-catalog) | Product and service catalog management | [eldrin-project/eldrin-catalog](https://github.com/eldrin-project/eldrin-catalog) |
| [`eldrin-crm`](./eldrin-crm) | Customer relationship management | [eldrin-project/eldrin-crm](https://github.com/eldrin-project/eldrin-crm) |

### Framework-Specific App Templates

| Directory | Description | Repository |
|-----------|-------------|------------|
| [`eldrin-app-angular`](./eldrin-app-angular) | Angular app template and integration | [eldrin-project/eldrin-app-angular](https://github.com/eldrin-project/eldrin-app-angular) |
| [`eldrin-app-react`](./eldrin-app-react) | React app template and integration | [eldrin-project/eldrin-app-react](https://github.com/eldrin-project/eldrin-app-react) |
| [`eldrin-app-svelte`](./eldrin-app-svelte) | Svelte app template and integration | [eldrin-project/eldrin-app-svelte](https://github.com/eldrin-project/eldrin-app-svelte) |
| [`eldrin-app-vue`](./eldrin-app-vue) | Vue app template and integration | [eldrin-project/eldrin-app-vue](https://github.com/eldrin-project/eldrin-app-vue) |

### Infrastructure & Tooling

| Directory | Description | Repository |
|-----------|-------------|------------|
| [`eldrin-website`](./eldrin-website) | Marketing website and landing pages | [eldrin-project/eldrin-website](https://github.com/eldrin-project/eldrin-website) |
| [`eldrin-docs`](./eldrin-docs) | Developer documentation (Starlight/Astro) | [eldrin-project/eldrin-docs](https://github.com/eldrin-project/eldrin-docs) |
| [`eldrin-templates`](./eldrin-templates) | Project scaffolding templates (`create-eldrin-project`) | [eldrin-project/eldrin-templates](https://github.com/eldrin-project/eldrin-templates) |
| [`eldrin-marketplace-dist`](./eldrin-marketplace-dist) | Marketplace distribution and CDN assets | [eldrin-project/eldrin-marketplace-dist](https://github.com/eldrin-project/eldrin-marketplace-dist) |

### Example Applications (Local Only)

These directories contain example/demo applications for learning purposes and are not tracked as submodules:

| Directory | Description |
|-----------|-------------|
| `angular-todo` | Angular example app |
| `react-todo` | React example app |
| `svelte-todo` | Svelte example app |
| `vue-todo` | Vue example app |

## Getting Started

### Prerequisites

- Git 2.13+
- Node.js 20+
- npm or pnpm

### Clone with Submodules

```bash
# Clone the entire project with all submodules
git clone --recurse-submodules git@github.com:eldrin-project/eldrin.git

# Or if you already cloned without submodules
git submodule update --init --recursive
```

### Initialize Development Environment

```bash
# Run the initialization script (after submodules setup is complete)
./scripts/init.sh
```

### Update Submodules

```bash
# Update all submodules to their latest commits
git submodule update --remote

# Or use the helper script
./scripts/update-submodules.sh
```

## Development Workflow

### Working with Submodules

Each submodule is an independent Git repository. The parent repository tracks specific commits (not branches) for each submodule. This section covers common submodule operations.

#### Understanding Submodule States

| State | Description | How to Identify |
|-------|-------------|-----------------|
| **Detached HEAD** | Default state after clone/update; not on any branch | `git status` shows "HEAD detached at..." |
| **Clean** | No uncommitted changes | `git status` shows "nothing to commit" |
| **Dirty** | Has uncommitted changes | `git status` shows modified/staged files |
| **Ahead** | Local commits not pushed to remote | `git status` shows "ahead of origin/main by N commits" |
| **Behind** | Remote has newer commits | `git status` shows "behind origin/main by N commits" |

#### Basic Submodule Workflow

1. **Navigate to the submodule directory**
   ```bash
   cd eldrin-invoicing
   ```

2. **Checkout a branch** (submodules start in detached HEAD state)
   ```bash
   git checkout main
   # or create a feature branch
   git checkout -b feature/my-feature
   ```

3. **Make changes and commit as usual**
   ```bash
   git add .
   git commit -m "Your commit message"
   git push origin feature/my-feature
   ```

4. **Update the parent repository reference**
   ```bash
   cd ..  # back to parent
   git add eldrin-invoicing
   git commit -m "Update eldrin-invoicing submodule reference"
   ```

> **Important:** After making changes in a submodule, you must commit the submodule reference in the parent repository. Otherwise, other developers won't see your submodule updates.

### Helper Scripts

We provide helper scripts to simplify common submodule operations. All scripts are located in the `scripts/` directory.

#### `scripts/init.sh` - Initialize Development Environment

Initializes a fresh clone for development. Run this after cloning the repository.

```bash
# Full initialization with dependencies
./scripts/init.sh

# Skip npm dependency installation
./scripts/init.sh --skip-deps

# Verbose output for debugging
./scripts/init.sh --verbose
```

**What it does:**
- Validates Git version requirements (2.13+)
- Initializes and updates all Git submodules
- Configures recommended Git settings for submodules
- Optionally installs npm dependencies for each component

#### `scripts/update-submodules.sh` - Update Submodules

Updates submodules to their recorded commits, remote HEAD, or a specific branch.

```bash
# Update all submodules to their recorded (pinned) commits
./scripts/update-submodules.sh

# Update all submodules to their remote HEAD (latest)
./scripts/update-submodules.sh --remote

# Update specific submodules to remote HEAD
./scripts/update-submodules.sh --remote eldrin-core eldrin-invoicing

# Update all submodules to a specific branch
./scripts/update-submodules.sh --branch develop

# Checkout tracked branch and pull latest in all submodules
./scripts/update-submodules.sh --checkout --pull

# Preview what would be updated (dry run)
./scripts/update-submodules.sh --remote --dry-run
```

**Options:**
| Option | Description |
|--------|-------------|
| `--remote` | Update submodules to their remote tracking branch HEAD |
| `--branch NAME` | Update submodules to a specific branch |
| `--pull` | Pull latest changes within each submodule |
| `--checkout` | Checkout the tracked branch (exit detached HEAD) |
| `--dry-run` | Preview changes without applying them |
| `--verbose` | Show detailed output |

#### `scripts/status.sh` - Check Submodule Status

Displays the status of all submodules, including commit info, branch state, and uncommitted changes.

```bash
# Check status of all submodules
./scripts/status.sh

# Show detailed status with file changes
./scripts/status.sh --full

# Check specific submodules only
./scripts/status.sh eldrin-core eldrin-invoicing

# Fetch remotes for accurate ahead/behind counts
./scripts/status.sh --fetch

# Only show submodules with issues (dirty, ahead/behind)
./scripts/status.sh --quiet

# Get JSON output for scripting
./scripts/status.sh --json
```

**Status Indicators:**
| Indicator | Meaning |
|-----------|---------|
| `[CLEAN]` | No uncommitted changes |
| `[DIRTY]` | Has uncommitted changes |
| `[AHEAD n]` | n commits ahead of remote |
| `[BEHIND n]` | n commits behind remote |
| `[DETACHED]` | HEAD is detached (not on a branch) |
| `[NOT INIT]` | Submodule not initialized |

### Common Submodule Operations

#### Cloning the Project

```bash
# Clone with all submodules (recommended)
git clone --recurse-submodules git@github.com:eldrin-project/eldrin.git

# If you already cloned without submodules
git submodule update --init --recursive
```

#### Updating to Latest Submodule Commits

```bash
# Update to commits recorded in parent repo (safe)
git submodule update

# Update to latest commits from remote (updates references)
git submodule update --remote

# Using helper script
./scripts/update-submodules.sh --remote
```

> **Note:** When using `--remote`, remember to commit the updated submodule references in the parent repository.

#### Exiting Detached HEAD State

After cloning or updating, submodules are in "detached HEAD" state. To work on a branch:

```bash
# Option 1: Manually checkout branch in each submodule
cd eldrin-core
git checkout main

# Option 2: Use helper script for all submodules
./scripts/update-submodules.sh --checkout
```

#### Pulling Changes in All Submodules

```bash
# Using native Git (from parent directory)
git submodule foreach 'git pull origin main'

# Using helper script (with checkout if needed)
./scripts/update-submodules.sh --checkout --pull
```

#### Adding a New Submodule

```bash
# Add a new submodule
git submodule add git@github.com:eldrin-project/new-module.git new-module

# Commit the addition
git add .gitmodules new-module
git commit -m "Add new-module submodule"
```

#### Removing a Submodule

```bash
# Deinitialize the submodule
git submodule deinit -f eldrin-module

# Remove from Git's tracking
git rm -f eldrin-module

# Clean up .git/modules directory
rm -rf .git/modules/eldrin-module

# Commit the removal
git commit -m "Remove eldrin-module submodule"
```

#### Syncing Submodule URLs

If a submodule's remote URL changes:

```bash
# Update .gitmodules with the new URL (edit manually or)
git config -f .gitmodules submodule.eldrin-core.url git@github.com:new-org/eldrin-core.git

# Sync the change to local config
git submodule sync

# Update the submodule
git submodule update --init --remote eldrin-core
```

#### Troubleshooting

**Problem: "fatal: no submodule mapping found"**
```bash
# Reinitialize submodules
git submodule init
git submodule update
```

**Problem: Submodule has merge conflicts**
```bash
cd problematic-submodule
git status
# Resolve conflicts manually, then:
git add .
git commit -m "Resolve merge conflicts"
cd ..
git add problematic-submodule
git commit -m "Update submodule after resolving conflicts"
```

**Problem: Submodule is stuck in wrong state**
```bash
# Reset submodule to recorded commit
git submodule update --force eldrin-core

# Or completely reinitialize
git submodule deinit -f eldrin-core
git submodule update --init eldrin-core
```

**Problem: SSH authentication issues**
```bash
# Verify SSH access to GitHub
ssh -T git@github.com

# If using HTTPS instead, update URLs in .gitmodules
git config -f .gitmodules submodule.eldrin-core.url https://github.com/eldrin-project/eldrin-core.git
git submodule sync
```

### Running Individual Components

Each component has its own development workflow. See the README in each submodule for specific instructions.

**Common patterns:**

```bash
# Core platform
cd eldrin-core
npm install
npm run dev

# Invoicing app
cd eldrin-invoicing
npm install
npm run dev

# Documentation
cd eldrin-docs
npm install
npm run dev
```

## App Development

### Creating a New App

Use the project scaffolding tool:

```bash
npm create eldrin-project@latest -- my-app
```

### App Manifest

Every Eldrin app requires a manifest file (`eldrin-app.manifest.json`):

```json
{
  "id": "my-app",
  "name": "My App",
  "version": "1.0.0",
  "compatibility": {
    "core": ">=1.0.0"
  }
}
```

### SDK Usage

```typescript
import { useEldrin, usePermission } from '@eldrin/sdk';

// Access SDK in components
const eldrin = useEldrin();

// Check permissions
const canEdit = usePermission('invoices:write');

// Call other app's hook
const invoice = await eldrin.apps.call('invoicing', 'getInvoiceById', { id });

// Emit event
eldrin.apps.emit('invoice:created', { invoiceId, total });
```

## Documentation

- **Technical Requirements**: See `eldrin-technical-requirements.md`
- **Quick Reference**: See `eldrin-quick-reference.md`
- **Developer Docs**: See `eldrin-docs/` or visit the docs site

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for development guidelines and submodule workflow.

## License

MIT
