# Contributing to Eldrin

Thank you for your interest in contributing to Eldrin! This guide covers the development workflow, including working with our multi-repository architecture using Git submodules.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Development Setup](#development-setup)
- [Project Architecture](#project-architecture)
- [Submodule Workflow](#submodule-workflow)
- [Making Changes](#making-changes)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Code Review](#code-review)
- [Troubleshooting](#troubleshooting)

## Prerequisites

Before contributing, ensure you have:

- **Git 2.13+** - Required for improved submodule support
- **Node.js 20+** - Runtime for development
- **npm or pnpm** - Package manager
- **SSH key configured for GitHub** - Required for cloning via SSH

Verify your setup:

```bash
git --version          # Should be 2.13 or higher
node --version         # Should be 20.x or higher
ssh -T git@github.com  # Should show "Hi username! You've been authenticated..."
```

## Development Setup

### Initial Clone

Clone the entire project with all submodules:

```bash
git clone --recurse-submodules git@github.com:eldrin-project/eldrin.git
cd eldrin
```

If you already cloned without `--recurse-submodules`:

```bash
git submodule update --init --recursive
```

### Run Initialization Script

```bash
./scripts/init.sh
```

This script:
- Validates Git version requirements
- Initializes and updates all submodules
- Configures recommended Git settings
- Optionally installs npm dependencies

### Verify Setup

Check the status of all submodules:

```bash
./scripts/status.sh
```

All submodules should show `[CLEAN]` status.

## Project Architecture

Eldrin uses a **parent repository with Git submodules** architecture. The parent repository (`eldrin`) orchestrates 13 independent repositories:

### Repository Structure

```
eldrin/                        # Parent repository
├── eldrin-core/               # Core platform shell
├── eldrin-app-core/           # Framework-agnostic app library
├── eldrin-invoicing/          # Invoicing module
├── eldrin-catalog/            # Catalog module
├── eldrin-crm/                # CRM module
├── eldrin-website/            # Marketing website
├── eldrin-docs/               # Documentation
├── eldrin-templates/          # Project scaffolding
├── eldrin-marketplace-dist/   # Marketplace distribution
├── eldrin-app-angular/        # Angular app template
├── eldrin-app-react/          # React app template
├── eldrin-app-svelte/         # Svelte app template
├── eldrin-app-vue/            # Vue app template
├── scripts/                   # Helper scripts
└── docs/                      # Parent repo documentation
```

### Key Concept: Submodule Commits

The parent repository tracks **specific commits** (not branches) for each submodule. This means:

1. When you clone the parent, you get exact versions of each submodule
2. Submodule updates must be committed to the parent repository
3. Submodules start in "detached HEAD" state after clone

## Submodule Workflow

### Understanding Detached HEAD

After cloning or updating, submodules are in "detached HEAD" state:

```bash
cd eldrin-invoicing
git status
# HEAD detached at abc1234
```

This is expected! Before making changes, checkout a branch:

```bash
git checkout main
# or create a feature branch
git checkout -b feature/my-feature
```

### Basic Development Workflow

#### Step 1: Navigate to the Submodule

```bash
cd eldrin-invoicing
```

#### Step 2: Checkout a Branch

```bash
# Switch to main branch
git checkout main

# Or create a feature branch
git checkout -b feature/my-feature
```

#### Step 3: Make Changes

Work on your changes as you would in any Git repository.

#### Step 4: Commit and Push in the Submodule

```bash
git add .
git commit -m "feat: add new invoice template"
git push origin feature/my-feature
```

#### Step 5: Update the Parent Repository

**Important:** After pushing changes in a submodule, you must update the parent repository to record the new commit reference:

```bash
# Go back to parent repository
cd ..

# Stage the submodule change
git add eldrin-invoicing

# Commit the reference update
git commit -m "chore: update eldrin-invoicing submodule"

# Push the parent repository
git push
```

### Multi-Submodule Changes

When your change spans multiple submodules:

1. Make and push changes in each submodule
2. Return to the parent repository
3. Stage all updated submodules together
4. Create a single commit in the parent

```bash
# After making changes in multiple submodules
cd /path/to/eldrin  # parent repo

git add eldrin-core eldrin-invoicing
git commit -m "feat: add cross-module event system"
git push
```

### Pulling Latest Changes

#### Update to Recorded Commits (Safe)

This updates submodules to the commits recorded in the parent repository:

```bash
# From parent repository
git pull
git submodule update

# Or use helper script
./scripts/update-submodules.sh
```

#### Update to Latest Remote Commits

This fetches the latest commits from each submodule's remote:

```bash
# Update all submodules to their remote HEAD
git submodule update --remote

# Or use helper script
./scripts/update-submodules.sh --remote
```

> **Note:** Using `--remote` changes the submodule references. Remember to commit these changes to the parent repository if you want to share them.

### Checking Submodule Status

Use the status script to see all submodules at a glance:

```bash
# Quick status check
./scripts/status.sh

# Detailed status with file changes
./scripts/status.sh --full

# Fetch remotes for accurate ahead/behind counts
./scripts/status.sh --fetch
```

**Status Indicators:**

| Indicator | Meaning |
|-----------|---------|
| `[CLEAN]` | No uncommitted changes |
| `[DIRTY]` | Has uncommitted changes |
| `[AHEAD n]` | n commits ahead of remote |
| `[BEHIND n]` | n commits behind remote |
| `[DETACHED]` | HEAD is detached (not on a branch) |

## Making Changes

### Which Repository to Change?

| Change Type | Repository |
|-------------|------------|
| Core platform functionality | `eldrin-core` |
| App SDK or shared utilities | `eldrin-app-core` |
| Invoicing features | `eldrin-invoicing` |
| Catalog features | `eldrin-catalog` |
| CRM features | `eldrin-crm` |
| Documentation | `eldrin-docs` |
| Website/marketing | `eldrin-website` |
| App templates | `eldrin-app-{framework}` |
| Build/distribution | `eldrin-marketplace-dist` |
| Project scaffolding | `eldrin-templates` |
| Submodule references or scripts | Parent `eldrin` repo |

### Feature Development

1. **Create a feature branch** in the relevant submodule(s)
2. **Develop and test** your changes
3. **Create a PR** in the submodule repository
4. **After merge**, update the parent repository reference

### Bug Fixes

1. **Identify the affected submodule(s)**
2. **Create a fix branch** in the submodule
3. **Test the fix** thoroughly
4. **Create a PR** in the submodule repository
5. **After merge**, update the parent repository reference

## Commit Guidelines

### Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**

```bash
# Feature in submodule
feat(invoicing): add recurring invoice support

# Bug fix
fix(catalog): resolve product search pagination issue

# Parent repository update
chore: update eldrin-invoicing to v1.2.0
```

### Submodule Reference Commits

When updating submodule references in the parent repository:

```bash
# Single submodule update
chore: update eldrin-core submodule

# Multiple submodules
chore: update submodules (core, invoicing)

# Feature-related update
feat: add event system (updates core and invoicing)
```

## Pull Request Process

### For Submodule Changes

1. **Create PR in the submodule repository**
   - Target the appropriate branch (usually `main` or `develop`)
   - Include tests and documentation
   - Link related issues

2. **Get review and approval**
   - Wait for CI checks to pass
   - Address review feedback

3. **Merge the submodule PR**

4. **Update the parent repository**
   - Create a PR to update the submodule reference
   - This can be done immediately or batched with other updates

### For Parent Repository Changes

1. **Create PR in the parent repository**
   - This is for changes to scripts, docs, or submodule references

2. **Ensure submodule changes are merged first**
   - The parent should only reference commits that exist on submodule remotes

3. **Get review and merge**

### PR Checklist

- [ ] Code follows project style guidelines
- [ ] Tests pass locally
- [ ] Documentation updated (if needed)
- [ ] Commit messages follow convention
- [ ] No unrelated submodule changes included
- [ ] Parent repo updated (if submodule changed)

## Code Review

### Review Focus Areas

- **Functionality**: Does the code do what it's supposed to?
- **Tests**: Are there adequate tests?
- **Documentation**: Is it documented appropriately?
- **Performance**: Are there any performance concerns?
- **Security**: Are there any security implications?

### Reviewing Submodule Changes

When reviewing a parent repository PR that updates submodule references:

1. **Check the submodule PR was merged** - Verify the referenced commit exists
2. **Review the submodule changes** - Link to the submodule PR for context
3. **Verify compatibility** - Ensure changes work with other submodules

## Troubleshooting

### "Detached HEAD" After Update

This is expected behavior. To work on changes:

```bash
cd eldrin-invoicing
git checkout main
```

Or for all submodules:

```bash
./scripts/update-submodules.sh --checkout
```

### Submodule Not Initialized

```bash
# Initialize specific submodule
git submodule update --init eldrin-core

# Initialize all submodules
git submodule update --init --recursive
```

### SSH Authentication Issues

```bash
# Test SSH connection
ssh -T git@github.com

# If issues persist, check your SSH key
ssh-add -l

# Add your key if not listed
ssh-add ~/.ssh/id_rsa
```

### Submodule Has Merge Conflicts

```bash
cd eldrin-invoicing
git status
# Resolve conflicts in files
git add .
git commit -m "Resolve merge conflicts"

# Update parent
cd ..
git add eldrin-invoicing
git commit -m "Update eldrin-invoicing after conflict resolution"
```

### Uncommitted Changes in Submodule

Before updating submodules, ensure a clean state:

```bash
# Check for dirty submodules
./scripts/status.sh

# If dirty, either commit or stash changes
cd eldrin-invoicing
git stash  # or git commit
```

### Reset Submodule to Recorded Commit

If a submodule is in a bad state:

```bash
# Reset to recorded commit
git submodule update --force eldrin-core

# Or completely reinitialize
git submodule deinit -f eldrin-core
git submodule update --init eldrin-core
```

### Accidental Commit in Detached HEAD

If you committed while in detached HEAD:

```bash
cd eldrin-invoicing

# Note the commit hash
git log -1 --oneline
# abc1234 Your commit message

# Checkout the branch you want
git checkout main

# Cherry-pick your commit
git cherry-pick abc1234

# Push
git push origin main
```

## Getting Help

- **Documentation**: See `eldrin-docs/` or the [docs site](https://docs.eldrin.io)
- **Issues**: File issues in the relevant submodule repository
- **Discussions**: Use GitHub Discussions in the main `eldrin` repository

---

Thank you for contributing to Eldrin! Your contributions help make the platform better for everyone.
