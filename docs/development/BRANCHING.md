# Branching Strategy

This document describes the branching strategy for the Eldrin project, covering both the parent repository and all submodule repositories.

## Table of Contents

- [Overview](#overview)
- [Branch Types](#branch-types)
- [Parent Repository Strategy](#parent-repository-strategy)
- [Submodule Repository Strategy](#submodule-repository-strategy)
- [Coordinated Releases](#coordinated-releases)
- [Workflows](#workflows)
- [Branch Naming Conventions](#branch-naming-conventions)
- [Submodule Reference Management](#submodule-reference-management)
- [Best Practices](#best-practices)

## Overview

The Eldrin project uses a **multi-repository architecture** with Git submodules. Each repository (parent and submodules) maintains its own branching strategy, but they are coordinated for releases and cross-cutting features.

### Key Principles

1. **Independent Development**: Each submodule can be developed independently
2. **Coordinated Releases**: Parent repository tracks specific submodule commits for releases
3. **Stable Main Branches**: The `main` branch should always be deployable
4. **Feature Isolation**: Feature branches keep work-in-progress separate from stable code

## Branch Types

### Long-Lived Branches

| Branch    | Purpose                       | Protection             |
| --------- | ----------------------------- | ---------------------- |
| `main`    | Production-ready code         | Protected, requires PR |
| `develop` | Integration branch (optional) | Protected, requires PR |

### Short-Lived Branches

| Branch Type | Purpose                 | Naming                  |
| ----------- | ----------------------- | ----------------------- |
| Feature     | New functionality       | `feature/<description>` |
| Bugfix      | Bug fixes               | `fix/<description>`     |
| Hotfix      | Urgent production fixes | `hotfix/<description>`  |
| Release     | Release preparation     | `release/<version>`     |
| Chore       | Maintenance tasks       | `chore/<description>`   |

## Parent Repository Strategy

The parent repository (`eldrin`) orchestrates all submodules and uses a simplified branching model.

### Main Branch

The `main` branch of the parent repository represents the **current stable state** of the entire project. It contains:

- Submodule references pointing to stable, tested commits
- Project-level documentation
- Helper scripts and tooling
- CI/CD configuration

```
main ─────●─────●─────●─────●───── (stable)
          │     │     │     │
          │     │     │     └── chore: update eldrin-invoicing to v1.3.0
          │     │     └── docs: update contribution guidelines
          │     └── chore: update eldrin-core and eldrin-catalog
          └── feat: add new helper script
```

### Feature Branches

Create feature branches in the parent repository for:

- Cross-cutting changes affecting multiple submodules
- New submodule additions
- Script or configuration updates
- Documentation changes

```bash
# Create feature branch in parent
git checkout -b feature/add-payment-module
```

### Release Branches

For coordinated releases across the platform:

```bash
git checkout -b release/v2.0.0
```

Release branches in the parent:
1. Pin all submodules to their release versions
2. Update version numbers and changelogs
3. Run integration tests
4. Merge to `main` and tag

## Submodule Repository Strategy

Each submodule repository follows its own development cycle while coordinating with the parent.

### Standard Model (Git Flow Simplified)

Most submodules use this model:

```
main ─────●─────●─────────●─────●───── (releases)
           \             /
            ●───●───●───●              (feature/invoice-templates)
```

### Branch Structure

#### `main` Branch

- Always deployable/releasable
- Protected branch (requires PR review)
- Tagged for releases

#### Feature Branches

```bash
# In submodule directory
cd eldrin-invoicing
git checkout main
git checkout -b feature/recurring-invoices

# Work on feature...
git commit -m "feat: add recurring invoice support"
git push origin feature/recurring-invoices

# Create PR, get review, merge to main
```

### Optional: `develop` Branch

Some submodules may use a `develop` branch for integration:

```
main ─────●───────────────●───────── (releases only)
           \             /
develop ────●───●───●───●───●─────   (integration)
             \         /
              ●───●───               (feature/xyz)
```

Use `develop` when:
- Multiple features need integration testing
- Pre-release stabilization is needed
- Team prefers continuous integration branch

## Coordinated Releases

### Release Workflow

When preparing a release that spans multiple repositories:

```
1. Create release branches in relevant submodules
2. Stabilize and test each submodule
3. Merge and tag each submodule release
4. Update parent repository with new submodule commits
5. Create release branch in parent
6. Test integrated system
7. Merge and tag parent release
```

### Example: Platform v2.0.0 Release

```bash
# 1. Each submodule team creates release branch
cd eldrin-core
git checkout -b release/v2.0.0
# ... stabilize, test, merge to main, tag v2.0.0

cd ../eldrin-invoicing
git checkout -b release/v1.5.0  # independent versioning
# ... stabilize, test, merge to main, tag v1.5.0

# 2. Update parent repository
cd ..  # parent repo
git checkout -b release/v2.0.0

# Update submodule references
git submodule update --remote eldrin-core
git submodule update --remote eldrin-invoicing
git add eldrin-core eldrin-invoicing
git commit -m "chore: update submodules for v2.0.0"

# 3. Test integrated system
./scripts/test-all.sh

# 4. Merge and tag
git checkout main
git merge release/v2.0.0
git tag -a v2.0.0 -m "Platform release v2.0.0"
git push origin main --tags
```

### Version Alignment Matrix

Track which submodule versions are compatible:

| Parent Version | eldrin-core | eldrin-app-core | eldrin-invoicing | eldrin-catalog |
| -------------- | ----------- | --------------- | ---------------- | -------------- |
| v2.0.0         | v2.0.0      | v1.3.0          | v1.5.0           | v1.2.0         |
| v1.9.0         | v1.8.0      | v1.2.0          | v1.4.0           | v1.1.0         |
| v1.8.0         | v1.7.0      | v1.2.0          | v1.3.0           | v1.0.0         |

## Workflows

### Workflow 1: Single Submodule Feature

For changes isolated to one submodule:

```bash
# 1. Enter submodule and checkout branch
cd eldrin-invoicing
git checkout main
git pull origin main
git checkout -b feature/pdf-export

# 2. Develop feature
# ... make changes ...
git add .
git commit -m "feat: add PDF export for invoices"
git push origin feature/pdf-export

# 3. Create PR in submodule repo, get review, merge

# 4. Update parent repository (optional, or during release)
cd ..
git checkout main
git submodule update --remote eldrin-invoicing
git add eldrin-invoicing
git commit -m "chore: update eldrin-invoicing with PDF export"
git push
```

### Workflow 2: Cross-Submodule Feature

For features spanning multiple submodules:

```bash
# 1. Create feature branches in all affected submodules
cd eldrin-core
git checkout -b feature/event-system

cd ../eldrin-invoicing
git checkout -b feature/event-system

cd ../eldrin-catalog
git checkout -b feature/event-system

# 2. Develop in each submodule
# Coordinate commits, ensure compatibility

# 3. Create PRs in each submodule repo

# 4. Create coordinating branch in parent (optional)
cd ..
git checkout -b feature/event-system

# 5. After submodule PRs merge, update parent
git submodule update --remote eldrin-core eldrin-invoicing eldrin-catalog
git add eldrin-core eldrin-invoicing eldrin-catalog
git commit -m "feat: add cross-module event system"
git push
```

### Workflow 3: Hotfix

For urgent production fixes:

```bash
# 1. Create hotfix branch from main
cd eldrin-invoicing
git checkout main
git pull origin main
git checkout -b hotfix/critical-calculation-bug

# 2. Fix, test, commit
git commit -m "fix: correct tax calculation rounding"
git push origin hotfix/critical-calculation-bug

# 3. Create PR with "hotfix" label, expedited review

# 4. After merge, tag patch release
git checkout main
git pull origin main
git tag -a v1.4.1 -m "Hotfix: tax calculation"
git push origin v1.4.1

# 5. Update parent immediately
cd ..
git submodule update --remote eldrin-invoicing
git add eldrin-invoicing
git commit -m "hotfix: update eldrin-invoicing to v1.4.1 (tax calculation fix)"
git push
```

## Branch Naming Conventions

### Format

```
<type>/<description>
```

### Types

| Type       | Purpose                 | Example                     |
| ---------- | ----------------------- | --------------------------- |
| `feature`  | New functionality       | `feature/user-avatars`      |
| `fix`      | Bug fixes               | `fix/login-redirect`        |
| `hotfix`   | Urgent production fixes | `hotfix/payment-timeout`    |
| `release`  | Release preparation     | `release/v2.0.0`            |
| `chore`    | Maintenance             | `chore/update-dependencies` |
| `docs`     | Documentation           | `docs/api-reference`        |
| `refactor` | Code refactoring        | `refactor/auth-module`      |
| `test`     | Test additions/fixes    | `test/invoice-validation`   |

### Description Guidelines

- Use kebab-case: `feature/add-user-search`
- Keep it short but descriptive
- Include ticket/issue number if applicable: `feature/INV-123-recurring-invoices`

### Examples

```bash
# Good
feature/add-invoice-templates
fix/catalog-pagination
hotfix/payment-double-charge
release/v1.5.0
chore/upgrade-typescript

# Avoid
feature/fix_stuff           # Don't use underscores
feature/Add-Invoice-Templates  # Don't use PascalCase
my-branch                   # Missing type prefix
```

## Submodule Reference Management

### When to Update Parent References

| Scenario                         | Update Parent? | When                                         |
| -------------------------------- | -------------- | -------------------------------------------- |
| Feature merged to submodule main | Optional       | During next release or immediately if needed |
| Hotfix merged                    | Yes            | Immediately                                  |
| Release tagged                   | Yes            | As part of release process                   |
| Breaking change                  | Yes            | With documentation update                    |

### Keeping Submodules in Sync

```bash
# Check status of all submodules
./scripts/status.sh

# Update all to recorded commits (safe)
git submodule update

# Update all to latest remote main (changes references)
git submodule update --remote
git add .
git commit -m "chore: update all submodules to latest"

# Update specific submodule
git submodule update --remote eldrin-invoicing
```

### Submodule Branch Tracking

Configure submodules to track specific branches:

```bash
# Set branch to track in .gitmodules
git config -f .gitmodules submodule.eldrin-core.branch main
git config -f .gitmodules submodule.eldrin-invoicing.branch main

# After config, --remote will fetch from tracked branch
git submodule update --remote
```

## Best Practices

### For All Repositories

1. **Keep main deployable**: Never commit broken code to main
2. **Use pull requests**: All changes go through PR review
3. **Write meaningful commits**: Follow [Conventional Commits](https://www.conventionalcommits.org/)
4. **Delete merged branches**: Clean up after PRs merge

### For Submodule Development

1. **Checkout a branch first**: Always exit detached HEAD before making changes
2. **Push before updating parent**: Ensure submodule commits exist on remote
3. **Coordinate breaking changes**: Communicate across teams for API changes
4. **Tag releases**: Use semantic versioning for submodule releases

### For Parent Repository

1. **Test before committing**: Verify submodule combination works together
2. **Document submodule updates**: Include context in commit messages
3. **Don't mix concerns**: Keep submodule updates separate from other changes
4. **Batch non-urgent updates**: Group submodule updates in release cycles

### Branch Protection Rules (Recommended)

For `main` branch in all repositories:

- Require pull request reviews (1-2 reviewers)
- Require status checks to pass
- Require branches to be up to date
- Do not allow force pushes
- Do not allow deletions

### Avoiding Common Mistakes

| Mistake                                            | Prevention                                     |
| -------------------------------------------------- | ---------------------------------------------- |
| Committing to detached HEAD                        | Always `git checkout <branch>` first           |
| Pushing unpushed submodule commits                 | Run `./scripts/status.sh` before parent commit |
| Updating parent with uncommitted submodule changes | Status script warns about dirty submodules     |
| Forgetting to update parent after submodule merge  | Add to PR checklist / CI reminder              |
| Force pushing submodule after parent references it | Enable branch protection                       |

---

## Quick Reference

### Daily Development Commands

```bash
# Start work in submodule
cd eldrin-invoicing
git checkout main && git pull
git checkout -b feature/my-feature

# Check all submodule status
./scripts/status.sh

# Update to latest recorded commits
git submodule update

# Update to latest remote
./scripts/update-submodules.sh --remote
```

### Release Commands

```bash
# Create release branch in submodule
git checkout -b release/v1.2.0

# Tag release after merge
git tag -a v1.2.0 -m "Release v1.2.0"
git push origin v1.2.0

# Update parent for release
git submodule update --remote
git add .
git commit -m "chore: update submodules for release"
```

---

For more detailed workflows, see [CONTRIBUTING.md](../CONTRIBUTING.md).
