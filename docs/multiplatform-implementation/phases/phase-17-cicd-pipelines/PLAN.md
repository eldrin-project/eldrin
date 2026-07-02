# Phase 17: CI/CD Pipelines

## Overview

GitHub Actions workflows for CI (lint, typecheck, test on PR) and per-target deployment (Cloudflare, AWS Lambda, AWS ECS, Azure Functions, Azure Container, GCP Functions, GCP Run, Standalone).

## Dependencies

- Phase 5 (build system — build scripts exist)

## Steps

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

- Reusable composite actions for shared steps
- GitHub Environments for secrets
- Build matrix for provider-specific targets
- Artifact caching

### 17.3 Tests — `ci.test.ts` (~4 cases)

- All YAML files valid
- CI runs test suite on PR triggers
- Deploy workflows trigger on push to main or manual dispatch
- All reference correct build scripts

## Test Gate

```bash
cd eldrin-core && npx vitest run -- ci.test.ts   # ~4 tests
```


## Commit

After all tests pass, commit the changes to the relevant submodule(s) using conventional commits format, then update the parent repo submodule reference.
