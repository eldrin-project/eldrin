# Phase 17: CI/CD Pipelines — DONE

## Completed: 2026-02-09

## What was delivered

### Reusable composite action (`.github/actions/setup/action.yml`)
- Checkout, Node.js 20 setup with npm cache, `npm ci`
- Used by all 9 workflows to avoid repetition

### CI workflow (`.github/workflows/ci.yml`)
- Triggers: `pull_request` (all branches), `push` to main
- Steps: lint (ESLint), typecheck (`tsc -b`), test (`vitest run`)
- Concurrency group cancels in-progress CI runs on same ref

### Deployment workflows (8 files)
- **Cloudflare Workers** — `build:cloudflare` + `wrangler deploy`
- **AWS Lambda** — `build` + SAM CLI build/deploy with `providers/aws/template.yaml`
- **AWS ECS** — `build` + Docker build/push to ECR + ECS service update
- **Azure Functions** — `build` + OIDC login + `azure/functions-action`
- **Azure Container Apps** — `build` + Docker build/push to ACR + Container Apps deploy
- **GCP Cloud Functions** — `build` + Workload Identity auth + `gcloud functions deploy`
- **GCP Cloud Run** — `build` + Docker build/push to Artifact Registry + `gcloud run deploy`
- **Standalone** — Bun build + upload binary artifact

All deploy workflows: push to main + `workflow_dispatch`, concurrency groups (no cancel), `production` environment

## Files created (11)
- `.github/actions/setup/action.yml` — Reusable composite action
- `.github/workflows/ci.yml` — CI pipeline
- `.github/workflows/deploy-cloudflare.yml` — Cloudflare Workers deploy
- `.github/workflows/deploy-aws-lambda.yml` — AWS Lambda deploy
- `.github/workflows/deploy-aws-ecs.yml` — AWS ECS/Fargate deploy
- `.github/workflows/deploy-azure-functions.yml` — Azure Functions deploy
- `.github/workflows/deploy-azure-container.yml` — Azure Container Apps deploy
- `.github/workflows/deploy-gcp-functions.yml` — GCP Cloud Functions deploy
- `.github/workflows/deploy-gcp-run.yml` — GCP Cloud Run deploy
- `.github/workflows/deploy-standalone.yml` — Standalone binary build
- `ci.test.ts` — 4 workflow validation tests

## Files modified (1)
- `vitest.config.ts` — added `ci.test.ts` to include

## Phase gate
- [x] 300 tests pass (296 existing + 4 new workflow validation tests)
- [x] `tsc -b` clean (zero errors)
- [x] All workflows valid YAML with correct triggers
- [x] All workflows reference composite setup action
- [x] No untrusted input in `run:` commands (secrets and github.sha only, via `env:` blocks)
