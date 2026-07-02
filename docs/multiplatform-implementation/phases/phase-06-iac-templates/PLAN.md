# Phase 6: IaC Templates

## Overview

Create Infrastructure as Code templates for each cloud provider, provisioning all services from Phases 4–18. Templates are parameterized by database type (sqlite, turso, postgres).

## Dependencies

- Phase 4 (cloud adapters define what services are needed)

## Steps

### 6.1 AWS SAM template — `providers/aws/template.yaml`

Parameterized with `DatabaseType` (sqlite-efs, turso, postgres):
- Lambda + API Gateway, S3, Secrets Manager, SQS
- Conditional: EFS (sqlite), RDS (postgres), ElastiCache Redis (optional)

### 6.2 AWS ECS SAM template — `providers/aws/ecs/template.yaml`

Adds ECS Fargate, ALB, ECR to above.

### 6.3 Azure Bicep — `providers/azure/bicep/main.bicep`

Parameterized with `databaseType` (sqlite-files, turso, postgres):
- Functions/Container Apps, Blob Storage, Key Vault, Service Bus
- Conditional: Azure Files (sqlite), PostgreSQL Flexible Server (postgres), Redis (optional)

### 6.4 GCP Terraform — `providers/gcp/terraform/main.tf`

Parameterized with `database_type` (sqlite-filestore, turso, postgres):
- Cloud Functions/Run, Cloud Storage, Secret Manager, Cloud Tasks
- Conditional: Filestore (sqlite), Cloud SQL (postgres), Memorystore Redis (optional)

### 6.5 Cloudflare wrangler — `providers/cloudflare/wrangler.jsonc`

D1, R2, KV, Queues, secrets, custom domain.

### 6.6 Tests — `iac.test.ts` (~6 cases)

- Template validation (SAM validate, Bicep build, Terraform validate)
- Valid JSON(C) for wrangler
- No hardcoded credentials

## Test Gate

```bash
cd eldrin-core && npx vitest run -- iac.test.ts   # ~6 tests
```


## Commit

After all tests pass, commit the changes to the relevant submodule(s) using conventional commits format, then update the parent repo submodule reference.
