# Phase 6: IaC Templates — DONE

## Completed: 2026-02-09

## What was delivered

### AWS SAM Lambda template (`providers/aws/template.yaml`)
- Parameterized with `DatabaseType` (sqlite-efs | turso | postgres)
- Lambda + HTTP API Gateway, S3 bucket, Secrets Manager, SQS queue
- Conditional: VPC + EFS (sqlite), RDS PostgreSQL (postgres), no VPC for Turso
- Optional: ElastiCache Redis (`EnableRedis` parameter)
- IAM policies via SAM policy templates (S3Crud, SQSSendMessage, SecretsManager)

### AWS ECS SAM template (`providers/aws/ecs/template.yaml`)
- ECS Fargate cluster + service + task definition, ALB + target group, ECR repository
- Full VPC with public/private subnets, NAT Gateway, Internet Gateway
- Same conditional DB resources and shared infrastructure as Lambda template
- CloudWatch Logs with 30-day retention

### Azure Bicep template (`providers/azure/bicep/main.bicep`)
- Function App (Linux, Node.js 20) with Key Vault references for secrets
- Storage Account + Blob container, Key Vault + secrets, Service Bus queue
- Managed Identity with RBAC (Key Vault Secrets User, Storage Blob Data Contributor)
- Conditional: File Share mount (sqlite), PostgreSQL Flexible Server (postgres)
- Optional: Azure Cache for Redis

### GCP Terraform (`providers/gcp/terraform/`)
- Cloud Run v2 service with Secret Manager env injection
- Cloud Storage bucket, Secret Manager secrets, Cloud Tasks queue, Artifact Registry
- Service account with storage.objectAdmin IAM binding
- Conditional: Filestore NFS mount (sqlite), Cloud SQL PostgreSQL (postgres)
- Optional: Memorystore Redis, VPC connector (when needed)

### Cloudflare wrangler.jsonc
- Added R2 bucket binding (`STORAGE`), KV namespace binding (`CACHE`)
- Added Queues producer (`TASKS`) + consumer configuration
- Preserved existing D1 database binding
- Commented guidance for Hyperdrive (external PostgreSQL)

## Files created (7)
- `providers/aws/template.yaml` — SAM Lambda template
- `providers/aws/ecs/template.yaml` — SAM ECS/Fargate template
- `providers/azure/bicep/main.bicep` — Azure Bicep template
- `providers/gcp/terraform/main.tf` — Terraform main config
- `providers/gcp/terraform/variables.tf` — Terraform input variables
- `providers/gcp/terraform/outputs.tf` — Terraform output values
- `iac.test.ts` — 8 structural validation tests

## Files modified (2)
- `wrangler.jsonc` — added R2, KV, Queues bindings
- `vitest.config.ts` — added iac.test.ts to include

## Phase gate
- [x] 296 tests pass (288 existing + 8 new IaC structural tests)
- [x] `tsc -b` clean (zero errors)
- [x] All templates have database-type parameterization
- [x] No hardcoded credentials in any template
- [x] Wrangler JSONC valid with all required bindings
