# Phase 6: IaC Templates

## Status: done
## Started: 2026-02-09
## Completed: 2026-02-09

## Progress:
- [x] Step 6.1: Create AWS SAM template (Lambda)
- [x] Step 6.2: Create AWS ECS SAM template
- [x] Step 6.3: Create Azure Bicep template
- [x] Step 6.4: Create GCP Terraform template
- [x] Step 6.5: Update Cloudflare wrangler.jsonc
- [x] Step 6.6: Write IaC validation tests

## Notes:
- All templates parameterized by database type (sqlite/turso/postgres) with conditional resource creation
- AWS SAM Lambda: Lambda + API Gateway + S3 + SQS + Secrets Manager, conditional VPC/EFS/RDS, optional ElastiCache
- AWS ECS: Fargate + ALB + ECR + full VPC networking, same shared resources
- Azure Bicep: Function App + Storage + Key Vault + Service Bus, conditional File Share/PostgreSQL Flexible Server, optional Redis
- GCP Terraform: Cloud Run + Cloud Storage + Secret Manager + Cloud Tasks + Artifact Registry, conditional Filestore/Cloud SQL, optional Memorystore
- Cloudflare wrangler.jsonc updated with R2, KV, Queues bindings (in addition to existing D1)
- Tests are structural validation (parse YAML/JSONC, check resource types, scan for hardcoded creds) — no CLI tools required
- YAML parser warns about CloudFormation custom tags (!Ref, !Sub, etc.) — expected, parsing still succeeds
