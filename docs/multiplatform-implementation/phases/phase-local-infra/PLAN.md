# Phase: Local Infrastructure

## Overview

Set up a Docker Compose environment with PostgreSQL, Redis, MinIO, and Mailpit so all cloud-dependent features can be tested locally without deploying to any cloud provider.

## Dependencies

- Phase 1 (SDK fixes — database adapters available)

## Steps

### L.1 Create `eldrin-core/docker-compose.yml`

Services:

| Service | Image | Purpose | Port |
|---------|-------|---------|------|
| PostgreSQL | `postgres:16-alpine` | Test PostgreSQL adapter | 5432 |
| Redis | `redis:7-alpine` | Cache + rate limiting + task queue | 6379 |
| MinIO | `minio/minio` | S3-compatible storage | 9000 (API) / 9001 (Console) |
| Mailpit | `axllent/mailpit` | Email capture (SMTP + web UI) | 1025 (SMTP) / 8025 (UI) |

All services optional — use profiles or just `docker compose up <service>`.

### L.2 Create `eldrin-core/.env.example`

Document all environment variables from the master plan with descriptive comments. Organized by service layer (Core, Database, Auth, Storage, Cache, Queue, Email, Security, Observability).

### L.3 Create `eldrin-core/.env.local`

Pre-configured for docker-compose defaults. Gitignored. Allows `npm run server:dev` to immediately connect to local services.

### L.4 Update `.gitignore`

Ensure `.env.local` is gitignored.

## Test Gate

```bash
cd eldrin-core && docker compose config   # Validates docker-compose.yml
```

## Notes

- **No Turso container** — Turso tests use mocked HTTP (already working in Phase 1). For integration tests against a real libsql server, add `ghcr.io/tursodatabase/libsql-server` later.
- MinIO provides S3-compatible API, so the same `s3.ts` storage adapter works for both local dev and AWS production.
- Mailpit captures all outgoing email without actually sending — perfect for testing email flows.
- Redis serves triple duty: cache, rate limiting, and task queue (via BullMQ or similar).

## Files Created

- `eldrin-core/docker-compose.yml`
- `eldrin-core/.env.example`
- `eldrin-core/.env.local`
