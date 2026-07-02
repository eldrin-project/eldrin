# Phase 9: Observability Stack

## Overview

Add structured logging, metrics collection, and OpenTelemetry-compatible tracing. All three are set on `AppVariables` as request-scoped services.

## Dependencies

- Phase 0 (testing infrastructure)

## Steps

### 9.1 Structured logging — `core/observability/logger.ts`

`Logger` interface: `info()`, `warn()`, `error()`, `debug()`, `child()`. Default implementation outputs JSON lines to stdout with `timestamp`, `level`, `message`, `requestId`, `userId`.

Provider routing:
- Cloudflare: Workers Logpush / console.log
- AWS: CloudWatch Logs (stdout → CloudWatch)
- Azure: Application Insights (stdout + custom telemetry)
- GCP: Cloud Logging (stdout → structured logs)

### 9.2 Metrics — `core/observability/metrics.ts`

`MetricsCollector` interface: `increment()`, `gauge()`, `histogram()`, `flush()`.

Built-in metrics: `http_requests_total`, `http_request_duration_ms`, `auth_login_total`, `auth_login_failed_total`, `db_query_duration_ms`.

Adapters: in-memory (dev), CloudWatch, Azure Monitor, Cloud Monitoring, Prometheus endpoint.

### 9.3 OpenTelemetry tracing — `core/observability/tracing.ts`

`Tracer` and `Span` interfaces. Default: no-op tracer (zero overhead). Hono middleware auto-creates request span.

### 9.4 Request-scoped context — `core/observability/middleware.ts`

Hono middleware creates per-request logger child with `requestId` (from `X-Request-ID` or generated UUID). Adds `logger`, `metrics`, `tracer` to `AppVariables`.

### 9.5 Tests

| Test file | Cases |
|-----------|-------|
| `core/observability/logger.test.ts` | ~8 |
| `core/observability/metrics.test.ts` | ~5 |
| `core/observability/middleware.test.ts` | ~5 |

## Test Gate

```bash
cd eldrin-core && npx vitest run -- core/observability/   # ~18 tests
```


## Commit

After all tests pass, commit the changes to the relevant submodule(s) using conventional commits format, then update the parent repo submodule reference.
