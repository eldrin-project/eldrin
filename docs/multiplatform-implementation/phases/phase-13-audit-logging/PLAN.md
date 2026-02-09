# Phase 13: Audit Logging

## Overview

Record security-relevant events (logins, user changes, permission changes, config updates) in a queryable `audit_log` table.

## Dependencies

- Phase 2 (unified Hono app — routes and middleware)

## Steps

### 13.1 Audit service — `core/audit/service.ts`

`recordAudit(db, entry)` and `queryAuditLog(db, filters)` with `AuditEntry` and `AuditFilters` types.

### 13.2 Built-in audit actions

`auth.login`, `auth.login_failed`, `auth.logout`, `user.create`, `user.approve`, `user.reject`, `user.disable`, `user.update`, `user.password_change`, `identity.link`, `identity.unlink`, `role.assign`, `role.revoke`, `permission.grant`, `permission.deny`, `app.create`, `app.update`, `app.delete`, `config.update`.

### 13.3 Audit routes — `core/routes/audit.ts`

| Route | Method | Permission | Purpose |
|-------|--------|------------|---------|
| `/api/audit` | GET | `audit:read` | Query with filters |
| `/api/audit/export` | GET | `audit:read` | Export as CSV/JSON |

### 13.4 Database migration — `audit_log` table

### 13.5 Tests

| Test file | Cases |
|-----------|-------|
| `core/audit/service.test.ts` | ~8 |
| `core/routes/audit.test.ts` | ~5 |
| Integration (login → audit entry) | ~3 |
| `e2e/admin/audit-log.spec.ts` | ~5 |

## Test Gate

```bash
cd eldrin-core && npx vitest run -- core/audit/ core/routes/audit.test.ts   # ~16 tests
cd eldrin-core && npx playwright test e2e/admin/audit-log.spec.ts           # ~5 E2E
cd eldrin-core && npx playwright test e2e/baseline.spec.ts                  # Regression
```


## Commit

After all tests pass, commit the changes to the relevant submodule(s) using conventional commits format, then update the parent repo submodule reference.
