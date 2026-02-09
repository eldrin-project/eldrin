# Phase 13: Audit Logging — DONE

## What was built

A queryable audit logging system that records security-relevant events across all mutation handlers.

## Files created

| File | Purpose |
|------|---------|
| `core/audit/interface.ts` | AuditService, AuditEntry, AuditLogRow, AuditFilter, AuditParams types |
| `core/audit/actions.ts` | AUDIT_ACTIONS constants (dot-separated: `auth.login`, `user.create`, etc.) |
| `core/audit/memory.ts` | MemoryAuditService — in-memory implementation for dev/test |
| `core/audit/database.ts` | DatabaseAuditService — production implementation with auto-table creation |
| `core/audit/index.ts` | Barrel exports |
| `core/routes/audit.ts` | handleGetAuditLog (paginated JSON), handleExportAuditLog (CSV/JSON) |
| `core/audit/audit.test.ts` | 15 unit + integration tests |
| `migrations/20260209000002-audit-log.sql` | _audit_log table with 4 indexes |

## Files modified

| File | Change |
|------|--------|
| `core/app.ts` | Added auditService to AppVariables, buildAuditParams() helper, wired audit to all mutation handlers, mounted audit query routes |
| `core/routes/index.ts` | Added audit route exports |
| `core/routes/auth.ts` | Added audit?: AuditParams to handleLogin, handleLogout |
| `core/routes/users.ts` | Added audit?: AuditParams to 5 mutation handlers |
| `core/routes/apps.ts` | Added audit?: AuditParams to handleAddApp, handleUpdateApp, handleDeleteApp |

## Key design decisions

- **AuditParams pattern**: Bundles service + actor identity + request metadata into one optional parameter, keeping handler signatures clean
- **Fire-and-forget**: Audit calls wrapped in try/catch — failures are logged but never block the primary operation
- **buildAuditParams(c)**: Helper in app.ts extracts actor from JWT and request metadata from headers
- **Login special case**: Public route with no JWT, so actorId defaults to 'anonymous' and handler overrides with actual user data
- **Resource capture before deletion**: Modified DELETE handlers to SELECT email/name before deleting, so audit entries have complete information

## Audited actions

| Handler | Action(s) | Resource |
|---------|-----------|----------|
| handleLogin | auth.login / auth.login_failed | user |
| handleLogout | auth.logout | user |
| handleCreateUser | user.create | user |
| handleUpdateUser | user.update / user.disable | user |
| handleUpdateUserRoles | role.assign | user |
| handleUpdateUserPassword | user.password_change | user |
| handleDeleteUser | user.delete | user |
| handleAddApp | app.create | app |
| handleUpdateApp | app.update | app |
| handleDeleteApp | app.delete | app |

## Test results

- 15 new tests (7 MemoryAuditService + 4 route handlers + 4 integration)
- 138 total tests pass (zero regressions)
- TypeScript: zero errors
