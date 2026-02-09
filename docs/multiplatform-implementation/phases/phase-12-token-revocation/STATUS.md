# Phase 12: Session Revocation & Token Blacklist

## Status: done
## Started: 2026-02-09
## Completed: 2026-02-09

## Progress:
- [x] Step 12.1: Create token revocation interface
- [x] Step 12.2: Implement memory + database-backed revocation stores
- [x] Step 12.3: Add jti to JWT, update createToken() and checkAuth()
- [x] Step 12.4: Integrate with logout, user disable, password change, user delete
- [x] Step 12.5: Create database migration (revoked_tokens + user_revocations tables)
- [x] Step 12.6: Write unit tests (13 cases)
- [ ] Step 12.7: Write E2E tests (~4 cases) — deferred, needs running server
- [ ] Step 12.8: E2E regression — deferred, needs running server

## Notes:
- Two-level revocation: individual jti blacklist + bulk user revocation timestamps
- No ALTER TABLE on users table — self-contained in _revoked_tokens and _user_revocations tables
- Store injected via CreateAppOptions.tokenRevocation or AppVariables.revocationStore
- 123 tests pass (13 new + 110 existing, zero regressions)
- TypeScript compiles cleanly
