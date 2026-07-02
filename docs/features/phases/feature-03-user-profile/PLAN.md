# Feature 3: User Profile Page

## Overview

Users currently can't edit their own profile — all user management goes through admin Settings. This adds a self-service Profile page accessible from the TopBar user dropdown. Users can update their name and change their password (with current password verification).

## Dependencies

Benefits from Feature 2 (Localization) — all strings should use `t()` calls.

## Steps

### 3.1 Create backend route handlers

**New file**: `core/routes/profile.ts`

**`handleUpdateProfile(request, db, userId, audit?)`**
- `PATCH /api/auth/profile`
- Parse `{ firstName, lastName }` from body
- Email changes NOT allowed (security — would need email verification flow)
- Update `users` table for the authenticated user's own ID
- Audit: `PROFILE_UPDATE`

**`handleChangePassword(request, db, userId, revocationStore?, audit?)`**
- `POST /api/auth/change-password`
- Parse `{ currentPassword, newPassword }` from body
- **Verify current password** using `verifyPassword()` from `core/auth/password.ts`
- Validate new password >= 8 chars
- Hash and update password using `hashPassword()` from `core/auth/password.ts`
- Revoke all other sessions (keep current one by excluding current JTI)
- Audit: `PASSWORD_CHANGE`

### 3.2 Wiring changes

- `core/audit/actions.ts` — add `PROFILE_UPDATE: 'profile.update'`
- `core/routes/index.ts` — add exports for `handleUpdateProfile`, `handleChangePassword`
- `core/app.ts` — register `PATCH /api/auth/profile` and `POST /api/auth/change-password` (authenticated, no admin permission required)

### 3.3 Create Profile page

**New file**: `src/pages/Profile.tsx`

Sections:
1. **Personal Info card** — firstName, lastName fields (editable), email (read-only), save button
2. **Change Password card** — current password, new password, confirm password fields
3. **Linked Identities card** — show SSO identities from `GET /api/auth/identities` (already exists)
4. **Account Info card** — read-only: platform roles, email verified status, account created date

### 3.4 Wire frontend routing

- `src/components/TopBar.tsx` — add "Profile" link to user dropdown menu (before "Sign out")
- `src/App.tsx` — add `<Route path="profile" element={<Profile />} />` inside protected Shell routes

## Reusable Code

| Function | Location | Purpose |
|----------|----------|---------|
| `verifyPassword()` | `core/auth/password.ts` | Verify current password |
| `hashPassword()` | `core/auth/password.ts` | Hash new password |
| `GET /api/auth/identities` | `core/routes/auth-providers.ts` | Already exists |
| `GET /api/auth/me` | `core/routes/auth.ts` | Already returns user data |

## Test Gate

```bash
cd eldrin-core && npx tsc -b && npx vitest run
```

1. TopBar dropdown shows "Profile" link
2. Profile page: update name → save → refreshing shows new name
3. Change password: requires correct current password, rejects wrong one
4. After password change: other sessions are invalidated
5. All existing tests pass

## Files Created

| File | Purpose |
|------|---------|
| `core/routes/profile.ts` | Self-service profile and password change handlers |
| `src/pages/Profile.tsx` | Profile page component |

## Files Modified

| File | Change |
|------|--------|
| `core/audit/actions.ts` | Add `PROFILE_UPDATE` action |
| `core/routes/index.ts` | Add exports |
| `core/app.ts` | Register 2 route handlers |
| `src/components/TopBar.tsx` | Add Profile link to dropdown |
| `src/App.tsx` | Add profile route |
