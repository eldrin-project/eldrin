# Feature 3: User Profile Page — DONE

## Summary
Added a self-service Profile page where users can update their name, change their password, view linked SSO identities, and see account information. Accessible from the TopBar user dropdown.

## What was built

### Backend — 2 new route handlers
- `core/routes/profile.ts`
  - `handleUpdateProfile` — `PATCH /api/auth/profile` — updates firstName/lastName for the authenticated user
  - `handleChangePassword` — `POST /api/auth/change-password` — verifies current password, hashes new one, revokes all sessions

### Backend wiring
- `core/audit/actions.ts` — added `PROFILE_UPDATE: 'profile.update'`
- `core/routes/index.ts` — added exports for both handlers
- `core/app.ts` — registered both routes in auth-only section (no admin permission required)

### Frontend — Profile page with 4 cards
- `src/pages/Profile.tsx`
  - **Personal Info** — editable firstName/lastName, read-only email, save button
  - **Change Password** — current password verification, new + confirm, auto-logout on success
  - **Linked Identities** — fetches from `GET /api/auth/identities`, displays provider + linked date
  - **Account Info** — read-only: platform roles (badges), email verified status, member since date

### Frontend wiring
- `src/components/TopBar.tsx` — added Profile link in user dropdown (before Sign out)
- `src/App.tsx` — added `/profile` route, added 'profile' to known routes in CatchAllRoute

### Localization
- `src/locales/en/common.json` — added `nav.profile` and `profile.*` section (30+ keys)

## Verification
- `npx tsc -b` — clean (zero errors)
- `npx vitest run` — 318/318 tests pass (45 files)

## Files Created
| File | Purpose |
|------|---------|
| `core/routes/profile.ts` | Self-service profile and password change handlers |
| `src/pages/Profile.tsx` | Profile page with 4 card sections |

## Files Modified
| File | Change |
|------|--------|
| `core/audit/actions.ts` | Added `PROFILE_UPDATE` action |
| `core/routes/index.ts` | Added profile handler exports |
| `core/app.ts` | Registered 2 auth-only routes, imported handlers |
| `src/components/TopBar.tsx` | Added Profile link to user dropdown |
| `src/App.tsx` | Added profile route + known route entry |
| `src/locales/en/common.json` | Added `nav.profile` + `profile.*` keys |
