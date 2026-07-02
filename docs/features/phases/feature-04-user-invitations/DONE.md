# Feature 4: User Invitations — DONE

## Summary
Added an invitation flow: admins invite users by email with a pre-assigned role. Invitees receive an email with a signup link and create their own account (name + password). Builds on the existing password-reset token infrastructure.

## What was built

### Database — 1 new migration
- `migrations/20260211000002-user-invitations.sql`
  - `user_invitations` table: id, email, role_id, token_hash, invited_by, expires_at, accepted_at, created_at
  - Indexes on email and token_hash

### Backend — 4 route handlers
- `core/routes/invitations.ts`
  - `handleSendInvitation` — `POST /api/users/invitations` — admin sends invitation email with token
  - `handleAcceptInvitation` — `POST /api/auth/accept-invitation` — public, validates token, creates user
  - `handleGetInvitations` — `GET /api/users/invitations` — admin lists pending invitations
  - `handleCancelInvitation` — `DELETE /api/users/invitations/:id` — admin cancels invitation

### Backend wiring
- `core/audit/actions.ts` — added `USER_INVITE`, `USER_INVITE_ACCEPT`
- `core/auth/middleware.ts` — added `/api/auth/accept-invitation` to `PUBLIC_ROUTES`
- `core/routes/index.ts` — added exports for all 4 handlers
- `core/app.ts` — registered all 4 routes (1 public, 3 permission-gated)
- `core/notifications/email/templates.ts` — added `invitationTemplate`

### Frontend — Public page
- `src/pages/AcceptInvitation.tsx`
  - Mirrors ResetPassword.tsx pattern: extract token+email from URL params
  - Form: firstName, lastName, password, confirmPassword
  - Success screen with "Sign in" button

### Frontend — Admin settings
- `src/pages/settings/users/InvitationForm.tsx` — email + role select, sends invitation
- `src/pages/settings/users/PendingInvitations.tsx` — lists pending invitations with cancel button
- `src/pages/settings/users/UserSettings.tsx` — added invitation card (before Add User card)

### Frontend wiring
- `src/App.tsx` — added `/accept-invitation` public route

### Localization
- `src/locales/en/settings.json` — added `users.invitations.*` and audit action labels
- `src/locales/en/auth.json` — added `acceptInvitation.*` section

## Verification
- `npx tsc -b` — clean (zero errors)
- `npx vitest run` — 318/318 tests pass (45 files)

## Files Created
| File | Purpose |
|------|---------|
| `migrations/20260211000002-user-invitations.sql` | Invitations table + indexes |
| `core/routes/invitations.ts` | 4 invitation route handlers |
| `src/pages/AcceptInvitation.tsx` | Public invitation acceptance page |
| `src/pages/settings/users/InvitationForm.tsx` | Admin invitation form |
| `src/pages/settings/users/PendingInvitations.tsx` | Pending invitations list |

## Files Modified
| File | Change |
|------|--------|
| `core/notifications/email/templates.ts` | Added `invitationTemplate` |
| `core/audit/actions.ts` | Added `USER_INVITE`, `USER_INVITE_ACCEPT` |
| `core/routes/index.ts` | Added invitation handler exports |
| `core/auth/middleware.ts` | Added accept-invitation to public routes |
| `core/app.ts` | Registered 4 new routes + imported handlers |
| `src/App.tsx` | Added /accept-invitation route + import |
| `src/pages/settings/users/UserSettings.tsx` | Added InvitationForm + PendingInvitations |
| `src/locales/en/settings.json` | Added invitation i18n keys + audit labels |
| `src/locales/en/auth.json` | Added acceptInvitation i18n keys |
