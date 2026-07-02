# Feature 4: User Invitations

## Overview

Admin invites users by email with a pre-assigned role. Invitee receives email with a signup link, creates their account with name and password. Builds on existing email provider infrastructure and user approval workflow.

## Dependencies

- Feature 2 (Localization) — strings should use `t()` calls
- Feature 3 (User Profile) — optional, but profile page exists for invited users

## Key Pieces

### Database
- New `user_invitations` table: id, email, role, token_hash, expires_at, status (pending/accepted/expired), invited_by, created_at

### Backend
- `POST /api/users/invite` — admin endpoint, generates invitation token, sends email
- `GET /api/auth/invitations/:token` — public, validates token and returns invitation details
- `POST /api/auth/accept-invite` — public, creates user from invitation with { token, firstName, lastName, password }
- New email template: `userInvitationTemplate`

### Frontend
- Invite button/form in user management settings (enter email + select role)
- `src/pages/AcceptInvite.tsx` — public page for accepting invitations (name + password form)
- Invitation status tracking in user list

## Test Gate

```bash
cd eldrin-core && npx tsc -b && npx vitest run
```

1. Admin can invite user by email
2. Invitation email sent (or logged in dev mode)
3. Invitee can accept and create account
4. Invitation token is single-use
5. Expired invitations are rejected

## Detailed plan will be written when implementation begins.
