# OAuth Co-Tenancy Validation — eldrin-email × eldrin-calendar

**Why:** Both apps share one Google Cloud Console client and one Entra app
registration (distinct redirect URIs and scopes per app). Each app stores its
own token grant, so refresh activity in one must never invalidate the other.
Risk focus: Microsoft rotates refresh tokens on every refresh.

## Tenancy rules (documented facts)

- Shared Google client: eldrin-email (gmail scopes) + eldrin-calendar
  (calendar scopes, redirect `http://localhost:4012/api/oauth/google/callback`).
- Shared Entra app: eldrin-email (Mail scopes) + eldrin-calendar
  (Calendars.ReadWrite, redirect `http://localhost:4012/api/oauth/microsoft/callback`).
- Token grants are per-app-per-flow: each app runs its own consent and stores
  its own refresh token. Rotating one grant's refresh token MUST NOT
  invalidate the other grant (same client id, separate token chains).
- Both apps persist rotated MS refresh tokens (calendar since 4c;
  email since parent commit 381047f (2026-07-10)).

## Live checklist (user-driven browser; do NOT automate the consents)

- [ ] 1. Task 6 merged; email + calendar dev servers restarted.
- [ ] 2. Link the SAME Microsoft account in eldrin-email (mailbox) AND
        eldrin-calendar (connected account).
- [ ] 3. Force refresh in calendar: `POST /api/sync/run` (or Sync now in
        Settings). Confirm account stays `active`.
- [ ] 4. Force refresh in email: trigger a mailbox sync. Confirm mailbox
        syncStatus is not `error`.
- [ ] 5. Wait ≥65 minutes (past access-token expiry, at least one rotation
        in each app), then repeat steps 3–4. BOTH must still succeed.
- [ ] 6. Same-account Google sanity pass: steps 2–5 with one Google account
        in both apps (no rotation expected; both must stay `active`).

## Results

| Date | Provider | Result | Notes |
|------|----------|--------|-------|
|      |          |        |       |
