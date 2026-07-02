# Eldrin-Core Feature Roadmap

## Overview

Second wave of platform features for eldrin-core. The multi-cloud infrastructure is complete (all 18 phases). This roadmap builds on that foundation to add user-facing features, security enhancements, and platform capabilities.

## Current State

### Already Built
- Authentication: login, JWT, SSO/OIDC (Entra, Google, Cognito), password reset
- User management: CRUD, RBAC (admin/editor/viewer), approval workflow
- App management: install from manifest, enable/disable, API proxy, permission sync
- API keys: scopes, rotation, IP whitelist, usage analytics
- Audit logging: 42 action types, query with filters, CSV/JSON export
- Storage: upload/download, signed URLs, adapters (filesystem, S3, R2)
- Background jobs: database-backed queue, handler registry
- Email notifications: templates, adapters (console, SendGrid, SMTP)
- Events: pub/sub for inter-app communication
- Security: rate limiting, headers, token revocation
- Observability: structured logging, metrics, tracing
- Full admin settings UI for all of the above
- Multi-cloud deployment: Cloudflare Workers, AWS Lambda/ECS, Azure Functions/Containers, GCP Functions/Cloud Run, standalone Bun

## Feature Roadmap

### Implementation Order

| # | Feature | Effort | Status |
|---|---------|--------|--------|
| 1 | [Dark Mode](#feature-1-dark-mode) | Small | complete |
| 2 | [Localization (i18n)](#feature-2-localization) | Medium-Large | complete |
| 3 | [User Profile](#feature-3-user-profile) | Small-Medium | complete |
| 4 | [User Invitations](#feature-4-user-invitations) | Medium | complete |
| 5 | [Two-Factor Auth (TOTP)](#feature-5-two-factor-auth) | Medium-Large | not_started |
| 6 | [Webhooks](#feature-6-webhooks) | Medium | not_started |
| 7 | [Global Search + Command Palette](#feature-7-global-search) | Medium-Large | not_started |

### Dependencies

```
Feature 1 (Dark Mode) → no deps
Feature 2 (Localization) → no deps (but do early to avoid retrofit)
Feature 3 (User Profile) → benefits from Feature 2 (i18n)
Feature 4 (User Invitations) → benefits from Feature 2 (i18n)
Feature 5 (Two-Factor Auth) → depends on Feature 3 (Profile page for setup UI)
Feature 6 (Webhooks) → no deps (builds on existing event pub/sub)
Feature 7 (Global Search) → no deps
```

---

## Feature 1: Dark Mode

**Effort**: Small (~30 LOC) | **Files**: 2

The dark mode infrastructure is already built: CSS variables with light/dark themes, `data-theme` attribute switching, toggle button in TopBar, Zustand store. Only missing: persistence (localStorage) and FOUC prevention (inline script in index.html).

**Key files**: `index.html`, `src/stores/shellStore.ts`

---

## Feature 2: Localization

**Effort**: Medium-Large | **Files**: ~45

All UI text and backend error messages are hardcoded English (~500-1000 strings across 120+ files). This sets up i18n infrastructure with `en` as system fallback language and `en-US` as first locale. Structure supports adding `fr-FR`, `fr-CA`, `en-CA`, etc. later.

- **Frontend**: react-i18next with namespace-based JSON files
- **Backend**: lightweight custom i18n with Accept-Language detection
- **Language hierarchy**: `en-US` → `en` (system fallback)

**Key files**: `src/i18n.ts`, `src/locales/en/*.json`, `core/i18n/index.ts`, all component files

---

## Feature 3: User Profile

**Effort**: Small-Medium | **Files**: 7

Self-service profile page: update name, change password (with current password verification), view linked SSO identities. Accessible from TopBar user dropdown.

- **Backend**: `PATCH /api/auth/profile`, `POST /api/auth/change-password`
- **Frontend**: `src/pages/Profile.tsx` with 4 cards (personal info, password, identities, account info)

**Key files**: `core/routes/profile.ts`, `src/pages/Profile.tsx`, `src/components/TopBar.tsx`

---

## Feature 4: User Invitations

**Effort**: Medium | **Files**: ~10

Admin invites users by email with pre-assigned role. Invitee receives email with signup link, creates account. Builds on existing email infrastructure.

**Key files**: new migration, `core/routes/invitations.ts`, email template, `src/pages/AcceptInvite.tsx`

---

## Feature 5: Two-Factor Auth

**Effort**: Medium-Large | **Files**: ~12

TOTP-based 2FA with QR code setup, backup codes, and enforcement policies. Modifies login flow to support two-step authentication.

**Key files**: new migration, `core/auth/totp.ts`, login flow changes, Profile page 2FA section

---

## Feature 6: Webhooks

**Effort**: Medium | **Files**: ~10

External systems register webhook URLs to receive event callbacks. HMAC-signed payloads, retry logic with exponential backoff, delivery logs.

**Key files**: new migration, `core/webhooks/`, delivery job, settings UI

---

## Feature 7: Global Search

**Effort**: Medium-Large | **Files**: ~8

Cmd+K command palette for quick navigation and cross-entity search (users, apps, settings). Fuzzy matching, keyboard navigation, recent searches.

**Key files**: `GET /api/search`, `src/components/CommandPalette.tsx`


---

## Extracted Features

| Feature | Destination | Requirements |
|---------|-------------|--------------|
| Workflow Engine | `eldrin-workflows` extension app | `docs/requirements/eldrin-workflows.md` |
