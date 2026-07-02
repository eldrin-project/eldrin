# Eldrin-Core Feature Roadmap

## Context

Eldrin-core has a solid foundation: auth (login, JWT, SSO/OIDC, password reset), user management (CRUD, RBAC, approval), app management, API keys, audit logging, storage, background jobs, email, events, and full admin settings UI. This roadmap adds the next wave of features — starting with quick wins and building toward larger capabilities.

## Implementation Order

1. **Dark Mode** — ~30 lines, toggle already exists, just needs persistence + FOUC prevention
2. **Localization (i18n)** — foundational; set up infrastructure + extract all strings. Start with `en` (system fallback) and `en-US`. Structure supports future `fr-FR`, `fr-CA`, `en-CA`, etc.
3. **User Profile** — new self-service page + 2 API endpoints
4. **User Invitations** — invite by email, builds on existing email infra
5. **Two-Factor Auth (TOTP)** — QR setup, backup codes, enforcement
6. **Webhooks** — external event subscriptions, builds on existing event pub/sub
7. **Global Search + Command Palette** — cross-entity search with Cmd+K UI
8. **Workflow Engine** — visual automation builder (largest scope)

We'll implement them one at a time. Detailed plans for features 1-3 below; features 4-8 are high-level summaries that we'll detail when we get to them.

---

## Feature 1: Dark Mode (Persistence + FOUC Prevention)

### Context

The dark mode infrastructure is **already built**: CSS variables with light/dark themes in `src/index.css`, `data-theme` attribute switching, a toggle button in TopBar using Sun/Moon icons, and a Zustand store (`shellStore.ts`) with `toggleTheme()`. The only gap: theme resets on reload because there's no persistence or OS preference detection.

### Changes

#### `index.html` — add inline FOUC prevention script before `<div id="root">`
```html
<script>
  (function() {
    var s = localStorage.getItem('eldrin-theme');
    var p = window.matchMedia('(prefers-color-scheme: dark)').matches;
    var t = s || (p ? 'dark' : 'light');
    document.documentElement.setAttribute('data-theme', t);
  })();
</script>
```

#### `src/stores/shellStore.ts` — add persistence + OS preference detection
- Initialize `theme` from `localStorage.getItem('eldrin-theme')` or OS `prefers-color-scheme`
- On `toggleTheme()` / `setTheme()`: save to `localStorage` + set `data-theme` attribute
- Add `matchMedia` listener for OS preference changes (only when no explicit user choice)

### Files

| File | Action |
|------|--------|
| `index.html` | Modify (add inline script) |
| `src/stores/shellStore.ts` | Modify (add persistence + OS detection) |

### Verification
1. Toggle dark mode → persists after reload
2. Clear localStorage → follows OS preference
3. No flash of wrong theme on load (FOUC prevention)

---

## Feature 2: Localization (i18n)

### Context

All UI text and backend error messages are hardcoded English strings (~500-1000 strings across 120+ files). No i18n infrastructure exists. This sets up the foundation with `en` as the system/fallback language and `en-US` as the first locale. The structure supports adding `fr-FR`, `fr-CA`, `en-CA`, etc. later — just add JSON files.

### Language hierarchy
- `en` — system language, always the fallback. Contains all keys.
- `en-US` — locale variant. Only needs to override keys that differ from `en` (e.g., date formats, spelling like "color" vs "colour"). Initially identical to `en`.
- Future locales (`fr-FR`, `fr-CA`, etc.) — fall back to their base language (`fr`), which falls back to `en`.

### Frontend — react-i18next

**Dependencies**: `i18next`, `react-i18next`, `i18next-browser-languagedetector`

**Directory structure**:
```
src/locales/
  en/                    # System language (fallback for everything)
    common.json          # Shared: nav, buttons, labels, generic
    auth.json            # Login, password reset, SSO
    settings.json        # Settings pages
    dashboard.json       # Dashboard page
    errors.json          # Error messages shown in UI
  en-US/
    common.json          # Overrides only (initially empty or minimal)
```

**Setup file**: `src/i18n.ts`
- Initialize i18next with `i18next-browser-languagedetector`
- Fallback chain: `en-US` → `en`
- Load JSON files via static import (bundled by Vite, no network requests)
- Export configured instance

**Integration**: Wrap `<App>` with `<I18nextProvider>` in `src/main.tsx`

**Migration pattern** (per component):
```tsx
// Before
<CardTitle>Welcome back</CardTitle>

// After
const { t } = useTranslation();
<CardTitle>{t('auth:welcomeBack')}</CardTitle>
```

**Migration scope** (files to update):
- `src/pages/` — all page components (~15 files)
- `src/pages/settings/` — all settings pages (~20 files)
- `src/components/` — TopBar, SideNav, Layout (~5 files)

### Backend — lightweight custom i18n

**New file**: `core/i18n/index.ts`
- `t(key, locale?, vars?)` function — looks up key in locale JSON, falls back to `en`
- Locale detection from `Accept-Language` header
- Bundled JSON (same `/locales` structure, imported at build time)

**New file**: `core/i18n/locales/en/errors.json`
- All backend error message strings keyed by ID

**Update**: `core/utils.ts`
- `errorResponse(key, status, locale?)` — resolve translation before returning

**Hono middleware** (in `core/app.ts`):
- Extract locale from `Accept-Language` header
- Store in Hono context: `c.set('locale', detectedLocale)`
- Routes access via `c.get('locale')`

### Migration strategy

We'll migrate in batches to keep PRs reviewable:
1. **Infrastructure**: add deps, create `src/i18n.ts`, create `core/i18n/`, create locale JSON files
2. **Auth pages**: Login, ForgotPassword, ResetPassword (small, self-contained)
3. **Dashboard + nav**: Dashboard, TopBar, SideNav
4. **Settings pages**: ApplicationSettings, UserSettings, AuthProviderSettings, AuditLog, ApiKeys
5. **Backend errors**: Update `errorResponse()`, migrate route error messages

### Files

| File | Action |
|------|--------|
| `src/i18n.ts` | Create (i18next config) |
| `src/main.tsx` | Modify (wrap with I18nextProvider) |
| `src/locales/en/common.json` | Create |
| `src/locales/en/auth.json` | Create |
| `src/locales/en/settings.json` | Create |
| `src/locales/en/dashboard.json` | Create |
| `src/locales/en/errors.json` | Create |
| `src/locales/en-US/common.json` | Create (minimal overrides) |
| `core/i18n/index.ts` | Create |
| `core/i18n/locales/en/errors.json` | Create |
| `core/utils.ts` | Modify (locale-aware errorResponse) |
| `core/app.ts` | Modify (add locale middleware) |
| `src/pages/*.tsx` | Modify (extract strings, ~15 files) |
| `src/pages/settings/**/*.tsx` | Modify (~20 files) |
| `src/components/*.tsx` | Modify (~5 files) |

### Verification
1. `npx tsc -b` + `npx vitest run`
2. All UI text renders identically (English, no visible change)
3. Browser language set to `en-US` → uses `en-US` overrides
4. Browser language set to `fr-FR` → falls back to `en` (no French yet)
5. Backend error messages unchanged for English requests
6. No missing translation warnings in console

---

## Feature 3: User Profile Page

### Context

Users currently can't edit their own profile — all user management goes through admin Settings. This adds a self-service Profile page accessible from the TopBar user dropdown. Users can update their name and change their password (with current password verification).

### Backend — New route handlers

**New file**: `core/routes/profile.ts`

#### `handleUpdateProfile(request, db, userId, audit?)`
- `PATCH /api/auth/profile`
- Parse `{ firstName, lastName }` from body (email changes NOT allowed — security)
- Update `users` table for the authenticated user's own ID
- Audit: `PROFILE_UPDATE`

#### `handleChangePassword(request, db, userId, revocationStore?, audit?)`
- `POST /api/auth/change-password`
- Parse `{ currentPassword, newPassword }` from body
- **Verify current password** using `verifyPassword()` from `core/auth/password.ts`
- Validate new password >= 8 chars
- Hash and update password
- Revoke all other sessions (keep current one by excluding current JTI)
- Audit: `PASSWORD_CHANGE`

### Wiring

| File | Change |
|------|--------|
| `core/audit/actions.ts` | Add `PROFILE_UPDATE: 'profile.update'` |
| `core/routes/index.ts` | Add export for `handleUpdateProfile`, `handleChangePassword` |
| `core/app.ts` | Register `PATCH /api/auth/profile` and `POST /api/auth/change-password` (authenticated, no admin perm needed) |

### Frontend

**New file**: `src/pages/Profile.tsx`

Sections:
1. **Personal Info card** — firstName, lastName fields (editable), email (read-only), save button
2. **Change Password card** — current password, new password, confirm password fields
3. **Linked Identities card** — show SSO identities from `GET /api/auth/identities` (already exists)
4. **Account Info card** — read-only: roles, email verified status, account created date

**Modify**: `src/components/TopBar.tsx` — add "Profile" link to user dropdown menu (before "Sign out")
**Modify**: `src/App.tsx` — add `<Route path="profile" element={<Profile />} />` inside protected Shell routes

### Key reusable code
- `verifyPassword()` — `core/auth/password.ts`
- `hashPassword()` — `core/auth/password.ts`
- `GET /api/auth/identities` — already exists in `core/routes/auth-providers.ts`
- `GET /api/auth/me` — already returns user data for populating the form

### Files

| File | Action |
|------|--------|
| `core/routes/profile.ts` | Create |
| `core/audit/actions.ts` | Modify (add 1 action) |
| `core/routes/index.ts` | Modify (add exports) |
| `core/app.ts` | Modify (add 2 route registrations) |
| `src/pages/Profile.tsx` | Create |
| `src/components/TopBar.tsx` | Modify (add Profile link to dropdown) |
| `src/App.tsx` | Modify (add route) |

### Verification
1. `npx tsc -b` + `npx vitest run`
2. TopBar dropdown shows "Profile" link
3. Profile page: update name → save → refreshing shows new name
4. Change password: requires correct current password, rejects wrong one
5. After password change: other sessions are invalidated

---

## Feature 4: User Invitations (high-level)

### Concept
Admin invites users by email → system sends invitation email with a signup link → invitee creates account with pre-assigned role. Builds on existing email provider infrastructure and user approval workflow.

### Key pieces
- New `user_invitations` table (token, email, role, expiry, status)
- `POST /api/users/invite` — admin endpoint, generates token, sends email
- `POST /api/auth/accept-invite` — public endpoint, creates user from invitation
- New email template (`userInvitationTemplate`)
- Frontend: invite form in user management settings, accept-invite public page

---

## Feature 5: Two-Factor Auth / TOTP (high-level)

### Concept
Users can enable TOTP-based 2FA from their Profile page. Login becomes a two-step flow: email/password → TOTP code. Backup codes for recovery.

### Key pieces
- New `user_totp_secrets` table (encrypted secret, backup codes)
- TOTP library: implement using Web Crypto API (HMAC-SHA1 for TOTP, no external deps)
- `POST /api/auth/totp/setup` — generate secret + QR code URI
- `POST /api/auth/totp/verify` — verify code and enable 2FA
- `POST /api/auth/totp/disable` — disable 2FA (with password verification)
- Modify login flow: if user has 2FA enabled, return `{ requires2FA: true, tempToken }` instead of full JWT, then `POST /api/auth/totp/authenticate` with code + temp token
- Frontend: 2FA setup in Profile page (QR code display, code verification), 2FA prompt in login flow
- Backup codes: 10 single-use codes, hashed in DB

---

## Feature 6: Webhooks (high-level)

### Concept
External systems register webhook URLs to receive event callbacks when things happen in Eldrin (user created, app installed, etc.). Builds on the existing event pub/sub system.

### Key pieces
- New `webhooks` table (URL, events filter, secret for HMAC signing, status)
- `POST /api/webhooks` — register webhook with event filter
- Webhook delivery: background job that POSTs to registered URLs with HMAC signature
- Retry logic with exponential backoff (reuse existing task queue)
- Webhook logs: delivery attempts, status codes, response times
- Frontend: webhook configuration page in Settings (URL, events, secret, delivery log)

---

## Feature 7: Global Search + Command Palette (high-level)

### Concept
Cmd+K opens a command palette for quick navigation and cross-entity search (users, apps, settings pages). Similar to VS Code / Linear / GitHub command palette.

### Key pieces
- `GET /api/search?q=...` — backend search across users, apps, audit entries
- Frontend: modal component triggered by Cmd+K or search icon
- Fuzzy matching for navigation items (pages, settings sections)
- Recent searches, keyboard navigation (arrow keys + enter)
- Result categories: Pages, Users, Apps, Actions

---

## Feature 8: Workflow Engine (high-level)

### Concept
Visual automation builder: "When X happens, do Y". Triggers (events, schedules, webhooks) → conditions → actions (send email, call API, update data). This is the largest scope item.

### Key pieces
- Workflow definition schema (JSON: triggers, conditions, steps)
- `workflows` and `workflow_runs` tables
- Workflow execution engine (builds on background jobs)
- Built-in actions: send email, HTTP request, update user, emit event
- Frontend: visual builder with drag-and-drop nodes
- Template library: common automation patterns

---

## Summary

| # | Feature | Effort | Key Files |
|---|---------|--------|-----------|
| 1 | Dark Mode | Small (~30 LOC) | `index.html`, `shellStore.ts` |
| 2 | Localization (i18n) | Medium-Large | `src/i18n.ts`, `src/locales/`, `core/i18n/`, ~40 component files |
| 3 | User Profile | Small-Medium | `core/routes/profile.ts`, `src/pages/Profile.tsx`, `TopBar.tsx` |
| 4 | User Invitations | Medium | new migration, route, email template, accept-invite page |
| 5 | Two-Factor Auth | Medium-Large | TOTP implementation, login flow changes, profile UI |
| 6 | Webhooks | Medium | new migration, delivery jobs, settings UI |
| 7 | Global Search | Medium-Large | search API, Cmd+K modal, fuzzy matching |
| 8 | Workflow Engine | Very Large | execution engine, visual builder, template system |
