# Feature 2: Localization (i18n)

## Overview

All UI text and backend error messages are hardcoded English strings (~500-1000 strings across 120+ files). No i18n infrastructure exists. This sets up the foundation with `en` as the system/fallback language and `en-US` as the first locale. The structure supports adding `fr-FR`, `fr-CA`, `en-CA`, etc. later — just add JSON files.

## Dependencies

None (but do early to avoid retrofitting future features).

## Language Hierarchy

- `en` — system language, always the fallback. Contains all keys.
- `en-US` — locale variant. Only needs to override keys that differ from `en`.
- Future: `fr-FR`, `fr-CA`, etc. fall back to their base language (`fr`), then to `en`.

## Steps

### 2.1 Install dependencies

```bash
npm install i18next react-i18next i18next-browser-languagedetector
```

### 2.2 Create i18n infrastructure — Frontend

**Create `src/i18n.ts`**: Initialize i18next with browser language detector, fallback chain (`en-US` → `en`), namespace-based JSON loading via static imports.

**Create locale files**:
```
src/locales/
  en/
    common.json      # Nav, buttons, labels, generic UI
    auth.json        # Login, password reset, SSO
    settings.json    # Settings pages (apps, users, providers, audit, API keys)
    dashboard.json   # Dashboard page
    errors.json      # Error messages shown in UI
  en-US/
    common.json      # Overrides only (initially empty or minimal)
```

**Modify `src/main.tsx`**: Import `./i18n` and wrap `<App>` with `<I18nextProvider>`.

### 2.3 Create i18n infrastructure — Backend

**Create `core/i18n/index.ts`**: Lightweight `t(key, locale?, vars?)` function. Looks up key in locale JSON, falls back to `en`. Locale detection from `Accept-Language` header.

**Create `core/i18n/locales/en/errors.json`**: All backend error message strings keyed by ID.

**Modify `core/utils.ts`**: Update `errorResponse()` to accept translation keys and resolve them.

**Modify `core/app.ts`**: Add Hono middleware to extract locale from `Accept-Language` header, store in context.

### 2.4 Migrate auth pages

Extract strings from:
- `src/pages/Login.tsx`
- `src/pages/ForgotPassword.tsx`
- `src/pages/ResetPassword.tsx`

Replace hardcoded strings with `t('auth:key')` calls.

### 2.5 Migrate dashboard + navigation

Extract strings from:
- `src/pages/Dashboard.tsx`
- `src/components/TopBar.tsx`
- `src/components/SideNav.tsx`
- `src/components/Layout.tsx` (if applicable)

### 2.6 Migrate settings pages

Extract strings from all settings page components:
- `src/pages/Settings.tsx`
- `src/pages/settings/ApplicationSettings.tsx` and sub-components
- `src/pages/settings/users/` — all user management components
- `src/pages/settings/AuthProviderSettings.tsx` and sub-components
- `src/pages/settings/AuditLogSettings.tsx` and sub-components
- `src/pages/settings/ApiKeySettings.tsx` and sub-components

### 2.7 Migrate backend error messages

Update error messages in route handlers to use translation keys:
- `core/routes/auth.ts`
- `core/routes/users.ts`
- `core/routes/apps.ts`
- `core/routes/api-keys.ts`
- `core/routes/password-reset.ts`
- `core/routes/auth-providers.ts`
- `core/routes/storage.ts`
- `core/routes/audit.ts`
- `core/routes/profile.ts` (if exists by then)

## Test Gate

```bash
cd eldrin-core && npx tsc -b && npx vitest run
```

1. All UI text renders identically (English, no visible change)
2. Browser language `en-US` → uses `en-US` overrides
3. Browser language `fr-FR` → falls back to `en` (no French yet)
4. Backend error messages unchanged for English requests
5. No missing translation warnings in console
6. All existing tests pass

## Files Created

| File | Purpose |
|------|---------|
| `src/i18n.ts` | i18next configuration |
| `src/locales/en/common.json` | Shared nav, buttons, labels |
| `src/locales/en/auth.json` | Auth page strings |
| `src/locales/en/settings.json` | Settings page strings |
| `src/locales/en/dashboard.json` | Dashboard strings |
| `src/locales/en/errors.json` | UI error messages |
| `src/locales/en-US/common.json` | US English overrides |
| `core/i18n/index.ts` | Backend i18n utility |
| `core/i18n/locales/en/errors.json` | Backend error strings |

## Files Modified

| File | Change |
|------|--------|
| `src/main.tsx` | Wrap with I18nextProvider |
| `core/utils.ts` | Locale-aware errorResponse |
| `core/app.ts` | Add locale middleware |
| `src/pages/*.tsx` | Extract strings (~15 files) |
| `src/pages/settings/**/*.tsx` | Extract strings (~20 files) |
| `src/components/*.tsx` | Extract strings (~5 files) |
| `core/routes/*.ts` | Backend error message migration |
