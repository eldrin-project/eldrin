# Feature 2: Localization (i18n) — DONE

## Summary
Set up complete i18n infrastructure for both frontend (react-i18next) and backend (custom lightweight i18n), then migrated all ~40 frontend component files from hardcoded English strings to `t()` calls.

## What was built

### Frontend Infrastructure
- `src/i18n.ts` — i18next config with LanguageDetector, static imports, fallback to `en`
- `src/main.tsx` — imports `./i18n` before app bootstrap
- 5 namespace JSON files in `src/locales/en/`: common, auth, dashboard, settings, errors
- `src/locales/en-US/common.json` — empty overrides placeholder

### Backend Infrastructure
- `core/i18n/index.ts` — `parseLocale()` + `t()` function with interpolation
- `core/i18n/locales/en/errors.json` — 25 backend error message keys
- `core/app.ts` — locale detection middleware (`Accept-Language` → `c.set('locale')`)

### Files Migrated (~40 components)
- Auth pages: Login, ForgotPassword, ResetPassword
- Dashboard + Navigation: Dashboard, TopBar, SideNav
- Settings: Settings, ApplicationSettings, AppList, AppListItem, LocalAppForm, AppDetails
- Auth Providers: AuthProviderSettings, AuthProviderList, AuthProviderForm
- Audit: AuditLogSettings, AuditLogList
- API Keys: ApiKeySettings, ApiKeyList, ApiKeyForm, ApiKeyUsageStats
- Users: UserSettings, UserForm, UserList, UserListItem, UserDetailPage, UserDetailHeader, PlatformRolesSection, AppPermissionsSection, AppPermissionCard
- Components: AppNotFound, LicenseWarning

## Verification
- `npx tsc -b` — clean (zero errors)
- `npx vitest run` — 318/318 tests pass (45 files)
- All UI text renders identically (English, no visible change)
- No missing translation keys (all JSON keys match t() calls)

## What was deferred
- Backend route handlers still return hardcoded English error strings. The infrastructure (JSON keys, `t()` function, locale middleware) is ready — actual migration deferred until a second language is added.
