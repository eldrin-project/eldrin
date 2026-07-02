# Feature 2: Localization (i18n)

## Status: complete
## Started: 2026-02-10
## Completed: 2026-02-10

## Progress:
- [x] Step 2.1: Install dependencies (i18next, react-i18next, i18next-browser-languagedetector)
- [x] Step 2.2: Create frontend i18n infrastructure (src/i18n.ts, locale JSON files, I18nextProvider)
- [x] Step 2.3: Create backend i18n infrastructure (core/i18n/, locale middleware)
- [x] Step 2.4: Migrate auth pages (Login, ForgotPassword, ResetPassword)
- [x] Step 2.5: Migrate dashboard + navigation (Dashboard, TopBar, SideNav)
- [x] Step 2.6: Migrate settings pages (all 24 settings components)
- [x] Step 2.7: Migrate remaining components (AppNotFound, LicenseWarning)
- [x] Step 2.8: Backend error message infrastructure (JSON keys documented, t() ready, deferred actual migration)
- [x] Verification: tsc -b clean, 318/318 tests pass, all text renders via t() calls

## Notes:
- Backend route handlers NOT yet migrated to call t() — infrastructure is ready but deferred until a second language is added (zero visible change for English-only)
- Locale middleware installed in core/app.ts, `c.get('locale')` available in all routes
- Frontend: 5 namespaces (common, auth, dashboard, settings, errors) with 500+ translation keys
- en-US/common.json is empty (overrides only — identical to en for now)
