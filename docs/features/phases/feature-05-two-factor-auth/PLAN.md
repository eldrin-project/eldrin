# Feature 5: Two-Factor Authentication (TOTP)

## Overview

Users can enable TOTP-based 2FA from their Profile page. Login becomes a two-step flow: email/password first, then TOTP code. Backup codes for recovery. Implements RFC 6238 using Web Crypto API (no external dependencies).

## Dependencies

- Feature 3 (User Profile) — 2FA setup UI lives in Profile page

## Key Pieces

### Database
- New `user_totp_secrets` table: id, user_id, encrypted_secret, is_enabled, backup_codes (JSON, hashed), created_at

### Backend
- `POST /api/auth/totp/setup` — generate secret + return otpauth:// URI for QR code
- `POST /api/auth/totp/verify` — verify code and enable 2FA
- `POST /api/auth/totp/disable` — disable 2FA (requires password verification)
- `POST /api/auth/totp/authenticate` — verify code during login (with temp token)
- Modify login flow: if user has 2FA, return `{ requires2FA: true, tempToken }` instead of full JWT
- TOTP implementation: HMAC-SHA1, 6-digit codes, 30-second window, +-1 step tolerance

### Frontend
- Profile page: 2FA setup section (QR code display, code verification, backup codes)
- Login page: 2FA code prompt (shown after successful email/password)
- Backup code display and download

## Test Gate

```bash
cd eldrin-core && npx tsc -b && npx vitest run
```

1. Enable 2FA from profile with QR code scan
2. Login requires TOTP code after password
3. Backup codes work as recovery
4. Disable 2FA with password verification
5. Users without 2FA login normally (unchanged)

## Detailed plan will be written when implementation begins.
