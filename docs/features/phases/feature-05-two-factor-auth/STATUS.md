# Feature 5: Two-Factor Authentication (TOTP)

## Status: complete
## Started: 2026-02-10
## Completed: 2026-02-10

## Progress:
- [x] Detailed plan
- [x] TOTP implementation (Web Crypto API)
- [x] Database migration
- [x] Backend endpoints (setup, verify, authenticate, disable)
- [x] Login flow modification
- [x] Profile page 2FA section
- [x] Login page 2FA prompt
- [x] Backup codes
- [x] Verification (tsc -b + vitest run: 45 files, 318 tests pass)

## Notes:
- RFC 6238 TOTP with HMAC-SHA1, 6-digit codes, 30s window, ±1 step tolerance
- All crypto via Web Crypto API (cross-runtime: Workers, Node, Bun)
- TOTP secrets encrypted at rest with AES-GCM (HKDF key from JWT_SECRET)
- Challenge tokens: stateless 5-min JWTs (no extra DB table)
- 10 backup codes per user (SHA-256 hashed, one-time use)
- Client-side QR code rendering via `qrcode` npm package
- Disable 2FA requires password confirmation
