# Slice 4c — Outlook/Microsoft Graph Sync + 4b Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Two-way Outlook (Microsoft Graph) calendar sync behind the existing `CalendarProvider` adapter (proving the multi-provider seam) plus 4b's deferred hardening: returnTo origin allowlist, exception-row instance-id persistence, non-UTC all-day tests, and live webhook validation for both providers.

**Architecture:** New `providers/outlook.ts` + `providers/graph-translate.ts` implement the SAME `CalendarProvider` contract Google uses; the sync core and write-through stay untouched except for two provider-neutral generalizations (`cal.provider !== 'local'` gating; a `presentExternalIds` reconciliation field on `ChangeSet` that Graph needs for master-delete detection). Incoming Graph sync = `calendarView/delta` (windowed −6mo/+18mo, full deltaLink stored as the sync token, `@removed` tombstones + master-id sweep); recurrence = deterministic `patternedRecurrence ⇄ RRULE`. OAuth routes become provider-parameterized with shared helpers.

**Tech Stack:** Hono 4, Drizzle + D1, Vitest + better-sqlite3 (Graph stubbed at fetch level), Microsoft identity platform v2.0 + Graph v1.0 over raw `fetch`, React 19 frontend.

**Spec:** `docs/superpowers/specs/2026-07-09-outlook-calendar-sync-design.md` (D16–D20; inherits D8–D15).

## Global Constraints

- **Working directory:** all tasks run in `/Users/tibor/projects/eldrin-backup/eldrin-calendar` on branch `feature/outlook-sync` (created in Task 1 from `main` @ 64bfe74). Bash cwd persists — absolute paths or `git -C`. Parent gitlink bump only at ship time.
- **D9 unchanged:** `provider='local'` behavior byte-identical; 4b's Google paths must also stay green — the existing 173 tests may only change where a task explicitly says so (gating generalization renames in Task 6, endpoint rename in Task 9).
- **Provider value:** `'microsoft'` everywhere (`connected_accounts.provider`, `calendars.provider`); the UI LABEL is "Outlook". Never introduce a third spelling.
- **No new migration** (spec §4): 4b columns absorb Graph values — `calendars.sync_token` stores the FULL `@odata.deltaLink` URL; `watch_channel_id` = Graph subscription id; `watch_resource_id` = literal `'graph-subscription'`; `watch_expires_at` = subscription expiry ms.
- **Graph wire rules (D18):** base `https://graph.microsoft.com/v1.0`; every read sends `Prefer: outlook.timezone="UTC"`; `start`/`end.dateTime` parse as real-UTC ms (append `Z` — Graph returns no offset suffix); row `timezone` from `originalStartTimeZone` (Graph may return Windows-zone names like `Pacific Standard Time` — if `Intl.DateTimeFormat` rejects the name, fall back to `'UTC'` with a console.warn); outbound sends `dateTime` in the event's IANA zone with `timeZone: <iana>`.
- **Recurrence (D17):** mappable subset both directions — pattern types `daily|weekly|absoluteMonthly|relativeMonthly|absoluteYearly|relativeYearly`, `interval`, `daysOfWeek`, `firstDayOfWeek→WKST`, `dayOfMonth`, `index→BYSETPOS (first..fourth=1..4, last=-1)`, `month`; range `endDate→UNTIL | numbered→COUNT | noEnd`. Outbound-unmappable → `ProviderApiError(400)` with message containing `not supported by Outlook`; inbound-unmappable → skip event with console.warn. **UNTIL⇄endDate boundary (4b lesson):** local UNTIL is wall-space; Graph `range.endDate` is an inclusive wall DATE — conversions in Task 3 are exact and test-pinned.
- **MS token rotation:** Microsoft refresh responses include a NEW `refresh_token` that MUST be persisted (unlike Google). `refreshMicrosoftToken` returns it; `freshAccessToken`'s microsoft branch stores both tokens.
- **D19 allowlist:** `returnTo` origin must be one of: the request's own origin, `env.ELDRIN_CORE_URL ?? 'http://localhost:4000'`, `env.PUBLIC_URL` (when set). Applies to BOTH providers' connect + callback validation. Env gains optional `ELDRIN_CORE_URL?: string`.
- **publicRoutes are /api-relative.** New entries exactly: `"/oauth/microsoft/connect"`, `"/oauth/microsoft/callback"`, `"/sync/notify/graph"`.
- **Secrets:** `MICROSOFT_CLIENT_ID`/`MICROSOFT_CLIENT_SECRET` values copied from `/Users/tibor/projects/eldrin-backup/eldrin-email/.dev.vars` into `.dev.vars` (gitignored — verify `git status` before every commit; never echo values into reports/commits).
- **Quality gates per task:** `npx vitest run` green (173 baseline + additions), `npx tsc -b` green, conventional commit. Frontend task adds `npm run build`. Test harness = 4b conventions (createTestDb, `vi.stubGlobal('fetch', …)`, app assembled in-test). If a verbatim test snippet trips a TS-only error (unused import etc.), fix minimally and flag in the report.
- **Files ≤ ~400 lines** — graph-translate and outlook client each stay under; split only if a task says so.

## File Structure

```
eldrin-calendar/
  worker/services/oauth-microsoft.ts          — Task 1 (MS identity v2.0: auth URL, exchange, ROTATING refresh, userinfo)
  worker/routes/oauth.ts                      — Task 2 (provider-parameterized rewrite + D19 allowlist)
  worker/services/providers/graph-translate.ts— Tasks 3–4 (recurrence conversion; event JSON ⇄ TranslatedEvent)
  worker/services/providers/types.ts          — Task 5 (ChangeSet gains presentExternalIds)
  worker/services/providers/outlook.ts        — Task 5 (Graph client implementing CalendarProvider)
  worker/services/accounts.ts                 — Task 6 (provider dispatch + MS refresh rotation)
  worker/services/sync.ts                     — Task 6 (provider-neutral calendar query + presentExternalIds sweep), Task 7 (renewWatches address per provider)
  worker/routes/events.ts                     — Task 6 (gating generalization), Task 8 (exception instance-id persistence)
  worker/routes/sync.ts                       — Task 7 (POST /api/sync/notify/graph), Task 9 (provider-calendars rename)
  public/eldrin-app.manifest.json             — Task 2 (publicRoutes, MICROSOFT settings, :provider connect-token), Task 9 (provider-calendars route)
  worker-configuration.d.ts                   — Task 2 (MICROSOFT_* + ELDRIN_CORE_URL)
  src/api.ts, src/components/SettingsView.tsx, src/components/CalendarSidebar.tsx — Task 9
  worker/__tests__/{oauth-microsoft,graph-recurrence,graph-translate,outlook-provider,accounts-dispatch,graph-notify,hardening}.test.ts + edits to oauth-routes/sync-routes/events-write-route/google-translate tests
```

Task 10 = live validation + D20 ngrok webhook test + ship (main session).

---

### Task 1: Branch + Microsoft OAuth service

**Files:**
- Create: `eldrin-calendar/worker/services/oauth-microsoft.ts`
- Test: `eldrin-calendar/worker/__tests__/oauth-microsoft.test.ts`

**Interfaces:**
- Consumes: nothing internal (pure fetch module). Port source: `/Users/tibor/projects/eldrin-backup/eldrin-email/worker/services/oauth-outlook.ts` — read it first.
- Produces: `getMicrosoftAuthUrl(clientId, redirectUri, state): string`; `exchangeMicrosoftCode(code, clientId, clientSecret, redirectUri): Promise<{accessToken, refreshToken, expiresIn}>`; `refreshMicrosoftToken(refreshToken, clientId, clientSecret): Promise<{accessToken, refreshToken: string | null, expiresIn}>` (**returns the rotated refresh token — null only if MS omits it**); `getMicrosoftUserInfo(accessToken): Promise<{email, name}>`.

- [ ] **Step 1: Create the branch**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar checkout main
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar pull
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar checkout -b feature/outlook-sync
```

- [ ] **Step 2: Write failing tests**

`worker/__tests__/oauth-microsoft.test.ts`:

```typescript
import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  getMicrosoftAuthUrl, exchangeMicrosoftCode, refreshMicrosoftToken, getMicrosoftUserInfo,
} from '../services/oauth-microsoft';

afterEach(() => vi.unstubAllGlobals());

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

describe('getMicrosoftAuthUrl', () => {
  it('builds a consent URL with Calendars.ReadWrite + offline_access and state', () => {
    const url = new URL(getMicrosoftAuthUrl('cid', 'http://localhost:4012/api/oauth/microsoft/callback', 'st4te'));
    expect(url.origin + url.pathname).toBe('https://login.microsoftonline.com/common/oauth2/v2.0/authorize');
    expect(url.searchParams.get('client_id')).toBe('cid');
    expect(url.searchParams.get('scope')).toContain('Calendars.ReadWrite');
    expect(url.searchParams.get('scope')).toContain('offline_access');
    expect(url.searchParams.get('response_mode')).toBe('query');
    expect(url.searchParams.get('prompt')).toBe('consent');
    expect(url.searchParams.get('state')).toBe('st4te');
  });
});

describe('exchangeMicrosoftCode', () => {
  it('POSTs the code and returns tokens', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({ access_token: 'at', refresh_token: 'rt', expires_in: 3600 }));
    vi.stubGlobal('fetch', fetchMock);
    const t = await exchangeMicrosoftCode('c0de', 'cid', 'sec', 'http://cb');
    expect(t).toEqual({ accessToken: 'at', refreshToken: 'rt', expiresIn: 3600 });
    expect(fetchMock.mock.calls[0][0]).toBe('https://login.microsoftonline.com/common/oauth2/v2.0/token');
    expect(String(fetchMock.mock.calls[0][1].body)).toContain('grant_type=authorization_code');
  });

  it('throws when no refresh token is returned', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ access_token: 'at', expires_in: 1 })));
    await expect(exchangeMicrosoftCode('c', 'i', 's', 'r')).rejects.toThrow(/refresh token/i);
  });

  it('throws on non-OK response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('nope', { status: 400 })));
    await expect(exchangeMicrosoftCode('c', 'i', 's', 'r')).rejects.toThrow(/exchange failed/i);
  });
});

describe('refreshMicrosoftToken', () => {
  it('returns the ROTATED refresh token when present', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ access_token: 'new', refresh_token: 'rotated', expires_in: 3599 })));
    expect(await refreshMicrosoftToken('rt', 'i', 's')).toEqual({ accessToken: 'new', refreshToken: 'rotated', expiresIn: 3599 });
  });

  it('returns refreshToken null when MS omits it', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ access_token: 'new', expires_in: 3599 })));
    expect(await refreshMicrosoftToken('rt', 'i', 's')).toEqual({ accessToken: 'new', refreshToken: null, expiresIn: 3599 });
  });
});

describe('getMicrosoftUserInfo', () => {
  it('prefers mail, falls back to userPrincipalName', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ mail: null, userPrincipalName: 'u@x.y', displayName: 'U' })));
    expect(await getMicrosoftUserInfo('tok')).toEqual({ email: 'u@x.y', name: 'U' });
  });
});
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-calendar && npx vitest run worker/__tests__/oauth-microsoft.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 4: Implement oauth-microsoft.ts**

Port `/Users/tibor/projects/eldrin-backup/eldrin-email/worker/services/oauth-outlook.ts` with these deltas (bodies otherwise identical):
- Header comment: Microsoft OAuth for Calendar sync (Slice 4c).
- `const CALENDAR_SCOPES = ['Calendars.ReadWrite', 'offline_access', 'User.Read'].join(' ');` replaces `OUTLOOK_SCOPES` (drop the Mail.* scopes) — use it in all three token calls.
- Renames: `getOutlookAuthUrl`→`getMicrosoftAuthUrl`, `exchangeOutlookCode`→`exchangeMicrosoftCode`, `refreshOutlookToken`→`refreshMicrosoftToken`; error prefixes become `Microsoft token exchange failed` / `Microsoft token refresh failed`.
- **`refreshMicrosoftToken` change (NOT in the port source — MS rotates refresh tokens):** parse `refresh_token?: string` from the response and return `{ accessToken, refreshToken: data.refresh_token ?? null, expiresIn }`.
- `getMicrosoftUserInfo` kept as-is (mail ?? userPrincipalName fallback).

- [ ] **Step 5: Run tests + full suite + typecheck**

Run: `npx vitest run && npx tsc -b`
Expected: 173 baseline + 7 new PASS, tsc clean.

- [ ] **Step 6: Commit**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar commit -m "feat: Microsoft OAuth service with Calendar scopes + rotating refresh (Slice 4c Task 1)"
```

---

### Task 2: Provider-parameterized OAuth routes + D19 allowlist + manifest/Env plumbing

**Files:**
- Modify: `eldrin-calendar/worker/routes/oauth.ts` (full rewrite, shown below)
- Modify: `eldrin-calendar/worker/__tests__/oauth-routes.test.ts` (path updates + new tests)
- Modify: `eldrin-calendar/public/eldrin-app.manifest.json`
- Modify: `eldrin-calendar/worker-configuration.d.ts`
- Modify: `eldrin-calendar/.dev.vars` (append MS creds — NOT committed)
- Modify: `eldrin-calendar/src/api.ts` + `src/components/SettingsView.tsx` (connect-token path only — one-line each, keeps the app working; full MS UI arrives in Task 9)

**Interfaces:**
- Consumes: Task 1 exports; `worker/services/oauth-google.ts` (unchanged); crypto; `requestUserIdOrNull`.
- Produces: routes `POST /api/oauth/:provider/connect-token`, `GET /api/oauth/:provider/connect`, `GET /api/oauth/:provider/callback` for `provider ∈ {google, microsoft}`; exported `isSafeReturnTo(value: string, c: {req: {url: string}}, env: Env): boolean` (D19 — Task 9's tests may reuse it); state payload gains `provider`.

- [ ] **Step 1: Update + extend the route tests**

In `worker/__tests__/oauth-routes.test.ts`: replace every literal `/api/oauth/google/` path with the same path (unchanged — google remains valid); update `mockEnv` to add `MICROSOFT_CLIENT_ID: 'mcid', MICROSOFT_CLIENT_SECRET: 'mcsec', ELDRIN_CORE_URL: 'http://localhost:4000'`. The existing tests must keep passing EXCEPT: tests that used `returnTo=http://x` or other arbitrary origins must switch to `http://localhost:4000/eldrin-calendar/settings` (now allowlisted). Then append:

```typescript
describe('D19 returnTo origin allowlist', () => {
  it('rejects an allowlisted-protocol but foreign-origin returnTo', async () => {
    const app = createApp(createTestDb());
    const token = await mintConnectToken(app);
    const res = await app.request(
      `/api/oauth/google/connect?token=${encodeURIComponent(token)}&returnTo=${encodeURIComponent('https://evil.example.com/phish')}`,
      {}, mockEnv,
    );
    expect(res.status).toBe(400);
  });

  it('accepts the request own origin and the core URL origin', async () => {
    const app = createApp(createTestDb());
    for (const rt of ['http://localhost:4000/eldrin-calendar/settings', 'http://localhost:4012/settings']) {
      const token = await mintConnectToken(app);
      const res = await app.request(
        `/api/oauth/google/connect?token=${encodeURIComponent(token)}&returnTo=${encodeURIComponent(rt)}`,
        {}, mockEnv,
      );
      expect(res.status).toBe(302); // own origin (4012 via app.request base) and core URL both pass
    }
  });

  it('rejects a forged callback state whose returnTo origin is not allowlisted', async () => {
    const app = createApp(createTestDb());
    const state = await encryptToken(JSON.stringify({
      provider: 'google', userId: 'u1', returnTo: 'https://evil.example.com/x', ts: Date.now(),
    }), 'test-secret');
    const res = await app.request(`/api/oauth/google/callback?code=c&state=${encodeURIComponent(state)}`, {}, mockEnv);
    expect(res.status).toBe(400);
  });
});

describe('microsoft provider flow', () => {
  const msState = () => encryptToken(JSON.stringify({
    provider: 'microsoft', userId: 'u1', returnTo: 'http://localhost:4000/eldrin-calendar/settings', ts: Date.now(),
  }), 'test-secret');

  it('connect redirects to login.microsoftonline.com', async () => {
    const app = createApp(createTestDb());
    const tokenRes = await app.request('/api/oauth/microsoft/connect-token', {
      method: 'POST', headers: { 'x-eldrin-user-id': 'u1' },
    }, mockEnv);
    const { token } = await tokenRes.json() as { token: string };
    const res = await app.request(
      `/api/oauth/microsoft/connect?token=${encodeURIComponent(token)}&returnTo=${encodeURIComponent('http://localhost:4000/eldrin-calendar/settings')}`,
      {}, mockEnv,
    );
    expect(res.status).toBe(302);
    expect(new URL(res.headers.get('Location')!).host).toBe('login.microsoftonline.com');
  });

  it('callback exchanges, stores a microsoft account encrypted, redirects with connected=microsoft', async () => {
    const db = createTestDb();
    const app = createApp(db);
    vi.stubGlobal('fetch', vi.fn()
      .mockResolvedValueOnce(json({ access_token: 'at', refresh_token: 'rt', expires_in: 3600 }))
      .mockResolvedValueOnce(json({ mail: 'me@outlook.com', userPrincipalName: 'me@outlook.com', displayName: 'Me' })));
    const res = await app.request(`/api/oauth/microsoft/callback?code=c0de&state=${encodeURIComponent(await msState())}`, {}, mockEnv);
    expect(res.status).toBe(302);
    expect(res.headers.get('Location')).toContain('connected=microsoft');
    const [acc] = await db.select().from(connectedAccounts);
    expect(acc.provider).toBe('microsoft');
    expect(acc.email).toBe('me@outlook.com');
    expect(await decryptToken(acc.refreshTokenEnc, 'test-secret')).toBe('rt');
  });

  it('a google-flavored state cannot drive the microsoft callback (provider pinned in state)', async () => {
    const app = createApp(createTestDb());
    const googleState = await encryptToken(JSON.stringify({
      provider: 'google', userId: 'u1', returnTo: 'http://localhost:4000/eldrin-calendar/settings', ts: Date.now(),
    }), 'test-secret');
    const res = await app.request(`/api/oauth/microsoft/callback?code=c&state=${encodeURIComponent(googleState)}`, {}, mockEnv);
    expect(res.status).toBe(400);
  });

  it('unknown provider segment → 404', async () => {
    const app = createApp(createTestDb());
    const res = await app.request('/api/oauth/caldav/connect-token', { method: 'POST', headers: { 'x-eldrin-user-id': 'u1' } }, mockEnv);
    expect(res.status).toBe(404);
  });
});
```

- [ ] **Step 2: Run tests to verify the new ones fail**

Run: `npx vitest run worker/__tests__/oauth-routes.test.ts`
Expected: new describes FAIL (routes/allowlist missing); pre-existing google tests may fail on returnTo updates until Step 3.

- [ ] **Step 3: Rewrite routes/oauth.ts (provider-parameterized)**

Full new content of `worker/routes/oauth.ts`:

```typescript
/**
 * Provider-parameterized OAuth connect flow (spec 4c §5, D19). Top-level
 * navigations can't carry auth headers, so the SPA first mints a short-lived
 * encrypted connect token (authed POST), then navigates to the public connect
 * route. State is AES-GCM-encrypted and pins {provider, userId, returnTo, ts}.
 */
import { Hono } from 'hono';
import { and, eq } from 'drizzle-orm';
import type { Database } from '../db';
import { connectedAccounts } from '../db';
import { generateId, now } from '../utils';
import { decryptToken, encryptToken } from '../services/crypto';
import { exchangeGoogleCode, getGoogleAuthUrl, getGoogleUserInfo } from '../services/oauth-google';
import { exchangeMicrosoftCode, getMicrosoftAuthUrl, getMicrosoftUserInfo } from '../services/oauth-microsoft';
import { requestUserIdOrNull } from './calendars';

type Variables = { db: Database; auth?: { userId?: string } };

export const oauthRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

const CONNECT_TOKEN_TTL_MS = 5 * 60 * 1000;
const STATE_TTL_MS = 10 * 60 * 1000;

interface ProviderConfig {
  authUrl: (clientId: string, redirectUri: string, state: string) => string;
  exchange: (code: string, clientId: string, clientSecret: string, redirectUri: string) =>
    Promise<{ accessToken: string; refreshToken: string; expiresIn: number }>;
  userInfo: (accessToken: string) => Promise<{ email: string; name: string }>;
  clientId: (env: Env) => string;
  clientSecret: (env: Env) => string;
}

const PROVIDERS: Record<string, ProviderConfig> = {
  google: {
    authUrl: getGoogleAuthUrl,
    exchange: exchangeGoogleCode,
    userInfo: getGoogleUserInfo,
    clientId: (env) => env.GOOGLE_CLIENT_ID,
    clientSecret: (env) => env.GOOGLE_CLIENT_SECRET,
  },
  microsoft: {
    authUrl: getMicrosoftAuthUrl,
    exchange: exchangeMicrosoftCode,
    userInfo: getMicrosoftUserInfo,
    clientId: (env) => env.MICROSOFT_CLIENT_ID,
    clientSecret: (env) => env.MICROSOFT_CLIENT_SECRET,
  },
};

function providerConfig(name: string | undefined): ProviderConfig | null {
  return name && Object.prototype.hasOwnProperty.call(PROVIDERS, name) ? PROVIDERS[name] : null;
}

/** D19: returnTo must be http(s) AND its origin allowlisted (own origin, core URL, PUBLIC_URL). */
export function isSafeReturnTo(value: string, requestUrl: string, env: Env): boolean {
  let target: URL;
  try {
    target = new URL(value);
  } catch {
    return false;
  }
  if (target.protocol !== 'http:' && target.protocol !== 'https:') return false;
  const allowed = new Set<string>();
  try { allowed.add(new URL(requestUrl).origin); } catch { /* ignore */ }
  try { allowed.add(new URL(env.ELDRIN_CORE_URL ?? 'http://localhost:4000').origin); } catch { /* ignore */ }
  if (env.PUBLIC_URL) { try { allowed.add(new URL(env.PUBLIC_URL).origin); } catch { /* ignore */ } }
  return allowed.has(target.origin);
}

function redirectBack(c: { redirect: (url: string) => Response }, returnTo: string, params: Record<string, string>) {
  const url = new URL(returnTo);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  return c.redirect(url.toString());
}

oauthRoutes.post('/api/oauth/:provider/connect-token', async (c) => {
  if (!providerConfig(c.req.param('provider'))) return c.json({ error: 'Unknown provider' }, 404);
  const userId = requestUserIdOrNull(c);
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);
  const payload = JSON.stringify({ userId, expiresAt: now() + CONNECT_TOKEN_TTL_MS });
  return c.json({ token: await encryptToken(payload, c.env.JWT_SECRET) });
});

oauthRoutes.get('/api/oauth/:provider/connect', async (c) => {
  const provider = c.req.param('provider');
  const cfg = providerConfig(provider);
  if (!cfg) return c.json({ error: 'Unknown provider' }, 404);

  const token = c.req.query('token');
  const returnTo = c.req.query('returnTo');
  if (!token || !returnTo) return c.json({ error: 'token and returnTo are required' }, 400);
  if (!isSafeReturnTo(returnTo, c.req.url, c.env)) {
    return c.json({ error: 'returnTo origin is not allowed' }, 400);
  }

  let userId: string;
  try {
    const payload = JSON.parse(await decryptToken(token, c.env.JWT_SECRET)) as { userId: string; expiresAt: number };
    if (payload.expiresAt < now()) return c.json({ error: 'Connect token expired' }, 401);
    userId = payload.userId;
  } catch {
    return c.json({ error: 'Invalid connect token' }, 401);
  }

  const redirectUri = new URL(`/api/oauth/${provider}/callback`, c.req.url).toString();
  const state = await encryptToken(JSON.stringify({ provider, userId, returnTo, ts: now() }), c.env.JWT_SECRET);
  return c.redirect(cfg.authUrl(cfg.clientId(c.env), redirectUri, state));
});

oauthRoutes.get('/api/oauth/:provider/callback', async (c) => {
  const provider = c.req.param('provider');
  const cfg = providerConfig(provider);
  if (!cfg) return c.json({ error: 'Unknown provider' }, 404);

  const stateRaw = c.req.query('state');
  let state: { provider: string; userId: string; returnTo: string; ts: number };
  try {
    state = JSON.parse(await decryptToken(stateRaw ?? '', c.env.JWT_SECRET));
    if (
      state.provider !== provider ||
      !state.userId ||
      !isSafeReturnTo(state.returnTo, c.req.url, c.env)
    ) throw new Error('bad state');
  } catch {
    return c.json({ error: 'Invalid state parameter' }, 400);
  }
  if (now() - state.ts > STATE_TTL_MS) {
    return redirectBack(c, state.returnTo, { connect_error: 'state_expired' });
  }

  const oauthError = c.req.query('error');
  if (oauthError) return redirectBack(c, state.returnTo, { connect_error: oauthError });

  const code = c.req.query('code');
  if (!code) return c.json({ error: 'Missing code parameter' }, 400);

  const redirectUri = new URL(`/api/oauth/${provider}/callback`, c.req.url);
  redirectUri.search = '';

  try {
    const tokens = await cfg.exchange(code, cfg.clientId(c.env), cfg.clientSecret(c.env), redirectUri.toString());
    const userInfo = await cfg.userInfo(tokens.accessToken);
    const [accessTokenEnc, refreshTokenEnc] = await Promise.all([
      encryptToken(tokens.accessToken, c.env.JWT_SECRET),
      encryptToken(tokens.refreshToken, c.env.JWT_SECRET),
    ]);
    const db = c.get('db');
    const ts = now();
    const [existing] = await db.select().from(connectedAccounts).where(and(
      eq(connectedAccounts.userId, state.userId),
      eq(connectedAccounts.provider, provider),
      eq(connectedAccounts.email, userInfo.email),
    ));
    if (existing) {
      await db.update(connectedAccounts).set({
        accessTokenEnc, refreshTokenEnc,
        tokenExpiresAt: ts + tokens.expiresIn * 1000,
        status: 'active', lastError: null, updatedAt: ts,
      }).where(eq(connectedAccounts.id, existing.id));
    } else {
      await db.insert(connectedAccounts).values({
        id: generateId(), userId: state.userId, provider, email: userInfo.email,
        accessTokenEnc, refreshTokenEnc, tokenExpiresAt: ts + tokens.expiresIn * 1000,
        status: 'active', createdAt: ts, updatedAt: ts,
      });
    }
    return redirectBack(c, state.returnTo, { connected: provider });
  } catch (err) {
    console.error(`[calendar] ${provider} OAuth callback error:`, err);
    return redirectBack(c, state.returnTo, { connect_error: 'exchange_failed' });
  }
});
```

- [ ] **Step 4: Manifest, Env, .dev.vars, frontend path**

Manifest `public/eldrin-app.manifest.json`:
- `api.publicRoutes` becomes: `["/health", "/oauth/google/connect", "/oauth/google/callback", "/oauth/microsoft/connect", "/oauth/microsoft/callback", "/sync/notify/google", "/sync/notify/graph"]` (graph notify pre-registered; route lands in Task 7).
- In `api.routes`, replace `{ "method": "POST", "path": "/api/oauth/google/connect-token", ... }` with `{ "method": "POST", "path": "/api/oauth/:provider/connect-token", "permission": "calendar:update" }`.
- `settings.groups` += (after the GOOGLE block):

```json
{
  "key": "MICROSOFT",
  "label": "Microsoft OAuth",
  "description": "OAuth 2.0 credentials for Outlook calendar sync",
  "fields": [
    { "key": "CLIENT_ID", "label": "Client ID", "type": "string", "storage": "config", "required": true, "description": "Microsoft Entra application (client) ID", "placeholder": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" },
    { "key": "CLIENT_SECRET", "label": "Client Secret", "type": "string", "storage": "secret", "required": true, "description": "Microsoft Entra client secret value" }
  ]
}
```

`worker-configuration.d.ts` — append inside `interface Env`:

```typescript
  /** Microsoft Entra OAuth client (Calendar scopes) — same app as eldrin-email */
  MICROSOFT_CLIENT_ID: string;
  MICROSOFT_CLIENT_SECRET: string;
  /** Shell origin for the returnTo allowlist (D19); defaults to http://localhost:4000 */
  ELDRIN_CORE_URL?: string;
```

`.dev.vars` — append `MICROSOFT_CLIENT_ID=` / `MICROSOFT_CLIENT_SECRET=` with values read from `/Users/tibor/projects/eldrin-backup/eldrin-email/.dev.vars`. Verify `git status` does NOT list `.dev.vars`.

Frontend path fix (keeps the app working — full MS UI is Task 9): in `src/api.ts` change `getConnectToken` to take a provider:

```typescript
export const getConnectToken = (base: string, h: Headers, provider: 'google' | 'microsoft') =>
  request<{ token: string }>(apiUrl(base, `/oauth/${provider}/connect-token`), h, { method: 'POST' });
```

and in `src/components/SettingsView.tsx` update its one call site to `api.getConnectToken(apiBase, headersRef.current, 'google')` (the connect redirect URL already contains `/oauth/google/connect` — leave it).

- [ ] **Step 5: Run all tests + typecheck + build, then commit**

Run: `npx vitest run && npx tsc -b && npm run build`
Expected: all PASS (updated oauth-routes suite + 173-baseline others). Confirm `.dev.vars` untracked.

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar commit -m "feat: provider-parameterized OAuth routes + returnTo origin allowlist (Slice 4c Task 2)"
```

---

### Task 3: Graph recurrence conversion (patternedRecurrence ⇄ RRULE)

The 4c analogue of 4b's highest-risk logic — pure functions, exhaustive tests FIRST, no route wiring.

**Files:**
- Create: `eldrin-calendar/worker/services/providers/graph-translate.ts` (recurrence section; Task 4 appends event translation to the SAME file)
- Test: `eldrin-calendar/worker/__tests__/graph-recurrence.test.ts`

**Interfaces:**
- Consumes: `wallMsInZone`/`zonedWallToUtcMs` NOT needed here — all recurrence math happens in wall space (local RRULEs are wall-space; Graph's `range.endDate`/`startDate` are wall dates). Uses `RRule` from `rrule` (already a dependency) for parsing/serializing.
- Produces:
  - `interface GraphRecurrence { pattern: { type: string; interval: number; daysOfWeek?: string[]; firstDayOfWeek?: string; dayOfMonth?: number; index?: string; month?: number }; range: { type: string; startDate: string; endDate?: string; numberOfOccurrences?: number; recurrenceTimeZone?: string } }`
  - `patternToRrule(rec: GraphRecurrence): string | null` — bare wall-space RRULE; null = unmappable (console.warn).
  - `rruleToPattern(rrule: string, startWallMs: number, timezone: string): GraphRecurrence | null` — null = unsupported (caller raises ProviderApiError 400). `startWallMs` = the series start as fake-UTC wall ms (`wallMsInZone(row.startAt, row.timezone)` — computed by the CALLER in Task 4/5; this module stays zone-free). `range.startDate` = wall date of `startWallMs`; `recurrenceTimeZone` = the passed IANA `timezone`.

- [ ] **Step 1: Write failing tests**

`worker/__tests__/graph-recurrence.test.ts`:

```typescript
import { describe, it, expect, vi, afterEach } from 'vitest';
import { patternToRrule, rruleToPattern, type GraphRecurrence } from '../services/providers/graph-translate';

afterEach(() => vi.restoreAllMocks());

// Series starts Fri 2026-07-10 09:00 wall time (fake-UTC wall ms).
const START_WALL = Date.UTC(2026, 6, 10, 9, 0, 0);
const TZ = 'Europe/Bucharest';

function rec(pattern: GraphRecurrence['pattern'], range: Partial<GraphRecurrence['range']> = {}): GraphRecurrence {
  return { pattern, range: { type: 'noEnd', startDate: '2026-07-10', recurrenceTimeZone: TZ, ...range } };
}

describe('patternToRrule (Graph → wall-space RRULE)', () => {
  it('daily / interval', () => {
    expect(patternToRrule(rec({ type: 'daily', interval: 2 }))).toBe('FREQ=DAILY;INTERVAL=2');
  });

  it('weekly with daysOfWeek and firstDayOfWeek', () => {
    expect(patternToRrule(rec({ type: 'weekly', interval: 1, daysOfWeek: ['monday', 'friday'], firstDayOfWeek: 'monday' })))
      .toBe('FREQ=WEEKLY;BYDAY=MO,FR;WKST=MO');
  });

  it('absoluteMonthly → BYMONTHDAY', () => {
    expect(patternToRrule(rec({ type: 'absoluteMonthly', interval: 1, dayOfMonth: 15 })))
      .toBe('FREQ=MONTHLY;BYMONTHDAY=15');
  });

  it('relativeMonthly → BYDAY+BYSETPOS (index last → -1)', () => {
    expect(patternToRrule(rec({ type: 'relativeMonthly', interval: 1, daysOfWeek: ['thursday'], index: 'last' })))
      .toBe('FREQ=MONTHLY;BYDAY=TH;BYSETPOS=-1');
  });

  it('absoluteYearly → BYMONTH+BYMONTHDAY', () => {
    expect(patternToRrule(rec({ type: 'absoluteYearly', interval: 1, dayOfMonth: 24, month: 12 })))
      .toBe('FREQ=YEARLY;BYMONTH=12;BYMONTHDAY=24');
  });

  it('relativeYearly → BYMONTH+BYDAY+BYSETPOS', () => {
    expect(patternToRrule(rec({ type: 'relativeYearly', interval: 1, daysOfWeek: ['sunday'], index: 'second', month: 5 })))
      .toBe('FREQ=YEARLY;BYMONTH=5;BYDAY=SU;BYSETPOS=2');
  });

  it('range numbered → COUNT', () => {
    expect(patternToRrule(rec({ type: 'daily', interval: 1 }, { type: 'numbered', numberOfOccurrences: 5 })))
      .toBe('FREQ=DAILY;COUNT=5');
  });

  it('range endDate → wall-space UNTIL at end of that wall day (inclusive)', () => {
    expect(patternToRrule(rec({ type: 'weekly', interval: 1, daysOfWeek: ['friday'] }, { type: 'endDate', endDate: '2026-07-31' })))
      .toBe('FREQ=WEEKLY;BYDAY=FR;UNTIL=20260731T235959Z');
  });

  it('unknown pattern type → null with warning', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect(patternToRrule(rec({ type: 'lunarMonthly', interval: 1 } as never))).toBeNull();
    expect(warn).toHaveBeenCalled();
  });
});

describe('rruleToPattern (wall-space RRULE → Graph)', () => {
  it('weekly BYDAY', () => {
    const r = rruleToPattern('FREQ=WEEKLY;BYDAY=FR', START_WALL, TZ)!;
    expect(r.pattern).toEqual({ type: 'weekly', interval: 1, daysOfWeek: ['friday'], firstDayOfWeek: 'sunday' });
    expect(r.range).toEqual({ type: 'noEnd', startDate: '2026-07-10', recurrenceTimeZone: TZ });
  });

  it('COUNT → numbered', () => {
    const r = rruleToPattern('FREQ=DAILY;COUNT=7', START_WALL, TZ)!;
    expect(r.range).toEqual({ type: 'numbered', startDate: '2026-07-10', numberOfOccurrences: 7, recurrenceTimeZone: TZ });
  });

  it('UNTIL after the daily start time → endDate is the UNTIL wall date (occurrence that day included)', () => {
    // until 2026-07-31T23:59:59 wall ≥ 09:00 start-of-day time → Jul 31 occurrence included → endDate Jul 31
    const r = rruleToPattern('FREQ=WEEKLY;BYDAY=FR;UNTIL=20260731T235959Z', START_WALL, TZ)!;
    expect(r.range).toEqual({ type: 'endDate', startDate: '2026-07-10', endDate: '2026-07-31', recurrenceTimeZone: TZ });
  });

  it('UNTIL before the daily start time → endDate is the PREVIOUS wall date (4b truncation shape)', () => {
    // headRuleUntil produces UNTIL = cut-occurrence-start − 1s = 2026-07-31T08:59:59 wall.
    // 08:59:59 < 09:00 start time → the Jul 31 occurrence is EXCLUDED → Graph endDate must be Jul 30.
    const r = rruleToPattern('FREQ=WEEKLY;BYDAY=FR;UNTIL=20260731T085959Z', START_WALL, TZ)!;
    expect(r.range).toEqual({ type: 'endDate', startDate: '2026-07-10', endDate: '2026-07-30', recurrenceTimeZone: TZ });
  });

  it('monthly BYMONTHDAY → absoluteMonthly', () => {
    const r = rruleToPattern('FREQ=MONTHLY;BYMONTHDAY=10', START_WALL, TZ)!;
    expect(r.pattern).toEqual({ type: 'absoluteMonthly', interval: 1, dayOfMonth: 10 });
  });

  it('monthly BYDAY+BYSETPOS → relativeMonthly', () => {
    const r = rruleToPattern('FREQ=MONTHLY;BYDAY=TH;BYSETPOS=-1', START_WALL, TZ)!;
    expect(r.pattern).toEqual({ type: 'relativeMonthly', interval: 1, daysOfWeek: ['thursday'], index: 'last', firstDayOfWeek: 'sunday' });
  });

  it('yearly BYMONTH+BYMONTHDAY → absoluteYearly', () => {
    const r = rruleToPattern('FREQ=YEARLY;BYMONTH=12;BYMONTHDAY=24', START_WALL, TZ)!;
    expect(r.pattern).toEqual({ type: 'absoluteYearly', interval: 1, dayOfMonth: 24, month: 12 });
  });

  it('unsupported RRULE (BYSETPOS without BYDAY-month context, HOURLY, multi-BYSETPOS) → null', () => {
    expect(rruleToPattern('FREQ=HOURLY;INTERVAL=2', START_WALL, TZ)).toBeNull();
    expect(rruleToPattern('FREQ=WEEKLY;BYDAY=MO;BYSETPOS=2', START_WALL, TZ)).toBeNull();
  });

  it('round-trips the 4a UI presets', () => {
    for (const rule of ['FREQ=DAILY', 'FREQ=WEEKLY;BYDAY=FR', 'FREQ=MONTHLY;BYMONTHDAY=10']) {
      const pattern = rruleToPattern(rule, START_WALL, TZ)!;
      const back = patternToRrule(pattern)!;
      // normalize: parse both and compare option-wise via RRule
      expect(back.split(';').sort()).toEqual(expect.arrayContaining(rule.split(';')));
    }
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run worker/__tests__/graph-recurrence.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement the recurrence section of graph-translate.ts**

Create `worker/services/providers/graph-translate.ts`:

```typescript
/**
 * Microsoft Graph ⇄ provider-neutral translation (Slice 4c, D17/D18).
 * Recurrence section: patternedRecurrence ⇄ wall-space RRULE. All math is in
 * wall space — Graph range dates are wall dates in recurrenceTimeZone, and
 * local RRULEs are 4a's fake-UTC wall convention. Pure functions, no fetch.
 */
import { RRule, type Options } from 'rrule';

export interface GraphRecurrence {
  pattern: {
    type: string;
    interval: number;
    daysOfWeek?: string[];
    firstDayOfWeek?: string;
    dayOfMonth?: number;
    index?: string;
    month?: number;
  };
  range: {
    type: string;
    startDate: string;
    endDate?: string;
    numberOfOccurrences?: number;
    recurrenceTimeZone?: string;
  };
}

const DAY_MS = 86400000;
const GRAPH_DAYS = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
const RRULE_DAYS = ['SU', 'MO', 'TU', 'WE', 'TH', 'FR', 'SA'];
const GRAPH_INDEX: Record<string, number> = { first: 1, second: 2, third: 3, fourth: 4, last: -1 };
const INDEX_NAMES: Record<number, string> = { 1: 'first', 2: 'second', 3: 'third', 4: 'fourth', [-1]: 'last' };

function graphDayToRrule(day: string): string | null {
  const i = GRAPH_DAYS.indexOf(day.toLowerCase());
  return i >= 0 ? RRULE_DAYS[i] : null;
}

function rruleDayToGraph(byweekdayNum: number): string {
  // rrule weekday numbers: MO=0..SU=6
  return GRAPH_DAYS[(byweekdayNum + 1) % 7];
}

function wallDate(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

/** Graph patternedRecurrence → bare wall-space RRULE. Null = unmappable (skip inbound). */
export function patternToRrule(rec: GraphRecurrence): string | null {
  const p = rec.pattern;
  const parts: string[] = [];
  const days = (p.daysOfWeek ?? []).map(graphDayToRrule);
  if (days.some((d) => d === null)) {
    console.warn(`[calendar] unmappable Graph daysOfWeek: ${JSON.stringify(p.daysOfWeek)}`);
    return null;
  }
  switch (p.type) {
    case 'daily':
      parts.push('FREQ=DAILY');
      break;
    case 'weekly':
      parts.push('FREQ=WEEKLY');
      if (days.length > 0) parts.push(`BYDAY=${days.join(',')}`);
      break;
    case 'absoluteMonthly':
      parts.push('FREQ=MONTHLY', `BYMONTHDAY=${p.dayOfMonth}`);
      break;
    case 'relativeMonthly': {
      const pos = GRAPH_INDEX[p.index ?? 'first'];
      parts.push('FREQ=MONTHLY', `BYDAY=${days.join(',')}`, `BYSETPOS=${pos}`);
      break;
    }
    case 'absoluteYearly':
      parts.push('FREQ=YEARLY', `BYMONTH=${p.month}`, `BYMONTHDAY=${p.dayOfMonth}`);
      break;
    case 'relativeYearly': {
      const pos = GRAPH_INDEX[p.index ?? 'first'];
      parts.push('FREQ=YEARLY', `BYMONTH=${p.month}`, `BYDAY=${days.join(',')}`, `BYSETPOS=${pos}`);
      break;
    }
    default:
      console.warn(`[calendar] unmappable Graph recurrence pattern type: ${p.type}`);
      return null;
  }
  if (p.interval && p.interval !== 1) parts.splice(1, 0, `INTERVAL=${p.interval}`);
  if (p.type === 'weekly' && p.firstDayOfWeek && p.firstDayOfWeek.toLowerCase() !== 'sunday') {
    const wkst = graphDayToRrule(p.firstDayOfWeek);
    if (wkst) parts.push(`WKST=${wkst}`);
  }
  if (rec.range.type === 'numbered' && rec.range.numberOfOccurrences) {
    parts.push(`COUNT=${rec.range.numberOfOccurrences}`);
  } else if (rec.range.type === 'endDate' && rec.range.endDate) {
    // Graph endDate is an INCLUSIVE wall date → UNTIL end-of-that-wall-day.
    const basic = rec.range.endDate.replace(/-/g, '');
    parts.push(`UNTIL=${basic}T235959Z`);
  }
  return parts.join(';');
}

/**
 * Bare wall-space RRULE → Graph patternedRecurrence.
 * Null = unsupported (caller surfaces "not supported by Outlook", D17).
 * startWallMs = series start as fake-UTC wall ms; range.startDate/endDate are wall dates.
 */
export function rruleToPattern(rrule: string, startWallMs: number, timezone: string): GraphRecurrence | null {
  let o: Partial<Options>;
  try {
    o = RRule.parseString(rrule);
  } catch {
    return null;
  }
  const interval = o.interval ?? 1;
  const byday = o.byweekday == null ? [] : (Array.isArray(o.byweekday) ? o.byweekday : [o.byweekday]);
  // Normalize rrule weekdays (Weekday objects or numbers) to plain numbers MO=0..SU=6.
  const dayNums = byday.map((d) => (typeof d === 'number' ? d : (d as { weekday: number }).weekday));
  const bysetpos = o.bysetpos == null ? [] : (Array.isArray(o.bysetpos) ? o.bysetpos : [o.bysetpos]);
  const bymonthday = o.bymonthday == null ? [] : (Array.isArray(o.bymonthday) ? o.bymonthday : [o.bymonthday]);
  const bymonth = o.bymonth == null ? [] : (Array.isArray(o.bymonth) ? o.bymonth : [o.bymonth]);

  let pattern: GraphRecurrence['pattern'] | null = null;
  switch (o.freq) {
    case RRule.DAILY:
      if (dayNums.length || bysetpos.length || bymonthday.length) return null;
      pattern = { type: 'daily', interval };
      break;
    case RRule.WEEKLY:
      if (bysetpos.length || bymonthday.length) return null;
      pattern = {
        type: 'weekly', interval,
        daysOfWeek: (dayNums.length ? dayNums : [new Date(startWallMs).getUTCDay() === 0 ? 6 : new Date(startWallMs).getUTCDay() - 1]).map(rruleDayToGraph),
        firstDayOfWeek: o.wkst != null ? rruleDayToGraph(typeof o.wkst === 'number' ? o.wkst : (o.wkst as { weekday: number }).weekday) : 'sunday',
      };
      break;
    case RRule.MONTHLY:
      if (bymonthday.length === 1 && !dayNums.length && !bysetpos.length) {
        pattern = { type: 'absoluteMonthly', interval, dayOfMonth: bymonthday[0] };
      } else if (dayNums.length >= 1 && bysetpos.length === 1 && INDEX_NAMES[bysetpos[0]]) {
        pattern = { type: 'relativeMonthly', interval, daysOfWeek: dayNums.map(rruleDayToGraph), index: INDEX_NAMES[bysetpos[0]], firstDayOfWeek: 'sunday' };
      } else return null;
      break;
    case RRule.YEARLY:
      if (bymonth.length !== 1) return null;
      if (bymonthday.length === 1 && !dayNums.length) {
        pattern = { type: 'absoluteYearly', interval, dayOfMonth: bymonthday[0], month: bymonth[0] };
      } else if (dayNums.length >= 1 && bysetpos.length === 1 && INDEX_NAMES[bysetpos[0]]) {
        pattern = { type: 'relativeYearly', interval, daysOfWeek: dayNums.map(rruleDayToGraph), index: INDEX_NAMES[bysetpos[0]], month: bymonth[0], firstDayOfWeek: 'sunday' };
      } else return null;
      break;
    default:
      return null; // HOURLY etc.
  }

  const range: GraphRecurrence['range'] = {
    type: 'noEnd',
    startDate: wallDate(startWallMs),
    recurrenceTimeZone: timezone,
  };
  if (o.count) {
    range.type = 'numbered';
    range.numberOfOccurrences = o.count;
  } else if (o.until) {
    // o.until is the wall-space UNTIL (fake UTC). Graph's endDate is an INCLUSIVE
    // wall date: an occurrence on day D at the series' start time is included by
    // UNTIL iff untilTimeOfDay ≥ startTimeOfDay; otherwise the last included day
    // is the previous one (4b headRuleUntil produces exactly this shape).
    const untilMs = o.until.getTime();
    const startTimeOfDay = ((startWallMs % DAY_MS) + DAY_MS) % DAY_MS;
    const untilTimeOfDay = ((untilMs % DAY_MS) + DAY_MS) % DAY_MS;
    range.type = 'endDate';
    range.endDate = wallDate(untilTimeOfDay >= startTimeOfDay ? untilMs : untilMs - DAY_MS);
  }
  return { pattern, range };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run worker/__tests__/graph-recurrence.test.ts && npx tsc -b`
Expected: PASS, tsc clean. If a specific assertion string differs only in RRULE part ORDER, adjust the implementation's part ordering (not the test) to emit in the tested order: FREQ, INTERVAL, BYMONTH, BYDAY/BYMONTHDAY, BYSETPOS, WKST, COUNT/UNTIL.

- [ ] **Step 5: Commit**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar commit -m "feat: Graph patternedRecurrence <-> RRULE conversion (Slice 4c Task 3)"
```

---

### Task 4: Graph event translation

**Files:**
- Modify: `eldrin-calendar/worker/services/providers/graph-translate.ts` (append event section)
- Test: `eldrin-calendar/worker/__tests__/graph-translate.test.ts`

**Interfaces:**
- Consumes: Task 3 (`patternToRrule`, `rruleToPattern`, `GraphRecurrence`); `wallMsInZone` from `../zoned-time` (for outbound wall formatting); `TranslatedEvent`/`OutboundEvent` from `./types`.
- Produces:
  - `interface GraphApiEvent { id?: string; '@removed'?: { reason?: string }; type?: 'singleInstance'|'occurrence'|'exception'|'seriesMaster'; subject?: string; bodyPreview?: string; body?: { content?: string; contentType?: string }; location?: { displayName?: string }; start?: { dateTime?: string; timeZone?: string }; end?: { dateTime?: string; timeZone?: string }; isAllDay?: boolean; recurrence?: GraphRecurrence | null; seriesMasterId?: string; originalStart?: string; originalStartTimeZone?: string; attendees?: { emailAddress?: { address?: string; name?: string }; type?: string }[] }`
  - `graphEventToTranslated(g: GraphApiEvent, masterRecurrence?: GraphRecurrence | null): TranslatedEvent | null` — null for `type:'occurrence'` (skipped, spec D16) and unmappable events; `@removed` items → cancelled TranslatedEvent carrying only externalId; `type:'exception'` → `recurringExternalId = seriesMasterId`, `originalStartTime = Date.parse(originalStart + 'Z' fixup)`; `type:'seriesMaster'` → recurrenceRule from `patternToRrule(g.recurrence)` (unmappable → null = skip whole event).
  - `graphSafeZone(zone: string | undefined): string` — returns the zone if `Intl.DateTimeFormat` accepts it, else `'UTC'` with console.warn (Windows-name fallback, D18).
  - `outboundToGraphBody(e: OutboundEvent): Record<string, unknown>` — `{ subject, body: {contentType:'text', content: description ?? ''}, location: {displayName: location ?? ''}, isAllDay, start: {dateTime, timeZone}, end: {dateTime, timeZone}, recurrence }`. Timed events: `dateTime` = the WALL time in the event zone formatted `YYYY-MM-DDTHH:mm:ss` (compute `new Date(wallMsInZone(e.startAt, e.timezone)).toISOString().slice(0,19)`), `timeZone: e.timezone`. All-day: `isAllDay: true`, wall dates at `T00:00:00` (start inclusive, end exclusive — matches Graph). `recurrence` = `rruleToPattern(e.recurrenceRule, wallMsInZone(e.startAt, e.timezone), e.timezone)` when a rule is set; **if rruleToPattern returns null, THROW `new ProviderApiError('This recurrence is not supported by Outlook calendars', 400)`** (import from `./types`).

- [ ] **Step 1: Write failing tests**

`worker/__tests__/graph-translate.test.ts`:

```typescript
import { describe, it, expect, vi, afterEach } from 'vitest';
import { graphEventToTranslated, outboundToGraphBody, graphSafeZone, type GraphApiEvent } from '../services/providers/graph-translate';
import { ProviderApiError, type OutboundEvent } from '../services/providers/types';

afterEach(() => vi.restoreAllMocks());

describe('graphEventToTranslated', () => {
  it('maps a timed singleInstance (UTC wire per D18, zone from originalStartTimeZone)', () => {
    const t = graphEventToTranslated({
      id: 'g1', type: 'singleInstance', subject: 'Standup',
      bodyPreview: 'daily', location: { displayName: 'Room 1' },
      start: { dateTime: '2026-07-10T06:00:00.0000000', timeZone: 'UTC' },
      end: { dateTime: '2026-07-10T06:30:00.0000000', timeZone: 'UTC' },
      originalStartTimeZone: 'Europe/Bucharest',
      attendees: [
        { emailAddress: { address: 'A@B.c', name: 'Al' }, type: 'required' },
        { emailAddress: { address: 'room@x' }, type: 'resource' },
      ],
    })!;
    expect(t.externalId).toBe('g1');
    expect(t.startAt).toBe(Date.parse('2026-07-10T06:00:00Z'));
    expect(t.endAt).toBe(Date.parse('2026-07-10T06:30:00Z'));
    expect(t.timezone).toBe('Europe/Bucharest');
    expect(t.allDay).toBe(false);
    expect(t.attendees).toEqual([{ email: 'a@b.c', displayName: 'Al' }]);
  });

  it('maps an all-day event as zone-midnight with exclusive end', () => {
    const t = graphEventToTranslated({
      id: 'g2', type: 'singleInstance', subject: 'Conf', isAllDay: true,
      start: { dateTime: '2026-07-10T00:00:00.0000000', timeZone: 'UTC' },
      end: { dateTime: '2026-07-11T00:00:00.0000000', timeZone: 'UTC' },
      originalStartTimeZone: 'Europe/Bucharest',
    })!;
    expect(t.allDay).toBe(true);
    // wire is UTC midnight; the local convention stores zone-midnight → convert via the zone
    expect(t.startAt).toBe(Date.parse('2026-07-09T21:00:00Z')); // midnight Bucharest (UTC+3)
    expect(t.endAt).toBe(Date.parse('2026-07-10T21:00:00Z'));
  });

  it('skips plain occurrences (derivable from the master)', () => {
    expect(graphEventToTranslated({ id: 'o1', type: 'occurrence', seriesMasterId: 'm1' })).toBeNull();
  });

  it('maps a seriesMaster with recurrence to a master TranslatedEvent', () => {
    const t = graphEventToTranslated({
      id: 'm1', type: 'seriesMaster', subject: 'Weekly',
      start: { dateTime: '2026-07-10T06:00:00.0000000', timeZone: 'UTC' },
      end: { dateTime: '2026-07-10T06:30:00.0000000', timeZone: 'UTC' },
      originalStartTimeZone: 'Europe/Bucharest',
      recurrence: {
        pattern: { type: 'weekly', interval: 1, daysOfWeek: ['friday'] },
        range: { type: 'noEnd', startDate: '2026-07-10', recurrenceTimeZone: 'Europe/Bucharest' },
      },
    })!;
    expect(t.recurrenceRule).toBe('FREQ=WEEKLY;BYDAY=FR');
    expect(t.recurringExternalId).toBeNull();
  });

  it('skips a seriesMaster whose recurrence is unmappable (with warning)', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const t = graphEventToTranslated({
      id: 'm2', type: 'seriesMaster', subject: 'Odd',
      start: { dateTime: '2026-07-10T06:00:00.0000000', timeZone: 'UTC' },
      end: { dateTime: '2026-07-10T06:30:00.0000000', timeZone: 'UTC' },
      recurrence: { pattern: { type: 'lunarMonthly', interval: 1 }, range: { type: 'noEnd', startDate: '2026-07-10' } } as never,
    });
    expect(t).toBeNull();
    expect(warn).toHaveBeenCalled();
  });

  it('maps an exception with seriesMasterId and originalStart', () => {
    const t = graphEventToTranslated({
      id: 'x1', type: 'exception', subject: 'Weekly (moved)', seriesMasterId: 'm1',
      start: { dateTime: '2026-07-17T08:00:00.0000000', timeZone: 'UTC' },
      end: { dateTime: '2026-07-17T08:30:00.0000000', timeZone: 'UTC' },
      originalStart: '2026-07-17T06:00:00.0000000Z', originalStartTimeZone: 'Europe/Bucharest',
    })!;
    expect(t.recurringExternalId).toBe('m1');
    expect(t.originalStartTime).toBe(Date.parse('2026-07-17T06:00:00Z'));
  });

  it('maps @removed tombstones to cancelled shells', () => {
    const t = graphEventToTranslated({ id: 'gone', '@removed': { reason: 'deleted' } })!;
    expect(t.status).toBe('cancelled');
    expect(t.externalId).toBe('gone');
    expect(t.startAt).toBeNull();
  });

  it('returns null for confirmed events without parseable times', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect(graphEventToTranslated({ id: 'weird', type: 'singleInstance', subject: 'x' })).toBeNull();
    expect(warn).toHaveBeenCalled();
  });
});

describe('graphSafeZone', () => {
  it('passes IANA zones through and falls back to UTC for Windows names', () => {
    expect(graphSafeZone('Europe/Bucharest')).toBe('Europe/Bucharest');
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect(graphSafeZone('Pacific Standard Time')).toBe('UTC');
    expect(warn).toHaveBeenCalled();
    expect(graphSafeZone(undefined)).toBe('UTC');
  });
});

describe('outboundToGraphBody', () => {
  const base: OutboundEvent = {
    title: 'Meet', description: 'd', location: 'l',
    startAt: Date.parse('2026-07-10T06:00:00Z'), endAt: Date.parse('2026-07-10T07:00:00Z'),
    allDay: false, timezone: 'Europe/Bucharest', recurrenceRule: null,
    attendees: [{ email: 'a@b.c', displayName: null }],
  };

  it('formats timed bounds as WALL time in the event zone', () => {
    const b = outboundToGraphBody(base);
    expect(b.subject).toBe('Meet');
    expect(b.start).toEqual({ dateTime: '2026-07-10T09:00:00', timeZone: 'Europe/Bucharest' }); // 06:00Z = 09:00 wall
    expect(b.end).toEqual({ dateTime: '2026-07-10T10:00:00', timeZone: 'Europe/Bucharest' });
    expect(b.isAllDay).toBe(false);
    expect(b.recurrence).toBeNull();
    expect(b.attendees).toEqual([{ emailAddress: { address: 'a@b.c' }, type: 'required' }]);
  });

  it('formats all-day bounds at wall midnight with exclusive end', () => {
    const b = outboundToGraphBody({
      ...base, allDay: true,
      startAt: Date.parse('2026-07-09T21:00:00Z'), endAt: Date.parse('2026-07-10T21:00:00Z'), // Bucharest Jul 10 all-day
    });
    expect(b.isAllDay).toBe(true);
    expect(b.start).toEqual({ dateTime: '2026-07-10T00:00:00', timeZone: 'Europe/Bucharest' });
    expect(b.end).toEqual({ dateTime: '2026-07-11T00:00:00', timeZone: 'Europe/Bucharest' });
  });

  it('converts the recurrence rule and pins the wall startDate', () => {
    const b = outboundToGraphBody({ ...base, recurrenceRule: 'FREQ=WEEKLY;BYDAY=FR' });
    const rec = b.recurrence as { pattern: { type: string }; range: { startDate: string } };
    expect(rec.pattern.type).toBe('weekly');
    expect(rec.range.startDate).toBe('2026-07-10');
  });

  it('throws ProviderApiError(400) for RRULEs Outlook cannot express', () => {
    expect(() => outboundToGraphBody({ ...base, recurrenceRule: 'FREQ=HOURLY' }))
      .toThrowError(ProviderApiError);
    try {
      outboundToGraphBody({ ...base, recurrenceRule: 'FREQ=HOURLY' });
    } catch (err) {
      expect((err as ProviderApiError).status).toBe(400);
      expect((err as ProviderApiError).message).toContain('not supported by Outlook');
    }
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run worker/__tests__/graph-translate.test.ts`
Expected: FAIL — exports missing.

- [ ] **Step 3: Append the event section to graph-translate.ts**

Add imports at the top (merge with existing): `import { wallMsInZone, zonedWallToUtcMs } from '../zoned-time';`, `import { ProviderApiError, type OutboundEvent, type TranslatedEvent } from './types';`. Then append:

```typescript
export interface GraphApiEvent {
  id?: string;
  '@removed'?: { reason?: string };
  type?: 'singleInstance' | 'occurrence' | 'exception' | 'seriesMaster';
  subject?: string;
  bodyPreview?: string;
  body?: { content?: string; contentType?: string };
  location?: { displayName?: string };
  start?: { dateTime?: string; timeZone?: string };
  end?: { dateTime?: string; timeZone?: string };
  isAllDay?: boolean;
  recurrence?: GraphRecurrence | null;
  seriesMasterId?: string;
  originalStart?: string;
  originalStartTimeZone?: string;
  attendees?: { emailAddress?: { address?: string; name?: string }; type?: string }[];
}

/** IANA-or-UTC zone guard (Graph can return Windows zone names, D18). */
export function graphSafeZone(zone: string | undefined): string {
  if (!zone) return 'UTC';
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: zone });
    return zone;
  } catch {
    console.warn(`[calendar] non-IANA Graph timezone "${zone}" — falling back to UTC`);
    return 'UTC';
  }
}

/** Graph wire datetime ("2026-07-10T06:00:00.0000000", Prefer UTC) → real-UTC ms. */
function parseGraphUtc(dt: string | undefined): number | null {
  if (!dt) return null;
  const ms = Date.parse(dt.endsWith('Z') ? dt : `${dt}Z`);
  return Number.isFinite(ms) ? ms : null;
}

export function graphEventToTranslated(g: GraphApiEvent): TranslatedEvent | null {
  if (!g.id) {
    console.warn('[calendar] skipping Graph event without id');
    return null;
  }
  if (g['@removed']) {
    return {
      externalId: g.id, status: 'cancelled', title: '', description: null, location: null,
      startAt: null, endAt: null, allDay: false, timezone: 'UTC',
      recurrenceRule: null, recurringExternalId: null, originalStartTime: null, attendees: [],
    };
  }
  if (g.type === 'occurrence') return null; // derivable from the master (D16)

  const timezone = graphSafeZone(g.originalStartTimeZone);
  const startUtc = parseGraphUtc(g.start?.dateTime);
  const endUtc = parseGraphUtc(g.end?.dateTime);
  if (startUtc === null || endUtc === null) {
    console.warn(`[calendar] skipping unmappable Graph event ${g.id} (missing start/end)`);
    return null;
  }
  // All-day events arrive as UTC midnight bounds; the local convention is zone-midnight.
  const startAt = g.isAllDay ? zonedWallToUtcMs(startUtc, timezone) : startUtc;
  const endAt = g.isAllDay ? zonedWallToUtcMs(endUtc, timezone) : endUtc;

  let recurrenceRule: string | null = null;
  if (g.type === 'seriesMaster') {
    if (!g.recurrence) {
      console.warn(`[calendar] skipping Graph seriesMaster ${g.id} without recurrence`);
      return null;
    }
    recurrenceRule = patternToRrule(g.recurrence);
    if (recurrenceRule === null) return null; // warned inside patternToRrule
  }

  return {
    externalId: g.id,
    status: 'confirmed',
    title: g.subject ?? '(no title)',
    description: g.bodyPreview?.trim() ? g.bodyPreview : null,
    location: g.location?.displayName?.trim() ? g.location.displayName : null,
    startAt, endAt,
    allDay: g.isAllDay === true,
    timezone,
    recurrenceRule,
    recurringExternalId: g.type === 'exception' ? (g.seriesMasterId ?? null) : null,
    originalStartTime: g.type === 'exception' ? parseGraphUtc(g.originalStart) : null,
    attendees: (g.attendees ?? [])
      .filter((a) => a.emailAddress?.address && a.type !== 'resource')
      .map((a) => ({ email: a.emailAddress!.address!.toLowerCase(), displayName: a.emailAddress!.name ?? null })),
  };
}

/** Wall time of a UTC instant in a zone, formatted for Graph ("YYYY-MM-DDTHH:mm:ss"). */
function graphWall(utcMs: number, zone: string): string {
  return new Date(wallMsInZone(utcMs, zone)).toISOString().slice(0, 19);
}

export function outboundToGraphBody(e: OutboundEvent): Record<string, unknown> {
  let recurrence: GraphRecurrence | null = null;
  if (e.recurrenceRule) {
    recurrence = rruleToPattern(e.recurrenceRule, wallMsInZone(e.startAt, e.timezone), e.timezone);
    if (recurrence === null) {
      throw new ProviderApiError('This recurrence is not supported by Outlook calendars', 400);
    }
  }
  return {
    subject: e.title,
    body: { contentType: 'text', content: e.description ?? '' },
    location: { displayName: e.location ?? '' },
    isAllDay: e.allDay,
    start: { dateTime: graphWall(e.startAt, e.timezone), timeZone: e.timezone },
    end: { dateTime: graphWall(e.endAt, e.timezone), timeZone: e.timezone },
    recurrence,
    attendees: e.attendees.map((a) => ({
      emailAddress: a.displayName ? { address: a.email, name: a.displayName } : { address: a.email },
      type: 'required',
    })),
  };
}
```

- [ ] **Step 4: Non-UTC inbound all-day test for GOOGLE too (hardening, spec §7)**

Append to `worker/__tests__/google-translate.test.ts`:

```typescript
describe('googleEventToTranslated — non-UTC all-day (4c hardening)', () => {
  it('parses date-only bounds as zone midnight for a non-UTC timeZone', () => {
    const t = googleEventToTranslated({
      id: 'g-tz', summary: 'Athens all-day',
      start: { date: '2026-07-10', timeZone: 'Europe/Bucharest' },
      end: { date: '2026-07-11', timeZone: 'Europe/Bucharest' },
    })!;
    expect(t.allDay).toBe(true);
    expect(t.startAt).toBe(Date.parse('2026-07-09T21:00:00Z')); // midnight +03:00
    expect(t.endAt).toBe(Date.parse('2026-07-10T21:00:00Z'));
  });
});
```

- [ ] **Step 5: Run all tests + typecheck, then commit**

Run: `npx vitest run && npx tsc -b`
Expected: PASS.

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar commit -m "feat: Graph event translation + non-UTC all-day hardening tests (Slice 4c Task 4)"
```

---

### Task 5: Graph API client (outlook.ts) + ChangeSet reconciliation field

**Files:**
- Modify: `eldrin-calendar/worker/services/providers/types.ts` (ChangeSet gains `presentExternalIds`)
- Create: `eldrin-calendar/worker/services/providers/outlook.ts`
- Test: `eldrin-calendar/worker/__tests__/outlook-provider.test.ts`

**Interfaces:**
- Consumes: Task 3–4 translation; `types.ts` contracts; `dateInZone` NOT needed.
- Produces: `createOutlookProvider(getToken: (forceRefresh?: boolean) => Promise<string>): CalendarProvider`. `ChangeSet` gains optional `presentExternalIds?: string[] | null` — when non-null, the sync core (Task 6) deletes local non-exception rows whose externalId is missing from it (Graph master-delete reconciliation; the Google client never sets it).
- Wire behaviors:
  - Every request: `Authorization: Bearer`, `Prefer: outlook.timezone="UTC"`, retry-once-on-401 with `getToken(true)` (same discipline as google.ts — read it first).
  - `listCalendars` → `GET /me/calendars?$select=id,name,hexColor,isDefaultCalendar&$top=100` paged via `@odata.nextLink`; `color` = `hexColor` if `#rrggbb` else null; `isPrimary` = `isDefaultCalendar === true`.
  - `listChanges(calExtId, syncToken)`:
    - `syncToken` null → initial: `GET /me/calendars/{id}/calendarView/delta?startDateTime={ISO(now-6mo)}&endDateTime={ISO(now+18mo)}`; else → GET the stored deltaLink verbatim.
    - Page via `@odata.nextLink` until `@odata.deltaLink`; `nextSyncToken` = the FULL deltaLink URL.
    - Item handling: `@removed` → cancelled shell (via `graphEventToTranslated`); `type:'occurrence'` → skip; `type:'exception'`/`'singleInstance'` → translate; for every DISTINCT `seriesMasterId` seen on occurrence/exception items, fetch the master ONCE per batch (`GET /me/events/{id}` — the delta feed does not carry masters) through a `Map<string, TranslatedEvent | null>` cache and include each fetched master in `events` (before its exceptions — order the output masters-first).
    - If ANY `@removed` item was seen, ALSO fetch the calendar's present ids (`GET /me/calendars/{id}/events?$select=id&$top=100` paged — this endpoint returns masters+singles only) and set `presentExternalIds`; otherwise leave it null.
    - Delta-token rejection: HTTP 410, or an error body whose text contains `SyncStateNotFound` → `{events: [], nextSyncToken: null, fullResyncRequired: true, presentExternalIds: null}`.
  - `createEvent`/`updateEvent`/`deleteEvent` → `POST /me/calendars/{id}/events`, `PATCH /me/events/{eventId}`, `DELETE /me/events/{eventId}` (delete tolerates 404/410); create/update responses translate via `graphEventToTranslated` (a created master comes back `type:'seriesMaster'`).
  - `getInstanceExternalId(calExtId, masterExternalId, originalStartUtcMs, timezone, allDay)` → `GET /me/events/{master}/instances?startDateTime={ISO(originalStartUtcMs - DAY)}&endDateTime={ISO(originalStartUtcMs + DAY)}&$select=id,originalStart,start&$top=50`; match item where `parseGraphUtc(originalStart) === originalStartUtcMs` (fallback: `parseGraphUtc(start.dateTime) === originalStartUtcMs`); 404 ProviderApiError when absent.
  - `watch(calExtId, channelId, token, address)` → `POST /subscriptions` `{ changeType: 'created,updated,deleted', notificationUrl: address, resource: '/me/calendars/{calExtId}/events', clientState: token, expirationDateTime: ISO(now + 4170 * 60_000) }` → `{channelId: sub.id, resourceId: 'graph-subscription', expiresAt: Date.parse(sub.expirationDateTime)}` (the passed `channelId` arg is IGNORED for Graph — the subscription id is server-assigned).
  - `stopWatch(subscriptionId)` → `DELETE /subscriptions/{id}` best-effort (warn on non-404 failure).

- [ ] **Step 1: Extend ChangeSet in types.ts**

In `worker/services/providers/types.ts`, change the `ChangeSet` interface to:

```typescript
export interface ChangeSet {
  events: TranslatedEvent[];
  nextSyncToken: string | null;
  fullResyncRequired: boolean;
  /**
   * When non-null: the authoritative set of external ids currently present on
   * the provider calendar (masters + singles). The sync core deletes local
   * non-exception rows whose externalId is absent. Graph sets this whenever a
   * delta batch contained tombstones (occurrence tombstones cannot identify a
   * deleted master); Google leaves it null.
   */
  presentExternalIds?: string[] | null;
}
```

Run: `npx vitest run` — expect the existing suites still green (field is optional).

- [ ] **Step 2: Write failing client tests**

`worker/__tests__/outlook-provider.test.ts` — follow `worker/__tests__/google-provider.test.ts`'s stub-fetch style (read it first). Cover, with a `getToken` mock and `vi.stubGlobal('fetch', …)` sequenced responses:

```typescript
import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { createOutlookProvider } from '../services/providers/outlook';

afterEach(() => vi.unstubAllGlobals());
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const getToken = vi.fn().mockResolvedValue('tok');
beforeEach(() => getToken.mockClear());

const MASTER = {
  id: 'm1', type: 'seriesMaster', subject: 'Weekly',
  start: { dateTime: '2026-07-10T06:00:00.0000000', timeZone: 'UTC' },
  end: { dateTime: '2026-07-10T06:30:00.0000000', timeZone: 'UTC' },
  originalStartTimeZone: 'Europe/Bucharest',
  recurrence: { pattern: { type: 'weekly', interval: 1, daysOfWeek: ['friday'] }, range: { type: 'noEnd', startDate: '2026-07-10', recurrenceTimeZone: 'Europe/Bucharest' } },
};

describe('createOutlookProvider', () => {
  it('lists calendars with paging, hexColor validation, and the UTC Prefer header', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json({ value: [{ id: 'c1', name: 'Cal', hexColor: '#a1b2c3', isDefaultCalendar: true }], '@odata.nextLink': 'https://graph.microsoft.com/v1.0/next' }))
      .mockResolvedValueOnce(json({ value: [{ id: 'c2', name: 'Two', hexColor: 'auto' }] }));
    vi.stubGlobal('fetch', fetchMock);
    const cals = await createOutlookProvider(getToken).listCalendars();
    expect(cals).toEqual([
      { externalId: 'c1', name: 'Cal', color: '#a1b2c3', isPrimary: true },
      { externalId: 'c2', name: 'Two', color: null, isPrimary: false },
    ]);
    expect(fetchMock.mock.calls[0][1].headers.Prefer).toBe('outlook.timezone="UTC"');
    expect(String(fetchMock.mock.calls[1][0])).toBe('https://graph.microsoft.com/v1.0/next');
  });

  it('initial listChanges pages the calendarView delta, fetches masters once, skips occurrences, returns the deltaLink', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json({ value: [
        { id: 'o1', type: 'occurrence', seriesMasterId: 'm1' },
        { id: 'o2', type: 'occurrence', seriesMasterId: 'm1' },
      ], '@odata.nextLink': 'https://graph.microsoft.com/v1.0/nextpage' }))
      .mockResolvedValueOnce(json({ value: [
        { id: 'x1', type: 'exception', seriesMasterId: 'm1', subject: 'Moved',
          start: { dateTime: '2026-07-17T08:00:00.0000000', timeZone: 'UTC' },
          end: { dateTime: '2026-07-17T08:30:00.0000000', timeZone: 'UTC' },
          originalStart: '2026-07-17T06:00:00.0000000Z', originalStartTimeZone: 'Europe/Bucharest' },
        { id: 's1', type: 'singleInstance', subject: 'One-off',
          start: { dateTime: '2026-07-20T10:00:00.0000000', timeZone: 'UTC' },
          end: { dateTime: '2026-07-20T11:00:00.0000000', timeZone: 'UTC' } },
      ], '@odata.deltaLink': 'https://graph.microsoft.com/v1.0/me/calendarView/delta?$deltatoken=abc' }))
      .mockResolvedValueOnce(json(MASTER)); // exactly ONE master fetch despite 3 references
    vi.stubGlobal('fetch', fetchMock);
    const cs = await createOutlookProvider(getToken).listChanges('c1', null);
    expect(String(fetchMock.mock.calls[0][0])).toContain('/me/calendars/c1/calendarView/delta?startDateTime=');
    expect(String(fetchMock.mock.calls[2][0])).toContain('/me/events/m1');
    expect(cs.nextSyncToken).toBe('https://graph.microsoft.com/v1.0/me/calendarView/delta?$deltatoken=abc');
    expect(cs.fullResyncRequired).toBe(false);
    expect(cs.presentExternalIds).toBeNull();
    const ids = cs.events.map((e) => e.externalId);
    expect(ids[0]).toBe('m1'); // master ordered before its exception
    expect(ids).toContain('x1');
    expect(ids).toContain('s1');
    expect(ids).not.toContain('o1');
  });

  it('continues from a stored deltaLink verbatim', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(json({ value: [], '@odata.deltaLink': 'https://graph.microsoft.com/v1.0/me/calendarView/delta?$deltatoken=next' }));
    vi.stubGlobal('fetch', fetchMock);
    const cs = await createOutlookProvider(getToken).listChanges('c1', 'https://graph.microsoft.com/v1.0/me/calendarView/delta?$deltatoken=abc');
    expect(String(fetchMock.mock.calls[0][0])).toBe('https://graph.microsoft.com/v1.0/me/calendarView/delta?$deltatoken=abc');
    expect(cs.nextSyncToken).toContain('deltatoken=next');
  });

  it('tombstones trigger the present-ids sweep', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json({ value: [{ id: 'dead', '@removed': { reason: 'deleted' } }], '@odata.deltaLink': 'https://graph.microsoft.com/v1.0/d?$deltatoken=t' }))
      .mockResolvedValueOnce(json({ value: [{ id: 'm1' }, { id: 's1' }], '@odata.nextLink': 'https://graph.microsoft.com/v1.0/p2' }))
      .mockResolvedValueOnce(json({ value: [{ id: 's2' }] }));
    vi.stubGlobal('fetch', fetchMock);
    const cs = await createOutlookProvider(getToken).listChanges('c1', 'https://graph.microsoft.com/v1.0/d?$deltatoken=old');
    expect(cs.events.find((e) => e.externalId === 'dead')?.status).toBe('cancelled');
    expect(cs.presentExternalIds).toEqual(['m1', 's1', 's2']);
    expect(String(fetchMock.mock.calls[1][0])).toContain('/me/calendars/c1/events?');
  });

  it('SyncStateNotFound → full resync sentinel', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: { code: 'SyncStateNotFound', message: 'resync' } }), { status: 410 })));
    const cs = await createOutlookProvider(getToken).listChanges('c1', 'https://graph.microsoft.com/v1.0/d?$deltatoken=stale');
    expect(cs).toEqual({ events: [], nextSyncToken: null, fullResyncRequired: true, presentExternalIds: null });
  });

  it('retries exactly once with a forced token on 401', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response('unauth', { status: 401 }))
      .mockResolvedValueOnce(json({ value: [] }));
    vi.stubGlobal('fetch', fetchMock);
    await createOutlookProvider(getToken).listCalendars();
    expect(getToken).toHaveBeenCalledTimes(2);
    expect(getToken).toHaveBeenLastCalledWith(true);
  });

  it('createEvent POSTs the Graph body and translates the seriesMaster response', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json(MASTER));
    vi.stubGlobal('fetch', fetchMock);
    const t = await createOutlookProvider(getToken).createEvent('c1', {
      title: 'Weekly', description: null, location: null,
      startAt: Date.parse('2026-07-10T06:00:00Z'), endAt: Date.parse('2026-07-10T06:30:00Z'),
      allDay: false, timezone: 'Europe/Bucharest', recurrenceRule: 'FREQ=WEEKLY;BYDAY=FR', attendees: [],
    });
    expect(t.externalId).toBe('m1');
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toContain('/me/calendars/c1/events');
    expect(JSON.parse(init.body).recurrence.pattern.type).toBe('weekly');
  });

  it('deleteEvent tolerates 404; other failures wrap in ProviderApiError with status', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('', { status: 404 })));
    await expect(createOutlookProvider(getToken).deleteEvent('c1', 'e1')).resolves.toBeUndefined();
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('forbidden', { status: 403 })));
    await expect(createOutlookProvider(getToken).listCalendars()).rejects.toMatchObject({ status: 403 });
  });

  it('getInstanceExternalId matches by originalStart within a ±1 day window', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({ value: [
      { id: 'inst-1', originalStart: '2026-07-17T06:00:00.0000000Z', start: { dateTime: '2026-07-17T08:00:00.0000000' } },
    ] }));
    vi.stubGlobal('fetch', fetchMock);
    const id = await createOutlookProvider(getToken).getInstanceExternalId('c1', 'm1', Date.parse('2026-07-17T06:00:00Z'), 'Europe/Bucharest', false);
    expect(id).toBe('inst-1');
    expect(String(fetchMock.mock.calls[0][0])).toContain('/me/events/m1/instances?startDateTime=');
  });

  it('watch POSTs a Graph subscription and returns its id + expiry', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({ id: 'sub-1', expirationDateTime: '2026-07-12T12:00:00Z' }));
    vi.stubGlobal('fetch', fetchMock);
    const w = await createOutlookProvider(getToken).watch('c1', 'ignored', 'hmac-token', 'https://x/api/sync/notify/graph');
    expect(w).toEqual({ channelId: 'sub-1', resourceId: 'graph-subscription', expiresAt: Date.parse('2026-07-12T12:00:00Z') });
    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.resource).toBe('/me/calendars/c1/events');
    expect(body.clientState).toBe('hmac-token');
    expect(body.notificationUrl).toBe('https://x/api/sync/notify/graph');
  });
});
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `npx vitest run worker/__tests__/outlook-provider.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 4: Implement outlook.ts**

Create `worker/services/providers/outlook.ts` following google.ts's structure (read it first — same `call`/`callJson` retry-once shape, plus the `Prefer: outlook.timezone="UTC"` header on every request). Implementation per the wire behaviors in this task's Interfaces block. Key constants: `const API_BASE = 'https://graph.microsoft.com/v1.0'; const PAGE = '$top=100'; const WINDOW_PAST_MS = 183 * 86400000; const WINDOW_FUTURE_MS = 548 * 86400000; const SUBSCRIPTION_TTL_MS = 4170 * 60_000;`. `listChanges` collects raw items across pages first, then: build `masterCache = new Map<string, TranslatedEvent | null>()`; for each distinct `seriesMasterId` on occurrence/exception items fetch `/me/events/{id}` once, translate, cache; output array = fetched masters (non-null) first, then translated exceptions/singles/tombstones. Sweep only when a tombstone was present. Delta URLs: when following `@odata.nextLink`/stored deltaLink, GET them VERBATIM (they're absolute).

- [ ] **Step 5: Run all tests + typecheck, then commit**

Run: `npx vitest run && npx tsc -b`
Expected: PASS (google-provider suite untouched).

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar commit -m "feat: Graph calendarView-delta client implementing CalendarProvider (Slice 4c Task 5)"
```

---

### Task 6: Provider dispatch + provider-neutral gating + reconciliation sweep

**Files:**
- Modify: `eldrin-calendar/worker/services/accounts.ts`
- Modify: `eldrin-calendar/worker/services/sync.ts`
- Modify: `eldrin-calendar/worker/routes/events.ts` (gating only)
- Test: `eldrin-calendar/worker/__tests__/accounts-dispatch.test.ts`, edits to `sync-service.test.ts` + `events-write-route.test.ts`

**Interfaces:**
- Consumes: Task 1 (`refreshMicrosoftToken`), Task 5 (`createOutlookProvider`, `presentExternalIds`).
- Produces: `SYNCED_PROVIDERS = ['google', 'microsoft'] as const` exported from `accounts.ts`; `isSyncedCalendar(cal: CalendarRow): boolean` (provider in SYNCED_PROVIDERS AND accountId non-null) exported from `accounts.ts`; `providerForAccount`/`providerForCalendar`/`freshAccessToken` dispatch on the account's provider; sync core honors `presentExternalIds`.

- [ ] **Step 1: Write failing dispatch tests**

`worker/__tests__/accounts-dispatch.test.ts`:

```typescript
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createTestDb } from './test-db';
import type { Database } from '../db';
import { connectedAccounts } from '../db';
import { eq } from 'drizzle-orm';
import { freshAccessToken, isSyncedCalendar } from '../services/accounts';
import { encryptToken, decryptToken } from '../services/crypto';
import type { CalendarRow } from '../db';

afterEach(() => vi.unstubAllGlobals());
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const env = {
  JWT_SECRET: 'test-secret',
  GOOGLE_CLIENT_ID: 'gid', GOOGLE_CLIENT_SECRET: 'gsec',
  MICROSOFT_CLIENT_ID: 'mid', MICROSOFT_CLIENT_SECRET: 'msec',
} as Env;

describe('freshAccessToken — microsoft branch', () => {
  let db: Database;
  beforeEach(async () => {
    db = createTestDb();
    await db.insert(connectedAccounts).values({
      id: 'ms1', userId: 'u1', provider: 'microsoft', email: 'me@outlook.com',
      accessTokenEnc: await encryptToken('old-at', 'test-secret'),
      refreshTokenEnc: await encryptToken('old-rt', 'test-secret'),
      tokenExpiresAt: 0, status: 'active', createdAt: 1, updatedAt: 1,
    });
  });

  it('refreshes via the Microsoft endpoint and persists the ROTATED refresh token', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({ access_token: 'new-at', refresh_token: 'new-rt', expires_in: 3600 }));
    vi.stubGlobal('fetch', fetchMock);
    expect(await freshAccessToken(db, env, 'ms1')).toBe('new-at');
    expect(String(fetchMock.mock.calls[0][0])).toContain('login.microsoftonline.com');
    const [acc] = await db.select().from(connectedAccounts).where(eq(connectedAccounts.id, 'ms1'));
    expect(await decryptToken(acc.refreshTokenEnc, 'test-secret')).toBe('new-rt');
  });

  it('keeps the old refresh token when MS omits a rotated one', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ access_token: 'new-at', expires_in: 3600 })));
    await freshAccessToken(db, env, 'ms1');
    const [acc] = await db.select().from(connectedAccounts).where(eq(connectedAccounts.id, 'ms1'));
    expect(await decryptToken(acc.refreshTokenEnc, 'test-secret')).toBe('old-rt');
  });
});

describe('isSyncedCalendar', () => {
  const base = { id: 'c', name: 'n', color: '#111111', ownerId: 'u', isDefault: false, externalId: 'x', createdAt: 1, updatedAt: 1 } as Partial<CalendarRow>;
  it('true for google/microsoft with an account, false for local or accountless', () => {
    expect(isSyncedCalendar({ ...base, provider: 'google', accountId: 'a' } as CalendarRow)).toBe(true);
    expect(isSyncedCalendar({ ...base, provider: 'microsoft', accountId: 'a' } as CalendarRow)).toBe(true);
    expect(isSyncedCalendar({ ...base, provider: 'local', accountId: null } as CalendarRow)).toBe(false);
    expect(isSyncedCalendar({ ...base, provider: 'google', accountId: null } as CalendarRow)).toBe(false);
  });
});
```

- [ ] **Step 2: Add failing sweep test to sync-service.test.ts**

Append to the `syncCalendar` describe (reuse its harness — `fakeProvider` returns ChangeSets; add `presentExternalIds` support to its queued objects):

```typescript
  it('presentExternalIds sweep deletes local masters/singles missing remotely, keeps exceptions', async () => {
    // seed: master m1 (externalId ext-m1) + its exception + single s1 (ext-s1)
    await syncCalendar(db, env, fakeProvider([{
      events: [
        translatedEvent({ externalId: 'ext-m1', title: 'Series', recurrenceRule: 'FREQ=WEEKLY;BYDAY=MO' }),
        translatedEvent({ externalId: 'ext-s1', title: 'Single' }),
        translatedEvent({ externalId: 'ext-m1-x', recurringExternalId: 'ext-m1', originalStartTime: T0 + WEEK, startAt: T0 + WEEK + HOUR, endAt: T0 + WEEK + 2 * HOUR }),
      ],
      nextSyncToken: 't1', fullResyncRequired: false,
    }]).provider, await calRow());
    vi.clearAllMocks();
    // sweep says only ext-s1 remains remotely → master (and its exception via FK... exceptions are child rows, hard-delete master removes them) go
    const result = await syncCalendar(db, env, fakeProvider([{
      events: [], nextSyncToken: 't2', fullResyncRequired: false, presentExternalIds: ['ext-s1'],
    }]).provider, await calRow());
    expect(result.removed).toBe(1);
    const rows = await db.select().from(events);
    expect(rows.map((r) => r.externalId)).toEqual(['ext-s1']);
    expect(emitter.emitCalendarEventDeleted).toHaveBeenCalledTimes(1);
  });
```

(Add `const WEEK = 7 * 24 * HOUR;` near the other constants if absent.)

- [ ] **Step 3: Update events-write-route + sync-service harness expectations**

In `worker/__tests__/events-write-route.test.ts`, add ONE new test to the google write-through describe (the gating generalization must not regress the provider-mock discipline):

```typescript
  it('microsoft calendars also route through write-through (provider-neutral gating)', async () => {
    await db.insert(calendars).values({
      id: 'cal-ms', name: 'MS', color: '#223344', ownerId: 'u1', isDefault: false,
      provider: 'microsoft', externalId: 'mscal-ext', accountId: 'acc-ms', createdAt: 1, updatedAt: 1,
    });
    providerMock.createEvent.mockResolvedValue({ externalId: 'ms-new' });
    const res = await post(app, { calendarId: 'cal-ms', title: 'MS meet', startAt: T0, endAt: T0 + HOUR, timezone: 'UTC' });
    expect(res.status).toBe(201);
    expect(providerMock.createEvent).toHaveBeenCalled();
  });
```

- [ ] **Step 4: Run tests to verify failures, then implement**

Run: `npx vitest run worker/__tests__/accounts-dispatch.test.ts worker/__tests__/sync-service.test.ts worker/__tests__/events-write-route.test.ts` — expect the new tests to FAIL.

**accounts.ts** changes:

```typescript
import { refreshMicrosoftToken } from './oauth-microsoft';
import { createOutlookProvider } from './providers/outlook';

export const SYNCED_PROVIDERS = ['google', 'microsoft'] as const;

export function isSyncedCalendar(cal: CalendarRow): boolean {
  return (SYNCED_PROVIDERS as readonly string[]).includes(cal.provider) && cal.accountId !== null;
}
```

In `freshAccessToken`, replace the single refresh call with a provider branch (everything around it unchanged — expiry margin, error persistence; error message becomes provider-neutral `Token refresh failed — reconnect the account`):

```typescript
    const refreshToken = await decryptToken(acc.refreshTokenEnc, env.JWT_SECRET);
    const ts = now();
    if (acc.provider === 'microsoft') {
      const fresh = await refreshMicrosoftToken(refreshToken, env.MICROSOFT_CLIENT_ID, env.MICROSOFT_CLIENT_SECRET);
      await db.update(connectedAccounts).set({
        accessTokenEnc: await encryptToken(fresh.accessToken, env.JWT_SECRET),
        // Microsoft ROTATES refresh tokens — persist the new one when present.
        ...(fresh.refreshToken ? { refreshTokenEnc: await encryptToken(fresh.refreshToken, env.JWT_SECRET) } : {}),
        tokenExpiresAt: ts + fresh.expiresIn * 1000,
        status: 'active', lastError: null, updatedAt: ts,
      }).where(eq(connectedAccounts.id, acc.id));
      return fresh.accessToken;
    }
    const fresh = await refreshGoogleToken(refreshToken, env.GOOGLE_CLIENT_ID, env.GOOGLE_CLIENT_SECRET);
    // ...existing google persistence unchanged...
```

`providerForAccount` becomes async (it must read the account's provider) — **update all call sites** (`routes/sync.ts` uses it twice; add `await`):

```typescript
export async function providerForAccount(db: Database, env: Env, accountId: string): Promise<CalendarProvider> {
  const [acc] = await db.select({ provider: connectedAccounts.provider }).from(connectedAccounts)
    .where(eq(connectedAccounts.id, accountId));
  if (!acc) throw new ProviderApiError('Connected account not found', 404);
  const getToken = (force?: boolean) => freshAccessToken(db, env, accountId, force === true);
  return acc.provider === 'microsoft' ? createOutlookProvider(getToken) : createGoogleProvider(getToken);
}

export async function providerForCalendar(db: Database, env: Env, cal: CalendarRow): Promise<CalendarProvider> {
  if (!isSyncedCalendar(cal)) throw new ProviderApiError('Not a provider-synced calendar', 400);
  return providerForAccount(db, env, cal.accountId!);
}
```

**sync.ts** changes: rename the private `googleCalendars(db)` helper to `syncedCalendars(db)` using `inArray(calendars.provider, [...SYNCED_PROVIDERS])` (import `inArray` from drizzle-orm and `SYNCED_PROVIDERS` from `./accounts`); update its three call sites. In `syncCalendar`, after `applyChanges` and before the success-bookkeeping update, add the sweep:

```typescript
    let swept = 0;
    if (changes.presentExternalIds != null) {
      const present = new Set(changes.presentExternalIds);
      const locals = await db.select().from(events).where(and(
        eq(events.calendarId, cal.id), isNull(events.recurringEventId), isNotNull(events.externalId),
      ));
      for (const row of locals) {
        if (present.has(row.externalId!)) continue;
        await db.delete(events).where(eq(events.id, row.id));
        swept++;
        fireAndForget(emitCalendarEventDeleted(env, row.id, 'all'));
      }
    }
```

(import `isNull` from drizzle-orm; include `swept` in the returned `removed` count: `removed: removed + swept`.)

**routes/events.ts** gating generalization: replace every `cal.provider === 'google'` guard (there are 10 across POST/PATCH/DELETE) with `isSyncedCalendar(cal)` (import from `../services/accounts`); rename the local `googleRejected` helper to `providerRejected` and its message to `` `Calendar provider rejected the change: ${err.message}` `` (update the two route tests that assert on `Google Calendar rejected` — change them to the new message).

- [ ] **Step 5: Run all tests + typecheck, then commit**

Run: `npx vitest run && npx tsc -b`
Expected: PASS — including the D9 test (`local calendars never touch the provider`).

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar commit -m "feat: provider dispatch (MS token rotation) + provider-neutral gating + reconciliation sweep (Slice 4c Task 6)"
```

---

### Task 7: Graph notify endpoint + provider-aware watch renewal

**Files:**
- Modify: `eldrin-calendar/worker/routes/sync.ts` (add notify/graph)
- Modify: `eldrin-calendar/worker/services/sync.ts` (renewWatches address per provider)
- Test: `eldrin-calendar/worker/__tests__/graph-notify.test.ts`, extend `scheduled.test.ts`

**Interfaces:**
- Consumes: `channelTokenFor`, `syncCalendar`, `providerForCalendar` (async now), calendars table.
- Produces: `POST /api/sync/notify/graph` (public; pre-registered in the manifest by Task 2): `?validationToken=` → 200 `text/plain` echo; else JSON body `{value: [{subscriptionId, clientState, ...}]}` — per notification: look up calendar by `watchChannelId === subscriptionId` (unknown → skip), `clientState !== channelTokenFor(cal.id, JWT_SECRET)` → 403 immediately, else waitUntil incremental sync; final response 202 `{ok: true}`. Malformed body → 202 (Graph retries on errors; never let it loop).

- [ ] **Step 1: Write failing notify tests**

`worker/__tests__/graph-notify.test.ts` — reuse the harness style of `sync-routes.test.ts` (same mocks of `../services/accounts` + `../services/sync`, same `mockEnv`/`mockExecutionCtx`/`createApp`; read that file first and mirror its `vi.mock` blocks exactly, including the `syncCalendarMock`):

```typescript
describe('POST /api/sync/notify/graph', () => {
  beforeEach(async () => {
    await db.insert(calendars).values({
      id: 'cal-ms', name: 'MS', color: '#223344', ownerId: 'u1', isDefault: false,
      provider: 'microsoft', externalId: 'mscal-ext', accountId: 'acc-ms',
      watchChannelId: 'sub-1', watchResourceId: 'graph-subscription', createdAt: 1, updatedAt: 1,
    });
  });

  it('echoes the validationToken as text/plain (subscription handshake)', async () => {
    const res = await app.request('/api/sync/notify/graph?validationToken=abc%20123', { method: 'POST' }, mockEnv, mockExecutionCtx);
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toContain('text/plain');
    expect(await res.text()).toBe('abc 123');
    expect(waited.length).toBe(0);
  });

  it('valid notification schedules a sync and returns 202', async () => {
    const token = await channelTokenFor('cal-ms', 'test-secret');
    const res = await app.request('/api/sync/notify/graph', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ value: [{ subscriptionId: 'sub-1', clientState: token, changeType: 'updated' }] }),
    }, mockEnv, mockExecutionCtx);
    expect(res.status).toBe(202);
    expect(waited.length).toBe(1);
  });

  it('403s a clientState mismatch', async () => {
    const res = await app.request('/api/sync/notify/graph', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ value: [{ subscriptionId: 'sub-1', clientState: 'forged' }] }),
    }, mockEnv, mockExecutionCtx);
    expect(res.status).toBe(403);
    expect(waited.length).toBe(0);
  });

  it('unknown subscription and malformed body are 202 no-ops', async () => {
    for (const body of [JSON.stringify({ value: [{ subscriptionId: 'ghost', clientState: 'x' }] }), 'not json']) {
      const res = await app.request('/api/sync/notify/graph', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body,
      }, mockEnv, mockExecutionCtx);
      expect(res.status).toBe(202);
    }
    expect(waited.length).toBe(0);
  });
});
```

- [ ] **Step 2: Extend scheduled.test.ts for the per-provider address**

Append to the `renewWatches` describe (its `providerForCalendar` mock returns `{ watch: watchMock }` — the address assertion is what matters):

```typescript
  it('arms microsoft calendars against the graph notify address', async () => {
    await db.insert(calendars).values({ ...baseCal, id: 'ms1', externalId: 'ms-ext', provider: 'microsoft' });
    await renewWatches(db, { JWT_SECRET: 's', WEBHOOKS_ENABLED: 'true', PUBLIC_URL: 'https://cal.example.com' } as Env);
    const addresses = watchMock.mock.calls.map((call) => call[3]);
    expect(addresses).toContain('https://cal.example.com/api/sync/notify/graph');
    expect(addresses).toContain('https://cal.example.com/api/sync/notify/google'); // baseCal (google) still armed
  });
```

(`baseCal` in that file has `provider: 'google'` — this test inserts BOTH and asserts both addresses.)

- [ ] **Step 3: Run to verify failures, then implement**

`routes/sync.ts` — append after the google notify route:

```typescript
syncRoutes.post('/api/sync/notify/graph', async (c) => {
  // Subscription-creation handshake: echo the validationToken as text/plain.
  const validationToken = c.req.query('validationToken');
  if (validationToken) return c.text(validationToken, 200);

  const db = c.get('db');
  let body: { value?: { subscriptionId?: string; clientState?: string }[] };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ ok: true }, 202); // malformed — never make Graph retry-loop
  }
  for (const n of body.value ?? []) {
    if (!n.subscriptionId) continue;
    const [cal] = await db.select().from(calendars).where(eq(calendars.watchChannelId, n.subscriptionId));
    if (!cal) continue; // stale subscription for a removed calendar
    const expected = await channelTokenFor(cal.id, c.env.JWT_SECRET);
    if (n.clientState !== expected) return c.json({ error: 'Invalid clientState' }, 403);
    c.executionCtx.waitUntil((async () => {
      await syncCalendar(db, c.env, await providerForCalendar(db, c.env, cal), cal);
    })());
  }
  return c.json({ ok: true }, 202);
});
```

`services/sync.ts` — in `renewWatches`, move the address inside the loop:

```typescript
    const notifyPath = cal.provider === 'microsoft' ? '/api/sync/notify/graph' : '/api/sync/notify/google';
    const address = `${env.PUBLIC_URL.replace(/\/$/, '')}${notifyPath}`;
```

(delete the pre-loop `address` computation; keep everything else identical.)

- [ ] **Step 4: Run all tests + typecheck, then commit**

Run: `npx vitest run && npx tsc -b`
Expected: PASS.

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar commit -m "feat: Graph change-notification endpoint + provider-aware watch renewal (Slice 4c Task 7)"
```

---

### Task 8: Hardening — exception-row instance-id persistence

**Files:**
- Modify: `eldrin-calendar/worker/routes/events.ts` (exception-row PATCH branch)
- Test: extend `eldrin-calendar/worker/__tests__/events-write-route.test.ts`

**Interfaces:**
- Consumes: existing `pushEditOccurrence` (returns the resolved instance externalId — currently discarded in this branch).
- Produces: an exception row that had `externalId: null` gets the resolved id persisted on its first successful provider PATCH (4b final-review deferral: previously it self-healed only via the sync slot-match).

- [ ] **Step 1: Write the failing test**

Append to the write-through describe in `events-write-route.test.ts`:

```typescript
  it('PATCHing an exception row without externalId persists the resolved instance id', async () => {
    // master on the google calendar + a locally-created exception row with no Google id yet
    await db.insert(events).values({
      id: 'master-1', calendarId: 'cal-g', title: 'Weekly', startAt: T0, endAt: T0 + HOUR,
      allDay: false, timezone: 'UTC', recurrenceRule: 'FREQ=WEEKLY;BYDAY=MO',
      status: 'confirmed', externalId: 'g-master', createdBy: 'u1', createdAt: 1, updatedAt: 1,
    });
    await db.insert(events).values({
      id: 'exc-1', calendarId: 'cal-g', title: 'Weekly (local move)', startAt: T0 + WEEK + HOUR, endAt: T0 + WEEK + 2 * HOUR,
      allDay: false, timezone: 'UTC', recurringEventId: 'master-1', originalStartTime: T0 + WEEK,
      status: 'confirmed', externalId: null, createdBy: 'u1', createdAt: 1, updatedAt: 1,
    });
    providerMock.getInstanceExternalId.mockResolvedValue('g-inst-42');
    providerMock.updateEvent.mockResolvedValue({ externalId: 'g-inst-42' });
    const res = await app.request('/api/events/exc-1', {
      method: 'PATCH', headers: { 'Content-Type': 'application/json', 'x-eldrin-user-id': 'u1' },
      body: JSON.stringify({ title: 'Renamed exception' }),
    }, mockEnv, mockExecutionCtx);
    expect(res.status).toBe(200);
    const [row] = await db.select().from(events).where(eq(events.id, 'exc-1'));
    expect(row.externalId).toBe('g-inst-42');
    expect(row.title).toBe('Renamed exception');
  });
```

(Add `const WEEK = 7 * 24 * HOUR;` to the file's constants if absent.)

- [ ] **Step 2: Run to verify it fails, then fix the branch**

In `routes/events.ts`, the exception-row branch currently discards `pushEditOccurrence`'s return. Change it to capture and persist:

```typescript
  if (row.recurringEventId) {
    const ts = now();
    let updated = { ...row, ...patchFields(row, patch), updatedAt: ts };
    if (isSyncedCalendar(cal)) {
      try {
        if (row.externalId) {
          await pushUpdateWhole(db, c.env, cal, updated as EventRow, []);
        } else {
          const [masterRow] = await db.select().from(events).where(eq(events.id, row.recurringEventId));
          if (masterRow) {
            const instanceId = await pushEditOccurrence(db, c.env, cal, masterRow, row.originalStartTime!, updated as EventRow);
            updated = { ...updated, externalId: instanceId };
          }
        }
      } catch (err) {
        return providerRejected(c, err);
      }
    }
    await db.update(events).set(setClause(updated)).where(eq(events.id, row.id));
    // ...rest of the branch unchanged (master fetch + finish)...
  }
```

- [ ] **Step 3: Run all tests + typecheck, then commit**

Run: `npx vitest run && npx tsc -b`
Expected: PASS.

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar commit -m "fix: persist resolved instance id on direct exception-row edits (Slice 4c Task 8)"
```

---

### Task 9: Frontend + provider-calendars endpoint rename

**Files:**
- Modify: `eldrin-calendar/worker/routes/sync.ts` (`google-calendars` → `provider-calendars`)
- Modify: `eldrin-calendar/public/eldrin-app.manifest.json` (that route's path)
- Modify: `eldrin-calendar/src/api.ts`, `src/components/SettingsView.tsx`, `src/components/CalendarSidebar.tsx`
- Test: update `worker/__tests__/sync-routes.test.ts` paths

**Interfaces:**
- Consumes: Task 2's `getConnectToken(base, h, provider)`; existing accounts/setSyncedCalendars/syncNow APIs (unchanged shapes).
- Produces: `GET /api/accounts/:id/provider-calendars` (handler code unchanged — path only; manifest api.routes entry updated to match; permission `calendar:read`); UI with per-provider connect buttons and provider-labeled groups. Provider LABEL mapping: `{ google: 'Google', microsoft: 'Outlook' }`.

- [ ] **Step 1: Rename the route + tests**

In `worker/routes/sync.ts` change `'/api/accounts/:id/google-calendars'` to `'/api/accounts/:id/provider-calendars'` (handler body unchanged). In the manifest, change that api.routes path accordingly. In `worker/__tests__/sync-routes.test.ts` update the two request paths. Run `npx vitest run worker/__tests__/sync-routes.test.ts` — PASS.

- [ ] **Step 2: Frontend updates**

`src/api.ts`: rename `listGoogleCalendars` → `listProviderCalendars` (path `/accounts/${accountId}/provider-calendars`); type `GoogleCalendarChoice` → `ProviderCalendarChoice` (same shape; keep an `export type GoogleCalendarChoice = ProviderCalendarChoice` alias ONLY if other imports exist — check; otherwise rename cleanly everywhere).

`src/components/SettingsView.tsx`:
- Heading "Google accounts" → "Connected accounts".
- Buttons: replace the single Connect Google with two: `Connect Google` → `connectProvider('google')`, `Connect Microsoft` → `connectProvider('microsoft')` where:

```typescript
  async function connectProvider(provider: 'google' | 'microsoft') {
    setBusy(true);
    setError(null);
    try {
      const { token } = await api.getConnectToken(apiBase, headersRef.current, provider);
      const returnTo = `${window.location.origin}${window.location.pathname}`;
      window.location.href = `${apiBase}/api/oauth/${provider}/connect?token=${encodeURIComponent(token)}&returnTo=${encodeURIComponent(returnTo)}`;
    } catch (err) {
      setError(err instanceof Error ? err.message : `Could not start ${provider} connect`);
      setBusy(false);
    }
  }
```

- Account card: show a provider badge next to the email: `<span className="badge badge-outline badge-sm">{PROVIDER_LABELS[acc.provider] ?? acc.provider}</span>` with `const PROVIDER_LABELS: Record<string, string> = { google: 'Google', microsoft: 'Outlook' };`
- The `?connected=` / `?connect_error=` handling already generic (value is the provider name) — verify the notice string doesn't hardcode Google; make it `setNotice('Account connected.')`.
- `listGoogleCalendars` call sites → `listProviderCalendars`.

`src/components/CalendarSidebar.tsx`: replace the single "Google" group with per-provider groups:

```typescript
  const providerGroups = (['google', 'microsoft'] as const)
    .map((p) => ({ label: p === 'google' ? 'Google' : 'Outlook', cals: calendars.filter((cal) => cal.provider === p) }))
    .filter((g) => g.cals.length > 0);
```

Render each non-empty group with its label using the existing group markup (same rows, same `allowDelete={false}`, same sync-status hints).

- [ ] **Step 3: Gates + commit**

Run: `npx vitest run && npx tsc -b && npm run build`
Expected: all green.

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar commit -m "feat: Connect Microsoft UI + provider-calendars endpoint + provider groups (Slice 4c Task 9)"
```

---

### Task 10: Live validation (real Microsoft account + D20 ngrok webhooks) + ship

Executed by the MAIN session (browser + user's accounts + ngrok).

**Prerequisites (user-manual; confirm before starting):**
- [ ] Entra admin center, same app as eldrin-email: API permissions → add delegated `Calendars.ReadWrite` (Microsoft Graph); Authentication → add Web redirect URI `http://localhost:4012/api/oauth/microsoft/callback`.
- [ ] `eldrin-calendar/.dev.vars` has `MICROSOFT_CLIENT_ID`/`MICROSOFT_CLIENT_SECRET` (Task 2 copied them — verify).
- [ ] ngrok installed and authed (`ngrok http 4012` will be needed for D20).

**Steps:**

- [ ] **Servers**: eldrin-core :4000 + eldrin-calendar :4012 (background), health-check both.
- [ ] **Outlook connect flow** (browser): Settings → Connect Microsoft → real consent → account card with Outlook badge → calendar list renders → enable a TEST calendar (create one at outlook.live.com first if needed; avoid the default calendar for write tests) → initial import lands with `sync_status ok`.
- [ ] **Write-through vs Graph ground truth** (read the Graph API directly with the stored token, same decrypt technique as 4b validation): create "E2E-4c create" in Eldrin on the Outlook calendar → present in Graph; rename → title changed; delete → gone (Graph hard-deletes; a 404 on GET is the pass condition).
- [ ] **Recurring round-trip**: weekly series in Eldrin → Graph master has `recurrence.pattern.type: 'weekly'`; single-occurrence move → `/instances` shows the exception with matching originalStart AND the local row carries the instance externalId; following-truncate → Graph `range` becomes `{type: 'endDate', endDate: <day before the cut>}` (the Task 3 boundary rule, verified live); scope=all delete → master 404.
- [ ] **Inbound**: create + modify an event in outlook.live.com on the test calendar → Sync now → appears/updates in Eldrin; delete it there → Sync now → gone locally (delta tombstone or sweep).
- [ ] **Google regression smoke**: one create+delete on the GTF Google calendar, verified via the Google API read (4b technique).
- [ ] **D20 ngrok webhook test (both providers)**: user starts `ngrok http 4012` and pastes the https URL; append `PUBLIC_URL=<tunnel>` + `WEBHOOKS_ENABLED=true` to `.dev.vars`; restart the calendar dev server; trigger the scheduled handler (`curl "http://localhost:4012/__scheduled?cron=*+*+*+*+*"` — wrangler dev exposes it when started with `--test-scheduled`; if the dev script lacks the flag, run `npx wrangler dev --test-scheduled --port 4013` temporarily OR arm via a one-off `POST /api/sync/run`-adjacent debug call — plan for `--test-scheduled`); verify `watch_channel_id`/`watch_expires_at` set for one Google + one Microsoft calendar (Graph subscription creation proves the validationToken handshake worked through the tunnel); make a change in Google Calendar web → notification hits `/api/sync/notify/google` (worker log) → change lands locally WITHOUT Sync now; same for Outlook web → `/api/sync/notify/graph`. Afterwards: best-effort stopWatch (delete the subscription/channel via a small script or leave to expiry ≤3 days), remove the two `.dev.vars` lines, restart.
- [ ] **Console + suite gates**: browser console clean of sync errors; `npx vitest run` + `npx tsc -b` + `npm run build` green.
- [ ] **Fix-forward** any live finding (small fixes inline with tests; the 4b UNTIL bug precedent says verify recurrence boundaries hard).
- [ ] **Ship** (superpowers:finishing-a-development-branch): merge `feature/outlook-sync` --no-ff → main, push; parent gitlink bump `chore: bump eldrin-calendar submodule — Outlook/Graph sync + hardening (Slice 4c)`; update the `calendar-standalone-app-decision` memory (4c shipped, lessons, remaining backlog); stop dev servers.

## Plan Self-Review Notes

- Spec coverage: D16 (Task 5 delta client + Task 6 sweep), D17 (Tasks 3–4 conversion + error semantics), D18 (Task 4/5 UTC Prefer + graphSafeZone + wall formatting), D19 (Task 2 allowlist, both flows), D20 (Task 10 ngrok both providers); §3 hardening: allowlist (T2), exception instance-id (T8), non-UTC all-day (T4 google + graph); §5 modules (T1–T7); §6 UI (T9 incl. endpoint rename, no alias); §7 tests distributed per task; §8 risks: recurrence-first ordering (T3 before any wiring), occurrence-noise batch cache (T5), delta ordering handled by 4b's two-pass core (T6 sweep test seeds masters+exceptions), subscription lifetime + disabled-gate (T7 + existing gate), token rotation (T1+T6), eldrin-email overlap (T10 validation note — confirm mailbox still works post-consent).
- Type consistency: `presentExternalIds` defined in T5 types.ts, consumed T6 sync.ts; `isSyncedCalendar`/`SYNCED_PROVIDERS` defined T6, used T6 events.ts; `providerForAccount` async change called out with call-site updates; `getConnectToken(base, h, provider)` defined T2, consumed T9.
- Deliberate simplification vs spec §5: `renewWatches`'s D16 window-staleness re-anchor check is NOT implemented as a cron feature — delta-token rejection (`SyncStateNotFound`) already forces full resync, and the window's +18-month horizon exceeds any realistic dev/production gap for this slice; noted for 4d if long-lived deployments need proactive re-anchoring.

