# Slice 4b — Google Calendar Sync Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Two-way Google Calendar sync for `eldrin-calendar`: OAuth connect, user-selected calendars import (webhook-ready incremental sync via syncToken), and write-through of local edits to Google — all purely additive to local calendars (D9).

**Architecture:** A provider-adapter layer (`worker/services/providers/`) translates Google event JSON ⇄ the app's RFC 5545 rows and exposes `listCalendars/listChanges/create/update/delete/watch`. `sync.ts` orchestrates incremental sync (syncToken, 410 → full resync) keyed by `(calendar_id, external_id)`; the same idempotent upsert makes write-through echoes no-ops. Local edits on `provider='google'` calendars call Google **first** (write-through, D13) and fail visibly on rejection. Triggers: webhook notify endpoint (config-gated), wrangler cron reconciliation poll (dev's primary), manual "Sync now".

**Tech Stack:** Hono 4, Drizzle + D1, Vitest + better-sqlite3 (fetch stubbed with `vi.stubGlobal`), Google Calendar API v3 over raw `fetch`, AES-GCM token encryption (Web Crypto), React 19 single-spa frontend.

**Spec:** `docs/superpowers/specs/2026-07-09-google-calendar-sync-design.md` (decisions D11–D15, inherits D8–D10).

## Global Constraints

- **Working directory**: all tasks run in `/Users/tibor/projects/eldrin-backup/eldrin-calendar` on branch `feature/google-sync` (created in Task 1 from `main`). Beware: Bash `cd` persists — use absolute paths or `git -C`. Parent-repo gitlink bump only in Task 11.
- **D9 — local calendars untouched**: every new behavior branches on `calendar.provider === 'google'`; the `provider === 'local'` path must be byte-identical to before. Existing 70 tests must stay green after every task.
- **D13 — write-through order**: Google API call happens BEFORE any D1 mutation; a `ProviderApiError` aborts the request with **502** and leaves D1 untouched. Never queue, never retry silently.
- **Migrations**: new migration file is exactly `migrations/20260709150000-google-sync.sql` (14-digit timestamp prefix or it is silently skipped). `worker/migrations.generated.ts` is gitignored — regenerate via `npm run generate:migrations`, never edit/commit it.
- **Token crypto**: AES-GCM + HKDF port of `eldrin-email/worker/services/crypto.ts` with `SALT = 'eldrin-calendar-oauth'` (distinct key domain). Tokens are NEVER stored or logged in plaintext; `.dev.vars` is gitignored — never paste secrets into committed files.
- **Google API base**: `https://www.googleapis.com/calendar/v3`. OAuth scopes exactly: `https://www.googleapis.com/auth/calendar` + `https://www.googleapis.com/auth/userinfo.email`, with `access_type=offline&prompt=consent`.
- **Sync list params**: `events.list` uses `maxResults=250`, pagination via `pageToken`, `syncToken` for incremental, NO `singleEvents`, NO `timeMin` (masters + exceptions come through as rows, matching our storage model). HTTP 410 → wipe token, full resync.
- **publicRoutes are `/api`-relative** (SDK matcher strips the prefix — `"/health"` matches `/api/health`). New public entries: `"/oauth/google/connect"`, `"/oauth/google/callback"`, `"/sync/notify/google"`.
- **Env additions** (extend `worker-configuration.d.ts` interface + `.dev.vars`): `GOOGLE_CLIENT_ID: string`, `GOOGLE_CLIENT_SECRET: string`, optional `WEBHOOKS_ENABLED?: string`, `PUBLIC_URL?: string`. Copy dev client id/secret values from `eldrin-email/.dev.vars` (same Cloud Console client, per D14).
- **All-day convention**: rows store all-day events with **exclusive end** (same as Google and FullCalendar). Inbound `start.date`/`end.date` are parsed as midnight in the event's zone via `zonedWallToUtcMs(Date.parse(date + 'T00:00:00Z'), tz)` with `tz = g.start.timeZone ?? 'UTC'`; outbound formats via `new Date(wallMsInZone(row.startAt, row.timezone)).toISOString().slice(0, 10)`.
- **RRULE mapping**: inbound takes the first `RRULE:` line of `recurrence[]` (prefix stripped); `EXDATE`/`RDATE` lines are dropped with `console.warn` (spec §6). Outbound emits `["RRULE:" + row.recurrenceRule]`.
- **Platform events**: sync-applied changes emit the existing `calendar.event.created/updated/deleted` via `worker/services/event-emitter.ts` so the CRM mirror keeps working. Emits are fire-and-forget (already never throw).
- **Quality gates per task**: `npx vitest run` green, `npx tsc -b` green, conventional commit. Immutable patterns (build new objects, never mutate fetched rows). Files ≤ ~400 lines — split when a module grows past that.
- **Test harness**: worker tests follow `worker/__tests__/events-write-route.test.ts` — `createTestDb()` (better-sqlite3 + real migrations), Hono app assembled in-test with a db-injection middleware, `app.request(path, init, mockEnv, mockExecutionCtx)`, Google API stubbed with `vi.stubGlobal('fetch', vi.fn(...))`. Frontend has NO unit-test harness (4a convention) — typecheck + build + Task 11 browser validation are its gates.

## File Structure

```
eldrin-calendar/
  migrations/20260709150000-google-sync.sql        — Task 1 (connected_accounts + calendars sync/watch columns)
  worker-configuration.d.ts                        — Task 6 (Env additions)
  worker/db/schema.ts                              — Task 1 (connectedAccounts table, calendars columns)
  worker/services/crypto.ts                        — Task 1 (AES-GCM token encryption port)
  worker/services/oauth-google.ts                  — Task 2 (consent URL, code exchange, refresh, userinfo, revoke)
  worker/services/providers/types.ts               — Task 3 (CalendarProvider interface, TranslatedEvent, ProviderApiError)
  worker/services/providers/google-translate.ts    — Task 3 (Google JSON ⇄ TranslatedEvent/outbound body)
  worker/services/providers/google.ts              — Task 4 (fetch-based API client implementing CalendarProvider)
  worker/services/accounts.ts                      — Task 4 (account load, token decrypt/refresh, provider factory)
  worker/services/sync.ts                          — Task 5 (syncCalendar, syncAllForUser, reconcileAll, channelTokenFor)
  worker/routes/oauth.ts                           — Task 6 (connect-token, connect redirect, callback)
  worker/routes/sync.ts                            — Task 7 (accounts CRUD, google-calendars list, PUT synced set, sync/run, notify)
  worker/services/write-through.ts                 — Task 8 (pushCreate/pushUpdate/pushSplit/pushDelete…)
  worker/services/event-edits.ts                   — Task 8 (headRuleUntil export, externalId param on editSingleOccurrence/splitSeries)
  worker/routes/events.ts                          — Task 8 (google branches calling write-through)
  worker/index.ts                                  — Task 6 (mount oauth), Task 7 (mount sync), Task 9 (scheduled handler)
  wrangler.jsonc                                   — Task 9 (cron trigger)
  public/eldrin-app.manifest.json                  — Task 6/7 (publicRoutes, api.routes, settings.groups, sideNav Settings)
  src/api.ts                                       — Task 10 (accounts/sync client + Calendar sync fields)
  src/components/SettingsView.tsx                  — Task 10 (accounts UI)
  src/components/CalendarSidebar.tsx               — Task 10 (provider grouping + Settings link)
  src/root.component.tsx                           — Task 10 (pathname view switch)
  worker/__tests__/{crypto,oauth-google,google-translate,google-provider,sync-service,oauth-routes,sync-routes,write-through,scheduled}.test.ts
```

---

### Task 1: Branch, migration, schema, token crypto

**Files:**
- Create: `eldrin-calendar/migrations/20260709150000-google-sync.sql`
- Modify: `eldrin-calendar/worker/db/schema.ts`
- Create: `eldrin-calendar/worker/services/crypto.ts`
- Test: `eldrin-calendar/worker/__tests__/crypto.test.ts`, extend `worker/__tests__/schema.test.ts`

**Interfaces:**
- Consumes: existing `calendars` table, `worker/__tests__/test-db.ts` harness.
- Produces: `connectedAccounts` Drizzle table (+ `ConnectedAccountRow` type) with columns `id,userId,provider,email,accessTokenEnc,refreshTokenEnc,tokenExpiresAt,status,lastError,createdAt,updatedAt`; `calendars` rows gain `accountId,syncToken,lastSyncedAt,syncStatus,syncError,watchChannelId,watchResourceId,watchExpiresAt` (all nullable); `encryptToken(token: string, secret: string): Promise<string>` and `decryptToken(encrypted: string, secret: string): Promise<string>`.

- [ ] **Step 1: Create the feature branch**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar checkout main
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar pull
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar checkout -b feature/google-sync
```

- [ ] **Step 2: Write failing schema tests**

Append to `worker/__tests__/schema.test.ts` (follow its existing style):

```typescript
import { connectedAccounts } from '../db';

describe('connected_accounts (Slice 4b)', () => {
  it('inserts and reads an account row', async () => {
    const db = createTestDb();
    await db.insert(connectedAccounts).values({
      id: 'acc1', userId: 'u1', provider: 'google', email: 'me@example.com',
      accessTokenEnc: 'enc-a', refreshTokenEnc: 'enc-r', tokenExpiresAt: 123,
      status: 'active', createdAt: 1, updatedAt: 1,
    });
    const [row] = await db.select().from(connectedAccounts);
    expect(row.email).toBe('me@example.com');
    expect(row.status).toBe('active');
    expect(row.lastError).toBeNull();
  });

  it('rejects duplicate (user, provider, email)', async () => {
    const db = createTestDb();
    const base = {
      userId: 'u1', provider: 'google', email: 'me@example.com',
      accessTokenEnc: 'a', refreshTokenEnc: 'r', tokenExpiresAt: 1,
      status: 'active', createdAt: 1, updatedAt: 1,
    };
    await db.insert(connectedAccounts).values({ id: 'acc1', ...base });
    await expect(db.insert(connectedAccounts).values({ id: 'acc2', ...base })).rejects.toThrow();
  });

  it('calendars carry sync bookkeeping columns', async () => {
    const db = createTestDb();
    await db.insert(calendars).values({
      id: 'g1', name: 'Work', color: '#112233', ownerId: 'u1', isDefault: false,
      provider: 'google', externalId: 'gcal-ext', accountId: 'acc1',
      syncToken: 'tok', lastSyncedAt: 99, syncStatus: 'ok',
      createdAt: 1, updatedAt: 1,
    });
    const [row] = await db.select().from(calendars).where(eq(calendars.id, 'g1'));
    expect(row.accountId).toBe('acc1');
    expect(row.syncToken).toBe('tok');
    expect(row.syncStatus).toBe('ok');
    expect(row.watchChannelId).toBeNull();
  });
});
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-calendar && npx vitest run worker/__tests__/schema.test.ts`
Expected: FAIL — `connectedAccounts` is not exported / unknown columns.

- [ ] **Step 4: Write the migration**

`migrations/20260709150000-google-sync.sql`:

```sql
-- Slice 4b: Google Calendar sync — connected accounts + per-calendar sync state.
CREATE TABLE connected_accounts (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  email TEXT NOT NULL,
  access_token_enc TEXT NOT NULL,
  refresh_token_enc TEXT NOT NULL,
  token_expires_at INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  last_error TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX idx_accounts_unique ON connected_accounts(user_id, provider, email);
CREATE INDEX idx_accounts_user ON connected_accounts(user_id);

-- Sync bookkeeping on calendars (no FK: disconnect deletes calendars explicitly in code).
ALTER TABLE calendars ADD COLUMN account_id TEXT;
ALTER TABLE calendars ADD COLUMN sync_token TEXT;
ALTER TABLE calendars ADD COLUMN last_synced_at INTEGER;
ALTER TABLE calendars ADD COLUMN sync_status TEXT;
ALTER TABLE calendars ADD COLUMN sync_error TEXT;
ALTER TABLE calendars ADD COLUMN watch_channel_id TEXT;
ALTER TABLE calendars ADD COLUMN watch_resource_id TEXT;
ALTER TABLE calendars ADD COLUMN watch_expires_at INTEGER;
CREATE INDEX idx_calendars_account ON calendars(account_id);
CREATE INDEX idx_events_external ON events(calendar_id, external_id);
```

- [ ] **Step 5: Extend the Drizzle schema**

In `worker/db/schema.ts`, add to the `calendars` table definition (after `externalId`):

```typescript
    accountId: text('account_id'),
    syncToken: text('sync_token'),
    lastSyncedAt: integer('last_synced_at', { mode: 'number' }),
    syncStatus: text('sync_status'),
    syncError: text('sync_error'),
    watchChannelId: text('watch_channel_id'),
    watchResourceId: text('watch_resource_id'),
    watchExpiresAt: integer('watch_expires_at', { mode: 'number' }),
```

And append the new table + type export:

```typescript
export const connectedAccounts = sqliteTable(
  'connected_accounts',
  {
    id: text('id').primaryKey(),
    userId: text('user_id').notNull(),
    provider: text('provider').notNull(),
    email: text('email').notNull(),
    accessTokenEnc: text('access_token_enc').notNull(),
    refreshTokenEnc: text('refresh_token_enc').notNull(),
    tokenExpiresAt: integer('token_expires_at', { mode: 'number' }).notNull(),
    status: text('status').notNull().default('active'),
    lastError: text('last_error'),
    createdAt: integer('created_at', { mode: 'number' }).notNull(),
    updatedAt: integer('updated_at', { mode: 'number' }).notNull(),
  },
  (t) => [
    uniqueIndex('idx_accounts_unique').on(t.userId, t.provider, t.email),
    index('idx_accounts_user').on(t.userId),
  ],
);

export type ConnectedAccountRow = typeof connectedAccounts.$inferSelect;
```

- [ ] **Step 6: Run schema tests to verify they pass**

Run: `npx vitest run worker/__tests__/schema.test.ts`
Expected: PASS.

- [ ] **Step 7: Write failing crypto tests**

`worker/__tests__/crypto.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import { encryptToken, decryptToken } from '../services/crypto';

describe('token crypto', () => {
  it('round-trips a token', async () => {
    const enc = await encryptToken('ya29.secret-token', 'jwt-secret');
    expect(enc).not.toContain('ya29');
    expect(await decryptToken(enc, 'jwt-secret')).toBe('ya29.secret-token');
  });

  it('produces distinct ciphertexts for the same input (random IV)', async () => {
    const a = await encryptToken('same', 's');
    const b = await encryptToken('same', 's');
    expect(a).not.toBe(b);
  });

  it('fails to decrypt with the wrong secret', async () => {
    const enc = await encryptToken('tok', 'right');
    await expect(decryptToken(enc, 'wrong')).rejects.toThrow();
  });

  it('rejects garbage input', async () => {
    await expect(decryptToken('AA', 's')).rejects.toThrow();
  });
});
```

- [ ] **Step 8: Run crypto tests to verify they fail**

Run: `npx vitest run worker/__tests__/crypto.test.ts`
Expected: FAIL — module `../services/crypto` not found.

- [ ] **Step 9: Port crypto.ts**

Create `worker/services/crypto.ts` as an exact copy of `/Users/tibor/projects/eldrin-backup/eldrin-email/worker/services/crypto.ts` with TWO edits: the header comment mentions eldrin-calendar, and `const SALT = 'eldrin-calendar-oauth';` (distinct key domain from email). Everything else (HKDF derive, AES-GCM, base64url helpers, `encryptToken`, `decryptToken`) is unchanged — read the email file and copy it.

- [ ] **Step 10: Run all tests + typecheck**

Run: `npx vitest run && npx tsc -b`
Expected: all suites PASS (70 existing + new), typecheck clean.

- [ ] **Step 11: Commit**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar commit -m "feat: connected_accounts schema + calendar sync columns + token crypto (Slice 4b Task 1)"
```

---

### Task 2: Google OAuth service

**Files:**
- Create: `eldrin-calendar/worker/services/oauth-google.ts`
- Test: `eldrin-calendar/worker/__tests__/oauth-google.test.ts`

**Interfaces:**
- Consumes: nothing internal (pure fetch module).
- Produces: `getGoogleAuthUrl(clientId: string, redirectUri: string, state: string): string`; `exchangeGoogleCode(code, clientId, clientSecret, redirectUri): Promise<{accessToken: string; refreshToken: string; expiresIn: number}>`; `refreshGoogleToken(refreshToken, clientId, clientSecret): Promise<{accessToken: string; expiresIn: number}>`; `getGoogleUserInfo(accessToken): Promise<{email: string; name: string}>`; `revokeGoogleToken(token): Promise<void>` (best-effort, never throws).

- [ ] **Step 1: Write failing tests**

`worker/__tests__/oauth-google.test.ts`:

```typescript
import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  getGoogleAuthUrl, exchangeGoogleCode, refreshGoogleToken,
  getGoogleUserInfo, revokeGoogleToken,
} from '../services/oauth-google';

afterEach(() => vi.unstubAllGlobals());

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

describe('getGoogleAuthUrl', () => {
  it('builds a consent URL with calendar scope, offline access and state', () => {
    const url = new URL(getGoogleAuthUrl('cid', 'http://localhost:4012/api/oauth/google/callback', 'st4te'));
    expect(url.origin + url.pathname).toBe('https://accounts.google.com/o/oauth2/v2/auth');
    expect(url.searchParams.get('client_id')).toBe('cid');
    expect(url.searchParams.get('scope')).toContain('https://www.googleapis.com/auth/calendar');
    expect(url.searchParams.get('scope')).toContain('userinfo.email');
    expect(url.searchParams.get('access_type')).toBe('offline');
    expect(url.searchParams.get('prompt')).toBe('consent');
    expect(url.searchParams.get('state')).toBe('st4te');
  });
});

describe('exchangeGoogleCode', () => {
  it('POSTs the code and returns tokens', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      access_token: 'at', refresh_token: 'rt', expires_in: 3600,
    }));
    vi.stubGlobal('fetch', fetchMock);
    const t = await exchangeGoogleCode('c0de', 'cid', 'sec', 'http://cb');
    expect(t).toEqual({ accessToken: 'at', refreshToken: 'rt', expiresIn: 3600 });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://oauth2.googleapis.com/token');
    expect(String(init.body)).toContain('grant_type=authorization_code');
  });

  it('throws when no refresh token is returned', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse({ access_token: 'at', expires_in: 1 })));
    await expect(exchangeGoogleCode('c', 'i', 's', 'r')).rejects.toThrow(/refresh token/i);
  });

  it('throws on non-OK response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('nope', { status: 400 })));
    await expect(exchangeGoogleCode('c', 'i', 's', 'r')).rejects.toThrow(/exchange failed/i);
  });
});

describe('refreshGoogleToken', () => {
  it('returns a fresh access token', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse({ access_token: 'new', expires_in: 3599 })));
    expect(await refreshGoogleToken('rt', 'i', 's')).toEqual({ accessToken: 'new', expiresIn: 3599 });
  });
});

describe('getGoogleUserInfo', () => {
  it('fetches email + name with bearer auth', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ email: 'a@b.c', name: 'A B' }));
    vi.stubGlobal('fetch', fetchMock);
    expect(await getGoogleUserInfo('tok')).toEqual({ email: 'a@b.c', name: 'A B' });
    expect(fetchMock.mock.calls[0][1].headers.Authorization).toBe('Bearer tok');
  });
});

describe('revokeGoogleToken', () => {
  it('never throws, even on failure', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('err', { status: 400 })));
    await expect(revokeGoogleToken('t')).resolves.toBeUndefined();
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run worker/__tests__/oauth-google.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement oauth-google.ts**

Create `worker/services/oauth-google.ts` as a port of `eldrin-email/worker/services/oauth-gmail.ts` (read it first) with these deltas — function bodies are otherwise identical:

```typescript
/**
 * Google OAuth 2.0 service for Calendar sync (Slice 4b).
 * Port of eldrin-email's oauth-gmail.ts with Calendar scopes.
 */

const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const GOOGLE_USERINFO_URL = 'https://www.googleapis.com/oauth2/v2/userinfo';
const GOOGLE_REVOKE_URL = 'https://oauth2.googleapis.com/revoke';

const CALENDAR_SCOPES = [
  'https://www.googleapis.com/auth/calendar',
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/userinfo.profile',
].join(' ');
```

Exported functions: `getGoogleAuthUrl`, `exchangeGoogleCode`, `refreshGoogleToken`, `getGoogleUserInfo`, `revokeGoogleToken` — same shapes as the gmail versions (`getGmailAuthUrl` → `getGoogleAuthUrl` etc.), same error messages but prefixed `Google token exchange failed` / `Google token refresh failed`, and `revokeGoogleToken` logs `[calendar]` instead of `[email]`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run worker/__tests__/oauth-google.test.ts && npx tsc -b`
Expected: PASS, typecheck clean.

- [ ] **Step 5: Commit**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar commit -m "feat: Google OAuth service with Calendar scopes (Slice 4b Task 2)"
```

---

### Task 3: Provider types + Google event translation

**Files:**
- Create: `eldrin-calendar/worker/services/providers/types.ts`
- Create: `eldrin-calendar/worker/services/providers/google-translate.ts`
- Test: `eldrin-calendar/worker/__tests__/google-translate.test.ts`

**Interfaces:**
- Consumes: `wallMsInZone(utcMs, zone)` and `zonedWallToUtcMs(wallMs, zone)` from `worker/services/zoned-time.ts` (existing 4a helpers: real-UTC ms ⇄ wall-clock-as-fake-UTC ms).
- Produces (types.ts): `ProviderCalendar {externalId, name, color: string|null, isPrimary}`; `TranslatedEvent {externalId, status: 'confirmed'|'cancelled', title, description, location, startAt: number|null, endAt: number|null, allDay, timezone, recurrenceRule: string|null, recurringExternalId: string|null, originalStartTime: number|null, attendees: {email, displayName}[]}`; `OutboundEvent {title, description, location, startAt: number, endAt: number, allDay, timezone, recurrenceRule: string|null, attendees}`; `ChangeSet {events: TranslatedEvent[], nextSyncToken: string|null, fullResyncRequired: boolean}`; `WatchInfo {channelId, resourceId, expiresAt}`; `class ProviderApiError extends Error {status: number}`; `interface CalendarProvider` (methods listed in Step 3).
- Produces (google-translate.ts): `googleEventToTranslated(g: GoogleApiEvent): TranslatedEvent | null` (null = skip unmappable, with `console.warn`); `outboundToGoogleBody(e: OutboundEvent): Record<string, unknown>`; `dateInZone(utcMs: number, zone: string): string` (YYYY-MM-DD wall date); `GoogleApiEvent` type.

- [ ] **Step 1: Write failing translation tests**

`worker/__tests__/google-translate.test.ts`:

```typescript
import { describe, it, expect, vi, afterEach } from 'vitest';
import { googleEventToTranslated, outboundToGoogleBody, dateInZone } from '../services/providers/google-translate';
import type { OutboundEvent } from '../services/providers/types';

afterEach(() => vi.restoreAllMocks());

describe('googleEventToTranslated — timed events', () => {
  it('maps a simple timed event', () => {
    const t = googleEventToTranslated({
      id: 'g1', status: 'confirmed', summary: 'Standup',
      description: 'daily', location: 'Room 1',
      start: { dateTime: '2026-07-09T09:00:00+03:00', timeZone: 'Europe/Athens' },
      end: { dateTime: '2026-07-09T09:30:00+03:00', timeZone: 'Europe/Athens' },
      attendees: [
        { email: 'A@B.c', displayName: 'Al' },
        { email: 'room@x', resource: true },
      ],
    })!;
    expect(t.externalId).toBe('g1');
    expect(t.status).toBe('confirmed');
    expect(t.title).toBe('Standup');
    expect(t.startAt).toBe(Date.parse('2026-07-09T09:00:00+03:00'));
    expect(t.endAt).toBe(Date.parse('2026-07-09T09:30:00+03:00'));
    expect(t.allDay).toBe(false);
    expect(t.timezone).toBe('Europe/Athens');
    expect(t.recurrenceRule).toBeNull();
    expect(t.attendees).toEqual([{ email: 'a@b.c', displayName: 'Al' }]);
  });

  it('defaults timezone to UTC and title to (no title)', () => {
    const t = googleEventToTranslated({
      id: 'g2',
      start: { dateTime: '2026-07-09T06:00:00Z' },
      end: { dateTime: '2026-07-09T07:00:00Z' },
    })!;
    expect(t.timezone).toBe('UTC');
    expect(t.title).toBe('(no title)');
  });
});

describe('googleEventToTranslated — all-day', () => {
  it('parses date-only bounds as zone midnight, keeping exclusive end', () => {
    const t = googleEventToTranslated({
      id: 'g3', summary: 'Conf',
      start: { date: '2026-07-10' },
      end: { date: '2026-07-11' },
    })!;
    expect(t.allDay).toBe(true);
    expect(t.startAt).toBe(Date.parse('2026-07-10T00:00:00Z')); // UTC fallback zone
    expect(t.endAt).toBe(Date.parse('2026-07-11T00:00:00Z'));   // exclusive, unchanged
  });
});

describe('googleEventToTranslated — recurrence', () => {
  it('extracts the RRULE line without prefix', () => {
    const t = googleEventToTranslated({
      id: 'g4', summary: 'Weekly',
      start: { dateTime: '2026-07-06T10:00:00Z' }, end: { dateTime: '2026-07-06T11:00:00Z' },
      recurrence: ['RRULE:FREQ=WEEKLY;BYDAY=MO'],
    })!;
    expect(t.recurrenceRule).toBe('FREQ=WEEKLY;BYDAY=MO');
  });

  it('drops EXDATE lines with a warning but keeps the RRULE', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const t = googleEventToTranslated({
      id: 'g5', summary: 'W',
      start: { dateTime: '2026-07-06T10:00:00Z' }, end: { dateTime: '2026-07-06T11:00:00Z' },
      recurrence: ['EXDATE;TZID=UTC:20260713T100000', 'RRULE:FREQ=WEEKLY'],
    })!;
    expect(t.recurrenceRule).toBe('FREQ=WEEKLY');
    expect(warn).toHaveBeenCalled();
  });

  it('maps a moved exception instance (recurringEventId + originalStartTime)', () => {
    const t = googleEventToTranslated({
      id: 'g4_20260713T100000Z', summary: 'Weekly',
      start: { dateTime: '2026-07-13T12:00:00Z' }, end: { dateTime: '2026-07-13T13:00:00Z' },
      recurringEventId: 'g4',
      originalStartTime: { dateTime: '2026-07-13T10:00:00Z' },
    })!;
    expect(t.recurringExternalId).toBe('g4');
    expect(t.originalStartTime).toBe(Date.parse('2026-07-13T10:00:00Z'));
    expect(t.status).toBe('confirmed');
  });

  it('maps a cancelled instance without start/end', () => {
    const t = googleEventToTranslated({
      id: 'g4_20260720T100000Z', status: 'cancelled',
      recurringEventId: 'g4',
      originalStartTime: { dateTime: '2026-07-20T10:00:00Z' },
    })!;
    expect(t.status).toBe('cancelled');
    expect(t.recurringExternalId).toBe('g4');
    expect(t.originalStartTime).toBe(Date.parse('2026-07-20T10:00:00Z'));
    expect(t.startAt).toBeNull();
  });

  it('maps a cancelled non-recurring event', () => {
    const t = googleEventToTranslated({ id: 'gone', status: 'cancelled' })!;
    expect(t.status).toBe('cancelled');
    expect(t.recurringExternalId).toBeNull();
  });
});

describe('googleEventToTranslated — unmappable', () => {
  it('returns null (with warning) for a confirmed event without start', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect(googleEventToTranslated({ id: 'weird', summary: 'x' })).toBeNull();
    expect(warn).toHaveBeenCalled();
  });
});

describe('outboundToGoogleBody', () => {
  const base: OutboundEvent = {
    title: 'Meet', description: 'd', location: 'l',
    startAt: Date.parse('2026-07-09T09:00:00Z'), endAt: Date.parse('2026-07-09T10:00:00Z'),
    allDay: false, timezone: 'Europe/Athens', recurrenceRule: null,
    attendees: [{ email: 'a@b.c', displayName: null }],
  };

  it('builds a timed body with timeZone', () => {
    const b = outboundToGoogleBody(base);
    expect(b.summary).toBe('Meet');
    expect(b.start).toEqual({ dateTime: '2026-07-09T09:00:00.000Z', timeZone: 'Europe/Athens' });
    expect(b.end).toEqual({ dateTime: '2026-07-09T10:00:00.000Z', timeZone: 'Europe/Athens' });
    expect(b.recurrence).toEqual([]);
    expect(b.attendees).toEqual([{ email: 'a@b.c' }]);
  });

  it('builds all-day date bounds in the event zone', () => {
    // Local midnight July 10 in Athens (UTC+3) = 21:00 UTC July 9 — the DATE must still be 2026-07-10.
    const b = outboundToGoogleBody({
      ...base, allDay: true,
      startAt: Date.parse('2026-07-09T21:00:00Z'), endAt: Date.parse('2026-07-10T21:00:00Z'),
    });
    expect(b.start).toEqual({ date: '2026-07-10' });
    expect(b.end).toEqual({ date: '2026-07-11' });
  });

  it('emits the RRULE with prefix', () => {
    const b = outboundToGoogleBody({ ...base, recurrenceRule: 'FREQ=DAILY;COUNT=5' });
    expect(b.recurrence).toEqual(['RRULE:FREQ=DAILY;COUNT=5']);
  });
});

describe('dateInZone', () => {
  it('formats the wall date of a UTC instant in a zone', () => {
    expect(dateInZone(Date.parse('2026-07-09T21:00:00Z'), 'Europe/Athens')).toBe('2026-07-10');
    expect(dateInZone(Date.parse('2026-07-09T21:00:00Z'), 'UTC')).toBe('2026-07-09');
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run worker/__tests__/google-translate.test.ts`
Expected: FAIL — modules not found.

- [ ] **Step 3: Create types.ts**

`worker/services/providers/types.ts`:

```typescript
/**
 * Provider-neutral adapter contract (spec D8/D10). Core CRUD/sync code talks
 * only to these types; Google (and later Outlook) implement them.
 */

export interface ProviderCalendar {
  externalId: string;
  name: string;
  color: string | null; // #rrggbb or null
  isPrimary: boolean;
}

export interface TranslatedEvent {
  externalId: string;
  status: 'confirmed' | 'cancelled';
  title: string;
  description: string | null;
  location: string | null;
  startAt: number | null; // null only on cancelled instances
  endAt: number | null;
  allDay: boolean;
  timezone: string;
  recurrenceRule: string | null; // bare RRULE, no prefix
  recurringExternalId: string | null; // master's external id (exception rows)
  originalStartTime: number | null;
  attendees: { email: string; displayName: string | null }[];
}

export interface OutboundEvent {
  title: string;
  description: string | null;
  location: string | null;
  startAt: number;
  endAt: number;
  allDay: boolean;
  timezone: string;
  recurrenceRule: string | null;
  attendees: { email: string; displayName: string | null }[];
}

export interface ChangeSet {
  events: TranslatedEvent[];
  nextSyncToken: string | null;
  fullResyncRequired: boolean;
}

export interface WatchInfo {
  channelId: string;
  resourceId: string;
  expiresAt: number; // ms epoch
}

export class ProviderApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
    this.name = 'ProviderApiError';
  }
}

export interface CalendarProvider {
  listCalendars(): Promise<ProviderCalendar[]>;
  listChanges(calendarExternalId: string, syncToken: string | null): Promise<ChangeSet>;
  createEvent(calendarExternalId: string, event: OutboundEvent): Promise<TranslatedEvent>;
  updateEvent(calendarExternalId: string, externalId: string, event: OutboundEvent): Promise<TranslatedEvent>;
  deleteEvent(calendarExternalId: string, externalId: string): Promise<void>;
  /** Resolve the provider id of one occurrence of a recurring master. */
  getInstanceExternalId(
    calendarExternalId: string,
    masterExternalId: string,
    originalStartUtcMs: number,
    timezone: string,
    allDay: boolean,
  ): Promise<string>;
  watch(calendarExternalId: string, channelId: string, token: string, address: string): Promise<WatchInfo>;
  stopWatch(channelId: string, resourceId: string): Promise<void>;
}
```

- [ ] **Step 4: Implement google-translate.ts**

`worker/services/providers/google-translate.ts`:

```typescript
/**
 * Google Calendar API v3 event JSON ⇄ provider-neutral TranslatedEvent.
 * Pure functions, no fetch — exhaustively unit-tested (spec §6, §9).
 */
import { wallMsInZone, zonedWallToUtcMs } from '../zoned-time';
import type { OutboundEvent, TranslatedEvent } from './types';

export interface GoogleEventTime {
  date?: string;      // all-day: YYYY-MM-DD
  dateTime?: string;  // RFC3339 with offset
  timeZone?: string;
}

export interface GoogleApiEvent {
  id?: string;
  status?: string;
  summary?: string;
  description?: string;
  location?: string;
  start?: GoogleEventTime;
  end?: GoogleEventTime;
  recurrence?: string[];
  recurringEventId?: string;
  originalStartTime?: GoogleEventTime;
  attendees?: { email?: string; displayName?: string; resource?: boolean }[];
}

interface ParsedTime { ms: number; allDay: boolean; timezone: string }

function parseTime(t: GoogleEventTime | undefined): ParsedTime | null {
  if (!t) return null;
  if (t.dateTime) {
    const ms = Date.parse(t.dateTime);
    if (!Number.isFinite(ms)) return null;
    return { ms, allDay: false, timezone: t.timeZone ?? 'UTC' };
  }
  if (t.date) {
    const wall = Date.parse(`${t.date}T00:00:00Z`);
    if (!Number.isFinite(wall)) return null;
    const timezone = t.timeZone ?? 'UTC';
    return { ms: zonedWallToUtcMs(wall, timezone), allDay: true, timezone };
  }
  return null;
}

/** Wall date (YYYY-MM-DD) of a UTC instant in a zone. */
export function dateInZone(utcMs: number, zone: string): string {
  return new Date(wallMsInZone(utcMs, zone)).toISOString().slice(0, 10);
}

function parseRecurrence(lines: string[] | undefined): string | null {
  if (!lines || lines.length === 0) return null;
  const rrule = lines.find((l) => l.startsWith('RRULE:'));
  if (lines.some((l) => l.startsWith('EXDATE') || l.startsWith('RDATE'))) {
    console.warn('[calendar] dropping EXDATE/RDATE lines from Google recurrence (unsupported, spec §6)');
  }
  return rrule ? rrule.slice('RRULE:'.length) : null;
}

export function googleEventToTranslated(g: GoogleApiEvent): TranslatedEvent | null {
  if (!g.id) {
    console.warn('[calendar] skipping Google event without id');
    return null;
  }
  const orig = parseTime(g.originalStartTime);
  const base = {
    externalId: g.id,
    recurringExternalId: g.recurringEventId ?? null,
    originalStartTime: orig ? orig.ms : null,
  };
  if (g.status === 'cancelled') {
    return {
      ...base,
      status: 'cancelled',
      title: g.summary ?? '',
      description: null,
      location: null,
      startAt: null,
      endAt: null,
      allDay: orig?.allDay ?? false,
      timezone: orig?.timezone ?? 'UTC',
      recurrenceRule: null,
      attendees: [],
    };
  }
  const start = parseTime(g.start);
  const end = parseTime(g.end);
  if (!start || !end) {
    console.warn(`[calendar] skipping unmappable Google event ${g.id} (missing start/end)`);
    return null;
  }
  return {
    ...base,
    status: 'confirmed',
    title: g.summary ?? '(no title)',
    description: g.description ?? null,
    location: g.location ?? null,
    startAt: start.ms,
    endAt: end.ms,
    allDay: start.allDay,
    timezone: start.timezone,
    recurrenceRule: parseRecurrence(g.recurrence),
    attendees: (g.attendees ?? [])
      .filter((a) => a.email && !a.resource)
      .map((a) => ({ email: a.email!.toLowerCase(), displayName: a.displayName ?? null })),
  };
}

export function outboundToGoogleBody(e: OutboundEvent): Record<string, unknown> {
  const start = e.allDay
    ? { date: dateInZone(e.startAt, e.timezone) }
    : { dateTime: new Date(e.startAt).toISOString(), timeZone: e.timezone };
  const end = e.allDay
    ? { date: dateInZone(e.endAt, e.timezone) }
    : { dateTime: new Date(e.endAt).toISOString(), timeZone: e.timezone };
  return {
    summary: e.title,
    description: e.description ?? '',
    location: e.location ?? '',
    start,
    end,
    recurrence: e.recurrenceRule ? [`RRULE:${e.recurrenceRule}`] : [],
    attendees: e.attendees.map((a) =>
      a.displayName ? { email: a.email, displayName: a.displayName } : { email: a.email },
    ),
  };
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `npx vitest run worker/__tests__/google-translate.test.ts && npx tsc -b`
Expected: PASS, typecheck clean.

- [ ] **Step 6: Commit**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar commit -m "feat: provider adapter types + Google event translation (Slice 4b Task 3)"
```

---

### Task 4: Google API client + account token service

**Files:**
- Create: `eldrin-calendar/worker/services/providers/google.ts`
- Create: `eldrin-calendar/worker/services/accounts.ts`
- Test: `eldrin-calendar/worker/__tests__/google-provider.test.ts`

**Interfaces:**
- Consumes: Task 2 (`refreshGoogleToken`), Task 1 (`connectedAccounts`, `encryptToken`/`decryptToken`), Task 3 (types + translation).
- Produces: `createGoogleProvider(getToken: (forceRefresh?: boolean) => Promise<string>): CalendarProvider`; `freshAccessToken(db: Database, env: Env, accountId: string, force?: boolean): Promise<string>`; `providerForAccount(db, env, accountId): CalendarProvider`; `providerForCalendar(db, env, cal: CalendarRow): Promise<CalendarProvider>` (throws `ProviderApiError(400)` on non-google calendars).

- [ ] **Step 1: Write failing tests**

`worker/__tests__/google-provider.test.ts`:

```typescript
import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { createTestDb } from './test-db';
import type { Database } from '../db';
import { connectedAccounts } from '../db';
import { eq } from 'drizzle-orm';
import { createGoogleProvider } from '../services/providers/google';
import { freshAccessToken } from '../services/accounts';
import { encryptToken, decryptToken } from '../services/crypto';
import { ProviderApiError } from '../services/providers/types';

afterEach(() => vi.unstubAllGlobals());

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

describe('createGoogleProvider', () => {
  const getToken = vi.fn().mockResolvedValue('tok');
  beforeEach(() => getToken.mockClear());

  it('lists calendars with pagination', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json({ items: [{ id: 'c1', summary: 'One', primary: true, backgroundColor: '#a1b2c3' }], nextPageToken: 'p2' }))
      .mockResolvedValueOnce(json({ items: [{ id: 'c2', summary: 'Two' }] }));
    vi.stubGlobal('fetch', fetchMock);
    const cals = await createGoogleProvider(getToken).listCalendars();
    expect(cals).toEqual([
      { externalId: 'c1', name: 'One', color: '#a1b2c3', isPrimary: true },
      { externalId: 'c2', name: 'Two', color: null, isPrimary: false },
    ]);
    expect(String(fetchMock.mock.calls[1][0])).toContain('pageToken=p2');
  });

  it('listChanges pages, translates and returns nextSyncToken', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json({
        items: [{ id: 'e1', summary: 'A', start: { dateTime: '2026-07-09T09:00:00Z' }, end: { dateTime: '2026-07-09T10:00:00Z' } }],
        nextPageToken: 'p2',
      }))
      .mockResolvedValueOnce(json({
        items: [{ id: 'weird' }], // unmappable → filtered out
        nextSyncToken: 'sync-2',
      }));
    vi.stubGlobal('fetch', fetchMock);
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const cs = await createGoogleProvider(getToken).listChanges('c1', 'sync-1');
    expect(cs.events).toHaveLength(1);
    expect(cs.events[0].externalId).toBe('e1');
    expect(cs.nextSyncToken).toBe('sync-2');
    expect(cs.fullResyncRequired).toBe(false);
    expect(String(fetchMock.mock.calls[0][0])).toContain('syncToken=sync-1');
  });

  it('listChanges flags full resync on 410 GONE', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('gone', { status: 410 })));
    const cs = await createGoogleProvider(getToken).listChanges('c1', 'stale');
    expect(cs).toEqual({ events: [], nextSyncToken: null, fullResyncRequired: true });
  });

  it('retries exactly once with a forced token on 401', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response('unauth', { status: 401 }))
      .mockResolvedValueOnce(json({ items: [] }));
    vi.stubGlobal('fetch', fetchMock);
    await createGoogleProvider(getToken).listCalendars();
    expect(getToken).toHaveBeenCalledTimes(2);
    expect(getToken).toHaveBeenLastCalledWith(true);
  });

  it('createEvent POSTs the outbound body and returns the translated response', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({
      id: 'new-ext', summary: 'Meet',
      start: { dateTime: '2026-07-09T09:00:00Z' }, end: { dateTime: '2026-07-09T10:00:00Z' },
    }));
    vi.stubGlobal('fetch', fetchMock);
    const t = await createGoogleProvider(getToken).createEvent('c1', {
      title: 'Meet', description: null, location: null,
      startAt: Date.parse('2026-07-09T09:00:00Z'), endAt: Date.parse('2026-07-09T10:00:00Z'),
      allDay: false, timezone: 'UTC', recurrenceRule: null, attendees: [],
    });
    expect(t.externalId).toBe('new-ext');
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toContain('/calendars/c1/events');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body).summary).toBe('Meet');
  });

  it('wraps API failures in ProviderApiError with status', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('forbidden', { status: 403 })));
    await expect(createGoogleProvider(getToken).listCalendars()).rejects.toMatchObject({ status: 403 });
  });

  it('deleteEvent tolerates 404/410 (already gone)', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('', { status: 404 })));
    await expect(createGoogleProvider(getToken).deleteEvent('c1', 'e1')).resolves.toBeUndefined();
  });

  it('getInstanceExternalId queries instances with RFC3339 originalStart', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({ items: [{ id: 'master_20260713T100000Z' }] }));
    vi.stubGlobal('fetch', fetchMock);
    const id = await createGoogleProvider(getToken).getInstanceExternalId(
      'c1', 'master', Date.parse('2026-07-13T10:00:00Z'), 'UTC', false,
    );
    expect(id).toBe('master_20260713T100000Z');
    const url = String(fetchMock.mock.calls[0][0]);
    expect(url).toContain('/events/master/instances');
    expect(url).toContain(encodeURIComponent('2026-07-13T10:00:00.000Z'));
    expect(url).toContain('showDeleted=true');
  });

  it('watch POSTs a web_hook channel and returns WatchInfo', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({ id: 'ch1', resourceId: 'res1', expiration: '1799999999000' }));
    vi.stubGlobal('fetch', fetchMock);
    const w = await createGoogleProvider(getToken).watch('c1', 'ch1', 'tok-hmac', 'https://x/api/sync/notify/google');
    expect(w).toEqual({ channelId: 'ch1', resourceId: 'res1', expiresAt: 1799999999000 });
    expect(JSON.parse(fetchMock.mock.calls[0][1].body).type).toBe('web_hook');
  });
});

describe('freshAccessToken', () => {
  let db: Database;
  const env = { JWT_SECRET: 'test-secret', GOOGLE_CLIENT_ID: 'cid', GOOGLE_CLIENT_SECRET: 'csec' } as Env;

  beforeEach(async () => {
    db = createTestDb();
    await db.insert(connectedAccounts).values({
      id: 'acc1', userId: 'u1', provider: 'google', email: 'me@x.y',
      accessTokenEnc: await encryptToken('old-at', 'test-secret'),
      refreshTokenEnc: await encryptToken('the-rt', 'test-secret'),
      tokenExpiresAt: Date.now() + 3600_000, status: 'active', createdAt: 1, updatedAt: 1,
    });
  });

  it('returns the stored token while fresh', async () => {
    expect(await freshAccessToken(db, env, 'acc1')).toBe('old-at');
  });

  it('refreshes an expired token and persists it encrypted', async () => {
    await db.update(connectedAccounts).set({ tokenExpiresAt: Date.now() - 1000 }).where(eq(connectedAccounts.id, 'acc1'));
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ access_token: 'new-at', expires_in: 3600 })));
    expect(await freshAccessToken(db, env, 'acc1')).toBe('new-at');
    const [acc] = await db.select().from(connectedAccounts).where(eq(connectedAccounts.id, 'acc1'));
    expect(await decryptToken(acc.accessTokenEnc, 'test-secret')).toBe('new-at');
    expect(acc.tokenExpiresAt).toBeGreaterThan(Date.now());
  });

  it('marks the account errored when refresh fails', async () => {
    await db.update(connectedAccounts).set({ tokenExpiresAt: 0 }).where(eq(connectedAccounts.id, 'acc1'));
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('bad', { status: 400 })));
    await expect(freshAccessToken(db, env, 'acc1')).rejects.toBeInstanceOf(ProviderApiError);
    const [acc] = await db.select().from(connectedAccounts).where(eq(connectedAccounts.id, 'acc1'));
    expect(acc.status).toBe('error');
    expect(acc.lastError).toBeTruthy();
  });

  it('throws 404 for an unknown account', async () => {
    await expect(freshAccessToken(db, env, 'nope')).rejects.toMatchObject({ status: 404 });
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run worker/__tests__/google-provider.test.ts`
Expected: FAIL — modules not found.

- [ ] **Step 3: Implement google.ts**

`worker/services/providers/google.ts`:

```typescript
/**
 * Google Calendar API v3 client implementing the CalendarProvider contract.
 * Raw fetch, bearer auth via an injected token getter (retry-once on 401).
 */
import {
  googleEventToTranslated, outboundToGoogleBody, dateInZone,
  type GoogleApiEvent,
} from './google-translate';
import {
  ProviderApiError,
  type CalendarProvider, type ChangeSet, type OutboundEvent,
  type ProviderCalendar, type TranslatedEvent, type WatchInfo,
} from './types';

const API_BASE = 'https://www.googleapis.com/calendar/v3';
const PAGE_SIZE = '250';
const HEX_COLOR_RE = /^#[0-9a-fA-F]{6}$/;

type GetToken = (forceRefresh?: boolean) => Promise<string>;

export function createGoogleProvider(getToken: GetToken): CalendarProvider {
  async function call(path: string, init: RequestInit = {}, retried = false): Promise<Response> {
    const token = await getToken(retried || undefined);
    const res = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...(init.headers ?? {}) },
    });
    if (res.status === 401 && !retried) return call(path, init, true);
    return res;
  }

  async function callJson<T>(path: string, init: RequestInit = {}): Promise<T> {
    const res = await call(path, init);
    if (!res.ok) {
      const body = await res.text();
      throw new ProviderApiError(
        `Google API ${init.method ?? 'GET'} ${path.split('?')[0]} failed: ${res.status} ${body.slice(0, 300)}`,
        res.status,
      );
    }
    return res.json() as Promise<T>;
  }

  function translated(g: GoogleApiEvent): TranslatedEvent {
    const t = googleEventToTranslated(g);
    if (!t) throw new ProviderApiError('Google returned an unmappable event', 502);
    return t;
  }

  return {
    async listCalendars(): Promise<ProviderCalendar[]> {
      const out: ProviderCalendar[] = [];
      let pageToken: string | undefined;
      do {
        const qs = new URLSearchParams({ maxResults: PAGE_SIZE });
        if (pageToken) qs.set('pageToken', pageToken);
        const data = await callJson<{
          items?: { id: string; summary?: string; primary?: boolean; backgroundColor?: string }[];
          nextPageToken?: string;
        }>(`/users/me/calendarList?${qs}`);
        for (const item of data.items ?? []) {
          out.push({
            externalId: item.id,
            name: item.summary ?? item.id,
            color: item.backgroundColor && HEX_COLOR_RE.test(item.backgroundColor) ? item.backgroundColor : null,
            isPrimary: item.primary === true,
          });
        }
        pageToken = data.nextPageToken;
      } while (pageToken);
      return out;
    },

    async listChanges(calendarExternalId: string, syncToken: string | null): Promise<ChangeSet> {
      const events: TranslatedEvent[] = [];
      let pageToken: string | undefined;
      let nextSyncToken: string | null = null;
      do {
        const qs = new URLSearchParams({ maxResults: PAGE_SIZE, showDeleted: 'true' });
        if (syncToken) qs.set('syncToken', syncToken);
        if (pageToken) qs.set('pageToken', pageToken);
        const res = await call(`/calendars/${encodeURIComponent(calendarExternalId)}/events?${qs}`);
        if (res.status === 410) return { events: [], nextSyncToken: null, fullResyncRequired: true };
        if (!res.ok) {
          throw new ProviderApiError(`Google events.list failed: ${res.status} ${(await res.text()).slice(0, 300)}`, res.status);
        }
        const data = (await res.json()) as { items?: GoogleApiEvent[]; nextPageToken?: string; nextSyncToken?: string };
        for (const item of data.items ?? []) {
          const t = googleEventToTranslated(item);
          if (t) events.push(t);
        }
        pageToken = data.nextPageToken;
        nextSyncToken = data.nextSyncToken ?? nextSyncToken;
      } while (pageToken);
      return { events, nextSyncToken, fullResyncRequired: false };
    },

    async createEvent(calendarExternalId, event: OutboundEvent) {
      const g = await callJson<GoogleApiEvent>(
        `/calendars/${encodeURIComponent(calendarExternalId)}/events`,
        { method: 'POST', body: JSON.stringify(outboundToGoogleBody(event)) },
      );
      return translated(g);
    },

    async updateEvent(calendarExternalId, externalId, event: OutboundEvent) {
      const g = await callJson<GoogleApiEvent>(
        `/calendars/${encodeURIComponent(calendarExternalId)}/events/${encodeURIComponent(externalId)}`,
        { method: 'PATCH', body: JSON.stringify(outboundToGoogleBody(event)) },
      );
      return translated(g);
    },

    async deleteEvent(calendarExternalId, externalId) {
      const res = await call(
        `/calendars/${encodeURIComponent(calendarExternalId)}/events/${encodeURIComponent(externalId)}`,
        { method: 'DELETE' },
      );
      // 404/410 = already gone on Google's side — that's the state we wanted.
      if (!res.ok && res.status !== 404 && res.status !== 410) {
        throw new ProviderApiError(`Google events.delete failed: ${res.status}`, res.status);
      }
    },

    async getInstanceExternalId(calendarExternalId, masterExternalId, originalStartUtcMs, timezone, allDay) {
      const originalStart = allDay
        ? dateInZone(originalStartUtcMs, timezone)
        : new Date(originalStartUtcMs).toISOString();
      const qs = new URLSearchParams({ originalStart, showDeleted: 'true' });
      const data = await callJson<{ items?: { id: string }[] }>(
        `/calendars/${encodeURIComponent(calendarExternalId)}/events/${encodeURIComponent(masterExternalId)}/instances?${qs}`,
      );
      const instance = data.items?.[0];
      if (!instance) throw new ProviderApiError('No Google instance at that start time', 404);
      return instance.id;
    },

    async watch(calendarExternalId, channelId, token, address): Promise<WatchInfo> {
      const data = await callJson<{ id: string; resourceId: string; expiration?: string }>(
        `/calendars/${encodeURIComponent(calendarExternalId)}/events/watch`,
        { method: 'POST', body: JSON.stringify({ id: channelId, type: 'web_hook', address, token }) },
      );
      return { channelId: data.id, resourceId: data.resourceId, expiresAt: Number(data.expiration ?? 0) };
    },

    async stopWatch(channelId, resourceId) {
      const res = await call('/channels/stop', {
        method: 'POST', body: JSON.stringify({ id: channelId, resourceId }),
      });
      if (!res.ok && res.status !== 404) {
        console.warn(`[calendar] channels.stop returned ${res.status} (best-effort, continuing)`);
      }
    },
  };
}
```

Note: `/channels/stop` is NOT under `/calendar/v3`? It is: `https://www.googleapis.com/calendar/v3/channels/stop` — the shared base is correct.

- [ ] **Step 4: Extend Env (needed by accounts.ts), then implement accounts.ts**

In `worker-configuration.d.ts`, extend the interface (full new content):

```typescript
// Generated by Wrangler
interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  /** JWT secret shared with eldrin-core for token verification */
  JWT_SECRET: string;
  /** Google OAuth client (Calendar scopes) — same Cloud Console client as eldrin-email */
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  /** 'true' enables Google watch-channel registration (prod only; dev uses cron/manual sync) */
  WEBHOOKS_ENABLED?: string;
  /** Public https origin for webhook callbacks, e.g. https://calendar.example.com */
  PUBLIC_URL?: string;
}
```

`worker/services/accounts.ts`:

```typescript
/**
 * Connected-account token lifecycle: decrypt, refresh-before-expiry, persist.
 * Provider factories bind a CalendarProvider to an account's token stream.
 */
import { eq } from 'drizzle-orm';
import type { CalendarRow, Database } from '../db';
import { connectedAccounts } from '../db';
import { decryptToken, encryptToken } from './crypto';
import { refreshGoogleToken } from './oauth-google';
import { createGoogleProvider } from './providers/google';
import { ProviderApiError, type CalendarProvider } from './providers/types';
import { now } from '../utils';

const EXPIRY_MARGIN_MS = 60_000;

export async function freshAccessToken(
  db: Database,
  env: Env,
  accountId: string,
  force = false,
): Promise<string> {
  const [acc] = await db.select().from(connectedAccounts).where(eq(connectedAccounts.id, accountId));
  if (!acc) throw new ProviderApiError('Connected account not found', 404);
  if (!force && acc.tokenExpiresAt > now() + EXPIRY_MARGIN_MS) {
    return decryptToken(acc.accessTokenEnc, env.JWT_SECRET);
  }
  try {
    const refreshToken = await decryptToken(acc.refreshTokenEnc, env.JWT_SECRET);
    const fresh = await refreshGoogleToken(refreshToken, env.GOOGLE_CLIENT_ID, env.GOOGLE_CLIENT_SECRET);
    const ts = now();
    await db.update(connectedAccounts).set({
      accessTokenEnc: await encryptToken(fresh.accessToken, env.JWT_SECRET),
      tokenExpiresAt: ts + fresh.expiresIn * 1000,
      status: 'active',
      lastError: null,
      updatedAt: ts,
    }).where(eq(connectedAccounts.id, acc.id));
    return fresh.accessToken;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[calendar] token refresh failed for account ${acc.id}: ${message}`);
    await db.update(connectedAccounts).set({
      status: 'error', lastError: message, updatedAt: now(),
    }).where(eq(connectedAccounts.id, acc.id));
    throw new ProviderApiError('Google token refresh failed — reconnect the account', 401);
  }
}

export function providerForAccount(db: Database, env: Env, accountId: string): CalendarProvider {
  return createGoogleProvider((force) => freshAccessToken(db, env, accountId, force === true));
}

export async function providerForCalendar(db: Database, env: Env, cal: CalendarRow): Promise<CalendarProvider> {
  if (cal.provider !== 'google' || !cal.accountId) {
    throw new ProviderApiError('Not a Google-synced calendar', 400);
  }
  return providerForAccount(db, env, cal.accountId);
}
```

- [ ] **Step 5: Run tests + typecheck, then commit**

Run: `npx vitest run && npx tsc -b`
Expected: all PASS.

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar commit -m "feat: Google Calendar API client + account token service (Slice 4b Task 4)"
```

---

### Task 5: Sync orchestration

**Files:**
- Create: `eldrin-calendar/worker/services/sync.ts`
- Test: `eldrin-calendar/worker/__tests__/sync-service.test.ts`

**Interfaces:**
- Consumes: Task 3/4 types + factories, existing `event-emitter.ts` (`buildEventPayload`, `emitCalendarEventCreated/Updated/Deleted`), existing tables.
- Produces: `syncCalendar(db, env, provider: CalendarProvider, cal: CalendarRow): Promise<SyncResult>` with `SyncResult {calendarId: string, applied: number, removed: number, error: string | null}`; `syncAllForUser(db, env, userId): Promise<SyncResult[]>`; `reconcileAll(db, env): Promise<SyncResult[]>`; `channelTokenFor(calendarId: string, secret: string): Promise<string>` (HMAC-SHA256 hex).
- Error policy: `syncCalendar` NEVER throws — failures are logged, persisted to `sync_status='error'`/`sync_error`, and returned in `SyncResult.error`.

- [ ] **Step 1: Write failing tests**

`worker/__tests__/sync-service.test.ts`:

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createTestDb } from './test-db';
import type { Database } from '../db';
import { calendars, events, eventAttendees } from '../db';
import { and, eq } from 'drizzle-orm';
import { syncCalendar, channelTokenFor } from '../services/sync';
import type { CalendarProvider, ChangeSet, TranslatedEvent } from '../services/providers/types';

vi.mock('../services/event-emitter', async (importOriginal) => {
  const mod = await importOriginal<typeof import('../services/event-emitter')>();
  return {
    ...mod,
    emitCalendarEventCreated: vi.fn().mockResolvedValue(undefined),
    emitCalendarEventUpdated: vi.fn().mockResolvedValue(undefined),
    emitCalendarEventDeleted: vi.fn().mockResolvedValue(undefined),
  };
});
import * as emitter from '../services/event-emitter';

const env = { JWT_SECRET: 'test-secret' } as Env;
const T0 = Date.UTC(2026, 6, 6, 9, 0, 0);
const HOUR = 3600000;

function translatedEvent(overrides: Partial<TranslatedEvent>): TranslatedEvent {
  return {
    externalId: 'ext-1', status: 'confirmed', title: 'Imported',
    description: null, location: null,
    startAt: T0, endAt: T0 + HOUR, allDay: false, timezone: 'UTC',
    recurrenceRule: null, recurringExternalId: null, originalStartTime: null,
    attendees: [], ...overrides,
  };
}

/** Fake provider returning queued ChangeSets; records listChanges calls. */
function fakeProvider(changeSets: ChangeSet[]) {
  const calls: (string | null)[] = [];
  const provider = {
    listChanges: vi.fn(async (_cal: string, token: string | null) => {
      calls.push(token);
      const next = changeSets.shift();
      if (!next) throw new Error('no more change sets queued');
      return next;
    }),
  } as unknown as CalendarProvider;
  return { provider, calls };
}

describe('syncCalendar', () => {
  let db: Database;
  const CAL = {
    id: 'cal-g', name: 'Google Work', color: '#112233', ownerId: 'u1', isDefault: false,
    provider: 'google', externalId: 'gcal-ext', accountId: 'acc1',
  };

  beforeEach(async () => {
    db = createTestDb();
    vi.clearAllMocks();
    await db.insert(calendars).values({ ...CAL, createdAt: 1, updatedAt: 1 });
  });

  async function calRow() {
    const [row] = await db.select().from(calendars).where(eq(calendars.id, 'cal-g'));
    return row;
  }

  it('applies inserts, stores the sync token, marks ok, emits created', async () => {
    const { provider, calls } = fakeProvider([{
      events: [
        translatedEvent({ externalId: 'e1', title: 'A' }),
        translatedEvent({
          externalId: 'e2', title: 'Weekly', recurrenceRule: 'FREQ=WEEKLY;BYDAY=MO',
          attendees: [{ email: 'a@b.c', displayName: 'Al' }],
        }),
      ],
      nextSyncToken: 'tok-1', fullResyncRequired: false,
    }]);
    const result = await syncCalendar(db, env, provider, await calRow());
    expect(result).toEqual({ calendarId: 'cal-g', applied: 2, removed: 0, error: null });
    expect(calls).toEqual([null]);
    const rows = await db.select().from(events);
    expect(rows).toHaveLength(2);
    const weekly = rows.find((r) => r.externalId === 'e2')!;
    expect(weekly.recurrenceRule).toBe('FREQ=WEEKLY;BYDAY=MO');
    expect(weekly.createdBy).toBe('u1');
    const att = await db.select().from(eventAttendees).where(eq(eventAttendees.eventId, weekly.id));
    expect(att).toHaveLength(1);
    const cal = await calRow();
    expect(cal.syncToken).toBe('tok-1');
    expect(cal.syncStatus).toBe('ok');
    expect(cal.lastSyncedAt).toBeGreaterThan(0);
    expect(emitter.emitCalendarEventCreated).toHaveBeenCalledTimes(2);
  });

  it('passes the stored sync token on incremental runs and updates in place', async () => {
    const first = fakeProvider([{ events: [translatedEvent({ externalId: 'e1', title: 'Old' })], nextSyncToken: 't1', fullResyncRequired: false }]);
    await syncCalendar(db, env, first.provider, await calRow());
    const second = fakeProvider([{ events: [translatedEvent({ externalId: 'e1', title: 'New name' })], nextSyncToken: 't2', fullResyncRequired: false }]);
    const result = await syncCalendar(db, env, second.provider, await calRow());
    expect(second.calls).toEqual(['t1']);
    expect(result.applied).toBe(1);
    const rows = await db.select().from(events);
    expect(rows).toHaveLength(1);
    expect(rows[0].title).toBe('New name');
    expect(emitter.emitCalendarEventUpdated).toHaveBeenCalledTimes(1);
    expect((await calRow()).syncToken).toBe('t2');
  });

  it('is idempotent: an identical echo applies without a duplicate emit', async () => {
    const payload = () => ({ events: [translatedEvent({ externalId: 'e1' })], nextSyncToken: 't', fullResyncRequired: false });
    await syncCalendar(db, env, fakeProvider([payload()]).provider, await calRow());
    vi.clearAllMocks();
    await syncCalendar(db, env, fakeProvider([payload()]).provider, await calRow());
    expect(await db.select().from(events)).toHaveLength(1);
    expect(emitter.emitCalendarEventCreated).not.toHaveBeenCalled();
    expect(emitter.emitCalendarEventUpdated).not.toHaveBeenCalled();
  });

  it('performs a full resync on 410: wipes local rows and refetches', async () => {
    await syncCalendar(db, env, fakeProvider([{ events: [translatedEvent({ externalId: 'stale' })], nextSyncToken: 't1', fullResyncRequired: false }]).provider, await calRow());
    const { provider, calls } = fakeProvider([
      { events: [], nextSyncToken: null, fullResyncRequired: true },
      { events: [translatedEvent({ externalId: 'fresh' })], nextSyncToken: 't2', fullResyncRequired: false },
    ]);
    const result = await syncCalendar(db, env, provider, await calRow());
    expect(calls).toEqual(['t1', null]);
    expect(result.error).toBeNull();
    const rows = await db.select().from(events);
    expect(rows).toHaveLength(1);
    expect(rows[0].externalId).toBe('fresh');
  });

  it('links exception rows to their local master even when listed first (two passes)', async () => {
    const { provider } = fakeProvider([{
      events: [
        translatedEvent({
          externalId: 'm1_inst', recurringExternalId: 'm1',
          originalStartTime: T0 + 7 * 24 * HOUR, startAt: T0 + 7 * 24 * HOUR + 2 * HOUR, endAt: T0 + 7 * 24 * HOUR + 3 * HOUR,
        }),
        translatedEvent({ externalId: 'm1', title: 'Series', recurrenceRule: 'FREQ=WEEKLY;BYDAY=MO' }),
      ],
      nextSyncToken: 't', fullResyncRequired: false,
    }]);
    await syncCalendar(db, env, provider, await calRow());
    const master = (await db.select().from(events).where(eq(events.externalId, 'm1')))[0];
    const [exc] = await db.select().from(events).where(eq(events.externalId, 'm1_inst'));
    expect(exc.recurringEventId).toBe(master.id);
    expect(exc.originalStartTime).toBe(T0 + 7 * 24 * HOUR);
    expect(exc.recurrenceRule).toBeNull();
  });

  it('applies cancelled instances as cancelled exception rows', async () => {
    await syncCalendar(db, env, fakeProvider([{
      events: [translatedEvent({ externalId: 'm1', title: 'Series', recurrenceRule: 'FREQ=WEEKLY;BYDAY=MO' })],
      nextSyncToken: 't1', fullResyncRequired: false,
    }]).provider, await calRow());
    const result = await syncCalendar(db, env, fakeProvider([{
      events: [translatedEvent({
        externalId: 'm1_gone', status: 'cancelled', recurringExternalId: 'm1',
        originalStartTime: T0 + 14 * 24 * HOUR, startAt: null, endAt: null,
      })],
      nextSyncToken: 't2', fullResyncRequired: false,
    }]).provider, await calRow());
    expect(result.removed).toBe(1);
    const [exc] = await db.select().from(events).where(eq(events.externalId, 'm1_gone'));
    expect(exc.status).toBe('cancelled');
    expect(exc.recurringEventId).toBeTruthy();
    expect(emitter.emitCalendarEventDeleted).toHaveBeenCalledTimes(1);
  });

  it('deletes local rows for cancelled parents and emits deleted', async () => {
    await syncCalendar(db, env, fakeProvider([{
      events: [translatedEvent({ externalId: 'e1' })], nextSyncToken: 't1', fullResyncRequired: false,
    }]).provider, await calRow());
    const result = await syncCalendar(db, env, fakeProvider([{
      events: [translatedEvent({ externalId: 'e1', status: 'cancelled', startAt: null, endAt: null })],
      nextSyncToken: 't2', fullResyncRequired: false,
    }]).provider, await calRow());
    expect(result.removed).toBe(1);
    expect(await db.select().from(events)).toHaveLength(0);
    expect(emitter.emitCalendarEventDeleted).toHaveBeenCalledTimes(1);
  });

  it('skips exceptions whose master never synced, with a warning', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const result = await syncCalendar(db, env, fakeProvider([{
      events: [translatedEvent({ externalId: 'orphan', recurringExternalId: 'missing', originalStartTime: T0 })],
      nextSyncToken: 't', fullResyncRequired: false,
    }]).provider, await calRow());
    expect(result.applied).toBe(0);
    expect(warn).toHaveBeenCalled();
  });

  it('records provider failures on the calendar and returns them (never throws)', async () => {
    const provider = {
      listChanges: vi.fn().mockRejectedValue(new Error('boom')),
    } as unknown as CalendarProvider;
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const result = await syncCalendar(db, env, provider, await calRow());
    expect(result.error).toContain('boom');
    const cal = await calRow();
    expect(cal.syncStatus).toBe('error');
    expect(cal.syncError).toContain('boom');
  });
});

describe('channelTokenFor', () => {
  it('is a deterministic hex HMAC of the calendar id', async () => {
    const a = await channelTokenFor('cal-1', 'secret');
    const b = await channelTokenFor('cal-1', 'secret');
    const c = await channelTokenFor('cal-2', 'secret');
    expect(a).toBe(b);
    expect(a).not.toBe(c);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run worker/__tests__/sync-service.test.ts`
Expected: FAIL — `../services/sync` not found.

- [ ] **Step 3: Implement sync.ts**

`worker/services/sync.ts`:

```typescript
/**
 * Incoming sync orchestration (spec §5, D10/D15): incremental fetch via
 * syncToken, idempotent upsert keyed (calendar_id, external_id), full resync
 * on 410, per-calendar status bookkeeping. syncCalendar NEVER throws — errors
 * are logged, persisted, and returned in the result.
 */
import { and, eq, isNotNull } from 'drizzle-orm';
import type { CalendarRow, Database, EventRow } from '../db';
import { calendars, eventAttendees, events } from '../db';
import { generateId, now } from '../utils';
import {
  buildEventPayload,
  emitCalendarEventCreated,
  emitCalendarEventDeleted,
  emitCalendarEventUpdated,
} from './event-emitter';
import { providerForCalendar } from './accounts';
import type { CalendarProvider, TranslatedEvent } from './providers/types';

export interface SyncResult {
  calendarId: string;
  applied: number;
  removed: number;
  error: string | null;
}

/** HMAC-SHA256 hex of the calendar id — Google watch channel token (spec §5). */
export async function channelTokenFor(calendarId: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(calendarId));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function sameEventData(existing: EventRow, candidate: Omit<EventRow, 'id' | 'createdAt' | 'updatedAt'>): boolean {
  return (
    existing.title === candidate.title &&
    existing.description === candidate.description &&
    existing.location === candidate.location &&
    existing.startAt === candidate.startAt &&
    existing.endAt === candidate.endAt &&
    existing.allDay === candidate.allDay &&
    existing.timezone === candidate.timezone &&
    existing.recurrenceRule === candidate.recurrenceRule &&
    existing.recurringEventId === candidate.recurringEventId &&
    existing.originalStartTime === candidate.originalStartTime &&
    existing.status === candidate.status
  );
}

async function findByExternalId(db: Database, calendarId: string, externalId: string): Promise<EventRow | null> {
  const [row] = await db.select().from(events)
    .where(and(eq(events.calendarId, calendarId), eq(events.externalId, externalId)));
  return row ?? null;
}

async function replaceAttendees(
  db: Database, eventId: string, attendees: { email: string; displayName: string | null }[],
): Promise<void> {
  await db.delete(eventAttendees).where(eq(eventAttendees.eventId, eventId));
  if (attendees.length > 0) {
    await db.insert(eventAttendees).values(
      attendees.map((a) => ({ id: generateId(), eventId, email: a.email, displayName: a.displayName })),
    );
  }
}

type Emit = (p: Promise<unknown>) => void;
const fireAndForget: Emit = (p) => { void p; };

async function upsertRow(
  db: Database, cal: CalendarRow, t: TranslatedEvent,
  masterLocalId: string | null,
): Promise<'created' | 'updated' | 'unchanged'> {
  const ts = now();
  // A locally created exception may predate its Google id — match by slot too.
  const existing =
    (await findByExternalId(db, cal.id, t.externalId)) ??
    (masterLocalId && t.originalStartTime !== null
      ? (await db.select().from(events).where(and(
          eq(events.recurringEventId, masterLocalId),
          eq(events.originalStartTime, t.originalStartTime),
        )))[0] ?? null
      : null);

  const candidate = {
    calendarId: cal.id,
    title: t.title,
    description: t.description,
    location: t.location,
    // Cancelled instances may arrive without times — fall back to the existing
    // slot or the original occurrence start (never rendered: status filters them).
    startAt: t.startAt ?? existing?.startAt ?? t.originalStartTime ?? 0,
    endAt: t.endAt ?? existing?.endAt ?? t.originalStartTime ?? 0,
    allDay: t.allDay,
    timezone: t.timezone,
    recurrenceRule: masterLocalId ? null : t.recurrenceRule,
    recurringEventId: masterLocalId,
    originalStartTime: t.originalStartTime,
    status: t.status,
    externalId: t.externalId,
    createdBy: cal.ownerId,
  };

  if (existing) {
    if (sameEventData(existing, candidate as Omit<EventRow, 'id' | 'createdAt' | 'updatedAt'>)) return 'unchanged';
    await db.update(events).set({ ...candidate, updatedAt: ts }).where(eq(events.id, existing.id));
    await replaceAttendees(db, existing.id, t.attendees);
    return 'updated';
  }
  const row: EventRow = { ...candidate, id: generateId(), createdAt: ts, updatedAt: ts } as EventRow;
  await db.insert(events).values(row);
  await replaceAttendees(db, row.id, t.attendees);
  return 'created';
}

async function applyChanges(
  db: Database, env: Env, cal: CalendarRow, changes: TranslatedEvent[],
): Promise<{ applied: number; removed: number }> {
  let applied = 0;
  let removed = 0;
  const parents = changes.filter((t) => !t.recurringExternalId);
  const exceptions = changes.filter((t) => t.recurringExternalId);

  for (const t of parents) {
    if (t.status === 'cancelled') {
      const existing = await findByExternalId(db, cal.id, t.externalId);
      if (existing) {
        await db.delete(events).where(eq(events.id, existing.id));
        removed++;
        fireAndForget(emitCalendarEventDeleted(env, existing.id, 'all'));
      }
      continue;
    }
    const outcome = await upsertRow(db, cal, t, null);
    if (outcome === 'unchanged') continue;
    applied++;
    const row = (await findByExternalId(db, cal.id, t.externalId))!;
    const payload = buildEventPayload(row, t.attendees);
    fireAndForget(outcome === 'created'
      ? emitCalendarEventCreated(env, payload)
      : emitCalendarEventUpdated(env, payload, 'all'));
  }

  for (const t of exceptions) {
    const master = await findByExternalId(db, cal.id, t.recurringExternalId!);
    if (!master || t.originalStartTime === null) {
      console.warn(`[calendar] skipping Google exception ${t.externalId}: master missing or no originalStartTime`);
      continue;
    }
    const outcome = await upsertRow(db, cal, t, master.id);
    if (outcome === 'unchanged') continue;
    if (t.status === 'cancelled') {
      removed++;
      fireAndForget(emitCalendarEventDeleted(env, master.id, 'single'));
    } else {
      applied++;
      fireAndForget(emitCalendarEventUpdated(env, buildEventPayload(master, t.attendees), 'single'));
    }
  }
  return { applied, removed };
}

export async function syncCalendar(
  db: Database, env: Env, provider: CalendarProvider, cal: CalendarRow,
): Promise<SyncResult> {
  await db.update(calendars).set({ syncStatus: 'syncing', updatedAt: now() }).where(eq(calendars.id, cal.id));
  try {
    let changes = await provider.listChanges(cal.externalId!, cal.syncToken ?? null);
    if (changes.fullResyncRequired) {
      await db.delete(events).where(eq(events.calendarId, cal.id));
      changes = await provider.listChanges(cal.externalId!, null);
    }
    const { applied, removed } = await applyChanges(db, env, cal, changes.events);
    await db.update(calendars).set({
      syncToken: changes.nextSyncToken ?? cal.syncToken,
      lastSyncedAt: now(),
      syncStatus: 'ok',
      syncError: null,
      updatedAt: now(),
    }).where(eq(calendars.id, cal.id));
    return { calendarId: cal.id, applied, removed, error: null };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[calendar] sync failed for calendar ${cal.id}: ${message}`);
    await db.update(calendars).set({
      syncStatus: 'error', syncError: message, updatedAt: now(),
    }).where(eq(calendars.id, cal.id));
    return { calendarId: cal.id, applied: 0, removed: 0, error: message };
  }
}

async function googleCalendars(db: Database): Promise<CalendarRow[]> {
  return db.select().from(calendars)
    .where(and(eq(calendars.provider, 'google'), isNotNull(calendars.accountId)));
}

export async function syncAllForUser(db: Database, env: Env, userId: string): Promise<SyncResult[]> {
  const all = (await googleCalendars(db)).filter((c) => c.ownerId === userId);
  const results: SyncResult[] = [];
  for (const cal of all) {
    try {
      results.push(await syncCalendar(db, env, await providerForCalendar(db, env, cal), cal));
    } catch (err) {
      // providerForCalendar/account failures — record and continue with the rest.
      results.push({ calendarId: cal.id, applied: 0, removed: 0, error: err instanceof Error ? err.message : String(err) });
    }
  }
  return results;
}

export async function reconcileAll(db: Database, env: Env): Promise<SyncResult[]> {
  const all = await googleCalendars(db);
  const results: SyncResult[] = [];
  for (const cal of all) {
    try {
      results.push(await syncCalendar(db, env, await providerForCalendar(db, env, cal), cal));
    } catch (err) {
      results.push({ calendarId: cal.id, applied: 0, removed: 0, error: err instanceof Error ? err.message : String(err) });
    }
  }
  return results;
}
```

Note the `fireAndForget` indirection: emits already never throw (event-emitter contract), and sync may run outside a request context (cron), so we intentionally don't `waitUntil` here — callers that have an execution context wrap the whole `syncCalendar` call instead.

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run worker/__tests__/sync-service.test.ts && npx vitest run && npx tsc -b`
Expected: PASS (new + all existing suites).

- [ ] **Step 5: Commit**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar commit -m "feat: incremental sync orchestration with idempotent upserts (Slice 4b Task 5)"
```

---

### Task 6: OAuth routes, manifest + Env plumbing

**Files:**
- Create: `eldrin-calendar/worker/routes/oauth.ts`
- Modify: `eldrin-calendar/worker/index.ts` (mount `oauthRoutes`)
- Modify: `eldrin-calendar/public/eldrin-app.manifest.json` (publicRoutes, api.routes, settings.groups)
- Modify: `eldrin-calendar/worker-configuration.d.ts` (Env additions)
- Modify: `eldrin-calendar/.dev.vars` (add Google client credentials — NOT committed)
- Test: `eldrin-calendar/worker/__tests__/oauth-routes.test.ts`

**Interfaces:**
- Consumes: Task 1 (`connectedAccounts`, crypto), Task 2 (`getGoogleAuthUrl`, `exchangeGoogleCode`, `getGoogleUserInfo`), `requestUserIdOrNull` from `routes/calendars.ts`.
- Produces: `oauthRoutes` (Hono router) with `POST /api/oauth/google/connect-token` (authed → `{token}`), `GET /api/oauth/google/connect?token=&returnTo=` (public; 302 to Google), `GET /api/oauth/google/callback?code=&state=` (public; upserts account, 302 back to `returnTo` with `?connected=google` or `?connect_error=...`).
- Flow (spec §5): the SPA can't attach auth headers to a top-level navigation, so it first POSTs for a short-lived encrypted connect token (eldrin-email pattern), then navigates to the public connect route.

- [ ] **Step 1: Write failing route tests**

`worker/__tests__/oauth-routes.test.ts`:

```typescript
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Hono } from 'hono';
import { createTestDb } from './test-db';
import type { Database } from '../db';
import { connectedAccounts } from '../db';
import { oauthRoutes } from '../routes/oauth';
import { encryptToken, decryptToken } from '../services/crypto';

afterEach(() => vi.unstubAllGlobals());

const mockEnv = {
  JWT_SECRET: 'test-secret',
  GOOGLE_CLIENT_ID: 'cid.apps.googleusercontent.com',
  GOOGLE_CLIENT_SECRET: 'csec',
} as Env;

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

function createApp(db: Database) {
  const app = new Hono<{ Bindings: Env; Variables: { db: Database } }>();
  app.use('*', async (c, next) => { c.set('db', db); await next(); });
  app.route('', oauthRoutes);
  return app;
}

async function mintConnectToken(app: ReturnType<typeof createApp>) {
  const res = await app.request('/api/oauth/google/connect-token', {
    method: 'POST', headers: { 'x-eldrin-user-id': 'u1' },
  }, mockEnv);
  return ((await res.json()) as { token: string }).token;
}

describe('POST /api/oauth/google/connect-token', () => {
  it('mints a decryptable token carrying the user', async () => {
    const app = createApp(createTestDb());
    const token = await mintConnectToken(app);
    const payload = JSON.parse(await decryptToken(token, 'test-secret'));
    expect(payload.userId).toBe('u1');
    expect(payload.expiresAt).toBeGreaterThan(Date.now());
  });

  it('rejects requests without a user', async () => {
    const app = createApp(createTestDb());
    const res = await app.request('/api/oauth/google/connect-token', { method: 'POST' }, mockEnv);
    expect(res.status).toBe(401);
  });
});

describe('GET /api/oauth/google/connect', () => {
  it('redirects to Google consent carrying state with userId and returnTo', async () => {
    const app = createApp(createTestDb());
    const token = await mintConnectToken(app);
    const res = await app.request(
      `/api/oauth/google/connect?token=${encodeURIComponent(token)}&returnTo=${encodeURIComponent('http://localhost:4000/eldrin-calendar/settings')}`,
      {}, mockEnv,
    );
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get('Location')!);
    expect(loc.host).toBe('accounts.google.com');
    const state = JSON.parse(atob(loc.searchParams.get('state')!));
    expect(state.userId).toBe('u1');
    expect(state.returnTo).toBe('http://localhost:4000/eldrin-calendar/settings');
  });

  it('rejects a missing/expired token', async () => {
    const app = createApp(createTestDb());
    expect((await app.request('/api/oauth/google/connect', {}, mockEnv)).status).toBe(400);
    const stale = await encryptToken(JSON.stringify({ userId: 'u1', expiresAt: Date.now() - 1 }), 'test-secret');
    const res = await app.request(`/api/oauth/google/connect?token=${encodeURIComponent(stale)}&returnTo=http%3A%2F%2Fx`, {}, mockEnv);
    expect(res.status).toBe(401);
  });

  it('rejects a non-http returnTo', async () => {
    const app = createApp(createTestDb());
    const token = await mintConnectToken(app);
    const res = await app.request(
      `/api/oauth/google/connect?token=${encodeURIComponent(token)}&returnTo=${encodeURIComponent('javascript:alert(1)')}`,
      {}, mockEnv,
    );
    expect(res.status).toBe(400);
  });
});

describe('GET /api/oauth/google/callback', () => {
  const state = () => btoa(JSON.stringify({
    userId: 'u1', returnTo: 'http://localhost:4000/eldrin-calendar/settings', ts: Date.now(),
  }));

  it('exchanges the code, stores the encrypted account, redirects to returnTo', async () => {
    const db = createTestDb();
    const app = createApp(db);
    vi.stubGlobal('fetch', vi.fn()
      .mockResolvedValueOnce(json({ access_token: 'at', refresh_token: 'rt', expires_in: 3600 })) // token exchange
      .mockResolvedValueOnce(json({ email: 'me@gmail.com', name: 'Me' })));                        // userinfo
    const res = await app.request(`/api/oauth/google/callback?code=c0de&state=${encodeURIComponent(state())}`, {}, mockEnv);
    expect(res.status).toBe(302);
    expect(res.headers.get('Location')).toBe('http://localhost:4000/eldrin-calendar/settings?connected=google');
    const [acc] = await db.select().from(connectedAccounts);
    expect(acc.userId).toBe('u1');
    expect(acc.email).toBe('me@gmail.com');
    expect(acc.accessTokenEnc).not.toContain('at');
    expect(await decryptToken(acc.refreshTokenEnc, 'test-secret')).toBe('rt');
  });

  it('re-connecting the same account updates tokens instead of duplicating', async () => {
    const db = createTestDb();
    const app = createApp(db);
    for (const tokens of [{ access_token: 'a1', refresh_token: 'r1', expires_in: 1 }, { access_token: 'a2', refresh_token: 'r2', expires_in: 1 }]) {
      vi.stubGlobal('fetch', vi.fn()
        .mockResolvedValueOnce(json(tokens))
        .mockResolvedValueOnce(json({ email: 'me@gmail.com', name: 'Me' })));
      await app.request(`/api/oauth/google/callback?code=c&state=${encodeURIComponent(state())}`, {}, mockEnv);
    }
    const accounts = await db.select().from(connectedAccounts);
    expect(accounts).toHaveLength(1);
    expect(await decryptToken(accounts[0].refreshTokenEnc, 'test-secret')).toBe('r2');
  });

  it('redirects with connect_error when the user denied consent', async () => {
    const app = createApp(createTestDb());
    const res = await app.request(`/api/oauth/google/callback?error=access_denied&state=${encodeURIComponent(state())}`, {}, mockEnv);
    expect(res.status).toBe(302);
    expect(res.headers.get('Location')).toContain('connect_error=access_denied');
  });

  it('redirects with connect_error when the exchange fails', async () => {
    const app = createApp(createTestDb());
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('bad', { status: 400 })));
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const res = await app.request(`/api/oauth/google/callback?code=c&state=${encodeURIComponent(state())}`, {}, mockEnv);
    expect(res.status).toBe(302);
    expect(res.headers.get('Location')).toContain('connect_error=');
  });

  it('400s on invalid state', async () => {
    const app = createApp(createTestDb());
    const res = await app.request('/api/oauth/google/callback?code=c&state=%%%', {}, mockEnv);
    expect(res.status).toBe(400);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run worker/__tests__/oauth-routes.test.ts`
Expected: FAIL — `../routes/oauth` not found.

- [ ] **Step 3: Implement routes/oauth.ts**

```typescript
/**
 * Google OAuth connect flow (spec §5). Top-level navigations can't carry auth
 * headers, so the SPA first mints a short-lived encrypted connect token
 * (authed POST), then navigates to the public connect route with it.
 */
import { Hono } from 'hono';
import { and, eq } from 'drizzle-orm';
import type { Database } from '../db';
import { connectedAccounts } from '../db';
import { generateId, now } from '../utils';
import { decryptToken, encryptToken } from '../services/crypto';
import { exchangeGoogleCode, getGoogleAuthUrl, getGoogleUserInfo } from '../services/oauth-google';
import { requestUserIdOrNull } from './calendars';

type Variables = { db: Database; auth?: { userId?: string } };

export const oauthRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

const CONNECT_TOKEN_TTL_MS = 5 * 60 * 1000;
const STATE_TTL_MS = 10 * 60 * 1000;

function isSafeReturnTo(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

function redirectBack(c: { redirect: (url: string) => Response }, returnTo: string, params: Record<string, string>) {
  const url = new URL(returnTo);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  return c.redirect(url.toString());
}

oauthRoutes.post('/api/oauth/google/connect-token', async (c) => {
  const userId = requestUserIdOrNull(c);
  if (!userId) return c.json({ error: 'Unauthorized' }, 401);
  const payload = JSON.stringify({ userId, expiresAt: now() + CONNECT_TOKEN_TTL_MS });
  return c.json({ token: await encryptToken(payload, c.env.JWT_SECRET) });
});

oauthRoutes.get('/api/oauth/google/connect', async (c) => {
  const token = c.req.query('token');
  const returnTo = c.req.query('returnTo');
  if (!token || !returnTo) return c.json({ error: 'token and returnTo are required' }, 400);
  if (!isSafeReturnTo(returnTo)) return c.json({ error: 'returnTo must be an http(s) URL' }, 400);

  let userId: string;
  try {
    const payload = JSON.parse(await decryptToken(token, c.env.JWT_SECRET)) as { userId: string; expiresAt: number };
    if (payload.expiresAt < now()) return c.json({ error: 'Connect token expired' }, 401);
    userId = payload.userId;
  } catch {
    return c.json({ error: 'Invalid connect token' }, 401);
  }

  const redirectUri = new URL('/api/oauth/google/callback', c.req.url).toString();
  const state = btoa(JSON.stringify({ userId, returnTo, ts: now() }));
  return c.redirect(getGoogleAuthUrl(c.env.GOOGLE_CLIENT_ID, redirectUri, state));
});

oauthRoutes.get('/api/oauth/google/callback', async (c) => {
  const stateRaw = c.req.query('state');
  let state: { userId: string; returnTo: string; ts: number };
  try {
    state = JSON.parse(atob(stateRaw ?? ''));
    if (!state.userId || !isSafeReturnTo(state.returnTo)) throw new Error('bad state');
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

  const redirectUri = new URL('/api/oauth/google/callback', c.req.url);
  redirectUri.search = '';

  try {
    const tokens = await exchangeGoogleCode(code, c.env.GOOGLE_CLIENT_ID, c.env.GOOGLE_CLIENT_SECRET, redirectUri.toString());
    const userInfo = await getGoogleUserInfo(tokens.accessToken);
    const [accessTokenEnc, refreshTokenEnc] = await Promise.all([
      encryptToken(tokens.accessToken, c.env.JWT_SECRET),
      encryptToken(tokens.refreshToken, c.env.JWT_SECRET),
    ]);
    const db = c.get('db');
    const ts = now();
    const [existing] = await db.select().from(connectedAccounts).where(and(
      eq(connectedAccounts.userId, state.userId),
      eq(connectedAccounts.provider, 'google'),
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
        id: generateId(), userId: state.userId, provider: 'google', email: userInfo.email,
        accessTokenEnc, refreshTokenEnc, tokenExpiresAt: ts + tokens.expiresIn * 1000,
        status: 'active', createdAt: ts, updatedAt: ts,
      });
    }
    return redirectBack(c, state.returnTo, { connected: 'google' });
  } catch (err) {
    console.error('[calendar] Google OAuth callback error:', err);
    return redirectBack(c, state.returnTo, { connect_error: 'exchange_failed' });
  }
});
```

- [ ] **Step 4: Mount the router and extend Env + manifest + .dev.vars**

In `worker/index.ts`, import and mount before the calendar routes:

```typescript
import { oauthRoutes } from './routes/oauth';
// ... after app.route('', calendarRoutes); is fine too — order doesn't matter here:
app.route('', oauthRoutes);
```

(`worker-configuration.d.ts` was already extended in Task 4 Step 4.)

In `public/eldrin-app.manifest.json`:
- `api.publicRoutes` becomes `["/health", "/oauth/google/connect", "/oauth/google/callback", "/sync/notify/google"]` (paths are `/api`-relative).
- Append to `api.routes`: `{ "method": "POST", "path": "/api/oauth/google/connect-token", "permission": "calendar:update" }`.
- Add a top-level `settings` block (same shape as eldrin-email's):

```json
"settings": {
  "groups": [
    {
      "key": "GOOGLE",
      "label": "Google OAuth",
      "description": "OAuth 2.0 credentials for Google Calendar sync",
      "fields": [
        { "key": "CLIENT_ID", "label": "Client ID", "type": "string", "storage": "config", "required": true, "description": "Google OAuth 2.0 Client ID", "placeholder": "123456789.apps.googleusercontent.com" },
        { "key": "CLIENT_SECRET", "label": "Client Secret", "type": "string", "storage": "secret", "required": true, "description": "Google OAuth 2.0 Client Secret" }
      ]
    }
  ]
}
```

Append to `.dev.vars` (values copied from `eldrin-email/.dev.vars` — do NOT commit this file; verify it is in `.gitignore`):

```
GOOGLE_CLIENT_ID=<copy from eldrin-email/.dev.vars>
GOOGLE_CLIENT_SECRET=<copy from eldrin-email/.dev.vars>
```

- [ ] **Step 5: Run tests + typecheck, then commit**

Run: `npx vitest run && npx tsc -b`
Expected: all PASS. Confirm `git status` does NOT list `.dev.vars`.

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar commit -m "feat: Google OAuth connect/callback routes + manifest settings (Slice 4b Task 6)"
```

---

### Task 7: Accounts + sync API routes

**Files:**
- Create: `eldrin-calendar/worker/routes/sync.ts`
- Modify: `eldrin-calendar/worker/index.ts` (mount `syncRoutes`)
- Modify: `eldrin-calendar/public/eldrin-app.manifest.json` (api.routes additions)
- Test: `eldrin-calendar/worker/__tests__/sync-routes.test.ts`

**Interfaces:**
- Consumes: Tasks 1–5 (`connectedAccounts`, `providerForAccount`, `providerForCalendar`, `syncCalendar`, `syncAllForUser`, `channelTokenFor`, `revokeGoogleToken`, `decryptToken`), `requestUserId`/`requestUserIdOrNull` from `routes/calendars.ts`, `DEFAULT_CALENDAR_COLOR`.
- Produces: `syncRoutes` (Hono router):
  - `GET /api/accounts` → `{accounts: [{id, provider, email, status, lastError, calendars: CalendarRow[]}]}`
  - `DELETE /api/accounts/:id` → `{deleted: true}` (best-effort revoke; deletes synced calendars + events)
  - `GET /api/accounts/:id/google-calendars` → `{calendars: [{externalId, name, color, isPrimary, synced}]}`
  - `PUT /api/accounts/:id/calendars` body `{externalIds: string[]}` → `{calendars: CalendarRow[]}` (creates rows `sync_status='syncing'` + kicks initial sync via `waitUntil`; removes deselected)
  - `POST /api/sync/run` → `{results: SyncResult[]}` (synchronous — the UI awaits it)
  - `POST /api/sync/notify/google` (public) → 200; validates `X-Goog-Channel-Token`, `waitUntil`s an incremental sync

- [ ] **Step 1: Write failing route tests**

`worker/__tests__/sync-routes.test.ts` — uses the standard harness plus a mock of the sync service and accounts factory so route logic is tested in isolation (the service itself was tested in Task 5):

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Hono } from 'hono';
import { createTestDb } from './test-db';
import type { Database } from '../db';
import { calendars, connectedAccounts, events } from '../db';
import { eq } from 'drizzle-orm';
import { syncRoutes } from '../routes/sync';
import { channelTokenFor } from '../services/sync';

const listCalendarsMock = vi.fn();
vi.mock('../services/accounts', () => ({
  providerForAccount: vi.fn(() => ({ listCalendars: listCalendarsMock })),
  providerForCalendar: vi.fn(async () => ({})),
}));
vi.mock('../services/oauth-google', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../services/oauth-google')>()),
  revokeGoogleToken: vi.fn().mockResolvedValue(undefined),
}));
const syncCalendarMock = vi.fn(async (_db, _env, _p, cal) => ({ calendarId: cal.id, applied: 1, removed: 0, error: null }));
const syncAllForUserMock = vi.fn(async () => [{ calendarId: 'g1', applied: 1, removed: 0, error: null }]);
// NOTE: syncAllForUser must be mocked directly — its real implementation calls the
// module-internal syncCalendar, which a mock of the export would NOT intercept.
vi.mock('../services/sync', async (importOriginal) => {
  const mod = await importOriginal<typeof import('../services/sync')>();
  return {
    ...mod,
    syncCalendar: (...args: Parameters<typeof mod.syncCalendar>) => syncCalendarMock(...args),
    syncAllForUser: (...args: Parameters<typeof mod.syncAllForUser>) => syncAllForUserMock(...args),
  };
});

const mockEnv = { JWT_SECRET: 'test-secret', GOOGLE_CLIENT_ID: 'cid', GOOGLE_CLIENT_SECRET: 'cs' } as Env;
const waited: Promise<unknown>[] = [];
const mockExecutionCtx = {
  waitUntil: (p: Promise<unknown>) => { waited.push(p); },
  passThroughOnException: () => {}, props: {},
} as unknown as ExecutionContext;

function createApp(db: Database) {
  const app = new Hono<{ Bindings: Env; Variables: { db: Database } }>();
  app.use('*', async (c, next) => { c.set('db', db); await next(); });
  app.route('', syncRoutes);
  return app;
}

const authed = { 'x-eldrin-user-id': 'u1', 'Content-Type': 'application/json' };

describe('accounts + sync routes', () => {
  let db: Database;
  let app: ReturnType<typeof createApp>;

  beforeEach(async () => {
    db = createTestDb();
    app = createApp(db);
    waited.length = 0;
    vi.clearAllMocks();
    await db.insert(connectedAccounts).values({
      id: 'acc1', userId: 'u1', provider: 'google', email: 'me@gmail.com',
      accessTokenEnc: 'enc-a', refreshTokenEnc: 'enc-r', tokenExpiresAt: 1,
      status: 'active', createdAt: 1, updatedAt: 1,
    });
  });

  it('GET /api/accounts lists the user accounts with their synced calendars', async () => {
    await db.insert(calendars).values({
      id: 'g1', name: 'Work', color: '#112233', ownerId: 'u1', isDefault: false,
      provider: 'google', externalId: 'ext-1', accountId: 'acc1', syncStatus: 'ok',
      createdAt: 1, updatedAt: 1,
    });
    const res = await app.request('/api/accounts', { headers: authed }, mockEnv, mockExecutionCtx);
    expect(res.status).toBe(200);
    const body = await res.json() as { accounts: { id: string; email: string; calendars: { id: string }[] }[] };
    expect(body.accounts).toHaveLength(1);
    expect(body.accounts[0].email).toBe('me@gmail.com');
    expect(body.accounts[0].calendars.map((c) => c.id)).toEqual(['g1']);
    expect(JSON.stringify(body)).not.toContain('enc-a'); // tokens never leave the worker
  });

  it("GET /api/accounts hides other users' accounts", async () => {
    const res = await app.request('/api/accounts', { headers: { 'x-eldrin-user-id': 'other' } }, mockEnv, mockExecutionCtx);
    expect(((await res.json()) as { accounts: unknown[] }).accounts).toHaveLength(0);
  });

  it('GET /api/accounts/:id/google-calendars merges live list with synced flags', async () => {
    listCalendarsMock.mockResolvedValue([
      { externalId: 'ext-1', name: 'Work', color: '#a1b2c3', isPrimary: true },
      { externalId: 'ext-2', name: 'Family', color: null, isPrimary: false },
    ]);
    await db.insert(calendars).values({
      id: 'g1', name: 'Work', color: '#112233', ownerId: 'u1', isDefault: false,
      provider: 'google', externalId: 'ext-1', accountId: 'acc1', createdAt: 1, updatedAt: 1,
    });
    const res = await app.request('/api/accounts/acc1/google-calendars', { headers: authed }, mockEnv, mockExecutionCtx);
    const body = await res.json() as { calendars: { externalId: string; synced: boolean }[] };
    expect(body.calendars).toEqual([
      { externalId: 'ext-1', name: 'Work', color: '#a1b2c3', isPrimary: true, synced: true },
      { externalId: 'ext-2', name: 'Family', color: null, isPrimary: false, synced: false },
    ]);
  });

  it('PUT /api/accounts/:id/calendars enables new calendars (syncing + waitUntil) and removes deselected', async () => {
    listCalendarsMock.mockResolvedValue([
      { externalId: 'ext-1', name: 'Work', color: '#a1b2c3', isPrimary: true },
      { externalId: 'ext-2', name: 'Family', color: null, isPrimary: false },
    ]);
    // enable ext-1
    let res = await app.request('/api/accounts/acc1/calendars', {
      method: 'PUT', headers: authed, body: JSON.stringify({ externalIds: ['ext-1'] }),
    }, mockEnv, mockExecutionCtx);
    expect(res.status).toBe(200);
    let rows = await db.select().from(calendars).where(eq(calendars.provider, 'google'));
    expect(rows).toHaveLength(1);
    expect(rows[0].externalId).toBe('ext-1');
    expect(rows[0].name).toBe('Work');
    expect(rows[0].color).toBe('#a1b2c3');
    expect(rows[0].syncStatus).toBe('syncing');
    expect(waited.length).toBeGreaterThan(0); // initial sync kicked off

    // switch selection to ext-2: ext-1 rows (and its events) are removed
    await db.insert(events).values({
      id: 'ev1', calendarId: rows[0].id, title: 'T', startAt: 1, endAt: 2,
      allDay: false, timezone: 'UTC', status: 'confirmed', createdBy: 'u1', createdAt: 1, updatedAt: 1,
    });
    res = await app.request('/api/accounts/acc1/calendars', {
      method: 'PUT', headers: authed, body: JSON.stringify({ externalIds: ['ext-2'] }),
    }, mockEnv, mockExecutionCtx);
    expect(res.status).toBe(200);
    rows = await db.select().from(calendars).where(eq(calendars.provider, 'google'));
    expect(rows.map((r) => r.externalId)).toEqual(['ext-2']);
    expect(await db.select().from(events)).toHaveLength(0); // FK cascade
  });

  it('PUT validates the body', async () => {
    const res = await app.request('/api/accounts/acc1/calendars', {
      method: 'PUT', headers: authed, body: JSON.stringify({ externalIds: 'nope' }),
    }, mockEnv, mockExecutionCtx);
    expect(res.status).toBe(400);
  });

  it('DELETE /api/accounts/:id revokes, removes calendars and the account', async () => {
    await db.insert(calendars).values({
      id: 'g1', name: 'Work', color: '#112233', ownerId: 'u1', isDefault: false,
      provider: 'google', externalId: 'ext-1', accountId: 'acc1', createdAt: 1, updatedAt: 1,
    });
    const res = await app.request('/api/accounts/acc1', { method: 'DELETE', headers: authed }, mockEnv, mockExecutionCtx);
    expect(res.status).toBe(200);
    expect(await db.select().from(connectedAccounts)).toHaveLength(0);
    expect(await db.select().from(calendars).where(eq(calendars.provider, 'google'))).toHaveLength(0);
  });

  it('404s account routes for other users', async () => {
    for (const [path, init] of [
      ['/api/accounts/acc1', { method: 'DELETE' }],
      ['/api/accounts/acc1/google-calendars', {}],
    ] as const) {
      const res = await app.request(path, { ...init, headers: { 'x-eldrin-user-id': 'intruder' } }, mockEnv, mockExecutionCtx);
      expect(res.status).toBe(404);
    }
  });

  it('POST /api/sync/run syncs the user calendars synchronously', async () => {
    const res = await app.request('/api/sync/run', { method: 'POST', headers: authed }, mockEnv, mockExecutionCtx);
    expect(res.status).toBe(200);
    const body = await res.json() as { results: { calendarId: string }[] };
    expect(body.results).toEqual([{ calendarId: 'g1', applied: 1, removed: 0, error: null }]);
    expect(syncAllForUserMock).toHaveBeenCalledTimes(1);
    expect(syncAllForUserMock.mock.calls[0][2]).toBe('u1'); // (db, env, userId)
  });

  describe('POST /api/sync/notify/google', () => {
    beforeEach(async () => {
      await db.insert(calendars).values({
        id: 'g1', name: 'Work', color: '#112233', ownerId: 'u1', isDefault: false,
        provider: 'google', externalId: 'ext-1', accountId: 'acc1',
        watchChannelId: 'ch1', createdAt: 1, updatedAt: 1,
      });
    });

    async function notify(headers: Record<string, string>) {
      return app.request('/api/sync/notify/google', { method: 'POST', headers }, mockEnv, mockExecutionCtx);
    }

    it('accepts a valid notification and schedules a sync', async () => {
      const token = await channelTokenFor('g1', 'test-secret');
      const res = await notify({
        'X-Goog-Channel-ID': 'ch1', 'X-Goog-Channel-Token': token, 'X-Goog-Resource-State': 'exists',
      });
      expect(res.status).toBe(200);
      expect(waited.length).toBe(1);
    });

    it('ignores the initial sync handshake message', async () => {
      const token = await channelTokenFor('g1', 'test-secret');
      const res = await notify({
        'X-Goog-Channel-ID': 'ch1', 'X-Goog-Channel-Token': token, 'X-Goog-Resource-State': 'sync',
      });
      expect(res.status).toBe(200);
      expect(waited.length).toBe(0);
    });

    it('403s a bad channel token', async () => {
      const res = await notify({
        'X-Goog-Channel-ID': 'ch1', 'X-Goog-Channel-Token': 'forged', 'X-Goog-Resource-State': 'exists',
      });
      expect(res.status).toBe(403);
      expect(waited.length).toBe(0);
    });

    it('200s (no-op) for an unknown channel — Google keeps retrying otherwise', async () => {
      const res = await notify({ 'X-Goog-Channel-ID': 'ghost', 'X-Goog-Channel-Token': 'x', 'X-Goog-Resource-State': 'exists' });
      expect(res.status).toBe(200);
      expect(waited.length).toBe(0);
    });
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run worker/__tests__/sync-routes.test.ts`
Expected: FAIL — `../routes/sync` not found.

- [ ] **Step 3: Implement routes/sync.ts**

```typescript
/**
 * Connected-account management + sync triggers (spec §5).
 * All account routes are scoped to the acting user; the notify route is
 * public but validated against the per-channel HMAC token.
 */
import { Hono } from 'hono';
import { and, eq } from 'drizzle-orm';
import type { Database } from '../db';
import { calendars, connectedAccounts } from '../db';
import { generateId, now } from '../utils';
import { decryptToken } from '../services/crypto';
import { revokeGoogleToken } from '../services/oauth-google';
import { providerForAccount, providerForCalendar } from '../services/accounts';
import { channelTokenFor, syncCalendar, syncAllForUser } from '../services/sync';
import { ProviderApiError } from '../services/providers/types';
import { requestUserId, DEFAULT_CALENDAR_COLOR } from './calendars';

type Variables = { db: Database; auth?: { userId?: string } };

export const syncRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

async function ownedAccount(db: Database, userId: string, accountId: string) {
  const [acc] = await db.select().from(connectedAccounts).where(and(
    eq(connectedAccounts.id, accountId), eq(connectedAccounts.userId, userId),
  ));
  return acc ?? null;
}

function providerError(c: { json: (body: unknown, status: number) => Response }, err: unknown) {
  if (err instanceof ProviderApiError) {
    return c.json({ error: `Google Calendar request failed: ${err.message}` }, 502);
  }
  throw err;
}

syncRoutes.get('/api/accounts', async (c) => {
  const db = c.get('db');
  const userId = requestUserId(c);
  const accounts = await db.select().from(connectedAccounts).where(eq(connectedAccounts.userId, userId));
  const result = [];
  for (const acc of accounts) {
    const cals = await db.select().from(calendars).where(and(
      eq(calendars.accountId, acc.id), eq(calendars.ownerId, userId),
    ));
    result.push({
      id: acc.id, provider: acc.provider, email: acc.email,
      status: acc.status, lastError: acc.lastError, createdAt: acc.createdAt,
      calendars: cals,
    });
  }
  return c.json({ accounts: result });
});

syncRoutes.get('/api/accounts/:id/google-calendars', async (c) => {
  const db = c.get('db');
  const userId = requestUserId(c);
  const acc = await ownedAccount(db, userId, c.req.param('id'));
  if (!acc) return c.json({ error: 'Account not found' }, 404);
  try {
    const provider = providerForAccount(db, c.env, acc.id);
    const remote = await provider.listCalendars();
    const local = await db.select().from(calendars).where(eq(calendars.accountId, acc.id));
    const syncedIds = new Set(local.map((l) => l.externalId));
    return c.json({
      calendars: remote.map((r) => ({ ...r, synced: syncedIds.has(r.externalId) })),
    });
  } catch (err) {
    return providerError(c, err);
  }
});

syncRoutes.put('/api/accounts/:id/calendars', async (c) => {
  const db = c.get('db');
  const userId = requestUserId(c);
  const acc = await ownedAccount(db, userId, c.req.param('id'));
  if (!acc) return c.json({ error: 'Account not found' }, 404);

  let body: { externalIds?: unknown };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }
  if (!Array.isArray(body.externalIds) || body.externalIds.some((x) => typeof x !== 'string')) {
    return c.json({ error: 'externalIds must be a string array' }, 400);
  }
  const wanted = new Set(body.externalIds as string[]);

  try {
    const provider = providerForAccount(db, c.env, acc.id);
    const remote = await provider.listCalendars();
    const remoteById = new Map(remote.map((r) => [r.externalId, r]));
    for (const id of wanted) {
      if (!remoteById.has(id)) return c.json({ error: `Unknown Google calendar: ${id}` }, 400);
    }

    const local = await db.select().from(calendars).where(eq(calendars.accountId, acc.id));
    const ts = now();

    // Remove deselected calendars (FK cascades their events).
    for (const cal of local) {
      if (!wanted.has(cal.externalId ?? '')) {
        await db.delete(calendars).where(eq(calendars.id, cal.id));
      }
    }
    // Add newly selected ones and kick their initial sync in the background.
    const localIds = new Set(local.map((l) => l.externalId));
    for (const id of wanted) {
      if (localIds.has(id)) continue;
      const remoteCal = remoteById.get(id)!;
      const row = {
        id: generateId(), name: remoteCal.name,
        color: remoteCal.color ?? DEFAULT_CALENDAR_COLOR,
        ownerId: userId, isDefault: false, provider: 'google', externalId: id,
        accountId: acc.id, syncToken: null, lastSyncedAt: null,
        syncStatus: 'syncing', syncError: null,
        createdAt: ts, updatedAt: ts,
      };
      await db.insert(calendars).values(row);
      c.executionCtx.waitUntil((async () => {
        const [cal] = await db.select().from(calendars).where(eq(calendars.id, row.id));
        await syncCalendar(db, c.env, await providerForCalendar(db, c.env, cal), cal);
      })());
    }

    const updated = await db.select().from(calendars).where(eq(calendars.accountId, acc.id));
    return c.json({ calendars: updated });
  } catch (err) {
    return providerError(c, err);
  }
});

syncRoutes.delete('/api/accounts/:id', async (c) => {
  const db = c.get('db');
  const userId = requestUserId(c);
  const acc = await ownedAccount(db, userId, c.req.param('id'));
  if (!acc) return c.json({ error: 'Account not found' }, 404);

  // Best-effort revoke — never blocks disconnect.
  try {
    await revokeGoogleToken(await decryptToken(acc.refreshTokenEnc, c.env.JWT_SECRET));
  } catch (err) {
    console.warn('[calendar] token revoke failed during disconnect (continuing):', err);
  }
  await db.delete(calendars).where(eq(calendars.accountId, acc.id)); // cascades events
  await db.delete(connectedAccounts).where(eq(connectedAccounts.id, acc.id));
  return c.json({ deleted: true });
});

syncRoutes.post('/api/sync/run', async (c) => {
  const db = c.get('db');
  const userId = requestUserId(c);
  const results = await syncAllForUser(db, c.env, userId);
  return c.json({ results });
});

syncRoutes.post('/api/sync/notify/google', async (c) => {
  const db = c.get('db');
  const channelId = c.req.header('X-Goog-Channel-ID');
  const token = c.req.header('X-Goog-Channel-Token');
  const state = c.req.header('X-Goog-Resource-State');
  if (!channelId) return c.json({ ok: true }); // malformed — 200 so Google stops retrying

  const [cal] = await db.select().from(calendars).where(eq(calendars.watchChannelId, channelId));
  if (!cal) return c.json({ ok: true }); // stale channel for a removed calendar

  const expected = await channelTokenFor(cal.id, c.env.JWT_SECRET);
  if (token !== expected) return c.json({ error: 'Invalid channel token' }, 403);

  if (state !== 'sync') {
    c.executionCtx.waitUntil((async () => {
      await syncCalendar(db, c.env, await providerForCalendar(db, c.env, cal), cal);
    })());
  }
  return c.json({ ok: true });
});
```

- [ ] **Step 4: Mount + manifest routes**

`worker/index.ts`:

```typescript
import { syncRoutes } from './routes/sync';
// after oauthRoutes:
app.route('', syncRoutes);
```

Append to manifest `api.routes`:

```json
{ "method": "GET", "path": "/api/accounts", "permission": "calendar:read" },
{ "method": "DELETE", "path": "/api/accounts/:id", "permission": "calendar:delete" },
{ "method": "GET", "path": "/api/accounts/:id/google-calendars", "permission": "calendar:read" },
{ "method": "PUT", "path": "/api/accounts/:id/calendars", "permission": "calendar:update" },
{ "method": "POST", "path": "/api/sync/run", "permission": "calendar:update" }
```

- [ ] **Step 5: Run tests + typecheck, then commit**

Run: `npx vitest run && npx tsc -b`
Expected: all PASS.

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar commit -m "feat: account management + sync trigger routes incl. webhook notify (Slice 4b Task 7)"
```

---

### Task 8: Write-through of local edits to Google

**Files:**
- Create: `eldrin-calendar/worker/services/write-through.ts`
- Modify: `eldrin-calendar/worker/services/event-edits.ts` (export `headRuleUntil`; `externalId` support on `editSingleOccurrence` and `splitSeries`)
- Modify: `eldrin-calendar/worker/routes/events.ts` (google branches)
- Test: `eldrin-calendar/worker/__tests__/write-through.test.ts`

**Interfaces:**
- Consumes: Tasks 3–4 (`providerForCalendar`, `CalendarProvider`, `OutboundEvent`, `ProviderApiError`), existing `event-edits.ts` functions.
- Produces (write-through.ts, all throw `ProviderApiError` on Google failure BEFORE any D1 write):
  - `rowToOutbound(row: EventRow, attendees: {email, displayName}[]): OutboundEvent`
  - `pushCreate(db, env, cal, row, attendees): Promise<string>` → new externalId
  - `pushUpdateWhole(db, env, cal, row, attendees): Promise<void>` (singles, synced exceptions, masters scope=all)
  - `pushEditOccurrence(db, env, cal, master, originalStartTime, patchedRow): Promise<string>` → instance externalId
  - `pushSplit(db, env, cal, master, originalStartTime, newMasterRow, attendees): Promise<string>` → tail master externalId (Google: PATCH head UNTIL onto old master, then insert tail)
  - `pushDelete(db, env, cal, externalId): Promise<void>`
  - `pushCancelOccurrence(db, env, cal, master, originalStartTime): Promise<void>`
  - `pushTruncate(db, env, cal, master, originalStartTime): Promise<void>`
- Produces (event-edits.ts): `headRuleUntil(master: EventRow, originalStartTime: number): string` (extracted from `truncateSeries`/`splitSeries`, both refactored to call it); `editSingleOccurrence(db, master, originalStartTime, patch, externalId?: string | null)`; `splitSeries(db, master, originalStartTime, patch, newMasterExternalId?: string | null)`.

- [ ] **Step 1: Write failing write-through service tests**

`worker/__tests__/write-through.test.ts`:

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createTestDb } from './test-db';
import type { Database, EventRow } from '../db';
import { calendars, events } from '../db';
import { eq } from 'drizzle-orm';
import {
  rowToOutbound, pushCreate, pushUpdateWhole, pushEditOccurrence,
  pushSplit, pushDelete, pushCancelOccurrence, pushTruncate,
} from '../services/write-through';
import { ProviderApiError, type CalendarProvider } from '../services/providers/types';

const providerMock = {
  createEvent: vi.fn(), updateEvent: vi.fn(), deleteEvent: vi.fn(),
  getInstanceExternalId: vi.fn(),
} as unknown as CalendarProvider & Record<string, ReturnType<typeof vi.fn>>;

vi.mock('../services/accounts', () => ({
  providerForCalendar: vi.fn(async () => providerMock),
}));

const env = { JWT_SECRET: 's' } as Env;
const T0 = Date.UTC(2026, 6, 6, 9, 0, 0);
const HOUR = 3600000;
const WEEK = 7 * 24 * HOUR;

const GCAL = {
  id: 'cal-g', name: 'G', color: '#112233', ownerId: 'u1', isDefault: false,
  provider: 'google', externalId: 'gcal-ext', accountId: 'acc1', createdAt: 1, updatedAt: 1,
};

function eventRow(overrides: Partial<EventRow>): EventRow {
  return {
    id: 'ev1', calendarId: 'cal-g', title: 'T', description: null, location: null,
    startAt: T0, endAt: T0 + HOUR, allDay: false, timezone: 'UTC',
    recurrenceRule: null, recurringEventId: null, originalStartTime: null,
    status: 'confirmed', externalId: 'ext-ev1', createdBy: 'u1', createdAt: 1, updatedAt: 1,
    ...overrides,
  } as EventRow;
}

describe('write-through service', () => {
  let db: Database;
  let cal: typeof GCAL & Record<string, unknown>;

  beforeEach(async () => {
    db = createTestDb();
    vi.clearAllMocks();
    await db.insert(calendars).values(GCAL);
    [cal] = await db.select().from(calendars).where(eq(calendars.id, 'cal-g')) as never;
  });

  it('rowToOutbound maps a row + attendees', () => {
    const out = rowToOutbound(eventRow({ recurrenceRule: 'FREQ=DAILY' }), [{ email: 'a@b.c', displayName: null }]);
    expect(out).toEqual({
      title: 'T', description: null, location: null,
      startAt: T0, endAt: T0 + HOUR, allDay: false, timezone: 'UTC',
      recurrenceRule: 'FREQ=DAILY', attendees: [{ email: 'a@b.c', displayName: null }],
    });
  });

  it('pushCreate creates on Google and returns the external id', async () => {
    providerMock.createEvent.mockResolvedValue({ externalId: 'new-ext' });
    const id = await pushCreate(db, env, cal as never, eventRow({ externalId: null }), []);
    expect(id).toBe('new-ext');
    expect(providerMock.createEvent).toHaveBeenCalledWith('gcal-ext', expect.objectContaining({ title: 'T' }));
  });

  it('pushCreate propagates ProviderApiError', async () => {
    providerMock.createEvent.mockRejectedValue(new ProviderApiError('quota', 403));
    await expect(pushCreate(db, env, cal as never, eventRow({}), [])).rejects.toMatchObject({ status: 403 });
  });

  it('pushUpdateWhole patches by the row external id', async () => {
    providerMock.updateEvent.mockResolvedValue({ externalId: 'ext-ev1' });
    await pushUpdateWhole(db, env, cal as never, eventRow({ title: 'New' }), []);
    expect(providerMock.updateEvent).toHaveBeenCalledWith('gcal-ext', 'ext-ev1', expect.objectContaining({ title: 'New' }));
  });

  it('pushUpdateWhole refuses rows without external id', async () => {
    await expect(pushUpdateWhole(db, env, cal as never, eventRow({ externalId: null }), []))
      .rejects.toBeInstanceOf(ProviderApiError);
  });

  it('pushEditOccurrence resolves the instance id then patches it (times only)', async () => {
    providerMock.getInstanceExternalId.mockResolvedValue('master_inst1');
    providerMock.updateEvent.mockResolvedValue({ externalId: 'master_inst1' });
    const master = eventRow({ externalId: 'master-ext', recurrenceRule: 'FREQ=WEEKLY;BYDAY=MO' });
    const patched = eventRow({ id: 'x', startAt: T0 + WEEK + HOUR, endAt: T0 + WEEK + 2 * HOUR, recurrenceRule: null });
    const instId = await pushEditOccurrence(db, env, cal as never, master, T0 + WEEK, patched);
    expect(instId).toBe('master_inst1');
    expect(providerMock.getInstanceExternalId).toHaveBeenCalledWith('gcal-ext', 'master-ext', T0 + WEEK, 'UTC', false);
    const sent = providerMock.updateEvent.mock.calls[0][2];
    expect(sent.recurrenceRule).toBeNull(); // instances never carry a rule
    expect(sent.startAt).toBe(T0 + WEEK + HOUR);
  });

  it('pushSplit patches the head rule onto the old master then inserts the tail', async () => {
    providerMock.updateEvent.mockResolvedValue({ externalId: 'master-ext' });
    providerMock.createEvent.mockResolvedValue({ externalId: 'tail-ext' });
    const master = eventRow({ externalId: 'master-ext', recurrenceRule: 'FREQ=WEEKLY;BYDAY=MO' });
    const newMaster = eventRow({ id: 'tail', externalId: null, startAt: T0 + WEEK, endAt: T0 + WEEK + HOUR, recurrenceRule: 'FREQ=WEEKLY;BYDAY=MO', title: 'Renamed' });
    const tailExt = await pushSplit(db, env, cal as never, master, T0 + WEEK, newMaster, []);
    expect(tailExt).toBe('tail-ext');
    const headBody = providerMock.updateEvent.mock.calls[0][2];
    expect(headBody.recurrenceRule).toContain('UNTIL=');
    expect(providerMock.createEvent).toHaveBeenCalledWith('gcal-ext', expect.objectContaining({ title: 'Renamed' }));
  });

  it('pushSplit does NOT touch Google create when the head patch fails', async () => {
    providerMock.updateEvent.mockRejectedValue(new ProviderApiError('nope', 400));
    const master = eventRow({ externalId: 'master-ext', recurrenceRule: 'FREQ=WEEKLY;BYDAY=MO' });
    await expect(pushSplit(db, env, cal as never, master, T0 + WEEK, eventRow({}), [])).rejects.toMatchObject({ status: 400 });
    expect(providerMock.createEvent).not.toHaveBeenCalled();
  });

  it('pushDelete / pushCancelOccurrence / pushTruncate hit the expected provider calls', async () => {
    providerMock.deleteEvent.mockResolvedValue(undefined);
    await pushDelete(db, env, cal as never, 'ext-ev1');
    expect(providerMock.deleteEvent).toHaveBeenCalledWith('gcal-ext', 'ext-ev1');

    providerMock.getInstanceExternalId.mockResolvedValue('inst-9');
    const master = eventRow({ externalId: 'master-ext', recurrenceRule: 'FREQ=WEEKLY;BYDAY=MO' });
    await pushCancelOccurrence(db, env, cal as never, master, T0 + WEEK);
    expect(providerMock.deleteEvent).toHaveBeenCalledWith('gcal-ext', 'inst-9');

    providerMock.updateEvent.mockResolvedValue({ externalId: 'master-ext' });
    await pushTruncate(db, env, cal as never, master, T0 + WEEK);
    const body = providerMock.updateEvent.mock.calls.at(-1)![2];
    expect(body.recurrenceRule).toContain('UNTIL=');
  });
});
```

- [ ] **Step 2: Add failing route-level tests to events-write-route.test.ts**

Append a `describe` block to `worker/__tests__/events-write-route.test.ts` (reuse its harness; add the same `vi.mock('../services/accounts', ...)` provider mock as above at the top of the file):

```typescript
describe('write-through on google calendars (Slice 4b)', () => {
  beforeEach(async () => {
    await db.insert(calendars).values({
      id: 'cal-g', name: 'G', color: '#112233', ownerId: 'u1', isDefault: false,
      provider: 'google', externalId: 'gcal-ext', accountId: 'acc1', createdAt: 1, updatedAt: 1,
    });
  });

  const validG = {
    calendarId: 'cal-g', title: 'Meet', startAt: T0, endAt: T0 + HOUR, timezone: 'UTC',
  };

  it('POST stores the Google-assigned external id', async () => {
    providerMock.createEvent.mockResolvedValue({ externalId: 'g-new' });
    const res = await post(app, validG);
    expect(res.status).toBe(201);
    const { event } = await res.json() as { event: { id: string; externalId: string } };
    expect(event.externalId).toBe('g-new');
    const [row] = await db.select().from(events).where(eq(events.id, event.id));
    expect(row.externalId).toBe('g-new');
  });

  it('POST returns 502 and writes NOTHING locally when Google rejects', async () => {
    providerMock.createEvent.mockRejectedValue(new ProviderApiError('quota exceeded', 403));
    const res = await post(app, validG);
    expect(res.status).toBe(502);
    expect((await res.json() as { error: string }).error).toContain('quota exceeded');
    expect(await db.select().from(events)).toHaveLength(0);
  });

  it('PATCH scope=all on a google single event patches Google first', async () => {
    providerMock.createEvent.mockResolvedValue({ externalId: 'g-1' });
    const created = await (await post(app, validG)).json() as { event: { id: string } };
    providerMock.updateEvent.mockResolvedValue({ externalId: 'g-1' });
    const res = await app.request(`/api/events/${created.event.id}`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json', 'x-eldrin-user-id': 'u1' },
      body: JSON.stringify({ title: 'Renamed' }),
    }, mockEnv, mockExecutionCtx);
    expect(res.status).toBe(200);
    expect(providerMock.updateEvent).toHaveBeenCalled();
    const [row] = await db.select().from(events).where(eq(events.id, created.event.id));
    expect(row.title).toBe('Renamed');
  });

  it('PATCH returns 502 and leaves the row untouched when Google rejects', async () => {
    providerMock.createEvent.mockResolvedValue({ externalId: 'g-1' });
    const created = await (await post(app, validG)).json() as { event: { id: string } };
    providerMock.updateEvent.mockRejectedValue(new ProviderApiError('gone', 410));
    const res = await app.request(`/api/events/${created.event.id}`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json', 'x-eldrin-user-id': 'u1' },
      body: JSON.stringify({ title: 'Renamed' }),
    }, mockEnv, mockExecutionCtx);
    expect(res.status).toBe(502);
    const [row] = await db.select().from(events).where(eq(events.id, created.event.id));
    expect(row.title).toBe('Meet');
  });

  it('DELETE on a google event deletes on Google first; 502 aborts local delete', async () => {
    providerMock.createEvent.mockResolvedValue({ externalId: 'g-1' });
    const created = await (await post(app, validG)).json() as { event: { id: string } };
    providerMock.deleteEvent.mockRejectedValue(new ProviderApiError('denied', 403));
    let res = await app.request(`/api/events/${created.event.id}`, {
      method: 'DELETE', headers: { 'x-eldrin-user-id': 'u1' },
    }, mockEnv, mockExecutionCtx);
    expect(res.status).toBe(502);
    expect(await db.select().from(events)).toHaveLength(1);

    providerMock.deleteEvent.mockResolvedValue(undefined);
    res = await app.request(`/api/events/${created.event.id}`, {
      method: 'DELETE', headers: { 'x-eldrin-user-id': 'u1' },
    }, mockEnv, mockExecutionCtx);
    expect(res.status).toBe(200);
    expect(await db.select().from(events)).toHaveLength(0);
  });

  it('local calendars never touch the provider (D9)', async () => {
    const res = await post(app, { ...valid });
    expect(res.status).toBe(201);
    expect(providerMock.createEvent).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `npx vitest run worker/__tests__/write-through.test.ts worker/__tests__/events-write-route.test.ts`
Expected: FAIL — module missing / route behavior missing.

- [ ] **Step 4: Refactor event-edits.ts (pure helper + externalId params)**

In `worker/services/event-edits.ts`:

```typescript
/** Head RRULE for a series cut strictly before originalStartTime (shared by truncate/split/write-through). */
export function headRuleUntil(master: EventRow, originalStartTime: number): string {
  const options = RRule.parseString(master.recurrenceRule ?? '');
  const fakeSplit = wallMsInZone(originalStartTime, master.timezone);
  return ruleToString({ ...options, until: new Date(fakeSplit - 1000), count: null });
}
```

Refactor `truncateSeries` and `splitSeries` to call `headRuleUntil(master, originalStartTime)` instead of computing `headRule` inline (behavior identical — existing tests must stay green).

Add optional `externalId` parameters (default `null`, applied to the inserted/updated rows):

```typescript
export async function editSingleOccurrence(
  db: Database, master: EventRow, originalStartTime: number,
  patch: CleanEventInput, externalId: string | null = null,
): Promise<EventRow>
// existing-row branch: include ...(externalId ? { externalId } : {}) in the .set() object
// new-row branch: slot gets externalId (instead of inheriting master's)

export async function splitSeries(
  db: Database, master: EventRow, originalStartTime: number,
  patch: CleanEventInput, newMasterExternalId: string | null = null,
): Promise<{ oldMaster: EventRow; newMaster: EventRow }>
// tailBase gets externalId: newMasterExternalId (instead of inheriting master's)
```

Also update `cancelOccurrence`'s new-row branch to set `externalId: null` (a locally cancelled slot has no Google id of its own — the master keeps its own row).

- [ ] **Step 5: Implement write-through.ts**

`worker/services/write-through.ts`:

```typescript
/**
 * Write-through to the owning provider (spec D13): every mutation of an event
 * on a provider='google' calendar calls Google FIRST; only after Google accepts
 * does the caller persist locally. All functions throw ProviderApiError on
 * rejection and perform no D1 writes themselves.
 */
import type { CalendarRow, Database, EventRow } from '../db';
import { providerForCalendar } from './accounts';
import { headRuleUntil } from './event-edits';
import { ProviderApiError, type OutboundEvent } from './providers/types';

type Attendees = { email: string; displayName: string | null }[];

export function rowToOutbound(row: EventRow, attendees: Attendees): OutboundEvent {
  return {
    title: row.title,
    description: row.description,
    location: row.location,
    startAt: row.startAt,
    endAt: row.endAt,
    allDay: row.allDay,
    timezone: row.timezone,
    recurrenceRule: row.recurrenceRule,
    attendees,
  };
}

function requireExternalId(row: EventRow): string {
  if (!row.externalId) {
    throw new ProviderApiError('Event has no Google id yet — run a sync and retry', 409);
  }
  return row.externalId;
}

export async function pushCreate(
  db: Database, env: Env, cal: CalendarRow, row: EventRow, attendees: Attendees,
): Promise<string> {
  const provider = await providerForCalendar(db, env, cal);
  const created = await provider.createEvent(cal.externalId!, rowToOutbound(row, attendees));
  return created.externalId;
}

export async function pushUpdateWhole(
  db: Database, env: Env, cal: CalendarRow, row: EventRow, attendees: Attendees,
): Promise<void> {
  const provider = await providerForCalendar(db, env, cal);
  await provider.updateEvent(cal.externalId!, requireExternalId(row), rowToOutbound(row, attendees));
}

export async function pushEditOccurrence(
  db: Database, env: Env, cal: CalendarRow, master: EventRow,
  originalStartTime: number, patchedRow: EventRow,
): Promise<string> {
  const provider = await providerForCalendar(db, env, cal);
  const instanceId = await provider.getInstanceExternalId(
    cal.externalId!, requireExternalId(master), originalStartTime, master.timezone, master.allDay,
  );
  await provider.updateEvent(cal.externalId!, instanceId, {
    ...rowToOutbound(patchedRow, []),
    recurrenceRule: null, // instances never carry a rule
  });
  return instanceId;
}

export async function pushSplit(
  db: Database, env: Env, cal: CalendarRow, master: EventRow,
  originalStartTime: number, newMasterRow: EventRow, attendees: Attendees,
): Promise<string> {
  const provider = await providerForCalendar(db, env, cal);
  // 1) Truncate the old master on Google (UNTIL just before the split) …
  await provider.updateEvent(cal.externalId!, requireExternalId(master), {
    ...rowToOutbound(master, attendees),
    recurrenceRule: headRuleUntil(master, originalStartTime),
  });
  // 2) … then insert the tail as a fresh Google event.
  const tail = await provider.createEvent(cal.externalId!, rowToOutbound(newMasterRow, attendees));
  return tail.externalId;
}

export async function pushDelete(
  db: Database, env: Env, cal: CalendarRow, externalId: string,
): Promise<void> {
  const provider = await providerForCalendar(db, env, cal);
  await provider.deleteEvent(cal.externalId!, externalId);
}

export async function pushCancelOccurrence(
  db: Database, env: Env, cal: CalendarRow, master: EventRow, originalStartTime: number,
): Promise<void> {
  const provider = await providerForCalendar(db, env, cal);
  const instanceId = await provider.getInstanceExternalId(
    cal.externalId!, requireExternalId(master), originalStartTime, master.timezone, master.allDay,
  );
  await provider.deleteEvent(cal.externalId!, instanceId);
}

export async function pushTruncate(
  db: Database, env: Env, cal: CalendarRow, master: EventRow, originalStartTime: number,
): Promise<void> {
  const provider = await providerForCalendar(db, env, cal);
  await provider.updateEvent(cal.externalId!, requireExternalId(master), {
    ...rowToOutbound(master, []),
    recurrenceRule: headRuleUntil(master, originalStartTime),
  });
}
```

- [ ] **Step 6: Wire the google branches into routes/events.ts**

Changes to `worker/routes/events.ts` (each mutation path gains a guarded google call BEFORE its local write; wrap handler bodies' google calls in try/catch mapping `ProviderApiError` → 502):

Add imports:

```typescript
import { ProviderApiError } from '../services/providers/types';
import {
  pushCancelOccurrence, pushCreate, pushDelete, pushEditOccurrence,
  pushSplit, pushTruncate, pushUpdateWhole,
} from '../services/write-through';
```

Add the shared error mapper near the top (matches `UserCtx` in `routes/calendars.ts`):

```typescript
import type { Context } from 'hono';
type EventCtx = Context<{ Bindings: Env; Variables: Variables }>;

function googleRejected(c: EventCtx, err: unknown) {
  if (err instanceof ProviderApiError) {
    return c.json({ error: `Google Calendar rejected the change: ${err.message}` }, 502);
  }
  throw err;
}
```

**POST /api/events** — keep the calendar value (change `if (!(await ownedCalendar(db, ownerId, body.calendarId)))` to `const cal = await ownedCalendar(db, ownerId, body.calendarId); if (!cal) ...`), then between building `row` and `db.insert`:

```typescript
  const ts = now();
  const row = { /* existing literal unchanged, externalId: null */ };
  const attendees = input.attendees ?? [];
  let externalId: string | null = null;
  if (cal.provider === 'google') {
    try {
      externalId = await pushCreate(db, c.env, cal, row as EventRow, attendees);
    } catch (err) {
      return googleRejected(c, err);
    }
  }
  const finalRow = { ...row, externalId };
  await db.insert(events).values(finalRow);
```

(Use `finalRow` in the response and event payload where the code previously used `row` — all write-through functions take `(db, env, cal, …)`.)

**PATCH /api/events/:id** — after loading `row` and the calendar (`const cal = await ownedCalendar(db, ownerId, row.calendarId)` — refactor the existing check to keep the value), insert google pushes per branch, each wrapped in `try { … } catch (err) { return googleRejected(c, err); }`:

- Exception-row branch (`row.recurringEventId`): before the local `db.update`, when `cal.provider === 'google'`:

```typescript
      const updated = { ...row, ...patchFields(row, patch), updatedAt: ts };
      if (cal.provider === 'google') {
        try {
          if (row.externalId) {
            await pushUpdateWhole(db, c.env, cal, updated as EventRow, []);
          } else {
            const [masterRow] = await db.select().from(events).where(eq(events.id, row.recurringEventId));
            if (masterRow) await pushEditOccurrence(db, c.env, cal, masterRow, row.originalStartTime!, updated as EventRow);
          }
        } catch (err) {
          return googleRejected(c, err);
        }
      }
```

- Single (non-recurring) branch: before `replaceAttendees`/`db.update`:

```typescript
      const updated = { ...row, ...patchFields(row, patch), updatedAt: ts };
      if (cal.provider === 'google') {
        try {
          await pushUpdateWhole(db, c.env, cal, updated as EventRow, patch.attendees ?? []);
        } catch (err) {
          return googleRejected(c, err);
        }
      }
```

- Master `scope === 'all'` branch: build the would-be row first (mirror `editAllInSeries`'s computation via `patchFields` + recurrenceRule override), push, then run the existing local calls:

```typescript
    if (scope === 'all') {
      if (cal.provider === 'google') {
        const wouldBe = {
          ...row, ...patchFields(row, patch),
          recurrenceRule: patch.recurrenceRule !== undefined ? patch.recurrenceRule : row.recurrenceRule,
        };
        try {
          await pushUpdateWhole(db, c.env, cal, wouldBe as EventRow, patch.attendees ?? []);
        } catch (err) {
          return googleRejected(c, err);
        }
      }
      if (patch.attendees) await replaceAttendees(db, row.id, patch.attendees);
      const updated = await editAllInSeries(db, row, patch);
      return finish(updated, 'all');
    }
```

- `scope === 'single'` branch: push first, thread the returned instance id into the local edit:

```typescript
  if (scope === 'single') {
    let instanceExternalId: string | null = null;
    if (cal.provider === 'google') {
      const duration = row.endAt - row.startAt;
      const patchedRow = {
        ...row, ...patchFields(row, patch),
        startAt: patch.startAt ?? originalStartTime,
        endAt: patch.endAt ?? originalStartTime + duration,
        recurrenceRule: null,
      };
      try {
        instanceExternalId = await pushEditOccurrence(db, c.env, cal, row, originalStartTime, patchedRow as EventRow);
      } catch (err) {
        return googleRejected(c, err);
      }
    }
    await editSingleOccurrence(db, row, originalStartTime, patch, instanceExternalId);
    return finish(row, 'single');
  }
```

- `following` branch: compute the tail row shape the same way `splitSeries` does is impractical pre-call — instead push with a minimal tail row built from the master + patch (matching what `splitSeries` will persist), then pass the returned external id into `splitSeries`:

```typescript
  let tailExternalId: string | null = null;
  if (cal.provider === 'google') {
    const duration = row.endAt - row.startAt;
    const tailPreview = {
      ...row, id: 'preview',
      startAt: patch.startAt ?? originalStartTime,
      endAt: patch.endAt ?? originalStartTime + duration,
      title: patch.title ?? row.title,
      description: patch.description !== undefined ? patch.description : row.description,
      location: patch.location !== undefined ? patch.location : row.location,
      allDay: patch.allDay ?? row.allDay,
      timezone: patch.timezone ?? row.timezone,
      recurrenceRule: patch.recurrenceRule !== undefined ? patch.recurrenceRule : row.recurrenceRule,
    };
    try {
      tailExternalId = await pushSplit(db, c.env, cal, row, originalStartTime, tailPreview as EventRow, patch.attendees ?? []);
    } catch (err) {
      return googleRejected(c, err);
    }
  }
  const { oldMaster, newMaster } = await splitSeries(db, row, originalStartTime, patch, tailExternalId);
```

**DELETE /api/events/:id** — same pattern per branch (`const cal = await ownedCalendar(...)` refactor first):

```typescript
  // exception row branch:
  if (row.recurringEventId) {
    if (cal.provider === 'google' && row.externalId) {
      try { await pushDelete(db, c.env, cal, row.externalId); } catch (err) { return googleRejected(c, err); }
    }
    // existing local cancel + emit unchanged
  }
  // single event or whole series:
  if (!row.recurrenceRule || scope === 'all') {
    if (cal.provider === 'google' && row.externalId) {
      try { await pushDelete(db, c.env, cal, row.externalId); } catch (err) { return googleRejected(c, err); }
    }
    // existing hard delete + emit unchanged
  }
  // scope === 'single':
    if (cal.provider === 'google') {
      try { await pushCancelOccurrence(db, c.env, cal, row, originalStartTime); } catch (err) { return googleRejected(c, err); }
    }
    await cancelOccurrence(db, row, originalStartTime);
  // scope === 'following':
    if (cal.provider === 'google') {
      try { await pushTruncate(db, c.env, cal, row, originalStartTime); } catch (err) { return googleRejected(c, err); }
    }
    await truncateSeries(db, row, originalStartTime);
```

- [ ] **Step 7: Run all tests to verify they pass**

Run: `npx vitest run && npx tsc -b`
Expected: PASS — new suites AND the untouched 4a suites (D9 regression gate).

- [ ] **Step 8: Commit**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar commit -m "feat: write-through of local edits to Google incl. recurring scopes (Slice 4b Task 8)"
```

---

### Task 9: Cron reconciliation + watch-channel renewal

**Files:**
- Modify: `eldrin-calendar/worker/services/sync.ts` (add `renewWatches`)
- Modify: `eldrin-calendar/worker/index.ts` (export `{fetch, scheduled}`)
- Modify: `eldrin-calendar/wrangler.jsonc` (cron trigger)
- Test: `eldrin-calendar/worker/__tests__/scheduled.test.ts`

**Interfaces:**
- Consumes: Task 5 (`reconcileAll`, `channelTokenFor`), Task 4 (`providerForCalendar`).
- Produces: `renewWatches(db: Database, env: Env): Promise<void>` — no-op unless `env.WEBHOOKS_ENABLED === 'true'` AND `env.PUBLIC_URL` is set; re-arms channels expiring within 12h (or never armed). `worker/index.ts` default export becomes `{ fetch, scheduled }`.

- [ ] **Step 1: Write failing tests**

`worker/__tests__/scheduled.test.ts`:

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createTestDb } from './test-db';
import type { Database } from '../db';
import { calendars } from '../db';
import { eq } from 'drizzle-orm';
import { renewWatches } from '../services/sync';
import type { CalendarProvider } from '../services/providers/types';

const watchMock = vi.fn();
vi.mock('../services/accounts', () => ({
  providerForCalendar: vi.fn(async () => ({ watch: watchMock } as unknown as CalendarProvider)),
}));

describe('renewWatches', () => {
  let db: Database;
  const baseCal = {
    id: 'g1', name: 'W', color: '#112233', ownerId: 'u1', isDefault: false,
    provider: 'google', externalId: 'ext-1', accountId: 'acc1', createdAt: 1, updatedAt: 1,
  };

  beforeEach(async () => {
    db = createTestDb();
    vi.clearAllMocks();
    watchMock.mockResolvedValue({ channelId: 'ch-new', resourceId: 'res-new', expiresAt: Date.now() + 86400000 });
  });

  it('does nothing when webhooks are disabled', async () => {
    await db.insert(calendars).values(baseCal);
    await renewWatches(db, { JWT_SECRET: 's' } as Env);
    expect(watchMock).not.toHaveBeenCalled();
  });

  it('arms a channel for calendars without one', async () => {
    await db.insert(calendars).values(baseCal);
    await renewWatches(db, { JWT_SECRET: 's', WEBHOOKS_ENABLED: 'true', PUBLIC_URL: 'https://cal.example.com' } as Env);
    expect(watchMock).toHaveBeenCalledTimes(1);
    expect(watchMock.mock.calls[0][3]).toBe('https://cal.example.com/api/sync/notify/google');
    const [row] = await db.select().from(calendars).where(eq(calendars.id, 'g1'));
    expect(row.watchChannelId).toBe('ch-new');
    expect(row.watchResourceId).toBe('res-new');
    expect(row.watchExpiresAt).toBeGreaterThan(Date.now());
  });

  it('skips calendars whose channel is still fresh', async () => {
    await db.insert(calendars).values({ ...baseCal, watchChannelId: 'ch', watchResourceId: 'r', watchExpiresAt: Date.now() + 48 * 3600000 });
    await renewWatches(db, { JWT_SECRET: 's', WEBHOOKS_ENABLED: 'true', PUBLIC_URL: 'https://x' } as Env);
    expect(watchMock).not.toHaveBeenCalled();
  });

  it('re-arms channels expiring within 12h and survives per-calendar failures', async () => {
    await db.insert(calendars).values([
      { ...baseCal, id: 'g1', externalId: 'e1', watchChannelId: 'ch', watchResourceId: 'r', watchExpiresAt: Date.now() + 3600000 },
      { ...baseCal, id: 'g2', externalId: 'e2' },
    ]);
    watchMock
      .mockRejectedValueOnce(new Error('quota'))
      .mockResolvedValueOnce({ channelId: 'ok', resourceId: 'ok-r', expiresAt: Date.now() + 86400000 });
    vi.spyOn(console, 'error').mockImplementation(() => {});
    await renewWatches(db, { JWT_SECRET: 's', WEBHOOKS_ENABLED: 'true', PUBLIC_URL: 'https://x' } as Env);
    expect(watchMock).toHaveBeenCalledTimes(2); // failure didn't stop the loop
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run worker/__tests__/scheduled.test.ts`
Expected: FAIL — `renewWatches` not exported.

- [ ] **Step 3: Implement renewWatches + scheduled handler + cron config**

Append to `worker/services/sync.ts`:

```typescript
const WATCH_RENEW_MARGIN_MS = 12 * 3600 * 1000;

/** Re-arm Google watch channels nearing expiry. No-op unless webhooks are enabled (spec §5). */
export async function renewWatches(db: Database, env: Env): Promise<void> {
  if (env.WEBHOOKS_ENABLED !== 'true' || !env.PUBLIC_URL) return;
  const address = `${env.PUBLIC_URL.replace(/\/$/, '')}/api/sync/notify/google`;
  const all = await googleCalendars(db);
  for (const cal of all) {
    if (cal.watchExpiresAt && cal.watchExpiresAt > now() + WATCH_RENEW_MARGIN_MS) continue;
    try {
      const provider = await providerForCalendar(db, env, cal);
      const token = await channelTokenFor(cal.id, env.JWT_SECRET);
      const info = await provider.watch(cal.externalId!, generateId(), token, address);
      await db.update(calendars).set({
        watchChannelId: info.channelId,
        watchResourceId: info.resourceId,
        watchExpiresAt: info.expiresAt,
        updatedAt: now(),
      }).where(eq(calendars.id, cal.id));
    } catch (err) {
      console.error(`[calendar] watch renewal failed for ${cal.id}:`, err instanceof Error ? err.message : err);
    }
  }
}
```

Rework the bottom of `worker/index.ts` (replace `export default app;`; `runMigrations`, `migrations`, and `createDb` are already imported at the top of the file — add only the sync import):

```typescript
import { reconcileAll, renewWatches } from './services/sync';

export default {
  fetch: app.fetch,
  scheduled: async (_event: ScheduledEvent, env: Env, _ctx: ExecutionContext) => {
    const result = await runMigrations(env.DB, {
      migrations,
      onLog: (msg: string, level: string) =>
        console[level as 'log' | 'warn' | 'error'](`[calendar] ${msg}`),
    });
    if (!result.success) {
      console.error('[calendar] cron aborted: migrations failed', result.error?.message);
      return;
    }
    const db = createDb(env.DB);
    const results = await reconcileAll(db, env);
    const failed = results.filter((r) => r.error);
    console.log(`[calendar] reconciliation: ${results.length} calendars, ${failed.length} failed`);
    await renewWatches(db, env);
  },
};
```

(Reuse the already-imported `runMigrations`/`migrations`/`createDb` — no duplicate imports.)

`wrangler.jsonc` — add:

```jsonc
"triggers": { "crons": ["*/5 * * * *"] }
```

- [ ] **Step 4: Run all tests + typecheck, then commit**

Run: `npx vitest run && npx tsc -b`
Expected: PASS.

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar commit -m "feat: cron reconciliation poll + watch-channel renewal (Slice 4b Task 9)"
```

---

### Task 10: Frontend — Settings view, sidebar grouping, API client

**Files:**
- Modify: `eldrin-calendar/src/api.ts` (accounts/sync endpoints + Calendar sync fields)
- Create: `eldrin-calendar/src/components/SettingsView.tsx`
- Modify: `eldrin-calendar/src/components/CalendarSidebar.tsx` (provider grouping + Settings link)
- Modify: `eldrin-calendar/src/root.component.tsx` (pathname view switch)
- Modify: `eldrin-calendar/public/eldrin-app.manifest.json` (sideNav Settings entry)

**Interfaces:**
- Consumes: Task 6/7 routes; existing `useAuthHeaders`, `Calendar` type, daisyUI classes and `cal-eyebrow`/toolbar styling conventions from 4a components (read `CalendarSidebar.tsx` + `EventModal.tsx` first and match their idiom).
- Produces: `ConnectedAccount {id, provider, email, status, lastError, createdAt, calendars: Calendar[]}`; `GoogleCalendarChoice {externalId, name, color: string|null, isPrimary, synced}`; API fns `getConnectToken`, `listAccounts`, `disconnectAccount`, `listGoogleCalendars`, `setSyncedCalendars`, `syncNow`; `<SettingsView apiBase headers onBack />` component; `Calendar` gains `accountId: string|null; syncStatus: string|null; lastSyncedAt: number|null; syncError: string|null`.
- Frontend gate: `npx tsc -b && npm run build` green (no unit harness, 4a convention); behavior verified in Task 11.

- [ ] **Step 1: Extend src/api.ts**

Update the `Calendar` interface:

```typescript
export interface Calendar {
  id: string; name: string; color: string; ownerId: string;
  isDefault: boolean; provider: string; externalId: string | null;
  accountId: string | null; syncStatus: string | null;
  lastSyncedAt: number | null; syncError: string | null;
  createdAt: number; updatedAt: number;
}
```

Append:

```typescript
export interface ConnectedAccount {
  id: string; provider: string; email: string;
  status: string; lastError: string | null; createdAt: number;
  calendars: Calendar[];
}

export interface GoogleCalendarChoice {
  externalId: string; name: string; color: string | null;
  isPrimary: boolean; synced: boolean;
}

export interface SyncRunResult { calendarId: string; applied: number; removed: number; error: string | null }

export const getConnectToken = (base: string, h: Headers) =>
  request<{ token: string }>(apiUrl(base, '/oauth/google/connect-token'), h, { method: 'POST' });

export const listAccounts = (base: string, h: Headers) =>
  request<{ accounts: ConnectedAccount[] }>(apiUrl(base, '/accounts'), h);

export const disconnectAccount = (base: string, h: Headers, id: string) =>
  request<{ deleted: boolean }>(apiUrl(base, `/accounts/${id}`), h, { method: 'DELETE' });

export const listGoogleCalendars = (base: string, h: Headers, accountId: string) =>
  request<{ calendars: GoogleCalendarChoice[] }>(apiUrl(base, `/accounts/${accountId}/google-calendars`), h);

export const setSyncedCalendars = (base: string, h: Headers, accountId: string, externalIds: string[]) =>
  request<{ calendars: Calendar[] }>(apiUrl(base, `/accounts/${accountId}/calendars`), h, {
    method: 'PUT', body: JSON.stringify({ externalIds }),
  });

export const syncNow = (base: string, h: Headers) =>
  request<{ results: SyncRunResult[] }>(apiUrl(base, '/sync/run'), h, { method: 'POST' });
```

- [ ] **Step 2: Create SettingsView.tsx**

`src/components/SettingsView.tsx` (match 4a's daisyUI idiom — `btn`, `card`, `checkbox`, `badge`, `alert`, `cal-eyebrow` headings):

```tsx
import { useCallback, useEffect, useState } from 'react';
import * as api from '../api';
import type { ConnectedAccount, GoogleCalendarChoice } from '../api';

interface SettingsViewProps {
  apiBase: string;
  headers: Record<string, string>;
  onBack: () => void;
}

function formatWhen(ms: number | null): string {
  return ms ? new Date(ms).toLocaleString() : 'never';
}

export function SettingsView({ apiBase, headers, onBack }: SettingsViewProps) {
  const [accounts, setAccounts] = useState<ConnectedAccount[]>([]);
  const [choices, setChoices] = useState<Record<string, GoogleCalendarChoice[]>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const { accounts } = await api.listAccounts(apiBase, headers);
      setAccounts(accounts);
      const loaded: Record<string, GoogleCalendarChoice[]> = {};
      for (const acc of accounts) {
        try {
          loaded[acc.id] = (await api.listGoogleCalendars(apiBase, headers, acc.id)).calendars;
        } catch (err) {
          loaded[acc.id] = [];
          setError(err instanceof Error ? err.message : 'Failed to list Google calendars');
        }
      }
      setChoices(loaded);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load accounts');
    }
  }, [apiBase, headers]);

  useEffect(() => {
    void refresh();
    const params = new URLSearchParams(window.location.search);
    if (params.get('connected')) setNotice('Google account connected.');
    const connectError = params.get('connect_error');
    if (connectError) setError(`Google connection failed: ${connectError}`);
  }, [refresh]);

  async function connectGoogle() {
    setBusy(true);
    setError(null);
    try {
      const { token } = await api.getConnectToken(apiBase, headers);
      const returnTo = `${window.location.origin}${window.location.pathname}`;
      window.location.href = `${apiBase}/api/oauth/google/connect?token=${encodeURIComponent(token)}&returnTo=${encodeURIComponent(returnTo)}`;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not start Google connect');
      setBusy(false);
    }
  }

  async function toggleCalendar(acc: ConnectedAccount, choice: GoogleCalendarChoice) {
    setBusy(true);
    setError(null);
    try {
      const current = (choices[acc.id] ?? []).filter((ch) => ch.synced).map((ch) => ch.externalId);
      const next = choice.synced ? current.filter((id) => id !== choice.externalId) : [...current, choice.externalId];
      await api.setSyncedCalendars(apiBase, headers, acc.id, next);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update synced calendars');
    } finally {
      setBusy(false);
    }
  }

  async function runSync() {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const { results } = await api.syncNow(apiBase, headers);
      const failed = results.filter((r) => r.error);
      setNotice(failed.length === 0
        ? `Synced ${results.length} calendar${results.length === 1 ? '' : 's'}.`
        : `Sync finished with ${failed.length} error(s): ${failed[0].error}`);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sync failed');
    } finally {
      setBusy(false);
    }
  }

  async function disconnect(acc: ConnectedAccount) {
    if (!window.confirm(`Disconnect ${acc.email}? Its synced calendars and events will be removed from Eldrin (Google is untouched).`)) return;
    setBusy(true);
    setError(null);
    try {
      await api.disconnectAccount(apiBase, headers, acc.id);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Disconnect failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="p-6 max-w-2xl mx-auto space-y-4 overflow-y-auto h-full">
      <div className="flex items-center justify-between">
        <h2 className="cal-eyebrow">Calendar settings</h2>
        <button className="btn btn-ghost btn-sm" onClick={onBack}>Back to calendar</button>
      </div>

      {error && <div className="alert alert-error text-sm py-2">{error}</div>}
      {notice && <div className="alert alert-success text-sm py-2">{notice}</div>}

      <section className="card bg-base-100 border border-base-300">
        <div className="card-body space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="font-medium">Google accounts</h3>
            <div className="flex gap-2">
              {accounts.length > 0 && (
                <button className="btn btn-sm" disabled={busy} onClick={() => void runSync()}>Sync now</button>
              )}
              <button className="btn btn-primary btn-sm" disabled={busy} onClick={() => void connectGoogle()}>
                Connect Google
              </button>
            </div>
          </div>

          {accounts.length === 0 && (
            <p className="text-sm opacity-70">No account connected yet. Connect Google to sync calendars two-way.</p>
          )}

          {accounts.map((acc) => (
            <div key={acc.id} className="border border-base-300 rounded-lg p-3 space-y-2">
              <div className="flex items-center justify-between">
                <div>
                  <span className="font-medium">{acc.email}</span>{' '}
                  <span className={`badge badge-sm ${acc.status === 'active' ? 'badge-success' : 'badge-error'}`}>{acc.status}</span>
                </div>
                <button className="btn btn-ghost btn-xs text-error" disabled={busy} onClick={() => void disconnect(acc)}>
                  Disconnect
                </button>
              </div>
              {acc.lastError && <p className="text-xs text-error">{acc.lastError}</p>}

              <ul className="space-y-1">
                {(choices[acc.id] ?? []).map((choice) => {
                  const local = acc.calendars.find((cal) => cal.externalId === choice.externalId);
                  return (
                    <li key={choice.externalId} className="flex items-center gap-2 text-sm">
                      <input
                        type="checkbox" className="checkbox checkbox-xs"
                        checked={choice.synced} disabled={busy}
                        onChange={() => void toggleCalendar(acc, choice)}
                      />
                      <span className="inline-block w-3 h-3 rounded-full" style={{ background: choice.color ?? '#4f6df5' }} />
                      <span className="flex-1">{choice.name}{choice.isPrimary ? ' (primary)' : ''}</span>
                      {local && (
                        <span className="text-xs opacity-60">
                          {local.syncStatus === 'error' ? `error: ${local.syncError}` : `${local.syncStatus ?? ''} · last sync ${formatWhen(local.lastSyncedAt)}`}
                        </span>
                      )}
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
```

- [ ] **Step 3: Pathname view switch in root.component.tsx**

Add a tiny hook and branch (keep ALL existing state/handlers untouched — the settings view mounts instead of the grid):

```tsx
function useIsSettingsRoute(): { isSettings: boolean; goToCalendar: () => void } {
  const [path, setPath] = useState(window.location.pathname);
  useEffect(() => {
    const onRoute = () => setPath(window.location.pathname);
    window.addEventListener('popstate', onRoute);
    window.addEventListener('single-spa:routing-event', onRoute);
    return () => {
      window.removeEventListener('popstate', onRoute);
      window.removeEventListener('single-spa:routing-event', onRoute);
    };
  }, []);
  const goToCalendar = useCallback(() => {
    window.history.pushState({}, '', path.replace(/\/settings\/?$/, '') || '/eldrin-calendar');
    window.dispatchEvent(new PopStateEvent('popstate'));
  }, [path]);
  return { isSettings: /\/settings\/?$/.test(path), goToCalendar };
}
```

In `Root`, right after `authHeaders` is available:

```tsx
  const { isSettings, goToCalendar } = useIsSettingsRoute();
  // … keep everything else, then in the render:
  if (isSettings) {
    return (
      <div data-theme={daisyTheme} className="cal-frame">
        <SettingsView apiBase={apiBase} headers={authHeaders} onBack={goToCalendar} />
      </div>
    );
  }
```

Match the actual outer wrapper of the existing render (read the file — reuse the same `data-theme` + frame classes the calendar view uses so theming is identical). When leaving settings (`goToCalendar`), the calendar view remounts and refetches — no extra invalidation needed; but ALSO refresh calendars when arriving back (the existing `loadCalendars` runs on mount — verify it does; if it runs in a `useEffect` with `[]` deps inside the always-mounted Root rather than per-view, call it from `goToCalendar` too).

- [ ] **Step 4: Sidebar grouping + Settings link in CalendarSidebar.tsx**

Read the current component first. Split its calendar list into two groups by `provider`:

```tsx
  const localCals = calendars.filter((cal) => cal.provider !== 'google');
  const googleCals = calendars.filter((cal) => cal.provider === 'google');
```

Render the existing list UI once per non-empty group with a small heading above each (`My calendars` / `Google`), reusing the exact row markup (color dot, visibility toggle, inline edit). For google rows: keep name/color editing enabled (calendar metadata stays local per spec §7) but suppress the delete affordance if the sidebar has one for non-default calendars (deletion of synced calendars goes through Settings). Add a sync-status hint on google rows:

```tsx
  {cal.syncStatus === 'error' && <span className="badge badge-error badge-xs" title={cal.syncError ?? ''}>sync error</span>}
  {cal.syncStatus === 'syncing' && <span className="loading loading-spinner loading-xs" />}
```

At the bottom of the sidebar (footer area), add:

```tsx
  <button
    className="btn btn-ghost btn-xs justify-start"
    onClick={() => {
      window.history.pushState({}, '', `${window.location.pathname.replace(/\/$/, '')}/settings`);
      window.dispatchEvent(new PopStateEvent('popstate'));
    }}
  >
    ⚙ Sync settings
  </button>
```

(If the sidebar receives no router-ish prop today, this self-contained pushState matches the hook in Step 3. In the standalone dev server the path is `/settings`; in the shell it's `/eldrin-calendar/settings` — the regex-based hook handles both.)

Manifest `ui.sideNav` gains:

```json
{ "label": "Settings", "icon": "settings", "path": "/eldrin-calendar/settings" }
```

- [ ] **Step 5: Typecheck + build + existing tests**

Run: `npx tsc -b && npm run build && npx vitest run`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-calendar commit -m "feat: settings view for Google accounts + sidebar sync grouping (Slice 4b Task 10)"
```

---

### Task 11: Live validation (Chrome DevTools MCP, real Google account) + ship

This task is executed by the MAIN session (not a subagent) because it drives the browser and needs the user's Google session.

**Prerequisites (user-visible; confirm before starting):**
- [ ] Google Cloud Console, same project/client as eldrin-email: **enable the Google Calendar API**; add `https://www.googleapis.com/auth/calendar` to the OAuth consent screen scopes; add `http://localhost:4012/api/oauth/google/callback` to the client's authorized redirect URIs. (These are manual user steps — ask the user to do them or confirm they're done before proceeding.)
- [ ] `eldrin-calendar/.dev.vars` contains `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET` (copied from `eldrin-email/.dev.vars`) and the shared `JWT_SECRET`.

**Steps:**

- [ ] **Start servers**: eldrin-core on 4000 (`cd eldrin-core && npm run dev`, background) and eldrin-calendar on 4012 (`cd eldrin-calendar && npm run dev`, background). The app was registered with core in 4a (app 39); re-verify with `curl -s http://localhost:4000/api/apps | grep eldrin-calendar` and re-register per 4a's dev-registration step if missing.
- [ ] **Browser validation with Chrome DevTools MCP** (load the tools via ToolSearch first, one batched call; new page on `http://localhost:4000`, log in, navigate to Calendar):
  1. **Settings + connect**: open `/eldrin-calendar/settings` via the sidebar link. Click **Connect Google** → real Google consent (user may need to pick the account/approve) → verify redirect back to settings with the account card visible and `?connected=google` in the URL.
  2. **Calendar selection**: verify the Google calendar list renders with primary pre-listed; enable a **test calendar** (create one in Google beforehand if needed — don't sync the primary calendar during validation). Wait for `syncStatus: ok` (refresh / re-open settings), then open the calendar grid and verify imported events render.
  3. **Write-through create**: create an event on the Google calendar in Eldrin → verify it appears in Google: open `https://calendar.google.com` in another tab (user is logged in) and confirm the event is there.
  4. **Write-through edit + delete**: rename the event in Eldrin, verify in Google; delete it in Eldrin, verify it's gone in Google.
  5. **Remote change pull**: create/edit an event directly in Google Calendar's web UI → back in Eldrin settings press **Sync now** → verify the change appears on the Eldrin grid.
  6. **Recurring round-trip**: create a weekly recurring event in Eldrin on the Google calendar; edit ONE occurrence (scope=single) and verify Google shows the moved instance; delete "this and following" from a later occurrence and verify Google truncates the series.
  7. **D9 regression**: create/edit/delete an event on a LOCAL calendar and confirm behavior is unchanged (no Google calls in the network log for those requests — check with `list_network_requests`).
  8. **Error surface** (optional but cheap): temporarily set a bogus `GOOGLE_CLIENT_SECRET` in `.dev.vars`, restart calendar dev server, press Sync now → account/calendar cards show the error; restore the secret afterwards and re-verify sync recovers.
  9. Check the browser console (`list_console_messages`) for errors after each major step.
- [ ] **Fix-forward** any issue found (small fixes inline; larger ones become new plan tasks) and re-run the affected validation step.
- [ ] **Ship**: use superpowers:finishing-a-development-branch — merge `feature/google-sync` to `main` in eldrin-calendar, push; bump the parent repo gitlink (`git add eldrin-calendar && git commit -m "chore: bump eldrin-calendar submodule — Google Calendar sync (Slice 4b)"`); stop dev servers.
- [ ] **Memory**: update the `calendar-standalone-app-decision` memory (4b shipped: what landed, webhook config gate, any new integration lessons).

## Plan Self-Review Notes

- Spec coverage: D11 (two-way: Tasks 5+8), D12 (selection: Task 7 PUT + Task 10 UI), D13 (write-through order: Task 8 tests assert Google-first + 502 abort), D14 (real-account validation: Task 11), D15 (Google authoritative: Task 5 idempotent upserts + echo suppression), §4 schema (Task 1), §5 modules/routes (Tasks 2–9), §6 translation incl. all-day/EXDATE (Task 3), §7 UI (Task 10), §8 testing (per-task TDD + Task 11), §9 risks (translation tests first — Task 3 before any wiring; instances endpoint instead of hand-built instance ids).
- The manifest `settings.groups` block ships in Task 6 with publicRoutes; sideNav ships in Task 10.
- Deliberate deviation from spec §5: spec sketched separate `sync.ts`-only trigger routes; this plan also routes account CRUD through `routes/sync.ts` — same file the spec names, no extra module.

