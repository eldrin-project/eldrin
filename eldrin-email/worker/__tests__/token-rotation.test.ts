import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockDecryptToken = vi.fn();
const mockEncryptToken = vi.fn();
vi.mock('../services/crypto', () => ({
  decryptToken: (...args: unknown[]) => mockDecryptToken(...args),
  encryptToken: (...args: unknown[]) => mockEncryptToken(...args),
}));

import { getAccessToken } from '../services/providers/index';
import { refreshOutlookToken } from '../services/oauth-outlook';
import type { Database } from '../db';
import type { EmailProvider } from '../services/providers/types';

function mailboxRow(overrides: Record<string, unknown> = {}) {
  return {
    id: 'mb1', provider: 'outlook',
    accessTokenEncrypted: 'enc:old-at', refreshTokenEncrypted: 'enc:old-rt',
    tokenExpiresAt: 0, // expired — forces a refresh
    ...overrides,
  } as never;
}

describe('rotated Microsoft refresh token persistence', () => {
  const updates: Record<string, unknown>[] = [];
  const db = {
    update: () => ({
      set: (vals: Record<string, unknown>) => ({
        where: async () => { updates.push(vals); },
      }),
    }),
  } as unknown as Database;
  const env = {
    JWT_SECRET: 's', MICROSOFT_CLIENT_ID: 'cid', MICROSOFT_CLIENT_SECRET: 'cs',
    GOOGLE_CLIENT_ID: 'g', GOOGLE_CLIENT_SECRET: 'gs',
  } as Env;

  beforeEach(() => {
    updates.length = 0;
    vi.clearAllMocks();
    mockDecryptToken.mockImplementation(async (v: string) => v.replace(/^enc:/, ''));
    mockEncryptToken.mockImplementation(async (v: string) => `enc:${v}`);
  });

  it('persists the rotated refresh token when the provider returns one', async () => {
    const provider = {
      refreshAccessToken: vi.fn(async () => ({
        accessToken: 'new-at', expiresIn: 3600, newRefreshToken: 'new-rt',
      })),
    } as unknown as EmailProvider;
    const token = await getAccessToken(db, mailboxRow(), env, provider);
    expect(token).toBe('new-at');
    expect(updates).toHaveLength(1);
    expect(updates[0].accessTokenEncrypted).toBe('enc:new-at');
    expect(updates[0].refreshTokenEncrypted).toBe('enc:new-rt');
  });

  it('leaves the stored refresh token alone when none is returned (Gmail path)', async () => {
    const provider = {
      refreshAccessToken: vi.fn(async () => ({ accessToken: 'new-at', expiresIn: 3600 })),
    } as unknown as EmailProvider;
    await getAccessToken(db, mailboxRow({ provider: 'gmail', GOOGLE: true }), env, provider);
    expect(updates).toHaveLength(1);
    expect(updates[0].refreshTokenEncrypted).toBeUndefined();
  });
});

describe('refreshOutlookToken response parsing', () => {
  it('surfaces the rotated refresh_token from the Microsoft response', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      access_token: 'at2', expires_in: 3600, refresh_token: 'rt2',
    }), { status: 200 })));
    try {
      const out = await refreshOutlookToken('rt1', 'cid', 'cs');
      expect(out.accessToken).toBe('at2');
      expect(out.newRefreshToken).toBe('rt2');
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
