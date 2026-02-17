import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  getGmailAuthUrl,
  exchangeGmailCode,
  refreshGmailToken,
  getGoogleUserInfo,
  revokeGmailToken,
} from '../services/oauth-gmail';

const CLIENT_ID = 'test-client-id.apps.googleusercontent.com';
const CLIENT_SECRET = 'test-client-secret';
const REDIRECT_URI = 'https://example.com/api/mailbox/callback/gmail';

// Mock global fetch
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

beforeEach(() => {
  mockFetch.mockReset();
});

describe('getGmailAuthUrl', () => {
  it('builds correct Google OAuth URL with required params', () => {
    const url = getGmailAuthUrl(CLIENT_ID, REDIRECT_URI, 'test-state');
    const parsed = new URL(url);

    expect(parsed.origin + parsed.pathname).toBe('https://accounts.google.com/o/oauth2/v2/auth');
    expect(parsed.searchParams.get('client_id')).toBe(CLIENT_ID);
    expect(parsed.searchParams.get('redirect_uri')).toBe(REDIRECT_URI);
    expect(parsed.searchParams.get('response_type')).toBe('code');
    expect(parsed.searchParams.get('access_type')).toBe('offline');
    expect(parsed.searchParams.get('prompt')).toBe('consent');
    expect(parsed.searchParams.get('state')).toBe('test-state');
  });

  it('includes required Gmail scopes', () => {
    const url = getGmailAuthUrl(CLIENT_ID, REDIRECT_URI, 'state');
    const parsed = new URL(url);
    const scope = parsed.searchParams.get('scope')!;

    expect(scope).toContain('gmail.readonly');
    expect(scope).toContain('gmail.send');
    expect(scope).toContain('gmail.compose');
    expect(scope).toContain('userinfo.email');
  });
});

describe('exchangeGmailCode', () => {
  it('exchanges code for tokens', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        access_token: 'ya29.access-token',
        refresh_token: '1//0refresh-token',
        expires_in: 3600,
      }),
    });

    const tokens = await exchangeGmailCode('auth-code', CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);

    expect(tokens.accessToken).toBe('ya29.access-token');
    expect(tokens.refreshToken).toBe('1//0refresh-token');
    expect(tokens.expiresIn).toBe(3600);

    expect(mockFetch).toHaveBeenCalledOnce();
    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe('https://oauth2.googleapis.com/token');
    expect(opts.method).toBe('POST');
  });

  it('throws when no refresh token is returned', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        access_token: 'ya29.access-token',
        expires_in: 3600,
        // no refresh_token
      }),
    });

    await expect(
      exchangeGmailCode('code', CLIENT_ID, CLIENT_SECRET, REDIRECT_URI),
    ).rejects.toThrow('No refresh token');
  });

  it('throws on HTTP error', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 400,
      text: () => Promise.resolve('{"error": "invalid_grant"}'),
    });

    await expect(
      exchangeGmailCode('bad-code', CLIENT_ID, CLIENT_SECRET, REDIRECT_URI),
    ).rejects.toThrow('Gmail token exchange failed');
  });
});

describe('refreshGmailToken', () => {
  it('refreshes an access token', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        access_token: 'ya29.new-token',
        expires_in: 3600,
      }),
    });

    const result = await refreshGmailToken('refresh-token', CLIENT_ID, CLIENT_SECRET);
    expect(result.accessToken).toBe('ya29.new-token');
    expect(result.expiresIn).toBe(3600);
  });
});

describe('getGoogleUserInfo', () => {
  it('fetches user email and name', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        email: 'user@gmail.com',
        name: 'Test User',
      }),
    });

    const info = await getGoogleUserInfo('access-token');
    expect(info.email).toBe('user@gmail.com');
    expect(info.name).toBe('Test User');

    const [, opts] = mockFetch.mock.calls[0];
    expect(opts.headers.Authorization).toBe('Bearer access-token');
  });
});

describe('revokeGmailToken', () => {
  it('calls revoke endpoint (best-effort)', async () => {
    mockFetch.mockResolvedValueOnce({ ok: true });

    await revokeGmailToken('some-token');

    const [url] = mockFetch.mock.calls[0];
    expect(url).toContain('https://oauth2.googleapis.com/revoke');
    expect(url).toContain('token=some-token');
  });

  it('does not throw on revocation failure', async () => {
    mockFetch.mockResolvedValueOnce({ ok: false, status: 400 });

    // Should not throw — revocation is best-effort
    await expect(revokeGmailToken('bad-token')).resolves.toBeUndefined();
  });
});
