/**
 * Microsoft / Outlook OAuth 2.0 service.
 *
 * Handles authorization URL generation, code exchange, and token refresh
 * against the Microsoft identity platform v2.0 endpoints.
 *
 * Scopes: Mail.Read, Mail.Send, Mail.ReadWrite, offline_access, User.Read
 */

const MS_AUTH_URL = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize';
const MS_TOKEN_URL = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';
const MS_GRAPH_URL = 'https://graph.microsoft.com/v1.0';

const OUTLOOK_SCOPES = [
  'Mail.Read',
  'Mail.Send',
  'Mail.ReadWrite',
  'offline_access',
  'User.Read',
].join(' ');

export interface OAuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface MicrosoftUserInfo {
  email: string;
  name: string;
}

/**
 * Build the Microsoft OAuth consent URL.
 */
export function getOutlookAuthUrl(
  clientId: string,
  redirectUri: string,
  state: string,
): string {
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: OUTLOOK_SCOPES,
    response_mode: 'query',
    prompt: 'consent',
    state,
  });
  return `${MS_AUTH_URL}?${params}`;
}

/**
 * Exchange an authorization code for access + refresh tokens.
 */
export async function exchangeOutlookCode(
  code: string,
  clientId: string,
  clientSecret: string,
  redirectUri: string,
): Promise<OAuthTokens> {
  const res = await fetch(MS_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
      scope: OUTLOOK_SCOPES,
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Outlook token exchange failed: ${res.status} ${body}`);
  }

  const data = await res.json() as {
    access_token: string;
    refresh_token?: string;
    expires_in: number;
  };

  if (!data.refresh_token) {
    throw new Error('No refresh token received — ensure offline_access scope is requested');
  }

  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresIn: data.expires_in,
  };
}

/**
 * Refresh an expired access token using a refresh token.
 */
export async function refreshOutlookToken(
  refreshToken: string,
  clientId: string,
  clientSecret: string,
): Promise<{ accessToken: string; expiresIn: number; newRefreshToken?: string }> {
  const res = await fetch(MS_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      refresh_token: refreshToken,
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: 'refresh_token',
      scope: OUTLOOK_SCOPES,
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Outlook token refresh failed: ${res.status} ${body}`);
  }

  const data = await res.json() as {
    access_token: string;
    expires_in: number;
    refresh_token?: string; // Microsoft ROTATES refresh tokens (AAD v2)
  };

  return {
    accessToken: data.access_token,
    expiresIn: data.expires_in,
    ...(data.refresh_token ? { newRefreshToken: data.refresh_token } : {}),
  };
}

/**
 * Fetch the authenticated user's email and display name from Microsoft Graph.
 */
export async function getMicrosoftUserInfo(accessToken: string): Promise<MicrosoftUserInfo> {
  const res = await fetch(`${MS_GRAPH_URL}/me`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!res.ok) {
    throw new Error(`Failed to fetch Microsoft user info: ${res.status}`);
  }

  const data = await res.json() as {
    mail?: string;
    userPrincipalName: string;
    displayName?: string;
  };

  // mail can be null for some account types; fall back to userPrincipalName
  const email = data.mail || data.userPrincipalName;
  return { email, name: data.displayName || email };
}
