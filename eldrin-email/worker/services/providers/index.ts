/**
 * Provider factory and shared utilities.
 *
 * Centralizes provider selection and the common getAccessToken pattern
 * that was previously duplicated in email-sync.ts and body-fetch.ts.
 */

import { eq } from 'drizzle-orm';
import type { Database } from '../../db';
import { connectedMailboxes } from '../../db/schema';
import { decryptToken, encryptToken } from '../crypto';
import { now } from '../../utils';
import type { EmailProvider } from './types';
import { GmailProvider } from './gmail';
import { OutlookProvider } from './outlook';

type MailboxRow = typeof connectedMailboxes.$inferSelect;

// Singleton instances (stateless, safe to reuse)
const gmailProvider = new GmailProvider();
const outlookProvider = new OutlookProvider();

/**
 * Get the provider implementation for a mailbox's provider type.
 */
export function getProvider(providerName: string): EmailProvider {
  switch (providerName) {
    case 'gmail':
      return gmailProvider;
    case 'outlook':
      return outlookProvider;
    default:
      throw new Error(`Unsupported email provider: ${providerName}`);
  }
}

/**
 * OAuth client credentials for a given provider.
 */
export interface OAuthConfig {
  clientId: string;
  clientSecret: string;
}

/**
 * Get the OAuth client ID and secret for a provider from env bindings.
 */
export function getOAuthConfig(env: Env, providerName: string): OAuthConfig {
  switch (providerName) {
    case 'gmail':
      return { clientId: env.GOOGLE_CLIENT_ID, clientSecret: env.GOOGLE_CLIENT_SECRET };
    case 'outlook':
      return { clientId: env.MICROSOFT_CLIENT_ID, clientSecret: env.MICROSOFT_CLIENT_SECRET };
    default:
      throw new Error(`No OAuth config for provider: ${providerName}`);
  }
}

/**
 * Get a valid access token — decrypts and refreshes if expired.
 * Updates the DB with the new encrypted access token after refresh.
 */
export async function getAccessToken(
  db: Database,
  mailbox: MailboxRow,
  env: Env,
  provider: EmailProvider,
): Promise<string> {
  const accessToken = await decryptToken(mailbox.accessTokenEncrypted, env.JWT_SECRET);

  // If token hasn't expired yet, use it directly
  if (mailbox.tokenExpiresAt > now()) {
    return accessToken;
  }

  // Refresh the token
  const refreshToken = await decryptToken(mailbox.refreshTokenEncrypted, env.JWT_SECRET);
  const { clientId, clientSecret } = getOAuthConfig(env, mailbox.provider);
  let refreshed;
  try {
    refreshed = await provider.refreshAccessToken(refreshToken, clientId, clientSecret);
  } catch (error) {
    // A revoked/expired grant is permanent — flag the mailbox so senders
    // and the first-active-mailbox fallback skip it until reconnected.
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes('invalid_grant')) {
      await db.update(connectedMailboxes)
        .set({
          syncStatus: 'error',
          errorMessage: 'Authorization expired or revoked — reconnect this mailbox',
          updatedAt: now(),
        })
        .where(eq(connectedMailboxes.id, mailbox.id));
    }
    throw error;
  }

  // Store the new encrypted access token
  const newEncrypted = await encryptToken(refreshed.accessToken, env.JWT_SECRET);
  const timestamp = now();

  await db.update(connectedMailboxes)
    .set({
      accessTokenEncrypted: newEncrypted,
      // Microsoft rotates refresh tokens — persist the replacement or the
      // mailbox bricks on the next refresh (live-verified in calendar 4c).
      ...(refreshed.newRefreshToken
        ? { refreshTokenEncrypted: await encryptToken(refreshed.newRefreshToken, env.JWT_SECRET) }
        : {}),
      tokenExpiresAt: timestamp + refreshed.expiresIn * 1000,
      updatedAt: timestamp,
    })
    .where(eq(connectedMailboxes.id, mailbox.id));

  return refreshed.accessToken;
}

// Re-export types for convenience
export { ProviderApiError } from './types';
export type { EmailProvider, MessageRef, SendResult } from './types';
export type { ParsedEmail, SendMessageParams } from './types';
