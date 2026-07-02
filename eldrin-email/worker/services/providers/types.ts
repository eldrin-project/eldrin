/**
 * Email provider abstraction.
 *
 * Defines the interface that Gmail, Outlook, and future providers implement
 * so the sync engine, body-fetch, and send route are provider-agnostic.
 */

import type { ParsedEmail, SendMessageParams } from '../gmail-client';

// ── Shared types ────────────────────────────────────────────────────────────

export interface MessageRef {
  id: string;
  threadId: string;
}

export interface SendResult {
  id: string;
  threadId: string;
}

export interface IncrementalSyncResult {
  refs: MessageRef[];
  cursorInvalid: boolean;
}

// ── Provider interface ──────────────────────────────────────────────────────

export interface EmailProvider {
  /** Refresh an expired access token using the refresh token. */
  refreshAccessToken(
    refreshToken: string,
    clientId: string,
    clientSecret: string,
  ): Promise<{ accessToken: string; expiresIn: number }>;

  /**
   * Collect message references for first-time sync.
   * @param syncDays - Number of days to look back (0 = all)
   * @param maxMessages - Maximum messages to fetch
   */
  collectFirstSyncRefs(
    accessToken: string,
    syncDays: number,
    maxMessages: number,
  ): Promise<MessageRef[]>;

  /**
   * Collect message references for incremental sync since cursor.
   * Returns cursorInvalid=true if the cursor has expired (caller should fall back to first sync).
   */
  collectIncrementalRefs(
    accessToken: string,
    cursor: string,
  ): Promise<IncrementalSyncResult>;

  /**
   * Fetch and parse a single message.
   * @param format - 'metadata' for sync (headers/snippet only), 'full' for body content
   */
  getMessage(
    accessToken: string,
    messageId: string,
    format: 'metadata' | 'full',
  ): Promise<ParsedEmail>;

  /**
   * Get the current sync cursor.
   * Gmail: historyId from profile. Outlook: deltaLink from initial delta query.
   */
  getSyncCursor(accessToken: string): Promise<string>;

  /**
   * Send an email message.
   */
  sendMessage(
    accessToken: string,
    params: SendMessageParams,
  ): Promise<SendResult>;
}

// ── Error class ─────────────────────────────────────────────────────────────

export class ProviderApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = 'ProviderApiError';
  }
}

// Re-export ParsedEmail and SendMessageParams so consumers can import from providers
export type { ParsedEmail, SendMessageParams } from '../gmail-client';
