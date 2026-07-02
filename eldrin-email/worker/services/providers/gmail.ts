/**
 * Gmail provider.
 *
 * Implements EmailProvider by wrapping the low-level gmail-client.ts
 * and oauth-gmail.ts modules.
 */

import type { EmailProvider, MessageRef, IncrementalSyncResult, SendResult } from './types';
import { ProviderApiError } from './types';
import type { ParsedEmail, SendMessageParams } from '../gmail-client';
import {
  listMessages,
  listHistory,
  getMessage as gmailGetMessage,
  getProfile,
  parseGmailMessage,
  sendMessage as gmailSendMessage,
  GmailApiError,
  type GmailMessageRef,
} from '../gmail-client';
import { refreshGmailToken } from '../oauth-gmail';

const FIRST_SYNC_MAX_MESSAGES = 500;

export class GmailProvider implements EmailProvider {
  async refreshAccessToken(
    refreshToken: string,
    clientId: string,
    clientSecret: string,
  ): Promise<{ accessToken: string; expiresIn: number }> {
    return refreshGmailToken(refreshToken, clientId, clientSecret);
  }

  async collectFirstSyncRefs(
    accessToken: string,
    syncDays: number,
    maxMessages: number,
  ): Promise<MessageRef[]> {
    const max = Math.min(maxMessages, FIRST_SYNC_MAX_MESSAGES);

    let query = '';
    if (syncDays > 0) {
      const since = new Date(Date.now() - syncDays * 24 * 60 * 60 * 1000);
      query = `after:${since.getFullYear()}/${since.getMonth() + 1}/${since.getDate()}`;
    }

    const refs: GmailMessageRef[] = [];
    let pageToken: string | undefined;

    do {
      const response = await listMessages(accessToken, query, 100, pageToken);
      if (response.messages) {
        refs.push(...response.messages);
      }
      pageToken = response.nextPageToken;
    } while (pageToken && refs.length < max);

    return refs.slice(0, max);
  }

  async collectIncrementalRefs(
    accessToken: string,
    cursor: string,
  ): Promise<IncrementalSyncResult> {
    const refs: MessageRef[] = [];
    let pageToken: string | undefined;

    try {
      do {
        const response = await listHistory(accessToken, cursor, pageToken);
        if (response.history) {
          for (const entry of response.history) {
            if (entry.messagesAdded) {
              refs.push(...entry.messagesAdded.map((a) => a.message));
            }
          }
        }
        pageToken = response.nextPageToken;
      } while (pageToken);
    } catch (err) {
      // historyId expired or invalid — caller should fall back to full sync
      if (err instanceof GmailApiError && (err.status === 404 || err.status === 410)) {
        return { refs: [], cursorInvalid: true };
      }
      throw this.wrapError(err);
    }

    return { refs, cursorInvalid: false };
  }

  async getMessage(
    accessToken: string,
    messageId: string,
    format: 'metadata' | 'full',
  ): Promise<ParsedEmail> {
    try {
      const raw = await gmailGetMessage(accessToken, messageId, format);
      return parseGmailMessage(raw);
    } catch (err) {
      throw this.wrapError(err);
    }
  }

  async getSyncCursor(accessToken: string): Promise<string> {
    const profile = await getProfile(accessToken);
    return profile.historyId;
  }

  async sendMessage(
    accessToken: string,
    params: SendMessageParams,
  ): Promise<SendResult> {
    try {
      const result = await gmailSendMessage(accessToken, params);
      return { id: result.id, threadId: result.threadId };
    } catch (err) {
      throw this.wrapError(err);
    }
  }

  /** Convert GmailApiError to ProviderApiError for uniform error handling. */
  private wrapError(err: unknown): Error {
    if (err instanceof GmailApiError) {
      return new ProviderApiError(err.status, err.message);
    }
    return err instanceof Error ? err : new Error(String(err));
  }
}
