/**
 * Outlook / Microsoft Graph provider.
 *
 * Implements EmailProvider using the Microsoft Graph v1.0 Mail API.
 * Handles message listing, delta sync, message fetch/parse, and send.
 */

import type { EmailProvider, MessageRef, IncrementalSyncResult, SendResult } from './types';
import { ProviderApiError } from './types';
import type { ParsedEmail, SendMessageParams } from '../gmail-client';
import { refreshOutlookToken } from '../oauth-outlook';

const GRAPH_API = 'https://graph.microsoft.com/v1.0/me';

// ── Graph API types ─────────────────────────────────────────────────────────

interface GraphMessageRef {
  id: string;
  conversationId: string;
}

interface GraphRecipient {
  emailAddress: {
    name?: string;
    address: string;
  };
}

interface GraphMessage {
  id: string;
  conversationId: string;
  internetMessageId?: string;
  subject?: string;
  bodyPreview?: string;
  body?: {
    contentType: 'text' | 'html';
    content: string;
  };
  from?: GraphRecipient;
  toRecipients?: GraphRecipient[];
  ccRecipients?: GraphRecipient[];
  bccRecipients?: GraphRecipient[];
  receivedDateTime?: string;
  sentDateTime?: string;
  isRead?: boolean;
  hasAttachments?: boolean;
  internetMessageHeaders?: Array<{ name: string; value: string }>;
}

interface GraphListResponse<T> {
  value: T[];
  '@odata.nextLink'?: string;
  '@odata.deltaLink'?: string;
}

// ── Helpers ─────────────────────────────────────────────────────────────────

async function graphFetch<T>(
  accessToken: string,
  url: string,
  init?: RequestInit,
): Promise<T> {
  const res = await fetch(url, {
    ...init,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      ...init?.headers,
    },
  });

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new ProviderApiError(res.status, `Graph API error: ${res.status} ${body}`);
  }

  return res.json() as Promise<T>;
}

function extractAddresses(recipients?: GraphRecipient[]): string[] {
  if (!recipients) return [];
  return recipients.map((r) => r.emailAddress.address);
}

function parseGraphMessage(msg: GraphMessage, format: 'metadata' | 'full'): ParsedEmail {
  const from = msg.from?.emailAddress;
  const internetMessageId = msg.internetMessageId || `<${msg.id}@outlook.provider>`;

  // Find In-Reply-To from internet message headers
  const inReplyTo = msg.internetMessageHeaders
    ?.find((h) => h.name.toLowerCase() === 'in-reply-to')?.value || null;

  const receivedAt = msg.receivedDateTime
    ? new Date(msg.receivedDateTime).getTime()
    : Date.now();
  const sentAt = msg.sentDateTime
    ? new Date(msg.sentDateTime).getTime()
    : null;

  let bodyText: string | null = null;
  let bodyHtml: string | null = null;

  if (format === 'full' && msg.body) {
    if (msg.body.contentType === 'html') {
      bodyHtml = msg.body.content;
    } else {
      bodyText = msg.body.content;
    }
  }

  return {
    providerMessageId: msg.id,
    providerThreadId: msg.conversationId,
    messageId: internetMessageId,
    inReplyTo,
    fromAddress: from?.address ?? '',
    fromName: from?.name ?? null,
    toAddresses: extractAddresses(msg.toRecipients),
    ccAddresses: extractAddresses(msg.ccRecipients),
    bccAddresses: extractAddresses(msg.bccRecipients),
    subject: msg.subject ?? '',
    bodyText,
    bodyHtml,
    snippet: msg.bodyPreview ?? '',
    hasAttachments: msg.hasAttachments ?? false,
    labels: [], // Outlook uses categories, not labels
    receivedAt,
    sentAt,
    isRead: msg.isRead ?? false,
  };
}

// ── Provider ────────────────────────────────────────────────────────────────

// Fields requested for metadata-only sync
const METADATA_SELECT = [
  'id', 'conversationId', 'internetMessageId', 'subject', 'bodyPreview',
  'from', 'toRecipients', 'ccRecipients', 'bccRecipients',
  'receivedDateTime', 'sentDateTime', 'isRead', 'hasAttachments',
  'internetMessageHeaders',
].join(',');

// Fields requested for full message fetch (adds body)
const FULL_SELECT = `${METADATA_SELECT},body`;

export class OutlookProvider implements EmailProvider {
  async refreshAccessToken(
    refreshToken: string,
    clientId: string,
    clientSecret: string,
  ): Promise<{ accessToken: string; expiresIn: number; newRefreshToken?: string }> {
    return refreshOutlookToken(refreshToken, clientId, clientSecret);
  }

  async collectFirstSyncRefs(
    accessToken: string,
    syncDays: number,
    maxMessages: number,
  ): Promise<MessageRef[]> {
    const refs: MessageRef[] = [];
    let url: string;

    if (syncDays > 0) {
      const since = new Date(Date.now() - syncDays * 24 * 60 * 60 * 1000).toISOString();
      url = `${GRAPH_API}/messages?$filter=receivedDateTime ge ${since}&$select=id,conversationId&$orderby=receivedDateTime desc&$top=100`;
    } else {
      url = `${GRAPH_API}/messages?$select=id,conversationId&$orderby=receivedDateTime desc&$top=100`;
    }

    do {
      const response = await graphFetch<GraphListResponse<GraphMessageRef>>(accessToken, url);
      for (const msg of response.value) {
        refs.push({ id: msg.id, threadId: msg.conversationId });
      }
      url = response['@odata.nextLink'] ?? '';
    } while (url && refs.length < maxMessages);

    return refs.slice(0, maxMessages);
  }

  async collectIncrementalRefs(
    accessToken: string,
    cursor: string,
  ): Promise<IncrementalSyncResult> {
    const refs: MessageRef[] = [];

    // cursor is a full delta URL (deltaLink from previous sync)
    let url = cursor;

    try {
      do {
        const response = await graphFetch<GraphListResponse<GraphMessageRef>>(accessToken, url);
        for (const msg of response.value) {
          // Delta can include deleted messages (with @removed); skip those
          if (msg.id && msg.conversationId) {
            refs.push({ id: msg.id, threadId: msg.conversationId });
          }
        }
        url = response['@odata.nextLink'] ?? '';
      } while (url);
    } catch (err) {
      // Delta token expired or invalid — fall back to full sync
      if (err instanceof ProviderApiError && (err.status === 404 || err.status === 410)) {
        return { refs: [], cursorInvalid: true };
      }
      throw err;
    }

    return { refs, cursorInvalid: false };
  }

  async getMessage(
    accessToken: string,
    messageId: string,
    format: 'metadata' | 'full',
  ): Promise<ParsedEmail> {
    const select = format === 'full' ? FULL_SELECT : METADATA_SELECT;
    const msg = await graphFetch<GraphMessage>(
      accessToken,
      `${GRAPH_API}/messages/${messageId}?$select=${select}`,
    );
    return parseGraphMessage(msg, format);
  }

  async getSyncCursor(accessToken: string): Promise<string> {
    // Do an initial delta query to capture the current state as a deltaLink.
    // Delta must be scoped to a mail folder — top-level /messages/delta is not supported.
    // We use the well-known "inbox" folder and request minimal data to reduce payload.
    let url = `${GRAPH_API}/mailFolders/inbox/messages/delta?$select=id,conversationId&$top=50`;
    let deltaLink = '';

    // Walk through all pages to reach the deltaLink
    do {
      const response = await graphFetch<GraphListResponse<{ id: string }>>(accessToken, url);
      if (response['@odata.deltaLink']) {
        deltaLink = response['@odata.deltaLink'];
        break;
      }
      url = response['@odata.nextLink'] ?? '';
    } while (url);

    if (!deltaLink) {
      throw new Error('Failed to obtain delta link from Microsoft Graph');
    }

    return deltaLink;
  }

  async sendMessage(
    accessToken: string,
    params: SendMessageParams,
  ): Promise<SendResult> {
    const toRecipients: GraphRecipient[] = params.to.map((addr) => ({
      emailAddress: { address: addr },
    }));
    const ccRecipients: GraphRecipient[] = (params.cc ?? []).map((addr) => ({
      emailAddress: { address: addr },
    }));
    const bccRecipients: GraphRecipient[] = (params.bcc ?? []).map((addr) => ({
      emailAddress: { address: addr },
    }));

    const message: Record<string, unknown> = {
      subject: params.subject,
      body: {
        contentType: 'HTML',
        content: params.bodyHtml,
      },
      toRecipients,
      ccRecipients,
      bccRecipients,
    };

    if (params.inReplyTo) {
      message.internetMessageHeaders = [
        { name: 'In-Reply-To', value: params.inReplyTo },
      ];
      if (params.references) {
        (message.internetMessageHeaders as Array<{ name: string; value: string }>).push(
          { name: 'References', value: params.references },
        );
      }
    }

    // Graph sendMail doesn't return message details directly.
    // We need to: 1) create a draft, 2) send it, to get the message ID.
    // OR use sendMail (simpler, but no ID returned).
    //
    // For consistency with Gmail, create draft then send:
    const draft = await graphFetch<{ id: string; conversationId: string }>(
      accessToken,
      `${GRAPH_API}/messages`,
      {
        method: 'POST',
        body: JSON.stringify(message),
      },
    );

    await graphFetch<void>(
      accessToken,
      `${GRAPH_API}/messages/${draft.id}/send`,
      { method: 'POST' },
    ).catch(() => {
      // send returns 202 Accepted with no body — fetch may fail on json parse
    });

    return { id: draft.id, threadId: draft.conversationId };
  }
}
