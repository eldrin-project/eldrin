/**
 * Gmail API client.
 *
 * Wraps the Gmail REST API for listing, getting, and parsing messages.
 * Uses format=metadata for efficient sync and format=full for body fetch.
 */

const GMAIL_API = 'https://gmail.googleapis.com/gmail/v1/users/me';

// ── Types ────────────────────────────────────────────────────────────────────

export interface GmailMessageRef {
  id: string;
  threadId: string;
}

export interface GmailListResponse {
  messages?: GmailMessageRef[];
  nextPageToken?: string;
  resultSizeEstimate?: number;
}

export interface GmailHistoryResponse {
  history?: Array<{
    id: string;
    messagesAdded?: Array<{ message: GmailMessageRef }>;
  }>;
  nextPageToken?: string;
  historyId: string;
}

interface GmailHeader {
  name: string;
  value: string;
}

interface GmailPart {
  mimeType: string;
  headers?: GmailHeader[];
  body?: { data?: string; size?: number; attachmentId?: string };
  parts?: GmailPart[];
}

export interface GmailRawMessage {
  id: string;
  threadId: string;
  labelIds?: string[];
  snippet?: string;
  historyId?: string;
  internalDate?: string;
  payload?: GmailPart & { headers: GmailHeader[] };
  sizeEstimate?: number;
}

export interface ParsedEmail {
  providerMessageId: string;
  providerThreadId: string;
  messageId: string;
  inReplyTo: string | null;
  fromAddress: string;
  fromName: string | null;
  toAddresses: string[];
  ccAddresses: string[];
  bccAddresses: string[];
  subject: string;
  bodyText: string | null;
  bodyHtml: string | null;
  snippet: string;
  hasAttachments: boolean;
  labels: string[];
  receivedAt: number;
  sentAt: number | null;
  isRead: boolean;
}

// ── API calls ────────────────────────────────────────────────────────────────

async function gmailFetch<T>(accessToken: string, path: string): Promise<T> {
  const res = await fetch(`${GMAIL_API}${path}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new GmailApiError(res.status, `Gmail API error: ${res.status} ${body}`);
  }

  return res.json() as Promise<T>;
}

export class GmailApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = 'GmailApiError';
  }
}

/**
 * List messages matching a query (for first sync).
 */
export async function listMessages(
  accessToken: string,
  query: string,
  maxResults = 100,
  pageToken?: string,
): Promise<GmailListResponse> {
  const params = new URLSearchParams({
    q: query,
    maxResults: String(maxResults),
  });
  if (pageToken) params.set('pageToken', pageToken);
  return gmailFetch(accessToken, `/messages?${params}`);
}

/**
 * List message changes since a historyId (for incremental sync).
 */
export async function listHistory(
  accessToken: string,
  startHistoryId: string,
  pageToken?: string,
): Promise<GmailHistoryResponse> {
  const params = new URLSearchParams({
    startHistoryId,
    historyTypes: 'messageAdded',
  });
  if (pageToken) params.set('pageToken', pageToken);
  return gmailFetch(accessToken, `/history?${params}`);
}

/**
 * Get a single message. Use format=metadata for sync, format=full for body.
 */
export async function getMessage(
  accessToken: string,
  messageId: string,
  format: 'metadata' | 'full' = 'metadata',
): Promise<GmailRawMessage> {
  const params = new URLSearchParams({ format });
  if (format === 'metadata') {
    params.set('metadataHeaders', 'From,To,Cc,Bcc,Subject,Message-ID,In-Reply-To,Date');
  }
  return gmailFetch(accessToken, `/messages/${messageId}?${params}`);
}

/**
 * Get the user's current historyId (for initializing sync cursor).
 */
export async function getProfile(
  accessToken: string,
): Promise<{ emailAddress: string; historyId: string }> {
  return gmailFetch(accessToken, '/profile');
}

// ── Parsing ──────────────────────────────────────────────────────────────────

function getHeader(headers: GmailHeader[], name: string): string {
  return headers.find((h) => h.name.toLowerCase() === name.toLowerCase())?.value ?? '';
}

function parseEmailAddress(raw: string): { address: string; name: string | null } {
  // "Display Name <email@example.com>" or just "email@example.com"
  const match = raw.match(/^(.+?)\s*<([^>]+)>$/);
  if (match) {
    return { name: match[1].replace(/^"|"$/g, '').trim(), address: match[2] };
  }
  return { name: null, address: raw.trim() };
}

function parseAddressList(raw: string): string[] {
  if (!raw) return [];
  // Split on comma but not within quoted strings
  return raw.split(/,(?=(?:[^"]*"[^"]*")*[^"]*$)/).map((s) => s.trim()).filter(Boolean);
}

function decodeBase64Url(data: string): string {
  const padded = data.replace(/-/g, '+').replace(/_/g, '/');
  return atob(padded);
}

function extractBody(part: GmailPart): { text: string | null; html: string | null } {
  let text: string | null = null;
  let html: string | null = null;

  if (part.mimeType === 'text/plain' && part.body?.data) {
    text = decodeBase64Url(part.body.data);
  } else if (part.mimeType === 'text/html' && part.body?.data) {
    html = decodeBase64Url(part.body.data);
  }

  if (part.parts) {
    for (const sub of part.parts) {
      const result = extractBody(sub);
      if (result.text && !text) text = result.text;
      if (result.html && !html) html = result.html;
    }
  }

  return { text, html };
}

function hasAttachmentParts(part: GmailPart): boolean {
  if (part.body?.attachmentId) return true;
  if (part.parts) return part.parts.some(hasAttachmentParts);
  return false;
}

/**
 * Parse a raw Gmail API message into our normalized format.
 * When format=metadata, bodyText and bodyHtml will be null.
 */
export function parseGmailMessage(raw: GmailRawMessage): ParsedEmail {
  const headers = raw.payload?.headers ?? [];
  const from = parseEmailAddress(getHeader(headers, 'From'));
  const toRaw = parseAddressList(getHeader(headers, 'To'));
  const ccRaw = parseAddressList(getHeader(headers, 'Cc'));
  const bccRaw = parseAddressList(getHeader(headers, 'Bcc'));

  // Extract body from payload (null when format=metadata)
  const body = raw.payload ? extractBody(raw.payload) : { text: null, html: null };

  const dateHeader = getHeader(headers, 'Date');
  const internalDate = raw.internalDate ? Number(raw.internalDate) : Date.now();
  const sentAt = dateHeader ? new Date(dateHeader).getTime() : null;

  const messageIdHeader = getHeader(headers, 'Message-ID') || getHeader(headers, 'Message-Id');
  // Fallback: use provider ID if no Message-ID header (rare but possible)
  const messageId = messageIdHeader || `<${raw.id}@gmail.provider>`;

  return {
    providerMessageId: raw.id,
    providerThreadId: raw.threadId,
    messageId,
    inReplyTo: getHeader(headers, 'In-Reply-To') || null,
    fromAddress: from.address,
    fromName: from.name,
    toAddresses: toRaw,
    ccAddresses: ccRaw,
    bccAddresses: bccRaw,
    subject: getHeader(headers, 'Subject'),
    bodyText: body.text,
    bodyHtml: body.html,
    snippet: raw.snippet ?? '',
    hasAttachments: raw.payload ? hasAttachmentParts(raw.payload) : false,
    labels: raw.labelIds ?? [],
    receivedAt: internalDate,
    sentAt,
    isRead: !(raw.labelIds?.includes('UNREAD') ?? true),
  };
}
