import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  listMessages,
  listHistory,
  getMessage,
  getProfile,
  parseGmailMessage,
  GmailApiError,
  type GmailRawMessage,
} from '../services/gmail-client';

const ACCESS_TOKEN = 'ya29.test-token';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

beforeEach(() => {
  mockFetch.mockReset();
});

// ── API calls ─────────────────────────────────────────────────────────────────

describe('listMessages', () => {
  it('lists messages with query and pagination', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        messages: [
          { id: 'msg-1', threadId: 'thread-1' },
          { id: 'msg-2', threadId: 'thread-1' },
        ],
        nextPageToken: 'page-2',
        resultSizeEstimate: 50,
      }),
    });

    const result = await listMessages(ACCESS_TOKEN, 'after:2025/1/1', 50);

    expect(result.messages).toHaveLength(2);
    expect(result.nextPageToken).toBe('page-2');

    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toContain('/messages?');
    expect(url).toContain('q=after');
    expect(url).toContain('maxResults=50');
    expect(opts.headers.Authorization).toBe(`Bearer ${ACCESS_TOKEN}`);
  });

  it('includes pageToken when provided', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ messages: [] }),
    });

    await listMessages(ACCESS_TOKEN, 'label:inbox', 100, 'next-page');

    const [url] = mockFetch.mock.calls[0];
    expect(url).toContain('pageToken=next-page');
  });
});

describe('listHistory', () => {
  it('fetches history since a given historyId', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        history: [
          {
            id: '12345',
            messagesAdded: [{ message: { id: 'msg-new', threadId: 'thread-1' } }],
          },
        ],
        historyId: '12346',
      }),
    });

    const result = await listHistory(ACCESS_TOKEN, '12340');

    expect(result.history).toHaveLength(1);
    expect(result.history![0].messagesAdded![0].message.id).toBe('msg-new');
  });
});

describe('getMessage', () => {
  it('fetches with metadata format by default', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ id: 'msg-1', threadId: 'thread-1' }),
    });

    await getMessage(ACCESS_TOKEN, 'msg-1');

    const [url] = mockFetch.mock.calls[0];
    expect(url).toContain('format=metadata');
    expect(url).toContain('metadataHeaders=');
  });

  it('fetches with full format when requested', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ id: 'msg-1', threadId: 'thread-1' }),
    });

    await getMessage(ACCESS_TOKEN, 'msg-1', 'full');

    const [url] = mockFetch.mock.calls[0];
    expect(url).toContain('format=full');
    expect(url).not.toContain('metadataHeaders=');
  });
});

describe('getProfile', () => {
  it('returns email and historyId', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        emailAddress: 'user@gmail.com',
        historyId: '99999',
      }),
    });

    const profile = await getProfile(ACCESS_TOKEN);
    expect(profile.emailAddress).toBe('user@gmail.com');
    expect(profile.historyId).toBe('99999');
  });
});

describe('GmailApiError', () => {
  it('throws on non-ok responses', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 401,
      text: () => Promise.resolve('{"error": "invalid_token"}'),
    });

    await expect(getMessage(ACCESS_TOKEN, 'msg-1')).rejects.toThrow(GmailApiError);
    await expect(getMessage(ACCESS_TOKEN, 'msg-1')).rejects.not.toBeUndefined();
  });

  it('includes status code on error', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 429,
      text: () => Promise.resolve('rate limited'),
    });

    try {
      await listMessages(ACCESS_TOKEN, 'label:inbox');
    } catch (err) {
      expect(err).toBeInstanceOf(GmailApiError);
      expect((err as GmailApiError).status).toBe(429);
    }
  });
});

// ── Parsing ───────────────────────────────────────────────────────────────────

describe('parseGmailMessage', () => {
  function makeRawMessage(overrides?: Partial<GmailRawMessage>): GmailRawMessage {
    return {
      id: 'msg-123',
      threadId: 'thread-456',
      labelIds: ['INBOX', 'UNREAD'],
      snippet: 'Hey, just checking in...',
      historyId: '12345',
      internalDate: '1700000000000',
      payload: {
        mimeType: 'multipart/alternative',
        headers: [
          { name: 'From', value: 'Alice Smith <alice@example.com>' },
          { name: 'To', value: 'bob@example.com, Charlie <charlie@example.com>' },
          { name: 'Cc', value: 'dave@example.com' },
          { name: 'Subject', value: 'Hello from Alice' },
          { name: 'Message-ID', value: '<abc123@mail.example.com>' },
          { name: 'In-Reply-To', value: '<xyz789@mail.example.com>' },
          { name: 'Date', value: 'Tue, 14 Nov 2023 12:00:00 +0000' },
        ],
        parts: [
          {
            mimeType: 'text/plain',
            body: { data: btoa('Hello plain text'), size: 16 },
          },
          {
            mimeType: 'text/html',
            body: { data: btoa('<p>Hello HTML</p>'), size: 18 },
          },
        ],
      },
      ...overrides,
    };
  }

  it('extracts provider IDs', () => {
    const parsed = parseGmailMessage(makeRawMessage());
    expect(parsed.providerMessageId).toBe('msg-123');
    expect(parsed.providerThreadId).toBe('thread-456');
  });

  it('parses from address and name', () => {
    const parsed = parseGmailMessage(makeRawMessage());
    expect(parsed.fromAddress).toBe('alice@example.com');
    expect(parsed.fromName).toBe('Alice Smith');
  });

  it('parses address lists (to, cc, bcc)', () => {
    const parsed = parseGmailMessage(makeRawMessage());
    expect(parsed.toAddresses).toHaveLength(2);
    expect(parsed.ccAddresses).toHaveLength(1);
    expect(parsed.bccAddresses).toHaveLength(0);
  });

  it('extracts Message-ID and In-Reply-To', () => {
    const parsed = parseGmailMessage(makeRawMessage());
    expect(parsed.messageId).toBe('<abc123@mail.example.com>');
    expect(parsed.inReplyTo).toBe('<xyz789@mail.example.com>');
  });

  it('extracts body text and HTML', () => {
    const parsed = parseGmailMessage(makeRawMessage());
    expect(parsed.bodyText).toBe('Hello plain text');
    expect(parsed.bodyHtml).toBe('<p>Hello HTML</p>');
  });

  it('returns null body when format=metadata (no body data)', () => {
    const raw = makeRawMessage();
    // Simulate metadata format — payload has headers but no body data in parts
    raw.payload!.parts = [];
    const parsed = parseGmailMessage(raw);
    expect(parsed.bodyText).toBeNull();
    expect(parsed.bodyHtml).toBeNull();
  });

  it('detects unread status from UNREAD label', () => {
    const parsed = parseGmailMessage(makeRawMessage());
    expect(parsed.isRead).toBe(false);

    const readMsg = makeRawMessage({ labelIds: ['INBOX'] });
    const parsedRead = parseGmailMessage(readMsg);
    expect(parsedRead.isRead).toBe(true);
  });

  it('detects attachments', () => {
    const raw = makeRawMessage();
    raw.payload!.parts!.push({
      mimeType: 'application/pdf',
      body: { attachmentId: 'att-1', size: 1024 },
    });
    const parsed = parseGmailMessage(raw);
    expect(parsed.hasAttachments).toBe(true);
  });

  it('handles no attachments', () => {
    const parsed = parseGmailMessage(makeRawMessage());
    expect(parsed.hasAttachments).toBe(false);
  });

  it('uses snippet from raw message', () => {
    const parsed = parseGmailMessage(makeRawMessage());
    expect(parsed.snippet).toBe('Hey, just checking in...');
  });

  it('uses internalDate for receivedAt', () => {
    const parsed = parseGmailMessage(makeRawMessage());
    expect(parsed.receivedAt).toBe(1700000000000);
  });

  it('parses Date header for sentAt', () => {
    const parsed = parseGmailMessage(makeRawMessage());
    expect(parsed.sentAt).toBeTypeOf('number');
    expect(parsed.sentAt).toBeGreaterThan(0);
  });

  it('falls back to provider ID as Message-ID when header missing', () => {
    const raw = makeRawMessage();
    raw.payload!.headers = raw.payload!.headers.filter(
      (h) => h.name !== 'Message-ID',
    );
    const parsed = parseGmailMessage(raw);
    expect(parsed.messageId).toBe('<msg-123@gmail.provider>');
  });

  it('parses from address without display name', () => {
    const raw = makeRawMessage();
    raw.payload!.headers = raw.payload!.headers.map((h) =>
      h.name === 'From' ? { ...h, value: 'plain@example.com' } : h,
    );
    const parsed = parseGmailMessage(raw);
    expect(parsed.fromAddress).toBe('plain@example.com');
    expect(parsed.fromName).toBeNull();
  });

  it('extracts labels array', () => {
    const parsed = parseGmailMessage(makeRawMessage());
    expect(parsed.labels).toEqual(['INBOX', 'UNREAD']);
  });

  it('handles nested multipart parts', () => {
    const raw: GmailRawMessage = {
      id: 'nested-1',
      threadId: 'thread-1',
      labelIds: [],
      internalDate: '1700000000000',
      payload: {
        mimeType: 'multipart/mixed',
        headers: [
          { name: 'From', value: 'test@example.com' },
          { name: 'To', value: 'recipient@example.com' },
          { name: 'Subject', value: 'Nested' },
          { name: 'Message-ID', value: '<nested@example.com>' },
        ],
        parts: [
          {
            mimeType: 'multipart/alternative',
            parts: [
              {
                mimeType: 'text/plain',
                body: { data: btoa('Nested plain'), size: 12 },
              },
              {
                mimeType: 'text/html',
                body: { data: btoa('<b>Nested HTML</b>'), size: 18 },
              },
            ],
          },
          {
            mimeType: 'application/pdf',
            body: { attachmentId: 'att-1', size: 2048 },
          },
        ],
      },
    };
    const parsed = parseGmailMessage(raw);
    expect(parsed.bodyText).toBe('Nested plain');
    expect(parsed.bodyHtml).toBe('<b>Nested HTML</b>');
    expect(parsed.hasAttachments).toBe(true);
  });
});
