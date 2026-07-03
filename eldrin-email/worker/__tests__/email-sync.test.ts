import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock all external dependencies before imports
const mockDecryptToken = vi.fn();
const mockEncryptToken = vi.fn();
const mockRefreshGmailToken = vi.fn();
const mockListMessages = vi.fn();
const mockListHistory = vi.fn();
const mockGetMessage = vi.fn();
const mockGetProfile = vi.fn();
const mockParseGmailMessage = vi.fn();
const mockEmitEmailReceived = vi.fn();

vi.mock('../services/crypto', () => ({
  decryptToken: (...args: unknown[]) => mockDecryptToken(...args),
  encryptToken: (...args: unknown[]) => mockEncryptToken(...args),
}));

vi.mock('../services/oauth-gmail', () => ({
  refreshGmailToken: (...args: unknown[]) => mockRefreshGmailToken(...args),
}));

vi.mock('../services/gmail-client', () => ({
  listMessages: (...args: unknown[]) => mockListMessages(...args),
  listHistory: (...args: unknown[]) => mockListHistory(...args),
  getMessage: (...args: unknown[]) => mockGetMessage(...args),
  getProfile: (...args: unknown[]) => mockGetProfile(...args),
  parseGmailMessage: (...args: unknown[]) => mockParseGmailMessage(...args),
  GmailApiError: class GmailApiError extends Error {
    constructor(public status: number, message: string) {
      super(message);
      this.name = 'GmailApiError';
    }
  },
}));

// Partial mock: capture emitted events but keep the real buildEventBodyText.
vi.mock('../services/event-emitter', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../services/event-emitter')>();
  return {
    ...actual,
    emitEmailReceived: (...args: unknown[]) => mockEmitEmailReceived(...args),
  };
});

import { syncMailbox } from '../services/email-sync';

// ── Mock database ────────────────────────────────────────────────────────────

function createMockDb() {
  const store = {
    mailboxes: new Map<string, Record<string, unknown>>(),
    threads: new Map<string, Record<string, unknown>>(),
    emails: new Map<string, Record<string, unknown>>(),
  };

  return {
    store,
    query: {
      connectedMailboxes: {
        findFirst: vi.fn(),
        findMany: vi.fn().mockResolvedValue([]),
      },
      emailThreads: {
        findFirst: vi.fn().mockResolvedValue(null),
        findMany: vi.fn().mockResolvedValue([]),
      },
      emails: {
        findFirst: vi.fn().mockResolvedValue(null),
        findMany: vi.fn().mockResolvedValue([]),
      },
    },
    insert: vi.fn().mockReturnValue({
      values: vi.fn().mockResolvedValue(undefined),
    }),
    update: vi.fn().mockReturnValue({
      set: vi.fn().mockReturnValue({
        where: vi.fn().mockResolvedValue(undefined),
      }),
    }),
    delete: vi.fn().mockReturnValue({
      where: vi.fn().mockResolvedValue(undefined),
    }),
  };
}

const ENV: Env = {
  DB: {} as D1Database,
  ASSETS: {} as Fetcher,
  JWT_SECRET: 'test-jwt-secret',
  GOOGLE_CLIENT_ID: 'test-client-id',
  GOOGLE_CLIENT_SECRET: 'test-client-secret',
  MICROSOFT_CLIENT_ID: 'test-ms-client-id',
  MICROSOFT_CLIENT_SECRET: 'test-ms-client-secret',
};

function createTestMailbox(overrides?: Record<string, unknown>) {
  return {
    id: 'mailbox-1',
    userId: 'user-1',
    provider: 'gmail',
    emailAddress: 'user@gmail.com',
    displayName: 'Test User',
    accessTokenEncrypted: 'encrypted-access',
    refreshTokenEncrypted: 'encrypted-refresh',
    tokenExpiresAt: Date.now() + 3600000, // 1 hour from now
    lastSyncAt: null,
    syncStatus: 'active',
    syncDepth: 'metadata',
    syncCursor: null,
    errorMessage: null,
    createdAt: Date.now(),
    updatedAt: Date.now(),
    ...overrides,
  };
}

function createParsedEmail(overrides?: Record<string, unknown>) {
  return {
    providerMessageId: 'msg-1',
    providerThreadId: 'thread-1',
    messageId: '<test@example.com>',
    inReplyTo: null,
    fromAddress: 'sender@example.com',
    fromName: 'Sender',
    toAddresses: ['user@gmail.com'],
    ccAddresses: [],
    bccAddresses: [],
    subject: 'Test Subject',
    bodyText: null,
    bodyHtml: null,
    snippet: 'Test snippet...',
    hasAttachments: false,
    labels: ['INBOX'],
    receivedAt: Date.now(),
    sentAt: Date.now(),
    isRead: false,
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  mockDecryptToken.mockResolvedValue('decrypted-access-token');
  mockEncryptToken.mockResolvedValue('encrypted-token');
  mockGetProfile.mockResolvedValue({ emailAddress: 'user@gmail.com', historyId: '99999' });
  mockEmitEmailReceived.mockResolvedValue(undefined);
});

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('syncMailbox', () => {
  it('performs first sync when no cursor exists', async () => {
    const db = createMockDb();
    const mailbox = createTestMailbox();
    const parsed = createParsedEmail();

    mockListMessages.mockResolvedValueOnce({
      messages: [{ id: 'msg-1', threadId: 'thread-1' }],
    });
    mockGetMessage.mockResolvedValueOnce({ id: 'msg-1', threadId: 'thread-1' });
    mockParseGmailMessage.mockReturnValueOnce(parsed);

    const result = await syncMailbox(db as any, mailbox as any, ENV);

    expect(result.messagesProcessed).toBe(1);
    expect(result.emailsInserted).toBe(1);
    expect(result.errors).toHaveLength(0);
    expect(mockListMessages).toHaveBeenCalled();
    expect(mockListHistory).not.toHaveBeenCalled();
  });

  it('performs incremental sync when cursor exists', async () => {
    const db = createMockDb();
    const mailbox = createTestMailbox({ syncCursor: '12340' });
    const parsed = createParsedEmail();

    mockListHistory.mockResolvedValueOnce({
      history: [
        {
          id: '12345',
          messagesAdded: [{ message: { id: 'msg-new', threadId: 'thread-1' } }],
        },
      ],
      historyId: '12346',
    });
    mockGetMessage.mockResolvedValueOnce({ id: 'msg-new', threadId: 'thread-1' });
    mockParseGmailMessage.mockReturnValueOnce(parsed);

    const result = await syncMailbox(db as any, mailbox as any, ENV);

    expect(result.messagesProcessed).toBe(1);
    expect(mockListHistory).toHaveBeenCalledWith('decrypted-access-token', '12340', undefined);
    expect(mockListMessages).not.toHaveBeenCalled();
  });

  it('skips duplicate messages by Message-ID', async () => {
    const db = createMockDb();
    const mailbox = createTestMailbox();
    const parsed = createParsedEmail();

    // Simulate message already exists in DB
    db.query.emails.findFirst.mockResolvedValueOnce({ id: 'existing-id' });

    mockListMessages.mockResolvedValueOnce({
      messages: [{ id: 'msg-1', threadId: 'thread-1' }],
    });
    mockGetMessage.mockResolvedValueOnce({ id: 'msg-1', threadId: 'thread-1' });
    mockParseGmailMessage.mockReturnValueOnce(parsed);

    const result = await syncMailbox(db as any, mailbox as any, ENV);

    expect(result.messagesProcessed).toBe(1);
    expect(result.skippedDuplicates).toBe(1);
    expect(result.emailsInserted).toBe(0);
  });

  it('uses full format for full sync depth', async () => {
    const db = createMockDb();
    const mailbox = createTestMailbox({ syncDepth: 'full' });
    const parsed = createParsedEmail({
      bodyText: 'Full body text',
      bodyHtml: '<p>Full body HTML</p>',
    });

    mockListMessages.mockResolvedValueOnce({
      messages: [{ id: 'msg-1', threadId: 'thread-1' }],
    });
    mockGetMessage.mockResolvedValueOnce({ id: 'msg-1', threadId: 'thread-1' });
    mockParseGmailMessage.mockReturnValueOnce(parsed);

    const result = await syncMailbox(db as any, mailbox as any, ENV);

    expect(result.emailsInserted).toBe(1);
    // getMessage should be called with 'full' format
    expect(mockGetMessage).toHaveBeenCalledWith('decrypted-access-token', 'msg-1', 'full');
  });

  it('uses metadata format for metadata sync depth', async () => {
    const db = createMockDb();
    const mailbox = createTestMailbox({ syncDepth: 'metadata' });
    const parsed = createParsedEmail();

    mockListMessages.mockResolvedValueOnce({
      messages: [{ id: 'msg-1', threadId: 'thread-1' }],
    });
    mockGetMessage.mockResolvedValueOnce({ id: 'msg-1', threadId: 'thread-1' });
    mockParseGmailMessage.mockReturnValueOnce(parsed);

    await syncMailbox(db as any, mailbox as any, ENV);

    expect(mockGetMessage).toHaveBeenCalledWith('decrypted-access-token', 'msg-1', 'metadata');
  });

  it('only creates thread rows for thread_only sync depth', async () => {
    const db = createMockDb();
    const mailbox = createTestMailbox({ syncDepth: 'thread_only' });
    const parsed = createParsedEmail();

    mockListMessages.mockResolvedValueOnce({
      messages: [{ id: 'msg-1', threadId: 'thread-1' }],
    });
    mockGetMessage.mockResolvedValueOnce({ id: 'msg-1', threadId: 'thread-1' });
    mockParseGmailMessage.mockReturnValueOnce(parsed);

    const result = await syncMailbox(db as any, mailbox as any, ENV);

    expect(result.messagesProcessed).toBe(1);
    expect(result.threadsCreated).toBe(1);
    // Should NOT insert email rows for thread_only
    expect(result.emailsInserted).toBe(0);
  });

  it('marks mailbox as error on sync failure', async () => {
    const db = createMockDb();
    const mailbox = createTestMailbox();

    mockDecryptToken.mockRejectedValueOnce(new Error('Decryption failed'));

    const result = await syncMailbox(db as any, mailbox as any, ENV);

    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toContain('Decryption failed');
    // Should update mailbox with error status
    expect(db.update).toHaveBeenCalled();
  });

  it('refreshes token when expired', async () => {
    const db = createMockDb();
    const mailbox = createTestMailbox({
      tokenExpiresAt: Date.now() - 1000, // expired
    });

    mockDecryptToken
      .mockResolvedValueOnce('old-access-token')   // first call: decrypt access
      .mockResolvedValueOnce('refresh-token');       // second call: decrypt refresh
    mockRefreshGmailToken.mockResolvedValueOnce({
      accessToken: 'new-access-token',
      expiresIn: 3600,
    });
    mockListMessages.mockResolvedValueOnce({ messages: [] });

    await syncMailbox(db as any, mailbox as any, ENV);

    expect(mockRefreshGmailToken).toHaveBeenCalledWith(
      'refresh-token',
      'test-client-id',
      'test-client-secret',
    );
  });

  it('handles empty message list gracefully', async () => {
    const db = createMockDb();
    const mailbox = createTestMailbox();

    mockListMessages.mockResolvedValueOnce({ messages: undefined });

    const result = await syncMailbox(db as any, mailbox as any, ENV);

    expect(result.messagesProcessed).toBe(0);
    expect(result.emailsInserted).toBe(0);
    expect(result.errors).toHaveLength(0);
  });

  it('determines direction: inbound when from differs from mailbox', async () => {
    const db = createMockDb();
    const mailbox = createTestMailbox();
    const parsed = createParsedEmail({ fromAddress: 'external@other.com' });

    mockListMessages.mockResolvedValueOnce({
      messages: [{ id: 'msg-1', threadId: 'thread-1' }],
    });
    mockGetMessage.mockResolvedValueOnce({ id: 'msg-1' });
    mockParseGmailMessage.mockReturnValueOnce(parsed);

    const result = await syncMailbox(db as any, mailbox as any, ENV);

    expect(result.emailsInserted).toBe(1);
    expect(result.messagesProcessed).toBe(1);
  });

  it('emits email.received with bodyText when the full body was fetched', async () => {
    const db = createMockDb();
    const mailbox = createTestMailbox({ syncDepth: 'full' });
    const parsed = createParsedEmail({
      fromAddress: 'external@other.com',
      bodyText: 'Hello,\n\nFull plain body.\n\nBest regards,\nJane',
      bodyHtml: '<p>Hello</p>',
    });

    mockListMessages.mockResolvedValueOnce({
      messages: [{ id: 'msg-1', threadId: 'thread-1' }],
    });
    mockGetMessage.mockResolvedValueOnce({ id: 'msg-1', threadId: 'thread-1' });
    mockParseGmailMessage.mockReturnValueOnce(parsed);

    await syncMailbox(db as any, mailbox as any, ENV);

    expect(mockEmitEmailReceived).toHaveBeenCalledTimes(1);
    const [, payload] = mockEmitEmailReceived.mock.calls[0];
    expect(payload.bodyText).toBe('Hello,\n\nFull plain body.\n\nBest regards,\nJane');
    expect(payload.snippet).toBe('Test snippet...');
    expect(payload.from).toBe('external@other.com');
  });

  it('emits email.received with bodyText derived from HTML when no plain text exists', async () => {
    const db = createMockDb();
    const mailbox = createTestMailbox({ syncDepth: 'full' });
    const parsed = createParsedEmail({
      fromAddress: 'external@other.com',
      bodyText: null,
      bodyHtml: '<div>Hi there</div>',
    });

    mockListMessages.mockResolvedValueOnce({
      messages: [{ id: 'msg-1', threadId: 'thread-1' }],
    });
    mockGetMessage.mockResolvedValueOnce({ id: 'msg-1', threadId: 'thread-1' });
    mockParseGmailMessage.mockReturnValueOnce(parsed);

    await syncMailbox(db as any, mailbox as any, ENV);

    expect(mockEmitEmailReceived).toHaveBeenCalledTimes(1);
    expect(mockEmitEmailReceived.mock.calls[0][1].bodyText).toBe('Hi there');
  });

  it('emits email.received with null bodyText for metadata sync depth', async () => {
    const db = createMockDb();
    const mailbox = createTestMailbox({ syncDepth: 'metadata' });
    // Metadata-format parses carry no body at all
    const parsed = createParsedEmail({ fromAddress: 'external@other.com' });

    mockListMessages.mockResolvedValueOnce({
      messages: [{ id: 'msg-1', threadId: 'thread-1' }],
    });
    mockGetMessage.mockResolvedValueOnce({ id: 'msg-1', threadId: 'thread-1' });
    mockParseGmailMessage.mockReturnValueOnce(parsed);

    await syncMailbox(db as any, mailbox as any, ENV);

    expect(mockEmitEmailReceived).toHaveBeenCalledTimes(1);
    const [, payload] = mockEmitEmailReceived.mock.calls[0];
    expect(payload.bodyText).toBeNull();
    expect(payload.snippet).toBe('Test snippet...');
  });

  it('does not emit email.received for outbound messages', async () => {
    const db = createMockDb();
    const mailbox = createTestMailbox({ syncDepth: 'full' });
    // fromAddress equals the mailbox address → outbound
    const parsed = createParsedEmail({ fromAddress: 'user@gmail.com' });

    mockListMessages.mockResolvedValueOnce({
      messages: [{ id: 'msg-1', threadId: 'thread-1' }],
    });
    mockGetMessage.mockResolvedValueOnce({ id: 'msg-1', threadId: 'thread-1' });
    mockParseGmailMessage.mockReturnValueOnce(parsed);

    await syncMailbox(db as any, mailbox as any, ENV);

    expect(mockEmitEmailReceived).not.toHaveBeenCalled();
  });

  it('updates sync cursor after successful sync', async () => {
    const db = createMockDb();
    const mailbox = createTestMailbox();

    mockListMessages.mockResolvedValueOnce({ messages: [] });
    mockGetProfile.mockResolvedValueOnce({
      emailAddress: 'user@gmail.com',
      historyId: '55555',
    });

    await syncMailbox(db as any, mailbox as any, ENV);

    // The last db.update call should set the syncCursor
    expect(db.update).toHaveBeenCalled();
  });
});
