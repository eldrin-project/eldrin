export interface Pagination {
  page: number;
  limit: number;
  total: number;
  pages: number;
}

export interface ThreadPreview {
  id: string;
  subject: string | null;
  fromAddress: string;
  fromName: string | null;
  snippet: string;
  lastMessageAt: number;
  messageCount: number;
  isRead: boolean;
  isStarred: boolean;
}

export interface EmailMessage {
  id: string;
  fromAddress: string;
  fromName: string | null;
  toAddresses: string[];
  ccAddresses: string[];
  bccAddresses: string[];
  subject: string | null;
  bodyText: string | null;
  bodyHtml: string | null;
  snippet: string | null;
  hasAttachments: boolean;
  direction: 'inbound' | 'outbound';
  sentAt: number | null;
  receivedAt: number;
  isRead: boolean;
}

export interface ThreadDetail {
  id: string;
  subject: string | null;
  messageCount: number;
  isRead: boolean;
  isStarred: boolean;
  isArchived: boolean;
  lastMessageAt: number;
}

export interface SentEmailRow {
  id: string;
  threadId: string;
  toAddresses: string[];
  subject: string | null;
  snippet: string | null;
  sentAt: number;
  openCount: number;
  clickCount: number;
  firstOpenedAt: number | null;
}

export interface SearchResult {
  id: string;
  threadId: string;
  fromAddress: string;
  fromName: string | null;
  subject: string | null;
  snippet: string | null;
  receivedAt: number;
  direction: 'inbound' | 'outbound';
}
