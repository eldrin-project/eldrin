import type { Mailbox, SyncDepth } from './types/mailbox';
import type {
  ThreadPreview,
  ThreadDetail,
  EmailMessage,
  SentEmailRow,
  SearchResult,
  Pagination,
} from './types/email';

type Headers = Record<string, string>;

function apiUrl(base: string, path: string): string {
  return `${base}/api${path}`;
}

async function request<T>(url: string, headers: Headers, init?: RequestInit): Promise<T> {
  const res = await fetch(url, { ...init, headers: { ...headers, ...init?.headers } });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error((body as { error?: string }).error || `Request failed: ${res.status}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

// ── Mailboxes ────────────────────────────────────────────────────────────────

export async function listMailboxes(
  base: string,
  headers: Headers,
): Promise<{ mailboxes: Mailbox[] }> {
  return request(apiUrl(base, '/mailboxes'), headers);
}

export async function disconnectMailbox(
  base: string,
  headers: Headers,
  id: string,
): Promise<{ deleted: boolean }> {
  return request(apiUrl(base, `/mailboxes/${id}`), headers, {
    method: 'DELETE',
  });
}

export async function updateMailbox(
  base: string,
  headers: Headers,
  id: string,
  data: { syncDepth?: SyncDepth },
): Promise<{ updated: boolean }> {
  return request(apiUrl(base, `/mailboxes/${id}`), headers, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
}

export async function pauseMailbox(
  base: string,
  headers: Headers,
  id: string,
): Promise<{ updated: boolean }> {
  return request(apiUrl(base, `/mailboxes/${id}/pause`), headers, {
    method: 'POST',
  });
}

export async function resumeMailbox(
  base: string,
  headers: Headers,
  id: string,
): Promise<{ updated: boolean }> {
  return request(apiUrl(base, `/mailboxes/${id}/resume`), headers, {
    method: 'POST',
  });
}

export async function syncMailboxNow(
  base: string,
  headers: Headers,
  id: string,
): Promise<{ synced: boolean; messagesProcessed: number; emailsInserted: number; errors: number }> {
  return request(apiUrl(base, `/mailboxes/${id}/sync`), headers, {
    method: 'POST',
  });
}

// ── Inbox & Threads ──────────────────────────────────────────────────────────

export async function listInbox(
  base: string,
  headers: Headers,
  params?: { page?: number; limit?: number; search?: string; unread?: boolean },
): Promise<{ data: ThreadPreview[]; pagination: Pagination }> {
  const qs = new URLSearchParams();
  if (params?.page) qs.set('page', String(params.page));
  if (params?.limit) qs.set('limit', String(params.limit));
  if (params?.search) qs.set('search', params.search);
  if (params?.unread) qs.set('unread', 'true');
  const query = qs.toString();
  return request(apiUrl(base, `/inbox${query ? `?${query}` : ''}`), headers);
}

export async function getThread(
  base: string,
  headers: Headers,
  threadId: string,
): Promise<{ thread: ThreadDetail; messages: EmailMessage[] }> {
  return request(apiUrl(base, `/inbox/${threadId}`), headers);
}

export async function updateThread(
  base: string,
  headers: Headers,
  threadId: string,
  data: { isRead?: boolean; isStarred?: boolean; isArchived?: boolean },
): Promise<{ updated: boolean }> {
  return request(apiUrl(base, `/inbox/${threadId}`), headers, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
}

export async function listSent(
  base: string,
  headers: Headers,
  params?: { page?: number; limit?: number; search?: string },
): Promise<{ data: SentEmailRow[]; pagination: Pagination }> {
  const qs = new URLSearchParams();
  if (params?.page) qs.set('page', String(params.page));
  if (params?.limit) qs.set('limit', String(params.limit));
  if (params?.search) qs.set('search', params.search);
  const query = qs.toString();
  return request(apiUrl(base, `/sent${query ? `?${query}` : ''}`), headers);
}

export async function searchEmails(
  base: string,
  headers: Headers,
  params: { q: string; page?: number; limit?: number },
): Promise<{ data: SearchResult[]; pagination: Pagination }> {
  const qs = new URLSearchParams({ q: params.q });
  if (params.page) qs.set('page', String(params.page));
  if (params.limit) qs.set('limit', String(params.limit));
  return request(apiUrl(base, `/email/search?${qs}`), headers);
}

/**
 * Open a popup window for Gmail OAuth flow.
 * The popup will redirect to Google, then back to our callback endpoint.
 */
export function connectGmail(base: string): void {
  const width = 600;
  const height = 700;
  const left = window.screenX + (window.innerWidth - width) / 2;
  const top = window.screenY + (window.innerHeight - height) / 2;

  window.open(
    `${base}/api/mailbox/connect/gmail`,
    'eldrin-email-gmail-connect',
    `width=${width},height=${height},left=${left},top=${top},popup=yes`,
  );
}
