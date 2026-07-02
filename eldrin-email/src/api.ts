import type { Mailbox, SyncDepth } from './types/mailbox';
import type {
  ThreadPreview,
  ThreadDetail,
  EmailMessage,
  SentEmailRow,
  SearchResult,
  Pagination,
} from './types/email';
import type {
  TemplateSummary,
  TemplateDetail,
  CreateTemplateParams,
  UpdateTemplateParams,
} from './types/template';

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
  data: { syncDepth?: SyncDepth; syncDays?: number },
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
  params?: { page?: number; limit?: number; search?: string; unread?: boolean; mailboxId?: string },
): Promise<{ data: ThreadPreview[]; pagination: Pagination }> {
  const qs = new URLSearchParams();
  if (params?.page) qs.set('page', String(params.page));
  if (params?.limit) qs.set('limit', String(params.limit));
  if (params?.search) qs.set('search', params.search);
  if (params?.unread) qs.set('unread', 'true');
  if (params?.mailboxId) qs.set('mailboxId', params.mailboxId);
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
  params?: { page?: number; limit?: number; search?: string; mailboxId?: string },
): Promise<{ data: SentEmailRow[]; pagination: Pagination }> {
  const qs = new URLSearchParams();
  if (params?.page) qs.set('page', String(params.page));
  if (params?.limit) qs.set('limit', String(params.limit));
  if (params?.search) qs.set('search', params.search);
  if (params?.mailboxId) qs.set('mailboxId', params.mailboxId);
  const query = qs.toString();
  return request(apiUrl(base, `/sent${query ? `?${query}` : ''}`), headers);
}

export async function searchEmails(
  base: string,
  headers: Headers,
  params: { q: string; page?: number; limit?: number; mailboxId?: string },
): Promise<{ data: SearchResult[]; pagination: Pagination }> {
  const qs = new URLSearchParams({ q: params.q });
  if (params.page) qs.set('page', String(params.page));
  if (params.limit) qs.set('limit', String(params.limit));
  if (params.mailboxId) qs.set('mailboxId', params.mailboxId);
  return request(apiUrl(base, `/email/search?${qs}`), headers);
}

// ── Email Sending ─────────────────────────────────────────────────────────────

export interface SendEmailParams {
  mailboxId: string;
  to: string[];
  cc?: string[];
  bcc?: string[];
  subject: string;
  bodyHtml: string;
  bodyText?: string;
  inReplyTo?: string;
  threadId?: string;
  scheduledAt?: number;
}

export async function sendEmail(
  base: string,
  headers: Headers,
  params: SendEmailParams,
): Promise<{ id: string; status: 'sent' | 'scheduled'; threadId?: string }> {
  return request(apiUrl(base, '/email/send'), headers, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
}

// ── Templates ────────────────────────────────────────────────────────────────

export async function listTemplates(
  base: string,
  headers: Headers,
  params?: { category?: string; search?: string },
): Promise<{ templates: TemplateSummary[] }> {
  const qs = new URLSearchParams();
  if (params?.category) qs.set('category', params.category);
  if (params?.search) qs.set('search', params.search);
  const query = qs.toString();
  return request(apiUrl(base, `/templates${query ? `?${query}` : ''}`), headers);
}

export async function getTemplate(
  base: string,
  headers: Headers,
  id: string,
): Promise<{ template: TemplateDetail }> {
  return request(apiUrl(base, `/templates/${id}`), headers);
}

export async function createTemplate(
  base: string,
  headers: Headers,
  params: CreateTemplateParams,
): Promise<{ id: string; mergeFields: string[] }> {
  return request(apiUrl(base, '/templates'), headers, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
}

export async function updateTemplate(
  base: string,
  headers: Headers,
  id: string,
  params: UpdateTemplateParams,
): Promise<{ updated: boolean }> {
  return request(apiUrl(base, `/templates/${id}`), headers, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
}

export async function deleteTemplate(
  base: string,
  headers: Headers,
  id: string,
): Promise<{ deleted: boolean }> {
  return request(apiUrl(base, `/templates/${id}`), headers, {
    method: 'DELETE',
  });
}

export async function previewTemplate(
  base: string,
  headers: Headers,
  id: string,
  context?: Record<string, unknown>,
): Promise<{ subject: string; bodyHtml: string }> {
  return request(apiUrl(base, `/templates/${id}/preview`), headers, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ context }),
  });
}

export async function incrementTemplateUsage(
  base: string,
  headers: Headers,
  id: string,
): Promise<{ incremented: boolean }> {
  return request(apiUrl(base, `/templates/${id}/use`), headers, {
    method: 'POST',
  });
}

/**
 * Open a popup window for an OAuth flow.
 * Two-step: fetch a short-lived connect token (authenticated), then open popup with it.
 */
async function connectProvider(base: string, headers: Headers, provider: 'gmail' | 'outlook'): Promise<void> {
  const { token } = await request<{ token: string }>(
    apiUrl(base, '/mailbox/connect-token'),
    headers,
    { method: 'POST' },
  );

  const width = 600;
  const height = 700;
  const left = window.screenX + (window.innerWidth - width) / 2;
  const top = window.screenY + (window.innerHeight - height) / 2;

  window.open(
    `${base}/api/mailbox/connect/${provider}?token=${encodeURIComponent(token)}`,
    `eldrin-email-${provider}-connect`,
    `width=${width},height=${height},left=${left},top=${top},popup=yes`,
  );
}

export function connectGmail(base: string, headers: Headers): Promise<void> {
  return connectProvider(base, headers, 'gmail');
}

export function connectOutlook(base: string, headers: Headers): Promise<void> {
  return connectProvider(base, headers, 'outlook');
}
