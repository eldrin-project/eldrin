import type { Mailbox, SyncDepth } from './types/mailbox';

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
