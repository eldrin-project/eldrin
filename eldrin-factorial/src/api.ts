import type { ConnectionStatus, EmployeeRow, Team, TimeOff, SyncResult } from './types/factorial';

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

export async function getConnection(base: string, headers: Headers): Promise<ConnectionStatus> {
  return request(apiUrl(base, '/connection'), headers);
}

export async function listEmployees(
  base: string,
  headers: Headers,
): Promise<{ employees: EmployeeRow[] }> {
  return request(apiUrl(base, '/employees'), headers);
}

export async function listTeams(base: string, headers: Headers): Promise<{ teams: Team[] }> {
  return request(apiUrl(base, '/teams'), headers);
}

export async function listTimeoff(base: string, headers: Headers): Promise<{ timeoff: TimeOff[] }> {
  return request(apiUrl(base, '/timeoff'), headers);
}

export async function runSync(base: string, headers: Headers): Promise<SyncResult> {
  return request(apiUrl(base, '/sync'), headers, { method: 'POST' });
}
