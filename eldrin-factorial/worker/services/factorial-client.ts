// Validated live against the sandbox: dated API version + resources structure.
const API_BASE_PATH = '/api/2026-04-01/resources';

export class FactorialError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = 'FactorialError';
    this.status = status;
  }
}

export interface FactorialClient {
  get<T>(path: string): Promise<T>;
  getAll<T>(path: string): Promise<T[]>;
}

interface Paged<T> {
  data: T[];
  meta?: { has_next_page?: boolean; end_cursor?: string };
}

export function createFactorialClient(
  env: Pick<Env, 'FACTORIAL_API_BASE_URL' | 'FACTORIAL_API_KEY'>,
): FactorialClient {
  const base = (env.FACTORIAL_API_BASE_URL || '').replace(/\/$/, '');
  const key = env.FACTORIAL_API_KEY || '';
  if (!base || !key) throw new FactorialError('Factorial credentials not configured', 400);

  async function get<T>(path: string): Promise<T> {
    const url = `${base}${API_BASE_PATH}${path}`;
    const res = await fetch(url, {
      headers: { 'x-api-key': key, Accept: 'application/json' },
    });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new FactorialError(`Factorial GET ${path} failed: ${res.status} ${body}`, res.status);
    }
    return res.json() as Promise<T>;
  }

  // Cursor pagination (validated): follow meta.end_cursor via after_id until
  // meta.has_next_page is false.
  async function getAll<T>(path: string): Promise<T[]> {
    const out: T[] = [];
    let afterId: string | undefined;
    for (;;) {
      const sep = path.includes('?') ? '&' : '?';
      const pagePath = afterId ? `${path}${sep}after_id=${encodeURIComponent(afterId)}` : path;
      const page = await get<Paged<T>>(pagePath);
      out.push(...(page.data ?? []));
      if (!page.meta?.has_next_page || !page.meta.end_cursor) break;
      afterId = page.meta.end_cursor;
    }
    return out;
  }

  return { get, getAll };
}
