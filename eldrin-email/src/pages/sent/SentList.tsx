import { useState, useEffect, useCallback, useRef } from 'react';
import { useAuthHeaders } from '@eldrin-project/eldrin-app-react';
import { toast } from 'sonner';
import { Send, Search, RefreshCw } from 'lucide-react';
import type { SentEmailRow, Pagination } from '../../types/email';
import * as api from '../../api';

interface SentListProps {
  apiBase: string;
  onNavigate: (path: string) => void;
}

function formatDate(timestamp: number): string {
  const date = new Date(timestamp);
  const now = new Date();
  const diff = now.getTime() - timestamp;

  if (date.toDateString() === now.toDateString()) {
    return date.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
  }
  if (diff < 7 * 24 * 60 * 60 * 1000) {
    return date.toLocaleDateString(undefined, { weekday: 'short' });
  }
  if (date.getFullYear() === now.getFullYear()) {
    return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  }
  return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

function recipientDisplay(toAddresses: string[]): string {
  if (toAddresses.length === 0) return '(no recipients)';
  // Extract just the name or email prefix from the first address
  const first = toAddresses[0];
  const match = first.match(/^(.+?)\s*<[^>]+>$/);
  const display = match ? match[1].replace(/^\"|\"$/g, '') : first.split('@')[0];
  if (toAddresses.length === 1) return display;
  return `${display} +${toAddresses.length - 1}`;
}

export function SentList({ apiBase, onNavigate }: SentListProps) {
  const authHeaders = useAuthHeaders();
  const headersRef = useRef(authHeaders);
  headersRef.current = authHeaders;

  const [emails, setEmails] = useState<SentEmailRow[]>([]);
  const [pagination, setPagination] = useState<Pagination>({ page: 1, limit: 25, total: 0, pages: 0 });
  const [loading, setLoading] = useState(true);
  const [searchInput, setSearchInput] = useState('');
  const [search, setSearch] = useState('');

  useEffect(() => {
    const timer = setTimeout(() => setSearch(searchInput), 300);
    return () => clearTimeout(timer);
  }, [searchInput]);

  const fetchSent = useCallback(
    async (page = 1) => {
      setLoading(true);
      try {
        const result = await api.listSent(apiBase, headersRef.current, {
          page,
          limit: 25,
          search: search || undefined,
        });
        setEmails(result.data);
        setPagination(result.pagination);
      } catch {
        toast.error('Failed to load sent emails');
      } finally {
        setLoading(false);
      }
    },
    [apiBase, search],
  );

  useEffect(() => {
    fetchSent();
  }, [fetchSent]);

  if (!loading && emails.length === 0 && !search) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-base-content/50">
        <Send className="w-12 h-12 mb-4 opacity-30" />
        <h2 className="text-lg font-semibold mb-1">No sent emails</h2>
        <p className="text-sm">Sent emails will appear here once you start sending.</p>
      </div>
    );
  }

  return (
    <div className="max-w-4xl">
      {/* Toolbar */}
      <div className="flex items-center gap-3 mb-4">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-base-content/40 pointer-events-none z-10" />
          <input
            className="input input-bordered input-sm w-full pl-9"
            placeholder="Search sent..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
          />
        </div>

        <button
          className="btn btn-sm btn-ghost gap-1"
          onClick={() => fetchSent(pagination.page)}
          disabled={loading}
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Email list */}
      {loading && emails.length === 0 ? (
        <div className="flex justify-center py-16">
          <span className="loading loading-spinner loading-md" />
        </div>
      ) : emails.length === 0 ? (
        <div className="flex flex-col items-center py-16 text-base-content/50">
          <Send className="w-10 h-10 mb-3 opacity-30" />
          <p className="text-sm">No sent emails match your search.</p>
        </div>
      ) : (
        <div className="border border-base-300 rounded-box divide-y divide-base-300 overflow-hidden">
          {emails.map((email) => (
            <button
              key={email.id}
              onClick={() => onNavigate(`/eldrin-email/inbox/${email.threadId}`)}
              className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-base-200 transition-colors"
            >
              {/* Avatar */}
              <div className="flex-shrink-0 w-9 h-9 rounded-full bg-accent/10 flex items-center justify-center">
                <Send className="w-4 h-4 text-accent" />
              </div>

              {/* Content */}
              <div className="flex-1 min-w-0">
                <div className="text-sm truncate">
                  To: {recipientDisplay(email.toAddresses)}
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="text-sm text-base-content/70 truncate">
                    {email.subject || '(no subject)'}
                  </span>
                  {email.snippet && (
                    <span className="text-sm text-base-content/40 truncate hidden sm:inline">
                      — {email.snippet}
                    </span>
                  )}
                </div>
              </div>

              {/* Date */}
              <span className="text-xs text-base-content/50 whitespace-nowrap flex-shrink-0">
                {formatDate(email.sentAt)}
              </span>
            </button>
          ))}
        </div>
      )}

      {/* Pagination */}
      {pagination.pages > 1 && (
        <div className="flex items-center justify-between mt-4">
          <span className="text-sm text-base-content/50">
            {pagination.total} email{pagination.total !== 1 ? 's' : ''}
          </span>
          <div className="join">
            <button
              className="join-item btn btn-sm"
              disabled={pagination.page <= 1}
              onClick={() => fetchSent(pagination.page - 1)}
            >
              Previous
            </button>
            <button className="join-item btn btn-sm btn-disabled">
              {pagination.page} / {pagination.pages}
            </button>
            <button
              className="join-item btn btn-sm"
              disabled={pagination.page >= pagination.pages}
              onClick={() => fetchSent(pagination.page + 1)}
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
