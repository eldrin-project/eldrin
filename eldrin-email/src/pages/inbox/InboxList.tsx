import { useState, useEffect, useCallback, useRef } from 'react';
import { useAuthHeaders } from '@eldrin-project/eldrin-app-react';
import { toast } from 'sonner';
import {
  Inbox,
  Search,
  Star,
  MailOpen,
  RefreshCw,
  Filter,
  Plus,
} from 'lucide-react';
import type { ThreadPreview, Pagination } from '../../types/email';
import * as api from '../../api';
import { ComposeModal } from '../compose/ComposeModal';

interface InboxListProps {
  apiBase: string;
  onNavigate: (path: string) => void;
}

function formatDate(timestamp: number): string {
  const date = new Date(timestamp);
  const now = new Date();
  const diff = now.getTime() - timestamp;

  // Today: show time
  if (date.toDateString() === now.toDateString()) {
    return date.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
  }
  // This week: show day name
  if (diff < 7 * 24 * 60 * 60 * 1000) {
    return date.toLocaleDateString(undefined, { weekday: 'short' });
  }
  // This year: show month/day
  if (date.getFullYear() === now.getFullYear()) {
    return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  }
  // Older: show full date
  return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

function senderInitial(name: string | null, address: string): string {
  if (name) return name.charAt(0).toUpperCase();
  return address.charAt(0).toUpperCase();
}

function senderDisplay(name: string | null, address: string): string {
  return name || address.split('@')[0];
}

export function InboxList({ apiBase, onNavigate }: InboxListProps) {
  const authHeaders = useAuthHeaders();
  const headersRef = useRef(authHeaders);
  headersRef.current = authHeaders;

  const [threads, setThreads] = useState<ThreadPreview[]>([]);
  const [pagination, setPagination] = useState<Pagination>({ page: 1, limit: 25, total: 0, pages: 0 });
  const [loading, setLoading] = useState(true);
  const [searchInput, setSearchInput] = useState('');
  const [search, setSearch] = useState('');
  const [unreadOnly, setUnreadOnly] = useState(false);
  const [showCompose, setShowCompose] = useState(false);

  // Debounce search
  useEffect(() => {
    const timer = setTimeout(() => setSearch(searchInput), 300);
    return () => clearTimeout(timer);
  }, [searchInput]);

  const fetchInbox = useCallback(
    async (page = 1) => {
      setLoading(true);
      try {
        const result = await api.listInbox(apiBase, headersRef.current, {
          page,
          limit: 25,
          search: search || undefined,
          unread: unreadOnly || undefined,
        });
        setThreads(result.data);
        setPagination(result.pagination);
      } catch {
        toast.error('Failed to load inbox');
      } finally {
        setLoading(false);
      }
    },
    [apiBase, search, unreadOnly],
  );

  useEffect(() => {
    fetchInbox();
  }, [fetchInbox]);

  async function handleStarToggle(e: React.MouseEvent, thread: ThreadPreview) {
    e.stopPropagation();
    try {
      await api.updateThread(apiBase, headersRef.current, thread.id, {
        isStarred: !thread.isStarred,
      });
      setThreads((prev) =>
        prev.map((t) => (t.id === thread.id ? { ...t, isStarred: !t.isStarred } : t)),
      );
    } catch {
      toast.error('Failed to update star');
    }
  }

  // Empty state when no mailbox connected and no threads
  if (!loading && threads.length === 0 && !search && !unreadOnly) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-base-content/50">
        <Inbox className="w-12 h-12 mb-4 opacity-30" />
        <h2 className="text-lg font-semibold mb-1">Your inbox is empty</h2>
        <p className="text-sm mb-4">Connect a mailbox and sync your emails to get started.</p>
        <button
          className="btn btn-primary btn-sm"
          onClick={() => onNavigate('/eldrin-email/settings')}
        >
          Connect Mailbox
        </button>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      {/* Sticky toolbar */}
      <div className="flex-shrink-0 px-4 sm:px-6 pt-4 pb-3 border-b border-base-300">
        <div className="flex items-center gap-3">
          <div className="relative flex-1 max-w-md">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-base-content/40 pointer-events-none z-10" />
            <input
              className="input input-bordered input-sm w-full pl-9"
              placeholder="Search inbox..."
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
            />
          </div>

          <button
            className={`btn btn-sm gap-1 ${unreadOnly ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => setUnreadOnly(!unreadOnly)}
            title="Show unread only"
          >
            <Filter className="w-4 h-4" />
            Unread
          </button>

          <button
            className="btn btn-sm btn-ghost gap-1"
            onClick={() => fetchInbox(pagination.page)}
            disabled={loading}
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>

          <button
            className="btn btn-sm btn-primary gap-1"
            onClick={() => setShowCompose(true)}
          >
            <Plus className="w-4 h-4" />
            Compose
          </button>
        </div>
      </div>

      {/* Scrollable thread list */}
      <div className="flex-1 overflow-y-auto min-h-0">
        {loading && threads.length === 0 ? (
          <div className="flex justify-center items-center h-full">
            <span className="loading loading-spinner loading-md" />
          </div>
        ) : threads.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-base-content/50">
            <MailOpen className="w-10 h-10 mb-3 opacity-30" />
            <p className="text-sm">
              {search ? 'No threads match your search.' : 'No unread threads.'}
            </p>
          </div>
        ) : (
          <div className="divide-y divide-base-300">
            {threads.map((thread) => (
              <button
                key={thread.id}
                onClick={() => onNavigate(`/eldrin-email/inbox/${thread.id}`)}
                className={`w-full flex items-center gap-3 px-4 sm:px-6 py-3 text-left hover:bg-base-200 transition-colors ${
                  !thread.isRead ? 'bg-base-100' : ''
                }`}
              >
                {/* Avatar */}
                <div className="flex-shrink-0 w-9 h-9 rounded-full bg-primary/10 flex items-center justify-center text-sm font-medium text-primary">
                  {senderInitial(thread.fromName, thread.fromAddress)}
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className={`text-sm truncate ${!thread.isRead ? 'font-semibold' : ''}`}>
                      {senderDisplay(thread.fromName, thread.fromAddress)}
                    </span>
                    {thread.messageCount > 1 && (
                      <span className="text-xs text-base-content/40">({thread.messageCount})</span>
                    )}
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className={`text-sm truncate ${!thread.isRead ? 'font-medium' : 'text-base-content/70'}`}>
                      {thread.subject || '(no subject)'}
                    </span>
                    {thread.snippet && (
                      <span className="text-sm text-base-content/40 truncate hidden sm:inline">
                        — {thread.snippet}
                      </span>
                    )}
                  </div>
                </div>

                {/* Right side: star + date */}
                <div className="flex items-center gap-2 flex-shrink-0">
                  <button
                    onClick={(e) => handleStarToggle(e, thread)}
                    className="p-1 hover:bg-base-300 rounded"
                  >
                    <Star
                      className={`w-4 h-4 ${
                        thread.isStarred
                          ? 'fill-warning text-warning'
                          : 'text-base-content/30'
                      }`}
                    />
                  </button>
                  <span className={`text-xs whitespace-nowrap ${!thread.isRead ? 'font-semibold' : 'text-base-content/50'}`}>
                    {formatDate(thread.lastMessageAt)}
                  </span>
                  {!thread.isRead && (
                    <div className="w-2 h-2 rounded-full bg-primary flex-shrink-0" />
                  )}
                </div>
              </button>
            ))}
          </div>
        )}

        {/* Pagination */}
        {pagination.pages > 1 && (
          <div className="flex items-center justify-between px-4 sm:px-6 py-3 border-t border-base-300">
            <span className="text-sm text-base-content/50">
              {pagination.total} thread{pagination.total !== 1 ? 's' : ''}
            </span>
            <div className="join">
              <button
                className="join-item btn btn-sm"
                disabled={pagination.page <= 1}
                onClick={() => fetchInbox(pagination.page - 1)}
              >
                Previous
              </button>
              <button className="join-item btn btn-sm btn-disabled">
                {pagination.page} / {pagination.pages}
              </button>
              <button
                className="join-item btn btn-sm"
                disabled={pagination.page >= pagination.pages}
                onClick={() => fetchInbox(pagination.page + 1)}
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Compose Modal */}
      {showCompose && (
        <ComposeModal
          apiBase={apiBase}
          context={{ mode: 'new' }}
          onClose={() => setShowCompose(false)}
          onSent={() => fetchInbox(1)}
        />
      )}
    </div>
  );
}
