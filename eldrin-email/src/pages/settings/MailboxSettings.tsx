import { useState, useEffect, useCallback, useRef } from 'react';
import { useAuthHeaders } from '@eldrin-project/eldrin-app-react';
import { toast } from 'sonner';
import {
  Mail,
  Trash2,
  Pause,
  Play,
  RefreshCw,
  AlertCircle,
  CheckCircle,
  Clock,
  Loader2,
} from 'lucide-react';
import type { Mailbox, SyncDepth } from '../../types/mailbox';
import * as api from '../../api';

interface MailboxSettingsProps {
  apiBase: string;
}

const SYNC_DEPTH_OPTIONS: { value: SyncDepth; label: string; description: string }[] = [
  { value: 'full', label: 'Full', description: 'Store complete emails locally (fastest browsing, uses more storage)' },
  { value: 'metadata', label: 'Metadata only', description: 'Store headers and snippets, fetch body on demand' },
  { value: 'thread_only', label: 'Thread summary', description: 'Store minimal thread data, fetch everything on demand (smallest storage)' },
];

function formatRelativeTime(timestamp: number | null): string {
  if (!timestamp) return 'Never';
  const diff = Date.now() - timestamp;
  const minutes = Math.floor(diff / 60000);
  if (minutes < 1) return 'Just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function StatusIndicator({ status }: { status: Mailbox['syncStatus'] }) {
  switch (status) {
    case 'active':
      return (
        <span className="flex items-center gap-1.5 text-success text-sm">
          <CheckCircle className="w-4 h-4" />
          Active
        </span>
      );
    case 'paused':
      return (
        <span className="flex items-center gap-1.5 text-warning text-sm">
          <Pause className="w-4 h-4" />
          Paused
        </span>
      );
    case 'error':
      return (
        <span className="flex items-center gap-1.5 text-error text-sm">
          <AlertCircle className="w-4 h-4" />
          Error
        </span>
      );
  }
}

function ProviderIcon({ provider }: { provider: Mailbox['provider'] }) {
  // Simple text badge — provider logos would be added in a future polish pass
  const labels: Record<string, string> = {
    gmail: 'Gmail',
    outlook: 'Outlook',
    imap: 'IMAP',
  };
  return (
    <span className="badge badge-soft badge-sm">{labels[provider] ?? provider}</span>
  );
}

export function MailboxSettings({ apiBase }: MailboxSettingsProps) {
  const authHeaders = useAuthHeaders();
  const headersRef = useRef(authHeaders);
  headersRef.current = authHeaders;

  const [mailboxes, setMailboxes] = useState<Mailbox[]>([]);
  const [loading, setLoading] = useState(true);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [syncingId, setSyncingId] = useState<string | null>(null);

  const fetchMailboxes = useCallback(async () => {
    try {
      const result = await api.listMailboxes(apiBase, headersRef.current);
      setMailboxes(result.mailboxes);
    } catch {
      toast.error('Failed to load mailboxes');
    } finally {
      setLoading(false);
    }
  }, [apiBase]);

  useEffect(() => {
    fetchMailboxes();
  }, [fetchMailboxes]);

  // Listen for OAuth popup completion
  useEffect(() => {
    function handleMessage(event: MessageEvent) {
      if (event.data?.type === 'eldrin-email:mailbox-connected') {
        toast.success('Gmail connected successfully');
        fetchMailboxes();
      } else if (event.data?.type === 'eldrin-email:mailbox-error') {
        toast.error(event.data.error || 'Failed to connect mailbox');
      }
    }
    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, [fetchMailboxes]);

  async function handleDisconnect(id: string) {
    try {
      await api.disconnectMailbox(apiBase, authHeaders, id);
      toast.success('Mailbox disconnected');
      setConfirmDeleteId(null);
      fetchMailboxes();
    } catch {
      toast.error('Failed to disconnect mailbox');
    }
  }

  async function handleToggleSync(mailbox: Mailbox) {
    try {
      if (mailbox.syncStatus === 'active') {
        await api.pauseMailbox(apiBase, authHeaders, mailbox.id);
        toast.success('Sync paused');
      } else {
        await api.resumeMailbox(apiBase, authHeaders, mailbox.id);
        toast.success('Sync resumed');
      }
      fetchMailboxes();
    } catch {
      toast.error('Failed to update sync status');
    }
  }

  async function handleSyncDepthChange(mailbox: Mailbox, syncDepth: SyncDepth) {
    try {
      await api.updateMailbox(apiBase, authHeaders, mailbox.id, { syncDepth });
      toast.success('Sync depth updated (takes effect on next sync)');
      fetchMailboxes();
    } catch {
      toast.error('Failed to update sync depth');
    }
  }

  async function handleSyncNow(mailbox: Mailbox) {
    setSyncingId(mailbox.id);
    try {
      const result = await api.syncMailboxNow(apiBase, authHeaders, mailbox.id);
      toast.success(`Synced: ${result.emailsInserted} new email(s)`);
      fetchMailboxes();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Sync failed');
    } finally {
      setSyncingId(null);
    }
  }

  if (loading) {
    return (
      <div className="flex justify-center py-12">
        <span className="loading loading-spinner loading-md" />
      </div>
    );
  }

  return (
    <div className="max-w-2xl">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-semibold">Mailbox Settings</h2>
      </div>

      {/* Connect buttons */}
      <div className="flex gap-3 mb-6">
        <button
          className="btn btn-primary gap-2"
          onClick={() => api.connectGmail(apiBase)}
        >
          <Mail className="w-4 h-4" />
          Connect Gmail
        </button>
        <button className="btn btn-ghost gap-2" disabled>
          <Mail className="w-4 h-4" />
          Connect Outlook
          <span className="badge badge-sm">Soon</span>
        </button>
      </div>

      {/* Mailbox list */}
      {mailboxes.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-base-content/50 border border-base-300 rounded-box">
          <Mail className="w-12 h-12 mb-4 opacity-30" />
          <h3 className="text-lg font-medium mb-1">No mailboxes connected</h3>
          <p className="text-sm">Connect your Gmail account to get started with email.</p>
        </div>
      ) : (
        <div className="flex flex-col gap-4">
          {mailboxes.map((mailbox) => (
            <div key={mailbox.id} className="card bg-base-200 shadow-sm">
              <div className="card-body p-4">
                {/* Header row */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="rounded-full bg-primary/10 p-2">
                      <Mail className="w-5 h-5 text-primary" />
                    </div>
                    <div>
                      <div className="font-medium">{mailbox.emailAddress}</div>
                      {mailbox.displayName && (
                        <div className="text-sm text-base-content/60">{mailbox.displayName}</div>
                      )}
                    </div>
                    <ProviderIcon provider={mailbox.provider} />
                  </div>
                  <StatusIndicator status={mailbox.syncStatus} />
                </div>

                {/* Error message */}
                {mailbox.syncStatus === 'error' && mailbox.errorMessage && (
                  <div className="text-sm text-error bg-error/10 rounded-box px-3 py-2 mt-2">
                    {mailbox.errorMessage}
                  </div>
                )}

                {/* Metadata row */}
                <div className="flex items-center gap-4 text-sm text-base-content/60 mt-2">
                  <span className="flex items-center gap-1">
                    <Clock className="w-3.5 h-3.5" />
                    Last sync: {formatRelativeTime(mailbox.lastSyncAt)}
                  </span>
                  <span className="flex items-center gap-1">
                    <RefreshCw className="w-3.5 h-3.5" />
                    Depth: {SYNC_DEPTH_OPTIONS.find((o) => o.value === mailbox.syncDepth)?.label ?? mailbox.syncDepth}
                  </span>
                </div>

                {/* Actions row */}
                <div className="flex items-center gap-2 mt-3 pt-3 border-t border-base-300">
                  {/* Sync depth selector */}
                  <select
                    className="select select-sm select-bordered"
                    value={mailbox.syncDepth}
                    onChange={(e) => handleSyncDepthChange(mailbox, e.target.value as SyncDepth)}
                    title="Sync depth"
                  >
                    {SYNC_DEPTH_OPTIONS.map((opt) => (
                      <option key={opt.value} value={opt.value}>
                        {opt.label}
                      </option>
                    ))}
                  </select>

                  {/* Sync Now */}
                  <button
                    className="btn btn-sm btn-ghost gap-1"
                    disabled={syncingId === mailbox.id || mailbox.syncStatus === 'paused'}
                    onClick={() => handleSyncNow(mailbox)}
                  >
                    {syncingId === mailbox.id ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin" />
                        Syncing...
                      </>
                    ) : (
                      <>
                        <RefreshCw className="w-4 h-4" />
                        Sync now
                      </>
                    )}
                  </button>

                  <div className="flex-1" />

                  {/* Pause/Resume */}
                  <button
                    className="btn btn-sm btn-ghost gap-1"
                    onClick={() => handleToggleSync(mailbox)}
                  >
                    {mailbox.syncStatus === 'active' ? (
                      <>
                        <Pause className="w-4 h-4" />
                        Pause
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4" />
                        Resume
                      </>
                    )}
                  </button>

                  {/* Disconnect */}
                  {confirmDeleteId === mailbox.id ? (
                    <div className="flex items-center gap-1">
                      <span className="text-sm text-error mr-1">Disconnect?</span>
                      <button
                        className="btn btn-sm btn-error"
                        onClick={() => handleDisconnect(mailbox.id)}
                      >
                        Yes
                      </button>
                      <button
                        className="btn btn-sm btn-ghost"
                        onClick={() => setConfirmDeleteId(null)}
                      >
                        No
                      </button>
                    </div>
                  ) : (
                    <button
                      className="btn btn-sm btn-ghost text-error gap-1"
                      onClick={() => setConfirmDeleteId(mailbox.id)}
                    >
                      <Trash2 className="w-4 h-4" />
                      Disconnect
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
