import { useState, useEffect, useCallback, useRef } from 'react';
import { useAuthHeaders } from '@eldrin-project/eldrin-app-react';
import { toast } from 'sonner';
import {
  ArrowLeft,
  Star,
  Archive,
  Mail,
  MailOpen,
  Reply,
  ReplyAll,
  Forward,
  ChevronDown,
  ChevronUp,
  Paperclip,
} from 'lucide-react';
import type { ThreadDetail, EmailMessage } from '../../types/email';
import * as api from '../../api';
import { ComposeModal, type ComposeContext } from '../compose/ComposeModal';

interface ThreadViewProps {
  apiBase: string;
  threadId: string;
  onNavigate: (path: string) => void;
}

function formatDateTime(timestamp: number): string {
  const date = new Date(timestamp);
  return date.toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
}

function senderInitial(name: string | null, address: string): string {
  if (name) return name.charAt(0).toUpperCase();
  return address.charAt(0).toUpperCase();
}

function MessageBody({ message }: { message: EmailMessage }) {
  if (message.bodyHtml) {
    return (
      <iframe
        srcDoc={message.bodyHtml}
        sandbox=""
        className="w-full border-0 min-h-[100px]"
        style={{ height: '300px' }}
        onLoad={(e) => {
          // Auto-resize iframe to content height
          const iframe = e.target as HTMLIFrameElement;
          try {
            const height = iframe.contentDocument?.body?.scrollHeight;
            if (height) iframe.style.height = `${height + 20}px`;
          } catch {
            // Cross-origin security — keep default height
          }
        }}
        title={`Message from ${message.fromAddress}`}
      />
    );
  }

  if (message.bodyText) {
    return (
      <div className="text-sm whitespace-pre-wrap text-base-content/80 leading-relaxed">
        {message.bodyText}
      </div>
    );
  }

  return (
    <div className="text-sm text-base-content/40 italic py-4">
      {message.snippet || 'No content available'}
    </div>
  );
}

function MessageCard({
  message,
  defaultExpanded,
  onReply,
  onReplyAll,
  onForward,
}: {
  message: EmailMessage;
  isLast?: boolean;
  defaultExpanded: boolean;
  onReply: (msg: EmailMessage) => void;
  onReplyAll: (msg: EmailMessage) => void;
  onForward: (msg: EmailMessage) => void;
}) {
  const [expanded, setExpanded] = useState(defaultExpanded);

  return (
    <div className="border border-base-300 rounded-box overflow-hidden">
      {/* Message header — always visible */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-base-200/50 transition-colors"
      >
        {/* Avatar */}
        <div className="flex-shrink-0 w-9 h-9 rounded-full bg-primary/10 flex items-center justify-center text-sm font-medium text-primary">
          {senderInitial(message.fromName, message.fromAddress)}
        </div>

        {/* Sender info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium truncate">
              {message.fromName || message.fromAddress}
            </span>
            {message.fromName && (
              <span className="text-xs text-base-content/40 truncate hidden sm:inline">
                &lt;{message.fromAddress}&gt;
              </span>
            )}
          </div>
          {!expanded && (
            <p className="text-sm text-base-content/50 truncate">
              {message.snippet}
            </p>
          )}
        </div>

        {/* Right side */}
        <div className="flex items-center gap-2 flex-shrink-0">
          {message.hasAttachments && (
            <Paperclip className="w-4 h-4 text-base-content/40" />
          )}
          <span className="text-xs text-base-content/50 whitespace-nowrap">
            {formatDateTime(message.receivedAt)}
          </span>
          {expanded ? (
            <ChevronUp className="w-4 h-4 text-base-content/40" />
          ) : (
            <ChevronDown className="w-4 h-4 text-base-content/40" />
          )}
        </div>
      </button>

      {/* Expanded content */}
      {expanded && (
        <div className="px-4 pb-4 border-t border-base-300">
          {/* Recipients */}
          <div className="text-xs text-base-content/50 py-2 space-y-0.5">
            <div>
              <span className="font-medium">To:</span>{' '}
              {message.toAddresses.join(', ')}
            </div>
            {message.ccAddresses.length > 0 && (
              <div>
                <span className="font-medium">Cc:</span>{' '}
                {message.ccAddresses.join(', ')}
              </div>
            )}
          </div>

          {/* Body */}
          <div className="mt-2 max-w-4xl">
            <MessageBody message={message} />
          </div>

          {/* Action buttons */}
          <div className="flex gap-2 mt-4 pt-3 border-t border-base-300">
            <button className="btn btn-sm btn-ghost gap-1" onClick={() => onReply(message)}>
              <Reply className="w-4 h-4" /> Reply
            </button>
            <button className="btn btn-sm btn-ghost gap-1" onClick={() => onReplyAll(message)}>
              <ReplyAll className="w-4 h-4" /> Reply All
            </button>
            <button className="btn btn-sm btn-ghost gap-1" onClick={() => onForward(message)}>
              <Forward className="w-4 h-4" /> Forward
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export function ThreadView({ apiBase, threadId, onNavigate }: ThreadViewProps) {
  const authHeaders = useAuthHeaders();
  const headersRef = useRef(authHeaders);
  headersRef.current = authHeaders;

  const [thread, setThread] = useState<ThreadDetail | null>(null);
  const [messages, setMessages] = useState<EmailMessage[]>([]);
  const [loading, setLoading] = useState(true);
  const [composeContext, setComposeContext] = useState<ComposeContext | null>(null);

  const fetchThread = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.getThread(apiBase, headersRef.current, threadId);
      setThread(result.thread);
      setMessages(result.messages);
    } catch {
      toast.error('Failed to load thread');
    } finally {
      setLoading(false);
    }
  }, [apiBase, threadId]);

  useEffect(() => {
    fetchThread();
  }, [fetchThread]);

  async function handleStarToggle() {
    if (!thread) return;
    try {
      await api.updateThread(apiBase, headersRef.current, thread.id, {
        isStarred: !thread.isStarred,
      });
      setThread({ ...thread, isStarred: !thread.isStarred });
    } catch {
      toast.error('Failed to update star');
    }
  }

  async function handleArchive() {
    if (!thread) return;
    try {
      await api.updateThread(apiBase, headersRef.current, thread.id, {
        isArchived: true,
      });
      toast.success('Thread archived');
      onNavigate('/eldrin-email/inbox');
    } catch {
      toast.error('Failed to archive thread');
    }
  }

  async function handleToggleRead() {
    if (!thread) return;
    try {
      await api.updateThread(apiBase, headersRef.current, thread.id, {
        isRead: !thread.isRead,
      });
      setThread({ ...thread, isRead: !thread.isRead });
    } catch {
      toast.error('Failed to update read status');
    }
  }

  function handleReply(msg: EmailMessage) {
    setComposeContext({
      mode: 'reply',
      to: [msg.fromAddress],
      subject: msg.subject?.startsWith('Re:') ? msg.subject : `Re: ${msg.subject ?? ''}`,
      inReplyTo: msg.id,
      threadId: thread?.id,
      quotedHtml: msg.bodyHtml ?? `<pre>${msg.bodyText ?? msg.snippet ?? ''}</pre>`,
    });
  }

  function handleReplyAll(msg: EmailMessage) {
    const allRecipients = [...msg.toAddresses, ...msg.ccAddresses];
    setComposeContext({
      mode: 'replyAll',
      to: [msg.fromAddress],
      cc: allRecipients.filter((a) => a !== msg.fromAddress),
      subject: msg.subject?.startsWith('Re:') ? msg.subject : `Re: ${msg.subject ?? ''}`,
      inReplyTo: msg.id,
      threadId: thread?.id,
      quotedHtml: msg.bodyHtml ?? `<pre>${msg.bodyText ?? msg.snippet ?? ''}</pre>`,
    });
  }

  function handleForward(msg: EmailMessage) {
    setComposeContext({
      mode: 'forward',
      to: [],
      subject: msg.subject?.startsWith('Fwd:') ? msg.subject : `Fwd: ${msg.subject ?? ''}`,
      threadId: undefined, // Forward starts a new thread
      quotedHtml: msg.bodyHtml ?? `<pre>${msg.bodyText ?? msg.snippet ?? ''}</pre>`,
    });
  }

  if (loading) {
    return (
      <div className="flex justify-center items-center h-full">
        <span className="loading loading-spinner loading-lg" />
      </div>
    );
  }

  if (!thread) {
    return (
      <div className="flex flex-col items-center justify-center h-full">
        <p className="text-base-content/50">Thread not found</p>
        <button
          className="btn btn-ghost btn-sm mt-4"
          onClick={() => onNavigate('/eldrin-email/inbox')}
        >
          Back to Inbox
        </button>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      {/* Sticky header */}
      <div className="flex-shrink-0 px-4 sm:px-6 pt-4 pb-3 border-b border-base-300">
        <div className="flex items-center gap-3">
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => onNavigate('/eldrin-email/inbox')}
          >
            <ArrowLeft className="w-4 h-4" />
          </button>

          <h1 className="text-lg font-semibold flex-1 truncate">
            {thread.subject || '(no subject)'}
          </h1>

          <span className="text-xs text-base-content/50">
            {thread.messageCount} message{thread.messageCount !== 1 ? 's' : ''}
          </span>
        </div>

        {/* Thread actions */}
        <div className="flex items-center gap-1 mt-2">
          <button
            className="btn btn-sm btn-ghost gap-1"
            onClick={handleStarToggle}
          >
            <Star
              className={`w-4 h-4 ${
                thread.isStarred ? 'fill-warning text-warning' : ''
              }`}
            />
            {thread.isStarred ? 'Starred' : 'Star'}
          </button>

          <button
            className="btn btn-sm btn-ghost gap-1"
            onClick={handleArchive}
          >
            <Archive className="w-4 h-4" />
            Archive
          </button>

          <button
            className="btn btn-sm btn-ghost gap-1"
            onClick={handleToggleRead}
          >
            {thread.isRead ? (
              <>
                <Mail className="w-4 h-4" /> Mark unread
              </>
            ) : (
              <>
                <MailOpen className="w-4 h-4" /> Mark read
              </>
            )}
          </button>
        </div>
      </div>

      {/* Scrollable messages */}
      <div className="flex-1 overflow-y-auto min-h-0 px-4 sm:px-6 py-4">
        <div className="flex flex-col gap-3">
          {messages.map((message, index) => (
            <MessageCard
              key={message.id}
              message={message}
              isLast={index === messages.length - 1}
              defaultExpanded={index === messages.length - 1}
              onReply={handleReply}
              onReplyAll={handleReplyAll}
              onForward={handleForward}
            />
          ))}
        </div>
      </div>

      {/* Compose Modal */}
      {composeContext && (
        <ComposeModal
          apiBase={apiBase}
          context={composeContext}
          onClose={() => setComposeContext(null)}
          onSent={() => fetchThread()}
        />
      )}
    </div>
  );
}
