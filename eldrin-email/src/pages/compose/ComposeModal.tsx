import { useState, useRef, useCallback, useEffect } from 'react';
import { useAuthHeaders } from '@eldrin-project/eldrin-app-react';
import { toast } from 'sonner';
import { useEditor, EditorContent } from '@tiptap/react';
import StarterKit from '@tiptap/starter-kit';
import Link from '@tiptap/extension-link';
import Underline from '@tiptap/extension-underline';
import {
  X,
  Send,
  Clock,
  Bold,
  Italic,
  Underline as UnderlineIcon,
  Link as LinkIcon,
  List,
  ListOrdered,
  Minus,
  ChevronDown,
  ChevronUp,
  Loader2,
  FileText,
  Braces,
} from 'lucide-react';
import * as api from '../../api';
import type { Mailbox } from '../../types/mailbox';
import type { TemplateSummary } from '../../types/template';

// ── Types ────────────────────────────────────────────────────────────────────

export interface ComposeContext {
  mode: 'new' | 'reply' | 'replyAll' | 'forward';
  to?: string[];
  cc?: string[];
  subject?: string;
  inReplyTo?: string;
  threadId?: string;
  quotedHtml?: string;
}

interface ComposeModalProps {
  apiBase: string;
  context?: ComposeContext;
  onClose: () => void;
  onSent?: () => void;
}

// ── Email Pill Input ─────────────────────────────────────────────────────────

function EmailPillInput({
  label,
  emails,
  onChange,
}: {
  label: string;
  emails: string[];
  onChange: (emails: string[]) => void;
}) {
  const [input, setInput] = useState('');

  function addEmail() {
    const trimmed = input.trim();
    if (trimmed && trimmed.includes('@') && !emails.includes(trimmed)) {
      onChange([...emails, trimmed]);
      setInput('');
    }
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'Enter' || e.key === ',' || e.key === 'Tab') {
      e.preventDefault();
      addEmail();
    } else if (e.key === 'Backspace' && !input && emails.length > 0) {
      onChange(emails.slice(0, -1));
    }
  }

  function removeEmail(index: number) {
    onChange(emails.filter((_, i) => i !== index));
  }

  return (
    <div className="flex items-start gap-2">
      <span className="text-sm text-base-content/50 pt-1.5 w-10 flex-shrink-0">{label}</span>
      <div className="flex-1 flex flex-wrap gap-1 items-center border border-base-300 rounded-lg px-2 py-1 min-h-[36px] focus-within:border-primary/50">
        {emails.map((email, i) => (
          <span key={i} className="badge badge-soft badge-sm gap-1 py-2.5">
            {email}
            <button
              type="button"
              onClick={() => removeEmail(i)}
              className="hover:text-error"
            >
              <X className="w-3 h-3" />
            </button>
          </span>
        ))}
        <input
          type="email"
          className="flex-1 min-w-[120px] text-sm bg-transparent border-none outline-none py-1"
          placeholder={emails.length === 0 ? 'Add recipient...' : ''}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          onBlur={addEmail}
        />
      </div>
    </div>
  );
}

// ── Merge Field Groups (for insertion in compose) ───────────────────────────

const COMPOSE_MERGE_FIELDS = [
  { label: 'Contact', fields: ['contact.firstName', 'contact.lastName', 'contact.email', 'contact.company'] },
  { label: 'Company', fields: ['company.name', 'company.domain'] },
  { label: 'Deal', fields: ['deal.name', 'deal.value'] },
  { label: 'User', fields: ['user.name', 'user.email'] },
];

// ── Editor Toolbar ──────────────────────────────────────────────────────────

function EditorToolbar({
  editor,
  onInsertMergeField,
}: {
  editor: ReturnType<typeof useEditor>;
  onInsertMergeField?: (field: string) => void;
}) {
  const [showFields, setShowFields] = useState(false);

  if (!editor) return null;

  function toggleLink() {
    if (editor!.isActive('link')) {
      editor!.chain().focus().unsetLink().run();
      return;
    }
    const url = window.prompt('URL:');
    if (url) {
      editor!.chain().focus().setLink({ href: url }).run();
    }
  }

  const btnClass = (active: boolean) =>
    `btn btn-xs btn-ghost ${active ? 'btn-active' : ''}`;

  return (
    <div className="flex items-center gap-0.5 border-b border-base-300 px-2 py-1">
      <button
        type="button"
        className={btnClass(editor.isActive('bold'))}
        onClick={() => editor.chain().focus().toggleBold().run()}
        title="Bold"
      >
        <Bold className="w-3.5 h-3.5" />
      </button>
      <button
        type="button"
        className={btnClass(editor.isActive('italic'))}
        onClick={() => editor.chain().focus().toggleItalic().run()}
        title="Italic"
      >
        <Italic className="w-3.5 h-3.5" />
      </button>
      <button
        type="button"
        className={btnClass(editor.isActive('underline'))}
        onClick={() => editor.chain().focus().toggleUnderline().run()}
        title="Underline"
      >
        <UnderlineIcon className="w-3.5 h-3.5" />
      </button>

      <div className="w-px h-4 bg-base-300 mx-1" />

      <button
        type="button"
        className={btnClass(editor.isActive('link'))}
        onClick={toggleLink}
        title="Link"
      >
        <LinkIcon className="w-3.5 h-3.5" />
      </button>

      <div className="w-px h-4 bg-base-300 mx-1" />

      <button
        type="button"
        className={btnClass(editor.isActive('bulletList'))}
        onClick={() => editor.chain().focus().toggleBulletList().run()}
        title="Bullet list"
      >
        <List className="w-3.5 h-3.5" />
      </button>
      <button
        type="button"
        className={btnClass(editor.isActive('orderedList'))}
        onClick={() => editor.chain().focus().toggleOrderedList().run()}
        title="Numbered list"
      >
        <ListOrdered className="w-3.5 h-3.5" />
      </button>

      <div className="w-px h-4 bg-base-300 mx-1" />

      <button
        type="button"
        className={btnClass(false)}
        onClick={() => editor.chain().focus().setHorizontalRule().run()}
        title="Horizontal rule"
      >
        <Minus className="w-3.5 h-3.5" />
      </button>

      {/* Merge field insertion */}
      {onInsertMergeField && (
        <>
          <div className="w-px h-4 bg-base-300 mx-1" />
          <div className="relative">
            <button
              type="button"
              className={`btn btn-xs btn-ghost gap-1 ${showFields ? 'btn-active' : ''}`}
              onClick={() => setShowFields(!showFields)}
              title="Insert merge field"
            >
              <Braces className="w-3.5 h-3.5" />
              <ChevronDown className="w-3 h-3" />
            </button>
            {showFields && (
              <div className="absolute left-0 top-full mt-1 z-50 bg-base-100 border border-base-300 rounded-box shadow-lg w-52 max-h-56 overflow-y-auto">
                {COMPOSE_MERGE_FIELDS.map((group) => (
                  <div key={group.label}>
                    <div className="px-3 py-1 text-xs font-semibold text-base-content/50 uppercase tracking-wider">
                      {group.label}
                    </div>
                    {group.fields.map((field) => (
                      <button
                        key={field}
                        type="button"
                        className="w-full text-left px-3 py-1.5 text-sm hover:bg-base-200 transition-colors"
                        onClick={() => {
                          onInsertMergeField(field);
                          setShowFields(false);
                        }}
                      >
                        <code className="text-xs">{`{{${field}}}`}</code>
                      </button>
                    ))}
                  </div>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

// ── Compose Modal ────────────────────────────────────────────────────────────

export function ComposeModal({ apiBase, context, onClose, onSent }: ComposeModalProps) {
  const authHeaders = useAuthHeaders();
  const headersRef = useRef(authHeaders);
  headersRef.current = authHeaders;

  const [to, setTo] = useState<string[]>(context?.to ?? []);
  const [cc, setCc] = useState<string[]>(context?.cc ?? []);
  const [bcc, setBcc] = useState<string[]>([]);
  const [subject, setSubject] = useState(context?.subject ?? '');
  const [showCcBcc, setShowCcBcc] = useState((context?.cc?.length ?? 0) > 0);
  const [sending, setSending] = useState(false);
  const [showSchedule, setShowSchedule] = useState(false);
  const [scheduleDate, setScheduleDate] = useState('');
  const [scheduleTime, setScheduleTime] = useState('');
  const [mailboxes, setMailboxes] = useState<Mailbox[]>([]);
  const [selectedMailboxId, setSelectedMailboxId] = useState('');
  const [templates, setTemplates] = useState<TemplateSummary[]>([]);
  const [selectedTemplateId, setSelectedTemplateId] = useState<string | null>(null);

  // Build initial HTML content with quoted text for reply/forward
  const initialContent = context?.quotedHtml
    ? `<p></p><br><blockquote>${context.quotedHtml}</blockquote>`
    : '<p></p>';

  const editor = useEditor({
    extensions: [
      StarterKit,
      Underline,
      Link.configure({ openOnClick: false }),
    ],
    content: initialContent,
    editorProps: {
      attributes: {
        class: 'prose prose-sm max-w-none min-h-[200px] px-3 py-2 focus:outline-none',
      },
    },
  });

  // Fetch mailboxes + templates on mount
  useEffect(() => {
    async function load() {
      try {
        const [mbResult, tplResult] = await Promise.all([
          api.listMailboxes(apiBase, headersRef.current),
          api.listTemplates(apiBase, headersRef.current),
        ]);
        setMailboxes(mbResult.mailboxes);
        if (mbResult.mailboxes.length > 0) {
          setSelectedMailboxId(mbResult.mailboxes[0].id);
        }
        setTemplates(tplResult.templates);
      } catch {
        toast.error('Failed to load mailboxes');
      }
    }
    load();
  }, [apiBase]);

  // Apply a template: load its body into the editor and subject
  const applyTemplate = useCallback(async (templateId: string) => {
    if (!templateId) {
      setSelectedTemplateId(null);
      return;
    }
    try {
      const { template } = await api.getTemplate(apiBase, headersRef.current, templateId);
      // Only overwrite if composing a new message (don't clobber reply context)
      if (context?.mode === 'new' || !context) {
        setSubject(template.subject);
      }
      editor?.commands.setContent(template.bodyHtml);
      setSelectedTemplateId(templateId);
    } catch {
      toast.error('Failed to load template');
    }
  }, [apiBase, context, editor]);

  // Insert merge field at cursor position
  const insertMergeField = useCallback((field: string) => {
    editor?.chain().focus().insertContent(`{{${field}}}`).run();
  }, [editor]);

  const handleSend = useCallback(async (scheduled = false) => {
    if (to.length === 0) {
      toast.error('Add at least one recipient');
      return;
    }
    if (!subject.trim()) {
      toast.error('Add a subject');
      return;
    }
    if (!selectedMailboxId) {
      toast.error('No mailbox selected');
      return;
    }

    const bodyHtml = editor?.getHTML() ?? '';

    let scheduledAt: number | undefined;
    if (scheduled && scheduleDate && scheduleTime) {
      scheduledAt = new Date(`${scheduleDate}T${scheduleTime}`).getTime();
      if (scheduledAt <= Date.now()) {
        toast.error('Scheduled time must be in the future');
        return;
      }
    }

    setSending(true);
    try {
      const result = await api.sendEmail(apiBase, headersRef.current, {
        mailboxId: selectedMailboxId,
        to,
        cc: cc.length > 0 ? cc : undefined,
        bcc: bcc.length > 0 ? bcc : undefined,
        subject,
        bodyHtml,
        inReplyTo: context?.inReplyTo,
        threadId: context?.threadId,
        scheduledAt,
      });

      // Increment template usage count
      if (selectedTemplateId) {
        api.incrementTemplateUsage(apiBase, headersRef.current, selectedTemplateId).catch(() => {});
      }

      toast.success(
        result.status === 'scheduled' ? 'Email scheduled' : 'Email sent',
      );
      onSent?.();
      onClose();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to send email');
    } finally {
      setSending(false);
    }
  }, [to, cc, bcc, subject, editor, selectedMailboxId, selectedTemplateId, apiBase, context, scheduleDate, scheduleTime, onClose, onSent]);

  const modeLabel = {
    new: 'New Message',
    reply: 'Reply',
    replyAll: 'Reply All',
    forward: 'Forward',
  }[context?.mode ?? 'new'];

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center">
      {/* Backdrop */}
      <div className="fixed inset-0 bg-black/30" onClick={onClose} />

      {/* Modal */}
      <div className="relative bg-base-100 rounded-t-xl sm:rounded-xl shadow-2xl w-full max-w-2xl max-h-[90vh] flex flex-col border border-base-300">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-base-300">
          <h2 className="text-sm font-semibold">{modeLabel}</h2>
          <button
            className="btn btn-ghost btn-xs btn-circle"
            onClick={onClose}
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Form */}
        <div className="flex-1 overflow-y-auto">
          <div className="px-4 py-3 space-y-2">
            {/* From (mailbox selector) */}
            {mailboxes.length > 1 && (
              <div className="flex items-center gap-2">
                <span className="text-sm text-base-content/50 w-10 flex-shrink-0">From</span>
                <select
                  className="select select-sm select-bordered flex-1"
                  value={selectedMailboxId}
                  onChange={(e) => setSelectedMailboxId(e.target.value)}
                >
                  {mailboxes.map((m) => (
                    <option key={m.id} value={m.id}>
                      {m.emailAddress}
                    </option>
                  ))}
                </select>
              </div>
            )}

            {/* Template selector (new message mode only) */}
            {templates.length > 0 && (context?.mode === 'new' || !context) && (
              <div className="flex items-center gap-2">
                <span className="text-sm text-base-content/50 w-10 flex-shrink-0">
                  <FileText className="w-4 h-4" />
                </span>
                <select
                  className="select select-sm select-bordered flex-1"
                  value={selectedTemplateId ?? ''}
                  onChange={(e) => applyTemplate(e.target.value)}
                >
                  <option value="">No template</option>
                  {templates.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name}{t.category ? ` (${t.category})` : ''}
                    </option>
                  ))}
                </select>
              </div>
            )}

            <EmailPillInput label="To" emails={to} onChange={setTo} />

            {/* CC/BCC toggle */}
            {!showCcBcc && (
              <button
                type="button"
                className="text-xs text-primary hover:underline ml-12"
                onClick={() => setShowCcBcc(true)}
              >
                Cc / Bcc
              </button>
            )}
            {showCcBcc && (
              <>
                <EmailPillInput label="Cc" emails={cc} onChange={setCc} />
                <EmailPillInput label="Bcc" emails={bcc} onChange={setBcc} />
              </>
            )}

            {/* Subject */}
            <div className="flex items-center gap-2">
              <span className="text-sm text-base-content/50 w-10 flex-shrink-0">Subj</span>
              <input
                className="flex-1 text-sm bg-transparent border border-base-300 rounded-lg px-2 py-1.5 outline-none focus:border-primary/50"
                placeholder="Subject"
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
              />
            </div>
          </div>

          {/* Rich text editor */}
          <div className="border-t border-base-300">
            <EditorToolbar editor={editor} onInsertMergeField={insertMergeField} />
            <EditorContent editor={editor} />
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-4 py-3 border-t border-base-300">
          <button
            className="btn btn-ghost btn-sm text-error"
            onClick={onClose}
            disabled={sending}
          >
            Discard
          </button>

          <div className="flex items-center gap-2">
            {/* Schedule toggle */}
            <button
              type="button"
              className={`btn btn-sm btn-ghost gap-1 ${showSchedule ? 'btn-active' : ''}`}
              onClick={() => setShowSchedule(!showSchedule)}
              title="Schedule send"
            >
              <Clock className="w-4 h-4" />
              {showSchedule ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            </button>

            {showSchedule && (
              <div className="flex items-center gap-1">
                <input
                  type="date"
                  className="input input-bordered input-xs"
                  value={scheduleDate}
                  onChange={(e) => setScheduleDate(e.target.value)}
                />
                <input
                  type="time"
                  className="input input-bordered input-xs"
                  value={scheduleTime}
                  onChange={(e) => setScheduleTime(e.target.value)}
                />
                <button
                  className="btn btn-sm btn-secondary gap-1"
                  onClick={() => handleSend(true)}
                  disabled={sending || !scheduleDate || !scheduleTime}
                >
                  {sending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Clock className="w-4 h-4" />}
                  Schedule
                </button>
              </div>
            )}

            {!showSchedule && (
              <button
                className="btn btn-sm btn-primary gap-1"
                onClick={() => handleSend(false)}
                disabled={sending}
              >
                {sending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                Send
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
