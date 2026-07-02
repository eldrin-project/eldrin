import { useState, useRef, useCallback, useEffect } from 'react';
import { useAuthHeaders } from '@eldrin-project/eldrin-app-react';
import { toast } from 'sonner';
import { useEditor, EditorContent } from '@tiptap/react';
import StarterKit from '@tiptap/starter-kit';
import Link from '@tiptap/extension-link';
import Underline from '@tiptap/extension-underline';
import {
  X,
  Save,
  Eye,
  Bold,
  Italic,
  Underline as UnderlineIcon,
  Link as LinkIcon,
  List,
  ListOrdered,
  Minus,
  ChevronDown,
  Loader2,
  Braces,
} from 'lucide-react';
import * as api from '../../api';
import type { CreateTemplateParams, UpdateTemplateParams } from '../../types/template';

// ── Merge Field Categories ──────────────────────────────────────────────────

const MERGE_FIELD_GROUPS = [
  {
    label: 'Contact',
    fields: [
      'contact.firstName',
      'contact.lastName',
      'contact.email',
      'contact.company',
      'contact.phone',
      'contact.title',
    ],
  },
  {
    label: 'Company',
    fields: ['company.name', 'company.domain', 'company.industry'],
  },
  {
    label: 'Deal',
    fields: ['deal.name', 'deal.value', 'deal.stage', 'deal.closeDate'],
  },
  {
    label: 'User',
    fields: ['user.name', 'user.email', 'user.title'],
  },
];

// ── Editor Toolbar ──────────────────────────────────────────────────────────

function EditorToolbar({
  editor,
  onInsertMergeField,
}: {
  editor: ReturnType<typeof useEditor>;
  onInsertMergeField: (field: string) => void;
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
      <button type="button" className={btnClass(editor.isActive('bold'))} onClick={() => editor.chain().focus().toggleBold().run()} title="Bold">
        <Bold className="w-3.5 h-3.5" />
      </button>
      <button type="button" className={btnClass(editor.isActive('italic'))} onClick={() => editor.chain().focus().toggleItalic().run()} title="Italic">
        <Italic className="w-3.5 h-3.5" />
      </button>
      <button type="button" className={btnClass(editor.isActive('underline'))} onClick={() => editor.chain().focus().toggleUnderline().run()} title="Underline">
        <UnderlineIcon className="w-3.5 h-3.5" />
      </button>

      <div className="w-px h-4 bg-base-300 mx-1" />

      <button type="button" className={btnClass(editor.isActive('link'))} onClick={toggleLink} title="Link">
        <LinkIcon className="w-3.5 h-3.5" />
      </button>

      <div className="w-px h-4 bg-base-300 mx-1" />

      <button type="button" className={btnClass(editor.isActive('bulletList'))} onClick={() => editor.chain().focus().toggleBulletList().run()} title="Bullet list">
        <List className="w-3.5 h-3.5" />
      </button>
      <button type="button" className={btnClass(editor.isActive('orderedList'))} onClick={() => editor.chain().focus().toggleOrderedList().run()} title="Numbered list">
        <ListOrdered className="w-3.5 h-3.5" />
      </button>

      <div className="w-px h-4 bg-base-300 mx-1" />

      <button type="button" className={btnClass(false)} onClick={() => editor.chain().focus().setHorizontalRule().run()} title="Horizontal rule">
        <Minus className="w-3.5 h-3.5" />
      </button>

      <div className="w-px h-4 bg-base-300 mx-1" />

      {/* Merge field dropdown */}
      <div className="relative">
        <button
          type="button"
          className={`btn btn-xs btn-ghost gap-1 ${showFields ? 'btn-active' : ''}`}
          onClick={() => setShowFields(!showFields)}
          title="Insert merge field"
        >
          <Braces className="w-3.5 h-3.5" />
          <span className="text-xs hidden sm:inline">Merge Field</span>
          <ChevronDown className="w-3 h-3" />
        </button>

        {showFields && (
          <div className="absolute left-0 top-full mt-1 z-50 bg-base-100 border border-base-300 rounded-box shadow-lg w-56 max-h-64 overflow-y-auto">
            {MERGE_FIELD_GROUPS.map((group) => (
              <div key={group.label}>
                <div className="px-3 py-1.5 text-xs font-semibold text-base-content/50 uppercase tracking-wider">
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
    </div>
  );
}

// ── Preview Panel ───────────────────────────────────────────────────────────
// Preview renders server-resolved merge fields inside a sandboxed iframe
// to avoid XSS from template HTML content.

function PreviewPanel({
  apiBase,
  templateId,
}: {
  apiBase: string;
  templateId: string;
}) {
  const authHeaders = useAuthHeaders();
  const headersRef = useRef(authHeaders);
  headersRef.current = authHeaders;

  const [preview, setPreview] = useState<{ subject: string; bodyHtml: string } | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    api.previewTemplate(apiBase, headersRef.current, templateId)
      .then(setPreview)
      .catch(() => toast.error('Failed to load preview'))
      .finally(() => setLoading(false));
  }, [apiBase, templateId]);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <span className="loading loading-spinner loading-md" />
      </div>
    );
  }

  if (!preview) return null;

  return (
    <div className="space-y-3">
      <div>
        <span className="text-xs font-medium text-base-content/50">Subject</span>
        <p className="text-sm mt-0.5">{preview.subject}</p>
      </div>
      <div>
        <span className="text-xs font-medium text-base-content/50">Body</span>
        <iframe
          srcDoc={`<style>html,body{background:#fff;color:#000;color-scheme:light;font-family:sans-serif;font-size:14px;margin:0;padding:12px}</style>${preview.bodyHtml}`}
          sandbox=""
          className="w-full border border-base-300 rounded-lg mt-1"
          style={{ height: '300px', colorScheme: 'light' }}
          onLoad={(e) => {
            const iframe = e.target as HTMLIFrameElement;
            try {
              const height = iframe.contentDocument?.body?.scrollHeight;
              if (height) iframe.style.height = `${height + 24}px`;
            } catch { /* sandbox */ }
          }}
          title="Template preview"
        />
      </div>
    </div>
  );
}

// ── Template Editor ─────────────────────────────────────────────────────────

interface TemplateEditorProps {
  apiBase: string;
  templateId?: string; // undefined = create mode
  onClose: () => void;
  onSaved: () => void;
}

export function TemplateEditor({ apiBase, templateId, onClose, onSaved }: TemplateEditorProps) {
  const authHeaders = useAuthHeaders();
  const headersRef = useRef(authHeaders);
  headersRef.current = authHeaders;

  const [name, setName] = useState('');
  const [subject, setSubject] = useState('');
  const [category, setCategory] = useState('');
  const [isShared, setIsShared] = useState(false);
  const [saving, setSaving] = useState(false);
  const [loading, setLoading] = useState(!!templateId);
  const [showPreview, setShowPreview] = useState(false);
  const [savedTemplateId, setSavedTemplateId] = useState(templateId);

  const editor = useEditor({
    extensions: [
      StarterKit,
      Underline,
      Link.configure({ openOnClick: false }),
    ],
    content: '<p></p>',
    editorProps: {
      attributes: {
        class: 'prose prose-sm max-w-none min-h-[200px] px-3 py-2 focus:outline-none',
      },
    },
  });

  // Load existing template data
  useEffect(() => {
    if (!templateId) return;
    api.getTemplate(apiBase, headersRef.current, templateId)
      .then(({ template }) => {
        setName(template.name);
        setSubject(template.subject);
        setCategory(template.category ?? '');
        setIsShared(template.isShared);
        editor?.commands.setContent(template.bodyHtml);
      })
      .catch(() => toast.error('Failed to load template'))
      .finally(() => setLoading(false));
  }, [apiBase, templateId, editor]);

  const insertMergeField = useCallback((field: string) => {
    if (!editor) return;
    editor.chain().focus().insertContent(`{{${field}}}`).run();
  }, [editor]);

  const handleSave = useCallback(async () => {
    if (!name.trim()) { toast.error('Name is required'); return; }
    if (!subject.trim()) { toast.error('Subject is required'); return; }
    const bodyHtml = editor?.getHTML() ?? '';
    if (!bodyHtml || bodyHtml === '<p></p>') { toast.error('Body is required'); return; }

    setSaving(true);
    try {
      if (savedTemplateId) {
        const params: UpdateTemplateParams = {
          name: name.trim(),
          subject: subject.trim(),
          bodyHtml,
          category: category.trim() || undefined,
          isShared,
        };
        await api.updateTemplate(apiBase, headersRef.current, savedTemplateId, params);
        toast.success('Template updated');
      } else {
        const params: CreateTemplateParams = {
          name: name.trim(),
          subject: subject.trim(),
          bodyHtml,
          category: category.trim() || undefined,
          isShared,
        };
        const result = await api.createTemplate(apiBase, headersRef.current, params);
        setSavedTemplateId(result.id);
        toast.success('Template created');
      }
      onSaved();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to save template');
    } finally {
      setSaving(false);
    }
  }, [name, subject, editor, category, isShared, savedTemplateId, apiBase, onSaved]);

  if (loading) {
    return (
      <div className="flex justify-center items-center h-full">
        <span className="loading loading-spinner loading-lg" />
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between px-4 sm:px-6 pt-4 pb-3 border-b border-base-300 flex-shrink-0">
        <h2 className="text-lg font-semibold">
          {templateId ? 'Edit Template' : 'New Template'}
        </h2>
        <div className="flex items-center gap-2">
          {savedTemplateId && (
            <button
              type="button"
              className={`btn btn-sm btn-ghost gap-1 ${showPreview ? 'btn-active' : ''}`}
              onClick={() => setShowPreview(!showPreview)}
            >
              <Eye className="w-4 h-4" />
              Preview
            </button>
          )}
          <button
            className="btn btn-sm btn-primary gap-1"
            onClick={handleSave}
            disabled={saving}
          >
            {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
            Save
          </button>
          <button className="btn btn-ghost btn-sm btn-circle" onClick={onClose}>
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto min-h-0">
        {showPreview && savedTemplateId ? (
          <div className="px-4 sm:px-6 py-4">
            <PreviewPanel apiBase={apiBase} templateId={savedTemplateId} />
          </div>
        ) : (
          <>
            {/* Form fields */}
            <div className="px-4 sm:px-6 py-4 space-y-3">
              <div className="flex items-center gap-2">
                <span className="text-sm text-base-content/50 w-16 flex-shrink-0">Name</span>
                <input
                  className="flex-1 text-sm bg-transparent border border-base-300 rounded-lg px-2 py-1.5 outline-none focus:border-primary/50"
                  placeholder="Template name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>

              <div className="flex items-center gap-2">
                <span className="text-sm text-base-content/50 w-16 flex-shrink-0">Subject</span>
                <input
                  className="flex-1 text-sm bg-transparent border border-base-300 rounded-lg px-2 py-1.5 outline-none focus:border-primary/50"
                  placeholder="Email subject (supports {{merge.fields}})"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                />
              </div>

              <div className="flex items-center gap-2">
                <span className="text-sm text-base-content/50 w-16 flex-shrink-0">Category</span>
                <input
                  className="flex-1 text-sm bg-transparent border border-base-300 rounded-lg px-2 py-1.5 outline-none focus:border-primary/50"
                  placeholder="Optional category (e.g. Sales, Support)"
                  value={category}
                  onChange={(e) => setCategory(e.target.value)}
                />
              </div>

              <div className="flex items-center gap-2">
                <span className="text-sm text-base-content/50 w-16 flex-shrink-0">Shared</span>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    className="toggle toggle-sm toggle-primary"
                    checked={isShared}
                    onChange={(e) => setIsShared(e.target.checked)}
                  />
                  <span className="text-sm text-base-content/60">
                    {isShared ? 'Visible to all team members' : 'Only visible to you'}
                  </span>
                </label>
              </div>
            </div>

            {/* Rich text editor */}
            <div className="border-t border-base-300">
              <EditorToolbar editor={editor} onInsertMergeField={insertMergeField} />
              <EditorContent editor={editor} />
            </div>
          </>
        )}
      </div>
    </div>
  );
}
