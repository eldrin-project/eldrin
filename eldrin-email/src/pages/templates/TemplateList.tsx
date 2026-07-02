import { useState, useEffect, useCallback, useRef } from 'react';
import { useAuthHeaders } from '@eldrin-project/eldrin-app-react';
import { toast } from 'sonner';
import {
  FileText,
  Plus,
  Search,
  RefreshCw,
  Pencil,
  Trash2,
  Users,
  Braces,
} from 'lucide-react';
import * as api from '../../api';
import type { TemplateSummary } from '../../types/template';
import { TemplateEditor } from './TemplateEditor';

interface TemplateListProps {
  apiBase: string;
}

function formatDate(ts: number): string {
  return new Date(ts).toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

export function TemplateList({ apiBase }: TemplateListProps) {
  const authHeaders = useAuthHeaders();
  const headersRef = useRef(authHeaders);
  headersRef.current = authHeaders;

  const [templates, setTemplates] = useState<TemplateSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchInput, setSearchInput] = useState('');
  const [search, setSearch] = useState('');
  const [editingId, setEditingId] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  // Debounce search
  useEffect(() => {
    const timer = setTimeout(() => setSearch(searchInput), 300);
    return () => clearTimeout(timer);
  }, [searchInput]);

  const fetchTemplates = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.listTemplates(apiBase, headersRef.current, {
        search: search || undefined,
      });
      setTemplates(result.templates);
    } catch {
      toast.error('Failed to load templates');
    } finally {
      setLoading(false);
    }
  }, [apiBase, search]);

  useEffect(() => {
    fetchTemplates();
  }, [fetchTemplates]);

  async function handleDelete(id: string) {
    try {
      await api.deleteTemplate(apiBase, headersRef.current, id);
      toast.success('Template deleted');
      setDeletingId(null);
      fetchTemplates();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to delete template');
    }
  }

  // Show editor view
  if (creating || editingId) {
    return (
      <TemplateEditor
        apiBase={apiBase}
        templateId={editingId ?? undefined}
        onClose={() => { setCreating(false); setEditingId(null); }}
        onSaved={() => fetchTemplates()}
      />
    );
  }

  // Empty state
  if (!loading && templates.length === 0 && !search) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-base-content/50">
        <FileText className="w-12 h-12 mb-4 opacity-30" />
        <h2 className="text-lg font-semibold mb-1">No templates yet</h2>
        <p className="text-sm mb-4">Create reusable email templates with merge fields.</p>
        <button
          className="btn btn-primary btn-sm gap-1"
          onClick={() => setCreating(true)}
        >
          <Plus className="w-4 h-4" />
          Create Template
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
              placeholder="Search templates..."
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
            />
          </div>

          <button
            className="btn btn-sm btn-ghost gap-1"
            onClick={() => fetchTemplates()}
            disabled={loading}
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>

          <button
            className="btn btn-sm btn-primary gap-1"
            onClick={() => setCreating(true)}
          >
            <Plus className="w-4 h-4" />
            New Template
          </button>
        </div>
      </div>

      {/* Scrollable template list */}
      <div className="flex-1 overflow-y-auto min-h-0">
        {loading && templates.length === 0 ? (
          <div className="flex justify-center items-center h-full">
            <span className="loading loading-spinner loading-md" />
          </div>
        ) : templates.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-base-content/50">
            <FileText className="w-10 h-10 mb-3 opacity-30" />
            <p className="text-sm">No templates match your search.</p>
          </div>
        ) : (
          <div className="divide-y divide-base-300">
            {templates.map((template) => (
              <div
                key={template.id}
                className="flex items-center gap-3 px-4 sm:px-6 py-3 hover:bg-base-200 transition-colors group"
              >
                {/* Icon */}
                <div className="flex-shrink-0 w-9 h-9 rounded-full bg-accent/10 flex items-center justify-center">
                  <FileText className="w-4 h-4 text-accent" />
                </div>

                {/* Content — clickable to edit */}
                <button
                  className="flex-1 min-w-0 text-left"
                  onClick={() => setEditingId(template.id)}
                >
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium truncate">
                      {template.name}
                    </span>
                    {template.isShared && (
                      <span className="badge badge-soft badge-xs gap-1">
                        <Users className="w-3 h-3" />
                        Shared
                      </span>
                    )}
                    {template.category && (
                      <span className="badge badge-soft badge-xs">
                        {template.category}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="text-sm text-base-content/70 truncate">
                      {template.subject}
                    </span>
                    {template.mergeFields.length > 0 && (
                      <span className="text-xs text-base-content/40 flex items-center gap-0.5 flex-shrink-0">
                        <Braces className="w-3 h-3" />
                        {template.mergeFields.length}
                      </span>
                    )}
                  </div>
                </button>

                {/* Meta */}
                <div className="flex items-center gap-3 flex-shrink-0">
                  <span className="text-xs text-base-content/40">
                    {template.usageCount > 0 && `Used ${template.usageCount}x · `}
                    {formatDate(template.updatedAt)}
                  </span>

                  {/* Actions (owner only) */}
                  {template.isOwner && (
                    <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                      <button
                        className="btn btn-ghost btn-xs btn-circle"
                        onClick={() => setEditingId(template.id)}
                        title="Edit"
                      >
                        <Pencil className="w-3.5 h-3.5" />
                      </button>
                      <button
                        className="btn btn-ghost btn-xs btn-circle text-error"
                        onClick={() => setDeletingId(template.id)}
                        title="Delete"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Delete confirmation modal */}
      {deletingId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="fixed inset-0 bg-black/30" onClick={() => setDeletingId(null)} />
          <div className="relative bg-base-100 rounded-xl shadow-2xl p-6 max-w-sm border border-base-300">
            <h3 className="text-lg font-semibold mb-2">Delete Template</h3>
            <p className="text-sm text-base-content/60 mb-4">
              Are you sure you want to delete this template? This action cannot be undone.
            </p>
            <div className="flex justify-end gap-2">
              <button className="btn btn-sm btn-ghost" onClick={() => setDeletingId(null)}>
                Cancel
              </button>
              <button className="btn btn-sm btn-error" onClick={() => handleDelete(deletingId)}>
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
