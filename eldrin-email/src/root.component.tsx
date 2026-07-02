import { useState, useEffect, useCallback, useRef } from 'react';
import { useAuthHeaders } from '@eldrin-project/eldrin-app-react';
import { Inbox, Send, FileText, Settings, ChevronDown } from 'lucide-react';
import { Toaster } from 'sonner';
import type { Mailbox } from './types/mailbox';
import * as api from './api';
import { InboxList } from './pages/inbox/InboxList';
import { ThreadView } from './pages/inbox/ThreadView';
import { SentList } from './pages/sent/SentList';
import { TemplateList } from './pages/templates/TemplateList';
import { MailboxSettings } from './pages/settings/MailboxSettings';

interface AppManifest {
  baseUrl?: string;
}

export interface RootProps {
  manifest?: AppManifest;
}

/** Maps the shell's data-theme to our scoped daisyUI theme name */
const getShellTheme = () =>
  document.documentElement.getAttribute('data-theme') === 'dark'
    ? 'eldrin-dark'
    : 'eldrin';

// ── Route Parsing ────────────────────────────────────────────────────────────

type EmailSection = 'inbox' | 'sent' | 'templates' | 'settings';

interface Route {
  section: EmailSection;
  id?: string;
}

const sections: { page: EmailSection; label: string; icon: React.ReactNode }[] = [
  { page: 'inbox', label: 'Inbox', icon: <Inbox className="w-5 h-5" /> },
  { page: 'sent', label: 'Sent', icon: <Send className="w-5 h-5" /> },
  { page: 'templates', label: 'Templates', icon: <FileText className="w-5 h-5" /> },
  { page: 'settings', label: 'Settings', icon: <Settings className="w-5 h-5" /> },
];

function parseRoute(pathname: string): Route {
  const prefix = '/eldrin-email';
  const path = pathname.startsWith(prefix) ? pathname.slice(prefix.length) : pathname;
  const parts = path.split('/').filter(Boolean);

  const validSections: EmailSection[] = ['inbox', 'sent', 'templates', 'settings'];

  const section = (parts[0] && validSections.includes(parts[0] as EmailSection))
    ? (parts[0] as EmailSection)
    : 'inbox';

  if (parts[1]) {
    return { section, id: parts[1] };
  }

  return { section };
}

// ── Root Component ───────────────────────────────────────────────────────────

export function Root({ manifest }: RootProps) {
  const apiBase = manifest?.baseUrl || '';
  const authHeaders = useAuthHeaders();
  const headersRef = useRef(authHeaders);
  headersRef.current = authHeaders;

  const [daisyTheme, setDaisyTheme] = useState(getShellTheme);
  const [pathname, setPathname] = useState(window.location.pathname);
  const [mailboxes, setMailboxes] = useState<Mailbox[]>([]);
  const [selectedMailboxId, setSelectedMailboxId] = useState<string | undefined>();

  // Fetch mailboxes once on mount
  useEffect(() => {
    api.listMailboxes(apiBase, headersRef.current)
      .then(({ mailboxes: list }) => setMailboxes(list))
      .catch(() => { /* settings page handles errors */ });
  }, [apiBase]);

  // Sync theme with shell
  useEffect(() => {
    const observer = new MutationObserver(() => setDaisyTheme(getShellTheme()));
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-theme'],
    });
    return () => observer.disconnect();
  }, []);

  // Listen for navigation
  useEffect(() => {
    const handleNav = () => setPathname(window.location.pathname);
    window.addEventListener('popstate', handleNav);
    return () => window.removeEventListener('popstate', handleNav);
  }, []);

  const navigate = useCallback((path: string) => {
    window.history.pushState({}, '', path);
    setPathname(path);
  }, []);

  const route = parseRoute(pathname);

  const renderPage = () => {
    switch (route.section) {
      case 'inbox':
        if (route.id) {
          return (
            <ThreadView
              apiBase={apiBase}
              threadId={route.id}
              onNavigate={navigate}
            />
          );
        }
        return <InboxList apiBase={apiBase} onNavigate={navigate} mailboxId={selectedMailboxId} />;
      case 'sent':
        return <SentList apiBase={apiBase} onNavigate={navigate} mailboxId={selectedMailboxId} />;
      case 'templates':
        return <TemplateList apiBase={apiBase} />;
      case 'settings':
        return <MailboxSettings apiBase={apiBase} />;
      default:
        return <InboxList apiBase={apiBase} onNavigate={navigate} mailboxId={selectedMailboxId} />;
    }
  };

  return (
    <div
      data-theme={daisyTheme}
      className="font-sans flex flex-col overflow-hidden bg-base-100 text-base-content"
      style={{ height: 'calc(100dvh - var(--layout-topbar-height, 56px) - 48px)' }}
    >
      {/* Standalone mode: show inline nav tabs */}
      {!manifest && (
        <div className="flex gap-1 border-b border-base-300 pb-2 pt-2 px-4 sm:px-6 flex-shrink-0">
          {sections.map((s) => (
            <button
              key={s.page}
              onClick={() =>
                navigate(
                  s.page === 'inbox'
                    ? '/eldrin-email'
                    : `/eldrin-email/${s.page}`,
                )
              }
              className={`btn btn-sm btn-ghost gap-2 ${
                route.section === s.page ? 'btn-active' : ''
              }`}
            >
              {s.icon}
              {s.label}
            </button>
          ))}
        </div>
      )}

      {/* Mailbox filter — shown when multiple mailboxes are connected */}
      {mailboxes.length > 1 && (route.section === 'inbox' || route.section === 'sent') && (
        <div className="flex-shrink-0 px-4 sm:px-6 pt-2 pb-1">
          <div className="relative inline-block">
            <select
              className="select select-bordered select-xs pr-8 min-w-[180px]"
              value={selectedMailboxId ?? ''}
              onChange={(e) => setSelectedMailboxId(e.target.value || undefined)}
            >
              <option value="">All mailboxes</option>
              {mailboxes.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.emailAddress}
                </option>
              ))}
            </select>
            <ChevronDown className="w-3 h-3 absolute right-2 top-1/2 -translate-y-1/2 pointer-events-none text-base-content/40" />
          </div>
        </div>
      )}

      <div className="flex-1 min-h-0">
        {renderPage()}
      </div>

      <Toaster
        position="bottom-right"
        richColors
        theme={daisyTheme === 'eldrin-dark' ? 'dark' : 'light'}
      />
    </div>
  );
}
