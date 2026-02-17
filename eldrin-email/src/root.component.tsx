import { useState, useEffect, useCallback } from 'react';
import { Inbox, Send, FileText, Settings } from 'lucide-react';
import { Toaster } from 'sonner';
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
  const [daisyTheme, setDaisyTheme] = useState(getShellTheme);
  const [pathname, setPathname] = useState(window.location.pathname);

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
        return <InboxList apiBase={apiBase} onNavigate={navigate} />;
      case 'sent':
        return <SentList apiBase={apiBase} onNavigate={navigate} />;
      case 'templates':
        return <TemplateList />;
      case 'settings':
        return <MailboxSettings apiBase={apiBase} />;
      default:
        return <InboxList apiBase={apiBase} onNavigate={navigate} />;
    }
  };

  return (
    <div data-theme={daisyTheme} className="font-sans p-6">
      {/* Standalone mode: show inline nav tabs */}
      {!manifest && (
        <div className="flex gap-1 mb-6 border-b border-base-300 pb-2">
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

      {renderPage()}

      <Toaster
        position="bottom-right"
        richColors
        theme={daisyTheme === 'eldrin-dark' ? 'dark' : 'light'}
      />
    </div>
  );
}
