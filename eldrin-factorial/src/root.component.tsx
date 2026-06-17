import { useState, useEffect, useCallback } from 'react';
import { Users, UsersRound, CalendarOff, Settings } from 'lucide-react';
import { Toaster } from 'sonner';
import { EmployeeList } from './pages/employees/EmployeeList';
import { TeamList } from './pages/teams/TeamList';
import { TimeOffList } from './pages/timeoff/TimeOffList';
import { ConnectionSettings } from './pages/settings/ConnectionSettings';

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

type FactorialSection = 'employees' | 'teams' | 'timeoff' | 'settings';

interface Route {
  section: FactorialSection;
  id?: string;
}

function parseRoute(pathname: string): Route {
  const prefix = '/eldrin-factorial';
  const path = pathname.startsWith(prefix) ? pathname.slice(prefix.length) : pathname;
  const parts = path.split('/').filter(Boolean);

  const validSections: FactorialSection[] = ['employees', 'teams', 'timeoff', 'settings'];

  const section = (parts[0] && validSections.includes(parts[0] as FactorialSection))
    ? (parts[0] as FactorialSection)
    : 'employees';

  if (parts[1]) {
    return { section, id: parts[1] };
  }

  return { section };
}

// ── Nav Sections ─────────────────────────────────────────────────────────────

const navSections: { page: FactorialSection; label: string; icon: React.ReactNode }[] = [
  { page: 'employees', label: 'Employees', icon: <Users className="w-5 h-5" /> },
  { page: 'teams', label: 'Teams', icon: <UsersRound className="w-5 h-5" /> },
  { page: 'timeoff', label: 'Time Off', icon: <CalendarOff className="w-5 h-5" /> },
  { page: 'settings', label: 'Settings', icon: <Settings className="w-5 h-5" /> },
];

// ── Root Component ────────────────────────────────────────────────────────────

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
      case 'employees':
        return <EmployeeList apiBase={apiBase} />;
      case 'teams':
        return <TeamList apiBase={apiBase} />;
      case 'timeoff':
        return <TimeOffList apiBase={apiBase} />;
      case 'settings':
        return <ConnectionSettings apiBase={apiBase} />;
      default:
        return <EmployeeList apiBase={apiBase} />;
    }
  };

  return (
    <div
      data-theme={daisyTheme}
      className="font-sans flex overflow-hidden bg-base-100 text-base-content"
      style={{ height: 'calc(100dvh - var(--layout-topbar-height, 56px) - 48px)' }}
    >
      {/* Left side-nav */}
      <aside className="flex flex-col w-52 flex-shrink-0 border-r border-base-300 bg-base-200 py-4">
        {navSections.map((s) => (
          <button
            key={s.page}
            onClick={() =>
              navigate(
                s.page === 'employees'
                  ? '/eldrin-factorial'
                  : `/eldrin-factorial/${s.page}`,
              )
            }
            className={`flex items-center gap-3 px-4 py-2 text-sm font-medium hover:bg-base-300 transition-colors ${
              route.section === s.page ? 'bg-base-300 text-primary' : 'text-base-content'
            }`}
          >
            {s.icon}
            {s.label}
          </button>
        ))}
      </aside>

      {/* Main content */}
      <div className="flex-1 min-w-0 overflow-auto">
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
