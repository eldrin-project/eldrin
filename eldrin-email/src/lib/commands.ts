/**
 * Email commands for the platform Cmd+K palette.
 * Registers navigation and quick action commands.
 */

interface CommandDefinition {
  id: string;
  label: string;
  icon?: string;
  keywords?: string[];
  onSelect?: () => void;
  getChildren?: () => Promise<CommandDefinition[]>;
}

interface CommandProvider {
  prefix: string;
  label: string;
  icon?: string;
  commands: CommandDefinition[];
}

interface EldrinGlobal {
  registerCommands?: (provider: CommandProvider) => void;
  unregisterCommands?: (prefix: string) => void;
}

declare global {
  interface Window {
    __ELDRIN__?: EldrinGlobal;
  }
}

function navigate(path: string) {
  window.history.pushState({}, '', path);
  window.dispatchEvent(new PopStateEvent('popstate'));
}

export function registerEmailCommands(_apiBase: string): void {
  const eldrin = window.__ELDRIN__;
  if (!eldrin?.registerCommands) return;

  const provider: CommandProvider = {
    prefix: 'email',
    label: 'Email',
    icon: 'mail',
    commands: [
      // ── Navigation commands ───────────────────────────────────────────
      {
        id: 'go-inbox',
        label: 'Go to Inbox',
        icon: 'inbox',
        keywords: ['navigate', 'inbox', 'messages', 'mail'],
        onSelect: () => navigate('/eldrin-email'),
      },
      {
        id: 'go-sent',
        label: 'Go to Sent',
        icon: 'send',
        keywords: ['navigate', 'sent', 'outbox'],
        onSelect: () => navigate('/eldrin-email/sent'),
      },
      {
        id: 'go-templates',
        label: 'Email Templates',
        icon: 'file-text',
        keywords: ['navigate', 'templates', 'email templates'],
        onSelect: () => navigate('/eldrin-email/templates'),
      },
      {
        id: 'go-settings',
        label: 'Email Settings',
        icon: 'settings',
        keywords: ['navigate', 'settings', 'mailbox', 'configuration'],
        onSelect: () => navigate('/eldrin-email/settings'),
      },

      // ── Quick actions ─────────────────────────────────────────────────
      {
        id: 'compose',
        label: 'Compose Email',
        icon: 'pen-square',
        keywords: ['new', 'compose', 'write', 'send', 'draft'],
        onSelect: () => {
          // Navigate to inbox and trigger compose modal via custom event
          navigate('/eldrin-email');
          window.dispatchEvent(new CustomEvent('eldrin-email:compose'));
        },
      },
      {
        id: 'search',
        label: 'Search Emails...',
        icon: 'search',
        keywords: ['find', 'search', 'lookup', 'email'],
        onSelect: () => {
          navigate('/eldrin-email');
          // Focus the search input after navigation
          requestAnimationFrame(() => {
            const input = document.querySelector<HTMLInputElement>(
              '[data-email-search]',
            );
            input?.focus();
          });
        },
      },
    ],
  };

  eldrin.registerCommands(provider);
}

export function unregisterEmailCommands(): void {
  const eldrin = window.__ELDRIN__;
  if (!eldrin?.unregisterCommands) return;
  eldrin.unregisterCommands('email');
}
