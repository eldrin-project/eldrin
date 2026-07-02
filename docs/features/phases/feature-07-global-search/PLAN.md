# Feature 7: Global Search + Command Palette

## Overview

Cmd+K opens a command palette for quick navigation and cross-entity search. Similar to VS Code / Linear / GitHub. Fuzzy matching, keyboard navigation, recent searches, and extensible command registration for micro-apps.

## Dependencies

- `cmdk` — React command palette primitives (~4KB)

## Architecture

### Extensible Command System

Extension apps register **command providers** via `window.__ELDRIN__.registerCommands()`. Each provider owns a prefix (namespace) and supplies a tree of commands.

```ts
interface CommandProvider {
  prefix: string;           // 'todo', 'crm'
  label: string;            // Group label in palette
  icon?: string;            // lucide icon name
  commands: CommandDefinition[];
}

interface CommandDefinition {
  id: string;               // 'create', 'approve'
  label: string;
  icon?: string;
  keywords?: string[];
  onSelect?: () => void;                           // terminal action
  getChildren?: () => Promise<CommandDefinition[]>; // drill-down
}
```

Multi-step flow: `user:approve` → `getChildren()` fetches pending users → user selects one → `onSelect()` fires.

### Backend

- `GET /api/search?q=...&types=...&limit=...` — permission-filtered search
- Users: name/email LIKE (requires `platform:core:users:read`)
- Apps: name LIKE (any authenticated user)
- Audit: action/actor LIKE (requires `platform:core:audit:read`)

### Frontend

- `src/components/ui/command.tsx` — shadcn Command primitives wrapping cmdk
- `src/stores/commandRegistry.ts` — Zustand store for command providers
- `src/hooks/useCommandPalette.ts` — debounced search, drill-down, recent searches
- `src/components/CommandPalette.tsx` — main palette UI
- `src/components/TopBar.tsx` — search button trigger + Cmd+K shortcut

### Files

| File | Purpose |
|------|---------|
| `src/components/ui/command.tsx` | shadcn Command primitives |
| `src/stores/commandRegistry.ts` | Extensible command provider store |
| `src/hooks/useCommandPalette.ts` | Search, drill-down, recent searches |
| `src/components/CommandPalette.tsx` | Main palette UI |
| `core/routes/search.ts` | Backend search endpoint |
| `core/routes/search.test.ts` | 11 backend tests |
| `src/stores/appRegistry.ts` | Extended with registerCommands/unregisterCommands |
| `core/routes/index.ts` | handleSearch export |
| `core/app.ts` | GET /api/search route registration |
| `src/components/TopBar.tsx` | Palette trigger + render |
| `src/locales/en/common.json` | search.* i18n keys |

## Test Gate

```bash
cd eldrin-core && npx tsc -b && npx vitest run
```

1. Cmd+K opens palette
2. Type to filter navigation items
3. Server search finds users/apps
4. Keyboard navigation works
5. Recent searches remembered
6. Extension apps can register commands via `window.__ELDRIN__.registerCommands()`
7. Multi-step drill-down with getChildren()
8. Backspace on empty input goes back one level
9. Non-admin users don't see permission-gated commands
