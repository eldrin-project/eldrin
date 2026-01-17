# Eldrin Multi-Framework Support Plan

**Version:** 2.0.0
**Date:** January 2025
**Status:** Proposal (Updated with Code Analysis)
**Author:** Architecture Team

> **Note:** This document has been updated based on comprehensive analysis of the actual codebase:
> - `@eldrin-project/eldrin-app-core` - SDK for building Eldrin apps
> - `@eldrin-project/eldrin-core` - Shell application
> - `create-eldrin-project` (eldrin-templates) - CLI scaffolding tool
> - `react-todo` - Reference implementation

---

## Executive Summary

This document outlines the technical plan to enable Eldrin apps to be built with frameworks beyond React, including Vue, Angular, and Svelte. The goal is to maintain the platform's cohesive user experience while giving developers freedom to use their preferred tools.

---

## Table of Contents

1. [Current State Analysis](#1-current-state-analysis)
2. [Target Architecture](#2-target-architecture)
3. [Implementation Phases](#3-implementation-phases)
4. [Technical Details](#4-technical-details)
5. [Migration Strategy](#5-migration-strategy)
6. [Risks and Mitigations](#6-risks-and-mitigations)
7. [Decision Points](#7-decision-points)
8. [Success Criteria](#8-success-criteria)

---

## 1. Current State Analysis

### 1.1 Actual Package Structure

| Package | Location | Purpose |
|---------|----------|---------|
| `@eldrin-project/eldrin-app-core` | `/eldrin-app-core` | SDK for building Eldrin marketplace apps |
| `@eldrin-project/eldrin-core` | `/eldrin-core` | Shell application (React + single-spa) |
| `create-eldrin-project` | `/eldrin-templates` | CLI scaffolding tool |

### 1.2 Framework Dependencies (Actual Code Analysis)

| Component | Location | Framework-Agnostic? |
|-----------|----------|---------------------|
| **Shell Application** | `eldrin-core/src/` | No (React 19 + Vite 7) |
| **App Orchestration** | `eldrin-core/src/App.tsx` | **Yes** (single-spa v6) |
| **App Factory** | `eldrin-app-core/src/app/createApp.tsx` | No (React DOM mounting) |
| **Database Context** | `eldrin-app-core/src/database/context.tsx` | No (React Context + hooks) |
| **Migration System** | `eldrin-app-core/src/migrations/` | **Yes** (pure TypeScript) |
| **Auth/JWT System** | `eldrin-app-core/src/auth/index.ts` | **Yes** (Web Crypto API) |
| **Permission Middleware** | `eldrin-app-core/src/middleware/` | **Yes** (pure functions) |
| **Event System** | `eldrin-app-core/src/events/` | **Yes** (class-based client) |
| **CLI Tools** | `eldrin-app-core/src/cli/` | **Yes** (Node.js scripts) |
| **Vite Plugin** | `eldrin-app-core/src/vite.ts` | **Yes** (build-time only) |
| **State Management** | `eldrin-core/src/stores/` | No (Zustand v5) |
| **Event Bus (Shell)** | `eldrin-core/src/stores/eventBus.ts` | Mixed (Zustand wrapper, but logic is agnostic) |
| **Design Tokens** | `eldrin-core/src/index.css` | **Yes** (CSS custom properties) |
| **Manifest System** | JSON files | **Yes** |
| **Global Context** | `window.__ELDRIN__` | **Yes** (plain JS object) |

### 1.3 Key Insight

**~70% of the SDK is already framework-agnostic.** The React-specific code is isolated to two modules:
- `eldrin-app-core/src/app/createApp.tsx` - Single-spa lifecycle with React DOM
- `eldrin-app-core/src/database/context.tsx` - React Context for database access

### 1.4 What Already Works (Framework-Agnostic)

| Feature | File | Notes |
|---------|------|-------|
| Design tokens | `eldrin-core/src/index.css` | Pure CSS variables, works with any framework |
| App manifest | `eldrin-app.manifest.json` | JSON schema, no framework assumptions |
| Migration execution | `eldrin-app-core/src/migrations/runner.ts` | Uses D1 API directly |
| JWT verification | `eldrin-app-core/src/auth/index.ts` | Web Crypto HMAC-SHA256 |
| Permission checking | `eldrin-app-core/src/auth/index.ts` | Wildcard pattern matching |
| Route middleware | `eldrin-app-core/src/middleware/` | Manifest-driven, pure functions |
| Event emission | `eldrin-app-core/src/events/client.ts` | Class-based, fetch API |
| CLI release/submit | `eldrin-app-core/src/cli/` | Node.js, no React deps |
| Single-spa loading | `eldrin-core/src/App.tsx:62-68` | Framework-agnostic registration |
| Global context | `eldrin-core/src/stores/appRegistry.ts:150-170` | Plain browser APIs |

### 1.5 React-Specific Code to Extract

| Module | File | What It Does |
|--------|------|--------------|
| `createApp()` | `eldrin-app-core/src/app/createApp.tsx` | Returns single-spa lifecycle, mounts React root |
| `DatabaseProvider` | `eldrin-app-core/src/database/context.tsx` | React Context provider |
| `useDatabase()` | `eldrin-app-core/src/database/context.tsx` | React hook for D1 access |
| `useMigrationsComplete()` | `eldrin-app-core/src/database/context.tsx` | React hook for migration status |
| Zustand stores | `eldrin-core/src/stores/` | React-based state management |

---

## 2. Target Architecture

### 2.1 Layered SDK Architecture (Based on Actual Codebase)

The current `@eldrin-project/eldrin-app-core` already has good separation. The refactoring approach is to:
1. **Keep** the framework-agnostic modules in `eldrin-app-core`
2. **Extract** React-specific code to a separate adapter
3. **Create** new adapters for Vue, Angular, Svelte

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           FRAMEWORK ADAPTERS                             │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐       │
│  │ @eldrin-project/ │  │ @eldrin-project/ │  │ @eldrin-project/ │       │
│  │ app-react        │  │ app-vue          │  │ app-svelte       │       │
│  │                  │  │                  │  │                  │       │
│  │ - createApp()    │  │ - createApp()    │  │ - createApp()    │       │
│  │ - useDatabase()  │  │ - useDatabase()  │  │ - dbStore        │       │
│  │ - DatabaseProv   │  │ - provideDb()    │  │ - getDatabase()  │       │
│  │ - useMigrations  │  │ - useMigrations  │  │ - migrations$    │       │
│  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘       │
│           │                     │                     │                  │
│           └─────────────────────┴─────────────────────┘                  │
│                                 │                                        │
├─────────────────────────────────┼────────────────────────────────────────┤
│                                 ▼                                        │
│              ┌──────────────────────────────────────┐                   │
│              │   @eldrin-project/eldrin-app-core    │                   │
│              │   (Already ~70% framework-agnostic)  │                   │
│              │                                      │                   │
│              │ KEEP AS-IS (framework-agnostic):     │                   │
│              │ - migrations/ (runner, checksum)     │                   │
│              │ - auth/ (JWT, permissions)           │                   │
│              │ - middleware/ (route protection)     │                   │
│              │ - events/ (EldrinEventClient)        │                   │
│              │ - cli/ (release, submit)             │                   │
│              │ - vite.ts (build plugin)             │                   │
│              │                                      │                   │
│              │ EXTRACT TO @eldrin-project/app-react:│                   │
│              │ - app/createApp.tsx                  │                   │
│              │ - database/context.tsx               │                   │
│              └──────────────────────────────────────┘                   │
│                              CORE LAYER                                  │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Package Structure (Proposed)

Based on actual codebase analysis, here's the recommended package structure:

```
# EXISTING PACKAGES (to be refactored)
@eldrin-project/eldrin-app-core    # Core SDK - KEEP framework-agnostic parts
@eldrin-project/eldrin-core        # Shell - NO CHANGES (stays React)
create-eldrin-project              # CLI - ADD framework templates

# NEW PACKAGES (to be created)
@eldrin-project/app-react          # React adapter (extracted from eldrin-app-core)
@eldrin-project/app-vue            # Vue 3 adapter
@eldrin-project/app-angular        # Angular 17+ adapter
@eldrin-project/app-svelte         # Svelte 4/5 adapter

# OPTIONAL FUTURE PACKAGES
@eldrin-project/tokens             # Design tokens as CSS/SCSS/JS
@eldrin-project/testing            # Framework-agnostic test utilities
```

### 2.3 What Changes vs What Stays

| Current File | Action | Destination |
|--------------|--------|-------------|
| `eldrin-app-core/src/migrations/` | **Keep** | `eldrin-app-core` |
| `eldrin-app-core/src/auth/` | **Keep** | `eldrin-app-core` |
| `eldrin-app-core/src/middleware/` | **Keep** | `eldrin-app-core` |
| `eldrin-app-core/src/events/` | **Keep** | `eldrin-app-core` |
| `eldrin-app-core/src/cli/` | **Keep** | `eldrin-app-core` |
| `eldrin-app-core/src/vite.ts` | **Keep** | `eldrin-app-core` |
| `eldrin-app-core/src/app/createApp.tsx` | **Extract** | `@eldrin-project/app-react` |
| `eldrin-app-core/src/database/context.tsx` | **Extract** | `@eldrin-project/app-react` |
| `eldrin-core/src/index.css` | **Extract** | `@eldrin-project/tokens` (optional) |

---

## 3. Implementation Phases

### Phase 1: Extract React Adapter from eldrin-app-core

**Objective:** Separate React-specific code from the already framework-agnostic core

**Note:** This is simpler than originally planned because `eldrin-app-core` is already ~70% framework-agnostic. We only need to extract 2 files.

**Deliverables:**

1. **Create `@eldrin-project/app-react` package**

   Extract from `eldrin-app-core/src/app/createApp.tsx`:
   ```typescript
   // @eldrin-project/app-react/src/createApp.tsx
   import { runMigrations, type MigrationFile } from '@eldrin-project/eldrin-app-core';
   import type { D1Database } from '@cloudflare/workers-types';

   interface CreateAppOptions {
     name: string;
     root: React.ComponentType<any>;
     migrations?: MigrationFile[];
     onMigrationsComplete?: (result: MigrationResult) => void;
     onMigrationError?: (error: Error) => void;
   }

   export function createApp(options: CreateAppOptions): AppLifecycle {
     // ... existing implementation from eldrin-app-core
   }
   ```

   Extract from `eldrin-app-core/src/database/context.tsx`:
   ```typescript
   // @eldrin-project/app-react/src/database.tsx
   import { createContext, useContext, type ReactNode } from 'react';
   import type { D1Database } from '@cloudflare/workers-types';
   import type { MigrationResult } from '@eldrin-project/eldrin-app-core';

   interface DatabaseContext {
     db: D1Database | null;
     migrationsComplete: boolean;
     migrationResult?: MigrationResult;
   }

   const EldrinDatabaseContext = createContext<DatabaseContext | null>(null);

   export function DatabaseProvider({ db, migrationsComplete, migrationResult, children }: {...}) {...}
   export function useDatabase(): D1Database | null {...}
   export function useDatabaseContext(): DatabaseContext {...}
   export function useMigrationsComplete(): boolean {...}
   ```

2. **Update `eldrin-app-core` exports**

   Remove React-specific exports, keep framework-agnostic:
   ```typescript
   // @eldrin-project/eldrin-app-core/src/index.ts (AFTER refactor)

   // Migrations (framework-agnostic) ✓
   export { runMigrations, getMigrationStatus, rollbackMigrations } from './migrations';
   export { calculateChecksum, verifyChecksum } from './migrations/checksum';
   export { generateMigrationManifest, validateMigrationManifest } from './migrations/marketplace';
   export type { MigrationFile, MigrationResult, MigrationStatus } from './migrations';

   // Auth (framework-agnostic) ✓
   export { verifyJWT, getAuthContextFromJWT, requireJWTAuth, requireJWTPermission } from './auth';
   export { getAuthContext, requireAuth, hasPermission, hasPlatformRole } from './auth';
   export type { AppAuthContext, JWTPayload, JWTVerifyOptions } from './auth';

   // Events (framework-agnostic) ✓
   export { EldrinEventClient, createEventClient } from './events';
   export type { EldrinEvent, EventDelivery, EmitOptions } from './events';

   // Middleware (framework-agnostic) ✓
   export { createPermissionMiddleware } from './middleware';
   export type { MiddlewareConfig, MiddlewareResult } from './middleware';

   // REMOVED: createApp, DatabaseProvider, useDatabase (moved to @eldrin-project/app-react)
   ```

**Tasks:**
- [ ] Create `@eldrin-project/app-react` package with tsup config
- [ ] Move `createApp.tsx` to new package
- [ ] Move `database/context.tsx` to new package
- [ ] Update `eldrin-app-core` to remove React exports from main index
- [ ] Update `react-todo` to use new import path
- [ ] Update tests
- [ ] Publish both packages

---

### Phase 2: Framework Adapters (Vue, Angular, Svelte)

**Objective:** Create idiomatic adapters for Vue, Angular, and Svelte

**Key Reference:** Use `react-todo` (`/react-todo/src/eldrin-react-todo.tsx`) as the pattern for single-spa integration.

#### 2.1 Vue Adapter (`@eldrin-project/app-vue`)

```typescript
// @eldrin-project/app-vue/src/createApp.ts
import { runMigrations, type MigrationFile, type MigrationResult } from '@eldrin-project/eldrin-app-core';
import type { D1Database } from '@cloudflare/workers-types';
import type { App, Component } from 'vue';

interface CreateAppOptions {
  name: string;
  root: Component;
  migrations?: MigrationFile[];
  onMigrationsComplete?: (result: MigrationResult) => void;
  onMigrationError?: (error: Error) => void;
}

export function createApp(options: CreateAppOptions) {
  let vueApp: App | null = null;
  let db: D1Database | null = null;
  let migrationsComplete = false;

  return {
    async bootstrap(props: SingleSpaProps) {
      db = props.db;
      if (options.migrations && db) {
        const result = await runMigrations(db, { migrations: options.migrations });
        migrationsComplete = result.success;
        options.onMigrationsComplete?.(result);
      }
    },

    async mount(props: SingleSpaProps) {
      const { createApp: createVueApp } = await import('vue');
      vueApp = createVueApp(options.root);

      // Provide database context
      vueApp.provide('eldrin-db', db);
      vueApp.provide('eldrin-migrations-complete', migrationsComplete);

      // Mount to single-spa container
      const container = props.domElement || document.getElementById(`single-spa-application:${options.name}`);
      vueApp.mount(container);
    },

    async unmount() {
      vueApp?.unmount();
      vueApp = null;
    }
  };
}
```

```typescript
// @eldrin-project/app-vue/src/composables.ts
import { inject, ref, onUnmounted, type Ref } from 'vue';
import type { D1Database } from '@cloudflare/workers-types';

export function useDatabase(): Ref<D1Database | null> {
  const db = inject<D1Database | null>('eldrin-db', null);
  return ref(db);
}

export function useMigrationsComplete(): Ref<boolean> {
  const complete = inject<boolean>('eldrin-migrations-complete', false);
  return ref(complete);
}

// Access shell's global context (same as React)
export function useEldrinGlobal() {
  const eldrin = (window as any).__ELDRIN__;
  return {
    getAuthHeaders: () => eldrin?.getAuthHeaders?.() || {},
    authenticatedFetch: (appId: string, url: string, init?: RequestInit) =>
      eldrin?.authenticatedFetch?.(appId, url, init),
  };
}
```

#### 2.2 Svelte Adapter (`@eldrin-project/app-svelte`)

```typescript
// @eldrin-project/app-svelte/src/createApp.ts
import { runMigrations, type MigrationFile } from '@eldrin-project/eldrin-app-core';
import type { Component } from 'svelte';

export function createApp(options: { name: string; root: Component; migrations?: MigrationFile[] }) {
  let component: any = null;

  return {
    async bootstrap(props: SingleSpaProps) {
      if (options.migrations && props.db) {
        await runMigrations(props.db, { migrations: options.migrations });
      }
    },

    async mount(props: SingleSpaProps) {
      const container = props.domElement || document.getElementById(`single-spa-application:${options.name}`);
      component = new options.root({
        target: container,
        props: { db: props.db }
      });
    },

    async unmount() {
      component?.$destroy();
      component = null;
    }
  };
}
```

```typescript
// @eldrin-project/app-svelte/src/stores.ts
import { writable, readable, type Writable } from 'svelte/store';
import type { D1Database } from '@cloudflare/workers-types';

export function createDatabaseStore(initialDb: D1Database | null): Writable<D1Database | null> {
  return writable(initialDb);
}

export function createAuthHeadersStore() {
  return readable({}, (set) => {
    const eldrin = (window as any).__ELDRIN__;
    set(eldrin?.getAuthHeaders?.() || {});
  });
}
```

#### 2.3 Angular Adapter (`@eldrin-project/app-angular`)

```typescript
// @eldrin-project/app-angular/src/createApp.ts
import { runMigrations, type MigrationFile } from '@eldrin-project/eldrin-app-core';
import { NgZone, ApplicationRef, Type } from '@angular/core';
import { createApplication } from '@angular/platform-browser';

interface CreateAppOptions {
  name: string;
  rootComponent: Type<unknown>;
  providers?: any[];
  migrations?: MigrationFile[];
}

export function createApp(options: CreateAppOptions) {
  let appRef: ApplicationRef | null = null;
  let db: any = null;

  return {
    async bootstrap(props: SingleSpaProps) {
      db = props.db;
      if (options.migrations && db) {
        await runMigrations(db, { migrations: options.migrations });
      }
    },

    async mount(props: SingleSpaProps) {
      const container = props.domElement || document.getElementById(`single-spa-application:${options.name}`);

      appRef = await createApplication({
        providers: [
          { provide: 'ELDRIN_DB', useValue: db },
          { provide: 'ELDRIN_GLOBAL', useValue: (window as any).__ELDRIN__ },
          ...(options.providers || []),
        ],
      });

      appRef.bootstrap(options.rootComponent, container);
    },

    async unmount() {
      appRef?.destroy();
      appRef = null;
    }
  };
}
```

```typescript
// @eldrin-project/app-angular/src/services.ts
import { Injectable, Inject, Optional } from '@angular/core';
import type { D1Database } from '@cloudflare/workers-types';

@Injectable({ providedIn: 'root' })
export class EldrinDatabaseService {
  constructor(@Inject('ELDRIN_DB') @Optional() private db: D1Database | null) {}

  getDatabase(): D1Database | null {
    return this.db;
  }
}

@Injectable({ providedIn: 'root' })
export class EldrinAuthService {
  constructor(@Inject('ELDRIN_GLOBAL') @Optional() private eldrin: any) {}

  getAuthHeaders(): Record<string, string> {
    return this.eldrin?.getAuthHeaders?.() || {};
  }

  authenticatedFetch(appId: string, url: string, init?: RequestInit): Promise<Response> {
    return this.eldrin?.authenticatedFetch?.(appId, url, init) || fetch(url, init);
  }
}
```

**Tasks:**
- [ ] Create `@eldrin-project/app-vue` package
  - [ ] `createApp()` with single-spa lifecycle
  - [ ] `useDatabase()` composable
  - [ ] `useEldrinGlobal()` composable
  - [ ] TypeScript definitions
  - [ ] Tests
- [ ] Create `@eldrin-project/app-angular` package
  - [ ] `createApp()` with single-spa lifecycle
  - [ ] `EldrinDatabaseService` injectable
  - [ ] `EldrinAuthService` injectable
  - [ ] TypeScript definitions
  - [ ] Tests
- [ ] Create `@eldrin-project/app-svelte` package
  - [ ] `createApp()` with single-spa lifecycle
  - [ ] Svelte stores for database/auth
  - [ ] TypeScript definitions
  - [ ] Tests

---

### Phase 3: Design Tokens Package (Optional)

**Objective:** Extract design tokens from shell for standalone use

**Priority:** Low (tokens already work via CSS custom properties in `eldrin-core/src/index.css`)

**Current State:** Design tokens are defined in `eldrin-core/src/index.css:87-200` as CSS custom properties. Apps can already use them directly:

```css
/* Works in any framework */
.my-component {
  background: var(--color-bg-surface);
  color: var(--color-text-primary);
  border-radius: var(--radius-md);
}
```

**Recommendation:** Defer this phase. The CSS-based approach already works for all frameworks. Only extract to a separate package if:
1. Multiple apps need to work standalone (outside shell)
2. There's demand for SCSS/JS token exports

**Tasks (if needed):**
- [ ] Extract tokens from `eldrin-core/src/index.css` to standalone package
- [ ] Generate SCSS variables
- [ ] Generate JavaScript exports
- [ ] Create Tailwind CSS preset

---

### Phase 4: CLI Multi-Framework Support

**Objective:** Add framework templates to `create-eldrin-project` CLI

**Current State Analysis:** Based on `/eldrin-templates`:

| Feature | Current Status |
|---------|---------------|
| CLI Tool | `create-eldrin-project` using `@inquirer/prompts` |
| Template Location | `/eldrin-templates/templates/{provider}-{frontend}-{database}/` |
| Existing Template | `cloudflare-react-sqlite` (47 files, full Todo app) |
| Variable Substitution | `{{variableName}}` in `.template` files |
| Framework Prompt | Currently disabled for Vue/Angular/Svelte ("coming soon") |

**Template Naming Convention:** `{provider}-{frontend}-{database}`
- Example: `cloudflare-vue-sqlite`, `cloudflare-svelte-sqlite`

**Files to Modify:**

1. **Enable framework options** (`eldrin-templates/src/prompts.ts`):
```typescript
// Current (disabled):
{ value: 'vue', name: 'Vue 3 (coming soon)', disabled: true }
{ value: 'angular', name: 'Angular (coming soon)', disabled: true }
{ value: 'svelte', name: 'Svelte (coming soon)', disabled: true }

// After:
{ value: 'vue', name: 'Vue 3' }
{ value: 'angular', name: 'Angular 17+' }
{ value: 'svelte', name: 'Svelte' }
```

2. **Add framework-specific templates:**

```
eldrin-templates/templates/
├── cloudflare-react-sqlite/     # Existing (47 files)
├── cloudflare-vue-sqlite/       # NEW
│   ├── template.json
│   ├── package.json.template
│   ├── vite.config.ts.template
│   ├── src/
│   │   ├── App.vue
│   │   ├── main.ts
│   │   ├── eldrin-{{appNameKebab}}.ts.template  # single-spa entry
│   │   └── components/
│   │       ├── TodoList.vue
│   │       └── TodoForm.vue
│   ├── worker/
│   │   └── index.ts.template    # Same worker code as React
│   ├── migrations/              # Same migrations
│   └── public/
│       └── eldrin-app.manifest.json.template
├── cloudflare-angular-sqlite/   # NEW
│   ├── template.json
│   ├── package.json.template
│   ├── angular.json.template
│   ├── src/
│   │   ├── app/
│   │   │   ├── app.component.ts
│   │   │   ├── app.component.html
│   │   │   └── components/
│   │   │       ├── todo-list.component.ts
│   │   │       └── todo-form.component.ts
│   │   ├── main.ts
│   │   └── eldrin-{{appNameKebab}}.ts.template  # single-spa entry
│   ├── worker/
│   │   └── index.ts.template    # Same worker code
│   ├── migrations/              # Same migrations
│   └── public/
│       └── eldrin-app.manifest.json.template
└── cloudflare-svelte-sqlite/    # NEW
    ├── template.json
    ├── package.json.template
    ├── vite.config.ts.template
    ├── src/
    │   ├── App.svelte
    │   ├── main.ts
    │   ├── eldrin-{{appNameKebab}}.ts.template  # single-spa entry
    │   └── components/
    │       ├── TodoList.svelte
    │       └── TodoForm.svelte
    ├── worker/
    │   └── index.ts.template    # Same worker code
    ├── migrations/              # Same migrations
    └── public/
        └── eldrin-app.manifest.json.template
```

**Template Variables Available** (from `eldrin-templates/src/template.ts`):
- `{{appName}}` - Original name
- `{{appNameKebab}}` - `my-app`
- `{{appNamePascal}}` - `MyApp`
- `{{appNameCamel}}` - `myApp`
- `{{appNameSnake}}` - `my_app`
- `{{port}}` - Dev server port
- `{{developerId}}` - Developer ID
- `{{developerName}}` - Developer name

**Vue Template Entry Point Example:**

```typescript
// eldrin-templates/templates/cloudflare-vue-sqlite/src/eldrin-{{appNameKebab}}.ts.template
import { createApp } from '@eldrin-project/app-vue';
import App from './App.vue';
import migrations from 'virtual:eldrin/migrations';

export const { bootstrap, mount, unmount } = createApp({
  name: '{{appNameKebab}}',
  root: App,
  migrations,
});
```

**Angular Template Entry Point Example:**

```typescript
// eldrin-templates/templates/cloudflare-angular-sqlite/src/eldrin-{{appNameKebab}}.ts.template
import { createApp } from '@eldrin-project/app-angular';
import { AppComponent } from './app/app.component';
import migrations from 'virtual:eldrin/migrations';

export const { bootstrap, mount, unmount } = createApp({
  name: '{{appNameKebab}}',
  rootComponent: AppComponent,
  migrations,
});
```

**Svelte Template Entry Point Example:**

```typescript
// eldrin-templates/templates/cloudflare-svelte-sqlite/src/eldrin-{{appNameKebab}}.ts.template
import { createApp } from '@eldrin-project/app-svelte';
import App from './App.svelte';
import migrations from 'virtual:eldrin/migrations';

export const { bootstrap, mount, unmount } = createApp({
  name: '{{appNameKebab}}',
  root: App,
  migrations,
});
```

**Tasks:**
- [ ] Enable Vue/Angular/Svelte options in `eldrin-templates/src/prompts.ts`
- [ ] Create `cloudflare-vue-sqlite` template
  - [ ] Port worker code from react template (identical)
  - [ ] Port migrations from react template (identical)
  - [ ] Create Vue-specific frontend files
  - [ ] Create Vue entry point using `@eldrin-project/app-vue`
  - [ ] Test with `npm link && create-eldrin-project test-vue-app`
- [ ] Create `cloudflare-angular-sqlite` template
  - [ ] Port worker code from react template (identical)
  - [ ] Port migrations from react template (identical)
  - [ ] Create Angular-specific frontend files
  - [ ] Create Angular entry point using `@eldrin-project/app-angular`
  - [ ] Test with `npm link && create-eldrin-project test-angular-app`
- [ ] Create `cloudflare-svelte-sqlite` template
  - [ ] Port worker code from react template (identical)
  - [ ] Port migrations from react template (identical)
  - [ ] Create Svelte-specific frontend files
  - [ ] Create Svelte entry point using `@eldrin-project/app-svelte`
  - [ ] Test with `npm link && create-eldrin-project test-svelte-app`
- [ ] Update template validation tests

---

### Phase 5: UI Strategy

**Objective:** Define approach for UI components across frameworks

**Duration Estimate:** Decision + 2-4 weeks implementation

#### Option A: Framework-Specific Libraries (Recommended for MVP)

```
@eldrin-project/ui          # React (existing)
@eldrin-project/ui-vue      # Vue (future, on demand)
@eldrin-project/ui-angular  # Angular (future, on demand)
```

**Pros:**
- Idiomatic APIs for each framework
- Best developer experience
- Optimal performance

**Cons:**
- Maintenance burden
- Feature parity challenges
- Higher development cost

#### Option B: Web Components

Create framework-agnostic Web Components that work everywhere.

```typescript
// @eldrin-project/ui-components (Web Components)
import { LitElement, html, css } from 'lit';

@customElement('eldrin-button')
export class EldrinButton extends LitElement {
  @property() variant: 'primary' | 'secondary' | 'ghost' = 'primary';
  @property() size: 'sm' | 'md' | 'lg' = 'md';
  @property({ type: Boolean }) loading = false;
  @property({ type: Boolean }) disabled = false;

  static styles = css`
    :host {
      display: inline-block;
    }
    button {
      font-family: var(--font-body);
      border-radius: var(--radius-md);
      /* ... */
    }
  `;

  render() {
    return html`
      <button
        class="btn btn-${this.variant} btn-${this.size}"
        ?disabled=${this.disabled || this.loading}
      >
        ${this.loading ? html`<eldrin-spinner size="sm" />` : ''}
        <slot></slot>
      </button>
    `;
  }
}
```

**Pros:**
- Single codebase
- Works in any framework
- Native browser support

**Cons:**
- Less idiomatic in each framework
- SSR challenges
- Slightly larger bundle
- React integration quirks

#### Option C: Headless Components + Design Tokens (Recommended Long-term)

Provide unstyled component logic that developers style using design tokens.

```typescript
// @eldrin-project/headless
export { useButton } from './button';
export { useModal } from './modal';
export { useDropdown } from './dropdown';
export { useTable } from './table';
// ...

// Usage in Vue
<script setup>
import { useButton } from '@eldrin-project/headless-vue';

const { buttonProps, isPressed } = useButton({
  onPress: () => console.log('clicked')
});
</script>

<template>
  <button v-bind="buttonProps" class="my-styled-button">
    Click me
  </button>
</template>
```

**Pros:**
- Maximum flexibility
- Smaller bundle
- Full theme compliance guaranteed

**Cons:**
- More work for app developers
- Less consistency (relies on guidelines)

#### Recommendation

**Short-term (MVP):**
- Keep `@eldrin-project/ui` for React
- Rely on design tokens + Tailwind preset for other frameworks
- Provide comprehensive styling guidelines

**Medium-term:**
- Create `@eldrin-project/ui-vue` if Vue adoption is high
- Consider headless approach for complex components

**Long-term:**
- Evaluate Web Components for truly universal components
- Build headless component library

**Tasks:**
- [ ] Document recommended approach for each framework
- [ ] Create comprehensive styling guide with examples
- [ ] Provide copy-paste component examples for Vue/Angular/Svelte
- [ ] Consider creating Storybook with all frameworks

---

### Phase 6: Documentation & Examples

**Objective:** Comprehensive documentation for all frameworks

**Duration Estimate:** 2-3 weeks

**Documentation Structure:**

```
docs/
├── getting-started/
│   ├── react.md
│   ├── vue.md
│   ├── angular.md
│   └── svelte.md
├── sdk/
│   ├── core.md           # @eldrin-project/core API reference
│   ├── react.md          # React-specific APIs
│   ├── vue.md            # Vue-specific APIs
│   ├── angular.md        # Angular-specific APIs
│   └── svelte.md         # Svelte-specific APIs
├── design/
│   ├── tokens.md         # Design token reference
│   ├── styling.md        # Styling guidelines
│   └── components/
│       ├── buttons.md    # With examples in all frameworks
│       ├── forms.md
│       ├── tables.md
│       └── ...
├── examples/
│   ├── react-app/        # Full example app
│   ├── vue-app/
│   ├── angular-app/
│   └── svelte-app/
└── migration/
    └── react-to-core.md  # Migration guide
```

**Example Apps:**

Create a simple "Contacts" app in each framework demonstrating:
- SDK integration
- Permission checking
- Inter-app communication
- Theme compliance
- Localization

**Tasks:**
- [ ] Write getting started guide for each framework
- [ ] Write SDK reference for each framework
- [ ] Create component examples for each framework
- [ ] Build example apps
- [ ] Create video tutorials (optional)
- [ ] Set up documentation site with framework selector

---

### Phase 7: Testing Infrastructure

**Objective:** Testing utilities for all frameworks

**Duration Estimate:** 1-2 weeks

```typescript
// @eldrin-project/testing (framework-agnostic)
export function createMockEldrinClient(options?: MockOptions): EldrinClient;
export function createMockUser(overrides?: Partial<User>): User;
export function createMockTheme(overrides?: Partial<Theme>): Theme;

// @eldrin-project/testing-react
export function renderWithEldrin(
  ui: React.ReactElement,
  options?: RenderOptions
): RenderResult;

// @eldrin-project/testing-vue
export function mountWithEldrin(
  component: Component,
  options?: MountOptions
): VueWrapper;

// @eldrin-project/testing-angular
export function configureEldrinTestingModule(
  config?: TestModuleConfig
): TestBed;

// @eldrin-project/testing-svelte
export function renderWithEldrin(
  component: SvelteComponent,
  options?: RenderOptions
): RenderResult;
```

**Tasks:**
- [ ] Create framework-agnostic mock utilities
- [ ] Create React testing utilities
- [ ] Create Vue testing utilities
- [ ] Create Angular testing utilities
- [ ] Create Svelte testing utilities
- [ ] Write testing documentation

---

## 4. Technical Details

### 4.1 single-spa Integration

Each framework adapter must export single-spa lifecycle functions:

```typescript
// React
import { createReactApp } from '@eldrin-project/sdk-react';
export default createReactApp({ App: MyApp });

// Vue
import { createVueApp } from '@eldrin-project/sdk-vue';
export default createVueApp({ App: MyApp });

// Angular
import { createAngularApp } from '@eldrin-project/sdk-angular';
export default createAngularApp({ AppModule: MyAppModule });

// Svelte
import { createSvelteApp } from '@eldrin-project/sdk-svelte';
export default createSvelteApp(MyApp);
```

### 4.2 Shell-to-App Communication

The shell passes the EldrinClient to apps via single-spa props:

```typescript
// Shell (remains React)
singleSpa.registerApplication({
  name: appId,
  app: loadApp(appId),
  activeWhen: manifest.routes,
  customProps: {
    eldrinClient: eldrinClient,  // Passed to all apps
    domElement: container,
  }
});

// App receives it
async mount(props: SingleSpaProps) {
  const { eldrinClient, domElement } = props;
  // Framework-specific mounting with client
}
```

### 4.3 Cross-Framework Component Embedding

When App A (React) needs to embed a component from App B (Vue):

```typescript
// Use single-spa parcels
import { mountParcel } from 'single-spa';

function ContactSelector({ onSelect }) {
  const containerRef = useRef(null);

  useEffect(() => {
    const parcel = mountParcel(
      () => import('@eldrin-project/crm/ContactPicker'),
      {
        domElement: containerRef.current,
        onSelect,
      }
    );

    return () => parcel.unmount();
  }, []);

  return <div ref={containerRef} />;
}
```

### 4.4 Shared State Considerations

For state that needs to be shared across frameworks:

```typescript
// @eldrin-project/core - SharedState
export class SharedState<T> {
  private value: T;
  private listeners = new Set<(value: T) => void>();

  constructor(initialValue: T) {
    this.value = initialValue;
  }

  get(): T {
    return this.value;
  }

  set(value: T): void {
    this.value = value;
    this.listeners.forEach(listener => listener(value));
  }

  subscribe(listener: (value: T) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
}

// Usage in React
function useSharedState<T>(state: SharedState<T>): T {
  return useSyncExternalStore(
    state.subscribe.bind(state),
    state.get.bind(state)
  );
}

// Usage in Vue
function useSharedState<T>(state: SharedState<T>): Ref<T> {
  const value = ref(state.get());
  onMounted(() => {
    const unsubscribe = state.subscribe((v) => { value.value = v; });
    onUnmounted(unsubscribe);
  });
  return value;
}
```

---

## 5. Migration Strategy

### 5.1 For Existing React Apps (like react-todo)

Minimal changes required. Based on actual `react-todo` codebase:

```typescript
// Before (current react-todo/src/eldrin-react-todo.tsx)
import { createApp } from '@eldrin-project/eldrin-app-core';

// After
import { createApp } from '@eldrin-project/app-react';
```

**Worker code unchanged** - The worker at `react-todo/worker/index.ts` uses only framework-agnostic imports:
```typescript
// These imports stay the same (framework-agnostic)
import { runMigrations, createPermissionMiddleware } from '@eldrin-project/eldrin-app-core';
```

### 5.2 Migration Steps for react-todo

1. Install new package: `npm install @eldrin-project/app-react`
2. Update import in `src/eldrin-react-todo.tsx`:
   ```typescript
   // From:
   import { createApp } from '@eldrin-project/eldrin-app-core';
   // To:
   import { createApp } from '@eldrin-project/app-react';
   ```
3. No other changes needed - worker code uses framework-agnostic imports

This is a clean breaking change. All existing apps must update their imports when upgrading.

---

## 6. Risks and Mitigations

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Framework adapter bugs | High | Medium | Comprehensive testing, staged rollout |
| Performance overhead | Medium | Low | Benchmark early, optimize core |
| Inconsistent UX across frameworks | High | Medium | Strong design guidelines, review process |
| Maintenance burden | High | High | Prioritize frameworks by demand |
| Breaking changes during extraction | High | Low | Clear migration guide, update all apps together |
| Developer confusion | Medium | Medium | Clear documentation, examples |

---

## 7. Decision Points

### Decision 1: UI Component Strategy

**Options:**
- A) Framework-specific libraries
- B) Web Components
- C) Headless + tokens only

**Recommendation:** Start with (C) for non-React frameworks, evaluate (A) based on adoption.

### Decision 2: State Management Library

**Options:**
- A) Custom EventBus (current plan)
- B) Adopt nanostores (has all framework adapters)
- C) Keep Zustand, create adapters

**Recommendation:** (A) Custom solution gives most control, (B) is viable alternative.

### Decision 3: Framework Priority

**Options:**
- A) All frameworks simultaneously
- B) Sequential rollout based on complexity
- C) Based on community demand

**Recommendation:** (A) All frameworks simultaneously. The adapter code is simple (~100 LOC each), and templates share 80% of code (worker, migrations, manifest). Parallel development is feasible.

### Decision 4: Shell Framework

**Options:**
- A) Keep shell as React
- B) Make shell framework-agnostic

**Recommendation:** (A) Shell remains React—simplifies development, apps don't need to know.

---

## 8. Success Criteria

### Phase 1 Complete When:
- [ ] `@eldrin-project/app-react` package published
- [ ] `react-todo` migrated to use new import path
- [ ] `@eldrin-project/eldrin-app-core` main export has no React dependencies
- [ ] All existing tests pass

### Phase 2 Complete When:
- [ ] `@eldrin-project/app-vue` package published
- [ ] `@eldrin-project/app-angular` package published
- [ ] `@eldrin-project/app-svelte` package published
- [ ] All framework apps can be created via CLI and registered with shell
- [ ] All framework apps can access D1 database via framework-idiomatic APIs
- [ ] All framework apps receive auth headers from `window.__ELDRIN__`

### Phase 3 Complete When (Optional):
- [ ] Design tokens extracted to `@eldrin-project/tokens`
- [ ] Tailwind preset available
- [ ] Documentation complete

### Phase 4 Complete When:
- [ ] `cloudflare-vue-sqlite` template added to `eldrin-templates`
- [ ] `cloudflare-angular-sqlite` template added to `eldrin-templates`
- [ ] `cloudflare-svelte-sqlite` template added to `eldrin-templates`
- [ ] Vue/Angular/Svelte options enabled in CLI prompts
- [ ] `create-eldrin-project my-app` works for all frameworks
- [ ] All generated apps build and run in shell

### Full Success Criteria:
- [ ] Vue, Angular, and Svelte apps run in the Eldrin shell alongside React apps
- [ ] Apps of different frameworks can communicate via events
- [ ] No performance regression in shell
- [ ] Developer can create a new app in any framework in under 5 minutes

---

## Appendix A: Package Dependency Graph (Based on Actual Codebase)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SHELL APPLICATION                               │
│                                                                              │
│    ┌────────────────────────────────────────────────────────────────────┐   │
│    │        @eldrin-project/eldrin-core (Shell - React 19)              │   │
│    │                                                                    │   │
│    │  src/App.tsx ─────────────────► single-spa v6                     │   │
│    │  src/stores/ ─────────────────► Zustand v5                        │   │
│    │  src/index.css ───────────────► Design Tokens (CSS vars)          │   │
│    │  window.__ELDRIN__ ───────────► Global Context (any framework)    │   │
│    └────────────────────────────────────────────────────────────────────┘   │
│                                      │                                       │
│                                      │ loads via single-spa                  │
│                                      ▼                                       │
└──────────────────────────────────────┼───────────────────────────────────────┘
                                       │
       ┌──────────────────┬──────────────────┬──────────────────┬──────────────────┐
       │                  │                  │                  │                  │
       ▼                  ▼                  ▼                  ▼                  ▼
┌────────────────┐ ┌────────────────┐ ┌────────────────┐ ┌────────────────┐
│ @eldrin-project│ │ @eldrin-project│ │ @eldrin-project│ │ @eldrin-project│
│ /app-react     │ │ /app-vue       │ │ /app-angular   │ │ /app-svelte    │
│                │ │                │ │                │ │                │
│ Deps:          │ │ Deps:          │ │ Deps:          │ │ Deps:          │
│ - react        │ │ - vue ^3       │ │ - @angular/*   │ │ - svelte       │
│ - react-dom    │ │ - single-spa-  │ │ - single-spa-  │ │ - single-spa-  │
│ - single-spa-  │ │   vue          │ │   angular      │ │   svelte       │
│   react        │ │                │ │                │ │                │
└───────┬────────┘ └───────┬────────┘ └───────┬────────┘ └───────┬────────┘
        │                  │                  │                  │
        └──────────────────┴──────────────────┴──────────────────┘
                                         │
                                         ▼
              ┌───────────────────────────────────────────────────────┐
              │        @eldrin-project/eldrin-app-core                │
              │        (Framework-Agnostic Core SDK)                  │
              │                                                       │
              │  ┌─────────────────────────────────────────────────┐  │
              │  │ migrations/  │ Auth/JWT    │ Events    │ CLI    │  │
              │  │ - runner     │ - verify    │ - client  │ - rel  │  │
              │  │ - checksum   │ - perms     │ - types   │ - sub  │  │
              │  │ - sql-parse  │ - guard     │           │        │  │
              │  ├─────────────────────────────────────────────────┤  │
              │  │ middleware/  │ vite.ts     │ types.ts           │  │
              │  │ - routes     │ (plugin)    │                    │  │
              │  │ - CORS       │             │                    │  │
              │  └─────────────────────────────────────────────────┘  │
              │                                                       │
              │  Deps: @cloudflare/workers-types (D1Database type)    │
              │  NO React/Vue/Svelte dependencies                     │
              └───────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                              CLI TOOLING                                     │
│                                                                              │
│    ┌────────────────────────────────────────────────────────────────────┐   │
│    │                    create-eldrin-project                           │   │
│    │                    (eldrin-templates)                              │   │
│    │                                                                    │   │
│    │  templates/cloudflare-react-sqlite/   ◄── existing                │   │
│    │  templates/cloudflare-vue-sqlite/    ◄── to be created            │   │
│    │  templates/cloudflare-angular-sqlite/◄── to be created            │   │
│    │  templates/cloudflare-svelte-sqlite/ ◄── to be created            │   │
│    └────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Appendix B: Key File Locations

| Component | File Path |
|-----------|-----------|
| Shell App Entry | `eldrin-core/src/App.tsx` |
| Shell single-spa registration | `eldrin-core/src/App.tsx:62-68` |
| Global Context (`window.__ELDRIN__`) | `eldrin-core/src/stores/appRegistry.ts:150-170` |
| Design Tokens | `eldrin-core/src/index.css:87-200` |
| React createApp | `eldrin-app-core/src/app/createApp.tsx` |
| React DatabaseProvider | `eldrin-app-core/src/database/context.tsx` |
| Migration Runner | `eldrin-app-core/src/migrations/runner.ts` |
| JWT Auth | `eldrin-app-core/src/auth/index.ts` |
| Event Client | `eldrin-app-core/src/events/client.ts` |
| Permission Middleware | `eldrin-app-core/src/middleware/index.ts` |
| CLI Release | `eldrin-app-core/src/cli/release.ts` |
| CLI Submit | `eldrin-app-core/src/cli/submit.ts` |
| Template Prompts | `eldrin-templates/src/prompts.ts` |
| Template Processor | `eldrin-templates/src/template.ts` |
| React Template | `eldrin-templates/templates/cloudflare-react-sqlite/` |
| Sample App Entry | `react-todo/src/eldrin-react-todo.tsx` |
| Sample App Worker | `react-todo/worker/index.ts` |
| Sample App Manifest | `react-todo/public/eldrin-app.manifest.json` |

---

## Appendix C: Effort Estimate (Revised)

| Phase | Scope | Complexity |
|-------|-------|------------|
| Phase 1: Extract React Adapter | 2 files to move, 1 new package | Low |
| Phase 2: Vue Adapter | ~100 LOC new package | Medium |
| Phase 2: Angular Adapter | ~120 LOC new package (services) | Medium |
| Phase 2: Svelte Adapter | ~80 LOC new package | Medium |
| Phase 3: Design Tokens (Optional) | Extract CSS to package | Low |
| Phase 4: Vue Template | ~30 files, most copied from React | Medium |
| Phase 4: Angular Template | ~35 files (more boilerplate) | Medium |
| Phase 4: Svelte Template | ~25 files | Medium |

**Key Insight:** The heavy lifting is already done. ~70% of `eldrin-app-core` is framework-agnostic. The main work is creating framework adapters and CLI templates.

**Template Reuse:** Worker code, migrations, and manifest files are identical across all framework templates (~80% of template content). Only the frontend files differ.

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | December 2024 | Architecture Team | Initial plan |
| 2.0.0 | January 2025 | Architecture Team | Updated with actual codebase analysis |
