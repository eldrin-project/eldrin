# Eldrin Multi-Framework Support Plan

**Version:** 1.0.0
**Date:** December 2024
**Status:** Proposal
**Author:** Architecture Team

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

### 1.1 Framework Dependencies

| Component | Current Implementation | Framework-Agnostic? |
|-----------|----------------------|---------------------|
| Shell | React + Vite | No |
| App Orchestration | single-spa | **Yes** |
| SDK (`@eldrin/sdk`) | React hooks | No |
| UI Library (`@eldrin/ui`) | React components | No |
| State Management | Zustand | No (React-focused) |
| Event Bus | Zustand pub/sub | No |
| Design Tokens | CSS custom properties | **Yes** |
| Manifest System | JSON | **Yes** |
| Backend APIs | REST/HTTP | **Yes** |

### 1.2 Key Insight

The architectural foundation (single-spa) already supports multiple frameworks. The limitation is in the **SDK and UI layers**, which are tightly coupled to React.

### 1.3 What Already Works

- Design tokens via CSS custom properties
- App manifest declarations
- Backend hook/API calls (HTTP-based)
- Navigation (URL-based)
- App registration with single-spa

---

## 2. Target Architecture

### 2.1 Layered SDK Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           FRAMEWORK ADAPTERS                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │ @eldrin/    │  │ @eldrin/    │  │ @eldrin/    │  │ @eldrin/    │    │
│  │ sdk-react   │  │ sdk-vue     │  │ sdk-angular │  │ sdk-svelte  │    │
│  │             │  │             │  │             │  │             │    │
│  │ - useEldrin │  │ - useEldrin │  │ - EldrinSvc │  │ - getEldrin │    │
│  │ - usePerm   │  │ - usePerm   │  │ - PermGuard │  │ - perm store│    │
│  │ - useTheme  │  │ - useTheme  │  │ - ThemeSvc  │  │ - theme str │    │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘    │
│         │                │                │                │            │
│         └────────────────┴────────────────┴────────────────┘            │
│                                   │                                      │
├───────────────────────────────────┼──────────────────────────────────────┤
│                                   ▼                                      │
│                        ┌─────────────────────┐                          │
│                        │   @eldrin/core      │                          │
│                        │                     │                          │
│                        │ Pure TypeScript     │                          │
│                        │ No framework deps   │                          │
│                        │                     │                          │
│                        │ - EldrinClient      │                          │
│                        │ - AuthManager       │                          │
│                        │ - NavigationManager │                          │
│                        │ - EventBus          │                          │
│                        │ - PermissionChecker │                          │
│                        │ - ThemeManager      │                          │
│                        │ - I18nManager       │                          │
│                        │ - StorageAdapter    │                          │
│                        └─────────────────────┘                          │
│                              CORE LAYER                                  │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Package Structure

```
@eldrin/core           # Framework-agnostic core (required)
@eldrin/sdk-react      # React bindings
@eldrin/sdk-vue        # Vue 3 bindings
@eldrin/sdk-angular    # Angular bindings
@eldrin/sdk-svelte     # Svelte bindings

@eldrin/ui             # React component library (optional)
@eldrin/ui-vue         # Vue component library (optional, future)
@eldrin/tokens         # Design tokens as CSS/SCSS/JS (standalone)

@eldrin/cli            # Updated CLI with multi-framework support
@eldrin/testing        # Framework-agnostic test utilities
@eldrin/testing-react  # React-specific test utilities
@eldrin/testing-vue    # Vue-specific test utilities
```

---

## 3. Implementation Phases

### Phase 1: Core Extraction (Foundation)

**Objective:** Extract framework-agnostic core from existing React SDK

**Duration Estimate:** 2-3 weeks

**Deliverables:**

1. **Create `@eldrin/core` package**
   ```typescript
   // @eldrin/core/src/index.ts
   export { EldrinClient } from './client';
   export { AuthManager } from './auth';
   export { NavigationManager } from './navigation';
   export { EventBus } from './events';
   export { PermissionChecker } from './permissions';
   export { ThemeManager } from './theme';
   export { I18nManager } from './i18n';
   export { AppRegistry } from './apps';

   // Types
   export type {
     User,
     Theme,
     Permission,
     AppManifest,
     EventHandler,
     NavigationOptions
   } from './types';
   ```

2. **Design the core client interface**
   ```typescript
   // @eldrin/core/src/client.ts
   export class EldrinClient {
     readonly auth: AuthManager;
     readonly navigation: NavigationManager;
     readonly apps: AppRegistry;
     readonly permissions: PermissionChecker;
     readonly theme: ThemeManager;
     readonly i18n: I18nManager;
     readonly storage: StorageAdapter;

     private eventBus: EventBus;

     constructor(config: EldrinConfig) {
       this.eventBus = new EventBus();
       this.auth = new AuthManager(config.auth, this.eventBus);
       this.navigation = new NavigationManager(config.navigation);
       this.apps = new AppRegistry(this.eventBus);
       this.permissions = new PermissionChecker(this.auth);
       this.theme = new ThemeManager(config.theme, this.eventBus);
       this.i18n = new I18nManager(config.i18n, this.eventBus);
       this.storage = new StorageAdapter(config.storage);
     }

     // Subscribe to any state changes (for framework adapters)
     subscribe(callback: StateChangeCallback): Unsubscribe {
       return this.eventBus.subscribe('*', callback);
     }
   }
   ```

3. **Framework-agnostic event bus**
   ```typescript
   // @eldrin/core/src/events.ts
   export class EventBus {
     private listeners = new Map<string, Set<EventHandler>>();

     emit(event: string, payload: unknown): void {
       const handlers = this.listeners.get(event);
       handlers?.forEach(handler => handler(payload));

       // Wildcard subscribers
       const wildcardHandlers = this.listeners.get('*');
       wildcardHandlers?.forEach(handler => handler({ event, payload }));
     }

     on(event: string, handler: EventHandler): Unsubscribe {
       if (!this.listeners.has(event)) {
         this.listeners.set(event, new Set());
       }
       this.listeners.get(event)!.add(handler);

       return () => this.listeners.get(event)?.delete(handler);
     }

     once(event: string, handler: EventHandler): Unsubscribe {
       const wrapper = (payload: unknown) => {
         handler(payload);
         this.listeners.get(event)?.delete(wrapper);
       };
       return this.on(event, wrapper);
     }
   }
   ```

4. **Refactor `@eldrin/sdk` to use core**
   ```typescript
   // @eldrin/sdk-react (renamed from @eldrin/sdk)
   import { EldrinClient } from '@eldrin/core';
   import { createContext, useContext, useSyncExternalStore } from 'react';

   const EldrinContext = createContext<EldrinClient | null>(null);

   export function EldrinProvider({ client, children }) {
     return (
       <EldrinContext.Provider value={client}>
         {children}
       </EldrinContext.Provider>
     );
   }

   export function useEldrin(): EldrinClient {
     const client = useContext(EldrinContext);
     if (!client) throw new Error('useEldrin must be used within EldrinProvider');
     return client;
   }

   export function usePermission(permission: string): boolean {
     const client = useEldrin();
     return useSyncExternalStore(
       (callback) => client.permissions.subscribe(callback),
       () => client.permissions.check(permission)
     );
   }
   ```

**Tasks:**
- [ ] Audit existing `@eldrin/sdk` for all functionality
- [ ] Design `@eldrin/core` interfaces
- [ ] Implement `EldrinClient` class
- [ ] Implement `EventBus` (framework-agnostic)
- [ ] Implement `AuthManager`
- [ ] Implement `NavigationManager`
- [ ] Implement `PermissionChecker`
- [ ] Implement `ThemeManager`
- [ ] Implement `I18nManager`
- [ ] Implement `AppRegistry` (inter-app communication)
- [ ] Implement `StorageAdapter`
- [ ] Refactor `@eldrin/sdk` → `@eldrin/sdk-react`
- [ ] Write unit tests for core
- [ ] Update documentation

---

### Phase 2: Framework Adapters

**Objective:** Create idiomatic SDK bindings for Vue, Angular, and Svelte

**Duration Estimate:** 3-4 weeks

#### 2.1 Vue Adapter (`@eldrin/sdk-vue`)

```typescript
// @eldrin/sdk-vue/src/index.ts
import { EldrinClient } from '@eldrin/core';
import { inject, provide, ref, computed, onUnmounted } from 'vue';

const ELDRIN_KEY = Symbol('eldrin');

// Provider
export function provideEldrin(client: EldrinClient) {
  provide(ELDRIN_KEY, client);
}

// Composables
export function useEldrin(): EldrinClient {
  const client = inject<EldrinClient>(ELDRIN_KEY);
  if (!client) throw new Error('useEldrin requires provideEldrin');
  return client;
}

export function usePermission(permission: string) {
  const client = useEldrin();
  const hasPermission = ref(client.permissions.check(permission));

  const unsubscribe = client.permissions.subscribe(() => {
    hasPermission.value = client.permissions.check(permission);
  });

  onUnmounted(unsubscribe);

  return hasPermission;
}

export function useCurrentUser() {
  const client = useEldrin();
  const user = ref(client.auth.getCurrentUser());

  const unsubscribe = client.auth.onAuthStateChange((newUser) => {
    user.value = newUser;
  });

  onUnmounted(unsubscribe);

  return user;
}

export function useTheme() {
  const client = useEldrin();
  const theme = ref(client.theme.getTheme());

  const unsubscribe = client.theme.onThemeChange((newTheme) => {
    theme.value = newTheme;
  });

  onUnmounted(unsubscribe);

  return theme;
}

// App registration helper
export function createVueApp(config: VueAppConfig) {
  return {
    async bootstrap() {
      // Vue app bootstrap
    },
    async mount(props: SingleSpaProps) {
      const { createApp } = await import('vue');
      const app = createApp(config.App);

      // Provide Eldrin client
      app.provide(ELDRIN_KEY, props.eldrinClient);

      // Mount
      app.mount(props.domElement);
      return app;
    },
    async unmount(app: VueApp) {
      app.unmount();
    }
  };
}
```

#### 2.2 Angular Adapter (`@eldrin/sdk-angular`)

```typescript
// @eldrin/sdk-angular/src/index.ts
import { Injectable, InjectionToken, inject } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';
import { EldrinClient, User, Theme } from '@eldrin/core';

export const ELDRIN_CLIENT = new InjectionToken<EldrinClient>('EldrinClient');

@Injectable({ providedIn: 'root' })
export class EldrinService {
  private client = inject(ELDRIN_CLIENT);

  // Auth
  private userSubject = new BehaviorSubject<User | null>(
    this.client.auth.getCurrentUser()
  );

  user$ = this.userSubject.asObservable();

  constructor() {
    this.client.auth.onAuthStateChange((user) => {
      this.userSubject.next(user);
    });
  }

  // Navigation
  navigate(path: string, options?: NavigationOptions): void {
    this.client.navigation.navigate(path, options);
  }

  // Apps
  callApp<T>(appId: string, hook: string, params: unknown): Promise<T> {
    return this.client.apps.call(appId, hook, params);
  }

  emitEvent(event: string, payload: unknown): void {
    this.client.apps.emit(event, payload);
  }

  onEvent(event: string): Observable<unknown> {
    return new Observable((subscriber) => {
      const unsubscribe = this.client.apps.on(event, (payload) => {
        subscriber.next(payload);
      });
      return unsubscribe;
    });
  }
}

@Injectable({ providedIn: 'root' })
export class PermissionService {
  private client = inject(ELDRIN_CLIENT);

  check(permission: string): boolean {
    return this.client.permissions.check(permission);
  }

  hasPermission$(permission: string): Observable<boolean> {
    return new Observable((subscriber) => {
      subscriber.next(this.client.permissions.check(permission));

      const unsubscribe = this.client.permissions.subscribe(() => {
        subscriber.next(this.client.permissions.check(permission));
      });

      return unsubscribe;
    });
  }
}

// Permission directive
@Directive({ selector: '[eldrinPermission]' })
export class PermissionDirective {
  private permissionService = inject(PermissionService);

  @Input() set eldrinPermission(permission: string) {
    // Show/hide based on permission
  }
}

// Route guard
@Injectable({ providedIn: 'root' })
export class PermissionGuard implements CanActivate {
  private permissionService = inject(PermissionService);

  canActivate(route: ActivatedRouteSnapshot): boolean {
    const permission = route.data['permission'];
    return this.permissionService.check(permission);
  }
}
```

#### 2.3 Svelte Adapter (`@eldrin/sdk-svelte`)

```typescript
// @eldrin/sdk-svelte/src/index.ts
import { getContext, setContext, onDestroy } from 'svelte';
import { writable, derived, readable } from 'svelte/store';
import { EldrinClient } from '@eldrin/core';

const ELDRIN_KEY = Symbol('eldrin');

// Context
export function setEldrinClient(client: EldrinClient) {
  setContext(ELDRIN_KEY, client);
}

export function getEldrinClient(): EldrinClient {
  const client = getContext<EldrinClient>(ELDRIN_KEY);
  if (!client) throw new Error('Eldrin client not found in context');
  return client;
}

// Stores
export function createUserStore() {
  const client = getEldrinClient();

  return readable(client.auth.getCurrentUser(), (set) => {
    return client.auth.onAuthStateChange(set);
  });
}

export function createPermissionStore(permission: string) {
  const client = getEldrinClient();

  return readable(client.permissions.check(permission), (set) => {
    return client.permissions.subscribe(() => {
      set(client.permissions.check(permission));
    });
  });
}

export function createThemeStore() {
  const client = getEldrinClient();

  return readable(client.theme.getTheme(), (set) => {
    return client.theme.onThemeChange(set);
  });
}

// Actions
export function useNavigation() {
  const client = getEldrinClient();

  return {
    navigate: (path: string) => client.navigation.navigate(path),
    getCurrentRoute: () => client.navigation.getCurrentRoute()
  };
}

export function useApps() {
  const client = getEldrinClient();

  return {
    call: <T>(appId: string, hook: string, params: unknown) =>
      client.apps.call<T>(appId, hook, params),
    emit: (event: string, payload: unknown) =>
      client.apps.emit(event, payload),
    on: (event: string, handler: (payload: unknown) => void) => {
      const unsubscribe = client.apps.on(event, handler);
      onDestroy(unsubscribe);
      return unsubscribe;
    }
  };
}

// App registration helper
export function createSvelteApp(App: typeof SvelteComponent) {
  let app: SvelteComponent;

  return {
    async bootstrap() {},
    async mount(props: SingleSpaProps) {
      app = new App({
        target: props.domElement,
        props: { eldrinClient: props.eldrinClient }
      });
    },
    async unmount() {
      app?.$destroy();
    }
  };
}
```

**Tasks:**
- [ ] Implement `@eldrin/sdk-vue`
  - [ ] Composables (useEldrin, usePermission, useUser, useTheme)
  - [ ] Vue 3 plugin
  - [ ] single-spa-vue integration helper
  - [ ] TypeScript definitions
- [ ] Implement `@eldrin/sdk-angular`
  - [ ] Services (EldrinService, PermissionService, ThemeService)
  - [ ] Directives (PermissionDirective)
  - [ ] Guards (PermissionGuard)
  - [ ] Module setup
  - [ ] single-spa-angular integration
- [ ] Implement `@eldrin/sdk-svelte`
  - [ ] Stores (user, permissions, theme)
  - [ ] Context helpers
  - [ ] single-spa-svelte integration
- [ ] Write tests for each adapter
- [ ] Create documentation for each framework

---

### Phase 3: Design Tokens Package

**Objective:** Make design tokens easily consumable by any framework

**Duration Estimate:** 1 week

**Deliverables:**

```
@eldrin/tokens/
├── css/
│   ├── tokens.css           # CSS custom properties
│   ├── tokens.min.css       # Minified
│   └── utilities.css        # Utility classes
├── scss/
│   ├── _variables.scss      # SCSS variables
│   ├── _mixins.scss         # Common mixins
│   └── _utilities.scss      # Utility classes
├── js/
│   ├── tokens.js            # JavaScript object
│   ├── tokens.d.ts          # TypeScript definitions
│   └── tokens.json          # Raw JSON
├── tailwind/
│   └── preset.js            # Tailwind CSS preset
└── figma/
    └── tokens.json          # Figma-compatible format
```

**Token Structure:**

```typescript
// @eldrin/tokens/js/tokens.js
export const tokens = {
  colors: {
    bg: {
      page: 'var(--color-bg-page)',
      surface: 'var(--color-bg-surface)',
      elevated: 'var(--color-bg-elevated)',
      sunken: 'var(--color-bg-sunken)',
    },
    text: {
      primary: 'var(--color-text-primary)',
      secondary: 'var(--color-text-secondary)',
      // ...
    },
    // ...
  },
  spacing: {
    0: '0',
    1: '4px',
    2: '8px',
    3: '12px',
    4: '16px',
    5: '24px',
    6: '32px',
    7: '48px',
    8: '64px',
  },
  typography: {
    fontFamily: {
      heading: 'var(--font-heading)',
      body: 'var(--font-body)',
      mono: 'var(--font-mono)',
    },
    fontSize: {
      xs: 'var(--text-xs)',
      sm: 'var(--text-sm)',
      base: 'var(--text-base)',
      lg: 'var(--text-lg)',
      xl: 'var(--text-xl)',
      '2xl': 'var(--text-2xl)',
      '3xl': 'var(--text-3xl)',
    },
  },
  // ...
};
```

**Tailwind Preset:**

```javascript
// @eldrin/tokens/tailwind/preset.js
module.exports = {
  theme: {
    colors: {
      bg: {
        page: 'var(--color-bg-page)',
        surface: 'var(--color-bg-surface)',
        elevated: 'var(--color-bg-elevated)',
        sunken: 'var(--color-bg-sunken)',
      },
      text: {
        primary: 'var(--color-text-primary)',
        secondary: 'var(--color-text-secondary)',
        tertiary: 'var(--color-text-tertiary)',
      },
      border: {
        default: 'var(--color-border-default)',
        subtle: 'var(--color-border-subtle)',
        strong: 'var(--color-border-strong)',
      },
      action: {
        primary: 'var(--color-action-primary)',
        'primary-hover': 'var(--color-action-primary-hover)',
        secondary: 'var(--color-action-secondary)',
      },
      status: {
        success: 'var(--color-status-success)',
        warning: 'var(--color-status-warning)',
        error: 'var(--color-status-error)',
        info: 'var(--color-status-info)',
      },
    },
    fontFamily: {
      heading: 'var(--font-heading)',
      body: 'var(--font-body)',
      mono: 'var(--font-mono)',
    },
    fontSize: {
      xs: 'var(--text-xs)',
      sm: 'var(--text-sm)',
      base: 'var(--text-base)',
      lg: 'var(--text-lg)',
      xl: 'var(--text-xl)',
      '2xl': 'var(--text-2xl)',
      '3xl': 'var(--text-3xl)',
    },
    spacing: {
      0: '0',
      1: 'var(--space-1)',
      2: 'var(--space-2)',
      3: 'var(--space-3)',
      4: 'var(--space-4)',
      5: 'var(--space-5)',
      6: 'var(--space-6)',
      7: 'var(--space-7)',
      8: 'var(--space-8)',
    },
    borderRadius: {
      none: '0',
      sm: 'var(--radius-sm)',
      md: 'var(--radius-md)',
      lg: 'var(--radius-lg)',
      full: 'var(--radius-full)',
    },
    boxShadow: {
      sm: 'var(--shadow-sm)',
      md: 'var(--shadow-md)',
      lg: 'var(--shadow-lg)',
      xl: 'var(--shadow-xl)',
      elevated: 'var(--shadow-elevated)',
      focus: 'var(--shadow-focus)',
    },
  },
};
```

**Tasks:**
- [ ] Create token generation pipeline
- [ ] Generate CSS custom properties file
- [ ] Generate SCSS variables and mixins
- [ ] Generate JavaScript/TypeScript exports
- [ ] Create Tailwind CSS preset
- [ ] Create utility classes
- [ ] Write usage documentation

---

### Phase 4: CLI Multi-Framework Support

**Objective:** Update CLI to scaffold apps in any supported framework

**Duration Estimate:** 2 weeks

**Updated CLI Commands:**

```bash
# Create new app with framework selection
eldrin create my-app

? Select a framework:
  ❯ React (recommended)
    Vue 3
    Angular
    Svelte

? Select additional features:
  ◉ TypeScript (recommended)
  ◉ Tailwind CSS
  ◯ CSS Modules
  ◯ Sass/SCSS

# Create with flags
eldrin create my-app --framework vue --typescript --tailwind

# Development
eldrin dev                    # Auto-detects framework
eldrin dev --with-shell       # Run with Eldrin shell

# Build
eldrin build

# Validate (framework-aware)
eldrin validate
```

**Template Structure:**

```
cli/templates/
├── react/
│   ├── base/
│   ├── typescript/
│   └── tailwind/
├── vue/
│   ├── base/
│   ├── typescript/
│   └── tailwind/
├── angular/
│   ├── base/
│   └── tailwind/
└── svelte/
    ├── base/
    ├── typescript/
    └── tailwind/
```

**Vue Template Example:**

```
vue/typescript/
├── src/
│   ├── App.vue
│   ├── main.ts
│   ├── eldrin.ts           # single-spa lifecycle
│   ├── components/
│   │   └── HelloWorld.vue
│   ├── pages/
│   │   └── Home.vue
│   ├── composables/
│   │   └── useAppData.ts
│   └── locales/
│       └── en-US.json
├── eldrin-app.manifest.json
├── package.json
├── tsconfig.json
├── vite.config.ts
└── README.md
```

**Tasks:**
- [ ] Update CLI framework selection prompt
- [ ] Create React template (update existing)
- [ ] Create Vue 3 template
- [ ] Create Angular template
- [ ] Create Svelte template
- [ ] Update `eldrin dev` for multi-framework
- [ ] Update `eldrin build` for multi-framework
- [ ] Update `eldrin validate` for multi-framework
- [ ] Write template documentation

---

### Phase 5: UI Strategy

**Objective:** Define approach for UI components across frameworks

**Duration Estimate:** Decision + 2-4 weeks implementation

#### Option A: Framework-Specific Libraries (Recommended for MVP)

```
@eldrin/ui          # React (existing)
@eldrin/ui-vue      # Vue (future, on demand)
@eldrin/ui-angular  # Angular (future, on demand)
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
// @eldrin/ui-components (Web Components)
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
// @eldrin/headless
export { useButton } from './button';
export { useModal } from './modal';
export { useDropdown } from './dropdown';
export { useTable } from './table';
// ...

// Usage in Vue
<script setup>
import { useButton } from '@eldrin/headless-vue';

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
- Keep `@eldrin/ui` for React
- Rely on design tokens + Tailwind preset for other frameworks
- Provide comprehensive styling guidelines

**Medium-term:**
- Create `@eldrin/ui-vue` if Vue adoption is high
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
│   ├── core.md           # @eldrin/core API reference
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
// @eldrin/testing (framework-agnostic)
export function createMockEldrinClient(options?: MockOptions): EldrinClient;
export function createMockUser(overrides?: Partial<User>): User;
export function createMockTheme(overrides?: Partial<Theme>): Theme;

// @eldrin/testing-react
export function renderWithEldrin(
  ui: React.ReactElement,
  options?: RenderOptions
): RenderResult;

// @eldrin/testing-vue
export function mountWithEldrin(
  component: Component,
  options?: MountOptions
): VueWrapper;

// @eldrin/testing-angular
export function configureEldrinTestingModule(
  config?: TestModuleConfig
): TestBed;

// @eldrin/testing-svelte
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
import { createReactApp } from '@eldrin/sdk-react';
export default createReactApp({ App: MyApp });

// Vue
import { createVueApp } from '@eldrin/sdk-vue';
export default createVueApp({ App: MyApp });

// Angular
import { createAngularApp } from '@eldrin/sdk-angular';
export default createAngularApp({ AppModule: MyAppModule });

// Svelte
import { createSvelteApp } from '@eldrin/sdk-svelte';
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
      () => import('@eldrin/crm/ContactPicker'),
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
// @eldrin/core - SharedState
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

### 5.1 For Existing React Apps

Minimal changes required:

```typescript
// Before
import { useEldrin, usePermission } from '@eldrin/sdk';

// After
import { useEldrin, usePermission } from '@eldrin/sdk-react';
```

Package rename with backwards compatibility:

```json
// @eldrin/sdk/package.json
{
  "name": "@eldrin/sdk",
  "main": "./dist/react/index.js",
  "exports": {
    ".": "./dist/react/index.js"
  },
  "dependencies": {
    "@eldrin/sdk-react": "^1.0.0"
  }
}
```

### 5.2 Migration Steps

1. Update imports from `@eldrin/sdk` to `@eldrin/sdk-react`
2. No API changes for React apps
3. Gradually adopt new patterns if desired

---

## 6. Risks and Mitigations

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Framework adapter bugs | High | Medium | Comprehensive testing, staged rollout |
| Performance overhead | Medium | Low | Benchmark early, optimize core |
| Inconsistent UX across frameworks | High | Medium | Strong design guidelines, review process |
| Maintenance burden | High | High | Prioritize frameworks by demand |
| Breaking changes during extraction | High | Medium | Semantic versioning, deprecation warnings |
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
- B) Vue first, then Angular, then Svelte
- C) Based on community demand

**Recommendation:** (B) Vue has highest synergy with React ecosystem, largest community.

### Decision 4: Shell Framework

**Options:**
- A) Keep shell as React
- B) Make shell framework-agnostic

**Recommendation:** (A) Shell remains React—simplifies development, apps don't need to know.

---

## 8. Success Criteria

### Phase 1 Complete When:
- [ ] `@eldrin/core` published with full API coverage
- [ ] `@eldrin/sdk-react` works identically to current `@eldrin/sdk`
- [ ] All existing tests pass
- [ ] Zero breaking changes for React apps

### Phase 2 Complete When:
- [ ] Vue app can be created and registered
- [ ] Angular app can be created and registered
- [ ] Svelte app can be created and registered
- [ ] All adapters have feature parity
- [ ] Cross-framework communication works

### Phase 3 Complete When:
- [ ] Design tokens available in all formats
- [ ] Tailwind preset works correctly
- [ ] Documentation complete

### Phase 4 Complete When:
- [ ] CLI creates apps in all frameworks
- [ ] All templates are validated
- [ ] Developer experience is smooth

### Full Success Criteria:
- [ ] A non-React app passes marketplace review
- [ ] Developer satisfaction score > 4/5
- [ ] No significant performance regression
- [ ] Documentation NPS > 50

---

## Appendix A: Package Dependency Graph

```
                    ┌─────────────────┐
                    │  @eldrin/core   │
                    │                 │
                    │ No dependencies │
                    │ (except types)  │
                    └────────┬────────┘
                             │
           ┌─────────────────┼─────────────────┐
           │                 │                 │
           ▼                 ▼                 ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ @eldrin/sdk-    │ │ @eldrin/sdk-    │ │ @eldrin/sdk-    │
│ react           │ │ vue             │ │ angular         │
│                 │ │                 │ │                 │
│ Deps: react     │ │ Deps: vue       │ │ Deps: @angular/*│
│ single-spa-react│ │ single-spa-vue  │ │ single-spa-ng   │
└─────────────────┘ └─────────────────┘ └─────────────────┘
         │
         ▼
┌─────────────────┐
│ @eldrin/ui      │
│                 │
│ Deps: react     │
│ @eldrin/tokens  │
└─────────────────┘
```

---

## Appendix B: Timeline Estimate

| Phase | Duration | Dependencies |
|-------|----------|--------------|
| Phase 1: Core Extraction | 2-3 weeks | None |
| Phase 2: Framework Adapters | 3-4 weeks | Phase 1 |
| Phase 3: Design Tokens | 1 week | None (parallel) |
| Phase 4: CLI Updates | 2 weeks | Phase 2 |
| Phase 5: UI Strategy | 2-4 weeks | Phase 2, 3 |
| Phase 6: Documentation | 2-3 weeks | All phases |
| Phase 7: Testing | 1-2 weeks | Phase 2 |

**Total Estimate:** 10-15 weeks for full multi-framework support

**MVP (React + Vue only):** 6-8 weeks

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | December 2024 | Architecture Team | Initial plan |
