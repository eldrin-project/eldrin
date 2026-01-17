# Eldrin Framework Adapter Alignment Plan

## Overview

Update `eldrin-app-react`, `eldrin-app-vue`, and `eldrin-app-svelte` to align with the patterns established in `eldrin-app-angular` and the latest `eldrin-app-core@0.0.5`.

**Key Decision:** Switch React to use `single-spa-react` wrapper for consistency with Vue/Svelte adapters.

## Current State

| Adapter | Version | Core Dep | Wrapper | Key Gap |
|---------|---------|----------|---------|---------|
| Angular | 0.0.3 | 0.0.5 | single-spa-angular | Reference (complete) |
| React | 0.0.1 | 0.0.3 | **None (custom)** | Switch to single-spa-react, add combineLifecycles |
| Vue | 0.0.1 | 0.0.3 | single-spa-vue | Add combineLifecycles, update README |
| Svelte | 0.0.1 | 0.0.3 | single-spa-svelte | Add combineLifecycles, update README |

---

## Part 1: Generic Changes (All Adapters)

### 1.1 Package Updates

**package.json changes:**
- [ ] Bump version: `0.0.1` → `0.0.2`
- [ ] Update core dependency: `@eldrin-project/eldrin-app-core` → `^0.0.5`
- [ ] Update peer dependencies to latest supported versions

### 1.2 Lifecycle Pattern Alignment

**Add `combineLifecycles()` helper:**
```typescript
export function combineLifecycles<T extends LifecycleProps>(
  eldrinLifecycle: AppLifecycle<T>,
  frameworkLifecycle: AppLifecycle<T>
): AppLifecycle<T>;
```

Purpose: Allows users to separate Eldrin concerns (migrations) from framework mounting:
- Bootstrap: Eldrin first → Framework second
- Mount: Framework only
- Unmount: Framework only

### 1.3 Type Exports Alignment

Ensure all adapters export:
- `EldrinGlobal` - Shell context type
- `DatabaseContext` - DB + migration status
- `LifecycleProps` - single-spa props shape
- `CreateAppOptions` - createApp configuration
- `AppLifecycle` - Lifecycle hooks type
- `MigrationFile`, `MigrationResult` (re-export from core)

### 1.4 Auth/Shell Context

Ensure all adapters provide shell context access:
- `EldrinGlobal` type definition
- Helper function `getEldrinGlobal()` for accessing `window.__ELDRIN__`
- Auth headers retrieval mechanism (framework-specific pattern)

### 1.5 README Documentation

Each README should include:
1. Architecture diagram showing adapter layer
2. Installation & peer dependencies
3. Quick start (3-step guide)
4. API reference with examples
5. Migration system explanation
6. Shell integration patterns
7. Framework-specific state access patterns

---

## Part 2: React-Specific Changes

**Files to modify:**
- `/Users/tibor/projects/eldrin/eldrin-app-react/package.json`
- `/Users/tibor/projects/eldrin/eldrin-app-react/src/index.ts`
- `/Users/tibor/projects/eldrin/eldrin-app-react/src/createApp.tsx` → rename to `createApp.ts`
- `/Users/tibor/projects/eldrin/eldrin-app-react/src/types.ts`
- `/Users/tibor/projects/eldrin/eldrin-app-react/src/context.tsx`
- `/Users/tibor/projects/eldrin/eldrin-app-react/README.md`

### React-Specific Details

**Current state:**
- Handles root component mounting itself (creates React root dynamically)
- Uses React Context with DatabaseProvider
- Provides hooks: `useDatabase()`, `useDatabaseContext()`, `useMigrationsComplete()`

**Major change:** Switch to `single-spa-react` wrapper for consistency.

### 2.1 Package.json Changes

```json
{
  "version": "0.0.2",
  "dependencies": {
    "@eldrin-project/eldrin-app-core": "^0.0.5",
    "single-spa-react": "^6.0.0"
  },
  "peerDependencies": {
    "react": "^18.0.0 || ^19.0.0",
    "react-dom": "^18.0.0 || ^19.0.0"
  }
}
```

### 2.2 Rewrite createApp.ts (significant rewrite)

**Remove:**
- Dynamic ReactDOM import and root management
- Custom mount/unmount handling
- `RootComponent` from options (users will pass to single-spa-react)

**New pattern (like Angular):**
```typescript
// createApp.ts - handles migrations only, no mounting
export function createApp(options: CreateAppOptions): AppLifecycle<LifecycleProps> {
  // Bootstrap: run migrations, update context
  // Mount: default no-op (delegated to single-spa-react)
  // Unmount: default no-op (delegated to single-spa-react)
}

// combineLifecycles merges Eldrin + single-spa-react lifecycles
export function combineLifecycles<T extends LifecycleProps>(
  eldrinLifecycle: AppLifecycle<T>,
  reactLifecycle: AppLifecycle<T>
): AppLifecycle<T>
```

### 2.3 Update context.tsx

**Add hooks:**
```typescript
export function useAuthHeaders(): Record<string, string>
export function useEldrinGlobal(): EldrinGlobal | null
```

### 2.4 Update types.ts

**Remove:**
- `root: ComponentType` from CreateAppOptions (no longer needed)

**Add:**
- `EldrinGlobal` type definition
- Ensure `DatabaseContext` matches Angular pattern

### 2.5 Usage Pattern (for README)

```tsx
// main.single-spa.ts
import singleSpaReact from 'single-spa-react';
import { createApp, combineLifecycles, DatabaseProvider } from '@eldrin-project/eldrin-app-react';
import App from './App';
import migrations from './migrations';

const eldrinLifecycle = createApp({
  name: 'my-react-app',
  migrations,
});

const reactLifecycle = singleSpaReact({
  React,
  ReactDOMClient,
  rootComponent: () => (
    <DatabaseProvider>
      <App />
    </DatabaseProvider>
  ),
  domElementGetter: () => document.getElementById('app-my-react-app')!,
});

const lifecycles = combineLifecycles(eldrinLifecycle, reactLifecycle);

export const { bootstrap, mount, unmount } = lifecycles;
```

---

## Part 3: Vue-Specific Changes

**Files to modify:**
- `/Users/tibor/projects/eldrin/eldrin-app-vue/package.json`
- `/Users/tibor/projects/eldrin/eldrin-app-vue/src/index.ts`
- `/Users/tibor/projects/eldrin/eldrin-app-vue/src/createApp.ts`
- `/Users/tibor/projects/eldrin/eldrin-app-vue/src/types.ts`
- `/Users/tibor/projects/eldrin/eldrin-app-vue/src/composables.ts`
- `/Users/tibor/projects/eldrin/eldrin-app-vue/README.md`

### Vue-Specific Details

**Current state:**
- Uses `single-spa-vue` wrapper (delegates mount/unmount)
- Uses Vue's provide/inject pattern
- Has composables: `useDatabase()`, `useDatabaseContext()`, `useMigrationsComplete()`, `useEldrinGlobal()`, `useAuthHeaders()`

**Changes needed:**

### 3.1 Package.json Changes

```json
{
  "version": "0.0.2",
  "dependencies": {
    "@eldrin-project/eldrin-app-core": "^0.0.5",
    "single-spa-vue": "^3.0.0"
  },
  "peerDependencies": {
    "vue": "^3.4.0 || ^3.5.0"
  }
}
```

### 3.2 Add combineLifecycles() to createApp.ts

```typescript
export function combineLifecycles<T extends LifecycleProps>(
  eldrinLifecycle: AppLifecycle<T>,
  vueLifecycle: AppLifecycle<T>
): AppLifecycle<T>
```

### 3.3 Verify exports in index.ts

Ensure all exports match Angular pattern:
- `createApp`, `combineLifecycles`
- `useDatabase`, `useDatabaseContext`, `useMigrationsComplete`
- `useEldrinGlobal`, `useAuthHeaders`
- Types: `EldrinGlobal`, `DatabaseContext`, `LifecycleProps`, etc.

### 3.4 Comprehensive README

Follow Angular README structure

---

## Part 4: Svelte-Specific Changes

**Files to modify:**
- `/Users/tibor/projects/eldrin/eldrin-app-svelte/package.json`
- `/Users/tibor/projects/eldrin/eldrin-app-svelte/src/index.ts`
- `/Users/tibor/projects/eldrin/eldrin-app-svelte/src/createApp.ts`
- `/Users/tibor/projects/eldrin/eldrin-app-svelte/src/types.ts`
- `/Users/tibor/projects/eldrin/eldrin-app-svelte/src/stores.ts`
- `/Users/tibor/projects/eldrin/eldrin-app-svelte/README.md`

### Svelte-Specific Details

**Current state:**
- Uses `single-spa-svelte` wrapper (delegates mount/unmount)
- Uses Svelte stores: `database`, `migrationsComplete`, `migrationResult`, `authHeaders`
- Has `databaseContextStore` (internal)

**Changes needed:**

### 4.1 Package.json Changes

```json
{
  "version": "0.0.2",
  "dependencies": {
    "@eldrin-project/eldrin-app-core": "^0.0.5",
    "single-spa-svelte": "^2.1.0"
  },
  "peerDependencies": {
    "svelte": "^4.0.0 || ^5.0.0"
  }
}
```

### 4.2 Add combineLifecycles() to createApp.ts

```typescript
export function combineLifecycles<T extends LifecycleProps>(
  eldrinLifecycle: AppLifecycle<T>,
  svelteLifecycle: AppLifecycle<T>
): AppLifecycle<T>
```

### 4.3 Verify exports in index.ts

Ensure all exports match Angular pattern:
- `createApp`, `combineLifecycles`
- Stores: `database`, `migrationsComplete`, `migrationResult`, `authHeaders`
- `getEldrinGlobal` function
- Types: `EldrinGlobal`, `DatabaseContext`, `LifecycleProps`, etc.

### 4.4 Comprehensive README

Follow Angular README structure

---

## Implementation Order

1. **eldrin-app-react** (first - most divergent from pattern)
2. **eldrin-app-vue** (second - uses single-spa-vue wrapper)
3. **eldrin-app-svelte** (third - similar to Vue pattern)

---

## Testing Checklist

For each adapter after updates:
- [ ] Build succeeds (`npm run build`)
- [ ] Types are correct (`npm run typecheck`)
- [ ] Exports are correctly mapped
- [ ] Publish to npm
- [ ] Test with corresponding template (if exists)

---

## File Structure Reference (Angular - Target Pattern)

```
src/
├── index.ts        # Public exports barrel
├── types.ts        # Type definitions (EldrinGlobal, DatabaseContext, etc.)
├── createApp.ts    # createApp() + combineLifecycles()
├── tokens.ts       # Framework-specific (Angular injection tokens)
└── providers.ts    # Framework-specific (Angular providers)
```

Equivalent patterns for other frameworks:
- **React**: `context.tsx` instead of tokens/providers
- **Vue**: `composables.ts` instead of tokens/providers
- **Svelte**: `stores.ts` instead of tokens/providers
