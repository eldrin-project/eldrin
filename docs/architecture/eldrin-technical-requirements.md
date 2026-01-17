# Eldrin Platform - Technical Requirements Specification

**Version:** 1.0.0  
**Date:** December 2024  
**Status:** Draft for Review  
**Timeline:** 4-6 Months to MVP

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Overview](#2-architecture-overview)
3. [Core Platform (Eldrin Shell)](#3-core-platform-eldrin-shell)
4. [App System Architecture](#4-app-system-architecture)
5. [App Manifest Specification](#5-app-manifest-specification)
6. [Security Model](#6-security-model)
7. [Data Architecture](#7-data-architecture)
8. [API & Communication](#8-api--communication)
9. [UI Integration Points](#9-ui-integration-points)
10. [Marketplace](#10-marketplace)
11. [Developer Experience](#11-developer-experience)
12. [First-Party Apps](#12-first-party-apps)
13. [Deployment Model](#13-deployment-model)
14. [Roadmap & Milestones](#14-roadmap--milestones)
15. [Technical Decisions Summary](#15-technical-decisions-summary)
16. [Glossary](#16-glossary)

---

## 1. Executive Summary

### 1.1 Vision

Eldrin is a modular business platform that serves as a lightweight shell application, enabling businesses to compose their software stack from independent, interoperable apps. The platform follows a single-tenant deployment model where each customer deploys their own Cloudflare Worker instance.

### 1.2 Key Principles

| Principle | Description |
|-----------|-------------|
| **Modularity** | Core provides minimal functionality; apps provide capabilities |
| **Reusability** | Apps can be used independently in other projects via npm |
| **Openness** | Open marketplace where any developer can publish apps |
| **Isolation** | Each app manages its own data; explicit sharing contracts |
| **Customer Ownership** | Customers deploy and control their own infrastructure |

### 1.3 Terminology

| Term | Definition |
|------|------------|
| **Eldrin** | The core platform/shell application |
| **App** | A modular addon that extends Eldrin's functionality |
| **Marketplace** | The central registry for discovering and installing apps |
| **Shell** | The core Eldrin application that orchestrates apps |

### 1.4 MVP Scope

The MVP will include:
- Core Eldrin shell with authentication, user management, and app orchestration
- Four first-party apps: Catalog, Invoicing, CRM, B2B E-commerce
- Full developer portal with documentation, playground, and publishing tools
- Marketplace with tiered review process and community ratings

---

## 2. Architecture Overview

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      CUSTOMER'S CLOUDFLARE WORKER                           │
│                                                                             │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                      ELDRIN SHELL (React + Vite)                       │ │
│  │                                                                        │ │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐  │ │
│  │  │    Auth &    │ │  Navigation  │ │     App      │ │   Settings   │  │ │
│  │  │    Users     │ │   Manager    │ │ Orchestrator │ │   Manager    │  │ │
│  │  │  (built-in)  │ │  (dynamic)   │ │ (single-spa) │ │  (theming)   │  │ │
│  │  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘  │ │
│  │                                                                        │ │
│  │  ┌──────────────────────────────────────────────────────────────────┐  │ │
│  │  │                    SHARED INFRASTRUCTURE                         │  │ │
│  │  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────┐ │  │ │
│  │  │  │  Zustand   │ │   Event    │ │ Permission │ │    i18n        │ │  │ │
│  │  │  │   Store    │ │    Bus     │ │   System   │ │   (per-app)    │ │  │ │
│  │  │  └────────────┘ └────────────┘ └────────────┘ └────────────────┘ │  │ │
│  │  └──────────────────────────────────────────────────────────────────┘  │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                      │                                      │
│              ┌───────────────────────┼───────────────────────┐              │
│              ▼                       ▼                       ▼              │
│  ┌───────────────────┐  ┌───────────────────┐  ┌───────────────────┐       │
│  │    Catalog App    │  │   Invoicing App   │  │      CRM App      │       │
│  │  (npm + dynamic)  │  │    (dynamic)      │  │    (dynamic)      │       │
│  │                   │  │                   │  │                   │       │
│  │  [React SPA]      │  │  [React SPA]      │  │  [React SPA]      │       │
│  └─────────┬─────────┘  └─────────┬─────────┘  └─────────┬─────────┘       │
│            │                      │                      │                  │
└────────────│──────────────────────│──────────────────────│──────────────────┘
             │                      │                      │
             ▼                      ▼                      ▼
    ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
    │  Catalog Worker │   │ Invoicing Worker│   │   CRM Worker    │
    │  (Cloudflare)   │   │  (Cloudflare)   │   │  (Cloudflare)   │
    │                 │   │                 │   │                 │
    │  ┌───────────┐  │   │  ┌───────────┐  │   │  ┌───────────┐  │
    │  │    D1     │  │   │  │    D1     │  │   │  │    D1     │  │
    │  │ Database  │  │   │  │ Database  │  │   │  │ Database  │  │
    │  └───────────┘  │   │  └───────────┘  │   │  └───────────┘  │
    │  ┌───────────┐  │   │  ┌───────────┐  │   │  ┌───────────┐  │
    │  │    R2     │  │   │  │    R2     │  │   │  │    R2     │  │
    │  │  Storage  │  │   │  │  Storage  │  │   │  │  Storage  │  │
    │  └───────────┘  │   │  └───────────┘  │   │  └───────────┘  │
    └─────────────────┘   └─────────────────┘   └─────────────────┘
```

### 2.2 Technology Stack

| Layer | Technology | Rationale |
|-------|------------|-----------|
| **Shell Frontend** | React + Vite | Modern tooling, excellent DX, wide ecosystem |
| **App Orchestration** | single-spa | Mature micro-frontend framework, good isolation |
| **Security Layer** | Module Federation + Runtime Validation | Code signature verification for marketplace apps |
| **State Management** | Zustand | Lightweight, React-native, supports shared atoms |
| **Hosting** | Cloudflare Workers | Edge deployment, single-tenant friendly |
| **Database** | Cloudflare D1 | SQLite at edge, Cloudflare-native, cost-effective |
| **File Storage** | Cloudflare R2 | S3-compatible, integrated with Workers |
| **Authentication** | Custom JWT | Full control over service-to-service auth |

### 2.3 Deployment Model

Each customer deploys their own Cloudflare Worker containing:
- The Eldrin shell
- Enabled apps (bundled at build time via npm OR loaded dynamically)
- Configuration for their enabled marketplace apps

```
Customer A Worker          Customer B Worker          Customer C Worker
┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
│ Eldrin Shell     │      │ Eldrin Shell     │      │ Eldrin Shell     │
│ + Catalog (npm)  │      │ + Catalog (npm)  │      │ + CRM (npm)      │
│ + Invoicing (cdn)│      │ + CRM (cdn)      │      │ + Custom App     │
│ + CRM (cdn)      │      │ + B2B (cdn)      │      │                  │
└──────────────────┘      └──────────────────┘      └──────────────────┘
```

---

## 3. Core Platform (Eldrin Shell)

### 3.1 Core Responsibilities

The Eldrin shell provides minimal built-in functionality:

| Feature | Description |
|---------|-------------|
| **Authentication** | User login, registration, session management |
| **User Management** | User CRUD, profile management |
| **App Orchestration** | Loading, mounting, unmounting apps via single-spa |
| **Navigation Management** | Dynamic side nav, top nav, user menu based on app manifests |
| **Permission System** | RBAC with app-defined roles |
| **Theming Engine** | White-label support, CSS custom properties |
| **Settings Framework** | Global and per-app settings UI |
| **Event Bus** | Zustand-based pub/sub for app communication |
| **Dependency Resolution** | Semver-compatible app dependency management |

### 3.2 Shell API Surface

```typescript
// Core SDK provided to all apps
interface EldrinSDK {
  // Authentication
  auth: {
    getCurrentUser(): User | null;
    getAccessToken(): Promise<string>;
    onAuthStateChange(callback: (user: User | null) => void): Unsubscribe;
  };

  // Navigation
  navigation: {
    navigate(path: string): void;
    registerRoute(route: RouteConfig): void;
    getCurrentRoute(): RouteInfo;
  };

  // App Communication
  apps: {
    call<T>(appId: string, hook: string, params: unknown): Promise<T>;
    emit(event: string, payload: unknown): void;
    on(event: string, handler: EventHandler): Unsubscribe;
    isInstalled(appId: string): boolean;
    getInstalledApps(): AppInfo[];
  };

  // Permissions
  permissions: {
    check(permission: string): boolean;
    request(permissions: string[]): Promise<boolean>;
    getCurrentUserPermissions(): string[];
  };

  // Theming
  theme: {
    getTheme(): Theme;
    onThemeChange(callback: (theme: Theme) => void): Unsubscribe;
  };

  // Storage (convenience wrapper)
  storage: {
    get<T>(key: string): Promise<T | null>;
    set<T>(key: string, value: T): Promise<void>;
    delete(key: string): Promise<void>;
  };

  // Internationalization
  i18n: {
    getLocale(): string; // e.g., "en-US", "de-DE"
    onLocaleChange(callback: (locale: string) => void): Unsubscribe;
  };
}
```

### 3.3 Authentication Flow

```
┌──────────┐         ┌──────────────┐         ┌──────────────┐
│  User    │         │ Eldrin Shell │         │  App Worker  │
└────┬─────┘         └──────┬───────┘         └──────┬───────┘
     │                      │                        │
     │  1. Login request    │                        │
     │─────────────────────▶│                        │
     │                      │                        │
     │  2. JWT (user token) │                        │
     │◀─────────────────────│                        │
     │                      │                        │
     │  3. Access app       │                        │
     │─────────────────────▶│                        │
     │                      │  4. Request service    │
     │                      │     token for app      │
     │                      │───────────────────────▶│
     │                      │                        │
     │                      │  5. Service token      │
     │                      │     (scoped to app)    │
     │                      │◀───────────────────────│
     │                      │                        │
     │                      │  6. API request with   │
     │                      │     service token      │
     │                      │───────────────────────▶│
     │                      │                        │
     │  7. Response         │                        │
     │◀─────────────────────│◀───────────────────────│
```

### 3.4 Theming & White-Label

Customers can fully customize their Eldrin instance:

```typescript
interface ThemeConfig {
  branding: {
    name: string;           // "Acme Corp"
    logo: string;           // URL to logo
    favicon: string;        // URL to favicon
    removePoweredBy: boolean;
  };
  
  colors: {
    primary: string;        // Main brand color
    secondary: string;
    accent: string;
    background: string;
    surface: string;
    text: string;
    textMuted: string;
    error: string;
    warning: string;
    success: string;
    info: string;
  };
  
  typography: {
    fontFamily: string;
    headingFontFamily: string;
    baseFontSize: string;
  };
  
  spacing: {
    unit: number;           // Base spacing unit in px
  };
  
  borderRadius: {
    small: string;
    medium: string;
    large: string;
  };
}
```

Apps MUST respect the customer's theme by using CSS custom properties:

```css
/* Apps use these variables */
.my-button {
  background-color: var(--eldrin-color-primary);
  color: var(--eldrin-color-text);
  border-radius: var(--eldrin-radius-medium);
  font-family: var(--eldrin-font-family);
}
```

---

## 4. App System Architecture

### 4.1 App Loading Strategies

Apps can be loaded via two mechanisms:

#### Strategy 1: NPM Package (Build-time)

For core/essential apps or when building custom distributions:

```bash
npm install @eldrin/app-catalog @eldrin/app-invoicing
```

```typescript
// eldrin.config.ts
export default {
  apps: {
    npm: [
      '@eldrin/app-catalog',
      '@eldrin/app-invoicing'
    ]
  }
};
```

#### Strategy 2: Dynamic Loading (Runtime)

For marketplace apps, loaded from CDN based on user's enabled apps:

```typescript
// Runtime app loading
const appManifest = await fetch(`https://marketplace.eldrin.io/apps/${appId}/eldrin-app.manifest.json`);
const appBundle = await loadRemoteModule(appManifest.entrypoint);
singleSpa.registerApplication({
  name: appId,
  app: appBundle,
  activeWhen: appManifest.routes
});
```

### 4.2 App Isolation

Each app runs in its own single-spa parcel with:

| Isolation Layer | Implementation |
|-----------------|----------------|
| **JavaScript Scope** | Separate module scope per app |
| **CSS Isolation** | CSS Modules + scoped custom properties |
| **State Isolation** | Dedicated Zustand slice per app |
| **Error Boundary** | React error boundary + circuit breaker |

### 4.3 Circuit Breaker Pattern

If an app fails repeatedly, it's automatically disabled:

```typescript
interface CircuitBreakerConfig {
  failureThreshold: 5;      // Failures before tripping
  resetTimeout: 60000;      // ms before attempting reset
  monitorWindow: 300000;    // ms window for counting failures
}

// States: CLOSED (normal) → OPEN (disabled) → HALF_OPEN (testing)
```

When circuit opens:
1. App UI is replaced with error boundary
2. User is notified
3. Admin can manually re-enable or wait for auto-reset

### 4.4 Dependency Resolution

When enabling an app with dependencies:

```typescript
// User enables "Accounting" app
// Accounting depends on "Invoicing" and "Expenses"

async function enableApp(appId: string) {
  const manifest = await getManifest(appId);
  
  // Resolve dependency tree
  const deps = resolveDependencies(manifest.dependencies);
  
  // Check for conflicts
  const conflicts = checkVersionConflicts(deps);
  if (conflicts.length > 0) {
    throw new DependencyConflictError(conflicts);
  }
  
  // Auto-enable dependencies (npm-style)
  for (const dep of deps) {
    if (!isEnabled(dep.id)) {
      await enableApp(dep.id); // Recursive
    }
  }
  
  // Finally enable requested app
  await doEnableApp(appId);
}
```

### 4.5 Lifecycle Hooks

Apps can implement any of these optional lifecycle hooks:

```typescript
interface AppLifecycle {
  // Installation
  onInstall?(): Promise<void>;      // First time enabled - run migrations, seed data
  onUninstall?(): Promise<void>;    // Being removed - cleanup data
  
  // Enable/Disable
  onEnable?(): Promise<void>;       // Turned on (after install)
  onDisable?(): Promise<void>;      // Turned off (not removed)
  
  // Upgrades
  onUpgrade?(fromVersion: string): Promise<void>;  // Version change - run migrations
  
  // User events
  onUserLogin?(user: User): Promise<void>;         // User authenticated
  onUserLogout?(): Promise<void>;                  // User logged out
  
  // Settings
  onSettingsChange?(settings: AppSettings): Promise<void>;  // App settings changed
}
```

---

## 5. App Manifest Specification

### 5.1 Complete Manifest Schema

```yaml
# eldrin-app.manifest.json

# ─────────────────────────────────────────────────────────────
# CORE METADATA
# ─────────────────────────────────────────────────────────────
id: "invoicing"                    # Unique identifier (lowercase, alphanumeric, hyphens)
name: "Invoicing Pro"              # Display name
description: "Professional invoicing with templates, recurring invoices, and payment tracking"
version: "2.1.0"                   # Semver
author:
  name: "Eldrin Team"
  email: "apps@eldrin.io"
  url: "https://eldrin.io"
license: "MIT"
repository: "https://github.com/eldrin/app-invoicing"
keywords:
  - invoicing
  - billing
  - payments

# ─────────────────────────────────────────────────────────────
# COMPATIBILITY
# ─────────────────────────────────────────────────────────────
compatibility:
  core: ">=1.0.0 <2.0.0"           # Semver range for Eldrin core

dependencies:                       # Other apps this app requires
  - id: "catalog"
    version: ">=1.2.0"
    optional: false                 # If true, graceful degradation when missing

peerDependencies:                   # Apps that enhance this app (not required)
  - id: "accounting"
    version: ">=1.0.0"

# ─────────────────────────────────────────────────────────────
# PRICING (Marketplace)
# ─────────────────────────────────────────────────────────────
pricing:
  model: "subscription"             # free | one-time | subscription
  plans:
    - id: "starter"
      name: "Starter"
      price: 0
      currency: "USD"
      interval: "month"
      features:
        - "50 invoices/month"
        - "Basic templates"
    - id: "pro"
      name: "Professional"
      price: 29
      currency: "USD"
      interval: "month"
      features:
        - "Unlimited invoices"
        - "Custom templates"
        - "Recurring invoices"
        - "Payment reminders"

# ─────────────────────────────────────────────────────────────
# FEATURE FLAGS
# ─────────────────────────────────────────────────────────────
features:
  - id: "recurring-invoices"
    name: "Recurring Invoices"
    description: "Automatically generate invoices on a schedule"
    default: true
    plans: ["pro"]                  # Only available in pro plan
    
  - id: "payment-reminders"
    name: "Payment Reminders"
    description: "Send automatic payment reminder emails"
    default: false
    plans: ["pro"]

# ─────────────────────────────────────────────────────────────
# UI INTEGRATION POINTS
# ─────────────────────────────────────────────────────────────
ui:
  # Side Navigation
  sideNav:
    - label: "Invoices"
      icon: "file-text"             # Icon name from shared icon library
      path: "/invoices"
      permission: "invoicing:read"
      badge:                        # Optional dynamic badge
        type: "count"
        source: "unpaidInvoices"
      children:
        - label: "All Invoices"
          path: "/invoices"
        - label: "Create Invoice"
          path: "/invoices/new"
          permission: "invoicing:write"
        - label: "Templates"
          path: "/invoices/templates"
          permission: "invoicing:templates"

  # Top Navigation
  topNav:
    - label: "Quick Invoice"
      icon: "plus"
      action: "openQuickInvoice"    # Triggers app action
      permission: "invoicing:write"

  # User Menu (dropdown)
  userMenu:
    - label: "My Invoices"
      icon: "file-text"
      path: "/invoices/mine"
    - type: "separator"
    - label: "Invoice Settings"
      icon: "settings"
      path: "/settings/invoicing"

  # Settings Page
  settingsPages:
    - id: "invoicing-general"
      label: "General"
      component: "InvoiceSettingsGeneral"
      category: "apps"              # Where in settings hierarchy
    - id: "invoicing-templates"
      label: "Templates"
      component: "InvoiceSettingsTemplates"
      category: "apps"

  # Dashboard Widgets
  dashboardWidgets:
    - id: "invoice-summary"
      name: "Invoice Summary"
      description: "Overview of invoice statistics"
      component: "InvoiceSummaryWidget"
      defaultSize: "medium"         # small | medium | large
      defaultPosition: { x: 0, y: 0 }
      permission: "invoicing:read"
      
    - id: "recent-invoices"
      name: "Recent Invoices"
      description: "List of recently created invoices"
      component: "RecentInvoicesWidget"
      defaultSize: "large"
      permission: "invoicing:read"
      configurable: true            # User can configure widget

  # Context Menus
  contextMenus:
    - context: "contact"            # When right-clicking a contact
      items:
        - label: "Create Invoice"
          icon: "file-plus"
          action: "createInvoiceForContact"
          permission: "invoicing:write"
        - label: "View Invoices"
          icon: "file-text"
          action: "viewContactInvoices"
          permission: "invoicing:read"
          
    - context: "product"            # When right-clicking a product
      items:
        - label: "Add to Invoice"
          icon: "plus"
          action: "addProductToInvoice"
          permission: "invoicing:write"

  # Keyboard Shortcuts
  keyboardShortcuts:
    - keys: ["ctrl", "shift", "i"]
      action: "openQuickInvoice"
      description: "Create new invoice"
      scope: "global"               # global | app (only when app focused)
      permission: "invoicing:write"
      
    - keys: ["ctrl", "s"]
      action: "saveInvoice"
      description: "Save current invoice"
      scope: "app"
      permission: "invoicing:write"

# ─────────────────────────────────────────────────────────────
# EXPORTS (for other apps)
# ─────────────────────────────────────────────────────────────
exports:
  # Events other apps can listen to
  events:
    - name: "invoice:created"
      description: "Fired when a new invoice is created"
      payload:
        type: "object"
        properties:
          invoiceId: { type: "string" }
          customerId: { type: "string" }
          total: { type: "number" }
          
    - name: "invoice:paid"
      description: "Fired when an invoice is marked as paid"
      payload:
        type: "object"
        properties:
          invoiceId: { type: "string" }
          paidAmount: { type: "number" }
          paymentMethod: { type: "string" }

  # Hooks other apps can call
  hooks:
    - name: "getInvoiceById"
      type: "query"
      description: "Retrieve an invoice by ID"
      params:
        type: "object"
        properties:
          id: { type: "string", required: true }
      returns:
        type: "Invoice"
        
    - name: "createInvoice"
      type: "mutation"
      description: "Create a new invoice"
      params:
        type: "CreateInvoiceInput"
      returns:
        type: "Invoice"
        
    - name: "getInvoicesForCustomer"
      type: "query"
      description: "Get all invoices for a customer"
      params:
        type: "object"
        properties:
          customerId: { type: "string", required: true }
          status: { type: "string", enum: ["draft", "sent", "paid", "overdue"] }
      returns:
        type: "Invoice[]"

# ─────────────────────────────────────────────────────────────
# PERMISSIONS
# ─────────────────────────────────────────────────────────────
permissions:
  # Permissions this app defines
  defines:
    - id: "invoicing:read"
      name: "View Invoices"
      description: "Can view invoices and reports"
      
    - id: "invoicing:write"
      name: "Manage Invoices"
      description: "Can create, edit, and delete invoices"
      
    - id: "invoicing:templates"
      name: "Manage Templates"
      description: "Can create and edit invoice templates"
      
    - id: "invoicing:admin"
      name: "Invoice Admin"
      description: "Full access to all invoicing features"
      includes: ["invoicing:read", "invoicing:write", "invoicing:templates"]

  # Permissions this app requires from other apps
  requires:
    - "catalog:read"                # Needs to read products/services

  # App-defined roles
  roles:
    - id: "invoice-viewer"
      name: "Invoice Viewer"
      permissions: ["invoicing:read"]
      
    - id: "invoice-manager"
      name: "Invoice Manager"
      permissions: ["invoicing:read", "invoicing:write"]
      
    - id: "invoice-admin"
      name: "Invoice Administrator"
      permissions: ["invoicing:admin"]

# ─────────────────────────────────────────────────────────────
# BACKEND SERVICE
# ─────────────────────────────────────────────────────────────
backend:
  worker: "https://invoicing-app.workers.dev"
  healthCheck: "/health"
  api:
    basePath: "/api/v1"
    docs: "/api/docs"               # OpenAPI spec location

# ─────────────────────────────────────────────────────────────
# LOCALIZATION
# ─────────────────────────────────────────────────────────────
localization:
  defaultLocale: "en-US"
  supportedLocales:
    - "en-US"
    - "en-GB"
    - "de-DE"
    - "fr-FR"
    - "es-ES"
  # App bundles its own translations

# ─────────────────────────────────────────────────────────────
# ASSETS
# ─────────────────────────────────────────────────────────────
assets:
  icon: "./assets/icon.svg"
  screenshots:
    - "./assets/screenshot-1.png"
    - "./assets/screenshot-2.png"
  banner: "./assets/banner.png"
```

### 5.2 Manifest Validation Rules

| Field | Required | Validation |
|-------|----------|------------|
| `id` | Yes | Lowercase alphanumeric + hyphens, 3-50 chars |
| `name` | Yes | 3-100 characters |
| `version` | Yes | Valid semver |
| `compatibility.core` | Yes | Valid semver range |
| `permissions.defines` | No | Each must have unique id |
| `ui.*` | No | Each path must be unique |

---

## 6. Security Model

### 6.1 Defense in Depth

Given the open marketplace, security is implemented in layers:

```
┌─────────────────────────────────────────────────────────────────┐
│                    LAYER 1: Marketplace Review                  │
│         Automated scans + Manual review for verified apps       │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                    LAYER 2: Code Signing                        │
│         Apps are signed; shell verifies signatures              │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                    LAYER 3: CSP + Permissions                   │
│         Strict Content Security Policy; declared permissions    │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                    LAYER 4: Runtime Isolation                   │
│         single-spa isolation; error boundaries                  │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                    LAYER 5: API Scoping                         │
│         Service tokens scoped to declared permissions           │
└─────────────────────────────────────────────────────────────────┘
```

### 6.2 Permission System (MVP)

MVP uses simple CRUD permissions:

```typescript
type Permission = `${Resource}:${Action}`;
type Resource = string;  // e.g., "invoices", "contacts", "products"
type Action = "read" | "write" | "delete";

// Examples
"invoices:read"    // Can view invoices
"invoices:write"   // Can create/update invoices
"invoices:delete"  // Can delete invoices
"contacts:read"    // Can view contacts from CRM app
```

### 6.3 Service-to-Service JWT

```typescript
interface ServiceToken {
  // Standard claims
  iss: string;           // "eldrin-core"
  sub: string;           // User ID
  aud: string;           // Target app ID
  exp: number;           // Expiration timestamp
  iat: number;           // Issued at timestamp
  
  // Custom claims
  tenant: string;        // Customer/tenant identifier
  permissions: string[]; // Scoped permissions for this app
  appId: string;         // Requesting app (if app-to-app)
}
```

Token flow:
1. User requests action requiring app backend
2. Shell requests scoped token from auth service
3. Token includes only permissions the app declared AND user has
4. App backend validates token signature and claims
5. App enforces permissions on its endpoints

### 6.4 Content Security Policy

```typescript
const cspPolicy = {
  "default-src": ["'self'"],
  "script-src": [
    "'self'",
    "https://marketplace.eldrin.io",  // Marketplace CDN
    // App-specific origins added dynamically
  ],
  "style-src": ["'self'", "'unsafe-inline'"],  // For CSS-in-JS
  "img-src": ["'self'", "data:", "https:"],
  "connect-src": [
    "'self'",
    "https://*.eldrin.io",
    // App worker URLs added dynamically
  ],
  "frame-src": ["'none'"],  // No iframes by default
};
```

### 6.5 App Code Signing

```typescript
interface AppSignature {
  algorithm: "Ed25519";
  publicKey: string;      // Developer's public key (registered in marketplace)
  signature: string;      // Signature of app bundle hash
  timestamp: number;      // When signed
  bundleHash: string;     // SHA-256 of app bundle
}

// Verification at load time
async function loadApp(appId: string) {
  const bundle = await fetchAppBundle(appId);
  const signature = await fetchAppSignature(appId);
  const developerKey = await getRegisteredPublicKey(appId);
  
  if (!verifySignature(bundle, signature, developerKey)) {
    throw new SecurityError(`App ${appId} failed signature verification`);
  }
  
  return loadModule(bundle);
}
```

---

## 7. Data Architecture

### 7.1 Database Per App

Each app manages its own Cloudflare D1 database:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Catalog App    │     │  Invoicing App  │     │    CRM App      │
│                 │     │                 │     │                 │
│  ┌───────────┐  │     │  ┌───────────┐  │     │  ┌───────────┐  │
│  │ D1: catalog│ │     │  │D1: invoice│  │     │  │  D1: crm  │  │
│  │           │  │     │  │           │  │     │  │           │  │
│  │ products  │  │     │  │ invoices  │  │     │  │ contacts  │  │
│  │ categories│  │     │  │ line_items│  │     │  │ companies │  │
│  │ variants  │  │     │  │ templates │  │     │  │ deals     │  │
│  └───────────┘  │     │  └───────────┘  │     │  └───────────┘  │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

### 7.2 Data Sharing Contracts

Apps share data via explicit exports/hooks, NOT direct database access:

```typescript
// ❌ WRONG - Direct DB access
const invoice = await otherAppDb.query("SELECT * FROM invoices WHERE id = ?", [id]);

// ✅ CORRECT - Via SDK hook
const invoice = await eldrin.apps.call('invoicing', 'getInvoiceById', { id });
```

### 7.3 File Storage (R2)

Each app gets its own R2 bucket namespace:

```typescript
// App SDK provides scoped storage access
const storage = eldrin.storage;

// Files are namespaced: /{tenantId}/{appId}/{path}
await storage.put('invoices/INV-001.pdf', pdfBuffer);
const url = await storage.getSignedUrl('invoices/INV-001.pdf', { expiresIn: 3600 });
```

### 7.4 Offline-Ready Design (Future)

Data contracts are designed with future offline support in mind:

```typescript
interface SyncableEntity {
  id: string;
  _version: number;        // For optimistic locking
  _lastModified: string;   // ISO timestamp
  _syncStatus: 'synced' | 'pending' | 'conflict';
  _localChanges?: object;  // Pending changes when offline
}

// Future: Apps can opt into sync
interface AppManifest {
  sync?: {
    enabled: true;
    entities: ['invoices', 'contacts'];
    conflictResolution: 'last-write-wins' | 'manual';
  };
}
```

---

## 8. API & Communication

### 8.1 Smart Routing for Inter-App Communication

When App A calls App B:

```typescript
async function call<T>(appId: string, hook: string, params: unknown): Promise<T> {
  // 1. Check if app is loaded in browser
  if (isAppLoadedInBrowser(appId)) {
    // Direct call (faster)
    return directCall(appId, hook, params);
  }
  
  // 2. Fallback to message bus
  return messageBusCall(appId, hook, params);
}

// Direct call implementation
function directCall(appId: string, hook: string, params: unknown) {
  const app = getLoadedApp(appId);
  return app.hooks[hook](params);
}

// Message bus call implementation
function messageBusCall(appId: string, hook: string, params: unknown) {
  return new Promise((resolve, reject) => {
    const requestId = generateId();
    
    eventBus.once(`response:${requestId}`, (response) => {
      if (response.error) reject(response.error);
      else resolve(response.data);
    });
    
    eventBus.emit(`request:${appId}:${hook}`, {
      requestId,
      params
    });
  });
}
```

### 8.2 Event Bus (Zustand)

```typescript
// Core event store
interface EventStore {
  // Event subscriptions
  subscriptions: Map<string, Set<EventHandler>>;
  
  // Shared state atoms (for cross-app state)
  sharedState: {
    currentUser: User | null;
    theme: Theme;
    locale: string;
    // Apps can register additional shared state
  };
  
  // Actions
  emit: (event: string, payload: unknown) => void;
  on: (event: string, handler: EventHandler) => Unsubscribe;
  setSharedState: <K extends keyof SharedState>(key: K, value: SharedState[K]) => void;
}

// Usage in apps
const unsubscribe = eldrin.apps.on('invoice:created', (payload) => {
  console.log('New invoice:', payload.invoiceId);
  // Update local state, refresh lists, etc.
});

// Emit events
eldrin.apps.emit('invoice:paid', {
  invoiceId: 'INV-001',
  paidAmount: 1500.00,
  paymentMethod: 'bank_transfer'
});
```

### 8.3 Backend API Contract

App backends expose REST APIs:

```typescript
// Standard API structure for app backends
// Base: https://{app-id}.workers.dev/api/v1

// Public endpoints (documented in manifest)
GET    /api/v1/invoices              // List invoices
POST   /api/v1/invoices              // Create invoice
GET    /api/v1/invoices/:id          // Get invoice
PUT    /api/v1/invoices/:id          // Update invoice
DELETE /api/v1/invoices/:id          // Delete invoice

// Internal endpoints (for inter-app calls)
POST   /api/v1/internal/hooks/:hookName  // Execute hook

// Health & metadata
GET    /health                        // Health check
GET    /api/docs                      // OpenAPI spec
```

---

## 9. UI Integration Points

### 9.1 Navigation System

```typescript
interface NavigationManager {
  // Collect navigation items from all enabled apps
  getSideNavItems(): SideNavItem[];
  getTopNavItems(): TopNavItem[];
  getUserMenuItems(): UserMenuItem[];
  
  // Dynamic updates
  updateBadge(appId: string, badgeId: string, value: number): void;
  
  // Filtering by permissions
  filterByPermissions(items: NavItem[], userPermissions: string[]): NavItem[];
}

// Side nav structure
interface SideNavItem {
  appId: string;
  label: string;
  icon: string;
  path: string;
  permission?: string;
  badge?: {
    type: 'count' | 'dot';
    value?: number;
  };
  children?: SideNavItem[];
  order?: number;  // For sorting
}
```

### 9.2 Dashboard System

```typescript
interface DashboardManager {
  // Widget registry
  registeredWidgets: Map<string, WidgetDefinition>;
  
  // User's dashboard layout
  userLayout: DashboardLayout;
  
  // Actions
  registerWidget(appId: string, widget: WidgetDefinition): void;
  addWidgetToLayout(widgetId: string, position: Position): void;
  removeWidget(widgetId: string): void;
  updateLayout(layout: DashboardLayout): void;
}

interface DashboardLayout {
  columns: number;        // Grid columns (default: 12)
  widgets: WidgetPlacement[];
}

interface WidgetPlacement {
  widgetId: string;
  x: number;              // Grid column
  y: number;              // Grid row
  width: number;          // Columns spanned
  height: number;         // Rows spanned
  config?: object;        // Widget-specific config
}
```

### 9.3 Context Menu System

```typescript
interface ContextMenuManager {
  // Register context menu items
  register(context: string, appId: string, items: ContextMenuItem[]): void;
  
  // Get items for a context
  getItems(context: string, contextData: unknown): ContextMenuItem[];
  
  // Execute action
  executeAction(appId: string, action: string, contextData: unknown): void;
}

// Supported contexts
type ContextType = 
  | 'contact'      // CRM contact
  | 'company'      // CRM company
  | 'product'      // Catalog product
  | 'invoice'      // Invoice
  | 'order'        // E-commerce order
  | 'file'         // Any file
  | 'selection'    // Text selection
  | string;        // Custom contexts

// Context data passed to actions
interface ContextData {
  type: ContextType;
  id: string;
  data: unknown;    // Full entity data
}
```

### 9.4 Keyboard Shortcuts

```typescript
interface ShortcutManager {
  // Registry
  shortcuts: Map<string, ShortcutDefinition>;
  
  // Current focus scope
  currentScope: 'global' | string;  // string = appId
  
  // Register shortcut
  register(shortcut: ShortcutDefinition): void;
  
  // Handle keypress
  handleKeyPress(event: KeyboardEvent): void;
  
  // Conflict detection
  detectConflicts(): ShortcutConflict[];
}

interface ShortcutDefinition {
  appId: string;
  keys: string[];           // ['ctrl', 'shift', 'i']
  action: string;
  description: string;
  scope: 'global' | 'app';
  permission?: string;
  priority?: number;        // Higher = takes precedence
}

// Priority system for conflicts
// 1. App-scoped shortcuts when app is focused
// 2. Global shortcuts by priority
// 3. First registered wins if equal priority
```

### 9.5 Settings System

```typescript
interface SettingsManager {
  // Categories
  categories: SettingsCategory[];
  
  // Pages from apps
  pages: Map<string, SettingsPage>;
  
  // Get settings tree
  getSettingsTree(): SettingsNode[];
}

interface SettingsCategory {
  id: string;
  label: string;
  icon: string;
  order: number;
}

// Default categories
const defaultCategories: SettingsCategory[] = [
  { id: 'account', label: 'Account', icon: 'user', order: 1 },
  { id: 'appearance', label: 'Appearance', icon: 'palette', order: 2 },
  { id: 'apps', label: 'Apps', icon: 'grid', order: 3 },
  { id: 'security', label: 'Security', icon: 'shield', order: 4 },
  { id: 'billing', label: 'Billing', icon: 'credit-card', order: 5 },
];
```

---

## 10. Marketplace

### 10.1 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    ELDRIN MARKETPLACE                           │
│                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │  App Registry   │  │   CDN (R2)      │  │  Review System  │ │
│  │  (Metadata DB)  │  │  (App Bundles)  │  │  (Automated +   │ │
│  │                 │  │                 │  │   Manual)       │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │ Payment System  │  │  Analytics      │  │  Developer      │ │
│  │ (Stripe Connect)│  │  (Usage Stats)  │  │  Portal         │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │     Customer Workers          │
              │  (Fetch manifests + bundles)  │
              └───────────────────────────────┘
```

### 10.2 Registry Types

Customers can configure multiple registries:

```typescript
interface RegistryConfig {
  registries: Registry[];
}

interface Registry {
  id: string;
  name: string;
  type: 'official' | 'private' | 'npm';
  url: string;
  priority: number;  // Lower = checked first
}

// Default config
const defaultRegistries: Registry[] = [
  {
    id: 'official',
    name: 'Eldrin Marketplace',
    type: 'official',
    url: 'https://marketplace.eldrin.io',
    priority: 1
  }
];

// Customer can add private registries
// {
//   id: 'acme-internal',
//   name: 'Acme Internal Apps',
//   type: 'private',
//   url: 'https://apps.acme.com',
//   priority: 0  // Check first
// }
```

### 10.3 Review Process

Tiered review system with community ratings:

```
┌─────────────────────────────────────────────────────────────────┐
│                     APP SUBMISSION FLOW                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │     AUTOMATED CHECKS          │
              │  • Manifest validation        │
              │  • Security scan (Snyk/etc)   │
              │  • Bundle size limits         │
              │  • API compliance check       │
              └───────────────────────────────┘
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
           ┌──────────────┐    ┌──────────────┐
           │   PASSED     │    │   FAILED     │
           └──────────────┘    └──────────────┘
                    │                   │
                    ▼                   ▼
           ┌──────────────┐    ┌──────────────┐
           │  UNVERIFIED  │    │  REJECTED    │
           │    BADGE     │    │  (with       │
           │              │    │   feedback)  │
           └──────────────┘    └──────────────┘
                    │
                    ▼
           ┌──────────────┐
           │   MANUAL     │
           │   REVIEW     │
           │  (optional)  │
           └──────────────┘
                    │
                    ▼
           ┌──────────────┐
           │   VERIFIED   │
           │    BADGE     │
           └──────────────┘
```

### 10.4 Trust Badges

| Badge | Meaning | Requirements |
|-------|---------|--------------|
| **Unverified** | Passed automated checks only | Automated scans pass |
| **Verified** | Passed manual review | Manual code review |
| **Official** | Built by Eldrin team | Internal apps |
| **Partner** | Trusted partner app | Partner agreement |

### 10.5 Community Features

```typescript
interface AppListing {
  // Core info
  manifest: AppManifest;
  
  // Trust indicators
  badge: 'unverified' | 'verified' | 'official' | 'partner';
  publishedAt: string;
  lastUpdated: string;
  
  // Community
  rating: number;            // 1-5 stars
  reviewCount: number;
  installCount: number;
  
  // Flags
  flags: AppFlag[];          // Community reports
  
  // Changelog
  changelog: ChangelogEntry[];
}

interface AppFlag {
  type: 'security' | 'spam' | 'broken' | 'misleading';
  reportedBy: string;
  reportedAt: string;
  status: 'pending' | 'reviewed' | 'dismissed';
}
```

### 10.6 Payment Integration (Stripe Connect)

```typescript
interface PaymentFlow {
  // Developer onboarding
  connectAccount: StripeConnectAccount;
  
  // Transaction flow
  // 1. Customer purchases app
  // 2. Payment goes to Eldrin's Stripe
  // 3. Eldrin takes commission (e.g., 20%)
  // 4. Remainder transferred to developer's Connect account
}

interface AppPurchase {
  appId: string;
  customerId: string;
  planId: string;
  amount: number;
  currency: string;
  commission: number;        // Eldrin's cut
  developerPayout: number;   // Developer's share
  stripePaymentId: string;
}
```

---

## 11. Developer Experience

### 11.1 CLI Tool

```bash
# Installation
npm install -g @eldrin/cli

# Create new app
eldrin create my-app
# Interactive prompts for:
# - App name and ID
# - Description
# - Initial UI integration points
# - Backend (yes/no)

# Development
eldrin dev                    # Start dev server with hot reload
eldrin dev --with-core        # Start with core shell

# Testing
eldrin test                   # Run unit tests
eldrin test:integration       # Run integration tests in sandbox

# Building
eldrin build                  # Build for production

# Publishing
eldrin login                  # Authenticate with marketplace
eldrin publish                # Publish to marketplace
eldrin publish --tag beta     # Publish as beta
```

### 11.2 Project Structure

```
my-app/
├── eldrin-app.manifest.json     # App manifest
├── package.json
├── tsconfig.json
├── vite.config.ts
│
├── src/
│   ├── index.ts                 # App entry point
│   ├── lifecycle.ts             # Lifecycle hooks
│   ├── hooks/                   # Exported hooks
│   │   └── index.ts
│   │
│   ├── components/              # React components
│   │   ├── pages/
│   │   ├── widgets/
│   │   └── settings/
│   │
│   ├── stores/                  # Zustand stores
│   │   └── index.ts
│   │
│   └── locales/                 # Translations
│       ├── en-US.json
│       └── de-DE.json
│
├── worker/                      # Backend (if needed)
│   ├── src/
│   │   ├── index.ts
│   │   └── routes/
│   ├── wrangler.toml
│   └── schema.sql               # D1 schema
│
└── tests/
    ├── unit/
    └── integration/
```

### 11.3 SDK

```typescript
// @eldrin/sdk
import { createApp, useEldrin, usePermission } from '@eldrin/sdk';

// App entry point
export default createApp({
  id: 'my-app',
  
  // React root component
  App: MyAppRoot,
  
  // Lifecycle hooks
  lifecycle: {
    onInstall: async () => { /* ... */ },
    onUpgrade: async (from) => { /* ... */ },
  },
  
  // Exported hooks for other apps
  hooks: {
    getInvoiceById: async ({ id }) => { /* ... */ },
    createInvoice: async (input) => { /* ... */ },
  },
});

// In components
function InvoiceList() {
  const eldrin = useEldrin();
  const canWrite = usePermission('invoicing:write');
  
  const createInvoice = async () => {
    // Get customer from CRM app
    const customer = await eldrin.apps.call('crm', 'getCustomerById', { id: customerId });
    
    // Navigate
    eldrin.navigation.navigate('/invoices/new', { customer });
  };
  
  return (
    <div>
      {canWrite && <button onClick={createInvoice}>New Invoice</button>}
    </div>
  );
}
```

### 11.4 Testing Infrastructure

#### Unit Test Helpers

```typescript
// @eldrin/testing
import { createMockEldrin, createMockApp } from '@eldrin/testing';

describe('InvoiceList', () => {
  it('shows create button for users with write permission', () => {
    const mockEldrin = createMockEldrin({
      permissions: ['invoicing:read', 'invoicing:write'],
      user: { id: 'user-1', name: 'Test User' }
    });
    
    render(
      <EldrinProvider value={mockEldrin}>
        <InvoiceList />
      </EldrinProvider>
    );
    
    expect(screen.getByText('New Invoice')).toBeInTheDocument();
  });
});
```

#### Integration Sandbox

```typescript
// Start sandbox environment
import { createSandbox } from '@eldrin/testing';

const sandbox = await createSandbox({
  apps: ['catalog', 'my-app'],  // Apps to load
  user: { permissions: ['*'] },  // Test user
  seed: './fixtures/test-data.json'  // Seed data
});

// Run tests
await sandbox.navigate('/invoices');
await sandbox.click('New Invoice');
await sandbox.type('#customer-search', 'Acme');
await sandbox.click('[data-testid="customer-acme"]');

// Assert
const invoice = await sandbox.apps.call('invoicing', 'getInvoiceById', { id: 'INV-001' });
expect(invoice.customer.name).toBe('Acme Corp');

// Cleanup
await sandbox.destroy();
```

### 11.5 Developer Portal

Full portal including:

| Section | Features |
|---------|----------|
| **Documentation** | API reference, guides, tutorials, examples |
| **Playground** | Interactive API explorer, live code editor |
| **Dashboard** | Install stats, revenue, error rates, user feedback |
| **Publishing** | Version management, release notes, beta channels |
| **Analytics** | Usage patterns, feature adoption, performance |
| **Support** | Community forum, issue tracker, direct support |

---

## 12. First-Party Apps

### 12.1 Catalog App

Core product/service management:

```yaml
id: "catalog"
name: "Catalog"
description: "Manage products, services, and categories"

features:
  - Categories (hierarchical)
  - Products with variants
  - Services
  - Pricing rules
  - Stock tracking (basic)
  - Import/Export

exports:
  hooks:
    - getProductById
    - searchProducts
    - getCategories
    - createProduct
  events:
    - product:created
    - product:updated
    - stock:low

dependencies: []  # No dependencies
```

### 12.2 Invoicing App

Invoice creation and management:

```yaml
id: "invoicing"
name: "Invoicing"
description: "Create and manage invoices"

features:
  - Invoice creation
  - Templates
  - Recurring invoices
  - Payment tracking
  - PDF generation
  - Email sending

exports:
  hooks:
    - getInvoiceById
    - createInvoice
    - getInvoicesForCustomer
  events:
    - invoice:created
    - invoice:sent
    - invoice:paid

dependencies:
  - id: "catalog"
    version: ">=1.0.0"
```

### 12.3 CRM App

Customer relationship management:

```yaml
id: "crm"
name: "CRM"
description: "Manage contacts, companies, and relationships"

features:
  - Contacts
  - Companies
  - Deals/Opportunities
  - Activities
  - Notes
  - Tags

exports:
  hooks:
    - getContactById
    - searchContacts
    - getCompanyById
    - createContact
  events:
    - contact:created
    - deal:won
    - deal:lost

dependencies: []
```

### 12.4 B2B E-Commerce App

Business-to-business storefront:

```yaml
id: "b2b-ecommerce"
name: "B2B E-Commerce"
description: "B2B storefront with customer-specific pricing"

features:
  - Storefront
  - Customer portals
  - Tiered pricing
  - Quote requests
  - Order management
  - Reordering

exports:
  hooks:
    - getOrderById
    - createOrder
    - getCustomerOrders
  events:
    - order:placed
    - order:shipped
    - quote:requested

dependencies:
  - id: "catalog"
    version: ">=1.0.0"
  - id: "crm"
    version: ">=1.0.0"
  - id: "invoicing"
    version: ">=1.0.0"
```

### 12.5 App Dependency Graph

```
                    ┌─────────────┐
                    │   Catalog   │
                    │  (no deps)  │
                    └──────┬──────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
           ▼               ▼               ▼
    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
    │  Invoicing  │ │     CRM     │ │  Inventory  │
    │(needs Catalog)│(no deps)    │ │(needs Catalog)
    └──────┬──────┘ └──────┬──────┘ └─────────────┘
           │               │
           └───────┬───────┘
                   │
                   ▼
           ┌─────────────┐
           │B2B E-Commerce│
           │(needs all 3) │
           └─────────────┘
```

---

## 13. Deployment Model

### 13.1 Customer Deployment Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    CUSTOMER ONBOARDING                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │  1. Sign up on Eldrin.io      │
              │     (create account)          │
              └───────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │  2. Select apps to enable     │
              │     (from marketplace)        │
              └───────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │  3. Configure branding        │
              │     (theme, logo, domain)     │
              └───────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │  4. Deploy to Cloudflare      │
              │     (one-click or CLI)        │
              └───────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │  5. Custom domain setup       │
              │     (optional)                │
              └───────────────────────────────┘
```

### 13.2 Deployment Configuration

```typescript
// eldrin.config.ts (customer's config)
export default {
  // Tenant identification
  tenant: {
    id: 'acme-corp',
    name: 'Acme Corporation'
  },
  
  // Branding
  theme: {
    branding: {
      name: 'Acme Platform',
      logo: '/assets/acme-logo.svg',
      removePoweredBy: true
    },
    colors: {
      primary: '#0052CC',
      secondary: '#172B4D'
    }
  },
  
  // Apps configuration
  apps: {
    // Built-in (npm)
    npm: [
      '@eldrin/app-catalog',
      '@eldrin/app-invoicing'
    ],
    
    // Marketplace (dynamic)
    marketplace: [
      { id: 'crm', version: '^1.0.0' },
      { id: 'b2b-ecommerce', version: '^1.0.0' }
    ],
    
    // Private registry
    private: [
      { 
        id: 'acme-custom-reports',
        registry: 'https://apps.acme.internal'
      }
    ]
  },
  
  // Feature flags
  features: {
    'invoicing:recurring-invoices': true,
    'crm:email-integration': false
  },
  
  // Registry configuration
  registries: [
    {
      id: 'acme-internal',
      url: 'https://apps.acme.internal',
      priority: 0
    }
  ]
};
```

### 13.3 Cloudflare Worker Setup

```toml
# wrangler.toml
name = "acme-eldrin"
main = "src/index.ts"
compatibility_date = "2024-01-01"

[vars]
TENANT_ID = "acme-corp"

# D1 Database (for core user data)
[[d1_databases]]
binding = "DB"
database_name = "eldrin-core"
database_id = "xxx"

# R2 Storage
[[r2_buckets]]
binding = "STORAGE"
bucket_name = "eldrin-files"

# KV for sessions/cache
[[kv_namespaces]]
binding = "KV"
id = "xxx"

# Custom domain
routes = [
  { pattern = "app.acme.com", zone_name = "acme.com" }
]
```

### 13.4 App Worker Binding

Each enabled app worker is bound to the main worker:

```toml
# wrangler.toml (continued)

# App service bindings
[[services]]
binding = "APP_CATALOG"
service = "eldrin-app-catalog"

[[services]]
binding = "APP_INVOICING"  
service = "eldrin-app-invoicing"

[[services]]
binding = "APP_CRM"
service = "eldrin-app-crm"
```

---

## 14. Roadmap & Milestones

### 14.1 Phase 1: Foundation (Weeks 1-6)

| Week | Deliverable |
|------|-------------|
| 1-2 | Core shell setup (React + Vite + single-spa) |
| 2-3 | Authentication system (JWT, user management) |
| 3-4 | App loading infrastructure (npm + dynamic) |
| 4-5 | Permission system (CRUD-based MVP) |
| 5-6 | Navigation system (side nav, top nav, user menu) |

**Milestone 1**: Core shell that can load and orchestrate apps

### 14.2 Phase 2: First Apps (Weeks 7-12)

| Week | Deliverable |
|------|-------------|
| 7-8 | Catalog app (products, categories) |
| 9-10 | Invoicing app (basic invoicing) |
| 10-11 | CRM app (contacts, companies) |
| 11-12 | Inter-app communication (events, hooks) |

**Milestone 2**: Three working first-party apps

### 14.3 Phase 3: Advanced Features (Weeks 13-18)

| Week | Deliverable |
|------|-------------|
| 13-14 | Dashboard system (widgets, customization) |
| 14-15 | Context menus & keyboard shortcuts |
| 15-16 | Theming & white-label system |
| 16-17 | Settings framework |
| 17-18 | B2B E-commerce app |

**Milestone 3**: Full UI integration system + fourth app

### 14.4 Phase 4: Marketplace & DX (Weeks 19-24)

| Week | Deliverable |
|------|-------------|
| 19-20 | Developer CLI & SDK |
| 20-21 | Marketplace backend (registry, CDN) |
| 21-22 | Review system (automated + manual) |
| 22-23 | Payment integration (Stripe Connect) |
| 23-24 | Developer portal (docs, playground, publishing) |

**Milestone 4**: MVP Complete - Full marketplace with developer tools

### 14.5 Post-MVP Roadmap

| Priority | Feature |
|----------|---------|
| High | Analytics dashboard (for customers and developers) |
| High | Webhook system |
| Medium | Mobile app (React Native shell) |
| Medium | Offline support |
| Medium | API versioning & adapter layers |
| Low | Plugin system for UI components |
| Low | Workflow automation engine |

---

## 15. Technical Decisions Summary

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Frontend Framework | React + Vite | Ecosystem, tooling, team familiarity |
| Micro-frontend | single-spa | Mature, framework-agnostic, good isolation |
| State Management | Zustand | Lightweight, React-native, shared atoms |
| App Distribution | npm + CDN hybrid | Flexibility for core and marketplace |
| Authentication | Custom JWT | Full control over service-to-service |
| Database | D1 per app | Isolation, Cloudflare-native, cost |
| File Storage | R2 | S3-compatible, integrated |
| Hosting | Cloudflare Workers | Edge, single-tenant friendly |
| Permissions | CRUD-based (MVP) | Simplicity, extensible later |
| Inter-app Comm | Smart routing | Performance + fallback |
| Error Handling | Circuit breaker | Resilience, auto-recovery |
| Marketplace | Centralized + custom | Control + flexibility |
| Payments | Stripe Connect | Developer-friendly, proven |
| Localization | Per-app (en-US format) | Country-specific support |
| Theming | Full white-label | Customer ownership |

---

## 16. Glossary

| Term | Definition |
|------|------------|
| **Eldrin** | The platform name; the core shell application |
| **App** | A modular addon that extends Eldrin functionality |
| **Shell** | The core Eldrin application that orchestrates apps |
| **Marketplace** | Central registry for discovering and installing apps |
| **Manifest** | YAML file declaring app metadata, UI integrations, and capabilities |
| **Hook** | Function exported by an app that other apps can call |
| **Event** | Message emitted by an app that other apps can subscribe to |
| **Parcel** | single-spa term for a mounted micro-frontend |
| **Circuit Breaker** | Pattern to disable failing apps automatically |
| **Service Token** | JWT for authenticated app-to-app or app-to-backend communication |
| **Tenant** | A customer deployment (single-tenant model) |

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | December 2024 | Architecture Team | Initial specification |

---

*This document serves as the technical blueprint for the Eldrin platform. All implementation decisions should reference this specification. Updates require review and version increment.*
