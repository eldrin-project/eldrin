# Eldrin Platform

## One-Liner

A modular business platform where companies compose their software stack from independent, interoperable apps.

## The Problem

Businesses waste resources integrating disconnected tools, managing duplicate data, and supporting fragmented workflows.

## The Solution

Eldrin provides a unified shell that orchestrates modular apps—each owns its data, but all work seamlessly together through standardized hooks and events.

## Key Differentiators

- **True modularity** — Apps are isolated micro-frontends, not shallow plugins
- **Data ownership** — Each app has its own database; explicit sharing contracts
- **Single-tenant** — Customers deploy on their own Cloudflare infrastructure
- **White-label** — Full branding control via design tokens
- **Open marketplace** — Any developer can publish apps

## Tech Stack

React + Vite + single-spa | Cloudflare Workers/D1/R2 | Zustand | Custom JWT

## First-Party Apps

Catalog → CRM → Invoicing → B2B E-Commerce

## Elevator Pitch

Eldrin is a composable business OS. Instead of juggling dozens of disconnected SaaS tools, businesses assemble their stack from modular apps that share a unified shell, design system, and data contracts—all deployed on infrastructure they control.

---

## Technical Overview

### Architecture

```
Cloudflare Worker (per customer)
└── Eldrin Shell (React + Vite + single-spa)
    ├── Auth, Navigation, Theming, Permissions
    └── App Orchestrator
        ├── App A (micro-frontend) → D1 + R2
        ├── App B (micro-frontend) → D1 + R2
        └── App C (micro-frontend) → D1 + R2
```

### App Concept

Apps are self-contained React micro-frontends loaded via **single-spa** + **Module Federation**. Each app:
- Declares capabilities in `eldrin-app.manifest.json` (routes, permissions, hooks, events, UI slots)
- Gets its own **D1 database** and **R2 bucket**—no shared tables
- Exports a `createApp()` entry point that the shell mounts

### Bootstrap Flow

1. Worker serves shell → shell reads `eldrin.config.ts` (enabled apps)
2. Shell fetches app manifests and registers routes with single-spa
3. On navigation, single-spa lazy-loads the target app bundle (npm or CDN)
4. App mounts into the shell's content area, receives `useEldrin()` SDK context

### Inter-App Communication

- **Hooks** — Sync calls: `eldrin.apps.call('invoicing', 'getInvoice', { id })`
- **Events** — Async pub/sub: `eldrin.apps.emit('invoice:paid', payload)`
- **Shared atoms** — Zustand stores for cross-app state (cart, notifications)

### Permissions

CRUD-based format: `resource:action` (e.g., `invoices:write`, `contacts:read`). Declared in manifest, enforced by shell and checked via `usePermission()` hook.
