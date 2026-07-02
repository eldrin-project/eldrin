# Super Phase 1: Core CRM Foundation (MVP)

## Overview

Deliver a functional CRM that replaces spreadsheets and provides a single source of truth for contacts, companies, deals, and activities. The MVP includes two strategic differentiators from day one: a **Zero Data Entry** engine that auto-captures emails, calendar events, and calls; and **Buyer-Side Deal Rooms** that give prospects a shared, transparent workspace.

**Requirements scope**: Phase 1 from `eldrin-crm-requirements.md`
- **97 requirements** (59 Must, 26 Should, 12 Could)
- **11 requirement modules** (1.1–1.11), mapped to 11 implementation sub-phases
- REQ-1.8 (Users, Roles & Permissions) has no sub-phase — auth/RBAC is already in eldrin-core

### Architecture

This is an Eldrin extension app (micro-frontend + micro-service) following the patterns proven in `eldrin-workflows`:

| Layer | Technology | Pattern |
|-------|------------|---------|
| Backend | Hono | CORS → migration middleware → DB injection → route modules → ASSETS fallback |
| Database | Drizzle ORM | SQLite schema, SQL migrations → `generate-migrations.ts` → SDK `runMigrations()` |
| Frontend | React 19 + single-spa | `createApp()` + `singleSpaReact()` + `combineLifecycles()` |
| UI | daisyUI 5 | MutationObserver theme sync, scoped `data-theme` |
| State | Zustand | Complex client-side state (filters, saved views, Kanban positions) |
| Charts | Recharts | Dashboard KPIs and report visualisations |
| Kanban | @hello-pangea/dnd | Deal pipeline drag-and-drop |
| Rich text | TipTap | Email composer, notes, deal room content |
| Auth | SDK `useAuthHeaders()` | JWT from shell, permission middleware from manifest |

### Project Structure

```
eldrin-crm/
├── migrations/                    # SQL migration files
├── public/
│   └── eldrin-app.manifest.json   # Permissions, routes, nav, database, events
├── scripts/
│   └── generate-migrations.ts     # SQL → TypeScript module
├── src/                           # React frontend
│   ├── components/{ui,contacts,companies,leads,deals,activities,reports,email,import-export,deal-rooms,shared}/
│   ├── pages/{contacts,companies,leads,deals,activities,reports,settings,deal-rooms}/
│   ├── stores/                    # Zustand stores
│   ├── hooks/                     # Custom React hooks
│   ├── lib/                       # Utility functions
│   ├── types/                     # TypeScript types
│   ├── eldrin-crm.tsx             # single-spa entry
│   ├── root.component.tsx         # Router + theme sync
│   └── index.css                  # daisyUI theme
├── worker/                        # Hono backend
│   ├── index.ts                   # App + route mounting
│   ├── db/{schema.ts, index.ts}   # Drizzle schema + factory
│   ├── routes/                    # Per-resource route handlers
│   ├── services/                  # Business logic
│   └── middleware/                # Permissions, audit
├── vite.config.ts                 # Library mode + devShellCompat plugin
├── wrangler.jsonc                 # D1 binding, assets
└── tsconfig.json                  # Project references (app, worker, node)
```

### App Manifest Outline

```json
{
  "id": "eldrin-crm",
  "name": "CRM",
  "permissions": [
    { "resource": "contacts", "actions": ["read", "create", "update", "delete"] },
    { "resource": "companies", "actions": ["read", "create", "update", "delete"] },
    { "resource": "leads", "actions": ["read", "create", "update", "delete"] },
    { "resource": "deals", "actions": ["read", "create", "update", "delete"] },
    { "resource": "activities", "actions": ["read", "create", "update", "delete"] },
    { "resource": "reports", "actions": ["read"] },
    { "resource": "email", "actions": ["read", "create"] },
    { "resource": "import-export", "actions": ["read", "create"] },
    { "resource": "deal-rooms", "actions": ["read", "create", "update", "delete"] },
    { "resource": "settings", "actions": ["read", "update"] }
  ],
  "groups": [
    { "id": "admin", "name": "Admin", "permissions": ["*:*"] },
    { "id": "sales-manager", "name": "Sales Manager", "permissions": ["contacts:*", "companies:*", "leads:*", "deals:*", "activities:*", "reports:read", "email:*", "settings:*"] },
    { "id": "sales-rep", "name": "Sales Rep", "permissions": ["contacts:*", "companies:read", "leads:*", "deals:*", "activities:*", "reports:read", "email:*"] },
    { "id": "viewer", "name": "Viewer", "permissions": ["contacts:read", "companies:read", "leads:read", "deals:read", "activities:read", "reports:read"] }
  ],
  "ui": {
    "sideNav": [
      { "label": "Dashboard", "icon": "layout-dashboard", "path": "/eldrin-crm" },
      { "label": "Contacts", "icon": "users", "path": "/eldrin-crm/contacts" },
      { "label": "Companies", "icon": "building-2", "path": "/eldrin-crm/companies" },
      { "label": "Leads", "icon": "target", "path": "/eldrin-crm/leads" },
      { "label": "Deals", "icon": "handshake", "path": "/eldrin-crm/deals" },
      { "label": "Activities", "icon": "calendar-check", "path": "/eldrin-crm/activities" },
      { "label": "Reports", "icon": "bar-chart-3", "path": "/eldrin-crm/reports" }
    ]
  },
  "database": { "name": "eldrin-crm", "migrationsPath": "migrations", "handledBy": "worker" },
  "events": { "subscribes": [{ "pattern": "*", "delivery": "push" }] }
}
```

---

## Sub-Phase Implementation Order

```
01 → 02 → 03 → 04 → 05 → 06 → 07 → 08 → 09 → 10 → 11
```

| # | Sub-Phase | Req Module | Effort | Req IDs |
|---|-----------|------------|--------|---------|
| 01 | [Project Scaffolding](phases/phase-01-project-scaffolding/PLAN.md) | — | Medium | — |
| 02 | [Contact & Company Management](phases/phase-02-contact-company-management/PLAN.md) | 1.1 | Large | REQ-1.1.01–1.1.12 |
| 03 | [Lead Management](phases/phase-03-lead-management/PLAN.md) | 1.2 | Medium | REQ-1.2.01–1.2.08 |
| 04 | [Deal / Pipeline Management](phases/phase-04-deal-pipeline-management/PLAN.md) | 1.3 | Large | REQ-1.3.01–1.3.10 |
| 05 | [Activity & Task Management](phases/phase-05-activity-task-management/PLAN.md) | 1.4 | Medium | REQ-1.4.01–1.4.08 |
| 06 | [Basic Reporting & Dashboards](phases/phase-06-basic-reporting-dashboards/PLAN.md) | 1.5 | Medium | REQ-1.5.01–1.5.08 |
| 07 | [Email Integration](phases/phase-07-email-integration/PLAN.md) | 1.6 | Medium | REQ-1.6.01–1.6.06 |
| 08 | [Data Import / Export](phases/phase-08-data-import-export/PLAN.md) | 1.7 | Medium | REQ-1.7.01–1.7.05 |
| 09 | [System & UX Foundations](phases/phase-09-system-ux-foundations/PLAN.md) | 1.9 | Medium | REQ-1.9.01–1.9.08 |
| 10 | [Zero Data Entry & Auto-Capture ★](phases/phase-10-zero-data-entry/PLAN.md) | 1.10 | X-Large | REQ-1.10.01–1.10.13 |
| 11 | [Buyer-Side Deal Rooms ★](phases/phase-11-buyer-side-deal-rooms/PLAN.md) | 1.11 | X-Large | REQ-1.11.01–1.11.13 |

### Dependencies

```
01 → All (foundation)
02 → 03, 04, 05, 07, 08, 09, 10, 11 (contacts/companies are core entities)
03 → 04 (lead conversion creates deals)
04 → 06 (pipeline reports), 11 (deal rooms link to deals)
05 → 06 (activity reports), 10 (auto-capture feeds activities)
06 → Semi-independent (enhances all modules)
07 → 08 (email integration enables email in import/export)
08 → 10 (auto-capture extends email)
09 → Needs 02–04 entities to import/export
10 → Needs 02, 04, 05, 07
11 → Needs 04
```

### MVP Boundary

**Sub-phases 01–09** deliver a fully functional CRM: contacts, companies, leads, deals, activities, reports, email integration, data import/export, and system foundations. This is a usable product that replaces spreadsheets.

**Sub-phases 10–11** add the two MVP differentiators (Zero Data Entry and Deal Rooms). These are architecturally significant but the core CRM is functional without them.

---

## Reference

- **Requirements**: `../eldrin-crm-requirements.md` (Phase 1, sections 1.1–1.11)
- **Workflow reference**: `eldrin-workflows/` (Hono + Drizzle + single-spa pattern)
- **SDK**: `eldrin-app-core/src/database/` (migration runner, database adapters)
