# eldrin-crm — Implementation Plan

## Overview

Build the **eldrin-crm** extension app: a comprehensive Customer Relationship Management application that runs as a standalone Eldrin extension. The CRM manages contacts, companies, leads, deals, activities, reporting, email, and data operations — plus two strategic differentiators from day one: **Zero Data Entry** (auto-capture engine) and **Buyer-Side Deal Rooms** (shared buyer-seller workspaces).

This is a production-grade Eldrin extension built with **Hono** (routing) + **Drizzle ORM** (database portability), following the same patterns established by `eldrin-workflows`.

### Requirements

Full requirements document: `docs/eldrin-crm-implementation/eldrin-crm-requirements.md`

324 total requirements across 8 requirement phases (141 Must, 118 Should, 65 Could).

### Key Technical Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Repo structure | New repo → parent submodule | Like eldrin-workflows, eldrin-invoicing |
| Backend routing | Hono | Matches eldrin-core and eldrin-workflows |
| ORM | Drizzle | Zero deps, first-class D1/PG/Turso/SQLite, proven in workflows |
| Migration strategy | drizzle-kit generates + SDK `runMigrations()` executes | Dialect-aware DDL + SDK tracking |
| Frontend UI | daisyUI 5 | Matches ecosystem, shared theme |
| State management | Zustand | Complex client-side state (filters, views, kanban) |
| Charts | Recharts | Lightweight, React-native, composable |
| Kanban board | @hello-pangea/dnd | Fork of react-beautiful-dnd, maintained |
| Calendar | Custom (day/week/month grid) | Lightweight, daisyUI-styled |
| Rich text | TipTap | ProseMirror-based, extensible, for email composer + notes |
| Real-time (deal rooms) | SSE via Hono streaming | Simple, no WebSocket infra needed |

### Project Structure

```
eldrin-crm/
├── migrations/                    # SQL migration files
├── public/
│   ├── _headers
│   └── eldrin-app.manifest.json   # App manifest
├── scripts/
│   └── generate-migrations.ts     # SQL → TypeScript module
├── src/                           # React frontend
│   ├── components/
│   │   ├── ui/                    # Base UI components (tables, badges, etc.)
│   │   ├── contacts/              # Contact-specific components
│   │   ├── companies/             # Company components
│   │   ├── leads/                 # Lead components
│   │   ├── deals/                 # Deal components (incl. Kanban)
│   │   ├── activities/            # Activity/task components
│   │   ├── reports/               # Chart/dashboard widgets
│   │   ├── email/                 # Email composer, templates
│   │   ├── import-export/         # Import wizard, export dialogs
│   │   ├── deal-rooms/            # Buyer-facing deal room UI
│   │   └── shared/                # Timeline, filter builder, etc.
│   ├── pages/
│   │   ├── contacts/
│   │   ├── companies/
│   │   ├── leads/
│   │   ├── deals/
│   │   ├── activities/
│   │   ├── reports/
│   │   ├── settings/
│   │   └── deal-rooms/
│   ├── stores/                    # Zustand stores
│   ├── hooks/                     # Custom React hooks
│   ├── lib/                       # Utility functions
│   ├── types/                     # TypeScript types
│   ├── eldrin-crm.tsx             # single-spa entry
│   ├── root.component.tsx         # Main React component + router
│   ├── main.tsx                   # Standalone dev entry
│   └── index.css                  # daisyUI theme
├── worker/                        # Hono backend
│   ├── index.ts                   # Hono app + route mounting
│   ├── db/
│   │   ├── schema.ts              # Drizzle schema (all tables)
│   │   └── index.ts               # DB factory
│   ├── routes/                    # Route handlers (per resource)
│   ├── services/                  # Business logic layer
│   ├── middleware/                # Permission, rate limiting
│   └── migrations.generated.ts    # Auto-generated
├── package.json
├── vite.config.ts
├── wrangler.jsonc
├── tsconfig.json                  # Project references
├── tsconfig.app.json              # Frontend
├── tsconfig.worker.json           # Worker
├── tsconfig.node.json             # Build scripts
└── worker-configuration.d.ts      # Env types
```

---

## Super-Phase Structure

The implementation is organised into **super-phases** that map to the 8 requirement phases. Each super-phase contains **sub-phases** with detailed PLAN.md and STATUS.md files.

```
docs/eldrin-crm-implementation/
├── eldrin-crm-requirements.md              # Requirements document
├── eldrin-crm-plan.md                      # This file (master plan)
├── HOW_TO.md                               # Quick-reference guide
│
├── 01_core_crm_foundation_mvp/             # Super Phase 1 (MVP)
│   ├── PLAN.md                             # MVP overview + architecture
│   ├── STATUS.md                           # Tracks 11 sub-phases
│   └── phases/
│       ├── phase-01-project-scaffolding/   # Repo setup, Hono, Drizzle, manifest
│       ├── phase-02-contact-company-management/  # REQ-1.1
│       ├── phase-03-lead-management/       # REQ-1.2
│       ├── phase-04-deal-pipeline-management/    # REQ-1.3
│       ├── phase-05-activity-task-management/    # REQ-1.4
│       ├── phase-06-basic-reporting-dashboards/  # REQ-1.5
│       ├── phase-07-email-integration/     # REQ-1.6
│       ├── phase-08-data-import-export/    # REQ-1.7
│       ├── phase-09-system-ux-foundations/ # REQ-1.9
│       ├── phase-10-zero-data-entry/       # REQ-1.10 ★
│       └── phase-11-buyer-side-deal-rooms/ # REQ-1.11 ★
│
├── 02_sales_automation_productivity/       # Super Phase 2
│   ├── PLAN.md                             # Phase 2 overview
│   └── STATUS.md                           # Tracks 10 sub-phases
│
└── (03–08 super-phases created when Phase 2 nears completion)
```

---

## Implementation Order

### Super Phase 1: Core CRM Foundation (MVP)

**97 requirements** (59 Must, 26 Should, 12 Could) across 11 sub-phases.

Detailed plan: [01_core_crm_foundation_mvp/PLAN.md](01_core_crm_foundation_mvp/PLAN.md)

```
01 → 02 → 03 → 04 → 05 → 06 → 07 → 08 → 09 → 10 → 11
```

| # | Sub-Phase | Req Module | Effort | Status |
|---|-----------|------------|--------|--------|
| 01 | Project Scaffolding | — | Medium | not_started |
| 02 | Contact & Company Management | 1.1 | Large | not_started |
| 03 | Lead Management | 1.2 | Medium | not_started |
| 04 | Deal / Pipeline Management | 1.3 | Large | not_started |
| 05 | Activity & Task Management | 1.4 | Medium | not_started |
| 06 | Basic Reporting & Dashboards | 1.5 | Medium | not_started |
| 07 | Email Integration | 1.6 | Medium | not_started |
| 08 | Data Import / Export | 1.7 | Medium | not_started |
| 09 | System & UX Foundations | 1.9 | Medium | not_started |
| 10 | Zero Data Entry & Auto-Capture ★ | 1.10 | X-Large | not_started |
| 11 | Buyer-Side Deal Rooms ★ | 1.11 | X-Large | not_started |

> **Note**: REQ-1.8 (Users, Roles & Permissions) has no sub-phase — auth/RBAC is already in eldrin-core.

**MVP Boundary**: Sub-phases 01–09 deliver a functional CRM. Sub-phases 10–11 add the differentiators.

### Super Phase 2: Sales Automation & Productivity

**57 requirements** (26 Must, 20 Should, 11 Could) across 10 sub-phases.

Detailed plan: [02_sales_automation_productivity/PLAN.md](02_sales_automation_productivity/PLAN.md)

| # | Sub-Phase | Req Module | Effort | Status |
|---|-----------|------------|--------|--------|
| 01 | Workflow Automation Engine | 2.1 | Large | not_started |
| 02 | Email Sequences & Cadences | 2.2 | Medium | not_started |
| 03 | Product & Price Book Management | 2.3 | Medium | not_started |
| 04 | Quote & Proposal Management | 2.4 | Large | not_started |
| 05 | Sales Forecasting | 2.5 | Medium | not_started |
| 06 | Advanced Customisation | 2.6 | X-Large | not_started |
| 07 | Document Management | 2.7 | Medium | not_started |
| 08 | Bulk Operations | 2.8 | Medium | not_started |
| 09 | Relationship Intelligence ★ | 2.9 | Large | not_started |
| 10 | Industry Playbooks ★ | 2.10 | Large | not_started |

### Super Phases 3–8: Future (planned, not yet elaborated)

These super-phases will be elaborated when Phase 2 nears completion.

| # | Super Phase | Modules | Req Count |
|---|-------------|---------|-----------|
| 3 | Marketing & Communication | Campaigns, Email Marketing, Landing Pages, Chat, SMS, Social | 31 |
| 4 | Customer Service & Support | Ticketing, SLA, Knowledge Base, Portal, Surveys, RevOps ★ | 37 |
| 5 | Advanced Analytics & BI | Custom Reports, Dashboards, Revenue Analytics, Productivity | 19 |
| 6 | Integration Platform | REST API, Webhooks, Integrations, Migration, Mobile, Composable ★ | 38 |
| 7 | AI & Intelligent Automation | AI Scoring, Copilot, Conversation Intel, Predictive | 16 |
| 8 | Enterprise Features & Scale | Multi-currency, Territories, Approvals, Compliance, PRM, Field Service, Commerce | 25 |

---

## Dependencies (Super Phase 1)

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

---

## Reference

- **Requirements**: `docs/eldrin-crm-implementation/eldrin-crm-requirements.md`
- **Workflow reference implementation**: `eldrin-workflows/` (Hono + Drizzle pattern)
- **SDK database adapter**: `eldrin-app-core/src/database/interface.ts`
- **React-todo (extension app pattern)**: `react-todo/`
- **Drizzle ORM docs**: https://orm.drizzle.team
