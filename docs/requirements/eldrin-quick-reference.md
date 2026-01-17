# Eldrin Platform - Quick Reference & Checklist

## Architecture At-a-Glance

```
┌─────────────────────────────────────────────────────────────┐
│              CUSTOMER CLOUDFLARE WORKER                      │
│  ┌────────────────────────────────────────────────────────┐ │
│  │           ELDRIN SHELL (React + Vite + single-spa)     │ │
│  │  Auth │ Navigation │ Orchestrator │ Theming │ Events   │ │
│  └────────────────────────────────────────────────────────┘ │
│       │           │            │            │               │
│  ┌────┴───┐  ┌────┴───┐  ┌────┴───┐  ┌────┴───┐           │
│  │Catalog │  │Invoice │  │  CRM   │  │B2B E-Com│           │
│  │  App   │  │  App   │  │  App   │  │  App    │           │
│  └────┬───┘  └────┬───┘  └────┬───┘  └────┬───┘           │
└───────│───────────│───────────│───────────│────────────────┘
        ▼           ▼           ▼           ▼
   [D1 + R2]   [D1 + R2]   [D1 + R2]   [D1 + R2]
```

---

## Key Decisions Summary

| Area | Decision |
|------|----------|
| **Platform Name** | Eldrin |
| **Addons Called** | Apps |
| **Frontend** | React + Vite |
| **Micro-frontend** | single-spa + Module Federation (security) |
| **State** | Zustand (events + shared atoms) |
| **Deployment** | Single-tenant (customer owns worker) |
| **Database** | D1 per app (default), extensible |
| **Storage** | Cloudflare R2 |
| **Auth** | Custom JWT (service-to-service) |
| **Permissions** | CRUD-based MVP (`resource:action`) |
| **Marketplace** | Centralized + custom registries |
| **Payments** | Stripe Connect |
| **Timeline** | 4-6 months to MVP |

---

## First-Party Apps

| App | Dependencies | Priority |
|-----|--------------|----------|
| **Catalog** | None | P0 |
| **CRM** | None | P0 |
| **Invoicing** | Catalog | P1 |
| **B2B E-Commerce** | Catalog, CRM, Invoicing | P2 |

---

## Implementation Checklist

### Phase 1: Foundation (Weeks 1-6)

- [ ] **Core Shell Setup**
  - [ ] React + Vite project scaffolding
  - [ ] single-spa orchestration
  - [ ] Module Federation configuration
  - [ ] Cloudflare Worker template (React Vite)

- [ ] **Authentication**
  - [ ] User registration
  - [ ] Login/logout
  - [ ] JWT token generation
  - [ ] Session management
  - [ ] Service-to-service token flow

- [ ] **App Loading**
  - [ ] NPM package loading (build-time)
  - [ ] Dynamic CDN loading (runtime)
  - [ ] Manifest parsing & validation
  - [ ] Dependency resolution (semver)
  - [ ] Code signature verification

- [ ] **Permission System**
  - [ ] CRUD permissions (`resource:read/write/delete`)
  - [ ] Role definitions per app
  - [ ] Permission checking API
  - [ ] UI permission guards

- [ ] **Navigation**
  - [ ] Dynamic side navigation
  - [ ] Top navigation
  - [ ] User menu
  - [ ] Route registration

### Phase 2: First Apps (Weeks 7-12)

- [ ] **Catalog App**
  - [ ] Categories (hierarchical)
  - [ ] Products with variants
  - [ ] Services
  - [ ] Basic pricing
  - [ ] Import/export
  - [ ] Exported hooks & events

- [ ] **CRM App**
  - [ ] Contacts CRUD
  - [ ] Companies CRUD
  - [ ] Deals/opportunities
  - [ ] Activities & notes
  - [ ] Exported hooks & events

- [ ] **Invoicing App**
  - [ ] Invoice CRUD
  - [ ] Template system
  - [ ] PDF generation
  - [ ] Payment tracking
  - [ ] Integration with Catalog
  - [ ] Exported hooks & events

- [ ] **Inter-App Communication**
  - [ ] Event bus (Zustand)
  - [ ] Hook system
  - [ ] Smart routing (direct + fallback)

### Phase 3: Advanced Features (Weeks 13-18)

- [ ] **Dashboard System**
  - [ ] Widget registry
  - [ ] Fixed grid layout
  - [ ] Drag-and-drop customization
  - [ ] Widget configuration

- [ ] **Context Menus**
  - [ ] Global context menu system
  - [ ] Context type registration
  - [ ] Permission filtering

- [ ] **Keyboard Shortcuts**
  - [ ] Global shortcut registry
  - [ ] Scoped shortcuts (per app)
  - [ ] Conflict detection
  - [ ] Priority system

- [ ] **Theming**
  - [ ] CSS custom properties
  - [ ] Theme configuration API
  - [ ] White-label support
  - [ ] Logo & branding

- [ ] **Settings Framework**
  - [ ] Settings categories
  - [ ] App settings pages
  - [ ] Per-app configuration

- [ ] **B2B E-Commerce App**
  - [ ] Storefront
  - [ ] Customer portals
  - [ ] Tiered pricing
  - [ ] Order management

### Phase 4: Marketplace & DX (Weeks 19-24)

- [ ] **Developer CLI**
  - [ ] `eldrin create` scaffolding
  - [ ] `eldrin dev` local development
  - [ ] `eldrin build` production build
  - [ ] `eldrin publish` marketplace publishing

- [ ] **SDK**
  - [ ] `@eldrin/sdk` package
  - [ ] `createApp()` helper
  - [ ] React hooks (`useEldrin`, `usePermission`)
  - [ ] TypeScript definitions

- [ ] **Testing Infrastructure**
  - [ ] Unit test helpers & mocks
  - [ ] Integration sandbox environment
  - [ ] Sample fixtures

- [ ] **Marketplace Backend**
  - [ ] App registry (metadata DB)
  - [ ] CDN for app bundles (R2)
  - [ ] Version management
  - [ ] Search & discovery

- [ ] **Review System**
  - [ ] Automated security scans
  - [ ] Manifest validation
  - [ ] Manual review queue
  - [ ] Badge system (Unverified/Verified)

- [ ] **Community Features**
  - [ ] Ratings & reviews
  - [ ] Flagging system
  - [ ] Install counts

- [ ] **Payment Integration**
  - [ ] Stripe Connect setup
  - [ ] Developer payouts
  - [ ] Commission handling
  - [ ] Subscription management

- [ ] **Developer Portal**
  - [ ] Documentation site
  - [ ] API playground
  - [ ] Publishing dashboard
  - [ ] Analytics dashboard

---

## Security Checklist

- [ ] Code signing for marketplace apps
- [ ] Signature verification at load time
- [ ] Content Security Policy (CSP)
- [ ] Permission declaration in manifests
- [ ] Scoped service tokens
- [ ] Rate limiting
- [ ] Automated security scans
- [ ] Manual review process
- [ ] Circuit breaker for failing apps
- [ ] Error boundaries

---

## Manifest Required Fields

```yaml
# Minimum viable manifest
id: "my-app"              # Required
name: "My App"            # Required
version: "1.0.0"          # Required (semver)
compatibility:
  core: ">=1.0.0"         # Required
```

---

## Key Files & Locations

| File | Purpose |
|------|---------|
| `eldrin-app.manifest.json` | App metadata and integrations |
| `eldrin.config.ts` | Customer deployment config |
| `wrangler.toml` | Cloudflare Worker config |
| `src/index.ts` | App entry point |
| `src/lifecycle.ts` | Lifecycle hooks |
| `src/hooks/index.ts` | Exported hooks |
| `worker/schema.sql` | D1 database schema |

---

## API Quick Reference

```typescript
// Access SDK in components
const eldrin = useEldrin();

// Check permissions
const canEdit = usePermission('invoices:write');

// Call other app's hook
const invoice = await eldrin.apps.call('invoicing', 'getInvoiceById', { id });

// Emit event
eldrin.apps.emit('invoice:created', { invoiceId, total });

// Listen to events
eldrin.apps.on('invoice:paid', (payload) => { /* ... */ });

// Navigate
eldrin.navigation.navigate('/invoices/new');

// Get current user
const user = eldrin.auth.getCurrentUser();

// Get theme
const theme = eldrin.theme.getTheme();

// Get locale
const locale = eldrin.i18n.getLocale(); // "en-US"
```

---

## Contact & Resources

- **Spec Document**: `eldrin-technical-requirements.md`
- **Target MVP Date**: ~6 months from project start
- **First Milestone**: Core shell with app loading (Week 6)
