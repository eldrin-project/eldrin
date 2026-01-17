# Eldrin App Frontend Design Requirements

**Version:** 1.0.0  
**Date:** December 2024  
**Status:** Draft  
**Audience:** App Developers

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [App Architecture](#2-app-architecture)
3. [Theme Integration](#3-theme-integration)
4. [Required Components](#4-required-components)
5. [UI Integration Points](#5-ui-integration-points)
6. [Layout Patterns](#6-layout-patterns)
7. [Component Guidelines](#7-component-guidelines)
8. [Data Display Patterns](#8-data-display-patterns)
9. [Forms & Input](#9-forms--input)
10. [Feedback & States](#10-feedback--states)
11. [Localization](#11-localization)
12. [Performance Requirements](#12-performance-requirements)
13. [Testing Requirements](#13-testing-requirements)
14. [Submission Checklist](#14-submission-checklist)

---

## 1. Introduction

### 1.1 Purpose

This document provides frontend design requirements and guidelines for developers building apps for the Eldrin platform. Following these guidelines ensures:

- Visual consistency across all apps
- Seamless integration with customer themes
- Optimal user experience
- Successful marketplace review

### 1.2 Philosophy

Apps should feel like **natural extensions** of Eldrin, not foreign plugins. Users should experience a unified platform, not a collection of disconnected tools.

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│    ❌ BAD: App feels foreign                                    │
│    ┌─────────────────────────────────────────────────────────┐  │
│    │  ELDRIN SHELL                                           │  │
│    │  ┌─────────────────────────────────────────────────┐    │  │
│    │  │  ╔═══════════════════════════════════════════╗  │    │  │
│    │  │  ║  APP WITH DIFFERENT FONTS, COLORS,        ║  │    │  │
│    │  │  ║  SPACING, AND STYLING                     ║  │    │  │
│    │  │  ╚═══════════════════════════════════════════╝  │    │  │
│    │  └─────────────────────────────────────────────────┘    │  │
│    └─────────────────────────────────────────────────────────┘  │
│                                                                 │
│    ✅ GOOD: App feels native                                    │
│    ┌─────────────────────────────────────────────────────────┐  │
│    │  ELDRIN SHELL                                           │  │
│    │  ┌─────────────────────────────────────────────────┐    │  │
│    │  │  App content using shell's design system,       │    │  │
│    │  │  tokens, and components seamlessly              │    │  │
│    │  └─────────────────────────────────────────────────┘    │  │
│    └─────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 1.3 Key Requirements

| Requirement | Description |
|-------------|-------------|
| **Use Design Tokens** | All colors, spacing, typography via CSS custom properties |
| **Theme Compliance** | App must work with any customer theme |
| **Responsive Design** | Support all breakpoints (mobile to desktop) |
| **Accessibility** | WCAG 2.1 AA compliance |
| **Performance** | First paint < 1s, interactive < 2s |

---

## 2. App Architecture

### 2.1 App Entry Point

Apps are mounted as single-spa parcels within the Eldrin shell:

```typescript
// src/index.ts - App entry point
import { createApp } from '@eldrin/sdk';
import { App } from './App';
import { lifecycle } from './lifecycle';
import { hooks } from './hooks';

export default createApp({
  id: 'my-app',
  App,           // Root React component
  lifecycle,     // Lifecycle hooks
  hooks,         // Exported hooks for other apps
});
```

### 2.2 Root Component Structure

```typescript
// src/App.tsx
import { EldrinProvider, useEldrin } from '@eldrin/sdk';
import { Routes, Route } from 'react-router-dom';
import { AppLayout } from './layouts/AppLayout';
import { ProductList } from './pages/ProductList';
import { ProductDetail } from './pages/ProductDetail';

export function App() {
  return (
    <AppLayout>
      <Routes>
        <Route path="/" element={<ProductList />} />
        <Route path="/:id" element={<ProductDetail />} />
      </Routes>
    </AppLayout>
  );
}
```

### 2.3 File Structure

```
my-app/
├── src/
│   ├── index.ts              # App entry point
│   ├── App.tsx               # Root component
│   │
│   ├── components/           # App-specific components
│   │   ├── ProductCard/
│   │   ├── InvoiceRow/
│   │   └── ...
│   │
│   ├── pages/               # Page components
│   │   ├── List/
│   │   ├── Detail/
│   │   ├── Create/
│   │   └── Settings/
│   │
│   ├── layouts/             # Layout components
│   │   └── AppLayout.tsx
│   │
│   ├── hooks/               # Custom React hooks
│   │   ├── useProducts.ts
│   │   └── ...
│   │
│   ├── stores/              # Zustand stores
│   │   └── productStore.ts
│   │
│   ├── services/            # API services
│   │   └── api.ts
│   │
│   ├── widgets/             # Dashboard widgets
│   │   ├── SummaryWidget.tsx
│   │   └── RecentWidget.tsx
│   │
│   ├── settings/            # Settings page components
│   │   └── GeneralSettings.tsx
│   │
│   ├── locales/             # Translations
│   │   ├── en-US.json
│   │   └── de-DE.json
│   │
│   └── styles/              # App-specific styles
│       └── components.css
│
├── eldrin-app.manifest.json
└── package.json
```

---

## 3. Theme Integration

### 3.1 Mandatory Token Usage

Apps **MUST** use Eldrin's CSS custom properties for all visual styling:

```css
/* ✅ CORRECT - Using design tokens */
.product-card {
  background: var(--color-bg-surface);
  border: 1px solid var(--color-border-default);
  border-radius: var(--radius-md);
  padding: var(--space-4);
}

.product-title {
  font-family: var(--font-heading);
  font-size: var(--text-lg);
  color: var(--color-text-primary);
}

/* ❌ WRONG - Hardcoded values */
.product-card {
  background: #ffffff;
  border: 1px solid #e5e5e5;
  border-radius: 8px;
  padding: 16px;
}

.product-title {
  font-family: Inter, sans-serif;
  font-size: 20px;
  color: #111111;
}
```

### 3.2 Available Design Tokens

#### Colors

```css
/* Backgrounds */
--color-bg-page          /* Page background */
--color-bg-surface       /* Card/panel background */
--color-bg-elevated      /* Elevated surfaces */
--color-bg-sunken        /* Recessed areas */
--color-bg-overlay       /* Modal overlays */

/* Text */
--color-text-primary     /* Main text */
--color-text-secondary   /* Supporting text */
--color-text-tertiary    /* Subtle text */
--color-text-disabled    /* Disabled state */
--color-text-inverse     /* Light text on dark bg */
--color-text-link        /* Link text */

/* Borders */
--color-border-default   /* Standard borders */
--color-border-subtle    /* Subtle dividers */
--color-border-strong    /* Emphasized borders */
--color-border-focus     /* Focus ring color */

/* Actions */
--color-action-primary        /* Primary button/link */
--color-action-primary-hover  /* Primary hover state */
--color-action-secondary      /* Secondary action */
--color-action-secondary-hover

/* Status */
--color-status-success   /* Success states */
--color-status-warning   /* Warning states */
--color-status-error     /* Error states */
--color-status-info      /* Info states */
```

#### Typography

```css
/* Font families */
--font-heading     /* Headings (monospace) */
--font-body        /* Body text (sans-serif) */
--font-mono        /* Code/data (monospace) */

/* Font sizes */
--text-xs          /* 10.24px */
--text-sm          /* 12.8px */
--text-base        /* 16px */
--text-lg          /* 20px */
--text-xl          /* 25px */
--text-2xl         /* 31.25px */
--text-3xl         /* 39px */

/* Font weights */
--weight-normal    /* 400 */
--weight-medium    /* 500 */
--weight-semibold  /* 600 */
--weight-bold      /* 700 */

/* Line heights */
--leading-tight    /* 1.2 */
--leading-snug     /* 1.35 */
--leading-normal   /* 1.5 */
--leading-relaxed  /* 1.65 */
```

#### Spacing

```css
--space-0    /* 0 */
--space-1    /* 4px */
--space-2    /* 8px */
--space-3    /* 12px */
--space-4    /* 16px */
--space-5    /* 24px */
--space-6    /* 32px */
--space-7    /* 48px */
--space-8    /* 64px */
```

#### Sizes & Radius

```css
/* Component heights */
--size-xs    /* 24px */
--size-sm    /* 32px */
--size-md    /* 40px */
--size-lg    /* 48px */

/* Border radius */
--radius-none   /* 0 */
--radius-sm     /* 2px */
--radius-md     /* 4px */
--radius-lg     /* 6px */
--radius-full   /* 9999px */
```

#### Shadows

```css
--shadow-sm        /* Subtle shadow */
--shadow-md        /* Medium shadow */
--shadow-lg        /* Large shadow */
--shadow-xl        /* Extra large shadow */
--shadow-elevated  /* Offset shadow (signature style) */
--shadow-focus     /* Focus ring shadow */
```

### 3.3 Theme-Safe Patterns

```css
/* Ensure sufficient contrast in any theme */
.status-badge-success {
  /* Use semantic colors - they adapt to theme */
  background: rgba(34, 197, 94, 0.1);
  color: var(--color-status-success);
}

/* Alpha transparency for overlays */
.overlay {
  background: var(--color-bg-overlay);
}

/* Use semantic shadows - they adapt to theme */
.dropdown {
  box-shadow: var(--shadow-lg);
}
```

### 3.4 Testing Theme Compliance

Before submission, test your app with:

1. **Light theme** (default)
2. **Dark theme**
3. **Custom brand colors** (high saturation primary)
4. **Inverted colors** (light primary on dark)

```bash
# Use CLI to test with different themes
eldrin dev --theme light
eldrin dev --theme dark
eldrin dev --theme custom --primary "#FF6600"
```

---

## 4. Required Components

### 4.1 Using Core Components

Apps should use Eldrin's component library for consistency:

```typescript
import {
  Button,
  Input,
  Select,
  Card,
  Modal,
  Table,
  Badge,
  Toast,
  Dropdown,
  Tabs,
  Tooltip,
  Skeleton,
  EmptyState,
  ErrorBoundary
} from '@eldrin/ui';
```

### 4.2 Button Usage

```typescript
import { Button } from '@eldrin/ui';

// Variants
<Button variant="primary">Save</Button>
<Button variant="secondary">Cancel</Button>
<Button variant="ghost">Learn More</Button>
<Button variant="danger">Delete</Button>

// Sizes
<Button size="sm">Small</Button>
<Button size="md">Medium</Button>
<Button size="lg">Large</Button>

// States
<Button loading>Saving...</Button>
<Button disabled>Unavailable</Button>

// With icon
<Button leftIcon={<PlusIcon />}>Add Item</Button>
<Button rightIcon={<ChevronRightIcon />}>Next</Button>
```

### 4.3 Form Components

```typescript
import { Input, Select, Checkbox, Radio, Switch, TextArea } from '@eldrin/ui';

// Input with label
<Input
  label="Product Name"
  placeholder="Enter product name"
  value={name}
  onChange={setName}
  error={errors.name}
  required
/>

// Select
<Select
  label="Category"
  options={categories}
  value={category}
  onChange={setCategory}
  placeholder="Select a category"
/>

// Checkbox group
<Checkbox.Group
  label="Features"
  value={selectedFeatures}
  onChange={setSelectedFeatures}
>
  <Checkbox value="recurring">Recurring billing</Checkbox>
  <Checkbox value="reminders">Payment reminders</Checkbox>
</Checkbox.Group>
```

### 4.4 Data Display Components

```typescript
import { Table, Card, Badge, Stat } from '@eldrin/ui';

// Table
<Table
  columns={[
    { key: 'name', header: 'Name', sortable: true },
    { key: 'status', header: 'Status', render: (row) => (
      <Badge variant={row.status}>{row.status}</Badge>
    )},
    { key: 'amount', header: 'Amount', align: 'right' },
  ]}
  data={invoices}
  onRowClick={(row) => navigate(`/invoices/${row.id}`)}
  pagination
  selectable
/>

// Stat card
<Stat
  label="Total Revenue"
  value="$45,230"
  change={{ value: 12.5, direction: 'up' }}
  icon={<DollarIcon />}
/>
```

### 4.5 Feedback Components

```typescript
import { Toast, Modal, Alert, Skeleton } from '@eldrin/ui';

// Toast notifications (via hook)
const { toast } = useToast();
toast.success('Invoice saved successfully');
toast.error('Failed to save invoice');

// Modal
<Modal
  open={isOpen}
  onClose={() => setIsOpen(false)}
  title="Confirm Delete"
  size="sm"
>
  <Modal.Body>
    Are you sure you want to delete this invoice?
  </Modal.Body>
  <Modal.Footer>
    <Button variant="secondary" onClick={() => setIsOpen(false)}>
      Cancel
    </Button>
    <Button variant="danger" onClick={handleDelete}>
      Delete
    </Button>
  </Modal.Footer>
</Modal>

// Loading skeleton
<Skeleton variant="text" width="200px" />
<Skeleton variant="rectangle" width="100%" height="200px" />
<Skeleton variant="circle" size="48px" />
```

---

## 5. UI Integration Points

### 5.1 Dashboard Widgets

Apps can provide dashboard widgets that users can add to their dashboard:

```typescript
// src/widgets/InvoiceSummaryWidget.tsx
import { Widget } from '@eldrin/sdk';
import { Stat } from '@eldrin/ui';

interface InvoiceSummaryConfig {
  showPending: boolean;
  showOverdue: boolean;
}

export const InvoiceSummaryWidget: Widget<InvoiceSummaryConfig> = {
  id: 'invoice-summary',
  name: 'Invoice Summary',
  description: 'Overview of invoice statistics',
  defaultSize: 'medium',
  configurable: true,
  
  // Configuration UI
  ConfigPanel: ({ config, onChange }) => (
    <div>
      <Checkbox
        checked={config.showPending}
        onChange={(v) => onChange({ ...config, showPending: v })}
      >
        Show pending invoices
      </Checkbox>
    </div>
  ),
  
  // Widget content
  Component: ({ config }) => {
    const { data, loading } = useInvoiceStats();
    
    if (loading) return <WidgetSkeleton />;
    
    return (
      <div className="invoice-summary-widget">
        <Stat label="Total" value={data.total} />
        {config.showPending && (
          <Stat label="Pending" value={data.pending} />
        )}
      </div>
    );
  }
};
```

#### Widget Size Guidelines

| Size | Grid Columns | Min Height | Use Case |
|------|--------------|------------|----------|
| `small` | 3 | 150px | Single stat, quick action |
| `medium` | 4 | 200px | Multiple stats, mini chart |
| `large` | 6 | 300px | List, detailed chart |
| `full` | 12 | 200px | Table, timeline |

### 5.2 Settings Pages

Apps can add pages to the Settings section:

```typescript
// src/settings/InvoiceSettings.tsx
import { SettingsPage } from '@eldrin/sdk';
import { Input, Select, Switch, Button } from '@eldrin/ui';

export const InvoiceSettings: SettingsPage = {
  id: 'invoicing-general',
  label: 'General',
  category: 'apps',
  
  Component: () => {
    const { settings, updateSettings, saving } = useAppSettings();
    
    return (
      <SettingsSection title="Invoice Defaults">
        <SettingsField
          label="Payment Terms"
          description="Default payment terms for new invoices"
        >
          <Select
            value={settings.paymentTerms}
            onChange={(v) => updateSettings({ paymentTerms: v })}
            options={[
              { value: 'net-15', label: 'Net 15' },
              { value: 'net-30', label: 'Net 30' },
              { value: 'net-60', label: 'Net 60' },
            ]}
          />
        </SettingsField>
        
        <SettingsField
          label="Auto-numbering"
          description="Automatically generate invoice numbers"
        >
          <Switch
            checked={settings.autoNumber}
            onChange={(v) => updateSettings({ autoNumber: v })}
          />
        </SettingsField>
        
        <SettingsField
          label="Invoice Prefix"
          description="Prefix for invoice numbers (e.g., INV-)"
        >
          <Input
            value={settings.prefix}
            onChange={(v) => updateSettings({ prefix: v })}
            placeholder="INV-"
          />
        </SettingsField>
      </SettingsSection>
    );
  }
};
```

### 5.3 Context Menu Items

Apps can add items to context menus:

```typescript
// In manifest
contextMenus:
  - context: "contact"
    items:
      - label: "Create Invoice"
        icon: "file-plus"
        action: "createInvoiceForContact"
        permission: "invoicing:write"

// Action handler
export const contextMenuHandlers = {
  createInvoiceForContact: async (contextData: ContactContext) => {
    const { contactId, contactName } = contextData;
    // Navigate to invoice creation with pre-filled contact
    navigate('/invoices/new', { 
      state: { customerId: contactId, customerName: contactName } 
    });
  }
};
```

### 5.4 Command Palette Actions

Apps can register commands in the global command palette:

```typescript
// src/commands.ts
import { Command } from '@eldrin/sdk';

export const commands: Command[] = [
  {
    id: 'invoicing:create-invoice',
    label: 'Create Invoice',
    keywords: ['new invoice', 'add invoice', 'bill'],
    icon: 'file-plus',
    action: () => navigate('/invoices/new'),
    permission: 'invoicing:write',
  },
  {
    id: 'invoicing:search',
    label: 'Search Invoices',
    keywords: ['find invoice', 'lookup'],
    icon: 'search',
    action: () => openInvoiceSearch(),
  }
];
```

---

## 6. Layout Patterns

### 6.1 Page Layout Structure

```typescript
// Standard page layout
import { PageLayout, PageHeader, PageContent } from '@eldrin/ui';

function ProductListPage() {
  return (
    <PageLayout>
      <PageHeader
        title="Products"
        description="Manage your product catalog"
        actions={
          <Button leftIcon={<PlusIcon />}>Add Product</Button>
        }
      />
      <PageContent>
        {/* Page content here */}
      </PageContent>
    </PageLayout>
  );
}
```

### 6.2 Page Header Pattern

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  Products                                        [+ Add Product] │
│  Manage your product catalog                                    │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ [All] [Active] [Draft] [Archived]                       │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

```css
.page-header {
  padding: var(--space-5) var(--space-6);
  background: var(--color-bg-surface);
  border-bottom: 1px solid var(--color-border-default);
}

.page-header-top {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--space-4);
}

.page-title {
  font-family: var(--font-heading);
  font-size: var(--text-2xl);
  font-weight: var(--weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--space-1);
}

.page-description {
  font-size: var(--text-sm);
  color: var(--color-text-secondary);
}
```

### 6.3 List Page Pattern

```
┌─────────────────────────────────────────────────────────────────┐
│  [Search...                    ]  [Filter ▼]  [Sort ▼]  [⋮]    │
├─────────────────────────────────────────────────────────────────┤
│  □  Name              Status      Amount      Date       ⋮     │
├─────────────────────────────────────────────────────────────────┤
│  □  Invoice #1234     Paid        $1,200      Dec 15     ⋮     │
│  □  Invoice #1235     Pending     $450        Dec 14     ⋮     │
│  □  Invoice #1236     Overdue     $2,100      Dec 10     ⋮     │
├─────────────────────────────────────────────────────────────────┤
│  Showing 1-10 of 156                        [◀] 1 2 3 ... [▶]  │
└─────────────────────────────────────────────────────────────────┘
```

### 6.4 Detail Page Pattern

```
┌─────────────────────────────────────────────────────────────────┐
│  ← Back to Invoices                                             │
│                                                                 │
│  Invoice #1234                              [Edit] [▼ Actions]  │
│  Created Dec 15, 2024                                           │
│                                                                 │
├──────────────────────────────────┬──────────────────────────────┤
│                                  │                              │
│  DETAILS                         │  SUMMARY                     │
│  ─────────────────────────────   │  ─────────────────────────   │
│                                  │                              │
│  Customer: Acme Corp             │  Subtotal:      $1,000.00   │
│  Due Date: Dec 30, 2024          │  Tax (10%):       $100.00   │
│  Status:   Pending               │  ─────────────────────────   │
│                                  │  Total:         $1,100.00   │
│                                  │                              │
│  LINE ITEMS                      │  [Mark as Paid]              │
│  ─────────────────────────────   │  [Send Reminder]             │
│                                  │  [Download PDF]              │
│  Widget Pro × 2    $400.00       │                              │
│  Service Fee       $600.00       │                              │
│                                  │                              │
└──────────────────────────────────┴──────────────────────────────┘
```

### 6.5 Form Page Pattern

```
┌─────────────────────────────────────────────────────────────────┐
│  ← Back                                                         │
│                                                                 │
│  Create Invoice                                                 │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Customer *                                                     │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Search customers...                                     │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌────────────────────────┐  ┌────────────────────────────┐    │
│  │ Invoice Date *         │  │ Due Date *                 │    │
│  │ [Dec 16, 2024      📅] │  │ [Dec 30, 2024         📅] │    │
│  └────────────────────────┘  └────────────────────────────┘    │
│                                                                 │
│  Line Items                                           [+ Add]   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Description          Qty    Unit Price    Total    [×]  │  │
│  ├──────────────────────────────────────────────────────────┤  │
│  │  [Widget Pro       ]  [2 ]   [$200.00  ]   $400.00  [×]  │  │
│  │  [Service Fee      ]  [1 ]   [$600.00  ]   $600.00  [×]  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│                                        Subtotal:    $1,000.00   │
│                                        Tax (10%):     $100.00   │
│                                        ─────────────────────    │
│                                        Total:       $1,100.00   │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                    [Cancel]  [Save as Draft]    │
│                                              [Create & Send]    │
└─────────────────────────────────────────────────────────────────┘
```

---

## 7. Component Guidelines

### 7.1 Custom Component Requirements

When building custom components (not using @eldrin/ui):

```typescript
// ✅ CORRECT - Custom component following guidelines
function ProductCard({ product, onClick }: ProductCardProps) {
  return (
    <article 
      className="product-card"
      onClick={onClick}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => e.key === 'Enter' && onClick?.()}
    >
      <img 
        src={product.image} 
        alt={product.name}
        className="product-card-image"
      />
      <div className="product-card-content">
        <h3 className="product-card-title">{product.name}</h3>
        <p className="product-card-price">
          {formatCurrency(product.price)}
        </p>
      </div>
    </article>
  );
}
```

```css
/* Custom component using design tokens */
.product-card {
  display: flex;
  flex-direction: column;
  background: var(--color-bg-surface);
  border: 1px solid var(--color-border-default);
  border-radius: var(--radius-md);
  overflow: hidden;
  cursor: pointer;
  transition: all 150ms ease;
}

.product-card:hover {
  border-color: var(--color-border-strong);
  box-shadow: var(--shadow-md);
}

.product-card:focus-visible {
  outline: none;
  box-shadow: var(--shadow-focus);
}

.product-card-image {
  width: 100%;
  aspect-ratio: 16 / 9;
  object-fit: cover;
  background: var(--color-bg-sunken);
}

.product-card-content {
  padding: var(--space-4);
}

.product-card-title {
  font-family: var(--font-body);
  font-size: var(--text-base);
  font-weight: var(--weight-medium);
  color: var(--color-text-primary);
  margin-bottom: var(--space-1);
}

.product-card-price {
  font-family: var(--font-heading);
  font-size: var(--text-lg);
  font-weight: var(--weight-semibold);
  color: var(--color-text-primary);
}
```

### 7.2 Icon Usage

Use Lucide icons for consistency:

```typescript
import { 
  Plus, 
  Search, 
  Filter, 
  Download,
  Trash2,
  Edit,
  MoreVertical,
  ChevronRight,
  Check,
  X,
  AlertCircle,
  Info
} from 'lucide-react';

// Standard icon sizes
<Plus size={16} />   // Small (buttons, badges)
<Plus size={20} />   // Medium (default)
<Plus size={24} />   // Large (headers, empty states)

// Standard stroke width
<Plus strokeWidth={1.5} />
```

### 7.3 Empty States

```typescript
import { EmptyState } from '@eldrin/ui';

<EmptyState
  icon={<FileTextIcon size={48} />}
  title="No invoices yet"
  description="Create your first invoice to get started"
  action={
    <Button leftIcon={<PlusIcon />}>Create Invoice</Button>
  }
/>
```

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│                         ┌──────────┐                            │
│                         │    📄    │                            │
│                         └──────────┘                            │
│                                                                 │
│                      No invoices yet                            │
│              Create your first invoice to get started           │
│                                                                 │
│                      [+ Create Invoice]                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 7.4 Error States

```typescript
import { ErrorState } from '@eldrin/ui';

<ErrorState
  title="Failed to load invoices"
  description="There was a problem connecting to the server"
  action={
    <Button variant="secondary" onClick={retry}>
      Try Again
    </Button>
  }
/>
```

---

## 8. Data Display Patterns

### 8.1 Tables

```typescript
import { DataTable } from '@eldrin/ui';

<DataTable
  columns={[
    { 
      key: 'number', 
      header: 'Invoice #',
      width: '120px',
    },
    { 
      key: 'customer', 
      header: 'Customer',
      render: (row) => (
        <div className="customer-cell">
          <Avatar name={row.customerName} size="sm" />
          <span>{row.customerName}</span>
        </div>
      ),
    },
    { 
      key: 'status', 
      header: 'Status',
      render: (row) => (
        <Badge variant={getStatusVariant(row.status)}>
          {row.status}
        </Badge>
      ),
    },
    { 
      key: 'amount', 
      header: 'Amount',
      align: 'right',
      render: (row) => formatCurrency(row.amount),
    },
    { 
      key: 'date', 
      header: 'Date',
      render: (row) => formatDate(row.date),
      sortable: true,
    },
    {
      key: 'actions',
      header: '',
      width: '48px',
      render: (row) => (
        <DropdownMenu>
          <DropdownMenu.Item onClick={() => edit(row.id)}>
            Edit
          </DropdownMenu.Item>
          <DropdownMenu.Item onClick={() => duplicate(row.id)}>
            Duplicate
          </DropdownMenu.Item>
          <DropdownMenu.Separator />
          <DropdownMenu.Item 
            variant="danger" 
            onClick={() => delete(row.id)}
          >
            Delete
          </DropdownMenu.Item>
        </DropdownMenu>
      ),
    },
  ]}
  data={invoices}
  loading={isLoading}
  emptyState={<InvoiceEmptyState />}
  pagination={{
    page,
    pageSize,
    total,
    onPageChange: setPage,
  }}
  selectable
  onSelectionChange={setSelected}
/>
```

### 8.2 Cards Grid

```typescript
<div className="card-grid">
  {products.map((product) => (
    <ProductCard 
      key={product.id} 
      product={product}
      onClick={() => navigate(`/products/${product.id}`)}
    />
  ))}
</div>
```

```css
.card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: var(--space-4);
}
```

### 8.3 List with Actions

```typescript
<List>
  {contacts.map((contact) => (
    <List.Item
      key={contact.id}
      leading={<Avatar name={contact.name} />}
      primary={contact.name}
      secondary={contact.email}
      trailing={
        <Button variant="ghost" size="sm">
          <MoreVerticalIcon />
        </Button>
      }
      onClick={() => navigate(`/contacts/${contact.id}`)}
    />
  ))}
</List>
```

---

## 9. Forms & Input

### 9.1 Form Structure

```typescript
import { Form, FormField, FormSection } from '@eldrin/ui';

<Form onSubmit={handleSubmit}>
  <FormSection title="Basic Information">
    <FormField
      label="Product Name"
      name="name"
      required
      error={errors.name}
    >
      <Input
        value={values.name}
        onChange={(v) => setFieldValue('name', v)}
        placeholder="Enter product name"
      />
    </FormField>
    
    <FormField
      label="Description"
      name="description"
      hint="Brief description for customers"
    >
      <TextArea
        value={values.description}
        onChange={(v) => setFieldValue('description', v)}
        rows={3}
      />
    </FormField>
  </FormSection>
  
  <FormSection title="Pricing">
    <FormField label="Price" name="price" required>
      <Input
        type="number"
        value={values.price}
        onChange={(v) => setFieldValue('price', v)}
        leftAddon="$"
      />
    </FormField>
  </FormSection>
  
  <Form.Actions>
    <Button variant="secondary" type="button" onClick={cancel}>
      Cancel
    </Button>
    <Button type="submit" loading={isSubmitting}>
      Save Product
    </Button>
  </Form.Actions>
</Form>
```

### 9.2 Validation Patterns

```typescript
// Real-time validation feedback
<FormField
  label="Email"
  name="email"
  error={touched.email && errors.email}
  success={touched.email && !errors.email && "Email is available"}
>
  <Input
    type="email"
    value={values.email}
    onChange={handleChange}
    onBlur={handleBlur}
  />
</FormField>

// Inline validation messages
<Input
  error="This field is required"
  // or
  error={
    <span>
      Password must include <strong>8+ characters</strong>
    </span>
  }
/>
```

### 9.3 Complex Inputs

```typescript
// Search/autocomplete
<SearchSelect
  label="Customer"
  placeholder="Search customers..."
  options={customers}
  value={selectedCustomer}
  onChange={setSelectedCustomer}
  onSearch={searchCustomers}
  renderOption={(customer) => (
    <div className="customer-option">
      <Avatar name={customer.name} size="sm" />
      <div>
        <div>{customer.name}</div>
        <div className="text-secondary">{customer.email}</div>
      </div>
    </div>
  )}
/>

// Date picker
<DatePicker
  label="Due Date"
  value={dueDate}
  onChange={setDueDate}
  minDate={new Date()}
/>

// File upload
<FileUpload
  label="Attachments"
  accept={['image/*', '.pdf']}
  maxSize={5 * 1024 * 1024} // 5MB
  multiple
  onUpload={handleUpload}
/>
```

---

## 10. Feedback & States

### 10.1 Loading States

```typescript
// Page loading
function ProductListPage() {
  const { data, loading, error } = useProducts();
  
  if (loading) {
    return (
      <PageLayout>
        <PageHeader.Skeleton />
        <PageContent>
          <TableSkeleton rows={5} />
        </PageContent>
      </PageLayout>
    );
  }
  
  if (error) {
    return <ErrorState error={error} onRetry={refetch} />;
  }
  
  return (
    <PageLayout>
      {/* ... */}
    </PageLayout>
  );
}

// Button loading
<Button loading={isSaving}>
  {isSaving ? 'Saving...' : 'Save'}
</Button>

// Inline loading
<div className="inline-loading">
  <Spinner size="sm" />
  <span>Loading more...</span>
</div>
```

### 10.2 Toast Notifications

```typescript
import { useToast } from '@eldrin/ui';

function InvoiceForm() {
  const toast = useToast();
  
  const handleSave = async () => {
    try {
      await saveInvoice(data);
      toast.success('Invoice saved successfully');
    } catch (error) {
      toast.error('Failed to save invoice', {
        description: error.message,
        action: {
          label: 'Retry',
          onClick: handleSave,
        },
      });
    }
  };
}
```

### 10.3 Confirmation Dialogs

```typescript
import { useConfirm } from '@eldrin/ui';

function DeleteButton({ invoiceId }) {
  const confirm = useConfirm();
  
  const handleDelete = async () => {
    const confirmed = await confirm({
      title: 'Delete Invoice',
      message: 'Are you sure you want to delete this invoice? This action cannot be undone.',
      confirmLabel: 'Delete',
      confirmVariant: 'danger',
    });
    
    if (confirmed) {
      await deleteInvoice(invoiceId);
    }
  };
  
  return (
    <Button variant="danger" onClick={handleDelete}>
      Delete
    </Button>
  );
}
```

### 10.4 Progress Indicators

```typescript
// Determinate progress
<Progress value={uploadProgress} max={100} />

// Indeterminate progress
<Progress indeterminate />

// Steps progress
<Steps current={currentStep}>
  <Steps.Step title="Details" />
  <Steps.Step title="Line Items" />
  <Steps.Step title="Review" />
  <Steps.Step title="Send" />
</Steps>
```

---

## 11. Localization

### 11.1 Translation Files

```json
// src/locales/en-US.json
{
  "invoicing": {
    "title": "Invoicing",
    "invoice": "Invoice",
    "invoices": "Invoices",
    "createInvoice": "Create Invoice",
    "editInvoice": "Edit Invoice",
    "deleteInvoice": "Delete Invoice",
    "status": {
      "draft": "Draft",
      "pending": "Pending",
      "paid": "Paid",
      "overdue": "Overdue"
    },
    "fields": {
      "invoiceNumber": "Invoice Number",
      "customer": "Customer",
      "dueDate": "Due Date",
      "amount": "Amount",
      "tax": "Tax",
      "total": "Total"
    },
    "messages": {
      "saved": "Invoice saved successfully",
      "deleted": "Invoice deleted",
      "sent": "Invoice sent to {customerName}"
    },
    "errors": {
      "saveFailed": "Failed to save invoice",
      "loadFailed": "Failed to load invoices"
    }
  }
}
```

### 11.2 Using Translations

```typescript
import { useTranslation } from '@eldrin/sdk';

function InvoiceList() {
  const { t } = useTranslation('invoicing');
  
  return (
    <PageLayout>
      <PageHeader
        title={t('invoices')}
        actions={
          <Button>{t('createInvoice')}</Button>
        }
      />
      {/* ... */}
    </PageLayout>
  );
}

// With interpolation
toast.success(t('messages.sent', { customerName: invoice.customerName }));
```

### 11.3 Locale-Aware Formatting

```typescript
import { useLocale } from '@eldrin/sdk';

function InvoiceAmount({ amount, currency }) {
  const { locale } = useLocale();
  
  const formatted = new Intl.NumberFormat(locale, {
    style: 'currency',
    currency,
  }).format(amount);
  
  return <span>{formatted}</span>;
}

// Date formatting
function InvoiceDate({ date }) {
  const { locale } = useLocale();
  
  const formatted = new Intl.DateTimeFormat(locale, {
    dateStyle: 'medium',
  }).format(new Date(date));
  
  return <span>{formatted}</span>;
}
```

### 11.4 Country-Specific Features

```typescript
// src/locales/de-DE.json
{
  "invoicing": {
    // German-specific: formal address
    "greeting": "Sehr geehrte Damen und Herren",
    
    // German-specific: tax terminology
    "tax": "MwSt.",
    "taxId": "USt-IdNr.",
    
    // German-specific: date format expectations
    "dateFormat": "DD.MM.YYYY"
  }
}
```

---

## 12. Performance Requirements

### 12.1 Bundle Size Limits

| Metric | Limit | Measurement |
|--------|-------|-------------|
| Initial JS bundle | < 200KB gzipped | Main entry point |
| Total JS (lazy loaded) | < 500KB gzipped | All app code |
| CSS bundle | < 50KB gzipped | All styles |
| Largest asset | < 100KB | Individual file |

### 12.2 Performance Metrics

| Metric | Target | Description |
|--------|--------|-------------|
| First Contentful Paint | < 1.0s | First content visible |
| Largest Contentful Paint | < 2.0s | Main content visible |
| Time to Interactive | < 2.5s | App fully interactive |
| Cumulative Layout Shift | < 0.1 | Visual stability |

### 12.3 Code Splitting

```typescript
// Lazy load pages
const ProductList = lazy(() => import('./pages/ProductList'));
const ProductDetail = lazy(() => import('./pages/ProductDetail'));
const ProductCreate = lazy(() => import('./pages/ProductCreate'));

// Route-based code splitting
<Routes>
  <Route 
    path="/" 
    element={
      <Suspense fallback={<PageSkeleton />}>
        <ProductList />
      </Suspense>
    } 
  />
  <Route 
    path="/:id" 
    element={
      <Suspense fallback={<PageSkeleton />}>
        <ProductDetail />
      </Suspense>
    } 
  />
</Routes>
```

### 12.4 Image Optimization

```typescript
// Use responsive images
<img
  src={product.image}
  srcSet={`
    ${product.imageSm} 400w,
    ${product.imageMd} 800w,
    ${product.imageLg} 1200w
  `}
  sizes="(max-width: 640px) 100vw, (max-width: 1024px) 50vw, 33vw"
  alt={product.name}
  loading="lazy"
/>

// Or use the Image component
import { Image } from '@eldrin/ui';

<Image
  src={product.image}
  alt={product.name}
  width={400}
  height={300}
  placeholder="blur"
/>
```

---

## 13. Testing Requirements

### 13.1 Required Tests

| Test Type | Coverage | Description |
|-----------|----------|-------------|
| Unit Tests | > 70% | Component logic, utilities |
| Integration Tests | Key flows | Page interactions |
| Accessibility Tests | All pages | WCAG compliance |
| Visual Regression | Critical UI | Screenshot comparison |

### 13.2 Unit Testing

```typescript
// ProductCard.test.tsx
import { render, screen, fireEvent } from '@testing-library/react';
import { ProductCard } from './ProductCard';

describe('ProductCard', () => {
  const mockProduct = {
    id: '1',
    name: 'Widget Pro',
    price: 199.99,
    image: '/images/widget.jpg',
  };
  
  it('renders product information', () => {
    render(<ProductCard product={mockProduct} />);
    
    expect(screen.getByText('Widget Pro')).toBeInTheDocument();
    expect(screen.getByText('$199.99')).toBeInTheDocument();
  });
  
  it('calls onClick when clicked', () => {
    const handleClick = jest.fn();
    render(<ProductCard product={mockProduct} onClick={handleClick} />);
    
    fireEvent.click(screen.getByRole('button'));
    expect(handleClick).toHaveBeenCalled();
  });
  
  it('is keyboard accessible', () => {
    const handleClick = jest.fn();
    render(<ProductCard product={mockProduct} onClick={handleClick} />);
    
    const card = screen.getByRole('button');
    card.focus();
    fireEvent.keyDown(card, { key: 'Enter' });
    
    expect(handleClick).toHaveBeenCalled();
  });
});
```

### 13.3 Integration Testing

```typescript
// InvoiceCreate.test.tsx
import { renderApp, screen, userEvent, waitFor } from '@eldrin/testing';

describe('Invoice Creation Flow', () => {
  it('creates an invoice successfully', async () => {
    renderApp(<InvoiceCreate />);
    
    // Select customer
    await userEvent.click(screen.getByLabelText('Customer'));
    await userEvent.type(screen.getByRole('searchbox'), 'Acme');
    await userEvent.click(await screen.findByText('Acme Corp'));
    
    // Add line item
    await userEvent.click(screen.getByText('Add Item'));
    await userEvent.type(screen.getByLabelText('Description'), 'Widget Pro');
    await userEvent.type(screen.getByLabelText('Quantity'), '2');
    await userEvent.type(screen.getByLabelText('Unit Price'), '100');
    
    // Submit
    await userEvent.click(screen.getByText('Create Invoice'));
    
    await waitFor(() => {
      expect(screen.getByText('Invoice created successfully')).toBeInTheDocument();
    });
  });
});
```

### 13.4 Accessibility Testing

```typescript
import { axe, toHaveNoViolations } from 'jest-axe';

expect.extend(toHaveNoViolations);

describe('Accessibility', () => {
  it('ProductList has no accessibility violations', async () => {
    const { container } = render(<ProductList products={mockProducts} />);
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});
```

---

## 14. Submission Checklist

### 14.1 Pre-Submission Checklist

#### Design Compliance

- [ ] All colors use CSS custom properties (no hardcoded values)
- [ ] All typography uses design tokens
- [ ] All spacing uses spacing scale
- [ ] Components use @eldrin/ui where available
- [ ] Custom components follow guidelines
- [ ] Icons use Lucide library

#### Theme Compliance

- [ ] Tested with light theme
- [ ] Tested with dark theme
- [ ] Tested with custom brand colors
- [ ] No color contrast issues

#### Responsive Design

- [ ] Works on mobile (< 640px)
- [ ] Works on tablet (640px - 1024px)
- [ ] Works on desktop (> 1024px)
- [ ] No horizontal scroll issues

#### Accessibility

- [ ] All interactive elements are keyboard accessible
- [ ] Focus indicators are visible
- [ ] ARIA labels are appropriate
- [ ] Color contrast meets WCAG AA
- [ ] Screen reader tested
- [ ] No accessibility violations (axe)

#### Performance

- [ ] Bundle size within limits
- [ ] Images are optimized
- [ ] Code splitting implemented
- [ ] No memory leaks
- [ ] Lighthouse score > 90

#### Localization

- [ ] All text is translatable
- [ ] RTL support (if applicable)
- [ ] Dates/numbers formatted per locale

#### Testing

- [ ] Unit test coverage > 70%
- [ ] Integration tests for key flows
- [ ] Accessibility tests pass
- [ ] Visual regression tests (if applicable)

### 14.2 Submission Command

```bash
# Validate app before submission
eldrin validate

# Run all checks
eldrin check --all

# Submit to marketplace
eldrin publish
```

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | December 2024 | Design Team | Initial specification |

---

*This document defines frontend design requirements for Eldrin apps. Following these guidelines ensures visual consistency, optimal user experience, and successful marketplace review.*
