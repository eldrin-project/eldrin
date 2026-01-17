# Eldrin Core Shell - Frontend Design Requirements

**Version:** 1.0.0  
**Date:** December 2024  
**Status:** Draft

---

## Table of Contents

1. [Design Philosophy](#1-design-philosophy)
2. [Aesthetic Direction](#2-aesthetic-direction)
3. [Design Tokens](#3-design-tokens)
4. [Typography System](#4-typography-system)
5. [Color System](#5-color-system)
6. [Layout System](#6-layout-system)
7. [Component Library](#7-component-library)
8. [Navigation Components](#8-navigation-components)
9. [Authentication UI](#9-authentication-ui)
10. [Dashboard System](#10-dashboard-system)
11. [Settings Interface](#11-settings-interface)
12. [Motion & Animation](#12-motion--animation)
13. [Theming Architecture](#13-theming-architecture)
14. [Accessibility Requirements](#14-accessibility-requirements)
15. [Responsive Design](#15-responsive-design)
16. [Technical Implementation](#16-technical-implementation)

---

## 1. Design Philosophy

### 1.1 Core Principles

Eldrin is a **professional business platform** that must balance:

| Principle | Description |
|-----------|-------------|
| **Professional Authority** | Inspire trust and confidence for business-critical operations |
| **Elegant Simplicity** | Complex functionality presented with clarity |
| **White-Label Flexibility** | Design system that transforms gracefully under customer branding |
| **Modular Cohesion** | Apps feel unified while maintaining their identity |

### 1.2 Design Goals

1. **Distinctive but Not Distracting** - The shell should be memorable without competing with app content
2. **Invisible When Working** - UI fades into background during focused work
3. **Discoverable When Needed** - Navigation and tools appear naturally when required
4. **Brandable Foundation** - Every visual element can be themed without breaking

### 1.3 Anti-Patterns to Avoid

```
❌ Generic SaaS dashboard aesthetics (gray everything, blue accents)
❌ Overused patterns (cards everywhere, rounded corners on everything)
❌ Cookie-cutter layouts (sidebar + header + content grid)
❌ AI-generated feel (purple gradients, Inter font, safe choices)
❌ Feature-dense overwhelm (every option visible at once)
```

---

## 2. Aesthetic Direction

### 2.1 Chosen Direction: "Refined Industrial"

Eldrin's visual identity draws from **industrial design** and **Swiss typography** traditions:

- **Clean geometric forms** with purposeful negative space
- **High contrast** between functional and decorative elements
- **Material honesty** - components look like what they are
- **Precision engineering** feel - every pixel intentional
- **Subtle depth** through shadow and layering, not gradients

### 2.2 Mood Board Concepts

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   INFLUENCES:                                                   │
│   • Dieter Rams (Braun) - functional minimalism                │
│   • Swiss International Style - grid precision, clean type      │
│   • Japanese product design - refined details, quality feel     │
│   • Architectural blueprints - structured, technical beauty     │
│                                                                 │
│   NOT:                                                          │
│   • Silicon Valley startup aesthetic                            │
│   • Material Design (too Google)                                │
│   • Flat design 2.0 (too generic)                              │
│   • Neumorphism (dated)                                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 2.3 Visual Signature Elements

| Element | Treatment |
|---------|-----------|
| **Corners** | Sharp or subtly rounded (2-4px max), never pill-shaped |
| **Shadows** | Crisp, offset shadows suggesting physical elevation |
| **Borders** | Thin, purposeful lines (1px) defining space |
| **Icons** | Geometric, line-based, consistent stroke weight |
| **Depth** | Layered planes with clear hierarchy |

---

## 3. Design Tokens

### 3.1 Token Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    TOKEN HIERARCHY                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  PRIMITIVE TOKENS (raw values)                                  │
│  └── --primitive-gray-900: #111111                             │
│  └── --primitive-blue-500: #0066FF                             │
│                                                                 │
│  SEMANTIC TOKENS (purpose-based)                                │
│  └── --color-text-primary: var(--primitive-gray-900)           │
│  └── --color-action-primary: var(--primitive-blue-500)         │
│                                                                 │
│  COMPONENT TOKENS (component-specific)                          │
│  └── --button-background: var(--color-action-primary)          │
│  └── --button-text: var(--color-text-inverse)                  │
│                                                                 │
│  THEME OVERRIDES (customer branding)                            │
│  └── --color-action-primary: #FF6600 (customer override)       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Spacing Scale

Based on 4px base unit with geometric progression:

```css
:root {
  --space-0: 0;
  --space-1: 4px;      /* Tight: icon padding */
  --space-2: 8px;      /* Compact: inline elements */
  --space-3: 12px;     /* Default: component padding */
  --space-4: 16px;     /* Comfortable: card padding */
  --space-5: 24px;     /* Relaxed: section gaps */
  --space-6: 32px;     /* Spacious: major sections */
  --space-7: 48px;     /* Generous: page margins */
  --space-8: 64px;     /* Expansive: hero areas */
  --space-9: 96px;     /* Maximum: page-level spacing */
}
```

### 3.3 Size Scale

```css
:root {
  /* Component heights (touch targets) */
  --size-xs: 24px;     /* Small badges, tags */
  --size-sm: 32px;     /* Compact buttons, inputs */
  --size-md: 40px;     /* Default buttons, inputs */
  --size-lg: 48px;     /* Large buttons, prominent inputs */
  --size-xl: 56px;     /* Hero buttons */
  
  /* Icon sizes */
  --icon-xs: 12px;
  --icon-sm: 16px;
  --icon-md: 20px;
  --icon-lg: 24px;
  --icon-xl: 32px;
  
  /* Border radius */
  --radius-none: 0;
  --radius-sm: 2px;
  --radius-md: 4px;
  --radius-lg: 6px;
  --radius-full: 9999px;
}
```

### 3.4 Z-Index Scale

```css
:root {
  --z-base: 0;
  --z-dropdown: 100;
  --z-sticky: 200;
  --z-overlay: 300;
  --z-modal: 400;
  --z-popover: 500;
  --z-tooltip: 600;
  --z-toast: 700;
  --z-max: 9999;
}
```

---

## 4. Typography System

### 4.1 Font Selection

**Primary Font (Headings):** `"JetBrains Mono"` or `"IBM Plex Mono"`
- Monospace conveys precision, technical authority
- Excellent for data-heavy interfaces
- Distinctive without being decorative

**Secondary Font (Body):** `"IBM Plex Sans"` or `"DM Sans"`
- Clean, professional, highly legible
- Excellent language support
- Pairs well with mono headings

**Fallback Stack:**
```css
--font-heading: "JetBrains Mono", "IBM Plex Mono", "SF Mono", monospace;
--font-body: "IBM Plex Sans", "DM Sans", -apple-system, sans-serif;
--font-mono: "JetBrains Mono", "Fira Code", monospace;
```

### 4.2 Type Scale

Using a 1.25 ratio (Major Third) for professional feel:

```css
:root {
  --text-xs: 0.64rem;    /* 10.24px - Labels, captions */
  --text-sm: 0.8rem;     /* 12.8px - Secondary text */
  --text-base: 1rem;     /* 16px - Body text */
  --text-lg: 1.25rem;    /* 20px - Lead text */
  --text-xl: 1.563rem;   /* 25px - Section headings */
  --text-2xl: 1.953rem;  /* 31.25px - Page titles */
  --text-3xl: 2.441rem;  /* 39px - Hero headings */
  --text-4xl: 3.052rem;  /* 48.8px - Display */
}
```

### 4.3 Line Heights

```css
:root {
  --leading-none: 1;
  --leading-tight: 1.2;    /* Headings */
  --leading-snug: 1.35;    /* Large text */
  --leading-normal: 1.5;   /* Body text */
  --leading-relaxed: 1.65; /* Long-form content */
}
```

### 4.4 Font Weights

```css
:root {
  --weight-normal: 400;
  --weight-medium: 500;
  --weight-semibold: 600;
  --weight-bold: 700;
}
```

### 4.5 Typography Compositions

```css
/* Heading styles */
.heading-display {
  font-family: var(--font-heading);
  font-size: var(--text-3xl);
  font-weight: var(--weight-bold);
  line-height: var(--leading-tight);
  letter-spacing: -0.02em;
}

.heading-page {
  font-family: var(--font-heading);
  font-size: var(--text-2xl);
  font-weight: var(--weight-semibold);
  line-height: var(--leading-tight);
  letter-spacing: -0.01em;
}

.heading-section {
  font-family: var(--font-heading);
  font-size: var(--text-xl);
  font-weight: var(--weight-medium);
  line-height: var(--leading-snug);
}

/* Body styles */
.body-default {
  font-family: var(--font-body);
  font-size: var(--text-base);
  font-weight: var(--weight-normal);
  line-height: var(--leading-normal);
}

.body-small {
  font-family: var(--font-body);
  font-size: var(--text-sm);
  font-weight: var(--weight-normal);
  line-height: var(--leading-normal);
}

/* Label styles */
.label-default {
  font-family: var(--font-body);
  font-size: var(--text-sm);
  font-weight: var(--weight-medium);
  line-height: var(--leading-tight);
  letter-spacing: 0.01em;
  text-transform: none;
}

.label-caps {
  font-family: var(--font-heading);
  font-size: var(--text-xs);
  font-weight: var(--weight-semibold);
  line-height: var(--leading-tight);
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
```

---

## 5. Color System

### 5.1 Primitive Colors

```css
:root {
  /* Neutrals - Warm gray tint for sophistication */
  --primitive-gray-50: #FAFAF9;
  --primitive-gray-100: #F5F5F4;
  --primitive-gray-200: #E7E5E4;
  --primitive-gray-300: #D6D3D1;
  --primitive-gray-400: #A8A29E;
  --primitive-gray-500: #78716C;
  --primitive-gray-600: #57534E;
  --primitive-gray-700: #44403C;
  --primitive-gray-800: #292524;
  --primitive-gray-900: #1C1917;
  --primitive-gray-950: #0C0A09;

  /* Primary - Deep blue with authority */
  --primitive-blue-50: #EFF6FF;
  --primitive-blue-100: #DBEAFE;
  --primitive-blue-200: #BFDBFE;
  --primitive-blue-300: #93C5FD;
  --primitive-blue-400: #60A5FA;
  --primitive-blue-500: #3B82F6;
  --primitive-blue-600: #2563EB;
  --primitive-blue-700: #1D4ED8;
  --primitive-blue-800: #1E40AF;
  --primitive-blue-900: #1E3A8A;

  /* Accent - Warm amber for highlights */
  --primitive-amber-50: #FFFBEB;
  --primitive-amber-500: #F59E0B;
  --primitive-amber-600: #D97706;

  /* Semantic colors */
  --primitive-red-500: #EF4444;
  --primitive-red-600: #DC2626;
  --primitive-green-500: #22C55E;
  --primitive-green-600: #16A34A;
  --primitive-yellow-500: #EAB308;
  --primitive-cyan-500: #06B6D4;
}
```

### 5.2 Semantic Colors (Light Theme)

```css
:root {
  /* Backgrounds */
  --color-bg-page: var(--primitive-gray-50);
  --color-bg-surface: #FFFFFF;
  --color-bg-elevated: #FFFFFF;
  --color-bg-sunken: var(--primitive-gray-100);
  --color-bg-overlay: rgba(12, 10, 9, 0.5);

  /* Text */
  --color-text-primary: var(--primitive-gray-900);
  --color-text-secondary: var(--primitive-gray-600);
  --color-text-tertiary: var(--primitive-gray-500);
  --color-text-disabled: var(--primitive-gray-400);
  --color-text-inverse: #FFFFFF;
  --color-text-link: var(--primitive-blue-600);

  /* Borders */
  --color-border-default: var(--primitive-gray-200);
  --color-border-subtle: var(--primitive-gray-100);
  --color-border-strong: var(--primitive-gray-300);
  --color-border-focus: var(--primitive-blue-500);

  /* Actions */
  --color-action-primary: var(--primitive-blue-600);
  --color-action-primary-hover: var(--primitive-blue-700);
  --color-action-secondary: var(--primitive-gray-100);
  --color-action-secondary-hover: var(--primitive-gray-200);

  /* Status */
  --color-status-success: var(--primitive-green-600);
  --color-status-warning: var(--primitive-yellow-500);
  --color-status-error: var(--primitive-red-600);
  --color-status-info: var(--primitive-cyan-500);
}
```

### 5.3 Semantic Colors (Dark Theme)

```css
[data-theme="dark"] {
  /* Backgrounds */
  --color-bg-page: var(--primitive-gray-950);
  --color-bg-surface: var(--primitive-gray-900);
  --color-bg-elevated: var(--primitive-gray-800);
  --color-bg-sunken: var(--primitive-gray-950);
  --color-bg-overlay: rgba(0, 0, 0, 0.7);

  /* Text */
  --color-text-primary: var(--primitive-gray-50);
  --color-text-secondary: var(--primitive-gray-400);
  --color-text-tertiary: var(--primitive-gray-500);
  --color-text-disabled: var(--primitive-gray-600);
  --color-text-inverse: var(--primitive-gray-900);
  --color-text-link: var(--primitive-blue-400);

  /* Borders */
  --color-border-default: var(--primitive-gray-700);
  --color-border-subtle: var(--primitive-gray-800);
  --color-border-strong: var(--primitive-gray-600);
  --color-border-focus: var(--primitive-blue-400);

  /* Actions */
  --color-action-primary: var(--primitive-blue-500);
  --color-action-primary-hover: var(--primitive-blue-400);
  --color-action-secondary: var(--primitive-gray-800);
  --color-action-secondary-hover: var(--primitive-gray-700);
}
```

### 5.4 Shadows

```css
:root {
  /* Crisp, offset shadows for "Refined Industrial" aesthetic */
  --shadow-sm: 
    0 1px 2px rgba(0, 0, 0, 0.05);
  
  --shadow-md: 
    0 2px 4px rgba(0, 0, 0, 0.05),
    0 4px 8px rgba(0, 0, 0, 0.05);
  
  --shadow-lg: 
    0 4px 8px rgba(0, 0, 0, 0.05),
    0 8px 16px rgba(0, 0, 0, 0.08);
  
  --shadow-xl: 
    0 8px 16px rgba(0, 0, 0, 0.08),
    0 16px 32px rgba(0, 0, 0, 0.08);
  
  /* Offset shadow for elevated elements */
  --shadow-elevated: 
    4px 4px 0 var(--color-border-default);
  
  /* Focus ring */
  --shadow-focus: 
    0 0 0 2px var(--color-bg-surface),
    0 0 0 4px var(--color-border-focus);
}
```

---

## 6. Layout System

### 6.1 Shell Layout Structure

```
┌─────────────────────────────────────────────────────────────────┐
│ TOP BAR (56px fixed)                                            │
│ ┌─────────┬─────────────────────────────────┬─────────────────┐ │
│ │ Logo    │ Global Search                   │ User Menu       │ │
│ └─────────┴─────────────────────────────────┴─────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│ ┌───────────┬───────────────────────────────────────────────┐   │
│ │           │                                               │   │
│ │ SIDE NAV  │              MAIN CONTENT                     │   │
│ │ (240px)   │                                               │   │
│ │           │  ┌─────────────────────────────────────────┐  │   │
│ │ Collaps-  │  │                                         │  │   │
│ │ ible to   │  │         APP MOUNTING AREA               │  │   │
│ │ 64px      │  │         (single-spa parcels)            │  │   │
│ │           │  │                                         │  │   │
│ │           │  │                                         │  │   │
│ │           │  └─────────────────────────────────────────┘  │   │
│ │           │                                               │   │
│ └───────────┴───────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### 6.2 Layout Dimensions

```css
:root {
  /* Fixed dimensions */
  --layout-topbar-height: 56px;
  --layout-sidenav-width: 240px;
  --layout-sidenav-collapsed: 64px;
  
  /* Content constraints */
  --layout-content-max-width: 1440px;
  --layout-content-padding: var(--space-6);
  
  /* Breakpoints */
  --breakpoint-sm: 640px;
  --breakpoint-md: 768px;
  --breakpoint-lg: 1024px;
  --breakpoint-xl: 1280px;
  --breakpoint-2xl: 1536px;
}
```

### 6.3 Grid System

12-column grid for app content areas:

```css
.grid-container {
  display: grid;
  grid-template-columns: repeat(12, 1fr);
  gap: var(--space-5);
  max-width: var(--layout-content-max-width);
  margin: 0 auto;
  padding: var(--layout-content-padding);
}

/* Responsive column spans */
.col-span-1 { grid-column: span 1; }
.col-span-2 { grid-column: span 2; }
.col-span-3 { grid-column: span 3; }
.col-span-4 { grid-column: span 4; }
.col-span-6 { grid-column: span 6; }
.col-span-12 { grid-column: span 12; }

@media (max-width: 768px) {
  .grid-container {
    grid-template-columns: 1fr;
  }
  [class*="col-span-"] {
    grid-column: span 1;
  }
}
```

---

## 7. Component Library

### 7.1 Button Components

```
┌─────────────────────────────────────────────────────────────────┐
│ BUTTON VARIANTS                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  PRIMARY      ████████████████████   Solid fill, primary color  │
│  SECONDARY    ░░░░░░░░░░░░░░░░░░░░   Subtle fill, border        │
│  GHOST        [  transparent bg  ]   No fill, text only         │
│  DANGER       ████████████████████   Red fill for destructive   │
│                                                                 │
│  SIZES: sm (32px) | md (40px) | lg (48px)                      │
│                                                                 │
│  STATES: default | hover | active | focus | disabled | loading  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

```css
/* Button base */
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: var(--space-2);
  height: var(--size-md);
  padding: 0 var(--space-4);
  font-family: var(--font-body);
  font-size: var(--text-sm);
  font-weight: var(--weight-medium);
  line-height: 1;
  border-radius: var(--radius-md);
  border: 1px solid transparent;
  cursor: pointer;
  transition: all 150ms ease;
}

/* Primary variant */
.btn-primary {
  background: var(--color-action-primary);
  color: var(--color-text-inverse);
  border-color: var(--color-action-primary);
}

.btn-primary:hover {
  background: var(--color-action-primary-hover);
  border-color: var(--color-action-primary-hover);
  transform: translateY(-1px);
  box-shadow: var(--shadow-md);
}

.btn-primary:active {
  transform: translateY(0);
  box-shadow: none;
}

/* Secondary variant */
.btn-secondary {
  background: var(--color-action-secondary);
  color: var(--color-text-primary);
  border-color: var(--color-border-default);
}

.btn-secondary:hover {
  background: var(--color-action-secondary-hover);
  border-color: var(--color-border-strong);
}

/* Ghost variant */
.btn-ghost {
  background: transparent;
  color: var(--color-text-secondary);
  border-color: transparent;
}

.btn-ghost:hover {
  background: var(--color-action-secondary);
  color: var(--color-text-primary);
}

/* Focus state (all variants) */
.btn:focus-visible {
  outline: none;
  box-shadow: var(--shadow-focus);
}

/* Disabled state */
.btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
  transform: none;
}

/* Size variants */
.btn-sm { height: var(--size-sm); padding: 0 var(--space-3); font-size: var(--text-xs); }
.btn-lg { height: var(--size-lg); padding: 0 var(--space-5); font-size: var(--text-base); }
```

### 7.2 Input Components

```css
/* Input base */
.input {
  height: var(--size-md);
  padding: 0 var(--space-3);
  font-family: var(--font-body);
  font-size: var(--text-base);
  color: var(--color-text-primary);
  background: var(--color-bg-surface);
  border: 1px solid var(--color-border-default);
  border-radius: var(--radius-md);
  transition: all 150ms ease;
}

.input::placeholder {
  color: var(--color-text-tertiary);
}

.input:hover {
  border-color: var(--color-border-strong);
}

.input:focus {
  outline: none;
  border-color: var(--color-border-focus);
  box-shadow: var(--shadow-focus);
}

.input:disabled {
  background: var(--color-bg-sunken);
  color: var(--color-text-disabled);
  cursor: not-allowed;
}

/* Error state */
.input-error {
  border-color: var(--color-status-error);
}

.input-error:focus {
  box-shadow: 0 0 0 2px var(--color-bg-surface),
              0 0 0 4px var(--color-status-error);
}

/* Input with icon */
.input-wrapper {
  position: relative;
  display: flex;
  align-items: center;
}

.input-icon {
  position: absolute;
  left: var(--space-3);
  color: var(--color-text-tertiary);
  pointer-events: none;
}

.input-with-icon {
  padding-left: calc(var(--space-3) + var(--icon-md) + var(--space-2));
}
```

### 7.3 Card Components

```css
/* Card base - distinctive offset shadow */
.card {
  background: var(--color-bg-surface);
  border: 1px solid var(--color-border-default);
  border-radius: var(--radius-md);
  overflow: hidden;
}

/* Elevated card with signature offset shadow */
.card-elevated {
  box-shadow: var(--shadow-elevated);
  transition: transform 150ms ease, box-shadow 150ms ease;
}

.card-elevated:hover {
  transform: translate(-2px, -2px);
  box-shadow: 6px 6px 0 var(--color-border-default);
}

/* Interactive card */
.card-interactive {
  cursor: pointer;
}

.card-interactive:hover {
  border-color: var(--color-border-strong);
}

/* Card sections */
.card-header {
  padding: var(--space-4);
  border-bottom: 1px solid var(--color-border-subtle);
}

.card-body {
  padding: var(--space-4);
}

.card-footer {
  padding: var(--space-4);
  border-top: 1px solid var(--color-border-subtle);
  background: var(--color-bg-sunken);
}
```

### 7.4 Badge & Tag Components

```css
/* Badge */
.badge {
  display: inline-flex;
  align-items: center;
  height: var(--size-xs);
  padding: 0 var(--space-2);
  font-family: var(--font-heading);
  font-size: var(--text-xs);
  font-weight: var(--weight-medium);
  line-height: 1;
  border-radius: var(--radius-sm);
}

.badge-default {
  background: var(--color-bg-sunken);
  color: var(--color-text-secondary);
}

.badge-primary {
  background: var(--primitive-blue-100);
  color: var(--primitive-blue-700);
}

.badge-success {
  background: rgba(34, 197, 94, 0.1);
  color: var(--color-status-success);
}

.badge-warning {
  background: rgba(234, 179, 8, 0.1);
  color: var(--color-status-warning);
}

.badge-error {
  background: rgba(239, 68, 68, 0.1);
  color: var(--color-status-error);
}

/* Notification dot */
.badge-dot {
  width: 8px;
  height: 8px;
  padding: 0;
  border-radius: var(--radius-full);
}
```

### 7.5 Modal & Dialog

```css
/* Modal overlay */
.modal-overlay {
  position: fixed;
  inset: 0;
  background: var(--color-bg-overlay);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: var(--z-modal);
  animation: fadeIn 150ms ease;
}

/* Modal container */
.modal {
  position: relative;
  width: 100%;
  max-width: 500px;
  max-height: calc(100vh - var(--space-8));
  background: var(--color-bg-surface);
  border: 1px solid var(--color-border-default);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-xl);
  animation: slideUp 200ms ease;
  overflow: hidden;
}

.modal-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--space-4) var(--space-5);
  border-bottom: 1px solid var(--color-border-subtle);
}

.modal-title {
  font-family: var(--font-heading);
  font-size: var(--text-lg);
  font-weight: var(--weight-semibold);
}

.modal-body {
  padding: var(--space-5);
  overflow-y: auto;
}

.modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: var(--space-3);
  padding: var(--space-4) var(--space-5);
  border-top: 1px solid var(--color-border-subtle);
  background: var(--color-bg-sunken);
}

/* Size variants */
.modal-sm { max-width: 400px; }
.modal-lg { max-width: 700px; }
.modal-xl { max-width: 900px; }
.modal-full { max-width: calc(100vw - var(--space-8)); }

@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}

@keyframes slideUp {
  from { 
    opacity: 0;
    transform: translateY(10px);
  }
  to { 
    opacity: 1;
    transform: translateY(0);
  }
}
```

### 7.6 Dropdown Menu

```css
/* Dropdown trigger */
.dropdown-trigger {
  position: relative;
}

/* Dropdown menu */
.dropdown-menu {
  position: absolute;
  top: calc(100% + var(--space-1));
  right: 0;
  min-width: 200px;
  background: var(--color-bg-surface);
  border: 1px solid var(--color-border-default);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-lg);
  z-index: var(--z-dropdown);
  animation: dropdownOpen 150ms ease;
}

.dropdown-item {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  padding: var(--space-2) var(--space-3);
  font-size: var(--text-sm);
  color: var(--color-text-primary);
  cursor: pointer;
  transition: background 100ms ease;
}

.dropdown-item:hover {
  background: var(--color-bg-sunken);
}

.dropdown-item:first-child {
  border-radius: var(--radius-md) var(--radius-md) 0 0;
}

.dropdown-item:last-child {
  border-radius: 0 0 var(--radius-md) var(--radius-md);
}

.dropdown-separator {
  height: 1px;
  margin: var(--space-1) 0;
  background: var(--color-border-subtle);
}

.dropdown-item-icon {
  width: var(--icon-sm);
  height: var(--icon-sm);
  color: var(--color-text-secondary);
}

@keyframes dropdownOpen {
  from {
    opacity: 0;
    transform: translateY(-4px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}
```

### 7.7 Toast Notifications

```css
/* Toast container */
.toast-container {
  position: fixed;
  bottom: var(--space-5);
  right: var(--space-5);
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
  z-index: var(--z-toast);
}

/* Toast */
.toast {
  display: flex;
  align-items: flex-start;
  gap: var(--space-3);
  min-width: 300px;
  max-width: 450px;
  padding: var(--space-4);
  background: var(--color-bg-surface);
  border: 1px solid var(--color-border-default);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-lg);
  animation: toastSlideIn 300ms ease;
}

.toast-icon {
  flex-shrink: 0;
  width: var(--icon-md);
  height: var(--icon-md);
}

.toast-content {
  flex: 1;
  min-width: 0;
}

.toast-title {
  font-weight: var(--weight-medium);
  color: var(--color-text-primary);
}

.toast-message {
  margin-top: var(--space-1);
  font-size: var(--text-sm);
  color: var(--color-text-secondary);
}

.toast-close {
  flex-shrink: 0;
  padding: var(--space-1);
  color: var(--color-text-tertiary);
  cursor: pointer;
}

/* Toast variants */
.toast-success { border-left: 3px solid var(--color-status-success); }
.toast-error { border-left: 3px solid var(--color-status-error); }
.toast-warning { border-left: 3px solid var(--color-status-warning); }
.toast-info { border-left: 3px solid var(--color-status-info); }

@keyframes toastSlideIn {
  from {
    opacity: 0;
    transform: translateX(100%);
  }
  to {
    opacity: 1;
    transform: translateX(0);
  }
}
```

---

## 8. Navigation Components

### 8.1 Top Bar

```
┌─────────────────────────────────────────────────────────────────────────┐
│ ┌──────┐                                                    ┌─────────┐ │
│ │ LOGO │  ┌──────────────────────────────────────────────┐  │[●] User│ │
│ │      │  │ 🔍 Search apps, commands, data...            │  │  Menu  │ │
│ └──────┘  └──────────────────────────────────────────────┘  └─────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

```css
.topbar {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  height: var(--layout-topbar-height);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 var(--space-4);
  background: var(--color-bg-surface);
  border-bottom: 1px solid var(--color-border-default);
  z-index: var(--z-sticky);
}

.topbar-logo {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  font-family: var(--font-heading);
  font-size: var(--text-lg);
  font-weight: var(--weight-bold);
  color: var(--color-text-primary);
  text-decoration: none;
}

.topbar-logo-image {
  height: 32px;
  width: auto;
}

.topbar-search {
  flex: 1;
  max-width: 600px;
  margin: 0 var(--space-6);
}

.topbar-actions {
  display: flex;
  align-items: center;
  gap: var(--space-2);
}

/* Global search */
.global-search {
  position: relative;
  width: 100%;
}

.global-search-input {
  width: 100%;
  height: var(--size-md);
  padding: 0 var(--space-4) 0 calc(var(--space-4) + var(--icon-md));
  background: var(--color-bg-sunken);
  border: 1px solid transparent;
  border-radius: var(--radius-md);
  transition: all 150ms ease;
}

.global-search-input:focus {
  background: var(--color-bg-surface);
  border-color: var(--color-border-focus);
  box-shadow: var(--shadow-focus);
}

.global-search-kbd {
  position: absolute;
  right: var(--space-3);
  top: 50%;
  transform: translateY(-50%);
  padding: var(--space-1) var(--space-2);
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--color-text-tertiary);
  background: var(--color-bg-surface);
  border: 1px solid var(--color-border-default);
  border-radius: var(--radius-sm);
}
```

### 8.2 Side Navigation

```
┌─────────────────────────┐
│  ≡ Eldrin               │  ← Collapse toggle
├─────────────────────────┤
│                         │
│  MAIN                   │  ← Section label
│  ◉ Dashboard            │  ← Active item
│  ◯ Notifications  (3)   │  ← With badge
│                         │
│  APPS                   │
│  ◯ Catalog              │
│    ├─ Products          │  ← Nested items
│    └─ Categories        │
│  ◯ Invoicing            │
│  ◯ CRM                  │
│                         │
├─────────────────────────┤
│  ◯ Settings             │  ← Footer items
│  ◯ Help                 │
└─────────────────────────┘
```

```css
.sidenav {
  position: fixed;
  top: var(--layout-topbar-height);
  left: 0;
  bottom: 0;
  width: var(--layout-sidenav-width);
  display: flex;
  flex-direction: column;
  background: var(--color-bg-surface);
  border-right: 1px solid var(--color-border-default);
  transition: width 200ms ease;
  z-index: var(--z-sticky);
}

.sidenav-collapsed {
  width: var(--layout-sidenav-collapsed);
}

.sidenav-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: 48px;
  padding: 0 var(--space-3);
  border-bottom: 1px solid var(--color-border-subtle);
}

.sidenav-toggle {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  color: var(--color-text-secondary);
  background: transparent;
  border: none;
  border-radius: var(--radius-md);
  cursor: pointer;
}

.sidenav-toggle:hover {
  background: var(--color-bg-sunken);
  color: var(--color-text-primary);
}

.sidenav-content {
  flex: 1;
  overflow-y: auto;
  padding: var(--space-3);
}

.sidenav-section {
  margin-bottom: var(--space-4);
}

.sidenav-section-label {
  padding: var(--space-2) var(--space-3);
  font-family: var(--font-heading);
  font-size: var(--text-xs);
  font-weight: var(--weight-semibold);
  color: var(--color-text-tertiary);
  letter-spacing: 0.05em;
  text-transform: uppercase;
}

.sidenav-item {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  padding: var(--space-2) var(--space-3);
  font-size: var(--text-sm);
  color: var(--color-text-secondary);
  text-decoration: none;
  border-radius: var(--radius-md);
  cursor: pointer;
  transition: all 100ms ease;
}

.sidenav-item:hover {
  background: var(--color-bg-sunken);
  color: var(--color-text-primary);
}

.sidenav-item-active {
  background: var(--primitive-blue-50);
  color: var(--color-action-primary);
}

.sidenav-item-active:hover {
  background: var(--primitive-blue-100);
}

.sidenav-item-icon {
  flex-shrink: 0;
  width: var(--icon-md);
  height: var(--icon-md);
}

.sidenav-item-label {
  flex: 1;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.sidenav-item-badge {
  flex-shrink: 0;
  min-width: 20px;
  height: 20px;
  padding: 0 var(--space-1);
  font-size: var(--text-xs);
  font-weight: var(--weight-medium);
  color: var(--color-text-inverse);
  background: var(--color-action-primary);
  border-radius: var(--radius-full);
  text-align: center;
  line-height: 20px;
}

/* Nested items */
.sidenav-nested {
  margin-left: calc(var(--icon-md) + var(--space-3));
  padding-left: var(--space-3);
  border-left: 1px solid var(--color-border-subtle);
}

.sidenav-nested .sidenav-item {
  font-size: var(--text-sm);
  padding: var(--space-1) var(--space-3);
}

/* Footer */
.sidenav-footer {
  padding: var(--space-3);
  border-top: 1px solid var(--color-border-subtle);
}

/* Collapsed state */
.sidenav-collapsed .sidenav-section-label,
.sidenav-collapsed .sidenav-item-label,
.sidenav-collapsed .sidenav-nested {
  display: none;
}

.sidenav-collapsed .sidenav-item {
  justify-content: center;
  padding: var(--space-2);
}
```

### 8.3 User Menu

```css
.user-menu-trigger {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  padding: var(--space-1) var(--space-2);
  background: transparent;
  border: none;
  border-radius: var(--radius-md);
  cursor: pointer;
  transition: background 100ms ease;
}

.user-menu-trigger:hover {
  background: var(--color-bg-sunken);
}

.user-avatar {
  width: 32px;
  height: 32px;
  border-radius: var(--radius-full);
  background: var(--primitive-blue-100);
  display: flex;
  align-items: center;
  justify-content: center;
  font-family: var(--font-heading);
  font-size: var(--text-sm);
  font-weight: var(--weight-semibold);
  color: var(--color-action-primary);
}

.user-avatar-image {
  width: 100%;
  height: 100%;
  border-radius: inherit;
  object-fit: cover;
}

.user-menu-dropdown {
  min-width: 240px;
}

.user-menu-header {
  padding: var(--space-3);
  border-bottom: 1px solid var(--color-border-subtle);
}

.user-menu-name {
  font-weight: var(--weight-medium);
  color: var(--color-text-primary);
}

.user-menu-email {
  font-size: var(--text-sm);
  color: var(--color-text-secondary);
}
```

---

## 9. Authentication UI

### 9.1 Login Page Layout

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│                     ┌─────────────────────┐                     │
│                     │                     │                     │
│                     │    [LOGO]           │                     │
│                     │                     │                     │
│                     │  ┌───────────────┐  │                     │
│                     │  │ Email         │  │                     │
│                     │  └───────────────┘  │                     │
│                     │                     │                     │
│                     │  ┌───────────────┐  │                     │
│                     │  │ Password      │  │                     │
│                     │  └───────────────┘  │                     │
│                     │                     │                     │
│                     │  [    Sign In    ]  │                     │
│                     │                     │                     │
│                     │  Forgot password?   │                     │
│                     │                     │                     │
│                     │  ─────────────────  │                     │
│                     │                     │                     │
│                     │  Don't have account?│                     │
│                     │  [   Register    ]  │                     │
│                     │                     │                     │
│                     └─────────────────────┘                     │
│                                                                 │
│                    Powered by Eldrin                            │
└─────────────────────────────────────────────────────────────────┘
```

### 9.2 Auth Components

```css
.auth-page {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: var(--space-5);
  background: var(--color-bg-page);
}

.auth-card {
  width: 100%;
  max-width: 400px;
  padding: var(--space-6);
  background: var(--color-bg-surface);
  border: 1px solid var(--color-border-default);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-lg);
}

.auth-logo {
  display: flex;
  justify-content: center;
  margin-bottom: var(--space-6);
}

.auth-logo img {
  height: 40px;
  width: auto;
}

.auth-title {
  font-family: var(--font-heading);
  font-size: var(--text-xl);
  font-weight: var(--weight-semibold);
  text-align: center;
  margin-bottom: var(--space-2);
}

.auth-subtitle {
  font-size: var(--text-sm);
  color: var(--color-text-secondary);
  text-align: center;
  margin-bottom: var(--space-5);
}

.auth-form {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
}

.auth-field {
  display: flex;
  flex-direction: column;
  gap: var(--space-1);
}

.auth-label {
  font-size: var(--text-sm);
  font-weight: var(--weight-medium);
  color: var(--color-text-primary);
}

.auth-divider {
  display: flex;
  align-items: center;
  gap: var(--space-4);
  margin: var(--space-5) 0;
}

.auth-divider::before,
.auth-divider::after {
  content: '';
  flex: 1;
  height: 1px;
  background: var(--color-border-default);
}

.auth-divider-text {
  font-size: var(--text-sm);
  color: var(--color-text-tertiary);
}

.auth-footer {
  margin-top: var(--space-5);
  text-align: center;
  font-size: var(--text-sm);
  color: var(--color-text-secondary);
}

.auth-footer a {
  color: var(--color-text-link);
  text-decoration: none;
}

.auth-footer a:hover {
  text-decoration: underline;
}

.auth-powered-by {
  margin-top: var(--space-6);
  text-align: center;
  font-size: var(--text-xs);
  color: var(--color-text-tertiary);
}
```

---

## 10. Dashboard System

### 10.1 Dashboard Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  Dashboard                           [+ Add Widget] [⚙ Edit]   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌───────────────────────┐  ┌───────────────────────────────┐  │
│  │ Invoice Summary       │  │ Recent Activity               │  │
│  │ ████████████████████  │  │                               │  │
│  │                       │  │ • Invoice #1234 paid          │  │
│  │ Total: $45,230        │  │ • New contact: John Doe       │  │
│  │ Pending: $12,400      │  │ • Order #567 shipped          │  │
│  │ Overdue: $3,200       │  │ • ...                         │  │
│  └───────────────────────┘  │                               │  │
│                             │                               │  │
│  ┌───────────────────────┐  │                               │  │
│  │ Quick Actions         │  │                               │  │
│  │ [New Invoice]         │  │                               │  │
│  │ [Add Contact]         │  └───────────────────────────────┘  │
│  │ [Create Order]        │                                     │
│  └───────────────────────┘                                     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 10.2 Widget Components

```css
/* Dashboard grid */
.dashboard-grid {
  display: grid;
  grid-template-columns: repeat(12, 1fr);
  gap: var(--space-4);
  padding: var(--space-5);
}

/* Widget base */
.widget {
  background: var(--color-bg-surface);
  border: 1px solid var(--color-border-default);
  border-radius: var(--radius-md);
  overflow: hidden;
}

/* Widget sizes */
.widget-small { grid-column: span 3; min-height: 150px; }
.widget-medium { grid-column: span 4; min-height: 200px; }
.widget-large { grid-column: span 6; min-height: 300px; }
.widget-full { grid-column: span 12; min-height: 200px; }

/* Widget header */
.widget-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--space-3) var(--space-4);
  border-bottom: 1px solid var(--color-border-subtle);
}

.widget-title {
  font-family: var(--font-heading);
  font-size: var(--text-sm);
  font-weight: var(--weight-semibold);
  color: var(--color-text-primary);
}

.widget-actions {
  display: flex;
  gap: var(--space-1);
}

.widget-action-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  color: var(--color-text-tertiary);
  background: transparent;
  border: none;
  border-radius: var(--radius-sm);
  cursor: pointer;
}

.widget-action-btn:hover {
  background: var(--color-bg-sunken);
  color: var(--color-text-primary);
}

/* Widget body */
.widget-body {
  padding: var(--space-4);
  height: calc(100% - 48px);
  overflow: auto;
}

/* Widget in edit mode */
.widget-editing {
  border: 2px dashed var(--color-action-primary);
  cursor: move;
}

/* Widget placeholder (while dragging) */
.widget-placeholder {
  background: var(--color-bg-sunken);
  border: 2px dashed var(--color-border-strong);
  border-radius: var(--radius-md);
}

/* Stat widget */
.widget-stat {
  display: flex;
  flex-direction: column;
  gap: var(--space-1);
}

.widget-stat-value {
  font-family: var(--font-heading);
  font-size: var(--text-3xl);
  font-weight: var(--weight-bold);
  color: var(--color-text-primary);
}

.widget-stat-label {
  font-size: var(--text-sm);
  color: var(--color-text-secondary);
}

.widget-stat-change {
  display: inline-flex;
  align-items: center;
  gap: var(--space-1);
  font-size: var(--text-sm);
  font-weight: var(--weight-medium);
}

.widget-stat-change-positive { color: var(--color-status-success); }
.widget-stat-change-negative { color: var(--color-status-error); }
```

---

## 11. Settings Interface

### 11.1 Settings Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  Settings                                                       │
├───────────────┬─────────────────────────────────────────────────┤
│               │                                                 │
│  Account      │  Profile Settings                               │
│  ○ Profile    │  ─────────────────────────────────────────────  │
│  ○ Security   │                                                 │
│               │  Display Name                                   │
│  Appearance   │  ┌─────────────────────────────────────────┐   │
│  ● Theme      │  │ John Doe                                │   │
│  ○ Language   │  └─────────────────────────────────────────┘   │
│               │                                                 │
│  Apps         │  Email                                          │
│  ○ Invoicing  │  ┌─────────────────────────────────────────┐   │
│  ○ CRM        │  │ john@example.com                        │   │
│  ○ Catalog    │  └─────────────────────────────────────────┘   │
│               │                                                 │
│  Billing      │  Avatar                                         │
│  ○ Plans      │  ┌───┐                                          │
│  ○ Invoices   │  │ 📷│  [Upload new]  [Remove]                 │
│               │  └───┘                                          │
│               │                                                 │
│               │                         [Cancel]  [Save Changes]│
└───────────────┴─────────────────────────────────────────────────┘
```

### 11.2 Settings Components

```css
.settings-layout {
  display: flex;
  min-height: calc(100vh - var(--layout-topbar-height));
}

/* Settings sidebar */
.settings-sidebar {
  width: 240px;
  padding: var(--space-4);
  background: var(--color-bg-surface);
  border-right: 1px solid var(--color-border-default);
}

.settings-nav-section {
  margin-bottom: var(--space-4);
}

.settings-nav-section-title {
  padding: var(--space-2) var(--space-3);
  font-size: var(--text-xs);
  font-weight: var(--weight-semibold);
  color: var(--color-text-tertiary);
  letter-spacing: 0.05em;
  text-transform: uppercase;
}

.settings-nav-item {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  padding: var(--space-2) var(--space-3);
  font-size: var(--text-sm);
  color: var(--color-text-secondary);
  text-decoration: none;
  border-radius: var(--radius-md);
  cursor: pointer;
}

.settings-nav-item:hover {
  background: var(--color-bg-sunken);
  color: var(--color-text-primary);
}

.settings-nav-item-active {
  background: var(--primitive-blue-50);
  color: var(--color-action-primary);
}

/* Settings content */
.settings-content {
  flex: 1;
  padding: var(--space-6);
  background: var(--color-bg-page);
  overflow-y: auto;
}

.settings-page {
  max-width: 700px;
}

.settings-page-title {
  font-family: var(--font-heading);
  font-size: var(--text-xl);
  font-weight: var(--weight-semibold);
  margin-bottom: var(--space-2);
}

.settings-page-description {
  font-size: var(--text-sm);
  color: var(--color-text-secondary);
  margin-bottom: var(--space-6);
}

/* Settings section */
.settings-section {
  padding: var(--space-5);
  margin-bottom: var(--space-5);
  background: var(--color-bg-surface);
  border: 1px solid var(--color-border-default);
  border-radius: var(--radius-md);
}

.settings-section-title {
  font-family: var(--font-heading);
  font-size: var(--text-base);
  font-weight: var(--weight-semibold);
  margin-bottom: var(--space-4);
  padding-bottom: var(--space-3);
  border-bottom: 1px solid var(--color-border-subtle);
}

/* Settings field */
.settings-field {
  display: grid;
  grid-template-columns: 200px 1fr;
  gap: var(--space-4);
  align-items: start;
  padding: var(--space-3) 0;
}

.settings-field:not(:last-child) {
  border-bottom: 1px solid var(--color-border-subtle);
}

.settings-field-label {
  font-size: var(--text-sm);
  font-weight: var(--weight-medium);
  color: var(--color-text-primary);
}

.settings-field-description {
  font-size: var(--text-sm);
  color: var(--color-text-secondary);
  margin-top: var(--space-1);
}

/* Settings footer */
.settings-footer {
  display: flex;
  justify-content: flex-end;
  gap: var(--space-3);
  padding-top: var(--space-5);
  margin-top: var(--space-5);
  border-top: 1px solid var(--color-border-default);
}
```

---

## 12. Motion & Animation

### 12.1 Animation Principles

| Principle | Application |
|-----------|-------------|
| **Purposeful** | Animation guides attention, never decorates |
| **Quick** | 150-300ms for UI, longer only for emphasis |
| **Consistent** | Same easing curves throughout |
| **Subtle** | Micro-interactions should be felt, not seen |

### 12.2 Timing Functions

```css
:root {
  /* Easing curves */
  --ease-default: cubic-bezier(0.4, 0, 0.2, 1);
  --ease-in: cubic-bezier(0.4, 0, 1, 1);
  --ease-out: cubic-bezier(0, 0, 0.2, 1);
  --ease-in-out: cubic-bezier(0.4, 0, 0.2, 1);
  --ease-bounce: cubic-bezier(0.34, 1.56, 0.64, 1);
  
  /* Durations */
  --duration-instant: 50ms;
  --duration-fast: 150ms;
  --duration-normal: 250ms;
  --duration-slow: 400ms;
  --duration-slower: 600ms;
}
```

### 12.3 Standard Animations

```css
/* Fade */
@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}

@keyframes fadeOut {
  from { opacity: 1; }
  to { opacity: 0; }
}

/* Slide */
@keyframes slideInFromRight {
  from { transform: translateX(100%); opacity: 0; }
  to { transform: translateX(0); opacity: 1; }
}

@keyframes slideInFromBottom {
  from { transform: translateY(20px); opacity: 0; }
  to { transform: translateY(0); opacity: 1; }
}

/* Scale */
@keyframes scaleIn {
  from { transform: scale(0.95); opacity: 0; }
  to { transform: scale(1); opacity: 1; }
}

/* Page transitions */
@keyframes pageEnter {
  from {
    opacity: 0;
    transform: translateY(8px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

/* Staggered list items */
.stagger-item {
  animation: slideInFromBottom var(--duration-normal) var(--ease-out) backwards;
}

.stagger-item:nth-child(1) { animation-delay: 0ms; }
.stagger-item:nth-child(2) { animation-delay: 50ms; }
.stagger-item:nth-child(3) { animation-delay: 100ms; }
.stagger-item:nth-child(4) { animation-delay: 150ms; }
.stagger-item:nth-child(5) { animation-delay: 200ms; }

/* Loading spinner */
@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.spinner {
  width: 20px;
  height: 20px;
  border: 2px solid var(--color-border-default);
  border-top-color: var(--color-action-primary);
  border-radius: var(--radius-full);
  animation: spin 600ms linear infinite;
}

/* Skeleton loading */
@keyframes shimmer {
  0% { background-position: -200% 0; }
  100% { background-position: 200% 0; }
}

.skeleton {
  background: linear-gradient(
    90deg,
    var(--color-bg-sunken) 25%,
    var(--color-bg-surface) 50%,
    var(--color-bg-sunken) 75%
  );
  background-size: 200% 100%;
  animation: shimmer 1.5s infinite;
  border-radius: var(--radius-sm);
}
```

### 12.4 Micro-Interactions

```css
/* Button press effect */
.btn:active:not(:disabled) {
  transform: translateY(1px);
}

/* Card hover lift */
.card-interactive:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-lg);
}

/* Icon rotation on expand */
.expand-icon {
  transition: transform var(--duration-fast) var(--ease-default);
}

.expand-icon-open {
  transform: rotate(180deg);
}

/* Checkbox check animation */
@keyframes checkmark {
  0% { stroke-dashoffset: 24; }
  100% { stroke-dashoffset: 0; }
}

.checkbox-checked .checkmark {
  animation: checkmark var(--duration-fast) var(--ease-out) forwards;
}

/* Focus ring pulse */
@keyframes focusPulse {
  0%, 100% { box-shadow: var(--shadow-focus); }
  50% { box-shadow: 0 0 0 2px var(--color-bg-surface), 0 0 0 6px var(--primitive-blue-200); }
}

.focus-visible-animated:focus-visible {
  animation: focusPulse 2s var(--ease-in-out) infinite;
}
```

---

## 13. Theming Architecture

### 13.1 Theme Token Structure

```css
/* Customer theme is applied via data attribute */
[data-theme="custom"] {
  /* Brand colors - overridden by customer */
  --color-action-primary: var(--customer-primary, #2563EB);
  --color-action-primary-hover: var(--customer-primary-hover, #1D4ED8);
  
  /* Can override any semantic token */
  --color-bg-page: var(--customer-bg-page, #FAFAF9);
  --color-bg-surface: var(--customer-bg-surface, #FFFFFF);
  
  /* Typography can be customized */
  --font-heading: var(--customer-font-heading, "JetBrains Mono", monospace);
  --font-body: var(--customer-font-body, "IBM Plex Sans", sans-serif);
}
```

### 13.2 Theme Application Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     THEME LOADING FLOW                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │  1. Load default theme        │
              │     (CSS custom properties)   │
              └───────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │  2. Load customer config      │
              │     (from eldrin.config.ts)   │
              └───────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │  3. Apply overrides           │
              │     (CSS variables updated)   │
              └───────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │  4. Load custom fonts         │
              │     (if specified)            │
              └───────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │  5. Apply to :root            │
              │     (or data-theme attribute) │
              └───────────────────────────────┘
```

### 13.3 Theme Provider Implementation

```typescript
interface ThemeConfig {
  mode: 'light' | 'dark' | 'system';
  
  branding: {
    name: string;
    logo: string;
    logoMark?: string;  // Square icon version
    favicon: string;
    removePoweredBy: boolean;
  };
  
  colors: {
    primary: string;
    primaryHover?: string;
    secondary?: string;
    accent?: string;
    // ... other color overrides
  };
  
  typography?: {
    fontHeading?: string;
    fontBody?: string;
    fontMono?: string;
    googleFonts?: string[];  // Fonts to load from Google Fonts
  };
  
  radius?: 'none' | 'small' | 'medium' | 'large';
}

// React context
const ThemeContext = createContext<ThemeContextValue>(null);

function ThemeProvider({ children, config }: ThemeProviderProps) {
  // Apply theme to document
  useEffect(() => {
    applyThemeTokens(config);
    loadCustomFonts(config.typography?.googleFonts);
  }, [config]);
  
  return (
    <ThemeContext.Provider value={{ theme: config, setTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}
```

---

## 14. Accessibility Requirements

### 14.1 WCAG 2.1 AA Compliance

| Requirement | Implementation |
|-------------|----------------|
| **Color Contrast** | Minimum 4.5:1 for text, 3:1 for large text |
| **Focus Indicators** | Visible focus ring on all interactive elements |
| **Keyboard Navigation** | All functionality accessible via keyboard |
| **Screen Readers** | Proper ARIA labels and landmarks |
| **Motion** | Respect prefers-reduced-motion |

### 14.2 Focus Management

```css
/* Visible focus for all interactive elements */
:focus-visible {
  outline: none;
  box-shadow: var(--shadow-focus);
}

/* Skip link */
.skip-link {
  position: absolute;
  top: -100%;
  left: var(--space-4);
  padding: var(--space-2) var(--space-4);
  background: var(--color-bg-surface);
  border: 1px solid var(--color-border-default);
  border-radius: var(--radius-md);
  z-index: var(--z-max);
}

.skip-link:focus {
  top: var(--space-4);
}
```

### 14.3 Reduced Motion

```css
@media (prefers-reduced-motion: reduce) {
  *,
  *::before,
  *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}
```

### 14.4 ARIA Patterns

```html
<!-- Navigation landmark -->
<nav aria-label="Main navigation">
  <ul role="list">
    <li><a href="/dashboard" aria-current="page">Dashboard</a></li>
  </ul>
</nav>

<!-- Modal dialog -->
<div 
  role="dialog" 
  aria-modal="true" 
  aria-labelledby="modal-title"
  aria-describedby="modal-description"
>
  <h2 id="modal-title">Confirm Action</h2>
  <p id="modal-description">Are you sure you want to proceed?</p>
</div>

<!-- Loading state -->
<button aria-busy="true" aria-disabled="true">
  <span class="spinner" aria-hidden="true"></span>
  <span class="sr-only">Loading...</span>
  Saving...
</button>

<!-- Live regions for notifications -->
<div aria-live="polite" aria-atomic="true" class="sr-only">
  Invoice saved successfully
</div>
```

---

## 15. Responsive Design

### 15.1 Breakpoint Strategy

```css
/* Mobile-first breakpoints */
/* Default: Mobile (<640px) */

@media (min-width: 640px) {
  /* Small tablets and up */
}

@media (min-width: 768px) {
  /* Tablets and up */
}

@media (min-width: 1024px) {
  /* Desktop and up */
}

@media (min-width: 1280px) {
  /* Large desktop and up */
}

@media (min-width: 1536px) {
  /* Extra large screens */
}
```

### 15.2 Responsive Layout Behavior

| Breakpoint | Side Nav | Top Bar | Content |
|------------|----------|---------|---------|
| < 768px | Hidden (hamburger menu) | Simplified | Full width |
| 768px - 1024px | Collapsed (icons only) | Full | With margin |
| > 1024px | Expanded | Full | With margin |

### 15.3 Mobile Navigation

```css
/* Mobile menu overlay */
@media (max-width: 767px) {
  .sidenav {
    position: fixed;
    inset: 0;
    width: 100%;
    max-width: 300px;
    transform: translateX(-100%);
    transition: transform var(--duration-normal) var(--ease-out);
    z-index: var(--z-modal);
  }
  
  .sidenav-open {
    transform: translateX(0);
  }
  
  .sidenav-backdrop {
    position: fixed;
    inset: 0;
    background: var(--color-bg-overlay);
    z-index: calc(var(--z-modal) - 1);
  }
  
  .main-content {
    margin-left: 0;
  }
}
```

---

## 16. Technical Implementation

### 16.1 CSS Architecture

```
styles/
├── tokens/
│   ├── _primitives.css      # Raw values
│   ├── _semantic.css        # Purpose-based tokens
│   └── _components.css      # Component-specific tokens
│
├── base/
│   ├── _reset.css           # CSS reset/normalize
│   ├── _typography.css      # Type scale & styles
│   └── _utilities.css       # Utility classes
│
├── components/
│   ├── _buttons.css
│   ├── _inputs.css
│   ├── _cards.css
│   ├── _modals.css
│   └── ...
│
├── layout/
│   ├── _shell.css           # Main layout structure
│   ├── _navigation.css      # Nav components
│   └── _grid.css            # Grid system
│
├── themes/
│   ├── _light.css           # Light theme overrides
│   └── _dark.css            # Dark theme overrides
│
└── main.css                 # Entry point
```

### 16.2 React Component Structure

```typescript
// Component file structure
components/
├── ui/                      # Primitive UI components
│   ├── Button/
│   │   ├── Button.tsx
│   │   ├── Button.styles.ts  # If using CSS-in-JS
│   │   ├── Button.test.tsx
│   │   └── index.ts
│   ├── Input/
│   ├── Card/
│   └── ...
│
├── layout/                  # Layout components
│   ├── Shell/
│   ├── TopBar/
│   ├── SideNav/
│   └── ...
│
├── features/               # Feature-specific components
│   ├── Auth/
│   ├── Dashboard/
│   ├── Settings/
│   └── ...
│
└── shared/                 # Shared/compound components
    ├── DataTable/
    ├── SearchCommand/
    └── ...
```

### 16.3 Styling Approach

**Recommended: CSS Modules + CSS Custom Properties**

```typescript
// Button.tsx
import styles from './Button.module.css';
import clsx from 'clsx';

interface ButtonProps {
  variant?: 'primary' | 'secondary' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  children: React.ReactNode;
}

export function Button({ 
  variant = 'primary', 
  size = 'md', 
  children,
  ...props 
}: ButtonProps) {
  return (
    <button 
      className={clsx(
        styles.btn,
        styles[`btn-${variant}`],
        styles[`btn-${size}`]
      )}
      {...props}
    >
      {children}
    </button>
  );
}
```

```css
/* Button.module.css */
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: var(--space-2);
  font-family: var(--font-body);
  font-weight: var(--weight-medium);
  border-radius: var(--radius-md);
  cursor: pointer;
  transition: all 150ms ease;
}

.btn-primary {
  background: var(--color-action-primary);
  color: var(--color-text-inverse);
}

/* ... etc */
```

### 16.4 Icon System

Using **Lucide React** for consistent, customizable icons:

```typescript
import { 
  Home, 
  FileText, 
  Users, 
  Settings,
  ChevronRight,
  Plus
} from 'lucide-react';

// Icon wrapper for consistent sizing
interface IconProps {
  icon: LucideIcon;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export function Icon({ icon: IconComponent, size = 'md', className }: IconProps) {
  const sizeMap = {
    sm: 16,
    md: 20,
    lg: 24
  };
  
  return (
    <IconComponent 
      size={sizeMap[size]} 
      strokeWidth={1.5}
      className={className}
    />
  );
}
```

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | December 2024 | Design Team | Initial specification |

---

*This document defines the frontend design system for the Eldrin Core Shell. All UI implementations should reference these specifications to ensure visual consistency across the platform.*
