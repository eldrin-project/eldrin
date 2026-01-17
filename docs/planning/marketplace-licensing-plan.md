# Eldrin Marketplace Code Protection & Licensing System

## Overview

Design a system to protect paid apps in the Eldrin marketplace, enforce license/subscription compliance, and deliver encrypted app bundles to customer Cloudflare Workers.

### Key Decisions (from user)
- **Bundle hosting**: Git repository (`github.com/eldrin-project/eldrin-marketplace-dist`)
- **Bundle convention**: `developer_id/app_name/version` (e.g., `eldrin.io/crm/v0.0.1`)
- **License server**: Separate worker in `eldrin-website` project
- **Server-bound hooks**: No - client-side only architecture
- **Grace period**: 7 days for subscription lapses

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    ELDRIN CENTRAL (eldrin-website Worker)               │
│  ┌──────────────────┐  ┌─────────────────────────────────────────────┐ │
│  │  License Server  │  │  Key Management                             │ │
│  │  /api/license/*  │  │  Per-customer keys, Key wrapping            │ │
│  │  Token issuance  │  │                                             │ │
│  └──────────────────┘  └─────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
              │
              │  License Token + Wrapped Key
              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│               MARKETPLACE DIST (GitHub Repository)                       │
│  github.com/eldrin-project/eldrin-marketplace-dist                       │
│  ├── eldrin.io/crm/v0.0.1/                                              │
│  │   ├── eldrin-app.manifest.json                                        │
│  │   ├── bundle.enc.js (encrypted)                                       │
│  │   └── meta.json                                                       │
│  └── eldrin.io/catalog/v0.0.1/                                          │
└─────────────────────────────────────────────────────────────────────────┘
              │
              │  Encrypted Bundle (via GitHub raw/Pages)
              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      CUSTOMER CLOUDFLARE WORKER                          │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │                      ELDRIN SHELL (eldrin-core)                    │ │
│  │  License Validator → Fetch Bundle → Decrypt → single-spa Register  │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Implementation Plan

### Phase 1: License Token System

**Goal**: Implement JWT-based license tokens for paid apps.

#### 1.1 License Types & Schema

**Pricing Models:**
| Model | Description | Billing |
|-------|-------------|---------|
| `free` | No cost | None |
| `one-time` | Single purchase, perpetual access | One-time payment |
| `subscription` | Fixed monthly/yearly fee | Recurring |
| `per-user` | Price per licensed user | Recurring (seats × price) |

```typescript
// New file: eldrin-website/worker/types/license.ts
interface LicenseToken {
  iss: 'license.eldrin.io';
  sub: string;              // customerId
  aud: string;              // appId
  exp: number;              // 24h expiry
  iat: number;
  jti: string;              // unique token ID

  license: {
    type: 'one-time' | 'subscription' | 'per-user';
    planId: string;
    features: string[];
    purchasedAt: string;
    subscriptionExpiresAt: string | null;
    graceUntil: string | null;  // 7 days after expiry

    // Per-user specific fields
    seats?: {
      purchased: number;      // Number of seats purchased
      used: number;           // Currently assigned users
      pricePerSeat: number;   // Price per seat (for display)
    };
    licensedUsers?: string[]; // User IDs with access (for validation)
  };

  keyVersion: number;
  keyId: string;
}
```

#### 1.1.1 Per-User License Flow

```
Per-User Subscription Flow:
1. Customer purchases app with X seats (e.g., 10 users at $1/user = $10/month)
2. Admin assigns users to seats in Eldrin shell settings
3. License token includes list of licensed user IDs
4. On app load, shell checks if current user is in licensedUsers list
5. If user not licensed → show "Request Access" prompt
6. Admin can add/remove users anytime (within seat limit)
7. To add more seats → upgrade subscription in billing portal
```

**Seat Management:**
- Seats can be reassigned between users at any time
- Adding seats: prorated charge for remainder of billing period
- Removing seats: takes effect at next billing cycle
- Over-limit: if more users assigned than seats, oldest assignments are revoked

#### 1.2 License Server Endpoints

Add to `eldrin-website/worker/`:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/license/validate` | POST | Validate license, return token |
| `/api/license/refresh` | POST | Refresh expiring token |
| `/api/license/revoke` | POST | Revoke license (admin) |
| `/api/license/status` | GET | Check subscription status |
| `/api/license/seats` | GET | Get seat assignments for per-user apps |
| `/api/license/seats/assign` | POST | Assign user to seat |
| `/api/license/seats/unassign` | POST | Remove user from seat |
| `/api/license/seats/upgrade` | POST | Purchase additional seats |

#### 1.3 Files to Create/Modify

- **CREATE**: `eldrin-website/worker/handlers/license.ts` - License API handlers
- **CREATE**: `eldrin-website/worker/services/jwt.ts` - JWT signing/verification
- **CREATE**: `eldrin-website/worker/types/license.ts` - License types
- **MODIFY**: `eldrin-website/worker/index.ts` - Add license routes

---

### Phase 2: Bundle Encryption & Delivery

**Goal**: Encrypt paid app bundles, deliver via CDN, decrypt in customer shell.

#### 2.1 Encryption Strategy

- **Algorithm**: AES-256-GCM (Web Crypto API native)
- **Bundle encryption**: At publish time, encrypt bundle with bundle key
- **Key wrapping**: Bundle key wrapped with customer-specific key
- **Storage**: Encrypted bundles on R2, wrapped keys in D1

```
App Bundle → [AES-GCM] → Encrypted Bundle (on R2)
                ↑
           Bundle Key → [Wrap with Customer Key] → Wrapped Key (in D1)
```

#### 2.2 Git Repository Structure

**Repository**: `github.com/eldrin-project/eldrin-marketplace-dist`
**URL Pattern**: `https://raw.githubusercontent.com/eldrin-project/eldrin-marketplace-dist/main/{developer_id}/{app_name}/{version}/`

```
eldrin-marketplace-dist/
├── eldrin.io/                        # Developer ID (first-party)
│   ├── catalog/
│   │   └── v0.0.1/
│   │       ├── eldrin-app.manifest.json  # Public (includes pricing info)
│   │       ├── bundle.js             # Free apps: plain bundle
│   │       ├── bundle.enc.js         # Paid apps: encrypted bundle
│   │       └── meta.json             # { algorithm, iv, hash, signature }
│   ├── crm/
│   │   └── v0.0.1/
│   │       ├── eldrin-app.manifest.json
│   │       └── bundle.js             # Free app
│   └── invoicing/
│       └── v0.0.1/
│           ├── eldrin-app.manifest.json
│           ├── bundle.enc.js         # Paid app
│           └── meta.json
├── third-party-dev/                  # Third-party developer ID
│   └── analytics/
│       └── v1.0.0/
│           ├── eldrin-app.manifest.json
│           ├── bundle.enc.js
│           └── meta.json
└── README.md
```

**URL Examples**:
- Manifest: `https://raw.githubusercontent.com/eldrin-project/eldrin-marketplace-dist/main/eldrin.io/crm/v0.0.1/eldrin-app.manifest.json`
- Bundle: `https://raw.githubusercontent.com/eldrin-project/eldrin-marketplace-dist/main/eldrin.io/crm/v0.0.1/bundle.js`

#### 2.3 Files to Create/Modify

- **CREATE**: `eldrin-website/worker/services/encryption.ts` - AES-GCM encrypt/decrypt
- **CREATE**: `eldrin-website/worker/services/keyManagement.ts` - Key generation, wrapping
- **CREATE**: `eldrin-marketplace-dist/` - Initialize Git repository structure
- **CREATE**: Build script to publish encrypted bundles to marketplace-dist repo

---

### Phase 3: Shell-Side License Enforcement

**Goal**: Modify eldrin-core to validate licenses before loading paid apps.

#### 3.1 License Validation Flow

```
1. Shell loads → fetchEnabledApps()
2. For each app → loadManifest()
3. If manifest.pricing.model !== 'free':
   a. Call license server → validateLicense(customerId, appId)
   b. If invalid → show upgrade prompt, skip registration
   c. If valid → get wrapped key, decrypt bundle
4. Register with single-spa
```

#### 3.2 Manifest Extension

```typescript
// Extend manifest.ts
interface AppManifest {
  // ... existing fields ...

  pricing?: {
    model: 'free' | 'one-time' | 'subscription' | 'per-user';
    plans?: Array<{
      id: string;
      price: number;
      currency: string;
      interval?: 'month' | 'year';
      features: string[];

      // Per-user specific
      perUser?: {
        minSeats: number;       // Minimum seats required (e.g., 1)
        maxSeats: number;       // Maximum seats allowed (e.g., 1000)
        pricePerSeat: number;   // Price per seat per interval
        includedSeats?: number; // Seats included in base price (e.g., 5)
      };
    }>;
  };

  // For paid apps
  encryptedEntry?: string;  // Path to .enc.js bundle
}
```

**Per-User Pricing Example (eldrin-app.manifest.json):**
```json
{
  "pricing": {
    "model": "per-user",
    "plans": [
      {
        "id": "team",
        "price": 0,
        "currency": "USD",
        "interval": "month",
        "features": ["basic", "reports"],
        "perUser": {
          "minSeats": 1,
          "maxSeats": 100,
          "pricePerSeat": 5,
          "includedSeats": 0
        }
      },
      {
        "id": "enterprise",
        "price": 99,
        "currency": "USD",
        "interval": "month",
        "features": ["basic", "reports", "api", "sso"],
        "perUser": {
          "minSeats": 10,
          "maxSeats": 1000,
          "pricePerSeat": 3,
          "includedSeats": 10
        }
      }
    ]
  }
}
```

#### 3.3 Per-User License Validation in Shell

For per-user licenses, the shell performs an additional check:

```typescript
// In licenseValidator.ts
async function validateUserAccess(
  license: LicenseToken,
  currentUserId: string
): Promise<{ allowed: boolean; reason?: string }> {
  // For non-per-user licenses, all authenticated users have access
  if (license.license.type !== 'per-user') {
    return { allowed: true };
  }

  // Check if current user is in the licensed users list
  if (!license.license.licensedUsers?.includes(currentUserId)) {
    return {
      allowed: false,
      reason: 'no_seat',  // User doesn't have a seat assigned
    };
  }

  return { allowed: true };
}
```

**UI States for Per-User Apps:**
| User State | UI Shown |
|------------|----------|
| Has seat | App loads normally |
| No seat (seats available) | "Request Access" button → notifies admin |
| No seat (seats full) | "No seats available" message with seat count |
| Admin | Seat management UI in app settings |

#### 3.4 Files to Create/Modify

- **CREATE**: `eldrin-core/src/services/licenseValidator.ts` - License validation
- **CREATE**: `eldrin-core/src/services/bundleDecryptor.ts` - AES-GCM decryption
- **CREATE**: `eldrin-core/src/stores/licenseStore.ts` - License state
- **CREATE**: `eldrin-core/src/types/license.ts` - License types
- **MODIFY**: `eldrin-core/src/services/manifestLoader.ts` - Add license check
- **MODIFY**: `eldrin-core/src/App.tsx` - Integrate license validation in registration
- **MODIFY**: `eldrin-core/src/types/manifest.ts` - Add pricing fields

---

### Phase 4: Revocation & Grace Period

**Goal**: Handle subscription cancellation with grace period.

#### 4.1 Revocation Flow

```
1. Stripe webhook → subscription cancelled
2. License server → add to revocation list
3. Set graceUntil = now + 7 days
4. Customer's next license check:
   - Token includes graceUntil claim
   - Shell shows "Subscription ending" warning
5. After grace period:
   - Token validation fails
   - App blocked from loading
```

#### 4.2 Grace Period States

| State | Token Valid | App Loads | UI Indicator |
|-------|-------------|-----------|--------------|
| Active | Yes | Yes | None |
| Grace (subscription expired) | Yes | Yes | Warning banner |
| Grace (network issue) | Yes (cached) | Yes | "Offline" indicator |
| Revoked | No | No | Upgrade prompt |

#### 4.3 Files to Create/Modify

- **CREATE**: `eldrin-website/worker/handlers/webhooks.ts` - Stripe webhooks
- **CREATE**: `eldrin-website/worker/services/revocation.ts` - Revocation list management
- **CREATE**: `eldrin-core/src/components/LicenseWarning.tsx` - Grace period UI
- **MODIFY**: `eldrin-core/src/layouts/Shell.tsx` - Show license warnings

---

### Phase 5: Database Migration Distribution

**Goal**: Distribute and execute app database migrations on customer infrastructure.

#### 5.1 Migration Package Structure

Migrations are included in the marketplace-dist repo alongside the bundle:

```
eldrin-marketplace-dist/
├── eldrin.io/
│   └── crm/
│       └── v0.0.1/
│           ├── eldrin-app.manifest.json
│           ├── bundle.js
│           └── migrations/
│               ├── index.json          # Migration manifest
│               ├── 0001_create_contacts.sql
│               ├── 0002_create_companies.sql
│               └── 0003_add_tags.sql
```

#### 5.2 Migration Manifest (migrations/index.json)

```json
{
  "database": "crm",
  "migrations": [
    { "id": "0001", "file": "0001_create_contacts.sql", "checksum": "sha256:abc..." },
    { "id": "0002", "file": "0002_create_companies.sql", "checksum": "sha256:def..." },
    { "id": "0003", "file": "0003_add_tags.sql", "checksum": "sha256:ghi..." }
  ]
}
```

#### 5.3 App Manifest Extension

```typescript
// Extend manifest.ts
interface AppManifest {
  // ... existing fields ...

  database?: {
    name: string;              // D1 database binding name (e.g., "CRM_DB")
    migrationsPath: string;    // Relative path to migrations folder
  };
}
```

#### 5.4 Migration Execution Flow

```
App Install/Update Flow:
1. Shell detects app needs installation or version upgrade
2. Fetch migrations/index.json from marketplace-dist
3. Compare with applied migrations (tracked in core D1)
4. For each pending migration:
   a. Fetch .sql file from marketplace-dist
   b. Validate checksum
   c. Execute SQL against app's D1 database
   d. Record migration as applied
5. Continue with app loading
```

#### 5.5 Migration Tracking Table (in eldrin-core D1)

```sql
CREATE TABLE app_migrations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id TEXT NOT NULL,
  migration_id TEXT NOT NULL,
  checksum TEXT NOT NULL,
  applied_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(app_id, migration_id)
);
```

#### 5.6 Migration Execution Options

| Option | When to Run | Pros | Cons |
|--------|-------------|------|------|
| **Shell startup** | On app load if pending migrations | Simple, automatic | Delays first load |
| **Background worker** | Via scheduled worker | Non-blocking | More complex setup |
| **Manual trigger** | Admin clicks "Update" | Full control | Requires user action |

**Recommendation**: Shell startup with progress indicator for initial install, background for updates.

#### 5.7 Handling Migration Failures

```typescript
interface MigrationResult {
  success: boolean;
  appliedMigrations: string[];
  failedMigration?: {
    id: string;
    error: string;
  };
}

// On failure:
// 1. Stop at failed migration (don't continue)
// 2. Show error to admin with SQL details
// 3. App remains on previous working version
// 4. Allow retry or manual intervention
```

#### 5.8 Files to Create/Modify

- **CREATE**: `eldrin-core/src/services/migrationRunner.ts` - Execute migrations
- **CREATE**: `eldrin-core/src/services/migrationTracker.ts` - Track applied migrations
- **MODIFY**: `eldrin-core/src/App.tsx` - Check migrations before app load
- **MODIFY**: `eldrin-core/src/types/manifest.ts` - Add database field
- **MODIFY**: `eldrin-core/migrations/` - Add app_migrations table

---

### Phase 6: SDK & Developer Experience

**Goal**: Provide SDK hooks for apps to check licenses/features.

#### 6.1 SDK License Hooks

```typescript
// @eldrin/sdk additions
export function useLicense(): LicenseState;
export function useFeature(featureId: string): boolean;
export function usePlan(): PlanInfo;
```

#### 6.2 Files to Create/Modify

- **CREATE**: `eldrin-core/src/sdk/license.ts` - License hooks
- **MODIFY**: Global `window.__ELDRIN__` API to expose license methods

---

## Database Schema Changes

### eldrin-website D1 (Central)

```sql
-- Customer licenses
CREATE TABLE customer_licenses (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  app_id TEXT NOT NULL,
  license_type TEXT NOT NULL,  -- 'one-time' | 'subscription' | 'per-user'
  plan_id TEXT NOT NULL,
  purchased_at TEXT NOT NULL,
  expires_at TEXT,             -- NULL for one-time
  stripe_subscription_id TEXT,
  status TEXT DEFAULT 'active',

  -- Per-user license fields
  seats_purchased INTEGER,     -- Number of seats purchased (per-user only)
  price_per_seat REAL,         -- Price per seat (for billing display)

  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(customer_id, app_id)
);

-- Seat assignments for per-user licenses
CREATE TABLE seat_assignments (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  app_id TEXT NOT NULL,
  user_id TEXT NOT NULL,       -- User ID assigned to this seat
  user_email TEXT NOT NULL,    -- User email (for display)
  assigned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  assigned_by TEXT NOT NULL,   -- Admin who made the assignment
  UNIQUE(customer_id, app_id, user_id),
  FOREIGN KEY (customer_id, app_id) REFERENCES customer_licenses(customer_id, app_id)
);

-- Index for quick lookup of user's licensed apps
CREATE INDEX idx_seat_assignments_user ON seat_assignments(user_id);

-- Wrapped keys per customer per app
CREATE TABLE customer_keys (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  app_id TEXT NOT NULL,
  app_version TEXT NOT NULL,
  wrapped_key TEXT NOT NULL,   -- AES key wrapped with customer key
  key_version INTEGER DEFAULT 1,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(customer_id, app_id, app_version)
);

-- Revocation list
CREATE TABLE revocations (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  app_id TEXT NOT NULL,
  revoked_at TEXT NOT NULL,
  reason TEXT NOT NULL,
  grace_ends TEXT NOT NULL,
  UNIQUE(customer_id, app_id)
);
```

---

## Critical Files Summary

### eldrin-website (License Server)
| File | Action | Purpose |
|------|--------|---------|
| `worker/index.ts` | MODIFY | Add license routes |
| `worker/handlers/license.ts` | CREATE | License API handlers |
| `worker/handlers/seats.ts` | CREATE | Seat management API handlers |
| `worker/handlers/webhooks.ts` | CREATE | Stripe webhooks |
| `worker/services/jwt.ts` | CREATE | JWT operations |
| `worker/services/encryption.ts` | CREATE | AES-GCM operations |
| `worker/services/keyManagement.ts` | CREATE | Key management |
| `worker/services/revocation.ts` | CREATE | Revocation handling |
| `worker/types/license.ts` | CREATE | Type definitions |
| `wrangler.toml` | MODIFY | Add D1 bindings |

### eldrin-marketplace-dist (Bundle Distribution)
| File | Action | Purpose |
|------|--------|---------|
| `README.md` | CREATE | Repository documentation |
| `eldrin.io/catalog/v0.0.1/eldrin-app.manifest.json` | CREATE | App manifest with pricing |
| `eldrin.io/catalog/v0.0.1/bundle.js` | CREATE | App bundle (free) |
| `eldrin.io/catalog/v0.0.1/migrations/` | CREATE | Database migrations |
| `eldrin.io/crm/v0.0.1/eldrin-app.manifest.json` | CREATE | App manifest |
| `eldrin.io/crm/v0.0.1/bundle.js` | CREATE | App bundle |
| `eldrin.io/crm/v0.0.1/migrations/` | CREATE | Database migrations |
| `.github/workflows/` | CREATE | CI for bundle validation (optional) |

### eldrin-core (Shell)
| File | Action | Purpose |
|------|--------|---------|
| `src/services/manifestLoader.ts` | MODIFY | Add license validation |
| `src/services/licenseValidator.ts` | CREATE | License validation logic |
| `src/services/bundleDecryptor.ts` | CREATE | Bundle decryption |
| `src/services/migrationRunner.ts` | CREATE | Execute SQL migrations |
| `src/services/migrationTracker.ts` | CREATE | Track applied migrations |
| `src/stores/licenseStore.ts` | CREATE | License state |
| `src/types/manifest.ts` | MODIFY | Add pricing & database fields |
| `src/types/license.ts` | CREATE | License types |
| `src/App.tsx` | MODIFY | Integrate license + migration flow |
| `src/components/LicenseWarning.tsx` | CREATE | Grace period UI |
| `src/components/SeatManagement.tsx` | CREATE | Per-user seat assignment UI |
| `src/components/NoSeatAccess.tsx` | CREATE | UI when user has no seat |
| `src/components/MigrationProgress.tsx` | CREATE | Migration progress UI |
| `src/layouts/Shell.tsx` | MODIFY | Show warnings |
| `src/sdk/license.ts` | CREATE | SDK license hooks |
| `migrations/0002_app_migrations.sql` | CREATE | Migration tracking table |

---

## Security Considerations

1. **JWT Signing**: Use Ed25519 for token signing (fast, secure)
2. **Key Storage**: Customer keys stored in D1 (wrapped), master keys in Cloudflare Secrets
3. **Bundle Hash**: SHA-256 hash verified after decryption
4. **Token Lifetime**: 24h with background refresh
5. **Grace Period**: 7 days for subscriptions, 4h for network issues
6. **Git Repository**: Public repo with encrypted bundles - encryption is the protection layer

## Limitations (Transparent to Developers)

- JavaScript is inherently readable once decrypted
- Determined attackers can bypass client-side protection
- Goal is "practical protection" - make piracy inconvenient, not impossible
- Backend logic (if needed later) provides stronger protection

---

## Implementation Order

1. **License token system** (Phase 1) - Foundation for everything
2. **Shell-side enforcement** (Phase 3) - Block unlicensed apps
3. **Bundle encryption** (Phase 2) - Protect code
4. **Database migrations** (Phase 5) - App database setup/updates
5. **Revocation & grace** (Phase 4) - Handle subscription lifecycle
6. **SDK hooks** (Phase 6) - Developer experience

---

## Implementation Progress

### Completed
- [ ] None yet

### In Progress
- [ ] Phase 1: License Token System

### Pending
- [ ] Phase 2: Bundle Encryption & Delivery
- [ ] Phase 3: Shell-Side License Enforcement
- [ ] Phase 4: Revocation & Grace Period
- [ ] Phase 5: Database Migration Distribution
- [ ] Phase 6: SDK & Developer Experience
