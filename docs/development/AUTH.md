# Plan: Authentication System with App-Scoped Permissions

## Goal

Implement email/password authentication with JWT tokens, featuring:
- **Platform-level roles** (admin/editor/viewer) for core features
- **App-scoped permissions** with format `developer_id:app_id:resource:action`
- **App-level groups** that bundle permissions
- **User overrides** (grants + denies) over group permissions

## Permission System Design

### Permission Format

```
developer_id:app_id:resource:action
```

Examples:
- `acme:invoicing:invoices:read`
- `acme:invoicing:invoices:write`
- `acme:crm:leads:delete`
- `platform:core:users:write` (platform-level)

### Two-Level Authorization

1. **Platform roles** (admin/editor/viewer) - for core features (settings, user management, app installation)
2. **App groups** - for app-specific features (defined per-app in manifest)

### Permission Calculation

```
effective_permissions =
  platform_role_permissions
  + user_app_group_permissions
  + user_explicit_grants
  - user_explicit_denies
```

User-level permissions (grants/denies) override group-level permissions.

### Manifest Declaration

Apps declare available permissions in `eldrin-app.manifest.json`:

```json
{
  "id": "invoicing",
  "developer_id": "acme",
  "permissions": [
    { "resource": "invoices", "actions": ["read", "write", "delete"] },
    { "resource": "customers", "actions": ["read", "write"] }
  ],
  "groups": [
    {
      "id": "admin",
      "name": "App Admin",
      "permissions": ["invoices:*", "customers:*"]
    },
    {
      "id": "viewer",
      "name": "Viewer",
      "permissions": ["invoices:read", "customers:read"]
    }
  ]
}
```

---

## Database Schema

### Core Auth Tables

```sql
-- Users
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  is_active INTEGER DEFAULT 1,
  created_at INTEGER,
  updated_at INTEGER
);

-- Platform Roles (admin, editor, viewer)
CREATE TABLE platform_roles (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  description TEXT
);

-- Platform Permissions (for core features)
CREATE TABLE platform_permissions (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,  -- e.g., "platform:core:users:write"
  description TEXT
);

-- Role -> Permission mapping
CREATE TABLE platform_role_permissions (
  role_id TEXT REFERENCES platform_roles(id),
  permission_id TEXT REFERENCES platform_permissions(id),
  PRIMARY KEY (role_id, permission_id)
);

-- User -> Platform Role mapping
CREATE TABLE user_platform_roles (
  user_id TEXT REFERENCES users(id),
  role_id TEXT REFERENCES platform_roles(id),
  PRIMARY KEY (user_id, role_id)
);
```

### App-Scoped Permission Tables

```sql
-- App Permissions (synced from manifest)
CREATE TABLE app_permissions (
  id TEXT PRIMARY KEY,
  app_id TEXT NOT NULL,
  developer_id TEXT NOT NULL,
  resource TEXT NOT NULL,
  action TEXT NOT NULL,
  full_name TEXT NOT NULL,  -- "developer_id:app_id:resource:action"
  UNIQUE (app_id, resource, action)
);

-- App Groups (synced from manifest)
CREATE TABLE app_groups (
  id TEXT PRIMARY KEY,
  app_id TEXT NOT NULL,
  developer_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  full_name TEXT NOT NULL,  -- "developer_id:app_id:group_id"
  UNIQUE (app_id, name)
);

-- Group -> Permission mapping
CREATE TABLE app_group_permissions (
  group_id TEXT REFERENCES app_groups(id),
  permission_id TEXT REFERENCES app_permissions(id),
  PRIMARY KEY (group_id, permission_id)
);

-- User -> App Group membership
CREATE TABLE user_app_groups (
  user_id TEXT REFERENCES users(id),
  group_id TEXT REFERENCES app_groups(id),
  PRIMARY KEY (user_id, group_id)
);

-- User explicit grants/denies (overrides groups)
CREATE TABLE user_app_permissions (
  user_id TEXT REFERENCES users(id),
  permission_id TEXT REFERENCES app_permissions(id),
  grant_type TEXT NOT NULL,  -- 'grant' or 'deny'
  PRIMARY KEY (user_id, permission_id)
);
```

---

## Implementation Phases

### Phase 1: Database Migration

**File**: `migrations/20251229000001-create-auth-tables.sql`

- Create all tables above
- Seed platform roles: admin, editor, viewer
- Seed platform permissions for core features
- Create default admin user

### Phase 2: Core Auth Module (`core/auth/`)

1. **`types.ts`** - Types including:
   ```typescript
   interface UserWithPermissions {
     id: string;
     email: string;
     platformRoles: string[];
     platformPermissions: string[];
     appPermissions: Record<string, string[]>;  // { "acme:invoicing": ["invoices:read", ...] }
   }
   ```

2. **`password.ts`** - PBKDF2 hashing (Web Crypto)

3. **`jwt.ts`** - JWT with compact permission payload

4. **`permissions.ts`** - Permission calculation:
   ```typescript
   async function calculateUserPermissions(db, userId): Promise<CalculatedPermissions>
   async function hasPermission(user, permission): boolean
   async function hasAppPermission(user, appId, resource, action): boolean
   ```

5. **`middleware.ts`** - Auth middleware with permission checking

### Phase 3: Permission Sync from Manifest

When an app is added/updated, sync its permissions and groups to the database:

**Modify**: `core/routes/apps.ts` - `handleAddApp()`, `handleUpdateApp()`

```typescript
async function syncAppPermissions(db, appId, developerId, manifest) {
  // 1. Upsert app_permissions from manifest.permissions
  // 2. Upsert app_groups from manifest.groups
  // 3. Update app_group_permissions mapping
}
```

### Phase 4: Auth Route Handlers

**File**: `core/routes/auth.ts`

| Endpoint | Description |
|----------|-------------|
| POST /api/auth/login | Return JWT with calculated permissions |
| GET /api/auth/me | Return user with all permissions |
| POST /api/auth/logout | Audit logging |

### Phase 5: Route Protection

- Platform endpoints check platform permissions
- App proxy injects calculated app permissions in headers

**Modify**: `core/routes/apps.ts` - `handleAppApiProxy()`

```typescript
// Inject headers:
X-Eldrin-User-Id: user-123
X-Eldrin-User-Permissions: invoices:read,invoices:write,customers:read
```

### Phase 6: Frontend Auth

**Modify**: `src/stores/authStore.ts`

```typescript
interface AuthState {
  user: User | null;
  platformPermissions: string[];
  appPermissions: Record<string, string[]>;

  hasPlatformPermission(perm: string): boolean;
  hasAppPermission(appId: string, resource: string, action: string): boolean;
}
```

### Phase 7: App Protection (eldrin-app-core)

**New**: `eldrin-app-core/src/auth/index.ts`

```typescript
export function getAuthContext(request: Request): AppAuthContext | null;
export function requirePermission(request: Request, resource: string, action: string): Response | AppAuthContext;
```

---

## Files to Create/Modify

### New Files (eldrin-core)
- `migrations/20251229000001-create-auth-tables.sql`
- `core/auth/types.ts`
- `core/auth/password.ts`
- `core/auth/jwt.ts`
- `core/auth/permissions.ts`
- `core/auth/middleware.ts`
- `core/auth/index.ts`
- `core/routes/auth.ts`
- `src/services/api.ts`

### Modify (eldrin-core)
- `core/routes/apps.ts` - sync permissions from manifest, inject auth headers
- `core/routes/index.ts` - export auth handlers
- `worker/index.ts` - auth routes + middleware
- `server/index.ts` - auth routes + middleware
- `src/stores/authStore.ts` - JWT-based auth with app permissions
- `src/pages/Login.tsx` - real API calls
- `src/types/manifest.ts` - add permissions/groups to manifest type

### New Files (eldrin-app-core)
- `src/auth/index.ts`

### Modify (eldrin-app-core)
- `src/index.ts` - export auth utilities
- `src/types.ts` - add permissions to manifest type

---

## Platform Permissions (Seed Data)

| Permission | Description | Roles |
|------------|-------------|-------|
| platform:core:apps:read | View installed apps | all |
| platform:core:apps:write | Install/remove apps | admin, editor |
| platform:core:users:read | View users | all |
| platform:core:users:write | Create/edit users | admin |
| platform:core:users:delete | Delete users | admin |
| platform:core:settings:read | View settings | all |
| platform:core:settings:write | Modify settings | admin |
| platform:core:permissions:manage | Manage user permissions | admin |

---

## Admin Hierarchy

1. **Platform Admin**: Full access to everything (platform + all apps)
2. **App Admin**: Can manage groups/permissions for their specific app only
   - Determined by `platform:core:permissions:manage` + membership in app admin group

---

## Deferred

- OAuth (Microsoft/Google)
- Password reset
- User management UI
- Permission management UI
- Refresh tokens
- MFA
