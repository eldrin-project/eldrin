# eldrin-app-core Library Requirements (Final)

## Overview

**Package Name:** `@eldrin/eldrin-app-core`  
**Purpose:** Standard library for Eldrin apps providing database migrations, storage isolation, event communication, and common utilities.  
**Distribution:** Public npm package  
**Target Users:** App developers building for the Eldrin platform

---

## Core Principles

1. **Zero-trust isolation** — Apps cannot access other apps' databases or storage
2. **Convention over configuration** — Sensible defaults, minimal boilerplate
3. **Optional database** — Support apps that don't need persistence
4. **Migration ownership** — Apps manage their own schema evolution
5. **Event-driven communication** — No direct inter-app database access

---

## Functional Requirements

### 1. Database Migration System

#### 1.1 Migration Definition
- **FR-1.1.1:** Migrations are plain SQL files stored in app's `/migrations` folder
- **FR-1.1.2:** Naming convention: `TIMESTAMP-description.sql` (e.g., `20250115120000-create-invoices-table.sql`)
- **FR-1.1.3:** Timestamp format: `YYYYMMDDHHmmss` (14 digits, sortable lexicographically)
- **FR-1.1.4:** Description uses kebab-case, descriptive of the change
- **FR-1.1.5:** Each file contains DDL/DML statements for a single migration
- **FR-1.1.6:** Support SQL comments for documentation
- **FR-1.1.7:** Multi-statement migrations supported via `db.batch()`

**Example:**
```sql
-- migrations/20250115120000-create-invoices-table.sql
CREATE TABLE invoices (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  total REAL NOT NULL,
  status TEXT DEFAULT 'draft',
  created_at INTEGER NOT NULL
);

CREATE INDEX idx_invoices_customer ON invoices(customer_id);
CREATE INDEX idx_invoices_status ON invoices(status);
```

#### 1.2 Migration Discovery & Execution
- **FR-1.2.1:** On app bootstrap, scan `/migrations` folder for all `.sql` files
- **FR-1.2.2:** Query app's `_eldrin_migrations` table for executed migrations
- **FR-1.2.3:** Compare filesystem files with database records to identify pending migrations
- **FR-1.2.4:** Sort pending migrations by timestamp (lexicographic sort of filename)
- **FR-1.2.5:** Execute migrations **one at a time** (not batched together) in timestamp order
- **FR-1.2.6:** Each migration runs in its own transaction (separate from other migrations)
- **FR-1.2.7:** Record successful migrations in `_eldrin_migrations` table
- **FR-1.2.8:** Halt on first migration failure and report error to shell

#### 1.3 Migration Tracking Table
- **FR-1.3.1:** Auto-create `_eldrin_migrations` table in app database if not exists
- **FR-1.3.2:** Table schema:
```sql
CREATE TABLE _eldrin_migrations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  filename TEXT NOT NULL UNIQUE,
  checksum TEXT NOT NULL,
  executed_at INTEGER NOT NULL,
  execution_time_ms INTEGER
);
```
- **FR-1.3.3:** Store complete filename (including timestamp and description)
- **FR-1.3.4:** Calculate and store SHA-256 checksum of migration file content
- **FR-1.3.5:** Record execution timestamp (Unix epoch milliseconds)
- **FR-1.3.6:** Record execution duration for monitoring
- **FR-1.3.7:** Prevent duplicate execution via UNIQUE constraint on filename

#### 1.4 Migration Rollback
- **FR-1.4.1:** Optional rollback files with naming convention: `TIMESTAMP-description.rollback.sql`
- **FR-1.4.2:** Rollback file must match corresponding migration timestamp
- **FR-1.4.3:** Rollback executes in reverse chronological order
- **FR-1.4.4:** Each rollback runs in its own transaction
- **FR-1.4.5:** Remove migration record from `_eldrin_migrations` after successful rollback
- **FR-1.4.6:** Support rollback to specific migration (rolls back all migrations after that point)

**Example:**
```sql
-- migrations/20250115120000-create-invoices-table.rollback.sql
DROP INDEX idx_invoices_status;
DROP INDEX idx_invoices_customer;
DROP TABLE invoices;
```

#### 1.5 Migration Integrity
- **FR-1.5.1:** On each run, verify checksums of previously executed migrations
- **FR-1.5.2:** Warn if executed migration file has been modified (checksum mismatch)
- **FR-1.5.3:** Prevent execution if modified migration detected (fail-safe mode)
- **FR-1.5.4:** Allow override flag for development environments
- **FR-1.5.5:** Detect and report orphaned migrations (in DB but file deleted)

#### 1.6 Migration Execution Flow
```
App Bootstrap
  ↓
Check for /migrations folder
  ↓
Create _eldrin_migrations table (if needed)
  ↓
Read all .sql files from /migrations
  ↓
Query _eldrin_migrations for executed list
  ↓
Calculate pending = filesystem - executed
  ↓
Sort pending by timestamp (filename)
  ↓
For each pending migration (ONE AT A TIME):
  - Calculate checksum
  - Start transaction
  - Execute SQL via db.batch()
  - Insert record into _eldrin_migrations
  - Commit transaction
  - Log execution time
  ↓
Report success/failure to shell
```

#### 1.7 Error Handling
- **FR-1.7.1:** Roll back failed migration transaction automatically
- **FR-1.7.2:** Do NOT roll back previously successful migrations
- **FR-1.7.3:** Log detailed error (SQL statement, line number, error message)
- **FR-1.7.4:** Mark app as "migration failed" status in shell
- **FR-1.7.5:** Prevent app loading until migration issue resolved
- **FR-1.7.6:** Provide retry mechanism after developer fixes migration

#### 1.8 Migration Utilities (CLI)
- **FR-1.8.1:** CLI command: `npx eldrin-app migrate:create <description>`
  - Generates new migration file with current timestamp
  - Optionally generates matching `.rollback.sql` file with template
  - Opens files in editor
- **FR-1.8.2:** CLI command: `npx eldrin-app migrate:status`
  - Lists pending and executed migrations
  - Shows checksum mismatches
  - Displays execution times
- **FR-1.8.3:** CLI command: `npx eldrin-app migrate:rollback [target]`
  - Rolls back migrations to specified target (or last migration if no target)
  - Requires corresponding `.rollback.sql` files
  - Confirms before executing
- **FR-1.8.4:** CLI command: `npx eldrin-app migrate:reset` (dev only)
  - Drops all tables and re-runs migrations from scratch
  - Requires `--confirm` flag

### 2. Database Seeding

#### 2.1 Seed Definition
- **FR-2.1.1:** Seed files are SQL files stored in app's `/seeds` folder
- **FR-2.1.2:** Naming convention: `TIMESTAMP-description.seed.sql` (e.g., `20250115120000-sample-invoices.seed.sql`)
- **FR-2.1.3:** Seeds are for development/testing data only
- **FR-2.1.4:** Seeds are NOT tracked in `_eldrin_migrations` table
- **FR-2.1.5:** Seeds can be re-run multiple times (should be idempotent)

**Example:**
```sql
-- seeds/20250115120000-sample-invoices.seed.sql
-- Insert sample invoices for development
INSERT OR IGNORE INTO invoices (id, customer_id, total, status, created_at)
VALUES 
  ('inv_001', 'cust_123', 1500.00, 'paid', 1705320000000),
  ('inv_002', 'cust_456', 2300.50, 'pending', 1705406400000),
  ('inv_003', 'cust_789', 750.00, 'draft', 1705492800000);
```

#### 2.2 Seed Execution
- **FR-2.2.1:** Seeds are NOT run automatically during app bootstrap
- **FR-2.2.2:** Seeds must be explicitly triggered via CLI or development mode
- **FR-2.2.3:** All seeds run in a single transaction (can be rolled back together)
- **FR-2.2.4:** Seeds run in timestamp order
- **FR-2.2.5:** Environment check: seeds only run in development/staging, never production

#### 2.3 Seed CLI Commands
- **FR-2.3.1:** `npx eldrin-app seed:create <description>` - Generate new seed file
- **FR-2.3.2:** `npx eldrin-app seed:run` - Execute all seeds in /seeds folder
- **FR-2.3.3:** `npx eldrin-app seed:run <filename>` - Execute specific seed file

### 3. Storage Isolation

#### 3.1 R2 Bucket Abstraction
- **FR-3.1.1:** Provide `useStorage()` hook/API that returns app-scoped R2 client
- **FR-3.1.2:** Automatically namespace all storage operations to app ID (e.g., `app-invoicing/file.pdf`)
- **FR-3.1.3:** Prevent access to storage paths outside app's namespace
- **FR-3.1.4:** Support for presigned URLs scoped to app storage

#### 3.2 File Management
- **FR-3.2.1:** Helper functions for upload, download, delete, list operations
- **FR-3.2.2:** Automatic file metadata tracking (size, type, upload date)
- **FR-3.2.3:** Support for file versioning/revisions (optional)
- **FR-3.2.4:** Temporary file cleanup utilities

### 4. Database Access Layer

#### 4.1 Database Client
- **FR-4.1.1:** Provide `useDatabase()` hook that returns app's isolated D1 instance
- **FR-4.1.2:** Automatically scope all queries to app's database
- **FR-4.1.3:** Prevent SQL injection through parameterized queries
- **FR-4.1.4:** Support for batch operations and transactions via `db.batch()`

#### 4.2 Query Helpers (Optional)
- **FR-4.2.1:** Optional lightweight helpers on top of D1
- **FR-4.2.2:** Type-safe query construction helpers
- **FR-4.2.3:** Support for common patterns (CRUD, pagination, filtering)

#### 4.3 Database-less Apps
- **FR-4.3.1:** Library functions gracefully when app declares no database in manifest
- **FR-4.3.2:** Skip migration system if no `/migrations` folder exists
- **FR-4.3.3:** `useDatabase()` returns null/undefined for database-less apps

### 5. Event Communication System

#### 5.1 Event Publishing
- **FR-5.1.1:** Provide `emit(eventName, payload)` function to publish events
- **FR-5.1.2:** Support typed event payloads (TypeScript generics)
- **FR-5.1.3:** Automatic app ID prefixing (e.g., `invoicing:invoice.paid`)
- **FR-5.1.4:** Event validation against manifest declarations

#### 5.2 Event Subscription
- **FR-5.2.1:** Provide `on(eventName, handler)` to subscribe to events
- **FR-5.2.2:** Support wildcard subscriptions (`crm:*` or `*:contact.created`)
- **FR-5.2.3:** Automatic cleanup on app unmount
- **FR-5.2.4:** Error handling and retry logic for failed handlers

#### 5.3 Event Lifecycle
- **FR-5.3.1:** Queue events if subscriber app is not loaded
- **FR-5.3.2:** Persist critical events to ensure delivery
- **FR-5.3.3:** Event deduplication to prevent duplicate processing
- **FR-5.3.4:** Event audit log (optional, for debugging)

### 6. App Lifecycle Management

#### 6.1 Initialization
- **FR-6.1.1:** Provide `createApp()` factory function that returns single-spa lifecycle
- **FR-6.1.2:** Handle bootstrap, mount, unmount phases
- **FR-6.1.3:** Run migrations automatically before first mount
- **FR-6.1.4:** Initialize event listeners and storage connections

#### 6.2 Configuration
- **FR-6.2.1:** Read app configuration from `eldrin-app.manifest.json`
- **FR-6.2.2:** Merge manifest config with runtime environment variables
- **FR-6.2.3:** Validate required permissions and capabilities
- **FR-6.2.4:** Expose `useConfig()` hook for accessing app settings

#### 6.3 Health Checks
- **FR-6.3.1:** Provide health check endpoint for app status
- **FR-6.3.2:** Report database connectivity, migration status, storage availability
- **FR-6.3.3:** Self-healing mechanisms (reconnect DB, retry failed operations)

### 7. Developer Experience

#### 7.1 Boilerplate Reduction
- **FR-7.1.1:** Scaffold new app with CLI: `npx create-eldrin-app`
- **FR-7.1.2:** Generate boilerplate for common patterns (CRUD, list views, forms)
- **FR-7.1.3:** Provide TypeScript types for all APIs
- **FR-7.1.4:** Auto-import common hooks in development

#### 7.2 Development Tools
- **FR-7.2.1:** Local development mode with hot module reload
- **FR-7.2.2:** Mock event bus for testing inter-app communication
- **FR-7.2.3:** Database seeding utilities for development
- **FR-7.2.4:** Storage emulator for local testing (miniflare/wrangler)

#### 7.3 Testing Utilities
- **FR-7.3.1:** Test helpers for mocking Eldrin context
- **FR-7.3.2:** Factory functions for creating test fixtures
- **FR-7.3.3:** Integration test harness for event flows
- **FR-7.3.4:** Migration rollback/reset utilities for tests

---

## Non-Functional Requirements

### Performance
- **NFR-1:** Migration discovery completes in <50ms (filesystem scan + DB query)
- **NFR-2:** Single migration execution limited to <2 seconds
- **NFR-3:** Total migration time <10 seconds on cold start (assuming reasonable number of pending migrations)
- **NFR-4:** Event dispatch overhead <10ms per event
- **NFR-5:** Storage operations use streaming for files >1MB
- **NFR-6:** Bundle size <50KB (gzipped) for core library

### Security
- **NFR-7:** Validate migration filenames against path traversal attacks
- **NFR-8:** Storage paths validated against path traversal attacks
- **NFR-9:** Event payloads sanitized to prevent XSS in shell UI
- **NFR-10:** Migration files checksummed to detect tampering
- **NFR-11:** SQL injection protection through parameterized queries
- **NFR-12:** Seeds blocked in production environment

### Reliability
- **NFR-13:** Failed migrations rollback automatically (per-migration transaction)
- **NFR-14:** Previously successful migrations remain intact after failure
- **NFR-15:** Event delivery guaranteed for critical events (at-least-once)
- **NFR-16:** Graceful degradation if database/storage unavailable
- **NFR-17:** Idempotent migrations (safe to re-run after crash)
- **NFR-18:** Checksum verification prevents silent corruption

### Compatibility
- **NFR-19:** Support Cloudflare Workers runtime environment
- **NFR-20:** Compatible with D1 (SQLite) and R2 APIs
- **NFR-21:** Works with React 18+ and single-spa 5+
- **NFR-22:** TypeScript 5+ support with strict mode

### Maintainability
- **NFR-23:** Semantic versioning (breaking changes = major bump)
- **NFR-24:** Comprehensive API documentation
- **NFR-25:** Migration guides for version upgrades
- **NFR-26:** Example apps demonstrating all features

---

## API Design

### Basic App Setup

```typescript
// src/index.tsx
import { createApp } from '@eldrin/eldrin-app-core';
import App from './App';

export const { bootstrap, mount, unmount } = createApp({
  name: 'invoicing',
  root: App,
  // Migrations auto-discovered from /migrations folder
  // Auto-executes pending migrations on bootstrap
});
```

### Migration Files (SQL)

```sql
-- migrations/20250115120000-create-invoices-table.sql
CREATE TABLE invoices (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  total REAL NOT NULL,
  status TEXT DEFAULT 'draft',
  created_at INTEGER NOT NULL
);

CREATE INDEX idx_invoices_customer ON invoices(customer_id);
CREATE INDEX idx_invoices_status ON invoices(status);
```

### Rollback Files (SQL)

```sql
-- migrations/20250115120000-create-invoices-table.rollback.sql
DROP INDEX idx_invoices_status;
DROP INDEX idx_invoices_customer;
DROP TABLE invoices;
```

### Additional Migrations

```sql
-- migrations/20250116093000-add-invoice-notes.sql
ALTER TABLE invoices ADD COLUMN notes TEXT;
```

```sql
-- migrations/20250116093000-add-invoice-notes.rollback.sql
ALTER TABLE invoices DROP COLUMN notes;
```

```sql
-- migrations/20250118150000-create-line-items-table.sql
CREATE TABLE line_items (
  id TEXT PRIMARY KEY,
  invoice_id TEXT NOT NULL,
  description TEXT NOT NULL,
  quantity REAL NOT NULL,
  price REAL NOT NULL,
  FOREIGN KEY (invoice_id) REFERENCES invoices(id) ON DELETE CASCADE
);

CREATE INDEX idx_line_items_invoice ON line_items(invoice_id);
```

### Seed Files

```sql
-- seeds/20250115120000-sample-invoices.seed.sql
INSERT OR IGNORE INTO invoices (id, customer_id, total, status, created_at)
VALUES 
  ('inv_001', 'cust_123', 1500.00, 'paid', 1705320000000),
  ('inv_002', 'cust_456', 2300.50, 'pending', 1705406400000);

INSERT OR IGNORE INTO line_items (id, invoice_id, description, quantity, price)
VALUES
  ('li_001', 'inv_001', 'Consulting Services', 10, 150.00),
  ('li_002', 'inv_002', 'Software License', 1, 2300.50);
```

### CLI Usage

```bash
# Create a new migration (with optional rollback)
npx eldrin-app migrate:create "add payment method column"
# Generates: 
#   migrations/20250120143022-add-payment-method-column.sql
#   migrations/20250120143022-add-payment-method-column.rollback.sql

# Check migration status
npx eldrin-app migrate:status
# Output:
# Pending migrations:
#   20250120143022-add-payment-method-column.sql
# 
# Executed migrations:
#   20250115120000-create-invoices-table.sql (2025-01-15 12:05:33, 145ms)
#   20250116093000-add-invoice-notes.sql (2025-01-16 09:31:12, 23ms)
#   20250118150000-create-line-items-table.sql (2025-01-18 15:02:45, 87ms)

# Rollback last migration
npx eldrin-app migrate:rollback
# Rolls back: 20250118150000-create-line-items-table.sql

# Rollback to specific migration
npx eldrin-app migrate:rollback 20250116093000-add-invoice-notes.sql
# Rolls back: 20250118150000-create-line-items-table.sql

# Reset database (dev only - WARNING: destroys all data)
npx eldrin-app migrate:reset --confirm

# Create seed file
npx eldrin-app seed:create "sample customer data"
# Generates: seeds/20250120150000-sample-customer-data.seed.sql

# Run all seeds (dev only)
npx eldrin-app seed:run
```

### Using Database

```typescript
// src/components/InvoiceList.tsx
import { useDatabase } from '@eldrin/eldrin-app-core';

function InvoiceList() {
  const db = useDatabase();
  
  const { results } = await db.prepare(
    'SELECT * FROM invoices WHERE customer_id = ? ORDER BY created_at DESC'
  ).bind(customerId).all();
  
  return <div>{/* render invoices */}</div>;
}
```

### Event Communication

```typescript
// Publishing an event
import { useEvents } from '@eldrin/eldrin-app-core';

function PayInvoice({ invoiceId }) {
  const { emit } = useEvents();
  
  const handlePayment = async () => {
    // ... payment logic
    await emit('invoice.paid', { 
      invoiceId, 
      amount, 
      paidAt: Date.now() 
    });
  };
}

// Subscribing to events
function CRMNotifications() {
  const { on } = useEvents();
  
  useEffect(() => {
    const unsubscribe = on('invoicing:invoice.paid', (payload) => {
      // Update customer record, send notification, etc.
      console.log('Invoice paid:', payload.invoiceId);
    });
    
    return unsubscribe;
  }, []);
}
```

### Storage Usage

```typescript
import { useStorage } from '@eldrin/eldrin-app-core';

function FileUpload() {
  const storage = useStorage();
  
  const handleUpload = async (file: File) => {
    // Automatically scoped to app's namespace
    await storage.put(`invoices/${invoiceId}/receipt.pdf`, file);
    
    // Get presigned URL
    const url = await storage.getSignedUrl(`invoices/${invoiceId}/receipt.pdf`);
  };
}
```

---

## Implementation Details

### Migration Execution Algorithm

```typescript
async function runMigrations(appId: string, db: D1Database) {
  // 1. Ensure tracking table exists
  await db.exec(`
    CREATE TABLE IF NOT EXISTS _eldrin_migrations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      filename TEXT NOT NULL UNIQUE,
      checksum TEXT NOT NULL,
      executed_at INTEGER NOT NULL,
      execution_time_ms INTEGER
    )
  `);
  
  // 2. Scan filesystem for migration files
  const migrationFiles = await readMigrationFiles('/migrations');
  // Returns: [{ name: '20250115120000-create-invoices-table.sql', content: '...' }, ...]
  
  // 3. Query executed migrations
  const { results: executed } = await db.prepare(
    'SELECT filename, checksum FROM _eldrin_migrations ORDER BY filename'
  ).all();
  
  // 4. Verify checksums of executed migrations
  for (const record of executed) {
    const file = migrationFiles.find(f => f.name === record.filename);
    if (!file) {
      console.warn(`Orphaned migration: ${record.filename}`);
      continue;
    }
    
    const currentChecksum = await calculateChecksum(file.content);
    if (currentChecksum !== record.checksum) {
      throw new Error(
        `Migration ${record.filename} has been modified after execution!`
      );
    }
  }
  
  // 5. Calculate pending migrations
  const executedFilenames = new Set(executed.map(e => e.filename));
  const pending = migrationFiles
    .filter(f => !executedFilenames.has(f.name))
    .sort((a, b) => a.name.localeCompare(b.name)); // Sort by timestamp
  
  if (pending.length === 0) {
    console.log('No pending migrations');
    return;
  }
  
  // 6. Execute pending migrations ONE AT A TIME
  for (const migration of pending) {
    console.log(`Executing migration: ${migration.name}`);
    const startTime = Date.now();
    
    try {
      // Parse SQL into statements for db.batch()
      const statements = parseSQLStatements(migration.content);
      
      // Execute in a single transaction via batch
      await db.batch([
        // Execute all statements from the migration
        ...statements.map(sql => db.prepare(sql)),
        
        // Record execution
        db.prepare(
          `INSERT INTO _eldrin_migrations 
           (filename, checksum, executed_at, execution_time_ms) 
           VALUES (?, ?, ?, ?)`
        ).bind(
          migration.name,
          await calculateChecksum(migration.content),
          Date.now(),
          Date.now() - startTime
        )
      ]);
      
      console.log(`✓ Migration ${migration.name} completed (${Date.now() - startTime}ms)`);
    } catch (error) {
      console.error(`✗ Migration ${migration.name} failed:`, error);
      // Transaction auto-rolls back
      // Previous migrations remain intact
      throw error;
    }
  }
}

function parseSQLStatements(sql: string): string[] {
  // Remove comments and split by semicolon
  const cleaned = sql
    .split('\n')
    .filter(line => !line.trim().startsWith('--'))
    .join('\n');
  
  return cleaned
    .split(';')
    .map(stmt => stmt.trim())
    .filter(stmt => stmt.length > 0);
}

async function calculateChecksum(content: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(content);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
```

### Rollback Algorithm

```typescript
async function rollbackMigrations(
  appId: string, 
  db: D1Database, 
  targetMigration?: string
) {
  // 1. Get executed migrations in reverse order
  const { results: executed } = await db.prepare(
    'SELECT filename FROM _eldrin_migrations ORDER BY filename DESC'
  ).all();
  
  // 2. Determine which migrations to rollback
  let toRollback: string[];
  if (targetMigration) {
    // Rollback everything after target
    const targetIndex = executed.findIndex(m => m.filename === targetMigration);
    if (targetIndex === -1) {
      throw new Error(`Target migration not found: ${targetMigration}`);
    }
    toRollback = executed.slice(0, targetIndex);
  } else {
    // Rollback only the last migration
    toRollback = executed.slice(0, 1);
  }
  
  // 3. Load rollback files
  const rollbackFiles = await readRollbackFiles('/migrations');
  
  // 4. Execute rollbacks ONE AT A TIME in reverse order
  for (const migration of toRollback) {
    const rollbackFilename = migration.filename.replace('.sql', '.rollback.sql');
    const rollbackFile = rollbackFiles.find(f => f.name === rollbackFilename);
    
    if (!rollbackFile) {
      throw new Error(`Rollback file not found: ${rollbackFilename}`);
    }
    
    console.log(`Rolling back: ${migration.filename}`);
    
    try {
      const statements = parseSQLStatements(rollbackFile.content);
      
      await db.batch([
        // Execute rollback statements
        ...statements.map(sql => db.prepare(sql)),
        
        // Remove migration record
        db.prepare(
          'DELETE FROM _eldrin_migrations WHERE filename = ?'
        ).bind(migration.filename)
      ]);
      
      console.log(`✓ Rolled back: ${migration.filename}`);
    } catch (error) {
      console.error(`✗ Rollback failed for ${migration.filename}:`, error);
      throw error;
    }
  }
}
```

### Migration File Reader (Cloudflare Workers)

```typescript
// Since Workers don't have filesystem access, migrations must be bundled
// Use Vite plugin to read migration files at build time

// vite.config.ts
import { defineConfig } from 'vite';
import { eldrinPlugin } from '@eldrin/eldrin-app-core/vite';

export default defineConfig({
  plugins: [
    eldrinPlugin({
      migrationsDir: './migrations',
      seedsDir: './seeds'
    })
  ]
});

// Plugin generates virtual modules:
// virtual:eldrin/migrations -> { migrations: [{ name, content }] }
// virtual:eldrin/seeds -> { seeds: [{ name, content }] }
```

---

## Implementation Phases

### Phase 1 - Foundation (MVP)
- ✅ Auto-discovery of SQL migration files
- ✅ Migration tracking table creation
- ✅ Pending migration calculation
- ✅ Sequential execution (one at a time) with checksum recording
- ✅ Multi-statement support via `db.batch()`
- ✅ Database access layer (useDatabase hook)
- ✅ App lifecycle (createApp factory)

### Phase 2 - Migration Safety & Rollback
- ✅ Checksum verification of executed migrations
- ✅ Transaction-based execution (per-migration)
- ✅ Error handling and automatic rollback
- ✅ Rollback file support (.rollback.sql)
- ✅ CLI for migration management

### Phase 3 - Seeding
- ✅ Seed file support (/seeds folder)
- ✅ Seed CLI commands
- ✅ Environment-based seed execution

### Phase 4 - Storage & Events
- R2 storage abstraction (useStorage)
- Path namespacing and validation
- Event system (emit, on)

### Phase 5 - Developer Tools
- Vite plugin for migration/seed bundling
- Testing utilities
- Development mode improvements

### Phase 6 - Advanced Features (Future)
- Type generation from SQL schema
- Query builder helpers
- Advanced event persistence

---

## Implementation Status

> Last updated: 2024-12-20

### Package Information

| Property | Value |
|----------|-------|
| Package | `@eldrin/eldrin-app-core` |
| Version | `0.1.0` |
| Location | `packages/app-core/` |
| Build System | tsup |
| Test Framework | Vitest |

### Implementation Progress

#### Phase 1 - Foundation (MVP) — **COMPLETE**

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| FR-1.1.1-7: Migration Definition | ✅ Done | `src/migrations/sql-parser.ts` |
| FR-1.2.1-8: Migration Discovery & Execution | ✅ Done | `src/migrations/runner.ts` |
| FR-1.3.1-7: Migration Tracking Table | ✅ Done | `src/migrations/runner.ts` |
| FR-4.1.1-4: Database Client | ✅ Done | `src/database/context.tsx` |
| FR-6.1.1-4: App Initialization | ✅ Done | `src/app/createApp.tsx` |

**Files Created:**
```
packages/app-core/
├── src/
│   ├── index.ts                    # Main exports
│   ├── types.ts                    # Type definitions
│   ├── vite.ts                     # Vite plugin for loading migrations
│   ├── vite-env.d.ts               # Virtual module type declarations
│   ├── app/
│   │   ├── index.ts
│   │   └── createApp.tsx           # createApp() factory
│   ├── database/
│   │   ├── index.ts
│   │   └── context.tsx             # useDatabase() hook
│   └── migrations/
│       ├── index.ts
│       ├── sql-parser.ts           # parseSQLStatements()
│       ├── sql-parser.test.ts      # 18 tests
│       ├── checksum.ts             # calculateChecksum()
│       ├── checksum.test.ts        # 8 tests
│       ├── runner.ts               # runMigrations()
│       └── rollback.ts             # rollbackMigrations()
├── dist/                           # Built output (ESM + CJS + types)
├── package.json
├── tsconfig.json
├── tsup.config.ts
└── vitest.config.ts
```

**Test Results:**
- ✅ 26 tests passing
- SQL parser tests: 18 passing
- Checksum tests: 8 passing

**Exports Available:**
```typescript
// App lifecycle
export { createApp, type AppLifecycle, type LifecycleProps, type MigrationFiles } from './app';

// Database
export { useDatabase, useDatabaseContext, useMigrationsComplete, DatabaseProvider } from './database';

// Migrations
export { runMigrations, getMigrationStatus, rollbackMigrations } from './migrations';
export { calculateChecksum, verifyChecksum } from './migrations';
export { parseSQLStatements, isValidMigrationFilename, isValidRollbackFilename } from './migrations';
```

#### Phase 2 - Migration Safety & Rollback — **COMPLETE**

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| FR-1.4.1-6: Migration Rollback | ✅ Done | `src/migrations/rollback.ts` |
| FR-1.5.1-5: Migration Integrity | ✅ Done | `src/migrations/runner.ts` |
| FR-1.7.1-6: Error Handling | ✅ Done | `src/migrations/runner.ts` |
| FR-1.8.1-4: CLI Commands | ⏳ Pending | Not yet implemented |

#### Phase 3 - Seeding — **NOT STARTED**

| Requirement | Status | Notes |
|-------------|--------|-------|
| FR-2.1.1-5: Seed Definition | ⏳ Pending | Vite plugin supports loading seeds |
| FR-2.2.1-5: Seed Execution | ⏳ Pending | |
| FR-2.3.1-3: Seed CLI Commands | ⏳ Pending | |

#### Phase 4 - Storage & Events — **NOT STARTED**

| Requirement | Status | Notes |
|-------------|--------|-------|
| FR-3.1.1-4: R2 Bucket Abstraction | ⏳ Pending | |
| FR-3.2.1-4: File Management | ⏳ Pending | |
| FR-5.1.1-4: Event Publishing | ⏳ Pending | |
| FR-5.2.1-4: Event Subscription | ⏳ Pending | |

#### Phase 5 - Developer Tools — **PARTIAL**

| Requirement | Status | Notes |
|-------------|--------|-------|
| Vite Plugin | ✅ Done | `src/vite.ts` - loads migrations/seeds at build time |
| Testing Utilities | ⏳ Pending | |
| Development Mode | ⏳ Pending | |

### Next Steps

1. **Create sample app** - Minimal invoicing app to validate integration with D1
2. **Add CLI commands** - `migrate:create`, `migrate:status`, `migrate:rollback`
3. **Implement seeding** - Seed runner and CLI commands
4. **Add storage abstraction** - R2 integration with useStorage()
5. **Add event system** - Inter-app communication via emit/on

---

## File Structure Example

```
my-invoicing-app/
├── src/
│   ├── index.tsx              # App entry point with createApp()
│   ├── App.tsx                # Root component
│   └── components/
│       └── InvoiceList.tsx
├── migrations/
│   ├── 20250115120000-create-invoices-table.sql
│   ├── 20250115120000-create-invoices-table.rollback.sql
│   ├── 20250116093000-add-invoice-notes.sql
│   ├── 20250116093000-add-invoice-notes.rollback.sql
│   ├── 20250118150000-create-line-items-table.sql
│   └── 20250118150000-create-line-items-table.rollback.sql
├── seeds/
│   ├── 20250115120000-sample-invoices.seed.sql
│   └── 20250116000000-sample-customers.seed.sql
├── eldrin-app.manifest.json
├── package.json
└── vite.config.ts
```

---

## Success Criteria

- ✅ Developers can add migrations by simply dropping SQL files in `/migrations`
- ✅ Zero configuration required for migration system
- ✅ Migrations execute automatically on app install/update
- ✅ Each migration runs in its own transaction (easier rollback)
- ✅ Rollback support via `.rollback.sql` files
- ✅ Seed data support for development environments
- ✅ Multi-statement migrations supported via `db.batch()`
- ✅ Migration status visible in shell admin interface
- ✅ <10 seconds total migration time on cold start
- ✅ Checksum verification prevents accidental schema corruption
- ✅ CLI tools reduce friction for migration management