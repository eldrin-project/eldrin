# Company Dedup (Prevent + Review-Merge) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop subdomain email senders from spawning duplicate companies, and add a review-and-merge surface to clean up existing duplicates.

**Architecture:** Capture-time normalization keys auto-created companies on the PSL registrable domain (`email.anthropic.com` → `anthropic.com`) via `tldts`. A read-only duplicates service groups existing companies by registrable domain (strong) and exact name (weak) with a suggested survivor. A sequential, ordered merge service re-points all references, fills empty survivor fields, and soft-deletes sources into the recycle bin. A modal in the Companies page drives suggest-and-confirm merging.

**Tech Stack:** eldrin-crm — Cloudflare Workers + Hono 4 + Drizzle/D1 (backend), React 19 + daisyUI 5 (frontend), Vitest + better-sqlite3 (tests), `tldts` (new dep).

**Spec:** `docs/superpowers/specs/2026-07-11-company-dedup-design.md` (parent repo).

## Global Constraints

- All work happens in the **eldrin-crm submodule**: `/Users/tibor/projects/eldrin-backup/eldrin-crm`. Always use absolute paths in Bash — a lingering `cd` into the submodule misdirects parent-repo git commands.
- Before Task 1: `cd /Users/tibor/projects/eldrin-backup/eldrin-crm && git checkout main && git pull && git checkout -b feature/company-dedup`.
- No schema changes → **no migration files** needed anywhere in this plan.
- Conventional commit messages (`feat:`, `test:`, `chore:`). No AI attribution lines.
- No `console.log` in production code. Immutable update patterns (spread, no in-place mutation of shared objects).
- Tests: `npx vitest run <file>` from the eldrin-crm directory. Typecheck: `npm run typecheck`.
- New API routes must be registered in `public/eldrin-app.manifest.json` (permission middleware gates `/api/*` per manifest) AND ordered before `/:id` catch-alls in `worker/routes/companies.ts` (Hono matches in registration order).

---

### Task 1: `registrableDomain` / `canonicalCompanyDomain` helpers

**Files:**
- Modify: `worker/services/company-domain.ts` (append)
- Create: `worker/__tests__/company-domain.test.ts`
- Modify: `package.json` (add `tldts` dependency)

**Interfaces:**
- Consumes: `tldts` `getDomain()`.
- Produces: `registrableDomain(host: string | null | undefined): string | null` and `canonicalCompanyDomain(domain: string): string` — used by Tasks 2, 3, 4.

- [ ] **Step 1: Install tldts**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-crm && npm install tldts`
Expected: `tldts` appears in `package.json` dependencies.

- [ ] **Step 2: Write the failing tests**

Create `worker/__tests__/company-domain.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import {
  canonicalCompanyDomain,
  registrableDomain,
} from '../services/company-domain';

describe('registrableDomain', () => {
  it('collapses subdomains to the registrable domain', () => {
    expect(registrableDomain('email.anthropic.com')).toBe('anthropic.com');
    expect(registrableDomain('mail.anthropic.com')).toBe('anthropic.com');
  });

  it('keeps a bare registrable domain unchanged', () => {
    expect(registrableDomain('anthropic.com')).toBe('anthropic.com');
  });

  it('respects multi-part public suffixes', () => {
    expect(registrableDomain('foo.co.uk')).toBe('foo.co.uk');
    expect(registrableDomain('mail.foo.co.uk')).toBe('foo.co.uk');
  });

  it('honours private suffixes — tenant subdomains are distinct orgs', () => {
    expect(registrableDomain('acme.github.io')).toBe('acme.github.io');
  });

  it('rejects IPs, localhost and single labels', () => {
    expect(registrableDomain('127.0.0.1')).toBeNull();
    expect(registrableDomain('localhost')).toBeNull();
    expect(registrableDomain('intranet')).toBeNull();
  });

  it('normalises case and whitespace, handles null input', () => {
    expect(registrableDomain(' EMAIL.Anthropic.COM ')).toBe('anthropic.com');
    expect(registrableDomain(null)).toBeNull();
    expect(registrableDomain('')).toBeNull();
  });
});

describe('canonicalCompanyDomain', () => {
  it('returns the registrable domain when the PSL recognises the host', () => {
    expect(canonicalCompanyDomain('email.anthropic.com')).toBe('anthropic.com');
  });

  it('falls back to the lowercased raw input for non-PSL hosts', () => {
    expect(canonicalCompanyDomain('foo.internal')).toBe('foo.internal');
    expect(canonicalCompanyDomain('Intranet')).toBe('intranet');
  });
});
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `npx vitest run worker/__tests__/company-domain.test.ts`
Expected: FAIL — `registrableDomain` is not exported.

- [ ] **Step 4: Implement**

Append to `worker/services/company-domain.ts`:

```typescript
import { getDomain } from 'tldts';

/**
 * Registrable (main) domain per the Public Suffix List, private suffixes
 * included — `acme.github.io` stays `acme.github.io` because PSL private
 * tenants are distinct organisations. Returns null for IPs, localhost,
 * single labels, and empty input. Mirrors the enricher's Rust
 * `registrable_domain()` semantics.
 */
export function registrableDomain(host: string | null | undefined): string | null {
  if (!host) return null;
  const trimmed = host.trim().toLowerCase();
  if (!trimmed) return null;
  return getDomain(trimmed, { allowPrivateDomains: true });
}

/**
 * Canonical domain a company is keyed on: the registrable domain when the
 * PSL recognises the host, otherwise the raw (lowercased) input.
 */
export function canonicalCompanyDomain(domain: string): string {
  const d = domain.trim().toLowerCase();
  return registrableDomain(d) ?? d;
}
```

(The `import` goes at the top of the file, above the existing docblock's function.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `npx vitest run worker/__tests__/company-domain.test.ts`
Expected: PASS (8 tests).

- [ ] **Step 6: Typecheck and commit**

Run: `npm run typecheck`
Expected: clean.

```bash
git add package.json package-lock.json worker/services/company-domain.ts worker/__tests__/company-domain.test.ts
git commit -m "feat: registrable-domain helpers via tldts for company dedup"
```

---

### Task 2: Capture-time normalization (auto-capture + matching)

**Files:**
- Modify: `worker/services/email-linking.ts:142-157` (`matchEmailToCompany`)
- Modify: `worker/services/auto-capture.ts:213` (domain derivation in `autoCreateContactFromEmail`)
- Test: `worker/__tests__/auto-capture.test.ts` (append a describe block)

**Interfaces:**
- Consumes: `canonicalCompanyDomain(domain: string): string` from `../services/company-domain` (Task 1).
- Produces: behavior change only — `matchEmailToCompany(db, rawAddress)` now matches raw OR canonical domain (canonical preferred); auto-created companies store the canonical domain.

- [ ] **Step 1: Write the failing tests**

Append to `worker/__tests__/auto-capture.test.ts` (inside the top-level `describe('auto-capture service', ...)` block; `seedCompany`, `companies`, `contactCompanyRelations`, `eq` are already imported/defined in this file):

```typescript
  describe('registrable-domain company grouping', () => {
    it('creates the provisional company under the registrable domain', async () => {
      const result = await autoCreateContactFromEmail(db, { from: 'a@email.anthropic.com' });
      expect(result?.companyAutoCreated).toBe(true);
      expect(result?.companyDomain).toBe('anthropic.com');
      const [company] = await db
        .select()
        .from(companies)
        .where(eq(companies.id, result!.autoCreatedCompanyId!));
      expect(company.domain).toBe('anthropic.com');
      expect(company.name).toBe('anthropic.com');
    });

    it('links a sibling-subdomain sender to the existing registrable-domain company', async () => {
      await seedCompany(db, 'co-anthropic', 'anthropic.com');
      const result = await autoCreateContactFromEmail(db, { from: 'b@mail.anthropic.com' });
      expect(result?.companyAutoCreated).toBe(false);
      const rels = await db
        .select()
        .from(contactCompanyRelations)
        .where(eq(contactCompanyRelations.contactId, result!.contactId));
      expect(rels).toHaveLength(1);
      expect(rels[0].companyId).toBe('co-anthropic');
    });

    it('still matches a legacy exact-subdomain company instead of creating a third', async () => {
      await seedCompany(db, 'co-legacy', 'email.anthropic.com');
      const result = await autoCreateContactFromEmail(db, { from: 'c@email.anthropic.com' });
      expect(result?.companyAutoCreated).toBe(false);
      const rels = await db
        .select()
        .from(contactCompanyRelations)
        .where(eq(contactCompanyRelations.contactId, result!.contactId));
      expect(rels[0].companyId).toBe('co-legacy');
    });

    it('prefers the registrable-domain company over a legacy subdomain one', async () => {
      await seedCompany(db, 'co-legacy', 'email.anthropic.com');
      await seedCompany(db, 'co-canonical', 'anthropic.com');
      const result = await autoCreateContactFromEmail(db, { from: 'd@email.anthropic.com' });
      const rels = await db
        .select()
        .from(contactCompanyRelations)
        .where(eq(contactCompanyRelations.contactId, result!.contactId));
      expect(rels[0].companyId).toBe('co-canonical');
    });

    it('rejects freemail subdomains (mail.gmail.com is still gmail)', async () => {
      const result = await autoCreateContactFromEmail(db, { from: 'e@mail.gmail.com' });
      expect(result?.companyAutoCreated).toBe(false);
      expect(result?.autoCreatedCompanyId).toBeNull();
    });
  });
```

- [ ] **Step 2: Run tests to verify the new ones fail**

Run: `npx vitest run worker/__tests__/auto-capture.test.ts`
Expected: the 5 new tests FAIL (company created as `email.anthropic.com`, sibling subdomain spawns a second company); all pre-existing tests still PASS.

- [ ] **Step 3: Implement — matchEmailToCompany**

In `worker/services/email-linking.ts`, add the import and replace the body of `matchEmailToCompany`:

```typescript
import { canonicalCompanyDomain } from './company-domain';
```

```typescript
export async function matchEmailToCompany(
  db: Database,
  rawAddress: string,
): Promise<{ companyId: string } | null> {
  const domain = extractDomain(rawAddress);
  if (!domain) return null;
  const raw = domain.toLowerCase();
  const canonical = canonicalCompanyDomain(raw);

  const rows = await db
    .select({ companyId: companies.id, domain: companies.domain })
    .from(companies)
    .where(
      and(
        inArray(sql`lower(${companies.domain})`, [...new Set([raw, canonical])]),
        eq(companies.isDeleted, false),
      ),
    );
  if (rows.length === 0) return null;
  // Prefer the canonical-domain company; the exact-subdomain match is the
  // fallback so un-merged legacy companies keep collecting their senders.
  const preferred = rows.find((r) => r.domain?.toLowerCase() === canonical) ?? rows[0];
  return { companyId: preferred.companyId };
}
```

- [ ] **Step 4: Implement — auto-capture canonical domain**

In `worker/services/auto-capture.ts`, add the import:

```typescript
import { canonicalCompanyDomain } from './company-domain';
```

and in `autoCreateContactFromEmail`, replace

```typescript
  const domain = address.split('@')[1]?.toLowerCase() ?? '';
```

with

```typescript
  const rawDomain = address.split('@')[1]?.toLowerCase() ?? '';
  const domain = rawDomain ? canonicalCompanyDomain(rawDomain) : '';
```

(Everything downstream — `isEnrichableDomain(domain)`, `autoCreateCompanyFromDomain(db, domain)`, `companyDomain: ... domain ...` — is untouched and now operates on the canonical domain. The freemail check hits `gmail.com` for `mail.gmail.com` automatically.)

- [ ] **Step 5: Run the full worker suite**

Run: `npx vitest run`
Expected: ALL tests PASS (new + pre-existing; `email-linking.test.ts` must stay green — exact-domain seeds still match via the raw arm).

- [ ] **Step 6: Typecheck and commit**

Run: `npm run typecheck`
Expected: clean.

```bash
git add worker/services/email-linking.ts worker/services/auto-capture.ts worker/__tests__/auto-capture.test.ts
git commit -m "feat: key auto-created companies on the registrable domain"
```

---

### Task 3: Duplicates detection service + GET endpoint

**Files:**
- Create: `worker/services/company-duplicates.ts`
- Modify: `worker/routes/companies.ts` (new GET route — MUST be registered before `GET /api/companies/:id`)
- Modify: `public/eldrin-app.manifest.json` (new route entry)
- Create: `worker/__tests__/company-duplicates.test.ts`
- Create: `worker/__tests__/company-dedup-routes.test.ts`

**Interfaces:**
- Consumes: `canonicalCompanyDomain` (Task 1).
- Produces (used by Tasks 4–6):
  - `MERGEABLE_FIELDS: readonly ['domain','industry','size','revenueRange','phone','website','addressLine1','addressLine2','city','state','postalCode','country','logoUrl','notes','ownerId']` and `type MergeableField`
  - `interface DuplicateGroupMember { id: string; name: string; domain: string | null; isAutoCreated: boolean; createdAt: number; contactCount: number; filledFieldCount: number }`
  - `interface CompanyDuplicateGroup { key: string; signal: 'domain' | 'name'; confidence: number; suggestedSurvivorId: string; members: DuplicateGroupMember[] }`
  - `suggestSurvivor(members: DuplicateGroupMember[]): string`
  - `findCompanyDuplicateGroups(db: Database): Promise<CompanyDuplicateGroup[]>`
  - HTTP: `GET /api/companies/duplicates` → `200 { groups: CompanyDuplicateGroup[] }`

- [ ] **Step 1: Write the failing service tests**

Create `worker/__tests__/company-duplicates.test.ts`:

```typescript
import { describe, it, expect, beforeEach } from 'vitest';
import { createTestDb } from './test-db';
import type { Database } from '../db';
import { companies, contactCompanyRelations, contacts } from '../db';
import {
  findCompanyDuplicateGroups,
  suggestSurvivor,
  type DuplicateGroupMember,
} from '../services/company-duplicates';

const T0 = 1700000000000;

async function seedCompany(
  db: Database,
  overrides: Partial<typeof companies.$inferInsert> & { id: string },
): Promise<void> {
  await db.insert(companies).values({
    name: overrides.id,
    createdBy: 'test',
    createdAt: T0,
    updatedAt: T0,
    ...overrides,
  });
}

describe('findCompanyDuplicateGroups', () => {
  let db: Database;

  beforeEach(() => {
    db = createTestDb();
  });

  it('groups companies sharing a registrable domain', async () => {
    await seedCompany(db, { id: 'a', name: 'Anthropic PBC', domain: 'email.anthropic.com' });
    await seedCompany(db, { id: 'b', name: 'Anthropic PBC', domain: 'mail.anthropic.com' });
    await seedCompany(db, { id: 'c', name: 'Other Co', domain: 'other.io' });
    const groups = await findCompanyDuplicateGroups(db);
    expect(groups).toHaveLength(1);
    expect(groups[0].signal).toBe('domain');
    expect(groups[0].confidence).toBe(0.9);
    expect(groups[0].key).toBe('anthropic.com');
    expect(groups[0].members.map((m) => m.id).sort()).toEqual(['a', 'b']);
  });

  it('groups same-named companies with unrelated domains as a name group', async () => {
    await seedCompany(db, { id: 'a', name: 'Acme', domain: 'acme.com' });
    await seedCompany(db, { id: 'b', name: 'acme', domain: 'acme.io' });
    const groups = await findCompanyDuplicateGroups(db);
    expect(groups).toHaveLength(1);
    expect(groups[0].signal).toBe('name');
    expect(groups[0].confidence).toBe(0.7);
    expect(groups[0].key).toBe('acme');
  });

  it('does not re-group members already covered by a domain group', async () => {
    await seedCompany(db, { id: 'a', name: 'Anthropic PBC', domain: 'email.anthropic.com' });
    await seedCompany(db, { id: 'b', name: 'Anthropic PBC', domain: 'mail.anthropic.com' });
    const groups = await findCompanyDuplicateGroups(db);
    expect(groups).toHaveLength(1);
    expect(groups[0].signal).toBe('domain');
  });

  it('excludes deleted companies and singletons', async () => {
    await seedCompany(db, { id: 'a', name: 'X', domain: 'x.com' });
    await seedCompany(db, {
      id: 'b', name: 'X dup', domain: 'mail.x.com', isDeleted: true, deletedAt: T0,
    });
    const groups = await findCompanyDuplicateGroups(db);
    expect(groups).toHaveLength(0);
  });

  it('reports contact counts and filled-field counts per member', async () => {
    await seedCompany(db, { id: 'a', name: 'A', domain: 'email.anthropic.com', industry: 'AI' });
    await seedCompany(db, { id: 'b', name: 'B', domain: 'anthropic.com' });
    await db.insert(contacts).values({
      id: 'p1', firstName: 'P', lastName: 'One',
      createdBy: 't', createdAt: T0, updatedAt: T0,
    });
    await db.insert(contactCompanyRelations).values({
      id: 'r1', contactId: 'p1', companyId: 'a', isPrimary: true, createdAt: T0,
    });
    const groups = await findCompanyDuplicateGroups(db);
    const memberA = groups[0].members.find((m) => m.id === 'a');
    expect(memberA?.contactCount).toBe(1);
    expect(memberA?.filledFieldCount).toBe(2); // domain + industry
  });
});

describe('suggestSurvivor', () => {
  const base: Omit<DuplicateGroupMember, 'id' | 'isAutoCreated' | 'createdAt'> = {
    name: '', domain: null, contactCount: 0, filledFieldCount: 0,
  };

  it('prefers human-created over auto-created', () => {
    expect(suggestSurvivor([
      { ...base, id: 'auto', isAutoCreated: true, createdAt: 1 },
      { ...base, id: 'manual', isAutoCreated: false, createdAt: 2 },
    ])).toBe('manual');
  });

  it('prefers the oldest among equals', () => {
    expect(suggestSurvivor([
      { ...base, id: 'newer', isAutoCreated: true, createdAt: 2 },
      { ...base, id: 'older', isAutoCreated: true, createdAt: 1 },
    ])).toBe('older');
  });

  it('breaks createdAt ties by most filled fields', () => {
    expect(suggestSurvivor([
      { ...base, id: 'sparse', isAutoCreated: true, createdAt: 1, filledFieldCount: 1 },
      { ...base, id: 'rich', isAutoCreated: true, createdAt: 1, filledFieldCount: 5 },
    ])).toBe('rich');
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run worker/__tests__/company-duplicates.test.ts`
Expected: FAIL — module `../services/company-duplicates` does not exist.

- [ ] **Step 3: Implement the service**

Create `worker/services/company-duplicates.ts`:

```typescript
/**
 * Company duplicate grouping (dedup review surface).
 *
 * Groups non-deleted companies that share a registrable domain (strong
 * signal, 0.9) or an exact case-insensitive name (weak signal, 0.7 —
 * enrichment often converges on the same display name). Read-only.
 */
import { eq, sql } from 'drizzle-orm';
import { companies, contactCompanyRelations, type Database } from '../db';
import { canonicalCompanyDomain } from './company-domain';

/** Fields counted for "most filled" and copied fill-empty-only on merge. */
export const MERGEABLE_FIELDS = [
  'domain', 'industry', 'size', 'revenueRange', 'phone', 'website',
  'addressLine1', 'addressLine2', 'city', 'state', 'postalCode', 'country',
  'logoUrl', 'notes', 'ownerId',
] as const;

export type MergeableField = (typeof MERGEABLE_FIELDS)[number];

type CompanyRow = typeof companies.$inferSelect;

export interface DuplicateGroupMember {
  id: string;
  name: string;
  domain: string | null;
  isAutoCreated: boolean;
  createdAt: number;
  contactCount: number;
  filledFieldCount: number;
}

export interface CompanyDuplicateGroup {
  /** Canonical domain for domain groups, normalized name for name groups. */
  key: string;
  signal: 'domain' | 'name';
  confidence: number;
  suggestedSurvivorId: string;
  members: DuplicateGroupMember[];
}

const DOMAIN_CONFIDENCE = 0.9;
const NAME_CONFIDENCE = 0.7;

function filledFieldCount(row: CompanyRow): number {
  return MERGEABLE_FIELDS.reduce(
    (n, field) => (row[field] !== null && String(row[field]).trim() !== '' ? n + 1 : n),
    0,
  );
}

/** Human-created beats auto-created, then oldest, then most filled fields. */
export function suggestSurvivor(members: DuplicateGroupMember[]): string {
  const ranked = [...members].sort((a, b) => {
    if (a.isAutoCreated !== b.isAutoCreated) return a.isAutoCreated ? 1 : -1;
    if (a.createdAt !== b.createdAt) return a.createdAt - b.createdAt;
    return b.filledFieldCount - a.filledFieldCount;
  });
  return ranked[0].id;
}

export async function findCompanyDuplicateGroups(
  db: Database,
): Promise<CompanyDuplicateGroup[]> {
  const rows = await db.select().from(companies).where(eq(companies.isDeleted, false));
  const counts = await db
    .select({
      companyId: contactCompanyRelations.companyId,
      total: sql<number>`count(*)`,
    })
    .from(contactCompanyRelations)
    .groupBy(contactCompanyRelations.companyId);
  const contactCounts = new Map(counts.map((r) => [r.companyId, r.total]));

  const toMember = (row: CompanyRow): DuplicateGroupMember => ({
    id: row.id,
    name: row.name,
    domain: row.domain,
    isAutoCreated: row.isAutoCreated,
    createdAt: row.createdAt,
    contactCount: contactCounts.get(row.id) ?? 0,
    filledFieldCount: filledFieldCount(row),
  });

  const groups: CompanyDuplicateGroup[] = [];
  const grouped = new Set<string>();

  // Strong signal: same registrable domain.
  const byDomain = new Map<string, CompanyRow[]>();
  for (const row of rows) {
    if (!row.domain?.trim()) continue;
    const key = canonicalCompanyDomain(row.domain);
    byDomain.set(key, [...(byDomain.get(key) ?? []), row]);
  }
  for (const [key, dupes] of byDomain) {
    if (dupes.length < 2) continue;
    const members = dupes.map(toMember);
    for (const member of members) grouped.add(member.id);
    groups.push({
      key,
      signal: 'domain',
      confidence: DOMAIN_CONFIDENCE,
      suggestedSurvivorId: suggestSurvivor(members),
      members,
    });
  }

  // Weak signal: exact case-insensitive name, skipping already-grouped rows.
  const byName = new Map<string, CompanyRow[]>();
  for (const row of rows) {
    if (grouped.has(row.id)) continue;
    const key = row.name.trim().toLowerCase();
    if (!key) continue;
    byName.set(key, [...(byName.get(key) ?? []), row]);
  }
  for (const [key, dupes] of byName) {
    if (dupes.length < 2) continue;
    const members = dupes.map(toMember);
    groups.push({
      key,
      signal: 'name',
      confidence: NAME_CONFIDENCE,
      suggestedSurvivorId: suggestSurvivor(members),
      members,
    });
  }

  return groups.sort(
    (a, b) => b.confidence - a.confidence || a.key.localeCompare(b.key),
  );
}
```

- [ ] **Step 4: Run service tests to verify they pass**

Run: `npx vitest run worker/__tests__/company-duplicates.test.ts`
Expected: PASS (8 tests).

- [ ] **Step 5: Write the failing route test**

Create `worker/__tests__/company-dedup-routes.test.ts` (mirrors the app-harness pattern of `companies-request-enhancement.test.ts`):

```typescript
import { describe, it, expect, beforeEach } from 'vitest';
import { Hono } from 'hono';
import { createTestDb } from './test-db';
import type { Database } from '../db';
import { companies } from '../db';
import { companyRoutes } from '../routes/companies';
import type { CompanyDuplicateGroup } from '../services/company-duplicates';

const T0 = 1700000000000;

function createApp(db: Database) {
  const app = new Hono<{
    Bindings: Env;
    Variables: { db: Database; auth?: { userId?: string } };
  }>();
  app.use('*', async (c, next) => {
    c.set('db', db);
    await next();
  });
  app.route('', companyRoutes);
  return app;
}

async function seedCompany(
  db: Database,
  overrides: Partial<typeof companies.$inferInsert> & { id: string },
): Promise<void> {
  await db.insert(companies).values({
    name: overrides.id,
    createdBy: 'test',
    createdAt: T0,
    updatedAt: T0,
    ...overrides,
  });
}

describe('GET /api/companies/duplicates', () => {
  let db: Database;
  let app: ReturnType<typeof createApp>;

  beforeEach(() => {
    db = createTestDb();
    app = createApp(db);
  });

  it('returns duplicate groups', async () => {
    await seedCompany(db, { id: 'a', name: 'Anthropic PBC', domain: 'email.anthropic.com' });
    await seedCompany(db, { id: 'b', name: 'Anthropic PBC', domain: 'mail.anthropic.com' });
    const res = await app.request('/api/companies/duplicates', {}, {} as Env);
    expect(res.status).toBe(200);
    const { groups } = (await res.json()) as { groups: CompanyDuplicateGroup[] };
    expect(groups).toHaveLength(1);
    expect(groups[0].key).toBe('anthropic.com');
  });

  it('returns an empty list when there are no duplicates', async () => {
    await seedCompany(db, { id: 'a', name: 'Solo', domain: 'solo.com' });
    const res = await app.request('/api/companies/duplicates', {}, {} as Env);
    expect(res.status).toBe(200);
    const { groups } = (await res.json()) as { groups: CompanyDuplicateGroup[] };
    expect(groups).toHaveLength(0);
  });

  it('is not shadowed by the /api/companies/:id route', async () => {
    // With no companies at all, a shadowing :id route would 404.
    const res = await app.request('/api/companies/duplicates', {}, {} as Env);
    expect(res.status).toBe(200);
  });
});
```

- [ ] **Step 6: Run route tests to verify they fail**

Run: `npx vitest run worker/__tests__/company-dedup-routes.test.ts`
Expected: FAIL — 404 (route not defined) or shadowed by `:id`.

- [ ] **Step 7: Implement the route**

In `worker/routes/companies.ts`:

1. Add the import: `import { findCompanyDuplicateGroups } from '../services/company-duplicates';`
2. Change the Variables type (needed by Task 5 too):

```typescript
type Variables = { db: Database; auth?: { userId?: string } };
```

3. Register this route **immediately after the `GET /api/companies` list handler and before `GET /api/companies/:id`**:

```typescript
// ── GET /api/companies/duplicates — dedup review groups ──────────────────────
// Registered before /api/companies/:id so "duplicates" is not read as an id.
companyRoutes.get('/api/companies/duplicates', async (c) => {
  const db = c.get('db');
  const groups = await findCompanyDuplicateGroups(db);
  return c.json({ groups });
});
```

4. In `public/eldrin-app.manifest.json`, add this entry to `api.routes` **before** the `GET /api/companies/:id` entry:

```json
{ "method": "GET", "path": "/api/companies/duplicates", "permission": "companies:read" },
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `npx vitest run worker/__tests__/company-dedup-routes.test.ts worker/__tests__/company-duplicates.test.ts`
Expected: PASS.

- [ ] **Step 9: Typecheck and commit**

Run: `npm run typecheck`
Expected: clean.

```bash
git add worker/services/company-duplicates.ts worker/routes/companies.ts public/eldrin-app.manifest.json worker/__tests__/company-duplicates.test.ts worker/__tests__/company-dedup-routes.test.ts
git commit -m "feat: company duplicates detection service + GET /api/companies/duplicates"
```

---

### Task 4: Merge service

**Files:**
- Create: `worker/services/company-merge.ts`
- Create: `worker/__tests__/company-merge.test.ts`

**Interfaces:**
- Consumes: `MERGEABLE_FIELDS`, `MergeableField` (Task 3); `canonicalCompanyDomain` (Task 1); `recordAuditChanges(db, recordId, 'company', oldRecord, newRecord, changedBy)` from `../middleware/audit`; `moveToRecycleBin(db, recordId, recordType, recordData, deletedBy)` from `../routes/recycle-bin`; `generateId()`, `now()` from `../utils`.
- Produces (used by Task 5):
  - `class MergeValidationError extends Error { readonly status: 400 | 404 }`
  - `interface MergeResult { survivorId: string; mergedIds: string[]; relationsRepointed: number; fieldsFilled: string[] }`
  - `mergeCompanies(db: Database, input: { survivorId: string; sourceIds: string[]; mergedBy: string }): Promise<MergeResult>`

- [ ] **Step 1: Write the failing tests**

Create `worker/__tests__/company-merge.test.ts`:

```typescript
import { describe, it, expect, beforeEach } from 'vitest';
import { and, eq } from 'drizzle-orm';
import { createTestDb } from './test-db';
import type { Database } from '../db';
import {
  activities,
  auditTrail,
  companies,
  contactCompanyRelations,
  contacts,
  dealSuggestions,
  leads,
  recordTags,
  recycleBin,
  tags,
} from '../db';
import { MergeValidationError, mergeCompanies } from '../services/company-merge';

const T0 = 1700000000000;

async function seedCompany(
  db: Database,
  overrides: Partial<typeof companies.$inferInsert> & { id: string },
): Promise<void> {
  await db.insert(companies).values({
    name: overrides.id,
    createdBy: 'test',
    createdAt: T0,
    updatedAt: T0,
    ...overrides,
  });
}

async function seedContact(db: Database, id: string): Promise<void> {
  await db.insert(contacts).values({
    id, firstName: 'C', lastName: id,
    createdBy: 'test', createdAt: T0, updatedAt: T0,
  });
}

async function link(
  db: Database,
  id: string,
  contactId: string,
  companyId: string,
  isPrimary = false,
): Promise<void> {
  await db.insert(contactCompanyRelations).values({
    id, contactId, companyId, isPrimary, createdAt: T0,
  });
}

describe('mergeCompanies', () => {
  let db: Database;

  beforeEach(() => {
    db = createTestDb();
  });

  it('re-points contact relations from sources to the survivor', async () => {
    await seedCompany(db, { id: 'keep', domain: 'anthropic.com' });
    await seedCompany(db, { id: 'dupe', domain: 'email.anthropic.com' });
    await seedContact(db, 'p1');
    await link(db, 'r1', 'p1', 'dupe', true);

    const result = await mergeCompanies(db, {
      survivorId: 'keep', sourceIds: ['dupe'], mergedBy: 'tester',
    });

    expect(result.relationsRepointed).toBe(1);
    const rels = await db.select().from(contactCompanyRelations)
      .where(eq(contactCompanyRelations.contactId, 'p1'));
    expect(rels).toHaveLength(1);
    expect(rels[0].companyId).toBe('keep');
    expect(rels[0].isPrimary).toBe(true);
  });

  it('drops duplicate relations and promotes primary onto the surviving link', async () => {
    await seedCompany(db, { id: 'keep' });
    await seedCompany(db, { id: 'dupe' });
    await seedContact(db, 'p1');
    await link(db, 'r1', 'p1', 'keep', false);
    await link(db, 'r2', 'p1', 'dupe', true);

    await mergeCompanies(db, { survivorId: 'keep', sourceIds: ['dupe'], mergedBy: 'tester' });

    const rels = await db.select().from(contactCompanyRelations)
      .where(eq(contactCompanyRelations.contactId, 'p1'));
    expect(rels).toHaveLength(1);
    expect(rels[0].id).toBe('r1');
    expect(rels[0].isPrimary).toBe(true);
  });

  it('fills empty survivor fields from sources without overwriting', async () => {
    await seedCompany(db, {
      id: 'keep', name: 'Anthropic PBC', domain: 'anthropic.com', industry: 'AI',
    });
    await seedCompany(db, {
      id: 'dupe', domain: 'email.anthropic.com',
      industry: 'Something else', website: 'https://anthropic.com', city: 'SF',
    });

    const result = await mergeCompanies(db, {
      survivorId: 'keep', sourceIds: ['dupe'], mergedBy: 'tester',
    });

    const [keep] = await db.select().from(companies).where(eq(companies.id, 'keep'));
    expect(keep.industry).toBe('AI'); // not overwritten
    expect(keep.website).toBe('https://anthropic.com'); // filled
    expect(keep.city).toBe('SF'); // filled
    expect(result.fieldsFilled.sort()).toEqual(['city', 'website']);
  });

  it('canonicalizes a subdomain survivor domain', async () => {
    await seedCompany(db, { id: 'keep', domain: 'email.anthropic.com' });
    await seedCompany(db, { id: 'dupe', domain: 'mail.anthropic.com' });

    await mergeCompanies(db, { survivorId: 'keep', sourceIds: ['dupe'], mergedBy: 'tester' });

    const [keep] = await db.select().from(companies).where(eq(companies.id, 'keep'));
    expect(keep.domain).toBe('anthropic.com');
  });

  it('re-points children, converted leads, deal suggestions and activities', async () => {
    await seedCompany(db, { id: 'keep' });
    await seedCompany(db, { id: 'dupe' });
    await seedCompany(db, { id: 'child', parentCompanyId: 'dupe' });
    await seedContact(db, 'p1');
    await db.insert(leads).values({
      id: 'l1', firstName: 'L', lastName: 'One', convertedCompanyId: 'dupe',
      createdBy: 'test', createdAt: T0, updatedAt: T0,
    });
    await db.insert(dealSuggestions).values({
      id: 'ds1', contactId: 'p1', companyId: 'dupe', suggestedName: 'Deal',
      createdAt: T0, updatedAt: T0,
    });
    await db.insert(activities).values({
      id: 'act1', typeId: 'type-email', title: 'Email',
      relatedRecordId: 'dupe', relatedRecordType: 'company',
      createdBy: 'test', createdAt: T0, updatedAt: T0,
    });

    await mergeCompanies(db, { survivorId: 'keep', sourceIds: ['dupe'], mergedBy: 'tester' });

    const [child] = await db.select().from(companies).where(eq(companies.id, 'child'));
    expect(child.parentCompanyId).toBe('keep');
    const [lead] = await db.select().from(leads).where(eq(leads.id, 'l1'));
    expect(lead.convertedCompanyId).toBe('keep');
    const [suggestion] = await db.select().from(dealSuggestions)
      .where(eq(dealSuggestions.id, 'ds1'));
    expect(suggestion.companyId).toBe('keep');
    const [activity] = await db.select().from(activities).where(eq(activities.id, 'act1'));
    expect(activity.relatedRecordId).toBe('keep');
  });

  it('clears the survivor parent pointer when its parent is merged away', async () => {
    await seedCompany(db, { id: 'dupe' });
    await seedCompany(db, { id: 'keep', parentCompanyId: 'dupe' });

    await mergeCompanies(db, { survivorId: 'keep', sourceIds: ['dupe'], mergedBy: 'tester' });

    const [keep] = await db.select().from(companies).where(eq(companies.id, 'keep'));
    expect(keep.parentCompanyId).toBeNull();
  });

  it('re-points tags, deduping ones the survivor already has', async () => {
    await seedCompany(db, { id: 'keep' });
    await seedCompany(db, { id: 'dupe' });
    await db.insert(tags).values([
      { id: 't-shared', name: 'shared', createdBy: 'test', createdAt: T0 },
      { id: 't-only', name: 'only-on-dupe', createdBy: 'test', createdAt: T0 },
    ]);
    await db.insert(recordTags).values([
      { recordId: 'keep', recordType: 'company', tagId: 't-shared' },
      { recordId: 'dupe', recordType: 'company', tagId: 't-shared' },
      { recordId: 'dupe', recordType: 'company', tagId: 't-only' },
    ]);

    await mergeCompanies(db, { survivorId: 'keep', sourceIds: ['dupe'], mergedBy: 'tester' });

    const keepTags = await db.select().from(recordTags).where(
      and(eq(recordTags.recordId, 'keep'), eq(recordTags.recordType, 'company')),
    );
    expect(keepTags.map((t) => t.tagId).sort()).toEqual(['t-only', 't-shared']);
    const dupeTags = await db.select().from(recordTags).where(
      and(eq(recordTags.recordId, 'dupe'), eq(recordTags.recordType, 'company')),
    );
    expect(dupeTags).toHaveLength(0);
  });

  it('soft-deletes sources into the recycle bin and writes a merge audit entry', async () => {
    await seedCompany(db, { id: 'keep', domain: 'anthropic.com' });
    await seedCompany(db, { id: 'dupe', name: 'Anthropic PBC', domain: 'email.anthropic.com' });

    await mergeCompanies(db, { survivorId: 'keep', sourceIds: ['dupe'], mergedBy: 'tester' });

    const [dupe] = await db.select().from(companies).where(eq(companies.id, 'dupe'));
    expect(dupe.isDeleted).toBe(true);
    const bin = await db.select().from(recycleBin).where(eq(recycleBin.recordId, 'dupe'));
    expect(bin).toHaveLength(1);
    expect(bin[0].recordType).toBe('company');
    const audit = await db.select().from(auditTrail).where(
      and(eq(auditTrail.recordId, 'keep'), eq(auditTrail.fieldName, 'merged_from')),
    );
    expect(audit).toHaveLength(1);
    expect(audit[0].changedBy).toBe('tester');
    expect(JSON.parse(audit[0].newValue!)).toMatchObject({ id: 'dupe', name: 'Anthropic PBC' });
  });

  it('rejects invalid input', async () => {
    await seedCompany(db, { id: 'keep' });
    await seedCompany(db, { id: 'gone', isDeleted: true, deletedAt: T0 });

    await expect(
      mergeCompanies(db, { survivorId: 'missing', sourceIds: ['keep'], mergedBy: 't' }),
    ).rejects.toThrowError(MergeValidationError);
    await expect(
      mergeCompanies(db, { survivorId: 'keep', sourceIds: [], mergedBy: 't' }),
    ).rejects.toThrowError(MergeValidationError);
    await expect(
      mergeCompanies(db, { survivorId: 'keep', sourceIds: ['keep'], mergedBy: 't' }),
    ).rejects.toThrowError(MergeValidationError);
    await expect(
      mergeCompanies(db, { survivorId: 'keep', sourceIds: ['gone'], mergedBy: 't' }),
    ).rejects.toThrowError(MergeValidationError);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run worker/__tests__/company-merge.test.ts`
Expected: FAIL — module `../services/company-merge` does not exist.

- [ ] **Step 3: Implement the service**

Create `worker/services/company-merge.ts`:

```typescript
/**
 * Company merge (dedup cleanup). Re-points every reference from the source
 * companies to the survivor, copies fields fill-empty-only, canonicalizes
 * the survivor's domain, and soft-deletes the sources into the recycle bin.
 *
 * D1 has no multi-statement transactions here, so writes run sequentially
 * with references re-pointed first and destructive steps last: an
 * interrupted merge leaves only already-re-pointed rows — nothing is lost,
 * and re-running the same merge completes the remainder.
 */
import { and, eq, inArray, ne } from 'drizzle-orm';
import {
  activities,
  auditTrail,
  companies,
  contactCompanyRelations,
  dealSuggestions,
  leads,
  recordTags,
  type Database,
} from '../db';
import { generateId, now } from '../utils';
import { recordAuditChanges } from '../middleware/audit';
import { moveToRecycleBin } from '../routes/recycle-bin';
import { canonicalCompanyDomain } from './company-domain';
import { MERGEABLE_FIELDS, type MergeableField } from './company-duplicates';

type CompanyRow = typeof companies.$inferSelect;

export class MergeValidationError extends Error {
  constructor(message: string, readonly status: 400 | 404 = 400) {
    super(message);
    this.name = 'MergeValidationError';
  }
}

export interface MergeResult {
  survivorId: string;
  mergedIds: string[];
  relationsRepointed: number;
  fieldsFilled: string[];
}

function isEmpty(value: unknown): boolean {
  return value === null || value === undefined || String(value).trim() === '';
}

export async function mergeCompanies(
  db: Database,
  input: { survivorId: string; sourceIds: string[]; mergedBy: string },
): Promise<MergeResult> {
  const { survivorId, mergedBy } = input;
  const sourceIds = [...new Set(input.sourceIds)].filter((id) => id !== survivorId);
  if (sourceIds.length === 0) {
    throw new MergeValidationError('No source companies to merge');
  }

  const rows = await db
    .select()
    .from(companies)
    .where(
      and(inArray(companies.id, [survivorId, ...sourceIds]), eq(companies.isDeleted, false)),
    );
  const survivor = rows.find((r) => r.id === survivorId);
  if (!survivor) {
    throw new MergeValidationError('Survivor company not found', 404);
  }
  const sources = rows.filter((r) => r.id !== survivorId);
  if (sources.length !== sourceIds.length) {
    throw new MergeValidationError('One or more source companies not found');
  }

  // 1. Contact relations: drop rows whose contact already links to the
  //    survivor (unique idx_ccr_unique), re-point the rest. A dropped
  //    duplicate that was the contact's primary link promotes the
  //    surviving one.
  const survivorRels = await db
    .select()
    .from(contactCompanyRelations)
    .where(eq(contactCompanyRelations.companyId, survivorId));
  const linkedContactIds = new Set(survivorRels.map((r) => r.contactId));
  const sourceRels = await db
    .select()
    .from(contactCompanyRelations)
    .where(inArray(contactCompanyRelations.companyId, sourceIds));

  let relationsRepointed = 0;
  for (const rel of sourceRels) {
    if (linkedContactIds.has(rel.contactId)) {
      await db
        .delete(contactCompanyRelations)
        .where(eq(contactCompanyRelations.id, rel.id));
      const existing = survivorRels.find((r) => r.contactId === rel.contactId);
      if (rel.isPrimary && existing && !existing.isPrimary) {
        await db
          .update(contactCompanyRelations)
          .set({ isPrimary: true })
          .where(eq(contactCompanyRelations.id, existing.id));
      }
    } else {
      await db
        .update(contactCompanyRelations)
        .set({ companyId: survivorId })
        .where(eq(contactCompanyRelations.id, rel.id));
      linkedContactIds.add(rel.contactId);
      relationsRepointed += 1;
    }
  }

  // 2. Children of merged sources become the survivor's (never the survivor
  //    itself — self-parenting is handled via the patch below).
  await db
    .update(companies)
    .set({ parentCompanyId: survivorId, updatedAt: now() })
    .where(
      and(inArray(companies.parentCompanyId, sourceIds), ne(companies.id, survivorId)),
    );

  // 3. Converted leads, deal suggestions, company-related activities.
  await db
    .update(leads)
    .set({ convertedCompanyId: survivorId })
    .where(inArray(leads.convertedCompanyId, sourceIds));
  await db
    .update(dealSuggestions)
    .set({ companyId: survivorId })
    .where(inArray(dealSuggestions.companyId, sourceIds));
  await db
    .update(activities)
    .set({ relatedRecordId: survivorId })
    .where(
      and(
        eq(activities.relatedRecordType, 'company'),
        inArray(activities.relatedRecordId, sourceIds),
      ),
    );

  // 4. Tags: composite PK (recordId, recordType, tagId) — drop source rows
  //    whose tag the survivor already has, re-point the rest.
  const survivorTags = await db
    .select({ tagId: recordTags.tagId })
    .from(recordTags)
    .where(and(eq(recordTags.recordId, survivorId), eq(recordTags.recordType, 'company')));
  const survivorTagIds = new Set(survivorTags.map((t) => t.tagId));
  const sourceTags = await db
    .select()
    .from(recordTags)
    .where(and(inArray(recordTags.recordId, sourceIds), eq(recordTags.recordType, 'company')));
  for (const tag of sourceTags) {
    const rowFilter = and(
      eq(recordTags.recordId, tag.recordId),
      eq(recordTags.recordType, 'company'),
      eq(recordTags.tagId, tag.tagId),
    );
    if (survivorTagIds.has(tag.tagId)) {
      await db.delete(recordTags).where(rowFilter);
    } else {
      await db.update(recordTags).set({ recordId: survivorId }).where(rowFilter);
      survivorTagIds.add(tag.tagId);
    }
  }

  // 5. Survivor patch: fill empty fields from sources (first donor wins),
  //    canonicalize the domain, clear a parent pointer that was merged away.
  const patch: Partial<Pick<CompanyRow, MergeableField>> & {
    parentCompanyId?: string | null;
  } = {};
  for (const field of MERGEABLE_FIELDS) {
    if (!isEmpty(survivor[field])) continue;
    const donor = sources.find((s) => !isEmpty(s[field]));
    if (donor) {
      (patch as Record<MergeableField, string | null>)[field] = donor[field];
    }
  }
  const effectiveDomain = (patch.domain ?? survivor.domain) as string | null;
  if (effectiveDomain) {
    const canonical = canonicalCompanyDomain(effectiveDomain);
    if (canonical !== effectiveDomain) patch.domain = canonical;
  }
  if (survivor.parentCompanyId && sourceIds.includes(survivor.parentCompanyId)) {
    patch.parentCompanyId = null;
  }
  if (Object.keys(patch).length > 0) {
    await db
      .update(companies)
      .set({ ...patch, updatedAt: now() })
      .where(eq(companies.id, survivorId));
    await recordAuditChanges(db, survivorId, 'company', survivor, { ...survivor, ...patch }, mergedBy);
  }

  // 6. Audit breadcrumb + soft-delete sources (last, so an interrupted merge
  //    never orphans references).
  const timestamp = now();
  for (const source of sources) {
    await db.insert(auditTrail).values({
      id: generateId(),
      recordId: survivorId,
      recordType: 'company',
      fieldName: 'merged_from',
      oldValue: null,
      newValue: JSON.stringify({ id: source.id, name: source.name, domain: source.domain }),
      changedBy: mergedBy,
      changedAt: timestamp,
    });
    await moveToRecycleBin(db, source.id, 'company', source, mergedBy);
    await db
      .update(companies)
      .set({ isDeleted: true, deletedAt: timestamp, updatedAt: timestamp })
      .where(eq(companies.id, source.id));
  }

  return {
    survivorId,
    mergedIds: sourceIds,
    relationsRepointed,
    fieldsFilled: Object.keys(patch).filter((f) => f !== 'parentCompanyId'),
  };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run worker/__tests__/company-merge.test.ts`
Expected: PASS (9 tests).

- [ ] **Step 5: Full suite, typecheck, commit**

Run: `npx vitest run && npm run typecheck`
Expected: all green.

```bash
git add worker/services/company-merge.ts worker/__tests__/company-merge.test.ts
git commit -m "feat: transactional-order company merge service"
```

---

### Task 5: Merge endpoint

**Files:**
- Modify: `worker/routes/companies.ts` (new POST route)
- Modify: `public/eldrin-app.manifest.json` (new route entry)
- Test: `worker/__tests__/company-dedup-routes.test.ts` (append)

**Interfaces:**
- Consumes: `mergeCompanies`, `MergeValidationError` (Task 4).
- Produces: `POST /api/companies/:id/merge` body `{ sourceIds: string[] }` → `200 { result: MergeResult }`, `400 { error }` on invalid input, `404 { error }` on missing survivor. Used by Task 6.

- [ ] **Step 1: Write the failing route tests**

Append to `worker/__tests__/company-dedup-routes.test.ts`:

```typescript
describe('POST /api/companies/:id/merge', () => {
  let db: Database;
  let app: ReturnType<typeof createApp>;

  beforeEach(() => {
    db = createTestDb();
    app = createApp(db);
  });

  function merge(path: string, body: unknown) {
    return app.request(
      path,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      },
      {} as Env,
    );
  }

  it('merges sources into the survivor', async () => {
    await seedCompany(db, { id: 'keep', name: 'Anthropic PBC', domain: 'anthropic.com' });
    await seedCompany(db, { id: 'dupe', name: 'Anthropic PBC', domain: 'email.anthropic.com' });
    const res = await merge('/api/companies/keep/merge', { sourceIds: ['dupe'] });
    expect(res.status).toBe(200);
    const { result } = (await res.json()) as {
      result: { survivorId: string; mergedIds: string[] };
    };
    expect(result.survivorId).toBe('keep');
    expect(result.mergedIds).toEqual(['dupe']);
  });

  it('rejects a missing or empty sourceIds array', async () => {
    await seedCompany(db, { id: 'keep' });
    expect((await merge('/api/companies/keep/merge', {})).status).toBe(400);
    expect((await merge('/api/companies/keep/merge', { sourceIds: [] })).status).toBe(400);
    expect((await merge('/api/companies/keep/merge', { sourceIds: [42] })).status).toBe(400);
  });

  it('404s for an unknown survivor', async () => {
    await seedCompany(db, { id: 'dupe' });
    const res = await merge('/api/companies/nope/merge', { sourceIds: ['dupe'] });
    expect(res.status).toBe(404);
  });

  it('400s when merging a company into itself', async () => {
    await seedCompany(db, { id: 'keep' });
    const res = await merge('/api/companies/keep/merge', { sourceIds: ['keep'] });
    expect(res.status).toBe(400);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run worker/__tests__/company-dedup-routes.test.ts`
Expected: new tests FAIL with 404 (route not defined).

- [ ] **Step 3: Implement the route**

In `worker/routes/companies.ts`, add the import:

```typescript
import { MergeValidationError, mergeCompanies } from '../services/company-merge';
```

and register (next to the `request-enhancement` handler):

```typescript
// ── POST /api/companies/:id/merge — merge duplicates into a survivor ─────────
companyRoutes.post('/api/companies/:id/merge', async (c) => {
  const db = c.get('db');
  const survivorId = c.req.param('id');
  const body = await c.req.json<{ sourceIds?: unknown }>().catch(() => null);
  const sourceIds = body?.sourceIds;
  if (
    !Array.isArray(sourceIds) ||
    sourceIds.length === 0 ||
    !sourceIds.every((s): s is string => typeof s === 'string' && s.length > 0)
  ) {
    return c.json({ error: 'sourceIds must be a non-empty array of company ids' }, 400);
  }

  try {
    const result = await mergeCompanies(db, {
      survivorId,
      sourceIds,
      mergedBy: c.get('auth')?.userId ?? 'system',
    });
    return c.json({ result });
  } catch (error) {
    if (error instanceof MergeValidationError) {
      return c.json({ error: error.message }, error.status);
    }
    throw error;
  }
});
```

In `public/eldrin-app.manifest.json`, add to `api.routes` alongside the other company entries:

```json
{ "method": "POST", "path": "/api/companies/:id/merge", "permission": "companies:update" },
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run worker/__tests__/company-dedup-routes.test.ts`
Expected: PASS (7 tests).

- [ ] **Step 5: Full suite, typecheck, commit**

Run: `npx vitest run && npm run typecheck`
Expected: all green.

```bash
git add worker/routes/companies.ts public/eldrin-app.manifest.json worker/__tests__/company-dedup-routes.test.ts
git commit -m "feat: POST /api/companies/:id/merge endpoint"
```

---

### Task 6: Duplicates review UI

**Files:**
- Modify: `src/types/contact.ts` (append types)
- Modify: `src/api.ts` (append helpers)
- Create: `src/pages/companies/CompanyDuplicates.tsx`
- Modify: `src/pages/companies/CompanyList.tsx`

No frontend test infra exists (vitest only includes `worker/**`), so this task is verified by typecheck + build + a browser walkthrough (Step 5) instead of component tests.

**Interfaces:**
- Consumes: `GET /api/companies/duplicates`, `POST /api/companies/:id/merge` (Tasks 3, 5); existing `request`/`apiUrl` helpers in `src/api.ts`; `useAuthHeaders` from `@eldrin-project/eldrin-app-react`.
- Produces: `CompanyDuplicates` React component; `api.getCompanyDuplicates(base, headers)`; `api.mergeCompanies(base, headers, survivorId, sourceIds)`.

- [ ] **Step 1: Add types and API helpers**

Append to `src/types/contact.ts`:

```typescript
export interface CompanyDuplicateMember {
  id: string;
  name: string;
  domain: string | null;
  isAutoCreated: boolean;
  createdAt: number;
  contactCount: number;
  filledFieldCount: number;
}

export interface CompanyDuplicateGroup {
  key: string;
  signal: 'domain' | 'name';
  confidence: number;
  suggestedSurvivorId: string;
  members: CompanyDuplicateMember[];
}
```

Append to `src/api.ts` (Companies section; add `CompanyDuplicateGroup` to the existing type-import list from `./types/contact`):

```typescript
export async function getCompanyDuplicates(
  base: string,
  headers: Headers,
): Promise<{ groups: CompanyDuplicateGroup[] }> {
  return request(apiUrl(base, '/companies/duplicates'), headers);
}

export async function mergeCompanies(
  base: string,
  headers: Headers,
  survivorId: string,
  sourceIds: string[],
): Promise<{ result: { survivorId: string; mergedIds: string[] } }> {
  return request(apiUrl(base, `/companies/${survivorId}/merge`), headers, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sourceIds }),
  });
}
```

- [ ] **Step 2: Create the review modal**

Create `src/pages/companies/CompanyDuplicates.tsx`:

```tsx
import { useState } from 'react';
import { useAuthHeaders } from '@eldrin-project/eldrin-app-react';
import { toast } from 'sonner';
import { GitMerge } from 'lucide-react';
import type { CompanyDuplicateGroup } from '../../types/contact';
import * as api from '../../api';

interface CompanyDuplicatesProps {
  apiBase: string;
  groups: CompanyDuplicateGroup[];
  onClose: () => void;
  onMerged: () => void;
}

function groupId(group: CompanyDuplicateGroup): string {
  return `${group.signal}:${group.key}`;
}

export function CompanyDuplicates({ apiBase, groups, onClose, onMerged }: CompanyDuplicatesProps) {
  const authHeaders = useAuthHeaders();
  const [survivors, setSurvivors] = useState<Record<string, string>>(() =>
    Object.fromEntries(groups.map((g) => [groupId(g), g.suggestedSurvivorId])),
  );
  const [merging, setMerging] = useState<string | null>(null);

  async function handleMerge(group: CompanyDuplicateGroup) {
    const gid = groupId(group);
    const survivorId = survivors[gid] ?? group.suggestedSurvivorId;
    const sourceIds = group.members.map((m) => m.id).filter((id) => id !== survivorId);
    setMerging(gid);
    try {
      await api.mergeCompanies(apiBase, authHeaders, survivorId, sourceIds);
      toast.success(`Merged ${sourceIds.length} duplicate${sourceIds.length === 1 ? '' : 's'}`);
      onMerged();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Merge failed');
    } finally {
      setMerging(null);
    }
  }

  return (
    <div className="modal modal-open">
      <div className="modal-box max-w-3xl">
        <h3 className="font-bold text-lg mb-1">Duplicate companies</h3>
        <p className="text-sm text-base-content/60 mb-4">
          Pick which record survives; the others are merged into it and moved to the recycle bin.
        </p>
        {groups.length === 0 && (
          <p className="text-sm text-base-content/60">No duplicates found.</p>
        )}
        <div className="flex flex-col gap-4">
          {groups.map((group) => (
            <div key={groupId(group)} className="card bg-base-200">
              <div className="card-body p-4">
                <div className="flex items-center justify-between">
                  <span className="font-medium">{group.key}</span>
                  <span className="badge badge-sm badge-soft">
                    {group.signal === 'domain' ? 'same domain' : 'same name'}
                  </span>
                </div>
                <div className="flex flex-col gap-2 mt-2">
                  {group.members.map((member) => (
                    <label key={member.id} className="flex items-center gap-3 cursor-pointer">
                      <input
                        type="radio"
                        className="radio radio-sm"
                        name={`survivor-${groupId(group)}`}
                        checked={(survivors[groupId(group)] ?? group.suggestedSurvivorId) === member.id}
                        onChange={() =>
                          setSurvivors((s) => ({ ...s, [groupId(group)]: member.id }))
                        }
                      />
                      <div className="flex-1">
                        <div className="text-sm font-medium">{member.name}</div>
                        <div className="text-xs text-base-content/50">
                          {member.domain ?? 'no domain'} · {member.contactCount} contact
                          {member.contactCount === 1 ? '' : 's'} · {member.filledFieldCount} filled
                          fields · {member.isAutoCreated ? 'auto-captured' : 'manual'} · created{' '}
                          {new Date(member.createdAt).toLocaleDateString()}
                        </div>
                      </div>
                      {member.id === group.suggestedSurvivorId && (
                        <span className="badge badge-xs badge-primary badge-soft">suggested</span>
                      )}
                    </label>
                  ))}
                </div>
                <div className="card-actions justify-end mt-2">
                  <button
                    className="btn btn-primary btn-sm gap-1"
                    disabled={merging !== null}
                    onClick={() => handleMerge(group)}
                  >
                    <GitMerge className="w-4 h-4" />
                    {merging === groupId(group) ? 'Merging…' : 'Merge'}
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
        <div className="modal-action">
          <button className="btn btn-ghost btn-sm" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
      <div className="modal-backdrop" onClick={onClose} />
    </div>
  );
}
```

- [ ] **Step 3: Wire into CompanyList**

In `src/pages/companies/CompanyList.tsx`:

1. Extend imports:

```tsx
import { Plus, Search, Upload, Download, GitMerge } from 'lucide-react';
import type { CompanyListRow, CompanyDuplicateGroup, Pagination, Tag } from '../../types/contact';
import { CompanyDuplicates } from './CompanyDuplicates';
```

2. Add state + fetch (below the existing `showExport` state):

```tsx
  const [duplicateGroups, setDuplicateGroups] = useState<CompanyDuplicateGroup[]>([]);
  const [showDuplicates, setShowDuplicates] = useState(false);

  const fetchDuplicates = useCallback(async () => {
    try {
      const result = await api.getCompanyDuplicates(apiBase, headersRef.current);
      setDuplicateGroups(result.groups);
    } catch {
      // Non-blocking: the list works without the dedup affordance.
    }
  }, [apiBase]);

  useEffect(() => {
    fetchDuplicates();
  }, [fetchDuplicates]);
```

3. In the `PageHeader` `actions` fragment, insert **before** the Import button:

```tsx
            {duplicateGroups.length > 0 && (
              <button
                className="btn btn-warning btn-outline btn-sm gap-1"
                onClick={() => setShowDuplicates(true)}
              >
                <GitMerge className="w-4 h-4" /> Duplicates
                <span className="badge badge-sm">{duplicateGroups.length}</span>
              </button>
            )}
```

4. Next to the `showForm` / `showExport` modals at the bottom, add:

```tsx
      {showDuplicates && (
        <CompanyDuplicates
          apiBase={apiBase}
          groups={duplicateGroups}
          onClose={() => setShowDuplicates(false)}
          onMerged={() => {
            fetchDuplicates();
            fetchCompanies(pagination.page);
          }}
        />
      )}
```

(After a merge the modal stays open and re-renders with the refreshed groups; it shows "No duplicates found." when the last group is merged.)

- [ ] **Step 4: Typecheck and build**

Run: `npm run typecheck && npm run build`
Expected: both clean.

- [ ] **Step 5: Browser verification**

In the user's local dev shell environment (eldrin-core shell with CRM loaded, as in prior sessions — CRM preview on port 4009):

1. Ensure the local D1 has the two `Anthropic PBC` companies (`email.anthropic.com`, `mail.anthropic.com`) or seed two companies with sibling subdomains.
2. Open the Companies page → a "Duplicates (1)" button appears.
3. Open it → one group keyed `anthropic.com` with both rows, suggestion pre-selected.
4. Merge → success toast; list refreshes to a single company whose domain is `anthropic.com`; contact links intact on the survivor; the merged row appears in the recycle bin.

Expected: all four observations hold. If the shell environment is unavailable, `npm run preview` + a JWT from `eldrin-core/.dev.vars` reproduces the same flow standalone.

- [ ] **Step 6: Commit**

```bash
git add src/types/contact.ts src/api.ts src/pages/companies/CompanyDuplicates.tsx src/pages/companies/CompanyList.tsx
git commit -m "feat: company duplicates review-and-merge UI"
```

---

### Task 7: Finalize — full verification and branch wrap-up

**Files:** none new.

- [ ] **Step 1: Full verification**

Run from `/Users/tibor/projects/eldrin-backup/eldrin-crm`:

```bash
npx vitest run && npm run typecheck && npm run build
```

Expected: entire suite green, clean typecheck, successful build.

- [ ] **Step 2: Push branch**

```bash
git push -u origin feature/company-dedup
```

- [ ] **Step 3: Acceptance on live data**

With the user (their dev shell): merge the two real Anthropic PBC rows via the new UI and confirm future inbound mail from any `*.anthropic.com` sender links to the surviving company. Then follow `superpowers:finishing-a-development-branch` for merge-to-main and the parent-repo submodule bump (`git add eldrin-crm && git commit -m "chore: update eldrin-crm submodule"` from the parent directory, never from inside the submodule).
