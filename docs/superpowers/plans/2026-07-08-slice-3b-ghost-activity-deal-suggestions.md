# Slice 3b — Ghost-Activity Detection + Deal Auto-Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface contacts/deals that have gone quiet on the CRM dashboard, and auto-suggest deals from buying signals in captured inbound emails via two parallel co-detectors (synchronous keyword heuristic + async AI workflow on every captured email).

**Architecture:** All work lands in `eldrin-crm` except one JSON workflow template (plus a small additive mock-provider extension) in `eldrin-workflows`. The heuristic runs inline in the `email.received` webhook; the AI leg rides a new `deal.detection.requested` event through the existing CRM → core event bus → eldrin-workflows → core proxy → CRM chain proven in Slice 3. Ghost activity is computed on read — no new tables for it.

**Tech Stack:** Cloudflare Workers + Hono 4, Drizzle ORM over D1/SQLite, Vitest + better-sqlite3 (in-memory), React 19 + daisyUI 5 (Quiet Ledger classes), eldrin-workflows template engine (no engine changes).

**Spec:** `docs/superpowers/specs/2026-07-03-ghost-activity-deal-suggestions-design.md` (v3). Read the Decisions table (D1–D7) before starting.

## Global Constraints

- Migration files MUST have a 14-digit timestamp prefix (`YYYYMMDDHHMMSS-description.sql`) — the runner silently skips misnamed files. This slice uses `20260217000000-deal-suggestions.sql`.
- After adding/changing migration SQL run `npm run generate:migrations` in eldrin-crm (dev/build do it too). Tests execute the raw SQL directly via `createTestDb()`.
- Named constants: `HEURISTIC_MIN_FAMILIES = 2`, `AI_SUGGESTION_MIN_CONFIDENCE = 0.6`, scanner input cap `4000` chars, snippet cap `120`, max `3` hits/family, `suggestedValue` rejected outside `(0, 1_000_000_000)`.
- The AI assess endpoint NEVER changes `status`, never deletes, never auto-creates a deal (spec D2/D3).
- `ai_assessment_status`: `'pending'` | `'assessed'`; failures stay `'pending'` (spec D6).
- Suggestion statuses: `'pending'` | `'accepted'` | `'dismissed'`. Sources: `'heuristic'` | `'ai'` | `'heuristic+ai'`.
- Timestamps are epoch **milliseconds** (`now()` from `worker/utils.ts`); ids via `generateId()` (= `crypto.randomUUID()`).
- Immutability: never mutate fetched rows/arrays — build new objects (user rule).
- No `console.log` in production code paths; `console.error` for swallowed failures matches existing emitter/webhook convention.
- Existing suites must stay green: `npm run test` + `npm run typecheck` in eldrin-crm, `npm test` in eldrin-workflows.
- eldrin-crm has NO frontend test harness (vitest is worker-only, `include: ['worker/**/*.test.ts']`). Frontend tasks are verified by `npm run typecheck` + the live-validation task.
- Work on feature branches: `feature/slice-3b-deal-suggestions` in eldrin-crm, `feature/crm-detect-deal-signals-template` in eldrin-workflows. Beware the cwd gotcha: prefer `git -C <abs-path>` over `cd`.
- **Noted deviation from spec §3:** the spec says "no eldrin-workflows engine changes", but the mock AI provider (`worker/engine/ai/providers/mock.ts`) only emits keys it recognizes (`jobTitle`, `phones`, `companyName`, `social`) and would return `{}` for our assessment schema, making dev/live validation impossible. Task 9 extends the mock provider additively (new recognized keys, existing behavior untouched). Flagged to the user in review.

---

### Task 0: Feature branches

**Files:** none (git only)

- [ ] **Step 1: Create the eldrin-crm branch**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-crm checkout main
git -C /Users/tibor/projects/eldrin-backup/eldrin-crm pull
git -C /Users/tibor/projects/eldrin-backup/eldrin-crm checkout -b feature/slice-3b-deal-suggestions
```

- [ ] **Step 2: Create the eldrin-workflows branch**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-workflows checkout main
git -C /Users/tibor/projects/eldrin-backup/eldrin-workflows pull
git -C /Users/tibor/projects/eldrin-backup/eldrin-workflows checkout -b feature/crm-detect-deal-signals-template
```

- [ ] **Step 3: Verify both suites are green before starting**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-crm && npm run test` — Expected: all pass.
Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-workflows && npm test` — Expected: all pass.

---

### Task 1: Reply/signature stripping helper (signature-parser)

**Files:**
- Modify: `eldrin-crm/worker/services/signature-parser.ts`
- Test: `eldrin-crm/worker/__tests__/signature-parser.test.ts` (append)

**Interfaces:**
- Produces: `export function stripQuotedAndSignature(text: string): string` — returns the body with `>`-quoted lines removed and everything at/below the first signature delimiter or sign-off line cut off. Reuses the module's private `SIGNATURE_DELIMITERS` and `SIGN_OFFS` constants.

- [ ] **Step 1: Write the failing tests** (append to `worker/__tests__/signature-parser.test.ts`)

```ts
import { stripQuotedAndSignature } from '../services/signature-parser';

describe('stripQuotedAndSignature', () => {
  it('removes >-quoted reply lines', () => {
    const out = stripQuotedAndSignature('We need pricing.\n> old quoted line about $99,000\nThanks');
    expect(out).toContain('We need pricing.');
    expect(out).not.toContain('$99,000');
  });

  it('cuts at a -- signature delimiter', () => {
    const out = stripQuotedAndSignature('Body text\n--\nJane Doe\nTel: +1 555 000 111');
    expect(out).toContain('Body text');
    expect(out).not.toContain('555 000 111');
  });

  it('cuts at a sign-off line', () => {
    const out = stripQuotedAndSignature('Body text\nBest regards,\nJane\nCFO');
    expect(out).not.toContain('CFO');
  });

  it('returns text unchanged when nothing matches', () => {
    expect(stripQuotedAndSignature('plain body')).toBe('plain body');
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd eldrin-crm && npx vitest run worker/__tests__/signature-parser.test.ts`
Expected: FAIL — `stripQuotedAndSignature` is not exported.

- [ ] **Step 3: Implement** (append to `worker/services/signature-parser.ts`, after `isolateSignatureLines`)

```ts
/**
 * Strip quoted-reply lines and the signature block from an email body so
 * downstream scanners (buying signals) never match on quoted history or
 * signature boilerplate. Cuts at the FIRST delimiter/sign-off line and
 * drops every `>`-prefixed line before it.
 */
export function stripQuotedAndSignature(text: string): string {
  const lines = text.split(/\r?\n/);
  const kept: string[] = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (SIGNATURE_DELIMITERS.some((d) => d.test(trimmed)) || SIGN_OFFS.test(trimmed)) break;
    if (trimmed.startsWith('>')) continue;
    kept.push(line);
  }
  return kept.join('\n');
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd eldrin-crm && npx vitest run worker/__tests__/signature-parser.test.ts` — Expected: PASS (all, incl. pre-existing).

- [ ] **Step 5: Commit**

```bash
git -C eldrin-crm add worker/services/signature-parser.ts worker/__tests__/signature-parser.test.ts
git -C eldrin-crm commit -m "feat(capture): export quoted-reply/signature stripping helper"
```

---

### Task 2: Buying-signal scanner service

**Files:**
- Create: `eldrin-crm/worker/services/buying-signals.ts`
- Test: `eldrin-crm/worker/__tests__/buying-signals.test.ts`

**Interfaces:**
- Consumes: `stripQuotedAndSignature` from Task 1.
- Produces:
  ```ts
  export interface SignalHit { family: 'budget' | 'timeline' | 'stakeholder' | 'intent'; snippet: string }
  export interface BuyingSignals { hits: SignalHit[]; families: string[]; suggestedValue: number | null }
  export const HEURISTIC_MIN_FAMILIES = 2;
  export function detectBuyingSignals(bodyText: string): BuyingSignals
  ```

- [ ] **Step 1: Write the failing tests** (`worker/__tests__/buying-signals.test.ts`)

```ts
import { describe, it, expect } from 'vitest';
import { detectBuyingSignals } from '../services/buying-signals';

describe('detectBuyingSignals', () => {
  it('detects budget signals from currency amounts and keywords', () => {
    const r = detectBuyingSignals('Our budget is $12,000 for this project.');
    expect(r.families).toContain('budget');
    expect(r.suggestedValue).toBe(12000);
  });

  it('parses European-style and suffixed amounts', () => {
    expect(detectBuyingSignals('estimate around 12.000 EUR total').suggestedValue).toBe(12000);
    expect(detectBuyingSignals('roughly €50k to spend').suggestedValue).toBe(50000);
    expect(detectBuyingSignals('a $1.5m engagement').suggestedValue).toBe(1500000);
  });

  it('rejects absurd values (> 1e9) and keeps the largest valid amount', () => {
    const r = detectBuyingSignals('budget $99,999,999,999 or realistically $20,000');
    expect(r.suggestedValue).toBe(20000);
  });

  it('detects timeline signals', () => {
    const r = detectBuyingSignals('We want to go-live by Q3, hard deadline.');
    expect(r.families).toContain('timeline');
  });

  it('detects stakeholder signals', () => {
    const r = detectBuyingSignals("Looping in our CTO and the procurement team.");
    expect(r.families).toContain('stakeholder');
  });

  it('detects intent signals', () => {
    const r = detectBuyingSignals('Please send a proposal; we are running an RFP.');
    expect(r.families).toContain('intent');
  });

  it('collects multiple families in one email', () => {
    const r = detectBuyingSignals(
      'We have a $30,000 budget and need a quote by next quarter. Our CFO will decide.',
    );
    expect(new Set(r.families)).toEqual(new Set(['budget', 'timeline', 'stakeholder', 'intent']));
  });

  it('ignores quoted replies and signature blocks (phone number is not a budget)', () => {
    const r = detectBuyingSignals(
      'Sounds good.\n> we had a $50,000 budget last year\n--\nJane Doe\nTel: +1 555 010 070',
    );
    expect(r.families).toEqual([]);
    expect(r.suggestedValue).toBeNull();
  });

  it('caps hits at 3 per family and snippets at 120 chars', () => {
    const body = Array.from({ length: 5 }, (_, i) => `budget line ${i} ${'x'.repeat(200)}`).join('\n');
    const r = detectBuyingSignals(body);
    const budgetHits = r.hits.filter((h) => h.family === 'budget');
    expect(budgetHits.length).toBeLessThanOrEqual(3);
    for (const h of budgetHits) expect(h.snippet.length).toBeLessThanOrEqual(120);
  });

  it('only scans the first 4000 chars', () => {
    const r = detectBuyingSignals(`${'a'.repeat(4000)} budget $10,000`);
    expect(r.families).toEqual([]);
  });

  it('returns empty result for empty input', () => {
    expect(detectBuyingSignals('')).toEqual({ hits: [], families: [], suggestedValue: null });
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd eldrin-crm && npx vitest run worker/__tests__/buying-signals.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement** (`worker/services/buying-signals.ts`)

```ts
/**
 * Heuristic buying-signal scanner (Slice 3b). Pure, deterministic, LLM-free.
 * Runs synchronously at email-capture time as one of two parallel
 * co-detectors (the other is the AI workflow — spec D1).
 */
import { stripQuotedAndSignature } from './signature-parser';

export interface SignalHit {
  family: 'budget' | 'timeline' | 'stakeholder' | 'intent';
  snippet: string;
}

export interface BuyingSignals {
  hits: SignalHit[];
  families: string[];
  suggestedValue: number | null;
}

/** A suggestion is only created when this many distinct families match. */
export const HEURISTIC_MIN_FAMILIES = 2;

/** Matches the captured bodyText cap applied upstream by eldrin-email. */
const MAX_INPUT_LENGTH = 4000;
const MAX_SNIPPET_LENGTH = 120;
const MAX_HITS_PER_FAMILY = 3;
const MAX_SUGGESTED_VALUE = 1_000_000_000;

/** `$12,000` · `€50k` · `12.000 EUR` · `1.5m USD` … */
const CURRENCY_RE =
  /(?:[$€£]\s?\d[\d.,]*\s?[km]?\b)|(?:\b\d[\d.,]*\s?[km]?\s?(?:usd|eur|gbp|dollars?|euros?)\b)/gi;

const FAMILY_PATTERNS: ReadonlyArray<{ family: SignalHit['family']; patterns: RegExp[] }> = [
  {
    family: 'budget',
    patterns: [CURRENCY_RE, /\b(budget|pricing|cost estimate|price range)\b/gi],
  },
  {
    family: 'timeline',
    patterns: [
      /\bby (q[1-4]|end of \w+|(?:early|mid|late) \w+)\b/gi,
      /\bdeadline\b/gi,
      /\bgo[- ]live\b/gi,
      /\b(?:this|next) (?:quarter|month|year)\b/gi,
    ],
  },
  {
    family: 'stakeholder',
    patterns: [
      /\blooping in\b/gi,
      /\bcc'?ing\b/gi,
      /\bour (?:cto|cfo|ceo|coo|cio|vp|head of [\w ]{1,40})\b/gi,
      /\bdecision[- ]makers?\b/gi,
      /\bprocurement\b/gi,
    ],
  },
  {
    family: 'intent',
    patterns: [
      /\brf[pi]\b/gi,
      /\brequest for proposal\b/gi,
      /\bproposal\b/gi,
      /\bquot(?:e|ation)\b/gi,
      /\bevaluat(?:e|ion|ing)\b/gi,
      /\b(?:trial|pilot|poc)\b/gi,
      /\bcontract\b/gi,
    ],
  },
];

/** Parse one currency-ish match into a number; null when implausible. */
function parseCurrencyAmount(raw: string): number | null {
  const suffix = /([km])\b/i.exec(raw)?.[1]?.toLowerCase() ?? null;
  const digits = raw.replace(/[^\d.,]/g, '');
  if (!digits) return null;

  let normalized = digits;
  const lastDot = digits.lastIndexOf('.');
  const lastComma = digits.lastIndexOf(',');
  if (lastDot !== -1 && lastComma !== -1) {
    // Both present: the later one is the decimal separator.
    normalized =
      lastDot > lastComma
        ? digits.replace(/,/g, '')
        : digits.replace(/\./g, '').replace(',', '.');
  } else if (lastDot !== -1 || lastComma !== -1) {
    const sep = lastDot !== -1 ? '.' : ',';
    const after = digits.length - (lastDot !== -1 ? lastDot : lastComma) - 1;
    // Exactly 3 digits after a lone separator reads as a thousands group.
    normalized =
      after === 3 ? digits.replace(new RegExp(`\\${sep}`, 'g'), '') : digits.replace(',', '.');
  }

  let value = Number(normalized);
  if (!Number.isFinite(value)) return null;
  if (suffix === 'k') value *= 1_000;
  if (suffix === 'm') value *= 1_000_000;
  if (value <= 0 || value > MAX_SUGGESTED_VALUE) return null;
  return value;
}

/** Scan a captured email body for buying signals. */
export function detectBuyingSignals(bodyText: string): BuyingSignals {
  const text = stripQuotedAndSignature(bodyText.slice(0, MAX_INPUT_LENGTH));
  if (!text.trim()) return { hits: [], families: [], suggestedValue: null };

  const hits: SignalHit[] = [];
  for (const { family, patterns } of FAMILY_PATTERNS) {
    const familyHits: SignalHit[] = [];
    for (const pattern of patterns) {
      pattern.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(text)) !== null && familyHits.length < MAX_HITS_PER_FAMILY) {
        const start = Math.max(0, match.index - 40);
        const snippet = text.slice(start, match.index + match[0].length + 40).trim();
        familyHits.push({ family, snippet: snippet.slice(0, MAX_SNIPPET_LENGTH) });
      }
      if (familyHits.length >= MAX_HITS_PER_FAMILY) break;
    }
    hits.push(...familyHits);
  }

  let suggestedValue: number | null = null;
  CURRENCY_RE.lastIndex = 0;
  for (const match of text.matchAll(CURRENCY_RE)) {
    const value = parseCurrencyAmount(match[0]);
    if (value !== null && (suggestedValue === null || value > suggestedValue)) {
      suggestedValue = value;
    }
  }

  const families = [...new Set(hits.map((h) => h.family))];
  return { hits, families, suggestedValue };
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd eldrin-crm && npx vitest run worker/__tests__/buying-signals.test.ts` — Expected: PASS. Iterate on regexes until every fixture passes; do not weaken the tests.

- [ ] **Step 5: Commit**

```bash
git -C eldrin-crm add worker/services/buying-signals.ts worker/__tests__/buying-signals.test.ts
git -C eldrin-crm commit -m "feat(deals): buying-signal scanner with reply/signature stripping"
```

---

### Task 3: `deal_suggestions` table (migration + Drizzle schema)

**Files:**
- Create: `eldrin-crm/migrations/20260217000000-deal-suggestions.sql`
- Modify: `eldrin-crm/worker/db/schema.ts` (append after `dealStageHistory`)
- Test: `eldrin-crm/worker/__tests__/deal-suggestions-schema.test.ts`

**Interfaces:**
- Produces: Drizzle table `dealSuggestions` exported from `worker/db/schema.ts` (re-exported via `worker/db/index.ts`'s `export * from './schema'`). Columns as below; timestamps epoch ms.

- [ ] **Step 1: Write the failing test** (`worker/__tests__/deal-suggestions-schema.test.ts`)

```ts
import { describe, it, expect } from 'vitest';
import { eq } from 'drizzle-orm';
import { createTestDb } from './test-db';
import { contacts, dealSuggestions } from '../db';

const T0 = 1700000000000;

describe('deal_suggestions table', () => {
  it('inserts and reads back a suggestion with defaults', async () => {
    const db = createTestDb();
    await db.insert(contacts).values({
      id: 'ct1', firstName: 'Ann', lastName: 'Lee',
      createdBy: 'system', createdAt: T0, updatedAt: T0,
    });
    await db.insert(dealSuggestions).values({
      id: 'ds1', contactId: 'ct1', signals: '[]',
      suggestedName: 'Acme — RFP', createdAt: T0, updatedAt: T0,
    });
    const [row] = await db.select().from(dealSuggestions).where(eq(dealSuggestions.id, 'ds1'));
    expect(row.status).toBe('pending');
    expect(row.source).toBe('heuristic');
    expect(row.aiAssessmentStatus).toBe('pending');
    expect(row.suggestedValue).toBeNull();
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd eldrin-crm && npx vitest run worker/__tests__/deal-suggestions-schema.test.ts`
Expected: FAIL — `dealSuggestions` not exported / table missing.

- [ ] **Step 3: Write the migration** (`migrations/20260217000000-deal-suggestions.sql`)

```sql
-- Slice 3b: deal auto-detection suggestions (heuristic + AI co-detectors).
CREATE TABLE deal_suggestions (
  id TEXT PRIMARY KEY,
  contact_id TEXT NOT NULL,
  company_id TEXT,
  source_message_id TEXT,
  signals TEXT NOT NULL DEFAULT '[]',
  suggested_name TEXT NOT NULL,
  suggested_value REAL,
  status TEXT NOT NULL DEFAULT 'pending',
  source TEXT NOT NULL DEFAULT 'heuristic',
  ai_assessment_status TEXT NOT NULL DEFAULT 'pending',
  ai_confidence REAL,
  ai_reasoning TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE,
  FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE SET NULL
);
CREATE INDEX idx_deal_suggestions_status ON deal_suggestions(status);
CREATE INDEX idx_deal_suggestions_contact ON deal_suggestions(contact_id);
CREATE INDEX idx_deal_suggestions_ai_status ON deal_suggestions(ai_assessment_status);
```

- [ ] **Step 4: Add the Drizzle table** (append to `worker/db/schema.ts` after `dealStageHistory`)

```ts
// ── Deal Suggestions (Slice 3b) ─────────────────────────────────────────

export const dealSuggestions = sqliteTable(
  'deal_suggestions',
  {
    id: text('id').primaryKey(),
    contactId: text('contact_id')
      .notNull()
      .references(() => contacts.id, { onDelete: 'cascade' }),
    companyId: text('company_id').references(() => companies.id, { onDelete: 'set null' }),
    sourceMessageId: text('source_message_id'),
    signals: text('signals').notNull().default('[]'),
    suggestedName: text('suggested_name').notNull(),
    suggestedValue: real('suggested_value'),
    status: text('status').notNull().default('pending'),
    source: text('source').notNull().default('heuristic'),
    aiAssessmentStatus: text('ai_assessment_status').notNull().default('pending'),
    aiConfidence: real('ai_confidence'),
    aiReasoning: text('ai_reasoning'),
    createdAt: integer('created_at', { mode: 'number' }).notNull(),
    updatedAt: integer('updated_at', { mode: 'number' }).notNull(),
  },
  (table) => [
    index('idx_deal_suggestions_status').on(table.status),
    index('idx_deal_suggestions_contact').on(table.contactId),
    index('idx_deal_suggestions_ai_status').on(table.aiAssessmentStatus),
  ],
);
```

- [ ] **Step 5: Regenerate bundled migrations and verify**

Run: `cd eldrin-crm && npm run generate:migrations && npx vitest run worker/__tests__/deal-suggestions-schema.test.ts`
Expected: PASS. Also run `npm run typecheck` — expected clean.

- [ ] **Step 6: Commit**

```bash
git -C eldrin-crm add migrations/20260217000000-deal-suggestions.sql worker/db/schema.ts worker/migrations.generated.ts worker/__tests__/deal-suggestions-schema.test.ts
git -C eldrin-crm commit -m "feat(deals): deal_suggestions table + Drizzle schema"
```

---

### Task 4: Suggestion store service (guards, merge, dedup)

**Files:**
- Create: `eldrin-crm/worker/services/deal-suggestions.ts`
- Test: `eldrin-crm/worker/__tests__/deal-suggestions-service.test.ts`

**Interfaces:**
- Consumes: `BuyingSignals`/`SignalHit` from Task 2, `dealSuggestions` from Task 3.
- Produces:
  ```ts
  export const AI_SUGGESTION_MIN_CONFIDENCE = 0.6;
  export function fallbackSuggestionName(firstName: string, lastName: string | null): string; // `Deal with ${first} ${last}`.trim()
  export function isFallbackName(name: string): boolean; // startsWith('Deal with ')
  export async function contactHasOpenDeal(db: Database, contactId: string): Promise<boolean>;
  export async function recordHeuristicSuggestion(
    db: Database,
    input: { contactId: string; messageId: string; subject: string | null; signals: BuyingSignals },
  ): Promise<{ action: 'created' | 'merged' | 'skipped' }>;
  ```
  "Open deal" predicate (mirrors `worker/services/reports.ts` `getDashboardKPIs`): `deals.isDeleted = false` AND joined `pipelineStages.name` not `'Closed Won'`/`'Closed Lost'`, reached from `dealContacts.contactId`.

- [ ] **Step 1: Write the failing tests** (`worker/__tests__/deal-suggestions-service.test.ts`)

```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { eq } from 'drizzle-orm';
import { createTestDb } from './test-db';
import type { Database } from '../db';
import {
  contacts, companies, contactCompanyRelations,
  deals, dealContacts, dealSuggestions, pipelines, pipelineStages,
} from '../db';
import { contactHasOpenDeal, recordHeuristicSuggestion } from '../services/deal-suggestions';
import type { BuyingSignals } from '../services/buying-signals';

const T0 = 1700000000000;

function signals(overrides: Partial<BuyingSignals> = {}): BuyingSignals {
  return {
    hits: [
      { family: 'budget', snippet: 'budget is $12,000' },
      { family: 'intent', snippet: 'send a proposal' },
    ],
    families: ['budget', 'intent'],
    suggestedValue: 12000,
    ...overrides,
  };
}

async function seedContact(db: Database, id = 'ct1') {
  await db.insert(contacts).values({
    id, firstName: 'Ann', lastName: 'Lee', createdBy: 'system', createdAt: T0, updatedAt: T0,
  });
}

async function seedCompanyFor(db: Database, contactId: string) {
  await db.insert(companies).values({
    id: 'co1', name: 'Acme Corp', createdBy: 'system', createdAt: T0, updatedAt: T0,
  });
  await db.insert(contactCompanyRelations).values({
    id: 'ccr1', contactId, companyId: 'co1', isPrimary: true, createdAt: T0,
  });
}

async function seedOpenDeal(db: Database, contactId: string) {
  await db.insert(pipelines).values({ id: 'p1', name: 'Default', createdBy: 'system', createdAt: T0, updatedAt: T0 });
  await db.insert(pipelineStages).values({ id: 's1', pipelineId: 'p1', name: 'Prospecting', position: 1, createdAt: T0, updatedAt: T0 });
  await db.insert(deals).values({ id: 'd1', name: 'Existing', pipelineId: 'p1', stageId: 's1', createdBy: 'u1', createdAt: T0, updatedAt: T0 });
  await db.insert(dealContacts).values({ id: 'dc1', dealId: 'd1', contactId, createdAt: T0 });
}

describe('contactHasOpenDeal', () => {
  it('is false with no deals and true with an open deal', async () => {
    const db = createTestDb();
    await seedContact(db);
    expect(await contactHasOpenDeal(db, 'ct1')).toBe(false);
    await seedOpenDeal(db, 'ct1');
    expect(await contactHasOpenDeal(db, 'ct1')).toBe(true);
  });

  it('ignores closed-won deals', async () => {
    const db = createTestDb();
    await seedContact(db);
    await db.insert(pipelines).values({ id: 'p1', name: 'Default', createdBy: 'system', createdAt: T0, updatedAt: T0 });
    await db.insert(pipelineStages).values({ id: 'sw', pipelineId: 'p1', name: 'Closed Won', position: 5, createdAt: T0, updatedAt: T0 });
    await db.insert(deals).values({ id: 'd1', name: 'Won', pipelineId: 'p1', stageId: 'sw', createdBy: 'u1', createdAt: T0, updatedAt: T0 });
    await db.insert(dealContacts).values({ id: 'dc1', dealId: 'd1', contactId: 'ct1', createdAt: T0 });
    expect(await contactHasOpenDeal(db, 'ct1')).toBe(false);
  });
});

describe('recordHeuristicSuggestion', () => {
  let db: Database;
  beforeEach(async () => {
    db = createTestDb();
    await seedContact(db);
  });

  it('creates a suggestion named "{Company} — {subject}" with the primary company', async () => {
    await seedCompanyFor(db, 'ct1');
    const res = await recordHeuristicSuggestion(db, {
      contactId: 'ct1', messageId: 'm1', subject: 'ERP rollout', signals: signals(),
    });
    expect(res.action).toBe('created');
    const [row] = await db.select().from(dealSuggestions);
    expect(row.suggestedName).toBe('Acme Corp — ERP rollout');
    expect(row.companyId).toBe('co1');
    expect(row.suggestedValue).toBe(12000);
    expect(row.source).toBe('heuristic');
    expect(row.aiAssessmentStatus).toBe('pending');
    expect(row.sourceMessageId).toBe('m1');
    expect(JSON.parse(row.signals)).toHaveLength(2);
  });

  it('falls back to "Deal with {contact}" without company/subject', async () => {
    await recordHeuristicSuggestion(db, {
      contactId: 'ct1', messageId: 'm1', subject: null, signals: signals(),
    });
    const [row] = await db.select().from(dealSuggestions);
    expect(row.suggestedName).toBe('Deal with Ann Lee');
  });

  it('skips when the contact has an open deal', async () => {
    await seedOpenDeal(db, 'ct1');
    const res = await recordHeuristicSuggestion(db, {
      contactId: 'ct1', messageId: 'm1', subject: 'x', signals: signals(),
    });
    expect(res.action).toBe('skipped');
    expect(await db.select().from(dealSuggestions)).toHaveLength(0);
  });

  it('merges into an existing pending suggestion (dedup by snippet, larger value wins, re-arms AI)', async () => {
    await recordHeuristicSuggestion(db, { contactId: 'ct1', messageId: 'm1', subject: 'x', signals: signals() });
    await db.update(dealSuggestions).set({ aiAssessmentStatus: 'assessed' });
    const res = await recordHeuristicSuggestion(db, {
      contactId: 'ct1', messageId: 'm2', subject: 'y',
      signals: signals({
        hits: [
          { family: 'budget', snippet: 'budget is $12,000' }, // duplicate snippet
          { family: 'timeline', snippet: 'go-live by Q3' },   // new
        ],
        families: ['budget', 'timeline'],
        suggestedValue: 30000,
      }),
    });
    expect(res.action).toBe('merged');
    const rows = await db.select().from(dealSuggestions);
    expect(rows).toHaveLength(1);
    expect(JSON.parse(rows[0].signals)).toHaveLength(3);
    expect(rows[0].suggestedValue).toBe(30000);
    expect(rows[0].aiAssessmentStatus).toBe('pending');
  });

  it('never re-creates for a dismissed sourceMessageId, but a newer message may suggest again', async () => {
    await recordHeuristicSuggestion(db, { contactId: 'ct1', messageId: 'm1', subject: 'x', signals: signals() });
    await db.update(dealSuggestions).set({ status: 'dismissed' });
    const again = await recordHeuristicSuggestion(db, { contactId: 'ct1', messageId: 'm1', subject: 'x', signals: signals() });
    expect(again.action).toBe('skipped');
    const newer = await recordHeuristicSuggestion(db, { contactId: 'ct1', messageId: 'm2', subject: 'x', signals: signals() });
    expect(newer.action).toBe('created');
    expect(await db.select().from(dealSuggestions)).toHaveLength(2);
  });
});
```

Note: check `pipelines`/`pipelineStages` required columns in `worker/db/schema.ts` when writing the seeds — if `position`/`createdBy` differ from the above, adjust the seeds (not the assertions).

- [ ] **Step 2: Run to verify failure**

Run: `cd eldrin-crm && npx vitest run worker/__tests__/deal-suggestions-service.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement** (`worker/services/deal-suggestions.ts`)

```ts
/**
 * Deal-suggestion store (Slice 3b). Shared by the capture-time heuristic
 * hook and the AI assess endpoint. Suggestion `status` is only ever changed
 * by the user-facing accept/dismiss routes — never here (spec D2).
 */
import { and, desc, eq, ne } from 'drizzle-orm';
import type { Database } from '../db';
import {
  companies, contactCompanyRelations, contacts,
  dealContacts, deals, dealSuggestions, pipelineStages,
} from '../db';
import { generateId, now } from '../utils';
import type { BuyingSignals, SignalHit } from './buying-signals';

/** AI may create a suggestion only at or above this confidence (spec D2). */
export const AI_SUGGESTION_MIN_CONFIDENCE = 0.6;

const FALLBACK_PREFIX = 'Deal with ';

export function fallbackSuggestionName(firstName: string, lastName: string | null): string {
  return `${FALLBACK_PREFIX}${firstName} ${lastName ?? ''}`.trim();
}

/** True when the heuristic used the contact-name fallback (refinable by AI). */
export function isFallbackName(name: string): boolean {
  return name.startsWith(FALLBACK_PREFIX);
}

/** Mirrors the open-deal predicate in worker/services/reports.ts. */
export async function contactHasOpenDeal(db: Database, contactId: string): Promise<boolean> {
  const rows = await db
    .select({ id: deals.id })
    .from(dealContacts)
    .innerJoin(deals, eq(dealContacts.dealId, deals.id))
    .leftJoin(pipelineStages, eq(deals.stageId, pipelineStages.id))
    .where(
      and(
        eq(dealContacts.contactId, contactId),
        eq(deals.isDeleted, false),
        ne(pipelineStages.name, 'Closed Won'),
        ne(pipelineStages.name, 'Closed Lost'),
      ),
    )
    .limit(1);
  return rows.length > 0;
}

interface SuggestionContext {
  contact: { firstName: string; lastName: string | null };
  companyId: string | null;
  companyName: string | null;
}

async function loadSuggestionContext(
  db: Database,
  contactId: string,
): Promise<SuggestionContext | null> {
  const [contact] = await db
    .select({ firstName: contacts.firstName, lastName: contacts.lastName })
    .from(contacts)
    .where(and(eq(contacts.id, contactId), eq(contacts.isDeleted, false)));
  if (!contact) return null;

  const [rel] = await db
    .select({ companyId: companies.id, companyName: companies.name })
    .from(contactCompanyRelations)
    .innerJoin(companies, eq(contactCompanyRelations.companyId, companies.id))
    .where(
      and(
        eq(contactCompanyRelations.contactId, contactId),
        eq(contactCompanyRelations.isPrimary, true),
      ),
    )
    .limit(1);
  return {
    contact,
    companyId: rel?.companyId ?? null,
    companyName: rel?.companyName ?? null,
  };
}

function buildSuggestedName(ctx: SuggestionContext, subject: string | null): string {
  const trimmedSubject = subject?.trim() ?? '';
  if (ctx.companyName && trimmedSubject) return `${ctx.companyName} — ${trimmedSubject}`;
  return fallbackSuggestionName(ctx.contact.firstName, ctx.contact.lastName);
}

function mergeHits(existingJson: string, incoming: SignalHit[]): SignalHit[] {
  let existing: SignalHit[] = [];
  try {
    existing = JSON.parse(existingJson) as SignalHit[];
  } catch {
    existing = [];
  }
  const seen = new Set(existing.map((h) => h.snippet));
  return [...existing, ...incoming.filter((h) => !seen.has(h.snippet))];
}

/**
 * Record a heuristic detection: create a pending suggestion, merge into the
 * contact's existing pending one, or skip (open deal / dismissed message).
 */
export async function recordHeuristicSuggestion(
  db: Database,
  input: { contactId: string; messageId: string; subject: string | null; signals: BuyingSignals },
): Promise<{ action: 'created' | 'merged' | 'skipped' }> {
  if (await contactHasOpenDeal(db, input.contactId)) return { action: 'skipped' };

  // A dismissed suggestion for this exact message is never re-created.
  const [dismissed] = await db
    .select({ id: dealSuggestions.id })
    .from(dealSuggestions)
    .where(
      and(
        eq(dealSuggestions.sourceMessageId, input.messageId),
        eq(dealSuggestions.status, 'dismissed'),
      ),
    )
    .limit(1);
  if (dismissed) return { action: 'skipped' };

  const [pending] = await db
    .select()
    .from(dealSuggestions)
    .where(
      and(
        eq(dealSuggestions.contactId, input.contactId),
        eq(dealSuggestions.status, 'pending'),
      ),
    )
    .orderBy(desc(dealSuggestions.updatedAt))
    .limit(1);

  if (pending) {
    const merged = mergeHits(pending.signals, input.signals.hits);
    const larger =
      input.signals.suggestedValue !== null &&
      (pending.suggestedValue === null || input.signals.suggestedValue > pending.suggestedValue);
    await db
      .update(dealSuggestions)
      .set({
        signals: JSON.stringify(merged),
        suggestedValue: larger ? input.signals.suggestedValue : pending.suggestedValue,
        aiAssessmentStatus: 'pending',
        updatedAt: now(),
      })
      .where(eq(dealSuggestions.id, pending.id));
    return { action: 'merged' };
  }

  const ctx = await loadSuggestionContext(db, input.contactId);
  if (!ctx) return { action: 'skipped' };

  await db.insert(dealSuggestions).values({
    id: generateId(),
    contactId: input.contactId,
    companyId: ctx.companyId,
    sourceMessageId: input.messageId,
    signals: JSON.stringify(input.signals.hits),
    suggestedName: buildSuggestedName(ctx, input.subject),
    suggestedValue: input.signals.suggestedValue,
    createdAt: now(),
    updatedAt: now(),
  });
  return { action: 'created' };
}
```

Note: verify `generateId` and `now` are the actual export names in `worker/utils.ts` (the enhancement route imports `now` from there); adjust imports if they differ.

- [ ] **Step 4: Run to verify pass**

Run: `cd eldrin-crm && npx vitest run worker/__tests__/deal-suggestions-service.test.ts` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git -C eldrin-crm add worker/services/deal-suggestions.ts worker/__tests__/deal-suggestions-service.test.ts
git -C eldrin-crm commit -m "feat(deals): suggestion store with open-deal/dismissed guards and merge"
```

---

### Task 5: `deal.detection.requested` event + capture-time hook

**Files:**
- Modify: `eldrin-crm/worker/services/event-emitter.ts` (new payload type + emitter)
- Modify: `eldrin-crm/worker/routes/events.ts` (`email.received` case, after the extraction emit at ~line 158)
- Modify: `eldrin-crm/public/eldrin-app.manifest.json` (`events.emits` — after the `email.extraction.requested` entry, ~line 888)
- Test: `eldrin-crm/worker/__tests__/events-route.test.ts` (append)

**Interfaces:**
- Consumes: `detectBuyingSignals`/`HEURISTIC_MIN_FAMILIES` (Task 2), `recordHeuristicSuggestion` (Task 4).
- Produces: `emitDealDetectionRequested(env, payload)` with payload `{ messageId, contactId, from, subject: string | null, bodyText }` — the workflow template (Task 9) consumes `payload.bodyText`, `payload.messageId`, `payload.contactId`.

- [ ] **Step 1: Write the failing tests** (append to `worker/__tests__/events-route.test.ts`; follow that file's existing seeding/mocking style — it already stubs the event client or asserts side effects; mirror how the existing `email.extraction.requested` gating test observes emits. If no emit-capture mechanism exists there, mock `../services/event-emitter` with `vi.mock` and assert calls.)

```ts
import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../services/event-emitter', async (importOriginal) => {
  const mod = await importOriginal<typeof import('../services/event-emitter')>();
  return {
    ...mod,
    emitEmailExtractionRequested: vi.fn().mockResolvedValue(undefined),
    emitDealDetectionRequested: vi.fn().mockResolvedValue(undefined),
  };
});
import { emitDealDetectionRequested, emitEmailExtractionRequested } from '../services/event-emitter';
import { dealSuggestions } from '../db';

// Inside the existing email.received describe block (reuse its app/db/webhook helpers):

it('emits deal.detection.requested unconditionally while extraction stays gated', async () => {
  // Seed a HUMAN-created contact (isAutoCreated: false, captureConfidence: null)
  // matching the sender, then POST an email.received envelope with bodyText.
  const res = await postWebhook(app, {
    type: 'email.received',
    payload: {
      messageId: 'm-uncond', from: 'known.human@example.com',
      subject: 'Quick note', bodyText: 'Just saying hi', receivedAt: T0,
    },
  });
  expect(res.status).toBe(200);
  expect(emitDealDetectionRequested).toHaveBeenCalledTimes(1);
  expect(emitEmailExtractionRequested).not.toHaveBeenCalled(); // human contact: pull-only
});

it('does not emit deal detection without bodyText', async () => {
  await postWebhook(app, {
    type: 'email.received',
    payload: { messageId: 'm-nobody', from: 'known.human@example.com', subject: 'x', receivedAt: T0 },
  });
  expect(emitDealDetectionRequested).not.toHaveBeenCalled();
});

it('creates a heuristic suggestion when >= 2 signal families hit', async () => {
  await postWebhook(app, {
    type: 'email.received',
    payload: {
      messageId: 'm-deal', from: 'known.human@example.com', subject: 'ERP project',
      bodyText: 'We have a $25,000 budget and need a proposal by next quarter.',
      receivedAt: T0,
    },
  });
  const rows = await db.select().from(dealSuggestions);
  expect(rows).toHaveLength(1);
  expect(rows[0].suggestedValue).toBe(25000);
});

it('records nothing below the family threshold', async () => {
  await postWebhook(app, {
    type: 'email.received',
    payload: {
      messageId: 'm-weak', from: 'known.human@example.com', subject: 'x',
      bodyText: 'Can you send a proposal?', receivedAt: T0,
    },
  });
  expect(await db.select().from(dealSuggestions)).toHaveLength(0);
  expect(emitDealDetectionRequested).toHaveBeenCalledTimes(1); // AI leg still fires
});
```

Adapt helper names (`postWebhook`, `app`, `db`, `T0`, contact seeding) to what `events-route.test.ts` already defines — read it first; do NOT invent a parallel harness. The `email.received` payload shape must satisfy `asInboundPayload` (check its required fields in `worker/routes/events.ts:70-99` — include any required `to`/`receivedAt` fields it validates).

- [ ] **Step 2: Run to verify failure**

Run: `cd eldrin-crm && npx vitest run worker/__tests__/events-route.test.ts`
Expected: FAIL — `emitDealDetectionRequested` not exported.

- [ ] **Step 3: Add the emitter** (in `worker/services/event-emitter.ts`, after `EmailExtractionRequestedPayload` and its emitter)

```ts
export interface DealDetectionRequestedPayload extends Record<string, unknown> {
  messageId: string;
  contactId: string;
  from: string;
  subject: string | null;
  bodyText: string;
}

/** Slice 3b: AI co-detector trigger — one per captured inbound email with a body (spec D7). */
export const emitDealDetectionRequested = (env: Env, payload: DealDetectionRequestedPayload) =>
  emit(env, 'deal.detection.requested', payload);
```

- [ ] **Step 4: Add the manifest `events.emits` entry** (in `public/eldrin-app.manifest.json`, after the `email.extraction.requested` entry; match the neighbors' exact JSON shape)

```json
{
  "type": "deal.detection.requested",
  "description": "Emitted for every captured inbound email with body text so the AI co-detector can assess buying signals (Slice 3b).",
  "payload": ["messageId", "contactId", "from", "subject", "bodyText"]
}
```

Check the sibling entries first: if their `payload` field is an object of `name: description` pairs rather than an array, mirror that shape exactly.

- [ ] **Step 5: Wire the capture hook** (in `worker/routes/events.ts`, `email.received` case, immediately after the existing `emitEmailExtractionRequested` block ending ~line 158, before the `return`)

```ts
// Slice 3b: deal auto-detection co-detectors. The AI leg fires for EVERY
// captured email with a body (spec D7 — deliberately NOT reusing the gated
// extraction event above); the heuristic leg runs inline. Failures are
// swallowed: suggestion detection must never break email capture.
if (payload.bodyText && capture.contactId) {
  c.executionCtx.waitUntil(
    emitDealDetectionRequested(c.env, {
      messageId: payload.messageId,
      contactId: capture.contactId,
      from: payload.from,
      subject: payload.subject,
      bodyText: payload.bodyText,
    }),
  );
  try {
    const signals = detectBuyingSignals(payload.bodyText);
    if (signals.families.length >= HEURISTIC_MIN_FAMILIES) {
      await recordHeuristicSuggestion(db, {
        contactId: capture.contactId,
        messageId: payload.messageId,
        subject: payload.subject,
        signals,
      });
    }
  } catch (err) {
    console.error('[crm] deal-suggestion hook failed:', err);
  }
}
```

Add imports at the top of `events.ts`:

```ts
import { detectBuyingSignals, HEURISTIC_MIN_FAMILIES } from '../services/buying-signals';
import { recordHeuristicSuggestion } from '../services/deal-suggestions';
```

and extend the existing emitter import with `emitDealDetectionRequested`.

- [ ] **Step 6: Run to verify pass**

Run: `cd eldrin-crm && npx vitest run worker/__tests__/events-route.test.ts` — Expected: PASS (new + all pre-existing gating tests).

- [ ] **Step 7: Commit**

```bash
git -C eldrin-crm add worker/services/event-emitter.ts worker/routes/events.ts public/eldrin-app.manifest.json worker/__tests__/events-route.test.ts
git -C eldrin-crm commit -m "feat(deals): capture-time co-detectors — unconditional deal.detection.requested + inline heuristic"
```

---

### Task 6: AI assess endpoint (`POST /api/enhancement/deal-suggestions/assess`)

**Files:**
- Modify: `eldrin-crm/worker/routes/enhancement.ts` (new handler; reuse `isValidServiceSecret`, `cleanString`)
- Test: `eldrin-crm/worker/__tests__/enhancement-routes.test.ts` (append)

**Interfaces:**
- Consumes: `dealSuggestions` (Task 3); `contactHasOpenDeal`, `isFallbackName`, `fallbackSuggestionName`, `AI_SUGGESTION_MIN_CONFIDENCE` (Task 4).
- Produces: endpoint consumed by the workflow template (Task 9). Request body:
  ```json
  { "messageId": "...", "contactId": "...", "assessment": { "isLikelyDeal": true, "confidence": 0.82, "dealName": "...", "estimatedValue": 30000, "reasoning": "..." }, "source": "workflow:detect-deal-signals" }
  ```
  Responses: `200 { action: 'refined' | 'created' | 'skipped', suggestion? }`, `400` invalid body, `401` bad secret, `404` unknown contact. Already public via the manifest's `"/enhancement/*"` glob — **no manifest change**.

- [ ] **Step 1: Write the failing tests** (append to `enhancement-routes.test.ts`; reuse its `createApp`/`post`/`SECRET` helpers)

```ts
import { dealSuggestions, pipelines, pipelineStages, deals, dealContacts } from '../db';
import { AI_SUGGESTION_MIN_CONFIDENCE } from '../services/deal-suggestions';

async function seedContactRow(db: Database, id = 'ct1') {
  await db.insert(contacts).values({
    id, firstName: 'Ann', lastName: 'Lee', createdBy: 'system', createdAt: T0, updatedAt: T0,
  });
}

async function seedPendingSuggestion(db: Database, overrides: Partial<typeof dealSuggestions.$inferInsert> = {}) {
  await db.insert(dealSuggestions).values({
    id: 'ds1', contactId: 'ct1', signals: '[{"family":"budget","snippet":"x"}]',
    suggestedName: 'Deal with Ann Lee', createdAt: T0, updatedAt: T0, ...overrides,
  });
}

const assessment = (over: Record<string, unknown> = {}) => ({
  messageId: 'm1', contactId: 'ct1', source: 'workflow:detect-deal-signals',
  assessment: { isLikelyDeal: true, confidence: 0.82, dealName: 'Acme ERP rollout', estimatedValue: 30000, reasoning: 'Budget and timeline present', ...over },
});

describe('POST /api/enhancement/deal-suggestions/assess', () => {
  let db: Database;
  let app: ReturnType<typeof createApp>;
  beforeEach(async () => {
    db = createTestDb();
    app = createApp(db);
    await seedContactRow(db);
  });

  it('rejects a wrong service secret', async () => {
    const res = await post(app, '/api/enhancement/deal-suggestions/assess', assessment(), 'wrong');
    expect(res.status).toBe(401);
  });

  it('404s for an unknown contact', async () => {
    const res = await post(app, '/api/enhancement/deal-suggestions/assess', { ...assessment(), contactId: 'nope' });
    expect(res.status).toBe(404);
  });

  it('refines an existing pending suggestion (fill-empty value, fallback name replaced, source upgraded)', async () => {
    await seedPendingSuggestion(db);
    const res = await post(app, '/api/enhancement/deal-suggestions/assess', assessment());
    expect(res.status).toBe(200);
    expect(((await res.json()) as { action: string }).action).toBe('refined');
    const [row] = await db.select().from(dealSuggestions);
    expect(row.suggestedName).toBe('Acme ERP rollout'); // fallback name → replaced
    expect(row.suggestedValue).toBe(30000);             // was null → filled
    expect(row.source).toBe('heuristic+ai');
    expect(row.aiAssessmentStatus).toBe('assessed');
    expect(row.aiConfidence).toBeCloseTo(0.82);
    expect(row.status).toBe('pending');                 // status untouched (D2)
  });

  it('keeps a non-fallback name and an existing value when refining', async () => {
    await seedPendingSuggestion(db, { suggestedName: 'Acme Corp — ERP rollout', suggestedValue: 12000 });
    await post(app, '/api/enhancement/deal-suggestions/assess', assessment());
    const [row] = await db.select().from(dealSuggestions);
    expect(row.suggestedName).toBe('Acme Corp — ERP rollout');
    expect(row.suggestedValue).toBe(12000);
  });

  it('records a low-confidence assessment on an existing suggestion without dismissing it', async () => {
    await seedPendingSuggestion(db);
    await post(app, '/api/enhancement/deal-suggestions/assess', assessment({ isLikelyDeal: false, confidence: 0.2 }));
    const [row] = await db.select().from(dealSuggestions);
    expect(row.status).toBe('pending');
    expect(row.aiAssessmentStatus).toBe('assessed');
    expect(row.aiConfidence).toBeCloseTo(0.2);
  });

  it('creates an AI-only suggestion at/above the confidence floor', async () => {
    const res = await post(app, '/api/enhancement/deal-suggestions/assess', assessment({ confidence: AI_SUGGESTION_MIN_CONFIDENCE }));
    expect(((await res.json()) as { action: string }).action).toBe('created');
    const [row] = await db.select().from(dealSuggestions);
    expect(row.source).toBe('ai');
    expect(row.signals).toBe('[]');
    expect(row.aiAssessmentStatus).toBe('assessed');
  });

  it('creates nothing below the floor or when isLikelyDeal is false', async () => {
    await post(app, '/api/enhancement/deal-suggestions/assess', assessment({ confidence: 0.59 }));
    await post(app, '/api/enhancement/deal-suggestions/assess', assessment({ isLikelyDeal: false }));
    expect(await db.select().from(dealSuggestions)).toHaveLength(0);
  });

  it('acks without recording when the contact has an open deal', async () => {
    await db.insert(pipelines).values({ id: 'p1', name: 'D', createdBy: 'system', createdAt: T0, updatedAt: T0 });
    await db.insert(pipelineStages).values({ id: 's1', pipelineId: 'p1', name: 'Prospecting', position: 1, createdAt: T0, updatedAt: T0 });
    await db.insert(deals).values({ id: 'd1', name: 'X', pipelineId: 'p1', stageId: 's1', createdBy: 'u1', createdAt: T0, updatedAt: T0 });
    await db.insert(dealContacts).values({ id: 'dc1', dealId: 'd1', contactId: 'ct1', createdAt: T0 });
    const res = await post(app, '/api/enhancement/deal-suggestions/assess', assessment());
    expect(((await res.json()) as { action: string }).action).toBe('skipped');
  });

  it('acks without recording for a dismissed source message', async () => {
    await seedPendingSuggestion(db, { sourceMessageId: 'm1', status: 'dismissed' });
    const res = await post(app, '/api/enhancement/deal-suggestions/assess', assessment());
    expect(((await res.json()) as { action: string }).action).toBe('skipped');
    expect(await db.select().from(dealSuggestions)).toHaveLength(1);
  });

  it('clamps/caps attacker-influenced fields', async () => {
    const res = await post(app, '/api/enhancement/deal-suggestions/assess', assessment({
      confidence: 7, dealName: 'x'.repeat(500), estimatedValue: 99_999_999_999, reasoning: 'r'.repeat(2000),
    }));
    expect(res.status).toBe(200);
    const [row] = await db.select().from(dealSuggestions);
    expect(row.aiConfidence).toBe(1);                       // clamped to [0,1]
    expect(row.suggestedName.length).toBeLessThanOrEqual(200);
    expect(row.suggestedValue).toBeNull();                  // out-of-range value dropped
    expect((row.aiReasoning ?? '').length).toBeLessThanOrEqual(500);
  });

  it('400s when messageId or contactId is missing', async () => {
    const res = await post(app, '/api/enhancement/deal-suggestions/assess', { assessment: {} });
    expect(res.status).toBe(400);
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd eldrin-crm && npx vitest run worker/__tests__/enhancement-routes.test.ts`
Expected: new describe FAILs with 404s (route not defined); pre-existing tests still pass.

- [ ] **Step 3: Implement the handler** (append to `worker/routes/enhancement.ts`, before `latestEmailMaterial`; extend the top imports with `dealSuggestions` from `../db`, `generateId` from `../utils`, and `contactHasOpenDeal`, `fallbackSuggestionName`, `isFallbackName`, `AI_SUGGESTION_MIN_CONFIDENCE` from `../services/deal-suggestions`)

```ts
const MAX_DEAL_NAME = 200;
const MAX_REASONING = 500;
const MAX_DEAL_VALUE = 1_000_000_000;

function clamp01(value: unknown): number {
  const n = typeof value === 'number' && Number.isFinite(value) ? value : 0;
  return Math.min(1, Math.max(0, n));
}

function cleanDealValue(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null;
  if (value <= 0 || value >= MAX_DEAL_VALUE) return null;
  return value;
}

// ── POST /api/enhancement/deal-suggestions/assess ────────────────────────────
// AI co-detector upsert (Slice 3b). May refine the contact's pending
// suggestion or create an AI-only one; NEVER changes status, never deletes,
// never auto-creates a deal (spec D2/D3).
enhancementRoutes.post('/api/enhancement/deal-suggestions/assess', async (c) => {
  if (!isValidServiceSecret(c.env.JWT_SECRET, c.req.header('X-Eldrin-App-Secret'))) {
    return c.json({ error: 'Invalid service secret' }, 401);
  }
  const db = c.get('db');

  let body: {
    messageId?: string;
    contactId?: string;
    assessment?: Record<string, unknown>;
    source?: string;
  };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }
  if (typeof body.messageId !== 'string' || !body.messageId.trim()) {
    return c.json({ error: 'messageId is required' }, 400);
  }
  if (typeof body.contactId !== 'string' || !body.contactId.trim()) {
    return c.json({ error: 'contactId is required' }, 400);
  }

  const [contact] = await db
    .select({ id: contacts.id, firstName: contacts.firstName, lastName: contacts.lastName })
    .from(contacts)
    .where(and(eq(contacts.id, body.contactId), eq(contacts.isDeleted, false)));
  if (!contact) return c.json({ error: 'Contact not found' }, 404);

  // Cap every attacker-influenced field before it can touch the store.
  const raw = body.assessment ?? {};
  const assessment = {
    isLikelyDeal: raw.isLikelyDeal === true,
    confidence: clamp01(raw.confidence),
    dealName: cleanString(raw.dealName, MAX_DEAL_NAME),
    estimatedValue: cleanDealValue(raw.estimatedValue),
    reasoning: cleanString(raw.reasoning, MAX_REASONING),
  };

  if (await contactHasOpenDeal(db, body.contactId)) {
    return c.json({ action: 'skipped', reason: 'open-deal' });
  }
  const [dismissed] = await db
    .select({ id: dealSuggestions.id })
    .from(dealSuggestions)
    .where(
      and(
        eq(dealSuggestions.sourceMessageId, body.messageId),
        eq(dealSuggestions.status, 'dismissed'),
      ),
    )
    .limit(1);
  if (dismissed) return c.json({ action: 'skipped', reason: 'dismissed-message' });

  const [pending] = await db
    .select()
    .from(dealSuggestions)
    .where(
      and(
        eq(dealSuggestions.contactId, body.contactId),
        eq(dealSuggestions.status, 'pending'),
      ),
    )
    .limit(1);

  if (pending) {
    // Refine — applies even when isLikelyDeal=false (low confidence is
    // recorded, the human still decides; spec D2).
    await db
      .update(dealSuggestions)
      .set({
        suggestedName:
          assessment.dealName && isFallbackName(pending.suggestedName)
            ? assessment.dealName
            : pending.suggestedName,
        suggestedValue: pending.suggestedValue ?? assessment.estimatedValue,
        source: pending.source === 'ai' ? 'ai' : 'heuristic+ai',
        aiAssessmentStatus: 'assessed',
        aiConfidence: assessment.confidence,
        aiReasoning: assessment.reasoning,
        updatedAt: now(),
      })
      .where(eq(dealSuggestions.id, pending.id));
    const [suggestion] = await db
      .select()
      .from(dealSuggestions)
      .where(eq(dealSuggestions.id, pending.id));
    return c.json({ action: 'refined', suggestion });
  }

  if (!assessment.isLikelyDeal || assessment.confidence < AI_SUGGESTION_MIN_CONFIDENCE) {
    return c.json({ action: 'skipped', reason: 'below-threshold' });
  }

  const id = generateId();
  await db.insert(dealSuggestions).values({
    id,
    contactId: body.contactId,
    sourceMessageId: body.messageId,
    signals: '[]',
    suggestedName:
      assessment.dealName ?? fallbackSuggestionName(contact.firstName, contact.lastName),
    suggestedValue: assessment.estimatedValue,
    source: 'ai',
    aiAssessmentStatus: 'assessed',
    aiConfidence: assessment.confidence,
    aiReasoning: assessment.reasoning,
    createdAt: now(),
    updatedAt: now(),
  });
  const [suggestion] = await db.select().from(dealSuggestions).where(eq(dealSuggestions.id, id));
  return c.json({ action: 'created', suggestion });
});
```

- [ ] **Step 4: Run to verify pass**

Run: `cd eldrin-crm && npx vitest run worker/__tests__/enhancement-routes.test.ts` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git -C eldrin-crm add worker/routes/enhancement.ts worker/__tests__/enhancement-routes.test.ts
git -C eldrin-crm commit -m "feat(deals): service-gated AI assess endpoint for deal suggestions"
```

---

### Task 7: Deal-suggestions API (list / accept / dismiss)

**Files:**
- Create: `eldrin-crm/worker/routes/deal-suggestions.ts`
- Modify: `eldrin-crm/worker/index.ts` (import + `app.route('', dealSuggestionRoutes)` beside the other route mounts)
- Modify: `eldrin-crm/public/eldrin-app.manifest.json` (three `api.routes` entries)
- Test: `eldrin-crm/worker/__tests__/deal-suggestions-routes.test.ts`

**Interfaces:**
- Produces (consumed by frontend Task 10-13):
  - `GET /api/deal-suggestions?status=pending&contactId=<id>` → `{ suggestions: DealSuggestionView[] }` where `DealSuggestionView` = suggestion row + `contactName`, `companyName`, and `signals` parsed to `SignalHit[]`.
  - `POST /api/deal-suggestions/:id/accept` → `{ suggestion }` (status → `'accepted'`); 404 unknown, 409 non-pending.
  - `POST /api/deal-suggestions/:id/dismiss` → `{ suggestion }` (status → `'dismissed'`); 404 unknown, 409 non-pending.

- [ ] **Step 1: Write the failing tests** (`worker/__tests__/deal-suggestions-routes.test.ts` — same harness style as `enhancement-routes.test.ts`: `createApp` mounting `dealSuggestionRoutes`, seed contact + company + relation + suggestion, then)

```ts
it('lists pending suggestions with display names and parsed signals', async () => {
  const res = await app.request('/api/deal-suggestions?status=pending', {}, mockEnvBindings);
  expect(res.status).toBe(200);
  const { suggestions } = (await res.json()) as { suggestions: Array<Record<string, unknown>> };
  expect(suggestions).toHaveLength(1);
  expect(suggestions[0].contactName).toBe('Ann Lee');
  expect(suggestions[0].companyName).toBe('Acme Corp');
  expect(Array.isArray(suggestions[0].signals)).toBe(true);
});

it('filters by contactId', async () => {
  await db.insert(contacts).values({
    id: 'ct2', firstName: 'Bo', lastName: 'Ng', createdBy: 'system', createdAt: T0, updatedAt: T0,
  });
  await db.insert(dealSuggestions).values({
    id: 'ds2', contactId: 'ct2', signals: '[]', suggestedName: 'Deal with Bo Ng',
    createdAt: T0, updatedAt: T0,
  });
  const res = await app.request('/api/deal-suggestions?status=pending&contactId=ct2', {}, mockEnvBindings);
  const { suggestions } = (await res.json()) as { suggestions: Array<{ id: string }> };
  expect(suggestions.map((s) => s.id)).toEqual(['ds2']);
});

it('accepts a pending suggestion and returns it', async () => {
  const res = await app.request('/api/deal-suggestions/ds1/accept', { method: 'POST' }, mockEnvBindings);
  expect(res.status).toBe(200);
  const [row] = await db.select().from(dealSuggestions);
  expect(row.status).toBe('accepted');
});

it('409s on accept/dismiss of a non-pending suggestion and 404s on unknown ids', async () => {
  await db.update(dealSuggestions).set({ status: 'dismissed' });
  expect((await app.request('/api/deal-suggestions/ds1/accept', { method: 'POST' }, mockEnvBindings)).status).toBe(409);
  expect((await app.request('/api/deal-suggestions/nope/dismiss', { method: 'POST' }, mockEnvBindings)).status).toBe(404);
});

it('dismisses a pending suggestion', async () => {
  const res = await app.request('/api/deal-suggestions/ds1/dismiss', { method: 'POST' }, mockEnvBindings);
  expect(res.status).toBe(200);
  const [row] = await db.select().from(dealSuggestions);
  expect(row.status).toBe('dismissed');
});
```

(Write the seeds and the `contactId` filter test in full — copy the seed helpers from Task 4's test file.)

- [ ] **Step 2: Run to verify failure** — module not found.

- [ ] **Step 3: Implement** (`worker/routes/deal-suggestions.ts`)

```ts
/**
 * User-facing deal-suggestion routes (Slice 3b). Permission-gated via the
 * manifest (deals:read / deals:update) — accept/dismiss are the ONLY code
 * paths that change a suggestion's status (spec D2/D3). Accept returns the
 * payload; the client opens DealForm pre-populated and creates the deal
 * through the normal deals API.
 */
import { Hono } from 'hono';
import { and, desc, eq } from 'drizzle-orm';
import type { Database } from '../db';
import { companies, contactCompanyRelations, contacts, dealSuggestions } from '../db';
import { now } from '../utils';

export const dealSuggestionRoutes = new Hono<{ Bindings: Env; Variables: { db: Database } }>();

const STATUSES = new Set(['pending', 'accepted', 'dismissed']);

dealSuggestionRoutes.get('/api/deal-suggestions', async (c) => {
  const db = c.get('db');
  const status = c.req.query('status') ?? 'pending';
  if (!STATUSES.has(status)) return c.json({ error: 'Invalid status' }, 400);
  const contactId = c.req.query('contactId');

  const conditions = [eq(dealSuggestions.status, status)];
  if (contactId) conditions.push(eq(dealSuggestions.contactId, contactId));

  const rows = await db
    .select({
      suggestion: dealSuggestions,
      firstName: contacts.firstName,
      lastName: contacts.lastName,
      companyName: companies.name,
    })
    .from(dealSuggestions)
    .innerJoin(contacts, eq(dealSuggestions.contactId, contacts.id))
    .leftJoin(companies, eq(dealSuggestions.companyId, companies.id))
    .where(and(...conditions))
    .orderBy(desc(dealSuggestions.updatedAt))
    .limit(50);

  const suggestions = rows.map(({ suggestion, firstName, lastName, companyName }) => {
    let signals: unknown[] = [];
    try {
      signals = JSON.parse(suggestion.signals) as unknown[];
    } catch {
      signals = [];
    }
    return {
      ...suggestion,
      signals,
      contactName: `${firstName} ${lastName ?? ''}`.trim(),
      companyName,
    };
  });
  return c.json({ suggestions });
});

async function transition(
  c: Parameters<Parameters<typeof dealSuggestionRoutes.post>[1]>[0],
  toStatus: 'accepted' | 'dismissed',
) {
  const db = c.get('db');
  const id = c.req.param('id');
  const [existing] = await db.select().from(dealSuggestions).where(eq(dealSuggestions.id, id));
  if (!existing) return c.json({ error: 'Suggestion not found' }, 404);
  if (existing.status !== 'pending') {
    return c.json({ error: `Suggestion is already ${existing.status}` }, 409);
  }
  await db
    .update(dealSuggestions)
    .set({ status: toStatus, updatedAt: now() })
    .where(eq(dealSuggestions.id, id));
  const [suggestion] = await db.select().from(dealSuggestions).where(eq(dealSuggestions.id, id));
  return c.json({ suggestion });
}

dealSuggestionRoutes.post('/api/deal-suggestions/:id/accept', (c) => transition(c, 'accepted'));
dealSuggestionRoutes.post('/api/deal-suggestions/:id/dismiss', (c) => transition(c, 'dismissed'));
```

(If the `transition` context typing fights Hono's generics, type it as a plain two-arg helper `async function transition(c: Context<{ Bindings: Env; Variables: { db: Database } }>, toStatus: ...)` importing `Context` from `hono` — match how other route files type helpers.)

- [ ] **Step 4: Register the routes** — in `worker/index.ts`, add `import { dealSuggestionRoutes } from './routes/deal-suggestions';` next to the other route imports and `app.route('', dealSuggestionRoutes);` next to the other mounts.

- [ ] **Step 5: Manifest entries** — in `public/eldrin-app.manifest.json` `api.routes`, next to the existing deals entries:

```json
{ "method": "GET",  "path": "/api/deal-suggestions",             "permission": "deals:read" },
{ "method": "POST", "path": "/api/deal-suggestions/:id/accept",  "permission": "deals:update" },
{ "method": "POST", "path": "/api/deal-suggestions/:id/dismiss", "permission": "deals:update" }
```

- [ ] **Step 6: Run to verify pass**

Run: `cd eldrin-crm && npx vitest run worker/__tests__/deal-suggestions-routes.test.ts && npm run typecheck` — Expected: PASS, clean.

- [ ] **Step 7: Commit**

```bash
git -C eldrin-crm add worker/routes/deal-suggestions.ts worker/index.ts public/eldrin-app.manifest.json worker/__tests__/deal-suggestions-routes.test.ts
git -C eldrin-crm commit -m "feat(deals): deal-suggestion list/accept/dismiss routes"
```

---

### Task 8: Ghost-activity service + `GET /api/reports/gone-quiet`

**Files:**
- Create: `eldrin-crm/worker/services/ghost-activity.ts`
- Modify: `eldrin-crm/worker/routes/reports.ts` (new endpoint)
- Modify: `eldrin-crm/public/eldrin-app.manifest.json` (one `api.routes` entry)
- Test: `eldrin-crm/worker/__tests__/ghost-activity.test.ts`

**Interfaces:**
- Produces:
  ```ts
  export interface GoneQuietContact { id: string; firstName: string; lastName: string | null; companyName: string | null; lastTouchAt: number; daysQuiet: number }
  export interface GoneQuietDeal { id: string; name: string; value: number | null; stageName: string | null; lastTouchAt: number; daysQuiet: number }
  export async function getGoneQuiet(db: Database, opts: { days: number; limit: number; nowMs: number }): Promise<{ contacts: GoneQuietContact[]; deals: GoneQuietDeal[]; days: number }>
  ```
  Endpoint: `GET /api/reports/gone-quiet?days=30&limit=25` (`days` clamped [7,365], `limit` clamped [1,100]), permission `reports:read`.

- [ ] **Step 1: Write the failing tests** (`worker/__tests__/ghost-activity.test.ts`)

```ts
import { describe, it, expect } from 'vitest';
import { createTestDb } from './test-db';
import type { Database } from '../db';
import {
  contacts, activities, activityTypes, deals, dealStageHistory,
  pipelines, pipelineStages,
} from '../db';
import { getGoneQuiet } from '../services/ghost-activity';

const DAY = 86_400_000;
const NOW = 1700000000000;

async function seedActivityType(db: Database) {
  await db.insert(activityTypes).values({
    id: 'at1', name: 'Email', createdAt: NOW, updatedAt: NOW,
  });
}
// NOTE: check activityTypes' required columns in schema.ts and adjust.

async function seedContactTouchedAt(db: Database, id: string, touchedAt: number | null, createdAt = NOW - 100 * DAY) {
  await db.insert(contacts).values({ id, firstName: id, lastName: 'X', createdBy: 'u', createdAt, updatedAt: createdAt });
  if (touchedAt !== null) {
    await db.insert(activities).values({
      id: `a-${id}`, typeId: 'at1', title: 't', relatedRecordId: id, relatedRecordType: 'contact',
      completedAt: touchedAt, createdBy: 'u', createdAt: touchedAt, updatedAt: touchedAt,
    });
  }
}

describe('getGoneQuiet', () => {
  it('flags contacts quiet ≥ N days and skips recently-touched ones', async () => {
    const db = createTestDb();
    await seedActivityType(db);
    await seedContactTouchedAt(db, 'quiet', NOW - 45 * DAY);
    await seedContactTouchedAt(db, 'active', NOW - 2 * DAY);
    const res = await getGoneQuiet(db, { days: 30, limit: 25, nowMs: NOW });
    expect(res.contacts.map((c) => c.id)).toEqual(['quiet']);
    expect(res.contacts[0].daysQuiet).toBe(45);
  });

  it('treats a never-touched contact as ghost from its createdAt', async () => {
    const db = createTestDb();
    await seedActivityType(db);
    await seedContactTouchedAt(db, 'never', null, NOW - 40 * DAY);
    const res = await getGoneQuiet(db, { days: 30, limit: 25, nowMs: NOW });
    expect(res.contacts.map((c) => c.id)).toEqual(['never']);
    expect(res.contacts[0].daysQuiet).toBe(40);
  });

  it('boundary: exactly N days quiet is included', async () => {
    const db = createTestDb();
    await seedActivityType(db);
    await seedContactTouchedAt(db, 'edge', NOW - 30 * DAY);
    const res = await getGoneQuiet(db, { days: 30, limit: 25, nowMs: NOW });
    expect(res.contacts.map((c) => c.id)).toEqual(['edge']);
  });

  it('uses the greatest of activity/stage-change/createdAt for deals and excludes closed ones', async () => {
    const db = createTestDb();
    await seedActivityType(db);
    await db.insert(pipelines).values({ id: 'p1', name: 'D', createdBy: 'u', createdAt: NOW, updatedAt: NOW });
    await db.insert(pipelineStages).values([
      { id: 's1', pipelineId: 'p1', name: 'Prospecting', position: 1, createdAt: NOW, updatedAt: NOW },
      { id: 'sw', pipelineId: 'p1', name: 'Closed Won', position: 5, createdAt: NOW, updatedAt: NOW },
    ]);
    // Quiet open deal: created 90d ago, stage change 50d ago (its last touch).
    await db.insert(deals).values({ id: 'd-quiet', name: 'Quiet', pipelineId: 'p1', stageId: 's1', createdBy: 'u', createdAt: NOW - 90 * DAY, updatedAt: NOW });
    await db.insert(dealStageHistory).values({ id: 'h1', dealId: 'd-quiet', toStageId: 's1', changedBy: 'u', changedAt: NOW - 50 * DAY });
    // Active open deal: activity 3d ago.
    await db.insert(deals).values({ id: 'd-active', name: 'Active', pipelineId: 'p1', stageId: 's1', createdBy: 'u', createdAt: NOW - 90 * DAY, updatedAt: NOW });
    await db.insert(activities).values({ id: 'a-d', typeId: 'at1', title: 't', relatedRecordId: 'd-active', relatedRecordType: 'deal', completedAt: NOW - 3 * DAY, createdBy: 'u', createdAt: NOW - 3 * DAY, updatedAt: NOW - 3 * DAY });
    // Closed deal: quiet but excluded.
    await db.insert(deals).values({ id: 'd-won', name: 'Won', pipelineId: 'p1', stageId: 'sw', createdBy: 'u', createdAt: NOW - 90 * DAY, updatedAt: NOW });
    const res = await getGoneQuiet(db, { days: 30, limit: 25, nowMs: NOW });
    expect(res.deals.map((d) => d.id)).toEqual(['d-quiet']);
    expect(res.deals[0].daysQuiet).toBe(50);
    expect(res.deals[0].stageName).toBe('Prospecting');
  });

  it('orders by daysQuiet descending and honors the limit', async () => {
    const db = createTestDb();
    await seedActivityType(db);
    await seedContactTouchedAt(db, 'q60', NOW - 60 * DAY);
    await seedContactTouchedAt(db, 'q90', NOW - 90 * DAY);
    const res = await getGoneQuiet(db, { days: 30, limit: 1, nowMs: NOW });
    expect(res.contacts.map((c) => c.id)).toEqual(['q90']);
  });
});
```

Route clamp test — append to the existing reports route test file if one exists (`grep -l "reports" worker/__tests__/`), otherwise add a small describe in this file mounting `reportRoutes` with the standard harness and asserting `GET /api/reports/gone-quiet?days=99999` responds 200 with `days: 365` and `?days=1` → `days: 7`.

- [ ] **Step 2: Run to verify failure** — module not found.

- [ ] **Step 3: Implement the service** (`worker/services/ghost-activity.ts`)

```ts
/**
 * Ghost-activity ("gone quiet") detection — computed on read, no new tables
 * (spec D4). Ghost = no captured activity at all within the window (and for
 * deals, also no stage change); distinct from "rotting" (spec D5).
 */
import { and, eq, sql } from 'drizzle-orm';
import type { Database } from '../db';
import {
  activities, companies, contactCompanyRelations, contacts,
  deals, pipelineStages,
} from '../db';

const DAY_MS = 86_400_000;

export interface GoneQuietContact {
  id: string;
  firstName: string;
  lastName: string | null;
  companyName: string | null;
  lastTouchAt: number;
  daysQuiet: number;
}

export interface GoneQuietDeal {
  id: string;
  name: string;
  value: number | null;
  stageName: string | null;
  lastTouchAt: number;
  daysQuiet: number;
}

export async function getGoneQuiet(
  db: Database,
  opts: { days: number; limit: number; nowMs: number },
): Promise<{ contacts: GoneQuietContact[]; deals: GoneQuietDeal[]; days: number }> {
  const cutoff = opts.nowMs - opts.days * DAY_MS;

  // Contact last touch: newest activity timestamp, else the contact's createdAt.
  const contactLastTouch = sql<number>`COALESCE(
    (SELECT MAX(COALESCE(a.completed_at, a.created_at)) FROM activities a
      WHERE a.related_record_id = ${contacts.id}
        AND a.related_record_type = 'contact'
        AND a.is_deleted = 0),
    ${contacts.createdAt}
  )`;

  const contactRows = await db
    .select({
      id: contacts.id,
      firstName: contacts.firstName,
      lastName: contacts.lastName,
      companyName: companies.name,
      lastTouchAt: contactLastTouch,
    })
    .from(contacts)
    .leftJoin(
      contactCompanyRelations,
      and(
        eq(contactCompanyRelations.contactId, contacts.id),
        eq(contactCompanyRelations.isPrimary, true),
      ),
    )
    .leftJoin(companies, eq(contactCompanyRelations.companyId, companies.id))
    .where(and(eq(contacts.isDeleted, false), sql`${contactLastTouch} <= ${cutoff}`))
    .orderBy(sql`${contactLastTouch} ASC`)
    .limit(opts.limit);

  // Deal last touch: greatest of createdAt, newest activity, newest stage change.
  const dealLastTouch = sql<number>`MAX(
    ${deals.createdAt},
    COALESCE((SELECT MAX(COALESCE(a.completed_at, a.created_at)) FROM activities a
      WHERE a.related_record_id = ${deals.id}
        AND a.related_record_type = 'deal'
        AND a.is_deleted = 0), 0),
    COALESCE((SELECT MAX(h.changed_at) FROM deal_stage_history h
      WHERE h.deal_id = ${deals.id}), 0)
  )`;

  const dealRows = await db
    .select({
      id: deals.id,
      name: deals.name,
      value: deals.value,
      stageName: pipelineStages.name,
      lastTouchAt: dealLastTouch,
    })
    .from(deals)
    .leftJoin(pipelineStages, eq(deals.stageId, pipelineStages.id))
    .where(
      and(
        eq(deals.isDeleted, false),
        sql`${pipelineStages.name} NOT IN ('Closed Won', 'Closed Lost')`,
        sql`${dealLastTouch} <= ${cutoff}`,
      ),
    )
    .orderBy(sql`${dealLastTouch} ASC`)
    .limit(opts.limit);

  const withDays = <T extends { lastTouchAt: number }>(row: T) => ({
    ...row,
    daysQuiet: Math.floor((opts.nowMs - row.lastTouchAt) / DAY_MS),
  });

  return {
    contacts: contactRows.map(withDays),
    deals: dealRows.map(withDays),
    days: opts.days,
  };
}
```

- [ ] **Step 4: Add the route** (in `worker/routes/reports.ts`, after the existing endpoints; import `getGoneQuiet` and `now` if not present)

```ts
function clampInt(raw: string | undefined, fallback: number, min: number, max: number): number {
  const n = Number(raw);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(n)));
}

reportRoutes.get('/api/reports/gone-quiet', async (c) => {
  const db = c.get('db');
  const days = clampInt(c.req.query('days'), 30, 7, 365);
  const limit = clampInt(c.req.query('limit'), 25, 1, 100);
  const result = await getGoneQuiet(db, { days, limit, nowMs: now() });
  return c.json(result);
});
```

- [ ] **Step 5: Manifest entry** — add to `api.routes` beside the other reports entries:

```json
{ "method": "GET", "path": "/api/reports/gone-quiet", "permission": "reports:read" }
```

- [ ] **Step 6: Run to verify pass**

Run: `cd eldrin-crm && npx vitest run worker/__tests__/ghost-activity.test.ts && npm run test && npm run typecheck`
Expected: all PASS (full suite green — this is the last backend task in eldrin-crm).

- [ ] **Step 7: Commit**

```bash
git -C eldrin-crm add worker/services/ghost-activity.ts worker/routes/reports.ts public/eldrin-app.manifest.json worker/__tests__/ghost-activity.test.ts
git -C eldrin-crm commit -m "feat(reports): gone-quiet ghost-activity endpoint"
```

---

### Task 9: Workflow template + mock-provider extension (eldrin-workflows)

**Files:**
- Create: `eldrin-workflows/workflows-templates/crm-detect-deal-signals.json`
- Modify: `eldrin-workflows/worker/engine/ai/providers/mock.ts` (additive: deal-assessment keys)
- Modify: `eldrin-workflows/worker/routes/workflows-import.test.ts` (add filename to the shipped-templates array at ~lines 82-84)
- Test: `eldrin-workflows/worker/engine/steps/ai-extract.test.ts` (append a mock-assessment case)

**Interfaces:**
- Consumes: `POST /api/enhancement/deal-suggestions/assess` (Task 6) via `call_app_api` through the core proxy (`X-Eldrin-App-Secret`).
- Produces: template with trigger `deal.detection.requested`; `ai_extract` output shape `{ isLikelyDeal, confidence, dealName, estimatedValue, reasoning }`.

- [ ] **Step 1: Write the failing tests**

In `worker/routes/workflows-import.test.ts`, extend the shipped-templates array:

```ts
const templates = [
  'crm-enrich-company.json',
  'crm-extract-email-insights.json',
  'crm-detect-deal-signals.json',
].map((f) => JSON.parse(readFileSync(path.join(dir, f), 'utf8')));
```

In `worker/engine/steps/ai-extract.test.ts`, append (mirror the existing mock-provider test's setup):

```ts
it('mock provider assesses deal signals when the schema requests assessment keys', async () => {
  const result = await runAiExtract(
    {
      name: 'assess',
      type: 'ai_extract',
      config: {
        prompt: 'Assess buying intent',
        input: 'We have a $30,000 budget and want a proposal by Q3.',
        schema: {
          type: 'object',
          properties: {
            isLikelyDeal: { type: 'boolean' },
            confidence: { type: 'number' },
            dealName: { type: 'string' },
            estimatedValue: { type: 'number' },
            reasoning: { type: 'string' },
          },
        },
      },
    },
    ctx, // reuse the existing test context/env with provider 'mock'
  );
  expect(result.output.isLikelyDeal).toBe(true);
  expect(result.output.confidence).toBeGreaterThanOrEqual(0.6);
  expect(typeof result.output.reasoning).toBe('string');
});
```

(Adapt the runner call to the file's existing helper — read the existing mock test at ~lines 33-44 first and copy its invocation shape exactly.)

- [ ] **Step 2: Run to verify failure**

Run: `cd eldrin-workflows && npm test`
Expected: FAIL — missing template file; mock returns `{}` for assessment keys.

- [ ] **Step 3: Create the template** (`workflows-templates/crm-detect-deal-signals.json`)

```json
{
  "name": "CRM: Detect deal signals",
  "description": "When the CRM captures an inbound email, assess the body for buying intent (budget, timeline, stakeholders, RFP/procurement language) and upsert a deal suggestion in the CRM. Runs on every captured email as the AI co-detector beside the CRM's keyword heuristic.",
  "definition": {
    "version": 1,
    "trigger": { "type": "event", "config": { "eventType": "deal.detection.requested" } },
    "steps": [
      {
        "name": "assess",
        "type": "ai_extract",
        "config": {
          "prompt": "You are assessing a single inbound business email for buying intent. Signals: explicit budget or money amounts, delivery timelines or deadlines, additional stakeholders being looped in (executives, procurement), and procurement language (RFP, RFI, proposal, quote, pilot, contract). Return isLikelyDeal (boolean), confidence (0..1), a short dealName suitable as a CRM deal title, estimatedValue (number, omit if none stated), and a one-line reasoning.",
          "input": "{{payload.bodyText}}",
          "schema": {
            "type": "object",
            "properties": {
              "isLikelyDeal": { "type": "boolean" },
              "confidence": { "type": "number" },
              "dealName": { "type": "string" },
              "estimatedValue": { "type": "number" },
              "reasoning": { "type": "string" }
            },
            "additionalProperties": false
          }
        }
      },
      {
        "name": "apply",
        "type": "call_app_api",
        "config": {
          "appId": "eldrin-crm",
          "method": "POST",
          "path": "/api/enhancement/deal-suggestions/assess",
          "body": {
            "messageId": "{{payload.messageId}}",
            "contactId": "{{payload.contactId}}",
            "assessment": "{{steps.assess.output}}",
            "source": "workflow:detect-deal-signals"
          }
        }
      }
    ]
  }
}
```

- [ ] **Step 4: Extend the mock provider** (`worker/engine/ai/providers/mock.ts` — additive branch; keep every existing key untouched. Deterministic keyword scan, same spirit as the existing extraction logic):

```ts
// Slice 3b: deal-signal assessment keys. Only emitted when the requested
// schema declares them, so existing extraction templates are unaffected.
const DEAL_SIGNAL_RE = /\b(budget|pricing|proposal|quote|rfp|rfi|contract|pilot|deadline|go[- ]live)\b/i;
const AMOUNT_RE = /[$€£]\s?(\d[\d.,]*)\s?([km])?\b/i;

function mockDealAssessment(input: string, properties: Record<string, unknown>) {
  const out: Record<string, unknown> = {};
  const likely = DEAL_SIGNAL_RE.test(input);
  if ('isLikelyDeal' in properties) out.isLikelyDeal = likely;
  if ('confidence' in properties) out.confidence = likely ? 0.75 : 0.2;
  if ('dealName' in properties && likely) {
    out.dealName = `Mock-detected opportunity`;
  }
  if ('estimatedValue' in properties) {
    const m = AMOUNT_RE.exec(input);
    if (m) {
      let v = Number(m[1].replace(/,/g, ''));
      if (m[2]?.toLowerCase() === 'k') v *= 1_000;
      if (m[2]?.toLowerCase() === 'm') v *= 1_000_000;
      if (Number.isFinite(v) && v > 0) out.estimatedValue = v;
    }
  }
  if ('reasoning' in properties) {
    out.reasoning = likely
      ? 'Mock assessment: buying-signal keywords found in the email body.'
      : 'Mock assessment: no buying-signal keywords found.';
  }
  return out;
}
```

Wire it into the provider's existing extract function: after the current key handling, if the schema's `properties` contains `isLikelyDeal`, merge `mockDealAssessment(input, properties)` into the result (read the file first and follow its exact structure — the function likely builds `result` per known key; add the branch in the same style, immutably: `return { ...result, ...mockDealAssessment(input, properties) }`).

- [ ] **Step 5: Run to verify pass**

Run: `cd eldrin-workflows && npm test` — Expected: all PASS (import test now covers 3 templates; new mock case green).

- [ ] **Step 6: Commit**

```bash
git -C eldrin-workflows add workflows-templates/crm-detect-deal-signals.json worker/engine/ai/providers/mock.ts worker/routes/workflows-import.test.ts worker/engine/steps/ai-extract.test.ts
git -C eldrin-workflows commit -m "feat(templates): CRM deal-signal detection template + mock assessment keys"
```

---

### Task 10: Frontend API client + DealForm prefill props

**Files:**
- Modify: `eldrin-crm/src/api.ts` (new types + 4 functions)
- Modify: `eldrin-crm/src/pages/deals/DealForm.tsx` (3 new props, contact link after create)

**Interfaces:**
- Consumes: Task 7 + Task 8 endpoints; existing `api.createDeal` (returns `{ deal }` — verify the exact return type in `api.ts` and adjust) and `api.addDealContact(base, headers, dealId, { contactId })`.
- Produces (for Tasks 11-13):
  ```ts
  export interface DealSuggestionSignal { family: 'budget' | 'timeline' | 'stakeholder' | 'intent'; snippet: string }
  export interface DealSuggestion {
    id: string; contactId: string; companyId: string | null;
    contactName: string; companyName: string | null;
    sourceMessageId: string | null; signals: DealSuggestionSignal[];
    suggestedName: string; suggestedValue: number | null;
    status: 'pending' | 'accepted' | 'dismissed';
    source: 'heuristic' | 'ai' | 'heuristic+ai';
    aiAssessmentStatus: 'pending' | 'assessed';
    aiConfidence: number | null; aiReasoning: string | null;
    createdAt: number; updatedAt: number;
  }
  export interface GoneQuietContact { id: string; firstName: string; lastName: string | null; companyName: string | null; lastTouchAt: number; daysQuiet: number }
  export interface GoneQuietDeal { id: string; name: string; value: number | null; stageName: string | null; lastTouchAt: number; daysQuiet: number }
  export async function listDealSuggestions(base: string, headers: Headers, params?: { status?: string; contactId?: string }): Promise<{ suggestions: DealSuggestion[] }>
  export async function acceptDealSuggestion(base: string, headers: Headers, id: string): Promise<{ suggestion: DealSuggestion }>
  export async function dismissDealSuggestion(base: string, headers: Headers, id: string): Promise<{ suggestion: DealSuggestion }>
  export async function getGoneQuiet(base: string, headers: Headers, days: number): Promise<{ contacts: GoneQuietContact[]; deals: GoneQuietDeal[]; days: number }>
  ```
  DealForm gains `initialName?: string; initialValue?: number | null; initialContactId?: string`.

- [ ] **Step 1: Add the API functions** (append to `src/api.ts`, following the file's `apiUrl`/`request` conventions)

```ts
// ── Deal suggestions (Slice 3b) ──────────────────────────────────────────────

export async function listDealSuggestions(
  base: string,
  headers: Headers,
  params?: { status?: string; contactId?: string },
): Promise<{ suggestions: DealSuggestion[] }> {
  const qs = new URLSearchParams();
  if (params?.status) qs.set('status', params.status);
  if (params?.contactId) qs.set('contactId', params.contactId);
  const suffix = qs.size > 0 ? `?${qs}` : '';
  return request(apiUrl(base, `/deal-suggestions${suffix}`), headers);
}

export async function acceptDealSuggestion(base: string, headers: Headers, id: string) {
  return request<{ suggestion: DealSuggestion }>(apiUrl(base, `/deal-suggestions/${id}/accept`), headers, { method: 'POST' });
}

export async function dismissDealSuggestion(base: string, headers: Headers, id: string) {
  return request<{ suggestion: DealSuggestion }>(apiUrl(base, `/deal-suggestions/${id}/dismiss`), headers, { method: 'POST' });
}

export async function getGoneQuiet(base: string, headers: Headers, days: number) {
  return request<{ contacts: GoneQuietContact[]; deals: GoneQuietDeal[]; days: number }>(
    apiUrl(base, `/reports/gone-quiet?days=${days}`),
    headers,
  );
}
```

(plus the four interfaces above — put them near the other deal types. Match the file's actual generic-passing style for `request<T>`.)

- [ ] **Step 2: Extend DealForm** (`src/pages/deals/DealForm.tsx`)

```ts
interface DealFormProps {
  apiBase: string;
  initialPipelineId?: string;
  initialStageId?: string;
  initialName?: string;
  initialValue?: number | null;
  initialContactId?: string;
  onClose: () => void;
  onCreated: () => void;
}
```

State seeding (lines ~31-32):

```ts
const [name, setName] = useState(initialName || '');
const [value, setValue] = useState(initialValue != null ? String(initialValue) : '');
```

Submit: capture the created deal and link the contact before `onCreated()` (check `createDeal`'s return type in `api.ts` — if it returns the created deal, use its id; the linking failure must not lose the deal):

```ts
const created = await api.createDeal(apiBase, authHeaders, { /* unchanged fields */ });
if (initialContactId && created?.deal?.id) {
  try {
    await api.addDealContact(apiBase, authHeaders, created.deal.id, { contactId: initialContactId });
  } catch {
    toast.error('Deal created, but linking the contact failed');
  }
}
toast.success('Deal created');
onCreated();
```

- [ ] **Step 3: Verify**

Run: `cd eldrin-crm && npm run typecheck` — Expected: clean. (No frontend test harness; behavior verified in Task 14.)

- [ ] **Step 4: Commit**

```bash
git -C eldrin-crm add src/api.ts src/pages/deals/DealForm.tsx
git -C eldrin-crm commit -m "feat(deals): suggestion/gone-quiet API client + DealForm prefill props"
```

---

### Task 11: SuggestedDealsWidget on the dashboard

**Files:**
- Create: `eldrin-crm/src/components/reports/SuggestedDealsWidget.tsx`
- Modify: `eldrin-crm/src/pages/reports/Dashboard.tsx` (slot into the charts grid)

**Interfaces:**
- Consumes: Task 10 API functions + `DealForm` prefill props; `StatusBadge` from `src/components/ui` (props `tone`, `title`, `titlePlacement`).
- Produces: `export function SuggestedDealsWidget({ apiBase }: { apiBase: string })` — self-fetching, mirrors `PipelineFunnel`'s structure.

- [ ] **Step 1: Implement the widget** (`src/components/reports/SuggestedDealsWidget.tsx`)

```tsx
import { useState, useEffect, useCallback, useRef } from 'react';
import { useAuthHeaders } from '@eldrin-project/eldrin-app-react';
import { toast } from 'sonner';
import { StatusBadge } from '../ui';
import { DealForm } from '../../pages/deals/DealForm';
import type { DealSuggestion } from '../../api';
import * as api from '../../api';

interface SuggestedDealsWidgetProps {
  apiBase: string;
}

/** Dashboard widget for pending auto-detected deal suggestions (Slice 3b). */
export function SuggestedDealsWidget({ apiBase }: SuggestedDealsWidgetProps) {
  const authHeaders = useAuthHeaders();
  const headersRef = useRef(authHeaders);
  headersRef.current = authHeaders;

  const [suggestions, setSuggestions] = useState<DealSuggestion[]>([]);
  const [loading, setLoading] = useState(true);
  const [accepted, setAccepted] = useState<DealSuggestion | null>(null);

  const fetchSuggestions = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.listDealSuggestions(apiBase, headersRef.current, { status: 'pending' });
      setSuggestions(res.suggestions);
    } finally {
      setLoading(false);
    }
  }, [apiBase]);

  useEffect(() => {
    fetchSuggestions();
  }, [fetchSuggestions]);

  async function handleAccept(s: DealSuggestion) {
    try {
      const res = await api.acceptDealSuggestion(apiBase, headersRef.current, s.id);
      setAccepted(res.suggestion);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to accept suggestion');
    }
  }

  async function handleDismiss(s: DealSuggestion) {
    try {
      await api.dismissDealSuggestion(apiBase, headersRef.current, s.id);
      setSuggestions((prev) => prev.filter((x) => x.id !== s.id));
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to dismiss suggestion');
    }
  }

  return (
    <div className="card bg-base-100 border border-base-300">
      <div className="card-body p-4">
        <h3 className="crm-eyebrow mb-3">Suggested Deals</h3>
        {loading ? (
          <div className="skeleton h-24 w-full" />
        ) : suggestions.length === 0 ? (
          <p className="text-sm text-base-content/40 text-center py-8">
            No suggested deals. Signals from inbound email will appear here.
          </p>
        ) : (
          <ul className="space-y-3">
            {suggestions.map((s) => (
              <li key={s.id} className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="text-sm font-medium truncate">{s.suggestedName}</div>
                  <div className="text-xs text-base-content/50 truncate">
                    {s.contactName}
                    {s.companyName ? ` · ${s.companyName}` : ''}
                    {s.suggestedValue != null ? ` · $${s.suggestedValue.toLocaleString()}` : ''}
                  </div>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {[...new Set(s.signals.map((h) => h.family))].map((family) => (
                      <StatusBadge
                        key={family}
                        tone="info"
                        titlePlacement="bottom"
                        title={s.signals
                          .filter((h) => h.family === family)
                          .map((h) => h.snippet)
                          .join(' · ')}
                      >
                        {family}
                      </StatusBadge>
                    ))}
                    {s.aiAssessmentStatus === 'assessed' && s.aiConfidence != null && (
                      <StatusBadge
                        tone="violet"
                        titlePlacement="bottom"
                        title={s.aiReasoning ?? undefined}
                      >
                        AI: {Math.round(s.aiConfidence * 100)}%
                      </StatusBadge>
                    )}
                  </div>
                </div>
                <div className="flex gap-1 shrink-0">
                  <button className="btn btn-success btn-xs btn-outline" onClick={() => handleAccept(s)}>
                    Accept
                  </button>
                  <button className="btn btn-ghost btn-xs" onClick={() => handleDismiss(s)}>
                    Dismiss
                  </button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
      {accepted && (
        <DealForm
          apiBase={apiBase}
          initialName={accepted.suggestedName}
          initialValue={accepted.suggestedValue}
          initialContactId={accepted.contactId}
          onClose={() => {
            setAccepted(null);
            fetchSuggestions();
          }}
          onCreated={() => {
            setAccepted(null);
            fetchSuggestions();
          }}
        />
      )}
    </div>
  );
}
```

- [ ] **Step 2: Slot into the dashboard** — in `src/pages/reports/Dashboard.tsx`, inside the charts grid (`grid grid-cols-1 lg:grid-cols-2 gap-6`, after the last widget ~line 149):

```tsx
<SuggestedDealsWidget apiBase={apiBase} />
```

with the import at the top beside `PipelineFunnel`.

- [ ] **Step 3: Verify**

Run: `cd eldrin-crm && npm run typecheck` — Expected: clean.

- [ ] **Step 4: Commit**

```bash
git -C eldrin-crm add src/components/reports/SuggestedDealsWidget.tsx src/pages/reports/Dashboard.tsx
git -C eldrin-crm commit -m "feat(deals): SuggestedDealsWidget with accept-to-prefilled-DealForm flow"
```

---

### Task 12: GoneQuietWidget on the dashboard

**Files:**
- Create: `eldrin-crm/src/components/reports/GoneQuietWidget.tsx`
- Modify: `eldrin-crm/src/pages/reports/Dashboard.tsx` (slot + optional `onNavigate` prop)
- Modify: `eldrin-crm/src/root.component.tsx` (pass `navigate` to both `<Dashboard>` renders, ~lines 159 and 225)

**Interfaces:**
- Consumes: `api.getGoneQuiet` (Task 10). `Dashboard` gains `onNavigate?: (path: string) => void`; the router's existing `navigate` function is passed in both render sites.
- Produces: `export function GoneQuietWidget({ apiBase, onNavigate }: { apiBase: string; onNavigate?: (path: string) => void })`.

- [ ] **Step 1: Implement the widget** (`src/components/reports/GoneQuietWidget.tsx`)

```tsx
import { useState, useEffect, useCallback, useRef } from 'react';
import { useAuthHeaders } from '@eldrin-project/eldrin-app-react';
import type { GoneQuietContact, GoneQuietDeal } from '../../api';
import * as api from '../../api';

const PERIODS = [14, 30, 60, 90] as const;

interface GoneQuietWidgetProps {
  apiBase: string;
  onNavigate?: (path: string) => void;
}

/** "Gone quiet" ghost-activity widget (Slice 3b) — computed on read. */
export function GoneQuietWidget({ apiBase, onNavigate }: GoneQuietWidgetProps) {
  const authHeaders = useAuthHeaders();
  const headersRef = useRef(authHeaders);
  headersRef.current = authHeaders;

  const [days, setDays] = useState<number>(30);
  const [contacts, setContacts] = useState<GoneQuietContact[]>([]);
  const [deals, setDeals] = useState<GoneQuietDeal[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.getGoneQuiet(apiBase, headersRef.current, days);
      setContacts(res.contacts);
      setDeals(res.deals);
    } finally {
      setLoading(false);
    }
  }, [apiBase, days]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const empty = contacts.length === 0 && deals.length === 0;

  function recordLink(path: string, label: string) {
    return onNavigate ? (
      <button className="link link-hover text-left truncate" onClick={() => onNavigate(path)}>
        {label}
      </button>
    ) : (
      <span className="truncate">{label}</span>
    );
  }

  return (
    <div className="card bg-base-100 border border-base-300">
      <div className="card-body p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="crm-eyebrow">Gone Quiet</h3>
          <select
            className="select select-bordered select-xs"
            value={days}
            onChange={(e) => setDays(Number(e.target.value))}
          >
            {PERIODS.map((p) => (
              <option key={p} value={p}>
                {p} days
              </option>
            ))}
          </select>
        </div>
        {loading ? (
          <div className="skeleton h-24 w-full" />
        ) : empty ? (
          <p className="text-sm text-base-content/40 text-center py-8">
            Nothing has gone quiet in the last {days} days.
          </p>
        ) : (
          <div className="space-y-4">
            {contacts.length > 0 && (
              <div>
                <div className="crm-section-title mb-1">Contacts</div>
                <ul className="space-y-1">
                  {contacts.map((c) => (
                    <li key={c.id} className="flex items-center justify-between gap-2 text-sm">
                      {recordLink(
                        `/eldrin-crm/contacts/${c.id}`,
                        `${c.firstName} ${c.lastName ?? ''}`.trim() +
                          (c.companyName ? ` · ${c.companyName}` : ''),
                      )}
                      <span className="crm-num text-xs text-base-content/50 shrink-0">
                        {c.daysQuiet}d quiet
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {deals.length > 0 && (
              <div>
                <div className="crm-section-title mb-1">Deals</div>
                <ul className="space-y-1">
                  {deals.map((d) => (
                    <li key={d.id} className="flex items-center justify-between gap-2 text-sm">
                      {recordLink(
                        `/eldrin-crm/deals/${d.id}`,
                        d.name + (d.stageName ? ` · ${d.stageName}` : ''),
                      )}
                      <span className="crm-num text-xs text-base-content/50 shrink-0">
                        {d.daysQuiet}d quiet
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Wire into Dashboard + router** — `Dashboard` props become `{ apiBase, onNavigate }: { apiBase: string; onNavigate?: (path: string) => void }`; render `<GoneQuietWidget apiBase={apiBase} onNavigate={onNavigate} />` in the charts grid next to `SuggestedDealsWidget`. In `src/root.component.tsx` change both `<Dashboard apiBase={apiBase} />` renders (~lines 159, 225) to `<Dashboard apiBase={apiBase} onNavigate={navigate} />`. Check the record paths against how `navigate` is called elsewhere in the router (e.g. ContactList row clicks) — if it expects paths without the `/eldrin-crm` prefix, strip it.

- [ ] **Step 3: Verify**

Run: `cd eldrin-crm && npm run typecheck` — Expected: clean.

- [ ] **Step 4: Commit**

```bash
git -C eldrin-crm add src/components/reports/GoneQuietWidget.tsx src/pages/reports/Dashboard.tsx src/root.component.tsx
git -C eldrin-crm commit -m "feat(reports): GoneQuietWidget with 14/30/60/90-day selector"
```

---

### Task 13: Contact-detail pending-suggestion banner

**Files:**
- Create: `eldrin-crm/src/components/contacts/DealSuggestionBanner.tsx`
- Modify: `eldrin-crm/src/pages/contacts/ContactDetail.tsx` (render between header ~line 283 and the main grid ~line 285)

**Interfaces:**
- Consumes: `api.listDealSuggestions(base, headers, { status: 'pending', contactId })`, `DealForm` prefill props, `StatusBadge`.
- Produces: `export function DealSuggestionBanner({ apiBase, contactId }: { apiBase: string; contactId: string })` — renders nothing when the contact has no pending suggestion.

- [ ] **Step 1: Implement the banner** (`src/components/contacts/DealSuggestionBanner.tsx`)

```tsx
import { useState, useEffect, useCallback, useRef } from 'react';
import { useAuthHeaders } from '@eldrin-project/eldrin-app-react';
import { toast } from 'sonner';
import { Sparkles } from 'lucide-react';
import { StatusBadge } from '../ui';
import { DealForm } from '../../pages/deals/DealForm';
import type { DealSuggestion } from '../../api';
import * as api from '../../api';

interface DealSuggestionBannerProps {
  apiBase: string;
  contactId: string;
}

/** Violet callout on the contact page when a pending deal suggestion exists (Slice 3b). */
export function DealSuggestionBanner({ apiBase, contactId }: DealSuggestionBannerProps) {
  const authHeaders = useAuthHeaders();
  const headersRef = useRef(authHeaders);
  headersRef.current = authHeaders;

  const [suggestion, setSuggestion] = useState<DealSuggestion | null>(null);
  const [accepted, setAccepted] = useState<DealSuggestion | null>(null);

  const fetchSuggestion = useCallback(async () => {
    const res = await api.listDealSuggestions(apiBase, headersRef.current, {
      status: 'pending',
      contactId,
    });
    setSuggestion(res.suggestions[0] ?? null);
  }, [apiBase, contactId]);

  useEffect(() => {
    fetchSuggestion().catch(() => setSuggestion(null));
  }, [fetchSuggestion]);

  if (!suggestion) return null;

  async function handleAccept() {
    if (!suggestion) return;
    try {
      const res = await api.acceptDealSuggestion(apiBase, headersRef.current, suggestion.id);
      setAccepted(res.suggestion);
      setSuggestion(null);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to accept suggestion');
    }
  }

  async function handleDismiss() {
    if (!suggestion) return;
    try {
      await api.dismissDealSuggestion(apiBase, headersRef.current, suggestion.id);
      setSuggestion(null);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to dismiss suggestion');
    }
  }

  return (
    <>
      <div
        className="crm-card p-3 mb-6 flex items-center justify-between gap-3"
        style={{ borderLeft: '3px solid var(--crm-tone, #8b5cf6)' }}
      >
        <div className="flex items-center gap-2 min-w-0">
          <Sparkles className="w-4 h-4 shrink-0 text-primary" />
          <div className="min-w-0">
            <div className="text-sm font-medium truncate">
              Suggested deal: {suggestion.suggestedName}
              {suggestion.suggestedValue != null
                ? ` ($${suggestion.suggestedValue.toLocaleString()})`
                : ''}
            </div>
            <div className="flex flex-wrap gap-1 mt-1">
              {[...new Set(suggestion.signals.map((h) => h.family))].map((family) => (
                <StatusBadge
                  key={family}
                  tone="info"
                  titlePlacement="bottom"
                  title={suggestion.signals
                    .filter((h) => h.family === family)
                    .map((h) => h.snippet)
                    .join(' · ')}
                >
                  {family}
                </StatusBadge>
              ))}
              {suggestion.aiAssessmentStatus === 'assessed' && suggestion.aiConfidence != null && (
                <StatusBadge tone="violet" titlePlacement="bottom" title={suggestion.aiReasoning ?? undefined}>
                  AI: {Math.round(suggestion.aiConfidence * 100)}%
                </StatusBadge>
              )}
            </div>
          </div>
        </div>
        <div className="flex gap-1 shrink-0">
          <button className="btn btn-success btn-xs btn-outline" onClick={handleAccept}>
            Accept
          </button>
          <button className="btn btn-ghost btn-xs" onClick={handleDismiss}>
            Dismiss
          </button>
        </div>
      </div>
      {accepted && (
        <DealForm
          apiBase={apiBase}
          initialName={accepted.suggestedName}
          initialValue={accepted.suggestedValue}
          initialContactId={accepted.contactId}
          onClose={() => setAccepted(null)}
          onCreated={() => setAccepted(null)}
        />
      )}
    </>
  );
}
```

- [ ] **Step 2: Render in ContactDetail** — in `src/pages/contacts/ContactDetail.tsx`, between the header block (ends ~line 283) and the main grid (~line 285):

```tsx
<DealSuggestionBanner apiBase={apiBase} contactId={contactId} />
```

with the import at the top.

- [ ] **Step 3: Verify**

Run: `cd eldrin-crm && npm run typecheck && npm run test` — Expected: clean, all green.

- [ ] **Step 4: Commit**

```bash
git -C eldrin-crm add src/components/contacts/DealSuggestionBanner.tsx src/pages/contacts/ContactDetail.tsx
git -C eldrin-crm commit -m "feat(deals): pending-suggestion banner on contact detail"
```

---

### Task 14: Live validation (end-to-end with mock provider)

**Files:** none (validation only). Requires the dev stack: eldrin-core :4000, eldrin-workflows :4008, eldrin-crm :4009 (already running; restart eldrin-crm and eldrin-workflows dev servers to pick up new code/migrations).

Preconditions: `JWT_SECRET` set in each app's `.dev.vars` (shared value = the service secret); `AI_PROVIDER` unset in eldrin-workflows (falls back to mock).

- [ ] **Step 1: Import + activate the new workflow template**

```bash
SECRET=$(grep JWT_SECRET /Users/tibor/projects/eldrin-backup/eldrin-crm/.dev.vars | cut -d= -f2)
curl -s -X POST http://localhost:4008/api/workflows/import \
  -H 'Content-Type: application/json' \
  -d "{\"workflows\": [$(cat /Users/tibor/projects/eldrin-backup/eldrin-workflows/workflows-templates/crm-detect-deal-signals.json)]}"
# Note the returned workflowId, then activate it (check the exact activate route in worker/routes/workflows.ts):
curl -s -X POST http://localhost:4008/api/workflows/<workflowId>/activate
```

If these endpoints require user auth (manifest-gated), perform the import/activate through the browser UI or with a core-proxied call instead — mirror whatever Slice 3 live validation did (see `docs/` notes in eldrin-crm if present).

- [ ] **Step 2: Path (a) — heuristic + AI on a deal-ish email**

Inject a captured email through the CRM webhook (bypasses eldrin-email):

```bash
curl -s -X POST http://localhost:4009/api/_events/webhook \
  -H 'Content-Type: application/json' \
  -H "X-Eldrin-App-Secret: $SECRET" \
  -d '{
    "type": "email.received",
    "payload": {
      "messageId": "live-3b-a",
      "from": "Dana Buyer <dana.buyer@globex.io>",
      "subject": "ERP rollout",
      "bodyText": "We have a $45,000 budget approved and need to go-live by Q4. Looping in our CFO. Please send a proposal.",
      "receivedAt": '"$(date +%s000)"'
    }
  }'
```

(First check `asInboundPayload` in `worker/routes/events.ts` for required fields — add `to`/others if it rejects the payload.)

Verify: `GET /api/deal-suggestions?status=pending` (through the browser dashboard or curl with a user JWT) shows one suggestion with heuristic chips; within ~10s the AI leg lands: `source: 'heuristic+ai'`, `ai_assessment_status: 'assessed'`, AI confidence chip visible on the dashboard widget.

- [ ] **Step 3: Path (b) — AI-only creation below the heuristic threshold**

Same curl with `"messageId": "live-3b-b"`, a different sender, and a body with ONE family only but mock-recognizable intent, e.g. `"We are considering a pilot."` — heuristic (<2 families) records nothing; the mock provider returns `isLikelyDeal: true, confidence: 0.75`, so the assess endpoint creates a `source: 'ai'` suggestion with zero heuristic chips.

- [ ] **Step 4: Path (c) — LLM-down durability**

Deactivate the workflow (or stop eldrin-workflows), send a third deal-ish email (`live-3b-c`, new sender), and verify the heuristic suggestion exists with `ai_assessment_status: 'pending'` and is fully usable (accept/dismiss work). Reactivate afterwards.

- [ ] **Step 5: UI checks (browser, light + dark)**

- Dashboard: SuggestedDealsWidget shows suggestions with family chips (snippet tooltips), AI chip with reasoning tooltip; GoneQuietWidget lists quiet contacts/deals, period selector refetches, links navigate.
- Contact detail (Dana Buyer): violet banner with chips + Accept/Dismiss.
- Accept flow: Accept → DealForm opens pre-populated (name/value) → submit → deal created and linked to the contact (check the deal's contacts) → suggestion gone from the widget.
- Dismiss flow: dismissed suggestion disappears; re-sending the SAME messageId does not resurrect it.
- Toggle the shell theme and re-check both widgets + banner in dark mode.

- [ ] **Step 6: Full regression**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-crm && npm run typecheck && npm run test
cd /Users/tibor/projects/eldrin-backup/eldrin-workflows && npm test
```

Expected: all green. Fix anything that surfaced before proceeding to branch finish (merge/PR is a separate step via superpowers:finishing-a-development-branch; parent-repo submodule bump happens there).

---

## Self-Review Notes

- Spec coverage: D1 (Task 5 both legs), D2/D3 (Tasks 6, 7, 11), D4/D5 (Task 8), D6 (Tasks 3, 4, 6, 14c), D7 (Task 5, new event not widened extraction). Ghost backend §1 → Task 8; widget → Task 12. Scanner §2 → Tasks 1-2; store → Task 3; hook → Task 5; AI leg → Tasks 6, 9; API → Task 7; frontend → Tasks 10-13. Testing §4 → per-task TDD + Task 14 live paths (a)/(b)/(c).
- Known deviation (flagged in Global Constraints): mock-provider extension in eldrin-workflows for dev validation.
- Line numbers are from exploration on 2026-07-08 — treat as anchors, not gospel; re-locate by content.
