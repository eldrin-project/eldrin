# CRM Assigned-Mailbox Integration (Email + Calendar) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Contacts/leads carry an assigned mailbox that drives the email FROM account and the target calendar for a new CRM→calendar meeting-scheduling flow, with the calendar→CRM mirror polished (deal linking, user-field protection, richer timeline, widget annotation) — all as progressive enhancement (D0: CRM stays fully standalone).

**Architecture:** eldrin-email additively extends the `email.received` payload with the receiving mailbox identity. CRM stores the assignment (2 columns × contacts/leads), auto-assigns on capture, passes `mailboxId` on send, and schedules meetings via synchronous core-proxy calls to eldrin-calendar (`GET /api/accounts` to resolve the target calendar, `POST /api/events` to create; mirror-back via the existing `calendar.event.created` webhook creates the CRM activity). eldrin-calendar is untouched.

**Tech Stack:** Cloudflare Workers + Hono 4, Drizzle/D1, React 19, Zustand 5, daisyUI 5, Vitest.

**Spec:** `docs/superpowers/specs/2026-07-10-crm-mailbox-calendar-integration-design.md` (D0–D12)

## Global Constraints

- **D0 standalone-first:** every integration surface renders/acts ONLY when the other app is available; absence never errors or blocks core CRM. Quick-log meeting is never removed.
- REPO LAYOUT: `eldrin-crm` is a SUBMODULE (feature branch `feature/mailbox-integration` from main). `eldrin-email` is PARENT-TRACKED (no own .git): its changes are committed in the PARENT repo on `feature/eldrin-factorial` with scope `feat(email)`/`fix(email)`; never run `git checkout/branch` inside eldrin-email; stage only the named files.
- CRM migrations: 14-digit filename `YYYYMMDDHHMMSS-description.sql`; after adding, run `npm run generate:migrations` (regenerates `worker/migrations.generated.ts`, which IS committed in eldrin-crm — check `git status`).
- Conventional commits, no AI attribution. TDD per task. Full `npx vitest run` + `npm run typecheck` green before each commit. Baselines: crm 178 tests, email 89 tests.
- Case-insensitive email matching everywhere (`.toLowerCase()` on both sides).
- Cross-app proxy calls from the CRM worker follow the `upcoming-meetings.ts` pattern: `${ELDRIN_CORE_URL||'http://localhost:4000'}/api/app/<appId>/<path>`, headers `X-Eldrin-App-Secret: env.JWT_SECRET`, 10s AbortController timeout, graceful degradation. Scheduling calls ADDITIONALLY pass `x-eldrin-user-id: <acting user>` (calendar's `requestUserId` honors it).
- The acting CRM user id comes from `c.get('auth')` (AppAuthContext) — use `(c.get('auth') as { userId?: string } | undefined)?.userId ?? 'dev-user'`.

---

### Task 1: eldrin-email — mailbox identity on `email.received` (D2 emitter half)

**Files:**
- Modify: `eldrin-email/worker/services/event-emitter.ts:32-45` (EmailReceivedPayload)
- Modify: `eldrin-email/worker/services/email-sync.ts:237-248` (push site)
- Test: `eldrin-email/worker/__tests__/event-emitter.test.ts` (payload shape) and `eldrin-email/worker/__tests__/email-sync.test.ts` (emit carries mailbox fields)

**Interfaces:**
- Produces: `EmailReceivedPayload` gains `mailboxId: string` and `mailboxEmail: string` (REQUIRED fields — every emit site knows its mailbox). CRM (Task 3) consumes them from the webhook payload; consumers ignoring them are unaffected (additive JSON).

- [ ] **Step 1: Write the failing test**

In `eldrin-email/worker/__tests__/email-sync.test.ts`, locate the existing test that asserts `mockEmitEmailReceived` was called (grep `mockEmitEmailReceived`) and add alongside it:

```ts
  it('email.received payload carries the receiving mailbox identity', async () => {
    // Reuse the suite's existing mailbox fixture + sync invocation for a new
    // inbound email, then inspect the emitted payload.
    const payload = mockEmitEmailReceived.mock.calls.at(-1)?.[1] as Record<string, unknown>;
    expect(payload.mailboxId).toBe(/* the fixture mailbox's id, e.g. */ 'mb1');
    expect(payload.mailboxEmail).toBe(/* the fixture mailbox's emailAddress */ 'user@example.com');
  });
```

Adapt the fixture id/email literals to the suite's actual mailbox fixture (read the top of the file; it uses a mock DB with a mailboxes map). Place the assertion inside/after an existing flow that triggers `emitEmailReceived` — extending the existing "emits email.received" test with the two new `expect` lines is equally acceptable and preferred if one exists.

- [ ] **Step 2: Run to verify it fails**

Run: `cd /Users/tibor/projects/eldrin-backup/eldrin-email && npx vitest run worker/__tests__/email-sync.test.ts`
Expected: FAIL — `payload.mailboxId` is `undefined`.

- [ ] **Step 3: Implement**

`worker/services/event-emitter.ts` — extend the interface (after `threadId`):

```ts
export interface EmailReceivedPayload {
  messageId: string;
  threadId: string;
  /** Receiving mailbox — lets consumers attribute the relationship (CRM assigned-mailbox). */
  mailboxId: string;
  mailboxEmail: string;
  from: string;
  to: string[];
  subject: string | null;
  snippet: string | null;
  bodyText: string | null;
  receivedAt: number;
}
```

`worker/services/email-sync.ts` push site (the `newInboundEmails.push({...})` at :237) — add two fields (`mailbox` is in scope):

```ts
            newInboundEmails.push({
              messageId: parsed.messageId,
              threadId,
              mailboxId: mailbox.id,
              mailboxEmail: mailbox.emailAddress,
              from: parsed.fromAddress,
              to: parsed.toAddresses,
              subject: parsed.subject,
              snippet: parsed.snippet,
              // Truncated plain text for downstream signature parsing; null
              // when this sync depth fetched no body (metadata format).
              bodyText: buildEventBodyText(parsed.bodyText, parsed.bodyHtml),
              receivedAt: parsed.receivedAt,
            });
```

If the TypeScript compiler reveals OTHER construction sites of `EmailReceivedPayload` (e.g. a test factory), fix each the same way — the required fields make `tsc` enumerate them for you.

- [ ] **Step 4: Verify green**

Run: `npx vitest run && npx tsc -b`
Expected: all email tests pass (90+), typecheck clean.

- [ ] **Step 5: Commit (PARENT repo — eldrin-email is parent-tracked)**

```bash
cd /Users/tibor/projects/eldrin-backup
git add eldrin-email/worker/services/event-emitter.ts eldrin-email/worker/services/email-sync.ts eldrin-email/worker/__tests__/
git commit -m "feat(email): carry receiving mailbox identity on email.received payload"
```

---

### Task 2: CRM — branch, migration, schema (D1)

**Files:**
- Create: `eldrin-crm/migrations/20260710130000-assigned-mailbox.sql`
- Modify: `eldrin-crm/worker/db/schema.ts:34` (contacts, after `captureSource`) and `:220` (leads, after `notes`)
- Modify (generated): `eldrin-crm/worker/migrations.generated.ts` via `npm run generate:migrations`
- Test: `eldrin-crm/worker/__tests__/assigned-mailbox-schema.test.ts`

**Interfaces:**
- Produces: `contacts.assignedMailboxId/assignedMailboxEmail` and `leads.assignedMailboxId/assignedMailboxEmail` (all `text`, nullable) on the Drizzle schema; used by Tasks 3–7.

- [ ] **Step 1: Create the branch**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-crm
git checkout main && git pull && git checkout -b feature/mailbox-integration
```

- [ ] **Step 2: Create the migration**

`migrations/20260710130000-assigned-mailbox.sql`:

```sql
-- Assigned mailbox (spec D1): the email identity that owns the relationship.
-- id = eldrin-email mailbox id (send API key); email = join key to
-- eldrin-calendar connected accounts. Nullable — unassigned falls back to
-- app defaults (D0/D4/D7).
ALTER TABLE contacts ADD COLUMN assigned_mailbox_id TEXT;
ALTER TABLE contacts ADD COLUMN assigned_mailbox_email TEXT;
ALTER TABLE leads ADD COLUMN assigned_mailbox_id TEXT;
ALTER TABLE leads ADD COLUMN assigned_mailbox_email TEXT;
```

Then run: `npm run generate:migrations`

- [ ] **Step 3: Add columns to `worker/db/schema.ts`**

In `contacts` directly after `captureSource: text('capture_source'),`:

```ts
    // Assigned mailbox (spec D1): drives email FROM + calendar target
    assignedMailboxId: text('assigned_mailbox_id'),
    assignedMailboxEmail: text('assigned_mailbox_email'),
```

In `leads` directly after `notes: text('notes'),` — same two lines (same comment).

- [ ] **Step 4: Write the pinning test**

`worker/__tests__/assigned-mailbox-schema.test.ts` (copy the create/read style of an existing schema-touching test — grep `createTestDb` for the suite's DB helper; CRM tests use a real-migrations test DB like the calendar app's):

```ts
import { describe, it, expect } from 'vitest';
import { createTestDb } from './test-db';
import { contacts, leads } from '../db';
import { eq } from 'drizzle-orm';

describe('assigned mailbox columns', () => {
  it('round-trips assignment on contacts and leads', async () => {
    const db = createTestDb();
    await db.insert(contacts).values({
      id: 'c1', firstName: 'A', lastName: 'B', createdBy: 'u1',
      assignedMailboxId: 'mb1', assignedMailboxEmail: 'sales@acme.io',
      createdAt: 1, updatedAt: 1,
    });
    await db.insert(leads).values({
      id: 'l1', firstName: 'C', lastName: 'D', createdBy: 'u1',
      assignedMailboxId: 'mb2', assignedMailboxEmail: 'eu@acme.io',
      createdAt: 1, updatedAt: 1,
    });
    const [c] = await db.select().from(contacts).where(eq(contacts.id, 'c1'));
    const [l] = await db.select().from(leads).where(eq(leads.id, 'l1'));
    expect([c.assignedMailboxId, c.assignedMailboxEmail]).toEqual(['mb1', 'sales@acme.io']);
    expect([l.assignedMailboxId, l.assignedMailboxEmail]).toEqual(['mb2', 'eu@acme.io']);
    // Nullable: rows without assignment stay null
    await db.insert(contacts).values({ id: 'c2', firstName: 'E', lastName: 'F', createdBy: 'u1', createdAt: 1, updatedAt: 1 });
    const [c2] = await db.select().from(contacts).where(eq(contacts.id, 'c2'));
    expect(c2.assignedMailboxId).toBeNull();
  });
});
```

If the CRM test-db helper has a different name/path, adapt the import — assertions stay identical.

- [ ] **Step 5: Verify green, commit**

Run: `npx vitest run && npm run typecheck`
Expected: 179+ tests pass.

```bash
git add migrations/20260710130000-assigned-mailbox.sql worker/db/schema.ts worker/migrations.generated.ts worker/__tests__/assigned-mailbox-schema.test.ts
git commit -m "feat(contacts): assigned-mailbox columns on contacts and leads"
```

---

### Task 3: CRM — auto-assign on capture (D2 consumer half)

**Files:**
- Modify: `eldrin-crm/worker/services/auto-capture.ts:405-469` (`captureInboundSender`)
- Modify: `eldrin-crm/worker/routes/events.ts:140` (pass-through)
- Test: extend the existing auto-capture suite (grep `captureInboundSender` under `worker/__tests__/`)

**Interfaces:**
- Consumes: Task 2 columns; Task 1 payload fields (`mailboxId`, `mailboxEmail` — may be ABSENT on old/replayed events: treat as optional).
- Produces: `captureInboundSender(db, payload)` where payload gains optional `mailboxId?: string | null; mailboxEmail?: string | null`. Assignment is fill-empty-only.

- [ ] **Step 1: Write the failing tests**

Add to the existing capture suite (reuse its DB fixture/factory helpers):

```ts
  it('assigns the receiving mailbox to a newly auto-created contact', async () => {
    await captureInboundSender(db, {
      from: 'new.person@corp.com', to: ['sales@acme.io'], snippet: null, bodyText: null,
      mailboxId: 'mb1', mailboxEmail: 'sales@acme.io',
    });
    const [row] = await db.select().from(contacts); // adapt: select the auto-created contact
    expect(row.assignedMailboxId).toBe('mb1');
    expect(row.assignedMailboxEmail).toBe('sales@acme.io');
  });

  it('backfills an existing unassigned contact, fill-empty-only', async () => {
    // seed a contact + contact_emails row for known@corp.com with NO assignment (use suite fixtures)
    await captureInboundSender(db, {
      from: 'known@corp.com', to: ['sales@acme.io'], snippet: null, bodyText: null,
      mailboxId: 'mb1', mailboxEmail: 'sales@acme.io',
    });
    // expect assignment set
    // then a second event from a DIFFERENT mailbox must NOT overwrite:
    await captureInboundSender(db, {
      from: 'known@corp.com', to: ['eu@acme.io'], snippet: null, bodyText: null,
      mailboxId: 'mb2', mailboxEmail: 'eu@acme.io',
    });
    // expect assignment still mb1/sales@acme.io
  });

  it('tolerates payloads without mailbox identity (old events)', async () => {
    const out = await captureInboundSender(db, {
      from: 'new2@corp.com', to: ['sales@acme.io'], snippet: null, bodyText: null,
    });
    expect(out.contactId).not.toBeNull(); // capture unaffected, assignment stays null
  });
```

Flesh out the seeded-fixture lines with the suite's existing helpers (it already seeds contacts + contact_emails for the linking tests).

- [ ] **Step 2: Run to verify RED**

Run: `npx vitest run <that test file>`
Expected: first two FAIL (columns stay null); third may pass (no behavior change) — confirm the pattern.

- [ ] **Step 3: Implement**

`auto-capture.ts` — extend the signature and add one block. Signature:

```ts
export async function captureInboundSender(
  db: Database,
  payload: {
    from: string; to: string[]; snippet: string | null; bodyText?: string | null;
    mailboxId?: string | null; mailboxEmail?: string | null;
  },
): Promise<InboundCaptureOutcome> {
```

After the `if (!contactId) { ... } else { ... }` block resolves `contactId` (i.e., just before the signature-parsing section at `const name = parseNameFromFromHeader(...)`), add:

```ts
  // Assigned mailbox (spec D2): the mailbox that received this email owns the
  // relationship. Fill-empty-only — never overwrite an existing (possibly
  // manual, D3) assignment.
  if (payload.mailboxId && payload.mailboxEmail) {
    await db
      .update(contacts)
      .set({
        assignedMailboxId: payload.mailboxId,
        assignedMailboxEmail: payload.mailboxEmail,
        updatedAt: now(),
      })
      .where(and(eq(contacts.id, contactId), isNull(contacts.assignedMailboxId)));
  }
```

Add `isNull` and `and` to the existing drizzle-orm import if missing.

`routes/events.ts:140` — the webhook already passes the raw payload object to `captureInboundSender(db, payload as ...)`; extend that cast with the two optional fields so the values flow (read the exact line; if it narrows the payload shape, add `mailboxId`/`mailboxEmail` to the narrowed type):

```ts
      const capture = await captureInboundSender(db, payload as {
        from: string; to: string[]; snippet: string | null; bodyText?: string | null;
        mailboxId?: string | null; mailboxEmail?: string | null;
      });
```

- [ ] **Step 4: GREEN + full suite**

Run: `npx vitest run && npm run typecheck`

- [ ] **Step 5: Commit**

```bash
git add worker/services/auto-capture.ts worker/routes/events.ts worker/__tests__/
git commit -m "feat(capture): auto-assign receiving mailbox on inbound capture (fill-empty-only)"
```

---

### Task 4: CRM — assignment API + mailbox selector UI (D3)

**Files:**
- Modify: `eldrin-crm/worker/routes/contacts.ts` and `eldrin-crm/worker/routes/leads.ts` (one new PATCH route each)
- Modify: `eldrin-crm/public/eldrin-app.manifest.json` (add the two routes to `api.routes` — copy the exact shape of a neighboring contacts PATCH entry, permission `contacts:update` / `leads:update` respectively)
- Modify: `eldrin-crm/src/hooks/useEmailApp.ts` (add `getMailboxes`)
- Create: `eldrin-crm/src/components/email/MailboxSelector.tsx`
- Modify: `eldrin-crm/src/pages/contacts/ContactDetail.tsx`, `eldrin-crm/src/pages/leads/LeadDetail.tsx` (mount selector)
- Modify: `eldrin-crm/src/api.ts` (typed helper)
- Test: `eldrin-crm/worker/__tests__/assigned-mailbox-routes.test.ts`

**Interfaces:**
- Consumes: Task 2 columns; `useEmailApp` availability gating.
- Produces: `PATCH /api/contacts/:id/assigned-mailbox` and `PATCH /api/leads/:id/assigned-mailbox`, body `{ mailboxId: string | null, mailboxEmail: string | null }` (both null = unassign; both non-null = assign; mixed = 400). `useEmailApp().getMailboxes(): Promise<Mailbox[]>` where `Mailbox = { id: string; emailAddress: string; displayName?: string | null; provider?: string }`. `MailboxSelector` props: `{ apiBase: string; recordId: string; recordKind: 'contacts' | 'leads'; value: { mailboxId: string | null; mailboxEmail: string | null }; onChanged: () => void }`.

- [ ] **Step 1: Write the failing route tests**

`worker/__tests__/assigned-mailbox-routes.test.ts` — copy the harness style of an existing contacts-route test (grep `app.request` under `worker/__tests__` for the Hono test pattern and auth-context stubbing):

```ts
  it('assigns and unassigns a mailbox on a contact', async () => {
    // seed contact c1 (suite fixture)
    let res = await app.request('/api/contacts/c1/assigned-mailbox', {
      method: 'PATCH', headers: JSON_HEADERS,
      body: JSON.stringify({ mailboxId: 'mb1', mailboxEmail: 'sales@acme.io' }),
    }, env);
    expect(res.status).toBe(200);
    // DB row now carries the assignment
    res = await app.request('/api/contacts/c1/assigned-mailbox', {
      method: 'PATCH', headers: JSON_HEADERS,
      body: JSON.stringify({ mailboxId: null, mailboxEmail: null }),
    }, env);
    expect(res.status).toBe(200);
    // DB row assignment back to null
  });

  it('rejects mixed null/non-null bodies and unknown records', async () => {
    const bad = await app.request('/api/contacts/c1/assigned-mailbox', {
      method: 'PATCH', headers: JSON_HEADERS,
      body: JSON.stringify({ mailboxId: 'mb1', mailboxEmail: null }),
    }, env);
    expect(bad.status).toBe(400);
    const missing = await app.request('/api/contacts/nope/assigned-mailbox', {
      method: 'PATCH', headers: JSON_HEADERS,
      body: JSON.stringify({ mailboxId: null, mailboxEmail: null }),
    }, env);
    expect(missing.status).toBe(404);
  });
```

Add the equivalent two tests for `/api/leads/:id/assigned-mailbox`.

- [ ] **Step 2: RED**

Run the file. Expected: 404s (route absent).

- [ ] **Step 3: Implement the routes**

In `worker/routes/contacts.ts` (mirror the file's existing handler idioms — `c.get('db')`, soft-delete guard):

```ts
// ── PATCH /api/contacts/:id/assigned-mailbox — set/clear assigned mailbox (spec D1/D3)
contactRoutes.patch('/api/contacts/:id/assigned-mailbox', async (c) => {
  const db = c.get('db');
  const id = c.req.param('id');
  let body: { mailboxId?: unknown; mailboxEmail?: unknown };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }
  const { mailboxId, mailboxEmail } = body;
  const assigning = typeof mailboxId === 'string' && typeof mailboxEmail === 'string';
  const clearing = mailboxId === null && mailboxEmail === null;
  if (!assigning && !clearing) {
    return c.json({ error: 'mailboxId and mailboxEmail must both be strings or both be null' }, 400);
  }
  const [existing] = await db.select({ id: contacts.id }).from(contacts)
    .where(and(eq(contacts.id, id), eq(contacts.isDeleted, false)));
  if (!existing) return c.json({ error: 'Contact not found' }, 404);
  await db.update(contacts).set({
    assignedMailboxId: assigning ? (mailboxId as string) : null,
    assignedMailboxEmail: assigning ? (mailboxEmail as string).toLowerCase() : null,
    updatedAt: now(),
  }).where(eq(contacts.id, id));
  return c.json({ ok: true });
});
```

Same handler in `worker/routes/leads.ts` with `leads`/`Lead not found`. Adjust imports (`and`, `eq`, `now`) per each file's existing imports. Register nothing new in `worker/index.ts` (the route files are already mounted).

Manifest: add to `public/eldrin-app.manifest.json` `api.routes`, copying the exact JSON shape of the existing `PATCH /contacts/:id` entry (path `/contacts/:id/assigned-mailbox`, permission the same as that entry's update permission); same for leads.

- [ ] **Step 4: GREEN on routes**

Run: `npx vitest run worker/__tests__/assigned-mailbox-routes.test.ts` then full suite + typecheck.

- [ ] **Step 5: Frontend — hook + selector + mounting**

`src/hooks/useEmailApp.ts` — add below `getEmailHistory`:

```ts
export interface Mailbox {
  id: string;
  emailAddress: string;
  displayName?: string | null;
  provider?: string;
}
```

```ts
  const getMailboxes = useCallback(async (): Promise<Mailbox[]> => {
    const body = await emailAppRequest<unknown>(headersRef.current, '/mailboxes');
    return extractList<Mailbox>(body, ['mailboxes', 'data']);
  }, []);
```

and add `getMailboxes` to the returned object.

`src/components/email/MailboxSelector.tsx` (new):

```tsx
import { useEffect, useState } from 'react';
import { useAuthHeaders } from '@eldrin-project/eldrin-app-react';
import { toast } from 'sonner';
import { useEmailApp, type Mailbox } from '../../hooks/useEmailApp';
import * as api from '../../api';

interface MailboxSelectorProps {
  apiBase: string;
  recordId: string;
  recordKind: 'contacts' | 'leads';
  value: { mailboxId: string | null; mailboxEmail: string | null };
  onChanged: () => void;
}

/** Assigned-mailbox dropdown (spec D3). Renders nothing when the email app is absent (D0). */
export function MailboxSelector({ apiBase, recordId, recordKind, value, onChanged }: MailboxSelectorProps) {
  const authHeaders = useAuthHeaders();
  const { isAvailable, getMailboxes } = useEmailApp();
  const [mailboxes, setMailboxes] = useState<Mailbox[] | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!isAvailable) return;
    getMailboxes().then(setMailboxes).catch(() => setMailboxes([]));
  }, [isAvailable, getMailboxes]);

  if (!isAvailable) return null;

  async function handleChange(e: React.ChangeEvent<HTMLSelectElement>) {
    const picked = mailboxes?.find((m) => m.id === e.target.value) ?? null;
    setSaving(true);
    try {
      await api.setAssignedMailbox(apiBase, authHeaders, recordKind, recordId, {
        mailboxId: picked?.id ?? null,
        mailboxEmail: picked?.emailAddress ?? null,
      });
      onChanged();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to update mailbox');
    } finally {
      setSaving(false);
    }
  }

  return (
    <label className="form-control w-full max-w-xs">
      <span className="label-text text-xs text-base-content/60">Mailbox</span>
      <select
        className="select select-bordered select-sm"
        value={value.mailboxId ?? ''}
        onChange={handleChange}
        disabled={saving || mailboxes === null}
      >
        <option value="">Unassigned</option>
        {(mailboxes ?? []).map((m) => (
          <option key={m.id} value={m.id}>
            {m.displayName ? `${m.displayName} — ${m.emailAddress}` : m.emailAddress}
          </option>
        ))}
      </select>
    </label>
  );
}
```

`src/api.ts` — add (matching the file's existing helper style, which takes `apiBase` + headers):

```ts
export async function setAssignedMailbox(
  apiBase: string,
  headers: Record<string, string>,
  recordKind: 'contacts' | 'leads',
  recordId: string,
  body: { mailboxId: string | null; mailboxEmail: string | null },
): Promise<void> {
  const res = await fetch(`${apiBase}/${recordKind}/${recordId}/assigned-mailbox`, {
    method: 'PATCH',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error((data as { error?: string }).error || `Request failed: ${res.status}`);
  }
}
```

Mount `MailboxSelector` in `ContactDetail.tsx` and `LeadDetail.tsx`: place it in the header/summary card near where `SendEmailButton` is rendered (grep `SendEmailButton` in each file), passing the record's `assignedMailboxId/assignedMailboxEmail` (the detail fetch returns full rows, so the new columns are already present — extend the page's local record type with the two fields) and `onChanged={reload}` using the page's existing refetch callback.

- [ ] **Step 6: Verify + commit**

Run: `npx vitest run && npm run typecheck`

```bash
git add worker/routes/contacts.ts worker/routes/leads.ts public/eldrin-app.manifest.json src/hooks/useEmailApp.ts src/components/email/MailboxSelector.tsx src/api.ts src/pages/contacts/ContactDetail.tsx src/pages/leads/LeadDetail.tsx worker/__tests__/assigned-mailbox-routes.test.ts
git commit -m "feat(contacts): assigned-mailbox PATCH routes + selector UI on contact/lead pages"
```

---

### Task 5: CRM — send email FROM the assigned mailbox (D4)

**Files:**
- Modify: `eldrin-crm/src/hooks/useEmailApp.ts` (`SendEmailInput`/`SendTemplateInput` gain `mailboxId?: string`)
- Modify: `eldrin-crm/src/components/email/SendEmailButton.tsx` (accept + forward `mailboxId`)
- Modify: the four mounts — `src/pages/contacts/ContactDetail.tsx`, `src/pages/companies/CompanyDetail.tsx`, `src/pages/deals/DealDetail.tsx`, `src/pages/leads/LeadDetail.tsx` (pass `mailboxId` where the record has one; CompanyDetail passes none)

**Interfaces:**
- Consumes: Task 2 columns on the fetched records; eldrin-email's send routes already accept `mailboxId` (emails.ts:371, integration.ts:48).
- Produces: `SendEmailButton` gains optional prop `mailboxId?: string | null` — when set, included in both send bodies; when null/undefined, omitted (email app default, D0).

- [ ] **Step 1: Implement (mechanical, no worker changes)**

`useEmailApp.ts`: add `mailboxId?: string;` to BOTH `SendEmailInput` and `SendTemplateInput`. The send functions already spread `...input`, so the field flows — verify JSON.stringify omits it when undefined (it does).

`SendEmailButton.tsx`: add `mailboxId?: string | null;` to its props interface; where it builds the `sendEmail(...)`/`sendTemplate(...)` inputs, add `...(mailboxId ? { mailboxId } : {})`.

Mounts: pass `mailboxId={record.assignedMailboxId}` on ContactDetail/LeadDetail/DealDetail (DealDetail: the deal's primary contact's assignment if the page already loads it — if it does not load a contact record, pass nothing; note it in the task report).

- [ ] **Step 2: Verify + commit**

Run: `npx vitest run && npm run typecheck` (type errors are the test here; no worker behavior changed).

```bash
git add src/hooks/useEmailApp.ts src/components/email/SendEmailButton.tsx src/pages
git commit -m "feat(email-send): send from the record's assigned mailbox when set"
```

---

### Task 6: CRM — schedule-meeting worker endpoints (D5/D6/D7)

**Files:**
- Create: `eldrin-crm/worker/services/meeting-scheduler.ts`
- Create: `eldrin-crm/worker/routes/meetings.ts`; register in `eldrin-crm/worker/index.ts` (grep `app.route` and add alongside the other route mounts)
- Modify: `eldrin-crm/public/eldrin-app.manifest.json` (`api.routes`: `GET /meetings/schedule-options`, `POST /meetings/schedule` — permission: same as the activities create entry)
- Test: `eldrin-crm/worker/__tests__/meeting-scheduler.test.ts`

**Interfaces:**
- Consumes: Task 2 columns; calendar proxy pattern from `worker/services/upcoming-meetings.ts:42-61`; acting user from `c.get('auth')`.
- Produces:
  - `getScheduleOptions(db, env, args: { contactId: string; userId: string; fetchImpl?: typeof fetch })` → `{ calendarAvailable: boolean; mode: 'auto' | 'picker'; calendars: { id: string; name: string; accountEmail: string | null }[]; autoCalendarId: string | null; reason: string | null }`
  - `scheduleMeeting(db, env, args: { userId: string; calendarId: string; title: string; startAt: number; endAt: number; timezone: string; location: string | null; attendees: { email: string; displayName: string | null }[]; fetchImpl?: typeof fetch })` → `{ ok: true; eventId: string } | { ok: false; status: number; error: string }`
  - Routes: `GET /api/meetings/schedule-options?contactId=<id>`; `POST /api/meetings/schedule` (validated body per scheduleMeeting args minus userId/fetchImpl).

- [ ] **Step 1: Write the failing tests**

`worker/__tests__/meeting-scheduler.test.ts` — mock `fetchImpl` (the proxy seam), real test DB:

```ts
import { describe, it, expect, vi } from 'vitest';
import { createTestDb } from './test-db';
import { contacts } from '../db';
import { getScheduleOptions, scheduleMeeting } from '../services/meeting-scheduler';

const env = { JWT_SECRET: 's', ELDRIN_CORE_URL: 'http://core.test' } as Env;

function accountsResponse(accounts: unknown[]) {
  return new Response(JSON.stringify({ accounts }), { status: 200 });
}

async function seedContact(db: ReturnType<typeof createTestDb>, assigned: { id: string; email: string } | null) {
  await db.insert(contacts).values({
    id: 'c1', firstName: 'A', lastName: 'B', createdBy: 'u1',
    assignedMailboxId: assigned?.id ?? null, assignedMailboxEmail: assigned?.email ?? null,
    createdAt: 1, updatedAt: 1,
  });
}

describe('getScheduleOptions', () => {
  it('auto mode: assigned mailbox matches an account with exactly one synced calendar', async () => {
    const db = createTestDb();
    await seedContact(db, { id: 'mb1', email: 'sales@acme.io' });
    const fetchImpl = vi.fn(async () => accountsResponse([
      { id: 'acc1', email: 'SALES@acme.io', calendars: [{ id: 'cal1', name: 'Work' }] },
    ]));
    const out = await getScheduleOptions(db, env, { contactId: 'c1', userId: 'u1', fetchImpl });
    expect(out).toMatchObject({ calendarAvailable: true, mode: 'auto', autoCalendarId: 'cal1' });
    // proxy call carried service secret + acting user
    const [, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>)['x-eldrin-user-id']).toBe('u1');
  });

  it('picker mode when unassigned, no matching account, or multiple synced calendars', async () => {
    const db = createTestDb();
    await seedContact(db, null);
    const fetchImpl = vi.fn(async () => accountsResponse([
      { id: 'acc1', email: 'other@x.io', calendars: [{ id: 'cal1', name: 'A' }, { id: 'cal2', name: 'B' }] },
    ]));
    const out = await getScheduleOptions(db, env, { contactId: 'c1', userId: 'u1', fetchImpl });
    expect(out.mode).toBe('picker');
    expect(out.calendars.map((c) => c.id)).toEqual(['cal1', 'cal2']);
    expect(out.reason).toBeTruthy();
  });

  it('degrades to calendarAvailable:false on proxy failure (D0/D7)', async () => {
    const db = createTestDb();
    await seedContact(db, { id: 'mb1', email: 'sales@acme.io' });
    const fetchImpl = vi.fn(async () => new Response('nope', { status: 502 }));
    const out = await getScheduleOptions(db, env, { contactId: 'c1', userId: 'u1', fetchImpl });
    expect(out).toMatchObject({ calendarAvailable: false, mode: 'picker', calendars: [] });
  });
});

describe('scheduleMeeting', () => {
  const args = {
    userId: 'u1', calendarId: 'cal1', title: 'Meeting with A',
    startAt: 1000, endAt: 2000, timezone: 'Europe/Bucharest', location: null,
    attendees: [{ email: 'a@corp.com', displayName: null }],
  };

  it('POSTs the event through the proxy and returns the created id', async () => {
    const db = createTestDb();
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ id: 'evt-1' }), { status: 201 }));
    const out = await scheduleMeeting(db, env, { ...args, fetchImpl });
    expect(out).toEqual({ ok: true, eventId: 'evt-1' });
    const [url, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('http://core.test/api/app/eldrin-calendar/events');
    expect(init.method).toBe('POST');
    const body = JSON.parse(init.body as string);
    expect(body).toMatchObject({ calendarId: 'cal1', title: 'Meeting with A', attendees: args.attendees });
    expect((init.headers as Record<string, string>)['x-eldrin-user-id']).toBe('u1');
  });

  it('maps calendar errors to ok:false without throwing', async () => {
    const db = createTestDb();
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ error: 'Calendar not found' }), { status: 404 }));
    const out = await scheduleMeeting(db, env, { ...args, fetchImpl });
    expect(out).toEqual({ ok: false, status: 502, error: 'Calendar not found' });
  });
});
```

- [ ] **Step 2: RED** — module doesn't exist; expected import failure.

- [ ] **Step 3: Implement `worker/services/meeting-scheduler.ts`**

```ts
/**
 * CRM → eldrin-calendar meeting scheduling (spec D5/D6/D7).
 *
 * Synchronous core-proxy calls as the ACTING USER (x-eldrin-user-id — the
 * calendar's requestUserId honors it alongside the service secret). The CRM
 * writes NO activity here: the calendar's `calendar.event.created` event
 * mirrors back through the existing webhook (D8), keeping one creation path.
 */
import { eq } from 'drizzle-orm';
import type { Database } from '../db';
import { contacts } from '../db';

const CALENDAR_APP_ID = 'eldrin-calendar';
const FETCH_TIMEOUT_MS = 10000;
const ERROR_MAX_LEN = 300;

export interface ScheduleOption {
  id: string;
  name: string;
  accountEmail: string | null;
}

export interface ScheduleOptions {
  calendarAvailable: boolean;
  mode: 'auto' | 'picker';
  calendars: ScheduleOption[];
  autoCalendarId: string | null;
  reason: string | null;
}

interface RawAccount {
  id: string;
  email?: string;
  calendars?: { id: string; name?: string }[];
}

function proxyHeaders(env: Env, userId: string): Record<string, string> {
  return {
    'X-Eldrin-App-Secret': env.JWT_SECRET ?? '',
    'x-eldrin-user-id': userId,
    'Content-Type': 'application/json',
  };
}

function coreUrl(env: Env): string {
  return ((env as { ELDRIN_CORE_URL?: string }).ELDRIN_CORE_URL || 'http://localhost:4000').replace(/\/+$/, '');
}

async function proxyFetch(
  env: Env, userId: string, path: string, init: RequestInit, fetchImpl: typeof fetch,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    return await fetchImpl(`${coreUrl(env)}/api/app/${CALENDAR_APP_ID}${path}`, {
      ...init,
      headers: { ...proxyHeaders(env, userId), ...(init.headers ?? {}) },
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}

/** Resolve the schedule dialog's calendar options for a contact (D6/D7). */
export async function getScheduleOptions(
  db: Database,
  env: Env,
  args: { contactId: string; userId: string; fetchImpl?: typeof fetch },
): Promise<ScheduleOptions> {
  const doFetch = args.fetchImpl ?? fetch;
  const unavailable: ScheduleOptions = {
    calendarAvailable: false, mode: 'picker', calendars: [], autoCalendarId: null,
    reason: 'Calendar app unavailable',
  };

  const [contact] = await db
    .select({ assignedMailboxEmail: contacts.assignedMailboxEmail })
    .from(contacts)
    .where(eq(contacts.id, args.contactId));
  const assignedEmail = contact?.assignedMailboxEmail?.toLowerCase() ?? null;

  let accounts: RawAccount[];
  try {
    const res = await proxyFetch(env, args.userId, '/accounts', {}, doFetch);
    if (!res.ok) return unavailable;
    const body = (await res.json()) as { accounts?: RawAccount[] };
    accounts = Array.isArray(body.accounts) ? body.accounts : [];
  } catch (error) {
    console.error('[crm] schedule-options calendar fetch failed:', error);
    return unavailable;
  }

  const calendars: ScheduleOption[] = accounts.flatMap((a) =>
    (a.calendars ?? []).map((c) => ({
      id: c.id,
      name: c.name ?? c.id,
      accountEmail: a.email?.toLowerCase() ?? null,
    })),
  );

  if (!assignedEmail) {
    return { calendarAvailable: true, mode: 'picker', calendars, autoCalendarId: null, reason: 'No mailbox assigned to this contact' };
  }
  const matched = accounts.find((a) => a.email?.toLowerCase() === assignedEmail);
  if (!matched) {
    return { calendarAvailable: true, mode: 'picker', calendars, autoCalendarId: null, reason: `No calendar account connected for ${assignedEmail}` };
  }
  const synced = matched.calendars ?? [];
  if (synced.length !== 1) {
    // Zero or several synced calendars on the account — the user picks (D6.3).
    return { calendarAvailable: true, mode: 'picker', calendars, autoCalendarId: null, reason: `${assignedEmail} has ${synced.length} synced calendars` };
  }
  return { calendarAvailable: true, mode: 'auto', calendars, autoCalendarId: synced[0].id, reason: null };
}

/** Create the event in eldrin-calendar via the core proxy (D5). Never throws. */
export async function scheduleMeeting(
  _db: Database,
  env: Env,
  args: {
    userId: string; calendarId: string; title: string; startAt: number; endAt: number;
    timezone: string; location: string | null;
    attendees: { email: string; displayName: string | null }[];
    fetchImpl?: typeof fetch;
  },
): Promise<{ ok: true; eventId: string } | { ok: false; status: number; error: string }> {
  const doFetch = args.fetchImpl ?? fetch;
  try {
    const res = await proxyFetch(env, args.userId, '/events', {
      method: 'POST',
      body: JSON.stringify({
        calendarId: args.calendarId,
        title: args.title,
        startAt: args.startAt,
        endAt: args.endAt,
        allDay: false,
        timezone: args.timezone,
        location: args.location,
        attendees: args.attendees,
      }),
    }, doFetch);
    if (!res.ok) {
      const body = (await res.json().catch(() => ({}))) as { error?: string };
      return { ok: false, status: 502, error: (body.error ?? `Calendar returned ${res.status}`).slice(0, ERROR_MAX_LEN) };
    }
    const created = (await res.json()) as { id?: string };
    return { ok: true, eventId: created.id ?? '' };
  } catch (error) {
    console.error('[crm] schedule-meeting calendar call failed:', error);
    return { ok: false, status: 502, error: 'Calendar app unreachable' };
  }
}
```

- [ ] **Step 4: Implement `worker/routes/meetings.ts`**

```ts
/** Schedule-meeting routes (spec D5-D7). Thin validation over meeting-scheduler. */
import { Hono } from 'hono';
import type { Database } from '../db';
import { getScheduleOptions, scheduleMeeting } from '../services/meeting-scheduler';

type Variables = { db: Database; auth?: { userId?: string } };

export const meetingRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

function actingUserId(c: { get: (k: 'auth') => { userId?: string } | undefined }): string {
  return c.get('auth')?.userId ?? 'dev-user';
}

meetingRoutes.get('/api/meetings/schedule-options', async (c) => {
  const contactId = c.req.query('contactId');
  if (!contactId) return c.json({ error: 'contactId is required' }, 400);
  const out = await getScheduleOptions(c.get('db'), c.env, { contactId, userId: actingUserId(c) });
  return c.json(out);
});

meetingRoutes.post('/api/meetings/schedule', async (c) => {
  let body: Record<string, unknown>;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }
  const errors: string[] = [];
  if (typeof body.calendarId !== 'string' || !body.calendarId) errors.push('calendarId is required');
  if (typeof body.title !== 'string' || !body.title.trim()) errors.push('title is required');
  if (typeof body.startAt !== 'number' || typeof body.endAt !== 'number') errors.push('startAt/endAt must be numbers');
  else if (body.endAt <= body.startAt) errors.push('endAt must be after startAt');
  if (typeof body.timezone !== 'string' || !body.timezone) errors.push('timezone is required');
  const attendees = Array.isArray(body.attendees)
    ? (body.attendees as Record<string, unknown>[])
        .filter((a) => typeof a?.email === 'string' && (a.email as string).includes('@'))
        .map((a) => ({ email: (a.email as string).toLowerCase(), displayName: typeof a.displayName === 'string' ? a.displayName : null }))
    : [];
  if (errors.length > 0) return c.json({ error: errors.join('; ') }, 400);

  const out = await scheduleMeeting(c.get('db'), c.env, {
    userId: actingUserId(c),
    calendarId: body.calendarId as string,
    title: (body.title as string).trim(),
    startAt: body.startAt as number,
    endAt: body.endAt as number,
    timezone: body.timezone as string,
    location: typeof body.location === 'string' && body.location.trim() ? (body.location as string).trim() : null,
    attendees,
  });
  if (!out.ok) return c.json({ error: out.error }, 502);
  return c.json({ eventId: out.eventId }, 201);
});
```

Register in `worker/index.ts` next to the other `app.route('', ...)` mounts: `app.route('', meetingRoutes);` (import at top). Manifest: add both routes to `api.routes` copying the activities-create entry's permission.

- [ ] **Step 5: GREEN + full suite + commit**

Run: `npx vitest run && npm run typecheck`

```bash
git add worker/services/meeting-scheduler.ts worker/routes/meetings.ts worker/index.ts public/eldrin-app.manifest.json worker/__tests__/meeting-scheduler.test.ts
git commit -m "feat(meetings): schedule-options + schedule endpoints proxying eldrin-calendar as the acting user"
```

---

### Task 7: CRM — useCalendarApp hook + ScheduleMeetingButton/dialog (D0/D5/D7 UI)

**Files:**
- Create: `eldrin-crm/src/hooks/useCalendarApp.ts`
- Create: `eldrin-crm/src/components/meetings/ScheduleMeetingButton.tsx`
- Modify: `eldrin-crm/src/pages/contacts/ContactDetail.tsx`, `eldrin-crm/src/pages/deals/DealDetail.tsx` (mount next to the QuickLogMeeting trigger — grep `QuickLogMeeting`)
- Modify: `eldrin-crm/src/api.ts` (two typed helpers)

**Interfaces:**
- Consumes: Task 6 endpoints; Task 2 columns for prefill.
- Produces: `useCalendarApp(): { isAvailable: boolean; loading: boolean }` (availability-only twin of useEmailApp, own zustand store, `CALENDAR_APP_ID = 'eldrin-calendar'`). `ScheduleMeetingButton` props: `{ apiBase: string; contactId: string; contactName: string; contactEmail: string | null; onScheduled: () => void }`.

- [ ] **Step 1: Implement `useCalendarApp.ts`**

Copy `useEmailApp.ts`'s availability half EXACTLY (store, claimCheck, extractApps, detect) with `eldrin-calendar` as the app id — do NOT copy the request helpers (the calendar is reached only via the CRM worker):

```ts
import { useEffect, useRef } from 'react';
import { create } from 'zustand';
import { useAuthHeaders } from '@eldrin-project/eldrin-app-react';

const CALENDAR_APP_ID = 'eldrin-calendar';

type AvailabilityStatus = 'unknown' | 'checking' | 'available' | 'unavailable';

interface CalendarAppState {
  status: AvailabilityStatus;
  claimCheck: () => boolean;
  setResolved: (available: boolean) => void;
}

export const useCalendarAppStore = create<CalendarAppState>((set, get) => ({
  status: 'unknown',
  claimCheck: () => {
    if (get().status !== 'unknown') return false;
    set({ status: 'checking' });
    return true;
  },
  setResolved: (available) => set({ status: available ? 'available' : 'unavailable' }),
}));

interface InstalledApp { id?: string; appId?: string; app_id?: string; enabled?: boolean | number }

function extractApps(body: unknown): InstalledApp[] {
  if (Array.isArray(body)) return body as InstalledApp[];
  if (body && typeof body === 'object') {
    const record = body as Record<string, unknown>;
    if (Array.isArray(record.apps)) return record.apps as InstalledApp[];
    if (Array.isArray(record.data)) return record.data as InstalledApp[];
  }
  return [];
}

function isCalendarApp(app: InstalledApp): boolean {
  return (
    (app.id === CALENDAR_APP_ID || app.appId === CALENDAR_APP_ID || app.app_id === CALENDAR_APP_ID) &&
    app.enabled !== false && app.enabled !== 0
  );
}

async function detectCalendarApp(headers: Record<string, string>): Promise<boolean> {
  try {
    const res = await fetch('/api/apps', { headers });
    if (!res.ok) return false;
    const body: unknown = await res.json().catch(() => null);
    return extractApps(body).some(isCalendarApp);
  } catch {
    return false;
  }
}

/** Availability of the optional eldrin-calendar app (spec D0). Never throws into render. */
export function useCalendarApp() {
  const authHeaders = useAuthHeaders();
  const headersRef = useRef(authHeaders);
  headersRef.current = authHeaders;
  const status = useCalendarAppStore((s) => s.status);

  useEffect(() => {
    if (!useCalendarAppStore.getState().claimCheck()) return;
    detectCalendarApp(headersRef.current).then((available) => {
      useCalendarAppStore.getState().setResolved(available);
    });
  }, []);

  return {
    isAvailable: status === 'available',
    loading: status === 'unknown' || status === 'checking',
  };
}
```

- [ ] **Step 2: api.ts helpers**

```ts
export interface ScheduleOptionsResponse {
  calendarAvailable: boolean;
  mode: 'auto' | 'picker';
  calendars: { id: string; name: string; accountEmail: string | null }[];
  autoCalendarId: string | null;
  reason: string | null;
}

export async function getScheduleOptions(
  apiBase: string,
  headers: Record<string, string>,
  contactId: string,
): Promise<ScheduleOptionsResponse> {
  const res = await fetch(`${apiBase}/meetings/schedule-options?contactId=${encodeURIComponent(contactId)}`, { headers });
  if (!res.ok) throw new Error(`Request failed: ${res.status}`);
  return res.json();
}

export async function scheduleMeeting(
  apiBase: string,
  headers: Record<string, string>,
  body: {
    calendarId: string; title: string; startAt: number; endAt: number;
    timezone: string; location: string | null;
    attendees: { email: string; displayName: string | null }[];
  },
): Promise<{ eventId: string }> {
  const res = await fetch(`${apiBase}/meetings/schedule`, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error((data as { error?: string }).error || `Request failed: ${res.status}`);
  }
  return res.json();
}
```

- [ ] **Step 3: Implement `ScheduleMeetingButton.tsx`**

Modal in the QuickLogMeeting style (daisyUI `modal modal-open`, sonner toasts):

```tsx
import { useEffect, useState } from 'react';
import { useAuthHeaders } from '@eldrin-project/eldrin-app-react';
import { toast } from 'sonner';
import { CalendarPlus, X } from 'lucide-react';
import { useCalendarApp } from '../../hooks/useCalendarApp';
import * as api from '../../api';

interface ScheduleMeetingButtonProps {
  apiBase: string;
  contactId: string;
  contactName: string;
  contactEmail: string | null;
  onScheduled: () => void;
}

const DURATION_PRESETS = [30, 60, 120];

/** Schedule a REAL calendar event via eldrin-calendar (spec D5). Hidden when the app is absent (D0). */
export function ScheduleMeetingButton({ apiBase, contactId, contactName, contactEmail, onScheduled }: ScheduleMeetingButtonProps) {
  const { isAvailable } = useCalendarApp();
  const authHeaders = useAuthHeaders();
  const [open, setOpen] = useState(false);
  const [options, setOptions] = useState<api.ScheduleOptionsResponse | null>(null);
  const [calendarId, setCalendarId] = useState('');
  const [title, setTitle] = useState(`Meeting with ${contactName}`);
  const [startLocal, setStartLocal] = useState(''); // datetime-local value
  const [duration, setDuration] = useState(60);
  const [location, setLocation] = useState('');
  const [attendeeEmails, setAttendeeEmails] = useState(contactEmail ?? '');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    api.getScheduleOptions(apiBase, authHeaders, contactId)
      .then((o) => {
        setOptions(o);
        setCalendarId(o.autoCalendarId ?? o.calendars[0]?.id ?? '');
      })
      .catch(() => setOptions({ calendarAvailable: false, mode: 'picker', calendars: [], autoCalendarId: null, reason: 'Calendar unavailable' }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  if (!isAvailable) return null;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!startLocal || !calendarId) return;
    const startAt = new Date(startLocal).getTime();
    setSubmitting(true);
    try {
      await api.scheduleMeeting(apiBase, authHeaders, {
        calendarId,
        title,
        startAt,
        endAt: startAt + duration * 60000,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        location: location.trim() || null,
        attendees: attendeeEmails
          .split(',')
          .map((s) => s.trim())
          .filter((s) => s.includes('@'))
          .map((email) => ({ email, displayName: null })),
      });
      toast.success('Meeting scheduled — invites go out via the calendar account');
      setOpen(false);
      onScheduled();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to schedule meeting');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
      <button type="button" className="btn btn-sm btn-outline gap-1" onClick={() => setOpen(true)}>
        <CalendarPlus className="w-4 h-4" /> Schedule meeting
      </button>
      {open && (
        <div className="modal modal-open">
          <div className="modal-box max-w-md">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-bold text-lg flex items-center gap-2">
                <CalendarPlus className="w-5 h-5 text-primary" /> Schedule Meeting
              </h3>
              <button type="button" className="btn btn-ghost btn-sm btn-circle" onClick={() => setOpen(false)}>
                <X className="w-4 h-4" />
              </button>
            </div>
            <form onSubmit={handleSubmit} className="space-y-3">
              {options === null ? (
                <div className="flex justify-center py-6"><span className="loading loading-spinner" /></div>
              ) : (
                <>
                  {options.mode === 'picker' && options.reason && (
                    <div className="alert alert-info text-xs py-2">{options.reason}</div>
                  )}
                  <label className="form-control">
                    <span className="label-text">Calendar</span>
                    <select className="select select-bordered select-sm" value={calendarId}
                      onChange={(e) => setCalendarId(e.target.value)} disabled={options.mode === 'auto'}>
                      {options.calendars.map((c) => (
                        <option key={c.id} value={c.id}>
                          {c.accountEmail ? `${c.name} — ${c.accountEmail}` : c.name}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="form-control">
                    <span className="label-text">Title</span>
                    <input className="input input-bordered input-sm" value={title} onChange={(e) => setTitle(e.target.value)} required />
                  </label>
                  <label className="form-control">
                    <span className="label-text">Start</span>
                    <input type="datetime-local" className="input input-bordered input-sm" value={startLocal}
                      onChange={(e) => setStartLocal(e.target.value)} required />
                  </label>
                  <div className="flex gap-2">
                    {DURATION_PRESETS.map((m) => (
                      <button key={m} type="button"
                        className={`btn btn-xs ${duration === m ? 'btn-primary' : 'btn-ghost'}`}
                        onClick={() => setDuration(m)}>
                        {m} min
                      </button>
                    ))}
                  </div>
                  <label className="form-control">
                    <span className="label-text">Location</span>
                    <input className="input input-bordered input-sm" value={location} onChange={(e) => setLocation(e.target.value)} />
                  </label>
                  <label className="form-control">
                    <span className="label-text">Attendees (comma-separated emails)</span>
                    <input className="input input-bordered input-sm" value={attendeeEmails}
                      onChange={(e) => setAttendeeEmails(e.target.value)} />
                  </label>
                  <div className="modal-action">
                    <button type="button" className="btn btn-ghost btn-sm" onClick={() => setOpen(false)}>Cancel</button>
                    <button type="submit" className="btn btn-primary btn-sm"
                      disabled={submitting || !calendarId || !options.calendarAvailable}>
                      {submitting ? <span className="loading loading-spinner loading-xs" /> : 'Schedule'}
                    </button>
                  </div>
                </>
              )}
            </form>
          </div>
        </div>
      )}
    </>
  );
}
```

- [ ] **Step 4: Mount on ContactDetail + DealDetail**

Next to the existing QuickLogMeeting trigger button (grep `QuickLogMeeting` — the trigger is nearby): `<ScheduleMeetingButton apiBase={apiBase} contactId={...} contactName={...} contactEmail={primaryEmail} onScheduled={reload} />`. On DealDetail use the deal's primary contact (the page already resolves contacts for SendEmailButton — reuse that source); if the deal page has no contact loaded, mount only on ContactDetail and record it in the report.

- [ ] **Step 5: Verify + commit**

Run: `npx vitest run && npm run typecheck`

```bash
git add src/hooks/useCalendarApp.ts src/components/meetings/ScheduleMeetingButton.tsx src/api.ts src/pages
git commit -m "feat(meetings): schedule-meeting dialog on contact/deal pages, calendar-gated (D0)"
```

---

### Task 8: CRM — mirror deal-linking (D9)

**Files:**
- Modify: `eldrin-crm/worker/services/calendar-mirror.ts:58-125` (`mirrorCalendarEvent`)
- Test: extend the existing mirror suite (grep `mirrorCalendarEvent` under `worker/__tests__/`)

**Interfaces:**
- Consumes: `deals` table (`worker/db/schema.ts:303`) — read its columns first; open deal = `isDeleted = false` AND its stage/status is not won/lost (read how `deals` models won/lost: grep `won` in schema.ts and deal-stage.ts, use the same predicate the codebase uses; the reports service has one).
- Produces: `mirrorCalendarEvent` unchanged signature; additionally creates/updates one Meeting activity per OPEN deal whose primary contact is among the matched contacts, `relatedRecordType: 'deal'`, same `sourceMessageId` dedupe.

- [ ] **Step 1: Write the failing test**

In the mirror suite:

```ts
  it('links the meeting to open deals of matched contacts (D9)', async () => {
    // seed: contact c1 with email a@corp.com (suite fixture)
    // seed: deal d1 (open) related to c1, deal d2 (won/closed) related to c1 — use the schema's
    // actual columns; copy a deal fixture from the deals route tests.
    await mirrorCalendarEvent(db, payloadWithAttendee('a@corp.com'));
    const rows = await db.select().from(activities).where(eq(activities.sourceMessageId, 'calendar:evt-1'));
    const byType = new Map(rows.map((r) => [r.relatedRecordType + ':' + r.relatedRecordId, r]));
    expect(byType.has('contact:c1')).toBe(true);
    expect(byType.has('deal:d1')).toBe(true);   // open deal linked
    expect(byType.has('deal:d2')).toBe(false);  // closed deal not linked
    // idempotent: re-mirror updates, no duplicates
    await mirrorCalendarEvent(db, payloadWithAttendee('a@corp.com'));
    const again = await db.select().from(activities).where(eq(activities.sourceMessageId, 'calendar:evt-1'));
    expect(again.length).toBe(rows.length);
  });
```

Adapt fixture helpers to the suite (it already has a payload factory; deals fixtures exist in deals tests).

- [ ] **Step 2: RED**, then **Step 3: Implement**

In `mirrorCalendarEvent`, after the matched-contacts loop, resolve open deals and run the SAME upsert body for each (extract the existing per-record upsert into a local helper first so the logic isn't duplicated):

```ts
  // D9: also link the meeting to each matched contact's OPEN deals so it
  // shows on deal timelines. Same dedupe key — (sourceMessageId, relatedRecordId).
  const contactIds = matched.map((m) => m.contactId);
  const openDeals = contactIds.length > 0
    ? await db.select({ id: deals.id }).from(deals).where(and(
        inArray(deals.contactId, contactIds),
        eq(deals.isDeleted, false),
        // open = not closed; use the codebase's canonical predicate here —
        // read schema.ts:303 and mirror what reports/deal-stage use.
        notInArray(deals.status, ['won', 'lost']),
      ))
    : [];
  for (const { id: dealId } of openDeals) {
    await upsertMirrorActivity(dealId, 'deal');
  }
```

where `upsertMirrorActivity(relatedRecordId: string, relatedRecordType: 'contact' | 'deal')` is the extracted helper closing over `db/payload/fields/sourceMessageId/ts` (the existing contact loop calls it too). IMPORTANT: the deal predicate above is illustrative — Step 3 REQUIRES reading `deals` in `schema.ts:303-360` and using its real column(s) for "open" (if deals track stage rather than status, join/`inArray` on the non-terminal stages the way `worker/services/reports.ts` distinguishes open pipelines). State the predicate you used in the task report.

- [ ] **Step 4: GREEN + full suite**, then **Step 5: Commit**

```bash
git add worker/services/calendar-mirror.ts worker/__tests__/
git commit -m "feat(mirror): link mirrored meetings to matched contacts' open deals"
```

---

### Task 9: CRM — mirror user-field whitelist pin + richer timeline (D10/D11)

**Files:**
- Test only: extend the mirror suite (D10 pin)
- Modify: `eldrin-crm/src/components/Timeline.tsx` (MeetingEntry)
- Modify: the server-side timeline builder — locate with `grep -rn "snippet" eldrin-crm/worker/routes | grep -i timeline` (the route that assembles `TimelineEvent.details` for activities; extend it to include meeting fields)
- Modify: `eldrin-crm/src/types/contact.ts` (TimelineEvent details typing if narrow)

**Interfaces:**
- Consumes: activities `metadata` JSON (`calendarEventId`, `location`, `timezone`, `allDay`), `typeId === 'type-meeting'`, `durationMinutes`, `dueDate`; `useCalendarApp` (Task 7) for the link gating.
- Produces: timeline `details` for meeting activities gains `{ meeting: { startAt: number; durationMinutes: number | null; location: string | null; calendarEventId: string | null } }`; `Timeline.tsx` renders `MeetingEntry` for them.

- [ ] **Step 1: D10 pinning test (mirror never clobbers user fields)**

In the mirror suite:

```ts
  it('preserves user-owned fields across mirror updates (D10)', async () => {
    await mirrorCalendarEvent(db, payloadWithAttendee('a@corp.com'));
    const [row] = await db.select().from(activities).where(eq(activities.sourceMessageId, 'calendar:evt-1'));
    await db.update(activities).set({
      description: 'Agenda: pricing walkthrough', outcome: 'Went well', nextSteps: 'Send quote', status: 'completed',
    }).where(eq(activities.id, row.id));
    // calendar-side change arrives (new title/time)
    await mirrorCalendarEvent(db, { ...payloadWithAttendee('a@corp.com'), title: 'Renamed', startAt: row.dueDate! + 3600000, endAt: row.dueDate! + 7200000 });
    const [after] = await db.select().from(activities).where(eq(activities.id, row.id));
    expect(after.title).toBe('Renamed');                        // calendar-sourced: updated
    expect(after.description).toBe('Agenda: pricing walkthrough'); // user-owned: preserved
    expect(after.outcome).toBe('Went well');
    expect(after.nextSteps).toBe('Send quote');
    expect(after.status).toBe('completed');
  });
```

Run — expected: PASSES already (the mirror's update `fields` never touches these). This is a contract pin, not a bug fix; if it FAILS, the mirror regressed — fix by restricting the update `set` to the existing `fields` object only.

- [ ] **Step 2: Timeline builder — meeting details**

In the located timeline-assembly route/service, where activity events get `details` (currently snippet/direction for emails), add for `typeId === 'type-meeting'` rows:

```ts
      details = {
        meeting: {
          startAt: activity.dueDate,
          durationMinutes: activity.durationMinutes,
          location: activityMetadata?.location ?? null,
          calendarEventId: activityMetadata?.calendarEventId ?? null,
        },
      };
```

(`activityMetadata` = `JSON.parse(activity.metadata ?? 'null')` guarded by try/catch — reuse the route's existing metadata parsing if present.) Local quick-logged meetings have no metadata → `location/calendarEventId` null; chips degrade (D11).

- [ ] **Step 3: `Timeline.tsx` — MeetingEntry**

Add below `ActivityEntry` and branch on it in the render (`details` carries `meeting`):

```tsx
interface MeetingDetails {
  meeting?: {
    startAt: number | null;
    durationMinutes: number | null;
    location: string | null;
    calendarEventId: string | null;
  };
}

/** Meeting entry: time range + location + Open-in-Calendar (mirrored only). */
function MeetingEntry({ event, calendarAvailable }: { event: TimelineEvent; calendarAvailable: boolean }) {
  const meeting = (event.details as MeetingDetails | undefined)?.meeting;
  return (
    <>
      <p className="font-medium">{event.description}</p>
      <p className="text-xs text-base-content/50 mt-1 flex flex-wrap items-center gap-2">
        {meeting?.startAt && (
          <span>
            {new Date(meeting.startAt).toLocaleString()}
            {meeting.durationMinutes ? ` · ${meeting.durationMinutes} min` : ''}
          </span>
        )}
        {meeting?.location && <span className="badge badge-ghost badge-xs">{meeting.location}</span>}
        {meeting?.calendarEventId && calendarAvailable && (
          <a href="/eldrin-calendar" className="link link-primary">Open in Calendar</a>
        )}
      </p>
    </>
  );
}
```

In `Timeline({ events, loading })`: call `const { isAvailable: calendarAvailable } = useCalendarApp();` at the top, and in the event branch render `MeetingEntry` when `(event.details as MeetingDetails)?.meeting` is present, else the existing `ActivityEntry`.

- [ ] **Step 4: Verify + commit**

Run: `npx vitest run && npm run typecheck`

```bash
git add worker/__tests__/ src/components/Timeline.tsx src/types worker/routes
git commit -m "feat(timeline): meeting chips + Open-in-Calendar link; pin mirror user-field whitelist"
```

---

### Task 10: CRM — widget mailbox annotation (D12) + D0 degradation tests

**Files:**
- Modify: `eldrin-crm/worker/services/upcoming-meetings.ts` (annotate with calendar name + account email)
- Modify: `eldrin-crm/src/components/reports/UpcomingMeetingsWidget.tsx` (render annotation)
- Test: extend `worker/__tests__` upcoming-meetings suite (grep `getUpcomingMeetings`); add D0 degradation tests

**Interfaces:**
- Consumes: calendar occurrences carry `calendarId` (verified: `eldrin-calendar/worker/services/expansion.ts:20`); accounts payload from `GET /api/accounts` as in Task 6.
- Produces: `UpcomingMeeting` gains `calendarName: string | null; accountEmail: string | null`.

- [ ] **Step 1: Failing test**

In the upcoming-meetings suite, extend the mocked fetch to answer BOTH proxy paths (`/events` and `/accounts` — dispatch on URL) and assert:

```ts
  it('annotates meetings with calendar name and account email (D12)', async () => {
    const fetchImpl = vi.fn(async (url: string | URL | Request) => {
      const u = String(url);
      if (u.includes('/accounts')) {
        return new Response(JSON.stringify({ accounts: [
          { id: 'acc1', email: 'sales@acme.io', calendars: [{ id: 'cal1', name: 'Work' }] },
        ] }), { status: 200 });
      }
      return new Response(JSON.stringify({ occurrences: [
        { id: 'o1', calendarId: 'cal1', title: 'Demo', startAt: 1, endAt: 2, allDay: false, location: null, attendees: [] },
      ] }), { status: 200 });
    });
    const out = await getUpcomingMeetings(db, env, { days: 7, nowMs: 0, fetchImpl });
    expect(out.meetings[0]).toMatchObject({ calendarName: 'Work', accountEmail: 'sales@acme.io' });
  });

  it('annotation failure degrades to nulls, not an error (D0)', async () => {
    const fetchImpl = vi.fn(async (url: string | URL | Request) =>
      String(url).includes('/accounts')
        ? new Response('nope', { status: 500 })
        : new Response(JSON.stringify({ occurrences: [{ id: 'o1', calendarId: 'cal1', title: 'Demo', startAt: 1, endAt: 2, allDay: false, location: null, attendees: [] }] }), { status: 200 }),
    );
    const out = await getUpcomingMeetings(db, env, { days: 7, nowMs: 0, fetchImpl });
    expect(out.calendarAvailable).toBe(true);
    expect(out.meetings[0]).toMatchObject({ calendarName: null, accountEmail: null });
  });
```

- [ ] **Step 2: RED → implement**

In `upcoming-meetings.ts`: add `calendarId: string` to `RawOccurrence`; `calendarName/accountEmail` to `UpcomingMeeting`; after fetching occurrences, best-effort fetch `/accounts` (same headers/timeout pattern; on ANY failure use an empty map), build `calendarId → { name, accountEmail }` from `accounts[].calendars[]`, and set both fields in the mapped meeting (null when unknown). NOTE: this route currently passes no user header; add `x-eldrin-user-id` here too IF the route handler has the auth context available (`worker/routes/reports.ts:88` — read it; if the acting user is accessible pass it for both calls, matching Task 6's headers).

- [ ] **Step 3: Widget rendering**

In `UpcomingMeetingsWidget.tsx`, under each meeting row add (matching the widget's existing muted-text style):

```tsx
  {(m.calendarName || m.accountEmail) && (
    <span className="text-xs text-base-content/40">
      {[m.calendarName, m.accountEmail].filter(Boolean).join(' · ')}
    </span>
  )}
```

- [ ] **Step 4: D0 degradation tests (spec §6)**

Add a UI-less worker test asserting the schedule endpoints stay well-behaved when the calendar proxy is down (Task 6 already covers `getScheduleOptions` 502 → `calendarAvailable:false`; add the route-level assertion if not covered). For the UI gates (button/selector hidden when apps absent) — the hooks return `isAvailable:false` when `/api/apps` lacks the app; both components early-return `null` on `!isAvailable` (code-reviewed in Tasks 4/7; note in the report that UI-level automated tests don't exist in this repo and the live validation covers it).

- [ ] **Step 5: Verify + commit**

```bash
git add worker/services/upcoming-meetings.ts src/components/reports/UpcomingMeetingsWidget.tsx worker/__tests__/ worker/routes/reports.ts
git commit -m "feat(reports): annotate upcoming meetings with calendar + account (graceful when unknown)"
```

---

### Task 11: Merge, gitlink, live validation

- [ ] **Step 1: Final suites**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-crm && npx vitest run && npm run typecheck
cd /Users/tibor/projects/eldrin-backup/eldrin-email && npx vitest run && npx tsc -b
```

- [ ] **Step 2: Merge crm branch (after user review) + parent bump**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-crm
git checkout main && git merge --no-ff feature/mailbox-integration && git push

cd /Users/tibor/projects/eldrin-backup
git add eldrin-crm
git commit -m "chore: bump eldrin-crm submodule — assigned-mailbox email+calendar integration"
git push
```

(eldrin-email changes are already parent commits on `feature/eldrin-factorial`; push happens with the parent push.)

- [ ] **Step 3: Live browser validation (chrome-devtools; delegate per session convention)**

Rebuild/restart the CRM and email dev servers (crm preview 4009, email preview 4010, calendar dev 4012, shell 4000). Then: (1) open a contact captured from email — Mailbox selector shows the receiving mailbox; (2) change assignment — persists across reload; (3) Send email — email app's sent record shows the assigned FROM mailbox; (4) Schedule meeting → auto mode picks the matching account's calendar → event visible in eldrin-calendar UI and at the provider (ground-truth read) → Meeting activity mirrors back onto contact + open-deal timelines with time/location chips; (5) edit description/outcome on the mirrored activity, rename the event in Calendar, re-sync → user fields intact; (6) dashboard widget shows calendar/account annotation; (7) D0: stop the calendar dev server, reload CRM — Schedule button gone, contact page fully functional, widget shows its calendar-unavailable state.

---

## Self-Review Notes

- Spec coverage: D0→Tasks 4/7/10 (gating + degradation tests) and every proxy fallback; D1→T2; D2→T1+T3; D3→T4; D4→T5; D5/D6/D7→T6+T7; D8→T6 (no CRM write; comment pins it); D9→T8; D10→T9 pin; D11→T9; D12→T10. Live validation §6→T11.
- Deliberately anchored-not-verbatim edits (large UI files, timeline builder location, deals open-predicate): each names an exact grep anchor and requires the implementer to state what they found in the report — the reviewer checks it.
- Type consistency: `ScheduleOptionsResponse` (api.ts) mirrors `ScheduleOptions` (worker) field-for-field; `Mailbox.emailAddress` matches eldrin-email's `/api/mailboxes` columns (verified mailbox.ts:319-334); attendee shape `{email, displayName}` matches calendar `POST /api/events` (validation.ts via events.ts:116) and `graph/google` translators.
- eldrin-email commits land in the PARENT repo; eldrin-crm on its own feature branch — Task 1 vs Tasks 2-10 keep the repos separate; no cross-repo commit mixes.
