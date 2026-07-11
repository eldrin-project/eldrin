# Company Dedup: Prevent + Review-Merge — Design

**Date:** 2026-07-11
**Repo:** eldrin-crm (worker + frontend)
**Status:** Approved

## Problem

Inbound emails from unknown senders auto-create provisional companies keyed by the
**exact** email domain (`worker/services/auto-capture.ts` →
`matchEmailToCompany`). Organisations that send from multiple subdomains
(`email.anthropic.com`, `mail.anthropic.com`) therefore spawn one company per
subdomain. The AI enricher already resolves subdomains to the registrable
domain when fetching (Rust `psl` crate in `eldrin-enricher/src/fetch.rs`), so
all of these get enriched to the same display name ("Anthropic PBC") and show
up as visible duplicates in the Companies list.

Existing machinery:

- `detectCompanyDuplicates` (exact-domain + name-LIKE) runs only as a warning
  on manual company creation.
- There is **no merge capability** for companies.

## Decisions (with user)

1. **Scope:** both prevention (capture-time normalization) and cleanup
   (detect + merge existing duplicates).
2. **Merge mode:** suggest + confirm in UI. No auto-merge anywhere.
3. **PSL source:** `tldts` npm package in the CRM worker (same semantics as
   the enricher's Rust `psl` crate; correct for multi-part TLDs like
   `co.uk`, works on Cloudflare Workers).

## Part 1 — Prevention: normalize to registrable domain at capture

Extend `worker/services/company-domain.ts`:

- `registrableDomain(host: string): string | null` — PSL-based via `tldts`
  `getDomain()`. Guards: IP literals and single-label hosts return `null`
  (mirrors the enricher's IpAddr guard). `email.anthropic.com` →
  `anthropic.com`; `foo.co.uk` → `foo.co.uk` (unchanged).

Changes in `worker/services/auto-capture.ts` /
`worker/services/email-linking.ts`:

- **Freemail check** (`isEnrichableDomain`) evaluates the registrable domain,
  so `mail.gmail.com` is rejected like `gmail.com`.
- **Company match** (`matchEmailToCompany`): match
  `lower(companies.domain) IN (rawDomain, registrableDomain)`, preferring the
  registrable match. Rationale: while un-merged subdomain companies still
  exist, senders from that exact subdomain keep linking to them instead of
  spawning a third company.
- **Company creation** (`autoCreateCompanyFromDomain`): store
  `domain = registrableDomain ?? rawDomain`; placeholder name likewise. A
  later sender from a sibling subdomain then matches the same company.

## Part 2 — Detection: duplicates endpoint

`GET /api/companies/duplicates` (new handler in
`worker/routes/companies.ts`, logic in a new
`worker/services/company-duplicates.ts`):

- Scan non-deleted companies (small table; in-worker grouping is fine).
- **Primary signal:** group by registrable domain of `companies.domain`.
- **Secondary signal:** case-insensitive exact-name equality (catches
  companies whose enrichment converged on the same name but whose domains
  differ). Marked with lower confidence in the response.
- Each group returns its members (id, name, domain, isAutoCreated,
  createdAt, linked-contact count, filled-field count) plus a
  **suggested survivor**: human-created beats auto-created, then oldest,
  then most filled fields.
- Read-only; no side effects.

## Part 3 — Merge: transactional service

`POST /api/companies/:id/merge` with body `{ sourceIds: string[] }`
(`:id` is the survivor). New `worker/services/company-merge.ts`:

- **Validate:** survivor and all sources exist, are distinct, are not
  deleted. Reject merging a company into itself or an empty source list.
- **Re-point references** from each source to the survivor:
  - `contactCompanyRelations.companyId` — skip rows whose contact already
    links to the survivor (unique index `idx_ccr_unique`); never demote an
    existing primary relation on the survivor side.
  - `companies.parentCompanyId` (children of merged sources).
  - `leads.convertedCompanyId`.
  - `dealSuggestions.companyId`.
  - Polymorphic rows where type = company: `recordTags`
    (`recordId`/`recordType`, dedupe against the composite PK) and
    `activities.relatedRecordId`/`relatedRecordType`.
  - `auditTrail` stays untouched (it is history); the merge itself writes an
    audit entry on the survivor recording source ids and re-pointed counts.
- **Fill-empty-only** field copy from sources into the survivor (first
  non-empty source value per empty survivor field). No overwrites.
- **Canonicalize** the survivor's `domain` to its registrable domain when the
  current value is a subdomain of it.
- **Soft-delete** sources (`isDeleted = true`, `deletedAt = now()`) — they
  land in the existing recycle bin, so a bad merge is recoverable.
- Writes run sequentially in a safe order (the codebase uses no D1 batch API,
  and the better-sqlite3 test harness could not exercise one): references are
  re-pointed first and destructive steps (soft-delete) run last, so an
  interrupted merge leaves only already-re-pointed rows — nothing is lost and
  re-running the same merge completes the remainder.

## Part 4 — UI: review surface in Companies

- Companies page (`src/pages/companies/`): a "Duplicates" button with a count
  badge, shown when `GET /api/companies/duplicates` returns groups.
- Review view: one card per group; each member shows name, domain,
  auto/manual origin, contact count, filled-field count. Radio selects the
  survivor (pre-selected to the suggestion). A per-group **Merge** button
  calls the merge endpoint and refreshes.
- API helpers in `src/api.ts`; daisyUI components consistent with the rest of
  the app.

## Error handling

- Merge endpoint returns 400 for invalid input (unknown ids, self-merge,
  deleted records), 404 for a missing survivor; errors are surfaced in the UI
  with a toast and no partial state (batch semantics).
- `registrableDomain` failures (IPs, garbage hosts) fall back to the raw
  domain everywhere — never a crash, never a null-named company.

## Testing (TDD, per house rules)

- **Unit:** `registrableDomain` (subdomain, multi-part TLD, IP, single
  label); updated `auto-capture` tests (subdomain sender links to
  registrable-domain company; sibling subdomain reuses it; freemail
  subdomain rejected; existing exact-subdomain company still matches).
- **Unit:** `company-duplicates` grouping (domain groups, name groups,
  survivor suggestion ordering).
- **Unit:** `company-merge` (each re-pointed table, relation dedupe, primary
  preservation, fill-empty copy, domain canonicalization, soft-delete +
  recycle-bin recovery, validation failures).
- **Route tests** for both endpoints (auth via existing permission
  middleware).
- **Browser walkthrough** for the duplicates review UI (render groups, pick
  survivor, merge) — the repo has no frontend test infra (vitest only covers
  `worker/**`), so the UI is verified by typecheck + build + live walkthrough.

## Outcome for the motivating case

After shipping, the duplicates view shows the two Anthropic rows as one group
(both `*.anthropic.com` → `anthropic.com`, same name); one click merges them,
and future mail from any `anthropic.com` subdomain links to the surviving
company.
