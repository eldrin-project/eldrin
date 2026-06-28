# Future Flow Elements — Capability Roadmap (CPI/Camel-inspired)

**Status:** living backlog — NOT a committed spec. A menu of flow components to design/build later, each its own brainstorm → spec → plan → SDD cycle when prioritized.
**Date:** 2026-06-29
**Scope:** the integration flow platform (`eldrin-integration` SDK runtime + later the SP8 canvas).

## Why this exists

The flow model today is a linear-to-branching pipeline of `source → [transform | map | filter | route] → destination`. Real integrations need richer elements: enriching a record from a second system, persisting data for reuse, splitting/aggregating collections, deduplicating, calling external services mid-flow. SAP CPI is a UI over Apache Camel, whose **Enterprise Integration Patterns (EIP)** are the canonical catalog. This document maps the patterns worth adopting onto our model so future work has a shared vocabulary and we don't design ourselves into a corner.

**Legend — model readiness:**
- 🟢 **kind exists** — `NodeKind` already names it; needs an executor stage + validation (like `route` did before SP6).
- 🟡 **new node kind** — additive to `NodeKind` + a config type + executor stage; fits the current per-row DAG walk.
- 🔴 **model extension** — needs new runtime primitives (state store, async I/O mid-flow, collection-shaped rows, multi-message correlation) beyond the current per-row, stateless, single-record-shaped walk.

Current `NodeKind`: `source | map | transform | filter | route | destination`. Current `TransformerRef`: `builtin | snippet`. Trigger: `cron | webhook | manual`.

---

## Tier 1 — Enrichment & external lookups (the user's first example)

> "Receives a list of users from a system and has to pull additional data based on the id or email from another system."

### Content Enricher 🔴 (Camel `enrich` / `pollEnrich`; CPI "Content Enricher" / "Request-Reply")
A node that, per row, calls an **external resource** (another source/API) keyed on a field (`id`, `email`) and merges the response into `current`. This is the headline future element.
- **Why 🔴:** the current walk is synchronous-stateless over one record's own fields. Enrichment needs **async I/O mid-flow** (an HTTP/transport call per row, or batched), plus a merge strategy (combine vs. replace). The executor's per-row `walk` would need to `await` a fetch inside a stage.
- **Design notes:** reuse the existing `Transport`. Key concerns: **batching** (don't issue one HTTP call per row across 10k rows — gather keys, bulk-fetch, join — Camel's aggregate-then-enrich), **caching** (an enrichment cache keyed on the lookup id, TTL'd — overlaps with the persistent store below), **failure policy** (row dropped vs. partial vs. fail-flow), and **rate limiting** against the upstream. Config: `{ resource, keyField, into?, strategy: 'merge'|'replace', batchSize?, cache? }`.
- **Performance-first:** strongly prefer **bulk enrichment** (collect N keys → one batched upstream request → hash-join back) over per-row calls. This is where the streaming/batched-sink design (SP1.5) pays off again.

### Service Call / Request-Reply 🔴 (Camel `to`/`recipientList` with reply; CPI "Request Reply")
A more general external call (not just data lookup) — POST to a downstream service mid-flow and use the response. Same async-I/O requirement as the enricher; the enricher is the read-shaped special case.

### Polling Consumer as a mid-flow source 🟡
Today `source` is the single origin. Enrichment is partly "a second source consulted mid-flow." If we generalize, an enrichment node is a constrained inline source. Worth keeping the enricher and source implementations sharing transport plumbing.

---

## Tier 2 — Persistence, reuse & idempotency (the user's second example)

> "Another component that before sending the data will store it for reuse."

### Persistent Store / Data Store 🔴 (CPI "Data Store Operations": Write/Get/Select/Delete; Camel JDBC/SQL)
A node that **writes rows to a reusable store** (a D1 table or KV) mid-flow, and a counterpart that **reads** from it — so a later run or a later branch can reuse the data without re-fetching.
- **Why 🔴:** introduces **flow-scoped or cross-run state** the current stateless walk doesn't have. Needs a store abstraction (table/keyspace), read/write/select/delete ops, and a retention/TTL policy.
- **Config sketch:** `store-write { store, key, value? }`, `store-read { store, key, into }`. Overlaps with the enrichment cache — likely one store primitive serves both.

### Claim Check 🔴 (Camel "Claim Check"; CPI "Persist Message")
Stash a large payload in the store, carry only a reference (claim) through the flow, retrieve it later. A performance/payload-size optimization for heavy records. Builds on the persistent store.

### Idempotent Repository 🟡→🔴 (Camel `idempotentConsumer`; CPI "Idempotent Process Call")
Drop rows already processed (by id/hash), so re-runs don't double-write. Partly expressible as a `filter` (🟡) if the dedup key is in-row, but a true cross-run idempotent repo needs the persistent store (🔴).

---

## Tier 3 — Collection shaping (splitter/aggregator family)

These change the **shape** of what flows — from one-record-per-row to collections — which the current per-row `Row` model doesn't represent. All 🔴 (need a collection-aware row or a sub-pipeline).

### Splitter 🔴 (Camel `split`; CPI "Splitter")
One incoming record containing a list → N rows (e.g. an order with line-items → one row per line-item). The inverse of how `source` already yields many rows; here the fan-out happens mid-flow.

### Aggregator 🔴 (Camel `aggregate`; CPI "Gather" / "Aggregator")
Combine N rows into one by a correlation key + completion condition (size, timeout, predicate). Needs **multi-message correlation + buffered state** — the hardest EIP. Pairs with Splitter (split → process → re-aggregate) and with bulk enrichment.

### Gather / Join 🔴 (CPI "Join" + "Gather")
Merge branches that were split, often after a multicast. Related to our reconverge (SP6) but at the collection level.

---

## Tier 4 — Routing & distribution refinements (extends SP6)

### Multicast / Broadcast 🟡 (Camel `multicast`; CPI "Multicast")
Send the **same** row down **all** branches (vs. SP6's route = first-match one branch). Additive to the executor: a node kind whose every outgoing edge gets a copy of the row. Fits the DAG walk if we allow a row to fan into multiple paths (relaxes the single-path invariant deliberately, for this kind only).

### Dynamic Router / Recipient List 🟡 (Camel `dynamicRouter`/`recipientList`)
Route targets computed at runtime from row content (vs. SP6's static edges). A `route` whose branch set is data-driven.

### Load Balancer / Throttle 🟡 (Camel `throttle`, `loadBalance`)
Rate-limit or distribute outbound calls — most relevant once external service-call nodes exist (Tier 1).

---

## Tier 5 — Reliability & control

### Dead Letter Channel 🟡 (Camel "Dead Letter Channel"; CPI exception subprocess)
Today errors are collected into `ExecuteResult.errors` and the row is dropped. A DLC routes failed rows to a **dead-letter destination** (a table) for inspection/retry instead of silent drop. Largely expressible as a destination + the existing error path, formalized.

### Retry / Circuit Breaker 🔴 (Camel `errorHandler` redelivery, `circuitBreaker`)
Per-node retry with backoff; trip a breaker on repeated upstream failure. Needs stateful retry bookkeeping — relevant once external calls (Tier 1) exist.

### Wire Tap 🟡 (Camel `wireTap`; CPI "Wire Tap")
Send a copy of the row to a side channel (audit/log/store) without affecting the main flow. A non-blocking multicast to one extra sink.

### Delay / Throttle nodes 🟡
Time-based pacing — straightforward stages once needed.

---

## Tier 6 — Trigger & transport breadth (orthogonal to nodes)

- **More triggers** 🟡: `event` (cross-app event bus — eldrin already has one), `queue`, `file-drop`, `manual-with-params`. Additive to `TriggerConfig`.
- **More source/destination transports** 🔴: today destination is `kind: 'd1'` only. Future: HTTP/SFTP/S3-R2/queue/another-app destinations; the `DestinationConfig.kind` union is the extension point (already discriminated for this).
- **More transformers** 🟢: the `builtin` library (concat/substring/…) extends freely; new builtins are pure additions to `BUILTINS`. Date/number/lookup-table builtins, etc.

---

## Sequencing guidance (when we come back)

A sensible order that front-loads the user's two examples and respects dependencies:

1. **Persistent Store primitive** (Tier 2) — unlocks reuse, enrichment caching, claim check, idempotent repo. Foundational.
2. **Content Enricher** (Tier 1) — the headline ask; builds on the store for caching + bulk lookup.
3. **Dead Letter Channel + Wire Tap** (Tier 5) — cheap reliability/observability wins, mostly formalizing existing error/multicast paths.
4. **Splitter** (Tier 3) — collection shaping; needed before Aggregator.
5. **Aggregator** (Tier 3) — the hardest; do last, after split + store + correlation are understood.
6. **Multicast / Dynamic Router** (Tier 4) — routing refinements once single-path branching (SP6) is proven.

Each is its own sub-project (brainstorm → spec → plan → SDD), SDK-first (runtime before the SP8 canvas exposes it), with the same regression discipline: new node kinds must not change existing linear/branching behavior.

## Model-extension themes to watch

Three recurring 🔴 requirements that, once built, unlock whole tiers:
- **Async I/O mid-flow** (a `walk` stage that can `await` a transport call) → enables enricher, service call, request-reply.
- **Flow state store** (read/write keyed store, TTL'd) → enables persistent store, claim check, idempotent repo, enrichment cache.
- **Collection-shaped rows + correlation** (a row can carry/become a list; buffered multi-row state) → enables splitter, aggregator, gather.

Designing the store and the async-stage primitives cleanly (the first two themes) is the highest-leverage future investment — most of this backlog hangs off them.

## References
- Apache Camel EIP catalog: enterprise integration patterns (Hohpe & Woolf) as implemented in Camel.
- SAP CPI palette: Content Enricher, Request-Reply, Data Store Operations, Splitter/Gather, Idempotent Process Call, Multicast, Wire Tap, exception subprocess.
- Our model: `eldrin-integration/src/flow/types.ts` (`NodeKind`, `NodeConfig`, `TransformerRef`, `TriggerConfig`).
- Related: [[cpi-flow-platform-status]] (roadmap state), SP6 routing-engine spec (the branching foundation these extend).
