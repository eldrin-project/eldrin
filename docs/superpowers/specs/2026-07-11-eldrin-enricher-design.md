# eldrin-enricher — Local LLM Enrichment App (Design)

**Date:** 2026-07-11
**Status:** Approved
**Repo:** new GitHub repository `eldrin-enricher`, added as a submodule of the parent orchestrator repo (same pattern as all other Eldrin components).

## Purpose

A local, on-demand Rust CLI that enriches Eldrin CRM contacts and companies using a
local LLM (Gemma 31B served by llama.cpp) plus direct web fetching. It consumes the
pull/apply enrichment contract shipped with CRM Phase 10 Slice 3 (see
`2026-07-03-ai-enhancement-workflows-design.md`, which explicitly reserved this role
for a "future local enhancer app"). No changes to any Eldrin app are required.

The user starts the model server themselves, e.g.:

```
llama-server -hf unsloth/gemma-4-31B-it-GGUF:UD-Q4_K_XL \
  --alias "gemma-4-31b" --port 8080 --ctx-size 262144 \
  --flash-attn on -ctk q8_0 -ctv q8_0 -ngl 99
```

## Decisions (from brainstorming)

| # | Decision | Choice |
|---|----------|--------|
| 1 | Internet search strategy | **Direct fetch only** (company homepage via its `domain`); search-engine sources (SearXNG, commercial APIs) can slot in later behind the `Fetcher` trait |
| 2 | App shape | **CLI with subcommands**; v1 ships only `run`. A `serve` HTTP mode (app-initiated enrichment requests) is designed-for but not built |
| 3 | Record types | **Companies + contacts**. Deal-suggestion assessment stays on the existing workflow path |
| 4 | Location | **New repo + submodule `eldrin-enricher`** |

## Existing contract this app consumes

All endpoints on the CRM app (`eldrin-crm/worker/routes/enhancement.ts`), reachable
either through the core proxy (`http://localhost:4000/api/app/eldrin-crm/...`,
the shipped service-principal pattern) or directly (`http://localhost:4009/...`).
Auth: header `X-Eldrin-App-Secret: <JWT_SECRET>` (shared dev secret across
core/crm/workflows).

- **Pull:** `GET /api/enhancement/pending?type=contact|company&limit&offset`
  (limit ≤ 100). Contact items include the latest captured email material
  (`messageId`, `from`, `bodyText`); company items include `{id, name, domain}`.
- **Apply (fill-empty-only, idempotent, sets `aiEnhancementStatus='enhanced'`):**
  - `POST /api/enhancement/companies/:id` — `{data: {name?, description?, logoUrl?, industry?}, source}`
  - `POST /api/enhancement/contacts/:id` — `{messageId, insights: {jobTitle?, phones?[], social?{linkedin?,twitter?,github?}}, source}`
- **Durability:** failures never change the flag; records stay `pending`, so a
  re-run of the enricher naturally retries. `source` is set to `"eldrin-enricher"`.

## Architecture

Rust binary crate: library + thin `main.rs` (units testable in isolation).

```
eldrin-enricher/
├── src/
│   ├── main.rs          # clap entry: `run --type contact|company|all --limit N --dry-run`
│   ├── config.rs        # TOML file + ELDRIN_* env overrides
│   ├── eldrin.rs        # CRM API client: pull pending / apply results
│   ├── llm.rs           # OpenAI-compatible chat client for llama.cpp
│   ├── fetch.rs         # Fetcher trait + DirectFetcher (v1 impl)
│   ├── extract.rs       # HTML → reduced text + mechanical metadata
│   ├── enrich/
│   │   ├── company.rs   # company pipeline
│   │   └── contact.rs   # contact pipeline
│   └── report.rs        # end-of-run summary
```

**Execution model:** sequential pipeline with bounded fetch concurrency. Web
fetches run 4–8 at a time; LLM calls run one at a time (a 31B model on one GPU
serializes anyway; parallel calls only thrash the KV cache). A job-queue/worker
pool was considered and rejected as overkill until `serve` mode exists.

### Component responsibilities

- **`eldrin.rs`** — typed client for the pull/apply endpoints. Base URL
  configurable (core-proxy path by default; direct CRM URL also works since the
  handlers self-gate on the same secret).
- **`llm.rs`** — OpenAI-compatible `/chat/completions` client. Replicates the
  convention of the workflows engine's `openai.ts` provider: JSON schema appended
  to the system prompt, `response_format: {type: "json_object"}`, response parsed
  into typed serde structs. One corrective retry on invalid JSON (re-prompt with
  the parse error).
- **`fetch.rs`** — `Fetcher` trait (async: domain → fetched documents). v1
  `DirectFetcher`: tries `https://<domain>`, falls back to `www.` and `http`;
  follows one `/about`-style link if the homepage links one. Timeouts and
  response-size caps from config.
- **`extract.rs`** — strips scripts/styles, keeps `<title>`/meta/og tags plus
  visible text, capped to a configurable text budget. **`logoUrl` is extracted
  mechanically from `og:image`/favicon — never asked of the LLM** — so it cannot
  be hallucinated.
- **`enrich/company.rs`** — `{id, name, domain}` → no domain? skip with reason →
  fetch + reduce → Gemma extracts `{name?, description?, industry?}` from page
  text only (prompt instructs: omit any field not evidenced by the text) → merge
  mechanical `logoUrl` → apply.
- **`enrich/contact.rs`** — pending item already carries the latest email body;
  no internet needed → Gemma extracts `{jobTitle?, phones?, social?}` → apply
  with the required `messageId`.
- **`report.rs`** — summary table: enhanced / skipped (no-domain, no-material) /
  failed (grouped by reason). `--dry-run` prints would-be payloads without
  applying.

## Error handling

- **Per-record isolation:** a fetch timeout, LLM garbage output, or apply 4xx is
  recorded for the summary and the run continues.
- **Typed errors** (`thiserror`) distinguishing: fetch failure, extraction empty,
  LLM transport error, LLM invalid output (after retry), apply rejection.
- **Preflight health checks** with actionable messages before any work: CRM/core
  reachable + secret accepted; llama.cpp reachable ("llama.cpp not reachable on
  :8080 — is llama-server running?").
- **Exit codes:** 0 when the run completes (even with per-record failures —
  they remain `pending` and are visible in the summary); non-zero only for setup
  failures (bad config, unreachable services).

## Configuration

`enricher.toml` + `ELDRIN_*` environment overrides (env wins). Checked-in
`enricher.example.toml`; the secret is env-only by recommendation and never
committed.

| Key | Default |
|-----|---------|
| `core_url` | `http://localhost:4000` |
| `app_secret` | — (from `JWT_SECRET`, env-only) |
| `llm.base_url` | `http://localhost:8080/v1` |
| `llm.model` | `gemma-4-31b` |
| `fetch.timeout_secs` | `15` |
| `fetch.concurrency` | `6` |
| `fetch.max_response_kb` | `1024` |
| `extract.text_budget_chars` | `24000` |
| `run.limit` | `25` |

## Testing

- **Unit tests:** HTML extraction/reduction, prompt building, LLM response
  parsing (valid, invalid, retry), config layering, report formatting.
- **Integration tests (`wiremock`):** mock CRM pull/apply and mock llama.cpp
  `/chat/completions`. Scenarios: happy path both record types, invalid-JSON
  then corrective retry, apply failure leaves record counted as failed,
  no-domain skip, dry-run posts nothing.
- **Optional ignored live test** against a real llama.cpp instance.
- CI: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`.
  Coverage target ≥ 80%.

**Stack:** Rust stable, tokio, reqwest (rustls), clap, serde, scraper,
thiserror, tracing.

## Deliberately out of scope (designed-for, not built)

- `serve` subcommand — small HTTP API (`POST /enrich`) so Eldrin apps can make
  on-demand enrichment requests; reuses the same core library.
- Search-engine sources (SearXNG local instance, commercial search APIs) as
  additional `Fetcher` implementations.
- Deal-suggestion assessment (stays on the eldrin-workflows path).
- Cron-hook registration (core-driven scheduling); v1 is user-invoked.
