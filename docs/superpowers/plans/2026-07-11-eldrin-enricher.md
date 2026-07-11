# eldrin-enricher Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A local Rust CLI (`eldrin-enricher run`) that pulls pending contacts/companies from Eldrin CRM, enriches them with a local Gemma LLM (llama.cpp, OpenAI-compatible, `localhost:8080/v1`) plus direct web fetch of company homepages, and applies results back through the shipped enhancement endpoints.

**Architecture:** Library crate + thin `main.rs`. Modules: `config` (TOML + env), `eldrin` (CRM pull/apply client), `llm` (chat-completions client, internally serialized), `fetch` (`Fetcher` trait + `DirectFetcher`), `extract` (HTML → reduced text + mechanical logo), `enrich::{company,contact}` (pipelines producing `Outcome`s), `report` (summary), `runner` (preflight + orchestration with bounded concurrency). All HTTP tested against `wiremock`; no test touches the real network.

**Tech Stack:** Rust stable (1.90 installed), edition 2021, tokio, reqwest (rustls), clap, serde/serde_json, toml, scraper, url, futures, async-trait, thiserror, tracing; dev: wiremock, tempfile.

**Spec:** `docs/superpowers/specs/2026-07-11-eldrin-enricher-design.md` (parent repo).

## Global Constraints

- New git repo `git@github.com:eldrin-project/eldrin-enricher.git`, added as submodule `eldrin-enricher` of `/Users/tibor/projects/eldrin-backup`.
- **Bash cwd persists between commands.** After any `cd` into the submodule, later parent-repo git commands are misdirected. Always use `git -C <absolute path>` or re-`cd` explicitly.
- Apply-payload `source` field is always the literal `"eldrin-enricher"`.
- Auth header is exactly `X-Eldrin-App-Secret`; value comes from env (`ELDRIN_APP_SECRET`, falling back to `JWT_SECRET`). The secret is NEVER committed — not in `enricher.example.toml`, not in tests, not in docs.
- LLM system-prompt convention must match the workflows engine's `openai.ts` verbatim instruction: `Respond with ONLY a JSON object conforming to this JSON schema (omit fields you are not confident about):` followed by the schema JSON, plus `response_format: {"type":"json_object"}`, `stream: false`.
- `logoUrl` is extracted mechanically (og:image / favicon) and NEVER taken from LLM output.
- Config defaults (spec table): `core_url=http://localhost:4000`, `llm.base_url=http://localhost:8080/v1`, `llm.model=gemma-4-31b`, `fetch.timeout_secs=15`, `fetch.concurrency=6`, `fetch.max_response_kb=1024`, `extract.text_budget_chars=24000`, `run.limit=25`.
- Exit code 0 when a run completes (even with per-record failures — they stay `pending` server-side); non-zero only for setup/preflight failures.
- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` must pass at every commit. Conventional commit messages. Files stay under 800 lines. Prefer constructing new values over mutating (struct-update syntax, `Iterator::collect`).
- Coverage target ≥ 80% lines (`cargo llvm-cov --fail-under-lines 80` locally if available; CI runs fmt/clippy/test).

---

### Task 1: Repo scaffold + config module

**Files:**
- Create: GitHub repo `eldrin-project/eldrin-enricher`, submodule at `/Users/tibor/projects/eldrin-backup/eldrin-enricher`
- Create: `eldrin-enricher/Cargo.toml`, `eldrin-enricher/.gitignore`, `eldrin-enricher/.github/workflows/ci.yml`, `eldrin-enricher/enricher.example.toml`
- Create: `eldrin-enricher/src/lib.rs`, `eldrin-enricher/src/main.rs` (stub), `eldrin-enricher/src/config.rs`

**Interfaces:**
- Produces: `Config` with public fields `core_url: String`, `app_secret: Option<String>`, `llm: LlmConfig {base_url, model}`, `fetch: FetchConfig {timeout_secs: u64, concurrency: usize, max_response_kb: usize}`, `extract: ExtractConfig {text_budget_chars: usize}`, `run: RunConfig {limit: u32}`; `Config::load(path: Option<&Path>) -> Result<Config, ConfigError>`; `Config::with_env_overrides(self, env: &HashMap<String, String>) -> Config`. Every later task consumes these exact names.

- [ ] **Step 1: Create the GitHub repo and submodule**

```bash
gh repo create eldrin-project/eldrin-enricher --private --description "Local LLM enrichment app for Eldrin CRM (Rust + llama.cpp)"
cd /Users/tibor/projects/eldrin-backup
git submodule add git@github.com:eldrin-project/eldrin-enricher.git eldrin-enricher
```

Expected: submodule dir exists (git warns it cloned an empty repo — fine). Do NOT commit the parent repo yet (that is Task 10).

- [ ] **Step 2: Scaffold the crate**

`eldrin-enricher/Cargo.toml`:

```toml
[package]
name = "eldrin-enricher"
version = "0.1.0"
edition = "2021"
description = "Local LLM enrichment app for Eldrin CRM"
publish = false

[dependencies]
async-trait = "0.1"
clap = { version = "4", features = ["derive"] }
futures = "0.3"
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls", "gzip"] }
scraper = "0.20"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "sync"] }
toml = "0.8"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
url = "2"

[dev-dependencies]
tempfile = "3"
wiremock = "0.6"
```

`eldrin-enricher/.gitignore`:

```
/target
enricher.toml
.env
```

`eldrin-enricher/src/lib.rs`:

```rust
pub mod config;
```

`eldrin-enricher/src/main.rs` (stub, replaced in Task 9):

```rust
fn main() {
    println!("eldrin-enricher: CLI wired in Task 9");
}
```

`eldrin-enricher/.github/workflows/ci.yml`:

```yaml
name: CI
on:
  push:
    branches: [main]
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - uses: Swatinem/rust-cache@v2
      - run: cargo fmt --check
      - run: cargo clippy --all-targets -- -D warnings
      - run: cargo test
```

`eldrin-enricher/enricher.example.toml`:

```toml
# Copy to enricher.toml (gitignored) and adjust. Every key is optional;
# defaults shown. The service secret is env-only by design:
#   export ELDRIN_APP_SECRET=<JWT_SECRET value from eldrin-core/.dev.vars>

core_url = "http://localhost:4000"

[llm]
base_url = "http://localhost:8080/v1"
model = "gemma-4-31b"

[fetch]
timeout_secs = 15
concurrency = 6
max_response_kb = 1024

[extract]
text_budget_chars = 24000

[run]
limit = 25
```

- [ ] **Step 3: Write the failing config tests**

Append to `eldrin-enricher/src/config.rs` (create the file with ONLY this test module for the RED step; the implementation code in Step 5 goes above it):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn defaults_match_spec() {
        let cfg = Config::default();
        assert_eq!(cfg.core_url, "http://localhost:4000");
        assert_eq!(cfg.app_secret, None);
        assert_eq!(cfg.llm.base_url, "http://localhost:8080/v1");
        assert_eq!(cfg.llm.model, "gemma-4-31b");
        assert_eq!(cfg.fetch.timeout_secs, 15);
        assert_eq!(cfg.fetch.concurrency, 6);
        assert_eq!(cfg.fetch.max_response_kb, 1024);
        assert_eq!(cfg.extract.text_budget_chars, 24000);
        assert_eq!(cfg.run.limit, 25);
    }

    #[test]
    fn partial_toml_overrides_only_named_keys() {
        let cfg: Config =
            toml::from_str("core_url = \"http://other:9999\"\n[llm]\nmodel = \"other-model\"")
                .expect("valid toml");
        assert_eq!(cfg.core_url, "http://other:9999");
        assert_eq!(cfg.llm.model, "other-model");
        // untouched keys keep defaults
        assert_eq!(cfg.llm.base_url, "http://localhost:8080/v1");
        assert_eq!(cfg.run.limit, 25);
    }

    #[test]
    fn unknown_toml_key_is_rejected() {
        let err = toml::from_str::<Config>("nonsense = 1").unwrap_err();
        assert!(err.to_string().contains("nonsense"));
    }

    #[test]
    fn env_overrides_win_and_jwt_secret_is_fallback() {
        let env: HashMap<String, String> = [
            ("ELDRIN_CORE_URL", "http://env:4000"),
            ("ELDRIN_LLM_BASE_URL", "http://env:8080/v1"),
            ("ELDRIN_LLM_MODEL", "env-model"),
            ("ELDRIN_RUN_LIMIT", "7"),
            ("JWT_SECRET", "jwt-fallback"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let cfg = Config::default().with_env_overrides(&env);
        assert_eq!(cfg.core_url, "http://env:4000");
        assert_eq!(cfg.llm.base_url, "http://env:8080/v1");
        assert_eq!(cfg.llm.model, "env-model");
        assert_eq!(cfg.run.limit, 7);
        assert_eq!(cfg.app_secret.as_deref(), Some("jwt-fallback"));
    }

    #[test]
    fn eldrin_app_secret_beats_jwt_secret() {
        let env: HashMap<String, String> = [
            ("ELDRIN_APP_SECRET", "primary"),
            ("JWT_SECRET", "fallback"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let cfg = Config::default().with_env_overrides(&env);
        assert_eq!(cfg.app_secret.as_deref(), Some("primary"));
    }

    #[test]
    fn empty_env_values_are_ignored() {
        let env: HashMap<String, String> =
            [("ELDRIN_CORE_URL".to_string(), String::new())].into_iter().collect();
        let cfg = Config::default().with_env_overrides(&env);
        assert_eq!(cfg.core_url, "http://localhost:4000");
    }

    #[test]
    fn load_reads_explicit_file_and_errors_on_missing_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("enricher.toml");
        std::fs::write(&path, "[run]\nlimit = 3\n").expect("write");
        let cfg = Config::load(Some(&path)).expect("loads");
        assert_eq!(cfg.run.limit, 3);

        let missing = dir.path().join("nope.toml");
        assert!(Config::load(Some(&missing)).is_err());
    }
}
```

- [ ] **Step 4: Run tests to verify they fail**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-enricher && cargo test
```

Expected: compile FAILURE — `Config` not defined.

- [ ] **Step 5: Implement `config.rs`**

Add above the test module in `eldrin-enricher/src/config.rs`:

```rust
//! Layered configuration: built-in defaults <- optional TOML file <- ELDRIN_* env vars.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config file: {0}")]
    Parse(#[from] toml::de::Error),
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub core_url: String,
    pub app_secret: Option<String>,
    pub llm: LlmConfig,
    pub fetch: FetchConfig,
    pub extract: ExtractConfig,
    pub run: RunConfig,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LlmConfig {
    pub base_url: String,
    pub model: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FetchConfig {
    pub timeout_secs: u64,
    pub concurrency: usize,
    pub max_response_kb: usize,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExtractConfig {
    pub text_budget_chars: usize,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RunConfig {
    pub limit: u32,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            core_url: "http://localhost:4000".to_string(),
            app_secret: None,
            llm: LlmConfig::default(),
            fetch: FetchConfig::default(),
            extract: ExtractConfig::default(),
            run: RunConfig::default(),
        }
    }
}

impl Default for LlmConfig {
    fn default() -> Self {
        LlmConfig {
            base_url: "http://localhost:8080/v1".to_string(),
            model: "gemma-4-31b".to_string(),
        }
    }
}

impl Default for FetchConfig {
    fn default() -> Self {
        FetchConfig { timeout_secs: 15, concurrency: 6, max_response_kb: 1024 }
    }
}

impl Default for ExtractConfig {
    fn default() -> Self {
        ExtractConfig { text_budget_chars: 24_000 }
    }
}

impl Default for RunConfig {
    fn default() -> Self {
        RunConfig { limit: 25 }
    }
}

impl Config {
    /// Load config: explicit path (error if missing) or `./enricher.toml` if
    /// present, else defaults — then apply process env overrides.
    pub fn load(path: Option<&Path>) -> Result<Config, ConfigError> {
        let base = match path {
            Some(p) => {
                let raw = std::fs::read_to_string(p).map_err(|source| ConfigError::Read {
                    path: p.display().to_string(),
                    source,
                })?;
                toml::from_str(&raw)?
            }
            None => match std::fs::read_to_string("enricher.toml") {
                Ok(raw) => toml::from_str(&raw)?,
                Err(_) => Config::default(),
            },
        };
        let env: HashMap<String, String> = std::env::vars().collect();
        Ok(base.with_env_overrides(&env))
    }

    /// Returns a new Config with non-empty ELDRIN_* env values applied.
    /// `ELDRIN_APP_SECRET` wins over `JWT_SECRET` for the service secret.
    pub fn with_env_overrides(self, env: &HashMap<String, String>) -> Config {
        let get = |key: &str| env.get(key).filter(|v| !v.is_empty()).cloned();
        Config {
            core_url: get("ELDRIN_CORE_URL").unwrap_or(self.core_url),
            app_secret: get("ELDRIN_APP_SECRET")
                .or_else(|| get("JWT_SECRET"))
                .or(self.app_secret),
            llm: LlmConfig {
                base_url: get("ELDRIN_LLM_BASE_URL").unwrap_or(self.llm.base_url),
                model: get("ELDRIN_LLM_MODEL").unwrap_or(self.llm.model),
            },
            fetch: self.fetch,
            extract: self.extract,
            run: RunConfig {
                limit: get("ELDRIN_RUN_LIMIT")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(self.run.limit),
            },
        }
    }
}
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-enricher && cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test
```

Expected: 7 tests PASS, clippy clean.

- [ ] **Step 7: Commit and push the initial main branch**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-enricher add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-enricher commit -m "feat: scaffold crate with layered config (TOML + env overrides)"
git -C /Users/tibor/projects/eldrin-backup/eldrin-enricher push -u origin main
```

---

### Task 2: Eldrin CRM client (`eldrin.rs`)

**Files:**
- Create: `eldrin-enricher/src/eldrin.rs`
- Modify: `eldrin-enricher/src/lib.rs` (add `pub mod eldrin;`)
- Test: inline `#[cfg(test)]` module using wiremock

**Interfaces:**
- Consumes: nothing from other tasks (constructed from `&str`/`Option<String>`, not `Config`, so tests stay simple).
- Produces:
  - `SOURCE: &str = "eldrin-enricher"`
  - `enum PendingItem { Contact(PendingContact), Company(PendingCompany) }` (serde internally tagged on `"type"`, lowercase)
  - `PendingContact { id: String, first_name: Option<String>, last_name: Option<String>, message_id: Option<String>, from: Option<String>, body_text: Option<String> }` (camelCase on the wire)
  - `PendingCompany { id: String, name: String, domain: Option<String> }`
  - `CompanyEnrichment { name, description, logo_url, industry: Option<String> }` (Serialize+Deserialize, camelCase, skip-none, `Default`, ignores unknown JSON keys)
  - `ContactInsights { job_title: Option<String>, phones: Vec<String>, social: Option<SocialLinks> }`, `SocialLinks { linkedin, twitter, github: Option<String> }` (same derives)
  - `EldrinClient::new(core_url: &str, secret: Option<String>, timeout_secs: u64) -> Result<Self, EldrinError>`
  - `async fn pull_pending(&self, record_type: Option<&str>, limit: u32, offset: u32) -> Result<Vec<PendingItem>, EldrinError>`
  - `async fn apply_company(&self, id: &str, data: &CompanyEnrichment) -> Result<Vec<String>, EldrinError>` (returns the server's `applied` list)
  - `async fn apply_contact(&self, id: &str, message_id: &str, insights: &ContactInsights) -> Result<Vec<String>, EldrinError>`
  - `async fn health_check(&self) -> Result<(), EldrinError>` (GET pending with `limit=1`)
  - `enum EldrinError { Transport(reqwest::Error), Api { status: u16, body: String } }` (thiserror)

**Wire contract (verified against `eldrin-crm/worker/routes/enhancement.ts`):**
- Base URL: `{core_url}/api/app/eldrin-crm`; endpoints under it: `/api/enhancement/pending`, `/api/enhancement/companies/:id`, `/api/enhancement/contacts/:id`. The core proxy strips/re-adds the `api/` prefix and forwards to the CRM worker.
- Header `X-Eldrin-App-Secret: <secret>` on EVERY request when a secret is configured.
- Pending response: `{"items": [...], "limit": n, "offset": n}`. Contact items spread `latestEmailMaterial` INTO the item (`messageId`, `from`, `bodyText` — absent entirely when the contact has no material). Company items: `{"type":"company","id","name","domain"}`.
- Apply company body: `{"data": {"name"?, "description"?, "logoUrl"?, "industry"?}, "source": "eldrin-enricher"}` → response `{"company": {...}, "applied": ["name", ...]}`.
- Apply contact body: `{"messageId": "...", "insights": {"jobTitle"?, "phones"?: [...], "social"?: {"linkedin"?, "twitter"?, "github"?}}, "source": "eldrin-enricher"}` → response `{"contact": {...}, "applied": [...]}`.

- [ ] **Step 1: Write the failing tests**

Create `eldrin-enricher/src/eldrin.rs` containing only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{body_partial_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client(server: &MockServer) -> EldrinClient {
        EldrinClient::new(&server.uri(), Some("s3cret".to_string()), 5).expect("client")
    }

    #[tokio::test]
    async fn pull_pending_parses_mixed_items_and_skips_unknown_types() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/app/eldrin-crm/api/enhancement/pending"))
            .and(header("X-Eldrin-App-Secret", "s3cret"))
            .and(query_param("limit", "25"))
            .and(query_param("offset", "0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [
                    {"type": "contact", "id": "ct1", "firstName": "Jane", "lastName": "Doe",
                     "messageId": "m1", "from": "jane@acme.com", "bodyText": "Hi\n--\nJane, CTO"},
                    {"type": "contact", "id": "ct2", "firstName": "No", "lastName": "Material"},
                    {"type": "company", "id": "co1", "name": "acme.com", "domain": "acme.com"},
                    {"type": "wormhole", "id": "??"}
                ],
                "limit": 25, "offset": 0
            })))
            .mount(&server)
            .await;

        let items = client(&server).pull_pending(None, 25, 0).await.expect("pull");
        assert_eq!(items.len(), 3); // unknown "wormhole" item skipped, not fatal
        match &items[0] {
            PendingItem::Contact(c) => {
                assert_eq!(c.id, "ct1");
                assert_eq!(c.message_id.as_deref(), Some("m1"));
                assert_eq!(c.body_text.as_deref(), Some("Hi\n--\nJane, CTO"));
            }
            other => panic!("expected contact, got {other:?}"),
        }
        match &items[1] {
            PendingItem::Contact(c) => assert_eq!(c.message_id, None),
            other => panic!("expected contact, got {other:?}"),
        }
        match &items[2] {
            PendingItem::Company(c) => assert_eq!(c.domain.as_deref(), Some("acme.com")),
            other => panic!("expected company, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn pull_pending_forwards_type_filter() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/app/eldrin-crm/api/enhancement/pending"))
            .and(query_param("type", "company"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"items": [], "limit": 25, "offset": 0})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let items = client(&server).pull_pending(Some("company"), 25, 0).await.expect("pull");
        assert!(items.is_empty());
    }

    #[tokio::test]
    async fn apply_company_sends_contract_body_and_returns_applied() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/app/eldrin-crm/api/enhancement/companies/co1"))
            .and(header("X-Eldrin-App-Secret", "s3cret"))
            .and(body_partial_json(json!({
                "data": {"name": "Acme Corp", "description": "Widgets.",
                          "logoUrl": "https://acme.com/logo.png", "industry": "Manufacturing"},
                "source": "eldrin-enricher"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "company": {"id": "co1"}, "applied": ["name", "notes", "logoUrl", "industry"]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let data = CompanyEnrichment {
            name: Some("Acme Corp".to_string()),
            description: Some("Widgets.".to_string()),
            logo_url: Some("https://acme.com/logo.png".to_string()),
            industry: Some("Manufacturing".to_string()),
        };
        let applied = client(&server).apply_company("co1", &data).await.expect("apply");
        assert_eq!(applied, vec!["name", "notes", "logoUrl", "industry"]);
    }

    #[tokio::test]
    async fn company_enrichment_serializes_none_fields_away() {
        let data = CompanyEnrichment { name: Some("A".to_string()), ..Default::default() };
        let value = serde_json::to_value(&data).expect("json");
        assert_eq!(value, json!({"name": "A"}));
    }

    #[tokio::test]
    async fn apply_contact_sends_message_id_and_insights() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/app/eldrin-crm/api/enhancement/contacts/ct1"))
            .and(body_partial_json(json!({
                "messageId": "m1",
                "insights": {"jobTitle": "CTO", "phones": ["+361234567"],
                              "social": {"linkedin": "https://linkedin.com/in/jane"}},
                "source": "eldrin-enricher"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "contact": {"id": "ct1"}, "applied": ["signature-fields"]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let insights = ContactInsights {
            job_title: Some("CTO".to_string()),
            phones: vec!["+361234567".to_string()],
            social: Some(SocialLinks {
                linkedin: Some("https://linkedin.com/in/jane".to_string()),
                ..Default::default()
            }),
        };
        let applied = client(&server).apply_contact("ct1", "m1", &insights).await.expect("apply");
        assert_eq!(applied, vec!["signature-fields"]);
    }

    #[tokio::test]
    async fn non_2xx_surfaces_status_and_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/app/eldrin-crm/api/enhancement/pending"))
            .respond_with(
                ResponseTemplate::new(401).set_body_json(json!({"error": "Invalid service secret"})),
            )
            .mount(&server)
            .await;
        let err = client(&server).pull_pending(None, 25, 0).await.unwrap_err();
        match err {
            EldrinError::Api { status, body } => {
                assert_eq!(status, 401);
                assert!(body.contains("Invalid service secret"));
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn health_check_hits_pending_with_limit_1() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/app/eldrin-crm/api/enhancement/pending"))
            .and(query_param("limit", "1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"items": [], "limit": 1, "offset": 0})),
            )
            .expect(1)
            .mount(&server)
            .await;
        client(&server).health_check().await.expect("healthy");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-enricher && cargo test eldrin
```

Expected: compile FAILURE — `EldrinClient` etc. not defined. (Also add `pub mod eldrin;` to `src/lib.rs` now.)

- [ ] **Step 3: Implement `eldrin.rs`**

Add above the test module:

```rust
//! Typed client for the Eldrin CRM enhancement contract, reached through the
//! eldrin-core app proxy ({core_url}/api/app/eldrin-crm/...). Auth is the
//! shared service secret in the X-Eldrin-App-Secret header.

use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

/// Value of the `source` field on every apply payload.
pub const SOURCE: &str = "eldrin-enricher";

#[derive(Debug, Error)]
pub enum EldrinError {
    #[error("transport error talking to Eldrin: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("Eldrin API returned HTTP {status}: {body}")]
    Api { status: u16, body: String },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum PendingItem {
    Contact(PendingContact),
    Company(PendingCompany),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingContact {
    pub id: String,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    /// Present only when the contact has captured email material.
    #[serde(default)]
    pub message_id: Option<String>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub body_text: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PendingCompany {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub domain: Option<String>,
}

/// Company apply payload. `logo_url` is only ever set mechanically from page
/// metadata (og:image/favicon), never from LLM output.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompanyEnrichment {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub industry: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactInsights {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_title: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub phones: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub social: Option<SocialLinks>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SocialLinks {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linkedin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub twitter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub github: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PendingResponse {
    items: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct ApplyResponse {
    #[serde(default)]
    applied: Vec<String>,
}

#[derive(Serialize)]
struct ApplyCompanyBody<'a> {
    data: &'a CompanyEnrichment,
    source: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApplyContactBody<'a> {
    message_id: &'a str,
    insights: &'a ContactInsights,
    source: &'a str,
}

pub struct EldrinClient {
    http: reqwest::Client,
    base_url: String,
    secret: Option<String>,
}

impl EldrinClient {
    pub fn new(
        core_url: &str,
        secret: Option<String>,
        timeout_secs: u64,
    ) -> Result<Self, EldrinError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()?;
        Ok(EldrinClient {
            http,
            base_url: format!("{}/api/app/eldrin-crm", core_url.trim_end_matches('/')),
            secret,
        })
    }

    fn request(&self, method: Method, endpoint: &str) -> reqwest::RequestBuilder {
        let builder = self.http.request(method, format!("{}{endpoint}", self.base_url));
        match &self.secret {
            Some(secret) => builder.header("X-Eldrin-App-Secret", secret),
            None => builder,
        }
    }

    async fn expect_success(response: reqwest::Response) -> Result<reqwest::Response, EldrinError> {
        let status = response.status();
        if status.is_success() {
            Ok(response)
        } else {
            Err(EldrinError::Api {
                status: status.as_u16(),
                body: response.text().await.unwrap_or_default(),
            })
        }
    }

    pub async fn pull_pending(
        &self,
        record_type: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<PendingItem>, EldrinError> {
        let base = self
            .request(Method::GET, "/api/enhancement/pending")
            .query(&[("limit", limit.to_string()), ("offset", offset.to_string())]);
        let request = match record_type {
            Some(t) => base.query(&[("type", t)]),
            None => base,
        };
        let response = Self::expect_success(request.send().await?).await?;
        let page: PendingResponse = response.json().await?;
        // Item-level tolerance: one unrecognized item must not fail the run.
        let items = page
            .items
            .into_iter()
            .filter_map(|value| match serde_json::from_value::<PendingItem>(value) {
                Ok(item) => Some(item),
                Err(err) => {
                    tracing::warn!("skipping unparseable pending item: {err}");
                    None
                }
            })
            .collect();
        Ok(items)
    }

    pub async fn apply_company(
        &self,
        id: &str,
        data: &CompanyEnrichment,
    ) -> Result<Vec<String>, EldrinError> {
        let response = self
            .request(Method::POST, &format!("/api/enhancement/companies/{id}"))
            .json(&ApplyCompanyBody { data, source: SOURCE })
            .send()
            .await?;
        let response = Self::expect_success(response).await?;
        let parsed: ApplyResponse = response.json().await?;
        Ok(parsed.applied)
    }

    pub async fn apply_contact(
        &self,
        id: &str,
        message_id: &str,
        insights: &ContactInsights,
    ) -> Result<Vec<String>, EldrinError> {
        let response = self
            .request(Method::POST, &format!("/api/enhancement/contacts/{id}"))
            .json(&ApplyContactBody { message_id, insights, source: SOURCE })
            .send()
            .await?;
        let response = Self::expect_success(response).await?;
        let parsed: ApplyResponse = response.json().await?;
        Ok(parsed.applied)
    }

    /// Preflight: proves the stack is reachable AND the secret is accepted.
    pub async fn health_check(&self) -> Result<(), EldrinError> {
        let response = self
            .request(Method::GET, "/api/enhancement/pending")
            .query(&[("limit", "1"), ("offset", "0")])
            .send()
            .await?;
        Self::expect_success(response).await.map(|_| ())
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-enricher && cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test
```

Expected: all tests PASS (7 config + 7 eldrin).

- [ ] **Step 5: Commit**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-enricher add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-enricher commit -m "feat: Eldrin CRM client for the enhancement pull/apply contract"
```

---

### Task 3: LLM client (`llm.rs`)

**Files:**
- Create: `eldrin-enricher/src/llm.rs`
- Modify: `eldrin-enricher/src/lib.rs` (add `pub mod llm;`)

**Interfaces:**
- Consumes: `crate::config::LlmConfig`.
- Produces:
  - `LlmClient::new(config: &LlmConfig, timeout_secs: u64) -> Result<Self, LlmError>`
  - `async fn extract<T: DeserializeOwned>(&self, prompt: &str, input: &str, schema: &serde_json::Value) -> Result<T, LlmError>` — schema-in-system-prompt convention, one corrective retry on unparseable output
  - `async fn health_check(&self) -> Result<(), LlmError>` (GET `{base_url}/models`)
  - `enum LlmError { Transport(reqwest::Error), Api { status: u16, body: String }, NoContent, InvalidOutput(String) }`
  - Internal: calls are serialized through a 1-permit `tokio::sync::Semaphore` — a 31B model on one GPU gains nothing from parallel requests, and this lets the runner use one concurrency setting for the whole pipeline.

- [ ] **Step 1: Write the failing tests**

Create `eldrin-enricher/src/llm.rs` with only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LlmConfig;
    use serde::Deserialize;
    use serde_json::json;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    #[derive(Debug, PartialEq, Deserialize)]
    struct Toy {
        answer: String,
    }

    fn client(server: &MockServer) -> LlmClient {
        let config = LlmConfig {
            base_url: format!("{}/v1", server.uri()),
            model: "gemma-4-31b".to_string(),
        };
        LlmClient::new(&config, 5).expect("client")
    }

    fn chat_response(content: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"role": "assistant", "content": content}}]
        }))
    }

    #[tokio::test]
    async fn extract_builds_openai_convention_request_and_parses_content() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(body_partial_json(json!({
                "model": "gemma-4-31b",
                "response_format": {"type": "json_object"},
                "stream": false
            })))
            .respond_with(chat_response(r#"{"answer": "42"}"#))
            .expect(1)
            .mount(&server)
            .await;

        let result: Toy = client(&server)
            .extract("Answer the question.", "meaning of life?", &json!({"type": "object"}))
            .await
            .expect("extract");
        assert_eq!(result, Toy { answer: "42".to_string() });

        // System message must carry the exact instruction + schema, user message the input.
        let requests = server.received_requests().await.expect("requests");
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).expect("body");
        let messages = body["messages"].as_array().expect("messages");
        assert_eq!(messages.len(), 2);
        let system = messages[0]["content"].as_str().expect("system");
        assert!(system.starts_with("Answer the question."));
        assert!(system.contains(
            "Respond with ONLY a JSON object conforming to this JSON schema \
             (omit fields you are not confident about):"
        ));
        assert!(system.contains(r#"{"type":"object"}"#));
        assert_eq!(messages[1]["content"], "meaning of life?");
    }

    #[tokio::test]
    async fn extract_strips_markdown_fences() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(chat_response("```json\n{\"answer\": \"fenced\"}\n```"))
            .mount(&server)
            .await;
        let result: Toy = client(&server)
            .extract("p", "i", &json!({}))
            .await
            .expect("extract");
        assert_eq!(result.answer, "fenced");
    }

    #[tokio::test]
    async fn extract_retries_once_with_corrective_message_on_bad_json() {
        let server = MockServer::start().await;
        // First call: garbage. Retry call (4 messages incl. corrective): valid.
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(move |request: &Request| {
                let body: serde_json::Value =
                    serde_json::from_slice(&request.body).expect("body");
                let count = body["messages"].as_array().expect("messages").len();
                if count == 2 {
                    chat_response("not json at all")
                } else {
                    chat_response(r#"{"answer": "recovered"}"#)
                }
            })
            .expect(2)
            .mount(&server)
            .await;

        let result: Toy = client(&server)
            .extract("p", "i", &json!({}))
            .await
            .expect("extract with retry");
        assert_eq!(result.answer, "recovered");
    }

    #[tokio::test]
    async fn extract_fails_after_second_bad_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(chat_response("still not json"))
            .expect(2)
            .mount(&server)
            .await;
        let err = client(&server)
            .extract::<Toy>("p", "i", &json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, LlmError::InvalidOutput(_)));
    }

    #[tokio::test]
    async fn http_error_surfaces_status() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;
        let err = client(&server)
            .extract::<Toy>("p", "i", &json!({}))
            .await
            .unwrap_err();
        match err {
            LlmError::Api { status, .. } => assert_eq!(status, 500),
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn health_check_hits_models() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
            .expect(1)
            .mount(&server)
            .await;
        client(&server).health_check().await.expect("healthy");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-enricher && cargo test llm
```

Expected: compile FAILURE — `LlmClient` not defined. (Add `pub mod llm;` to `src/lib.rs`.)

- [ ] **Step 3: Implement `llm.rs`**

```rust
//! OpenAI-compatible chat-completions client for the local llama.cpp server.
//! Mirrors the eldrin-workflows openai.ts provider convention: JSON schema
//! appended to the system prompt, response_format json_object, stream false.

use crate::config::LlmConfig;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Semaphore;

/// Must stay byte-identical to the instruction in eldrin-workflows openai.ts.
const JSON_INSTRUCTION: &str = "Respond with ONLY a JSON object conforming to this JSON schema (omit fields you are not confident about):";

#[derive(Debug, Error)]
pub enum LlmError {
    #[error("transport error talking to LLM: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("LLM endpoint returned HTTP {status}: {body}")]
    Api { status: u16, body: String },
    #[error("LLM response had no message content")]
    NoContent,
    #[error("LLM output was not valid JSON for the schema after retry: {0}")]
    InvalidOutput(String),
}

pub struct LlmClient {
    http: reqwest::Client,
    base_url: String,
    model: String,
    /// One permit: a 31B model on a single GPU serializes anyway; parallel
    /// requests only thrash the KV cache. Lets the runner parallelize fetches
    /// freely while LLM calls queue here.
    lock: Arc<Semaphore>,
}

impl LlmClient {
    pub fn new(config: &LlmConfig, timeout_secs: u64) -> Result<Self, LlmError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()?;
        Ok(LlmClient {
            http,
            base_url: config.base_url.trim_end_matches('/').to_string(),
            model: config.model.clone(),
            lock: Arc::new(Semaphore::new(1)),
        })
    }

    /// Extract a `T` from `input` guided by `prompt` and a JSON schema.
    /// One corrective retry when the model's output fails to parse.
    pub async fn extract<T: DeserializeOwned>(
        &self,
        prompt: &str,
        input: &str,
        schema: &Value,
    ) -> Result<T, LlmError> {
        let system = format!("{prompt}\n\n{JSON_INSTRUCTION}\n{schema}");
        let messages = vec![
            json!({"role": "system", "content": system}),
            json!({"role": "user", "content": input}),
        ];
        let content = self.chat(&messages).await?;
        match parse_json_output::<T>(&content) {
            Ok(value) => Ok(value),
            Err(parse_err) => {
                let corrective = format!(
                    "Your previous response was not a valid JSON object for the schema \
                     ({parse_err}). Respond again with ONLY the JSON object."
                );
                let retry_messages = [
                    messages,
                    vec![
                        json!({"role": "assistant", "content": content}),
                        json!({"role": "user", "content": corrective}),
                    ],
                ]
                .concat();
                let retry = self.chat(&retry_messages).await?;
                parse_json_output::<T>(&retry)
                    .map_err(|err| LlmError::InvalidOutput(err.to_string()))
            }
        }
    }

    async fn chat(&self, messages: &[Value]) -> Result<String, LlmError> {
        let _permit = self.lock.acquire().await.expect("semaphore never closed");
        let response = self
            .http
            .post(format!("{}/chat/completions", self.base_url))
            .json(&json!({
                "model": self.model,
                "messages": messages,
                "response_format": {"type": "json_object"},
                "stream": false,
            }))
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            return Err(LlmError::Api {
                status: status.as_u16(),
                body: response.text().await.unwrap_or_default(),
            });
        }
        let body: Value = response.json().await?;
        body["choices"][0]["message"]["content"]
            .as_str()
            .map(str::to_string)
            .ok_or(LlmError::NoContent)
    }

    /// Preflight: llama.cpp serves GET /v1/models when up.
    pub async fn health_check(&self) -> Result<(), LlmError> {
        let response = self.http.get(format!("{}/models", self.base_url)).send().await?;
        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(LlmError::Api {
                status: status.as_u16(),
                body: response.text().await.unwrap_or_default(),
            })
        }
    }
}

/// Parse model output as JSON, tolerating ```json fences some models emit.
fn parse_json_output<T: DeserializeOwned>(content: &str) -> Result<T, serde_json::Error> {
    let trimmed = content.trim();
    let unfenced = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .map(|rest| rest.trim_end_matches("```"))
        .unwrap_or(trimmed);
    serde_json::from_str(unfenced.trim())
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-enricher && cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test
```

Expected: all PASS. Note: the closure-based `respond_with` requires `wiremock`'s `Respond` impl for closures — write `.respond_with(move |request: &Request| { ... })`; if the closure form gives type trouble, replace with `Mock::given(...).and(body_partial_json(...))` pairs using `.up_to_n_times(1)` for the first response instead.

- [ ] **Step 5: Commit**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-enricher add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-enricher commit -m "feat: serialized OpenAI-compatible LLM client with corrective retry"
```

---

### Task 4: HTML reduction (`extract.rs`)

**Files:**
- Create: `eldrin-enricher/src/extract.rs`
- Modify: `eldrin-enricher/src/lib.rs` (add `pub mod extract;`)

**Interfaces:**
- Consumes: nothing (pure functions).
- Produces:
  - `PageContent { text: String, logo_url: Option<String>, about_url: Option<String> }`
  - `pub fn reduce_html(html: &str, base_url: &str, text_budget_chars: usize) -> PageContent`
  - Guarantees: script/style/noscript/svg/template text excluded; text begins with `Title:`/meta lines when present; `logo_url` from `og:image` else `link rel*=icon`, resolved absolute, http(s) only; `about_url` is the first same-host `<a>` whose href or text contains "about" (case-insensitive); `text` is truncated at a char boundary to the budget.

- [ ] **Step 1: Write the failing tests**

Create `eldrin-enricher/src/extract.rs` with only:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = r#"<!doctype html>
<html><head>
  <title>Acme Corp — Widgets</title>
  <meta name="description" content="Acme builds industrial widgets.">
  <meta property="og:image" content="/assets/logo.png">
  <script>var hidden = "SCRIPT_NOISE";</script>
  <style>.x { color: red }</style>
</head>
<body>
  <nav><a href="/about-us">About us</a><a href="mailto:x@acme.com">Mail</a></nav>
  <h1>Widgets for the modern factory</h1>
  <script>console.log("MORE_NOISE")</script>
  <p>Since 1999 we ship widgets worldwide.</p>
</body></html>"#;

    #[test]
    fn extracts_title_meta_and_visible_text_without_script_noise() {
        let content = reduce_html(PAGE, "https://acme.com", 24_000);
        assert!(content.text.contains("Title: Acme Corp — Widgets"));
        assert!(content.text.contains("description: Acme builds industrial widgets."));
        assert!(content.text.contains("Widgets for the modern factory"));
        assert!(content.text.contains("Since 1999 we ship widgets worldwide."));
        assert!(!content.text.contains("SCRIPT_NOISE"));
        assert!(!content.text.contains("MORE_NOISE"));
        assert!(!content.text.contains("color: red"));
    }

    #[test]
    fn logo_from_og_image_resolved_against_base() {
        let content = reduce_html(PAGE, "https://acme.com", 24_000);
        assert_eq!(content.logo_url.as_deref(), Some("https://acme.com/assets/logo.png"));
    }

    #[test]
    fn logo_falls_back_to_icon_link() {
        let html = r#"<html><head>
            <link rel="shortcut icon" href="https://cdn.acme.com/favicon.ico">
            </head><body>x</body></html>"#;
        let content = reduce_html(html, "https://acme.com", 24_000);
        assert_eq!(content.logo_url.as_deref(), Some("https://cdn.acme.com/favicon.ico"));
    }

    #[test]
    fn no_logo_when_absent() {
        let content = reduce_html("<html><body>plain</body></html>", "https://acme.com", 24_000);
        assert_eq!(content.logo_url, None);
    }

    #[test]
    fn about_link_same_host_resolved() {
        let content = reduce_html(PAGE, "https://acme.com", 24_000);
        assert_eq!(content.about_url.as_deref(), Some("https://acme.com/about-us"));
    }

    #[test]
    fn about_link_ignores_other_hosts_and_non_http() {
        let html = r#"<html><body>
            <a href="https://elsewhere.com/about">About</a>
            <a href="mailto:about@acme.com">about</a>
            </body></html>"#;
        let content = reduce_html(html, "https://acme.com", 24_000);
        assert_eq!(content.about_url, None);
    }

    #[test]
    fn text_budget_truncates_on_char_boundary() {
        let html = format!("<html><body>{}</body></html>", "é".repeat(100));
        let content = reduce_html(&html, "https://acme.com", 10);
        assert_eq!(content.text.chars().count(), 10);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-enricher && cargo test extract
```

Expected: compile FAILURE. (Add `pub mod extract;` to `src/lib.rs`.)

- [ ] **Step 3: Implement `extract.rs`**

```rust
//! HTML → reduced text for LLM input, plus mechanically extracted metadata.
//! The logo URL comes ONLY from og:image / icon links (never the LLM), so it
//! cannot be hallucinated.

use scraper::{ElementRef, Html, Selector};
use url::Url;

#[derive(Debug, Clone, PartialEq)]
pub struct PageContent {
    pub text: String,
    pub logo_url: Option<String>,
    pub about_url: Option<String>,
}

const SKIP_TAGS: [&str; 5] = ["script", "style", "noscript", "svg", "template"];
const META_KEYS: [&str; 4] = ["description", "og:title", "og:description", "og:site_name"];

fn sel(selector: &str) -> Selector {
    Selector::parse(selector).expect("static selector is valid")
}

pub fn reduce_html(html: &str, base_url: &str, text_budget_chars: usize) -> PageContent {
    let doc = Html::parse_document(html);
    let base = Url::parse(base_url).ok();

    let title_line = doc
        .select(&sel("title"))
        .next()
        .map(|t| format!("Title: {}", collapse_ws(&t.text().collect::<String>())));
    let meta_lines: Vec<String> = doc
        .select(&sel("meta[content]"))
        .filter_map(|meta| {
            let key = meta
                .value()
                .attr("name")
                .or_else(|| meta.value().attr("property"))?;
            let content = meta.value().attr("content")?;
            META_KEYS
                .contains(&key)
                .then(|| format!("{key}: {}", collapse_ws(content)))
        })
        .collect();
    let body_text = doc.select(&sel("body")).next().map(|body| visible_text(body));

    let lines: Vec<String> = title_line
        .into_iter()
        .chain(meta_lines)
        .chain(body_text)
        .filter(|line| !line.is_empty())
        .collect();

    PageContent {
        text: truncate_chars(&lines.join("\n"), text_budget_chars),
        logo_url: find_logo(&doc, base.as_ref()),
        about_url: find_about_link(&doc, base.as_ref()),
    }
}

/// Concatenate text nodes under `root`, skipping non-visible containers.
fn visible_text(root: ElementRef) -> String {
    let fragments: Vec<String> = root
        .descendants()
        .filter_map(|node| {
            let text = node.value().as_text()?;
            let hidden = node
                .ancestors()
                .filter_map(ElementRef::wrap)
                .any(|el| SKIP_TAGS.contains(&el.value().name()));
            if hidden {
                return None;
            }
            let collapsed = collapse_ws(text);
            (!collapsed.is_empty()).then_some(collapsed)
        })
        .collect();
    fragments.join(" ")
}

fn find_logo(doc: &Html, base: Option<&Url>) -> Option<String> {
    let og = doc
        .select(&sel(r#"meta[property="og:image"][content]"#))
        .next()
        .and_then(|m| m.value().attr("content"));
    let icon = doc
        .select(&sel("link[rel][href]"))
        .find(|link| {
            link.value()
                .attr("rel")
                .is_some_and(|rel| rel.to_ascii_lowercase().contains("icon"))
        })
        .and_then(|link| link.value().attr("href"));
    og.or(icon).and_then(|href| resolve_http(base, href))
}

fn find_about_link(doc: &Html, base: Option<&Url>) -> Option<String> {
    doc.select(&sel("a[href]")).find_map(|a| {
        let href = a.value().attr("href")?;
        let label = a.text().collect::<String>();
        let looks_about = href.to_ascii_lowercase().contains("about")
            || label.to_ascii_lowercase().contains("about");
        if !looks_about {
            return None;
        }
        let resolved = resolve_http(base, href)?;
        let same_host = base
            .and_then(|b| Url::parse(&resolved).ok().map(|u| u.host_str() == b.host_str()))
            .unwrap_or(false);
        same_host.then_some(resolved)
    })
}

/// Resolve `href` against `base`; keep only http(s) results.
fn resolve_http(base: Option<&Url>, href: &str) -> Option<String> {
    let resolved = match base {
        Some(b) => b.join(href).ok()?,
        None => Url::parse(href).ok()?,
    };
    matches!(resolved.scheme(), "http" | "https").then(|| resolved.to_string())
}

fn collapse_ws(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn truncate_chars(input: &str, budget: usize) -> String {
    match input.char_indices().nth(budget) {
        Some((byte_index, _)) => input[..byte_index].to_string(),
        None => input.to_string(),
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-enricher && cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test
```

Expected: all PASS. If `scraper 0.20` renamed `ElementRef::wrap`, the alternative is `node.ancestors().any(|a| a.value().as_element().is_some_and(|e| SKIP_TAGS.contains(&e.name())))`.

- [ ] **Step 5: Commit**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-enricher add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-enricher commit -m "feat: HTML reduction with mechanical logo and about-link extraction"
```

---

### Task 5: Web fetching (`fetch.rs`)

**Files:**
- Create: `eldrin-enricher/src/fetch.rs`
- Modify: `eldrin-enricher/src/lib.rs` (add `pub mod fetch;`)

**Interfaces:**
- Consumes: `crate::config::FetchConfig`.
- Produces:
  - `FetchedPage { url: String, html: String }` (`url` is the FINAL url after redirects — used as base for relative link resolution)
  - `pub fn candidate_urls(domain: &str) -> Vec<String>` — `https://{d}`, `https://www.{d}`, `http://{d}` (input stripped of scheme/trailing slash)
  - `#[async_trait] pub trait Fetcher: Send + Sync { async fn fetch_homepage(&self, domain: &str) -> Result<FetchedPage, FetchError>; async fn fetch_url(&self, url: &str) -> Result<FetchedPage, FetchError>; }`
  - `DirectFetcher::new(config: &FetchConfig) -> Result<Self, FetchError>`
  - `enum FetchError { Transport(String), Status(u16), NotHtml(String), NoCandidates }`

- [ ] **Step 1: Write the failing tests**

Create `eldrin-enricher/src/fetch.rs` with only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FetchConfig;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn fetcher() -> DirectFetcher {
        DirectFetcher::new(&FetchConfig { timeout_secs: 2, concurrency: 2, max_response_kb: 1 })
            .expect("fetcher")
    }

    #[test]
    fn candidate_urls_cover_https_www_and_http() {
        assert_eq!(
            candidate_urls("acme.com"),
            vec!["https://acme.com", "https://www.acme.com", "http://acme.com"]
        );
    }

    #[test]
    fn candidate_urls_strip_existing_scheme_and_slash() {
        assert_eq!(
            candidate_urls("https://acme.com/"),
            vec!["https://acme.com", "https://www.acme.com", "http://acme.com"]
        );
    }

    #[tokio::test]
    async fn fetch_homepage_falls_back_to_http_candidate() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html; charset=utf-8")
                    .set_body_string("<html><body>hello</body></html>"),
            )
            .mount(&server)
            .await;

        // server.uri() is http://127.0.0.1:{port}; strip the scheme to get a
        // "domain". https candidates fail to connect, http succeeds.
        let domain = server.uri().trim_start_matches("http://").to_string();
        let page = fetcher().fetch_homepage(&domain).await.expect("fallback works");
        assert!(page.html.contains("hello"));
        assert!(page.url.starts_with("http://"));
    }

    #[tokio::test]
    async fn fetch_url_rejects_non_html_content_type() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/data.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_string("{}"),
            )
            .mount(&server)
            .await;
        let err = fetcher().fetch_url(&format!("{}/data.json", server.uri())).await.unwrap_err();
        assert!(matches!(err, FetchError::NotHtml(_)));
    }

    #[tokio::test]
    async fn fetch_url_surfaces_http_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/gone"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let err = fetcher().fetch_url(&format!("{}/gone", server.uri())).await.unwrap_err();
        assert!(matches!(err, FetchError::Status(404)));
    }

    #[tokio::test]
    async fn fetch_url_caps_response_size() {
        let server = MockServer::start().await;
        // max_response_kb = 1 → 1024 bytes cap; serve 10 KB.
        Mock::given(method("GET"))
            .and(path("/big"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string("x".repeat(10 * 1024)),
            )
            .mount(&server)
            .await;
        let page = fetcher().fetch_url(&format!("{}/big", server.uri())).await.expect("fetch");
        assert_eq!(page.html.len(), 1024);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-enricher && cargo test fetch
```

Expected: compile FAILURE. (Add `pub mod fetch;` to `src/lib.rs`.)

- [ ] **Step 3: Implement `fetch.rs`**

```rust
//! Web fetching behind the Fetcher trait. v1 ships DirectFetcher (no search
//! engine): candidate URLs derived from the company domain. Future SearXNG or
//! search-API sources implement the same trait.

use crate::config::FetchConfig;
use async_trait::async_trait;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("transport: {0}")]
    Transport(String),
    #[error("HTTP status {0}")]
    Status(u16),
    #[error("not an HTML response ({0})")]
    NotHtml(String),
    #[error("no fetch candidates for domain")]
    NoCandidates,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FetchedPage {
    /// Final URL after redirects — base for resolving relative links.
    pub url: String,
    pub html: String,
}

#[async_trait]
pub trait Fetcher: Send + Sync {
    async fn fetch_homepage(&self, domain: &str) -> Result<FetchedPage, FetchError>;
    async fn fetch_url(&self, url: &str) -> Result<FetchedPage, FetchError>;
}

/// `https://d`, `https://www.d`, `http://d` for a bare or scheme-prefixed domain.
pub fn candidate_urls(domain: &str) -> Vec<String> {
    let bare = domain.trim().trim_end_matches('/');
    let bare = bare
        .strip_prefix("https://")
        .or_else(|| bare.strip_prefix("http://"))
        .unwrap_or(bare);
    vec![
        format!("https://{bare}"),
        format!("https://www.{bare}"),
        format!("http://{bare}"),
    ]
}

pub struct DirectFetcher {
    http: reqwest::Client,
    max_response_bytes: usize,
}

impl DirectFetcher {
    pub fn new(config: &FetchConfig) -> Result<Self, FetchError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .redirect(reqwest::redirect::Policy::limited(5))
            .user_agent(concat!("eldrin-enricher/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|err| FetchError::Transport(err.to_string()))?;
        Ok(DirectFetcher { http, max_response_bytes: config.max_response_kb * 1024 })
    }
}

#[async_trait]
impl Fetcher for DirectFetcher {
    async fn fetch_homepage(&self, domain: &str) -> Result<FetchedPage, FetchError> {
        let candidates = candidate_urls(domain);
        let mut last_error = FetchError::NoCandidates;
        for url in candidates {
            match self.fetch_url(&url).await {
                Ok(page) => return Ok(page),
                Err(err) => {
                    tracing::debug!("candidate {url} failed: {err}");
                    last_error = err;
                }
            }
        }
        Err(last_error)
    }

    async fn fetch_url(&self, url: &str) -> Result<FetchedPage, FetchError> {
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|err| FetchError::Transport(err.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(FetchError::Status(status.as_u16()));
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string();
        // Missing content-type is tolerated (some small sites omit it).
        if !content_type.is_empty() && !content_type.contains("text/html") {
            return Err(FetchError::NotHtml(content_type));
        }
        let final_url = response.url().to_string();
        let bytes = response
            .bytes()
            .await
            .map_err(|err| FetchError::Transport(err.to_string()))?;
        let capped = &bytes[..bytes.len().min(self.max_response_bytes)];
        Ok(FetchedPage { url: final_url, html: String::from_utf8_lossy(capped).into_owned() })
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-enricher && cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test
```

Expected: all PASS. The fallback test relies on `https://127.0.0.1:{port}` failing fast (connection refused/TLS error) — no external network is touched (`www.127.0.0.1...` fails DNS locally).

- [ ] **Step 5: Commit**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-enricher add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-enricher commit -m "feat: Fetcher trait with DirectFetcher candidate fallback"
```

---

### Task 6: Company pipeline (`enrich/mod.rs` + `enrich/company.rs`)

**Files:**
- Create: `eldrin-enricher/src/enrich/mod.rs`, `eldrin-enricher/src/enrich/company.rs`
- Modify: `eldrin-enricher/src/lib.rs` (add `pub mod enrich;`)

**Interfaces:**
- Consumes: `EldrinClient`, `PendingCompany`, `CompanyEnrichment` (Task 2); `LlmClient` (Task 3); `reduce_html` (Task 4); `Fetcher`, `FetchedPage` (Task 5); `Config` (Task 1).
- Produces (in `enrich/mod.rs`, shared with Task 7):
  - `RecordRef { kind: &'static str, id: String, label: String }`
  - `enum Outcome { Enhanced { record: RecordRef, applied: Vec<String> }, Skipped { record: RecordRef, reason: String }, Failed { record: RecordRef, reason: String }, WouldApply { record: RecordRef, payload: serde_json::Value } }`
  - `Deps<'a> { fetcher: &'a dyn Fetcher, llm: &'a LlmClient, eldrin: &'a EldrinClient, config: &'a Config }`
- Produces (in `enrich/company.rs`):
  - `pub async fn enrich_company(company: &PendingCompany, deps: &Deps<'_>, dry_run: bool) -> Outcome`
  - `pub const COMPANY_PROMPT: &str`, `pub fn company_schema() -> serde_json::Value` (schema has NO logoUrl property — the model is never invited to produce one)

- [ ] **Step 1: Write the failing tests**

Create `eldrin-enricher/src/enrich/mod.rs`:

```rust
pub mod company;

use crate::config::Config;
use crate::eldrin::EldrinClient;
use crate::fetch::Fetcher;
use crate::llm::LlmClient;

/// Identifies a processed record in outcomes and the run summary.
#[derive(Debug, Clone, PartialEq)]
pub struct RecordRef {
    pub kind: &'static str,
    pub id: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Enhanced { record: RecordRef, applied: Vec<String> },
    Skipped { record: RecordRef, reason: String },
    Failed { record: RecordRef, reason: String },
    /// Dry-run result: what would have been POSTed.
    WouldApply { record: RecordRef, payload: serde_json::Value },
}

/// Shared dependencies for the enrichment pipelines.
pub struct Deps<'a> {
    pub fetcher: &'a dyn Fetcher,
    pub llm: &'a LlmClient,
    pub eldrin: &'a EldrinClient,
    pub config: &'a Config,
}
```

Create `eldrin-enricher/src/enrich/company.rs` with only this test module (implementation goes above it in Step 3):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::eldrin::{EldrinClient, PendingCompany};
    use crate::fetch::{FetchError, FetchedPage, Fetcher};
    use crate::llm::LlmClient;
    use async_trait::async_trait;
    use serde_json::json;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const HOMEPAGE: &str = r#"<html><head><title>Acme</title>
        <meta property="og:image" content="/logo.png"></head>
        <body><p>Acme builds widgets.</p></body></html>"#;

    /// Test double: serves canned pages, or errors for unknown domains.
    struct FakeFetcher;

    #[async_trait]
    impl Fetcher for FakeFetcher {
        async fn fetch_homepage(&self, domain: &str) -> Result<FetchedPage, FetchError> {
            match domain {
                "acme.com" => Ok(FetchedPage {
                    url: "https://acme.com/".to_string(),
                    html: HOMEPAGE.to_string(),
                }),
                _ => Err(FetchError::Transport("connection refused".to_string())),
            }
        }
        async fn fetch_url(&self, _url: &str) -> Result<FetchedPage, FetchError> {
            Err(FetchError::Transport("no about page in this test".to_string()))
        }
    }

    struct Harness {
        server: MockServer,
        config: Config,
    }

    impl Harness {
        async fn new() -> Self {
            let server = MockServer::start().await;
            let config = Config {
                core_url: server.uri(),
                llm: crate::config::LlmConfig {
                    base_url: format!("{}/v1", server.uri()),
                    model: "gemma-4-31b".to_string(),
                },
                ..Config::default()
            };
            Harness { server, config }
        }

        fn eldrin(&self) -> EldrinClient {
            EldrinClient::new(&self.config.core_url, None, 5).expect("client")
        }

        fn llm(&self) -> LlmClient {
            LlmClient::new(&self.config.llm, 5).expect("client")
        }

        async fn mock_llm(&self, content: serde_json::Value) {
            Mock::given(method("POST"))
                .and(path("/v1/chat/completions"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "choices": [{"message": {"content": content.to_string()}}]
                })))
                .mount(&self.server)
                .await;
        }
    }

    fn company(domain: Option<&str>) -> PendingCompany {
        PendingCompany {
            id: "co1".to_string(),
            name: "acme.com".to_string(),
            domain: domain.map(str::to_string),
        }
    }

    #[tokio::test]
    async fn happy_path_merges_mechanical_logo_and_applies() {
        let h = Harness::new().await;
        h.mock_llm(json!({"name": "Acme Corp", "description": "Widget maker.",
                           "industry": "Manufacturing",
                           "logoUrl": "https://EVIL.example/hallucinated.png"}))
            .await;
        Mock::given(method("POST"))
            .and(path("/api/app/eldrin-crm/api/enhancement/companies/co1"))
            .and(body_partial_json(json!({
                "data": {"name": "Acme Corp", "logoUrl": "https://acme.com/logo.png"},
                "source": "eldrin-enricher"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "company": {}, "applied": ["name", "notes", "logoUrl", "industry"]
            })))
            .expect(1)
            .mount(&h.server)
            .await;

        let (eldrin, llm) = (h.eldrin(), h.llm());
        let deps = Deps { fetcher: &FakeFetcher, llm: &llm, eldrin: &eldrin, config: &h.config };
        let outcome = enrich_company(&company(Some("acme.com")), &deps, false).await;
        match outcome {
            Outcome::Enhanced { applied, .. } => {
                assert_eq!(applied, vec!["name", "notes", "logoUrl", "industry"]);
            }
            other => panic!("expected Enhanced, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn missing_domain_skips_without_any_request() {
        let h = Harness::new().await;
        let (eldrin, llm) = (h.eldrin(), h.llm());
        let deps = Deps { fetcher: &FakeFetcher, llm: &llm, eldrin: &eldrin, config: &h.config };
        let outcome = enrich_company(&company(None), &deps, false).await;
        match outcome {
            Outcome::Skipped { reason, .. } => assert_eq!(reason, "no-domain"),
            other => panic!("expected Skipped, got {other:?}"),
        }
        assert!(h.server.received_requests().await.expect("requests").is_empty());
    }

    #[tokio::test]
    async fn fetch_failure_is_failed_outcome() {
        let h = Harness::new().await;
        let (eldrin, llm) = (h.eldrin(), h.llm());
        let deps = Deps { fetcher: &FakeFetcher, llm: &llm, eldrin: &eldrin, config: &h.config };
        let outcome = enrich_company(&company(Some("unreachable.example")), &deps, false).await;
        match outcome {
            Outcome::Failed { reason, .. } => assert!(reason.starts_with("fetch:")),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dry_run_reports_payload_and_posts_nothing() {
        let h = Harness::new().await;
        h.mock_llm(json!({"name": "Acme Corp"})).await;
        let (eldrin, llm) = (h.eldrin(), h.llm());
        let deps = Deps { fetcher: &FakeFetcher, llm: &llm, eldrin: &eldrin, config: &h.config };
        let outcome = enrich_company(&company(Some("acme.com")), &deps, true).await;
        match outcome {
            Outcome::WouldApply { payload, .. } => {
                assert_eq!(payload["name"], "Acme Corp");
                assert_eq!(payload["logoUrl"], "https://acme.com/logo.png");
            }
            other => panic!("expected WouldApply, got {other:?}"),
        }
        let requests = h.server.received_requests().await.expect("requests");
        assert!(requests.iter().all(|r| !r.url.path().contains("/enhancement/companies/")));
    }

    #[tokio::test]
    async fn apply_failure_is_failed_outcome() {
        let h = Harness::new().await;
        h.mock_llm(json!({"name": "Acme Corp"})).await;
        Mock::given(method("POST"))
            .and(path("/api/app/eldrin-crm/api/enhancement/companies/co1"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&h.server)
            .await;
        let (eldrin, llm) = (h.eldrin(), h.llm());
        let deps = Deps { fetcher: &FakeFetcher, llm: &llm, eldrin: &eldrin, config: &h.config };
        let outcome = enrich_company(&company(Some("acme.com")), &deps, false).await;
        match outcome {
            Outcome::Failed { reason, .. } => assert!(reason.starts_with("apply:")),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn schema_never_mentions_logo() {
        assert!(!company_schema().to_string().to_lowercase().contains("logo"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-enricher && cargo test company
```

Expected: compile FAILURE — `enrich_company` not defined. (Add `pub mod enrich;` to `src/lib.rs`.)

- [ ] **Step 3: Implement `enrich/company.rs`**

Add above the test module:

```rust
//! Company enrichment: homepage (+ optional about page) → reduced text →
//! LLM extraction → mechanical logo merge → apply.

use super::{Deps, Outcome, RecordRef};
use crate::eldrin::{CompanyEnrichment, PendingCompany};
use crate::extract::reduce_html;
use serde_json::{json, Value};

pub const COMPANY_PROMPT: &str = "You are a data-extraction assistant. The user message contains text \
extracted from a company's website. Extract facts about the company using ONLY information present \
in the text — never guess or use outside knowledge. Omit any field that is not clearly evidenced. \
Fields: name = the official company name; description = a 1-3 sentence plain-text summary of what \
the company does; industry = a short industry label such as \"Software\" or \"Logistics\".";

/// Deliberately excludes logoUrl: the logo is extracted mechanically from
/// page metadata, never generated by the model.
pub fn company_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "description": {"type": "string"},
            "industry": {"type": "string"}
        },
        "additionalProperties": false
    })
}

pub async fn enrich_company(
    company: &PendingCompany,
    deps: &Deps<'_>,
    dry_run: bool,
) -> Outcome {
    let record = RecordRef {
        kind: "company",
        id: company.id.clone(),
        label: company.name.clone(),
    };

    let Some(domain) = company.domain.as_deref().filter(|d| !d.trim().is_empty()) else {
        return Outcome::Skipped { record, reason: "no-domain".to_string() };
    };

    let homepage = match deps.fetcher.fetch_homepage(domain).await {
        Ok(page) => page,
        Err(err) => return Outcome::Failed { record, reason: format!("fetch: {err}") },
    };
    let budget = deps.config.extract.text_budget_chars;
    let content = reduce_html(&homepage.html, &homepage.url, budget);

    // Best-effort about page: failure to fetch it is not a record failure.
    let text = match &content.about_url {
        Some(about_url) => match deps.fetcher.fetch_url(about_url).await {
            Ok(about_page) => {
                let about = reduce_html(&about_page.html, about_url, budget);
                format!("{}\n\n--- About page ---\n{}", content.text, about.text)
            }
            Err(err) => {
                tracing::debug!("about page {about_url} failed: {err}");
                content.text.clone()
            }
        },
        None => content.text.clone(),
    };

    if text.trim().is_empty() {
        return Outcome::Failed { record, reason: "extraction-empty".to_string() };
    }

    let extracted: CompanyEnrichment =
        match deps.llm.extract(COMPANY_PROMPT, &text, &company_schema()).await {
            Ok(value) => value,
            Err(err) => return Outcome::Failed { record, reason: format!("llm: {err}") },
        };
    // logo_url set ONLY from mechanical extraction — overrides anything the
    // model may have smuggled into unknown JSON keys.
    let enrichment = CompanyEnrichment { logo_url: content.logo_url.clone(), ..extracted };

    if dry_run {
        let payload = serde_json::to_value(&enrichment).unwrap_or_default();
        return Outcome::WouldApply { record, payload };
    }
    match deps.eldrin.apply_company(&company.id, &enrichment).await {
        Ok(applied) => Outcome::Enhanced { record, applied },
        Err(err) => Outcome::Failed { record, reason: format!("apply: {err}") },
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-enricher && cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test
```

Expected: all PASS. Note the happy-path test asserts the hallucinated `logoUrl` from the model is REPLACED by the mechanical one.

- [ ] **Step 5: Commit**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-enricher add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-enricher commit -m "feat: company enrichment pipeline with mechanical logo merge"
```

---

### Task 7: Contact pipeline (`enrich/contact.rs`)

**Files:**
- Create: `eldrin-enricher/src/enrich/contact.rs`
- Modify: `eldrin-enricher/src/enrich/mod.rs` (add `pub mod contact;`)

**Interfaces:**
- Consumes: `Deps`, `Outcome`, `RecordRef` (Task 6); `PendingContact`, `ContactInsights` (Task 2); `LlmClient` (Task 3). No fetching — the pending item already carries the email material.
- Produces:
  - `pub async fn enrich_contact(contact: &PendingContact, deps: &Deps<'_>, dry_run: bool) -> Outcome`
  - `pub const CONTACT_PROMPT: &str`, `pub fn contact_schema() -> serde_json::Value`

- [ ] **Step 1: Write the failing tests**

Create `eldrin-enricher/src/enrich/contact.rs` with only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::eldrin::{EldrinClient, PendingContact};
    use crate::fetch::{FetchError, FetchedPage, Fetcher};
    use crate::llm::LlmClient;
    use async_trait::async_trait;
    use serde_json::json;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Contacts never fetch; this fetcher fails loudly if they try.
    struct NeverFetch;

    #[async_trait]
    impl Fetcher for NeverFetch {
        async fn fetch_homepage(&self, _: &str) -> Result<FetchedPage, FetchError> {
            panic!("contact pipeline must not fetch");
        }
        async fn fetch_url(&self, _: &str) -> Result<FetchedPage, FetchError> {
            panic!("contact pipeline must not fetch");
        }
    }

    fn contact(with_material: bool) -> PendingContact {
        PendingContact {
            id: "ct1".to_string(),
            first_name: Some("Jane".to_string()),
            last_name: Some("Doe".to_string()),
            message_id: with_material.then(|| "m1".to_string()),
            from: with_material.then(|| "jane@acme.com".to_string()),
            body_text: with_material.then(|| "Hi!\n--\nJane Doe\nCTO, Acme\n+36 1 234 567".to_string()),
        }
    }

    async fn harness() -> (MockServer, Config) {
        let server = MockServer::start().await;
        let config = Config {
            core_url: server.uri(),
            llm: crate::config::LlmConfig {
                base_url: format!("{}/v1", server.uri()),
                model: "gemma-4-31b".to_string(),
            },
            ..Config::default()
        };
        (server, config)
    }

    #[tokio::test]
    async fn happy_path_extracts_and_applies_with_message_id() {
        let (server, config) = harness().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "choices": [{"message": {"content":
                    "{\"jobTitle\": \"CTO\", \"phones\": [\"+36 1 234 567\"]}"}}]
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/app/eldrin-crm/api/enhancement/contacts/ct1"))
            .and(body_partial_json(json!({
                "messageId": "m1",
                "insights": {"jobTitle": "CTO", "phones": ["+36 1 234 567"]},
                "source": "eldrin-enricher"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "contact": {}, "applied": ["signature-fields"]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let eldrin = EldrinClient::new(&config.core_url, None, 5).expect("client");
        let llm = LlmClient::new(&config.llm, 5).expect("client");
        let deps = Deps { fetcher: &NeverFetch, llm: &llm, eldrin: &eldrin, config: &config };
        let outcome = enrich_contact(&contact(true), &deps, false).await;
        match outcome {
            Outcome::Enhanced { record, applied } => {
                assert_eq!(record.label, "Jane Doe");
                assert_eq!(applied, vec!["signature-fields"]);
            }
            other => panic!("expected Enhanced, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn no_material_skips_without_llm_call() {
        let (server, config) = harness().await;
        let eldrin = EldrinClient::new(&config.core_url, None, 5).expect("client");
        let llm = LlmClient::new(&config.llm, 5).expect("client");
        let deps = Deps { fetcher: &NeverFetch, llm: &llm, eldrin: &eldrin, config: &config };
        let outcome = enrich_contact(&contact(false), &deps, false).await;
        match outcome {
            Outcome::Skipped { reason, .. } => assert_eq!(reason, "no-material"),
            other => panic!("expected Skipped, got {other:?}"),
        }
        assert!(server.received_requests().await.expect("requests").is_empty());
    }

    #[tokio::test]
    async fn dry_run_reports_payload_and_posts_nothing() {
        let (server, config) = harness().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "choices": [{"message": {"content": "{\"jobTitle\": \"CTO\"}"}}]
            })))
            .mount(&server)
            .await;
        let eldrin = EldrinClient::new(&config.core_url, None, 5).expect("client");
        let llm = LlmClient::new(&config.llm, 5).expect("client");
        let deps = Deps { fetcher: &NeverFetch, llm: &llm, eldrin: &eldrin, config: &config };
        let outcome = enrich_contact(&contact(true), &deps, true).await;
        match outcome {
            Outcome::WouldApply { payload, .. } => {
                assert_eq!(payload["messageId"], "m1");
                assert_eq!(payload["insights"]["jobTitle"], "CTO");
            }
            other => panic!("expected WouldApply, got {other:?}"),
        }
        let requests = server.received_requests().await.expect("requests");
        assert!(requests.iter().all(|r| !r.url.path().contains("/enhancement/contacts/")));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-enricher && cargo test contact
```

Expected: compile FAILURE. (Add `pub mod contact;` to `src/enrich/mod.rs`.)

- [ ] **Step 3: Implement `enrich/contact.rs`**

Add above the test module:

```rust
//! Contact enrichment: the pending item already carries the latest email
//! body (messageId/from/bodyText) — no internet access needed.

use super::{Deps, Outcome, RecordRef};
use crate::eldrin::{ContactInsights, PendingContact};
use serde_json::{json, Value};

pub const CONTACT_PROMPT: &str = "You are a data-extraction assistant. The user message contains the \
text of an email received from a contact, usually ending in a signature block. Extract details about \
the SENDER using ONLY information present in the text — never guess. Omit any field that is not \
clearly evidenced. Fields: jobTitle = the sender's job title; phones = phone numbers from the \
signature; social = the sender's profile URLs for linkedin, twitter, github.";

pub fn contact_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "jobTitle": {"type": "string"},
            "phones": {"type": "array", "items": {"type": "string"}},
            "social": {
                "type": "object",
                "properties": {
                    "linkedin": {"type": "string"},
                    "twitter": {"type": "string"},
                    "github": {"type": "string"}
                },
                "additionalProperties": false
            }
        },
        "additionalProperties": false
    })
}

pub async fn enrich_contact(
    contact: &PendingContact,
    deps: &Deps<'_>,
    dry_run: bool,
) -> Outcome {
    let label = [contact.first_name.as_deref(), contact.last_name.as_deref()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    let record = RecordRef { kind: "contact", id: contact.id.clone(), label };

    let (Some(message_id), Some(body_text)) =
        (contact.message_id.as_deref(), contact.body_text.as_deref())
    else {
        return Outcome::Skipped { record, reason: "no-material".to_string() };
    };

    let input = format!("From: {}\n\n{body_text}", contact.from.as_deref().unwrap_or(""));
    let insights: ContactInsights =
        match deps.llm.extract(CONTACT_PROMPT, &input, &contact_schema()).await {
            Ok(value) => value,
            Err(err) => return Outcome::Failed { record, reason: format!("llm: {err}") },
        };

    if dry_run {
        let payload = json!({
            "messageId": message_id,
            "insights": serde_json::to_value(&insights).unwrap_or_default(),
        });
        return Outcome::WouldApply { record, payload };
    }
    match deps.eldrin.apply_contact(&contact.id, message_id, &insights).await {
        Ok(applied) => Outcome::Enhanced { record, applied },
        Err(err) => Outcome::Failed { record, reason: format!("apply: {err}") },
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-enricher && cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-enricher add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-enricher commit -m "feat: contact enrichment pipeline from captured email material"
```

---

### Task 8: Run summary (`report.rs`)

**Files:**
- Create: `eldrin-enricher/src/report.rs`
- Modify: `eldrin-enricher/src/lib.rs` (add `pub mod report;`)

**Interfaces:**
- Consumes: `Outcome`, `RecordRef` (Task 6).
- Produces: `RunSummary { outcomes: Vec<Outcome> }`; `RunSummary::render(&self) -> String`; `RunSummary::counts(&self) -> Counts` with `Counts { enhanced: usize, skipped: usize, failed: usize, would_apply: usize }`.

- [ ] **Step 1: Write the failing tests**

Create `eldrin-enricher/src/report.rs` with only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrich::{Outcome, RecordRef};
    use serde_json::json;

    fn record(kind: &'static str, id: &str, label: &str) -> RecordRef {
        RecordRef { kind, id: id.to_string(), label: label.to_string() }
    }

    fn sample() -> RunSummary {
        RunSummary {
            outcomes: vec![
                Outcome::Enhanced {
                    record: record("company", "co1", "Acme"),
                    applied: vec!["name".to_string(), "logoUrl".to_string()],
                },
                Outcome::Skipped {
                    record: record("contact", "ct2", "No Material"),
                    reason: "no-material".to_string(),
                },
                Outcome::Failed {
                    record: record("company", "co3", "Broken"),
                    reason: "fetch: HTTP status 404".to_string(),
                },
                Outcome::WouldApply {
                    record: record("contact", "ct4", "Dry Run"),
                    payload: json!({"messageId": "m4"}),
                },
            ],
        }
    }

    #[test]
    fn counts_group_by_variant() {
        let counts = sample().counts();
        assert_eq!(counts.enhanced, 1);
        assert_eq!(counts.skipped, 1);
        assert_eq!(counts.failed, 1);
        assert_eq!(counts.would_apply, 1);
    }

    #[test]
    fn render_contains_header_and_one_line_per_record() {
        let output = sample().render();
        assert!(output.contains("1 enhanced"));
        assert!(output.contains("1 skipped"));
        assert!(output.contains("1 failed"));
        assert!(output.contains("company co1 (Acme) — applied: name, logoUrl"));
        assert!(output.contains("contact ct2 (No Material) — skipped: no-material"));
        assert!(output.contains("company co3 (Broken) — failed: fetch: HTTP status 404"));
        assert!(output.contains("contact ct4 (Dry Run) — would apply: {\"messageId\":\"m4\"}"));
    }

    #[test]
    fn empty_run_renders_nothing_pending_message() {
        let output = RunSummary { outcomes: vec![] }.render();
        assert!(output.contains("Nothing pending"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-enricher && cargo test report
```

Expected: compile FAILURE. (Add `pub mod report;` to `src/lib.rs`.)

- [ ] **Step 3: Implement `report.rs`**

```rust
//! End-of-run summary rendering.

use crate::enrich::Outcome;

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Counts {
    pub enhanced: usize,
    pub skipped: usize,
    pub failed: usize,
    pub would_apply: usize,
}

#[derive(Debug)]
pub struct RunSummary {
    pub outcomes: Vec<Outcome>,
}

impl RunSummary {
    pub fn counts(&self) -> Counts {
        self.outcomes.iter().fold(Counts::default(), |acc, outcome| match outcome {
            Outcome::Enhanced { .. } => Counts { enhanced: acc.enhanced + 1, ..acc },
            Outcome::Skipped { .. } => Counts { skipped: acc.skipped + 1, ..acc },
            Outcome::Failed { .. } => Counts { failed: acc.failed + 1, ..acc },
            Outcome::WouldApply { .. } => Counts { would_apply: acc.would_apply + 1, ..acc },
        })
    }

    pub fn render(&self) -> String {
        if self.outcomes.is_empty() {
            return "Nothing pending — all records are already enhanced.".to_string();
        }
        let c = self.counts();
        let header = format!(
            "Run summary: {} enhanced, {} skipped, {} failed{}",
            c.enhanced,
            c.skipped,
            c.failed,
            if c.would_apply > 0 {
                format!(", {} would apply (dry run)", c.would_apply)
            } else {
                String::new()
            }
        );
        let lines: Vec<String> = self
            .outcomes
            .iter()
            .map(|outcome| match outcome {
                Outcome::Enhanced { record, applied } => format!(
                    "  ✓ {} {} ({}) — applied: {}",
                    record.kind,
                    record.id,
                    record.label,
                    if applied.is_empty() { "(nothing new)".to_string() } else { applied.join(", ") }
                ),
                Outcome::Skipped { record, reason } => format!(
                    "  – {} {} ({}) — skipped: {reason}",
                    record.kind, record.id, record.label
                ),
                Outcome::Failed { record, reason } => format!(
                    "  ✗ {} {} ({}) — failed: {reason}",
                    record.kind, record.id, record.label
                ),
                Outcome::WouldApply { record, payload } => format!(
                    "  → {} {} ({}) — would apply: {payload}",
                    record.kind, record.id, record.label
                ),
            })
            .collect();
        [header, lines.join("\n")].join("\n")
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-enricher && cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-enricher add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-enricher commit -m "feat: run summary with per-record outcome lines"
```

---

### Task 9: Runner + CLI (`runner.rs`, `main.rs`) with end-to-end test

**Files:**
- Create: `eldrin-enricher/src/runner.rs`, `eldrin-enricher/tests/e2e_run.rs`
- Modify: `eldrin-enricher/src/lib.rs` (add `pub mod runner;`), `eldrin-enricher/src/main.rs` (replace stub)

**Interfaces:**
- Consumes: everything from Tasks 1–8.
- Produces:
  - `enum RecordFilter { Contact, Company, All }` with `fn as_query_param(&self) -> Option<&'static str>` (`Some("contact")` / `Some("company")` / `None`)
  - `RunOptions { record_type: RecordFilter, limit: u32, dry_run: bool }`
  - `pub async fn run(config: &Config, options: &RunOptions, fetcher: &dyn Fetcher) -> Result<RunSummary, RunError>`
  - `enum RunError { Preflight(String), Client(String) }` (thiserror; `Preflight` carries the actionable message)
  - Concurrency: pipelines run through `futures::stream::iter(...).map(...).buffered(config.fetch.concurrency)`; LLM calls stay serialized by the client's internal semaphore, so fetches overlap while inference queues.

- [ ] **Step 1: Write the failing end-to-end test**

Create `eldrin-enricher/tests/e2e_run.rs`:

```rust
//! Full run against wiremock: CRM pending/apply + llama.cpp chat + a fake
//! company homepage — using the REAL DirectFetcher (its http:// candidate
//! fallback reaches the wiremock "homepage").

use eldrin_enricher::config::{Config, LlmConfig};
use eldrin_enricher::fetch::DirectFetcher;
use eldrin_enricher::runner::{run, RecordFilter, RunOptions};
use serde_json::json;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn start_stack() -> (MockServer, MockServer, Config) {
    let api = MockServer::start().await; // plays eldrin-core proxy + llama.cpp
    let web = MockServer::start().await; // plays the company homepage

    // llama.cpp: health + a schema-shaped answer for both pipelines.
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&api)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"content":
                "{\"name\": \"Acme Corp\", \"description\": \"Widgets.\", \"jobTitle\": \"CTO\"}"}}]
        })))
        .mount(&api)
        .await;

    // Homepage served over http (DirectFetcher's third candidate).
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/html")
                .set_body_string("<html><head><title>Acme</title></head><body>Widgets.</body></html>"),
        )
        .mount(&web)
        .await;

    let web_domain = web.uri().trim_start_matches("http://").to_string();

    // CRM: pending page with one of everything, then the two apply endpoints.
    Mock::given(method("GET"))
        .and(path("/api/app/eldrin-crm/api/enhancement/pending"))
        .and(query_param("limit", "25"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [
                {"type": "company", "id": "co1", "name": "acme", "domain": web_domain},
                {"type": "company", "id": "co2", "name": "nodomain", "domain": null},
                {"type": "contact", "id": "ct1", "firstName": "Jane", "lastName": "Doe",
                 "messageId": "m1", "from": "jane@acme.com", "bodyText": "Hi -- Jane, CTO"},
                {"type": "contact", "id": "ct2", "firstName": "No", "lastName": "Material"}
            ],
            "limit": 25, "offset": 0
        })))
        .mount(&api)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/app/eldrin-crm/api/enhancement/companies/co1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "company": {}, "applied": ["name", "notes"]
        })))
        .expect(1)
        .mount(&api)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/app/eldrin-crm/api/enhancement/contacts/ct1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "contact": {}, "applied": ["signature-fields"]
        })))
        .expect(1)
        .mount(&api)
        .await;

    let config = Config {
        core_url: api.uri(),
        llm: LlmConfig { base_url: format!("{}/v1", api.uri()), model: "gemma-4-31b".to_string() },
        ..Config::default()
    };
    (api, web, config)
}

#[tokio::test]
async fn full_run_enhances_skips_and_reports() {
    let (_api, _web, config) = start_stack().await;
    let fetcher = DirectFetcher::new(&config.fetch).expect("fetcher");
    let options = RunOptions { record_type: RecordFilter::All, limit: 25, dry_run: false };

    let summary = run(&config, &options, &fetcher).await.expect("run succeeds");
    let counts = summary.counts();
    assert_eq!(counts.enhanced, 2); // co1 + ct1
    assert_eq!(counts.skipped, 2); // co2 (no-domain) + ct2 (no-material)
    assert_eq!(counts.failed, 0);
    // Mock .expect(1) assertions verify the apply endpoints were each hit once.
}

#[tokio::test]
async fn preflight_fails_fast_when_llm_is_down() {
    let api = MockServer::start().await;
    // CRM healthy…
    Mock::given(method("GET"))
        .and(path("/api/app/eldrin-crm/api/enhancement/pending"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"items": [], "limit": 1, "offset": 0})),
        )
        .mount(&api)
        .await;
    // …but llm.base_url points at a dead port.
    let config = Config {
        core_url: api.uri(),
        llm: LlmConfig {
            base_url: "http://127.0.0.1:9".to_string(),
            model: "gemma-4-31b".to_string(),
        },
        ..Config::default()
    };
    let fetcher = DirectFetcher::new(&config.fetch).expect("fetcher");
    let options = RunOptions { record_type: RecordFilter::All, limit: 25, dry_run: false };

    let err = run(&config, &options, &fetcher).await.unwrap_err();
    let message = err.to_string();
    assert!(message.contains("llama-server"), "actionable hint expected, got: {message}");
}

/// Live check against a real llama.cpp server. Run explicitly with:
/// `cargo test --test e2e_run -- --ignored`
#[tokio::test]
#[ignore = "requires a running llama-server on localhost:8080"]
async fn live_llama_extracts_json() {
    use eldrin_enricher::llm::LlmClient;

    #[derive(Debug, serde::Deserialize)]
    struct Out {
        name: Option<String>,
    }

    let config = LlmConfig {
        base_url: "http://localhost:8080/v1".to_string(),
        model: "gemma-4-31b".to_string(),
    };
    let client = LlmClient::new(&config, 300).expect("client");
    let out: Out = client
        .extract(
            "Extract the company name from the text.",
            "Welcome to Acme Corporation, the world's leading widget maker.",
            &json!({"type": "object", "properties": {"name": {"type": "string"}}}),
        )
        .await
        .expect("live extract");
    assert!(out.name.unwrap_or_default().to_lowercase().contains("acme"));
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-enricher && cargo test --test e2e_run
```

Expected: compile FAILURE — `runner` module missing.

- [ ] **Step 3: Implement `runner.rs`**

```rust
//! Preflight checks + orchestration: pull pending, run pipelines with bounded
//! concurrency, collect outcomes.

use crate::config::Config;
use crate::eldrin::{EldrinClient, PendingItem};
use crate::enrich::company::enrich_company;
use crate::enrich::contact::enrich_contact;
use crate::enrich::{Deps, Outcome};
use crate::fetch::Fetcher;
use crate::llm::LlmClient;
use crate::report::RunSummary;
use futures::{stream, StreamExt};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RunError {
    #[error("{0}")]
    Preflight(String),
    #[error("run failed: {0}")]
    Client(String),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RecordFilter {
    Contact,
    Company,
    All,
}

impl RecordFilter {
    pub fn as_query_param(&self) -> Option<&'static str> {
        match self {
            RecordFilter::Contact => Some("contact"),
            RecordFilter::Company => Some("company"),
            RecordFilter::All => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub record_type: RecordFilter,
    pub limit: u32,
    pub dry_run: bool,
}

pub async fn run(
    config: &Config,
    options: &RunOptions,
    fetcher: &dyn Fetcher,
) -> Result<RunSummary, RunError> {
    let eldrin = EldrinClient::new(&config.core_url, config.app_secret.clone(), 30)
        .map_err(|err| RunError::Client(err.to_string()))?;
    let llm = LlmClient::new(&config.llm, 300).map_err(|err| RunError::Client(err.to_string()))?;

    eldrin.health_check().await.map_err(|err| {
        RunError::Preflight(format!(
            "Eldrin CRM not reachable via {} — is the local stack running and the \
             secret correct? ({err})",
            config.core_url
        ))
    })?;
    llm.health_check().await.map_err(|err| {
        RunError::Preflight(format!(
            "llama.cpp not reachable on {} — is llama-server running? ({err})",
            config.llm.base_url
        ))
    })?;

    let items = eldrin
        .pull_pending(options.record_type.as_query_param(), options.limit, 0)
        .await
        .map_err(|err| RunError::Client(err.to_string()))?;
    tracing::info!("pulled {} pending record(s)", items.len());

    let deps = Deps { fetcher, llm: &llm, eldrin: &eldrin, config };
    let dry_run = options.dry_run;
    // Bounded concurrency: fetches overlap up to fetch.concurrency; LLM calls
    // queue on the client's internal 1-permit semaphore.
    let outcomes: Vec<Outcome> = stream::iter(items)
        .map(|item| {
            let deps = &deps;
            async move {
                match item {
                    PendingItem::Company(company) => {
                        enrich_company(&company, deps, dry_run).await
                    }
                    PendingItem::Contact(contact) => {
                        enrich_contact(&contact, deps, dry_run).await
                    }
                }
            }
        })
        .buffered(config.fetch.concurrency.max(1))
        .collect()
        .await;

    Ok(RunSummary { outcomes })
}
```

- [ ] **Step 4: Replace `main.rs` with the real CLI**

```rust
use clap::{Parser, Subcommand, ValueEnum};
use eldrin_enricher::config::Config;
use eldrin_enricher::fetch::DirectFetcher;
use eldrin_enricher::runner::{run, RecordFilter, RunOptions};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "eldrin-enricher", version, about = "Local LLM enrichment for Eldrin CRM")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Pull pending records, enrich via the local LLM, apply results back.
    Run {
        /// Which record types to process.
        #[arg(long = "type", value_enum, default_value_t = TypeArg::All)]
        record_type: TypeArg,
        /// Max records to pull (server caps at 100).
        #[arg(long)]
        limit: Option<u32>,
        /// Print would-be payloads without applying anything.
        #[arg(long)]
        dry_run: bool,
        /// Path to enricher.toml (default: ./enricher.toml if present).
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum TypeArg {
    Contact,
    Company,
    All,
}

impl From<TypeArg> for RecordFilter {
    fn from(value: TypeArg) -> Self {
        match value {
            TypeArg::Contact => RecordFilter::Contact,
            TypeArg::Company => RecordFilter::Company,
            TypeArg::All => RecordFilter::All,
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("eldrin_enricher=info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Run { record_type, limit, dry_run, config } => {
            let config = match Config::load(config.as_deref()) {
                Ok(config) => config,
                Err(err) => {
                    eprintln!("config error: {err}");
                    return ExitCode::FAILURE;
                }
            };
            let fetcher = match DirectFetcher::new(&config.fetch) {
                Ok(fetcher) => fetcher,
                Err(err) => {
                    eprintln!("fetcher error: {err}");
                    return ExitCode::FAILURE;
                }
            };
            let options = RunOptions {
                record_type: record_type.into(),
                limit: limit.unwrap_or(config.run.limit),
                dry_run,
            };
            match run(&config, &options, &fetcher).await {
                Ok(summary) => {
                    println!("{}", summary.render());
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("error: {err}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}
```

- [ ] **Step 5: Run all tests to verify they pass**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-enricher && cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test
```

Expected: all unit + e2e tests PASS.

- [ ] **Step 6: Smoke the binary manually (no services needed — expect the actionable preflight error)**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-enricher && cargo run -- run --dry-run 2>&1 | tail -2
```

Expected: `error: Eldrin CRM not reachable via http://localhost:4000 — ...` and exit code 1 (or a real dry-run summary if the local stack happens to be running).

- [ ] **Step 7: Commit**

```bash
git -C /Users/tibor/projects/eldrin-backup/eldrin-enricher add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-enricher commit -m "feat: runner orchestration and clap CLI with preflight checks"
```

---

### Task 10: Docs, coverage check, push, and parent-repo submodule wiring

**Files:**
- Create: `eldrin-enricher/README.md`, `eldrin-enricher/CLAUDE.md`
- Modify: parent repo `.gitmodules` (already staged by Task 1's `submodule add`), parent gitlink commit

- [ ] **Step 1: Write `README.md`**

```markdown
# eldrin-enricher

Local, on-demand enrichment app for Eldrin CRM. Pulls contacts/companies whose
`aiEnhancementStatus` is `pending`, enriches them with a **local LLM** (Gemma
via llama.cpp) plus direct web fetch of company homepages, and applies results
back through the CRM's enhancement endpoints. Failures leave records `pending`,
so re-running retries naturally.

## Prerequisites

1. The local Eldrin stack (eldrin-core on :4000, eldrin-crm on :4009).
2. A llama.cpp server:

   ```bash
   llama-server -hf unsloth/gemma-4-31B-it-GGUF:UD-Q4_K_XL \
     --alias "gemma-4-31b" --port 8080 --ctx-size 262144 \
     --flash-attn on -ctk q8_0 -ctv q8_0 -ngl 99
   ```

## Usage

```bash
export ELDRIN_APP_SECRET=<JWT_SECRET from eldrin-core/.dev.vars>
cargo run --release -- run                 # everything pending
cargo run --release -- run --type company  # companies only
cargo run --release -- run --dry-run       # show payloads, apply nothing
cargo run --release -- run --limit 5
```

Configuration: copy `enricher.example.toml` to `enricher.toml` (gitignored) or
use `ELDRIN_*` env vars. Env wins over file. The secret is env-only.

## How it works

pull `GET /api/enhancement/pending` → per record:
- **company**: fetch `https://<domain>` (fallback `www.`/`http`, + about page)
  → reduce HTML → Gemma extracts `{name, description, industry}` from page
  text only → logo taken mechanically from `og:image`/favicon (never the LLM)
  → `POST /api/enhancement/companies/:id`
- **contact**: latest email body ships with the pending item → Gemma extracts
  `{jobTitle, phones, social}` → `POST /api/enhancement/contacts/:id`

Fetches run concurrently (`fetch.concurrency`); LLM calls are serialized —
one 31B model on one GPU gains nothing from parallel requests.

## Development

```bash
cargo test                                  # unit + wiremock integration tests
cargo clippy --all-targets -- -D warnings
cargo llvm-cov --fail-under-lines 80        # optional, needs cargo-llvm-cov
```

Design spec: `docs/superpowers/specs/2026-07-11-eldrin-enricher-design.md`
(parent repo). Future (designed-for, not built): `serve` HTTP mode for
app-initiated enrichment, search-engine `Fetcher` implementations (SearXNG),
deal-suggestion assessment.
```

- [ ] **Step 2: Write `CLAUDE.md`**

```markdown
# eldrin-enricher — Development Guide

Local Rust CLI that enriches Eldrin CRM contacts/companies with a local LLM
(llama.cpp, OpenAI-compatible on :8080) + direct web fetch. Consumes the CRM
enhancement contract (`eldrin-crm/worker/routes/enhancement.ts`); auth is the
`X-Eldrin-App-Secret` header (value = shared `JWT_SECRET`, env-only).

## Commands

```bash
cargo test                                # all tests (wiremock, no network)
cargo clippy --all-targets -- -D warnings # must stay clean
cargo run -- run --dry-run                # needs local stack + llama-server
```

## Architecture

- `config.rs` — defaults <- enricher.toml <- ELDRIN_* env (env wins)
- `eldrin.rs` — CRM pull/apply client via core proxy (`/api/app/eldrin-crm`)
- `llm.rs` — chat-completions client; schema-in-system-prompt convention must
  stay byte-identical to eldrin-workflows `openai.ts`; internal 1-permit
  semaphore serializes inference
- `fetch.rs` — `Fetcher` trait + `DirectFetcher` (https → www → http fallback)
- `extract.rs` — HTML → text; logo mechanically from og:image/favicon ONLY
- `enrich/{company,contact}.rs` — pipelines returning `Outcome`
- `runner.rs` — preflight + `stream::buffered` orchestration
- `report.rs` — summary rendering

## Invariants

- `source` on apply payloads is `"eldrin-enricher"`.
- `logoUrl` never comes from LLM output.
- Per-record failures don't abort the run and leave the record `pending`
  server-side (the retry mechanism) — exit 0. Only preflight/config errors
  exit non-zero.
- Tests never touch the real network; everything mocks via wiremock.
```

- [ ] **Step 3: Optional coverage check, then commit and push the submodule**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-enricher
cargo llvm-cov --fail-under-lines 80 2>/dev/null || echo "cargo-llvm-cov not installed — skipping coverage gate"
git -C /Users/tibor/projects/eldrin-backup/eldrin-enricher add -A
git -C /Users/tibor/projects/eldrin-backup/eldrin-enricher commit -m "docs: README and CLAUDE.md"
git -C /Users/tibor/projects/eldrin-backup/eldrin-enricher push -u origin main
```

- [ ] **Step 4: Verify CI is green**

```bash
gh run watch --repo eldrin-project/eldrin-enricher --exit-status $(gh run list --repo eldrin-project/eldrin-enricher --limit 1 --json databaseId --jq '.[0].databaseId')
```

Expected: CI PASSES (fmt, clippy, test). Fix and re-push if not.

- [ ] **Step 5: Commit the parent repo (submodule + plan)**

```bash
git -C /Users/tibor/projects/eldrin-backup add .gitmodules eldrin-enricher docs/superpowers/plans/2026-07-11-eldrin-enricher.md
git -C /Users/tibor/projects/eldrin-backup commit -m "feat: add eldrin-enricher submodule (local LLM enrichment app)"
git -C /Users/tibor/projects/eldrin-backup submodule status eldrin-enricher
```

Expected: parent commit created on the current branch; submodule status shows the pushed commit SHA. (Do NOT push the parent without the user's go-ahead.)

- [ ] **Step 6: Live smoke test (only if the local stack + llama-server are running)**

```bash
cd /Users/tibor/projects/eldrin-backup/eldrin-enricher
export ELDRIN_APP_SECRET=$(grep '^JWT_SECRET=' /Users/tibor/projects/eldrin-backup/eldrin-crm/.dev.vars | cut -d= -f2-)
cargo run --release -- run --dry-run --limit 3
```

Expected: preflight passes, up to 3 records processed, `→ would apply` lines with plausible payloads, exit 0. If the stack is down, note it in the completion report and leave this for the user.
