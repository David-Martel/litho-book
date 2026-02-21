# Rust Context Slice - litho-book v0.4.0

## Build
```bash
cargo build --release
cargo run -- --docs-dir ./docs --open --verbose
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo test  # 43 tests
```

**sccache note:** Port 4226 blocked on this machine. Use `RUSTC_WRAPPER="" cargo build` or ensure `SCCACHE_SERVER_PORT=4400`.

## Environment
- Rust 1.93.0, Edition 2024
- CARGO_HOME=T:\RustCache\cargo-home
- CARGO_TARGET_DIR=T:\RustCache\cargo-target
- sccache at port 4400

## Crate Structure
Single binary crate (no workspace, no lib). Entry: `src/main.rs`.

5 source files + 1 utils module:
- main.rs (159 lines) - entry, logging, browser open
- cli.rs (84 lines) - clap derive Args
- utils.rs (142 lines) - shared: format_bytes, format_system_time, should_skip, sort_entries
- filesystem.rs (627 lines) - DocumentTree, search, highlight, render_markdown
- server.rs (662 lines) - Axum router, handlers, SSE chat streaming
- error.rs (98 lines) - LithoBookError with IntoResponse

## Key Dependencies
axum 0.8.4, tokio 1.47 (full), pulldown-cmark 0.13, clap 4.5 (derive), reqwest 0.12 (json+stream), tower-http 0.6 (fs+cors), serde/serde_json 1.0, tracing 0.1, chrono 0.4, async-stream 0.3, futures 0.3, anyhow 1.0, thiserror 1.0. Unix-only: libc 0.2.

Dev-deps: tempfile 3, tower 0.5 (util), http 1.

## Patterns
- Error handling: `LithoBookError` with `IntoResponse` impl; handlers return `Result<T, LithoBookError>`
- State: `AppState { doc_tree: Arc<DocumentTree>, docs_path, index_html: Arc<String>, http_client: reqwest::Client, llm_key: Arc<String> }`
- DocumentTree: `Clone`, built once at startup, never refreshed. Files served from in-memory search_index.
- node_map: `HashMap<String, FileNode>` for O(1) metadata lookups (no disk stat per request)
- docs_base_canonical: PathBuf for path traversal defense
- Template: `include_str!("../templates/index.html.tpl")` with `String::replace()` for two placeholders, cached at startup
- AI chat: SSE via `axum::response::sse::Sse`, reqwest streaming to Zhipu API with proper partial-line buffering
- Tests: 43 total using tempfile dirs and tower::ServiceExt::oneshot for handler integration tests
