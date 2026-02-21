# Rust Context Slice - litho-book

## Build
```bash
cargo build --release
cargo run -- --docs-dir ./docs --open --verbose
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo test  # zero tests currently
```

## Environment
- Rust 1.93.0, Edition 2024
- CARGO_HOME=T:\RustCache\cargo-home
- CARGO_TARGET_DIR=T:\RustCache\cargo-target
- sccache available

## Crate Structure
Single binary crate (no workspace, no lib). Entry: `src/main.rs`.

## Key Dependencies
axum 0.8.4, tokio 1.47 (full), pulldown-cmark 0.13, clap 4.5 (derive), reqwest 0.12 (json+stream), tower-http 0.6 (fs+cors), serde/serde_json 1.0, tracing 0.1, chrono 0.4, async-stream 0.3, futures 0.3, anyhow 1.0, thiserror 1.0. Unix-only: libc 0.2.

## Unused Dep
`walkdir 2.5` is declared but never imported. Filesystem scan uses `std::fs::read_dir` manually.

## Patterns
- Error handling: `anyhow::Result` throughout handlers, `LithoBookError` enum defined but underutilized
- State: `AppState { doc_tree: DocumentTree, docs_path: String }` shared via `axum::extract::State`
- DocumentTree: `Clone`, built once at startup, never refreshed
- Template: `include_str!("../templates/index.html.tpl")` with `String::replace()` for two placeholders
- AI chat: SSE via `axum::response::sse::Sse`, reqwest streaming to Zhipu API
