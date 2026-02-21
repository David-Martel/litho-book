# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**litho-book** (v0.3.9) is a Rust-based local web server that renders directories of Markdown files as a browsable SPA. It is the reader companion to [deepwiki-rs (Litho)](https://github.com/sopaco/deepwiki-rs), which generates architecture documentation from codebases. The typical workflow is:

```bash
deepwiki-rs -p ./some-project -o ./docs   # generate docs
litho-book --docs-dir ./docs --open       # read them
```

`deepwiki-rs` is installed locally at `C:\Users\david\.cargo\bin\deepwiki-rs.exe`.

## Build Commands

All builds use a shared Rust cache on `T:\RustCache\` (CARGO_HOME, RUSTUP_HOME, CARGO_TARGET_DIR are set globally). sccache is available at `T:\RustCache\sccache`.

```bash
# Build (release)
cargo build --release

# Dev run (uses ./docs as sample content)
cargo run -- --docs-dir ./docs --open --verbose

# Lint & format
cargo clippy --all-targets -- -D warnings
cargo fmt --check          # verify; omit --check to auto-format

# Tests (none exist yet - the test harness runs but finds zero tests)
cargo test
```

**CargoTools PowerShell module** (`~/wezterm/tools/CargoTools/`) provides `Invoke-CargoRoute` for routing builds to Windows/WSL/Docker by target triple and managing sccache. From Git Bash, invoke via:
```bash
powershell.exe -NoProfile -Command "Import-Module ~/wezterm/tools/CargoTools; Invoke-CargoWrapper build --release"
```
For plain Windows-target builds (this project), direct `cargo` commands in Git Bash work fine. CargoTools is mainly useful for cross-compilation scenarios.

**Git Bash caveat**: Forward-slash paths in arguments can be misinterpreted. For paths passed to PowerShell or Windows tools, use backslashes or quote carefully.

## Architecture

Four Rust source files, one self-contained HTML template:

### Source Layout

| File | Role |
|------|------|
| `src/main.rs` | Entry point: logging init, `DocumentTree` creation, Axum server bind, cross-platform browser open |
| `src/cli.rs` | `Args` struct (clap derive): `--docs-dir`, `--port`, `--host`, `--open`, `--verbose` |
| `src/server.rs` | Axum router, all HTTP handlers, AI chat SSE streaming (Zhipu GLM-4.7-Flash via `LITHO_BOOK_LLM_KEY` env var) |
| `src/filesystem.rs` | `DocumentTree`: recursive dir scan, `FileNode` tree, in-memory search index (`HashMap<String, Vec<String>>`), markdown→HTML via pulldown-cmark |
| `src/error.rs` | `LithoBookError` enum (thiserror) with StatusCode mapping; server code mostly uses `anyhow::Result` in practice |

### Frontend

`templates/index.html.tpl` (~5,600 lines) is a **fully self-contained SPA** — all CSS, HTML, and JS inline. It is embedded at compile time via `include_str!` in `server.rs`. Two placeholders are string-replaced at runtime:
- `{{ tree_json|safe }}` → JSON doc tree
- `{{ docs_path }}` → docs directory path

No npm, no bundler. Only external runtime dependency is Mermaid from jsDelivr CDN.

### API Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Serves the SPA (template with injected tree JSON) |
| `/api/file?file=<path>` | GET | Returns JSON: raw content + rendered HTML |
| `/api/tree` | GET | Full document tree as JSON |
| `/api/search?q=<query>` | GET | Full-text line-by-line search, max 50 results |
| `/api/stats` | GET | File/dir counts, total size |
| `/api/chat` | POST | SSE streaming AI chat (requires `LITHO_BOOK_LLM_KEY`) |
| `/health` | GET | Health check |
| `/assets/*` | GET | Static file serving from `assets/` dir |

### Key Design Decisions

- **Single binary deployment**: The HTML template is compiled in; no external files needed except the docs directory and optional `assets/`.
- **No hot reload**: Document tree is built once at startup. New files require restart.
- **In-memory search**: All `.md` file lines loaded into a HashMap at startup. Works well for typical doc sets; memory-intensive for very large corpora.
- **`DocumentTree` is `Clone`**: Shared via Axum's `State` extractor.
- **Path normalization**: Windows backslashes converted to forward slashes for API compatibility.
- **`walkdir` crate is declared but unused**: The filesystem scan uses manual `std::fs::read_dir` recursion instead.

## CI

GitHub Actions (`.github/workflows/rust.yml`): build + test on ubuntu-latest, triggered on push/PR to main. No clippy or fmt checks in CI.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `LITHO_BOOK_LLM_KEY` | API key for Zhipu AI chat feature (optional; chat degrades gracefully without it) |

## Crate Dependencies (notable)

axum 0.8, tokio (full), pulldown-cmark 0.13, clap 4.5 (derive), reqwest 0.12 (json+stream for AI chat), tower-http (fs+cors), serde/serde_json, tracing/tracing-subscriber, chrono, async-stream, futures. Unix-only: libc (privilege check for low ports).
