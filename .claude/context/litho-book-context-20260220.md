# Litho Book - Project Context

**Context ID:** ctx-litho-book-20260220
**Created:** 2026-02-20
**Created By:** claude-opus-4-6 (context-save skill)
**Schema Version:** 2.0

## Project

| Field | Value |
|-------|-------|
| Name | litho-book |
| Root | `C:\codedev\litho-book` |
| Type | Rust (single crate, no workspace) |
| Branch | main |
| Commit | be55de9 |
| Version | 0.3.9 |
| Upstream | sopaco/litho-book |
| Fork | David-Martel/litho-book |

## Current State

Litho-book is a Rust/Axum web server that renders Markdown directories as a browsable SPA. It is the reader companion to deepwiki-rs (Litho), which generates architecture documentation from codebases.

### Session Work Completed
- Created `CLAUDE.md` with full architectural documentation
- Forked `sopaco/litho-book` to `David-Martel/litho-book`
- Forked and cloned `sopaco/deepwiki-rs` to `C:\codedev\deepwiki-rs` (source for debugging/customizing)
- Forked and cloned `sopaco/mermaid-fixer` to `C:\codedev\mermaid-fixer` (mermaid diagram fix utility)
- Configured remotes: `origin` = David-Martel, `upstream` = sopaco (all 3 repos)

### Related Repos (sopaco ecosystem)

| Repo | Local Path | Purpose |
|------|-----------|---------|
| sopaco/deepwiki-rs | `C:\codedev\deepwiki-rs` | AI doc generation engine (litho-book reads its output) |
| sopaco/mermaid-fixer | `C:\codedev\mermaid-fixer` | Auto-fix mermaid syntax errors in markdown |
| sopaco/litho-book | `C:\codedev\litho-book` | This repo - markdown reader SPA |
| sopaco/saga-reader | not cloned | Another reader project by sopaco |
| sopaco/cortex-mem | not cloned | Memory/context management tool |
| sopaco/cowork-forge | not cloned | Collaboration forge tool |

### Binary Install
- `deepwiki-rs` installed at `C:\Users\david\.cargo\bin\deepwiki-rs.exe` (cargo install)

## Architecture Summary

4 Rust source files + 1 self-contained HTML template (~5,600 lines):

| File | Role |
|------|------|
| `src/main.rs` | Entry: logging, DocumentTree creation, Axum bind, browser open |
| `src/cli.rs` | clap Args: `--docs-dir`, `--port`, `--host`, `--open`, `--verbose` |
| `src/server.rs` | Axum router, HTTP handlers, AI chat SSE (Zhipu GLM-4.7-Flash) |
| `src/filesystem.rs` | DocumentTree: recursive scan, FileNode tree, in-memory search index, pulldown-cmark rendering |
| `src/error.rs` | LithoBookError enum (thiserror), StatusCode mapping |
| `templates/index.html.tpl` | Self-contained SPA (CSS+HTML+JS), `include_str!` at compile time |

### API Routes
- `GET /` - SPA with injected tree JSON
- `GET /api/file?file=<path>` - Raw + rendered markdown
- `GET /api/tree` - Document tree JSON
- `GET /api/search?q=<query>` - Full-text search (max 50 results)
- `GET /api/stats` - File/dir counts
- `POST /api/chat` - SSE AI chat (requires `LITHO_BOOK_LLM_KEY`)
- `GET /health` - Health check

## Decisions

### dec-001: Fork strategy
- **Decision:** Fork all 3 sopaco repos to David-Martel, clone deepwiki-rs and mermaid-fixer locally
- **Rationale:** Enables customization, debugging, and PR contributions. deepwiki-rs source needed to understand output format. mermaid-fixer relevant for diagram handling.
- **Date:** 2026-02-20

### dec-002: Remote naming convention
- **Decision:** `origin` = David-Martel fork, `upstream` = sopaco original
- **Rationale:** Consistent with C:\codedev workspace convention (all repos have remotes pointing to David-Martel)
- **Date:** 2026-02-20

## Patterns

### Build Environment
- Shared Rust cache: `T:\RustCache\` (CARGO_HOME, RUSTUP_HOME, CARGO_TARGET_DIR)
- sccache available at `T:\RustCache\sccache`
- CargoTools PowerShell module at `~/wezterm/tools/CargoTools/` for cross-compilation routing
- Shell: Git Bash (forward-slash path issues with PowerShell/cmd)
- Rust 1.93.0, Cargo 1.93.0

### Coding Conventions (from source analysis)
- Comments in Chinese (Chinese developer audience)
- `anyhow::Result` for error propagation (despite thiserror enum existing)
- No tests exist
- No hot reload - restart required for doc changes
- `walkdir` declared but unused (manual recursion instead)
- Template "engine" is naive `String::replace()` (not Askama despite README claim)

### Testing Strategy
- **None currently.** CI runs `cargo test` but zero tests exist.

## Agent Work Registry

| Agent | Task | Files | Status | Handoff |
|-------|------|-------|--------|---------|
| Explore (sonnet) | Full codebase analysis | all src, templates, config | Complete | Architecture documented in CLAUDE.md |
| claude-opus-4-6 | CLAUDE.md creation | CLAUDE.md | Complete | Ready for use |
| claude-opus-4-6 | GitHub fork + clone setup | .git/config (3 repos) | Complete | Remotes configured |

## Roadmap

### Immediate
- [ ] Push CLAUDE.md to David-Martel/litho-book fork
- [ ] Build and test locally: `cargo build --release`
- [ ] Run against local codebase docs: `deepwiki-rs -p /c/codedev/some-project -o ./test-docs && cargo run -- --docs-dir ./test-docs --open`

### This Week
- [ ] Add basic tests (filesystem.rs parsing, server route handlers)
- [ ] Evaluate replacing Zhipu AI with local/configurable LLM endpoint
- [ ] Study deepwiki-rs output format to understand litho-book input expectations

### Tech Debt
- [ ] Remove unused `walkdir` dependency
- [ ] Add clippy + fmt checks to CI
- [ ] Fix README inaccuracy: claims Askama but uses String::replace
- [ ] Consider hot-reload for document tree (filesystem watcher)

### Customization Opportunities
- [ ] Make LLM endpoint configurable (not hardcoded to Zhipu)
- [ ] Add English UI strings (currently Chinese-primary)
- [ ] Add `--config` flag to read `.litho-book.toml` (file exists but is never parsed)

## Validation

- **Last Validated:** 2026-02-20
- **Git State:** Clean (main @ be55de9)
- **Remotes Verified:** origin=David-Martel, upstream=sopaco

## Next Agent Recommendations

1. **rust-pro**: Add tests for filesystem.rs and server.rs
2. **security-auditor**: Review the AI chat endpoint (SSE, API key handling, user input in search)
3. **code-reviewer**: Review template injection pattern for XSS in search/file content display
