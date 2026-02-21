# litho-book v0.4.0 Context Save

**Date:** 2026-02-20
**Branch:** main @ be55de9
**Version:** 0.4.0 (upgraded from 0.3.9)

## State Summary

litho-book v0.4.0 is a complete optimization and quality assurance release. All dead code has been wired up (not deleted), duplicated functions extracted to a shared `utils.rs` module, performance improved via `Arc<AppState>` and in-memory file serving, security hardened with path traversal guards and XSS fixes, and the project now has 43 passing tests (from zero). The SSE buffer parser bug that silently dropped partial lines at TCP chunk boundaries has been fixed. The template has been generalized to work with any markdown repo, not just Chinese litho-generated docs.

## Architecture (v0.4.0)

```
src/
  main.rs      (159 lines) - Entry, logging, browser open
  cli.rs       (84 lines)  - Clap derive Args
  utils.rs     (142 lines) - NEW: shared format_bytes, format_system_time, should_skip, sort_entries
  filesystem.rs (627 lines) - DocumentTree with node_map, memory-first serving, path traversal guard
  server.rs    (662 lines) - Arc<AppState>, cached index HTML, shared reqwest::Client, fixed SSE
  error.rs     (98 lines)  - LithoBookError with IntoResponse impl
templates/
  index.html.tpl (5659 lines) - SPA with escapeHtml, generalized defaults
```

## Key Changes in v0.4.0

### Performance
- `AppState` uses `Arc<DocumentTree>` instead of deep-cloning on every request
- Index HTML computed once at startup, cached as `Arc<String>`
- Shared `reqwest::Client` (one connection pool for process lifetime)
- LLM key read once at startup (was per-request `env::var`)
- File content served from in-memory search index (no disk I/O for indexed .md files)
- `node_map` provides O(1) file metadata lookups (no `fs::metadata` per request)

### Security
- Path traversal guard on disk-read fallback (canonicalize + prefix check)
- HTML entity escaping in search highlight output
- `escapeHtml()` in template's renderSimpleMarkdown (XSS in code blocks)

### Bug Fixes
- SSE buffer parser: partial lines at TCP chunk boundaries were silently dropped
- `highlight_matches()` now marks ALL occurrences (was only first)
- Sort consistency: root dir was case-sensitive, subdirs case-insensitive (now all case-insensitive)

### Code Quality
- 4 duplicate functions extracted to `utils.rs`
- `LithoBookError` has `IntoResponse` impl - handlers return proper error types
- Removed unused `walkdir` and `tower` direct dependencies
- CI now runs `cargo fmt --check` and `cargo clippy` before build
- 43 tests: 10 utils + 7 error + 17 filesystem + 9 server integration

### Template Generalization
- Default file list: README.md first, Chinese-specific names last
- `findArchitectureFile()` helper replaces 4 hardcoded `'2、架构概览.md'` references
- Works with any markdown repo, not just litho-generated docs

## Agent Work Registry

| Agent | Phase | Files Touched | Duration |
|-------|-------|---------------|----------|
| (direct) | 1: utils.rs | src/utils.rs, src/main.rs | ~2 min |
| rust-pro | 2A: filesystem | src/filesystem.rs, src/utils.rs | ~110s |
| rust-pro | 2B+2C+3: server | src/error.rs, src/server.rs | ~113s |
| javascript-pro | 4: template | templates/index.html.tpl | ~82s |
| general-purpose | 5: infra | Cargo.toml, CI, sccache configs | ~115s |
| rust-pro | 6: tests | error.rs, filesystem.rs, server.rs, Cargo.toml | ~222s |

## Build Environment Notes
- sccache port 4226 blocked by Windows port exclusion range 4171-4270
- Fixed to port 4400 in: CargoTools/Private/Environment.ps1, setup-sccache-env.ps1, .cargo/config.toml
- Bash workaround: `RUSTC_WRAPPER="" cargo build` bypasses sccache entirely
- `SCCACHE_SERVER_PORT` env var in system still set to 4226 (needs system env update)

## Dependencies (notable changes)
- Removed: walkdir 2.5, tower 0.5 (direct dep)
- Added dev-deps: tempfile 3, tower 0.5 (util feature), http 1
- Kept: axum 0.8.4, tokio 1.47, pulldown-cmark 0.13, reqwest 0.12, tower-http 0.6

## Not Addressed (intentional)
- Windows `is_privileged()` always returns true (low impact for localhost)
- CORS permissive (intentional for localhost)
- Pre-computed lowercase search index (2x memory for marginal gain)
- Mermaid CDN without SRI hash
