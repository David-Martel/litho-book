# litho-book Enhanced Pipeline Design

**Date:** 2026-02-20
**Version:** 0.5.0 (target)
**Status:** Draft - Pending Approval
**Scope:** Full pipeline + new features (all sections)

## 1. Overview

litho-book v0.4.0 is a stable markdown doc server with in-memory indexing, Arc-based shared state, and 43 tests. This design extends it into a full-featured code intelligence platform that complements deepwiki-rs by adding AST-powered code analysis, hot reload, enhanced visualization, and multi-project workspace support.

### Goals

1. **Hot reload** - filesystem watching replaces restart-on-change workflow
2. **AST analysis** - structural code understanding via ast-grep/tree-sitter
3. **deepwiki-rs integration** - consume structured analysis output, trigger regeneration
4. **Rich visualization** - interactive dependency graphs, complexity heatmaps, auto-generated C4 diagrams
5. **Advanced search** - code search, symbol cross-references, fuzzy find
6. **Multi-project** - workspace mode serving multiple doc sets with cross-linking
7. **Middleware hardening** - timeouts, compression, rate limiting, panic recovery

### Non-Goals

- Modifying deepwiki-rs source code (it's upstream sopaco/deepwiki-rs)
- Full LSP protocol implementation
- Persistent database storage (all analysis stays in-memory)
- Authentication/authorization (remains localhost-only)
- Remote/cloud deployment

## 2. Architecture

### 2.1 Module Layout (target)

```
src/
  main.rs          - Entry, CLI dispatch, watcher bootstrap
  cli.rs           - Extended clap Args (new flags)
  utils.rs         - Shared utilities (unchanged)
  filesystem.rs    - DocumentTree with RwLock upgrade
  server.rs        - Axum router, middleware stack, all handlers
  error.rs         - Extended error variants
  ast_analysis.rs  - NEW: ast-grep integration, symbol extraction
  ast_rules.rs     - NEW: complexity, patterns, smells rule definitions
  code_search.rs   - NEW: source file indexing and search
  visualization.rs - NEW: graph generation (Mermaid + D3 JSON)
  deepwiki.rs      - NEW: deepwiki-rs output parser, re-analyze trigger
  workspace.rs     - NEW: multi-project coordination
  watcher.rs       - NEW: notify-based hot reload
templates/
  index.html.tpl   - Enhanced SPA with new panels
```

### 2.2 State Architecture

```rust
pub struct AppState {
    // Existing (v0.4.0)
    pub docs_path: String,
    pub index_html: Arc<String>,
    pub http_client: reqwest::Client,
    pub llm_key: Arc<String>,

    // Upgraded: Arc<DocumentTree> -> Arc<RwLock<DocumentTree>>
    pub doc_tree: Arc<RwLock<DocumentTree>>,

    // New
    pub ast_index: Arc<RwLock<Option<AstIndex>>>,
    pub source_path: Option<PathBuf>,
    pub workspace: Arc<RwLock<Workspace>>,
    pub watcher_tx: Option<broadcast::Sender<WatchEvent>>,
    pub deepwiki_meta: Arc<RwLock<Option<DeepwikiMeta>>>,
}
```

### 2.3 Dependency Additions

| Crate | Version | Purpose |
|-------|---------|---------|
| `notify` | 7 | Cross-platform filesystem watching |
| `ast-grep-core` | 0.39 | AST parsing via tree-sitter |
| `tree-sitter` | 0.24 | Grammar loading for ast-grep |
| `tree-sitter-rust` | 0.24 | Rust grammar |
| `tree-sitter-python` | 0.23 | Python grammar |
| `tree-sitter-typescript` | 0.23 | TypeScript/JavaScript grammars |
| `tree-sitter-go` | 0.23 | Go grammar |
| `tree-sitter-java` | 0.23 | Java grammar |
| `tower` | 0.5 | Middleware (re-added as runtime dep) |
| `parking_lot` | 0.12 | Fast RwLock (optional, vs std) |

Dev-dependencies remain: tempfile, tower (util), http.

## 3. Hot Reload (watcher.rs)

### 3.1 Design

```
notify::RecommendedWatcher
    │
    ├─ Create/Modify .md → rebuild affected FileNode + search_index entries
    ├─ Delete .md → remove from tree + index
    ├─ Create/Modify source → re-run AST analysis for file
    └─ Any change → broadcast WatchEvent to SSE subscribers
```

### 3.2 Implementation

- `notify` v7 with `RecommendedWatcher` in debounced mode (500ms)
- Background tokio task receives `notify::Event`, maps to `WatchEvent` enum
- `WatchEvent` variants: `DocChanged(path)`, `DocDeleted(path)`, `SourceChanged(path)`, `TreeRebuilt`
- DocumentTree upgraded to `Arc<RwLock<DocumentTree>>` - watcher acquires write lock to update
- Partial rebuild: only reparse changed files, don't rebuild entire tree
- SSE endpoint `/api/events` streams `WatchEvent` to browser via `broadcast::channel`
- Template adds `EventSource('/api/events')` listener that refreshes sidebar on `TreeRebuilt`

### 3.3 CLI

```
--watch              Enable hot reload (default: off)
--watch-debounce     Debounce interval in ms (default: 500)
```

## 4. AST Analysis Pipeline (ast_analysis.rs, ast_rules.rs)

### 4.1 Core Symbol Extraction

Using `ast-grep-core` with tree-sitter grammars to extract:

| Symbol Type | Languages | ast-grep Pattern Example |
|-------------|-----------|--------------------------|
| Functions | All | `fn $NAME($$$PARAMS) { $$$ }` (Rust) |
| Structs/Classes | All | `struct $NAME { $$$ }` (Rust), `class $NAME { $$$ }` (TS/Py) |
| Traits/Interfaces | Rust, TS, Java, Go | `trait $NAME { $$$ }` |
| Impl blocks | Rust | `impl $TRAIT for $TYPE { $$$ }` |
| Imports | All | `use $PATH;` (Rust), `import $$$` (TS) |
| Exports | TS, JS | `export $$$` |
| Test functions | Rust, Python | `#[test] fn $NAME() { $$$ }`, `def test_$NAME($$$)` |

### 4.2 Complexity Metrics

Per-function analysis using AST node counting:

- **Cyclomatic complexity**: Count branching nodes (if, match, while, for, &&, ||)
- **Cognitive complexity**: Weighted by nesting depth (B. cognitive complexity paper)
- **Lines of code**: Function body line count
- **Parameter count**: From function signature
- **Fan-out**: Count of distinct function calls within body

Thresholds (configurable):
- Green: complexity < 10
- Yellow: 10 <= complexity < 20
- Red: complexity >= 20

### 4.3 Design Pattern Detection

ast-grep rules for common patterns:

| Pattern | Detection Rule |
|---------|---------------|
| Builder | Struct with methods returning `Self`, `build()` method |
| Observer | Trait with `on_*`/`handle_*` methods + subscriber vec |
| Strategy | Trait object field + impl dispatch |
| Singleton | `static` + `Once`/`OnceLock` + `get_instance()` |
| Factory | Function returning `Box<dyn Trait>` or `impl Trait` |

### 4.4 Code Smell Detection

| Smell | Rule | Threshold |
|-------|------|-----------|
| Long method | Function body > N lines | 50 lines |
| Deep nesting | Max nesting depth > N | 4 levels |
| God struct | Struct with > N fields | 15 fields |
| High fan-out | Function calls > N distinct functions | 10 calls |
| Unused imports | Import not referenced in file body | 0 refs |

### 4.5 Test Coverage Correlation

- Match `#[test]` / `#[cfg(test)]` functions to their tested symbols
- Heuristic: test function name contains symbol name (e.g., `test_format_bytes` tests `format_bytes`)
- AST-based: test body calls the symbol directly
- Coverage indicators: tested (green), partially tested (yellow), untested (red)

### 4.6 AstIndex Structure

```rust
pub struct AstIndex {
    pub symbols: HashMap<String, Vec<Symbol>>,      // file -> symbols
    pub references: HashMap<String, Vec<Reference>>, // symbol -> usages
    pub complexity: HashMap<String, Vec<FnMetrics>>, // file -> function metrics
    pub patterns: HashMap<String, Vec<Pattern>>,     // file -> detected patterns
    pub smells: HashMap<String, Vec<CodeSmell>>,     // file -> code smells
    pub test_coverage: HashMap<String, CoverageStatus>, // symbol -> coverage
    pub languages: HashSet<String>,                  // active languages
}

pub struct Symbol {
    pub name: String,
    pub kind: SymbolKind, // Function, Struct, Trait, Impl, Import, Test
    pub line: usize,
    pub end_line: usize,
    pub signature: String,
    pub visibility: Visibility, // Pub, PubCrate, Private
    pub parent: Option<String>, // impl block or module
}
```

## 5. deepwiki-rs Output Integration (deepwiki.rs)

### 5.1 Structured Metadata Parsing

deepwiki-rs generates docs in a directory structure. When present, a `.litho/` metadata directory contains intermediate analysis. litho-book will parse:

- **File importance scores** (0.0-1.0) - used to weight sidebar ordering
- **Dependency lists** - parsed from CodeDossier for graph generation
- **Interface definitions** - public API surface per file
- **Code purpose classifications** - Core Logic, Configuration, Testing, Utilities, etc.

### 5.2 Fallback: Markdown Header Parsing

When `.litho/` metadata isn't available, extract structure from the markdown docs themselves:
- Parse H1/H2/H3 headers for document structure
- Extract code blocks for language detection
- Parse mermaid diagrams for relationship data
- Look for `<!--litho:importance=0.8-->` HTML comments

### 5.3 Re-Analyze Trigger

- UI button "Regenerate Docs" checks for `deepwiki-rs` in PATH
- Shells out to: `deepwiki-rs -p {source_dir} -o {docs_dir} --force`
- Watches for completion, then triggers hot-reload of docs
- Progress shown via SSE events
- Disabled (greyed out) if deepwiki-rs not found

### 5.4 Importance-Weighted Navigation

Sidebar sorting modes (user-toggleable):
1. **Alphabetical** (current default)
2. **By importance** (deepwiki-rs scores, highest first)
3. **By complexity** (AST metrics, most complex first)
4. **By recent change** (file modification time, newest first)

## 6. Enhanced Visualization

### 6.1 Interactive Dependency Graph

**Technology**: D3.js force-directed graph (bundled inline, ~30KB minified)

- Nodes = files/modules, sized by importance score
- Edges = dependencies (import/use), colored by type
- Click node → navigate to that file's docs
- Hover → show file summary tooltip
- Filter by: module, dependency type, importance threshold
- Layout: force-directed with gravity toward center

**API**: `GET /api/viz/dependency-graph` returns:
```json
{
  "nodes": [{"id": "src/main.rs", "importance": 0.9, "group": "core", "complexity": 12}],
  "links": [{"source": "src/main.rs", "target": "src/server.rs", "type": "import"}]
}
```

### 6.2 Complexity Heatmap

- File list sidebar shows color-coded complexity badges
- Click badge → expand to per-function breakdown
- Color scale: green (low) → yellow (medium) → red (high)
- Sortable by max complexity, average complexity, or total LOC

### 6.3 Auto-Generated C4 Diagrams

When AST data is available (no deepwiki-rs needed), generate Mermaid diagrams:

- **Context diagram**: External dependencies (from Cargo.toml/package.json/pyproject.toml)
- **Container diagram**: Binary/library crates with their roles
- **Component diagram**: Module-level relationships from import analysis
- **Code diagram**: Struct/trait relationships within a module

Rendered via existing Mermaid CDN integration. Accessible at `/api/viz/c4?level=component`.

## 7. Advanced Search & Symbol Navigation (code_search.rs)

### 7.1 Code Search

When `--source-dir` is provided, index source files for full-text search:

- Separate search index from doc search (`search_index` for docs, `code_index` for source)
- `GET /api/search/code?q=<query>&lang=<optional>` endpoint
- Results include: file, line number, surrounding context, symbol context (which function)
- Syntax-highlighted results in UI

### 7.2 Symbol Cross-References

Bidirectional linking between docs and code:

- **Doc → Code**: When docs mention a symbol name (detected via backtick parsing), link to its definition
- **Code → Doc**: For each symbol, find which doc files reference it
- UI: Hovering a backticked symbol in docs shows a tooltip with definition + link to source
- `GET /api/ast/xref?symbol=<name>` returns both doc and code references

### 7.3 Fuzzy Symbol Search

Ctrl+P style quick-open dialog:

- Searches across: doc files, source symbols, headings
- Weighted ranking: exact match > prefix > fuzzy (Levenshtein)
- Results grouped by type (Doc, Symbol, Heading)
- `GET /api/search/fuzzy?q=<query>&limit=20`
- Implementation: pre-computed trigram index for sub-10ms response

## 8. Multi-Project Workspace (workspace.rs)

### 8.1 CLI

```
litho-book --workspace ./workspace.toml
# OR
litho-book --docs-dir ./project-a/docs --docs-dir ./project-b/docs \
           --source-dir ./project-a --source-dir ./project-b
```

### 8.2 Workspace Config

```toml
# workspace.toml
[workspace]
name = "My Projects"

[[project]]
name = "litho-book"
docs = "./litho-book/docs"
source = "./litho-book"

[[project]]
name = "deepwiki-rs"
docs = "./deepwiki-rs/docs"
source = "./deepwiki-rs"
```

### 8.3 Features

- **Tab bar** at top of SPA for switching between projects
- **Unified search** across all loaded projects (prefixed by project name)
- **Cross-project linking**: if project A imports crate B and project B is loaded, clicking the import navigates to B's docs
- **Shared analysis**: AST index spans all projects for cross-reference resolution
- **Independent hot-reload**: each project has its own watcher

### 8.4 State Architecture

```rust
pub struct Workspace {
    pub name: String,
    pub projects: Vec<Project>,
    pub active_project: usize,
    pub cross_refs: HashMap<String, Vec<CrossRef>>, // symbol -> projects referencing it
}

pub struct Project {
    pub name: String,
    pub doc_tree: Arc<RwLock<DocumentTree>>,
    pub ast_index: Arc<RwLock<Option<AstIndex>>>,
    pub docs_path: PathBuf,
    pub source_path: Option<PathBuf>,
    pub deepwiki_meta: Option<DeepwikiMeta>,
}
```

## 9. Middleware Stack

### 9.1 Tower Layers

```rust
let app = Router::new()
    .merge(api_routes)
    .layer(CatchPanicLayer::new())
    .layer(CompressionLayer::new())
    .layer(TimeoutLayer::new(Duration::from_secs(30)))
    .layer(RequestBodyLimitLayer::new(1_048_576)) // 1MB
    .layer(CorsLayer::permissive()) // existing
    .layer(TraceLayer::new_for_http()); // existing
```

### 9.2 Rate Limiting

- `/api/chat`: 10 requests/minute per IP (token bucket)
- `/api/search/*`: 60 requests/minute per IP
- Other endpoints: no limit (static content)
- Returns 429 with `Retry-After` header

## 10. Extended Error Variants

```rust
pub enum LithoBookError {
    // Existing
    Io(std::io::Error),
    Json(serde_json::Error),
    FileNotFound(String),
    InvalidPath(String),

    // New
    WatcherError(String),
    LlmError { status: u16, message: String },
    RateLimited { retry_after: u64 },
    AstError(String),
    WorkspaceError(String),
    DeepwikiError(String),
}
```

## 11. API Route Summary (complete)

| Route | Method | Description | New? |
|-------|--------|-------------|------|
| `/` | GET | SPA (template with injected tree JSON) | |
| `/api/file?file=<path>` | GET | File content + rendered HTML | |
| `/api/tree` | GET | Full document tree as JSON | |
| `/api/search?q=<query>` | GET | Doc full-text search | |
| `/api/stats` | GET | File/dir counts, total size | |
| `/api/chat` | POST | SSE streaming AI chat | |
| `/health` | GET | Health check | |
| `/assets/*` | GET | Static file serving | |
| `/api/events` | GET | SSE hot-reload notifications | NEW |
| `/api/ast/symbols?file=<path>` | GET | Symbol list for a file | NEW |
| `/api/ast/references?symbol=<name>` | GET | Cross-file references | NEW |
| `/api/ast/complexity?file=<path>` | GET | Complexity metrics | NEW |
| `/api/ast/patterns?file=<path>` | GET | Detected design patterns | NEW |
| `/api/ast/smells?file=<path>` | GET | Code smell warnings | NEW |
| `/api/ast/coverage` | GET | Test coverage correlation | NEW |
| `/api/ast/xref?symbol=<name>` | GET | Doc↔code cross-references | NEW |
| `/api/search/code?q=<query>` | GET | Source code search | NEW |
| `/api/search/fuzzy?q=<query>` | GET | Fuzzy symbol search | NEW |
| `/api/viz/dependency-graph` | GET | D3 graph data JSON | NEW |
| `/api/viz/c4?level=<level>` | GET | Auto-gen Mermaid C4 diagram | NEW |
| `/api/viz/heatmap` | GET | Complexity heatmap data | NEW |
| `/api/workspace` | GET | Workspace metadata | NEW |
| `/api/workspace/switch?project=<name>` | POST | Switch active project | NEW |
| `/api/deepwiki/regenerate` | POST | Trigger deepwiki-rs re-analysis | NEW |

## 12. Implementation Phases

### Phase 1: Foundation (P0)
- Hot reload (watcher.rs + RwLock migration + SSE events)
- Tower middleware stack
- Extended error variants
- CLI extensions (--watch, --source-dir)
- **Tests**: watcher debounce, RwLock contention, middleware behavior

### Phase 2: AST Core (P1)
- ast_analysis.rs: symbol extraction for Rust + TypeScript
- ast_rules.rs: complexity metrics
- API endpoints: /api/ast/symbols, /api/ast/complexity
- Template: symbol sidebar panel
- **Tests**: symbol extraction accuracy, complexity calculations

### Phase 3: AST Advanced (P1)
- Pattern detection rules
- Code smell detection
- Test coverage correlation
- API endpoints: /api/ast/patterns, /api/ast/smells, /api/ast/coverage
- **Tests**: pattern detection, smell thresholds

### Phase 4: deepwiki-rs Integration (P1)
- deepwiki.rs: metadata parsing (.litho/ directory)
- Importance-weighted navigation
- Re-analyze trigger
- Fallback markdown header parsing
- **Tests**: metadata parsing, fallback behavior

### Phase 5: Visualization (P2)
- D3.js dependency graph (inline bundle)
- Complexity heatmap UI
- Auto-generated C4 Mermaid diagrams
- API endpoints: /api/viz/*
- **Tests**: graph data generation, diagram correctness

### Phase 6: Search & Navigation (P2)
- code_search.rs: source file indexing
- Symbol cross-references
- Fuzzy symbol search with trigram index
- API endpoints: /api/search/code, /api/search/fuzzy, /api/ast/xref
- Template: Ctrl+P dialog, hover tooltips
- **Tests**: search accuracy, fuzzy ranking, cross-ref correctness

### Phase 7: Multi-Project (P2)
- workspace.rs: project loading, tab management
- workspace.toml parser
- Cross-project symbol linking
- Unified search across projects
- API endpoints: /api/workspace/*
- Template: tab bar, cross-project navigation
- **Tests**: multi-project loading, cross-refs, search scoping

### Phase 8: Polish & Integration Testing (P3)
- End-to-end testing with real repos
- Performance profiling (target: <100ms for all API responses)
- Template UX polish
- Documentation update
- Version bump to 0.5.0

## 13. Risk Assessment

| Risk | Mitigation |
|------|------------|
| ast-grep-core binary size increase | Feature-gate behind `--features ast` |
| tree-sitter grammar compilation time | Pre-compile grammars, cache in build |
| RwLock contention on hot-reload | Short write locks, reader-priority default |
| D3.js bundle size (~30KB) | Lazy-load only when graph tab opened |
| deepwiki-rs shell-out security | Validate paths, no user-controlled args |
| Multi-project memory usage | Lazy-load projects, unload inactive |
| Scope creep | Feature flags, each phase independently shippable |

## 14. Success Criteria

- All existing 43 tests continue passing
- Each phase adds >20 new tests
- Target: 150+ total tests at v0.5.0
- All API responses < 100ms (excluding LLM chat)
- Hot reload detects changes within 1s
- AST analysis completes within 5s for repos up to 10k files
- Zero new clippy warnings
- cargo fmt clean
