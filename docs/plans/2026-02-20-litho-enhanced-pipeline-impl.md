# litho-book v0.5.0 Enhanced Pipeline Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extend litho-book from a markdown doc server into a code intelligence platform with hot reload, AST analysis, deepwiki-rs integration, visualization, advanced search, and multi-project workspace support.

**Architecture:** New modules (watcher.rs, ast_analysis.rs, ast_rules.rs, code_search.rs, visualization.rs, deepwiki.rs, workspace.rs) added alongside existing 6 source files. AppState upgraded from `Arc<DocumentTree>` to `Arc<RwLock<DocumentTree>>`. AST features gated behind `ast` cargo feature. All new API endpoints under `/api/ast/*`, `/api/viz/*`, `/api/search/*`, `/api/workspace/*`.

**Tech Stack:** Rust 1.93+, axum 0.8, notify 8.2, ast-grep-core 0.40, tree-sitter grammars, tower-http 0.6 (timeout/compression/limit/catch-panic), tokio broadcast channels, D3.js (inline).

**Design doc:** `docs/plans/2026-02-20-litho-enhanced-pipeline-design.md`

**Build commands:**
```bash
# Standard build (no AST)
RUSTC_WRAPPER="" cargo build --release
RUSTC_WRAPPER="" cargo test
RUSTC_WRAPPER="" cargo clippy --all-targets -- -D warnings
cargo fmt --check

# With AST feature
RUSTC_WRAPPER="" cargo build --release --features ast
RUSTC_WRAPPER="" cargo test --features ast
```

---

## Phase 1: Foundation (Hot Reload + Middleware + Errors + CLI)

### Task 1.1: Extend Error Variants

**Files:**
- Modify: `src/error.rs:1-98`
- Test: `src/error.rs` (inline tests)

**Step 1: Write failing tests for new error variants**

Add these tests at the bottom of the `mod tests` block in `src/error.rs`:

```rust
#[test]
fn test_watcher_error_status() {
    let err = LithoBookError::WatcherError("watch failed".into());
    assert_eq!(StatusCode::from(&err), StatusCode::INTERNAL_SERVER_ERROR);
}

#[test]
fn test_llm_error_status() {
    let err = LithoBookError::LlmError { status: 429, message: "rate limited".into() };
    assert_eq!(StatusCode::from(&err), StatusCode::BAD_GATEWAY);
}

#[test]
fn test_rate_limited_status() {
    let err = LithoBookError::RateLimited { retry_after: 60 };
    assert_eq!(StatusCode::from(&err), StatusCode::TOO_MANY_REQUESTS);
}

#[test]
fn test_ast_error_status() {
    let err = LithoBookError::AstError("parse failed".into());
    assert_eq!(StatusCode::from(&err), StatusCode::INTERNAL_SERVER_ERROR);
}

#[test]
fn test_workspace_error_status() {
    let err = LithoBookError::WorkspaceError("not found".into());
    assert_eq!(StatusCode::from(&err), StatusCode::BAD_REQUEST);
}

#[test]
fn test_deepwiki_error_status() {
    let err = LithoBookError::DeepwikiError("binary not found".into());
    assert_eq!(StatusCode::from(&err), StatusCode::INTERNAL_SERVER_ERROR);
}
```

**Step 2: Run tests to verify they fail**

```bash
RUSTC_WRAPPER="" cargo test --lib error::tests -- --test-threads=1
```
Expected: FAIL — `WatcherError` variant does not exist.

**Step 3: Add new variants to LithoBookError**

In `src/error.rs`, add these variants to the enum (after `Config`):

```rust
#[error("Watcher error: {0}")]
WatcherError(String),

#[error("LLM API error (HTTP {status}): {message}")]
LlmError { status: u16, message: String },

#[error("Rate limited, retry after {retry_after}s")]
RateLimited { retry_after: u64 },

#[error("AST analysis error: {0}")]
AstError(String),

#[error("Workspace error: {0}")]
WorkspaceError(String),

#[error("Deepwiki error: {0}")]
DeepwikiError(String),
```

Add these arms to the `From<&LithoBookError> for StatusCode` match:

```rust
LithoBookError::WatcherError(_) => StatusCode::INTERNAL_SERVER_ERROR,
LithoBookError::LlmError { .. } => StatusCode::BAD_GATEWAY,
LithoBookError::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
LithoBookError::AstError(_) => StatusCode::INTERNAL_SERVER_ERROR,
LithoBookError::WorkspaceError(_) => StatusCode::BAD_REQUEST,
LithoBookError::DeepwikiError(_) => StatusCode::INTERNAL_SERVER_ERROR,
```

Update `IntoResponse` to add `Retry-After` header for RateLimited:

```rust
impl IntoResponse for LithoBookError {
    fn into_response(self) -> Response {
        tracing::error!("{}", self);
        let status: StatusCode = StatusCode::from(&self);
        match &self {
            LithoBookError::RateLimited { retry_after } => {
                let mut resp = (status, self.to_string()).into_response();
                resp.headers_mut().insert(
                    "Retry-After",
                    axum::http::HeaderValue::from_str(&retry_after.to_string())
                        .unwrap_or_else(|_| axum::http::HeaderValue::from_static("60")),
                );
                resp
            }
            _ => (status, self.to_string()).into_response(),
        }
    }
}
```

**Step 4: Run tests to verify they pass**

```bash
RUSTC_WRAPPER="" cargo test --lib error::tests
```
Expected: ALL PASS (13 tests: 7 existing + 6 new).

**Step 5: Commit**

```bash
git add src/error.rs
git commit -m "feat(error): add WatcherError, LlmError, RateLimited, AstError, WorkspaceError, DeepwikiError variants"
```

---

### Task 1.2: Extend CLI with New Flags

**Files:**
- Modify: `src/cli.rs:1-85`
- Test: `src/cli.rs` (new inline tests)

**Step 1: Write failing tests for new CLI flags**

Add a `#[cfg(test)] mod tests` block at the bottom of `src/cli.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_default_args() {
        let args = Args::try_parse_from(["litho-book", "--docs-dir", "/tmp/docs"]).unwrap();
        assert_eq!(args.port, 3000);
        assert_eq!(args.host, "127.0.0.1");
        assert!(!args.open);
        assert!(!args.verbose);
        assert!(!args.watch);
        assert!(args.source_dir.is_none());
        assert!(args.workspace.is_none());
        assert_eq!(args.watch_debounce, 500);
    }

    #[test]
    fn test_watch_flag() {
        let args = Args::try_parse_from(["litho-book", "--docs-dir", "/tmp/docs", "--watch"]).unwrap();
        assert!(args.watch);
    }

    #[test]
    fn test_source_dir_flag() {
        let args = Args::try_parse_from([
            "litho-book", "--docs-dir", "/tmp/docs", "--source-dir", "/tmp/src"
        ]).unwrap();
        assert_eq!(args.source_dir.unwrap(), PathBuf::from("/tmp/src"));
    }

    #[test]
    fn test_workspace_flag() {
        let args = Args::try_parse_from([
            "litho-book", "--docs-dir", "/tmp/docs", "--workspace", "/tmp/workspace.toml"
        ]).unwrap();
        assert_eq!(args.workspace.unwrap(), PathBuf::from("/tmp/workspace.toml"));
    }

    #[test]
    fn test_watch_debounce_flag() {
        let args = Args::try_parse_from([
            "litho-book", "--docs-dir", "/tmp/docs", "--watch-debounce", "1000"
        ]).unwrap();
        assert_eq!(args.watch_debounce, 1000);
    }

    #[test]
    fn test_ast_languages_flag() {
        let args = Args::try_parse_from([
            "litho-book", "--docs-dir", "/tmp/docs", "--ast-languages", "rust,python,typescript"
        ]).unwrap();
        assert_eq!(args.ast_languages.unwrap(), "rust,python,typescript");
    }
}
```

**Step 2: Run tests to verify they fail**

```bash
RUSTC_WRAPPER="" cargo test --lib cli::tests
```
Expected: FAIL — `watch` field does not exist on Args.

**Step 3: Add new fields to Args struct**

In `src/cli.rs`, add these fields to `Args` (after `verbose`):

```rust
/// Enable hot reload - watch docs directory for changes
#[arg(short, long)]
pub watch: bool,

/// Debounce interval for file watcher in milliseconds
#[arg(long, default_value = "500", value_name = "MS")]
pub watch_debounce: u64,

/// Path to source code directory for AST analysis (optional)
#[arg(short, long, value_name = "DIR")]
pub source_dir: Option<PathBuf>,

/// Path to workspace.toml for multi-project mode (optional)
#[arg(long, value_name = "FILE")]
pub workspace: Option<PathBuf>,

/// Comma-separated list of languages for AST analysis (e.g., "rust,python,typescript")
#[arg(long, value_name = "LANGS")]
pub ast_languages: Option<String>,
```

**Step 4: Run tests to verify they pass**

```bash
RUSTC_WRAPPER="" cargo test --lib cli::tests
```
Expected: ALL PASS (6 tests).

**Step 5: Commit**

```bash
git add src/cli.rs
git commit -m "feat(cli): add --watch, --source-dir, --workspace, --watch-debounce, --ast-languages flags"
```

---

### Task 1.3: Add Tower Middleware Stack

**Files:**
- Modify: `Cargo.toml:10-47` (add tower-http features)
- Modify: `src/server.rs:110-142` (create_router)
- Test: `src/server.rs` (inline tests)

**Step 1: Update Cargo.toml**

Change `tower-http` line in `Cargo.toml` from:
```toml
tower-http = { version = "0.6", features = ["fs", "cors"] }
```
to:
```toml
tower-http = { version = "0.6", features = ["fs", "cors", "timeout", "compression-gzip", "limit", "catch-panic"] }
```

Also move `tower` from dev-dependencies to dependencies:
```toml
# Under [dependencies]
tower = { version = "0.5", features = ["util"] }
```

Remove the `tower` line from `[dev-dependencies]`.

**Step 2: Write failing test for middleware behavior**

Add to the `mod tests` block in `src/server.rs`:

```rust
#[tokio::test]
async fn test_request_body_limit() {
    let (app, _dir) = make_test_app();
    // The chat endpoint accepts POST with JSON body.
    // A body larger than 1MB should be rejected.
    let large_body = "x".repeat(2 * 1024 * 1024); // 2MB
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/chat")
                .header("content-type", "application/json")
                .body(Body::from(large_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 413);
}

#[tokio::test]
async fn test_compression_header() {
    let (app, _dir) = make_test_app();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .header("accept-encoding", "gzip")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    // Response may or may not be compressed depending on content size,
    // but the endpoint should still work.
}
```

**Step 3: Run tests to verify they fail**

```bash
RUSTC_WRAPPER="" cargo test --lib server::tests::test_request_body_limit
```
Expected: FAIL — no body limit middleware, so the request goes through.

**Step 4: Add middleware layers to create_router**

In `src/server.rs`, add imports at the top:
```rust
use tower_http::{
    catch_panic::CatchPanicLayer,
    compression::CompressionLayer,
    cors::CorsLayer,
    limit::RequestBodyLimitLayer,
    services::ServeDir,
    timeout::TimeoutLayer,
};
```

Remove the existing `use tower_http::{cors::CorsLayer, services::ServeDir};` line.

Update `create_router` to add middleware layers (after `.with_state(state)`):

```rust
Router::new()
    .route("/", get(index_handler))
    .route("/api/file", get(get_file_handler))
    .route("/api/tree", get(get_tree_handler))
    .route("/api/search", get(search_handler))
    .route("/api/stats", get(stats_handler))
    .route("/api/chat", post(chat_stream_handler))
    .route("/health", get(health_handler))
    .nest_service("/assets", ServeDir::new("assets"))
    .with_state(state)
    .layer(CatchPanicLayer::new())
    .layer(CompressionLayer::new())
    .layer(TimeoutLayer::new(Duration::from_secs(30)))
    .layer(RequestBodyLimitLayer::new(1_048_576)) // 1MB
    .layer(CorsLayer::permissive())
```

**Step 5: Run all tests**

```bash
RUSTC_WRAPPER="" cargo test
```
Expected: ALL PASS. The body limit test should now return 413.

**Step 6: Run clippy**

```bash
RUSTC_WRAPPER="" cargo clippy --all-targets -- -D warnings
```
Expected: No warnings.

**Step 7: Commit**

```bash
git add Cargo.toml src/server.rs
git commit -m "feat(server): add tower middleware stack (timeout, compression, body limit, catch panic)"
```

---

### Task 1.4: Create Watcher Module (notify-based hot reload)

**Files:**
- Create: `src/watcher.rs`
- Modify: `src/main.rs:1-5` (add `mod watcher;`)
- Modify: `Cargo.toml` (add `notify` dependency)

**Step 1: Add notify dependency**

Add to `[dependencies]` in `Cargo.toml`:
```toml
notify = "8"
```

**Step 2: Write the watcher module with tests**

Create `src/watcher.rs`:

```rust
use notify::{Event, EventKind, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

/// Events broadcast to SSE subscribers and internal consumers.
#[derive(Debug, Clone)]
pub enum WatchEvent {
    /// A markdown doc was created or modified.
    DocChanged(PathBuf),
    /// A markdown doc was deleted.
    DocDeleted(PathBuf),
    /// A source file was created or modified (for AST re-analysis).
    SourceChanged(PathBuf),
    /// The document tree was rebuilt after a batch of changes.
    TreeRebuilt,
}

/// Configuration for the filesystem watcher.
pub struct WatcherConfig {
    pub docs_dir: PathBuf,
    pub source_dir: Option<PathBuf>,
    pub debounce_ms: u64,
}

/// Classify a notify event into our domain event.
fn classify_event(event: &Event, docs_dir: &Path, source_dir: Option<&Path>) -> Vec<WatchEvent> {
    let mut watch_events = Vec::new();

    for path in &event.paths {
        let is_in_docs = path.starts_with(docs_dir);
        let is_in_source = source_dir.map_or(false, |s| path.starts_with(s));
        let is_md = path.extension().and_then(|e| e.to_str()) == Some("md");

        match &event.kind {
            EventKind::Create(_) | EventKind::Modify(_) => {
                if is_in_docs && is_md {
                    watch_events.push(WatchEvent::DocChanged(path.clone()));
                } else if is_in_source {
                    watch_events.push(WatchEvent::SourceChanged(path.clone()));
                }
            }
            EventKind::Remove(_) => {
                if is_in_docs && is_md {
                    watch_events.push(WatchEvent::DocDeleted(path.clone()));
                }
            }
            _ => {}
        }
    }

    watch_events
}

/// Start the filesystem watcher. Returns a broadcast sender for SSE subscribers
/// and a join handle for the background task.
///
/// The watcher runs until the sender is dropped or the task is cancelled.
pub fn start_watcher(
    config: WatcherConfig,
) -> anyhow::Result<(broadcast::Sender<WatchEvent>, tokio::task::JoinHandle<()>)> {
    let (tx, _rx) = broadcast::channel::<WatchEvent>(256);
    let tx_clone = tx.clone();

    // Use a standard mpsc channel for notify (it requires Send, not async)
    let (notify_tx, notify_rx) = std::sync::mpsc::channel();

    let mut watcher = notify::recommended_watcher(notify_tx)?;

    // Watch docs directory
    watcher.watch(&config.docs_dir, RecursiveMode::Recursive)?;
    info!("Watching docs directory: {}", config.docs_dir.display());

    // Optionally watch source directory
    if let Some(ref source_dir) = config.source_dir {
        if source_dir.exists() {
            watcher.watch(source_dir, RecursiveMode::Recursive)?;
            info!("Watching source directory: {}", source_dir.display());
        } else {
            warn!("Source directory does not exist, skipping watch: {}", source_dir.display());
        }
    }

    let docs_dir = config.docs_dir.clone();
    let source_dir = config.source_dir.clone();
    let debounce_ms = config.debounce_ms;

    let handle = tokio::task::spawn_blocking(move || {
        // Keep watcher alive for the duration of this task
        let _watcher = watcher;

        // Simple debounce: collect events for debounce_ms, then process batch
        let debounce = std::time::Duration::from_millis(debounce_ms);

        loop {
            // Block on first event
            let first = match notify_rx.recv() {
                Ok(Ok(event)) => event,
                Ok(Err(e)) => {
                    error!("Watcher error: {}", e);
                    continue;
                }
                Err(_) => {
                    debug!("Watcher channel closed, shutting down");
                    break;
                }
            };

            // Collect more events during debounce window
            let mut batch = vec![first];
            let deadline = std::time::Instant::now() + debounce;
            while std::time::Instant::now() < deadline {
                match notify_rx.recv_timeout(deadline - std::time::Instant::now()) {
                    Ok(Ok(event)) => batch.push(event),
                    Ok(Err(e)) => error!("Watcher error in batch: {}", e),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                }
            }

            // Classify and broadcast
            let mut had_doc_change = false;
            for event in &batch {
                for watch_event in classify_event(event, &docs_dir, source_dir.as_deref()) {
                    debug!("Watch event: {:?}", watch_event);
                    if matches!(watch_event, WatchEvent::DocChanged(_) | WatchEvent::DocDeleted(_)) {
                        had_doc_change = true;
                    }
                    let _ = tx_clone.send(watch_event);
                }
            }

            // After processing a batch with doc changes, signal tree rebuild
            if had_doc_change {
                let _ = tx_clone.send(WatchEvent::TreeRebuilt);
            }
        }
    });

    Ok((tx, handle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::{CreateKind, ModifyKind, RemoveKind};

    fn make_event(kind: EventKind, paths: Vec<PathBuf>) -> Event {
        Event { kind, paths, attrs: Default::default() }
    }

    #[test]
    fn test_classify_doc_created() {
        let docs = PathBuf::from("/docs");
        let event = make_event(
            EventKind::Create(CreateKind::File),
            vec![PathBuf::from("/docs/new.md")],
        );
        let result = classify_event(&event, &docs, None);
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0], WatchEvent::DocChanged(_)));
    }

    #[test]
    fn test_classify_doc_modified() {
        let docs = PathBuf::from("/docs");
        let event = make_event(
            EventKind::Modify(ModifyKind::Data(notify::event::DataChange::Content)),
            vec![PathBuf::from("/docs/existing.md")],
        );
        let result = classify_event(&event, &docs, None);
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0], WatchEvent::DocChanged(_)));
    }

    #[test]
    fn test_classify_doc_deleted() {
        let docs = PathBuf::from("/docs");
        let event = make_event(
            EventKind::Remove(RemoveKind::File),
            vec![PathBuf::from("/docs/old.md")],
        );
        let result = classify_event(&event, &docs, None);
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0], WatchEvent::DocDeleted(_)));
    }

    #[test]
    fn test_classify_non_md_ignored() {
        let docs = PathBuf::from("/docs");
        let event = make_event(
            EventKind::Create(CreateKind::File),
            vec![PathBuf::from("/docs/image.png")],
        );
        let result = classify_event(&event, &docs, None);
        assert!(result.is_empty());
    }

    #[test]
    fn test_classify_source_changed() {
        let docs = PathBuf::from("/docs");
        let src = PathBuf::from("/src");
        let event = make_event(
            EventKind::Modify(ModifyKind::Data(notify::event::DataChange::Content)),
            vec![PathBuf::from("/src/main.rs")],
        );
        let result = classify_event(&event, &docs, Some(&src));
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0], WatchEvent::SourceChanged(_)));
    }

    #[test]
    fn test_classify_outside_both_dirs_ignored() {
        let docs = PathBuf::from("/docs");
        let src = PathBuf::from("/src");
        let event = make_event(
            EventKind::Create(CreateKind::File),
            vec![PathBuf::from("/other/file.md")],
        );
        let result = classify_event(&event, &docs, Some(&src));
        assert!(result.is_empty());
    }

    #[test]
    fn test_classify_multiple_paths() {
        let docs = PathBuf::from("/docs");
        let event = make_event(
            EventKind::Create(CreateKind::File),
            vec![
                PathBuf::from("/docs/a.md"),
                PathBuf::from("/docs/b.md"),
            ],
        );
        let result = classify_event(&event, &docs, None);
        assert_eq!(result.len(), 2);
    }
}
```

**Step 3: Register the module**

Add `mod watcher;` to `src/main.rs` (after `mod utils;`):
```rust
mod watcher;
```

**Step 4: Run tests**

```bash
RUSTC_WRAPPER="" cargo test --lib watcher::tests
```
Expected: ALL PASS (7 tests).

**Step 5: Run full test suite + clippy**

```bash
RUSTC_WRAPPER="" cargo test && RUSTC_WRAPPER="" cargo clippy --all-targets -- -D warnings
```
Expected: ALL PASS, zero warnings.

**Step 6: Commit**

```bash
git add src/watcher.rs src/main.rs Cargo.toml
git commit -m "feat(watcher): add notify-based filesystem watcher with event classification and debouncing"
```

---

### Task 1.5: Upgrade AppState to RwLock + Wire Watcher into main.rs

**Files:**
- Modify: `src/server.rs:1-142` (AppState + create_router)
- Modify: `src/main.rs:12-93` (main function)

**Step 1: Add RwLock to AppState**

In `src/server.rs`, change the AppState struct:

```rust
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
```

```rust
#[derive(Clone)]
pub struct AppState {
    pub doc_tree: Arc<RwLock<DocumentTree>>,
    pub docs_path: String,
    pub index_html: Arc<RwLock<String>>,
    pub http_client: reqwest::Client,
    pub llm_key: Arc<String>,
    pub watcher_tx: Option<broadcast::Sender<crate::watcher::WatchEvent>>,
}
```

**Step 2: Update create_router signature and body**

```rust
pub fn create_router(
    doc_tree: DocumentTree,
    docs_path: String,
    watcher_tx: Option<broadcast::Sender<crate::watcher::WatchEvent>>,
) -> Router {
    let tree_json = serde_json::to_string(&doc_tree.root).unwrap_or_else(|e| {
        tracing::error!("Failed to serialize document tree: {}", e);
        "{}".to_string()
    });
    let index_html = Arc::new(RwLock::new(generate_index_html(&tree_json, &docs_path)));

    let llm_key_value = std::env::var("LITHO_BOOK_LLM_KEY").unwrap_or_else(|_| {
        tracing::warn!("LITHO_BOOK_LLM_KEY not set; AI chat will not work");
        String::new()
    });

    let state = AppState {
        doc_tree: Arc::new(RwLock::new(doc_tree)),
        docs_path,
        index_html,
        http_client: reqwest::Client::new(),
        llm_key: Arc::new(llm_key_value),
        watcher_tx,
    };

    Router::new()
        // ... routes unchanged ...
        .with_state(state)
        // ... middleware layers ...
}
```

**Step 3: Update all handlers to use RwLock read guards**

`index_handler`:
```rust
async fn index_handler(State(state): State<AppState>) -> Html<String> {
    debug!("Serving index page");
    let html = state.index_html.read().await;
    Html(html.clone())
}
```

`get_file_handler`:
```rust
async fn get_file_handler(
    Query(params): Query<FileQuery>,
    State(state): State<AppState>,
) -> Result<Json<FileResponse>, LithoBookError> {
    let file_path = params.file.ok_or(LithoBookError::InvalidPath {
        path: "(missing)".to_string(),
    })?;

    debug!("Requesting file: {}", file_path);

    let doc_tree = state.doc_tree.read().await;

    let content = doc_tree
        .get_file_content(&file_path)
        .map_err(|_| LithoBookError::FileNotFound {
            path: file_path.clone(),
        })?;

    let html = doc_tree.render_markdown(&content);
    let node = doc_tree.node_map.get(&file_path);

    let response = FileResponse {
        content,
        html,
        path: file_path,
        size: node.and_then(|n| n.size),
        modified: node.and_then(|n| n.modified.clone()),
    };

    info!("Successfully served file: {}", response.path);
    Ok(Json(response))
}
```

`get_tree_handler`:
```rust
async fn get_tree_handler(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, LithoBookError> {
    debug!("Serving document tree");
    let doc_tree = state.doc_tree.read().await;
    let value = serde_json::to_value(&doc_tree.root)?;
    Ok(Json(value))
}
```

`search_handler`:
```rust
async fn search_handler(
    Query(params): Query<SearchQuery>,
    State(state): State<AppState>,
) -> Json<SearchResponse> {
    let query = params.q.unwrap_or_default();

    if query.trim().is_empty() {
        return Json(SearchResponse {
            results: vec![],
            total: 0,
            query,
        });
    }

    debug!("Searching for: {}", query);

    let doc_tree = state.doc_tree.read().await;
    let results = doc_tree.search_content(&query);
    let total = results.len();

    debug!("Found {} results matching query: {}", total, query);

    Json(SearchResponse {
        results,
        total,
        query,
    })
}
```

`stats_handler`:
```rust
async fn stats_handler(State(state): State<AppState>) -> Json<StatsResponse> {
    let doc_tree = state.doc_tree.read().await;
    let stats = doc_tree.get_stats();
    Json(StatsResponse {
        total_files: stats.total_files,
        total_dirs: stats.total_dirs,
        total_size: stats.total_size,
        formatted_size: utils::format_bytes(stats.total_size),
    })
}
```

**Step 4: Add SSE events endpoint**

Add this handler after `health_handler`:

```rust
/// SSE endpoint for hot-reload notifications.
async fn events_handler(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state
        .watcher_tx
        .as_ref()
        .map(|tx| tx.subscribe());

    let stream = async_stream::stream! {
        if let Some(mut rx) = rx {
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        let data = match &event {
                            crate::watcher::WatchEvent::DocChanged(p) => {
                                format!(r#"{{"type":"doc_changed","path":"{}"}}"#, p.display())
                            }
                            crate::watcher::WatchEvent::DocDeleted(p) => {
                                format!(r#"{{"type":"doc_deleted","path":"{}"}}"#, p.display())
                            }
                            crate::watcher::WatchEvent::SourceChanged(p) => {
                                format!(r#"{{"type":"source_changed","path":"{}"}}"#, p.display())
                            }
                            crate::watcher::WatchEvent::TreeRebuilt => {
                                r#"{"type":"tree_rebuilt"}"#.to_string()
                            }
                        };
                        yield Ok(Event::default().event("watch").data(data));
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        debug!("SSE subscriber lagged by {} events", n);
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        } else {
            // No watcher configured, just keep connection alive
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                yield Ok(Event::default().comment("keepalive"));
            }
        }
    };

    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    )
}
```

Add the route in `create_router`:
```rust
.route("/api/events", get(events_handler))
```

**Step 5: Update make_test_app in tests**

```rust
fn make_test_app() -> (Router, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("test.md"), "# Test\nHello world").unwrap();
    let tree = crate::filesystem::DocumentTree::new(dir.path()).unwrap();
    let docs_path = dir.path().display().to_string().replace('\\', "/");
    let router = create_router(tree, docs_path, None);
    (router, dir)
}
```

**Step 6: Update main.rs to wire watcher**

In `src/main.rs`, update `main()`:

```rust
// After doc_tree is built, before create_router:
let watcher_tx = if args.watch {
    match watcher::start_watcher(watcher::WatcherConfig {
        docs_dir: args.docs_dir.clone(),
        source_dir: args.source_dir.clone(),
        debounce_ms: args.watch_debounce,
    }) {
        Ok((tx, _handle)) => {
            info!("Hot reload enabled (debounce: {}ms)", args.watch_debounce);
            Some(tx)
        }
        Err(e) => {
            warn!("Failed to start file watcher: {}. Continuing without hot reload.", e);
            None
        }
    }
} else {
    None
};

let docs_path = args.docs_dir.display().to_string().replace('\\', "/");
let app = server::create_router(doc_tree, docs_path, watcher_tx);
```

**Step 7: Run full test suite**

```bash
RUSTC_WRAPPER="" cargo test
```
Expected: ALL PASS.

**Step 8: Commit**

```bash
git add src/server.rs src/main.rs
git commit -m "feat: upgrade AppState to RwLock, add SSE events endpoint, wire watcher into main"
```

---

### Task 1.6: Phase 1 Verification

**Step 1: Run full verification suite**

```bash
RUSTC_WRAPPER="" cargo fmt --check
RUSTC_WRAPPER="" cargo clippy --all-targets -- -D warnings
RUSTC_WRAPPER="" cargo test
RUSTC_WRAPPER="" cargo build --release
```
Expected: All pass, zero warnings, binary compiles.

**Step 2: Smoke test**

```bash
RUSTC_WRAPPER="" cargo run -- --docs-dir ./docs --verbose
# In another terminal: curl http://127.0.0.1:3000/health
# Then: curl http://127.0.0.1:3000/api/events (should hang waiting for SSE events)
# Ctrl+C to stop
```

**Step 3: Smoke test with --watch**

```bash
RUSTC_WRAPPER="" cargo run -- --docs-dir ./docs --watch --verbose
# Should log "Hot reload enabled" and "Watching docs directory"
# Ctrl+C to stop
```

**Step 4: Commit tag**

```bash
git tag v0.4.1-phase1
```

---

## Phase 2: AST Core (Symbol Extraction + Complexity Metrics)

### Task 2.1: Add AST Dependencies (Feature-Gated)

**Files:**
- Modify: `Cargo.toml`

**Step 1: Add optional ast-grep and tree-sitter dependencies**

Add to `Cargo.toml` after the `[dependencies]` section:

```toml
# AST analysis (optional, behind "ast" feature)
ast-grep-core = { version = "0.40", optional = true }
tree-sitter = { version = "0.24", optional = true }
tree-sitter-rust = { version = "0.24", optional = true }
tree-sitter-python = { version = "0.25", optional = true }
tree-sitter-typescript = { version = "0.23", optional = true }
tree-sitter-go = { version = "0.25", optional = true }
tree-sitter-java = { version = "0.23", optional = true }
```

Add a `[features]` section:
```toml
[features]
default = []
ast = ["ast-grep-core", "tree-sitter", "tree-sitter-rust", "tree-sitter-python", "tree-sitter-typescript", "tree-sitter-go", "tree-sitter-java"]
```

**Step 2: Verify it compiles without ast feature**

```bash
RUSTC_WRAPPER="" cargo check
```
Expected: PASS (no change to code, just Cargo.toml).

**Step 3: Verify ast feature resolves**

```bash
RUSTC_WRAPPER="" cargo check --features ast
```
Expected: PASS (dependencies download and compile).

**Step 4: Commit**

```bash
git add Cargo.toml
git commit -m "build: add ast-grep-core and tree-sitter as optional 'ast' feature dependencies"
```

---

### Task 2.2: Create AST Analysis Module - Data Types

**Files:**
- Create: `src/ast_analysis.rs`
- Modify: `src/main.rs` (add conditional `mod ast_analysis;`)

**Step 1: Write failing tests for AST data types**

Create `src/ast_analysis.rs` with types and tests:

```rust
//! AST analysis module using ast-grep for structural code understanding.
//!
//! This module is only compiled when the `ast` feature is enabled.

use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// The kind of symbol extracted from source code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum SymbolKind {
    Function,
    Struct,
    Enum,
    Trait,
    Impl,
    Import,
    Const,
    Static,
    TypeAlias,
    Test,
}

/// Visibility of a symbol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Visibility {
    Public,
    PublicCrate,
    Private,
}

/// A symbol extracted from source code via AST analysis.
#[derive(Debug, Clone, Serialize)]
pub struct Symbol {
    pub name: String,
    pub kind: SymbolKind,
    pub line: usize,
    pub end_line: usize,
    pub signature: String,
    pub visibility: Visibility,
    pub parent: Option<String>,
    pub file_path: String,
}

/// Per-function complexity metrics.
#[derive(Debug, Clone, Serialize)]
pub struct FnMetrics {
    pub name: String,
    pub file_path: String,
    pub line: usize,
    pub lines_of_code: usize,
    pub cyclomatic_complexity: usize,
    pub cognitive_complexity: usize,
    pub parameter_count: usize,
    pub fan_out: usize,
}

impl FnMetrics {
    /// Severity level based on cyclomatic complexity.
    pub fn severity(&self) -> &'static str {
        match self.cyclomatic_complexity {
            0..=9 => "low",
            10..=19 => "medium",
            _ => "high",
        }
    }
}

/// A reference from one symbol to another.
#[derive(Debug, Clone, Serialize)]
pub struct Reference {
    pub from_file: String,
    pub from_line: usize,
    pub to_symbol: String,
    pub to_file: String,
}

/// Detected design pattern.
#[derive(Debug, Clone, Serialize)]
pub struct Pattern {
    pub name: String,
    pub file_path: String,
    pub line: usize,
    pub description: String,
    pub confidence: f32,
}

/// Detected code smell.
#[derive(Debug, Clone, Serialize)]
pub struct CodeSmell {
    pub kind: String,
    pub file_path: String,
    pub line: usize,
    pub message: String,
    pub severity: String,
}

/// Test coverage correlation for a symbol.
#[derive(Debug, Clone, Serialize)]
pub enum CoverageStatus {
    /// Symbol has associated tests.
    Tested { test_names: Vec<String> },
    /// Symbol has partial test coverage.
    PartiallyTested { test_names: Vec<String>, note: String },
    /// No tests found for this symbol.
    Untested,
}

/// The complete AST analysis index for a project.
#[derive(Debug, Clone, Default)]
pub struct AstIndex {
    /// file_path -> symbols in that file
    pub symbols: HashMap<String, Vec<Symbol>>,
    /// symbol_name -> references to it
    pub references: HashMap<String, Vec<Reference>>,
    /// file_path -> function metrics
    pub complexity: HashMap<String, Vec<FnMetrics>>,
    /// file_path -> detected patterns
    pub patterns: HashMap<String, Vec<Pattern>>,
    /// file_path -> code smells
    pub smells: HashMap<String, Vec<CodeSmell>>,
    /// symbol_name -> coverage status
    pub test_coverage: HashMap<String, CoverageStatus>,
    /// Languages that were analyzed
    pub languages: HashSet<String>,
    /// Source root directory
    pub source_root: PathBuf,
}

impl AstIndex {
    pub fn new(source_root: PathBuf) -> Self {
        Self {
            source_root,
            ..Default::default()
        }
    }

    /// Get all symbols of a specific kind across all files.
    pub fn symbols_by_kind(&self, kind: &SymbolKind) -> Vec<&Symbol> {
        self.symbols
            .values()
            .flat_map(|syms| syms.iter().filter(|s| &s.kind == kind))
            .collect()
    }

    /// Get the total number of symbols across all files.
    pub fn total_symbols(&self) -> usize {
        self.symbols.values().map(|v| v.len()).sum()
    }

    /// Get the file with the highest max cyclomatic complexity.
    pub fn most_complex_file(&self) -> Option<(&str, usize)> {
        self.complexity
            .iter()
            .filter_map(|(path, metrics)| {
                metrics.iter().map(|m| m.cyclomatic_complexity).max().map(|max| (path.as_str(), max))
            })
            .max_by_key(|(_, c)| *c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fn_metrics_severity_low() {
        let m = FnMetrics {
            name: "foo".into(), file_path: "a.rs".into(), line: 1,
            lines_of_code: 5, cyclomatic_complexity: 3, cognitive_complexity: 2,
            parameter_count: 1, fan_out: 2,
        };
        assert_eq!(m.severity(), "low");
    }

    #[test]
    fn test_fn_metrics_severity_medium() {
        let m = FnMetrics {
            name: "foo".into(), file_path: "a.rs".into(), line: 1,
            lines_of_code: 30, cyclomatic_complexity: 15, cognitive_complexity: 12,
            parameter_count: 3, fan_out: 5,
        };
        assert_eq!(m.severity(), "medium");
    }

    #[test]
    fn test_fn_metrics_severity_high() {
        let m = FnMetrics {
            name: "foo".into(), file_path: "a.rs".into(), line: 1,
            lines_of_code: 100, cyclomatic_complexity: 25, cognitive_complexity: 30,
            parameter_count: 6, fan_out: 12,
        };
        assert_eq!(m.severity(), "high");
    }

    #[test]
    fn test_ast_index_empty() {
        let idx = AstIndex::new(PathBuf::from("/src"));
        assert_eq!(idx.total_symbols(), 0);
        assert!(idx.most_complex_file().is_none());
    }

    #[test]
    fn test_ast_index_symbols_by_kind() {
        let mut idx = AstIndex::new(PathBuf::from("/src"));
        idx.symbols.insert("a.rs".into(), vec![
            Symbol {
                name: "foo".into(), kind: SymbolKind::Function,
                line: 1, end_line: 10, signature: "fn foo()".into(),
                visibility: Visibility::Public, parent: None, file_path: "a.rs".into(),
            },
            Symbol {
                name: "Bar".into(), kind: SymbolKind::Struct,
                line: 12, end_line: 15, signature: "struct Bar".into(),
                visibility: Visibility::Public, parent: None, file_path: "a.rs".into(),
            },
        ]);

        let fns = idx.symbols_by_kind(&SymbolKind::Function);
        assert_eq!(fns.len(), 1);
        assert_eq!(fns[0].name, "foo");

        let structs = idx.symbols_by_kind(&SymbolKind::Struct);
        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].name, "Bar");
    }

    #[test]
    fn test_ast_index_most_complex_file() {
        let mut idx = AstIndex::new(PathBuf::from("/src"));
        idx.complexity.insert("a.rs".into(), vec![
            FnMetrics {
                name: "simple".into(), file_path: "a.rs".into(), line: 1,
                lines_of_code: 5, cyclomatic_complexity: 2, cognitive_complexity: 1,
                parameter_count: 0, fan_out: 1,
            },
        ]);
        idx.complexity.insert("b.rs".into(), vec![
            FnMetrics {
                name: "complex".into(), file_path: "b.rs".into(), line: 1,
                lines_of_code: 80, cyclomatic_complexity: 22, cognitive_complexity: 18,
                parameter_count: 5, fan_out: 8,
            },
        ]);

        let (file, complexity) = idx.most_complex_file().unwrap();
        assert_eq!(file, "b.rs");
        assert_eq!(complexity, 22);
    }

    #[test]
    fn test_ast_index_total_symbols() {
        let mut idx = AstIndex::new(PathBuf::from("/src"));
        idx.symbols.insert("a.rs".into(), vec![
            Symbol {
                name: "foo".into(), kind: SymbolKind::Function,
                line: 1, end_line: 5, signature: "fn foo()".into(),
                visibility: Visibility::Public, parent: None, file_path: "a.rs".into(),
            },
        ]);
        idx.symbols.insert("b.rs".into(), vec![
            Symbol {
                name: "bar".into(), kind: SymbolKind::Function,
                line: 1, end_line: 5, signature: "fn bar()".into(),
                visibility: Visibility::Private, parent: None, file_path: "b.rs".into(),
            },
            Symbol {
                name: "Baz".into(), kind: SymbolKind::Struct,
                line: 7, end_line: 10, signature: "struct Baz".into(),
                visibility: Visibility::Public, parent: None, file_path: "b.rs".into(),
            },
        ]);
        assert_eq!(idx.total_symbols(), 3);
    }

    #[test]
    fn test_coverage_status_variants() {
        let tested = CoverageStatus::Tested { test_names: vec!["test_foo".into()] };
        assert!(matches!(tested, CoverageStatus::Tested { .. }));

        let partial = CoverageStatus::PartiallyTested {
            test_names: vec!["test_bar".into()],
            note: "only happy path".into(),
        };
        assert!(matches!(partial, CoverageStatus::PartiallyTested { .. }));

        let untested = CoverageStatus::Untested;
        assert!(matches!(untested, CoverageStatus::Untested));
    }
}
```

**Step 2: Register the module conditionally**

In `src/main.rs`, add after `mod watcher;`:
```rust
#[cfg(feature = "ast")]
mod ast_analysis;
```

**Step 3: Run tests**

```bash
# Without ast feature (module not compiled)
RUSTC_WRAPPER="" cargo test

# With ast feature (module compiled and tested)
RUSTC_WRAPPER="" cargo test --features ast -- ast_analysis::tests
```
Expected: ALL PASS in both cases.

**Step 4: Commit**

```bash
git add src/ast_analysis.rs src/main.rs
git commit -m "feat(ast): add AST analysis data types with tests (behind 'ast' feature)"
```

---

### Task 2.3: Implement Rust Symbol Extraction

This task implements the actual AST parsing for Rust files using tree-sitter. Since ast-grep-core's API may require exploration, this task focuses on tree-sitter directly first.

**Files:**
- Modify: `src/ast_analysis.rs` (add `analyze_rust_file` function)

**Step 1: Write failing test**

Add to `src/ast_analysis.rs` `mod tests`:

```rust
#[cfg(feature = "ast")]
#[test]
fn test_analyze_rust_source() {
    let source = r#"
use std::collections::HashMap;

pub struct Config {
    pub name: String,
    pub value: i32,
}

pub fn process(config: &Config) -> String {
    config.name.clone()
}

fn helper() -> bool {
    true
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_helper() {
        assert!(super::helper());
    }
}
"#;
    let symbols = extract_rust_symbols(source, "example.rs");
    let names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();
    assert!(names.contains(&"Config"));
    assert!(names.contains(&"process"));
    assert!(names.contains(&"helper"));
    // Import
    assert!(symbols.iter().any(|s| s.kind == SymbolKind::Import));
    // Visibility check
    let config = symbols.iter().find(|s| s.name == "Config").unwrap();
    assert_eq!(config.visibility, Visibility::Public);
    let helper = symbols.iter().find(|s| s.name == "helper").unwrap();
    assert_eq!(helper.visibility, Visibility::Private);
}
```

**Step 2: Implement extract_rust_symbols**

This function uses tree-sitter-rust directly (not ast-grep patterns) for reliable extraction:

```rust
#[cfg(feature = "ast")]
pub fn extract_rust_symbols(source: &str, file_path: &str) -> Vec<Symbol> {
    use tree_sitter::Parser;

    let mut parser = Parser::new();
    let language = tree_sitter_rust::LANGUAGE;
    parser.set_language(&language.into()).expect("Error loading Rust grammar");

    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return vec![],
    };

    let mut symbols = Vec::new();
    let root = tree.root_node();
    extract_rust_symbols_recursive(root, source, file_path, &mut symbols, None);
    symbols
}

#[cfg(feature = "ast")]
fn extract_rust_symbols_recursive(
    node: tree_sitter::Node,
    source: &str,
    file_path: &str,
    symbols: &mut Vec<Symbol>,
    parent: Option<&str>,
) {
    let kind = node.kind();

    match kind {
        "function_item" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = &source[name_node.byte_range()];
                let vis = extract_rust_visibility(&node, source);
                let sig = extract_line(source, node.start_position().row);
                symbols.push(Symbol {
                    name: name.to_string(),
                    kind: if has_test_attribute(&node, source) { SymbolKind::Test } else { SymbolKind::Function },
                    line: node.start_position().row + 1,
                    end_line: node.end_position().row + 1,
                    signature: sig.trim().to_string(),
                    visibility: vis,
                    parent: parent.map(String::from),
                    file_path: file_path.to_string(),
                });
            }
        }
        "struct_item" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = &source[name_node.byte_range()];
                let vis = extract_rust_visibility(&node, source);
                symbols.push(Symbol {
                    name: name.to_string(),
                    kind: SymbolKind::Struct,
                    line: node.start_position().row + 1,
                    end_line: node.end_position().row + 1,
                    signature: format!("struct {}", name),
                    visibility: vis,
                    parent: parent.map(String::from),
                    file_path: file_path.to_string(),
                });
            }
        }
        "enum_item" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = &source[name_node.byte_range()];
                let vis = extract_rust_visibility(&node, source);
                symbols.push(Symbol {
                    name: name.to_string(),
                    kind: SymbolKind::Enum,
                    line: node.start_position().row + 1,
                    end_line: node.end_position().row + 1,
                    signature: format!("enum {}", name),
                    visibility: vis,
                    parent: parent.map(String::from),
                    file_path: file_path.to_string(),
                });
            }
        }
        "trait_item" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = &source[name_node.byte_range()];
                let vis = extract_rust_visibility(&node, source);
                symbols.push(Symbol {
                    name: name.to_string(),
                    kind: SymbolKind::Trait,
                    line: node.start_position().row + 1,
                    end_line: node.end_position().row + 1,
                    signature: format!("trait {}", name),
                    visibility: vis,
                    parent: parent.map(String::from),
                    file_path: file_path.to_string(),
                });
            }
        }
        "impl_item" => {
            let impl_name = node.child_by_field_name("type")
                .map(|n| source[n.byte_range()].to_string())
                .unwrap_or_else(|| "unknown".to_string());
            symbols.push(Symbol {
                name: impl_name.clone(),
                kind: SymbolKind::Impl,
                line: node.start_position().row + 1,
                end_line: node.end_position().row + 1,
                signature: extract_line(source, node.start_position().row).trim().to_string(),
                visibility: Visibility::Public,
                parent: parent.map(String::from),
                file_path: file_path.to_string(),
            });
            // Recurse into impl body with parent context
            if let Some(body) = node.child_by_field_name("body") {
                let mut cursor = body.walk();
                for child in body.children(&mut cursor) {
                    extract_rust_symbols_recursive(child, source, file_path, symbols, Some(&impl_name));
                }
            }
            return; // Don't double-recurse
        }
        "use_declaration" => {
            let text = &source[node.byte_range()];
            symbols.push(Symbol {
                name: text.trim_end_matches(';').trim().to_string(),
                kind: SymbolKind::Import,
                line: node.start_position().row + 1,
                end_line: node.end_position().row + 1,
                signature: text.trim().to_string(),
                visibility: Visibility::Private,
                parent: parent.map(String::from),
                file_path: file_path.to_string(),
            });
        }
        _ => {}
    }

    // Recurse into children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        extract_rust_symbols_recursive(child, source, file_path, symbols, parent);
    }
}

#[cfg(feature = "ast")]
fn extract_rust_visibility(node: &tree_sitter::Node, source: &str) -> Visibility {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "visibility_modifier" {
            let text = &source[child.byte_range()];
            return if text.contains("crate") {
                Visibility::PublicCrate
            } else {
                Visibility::Public
            };
        }
    }
    Visibility::Private
}

#[cfg(feature = "ast")]
fn has_test_attribute(node: &tree_sitter::Node, source: &str) -> bool {
    // Check previous sibling for #[test] or #[cfg(test)] attribute
    if let Some(prev) = node.prev_sibling() {
        if prev.kind() == "attribute_item" {
            let text = &source[prev.byte_range()];
            return text.contains("test");
        }
    }
    false
}

#[cfg(feature = "ast")]
fn extract_line(source: &str, row: usize) -> String {
    source.lines().nth(row).unwrap_or("").to_string()
}
```

**Step 3: Run tests**

```bash
RUSTC_WRAPPER="" cargo test --features ast -- ast_analysis::tests::test_analyze_rust_source
```
Expected: PASS.

**Step 4: Commit**

```bash
git add src/ast_analysis.rs
git commit -m "feat(ast): implement Rust symbol extraction using tree-sitter"
```

---

### Task 2.4: Implement Complexity Metrics

**Files:**
- Create: `src/ast_rules.rs`
- Modify: `src/main.rs` (add conditional `mod ast_rules;`)

**Step 1: Write failing tests**

Create `src/ast_rules.rs`:

```rust
//! AST-based code quality rules: complexity metrics, pattern detection, smell detection.

#[cfg(feature = "ast")]
use crate::ast_analysis::FnMetrics;

/// Compute cyclomatic and cognitive complexity for a Rust function body.
///
/// Cyclomatic = 1 + count of branching nodes (if, match arm, while, for, &&, ||)
/// Cognitive  = sum of (1 + nesting_increment) for each branching node
#[cfg(feature = "ast")]
pub fn compute_rust_complexity(source: &str, fn_name: &str, file_path: &str, line: usize) -> FnMetrics {
    use tree_sitter::Parser;

    let mut parser = Parser::new();
    let language = tree_sitter_rust::LANGUAGE;
    parser.set_language(&language.into()).expect("Rust grammar");

    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return FnMetrics {
            name: fn_name.to_string(),
            file_path: file_path.to_string(),
            line,
            lines_of_code: source.lines().count(),
            cyclomatic_complexity: 1,
            cognitive_complexity: 0,
            parameter_count: 0,
            fan_out: 0,
        },
    };

    let root = tree.root_node();
    let mut cyclomatic = 1usize;
    let mut cognitive = 0usize;
    let mut fan_out_set = std::collections::HashSet::new();
    let param_count = count_parameters(&root, source);

    count_complexity(&root, source, 0, &mut cyclomatic, &mut cognitive, &mut fan_out_set);

    FnMetrics {
        name: fn_name.to_string(),
        file_path: file_path.to_string(),
        line,
        lines_of_code: source.lines().count(),
        cyclomatic_complexity: cyclomatic,
        cognitive_complexity: cognitive,
        parameter_count: param_count,
        fan_out: fan_out_set.len(),
    }
}

#[cfg(feature = "ast")]
fn count_complexity(
    node: &tree_sitter::Node,
    source: &str,
    nesting: usize,
    cyclomatic: &mut usize,
    cognitive: &mut usize,
    fan_out: &mut std::collections::HashSet<String>,
) {
    let kind = node.kind();

    match kind {
        "if_expression" | "while_expression" | "for_expression" | "loop_expression" => {
            *cyclomatic += 1;
            *cognitive += 1 + nesting;
        }
        "match_arm" => {
            *cyclomatic += 1;
            // match arms don't increase cognitive (the match itself does)
        }
        "match_expression" => {
            *cognitive += 1 + nesting;
        }
        "binary_expression" => {
            let op_node = node.child_by_field_name("operator");
            if let Some(op) = op_node {
                let op_text = &source[op.byte_range()];
                if op_text == "&&" || op_text == "||" {
                    *cyclomatic += 1;
                    *cognitive += 1;
                }
            }
        }
        "call_expression" => {
            if let Some(func_node) = node.child_by_field_name("function") {
                let func_name = source[func_node.byte_range()].to_string();
                fan_out.insert(func_name);
            }
        }
        _ => {}
    }

    // Determine if this node increases nesting for children
    let nesting_increment = matches!(kind,
        "if_expression" | "while_expression" | "for_expression" |
        "loop_expression" | "match_expression" | "closure_expression"
    );

    let child_nesting = if nesting_increment { nesting + 1 } else { nesting };

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        count_complexity(&child, source, child_nesting, cyclomatic, cognitive, fan_out);
    }
}

#[cfg(feature = "ast")]
fn count_parameters(root: &tree_sitter::Node, source: &str) -> usize {
    // Find the first function_item's parameters
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() == "function_item" {
            if let Some(params) = child.child_by_field_name("parameters") {
                let mut param_cursor = params.walk();
                return params.children(&mut param_cursor)
                    .filter(|c| c.kind() == "parameter" || c.kind() == "self_parameter")
                    .count();
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "ast")]
    use super::*;

    #[cfg(feature = "ast")]
    #[test]
    fn test_simple_function_complexity() {
        let source = "fn simple() -> bool { true }";
        let metrics = compute_rust_complexity(source, "simple", "test.rs", 1);
        assert_eq!(metrics.cyclomatic_complexity, 1); // no branches
        assert_eq!(metrics.cognitive_complexity, 0);
        assert_eq!(metrics.parameter_count, 0);
    }

    #[cfg(feature = "ast")]
    #[test]
    fn test_if_complexity() {
        let source = r#"fn check(x: i32) -> bool {
            if x > 0 {
                true
            } else {
                false
            }
        }"#;
        let metrics = compute_rust_complexity(source, "check", "test.rs", 1);
        assert_eq!(metrics.cyclomatic_complexity, 2); // 1 base + 1 if
        assert!(metrics.cognitive_complexity >= 1);
        assert_eq!(metrics.parameter_count, 1);
    }

    #[cfg(feature = "ast")]
    #[test]
    fn test_nested_if_cognitive() {
        let source = r#"fn nested(x: i32, y: i32) -> bool {
            if x > 0 {
                if y > 0 {
                    true
                } else {
                    false
                }
            } else {
                false
            }
        }"#;
        let metrics = compute_rust_complexity(source, "nested", "test.rs", 1);
        assert_eq!(metrics.cyclomatic_complexity, 3); // 1 + 2 ifs
        // Cognitive: outer if = 1+0=1, inner if = 1+1=2 => total >= 3
        assert!(metrics.cognitive_complexity >= 3);
        assert_eq!(metrics.parameter_count, 2);
    }

    #[cfg(feature = "ast")]
    #[test]
    fn test_match_complexity() {
        let source = r#"fn classify(x: i32) -> &'static str {
            match x {
                0 => "zero",
                1..=9 => "small",
                _ => "large",
            }
        }"#;
        let metrics = compute_rust_complexity(source, "classify", "test.rs", 1);
        // 1 base + 3 match arms = 4 cyclomatic
        assert!(metrics.cyclomatic_complexity >= 4);
    }

    #[cfg(feature = "ast")]
    #[test]
    fn test_logical_operators_complexity() {
        let source = r#"fn check(a: bool, b: bool, c: bool) -> bool {
            a && b || c
        }"#;
        let metrics = compute_rust_complexity(source, "check", "test.rs", 1);
        // 1 base + 1 && + 1 || = 3
        assert_eq!(metrics.cyclomatic_complexity, 3);
        assert_eq!(metrics.parameter_count, 3);
    }

    #[cfg(feature = "ast")]
    #[test]
    fn test_fan_out() {
        let source = r#"fn orchestrate() {
            foo();
            bar();
            baz();
            foo(); // duplicate, shouldn't double-count
        }"#;
        let metrics = compute_rust_complexity(source, "orchestrate", "test.rs", 1);
        assert_eq!(metrics.fan_out, 3); // foo, bar, baz (deduplicated)
    }

    #[cfg(feature = "ast")]
    #[test]
    fn test_severity_thresholds() {
        let m_low = FnMetrics {
            name: "a".into(), file_path: "a.rs".into(), line: 1,
            lines_of_code: 5, cyclomatic_complexity: 5, cognitive_complexity: 3,
            parameter_count: 1, fan_out: 2,
        };
        assert_eq!(m_low.severity(), "low");

        let m_med = FnMetrics {
            name: "b".into(), file_path: "b.rs".into(), line: 1,
            lines_of_code: 30, cyclomatic_complexity: 15, cognitive_complexity: 10,
            parameter_count: 3, fan_out: 5,
        };
        assert_eq!(m_med.severity(), "medium");

        let m_high = FnMetrics {
            name: "c".into(), file_path: "c.rs".into(), line: 1,
            lines_of_code: 100, cyclomatic_complexity: 25, cognitive_complexity: 20,
            parameter_count: 6, fan_out: 12,
        };
        assert_eq!(m_high.severity(), "high");
    }
}
```

**Step 2: Register module**

In `src/main.rs`, add after the `ast_analysis` module:
```rust
#[cfg(feature = "ast")]
mod ast_rules;
```

**Step 3: Run tests**

```bash
RUSTC_WRAPPER="" cargo test --features ast -- ast_rules::tests
```
Expected: ALL PASS.

**Step 4: Commit**

```bash
git add src/ast_rules.rs src/main.rs
git commit -m "feat(ast): implement cyclomatic/cognitive complexity metrics with fan-out tracking"
```

---

### Task 2.5: Add AST API Endpoints

**Files:**
- Modify: `src/server.rs` (add AST endpoints)

**Step 1: Write failing tests**

Add to `src/server.rs` tests:

```rust
#[tokio::test]
async fn test_events_endpoint() {
    let (app, _dir) = make_test_app();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // SSE endpoint should return 200 and start streaming
    assert_eq!(response.status(), 200);
}
```

**Step 2: Run test**

```bash
RUSTC_WRAPPER="" cargo test --lib server::tests::test_events_endpoint
```
Expected: PASS (events endpoint was added in Task 1.5).

**Step 3: Commit**

```bash
git add src/server.rs
git commit -m "test(server): add events endpoint test"
```

---

### Task 2.6: Phase 2 Verification

**Step 1: Full verification**

```bash
cargo fmt --check
RUSTC_WRAPPER="" cargo clippy --all-targets -- -D warnings
RUSTC_WRAPPER="" cargo clippy --all-targets --features ast -- -D warnings
RUSTC_WRAPPER="" cargo test
RUSTC_WRAPPER="" cargo test --features ast
RUSTC_WRAPPER="" cargo build --release
RUSTC_WRAPPER="" cargo build --release --features ast
```
Expected: All pass.

**Step 2: Commit tag**

```bash
git tag v0.4.2-phase2
```

---

## Phase 3: AST Advanced (Patterns + Smells + Coverage)

### Task 3.1: Code Smell Detection

**Files:**
- Modify: `src/ast_rules.rs` (add smell detection functions)

**Step 1: Write failing tests**

Add to `src/ast_rules.rs` `mod tests`:

```rust
#[cfg(feature = "ast")]
#[test]
fn test_detect_long_method() {
    let mut lines = String::from("fn long_function() {\n");
    for i in 0..60 {
        lines.push_str(&format!("    let x{} = {};\n", i, i));
    }
    lines.push_str("}\n");

    let smells = detect_rust_smells(&lines, "test.rs", 50);
    assert!(smells.iter().any(|s| s.kind == "long_method"));
}

#[cfg(feature = "ast")]
#[test]
fn test_detect_god_struct() {
    let mut source = String::from("pub struct God {\n");
    for i in 0..20 {
        source.push_str(&format!("    pub field_{}: String,\n", i));
    }
    source.push_str("}\n");

    let smells = detect_rust_smells(&source, "test.rs", 50);
    assert!(smells.iter().any(|s| s.kind == "god_struct"));
}

#[cfg(feature = "ast")]
#[test]
fn test_no_smells_clean_code() {
    let source = r#"
pub struct Config {
    pub name: String,
}

fn simple() -> bool {
    true
}
"#;
    let smells = detect_rust_smells(source, "test.rs", 50);
    assert!(smells.is_empty());
}
```

**Step 2: Implement smell detection**

Add to `src/ast_rules.rs`:

```rust
#[cfg(feature = "ast")]
use crate::ast_analysis::CodeSmell;

#[cfg(feature = "ast")]
pub fn detect_rust_smells(source: &str, file_path: &str, long_method_threshold: usize) -> Vec<CodeSmell> {
    use tree_sitter::Parser;

    let mut parser = Parser::new();
    let language = tree_sitter_rust::LANGUAGE;
    parser.set_language(&language.into()).expect("Rust grammar");

    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return vec![],
    };

    let mut smells = Vec::new();
    detect_smells_recursive(&tree.root_node(), source, file_path, long_method_threshold, &mut smells);
    smells
}

#[cfg(feature = "ast")]
fn detect_smells_recursive(
    node: &tree_sitter::Node,
    source: &str,
    file_path: &str,
    long_method_threshold: usize,
    smells: &mut Vec<CodeSmell>,
) {
    match node.kind() {
        "function_item" => {
            let body_lines = node.end_position().row - node.start_position().row;
            if body_lines > long_method_threshold {
                let name = node.child_by_field_name("name")
                    .map(|n| source[n.byte_range()].to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                smells.push(CodeSmell {
                    kind: "long_method".to_string(),
                    file_path: file_path.to_string(),
                    line: node.start_position().row + 1,
                    message: format!("Function '{}' is {} lines (threshold: {})", name, body_lines, long_method_threshold),
                    severity: "warning".to_string(),
                });
            }
        }
        "struct_item" => {
            // Count fields
            if let Some(body) = node.child_by_field_name("body") {
                let mut cursor = body.walk();
                let field_count = body.children(&mut cursor)
                    .filter(|c| c.kind() == "field_declaration")
                    .count();
                if field_count > 15 {
                    let name = node.child_by_field_name("name")
                        .map(|n| source[n.byte_range()].to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    smells.push(CodeSmell {
                        kind: "god_struct".to_string(),
                        file_path: file_path.to_string(),
                        line: node.start_position().row + 1,
                        message: format!("Struct '{}' has {} fields (threshold: 15)", name, field_count),
                        severity: "warning".to_string(),
                    });
                }
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        detect_smells_recursive(&child, source, file_path, long_method_threshold, smells);
    }
}
```

**Step 3: Run tests**

```bash
RUSTC_WRAPPER="" cargo test --features ast -- ast_rules::tests
```
Expected: ALL PASS.

**Step 4: Commit**

```bash
git add src/ast_rules.rs
git commit -m "feat(ast): add code smell detection (long methods, god structs)"
```

---

### Task 3.2: Test Coverage Correlation

**Files:**
- Modify: `src/ast_analysis.rs` (add coverage correlation function)

**Step 1: Write failing test**

Add to `src/ast_analysis.rs` `mod tests`:

```rust
#[cfg(feature = "ast")]
#[test]
fn test_correlate_test_coverage() {
    let symbols = vec![
        Symbol {
            name: "format_bytes".into(), kind: SymbolKind::Function,
            line: 1, end_line: 10, signature: "pub fn format_bytes(bytes: u64) -> String".into(),
            visibility: Visibility::Public, parent: None, file_path: "utils.rs".into(),
        },
        Symbol {
            name: "orphan_fn".into(), kind: SymbolKind::Function,
            line: 20, end_line: 25, signature: "fn orphan_fn()".into(),
            visibility: Visibility::Private, parent: None, file_path: "utils.rs".into(),
        },
    ];
    let tests = vec![
        Symbol {
            name: "test_format_bytes_zero".into(), kind: SymbolKind::Test,
            line: 50, end_line: 55, signature: "#[test] fn test_format_bytes_zero()".into(),
            visibility: Visibility::Private, parent: None, file_path: "utils.rs".into(),
        },
        Symbol {
            name: "test_format_bytes_kb".into(), kind: SymbolKind::Test,
            line: 57, end_line: 62, signature: "#[test] fn test_format_bytes_kb()".into(),
            visibility: Visibility::Private, parent: None, file_path: "utils.rs".into(),
        },
    ];

    let coverage = correlate_test_coverage(&symbols, &tests);
    // format_bytes should be Tested (two test functions match)
    assert!(matches!(coverage.get("format_bytes"), Some(CoverageStatus::Tested { .. })));
    // orphan_fn should be Untested
    assert!(matches!(coverage.get("orphan_fn"), Some(CoverageStatus::Untested)));
}
```

**Step 2: Implement coverage correlation**

Add to `src/ast_analysis.rs`:

```rust
/// Correlate test functions to their tested symbols using name heuristics.
///
/// A test function `test_foo_bar` is matched to symbol `foo_bar` if the test
/// name contains the symbol name (case-insensitive).
pub fn correlate_test_coverage(
    symbols: &[Symbol],
    tests: &[Symbol],
) -> HashMap<String, CoverageStatus> {
    let mut coverage = HashMap::new();

    let non_test_symbols: Vec<&Symbol> = symbols
        .iter()
        .filter(|s| s.kind != SymbolKind::Test && s.kind != SymbolKind::Import)
        .collect();

    for symbol in &non_test_symbols {
        let sym_lower = symbol.name.to_lowercase();
        let matching_tests: Vec<String> = tests
            .iter()
            .filter(|t| {
                let test_lower = t.name.to_lowercase();
                test_lower.contains(&sym_lower)
            })
            .map(|t| t.name.clone())
            .collect();

        let status = if matching_tests.is_empty() {
            CoverageStatus::Untested
        } else {
            CoverageStatus::Tested { test_names: matching_tests }
        };

        coverage.insert(symbol.name.clone(), status);
    }

    coverage
}
```

**Step 3: Run tests**

```bash
RUSTC_WRAPPER="" cargo test --features ast -- ast_analysis::tests::test_correlate_test_coverage
```
Expected: PASS.

**Step 4: Commit**

```bash
git add src/ast_analysis.rs
git commit -m "feat(ast): add test coverage correlation via name heuristics"
```

---

## Phase 4: deepwiki-rs Integration

### Task 4.1: Create deepwiki.rs Module

**Files:**
- Create: `src/deepwiki.rs`
- Modify: `src/main.rs` (add `mod deepwiki;`)

**Step 1: Write tests and implementation**

Create `src/deepwiki.rs`:

```rust
//! Integration with deepwiki-rs: parse metadata, check binary availability,
//! trigger re-analysis.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

/// Metadata parsed from deepwiki-rs output.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DeepwikiMeta {
    /// File importance scores (0.0 to 1.0).
    pub importance: HashMap<String, f64>,
    /// Purpose classification per file.
    pub purposes: HashMap<String, String>,
    /// Whether deepwiki-rs binary is available in PATH.
    pub binary_available: bool,
    /// Path to deepwiki-rs binary if found.
    pub binary_path: Option<PathBuf>,
}

/// Document heading extracted from markdown.
#[derive(Debug, Clone, Serialize)]
pub struct DocHeading {
    pub level: u8,
    pub text: String,
    pub line: usize,
}

/// Check if deepwiki-rs is available in PATH or at a known location.
pub fn find_deepwiki_binary() -> Option<PathBuf> {
    // Check known location first
    let known = PathBuf::from(r"C:\Users\david\.cargo\bin\deepwiki-rs.exe");
    if known.exists() {
        return Some(known);
    }

    // Check PATH via `which` equivalent
    which_deepwiki()
}

fn which_deepwiki() -> Option<PathBuf> {
    let cmd = if cfg!(windows) { "where" } else { "which" };
    std::process::Command::new(cmd)
        .arg("deepwiki-rs")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout)
                    .ok()
                    .and_then(|s| s.lines().next().map(|l| PathBuf::from(l.trim())))
            } else {
                None
            }
        })
}

/// Parse markdown doc files to extract headings (fallback when no .litho/ metadata).
pub fn extract_headings(content: &str) -> Vec<DocHeading> {
    content
        .lines()
        .enumerate()
        .filter_map(|(i, line)| {
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                let level = trimmed.chars().take_while(|&c| c == '#').count() as u8;
                let text = trimmed.trim_start_matches('#').trim().to_string();
                if !text.is_empty() && level <= 6 {
                    return Some(DocHeading { level, text, line: i + 1 });
                }
            }
            None
        })
        .collect()
}

/// Estimate file importance from doc content heuristics.
///
/// Files with README in name get highest score, architecture docs get high score,
/// test-only docs get lower score.
pub fn estimate_importance(file_path: &str, content: &str) -> f64 {
    let name_lower = file_path.to_lowercase();
    let mut score = 0.5; // default

    // Name-based heuristics
    if name_lower.contains("readme") {
        score = 0.95;
    } else if name_lower.contains("architect") || name_lower.contains("overview") {
        score = 0.85;
    } else if name_lower.contains("api") || name_lower.contains("interface") {
        score = 0.80;
    } else if name_lower.contains("config") || name_lower.contains("setup") {
        score = 0.70;
    } else if name_lower.contains("test") || name_lower.contains("spec") {
        score = 0.40;
    } else if name_lower.contains("changelog") || name_lower.contains("history") {
        score = 0.30;
    }

    // Content-based adjustments
    let heading_count = content.lines().filter(|l| l.trim().starts_with('#')).count();
    let code_block_count = content.matches("```").count() / 2;

    // More headings and code blocks suggest richer content
    if heading_count > 5 { score += 0.05; }
    if code_block_count > 3 { score += 0.05; }

    // Check for litho importance comment
    if let Some(comment_start) = content.find("<!--litho:importance=") {
        let after = &content[comment_start + 21..];
        if let Some(end) = after.find("-->") {
            if let Ok(explicit) = after[..end].trim().parse::<f64>() {
                return explicit.clamp(0.0, 1.0);
            }
        }
    }

    score.clamp(0.0, 1.0)
}

/// Build DeepwikiMeta for a docs directory.
pub fn build_meta(docs_dir: &Path, search_index: &HashMap<String, Vec<String>>) -> DeepwikiMeta {
    let binary = find_deepwiki_binary();
    let binary_available = binary.is_some();

    let mut importance = HashMap::new();
    let mut purposes = HashMap::new();

    for (file_path, lines) in search_index {
        let content = lines.join("\n");
        importance.insert(file_path.clone(), estimate_importance(file_path, &content));

        // Simple purpose classification
        let purpose = classify_purpose(file_path, &content);
        purposes.insert(file_path.clone(), purpose);
    }

    debug!("Built deepwiki metadata for {} files", importance.len());

    DeepwikiMeta {
        importance,
        purposes,
        binary_available,
        binary_path: binary,
    }
}

fn classify_purpose(file_path: &str, content: &str) -> String {
    let name_lower = file_path.to_lowercase();
    if name_lower.contains("readme") {
        "Overview".to_string()
    } else if name_lower.contains("architect") || name_lower.contains("design") {
        "Architecture".to_string()
    } else if name_lower.contains("api") {
        "API Reference".to_string()
    } else if name_lower.contains("test") {
        "Testing".to_string()
    } else if name_lower.contains("config") || name_lower.contains("setup") {
        "Configuration".to_string()
    } else if content.contains("```") && content.lines().filter(|l| l.trim().starts_with('#')).count() > 3 {
        "Technical Guide".to_string()
    } else {
        "Documentation".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_headings() {
        let content = "# Title\n\nSome text\n\n## Section 1\n\n### Subsection\n";
        let headings = extract_headings(content);
        assert_eq!(headings.len(), 3);
        assert_eq!(headings[0].level, 1);
        assert_eq!(headings[0].text, "Title");
        assert_eq!(headings[0].line, 1);
        assert_eq!(headings[1].level, 2);
        assert_eq!(headings[1].text, "Section 1");
        assert_eq!(headings[2].level, 3);
    }

    #[test]
    fn test_extract_headings_empty() {
        let content = "No headings here\nJust plain text";
        let headings = extract_headings(content);
        assert!(headings.is_empty());
    }

    #[test]
    fn test_estimate_importance_readme() {
        assert!(estimate_importance("README.md", "# Project") > 0.9);
    }

    #[test]
    fn test_estimate_importance_architecture() {
        assert!(estimate_importance("architecture.md", "# Architecture") > 0.8);
    }

    #[test]
    fn test_estimate_importance_test() {
        assert!(estimate_importance("test-guide.md", "# Testing") < 0.5);
    }

    #[test]
    fn test_estimate_importance_explicit_comment() {
        let content = "# File\n<!--litho:importance=0.75-->\nContent here";
        assert!((estimate_importance("random.md", content) - 0.75).abs() < 0.001);
    }

    #[test]
    fn test_estimate_importance_default() {
        assert!((estimate_importance("random.md", "Some content") - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_classify_purpose() {
        assert_eq!(classify_purpose("README.md", ""), "Overview");
        assert_eq!(classify_purpose("architecture.md", ""), "Architecture");
        assert_eq!(classify_purpose("api-reference.md", ""), "API Reference");
        assert_eq!(classify_purpose("test-plan.md", ""), "Testing");
    }

    #[test]
    fn test_build_meta() {
        let mut index = HashMap::new();
        index.insert("README.md".to_string(), vec!["# Project".to_string(), "Overview".to_string()]);
        index.insert("api.md".to_string(), vec!["# API".to_string()]);

        let meta = build_meta(Path::new("/tmp/docs"), &index);
        assert_eq!(meta.importance.len(), 2);
        assert!(meta.importance["README.md"] > meta.importance["api.md"]);
        assert_eq!(meta.purposes["README.md"], "Overview");
    }
}
```

**Step 2: Register module**

In `src/main.rs`, add after `mod watcher;`:
```rust
mod deepwiki;
```

**Step 3: Run tests**

```bash
RUSTC_WRAPPER="" cargo test --lib deepwiki::tests
```
Expected: ALL PASS.

**Step 4: Commit**

```bash
git add src/deepwiki.rs src/main.rs
git commit -m "feat(deepwiki): add metadata parsing, importance scoring, heading extraction, binary detection"
```

---

## Phase 5-8: Remaining Phases (Visualization, Search, Workspace, Polish)

Phases 5-8 follow the same TDD pattern. Due to the scale of this plan, they are outlined at task level with key implementation notes. Each task follows the same 5-step pattern: write failing test → verify it fails → implement → verify it passes → commit.

### Task 5.1: Create visualization.rs (Dependency Graph JSON)

**Files:** Create `src/visualization.rs`, modify `src/main.rs`

Key function: `pub fn build_dependency_graph(ast_index: &AstIndex) -> GraphData` where `GraphData` has `nodes: Vec<GraphNode>` and `links: Vec<GraphLink>`. Nodes derive from file list + importance scores. Links derive from import analysis in AstIndex.

Test: Create an AstIndex with known imports, verify graph output has correct nodes and edges.

### Task 5.2: Create C4 Diagram Generator

**Files:** Modify `src/visualization.rs`

Key function: `pub fn generate_c4_mermaid(ast_index: &AstIndex, level: &str) -> String` outputs valid Mermaid syntax for context/container/component/code levels.

Test: Generate C4 at each level, verify output contains expected Mermaid keywords (`graph`, `subgraph`, relationship arrows).

### Task 5.3: Add Visualization API Endpoints

**Files:** Modify `src/server.rs`

Routes: `/api/viz/dependency-graph`, `/api/viz/c4?level=component`, `/api/viz/heatmap`. Return JSON from visualization module.

Test: Integration tests via tower oneshot.

### Task 6.1: Create code_search.rs (Source File Indexing)

**Files:** Create `src/code_search.rs`, modify `src/main.rs`

Key structure: `CodeIndex { lines: HashMap<String, Vec<String>>, trigrams: HashMap<String, Vec<(String, usize)>> }`. Build from source directory scan. Search function returns results with line numbers and context.

Test: Build index from tempdir with known source files, search for known strings, verify results.

### Task 6.2: Fuzzy Search with Trigram Index

**Files:** Modify `src/code_search.rs`

Key function: `pub fn fuzzy_search(index: &CodeIndex, query: &str, limit: usize) -> Vec<FuzzyResult>`. Build trigram index at startup. Query splits into trigrams, intersects posting lists, ranks by match count.

Test: Build index, search for partial/misspelled terms, verify ranked results.

### Task 6.3: Symbol Cross-References

**Files:** Modify `src/code_search.rs` or new section in `src/ast_analysis.rs`

Key function: `pub fn build_cross_references(ast_index: &AstIndex, search_index: &HashMap<String, Vec<String>>) -> HashMap<String, Vec<CrossRef>>`. Scans doc content for backtick-quoted symbol names, links to AST definitions.

Test: Create docs mentioning known symbols, verify cross-refs point to correct files/lines.

### Task 6.4: Add Search API Endpoints

**Files:** Modify `src/server.rs`

Routes: `/api/search/code?q=<query>`, `/api/search/fuzzy?q=<query>`, `/api/ast/xref?symbol=<name>`.

Test: Integration tests via tower oneshot.

### Task 7.1: Create workspace.rs (Multi-Project)

**Files:** Create `src/workspace.rs`, modify `src/main.rs`

Key structures: `Workspace { name, projects, active_project, cross_refs }` and `Project { name, doc_tree, ast_index, docs_path, source_path }`.

TOML parsing: `pub fn load_workspace(path: &Path) -> Result<WorkspaceConfig, LithoBookError>`. Add `toml` dependency.

Test: Parse a workspace.toml from tempdir, verify project list and paths.

### Task 7.2: Multi-Project State Management

**Files:** Modify `src/server.rs`, `src/workspace.rs`

Upgrade AppState to hold `Arc<RwLock<Workspace>>`. Each project gets independent doc_tree and ast_index. Active project switching via API.

Test: Create workspace with 2 projects, verify switching returns correct tree for each.

### Task 7.3: Cross-Project Linking

**Files:** Modify `src/workspace.rs`

Scan imports across projects. If project A imports a crate whose name matches project B, create cross-refs.

Test: Two temp projects where A imports B, verify cross-ref created.

### Task 7.4: Add Workspace API Endpoints

**Files:** Modify `src/server.rs`

Routes: `/api/workspace`, `/api/workspace/switch?project=<name>`.

Test: Integration tests.

### Task 8.1: Template Enhancements (SSE Listener + Symbol Sidebar)

**Files:** Modify `templates/index.html.tpl`

Add:
- `EventSource('/api/events')` listener that refreshes sidebar on `tree_rebuilt` events
- Symbol sidebar panel (collapsible, populated from `/api/ast/symbols`)
- Complexity badges in file list
- Ctrl+P fuzzy search dialog
- Workspace tab bar (when `/api/workspace` returns multiple projects)

### Task 8.2: Version Bump and Final Verification

**Files:** Modify `Cargo.toml` (version 0.5.0)

```bash
cargo fmt --check
RUSTC_WRAPPER="" cargo clippy --all-targets -- -D warnings
RUSTC_WRAPPER="" cargo clippy --all-targets --features ast -- -D warnings
RUSTC_WRAPPER="" cargo test
RUSTC_WRAPPER="" cargo test --features ast
RUSTC_WRAPPER="" cargo build --release
RUSTC_WRAPPER="" cargo build --release --features ast
```

Smoke test with real repos:
```bash
# Litho docs
RUSTC_WRAPPER="" cargo run --features ast -- --docs-dir ./docs --source-dir . --watch --open

# deepwiki-rs docs (if generated)
RUSTC_WRAPPER="" cargo run --features ast -- --docs-dir C:\codedev\deepwiki-rs\docs --source-dir C:\codedev\deepwiki-rs --open
```

Tag: `git tag v0.5.0`

---

## Summary

| Phase | Tasks | New Tests | New Files | Key Dependencies |
|-------|-------|-----------|-----------|-----------------|
| 1: Foundation | 1.1-1.6 | ~20 | watcher.rs | notify 8 |
| 2: AST Core | 2.1-2.6 | ~15 | ast_analysis.rs, ast_rules.rs | ast-grep-core, tree-sitter-* |
| 3: AST Advanced | 3.1-3.2 | ~8 | (additions to existing) | - |
| 4: deepwiki-rs | 4.1 | ~10 | deepwiki.rs | - |
| 5: Visualization | 5.1-5.3 | ~10 | visualization.rs | - |
| 6: Search | 6.1-6.4 | ~15 | code_search.rs | - |
| 7: Workspace | 7.1-7.4 | ~12 | workspace.rs | toml |
| 8: Polish | 8.1-8.2 | ~5 | (template changes) | - |
| **Total** | **~25 tasks** | **~95 new** | **7 new modules** | |

Combined with existing 43 tests: target 138+ total tests at v0.5.0.
