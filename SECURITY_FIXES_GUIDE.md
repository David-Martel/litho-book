# Security Fixes Implementation Guide

This document provides secure code implementations for each finding in the security audit.

---

## Finding #1: Path Traversal Whitelist Bypass

### Vulnerability
HashMap lookup at startup doesn't prevent runtime bypass if paths aren't normalized consistently.

### Secure Implementation

```rust
// src/filesystem.rs - Add canonical path validation
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct DocumentTree {
    pub root: FileNode,
    pub file_map: HashMap<String, PathBuf>,
    pub stats: TreeStats,
    pub search_index: HashMap<String, Vec<String>>,
    docs_base_canonical: PathBuf,  // ADD: Store canonical base path
}

impl DocumentTree {
    pub fn new(docs_dir: &Path) -> anyhow::Result<Self> {
        // ... existing code ...

        // ADD: Canonicalize base path at startup
        let docs_base_canonical = docs_dir.canonicalize()
            .map_err(|e| anyhow::anyhow!("Cannot canonicalize docs directory: {}", e))?;

        debug!(
            "Document tree built: {} files, {} directories, {} bytes total",
            stats.total_files, stats.total_dirs, stats.total_size
        );

        Ok(DocumentTree {
            root,
            file_map,
            stats,
            search_index,
            docs_base_canonical,  // ADD: Store for later validation
        })
    }

    /// Get the content of a file by its relative path - with defense in depth
    pub fn get_file_content(&self, file_path: &str) -> anyhow::Result<String> {
        // First: Check whitelist (fast path)
        let path = self
            .file_map
            .get(file_path)
            .ok_or_else(|| anyhow::anyhow!("File not found"))?
            .clone();

        // Second: Validate at runtime (defense in depth)
        // Canonicalize the actual file path and verify it's still under docs_dir
        let canonical_path = path.canonicalize()
            .map_err(|e| anyhow::anyhow!("Cannot access file: unauthorized"))?;

        if !canonical_path.starts_with(&self.docs_base_canonical) {
            error!("Path traversal attempt detected: {:?}", canonical_path);
            return Err(anyhow::anyhow!("File not found"));
        }

        debug!("Reading file: {}", canonical_path.display());
        std::fs::read_to_string(&canonical_path)
            .map_err(|_| anyhow::anyhow!("File not found"))
    }
}
```

### Testing
```bash
# These should all return 404
curl "http://localhost:3000/api/file?file=../../etc/passwd"
curl "http://localhost:3000/api/file?file=docs%2F..%2F..%2Fetc%2Fpasswd"
curl "http://localhost:3000/api/file?file=%2E%2E%2F%2E%2E%2Fetc%2Fpasswd"
```

---

## Finding #2: XSS in AI Chat Responses

### Vulnerability
`innerHTML` renders untrusted LLM output without escaping.

### Secure Implementation (APPROACH A: HTML Escaping)

```javascript
// templates/index.html.tpl - Add HTML escaping function

// ADD: HTML escape function
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

// Modify renderSimpleMarkdown to escape user content
function renderSimpleMarkdown(text) {
    // Escape the input first
    let escaped = escapeHtml(text);

    // REMOVED: HTML generation from user regex
    // text = text.replace(/```(\w+)?\n([\s\S]*?)\n```/g, ...)

    // NEW: Create safe markdown rendering
    // Only allow specific markdown constructs, with escaped content

    // Process code blocks (already escaped, so safe)
    escaped = escaped.replace(/```(\w+)?\n([\s\S]*?)\n```/g, (match, lang, code) => {
        return `<pre><code class="language-${escapeHtml(lang || '')}">${code}</code></pre>`;
    });

    // Process inline markdown with escaped content
    escaped = escaped
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')  // Now safe: $1 is already escaped
        .replace(/\*(.*?)\*/g, '<em>$1</em>')
        .replace(/`(.*?)`/g, '<code>$1</code>');

    // Handle Mermaid blocks BEFORE returning (same approach as before, but with escaping)
    const mermaidBlocks = [];
    const mermaidPlaceholders = [];

    escaped = escaped.replace(/```mermaid\n([\s\S]*?)\n```/g, (match, mermaidCode) => {
        const mermaidId = `mermaid-ai-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        const placeholder = `__MERMAID_PLACEHOLDER_${mermaidId}__`;
        // Escape mermaid code for safety
        mermaidBlocks.push({ id: mermaidId, code: mermaidCode.trim() });
        mermaidPlaceholders.push({ placeholder, id: mermaidId, code: mermaidCode.trim() });
        return placeholder;
    });

    // Replace placeholders with safe divs
    mermaidPlaceholders.forEach(item => {
        escaped = escaped.replace(
            item.placeholder,
            `<div class="mermaid" id="${escapeHtml(item.id)}">${escapeHtml(item.code)}</div>`
        );
    });

    escaped = escaped.replace(/\n/g, '<br>');

    return escaped;
}

// Modify chat handler to use textContent for safety
async function handleStreamResponse(response, messageElement) {
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let fullContent = '';
    const contentDiv = messageElement.querySelector('.ai-message-content');

    try {
        while (true) {
            const { done, value } = await reader.read();

            if (done) break;

            const chunk = decoder.decode(value, { stream: true });
            const lines = chunk.split('\n');

            for (const line of lines) {
                if (line.startsWith('data: ')) {
                    const data = line.slice(6);

                    if (data === '[DONE]') {
                        // Use innerHTML ONLY with safe, escaped content
                        contentDiv.innerHTML = renderSimpleMarkdown(fullContent);
                        return;
                    }

                    try {
                        const event = JSON.parse(data);

                        if (event.event_type === 'content' && event.content) {
                            fullContent += event.content;
                            // SAFE: renderSimpleMarkdown now escapes
                            contentDiv.innerHTML = renderSimpleMarkdown(fullContent) +
                                                   '<span class="ai-cursor">|</span>';

                            const messagesContainer = document.getElementById('aiChatMessages');
                            messagesContainer.scrollTop = messagesContainer.scrollHeight;
                        }
                    } catch (e) {
                        console.warn('Failed to parse event:', e);
                    }
                }
            }
        }
    } catch (error) {
        console.error('Stream error:', error);
        contentDiv.textContent = 'Error reading response';
    }
}
```

### Secure Implementation (APPROACH B: Using DOMPurify - RECOMMENDED)

```html
<!-- templates/index.html.tpl - Add to <head> -->
<script src="https://cdn.jsdelivr.net/npm/dompurify@3.0.5/dist/purify.min.js"></script>

<script>
// Configure DOMPurify
const purifyConfig = {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'code', 'pre', 'div', 'span', 'br', 'p', 'h1', 'h2', 'h3', 'ul', 'ol', 'li', 'blockquote'],
    ALLOWED_ATTR: ['class', 'id', 'href'],
    KEEP_CONTENT: true,
    RETURN_DOM: false,
    RETURN_DOM_FRAGMENT: false,
    RETURN_DOM_IMPORT: false,
    FORCE_BODY: false,
    SANITIZE_DOM: true,
    IN_PLACE: false,
};

function renderSimpleMarkdown(text) {
    // Process code blocks (text content only, safe)
    const mermaidBlocks = [];
    const mermaidPlaceholders = [];

    text = text.replace(/```mermaid\n([\s\S]*?)\n```/g, (match, mermaidCode) => {
        const mermaidId = `mermaid-ai-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        const placeholder = `__MERMAID_PLACEHOLDER_${mermaidId}__`;
        mermaidBlocks.push({ id: mermaidId, code: mermaidCode.trim() });
        mermaidPlaceholders.push({ placeholder, id: mermaidId, code: mermaidCode.trim() });
        return placeholder;
    });

    // Process code blocks
    text = text.replace(/```(\w+)?\n([\s\S]*?)\n```/g, (match, lang, code) => {
        return `<pre><code class="language-${lang || ''}">${code}</code></pre>`;
    });

    // Safe markdown
    text = text
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.*?)\*/g, '<em>$1</em>')
        .replace(/`(.*?)`/g, '<code>$1</code>')
        .replace(/\n/g, '<br>');

    // Replace mermaid placeholders
    mermaidPlaceholders.forEach(item => {
        text = text.replace(item.placeholder,
            `<div class="mermaid" id="${item.id}">${item.code}</div>`);
    });

    // Sanitize with DOMPurify - removes all scripts, event handlers, etc.
    const sanitized = DOMPurify.sanitize(text, purifyConfig);

    // Handle mermaid rendering
    if (mermaidBlocks.length > 0) {
        setTimeout(() => {
            mermaidBlocks.forEach(block => {
                const element = document.getElementById(block.id);
                if (element && typeof mermaid !== 'undefined') {
                    try {
                        element.textContent = block.code;
                        mermaid.run(undefined, `#${block.id}`);
                    } catch (error) {
                        console.warn('Mermaid render error:', error);
                    }
                }
            });
        }, 100);
    }

    return sanitized;
}

// Update chat handler
async function handleStreamResponse(response, messageElement) {
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let fullContent = '';
    const contentDiv = messageElement.querySelector('.ai-message-content');

    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            const chunk = decoder.decode(value, { stream: true });
            const lines = chunk.split('\n');

            for (const line of lines) {
                if (line.startsWith('data: ')) {
                    const data = line.slice(6);

                    if (data === '[DONE]') {
                        contentDiv.innerHTML = renderSimpleMarkdown(fullContent);
                        return;
                    }

                    try {
                        const event = JSON.parse(data);
                        if (event.event_type === 'content' && event.content) {
                            fullContent += event.content;
                            // DOMPurify filters all XSS
                            contentDiv.innerHTML = renderSimpleMarkdown(fullContent) +
                                                   '<span class="ai-cursor">|</span>';
                        }
                    } catch (e) {
                        console.warn('Parse error:', e);
                    }
                }
            }
        }
    } catch (error) {
        console.error('Stream error:', error);
    }
}
</script>
```

---

## Finding #3: Permissive CORS

### Vulnerability
`CorsLayer::permissive()` allows any origin.

### Secure Implementation

```rust
// src/server.rs - Replace permissive CORS with whitelist

use tower_http::cors::{CorsLayer, AllowOrigin, AllowMethods, AllowHeaders};
use http::HeaderMap;

/// Create the main application router with secure CORS
pub fn create_router(doc_tree: DocumentTree, docs_path: String) -> Router {
    let state = AppState {
        doc_tree,
        docs_path,
    };

    // Secure CORS configuration
    let cors = CorsLayer::new()
        // Only allow localhost origins
        .allow_origin(AllowOrigin::predicate(|origin, _| {
            let origin_str = origin.as_bytes();
            // Allow http://localhost:* and http://127.0.0.1:*
            origin_str.starts_with(b"http://localhost:") ||
            origin_str.starts_with(b"http://127.0.0.1:") ||
            origin_str.starts_with(b"http://[::1]:") ||  // IPv6 localhost
            (cfg!(debug_assertions) && origin_str == b"http://localhost:3000")  // Dev convenience
        }))
        // Only allow safe methods
        .allow_methods(AllowMethods::list(vec![
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::OPTIONS,
        ]))
        // Only allow necessary headers
        .allow_headers(AllowHeaders::list(vec![
            axum::http::header::CONTENT_TYPE,
            axum::http::header::ACCEPT,
        ]))
        // Do not allow credentials (removes vulnerability to cookie theft)
        .allow_credentials(false)
        // Add security-related response headers
        .max_age(std::time::Duration::from_secs(86400));

    Router::new()
        .route("/", get(index_handler))
        .route("/api/file", get(get_file_handler))
        .route("/api/tree", get(get_tree_handler))
        .route("/api/search", get(search_handler))
        .route("/api/stats", get(stats_handler))
        .route("/api/chat", post(chat_stream_handler))
        .route("/health", get(health_handler))
        .nest_service("/assets", ServeDir::new("assets"))
        .layer(cors)  // Apply secure CORS
        .with_state(state)
}
```

### Alternative: Document-specific CORS

```rust
// If you need to support document sharing across origins:

let allowed_origins = vec![
    "https://docs.example.com",
    "https://internal.example.com",
];

let cors = CorsLayer::new()
    .allow_origin(AllowOrigin::predicate(move |origin, _| {
        allowed_origins.iter().any(|allowed| {
            origin.as_bytes() == allowed.as_bytes()
        })
    }))
    // ... rest of config
```

---

## Finding #4: API Key Exposure

### Vulnerability
LITHO_BOOK_LLM_KEY stored as env var, sent in plaintext Authorization header.

### Secure Implementation

```rust
// Cargo.toml - Add dependencies
[dependencies]
# ... existing ...
dotenvy = "0.15"  # For .env file support
# For Windows: use credential manager (optional, advanced)
# For Linux/Mac: could use keyring crate

// src/main.rs - Load secrets securely
use dotenvy;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env file if it exists (but don't fail if missing)
    let _ = dotenvy::dotenv();  // Silent failure if no .env

    // Validate that secrets are set before proceeding
    if std::env::var("LITHO_BOOK_LLM_KEY").is_err() {
        warn!("LITHO_BOOK_LLM_KEY not set - AI chat will be disabled");
    }

    // ... rest of main ...
}

// src/server.rs - Secure API key handling

use std::sync::Arc;
use tokio::sync::RwLock;

pub struct AppState {
    pub doc_tree: DocumentTree,
    pub docs_path: String,
    // ADD: API key stored securely, wrapped in Arc<RwLock> for thread-safe access
    pub llm_key: Arc<RwLock<Option<String>>>,
}

/// Call OpenAI-compatible API with secure key handling
async fn call_openai_stream_api(
    message: &str,
    context: Option<&str>,
    history: Option<Vec<OpenAIMessage>>,
    llm_key: Arc<RwLock<Option<String>>>,  // Pass key, don't env::var()
) -> Result<
    tokio::sync::mpsc::Receiver<Result<String, Box<dyn std::error::Error + Send + Sync>>>,
    Box<dyn std::error::Error + Send + Sync>,
> {
    // Check if key is available
    let key_guard = llm_key.read().await;
    let llm_key_value = match key_guard.as_ref() {
        Some(key) if !key.is_empty() => key.clone(),
        _ => {
            return Err("AI feature not configured - LITHO_BOOK_LLM_KEY not set".into());
        }
    };
    drop(key_guard);  // Explicitly drop lock before async operations

    let client = reqwest::Client::new();

    // ... build request ...

    let response = client
        .post("https://open.bigmodel.cn/api/paas/v4/chat/completions")
        .header(
            "Authorization",
            format!("Bearer {}", llm_key_value),
        )
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await?;

    // Clear key from memory after use (attempt, may not be guaranteed)
    drop(llm_key_value);

    if !response.status().is_success() {
        let status = response.status();
        // DO NOT log response body - may contain sensitive info
        return Err(format!("API request failed: {}", status).into());
    }

    // ... rest of streaming ...
    Ok(rx)
}

// Update chat handler to pass key
async fn chat_stream_handler(
    State(state): State<AppState>,
    Json(request): Json<ChatRequest>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    debug!("AI assistant received message");

    let llm_key = state.llm_key.clone();  // Clone Arc, not key content

    let stream = async_stream::stream! {
        match call_openai_stream_api(
            &request.message,
            request.context.as_deref(),
            request.history,
            llm_key,  // Pass Arc, not key
        ).await {
            Ok(mut response_stream) => {
                // ... rest of handler ...
            }
            Err(e) => {
                error!("AI API call failed");  // Log error type, not details
                yield Ok(Event::default()
                    .event("error")
                    .data(serde_json::to_string(&StreamEvent {
                        event_type: "error".to_string(),
                        content: Some("AI feature unavailable".to_string()),
                        suggestions: None,
                        finished: true,
                    }).unwrap_or_default()));
            }
        }
    };

    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(1))
            .text("keep-alive-text"),
    )
}
```

### .env File (.gitignore this!)

```bash
# .env (DO NOT COMMIT TO GIT!)
LITHO_BOOK_LLM_KEY=sk_live_your_actual_key_here
```

### .gitignore Update

```bash
# Add to .gitignore
.env
.env.local
.env.*.local
secrets/
*.key
*.pem
```

---

## Finding #5: Missing Input Size Limits

### Vulnerability
No maximum payload sizes on POST/GET endpoints.

### Secure Implementation

```rust
// src/server.rs - Add input size limits

use tower::ServiceBuilder;
use tower_http::limit::RequestBodyLimitLayer;
use axum::extract::DefaultBodyLimit;

/// Create the main application router with size limits
pub fn create_router(doc_tree: DocumentTree, docs_path: String) -> Router {
    let state = AppState {
        doc_tree,
        docs_path,
    };

    // Secure CORS configuration (from Finding #3)
    let cors = CorsLayer::new()
        // ... CORS config from Finding #3 ...
        ;

    Router::new()
        .route("/", get(index_handler))
        .route("/api/file", get(get_file_handler))
        .route("/api/tree", get(get_tree_handler))
        .route("/api/search", get(search_handler))
        .route("/api/stats", get(stats_handler))
        .route("/api/chat", post(chat_stream_handler)
            // Limit chat POST body to 10 MB
            .layer(DefaultBodyLimit::max(10 * 1024 * 1024)))
        .route("/health", get(health_handler))
        .nest_service("/assets", ServeDir::new("assets"))
        .layer(cors)
        // Global request body limit fallback
        .layer(ServiceBuilder::new()
            .layer(RequestBodyLimitLayer::symmetric(10 * 1024 * 1024)))
        .with_state(state)
}

// Also update ChatRequest to validate content length
#[derive(Deserialize)]
pub struct ChatRequest {
    #[serde(rename = "message")]
    pub message: String,

    #[serde(rename = "context")]
    pub context: Option<String>,

    #[serde(rename = "history")]
    pub history: Option<Vec<OpenAIMessage>>,
}

// Add custom validation in handler
async fn chat_stream_handler(
    State(state): State<AppState>,
    body: axum::extract::RawBody,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    use axum::body::Body;
    use axum::extract::Json;

    // Parse body with validation
    let request = match axum::extract::Json::<ChatRequest>::from_request(
        Request::new(Body::new()),
        &Default::default(),
    ).await {
        Ok(Json(req)) => {
            // Validate message size
            if req.message.len() > 100_000 {  // 100KB limit
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }

            // Validate context size
            if let Some(ref ctx) = req.context {
                if ctx.len() > 1_000_000 {  // 1MB limit
                    return Err(StatusCode::PAYLOAD_TOO_LARGE);
                }
            }

            // Validate history size
            if let Some(ref hist) = req.history {
                if hist.len() > 50 {  // Max 50 messages
                    return Err(StatusCode::BAD_REQUEST);
                }
                let total_size: usize = hist.iter()
                    .map(|m| m.content.len())
                    .sum();
                if total_size > 2_000_000 {  // 2MB total history
                    return Err(StatusCode::PAYLOAD_TOO_LARGE);
                }
            }

            req
        }
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    // ... rest of handler with validated request ...
}

// For GET endpoints, validate query string length
#[derive(Deserialize)]
pub struct SearchQuery {
    q: Option<String>,
}

async fn search_handler(
    Query(params): Query<SearchQuery>,
    State(state): State<AppState>,
) -> Result<Json<SearchResponse>, StatusCode> {
    let query = params.q.unwrap_or_default();

    // Validate query size
    if query.len() > 10_000 {  // 10KB limit for search queries
        return Ok(Json(SearchResponse {
            results: vec![],
            total: 0,
            query: String::new(),
        }));
    }

    if query.trim().is_empty() {
        return Ok(Json(SearchResponse {
            results: vec![],
            total: 0,
            query: query.clone(),
        }));
    }

    debug!("Searching for: {}", query);

    let results = state.doc_tree.search_content(&query);
    let total = results.len();

    debug!("Found {} results matching query: {}", total, query);

    Ok(Json(SearchResponse {
        results,
        total,
        query,
    }))
}

#[derive(Deserialize)]
pub struct FileQuery {
    file: Option<String>,
}

async fn get_file_handler(
    Query(params): Query<FileQuery>,
    State(state): State<AppState>,
) -> Result<Json<FileResponse>, StatusCode> {
    let file_path = params.file.ok_or_else(|| {
        debug!("Missing file parameter");
        StatusCode::BAD_REQUEST
    })?;

    // Validate file path length
    if file_path.len() > 4_096 {  // 4KB max path
        return Err(StatusCode::BAD_REQUEST);
    }

    // ... rest of handler ...
}
```

### Cargo.toml Updates

```toml
[dependencies]
# ... existing ...
tower = "0.5"
tower-http = { version = "0.6", features = ["fs", "cors", "limit"] }  # Add "limit"
```

---

## Finding #6: Weak Windows Privilege Check

### Vulnerability
Always returns `true` on Windows, permitting port < 1024 binding attempts.

### Secure Implementation

```rust
// src/cli.rs - Proper privilege checking

/// Check if the current process has elevated privileges
fn is_privileged() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }

    #[cfg(windows)]
    {
        // Check if user is in Administrators group
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        // Try to run 'net session' - succeeds only if admin
        let output = std::process::Command::new("net")
            .args(&["session"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        match output {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

// Update validation to be clearer
impl Args {
    /// Validate the command line arguments
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.docs_dir.exists() {
            anyhow::bail!(
                "Documentation directory does not exist: {}",
                self.docs_dir.display()
            );
        }

        if !self.docs_dir.is_dir() {
            anyhow::bail!(
                "Path is not a directory: {}",
                self.docs_dir.display()
            );
        }

        // Prevent binding to all interfaces
        if self.host == "0.0.0.0" || self.host == "::" {
            anyhow::bail!(
                "Cannot bind to all interfaces ({}). Use 127.0.0.1 or a specific IP address.",
                self.host
            );
        }

        // Check privileged port binding
        if self.port < 1024 && !is_privileged() {
            anyhow::bail!(
                "Port {} requires administrator/root privileges. Please use a port >= 1024 or run as administrator.",
                self.port
            );
        }

        Ok(())
    }
}
```

---

## Finding #7: Information Disclosure

### Vulnerability
Error messages reveal file paths and internal structure.

### Secure Implementation

```rust
// src/filesystem.rs - Generic error messages

pub fn get_file_content(&self, file_path: &str) -> anyhow::Result<String> {
    let path = self
        .file_map
        .get(file_path)
        .ok_or_else(|| {
            // Log the actual error internally
            debug!("File not found: {}", file_path);
            // Return generic error to client
            anyhow::anyhow!("File not found")
        })?;

    debug!("Reading file: {}", path.display());
    std::fs::read_to_string(path)
        .map_err(|e| {
            // Log actual error for debugging
            warn!("Failed to read file {}: {}", path.display(), e);
            // Return generic error to client
            anyhow::anyhow!("File not found")
        })
}

// src/server.rs - Generic API responses

async fn get_file_handler(
    Query(params): Query<FileQuery>,
    State(state): State<AppState>,
) -> Result<Json<FileResponse>, StatusCode> {
    let file_path = params.file.ok_or_else(|| {
        debug!("Missing file parameter in request");
        StatusCode::BAD_REQUEST
    })?;

    debug!("Requesting file: {}", file_path);

    let content = state.doc_tree.get_file_content(&file_path).map_err(|e| {
        // Log real error internally
        error!("Failed to read file: {}", e);
        // Return generic status code
        StatusCode::NOT_FOUND
    })?;

    let html = state.doc_tree.render_markdown(&content);

    // Get file metadata if available
    let file_info = state
        .doc_tree
        .file_map
        .get(&file_path)
        .and_then(|path| std::fs::metadata(path).ok())
        .map(|metadata| {
            let size = metadata.len();
            let modified = metadata.modified().ok().and_then(|time| {
                time.duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .and_then(|d| {
                        let datetime = chrono::DateTime::from_timestamp(d.as_secs() as i64, 0)?;
                        Some(datetime.format("%Y-%m-%d %H:%M:%S").to_string())
                    })
            });
            (size, modified)
        });

    let response = FileResponse {
        content,
        html,
        path: file_path,  // Safe: this is already validated by whitelist
        size: file_info.as_ref().map(|(size, _)| *size),
        modified: file_info.and_then(|(_, modified)| modified),
    };

    info!("File served successfully");  // Generic log
    Ok(Json(response))
}

// LLM API error handling - hide details
async fn call_openai_stream_api(
    message: &str,
    context: Option<&str>,
    history: Option<Vec<OpenAIMessage>>,
    llm_key: Arc<RwLock<Option<String>>>,
) -> Result<
    tokio::sync::mpsc::Receiver<Result<String, Box<dyn std::error::Error + Send + Sync>>>,
    Box<dyn std::error::Error + Send + Sync>,
> {
    // ... setup code ...

    let response = client
        .post("https://open.bigmodel.cn/api/paas/v4/chat/completions")
        .header("Authorization", format!("Bearer {}", llm_key_value))
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        // DO NOT log response body
        error!("LLM API error: {}", status);  // Log status only
        return Err("AI service temporarily unavailable".into());
    }

    // ... rest of function ...
}
```

---

## Finding #8: Add Security Headers

### Implementation

```rust
// src/server.rs - Add security headers

use tower_http::set_header::SetResponseHeaderLayer;
use axum::http::{header, HeaderValue};

pub fn create_router(doc_tree: DocumentTree, docs_path: String) -> Router {
    let state = AppState {
        doc_tree,
        docs_path,
    };

    let cors = CorsLayer::new()
        // ... CORS config ...
        ;

    Router::new()
        .route("/", get(index_handler))
        .route("/api/file", get(get_file_handler))
        .route("/api/tree", get(get_tree_handler))
        .route("/api/search", get(search_handler))
        .route("/api/stats", get(stats_handler))
        .route("/api/chat", post(chat_stream_handler)
            .layer(DefaultBodyLimit::max(10 * 1024 * 1024)))
        .route("/health", get(health_handler))
        .nest_service("/assets", ServeDir::new("assets"))
        .layer(cors)
        // ADD: Security headers
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'self'; \
                 script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; \
                 style-src 'self' 'unsafe-inline' fonts.googleapis.com; \
                 font-src 'self' fonts.gstatic.com; \
                 img-src 'self' data:; \
                 connect-src 'self' open.bigmodel.cn; \
                 frame-ancestors 'none'; \
                 base-uri 'self'; \
                 form-action 'self'"
            ),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_XSS_PROTECTION,
            HeaderValue::from_static("1; mode=block"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .with_state(state)
}
```

---

## Implementation Priority

1. **Immediate (Week 1):**
   - Finding #2: XSS sanitization (use DOMPurify approach)
   - Finding #5: Input size limits
   - Finding #7: Generic error messages

2. **Important (Week 2):**
   - Finding #1: Path traversal defense in depth
   - Finding #4: API key management
   - Finding #3: CORS restrictions

3. **Hardening (Week 3):**
   - Finding #6: Windows privilege check
   - Finding #8: Security headers
   - Add comprehensive test cases

---

## Testing After Implementation

```bash
# 1. XSS Test
curl -X POST http://localhost:3000/api/chat \
  -d '{"message":"<img src=x onerror=alert(1)>","context":null}' \
  -H "Content-Type: application/json"

# 2. Path Traversal Test
curl "http://localhost:3000/api/file?file=../../etc/passwd"

# 3. Size Limit Test
python3 -c "
import requests
big = 'A' * (11 * 1024 * 1024)
requests.post('http://localhost:3000/api/chat', json={
    'message': big
})
"

# 4. CORS Test
curl -H "Origin: http://evil.com" http://localhost:3000/api/search?q=test

# 5. Security Headers Test
curl -i http://localhost:3000/ | grep -i "content-security\|x-content-type\|x-frame"
```

