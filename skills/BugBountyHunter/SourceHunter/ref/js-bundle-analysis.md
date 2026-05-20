## JS Bundle Analysis Methodology

Activated when `source-js-bundle` worker runs (condition: `source_snapshot_dir contains *.js
OR js_bundles_available`). This section defines the full methodology the worker must execute —
the sink list and tool invocations above are necessary but not sufficient without this workflow.

### 1. Bundle Acquisition

Before static analysis begins, ensure all available JS is collected:

| Source | How to Collect | Priority |
|--------|---------------|---------|
| **Webpack bundle** | Spider target at startup; capture all `*.bundle.js`, `*.chunk.js`, `*.min.js` | High |
| **Webpack manifest** | Fetch `webpack.manifest.json`, `asset-manifest.json`, `manifest.json` at webroot | High |
| **Source map links** | Look for `//# sourceMappingURL=` comment at end of every JS file | High |
| **Service worker** | `GET /sw.js`, `GET /service-worker.js` | Medium |
| **Dynamic chunks** | Scan HTML and existing bundles for `import(` or `require.ensure(` calls; fetch referenced chunk IDs | Medium |
| **`/.well-known/` scripts** | Some SaaS expose debugging bundles here | Low |

Tool: `jsluice urls -r <bundle_file>` to extract all URLs/endpoints referenced in each bundle.

### 2. Source Map Recovery

When `//# sourceMappingURL=<path>` is found at the end of a JS file:

```
Step 1: Resolve the map URL
  If path is relative → concatenate with bundle URL base
  If path is absolute → fetch as-is
  Common pattern: bundle.js → bundle.js.map

Step 2: Fetch the .map file
  GET https://target.com/static/js/main.chunk.js.map
  If 200: source map is publicly accessible (high value — emit sourcemap_secret_sink signal)
  If 401/403: file exists but gated; note as evidence of build artifact leak

Step 3: Extract original source
  Tool: sourcemapper --url https://target.com/static/js/main.chunk.js.map --output ./recovered/
  Output: ./recovered/ contains original pre-minification source files
  Re-run semgrep and trufflehog against ./recovered/ — secret density is much higher here
```

Emit `sourcemap_available: true`, `sourcemap_url`, `original_files_count` when recovered.

### 3. Webpack Bundle Structure Analysis

When processing a webpack bundle (`webpackJsonp`, `__webpack_require__`, `__webpack_modules__`
are present in the JS):

| Indicator | What to Extract | Why |
|-----------|----------------|-----|
| `__webpack_require__(N)` | All module IDs → map to file paths via source map | Enumerate all bundled modules |
| `process.env.REACT_APP_*` | Baked-in environment variables | API keys, feature flags, internal endpoints |
| `process.env.NODE_ENV` | Check if production or debug build | Debug builds often include verbose error messages and internal paths |
| `webpackJsonpArray.push([[id], {...modules}])` | Module boundaries | Find auth/payment modules by name |
| `splitChunks` / `import(` | Async chunk references | Fetch all chunk IDs referenced in lazy imports |

Extract environment variables using:
```bash
grep -Eo 'process\.env\.[A-Z_]+' bundle.js | sort -u
grep -Eo '"[A-Z_]{4,}":"[^"]{8,}"' bundle.js  # baked env var values
```

### 4. Secret Pattern Library

Scan every JS file and recovered source file against these patterns:

| Secret Type | Pattern | Example Match |
|-------------|---------|--------------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` | `AKIAIOSFODNN7EXAMPLE` |
| AWS Secret Key | `(?i)(aws.{0,20}secret[^=\n]{0,20}=\s*)[A-Za-z0-9/+=]{40}` | |
| Google API Key | `AIza[0-9A-Za-z\-_]{35}` | |
| GitHub Token | `(ghp_\|github_pat_)[A-Za-z0-9_]{36,}` | |
| Slack Token | `xox[baprs]-[0-9A-Za-z\-]+` | |
| Stripe API Key | `(sk_live_\|pk_live_)[0-9a-zA-Z]{24,}` | |
| Twilio Token | `SK[0-9a-fA-F]{32}` | |
| Generic JWT | `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}` | Hardcoded token |
| Generic Bearer | `(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*` | In fetch() calls |
| PEM private key | `-----BEGIN (RSA \|EC \|OPENSSH )?PRIVATE KEY-----` | |
| Basic auth credential | `https?://[^:@/\n]+:[^:@/\n]+@` | Hardcoded cred in URL |
| Internal hostname | `https?://(localhost\|127\.0\.0\.1\|10\.\d+\|192\.168\.\d+\|172\.(1[6-9]\|2\d\|3[01])\.)` | Dev/staging endpoints |
| GraphQL endpoint | `/graphql`, `/api/graphql`, `gql\``, `graphQLUrl` | Hidden GQL surface |
| Internal API route | `(?i)(internal\|admin\|backstage\|debug\|management)/` | Admin endpoints |

Run `trufflehog filesystem --json --no-verification <dir>` for broad coverage, then layer
specific grep patterns for any findings trufflehog misses.

**CRITICAL**: never emit actual secret values — emit `secret_detected: true` with file path
and obfuscated first 4 chars only (policy: `deny_secret_exfiltration: true`).

### 5. Endpoint Extraction

Extract all URLs and API paths referenced in the bundle for addition to the live triage scope:

```bash
# jsluice: extract all URL-like strings
jsluice urls -r bundle.js > js-endpoints.txt

# grep for REST-style paths (feed to ReconAnalyzer endpoint discovery)
grep -Eo '"(/[a-zA-Z0-9_/-]{3,})"' bundle.js | tr -d '"' | sort -u >> js-endpoints.txt

# GraphQL operation names
grep -Eo 'query\s+[A-Za-z]+|mutation\s+[A-Za-z]+|subscription\s+[A-Za-z]+' bundle.js
```

Feed all extracted endpoints to TrafficTriage as supplemental discovery. Tag each
extracted endpoint with `origin: js_bundle` for traceability.

### 6. Feature Flag & Admin Path Detection

Scan for conditional feature blocks and admin-gated paths:

```javascript
// Patterns that reveal hidden functionality
if (process.env.REACT_APP_FEATURE_X === 'true')     // feature flags
if (user.role === 'admin' || user.is_internal)        // admin-gated UI routes
window.__INITIAL_STATE__ = {...}                       // server-side rendered state (PII risk)
window.__REDUX_STATE__ = {...}                        // full Redux store hydrated from server
```

If `window.__INITIAL_STATE__` or `window.__REDUX_STATE__` contains user PII or
auth tokens, emit `ssr_state_pii_leak: true` with the key names (not values).

### 7. JS Bundle Analysis Output Fields

Append to each `source_correlation` record when bundle analysis contributed to it:

```jsonc
{
  "js_bundle_analysis": {
    "bundle_file": "static/js/main.2a3f1c.chunk.js",
    "sourcemap_available": true,
    "sourcemap_url": "https://target.com/static/js/main.2a3f1c.chunk.js.map",
    "original_files_recovered": 142,
    "secrets_detected_count": 3,
    "secrets_detail": [
      {"type": "AWS Access Key", "file": "src/config/aws.js", "obfuscated_prefix": "AKIA"}
    ],
    "endpoints_extracted_count": 78,
    "hidden_admin_paths": ["/internal/debug", "/api/admin/users"],
    "ssr_state_pii_leak": false,
    "env_vars_baked_in": ["REACT_APP_API_URL", "REACT_APP_STRIPE_KEY"]
  }
}
```

---

### JS / Frontend + Backend Correlation

When the `source-js-bundle` worker completes, correlate frontend sinks with
their backend entry points before emitting final correlations.

1. **DOM XSS → Backend API Origin** — For each `dom_xss_sink`, extract the
   data source via AST analysis. If data flows from a `fetch()` / `XHR` call,
   trace the backend endpoint URL and emit a linked pair:
   `dom_xss_sink` (frontend) → backend endpoint serving unescaped data
   (often `cors_sink` or `idor_sink`).

2. **postMessage Handler → Backend Trigger** — For each `postmessage_sink` /
   `postmessage_no_origin_sink`, trace the handler body. If it makes a
   `fetch()`/`XHR` call or modifies `location`, identify the backend mutation
   endpoint and emit a linked pair with `cross_layer_correlation: true`.

3. **WebSocket Frontend → Backend Auth** — For each `websocket_origin_sink`
   in frontend JS, extract the WebSocket URL and trace to the backend upgrade
   handler to assess `websocket_origin_sink` / `websocket_auth_bypass` on the
   server side.

4. **JS-Discovered Endpoints → Taint Workers** — During bundle analysis,
   extract all backend API base URLs and endpoint paths via jsluice. Feed
   these as `js_discovered_endpoints` into the main taint flow workers so
   server-side sinks on those paths are prioritized.

Add `cross_layer_correlation` to `source-correlations.json` when frontend
and backend sinks are linked:
```jsonc
"cross_layer_correlation": {
  "frontend_sink": "dom_xss_sink",
  "frontend_file": "static/app.bundle.js",
  "frontend_line": 4412,
  "data_source": "fetch('/api/v1/user/profile').then(r => r.json())",
  "backend_endpoint": "/api/v1/user/profile",
  "backend_sink": "idor_sink"
}
```

