# Caido Integration — Comprehensive Analysis

## 1. Executive Summary

Caido is a lightweight, Rust-based HTTP proxy purpose-built for security
research. It fills a distinct niche that neither Burp Suite Enterprise nor
mitmproxy covers well:

| Capability | Burp Enterprise | mitmproxy | **Caido** |
|---|---|---|---|
| Automated active scanning | ✅ | ❌ | ❌ |
| Programmatic replay (Repeater) | via API (slow) | via addon | ✅ fast |
| Parametric fuzzing (Intruder) | limited API | ❌ | ✅ Automate |
| HTTP history query language | ❌ | Python only | ✅ **HTTPQL** |
| TypeScript plugin hooks | ❌ | Python only | ✅ SDK |
| GraphQL-first API | ❌ (REST) | REST | ✅ |
| Passive real-time callbacks | ❌ | addon required | ✅ per-request |
| Resource footprint | 1–4 GB JVM | ~50 MB | ~30 MB Rust |
| Per-request TypeScript logic | ❌ | Python addon | ✅ |

The CaseCrack integration treats Caido as a **third-tier proxy layer**:

```
Target ◄─── Burp Enterprise (automated active scans)
         ◄─── Caido (interactive manipulation, fuzzing, passive callbacks)
         ◄─── mitmproxy (flow recording, script-driven attacks)
```

Each proxy has a distinct role and the agent selects the right tool per task.

---

## 2. Architecture

### 2.1 Component Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│  CaseCrack Agent Loop                                               │
│                                                                     │
│  ┌───────────────┐   ┌──────────────────┐   ┌───────────────────┐  │
│  │  BurpEnterprise│   │  CaidoProvider   │   │ MitmproxyProvider │  │
│  │  Provider     │   │  (Python)        │   │  (Python)         │  │
│  │  :8080        │   │  GraphQL client  │   │  REST client      │  │
│  └───────────────┘   └────────┬─────────┘   └───────────────────┘  │
│                               │                                     │
└───────────────────────────────┼─────────────────────────────────────┘
                                │ HTTP
                     ┌──────────▼──────────┐
                     │  Caido Proxy        │
                     │  :8282 ← scan traffic
                     │  :8283 GraphQL API  │
                     │                     │
                     │  CaseCrack Bridge   │
                     │  Plugin (TS)        │  ← D1–D8 detectors
                     └──────────┬──────────┘
                                │ POST /api/caido-event
                     ┌──────────▼──────────┐
                     │  CaseCrack EventBus │
                     │  (finding injection)│
                     └─────────────────────┘
```

### 2.2 Docker Network

All services share the `secnet` bridge network:

| Service | Port (host) | Port (container) | Role |
|---|---|---|---|
| venator | 8080 | 8080 | CaseCrack main app |
| zap | 8090 | 8090 | OWASP ZAP active scanner |
| caido | 8282 | 8080 | Caido proxy |
| caido | 8283 | 8443 | Caido GraphQL / Web UI |
| grpc-testserver | 50051 | 50051 | gRPC test target |

### 2.3 Auth Modes

| Mode | Config | Best for |
|---|---|---|
| `CAIDO_NO_AUTH=true` | Docker env | CI / automated pipelines |
| PAT (api_key) | Set in `CaidoGraphQLClient(api_key=...)` | Persistent dev instances |
| Username / password | `username=`, `password=` | Interactive / cloud |

---

## 3. Agent Capability Uplift

### 3.1 HTTPQL — Structured History Queries

Caido's HTTPQL is a SQL-like language for filtering HTTP history. The agent
can issue queries such as:

```
# Find all admin endpoints that returned 200
req.path contains "/admin" and resp.code = 200

# Find Bearer tokens sent over HTTP
req.isTls = false and req.header["Authorization"] contains "Bearer"

# Find JSON POST requests returning HTML (error pages)
req.method = "POST" and req.header["Content-Type"] contains "json"
  and resp.header["Content-Type"] contains "text/html"

# Find potential IDOR targets (numeric IDs in path)
req.path matches "/api/[a-z]+/[0-9]+"
```

All queries are exposed via `CaidoProvider.search_history()` and
`CaidoProvider.find_interesting_endpoints()`.

### 3.2 Programmatic Replay (Repeater)

```python
provider = CaidoProvider(api_url="http://localhost:8282")
session = provider.replay("req_abc123")
# session["entries"] contains the full request+response pair
```

Compared to Burp's Repeater:
- No UI interaction required
- Full GraphQL response with structured body
- Can be batched in loops
- Response data available programmatically for assertion

### 3.3 Automate (Intruder / Fuzzer)

Two strategies are supported:

**SNIPER** — one insertion point, one payload list:
```python
results = provider.automate_sniper(
    request_id="req_abc123",
    payloads=["' OR 1=1 --", "admin'--", "\" OR \"1\"=\"1"],
)
```

**CLUSTER BOMB** — multiple insertion points, all combinations:
```python
results = provider.automate_cluster_bomb(
    request_id="req_abc123",
    payload_sets=[
        ["admin", "user", "guest"],       # username field
        ["password", "admin123", "123456"], # password field
    ],
)
```

Each result entry includes the full request, response code, response size,
and response body — enabling the agent to detect anomalies (e.g. different
response length = injection success) without manual UI review.

### 3.4 Per-request TypeScript Hooks

The `CaseCrackPlugin` TypeScript plugin installs 8 passive detectors that
fire synchronously for every proxied request:

| ID | Detector | Severity |
|---|---|---|
| D1 | Auth header over plain HTTP | High |
| D2 | JWT in URL query string | Medium |
| D3 | Sensitive path accessed | Medium |
| D4 | HTTP 5xx cluster (≥3) | Medium |
| D5 | Parameter reflected in response | High |
| D6 | API key / secret in request header | Medium |
| D7 | Content-Type mismatch (JSON→HTML) | Low |
| D8 | CORS wildcard on credentialled request | High |

Each detector:
1. Creates a Caido Finding (visible in the web UI, linked to the request).
2. POSTs a structured `CaseCrackEvent` JSON to `http://venator:8080/api/caido-event`.

This means the agent receives passive findings in near-real-time without
polling, and all findings are visible in both the Caido UI and the CaseCrack
dashboard simultaneously.

### 3.5 Project Isolation

Caido supports named Projects for traffic isolation. The agent can:
```python
provider = CaidoProvider(project_name="target-acme-corp")
provider.run("https://acme.example.com")
```

Each target scan gets its own Caido project, preventing history cross-contamination
between concurrent scans — important for multi-target agent workflows.

---

## 4. Caido vs Existing Tools

### 4.1 Caido vs Burp Suite Enterprise

Burp Enterprise is the CaseCrack primary scanner — it performs deep
active scanning (SQLi, XSS, etc.) against targets. Caido complements
this by providing:

- **Faster replay** — Burp's Repeater is UI-only; Caido Replay is API-first.
- **Richer fuzzing API** — Burp Intruder has limited automation API; Caido
  Automate is fully programmatic.
- **Plugin SDK** — Caido has a first-class TS plugin system; Burp's BApp API
  is JVM-only and much heavier.
- **HTTPQL** — Burp has no equivalent structured query language for history.
- **Low memory** — Caido is ~30 MB Rust; Burp Enterprise is a 1–4 GB JVM process.

**Not a replacement** — Caido has no active scanner, no vulnerability classification
engine, no issue severity scoring, and no scan orchestration.

### 4.2 Caido vs mitmproxy

| Feature | mitmproxy | Caido |
|---|---|---|
| Language | Python addon | TypeScript plugin |
| Scripting model | Python class with method hooks | TS async function hooks |
| Fuzzing | Manual script | Automate (built-in) |
| History query | Python only | HTTPQL (structured) |
| Web UI | Basic | Modern, full-featured |
| Project isolation | No | Yes |
| API | REST | GraphQL |
| Community | Large, mature | Growing |

**Decision rule**: mitmproxy is used for complex Python-driven flow
manipulation and script-heavy attacks. Caido is used for interactive
analysis, structured history querying, and rapid replay/fuzzing.

---

## 5. Integration Points

### 5.1 Python Layer

| File | Purpose |
|---|---|
| `tools/burp_enterprise/integrations/caido_graphql_client.py` | Full GraphQL client — authentication, history, replay, automate, findings, scope, projects |
| `tools/burp_enterprise/tool_wrappers/caido_provider.py` | `DockerToolProvider` subclass — `run()`, `replay()`, `automate_sniper()`, `automate_cluster_bomb()`, `search_history()`, passive heuristics |

### 5.2 TypeScript Layer

| File | Purpose |
|---|---|
| `mcp-extension/caido-casecrack-plugin/src/index.ts` | Plugin — D1–D8 detectors, Caido Finding creation, CaseCrack webhook forwarding |
| `mcp-extension/caido-casecrack-plugin/manifest.json` | Plugin manifest (Caido plugin registry format) |
| `mcp-extension/caido-casecrack-plugin/package.json` | npm deps: `@caido/sdk-backend` |

### 5.3 Infrastructure

| File | Purpose |
|---|---|
| `docker-compose.yml` | `caido` service — ports 8282 (proxy), 8283 (API), `secnet` bridge, healthcheck |

### 5.4 EventBus Integration

The TypeScript plugin posts to `http://venator:8080/api/caido-event`.
CaseCrack must expose this endpoint and convert the payload into an
`EventBus.emit(BusEventType.FINDING_ADDED, ...)` call.  Recommended
receiver location: `tools/burp_enterprise/api/caido_event_receiver.py`
(thin FastAPI/Flask route that accepts the JSON and fires the bus).

---

## 6. Deployment

### 6.1 Quick Start

```bash
# Start all services including Caido
docker compose up -d caido

# Verify Caido is healthy
curl http://localhost:8283/health

# Run scan routing traffic through Caido
python -m casecrack scan --target https://example.com \
  --proxy http://localhost:8282
```

### 6.2 CI / No-Auth Mode

```bash
# .env or docker-compose override
CAIDO_NO_AUTH=true docker compose up -d caido
```

### 6.3 Plugin Installation

```bash
cd mcp-extension/caido-casecrack-plugin
npm install
npm run build
# Then in Caido UI: Extensions → Install from file → select dist/index.js
# Or use caido-cli: caido-cli plugin install --path dist/
```

### 6.4 Environment Variables

| Variable | Default | Description |
|---|---|---|
| `CAIDO_NO_AUTH` | `false` | Skip authentication (dev/CI) |
| `CASECRACK_WEBHOOK_URL` | `http://venator:8080/api/caido-event` | Where the plugin posts events |
| `CAIDO_LISTEN_ADDR` | `0.0.0.0:8080` | Proxy listener address |
| `CAIDO_API_ADDR` | `0.0.0.0:8443` | GraphQL API listener |

---

## 7. Security Considerations

1. **TLS verification**: The GraphQL client defaults to `verify_tls=False`
   for Docker-internal communication. Enable TLS verification for any
   non-localhost deployment.

2. **Auth token storage**: PAT tokens must be stored in environment
   variables or the CaseCrack secrets vault — never hardcoded.

3. **Webhook endpoint**: `POST /api/caido-event` should validate that
   the source IP is within the `secnet` subnet (Docker-internal) to
   prevent external event injection.

4. **Plugin code signing**: Caido supports plugin signing. Production
   deployments should sign the `dist/index.js` artifact.

5. **`CAIDO_NO_AUTH=true`**: Must never be set in production — only for
   local dev and CI pipelines behind a firewall.

---

## 8. Roadmap

| Priority | Item |
|---|---|
| P1 | Implement `POST /api/caido-event` receiver in CaseCrack API layer |
| P1 | Wire `CaidoProvider` into the main scan phase registry |
| P2 | Add `automate_sniper` results to ToolResult SARIF conversion |
| P2 | Add Match-and-Replace rule management to `CaidoGraphQLClient` |
| P3 | Implement `automate_pitchfork` strategy (parallel payload injection) |
| P3 | Build Caido panel in CaseCrack dashboard (embedded UI via iframe) |
| P3 | Add HTTPQL query builder helper for common security test patterns |
| P4 | Sign plugin artifact in CI pipeline |
| P4 | Caido project auto-archiving after scan completion |
