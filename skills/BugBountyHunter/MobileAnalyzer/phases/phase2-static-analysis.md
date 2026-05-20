## Phase 2: Static Analysis

### MobSF Automated Static Analysis (Run First)

MobSF (Mobile Security Framework, v4.x as of 2026) is the automated static analysis
foundation — run it as the **first action** on every APK/IPA. It surfaces exported
components, insecure permissions, hardcoded secrets, tracker SDKs, and API endpoint
candidates in structured JSON in minutes. JADX/apktool deep-dives are then focused
exclusively on items MobSF flags HIGH+, not the full codebase.

```bash
# Start MobSF (Docker recommended)
docker run -it --rm -p 8000:8000 \
  opensecurity/mobile-security-framework-mobsf:latest
# Or local install: pip install mobsf && mobsf

# Upload, scan, and export JSON report via REST API
APIKEY=$(curl -s http://localhost:8000/api/v1/api_docs \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('api_key','REST_API_KEY'))")
HASH=$(curl -s -F "file=@target.apk" -H "Authorization: ${APIKEY}" \
         http://localhost:8000/api/v1/upload \
         | python3 -c "import sys,json; print(json.load(sys.stdin)['hash'])")
curl -s -X POST -d "hash=${HASH}" -H "Authorization: ${APIKEY}" \
     http://localhost:8000/api/v1/scan
curl -s -X POST -d "hash=${HASH}" -H "Authorization: ${APIKEY}" \
     http://localhost:8000/api/v1/report_json -o mobsf-report.json
```

**Parse MobSF output for agent triage routing:**

```python
import json

with open("mobsf-report.json") as f:
    report = json.load(f)

# High-signal fields to extract immediately
high_issues   = [i for i in report.get("android_api", [])
                 if i.get("severity") in ("high", "critical")]
exported_acts = report.get("exported_activities", [])
exported_prov = report.get("exported_providers", [])
hardcoded     = report.get("secrets", [])          # MobSF regex-based secret detection
api_urls      = report.get("urls", [])              # API endpoint candidates
tracker_sdks  = report.get("trackers", {}).get("trackers", [])
native_libs   = report.get("binary_analysis", {})   # Vulnerable .so CVE hits

# Routing rule: JADX deep-dive only on components flagged HIGH+ by MobSF
jadx_targets = (
    [c["name"] for c in exported_acts] +
    [i.get("title", "") for i in high_issues])
```

> **Workflow contract:** MobSF low/medium issues flow directly into `mobile-findings.json`
> (`vuln_source: mobsf`). Only HIGH+ items enter the JADX deep-dive queue. MobSF also
> surfaces native library CVEs via `binary_analysis` — ingest those without re-scanning.
> Do NOT repeat MobSF checks manually on items it already covers.

---

### Android Manifest Analysis

```xml
<!-- Priority analysis targets in AndroidManifest.xml -->

<!-- 1. EXPORTED ACTIVITIES — accessible to external apps -->
<activity android:name=".DeepLinkActivity"
          android:exported="true">
  <intent-filter>
    <action android:name="android.intent.action.VIEW"/>
    <data android:scheme="example" android:host="open"/>
  </intent-filter>
</activity>

<!-- 2. EXPORTED CONTENT PROVIDERS — data exposure risk -->
<provider android:name=".UserDataProvider"
          android:exported="true"
          android:authorities="com.example.provider"
          android:readPermission="..."/>
<!-- If no permission: CRITICAL — any app can read provider data -->

<!-- 3. EXPORTED BROADCAST RECEIVERS -->
<receiver android:name=".UpdateReceiver"
          android:exported="true"/>
<!-- Can receive crafted broadcasts from malicious apps -->

<!-- 4. BACKUP ENABLED -->
android:allowBackup="true"
<!-- Device backup includes app data, credential stores -->
```

### Manifest Analysis Checklist

- [ ] List all exported activities → each is a potential deep link/intent attack surface
- [ ] List all exported content providers → check for missing permission attributes
- [ ] List all exported broadcast receivers → check for injection via ACTION data
- [ ] Check `android:allowBackup="true"` → backup data extraction attack
- [ ] Check `android:debuggable="true"` → should NOT be present in prod
- [ ] Check `android:usesCleartextTraffic="true"` → HTTP allowed, intercept easier
- [ ] Check network security config (`res/xml/network_security_config.xml`)
- [ ] Find custom URL schemes (`android:scheme`) → enumerate all deep link entry points

### iOS Info.plist Analysis

```xml
<!-- Priority analysis targets in Info.plist -->

<!-- 1. URL SCHEMES — custom deep link handlers -->
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleURLSchemes</key>
    <array>
      <string>example</string>  <!-- handles example:// URIs -->
    </array>
  </dict>
</array>

<!-- 2. UNIVERSAL LINKS — HTTPS deep links -->
<key>com.apple.developer.associated-domains</key>
<array>
  <string>applinks:example.com</string>
</array>
<!-- apple-app-site-association file at https://example.com/.well-known/apple-app-site-association -->

<!-- 3. TRANSPORT SECURITY EXCEPTIONS -->
<key>NSAppTransportSecurity</key>
<dict>
  <key>NSAllowsArbitraryLoads</key>
  <true/>  <!-- ALL HTTP traffic allowed — cert pinning bypass easier -->
</dict>

<!-- 4. QUERIED URL SCHEMES — apps this app probes -->
<key>LSApplicationQueriesSchemes</key>
```

### Hardcoded Secret Extraction

```python
# Scan decompiled Java/Kotlin code for hardcoded values
SECRET_PATTERNS = [
    r'(?i)(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token)'
     r'\s*[=:]\s*["\']([A-Za-z0-9+/=_\-]{20,})["\']',
    r'(?i)(client[_-]?secret|client[_-]?id)\s*[=:]\s*["\']([^"\']{10,})["\']',
    r'(?i)(aws[_-]?key|aws[_-]?secret)\s*[=:]\s*["\']([A-Z0-9]{20,})["\']',
    r'BEGIN (RSA|EC|OPENSSH) PRIVATE KEY',
    r'(?i)(firebase[_-]?api[_-]?key)\s*[=:]\s*["\']([A-Za-z0-9_-]{39})["\']',
    r'AIza[0-9A-Za-z_\-]{35}',  # Google API key
    r'sk[-_](live|test)_[0-9a-zA-Z]{24,}',  # Stripe
]

# Scan across all .java, .kt, .js (React Native), and .swift files
# Also check res/values/strings.xml and assets/*.json
```

### Framework-Specific Analysis

```yaml
framework_analysis:
  react_native:
    targets:
      - "assets/index.android.bundle  # WARNING: may be Hermes .hbc bytecode (default in RN 0.64+)"
      - assets/index.ios.bundle
    checks:
      - "STEP 1: Detect format — run `file assets/index.android.bundle` (see Hermes section below)"
      - "STEP 2a (Hermes .hbc): pip install hermes-dec; hbc-decompile bundle > bundle-decompiled.js"
      - "STEP 2b (plain JS): npx prettier / js-beautify for minified bundles"
      - Search decompiled/beautified output for hardcoded API keys and client_secret values
      - Find all API endpoint URL constants (fetch, axios, XHR, WebSocket calls)
      - Trace Redux action creators for data model and privilege structure intelligence
      - Find NativeModule bridge definitions — each exposed method is an attack surface boundary

  flutter:
    targets:
      - assets/flutter_assets/
      - libflutter.so or App.framework
    checks:
      - Extract Dart code using reFlutter or blutter
      - Find API endpoints in Dart VM snapshot
      - Look for hardcoded AWS/Firebase config

  cordova_ionic:
    targets:
      - www/js/*.js (may be minified/obfuscated)
    checks:
      - Unminify using beautify-js
      - Find WebView-to-native bridge calls
      - Check for insecure local HTML storage
```

### Hermes Bytecode Detection & Decompilation

Hermes is the default JS engine in React Native since v0.64 (2021), covering the vast
majority of RN apps in 2025+. When an app ships Hermes, `assets/index.android.bundle`
is a binary `.hbc` file — not readable JS. Beautify-js, grep, and eslint fail silently.
Use **hermes-dec** (P1Sec; referenced in OWASP MASTG) for disassembly and pseudo-JS
decompilation before any secret hunting or endpoint extraction.

```bash
# Step 1: Identify file type (do this before ANY bundle analysis)
file assets/index.android.bundle
# → "Hermes JavaScript bytecode, version 96" → binary .hbc path
# → "ASCII text" or "data"                   → plain JS or Metro-bundled path

# Step 2a: Hermes disassembly + pseudo-JS decompilation
pip install hermes-dec
hbc-disassemble assets/index.android.bundle > bundle.hasm      # raw bytecode listing
hbc-decompile   assets/index.android.bundle > bundle-decompiled.js  # pseudo-JS output

# Step 2b: Plain JS unminify (fallback for older RN or custom Babel builds)
npx prettier --write assets/index.android.bundle
# OR: npx js-beautify -o bundle-beautified.js assets/index.android.bundle

# Step 3: Search for secrets and endpoints (works on both decompiled outputs)
grep -E '(api[_-]?key|client[_-]?secret|Bearer|apiSecret)' bundle-decompiled.js
grep -oE 'https?://[^"'\''\s]+' bundle-decompiled.js | sort -u > api-endpoints.txt
```

### Dependency & Supply-Chain Scanning

Vulnerable third-party libraries are a reliable finding class — MobSF `binary_analysis`
covers many .so CVEs automatically. Supplement with explicit dependency checks:

```bash
# Android: Gradle dependency tree (from decompiled build.gradle or extracted from APK)
grep -E '(implementation|api)\s+["\x27]' build.gradle | sort > gradle-deps.txt

# iOS: Podfile.lock ships inside IPA (Payload/App.app/) in some builds
find ./ipa-contents/ -name "Podfile.lock" | xargs cat | grep -E '^  [A-Za-z]' > pods.txt

# React Native: package.json embedded in APK assets
find . -name "package.json" | head -3 | xargs python3 -c "
import sys, json
for path in sys.argv[1:]:
    try:
        d = json.load(open(path))
        for pkg, ver in {**d.get('dependencies',{}), **d.get('devDependencies',{})}.items():
            print(f'{pkg}@{ver}')
    except: pass
" > rn-deps.txt

# Cross-reference against OSV/NVD (or pipe through osv-scanner if available)
osv-scanner --lockfile=Podfile.lock 2>/dev/null || true
osv-scanner --lockfile=build.gradle 2>/dev/null || true
```

### Native Code (.so / JNI) Analysis

```bash
# List native libraries bundled in APK
unzip -l target.apk "*.so" | awk '{print $NF}'

# Quick wins via strings analysis (keys, URLs, debug markers)
strings lib/arm64-v8a/libnative.so \
  | grep -E '(https?://|api[_-]?key|token|secret|password|BEGIN PRIVATE)' | head -50

# Frida: trace all JNI library loads at runtime
Java.perform(function() {
    var System = Java.use("java.lang.System");
    System.loadLibrary.implementation = function(lib) {
        console.log("[JNI] loadLibrary: " + lib);
        return System.loadLibrary(lib);
    };
});

# Deep analysis with Ghidra (batch headless)
analyzeHeadless /project MobileProject \
    -import lib/arm64-v8a/libnative.so \
    -postScript ExtractStrings.java \
    -scriptPath /ghidra_scripts/

# Flutter: libapp.so contains Dart AOT — use blutter for decompilation
# https://github.com/worawit/blutter
blutter libapp.so arm64 output/
```

