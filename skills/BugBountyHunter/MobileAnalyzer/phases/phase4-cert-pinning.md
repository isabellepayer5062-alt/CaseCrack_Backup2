## Phase 4: Certificate Pinning Bypass

### Frida-Based Bypass

```javascript
// Universal SSL pinning bypass using frida-ssl-pinning-bypass
// Attach: frida -U -f com.example.app -l ssl-bypass.js

Java.perform(function() {
    // Method 1: TrustManager bypass
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function() {
        return arguments[0]; // Return untrusted chain as trusted
    };

    // Method 2: OkHttp CertificatePinner bypass
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List')
      .implementation = function() {
        return; // No-op the pin check
    };

    // Method 3: Network Security Config bypass
    var NetworkSecurityTrustManager = Java.use(
        'android.security.net.config.NetworkSecurityTrustManager'
    );
    NetworkSecurityTrustManager.checkPinning.implementation = function() {
        return; // No-op
    };
});
```

### objection Automated Bypass

```bash
# Launch app with objection
objection --gadget com.example.app explore

# Disable SSL pinning
android sslpinning disable

# Disable iOS pinning  
ios sslpinning disable

# Now route traffic through Burp
# Configure proxy: 127.0.0.1:8080 in device settings
```

### iOS Certificate Bypass

```bash
# Using objection on jailbroken device
objection --gadget "App Name" explore
ios sslpinning disable --quiet

# Using Frida script for specific iOS libraries
# TrustKit bypass, AFNetworking bypass, URLSession bypass
```

> **WKWebView note (iOS 2024+):** WKWebView ignores `NSAllowsArbitraryLoads` for TLS
> and does not expose `UIWebView`-style JS bridge attacks. Use
> `WKURLSchemeHandler` injection vectors and `WKContentWorld` for modern iOS WebView testing.
> Non-jailbroken device limitations: App Attest / DeviceCheck prevents Frida attach in
> strict-integrity apps without device compromise. Use iOS Simulator + LLDB as fallback.

### RASP, Root Detection & Obfuscation Bypass

Widely deployed in fintech, gaming, and enterprise apps. Identify and disable
tamper-detection controls **before** Frida dynamic analysis; otherwise hooks are
detected and the app terminates or changes behaviour.

**Detect RASP libraries (check MobSF `trackers` and decompiled source):**

```python
rasp_indicators_android = [
    "com.scottyab.rootbeer",      # RootBeer (most common OSS root detection)
    "com.guardsquare.dexguard",   # DexGuard (commercial RASP + obfuscator)
    "com.arxan",                  # Arxan GuardIT
    "com.licel.jscrambler",       # JSScrambler (React Native)
    "com.topjohnwu.magisk",       # Magisk path checks
    "com.noshufou.android.su",    # SuperSU binary checks
]
rasp_indicators_ios = [
    "IOSSecuritySuite",           # IOSSecuritySuite (most common OSS)
    "AmIJailbroken",              # DTTJailbreakDetection
    "fishhook",                   # Method swizzle/hook detection
]
```

**Frida bypass — root/JB detection:**

```javascript
Java.perform(function() {
    // RootBeer bypass
    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        RootBeer.isRooted.implementation = function() { return false; };
        RootBeer.isRootedWithBusyBoxCheck.implementation = function() { return false; };
    } catch(e) {}

    // Generic su/magisk file-existence bypass
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf("/su") !== -1 || path.indexOf("magisk") !== -1 ||
            path.indexOf("/sbin/.") !== -1) { return false; }
        return this.exists();
    };
});
```

**Obfuscation strategy per tool:**

| Obfuscator | Indicators | Analysis Strategy |
|-----------|-----------|------------------|
| ProGuard | Short `a/b/c` class names | JADX `--deobf` mode re-maps names |
| R8 | String encryption via static `a.a()` calls | JADX + Frida hook to intercept decrypt |
| DexGuard | DEX encryption + native loader | Dump decrypted DEX from memory post-init |
| Arxan / DashO | Native self-integrity checks, anti-Frida | Memory dump via Frida post-load |
| Flutter/Dart AOT | `.dill` snapshot, no Java classes | Use blutter / reFlutter for Dart decompile |

---

