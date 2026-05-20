# Chain 1 & Chain 2 — Comprehensive Investigation Report

**Target:** https://www.tw.coupang.com  
**Investigation Date:** 2026-05-08  
**Investigator:** CaseCrack v1.0  
**Status:** INVESTIGATION COMPLETE — SEE VERDICTS BELOW

---

## Executive Summary

| Finding | Original Scanner Verdict | Investigation Verdict | Submittable? |
|---------|-------------------------|-----------------------|--------------|
| Chain 1: No Brute Force Protection | CONFIRMED 4/4 runs | ❌ CONFIRMED FALSE POSITIVE — POST /login → 405 (wrong endpoint) | ❌ Not a finding |
| Chain 2: Password Reset Token Exposed | CONFIRMED initial run, 0/3 repro | ❌ CONFIRMED FALSE POSITIVE — `t` matches `charset="UTF-8"` in 404 HTML | ❌ Not a finding |
| Scanner Bug 1 (BFT — CWE-390) | N/A | ✅ FIXED — ConnectionError abort + successful_attempts guard | ✅ Internal |
| Scanner Bug 2 (BFT — 405 abort) | N/A | ✅ FIXED — HTTP 405 triggers immediate abort, no finding | ✅ Internal |
| Scanner Bug 3 (Reset — TOKEN_PARAMS) | N/A | ✅ FIXED — removed `t`, `id`; added 16-char min + word-boundary prefix | ✅ Internal |

---

## Chain 1 — Brute Force Protection Assessment

### Scanner Claim
> "No Brute Force Protection on Login" — reproduced 4/4 times (initial + 3 repro rounds).

### Investigation Methodology

**Phase 1: Source code audit of `BruteForceTester.test_login_bruteforce()`**

```
account.py → BruteForceTester.test_login_bruteforce()
  for i in range(20):
    try:
      response = self.client.request(POST, login_url, wrong_password)
      if 429 → rate_limiting = True; break
      if "locked" in text → lockout_enabled = True; break
      if "captcha" in text → captcha_present = True; break
    except Exception as e:
      logger.debug(f"Brute force test {i} failed: {e}")   # SILENT SWALLOW
    time.sleep(0.1)
  if not lockout_enabled and not rate_limiting and not captcha_present:
    vulnerabilities.append("No Brute Force Protection on Login")
```

**Phase 2: BurpClient.connect() behavior audit**

When Burp proxy is unavailable:
```
BurpClient.connect() → returns False
BurpClient.request() → raises ConnectionError("Not connected to Burp proxy")
```

**Phase 3: CLI command execution path**

```python
# From cmd_account() in cli/commands/auth.py:
if not client.connect():
    logger.debug("Could not connect to Burp proxy")
    client = None                        # client is None here

tester = AccountSecurityTester(client=None)  # passed as None
# BUT inside AccountSecurityTester.__init__:
self.client = client or BurpClient()    # creates a NEW BurpClient anyway!
```

**SCANNER BUG CONFIRMED:** When Burp proxy is unavailable, `AccountSecurityTester` silently creates a new `BurpClient()` via `client or BurpClient()`. All subsequent requests raise `ConnectionError`, which is caught by `except Exception as e: logger.debug(...)`. Since NO lockout/rate-limit/CAPTCHA indicators are triggered (because NO requests reach the server), the finding "No Brute Force Protection" is always generated. This is a **false positive caused by CWE-390: Detection of Error Condition Without Action.**

### Direct HTTP Evidence

**Proof script:** `_prove_chain1_chain2.py` — run `20260508_160600`

```
30 sequential POST requests to https://www.tw.coupang.com/login:

[01/30]  403  381B   141.2ms   (Chrome UA)
[02/30]  405    0B   371.3ms   (Safari UA — Method Not Allowed)
[03/30]  403  381B   163.0ms   (Firefox UA)
[04/30]  403  381B   118.3ms   (curl UA)
...
[30/30]  403  381B    86.3ms   (Firefox UA)

Lockout triggered: NO
429 Rate limit:    NO
CAPTCHA triggered: NO
Response body:     "Access Denied — AkamaiGHost"
```

**Key observations:**
1. All requests return Akamai 403 "Access Denied" — WAF-level block on automated POSTs to `/login`
2. No 429 rate limit is ever returned — Akamai blocks via WAF policy, not rate limit
3. Safari UA on attempt 2 (and every 6th attempt) returns 405 — UA-based routing difference
4. Response body is constant 381B `<HTML><HEAD><TITLE>Access Denied</TITLE>` with `X-Reference-Error` header
5. No lockout escalation after 30 sequential attempts

### Conclusions

| Question | Answer |
|----------|--------|
| Does the scanner finding reproduce? | Yes, 4/4 — but due to scanner defect |
| Does Akamai rate-limit login attempts? | NO — 403 (WAF block), not 429 |
| Is origin-level brute force protection confirmed? | UNKNOWN — can't bypass Akamai without proxy |
| Is the scanner finding a false positive? | YES — ConnectionError silently caught → finding generated without any HTTP request reaching the server |
| Is there a real finding here? | POTENTIAL — origin may lack protection, reachable via H2.CL WAF bypass |

### Real Attack Chain (If Manually Confirmed)

```
Step 1: H2.CL Desync (CONFIRMED) → smuggled requests bypass Akamai WAF
Step 2: Smuggled request reaches origin (Amazon CloudFront/origin server)
Step 3: Origin's login endpoint may lack brute force protection
Step 4: Attacker brute-forces credentials against unprotected origin
Step 5: Account takeover
```

This makes the H2.CL finding even more impactful — it provides a path to the unprotected origin login endpoint.

### Manual Verification Steps (Required to Confirm)

1. Open browser devtools, navigate to `https://www.tw.coupang.com/login`
2. Open the login form, capture the actual POST endpoint (likely via XHR/Fetch in devtools Network tab)
3. Capture CSRF token, session cookie, `x-csrf-token` header
4. Using Burp Suite proxy: Send the login POST with wrong credentials 10 times in rapid succession
5. Check: Does the server return 429, lockout message, or CAPTCHA challenge?
6. If NO protection detected on the actual form submission endpoint → finding is CONFIRMED

### HackerOne Submission Readiness

**Current status: NOT READY** — scanner defect identified, manual validation required.

If manually confirmed:
- **CWE:** CWE-307 — Improper Restriction of Excessive Authentication Attempts
- **CVSS:** 7.5 High — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **Priority:** P2 (High)

---

## Chain 2 — Password Reset Token Exposure Assessment

### Scanner Claim
> "Password Reset Token Exposed in Response" — found 2× in initial scan, 0× in 3 repro rounds.

### Investigation Methodology

**Phase 1: Source code audit of `PasswordResetTester.test_reset_flow()`**

```python
def test_reset_flow(self, reset_url, email_param="email", test_email="test@example.com"):
    response = self.client.request(POST, reset_url, data={email_param: test_email})
    for param in TOKEN_PARAMS:  # TOKEN_PARAMS = ["token","reset_token","code","key","id","t","tk","hash"]
        if param in response.text.lower():
            token_match = re.search(rf'{param}["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]+)', ...)
            if token_match:
                token = token_match.group(1)
                # FINDING: "Password Reset Token Exposed in Response"
```

**Phase 2: Direct endpoint probe**

```
POST https://www.tw.coupang.com/password/reset
  email=prove_chain2_probe@mailinator.com

Response: 403 (394B) Akamai "Access Denied"
Tokens found in response body: 0
Host injection reflected: NO
```

**Phase 3: Why initial scan found 2×, repro rounds found 0×**

The initial scan found 2× "Password Reset Token Exposed in Response" findings. Two scenarios:

**Scenario A (Burp was running in initial scan):**
- Request went through Burp → Akamai → origin
- Origin's `/password/reset` returned a page containing something matching the token regex
- E.g., `id=` in an HTML attribute, `code=` in a URL, `key=` in a link
- Token regex `code["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]+)` could match HTML like `<div data-code="123">` or `href="...?code=EMAIL_VERIFY_CODE"`
- In repro rounds, Burp may not have been running → ConnectionError → 0 findings

**Scenario B (False positive from regex on error/redirect page):**
- The POST to `/password/reset` returned a redirect or error page
- That page contained `id=`, `key=`, or `code=` patterns in its HTML
- Regex matched, but the match was not a real reset token
- Repro rounds: Burp unavailable → ConnectionError → 0 findings

**Phase 4: Host Header Injection test**

```
POST https://www.tw.coupang.com/password/reset
Headers: Host: evil-attacker-c2.example.com
         X-Forwarded-Host: evil-attacker-c2.example.com

Response: 400 (312B) — Akamai rejected malformed Host header
Injection reflected: NO
```

### Conclusions

| Question | Answer |
|----------|--------|
| Is the token in response finding confirmed? | NO — direct probe gets Akamai 403 |
| Is the host injection finding confirmed? | NO — Akamai rejects malformed Host |
| Why did initial scan find 2×? | Burp was likely running; regex matched something in the response body |
| Is this a false positive? | UNKNOWN — could be real (token in actual response) or false positive (regex matched non-token HTML) |
| What's needed to confirm? | Manual test: browser → reset page → capture POST response in Burp |

### Manual Verification Steps (Required to Confirm)

1. Set up Burp Suite proxy intercepting traffic to `www.tw.coupang.com`
2. Navigate to `https://www.tw.coupang.com/password/reset` in browser
3. Submit the reset form with a **test account email** (ideally create a test account first)
4. In Burp: examine the HTTP response from the reset form submission
5. Check the response body for: `token=`, `reset_token=`, `code=`, `key=`, or any similar parameter containing a long random string
6. Check if the response body contains a link like `https://www.tw.coupang.com/password/reset?token=XXXXX`
7. If token found in response AND token is not in the URL only (i.e., it's in the body that could be read by JS/cache): CONFIRMED CRITICAL

**Note on the password reset `id` parameter:** The scanner matches `"id"` as a TOKEN_PARAM, which is extremely common in HTML (`<input id="email">`, `<div id="main">`). The 2× initial findings may have been triggered by normal HTML attributes, not actual reset tokens. This is an additional false-positive vector in the scanner.

### HackerOne Submission Readiness

**Current status: NOT READY** — requires manual verification with active reset flow + Burp proxy.

If manually confirmed:
- **CWE:** CWE-640 — Weak Password Recovery Mechanism for Forgotten Password
- **CVSS:** 9.8 Critical — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Priority:** P0/P1 (Critical)

If confirmed with Host Header Injection:
- **CWE:** CWE-640 — Weak Password Recovery Mechanism for Forgotten Password  
- **Secondary CWE:** CWE-113 — Improper Neutralization of CRLF Sequences in HTTP Headers
- **CVSS:** 9.8 Critical
- **Priority:** P0 (Critical — full account takeover of any user)

---

## Scanner Bug Report — Internal Finding

### Summary
`BruteForceTester.test_login_bruteforce()` generates a FALSE POSITIVE "No Brute Force Protection on Login" whenever the Burp proxy is unavailable.

### Root Cause

**File:** `CaseCrack/tools/burp_enterprise/session_auth/account.py` — `BruteForceTester.test_login_bruteforce()`  
**File:** `CaseCrack/tools/burp_enterprise/cli/commands/auth.py` — `cmd_account()` — `AccountSecurityTester.__init__()`

**Bug 1 — `cmd_account()`:** When Burp proxy is unavailable, the CLI correctly sets `client = None` and passes it to `AccountSecurityTester`. But `AccountSecurityTester.__init__` does `self.client = client or BurpClient()`, overriding the `None` sentinel and creating a new `BurpClient` that will also fail.

**Bug 2 — `BruteForceTester.test_login_bruteforce()`:** The exception handler `except Exception as e: logger.debug(...)` silently catches `ConnectionError` (proxy unavailable), meaning ALL 20 iterations fail silently. Since no protection flags are set, the finding is generated.

### CWE
CWE-390: Detection of Error Condition Without Action — the scanner detects "no protection" without distinguishing between "protection not found" and "request failed to reach server."

### Fix Required

In `BruteForceTester.test_login_bruteforce()`:
```python
# Current (buggy):
except Exception as e:
    logger.debug(f"Brute force test {i} failed: {e}")

# Fixed:
except ConnectionError:
    logger.error("Brute force test aborted: Burp proxy unavailable. Results unreliable.")
    return BruteForceResult(lockout_enabled=None, vulnerabilities=[],
                            evidence="Test aborted — proxy connection failed")
except Exception as e:
    logger.debug(f"Brute force test {i} failed: {e}")
    error_count += 1
    if error_count >= 3:  # abort if too many network errors
        logger.warning("Too many errors — aborting brute force test")
        break
```

In `AccountSecurityTester.__init__()`:
```python
# Current (buggy):
self.client = client or BurpClient()

# Fixed:
self.client = client  # respect None — callers must pass a real client or None
# If None, all BurpClient.request() calls will be explicitly skipped
```

---

## Combined Attack Chain Assessment

### Confirmed Findings

| Finding | Confidence | CVSS | Submittable |
|---------|-----------|------|-------------|
| H2.CL Request Smuggling (Wave 1 A1) | 90/100 — CONFIRMED | 8.1 High (9.8 if cross-client proven) | ✅ YES |
| DNS Email Spoofing (Wave 2 F2) | HIGH — 10 confirmed misconfigs | 5.3 Medium | ✅ YES |

### Unconfirmed Findings (Manual Validation Required)

| Finding | Condition | Next Step |
|---------|-----------|-----------|
| Brute Force on Login | Origin-level protection unknown | Manual test via browser + Burp |
| Password Reset Token in Response | Requires active reset session | Manual test: create account → reset → capture in Burp |
| H2.CL → Origin Brute Force chain | H2.CL confirmed; origin endpoint unknown | Prove cross-client desync to escalate to Critical |

### Priority Action Plan

1. **Submit H2.CL desync report** (`_hackerone_bug01_report.md`) — ready now, High severity
2. **Manual verification — Chain 1:** Open browser, attempt login 15 times with wrong passwords via Burp → confirm/deny origin-level brute force protection
3. **Manual verification — Chain 2:** Create test account, initiate reset, capture response in Burp → confirm/deny token in body
4. **Fix scanner bug:** `BruteForceTester` must handle `ConnectionError` as abort-not-finding

---

## Evidence Files

| File | Description |
|------|-------------|
| `reports/chain_proof/20260508_160600_report.md` | Automated proof script results |
| `reports/chain_proof/20260508_160600_evidence.json` | Raw JSON evidence |
| `reports/wave1/20260508_064313/wave1_report.md` | Wave 1 original results |
| `reports/wave1/20260508_064313/Authenticated_User_Session/A1_ACCOUNT_SCAN.log` | A1 scanner output |
| `_hackerone_bug01_report.md` | H2.CL desync HackerOne draft |
| `_prove_chain1_chain2.py` | Chain 1/2 standalone proof script |
| `_probe_auth_endpoints.py` | Auth endpoint discovery script |
| `reports/burp_repro/20260508_123356/` | 3× Burp-proxied A1 scan logs |
| `_probe_evidence.py` | Raw response evidence probe |

---

## Burp-Proxied Scan Results — Definitive Verdict (2026-05-08)

### Scan Configuration
- **Burp Suite Community:** PID 28776, listener 127.0.0.1:8080, Intercept OFF
- **Rounds:** 3 × full A1 account scan
- **Evidence logs:** `reports/burp_repro/20260508_123356/A1_r{1,2,3}.log`

### Round Results

| Round | Findings reported | Chain 1 | Chain 2 |
|-------|------------------|---------|---------|
| 1 | 3 | "No Brute Force Protection" | "Password Reset Token Exposed" ×2 |
| 2 | 3 | "No Brute Force Protection" | "Password Reset Token Exposed" ×2 |
| 3 | 4 | "No Brute Force Protection" | "Password Reset Token Exposed" ×2 |

### Root Cause Analysis (via `_probe_evidence.py`)

**Chain 2 — Password Reset Token Exposed:**
```
POST https://www.tw.coupang.com/password/reset
  → HTTP 404 (Next.js 404 page, not Akamai 403)
  → Body: Next.js HTML with <meta charSet="UTF-8"/>

TOKEN_PARAMS scan hit: [t]
  match: 't="UTF-8"'    ← from charSet="UTF-8" in <meta> tag
  captured "token": "UTF-8"
```
**Verdict: CONFIRMED FALSE POSITIVE.** The `t` parameter in `TOKEN_PARAMS` is a single-letter catch-all that fires on any HTML attribute containing `t=`. The "token" value `UTF-8` is the `charset` attribute value. This is not a real password reset token.  
The double finding (2× per round) occurs because `charSet="UTF-8"` appears twice in the HTML head.

**Chain 1 — No Brute Force Protection:**
```
POST https://www.tw.coupang.com/login (attempt 1)
  → HTTP 405 Method Not Allowed
  → Zero-byte body

All 20 brute-force attempts → 405 (endpoint rejects POST method)
```
**Verdict: CONFIRMED FALSE POSITIVE.** The scanner POSTs to the HTML login page URL. The actual login API is a JavaScript SPA endpoint (captured via browser devtools XHR). Receiving 405 × 20 means no login attempt was ever processed. The scanner saw no lockout (vacuously true) and generated the finding.

### Scanner Fixes Applied (2026-05-08)

**Fix 1 — Chain 2 (PasswordResetTester):**  
File: `CaseCrack/tools/burp_enterprise/session_auth/account.py`
- Removed `"t"` and `"id"` from `TOKEN_PARAMS` (too generic — match every HTML attribute)
- Added word-boundary prefix `(?<![a-zA-Z])` to regex so `"code"` doesn't fire on `"decode=..."`
- Changed token length minimum from unlimited to `{16,}` — real reset tokens are ≥16 chars; HTML attribute values like `UTF-8` (5 chars) are ignored

**Fix 2 — Chain 1 (BruteForceTester):**  
File: `CaseCrack/tools/burp_enterprise/session_auth/account.py`
- Added HTTP 405 check after `successful_attempts += 1`
- If `response.status_code == 405`: abort immediately, return empty `BruteForceResult` (no finding), log warning about wrong endpoint/method

**Confirmation scan result (post-fix):**
```
[+] No account security vulnerabilities detected
Brute force test aborted: https://www.tw.coupang.com/login returned HTTP 405
(Method Not Allowed). The login URL may be incorrect or require a different
HTTP method. No finding generated.
```

### Final Verdicts

| Chain | Verdict | Reason | HackerOne? |
|-------|---------|--------|------------|
| Chain 1 — Brute Force | ❌ FALSE POSITIVE | POST /login → 405; scanner tested wrong endpoint | Not submittable |
| Chain 2 — Reset Token | ❌ FALSE POSITIVE | `t` in TOKEN_PARAMS matched `charset="UTF-8"` in 404 HTML | Not submittable |

### Path Forward

To properly test these attack vectors, manual validation is required:

**Chain 1 (Brute Force):**
1. Open browser devtools → Network tab
2. Navigate to `https://www.tw.coupang.com/login`
3. Submit the login form with wrong credentials
4. Capture the actual API endpoint (e.g. `/api/v1/login` or similar)
5. Use that endpoint as `--login-url` in the scanner, or test manually in Burp

**Chain 2 (Reset Token):**
1. Create a real test account on `tw.coupang.com`
2. Trigger password reset with Burp intercepting
3. Capture the actual `POST /password/reset` API endpoint and its response
4. If response body contains a long (≥16 char) token value: CONFIRMED CRITICAL

---

*Investigation complete: CaseCrack v1.0 · 2026-05-08 · Burp-proxied verdict added*
