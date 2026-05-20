#!/usr/bin/env python3
"""Repair the broken test_login_bruteforce method in account.py."""
import pathlib

path = pathlib.Path('CaseCrack/tools/burp_enterprise/session_auth/account.py')
text = path.read_text()

# ---- Region 1: replace the broken for-loop section ----
broken1_start = (
    '        for i in range(max_attempts):\n'
    '               successful_attempts = 0\n'
    '               connection_errors = 0\n'
    '               for i in range(max_attempts):\n'
    '                   password = f"wrong_password_{i}"'
)
broken1_end_marker = '            successful_attempts = 0  # noqa: unreachable (kept for symmetry)\n\n'

fixed1 = (
    '        successful_attempts = 0\n'
    '        connection_errors = 0\n'
    '\n'
    '        for i in range(max_attempts):\n'
    '            password = f"wrong_password_{i}"\n'
    '\n'
    '            try:\n'
    '                response = self.client.request(\n'
    '                    method="POST",\n'
    '                    url=login_url,\n'
    '                    headers=headers or {},\n'
    '                    data={username_param: username, password_param: password},\n'
    '                )\n'
    '                successful_attempts += 1\n'
    '\n'
    '                # Check for lockout\n'
    '                if response.status_code == 429:\n'
    '                    rate_limiting = True\n'
    '                    lockout_threshold = i + 1\n'
    '                    break\n'
    '\n'
    '                response_text = response.text.lower()\n'
    '\n'
    '                if any(\n'
    '                    phrase in response_text\n'
    '                    for phrase in [\n'
    '                        "locked",\n'
    '                        "too many attempts",\n'
    '                        "temporarily disabled",\n'
    '                        "try again later",\n'
    '                        "account suspended",\n'
    '                    ]\n'
    '                ):\n'
    '                    lockout_enabled = True\n'
    '                    lockout_threshold = i + 1\n'
    '                    break\n'
    '\n'
    '                if "captcha" in response_text or "recaptcha" in response_text:\n'
    '                    captcha_present = True\n'
    '                    lockout_threshold = i + 1\n'
    '                    break\n'
    '\n'
    '            except ConnectionError as e:\n'
    '                # Proxy or network unavailable -- abort to prevent false positive.\n'
    '                # If no requests reach the server we cannot conclude absence of\n'
    '                # brute-force protection (CWE-390 fix).\n'
    '                connection_errors += 1\n'
    '                logger.warning(\n'
    '                    "Brute force test attempt %d failed (connection error): %s",\n'
    '                    i + 1, e,\n'
    '                )\n'
    '                if connection_errors >= 3:\n'
    '                    logger.error(\n'
    '                        "Brute force test aborted: %d consecutive connection errors. "\n'
    '                        "Ensure Burp proxy is running. No finding generated.",\n'
    '                        connection_errors,\n'
    '                    )\n'
    '                    return BruteForceResult(\n'
    '                        lockout_enabled=False,\n'
    '                        lockout_threshold=None,\n'
    '                        lockout_duration=None,\n'
    '                        rate_limiting=False,\n'
    '                        captcha_present=False,\n'
    '                        vulnerabilities=[],\n'
    '                    )\n'
    '            except Exception as e:\n'
    '                logger.debug(f"Brute force test {i} failed: {e}")\n'
    '\n'
    '            time.sleep(0.1)  # Small delay\n'
    '\n'
    '        # Only flag missing protection when at least one request reached the\n'
    '        # server.  Zero successful_attempts means proxy was down -- no finding.\n'
    '        if successful_attempts == 0:\n'
    '            logger.warning(\n'
    '                "Brute force test: 0 requests reached the server -- "\n'
    '                "no finding generated (check proxy connection)."\n'
    '            )\n'
    '            return BruteForceResult(\n'
    '                lockout_enabled=False,\n'
    '                lockout_threshold=None,\n'
    '                lockout_duration=None,\n'
    '                rate_limiting=False,\n'
    '                captcha_present=False,\n'
    '                vulnerabilities=[],\n'
    '            )\n'
    '\n'
    '        # No protection detected across requests that reached the server\n'
    '        if not lockout_enabled and not rate_limiting and not captcha_present:\n'
    '            vulnerabilities.append(\n'
    '                AccountSecurityFinding(\n'
    '                    severity=SeverityLevel.HIGH,\n'
    '                    vulnerability_type=VulnerabilityType.BRUTE_FORCE,\n'
    '                    title="No Brute Force Protection on Login",\n'
    '                    description="Login endpoint lacks rate limiting or account lockout",\n'
    '                    url=login_url,\n'
    '                    evidence=(\n'
    '                        f"Completed {successful_attempts}/{max_attempts} failed attempts "\n'
    '                        f"without triggering lockout, rate limiting, or CAPTCHA"\n'
    '                    ),\n'
    '                    steps_to_reproduce=[\n'
    '                        f"Send {max_attempts} login requests with wrong passwords",\n'
    '                        "No lockout, rate limiting, or CAPTCHA triggered",\n'
    '                    ],\n'
    '                    impact="Attacker can brute force passwords without restriction",\n'
    '                    recommendation="Implement account lockout, rate limiting, and CAPTCHA",\n'
    '                    cwe_id="CWE-307",\n'
    '                )\n'
    '            )\n'
    '\n'
    '        return BruteForceResult(\n'
    '            lockout_enabled=lockout_enabled,\n'
    '            lockout_threshold=lockout_threshold,\n'
    '            lockout_duration=None,  # Would need to test recovery\n'
    '            rate_limiting=rate_limiting,\n'
    '            captcha_present=captcha_present,\n'
    '            vulnerabilities=vulnerabilities,\n'
    '        )\n'
    '\n'
)

pos1s = text.find(broken1_start)
pos1e = text.find(broken1_end_marker, pos1s) + len(broken1_end_marker)
assert pos1s >= 0, 'Region 1 start not found'
assert pos1e > pos1s, 'Region 1 end not found'
print(f'Region 1: chars {pos1s}-{pos1e}')

new_text = text[:pos1s] + fixed1 + text[pos1e:]

# ---- Region 2: stray lines in test_password_policy ----
broken2 = (
    '                        successful_attempts = 0\n'
    '                        connection_errors = 0\n'
    '        findings = []'
)
fixed2 = '        findings = []'
if broken2 in new_text:
    new_text = new_text.replace(broken2, fixed2, 1)
    print('Region 2 fixed')
else:
    print('Region 2 not found (already clean)')

path.write_text(new_text, encoding='utf-8')
print(f'File written: {len(new_text)} chars')

# Verify syntax
import ast
try:
    ast.parse(new_text)
    print('Syntax OK')
except SyntaxError as e:
    print(f'SYNTAX ERROR: {e}')
