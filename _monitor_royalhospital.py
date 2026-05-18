#!/usr/bin/env python3
"""
Real-time scan monitor — royalhospital.so full 46-phase parallel run (2026-05-07)

Captures ALL console output (stdout + stderr), flags issues/errors/bugs,
records degraded phases, and tracks cutting-edge attack chains.

Run:  python _monitor_royalhospital.py
Output: _scan_monitor_royalhospital.log   (all events)
        _scan_issues_royalhospital.txt    (issues/errors only)
        _scan_chains_royalhospital.txt    (attack chains & interesting signals)
"""

import json
import re
import sys
import time
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone

# Ensure stdout can handle arbitrary Unicode on Windows cp1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

TOKEN = "vJVYWBcadGbW5sNfOCwFCDHrN8iRPNFoRiEJbV7sUTE"
BASE  = "http://localhost:8770"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

TARGET = "https://royalhospital.so/"

LOG_FILE    = "_scan_monitor_royalhospital.log"
ISSUE_FILE  = "_scan_issues_royalhospital.txt"
CHAINS_FILE = "_scan_chains_royalhospital.txt"

# ── Issue keyword lists ────────────────────────────────────────────────────

ISSUE_KEYWORDS = [
    "traceback", "exception", "attributeerror", "typeerror",
    "valueerror", "keyerror", "importerror", "filenotfounderror",
    "oserror", "runtimeerror", "indexerror", "nameerror",
    "failed", "failure", "degraded", "crash",
    "unrecognized arguments", "no such file", "cannot", "unable to",
    "timed out", "connection refused", "connection error",
    "ssl error", "no module named", "broken pipe",
    "no cli handler", "unexpected keyword argument",
    "is not a valid", "object has no attribute",
    "got an unexpected", "missing required argument",
    "unicodedecodeerror", "recursionerror", "memorylimit",
]

ISSUE_KEYWORDS_EXACT = [
    "error", "timeout", "warning", "missing", "abort", "warn",
]

# Progress / info patterns that must NOT be flagged even when an issue keyword
# appears as a substring.
FALSE_POSITIVE_PATTERNS = [
    "[dorking]",                     # dorking progress: "0 errors | …"
    "q/s eta=",                      # eta progress
    "queries |",                     # query counter
    "cache hits (skipped)",          # normal cache
    "| 0 errors |",                  # zero-error stat
    "categories:",                   # category summary
    "error-pages:",                  # category label
    '"failure_count"',               # exploit graph JSON field
    '"last_failure_at"',             # exploit graph JSON field
    "polling for oob interactions",  # SSRF polling (informational)
    "polling for callbacks",         # OOB callback polling
    "soft-timeout",                  # normal phase flow control
    "soft limit",                    # soft-limit progress marker
    "tests queued",                  # injection test queue info
    "skipped tests",                 # skip summary (not an error)
    "42 tests queued",               # specific test-queue progress
    "skipped (6)",                   # skip count info
    "0 errors",                      # zero error count in progress
    "no errors",                     # zero errors summary
]

# ── Attack chain & interesting security patterns ───────────────────────────

CHAIN_PATTERNS = [
    # Exploit categories / severity
    "attack chain", "exploit chain", "chain:", "chain found",
    "critical", "high severity", "high confidence",
    # Injection classes
    "injection", "sqli", "sql injection", "xss", "cross-site scripting",
    "ssrf", "server-side request forgery",
    "rce", "remote code execution", "command injection", "cmdi",
    "lfi", "local file inclusion", "rfi", "remote file inclusion",
    "ssti", "template injection", "server-side template",
    "open redirect", "idor", "insecure direct object",
    "path traversal", "directory traversal",
    "xxe", "xml external entity",
    "deserialization",
    # Auth / access control
    "authentication bypass", "broken auth", "auth bypass",
    "privilege escalation", "broken access control",
    "jwt", "session fixation", "csrf",
    # Exposure
    "disclosure", "exposure", "leak", "leaked",
    "api key", "secret", "token", "password", "credential",
    "redis", "mongodb", "elasticsearch", "memcached",
    # Recon targets
    "graphql", "introspection",
    "backup file", "htaccess", "git exposed", "svn exposed",
    "debug", "admin panel", "admin interface",
    ".env", "config file", "phpinfo", "server-status",
    # Network
    "request smuggling", "http smuggling", "h2", "http/2",
    "continuation flood", "cve-",
    # DNS/TLS
    "dnssec", "zone transfer", "axfr",
    "certificate", "ssl", "tls",
    # Attack patterns
    "bypass", "evasion", "waf bypass",
    # Finding signals
    "found finding", "finding added", "finding:", "new finding",
    "cwe-", "cve-",
    # CaseCrack-specific
    "exploit verified", "proof of concept", "poc",
    "payload worked", "vulnerable", "confirmed",
]

# ── Console line color helpers ─────────────────────────────────────────────

RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
BOLD   = "\033[1m"


def api_get(path: str) -> dict:
    req = urllib.request.Request(BASE + path, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def api_post(path: str, payload: dict) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        BASE + path,
        data=data,
        headers={**HEADERS, "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def is_issue(text: str) -> bool:
    low = text.lower()
    for fp in FALSE_POSITIVE_PATTERNS:
        if fp in low:
            return False
    if any(kw in low for kw in ISSUE_KEYWORDS):
        return True
    for kw in ISSUE_KEYWORDS_EXACT:
        if re.search(r'\b' + re.escape(kw) + r'\b', low):
            return True
    return False


def is_chain_signal(text: str) -> bool:
    low = text.lower()
    return any(pat in low for pat in CHAIN_PATTERNS)


def ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def main() -> None:
    since = 0
    issues: list[dict] = []
    phase_issues: defaultdict[str, list[str]] = defaultdict(list)
    seen_ids: set[str] = set()
    seen_phases_degraded: set[str] = set()
    chain_signals: list[str] = []

    print(f"{BOLD}{'='*60}{RESET}", flush=True)
    print(f"{BOLD}  CaseCrack Monitor — royalhospital.so{RESET}", flush=True)
    print(f"{BOLD}  46-Phase Parallel Scan — {datetime.now().strftime('%Y-%m-%d')}{RESET}", flush=True)
    print(f"{BOLD}{'='*60}{RESET}", flush=True)
    print(f"[{ts()}] Monitor started — polling {BASE}", flush=True)
    print(f"[{ts()}] Target : {TARGET}", flush=True)
    print(f"[{ts()}] Log    -> {LOG_FILE}", flush=True)
    print(f"[{ts()}] Issues -> {ISSUE_FILE}", flush=True)
    print(f"[{ts()}] Chains -> {CHAINS_FILE}", flush=True)
    print(flush=True)

    # ── Launch the scan ────────────────────────────────────────────────────
    print(f"[{ts()}] Launching full parallel scan against {TARGET} ...", flush=True)
    try:
        launch_resp = api_post("/api/standalone/run", {
            "target_url": TARGET,
            "parallel": True,
        })
        print(f"[{ts()}] {GREEN}Scan launched: {launch_resp}{RESET}", flush=True)
    except Exception as e:
        print(f"[{ts()}] {RED}FAILED to launch scan: {e}{RESET}", flush=True)
        sys.exit(1)

    # Brief pause before starting to poll
    time.sleep(3)

    poll_interval = 3.0
    consecutive_complete_polls = 0
    scan_start = time.time()

    with open(LOG_FILE, "w", encoding="utf-8") as log_fh, \
         open(ISSUE_FILE, "w", encoding="utf-8") as issue_fh, \
         open(CHAINS_FILE, "w", encoding="utf-8") as chains_fh:

        issue_fh.write(
            f"=== Scan Issue Report — royalhospital.so "
            f"— {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n\n"
        )
        chains_fh.write(
            f"=== Attack Chains & Security Signals — royalhospital.so "
            f"— {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n\n"
        )

        while True:
            # ── Fetch new console lines ────────────────────────────────
            try:
                data = api_get(f"/api/standalone/console?limit=500&since={since}")
                lines = data.get("lines", [])
                next_since = data.get("next_since", since)
            except Exception as exc:
                print(f"[{ts()}] Console fetch error: {exc}", flush=True)
                time.sleep(poll_interval)
                continue

            for line in lines:
                uid = (
                    f"{line.get('ts', 0)}-{line.get('phase', '')}"
                    f"-{line.get('text', '')[:50]}"
                )
                if uid in seen_ids:
                    continue
                seen_ids.add(uid)

                phase   = line.get("phase", "")
                stream  = line.get("stream", "")
                text    = line.get("text", "")
                line_ts = line.get("ts", 0)

                # Write everything to the full log
                log_fh.write(json.dumps(line) + "\n")
                log_fh.flush()

                # Print ALL stderr lines (highlighted)
                if stream == "stderr":
                    print(f"[{ts()}] {YELLOW}[STDERR][{phase}] {text[:200]}{RESET}", flush=True)
                    if is_issue(text):
                        rec = {"ts": line_ts, "phase": phase,
                               "stream": stream, "text": text}
                        issues.append(rec)
                        phase_issues[phase].append(text)
                        issue_fh.write(f"[{phase}] [stderr] {text}\n")
                        issue_fh.flush()

                elif stream == "cmd":
                    print(f"[{ts()}] [CMD][{phase}] {text[:200]}", flush=True)

                elif stream in ("log", "event"):
                    if is_issue(text):
                        print(
                            f"[{ts()}] {RED}[ISSUE][{stream}][{phase}] {text[:200]}{RESET}",
                            flush=True,
                        )
                        rec = {"ts": line_ts, "phase": phase,
                               "stream": stream, "text": text}
                        issues.append(rec)
                        phase_issues[phase].append(text)
                        issue_fh.write(f"[{phase}] [{stream}] {text}\n")
                        issue_fh.flush()
                    else:
                        # Print non-issue log lines too (verbose)
                        print(f"[{ts()}] [{stream}][{phase}] {text[:200]}", flush=True)

                elif stream == "stdout":
                    print(f"[{ts()}] [OUT][{phase}] {text[:200]}", flush=True)

                # Track attack chain / security signals in all streams
                if is_chain_signal(text) and text not in chain_signals:
                    chain_signals.append(text)
                    print(
                        f"[{ts()}] {CYAN}{BOLD}[CHAIN/SIGNAL][{phase}] {text[:200]}{RESET}",
                        flush=True,
                    )
                    chains_fh.write(f"[{phase}] {text}\n")
                    chains_fh.flush()

            if next_since > since:
                since = next_since

            # ── Check scan status ──────────────────────────────────────
            try:
                status = api_get("/api/standalone/status")
            except Exception as exc:
                print(f"[{ts()}] Status fetch error: {exc}", flush=True)
                time.sleep(poll_interval)
                continue

            is_complete    = status.get("is_complete", False)
            completed      = status.get("completed_phases", 0)
            phase_statuses = status.get("phase_status", {})
            total          = len(phase_statuses) or status.get("total_phases", 46)
            findings_cnt   = status.get("findings_count", 0)
            current        = status.get("current_phase", "")
            elapsed        = int(time.time() - scan_start)

            # Degraded phase detection (report each phase once only)
            for ph, st in phase_statuses.items():
                if st == "degraded" and ph not in seen_phases_degraded:
                    seen_phases_degraded.add(ph)
                    msg = f"Phase DEGRADED: {ph}"
                    issues.append({"phase": ph, "stream": "status", "text": msg})
                    phase_issues[ph].append(msg)
                    issue_fh.write(f"[{ph}] [status] {msg}\n")
                    issue_fh.flush()
                    print(f"[{ts()}] {RED}*** {msg} ***{RESET}", flush=True)

            elapsed_str = f"{elapsed//60}m{elapsed%60:02d}s"
            print(
                f"[{ts()}] Status: {completed}/{total} complete"
                f" | findings={findings_cnt}"
                f" | elapsed={elapsed_str}"
                f" | issues={len(issues)}"
                + (f" | current={current}" if current else ""),
                flush=True,
            )

            if is_complete:
                consecutive_complete_polls += 1
                if consecutive_complete_polls >= 2:
                    print(f"\n[{ts()}] {GREEN}{BOLD}=== SCAN COMPLETE ==={RESET}", flush=True)
                    break
            else:
                consecutive_complete_polls = 0

            time.sleep(poll_interval)

    # ── Post-scan: fetch attack graph summary ──────────────────────────────
    print(f"\n[{ts()}] Fetching attack graph summary ...", flush=True)
    try:
        graph = api_get("/api/exploit-graph/summary")
        print(f"[{ts()}] {CYAN}Attack Graph: {json.dumps(graph, indent=2)[:1000]}{RESET}", flush=True)
    except Exception as e:
        print(f"[{ts()}] Attack graph fetch error: {e}", flush=True)

    # ── Post-scan: fetch top findings ─────────────────────────────────────
    print(f"\n[{ts()}] Fetching top findings ...", flush=True)
    try:
        findings = api_get("/api/standalone/findings?limit=100&severity=high,critical")
        items = findings.get("findings", findings.get("items", []))
        print(f"[{ts()}] {CYAN}Top {len(items)} high/critical findings:{RESET}", flush=True)
        for f in items[:20]:
            sev  = f.get("severity", "?")
            name = f.get("name", f.get("title", "?"))
            desc = f.get("description", "")[:100]
            print(f"  [{sev.upper()}] {name} — {desc}", flush=True)
    except Exception as e:
        print(f"[{ts()}] Findings fetch error: {e}", flush=True)

    # ── Final issue summary ────────────────────────────────────────────────
    print(f"\n{'='*60}", flush=True)
    print(f"{RED}ISSUE SUMMARY — {len(issues)} total issues found{RESET}", flush=True)
    print(f"{'='*60}", flush=True)

    if not issues:
        print("  No issues detected!", flush=True)
    else:
        for phase, msgs in sorted(phase_issues.items()):
            print(f"\n  [{phase}] — {len(msgs)} issue(s):", flush=True)
            for m in msgs[:5]:
                print(f"    • {m[:140]}", flush=True)
            if len(msgs) > 5:
                print(f"    ... and {len(msgs) - 5} more", flush=True)

    # ── Attack chains summary ──────────────────────────────────────────────
    print(f"\n{'='*60}", flush=True)
    print(f"{CYAN}ATTACK CHAINS & SECURITY SIGNALS — {len(chain_signals)} lines{RESET}", flush=True)
    print(f"{'='*60}", flush=True)
    for sig in chain_signals[:80]:
        print(f"  >> {sig[:160]}", flush=True)
    if len(chain_signals) > 80:
        print(f"  ... and {len(chain_signals) - 80} more (see {CHAINS_FILE})", flush=True)

    # ── Write final summary to files ───────────────────────────────────────
    with open(ISSUE_FILE, "a", encoding="utf-8") as fh:
        fh.write(f"\n\n=== SUMMARY: {len(issues)} issues found ===\n")
        for phase, msgs in sorted(phase_issues.items()):
            fh.write(f"\n[{phase}] ({len(msgs)} issues):\n")
            for m in msgs:
                fh.write(f"  • {m[:200]}\n")
        fh.write(f"\n\n=== CHAIN SIGNALS: {len(chain_signals)} ===\n")
        for sig in chain_signals:
            fh.write(f"  >> {sig[:300]}\n")

    with open(CHAINS_FILE, "a", encoding="utf-8") as fh:
        fh.write(f"\n\n=== FINAL CHAIN SUMMARY: {len(chain_signals)} signals ===\n")
        for sig in chain_signals:
            fh.write(f"  >> {sig[:300]}\n")

    print(f"\n[{ts()}] Full log    : {LOG_FILE}", flush=True)
    print(f"[{ts()}] Issues      : {ISSUE_FILE}", flush=True)
    print(f"[{ts()}] Chain log   : {CHAINS_FILE}", flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[Interrupted by user]", flush=True)
        sys.exit(0)
