#!/usr/bin/env python3
"""
Real-time scan monitor — thewhiteleafstudio.com run (2026-05-07)

Captures ALL console output (stdout + stderr), flags issues/errors,
records degraded phases, and produces a final summary.

Run:  python _monitor_whiteleaf.py
Output: _scan_monitor_whiteleaf.log   (all events)
        _scan_issues_whiteleaf.txt    (issues/errors only)
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

TOKEN = "KQo1ByJTDHqJOcSDnyoL-fai1MkhRArIXPc3IX4XMkk"
BASE  = "http://localhost:8770"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

LOG_FILE   = "_scan_monitor_whiteleaf.log"
ISSUE_FILE = "_scan_issues_whiteleaf.txt"

# ── Keyword lists ──────────────────────────────────────────────────────────

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
]


def api_get(path: str) -> dict:
    req = urllib.request.Request(BASE + path, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=30) as r:
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


def ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def main() -> None:
    since = 0
    issues: list[dict] = []
    phase_issues: defaultdict[str, list[str]] = defaultdict(list)
    seen_ids: set[str] = set()
    seen_phases_degraded: set[str] = set()

    # Also track interesting security findings printed to console
    interesting_findings: list[str] = []
    INTERESTING_PATTERNS = [
        "critical", "high severity", "injection", "xss", "sqli",
        "ssrf", "rce", "lfi", "rfi", "ssti", "open redirect",
        "idor", "broken auth", "authentication bypass",
        "exposure", "disclosure", "introspection",
        "graphql", "api key", "secret", "token", "password",
        "redis", "mongodb", "elasticsearch",
        "backup file", "htaccess", "debug", "admin",
        "found finding", "finding added", "finding:",
        "cve-", "cwe-",
    ]

    print(f"[{ts()}] Monitor started — polling {BASE}", flush=True)
    print(f"[{ts()}] Target: https://www.thewhiteleafstudio.com/", flush=True)
    print(f"[{ts()}] Log    -> {LOG_FILE}", flush=True)
    print(f"[{ts()}] Issues -> {ISSUE_FILE}", flush=True)
    print(flush=True)

    poll_interval = 3.0
    consecutive_complete_polls = 0

    with open(LOG_FILE, "w", encoding="utf-8") as log_fh, \
         open(ISSUE_FILE, "w", encoding="utf-8") as issue_fh:

        issue_fh.write(
            f"=== Scan Issue Report — thewhiteleafstudio.com "
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

                # Print ALL stderr lines
                if stream == "stderr":
                    print(f"[{ts()}] [STDERR][{phase}] {text[:200]}", flush=True)
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
                            f"[{ts()}] [ISSUE][{stream}][{phase}] {text[:200]}",
                            flush=True,
                        )
                        rec = {"ts": line_ts, "phase": phase,
                               "stream": stream, "text": text}
                        issues.append(rec)
                        phase_issues[phase].append(text)
                        issue_fh.write(f"[{phase}] [{stream}] {text}\n")
                        issue_fh.flush()

                # Track interesting security signal on stdout too
                low = text.lower()
                for pat in INTERESTING_PATTERNS:
                    if pat in low and text not in interesting_findings:
                        interesting_findings.append(text)
                        break

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
            total          = len(phase_statuses) or status.get("total_phases", 38)
            findings_cnt   = status.get("findings_count", 0)
            current        = status.get("current_phase", "")

            # Degraded phase detection (report each phase once only)
            for ph, st in phase_statuses.items():
                if st == "degraded" and ph not in seen_phases_degraded:
                    seen_phases_degraded.add(ph)
                    msg = f"Phase DEGRADED: {ph}"
                    issues.append({"phase": ph, "stream": "status", "text": msg})
                    phase_issues[ph].append(msg)
                    issue_fh.write(f"[{ph}] [status] {msg}\n")
                    issue_fh.flush()
                    print(f"[{ts()}] *** {msg} ***", flush=True)

            print(
                f"[{ts()}] Status: {completed}/{total} complete"
                f" | findings={findings_cnt}"
                + (f" | current={current}" if current else ""),
                flush=True,
            )

            if is_complete:
                consecutive_complete_polls += 1
                if consecutive_complete_polls >= 2:
                    print(f"\n[{ts()}] === SCAN COMPLETE ===", flush=True)
                    break
            else:
                consecutive_complete_polls = 0

            time.sleep(poll_interval)

    # ── Final issue summary ───────────────────────────────────────────────
    print(f"\n{'='*60}", flush=True)
    print(f"ISSUE SUMMARY — {len(issues)} total issues found", flush=True)
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

    # ── Interesting findings ──────────────────────────────────────────────
    print(f"\n{'='*60}", flush=True)
    print(f"INTERESTING SECURITY SIGNALS — {len(interesting_findings)} lines", flush=True)
    print(f"{'='*60}", flush=True)
    for f in interesting_findings[:50]:
        print(f"  >> {f[:160]}", flush=True)
    if len(interesting_findings) > 50:
        print(f"  ... and {len(interesting_findings) - 50} more (see {LOG_FILE})", flush=True)

    # ── Write final summary to issue file ────────────────────────────────
    with open(ISSUE_FILE, "a", encoding="utf-8") as fh:
        fh.write(f"\n\n=== SUMMARY: {len(issues)} issues found ===\n")
        for phase, msgs in sorted(phase_issues.items()):
            fh.write(f"\n[{phase}] ({len(msgs)} issues):\n")
            for m in msgs:
                fh.write(f"  • {m[:200]}\n")
        fh.write(f"\n\n=== INTERESTING SIGNALS: {len(interesting_findings)} ===\n")
        for f in interesting_findings:
            fh.write(f"  >> {f[:300]}\n")

    print(f"\n[{ts()}] Full log : {LOG_FILE}", flush=True)
    print(f"[{ts()}] Issues   : {ISSUE_FILE}", flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[Interrupted by user]", flush=True)
        sys.exit(0)
