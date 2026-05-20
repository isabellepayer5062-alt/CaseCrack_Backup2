#!/usr/bin/env python3
"""
Real-time scan monitor — run 4 (2026-05-04, Docker+Burp+Ollama running)
Pulls console feed and records all errors, warnings, failures,
and degraded phases.

Run:  python _monitor_scan_run4.py
Output: _scan_monitor_run4.log  (all events)
        _scan_issues_run4.txt   (issues/errors only)
"""

import json
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

BASE = "http://localhost:8770"
HEADERS = {}  # GET endpoints don't require auth

LOG_FILE   = "_scan_monitor_run4.log"
ISSUE_FILE = "_scan_issues_run4.txt"
POLL_INTERVAL = 3  # seconds

ISSUE_KEYWORDS = [
    "error", "traceback", "exception", "failed", "failure",
    "degraded", "crash", "critical", "fatal", "abort",
    "circuit breaker", "OPEN", "timeout", "timed out",
    "connection refused", "cannot connect", "not found",
    "module not found", "importerror", "attributeerror",
    "typeerror", "valueerror", "keyerror", "indexerror",
    "permission denied", "access denied", "unauthorized",
    "docker", "cannot pull", "image not found",
    "stall", "hung", "deadlock",
]

# Lines matching these are NOT issues (false positives)
FALSE_POSITIVE_PATTERNS = [
    "[dorking]",
    "q/s eta=",
    '"failure_count"',
    '"last_failure_at"',
    "polling for oob",
    "soft-timeout",
    "tests queued",
    "skipped tests",
    "skipped (",
    "waf/rate-limit",
    "passive observation",
    "fix-84",        # CDN challenge handling (expected)
    "fix-86",        # CDN challenge handling (expected)
    "fix-151",       # CDN challenge retries (expected)
    "cdn_challenge", # Expected Cloudflare behaviour
    "http 429",      # Rate limiting (expected)
    "port 8080 is closed",  # ZAP sidecar not running (expected without ZAP)
    "zap sidecar not running",
    "mitmproxy sidecar not running",
    "stale production build",  # CSS build warning (cosmetic)
]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _is_issue(line: str) -> bool:
    ll = line.lower()
    for fp in FALSE_POSITIVE_PATTERNS:
        if fp.lower() in ll:
            return False
    for kw in ISSUE_KEYWORDS:
        if kw.lower() in ll:
            return True
    return False


def _fetch(path: str) -> dict | None:
    try:
        req = urllib.request.Request(f"{BASE}{path}", headers=HEADERS)
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return None


def main() -> None:
    since = 0
    consecutive_complete = 0
    seen_degraded: set[str] = set()
    phase_counts: dict[str, int] = defaultdict(int)

    with open(LOG_FILE, "w", encoding="utf-8", errors="replace") as log_f, \
         open(ISSUE_FILE, "w", encoding="utf-8", errors="replace") as issue_f:

        log_f.write(f"=== Scan Monitor Run 4 started at {_now()} UTC ===\n")
        log_f.write(f"=== Docker + Burp + Ollama running ===\n")
        issue_f.write(f"=== Issues Log Run 4 started at {_now()} UTC ===\n")
        log_f.flush(); issue_f.flush()

        while True:
            # ── status ──────────────────────────────────────────────────
            status = _fetch("/api/standalone/status")
            if status:
                completed = status.get("completed_phases", 0)
                total = len(status.get("phase_status", {}))
                findings = status.get("findings_count", 0)
                running = status.get("running_phases", [])
                is_complete = status.get("is_complete", False)

                # Detect newly degraded phases
                phase_status = status.get("phase_status", {})
                for phase, st in phase_status.items():
                    if st == "degraded" and phase not in seen_degraded:
                        seen_degraded.add(phase)
                        msg = f"[{_now()}] *** NEW DEGRADED PHASE: {phase} ***\n"
                        print(msg.strip())
                        log_f.write(msg); issue_f.write(msg)
                        log_f.flush(); issue_f.flush()

                summary = (
                    f"[{_now()}] Status: {completed}/{total} complete | "
                    f"findings={findings} | "
                    f"current={' | '.join(running[:3])}"
                )
                print(summary)
                log_f.write(summary + "\n"); log_f.flush()

                if is_complete:
                    consecutive_complete += 1
                    if consecutive_complete >= 2:
                        final = f"[{_now()}] === SCAN COMPLETE — {findings} total findings ===\n"
                        print(final.strip())
                        log_f.write(final); issue_f.write(final)
                        log_f.flush(); issue_f.flush()
                        break
                else:
                    consecutive_complete = 0

            # ── console feed ─────────────────────────────────────────────
            console = _fetch(f"/api/standalone/console?limit=500&since={since}")
            if console:
                entries = console.get("entries", [])
                for entry in entries:
                    ts = entry.get("ts", since + 1)
                    if ts <= since:
                        continue
                    since = max(since, ts)

                    level = entry.get("level", "")
                    phase = entry.get("phase", "")
                    text  = entry.get("text", "")
                    line  = f"[{level}][{phase}] {text}"

                    log_f.write(line + "\n")

                    if _is_issue(line):
                        issue_line = f"[{_now()}] {line}\n"
                        issue_f.write(issue_line)
                        issue_f.flush()
                        print(f"  ISSUE: {line[:120]}")

                log_f.flush()

            time.sleep(POLL_INTERVAL)

    print(f"\nDone. Log: {LOG_FILE}  Issues: {ISSUE_FILE}")


if __name__ == "__main__":
    main()
