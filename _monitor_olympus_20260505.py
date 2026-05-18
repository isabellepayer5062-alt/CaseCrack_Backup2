#!/usr/bin/env python3
"""
Real-time scan monitor — olympus-entertainment.com full parallel run (2026-05-05)
Pulls console feed and records all errors, warnings, failures, and degraded phases.

Run:  python _monitor_olympus_20260505.py
Output: _scan_monitor_olympus_20260505.log  (all events, full fidelity)
        _scan_issues_olympus_20260505.txt   (issues/errors only)
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

TOKEN = "EukCObGStywVZJZ6O0WdUAXaMQR9lm3bUVBxZIOClFU"
BASE  = "http://localhost:8770"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

LOG_FILE   = "_scan_monitor_olympus_20260505.log"
ISSUE_FILE = "_scan_issues_olympus_20260505.txt"

# ── Issue detection keywords ───────────────────────────────────────────────────
ISSUE_KEYWORDS = [
    "traceback", "exception", "attributeerror", "typeerror",
    "valueerror", "keyerror", "importerror", "filenotfounderror",
    "oserror", "runtimeerror", "indexerror", "nameerror",
    "failed", "failure", "degraded", "crash",
    "unrecognized arguments", "no such file", "cannot", "unable to",
    "timed out", "connection refused", "connection error",
    "ssl error", "no module named", "broken pipe",
    "no cli handler", "unicodedecodeerror", "got an unexpected keyword argument",
    "is not a valid", "object has no attribute",
]
# Exact-word match for ambiguous keywords
ISSUE_KEYWORDS_EXACT = [
    "error", "failed", "timeout", "warning", "missing",
    "abort", "warn",
]

# ── False-positive suppression ─────────────────────────────────────────────────
# Patterns that contain issue keywords but are NORMAL output — suppress them.
FALSE_POSITIVE_PATTERNS = [
    "[dorking]",                          # dorking progress: "0 errors | …"
    "q/s eta=",                           # ETA progress lines
    "queries |",                          # query counter progress
    "cache hits (skipped)",               # normal cache operation
    "| 0 errors |",                       # zero-error stat
    "categories:",                        # category summary (error-pages)
    "error-pages:",                       # category label
    # FIX-FP-1: Exploit Graph Analysis — structured JSON fields
    '"failure_count"',                    # "failure_count": 0
    '"last_failure_at"',                  # "last_failure_at": null
    # FIX-FP-2: OOB/callback polling — expected probe behaviour
    "polling for oob interactions",
    "polling for callbacks",
    # FIX-FP-3: Soft-timeout is normal phase flow control
    "soft-timeout",
    "soft limit",
    # FIX-FP-4: Informational test-queue messages (sugarrushed run)
    "tests queued",                       # "42 tests queued, 6 skipped"
    "skipped tests",                      # summary line
    "skipped (",                          # "Skipped Tests (6)"
    # FIX-FP-5: Docker preflight — "docker info" is routine health-check
    "docker info --format",
    # FIX-FP-6: nuclei / droopescan binary-not-found (infrastructure gap, not bug)
    "nuclei binary not found",
    "droopescan not installed",
    # FIX-FP-7: gRPC probe — expected on targets without gRPC
    "grpc port 50051",
    # FIX-FP-8: URL-dorking timeout is a configured budget, not a failure
    "url dorking 480s",
    "dns brute-force 10s",
    # FIX-FP-9: Zero-count "warning" inside JSON summary blobs
    '"warning_count": 0',
    '"warnings": []',
    # FIX-FP-10: supply_chain_check "skipped" tag in structured output
    '"status": "skipped"',
]


def api_get(path: str) -> dict:
    req = urllib.request.Request(BASE + path, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def is_issue(text: str) -> bool:
    low = text.lower()
    # Suppress known false-positive progress/info patterns first
    for fp in FALSE_POSITIVE_PATTERNS:
        if fp.lower() in low:
            return False
    # Primary: substring match on unambiguous keywords
    if any(kw in low for kw in ISSUE_KEYWORDS):
        return True
    # Secondary: exact-word match for ambiguous keywords
    for kw in ISSUE_KEYWORDS_EXACT:
        if re.search(r'\b' + re.escape(kw) + r'\b', low):
            return True
    return False


def ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def main() -> None:
    since = 0
    issues: list = []
    phase_issues: defaultdict = defaultdict(list)
    seen_ids: set = set()

    print(f"[{ts()}] Monitor started — target: https://olympus-entertainment.com/", flush=True)
    print(f"[{ts()}] Polling: {BASE}", flush=True)
    print(f"[{ts()}] Full log -> {LOG_FILE}", flush=True)
    print(f"[{ts()}] Issues  -> {ISSUE_FILE}", flush=True)
    print(flush=True)

    poll_interval = 3.0
    consecutive_complete_polls = 0

    with open(LOG_FILE, "w", encoding="utf-8") as log_fh, \
         open(ISSUE_FILE, "w", encoding="utf-8") as issue_fh:

        issue_fh.write(
            f"=== Olympus Scan Issue Report — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC ===\n"
            f"=== Target: https://olympus-entertainment.com/ ===\n\n"
        )
        issue_fh.flush()

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
                uid = "{}-{}-{}".format(
                    line.get("ts", 0),
                    line.get("phase", ""),
                    line.get("text", "")[:40]
                )
                if uid in seen_ids:
                    continue
                seen_ids.add(uid)

                phase  = line.get("phase", "")
                stream = line.get("stream", "")
                text   = line.get("text", "")
                line_ts = line.get("ts", 0)

                # Write everything to full log (raw NDJSON)
                log_fh.write(json.dumps(line) + "\n")
                log_fh.flush()

                # Always print stderr + flag issues
                if stream == "stderr":
                    print(f"[{ts()}] [stderr][{phase}] {text[:180]}", flush=True)
                    if is_issue(text):
                        rec = {"ts": line_ts, "phase": phase, "stream": stream, "text": text}
                        issues.append(rec)
                        phase_issues[phase].append(text)
                        issue_fh.write(f"[{phase}] [stderr] {text}\n")
                        issue_fh.flush()

                elif stream == "cmd":
                    print(f"[{ts()}] [CMD][{phase}] {text[:180]}", flush=True)

                elif stream in ("log", "event") and is_issue(text):
                    print(f"[{ts()}] [ISSUE][{stream}][{phase}] {text[:180]}", flush=True)
                    rec = {"ts": line_ts, "phase": phase, "stream": stream, "text": text}
                    issues.append(rec)
                    phase_issues[phase].append(text)
                    issue_fh.write(f"[{phase}] [{stream}] {text}\n")
                    issue_fh.flush()

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
            phase_status   = status.get("phase_status", {})
            total          = len(phase_status) or status.get("total_phases", 36)
            findings_cnt   = status.get("findings_count", 0)
            current        = status.get("current_phase", "")

            # Track degraded phases
            for ph, st in phase_status.items():
                if st in ("degraded", "error", "failed", "timeout"):
                    uid2 = f"{st}-{ph}"
                    if uid2 not in seen_ids:
                        seen_ids.add(uid2)
                        msg = f"Phase {st.upper()}: {ph}"
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

    # ── Final summary ─────────────────────────────────────────────────────────
    print(f"\n{'='*60}", flush=True)
    print(f"ISSUE SUMMARY — {len(issues)} total issues found", flush=True)
    print(f"{'='*60}", flush=True)

    if not issues:
        print("  No issues detected!", flush=True)
    else:
        for phase, msgs in sorted(phase_issues.items()):
            print(f"\n  [{phase}] — {len(msgs)} issue(s):", flush=True)
            for m in msgs[:5]:
                print(f"    • {m[:120]}", flush=True)
            if len(msgs) > 5:
                print(f"    ... and {len(msgs)-5} more", flush=True)

    with open(ISSUE_FILE, "a", encoding="utf-8") as fh:
        fh.write(f"\n\n=== SUMMARY: {len(issues)} issues found ===\n")
        for phase, msgs in sorted(phase_issues.items()):
            fh.write(f"\n[{phase}] ({len(msgs)} issues):\n")
            for m in msgs:
                fh.write(f"  • {m[:200]}\n")

    print(f"\n[{ts()}] Full log : {LOG_FILE}", flush=True)
    print(f"[{ts()}] Issues   : {ISSUE_FILE}", flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[Interrupted by user]", flush=True)
        sys.exit(0)
