#!/usr/bin/env python3
"""
Real-time scan monitor — Run 3 (2026-05-05) sugarrushed.ca
Pulls console feed and records all errors, warnings, failures, and degraded phases.

Run:  python _monitor_scan_20260505.py
Output: _scan_monitor_20260505_run3.log  (all events)
        _scan_issues_20260505_run3.txt   (issues/errors only)
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

TOKEN = "mpogZXAS82-WoTm6_5evKtWQlQUIt23KVCxTV73qoY0"
BASE  = "http://localhost:8770"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

LOG_FILE   = "_scan_monitor_20260505_run3.log"
ISSUE_FILE = "_scan_issues_20260505_run3.txt"

ISSUE_KEYWORDS = [
    "traceback", "exception", "attributeerror", "typeerror",
    "valueerror", "keyerror", "importerror", "filenotfounderror",
    "oserror", "runtimeerror", "indexerror", "nameerror",
    "failed", "failure", "degraded", "crash",
    "unrecognized arguments", "no such file", "cannot", "unable to",
    "timed out", "connection refused", "connection error",
    "ssl error", "no module named", "broken pipe",
    "no cli handler", "unicodedecodeerror", "unexpected keyword argument",
    "is not a valid", "has no attribute",
]

ISSUE_KEYWORDS_EXACT = [
    "error", "failed", "timeout", "warning", "missing",
    "abort", "warn",
]

# Patterns that look like issues but are normal progress/informational output.
FALSE_POSITIVE_PATTERNS = [
    "[dorking]",
    "q/s eta=",
    "queries |",
    "cache hits (skipped)",
    "| 0 errors |",
    "categories:",
    "error-pages:",
    # Exploit Graph JSON fields
    '"failure_count"',
    '"last_failure_at"',
    # OOB/callback polling
    "polling for oob interactions",
    "polling for callbacks",
    # Phase flow control
    "soft-timeout",
    "soft limit",
    # Stats summary lines
    "tests queued",
    "skipped tests",
    "skipped (",
    # Normal info lines
    "42 tests queued",
    "6 skipped",
    "polling for oob",
    # Monitor self-messages
    "monitor started",
    "log  ->",
    "issues ->",
    # Phase timing info
    "phase started",
    "phase completed",
    "phase running",
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
    issues: list[dict] = []
    phase_issues: defaultdict[str, list[str]] = defaultdict(list)
    seen_ids: set[str] = set()
    seen_phases_degraded: set[str] = set()

    print(f"[{ts()}] Monitor started — polling {BASE}", flush=True)
    print(f"[{ts()}] Log    -> {LOG_FILE}", flush=True)
    print(f"[{ts()}] Issues -> {ISSUE_FILE}", flush=True)
    print(flush=True)

    poll_interval = 3.0
    consecutive_complete_polls = 0
    last_status_print = 0.0

    with open(LOG_FILE, "w", encoding="utf-8") as log_fh, \
         open(ISSUE_FILE, "w", encoding="utf-8") as issue_fh:

        issue_fh.write(f"=== Scan Issue Report (Run 3) — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n")
        issue_fh.write("=== Target: sugarrushed.ca | Mode: parallel ===\n\n")
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
                uid = f"{line.get('ts', 0)}-{line.get('phase', '')}-{line.get('text', '')[:60]}"
                if uid in seen_ids:
                    continue
                seen_ids.add(uid)

                phase  = line.get("phase", "")
                stream = line.get("stream", "")
                text   = line.get("text", "")
                line_ts = line.get("ts", 0)

                # Write everything to full log
                log_fh.write(json.dumps(line) + "\n")
                log_fh.flush()

                flag = is_issue(text)

                # Always print stderr (often contains real errors)
                if stream == "stderr":
                    marker = "*** " if flag else ""
                    print(f"[{ts()}] {marker}[stderr][{phase}] {text[:180]}", flush=True)
                    if flag:
                        rec = {"ts": line_ts, "phase": phase, "stream": stream, "text": text}
                        issues.append(rec)
                        phase_issues[phase].append(text)
                        issue_fh.write(f"[{phase}] [stderr] {text}\n")
                        issue_fh.flush()

                elif stream == "cmd":
                    print(f"[{ts()}] [CMD][{phase}] {text[:180]}", flush=True)

                elif stream in ("log", "event") and flag:
                    print(f"[{ts()}] *** [ISSUE][{stream}][{phase}] {text[:180]}", flush=True)
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

            is_complete  = status.get("is_complete", False)
            completed    = status.get("completed_phases", 0)
            total        = len(status.get("phase_status", {})) or status.get("total_phases", 36)
            findings_cnt = status.get("findings_count", 0)
            current      = status.get("current_phase", "")
            running_list = status.get("running_phases", [])
            phase_statuses = status.get("phase_status", {})
            errors_cnt   = status.get("errors", 0)

            # Collect degraded phases (report each only once)
            for ph, st in phase_statuses.items():
                if st == "degraded" and ph not in seen_phases_degraded:
                    seen_phases_degraded.add(ph)
                    msg = f"Phase DEGRADED: {ph}"
                    issues.append({"phase": ph, "stream": "status", "text": msg})
                    phase_issues[ph].append(msg)
                    issue_fh.write(f"[{ph}] [status] {msg}\n")
                    issue_fh.flush()
                    print(f"[{ts()}] *** {msg} ***", flush=True)

            # Status line every poll
            now = time.monotonic()
            running_str = ", ".join(running_list[:4]) if running_list else (current or "")
            print(
                f"[{ts()}] {completed}/{total} done | findings={findings_cnt}"
                + (f" | errs={errors_cnt}" if errors_cnt else "")
                + (f" | running=[{running_str}]" if running_str else ""),
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

    # ── Final summary ─────────────────────────────────────────────────
    print(f"\n{'='*70}", flush=True)
    print(f"ISSUE SUMMARY — {len(issues)} total issues found", flush=True)
    print(f"{'='*70}", flush=True)

    if not issues:
        print("  No issues detected!", flush=True)
    else:
        for phase, msgs in sorted(phase_issues.items()):
            print(f"\n  [{phase}] — {len(msgs)} issue(s):", flush=True)
            for m in msgs[:6]:
                print(f"    • {m[:130]}", flush=True)
            if len(msgs) > 6:
                print(f"    ... and {len(msgs) - 6} more", flush=True)

    with open(ISSUE_FILE, "a", encoding="utf-8") as fh:
        fh.write(f"\n\n=== SUMMARY: {len(issues)} issues found ===\n")
        for phase, msgs in sorted(phase_issues.items()):
            fh.write(f"\n[{phase}] ({len(msgs)} issues):\n")
            for m in msgs:
                fh.write(f"  • {m[:250]}\n")

    print(f"\n[{ts()}] Full log: {LOG_FILE}", flush=True)
    print(f"[{ts()}] Issues:  {ISSUE_FILE}", flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[Interrupted by user]", flush=True)
        sys.exit(0)
