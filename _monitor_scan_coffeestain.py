#!/usr/bin/env python3
"""
Real-time scan monitor — coffeestain.com full 38-phase parallel run.
Session: scan-83b0  (2026-05-07)

Run:  python _monitor_scan_coffeestain.py
Output:
  _scan_monitor_coffeestain.log   (all console events)
  _scan_issues_coffeestain.txt    (errors/warnings/degraded only)
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

TOKEN = "ddxsLkafS6FS-tkAfqEJxoTXFyTCMQ8yWApHZa2iy-c"
BASE  = "http://localhost:8770"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

LOG_FILE   = "_scan_monitor_coffeestain.log"
ISSUE_FILE = "_scan_issues_coffeestain.txt"

ISSUE_KEYWORDS = [
    "traceback", "exception", "attributeerror", "typeerror",
    "valueerror", "keyerror", "importerror", "filenotfounderror",
    "oserror", "runtimeerror", "indexerror", "nameerror",
    "failed", "failure", "degraded", "crash",
    "unrecognized arguments", "no such file", "cannot", "unable to",
    "timed out", "connection refused", "connection error",
    "ssl error", "no module named", "broken pipe",
    "no cli handler",
]

ISSUE_KEYWORDS_EXACT = [
    "error", "failed", "timeout", "warning", "missing",
    "skipped", "abort", "warn",
]

FALSE_POSITIVE_PATTERNS = [
    "[dorking]",
    "q/s eta=",
    "queries |",
    "cache hits (skipped)",
    "| 0 errors |",
    "categories:",
    "error-pages:",
    '"failure_count"',
    '"last_failure_at"',
    "polling for oob interactions",
    "polling for callbacks",
    "soft-timeout",
    "soft limit",
    "tests queued",
    "skipped tests",
    "42 tests queued",
    "6 skipped",
    "polling for oob",
]


def api_get(path: str) -> dict:
    req = urllib.request.Request(BASE + path, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def is_issue(text: str) -> bool:
    import re
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

    print(f"[{ts()}] Monitor started — coffeestain.com scan (scan-83b0)", flush=True)
    print(f"[{ts()}] Dashboard: {BASE}", flush=True)
    print(f"[{ts()}] Log    -> {LOG_FILE}", flush=True)
    print(f"[{ts()}] Issues -> {ISSUE_FILE}", flush=True)
    print(flush=True)

    poll_interval = 5.0
    consecutive_complete_polls = 0
    last_progress_print = 0.0

    with open(LOG_FILE, "w", encoding="utf-8") as log_fh, \
         open(ISSUE_FILE, "w", encoding="utf-8") as issue_fh:

        issue_fh.write(f"=== Scan Issue Report — coffeestain.com — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n\n")

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
                uid = f"{line.get('ts',0)}-{line.get('phase','')}-{line.get('text','')[:60]}"
                if uid in seen_ids:
                    continue
                seen_ids.add(uid)

                phase  = line.get("phase", "")
                stream = line.get("stream", "")
                text   = line.get("text", "")
                line_ts = line.get("ts", 0)

                log_fh.write(json.dumps(line) + "\n")
                log_fh.flush()

                if stream == "stderr":
                    print(f"[{ts()}] [stderr][{phase}] {text[:160]}", flush=True)
                    if is_issue(text):
                        rec = {"ts": line_ts, "phase": phase, "stream": stream, "text": text}
                        issues.append(rec)
                        phase_issues[phase].append(text)
                        issue_fh.write(f"[{phase}] [stderr] {text}\n")
                        issue_fh.flush()

                elif stream == "cmd":
                    print(f"[{ts()}] [CMD][{phase}] {text[:160]}", flush=True)

                elif stream in ("log", "event") and is_issue(text):
                    print(f"[{ts()}] [ISSUE][{stream}][{phase}] {text[:160]}", flush=True)
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
            total        = len(status.get("phase_status", {})) or status.get("total_phases", 38)
            findings_cnt = status.get("findings_count", status.get("findings", 0))
            running_ph   = status.get("running_phases", [])
            phase_statuses = status.get("phase_status", {})
            errors_cnt   = status.get("errors", 0)
            subdomains   = status.get("subdomains_found", 0)
            endpoints    = status.get("endpoints_found", 0)
            technologies = status.get("technologies_found", 0)

            # Track degraded phases (once each)
            for ph, st in phase_statuses.items():
                if st in ("degraded", "failed"):
                    uid2 = f"{st}-{ph}"
                    if uid2 not in seen_phases_degraded:
                        seen_phases_degraded.add(uid2)
                        msg = f"Phase {st.upper()}: {ph}"
                        issues.append({"phase": ph, "stream": "status", "text": msg})
                        phase_issues[ph].append(msg)
                        issue_fh.write(f"[{ph}] [status] {msg}\n")
                        issue_fh.flush()
                        print(f"[{ts()}] *** {msg} ***", flush=True)

            # Print running phases every poll
            running_str = ", ".join(running_ph[:6]) if running_ph else "—"
            if len(running_ph) > 6:
                running_str += f" +{len(running_ph)-6} more"

            now = time.time()
            if now - last_progress_print >= poll_interval - 0.5:
                last_progress_print = now
                print(
                    f"[{ts()}] {completed}/{total} phases | findings={findings_cnt} "
                    f"errors={errors_cnt} subs={subdomains} eps={endpoints} tech={technologies}",
                    flush=True,
                )
                if running_ph:
                    print(f"[{ts()}] Running: {running_str}", flush=True)

            if is_complete:
                consecutive_complete_polls += 1
                if consecutive_complete_polls >= 2:
                    print(f"\n[{ts()}] === SCAN COMPLETE ===", flush=True)
                    break
            else:
                consecutive_complete_polls = 0

            time.sleep(poll_interval)

    # ── Final summary ─────────────────────────────────────────────────
    try:
        final_status = api_get("/api/standalone/status")
        final_findings = final_status.get("findings_count", final_status.get("findings", 0))
        final_errors   = final_status.get("errors", 0)
        final_completed = final_status.get("completed_phases", 0)
    except Exception:
        final_findings = "?"
        final_errors   = "?"
        final_completed = "?"

    print(f"\n{'='*60}", flush=True)
    print(f"FINAL RESULTS — coffeestain.com", flush=True)
    print(f"  Phases complete : {final_completed}", flush=True)
    print(f"  Findings        : {final_findings}", flush=True)
    print(f"  Scan errors     : {final_errors}", flush=True)
    print(f"  Issues detected : {len(issues)}", flush=True)
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
        fh.write(f"Findings: {final_findings} | Errors: {final_errors} | Phases: {final_completed}\n")
        for phase, msgs in sorted(phase_issues.items()):
            fh.write(f"\n[{phase}] ({len(msgs)} issues):\n")
            for m in msgs:
                fh.write(f"  • {m[:200]}\n")

    print(f"\n[{ts()}] Full log: {LOG_FILE}", flush=True)
    print(f"[{ts()}] Issues:  {ISSUE_FILE}", flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[Interrupted by user]", flush=True)
        sys.exit(0)
