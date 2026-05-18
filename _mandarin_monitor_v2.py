#!/usr/bin/env python3
"""
Monitor v2 — attaches to already-running mandarin scan.
Appends to existing log/issues files.
"""
import json
import re
import sys
import time
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

TOKEN = "YbX_VV84LaC7LSJYyToPYztXcmGvTg113fjwwmWbevE"
BASE = "http://localhost:8770"
LOG_FILE  = "_mandarin_console.log"
ISSUE_FILE = "_mandarin_issues.txt"

ISSUE_KEYWORDS = [
    "traceback", "exception", "attributeerror", "typeerror",
    "valueerror", "keyerror", "importerror", "filenotfounderror",
    "oserror", "runtimeerror", "indexerror", "nameerror",
    "modulenotfounderror", "syntaxerror", "permissionerror",
    "failed", "failure", "degraded", "crash", "fatal",
    "unrecognized arguments", "no such file", "cannot", "unable to",
    "timed out", "connection refused", "connection error",
    "ssl error", "no module named", "broken pipe",
    "no cli handler", "unicodedecodeerror",
    "got an unexpected keyword argument", "is not a valid",
    "object has no attribute", "unexpected error",
]
ISSUE_EXACT = ["error", "failed", "timeout", "warning", "missing", "abort", "warn"]
FALSE_POSITIVES = [
    "[dorking]", "q/s eta=", "queries |", "cache hits (skipped)",
    "| 0 errors |", "categories:", "error-pages:",
    '"failure_count"', '"last_failure_at"', '"warning_count": 0',
    '"warnings": []', '"status": "skipped"',
    "polling for oob", "polling for callbacks",
    "soft-timeout", "soft limit",
    "tests queued", "skipped tests", "skipped (",
    "docker info --format", "nuclei binary not found",
    "droopescan not installed", "grpc port 50051",
    "waf/rate-limit", "passive observation", "cdn_challenge",
    "http 429", "http 403",
    "port 8080 is closed", "zap sidecar not running",
    "mitmproxy sidecar not running", "stale production build",
    "baseline responses differ", "no clear majority",
]


def is_issue(text: str) -> bool:
    low = text.lower()
    for fp in FALSE_POSITIVES:
        if fp.lower() in low:
            return False
    if any(k in low for k in ISSUE_KEYWORDS):
        return True
    for k in ISSUE_EXACT:
        if re.search(r'\b' + re.escape(k) + r'\b', low):
            return True
    return False


def api(path: str) -> dict:
    req = urllib.request.Request(BASE + path, headers={"Authorization": f"Bearer {TOKEN}"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"_exc": str(e)}


def ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def main() -> None:
    print(f"[{ts()}] === Mandarin monitor v2 (attaching to running scan) ===", flush=True)
    since = 0
    seen: set = set()
    issues: list = []
    phase_issues: defaultdict = defaultdict(list)
    consecutive_complete = 0
    all_lines = 0
    phase_completion_events: list = []

    with open(LOG_FILE, "a", encoding="utf-8") as log_fh, \
         open(ISSUE_FILE, "a", encoding="utf-8") as issue_fh:
        issue_fh.write(f"\n=== Monitor v2 resumed: {datetime.now(timezone.utc).isoformat()} ===\n\n")
        issue_fh.flush()

        while True:
            # ── Console feed ─────────────────────────────────────────────
            data = api(f"/api/standalone/console?limit=500&since={since}")
            if "_exc" not in data:
                lines = data.get("lines", data.get("entries", []))
                ns = data.get("next_since", since)

                for line in lines:
                    uid = "{}-{}-{}".format(
                        line.get("ts", 0),
                        line.get("phase", ""),
                        str(line.get("text", ""))[:50],
                    )
                    if uid in seen:
                        continue
                    seen.add(uid)

                    phase  = line.get("phase", "")
                    stream = line.get("stream", "")
                    text   = (line.get("text", "") or line.get("message", "") or "")
                    level  = (line.get("level", "") or "").upper()

                    log_fh.write(json.dumps(line) + "\n")
                    all_lines += 1

                    if stream == "stderr":
                        print(f"[{ts()}] [STDERR][{phase}] {text[:180]}", flush=True)
                        if is_issue(text):
                            issues.append({"phase": phase, "text": text})
                            phase_issues[phase].append(text)
                            issue_fh.write(f"[{phase}] [stderr] {text}\n")
                            issue_fh.flush()
                    elif line.get("type") == "phase_complete":
                        outcome = line.get("outcome", "")
                        phase_completion_events.append({"phase": phase, "outcome": outcome})
                        icon = {"ok": "[OK]", "degraded": "[DEGRADED]", "error": "[ERROR]",
                                "timeout": "[TIMEOUT]", "skipped": "[SKIP]"}.get(outcome, f"[{outcome}]")
                        print(f"[{ts()}] {icon} Phase complete: {phase} ({outcome})", flush=True)
                        if outcome in ("degraded", "error", "timeout", "failed"):
                            msg = f"Phase {outcome.upper()}: {phase}"
                            issues.append({"phase": phase, "text": msg})
                            phase_issues[phase].append(msg)
                            issue_fh.write(f"[{phase}] [phase_complete] {msg}\n")
                            issue_fh.flush()
                    elif level in ("ERROR", "WARNING", "WARN", "CRITICAL"):
                        print(f"[{ts()}] [{level}][{phase}] {text[:160]}", flush=True)
                        if is_issue(text):
                            issues.append({"phase": phase, "text": text})
                            phase_issues[phase].append(text)
                            issue_fh.write(f"[{phase}] [{level}] {text}\n")
                            issue_fh.flush()
                    elif stream == "cmd":
                        print(f"[{ts()}] [CMD][{phase}] {text[:160]}", flush=True)
                    elif is_issue(text):
                        print(f"[{ts()}] [ISSUE/{stream}][{phase}] {text[:160]}", flush=True)
                        issues.append({"phase": phase, "text": text})
                        phase_issues[phase].append(text)
                        issue_fh.write(f"[{phase}] [{stream}] {text}\n")
                        issue_fh.flush()

                if ns and ns > since:
                    since = ns
                log_fh.flush()

            # ── Status ───────────────────────────────────────────────────
            status = api("/api/standalone/status")
            if "_exc" in status:
                print(f"[{ts()}] Status err: {status}", flush=True)
                time.sleep(5)
                continue

            running    = status.get("running", True)
            is_complete = status.get("is_complete", False)
            running_ph = status.get("running_phases", [])
            completed  = status.get("completed_phases", 0)
            total      = len(status.get("phase_status", {})) or 38
            findings   = status.get("findings_count", 0)

            for ph, st in status.get("phase_status", {}).items():
                if st in ("degraded", "error", "failed", "timeout"):
                    uid2 = f"STATUS-{st}-{ph}"
                    if uid2 not in seen:
                        seen.add(uid2)
                        msg = f"Phase status={st.upper()}: {ph}"
                        issues.append({"phase": ph, "text": msg})
                        phase_issues[ph].append(msg)
                        issue_fh.write(f"[{ph}] [status] {msg}\n")
                        issue_fh.flush()
                        print(f"[{ts()}] *** {msg} ***", flush=True)

            running_disp = ", ".join(running_ph[:4]) if running_ph else ""
            print(
                f"[{ts()}] Progress: {completed}/{total} | findings={findings}"
                + (f" | running=[{running_disp}]" if running_disp else ""),
                flush=True,
            )

            # Only exit if truly done: not running, no running phases
            actually_done = is_complete and not running and not running_ph
            if actually_done:
                consecutive_complete += 1
                if consecutive_complete >= 2:
                    print(f"[{ts()}] === SCAN COMPLETE ===", flush=True)
                    break
            else:
                consecutive_complete = 0

            time.sleep(4)

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{'='*68}", flush=True)
    print(f"ISSUE SUMMARY — {len(issues)} total issues", flush=True)
    print(f"{'='*68}", flush=True)
    if not issues:
        print("  No issues detected!", flush=True)
    else:
        for phase, msgs in sorted(phase_issues.items()):
            print(f"\n  [{phase}] — {len(msgs)} issue(s):", flush=True)
            for m in msgs[:5]:
                print(f"    • {m[:130]}", flush=True)
            if len(msgs) > 5:
                print(f"    ... and {len(msgs)-5} more", flush=True)

    print(f"\n[{ts()}] Log    : {LOG_FILE}", flush=True)
    print(f"[{ts()}] Issues : {ISSUE_FILE}", flush=True)

    with open(ISSUE_FILE, "a", encoding="utf-8") as fh:
        fh.write(f"\n\n=== SUMMARY (monitor v2): {len(issues)} issues ===\n")
        for ph, msgs in sorted(phase_issues.items()):
            fh.write(f"\n[{ph}] ({len(msgs)} issues):\n")
            for m in msgs:
                fh.write(f"  • {m[:200]}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n[Interrupted]", flush=True)
        sys.exit(0)
