#!/usr/bin/env python3
"""
All-in-one launcher + real-time monitor for the full parallel recon scan
against https://www.mandarinrestaurant.com/

Usage:  python _mandarin_scan_launch_monitor.py
Output: _mandarin_console.log       (full raw NDJSON console feed)
        _mandarin_issues.txt        (issues / errors / failures only)
        _mandarin_summary.txt       (final summary)
"""

import json
import os
import re
import subprocess
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ── Unicode safety ─────────────────────────────────────────────────────────────
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ── Config ─────────────────────────────────────────────────────────────────────
TARGET      = "https://www.mandarinrestaurant.com/"
ROOT        = Path(__file__).resolve().parent
CASECRACK   = ROOT / "CaseCrack"
HTTP_PORT   = 8770
WS_PORT     = 8771
MAX_PARALLEL_SLOTS = 5
MAX_MONITOR_HOURS  = 6      # safety cap

BASE        = f"http://localhost:{HTTP_PORT}"
LOG_FILE    = "_mandarin_console.log"
ISSUE_FILE  = "_mandarin_issues.txt"
SUMMARY_FILE= "_mandarin_summary.txt"

# ── Issue detection ────────────────────────────────────────────────────────────
ISSUE_KEYWORDS = [
    "traceback", "exception", "attributeerror", "typeerror",
    "valueerror", "keyerror", "importerror", "filenotfounderror",
    "oserror", "runtimeerror", "indexerror", "nameerror",
    "modulenotfounderror", "syntaxerror", "permissionerror",
    "failed", "failure", "degraded", "crash", "fatal",
    "unrecognized arguments", "no such file", "cannot", "unable to",
    "timed out", "connection refused", "connection error",
    "ssl error", "no module named", "broken pipe", "broken_pipe",
    "no cli handler", "unicodedecodeerror",
    "got an unexpected keyword argument", "is not a valid",
    "object has no attribute", "unexpected error",
]
ISSUE_KEYWORDS_EXACT = [
    "error", "failed", "timeout", "warning", "missing",
    "abort", "warn",
]

# Lines matching these are NOT issues
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
    '"warning_count": 0',
    '"warnings": []',
    '"status": "skipped"',
    "polling for oob interactions",
    "polling for callbacks",
    "soft-timeout",
    "soft limit",
    "tests queued",
    "skipped tests",
    "skipped (",
    "docker info --format",
    "nuclei binary not found",
    "droopescan not installed",
    "grpc port 50051",
    "url dorking 480s",
    "dns brute-force 10s",
    "waf/rate-limit",
    "passive observation",
    "cdn_challenge",
    "http 429",
    "http 403",
    "port 8080 is closed",
    "zap sidecar not running",
    "mitmproxy sidecar not running",
    "stale production build",
    "fix-84", "fix-86", "fix-151",
    "baseline responses differ",
    "no clear majority",
    "confidence: 80% │ source: graphql",
    "│ source: graphql │",
    # Exploit graph JSON fields (emitted to stderr, zero-failure data)
    '"failure_count": 0',
    '"last_failure_at": null',
    # Common informational patterns
    "42 tests queued",
    "skipped tests (6)",
    "polling for oob",
    "polling for callbacks",
]


def api(path: str, method: str = "GET", body: dict | None = None,
        token: str = "") -> dict | None:
    headers: dict = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
        req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    else:
        req = urllib.request.Request(BASE + path, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode(errors="replace")[:300]
        return {"_http_error": e.code, "_body": body_text}
    except Exception as exc:
        return {"_exc": str(exc)}


def is_issue(text: str) -> bool:
    low = text.lower()
    for fp in FALSE_POSITIVE_PATTERNS:
        if fp.lower() in low:
            return False
    if any(kw in low for kw in ISSUE_KEYWORDS):
        return True
    for kw in ISSUE_KEYWORDS_EXACT:
        if re.search(r'\b' + re.escape(kw) + r'\b', low):
            return True
    return False


def ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def wait_for_health(port: int, timeout: float = 60.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"http://localhost:{port}/health", timeout=2.0) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    print("=" * 68)
    print(f"  CaseCrack Full 46-Phase Parallel Recon")
    print(f"  Target : {TARGET}")
    print(f"  Started: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 68)

    # ── 0. Kill any leftover dashboard process on the port ─────────────────────
    print(f"[{ts()}] Checking for existing process on port {HTTP_PORT} ...", flush=True)
    kill_result = os.popen(
        f'for /f "tokens=5" %a in (\'netstat -ano ^| findstr ":{HTTP_PORT}"\') do taskkill /PID %a /F 2>nul'
    ).read().strip()
    if kill_result:
        print(f"[{ts()}] Killed old process: {kill_result}", flush=True)
        time.sleep(2)
    else:
        print(f"[{ts()}] No existing process on port {HTTP_PORT}", flush=True)

    # ── 1. Start dashboard ────────────────────────────────────────────────────
    env = os.environ.copy()
    pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(CASECRACK) + (os.pathsep + pp if pp else "")

    dashboard_cmd = [
        sys.executable, "-c",
        (
            "import sys; sys.path.insert(0,'CaseCrack'); "
            "from tools.burp_enterprise.recon_dashboard import ReconDashboard; "
            f"d = ReconDashboard("
            f"    target_url='{TARGET}',"
            f"    http_port={HTTP_PORT},"
            f"    ws_port={WS_PORT},"
            f"    auto_open=False,"
            f"    parallel=True,"
            f"    max_parallel_slots={MAX_PARALLEL_SLOTS},"
            ");"
            "d.start()"
        ),
    ]

    stdout_log = open(ROOT / "dashboard_stdout.log", "w", encoding="utf-8")
    stderr_log = open(ROOT / "dashboard_stderr.log", "w", encoding="utf-8")

    proc = subprocess.Popen(
        dashboard_cmd,
        stdout=stdout_log,
        stderr=stderr_log,
        cwd=str(ROOT),
        env=env,
    )
    print(f"[{ts()}] Dashboard PID {proc.pid} started", flush=True)
    print(f"[{ts()}] Waiting for server on port {HTTP_PORT} ...", flush=True)

    if not wait_for_health(HTTP_PORT, timeout=60.0):
        print(f"[{ts()}] ERROR: Dashboard did not start within 60s — check dashboard_stderr.log", flush=True)
        proc.terminate()
        stdout_log.close()
        stderr_log.close()
        sys.exit(1)

    print(f"[{ts()}] Dashboard healthy at http://localhost:{HTTP_PORT}", flush=True)
    time.sleep(1)  # brief settle

    # ── 2. Fetch auth token ───────────────────────────────────────────────────
    token = ""
    tok_resp = api("/api/token")
    if tok_resp and "token" in tok_resp:
        token = tok_resp["token"]
        masked = token[:8] + "..." + token[-4:]
        print(f"[{ts()}] Auth token: {masked}", flush=True)
    else:
        print(f"[{ts()}] Note: no auth token or fetch failed: {tok_resp}", flush=True)

    # ── 3. Start the full parallel scan ───────────────────────────────────────
    print(f"[{ts()}] Starting full parallel scan against {TARGET} ...", flush=True)

    # Try /api/standalone/run first (the canonical parallel-run endpoint)
    run_resp = api("/api/standalone/run", method="POST",
                   body={"target": TARGET, "parallel": True,
                         "max_parallel_slots": MAX_PARALLEL_SLOTS},
                   token=token)
    print(f"[{ts()}] /api/standalone/run response: {run_resp}", flush=True)

    # If that fails or scan already running, try /api/scan/start
    if not run_resp or ("_exc" in run_resp and "already" not in str(run_resp).lower()):
        start_resp = api("/api/scan/start", method="POST",
                         body={"target": TARGET}, token=token)
        print(f"[{ts()}] /api/scan/start response: {start_resp}", flush=True)

    # ── 4. Monitor loop ───────────────────────────────────────────────────────
    print(f"[{ts()}] Monitor running (max {MAX_MONITOR_HOURS}h). Ctrl+C to stop.", flush=True)
    print(f"[{ts()}] Full log   -> {LOG_FILE}", flush=True)
    print(f"[{ts()}] Issues     -> {ISSUE_FILE}", flush=True)
    print(flush=True)

    since = 0
    issues: list = []
    phase_issues: defaultdict = defaultdict(list)
    seen_ids: set = set()
    consecutive_complete = 0
    deadline_mono = time.monotonic() + MAX_MONITOR_HOURS * 3600
    poll_interval = 3.0

    errors_total        = 0
    warnings_total      = 0
    console_error_lines = 0
    all_console_lines   = 0
    phase_completion_events: list = []

    with open(ROOT / LOG_FILE, "w", encoding="utf-8") as log_fh, \
         open(ROOT / ISSUE_FILE, "w", encoding="utf-8") as issue_fh:

        issue_fh.write(
            f"=== Mandarin Restaurant Scan Issue Report ===\n"
            f"=== Target: {TARGET} ===\n"
            f"=== Started: {datetime.now(timezone.utc).isoformat()} ===\n\n"
        )
        issue_fh.flush()

        while time.monotonic() < deadline_mono:
            # ── Poll console feed ─────────────────────────────────────────
            try:
                data = api(f"/api/standalone/console?limit=500&since={since}",
                           token=token)
            except Exception as exc:
                print(f"[{ts()}] Console fetch error: {exc}", flush=True)
                time.sleep(poll_interval)
                continue

            if not data or "_exc" in data:
                time.sleep(poll_interval)
                continue

            lines = data.get("lines", data.get("entries", []))
            next_since = data.get("next_since", since)

            for line in lines:
                # Build a dedup key
                uid = "{}-{}-{}".format(
                    line.get("ts", 0),
                    line.get("phase", ""),
                    (line.get("text", "") or "")[:50],
                )
                if uid in seen_ids:
                    continue
                seen_ids.add(uid)

                phase  = line.get("phase", "")
                stream = line.get("stream", "")
                text   = (line.get("text", "") or line.get("message", "") or "")
                level  = (line.get("level", "") or "").upper()

                # Write raw NDJSON to full log
                log_fh.write(json.dumps(line) + "\n")
                all_console_lines += 1

                # stderr — always print + flag
                if stream == "stderr":
                    print(f"[{ts()}] [STDERR][{phase}] {text[:180]}", flush=True)
                    if is_issue(text):
                        rec = {"phase": phase, "stream": stream, "text": text}
                        issues.append(rec)
                        phase_issues[phase].append(text)
                        issue_fh.write(f"[{phase}] [stderr] {text}\n")
                        issue_fh.flush()
                        console_error_lines += 1

                # phase_complete events
                elif line.get("type") == "phase_complete":
                    outcome = line.get("outcome", "")
                    phase_completion_events.append({"phase": phase, "outcome": outcome})
                    status_icon = {"ok": "[OK]", "degraded": "[DEGRADED]",
                                   "error": "[ERROR]", "timeout": "[TIMEOUT]",
                                   "skipped": "[SKIP]"}.get(outcome, f"[{outcome}]")
                    print(f"[{ts()}] {status_icon} Phase complete: {phase} ({outcome})", flush=True)
                    if outcome in ("degraded", "error", "timeout", "failed"):
                        msg = f"Phase {outcome.upper()}: {phase}"
                        issues.append({"phase": phase, "stream": "phase_complete", "text": msg})
                        phase_issues[phase].append(msg)
                        issue_fh.write(f"[{phase}] [phase_complete] {msg}\n")
                        issue_fh.flush()

                # warn/error level — always surface
                elif level in ("ERROR", "WARNING", "WARN", "CRITICAL"):
                    print(f"[{ts()}] [{level}][{phase}] {text[:160]}", flush=True)
                    if level in ("ERROR", "CRITICAL"):
                        errors_total += 1
                    elif level in ("WARNING", "WARN"):
                        warnings_total += 1
                    if is_issue(text):
                        rec = {"phase": phase, "stream": level, "text": text}
                        issues.append(rec)
                        phase_issues[phase].append(text)
                        issue_fh.write(f"[{phase}] [{level}] {text}\n")
                        issue_fh.flush()
                        console_error_lines += 1

                # cmd stream — print for visibility
                elif stream == "cmd":
                    print(f"[{ts()}] [CMD][{phase}] {text[:160]}", flush=True)

                # info/log — only print if flagged as issue
                elif is_issue(text):
                    lvl_tag = level or stream or "log"
                    print(f"[{ts()}] [ISSUE/{lvl_tag}][{phase}] {text[:160]}", flush=True)
                    rec = {"phase": phase, "stream": lvl_tag, "text": text}
                    issues.append(rec)
                    phase_issues[phase].append(text)
                    issue_fh.write(f"[{phase}] [{lvl_tag}] {text}\n")
                    issue_fh.flush()
                    console_error_lines += 1

            if next_since and next_since > since:
                since = next_since

            log_fh.flush()

            # ── Poll scan status ──────────────────────────────────────────
            try:
                status = api("/api/standalone/status", token=token)
                if not status or "_exc" in status:
                    status = api("/api/scan/status", token=token)
            except Exception as exc:
                print(f"[{ts()}] Status fetch error: {exc}", flush=True)
                time.sleep(poll_interval)
                continue

            if not status or "_exc" in status:
                time.sleep(poll_interval)
                continue

            is_complete  = status.get("is_complete", False)
            completed    = status.get("completed_phases", status.get("phases_completed", 0))
            phase_status = status.get("phase_status", {})
            total        = len(phase_status) or status.get("total_phases", status.get("phases_total", 46))
            findings_cnt = status.get("findings_count", 0)
            current      = status.get("current_phase", "")
            running_ph   = status.get("running_phases", [])

            # Detect newly degraded/error phases from status map
            for ph, st in phase_status.items():
                if st in ("degraded", "error", "failed", "timeout"):
                    uid2 = f"STATUS-{st}-{ph}"
                    if uid2 not in seen_ids:
                        seen_ids.add(uid2)
                        msg = f"Phase status={st.upper()}: {ph}"
                        issues.append({"phase": ph, "stream": "status", "text": msg})
                        phase_issues[ph].append(msg)
                        issue_fh.write(f"[{ph}] [status] {msg}\n")
                        issue_fh.flush()
                        print(f"[{ts()}] *** {msg} ***", flush=True)

            running_disp = ", ".join(running_ph[:4]) if running_ph else current
            print(
                f"[{ts()}] Progress: {completed}/{total} phases"
                f" | findings={findings_cnt}"
                + (f" | running=[{running_disp}]" if running_disp else ""),
                flush=True,
            )

            # Only treat as complete if scan is NOT running and is_complete is True
            actually_complete = is_complete and not status.get("running", True) and not running_ph
            if actually_complete:
                consecutive_complete += 1
                if consecutive_complete >= 2:
                    print(f"\n[{ts()}] === SCAN COMPLETE ===", flush=True)
                    break
            else:
                consecutive_complete = 0

            time.sleep(poll_interval)

    # ── Final summary ──────────────────────────────────────────────────────────
    print(f"\n{'='*68}", flush=True)
    print(f"SCAN COMPLETE — ISSUE SUMMARY", flush=True)
    print(f"{'='*68}", flush=True)
    print(f"  Total issues detected  : {len(issues)}", flush=True)
    print(f"  Errors (log level)     : {errors_total}", flush=True)
    print(f"  Warnings (log level)   : {warnings_total}", flush=True)
    print(f"  Console error lines    : {console_error_lines}", flush=True)
    print(f"  Total console lines    : {all_console_lines}", flush=True)

    if not issues:
        print("  No issues detected!", flush=True)
    else:
        for phase, msgs in sorted(phase_issues.items()):
            print(f"\n  [{phase}] — {len(msgs)} issue(s):", flush=True)
            for m in msgs[:6]:
                print(f"    • {m[:130]}", flush=True)
            if len(msgs) > 6:
                print(f"    ... and {len(msgs)-6} more", flush=True)

    # Write summary file
    with open(ROOT / SUMMARY_FILE, "w", encoding="utf-8") as sf:
        sf.write(f"{'='*80}\n")
        sf.write(f"FULL 46-PHASE PARALLEL RECON — {TARGET}\n")
        sf.write(f"Run completed : {datetime.now(timezone.utc).isoformat()}\n")
        sf.write(f"{'='*80}\n\n")
        sf.write(f"TOTAL ERRORS          : {errors_total}\n")
        sf.write(f"TOTAL WARNINGS        : {warnings_total}\n")
        sf.write(f"CONSOLE ERROR LINES   : {console_error_lines}\n")
        sf.write(f"TOTAL CONSOLE LINES   : {all_console_lines}\n\n")

        sf.write("── PHASE COMPLETION STATUS ──\n")
        for evt in phase_completion_events:
            sf.write(f"  {evt['phase']:50s}  {evt['outcome']}\n")
        if not phase_completion_events:
            sf.write("  (no phase completion events received via console — check status API)\n")

        sf.write("\n── ISSUES BY PHASE ──\n")
        if not issues:
            sf.write("  None.\n")
        else:
            for ph, msgs in sorted(phase_issues.items()):
                sf.write(f"\n[{ph}] ({len(msgs)} issues):\n")
                for m in msgs:
                    sf.write(f"  • {m[:200]}\n")

    print(f"\n[{ts()}] Full log   : {LOG_FILE}", flush=True)
    print(f"[{ts()}] Issues     : {ISSUE_FILE}", flush=True)
    print(f"[{ts()}] Summary    : {SUMMARY_FILE}", flush=True)

    # Keep dashboard alive for browsing results
    print(f"\n[{ts()}] Dashboard still running at http://localhost:{HTTP_PORT}", flush=True)
    print(f"[{ts()}] Press Ctrl+C to stop the dashboard.", flush=True)
    try:
        proc.wait()
    except KeyboardInterrupt:
        print(f"\n[{ts()}] Stopping dashboard ...", flush=True)
        proc.terminate()
        proc.wait(timeout=10)
    finally:
        stdout_log.close()
        stderr_log.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n[Interrupted]", flush=True)
        sys.exit(0)
