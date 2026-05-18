#!/usr/bin/env python3
"""
Full 31-Phase Parallel Recon Monitor
Launches all phases in parallel mode against sugarrushed.ca,
captures every error/failure/warning, and writes a comprehensive log.
"""

import json
import os
import sys
import time
import threading
import traceback
import urllib.request
import urllib.error
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone

TARGET = "https://sugarrushed.ca"
BASE_URL = "http://localhost:8770"
TOKEN = "OCNU6wFZZhLYle9cdX4K_5Nlrj_yUT84GPMD3B1v4no"
HEADERS_JSON = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {TOKEN}",
}
HEADERS_GET = {"Authorization": f"Bearer {TOKEN}"}

LOG_FILE = os.path.join(os.path.dirname(__file__), "_parallel_recon_log.jsonl")
SUMMARY_FILE = os.path.join(os.path.dirname(__file__), "_parallel_recon_summary.txt")

# Tracking
errors = []
warnings = []
phase_errors = defaultdict(list)
phase_status = {}
console_lines = []
lock = threading.Lock()


def log(msg: str, level: str = "INFO"):
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)


def api_get(path: str):
    url = BASE_URL + path
    req = urllib.request.Request(url, headers=HEADERS_GET)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def api_post(path: str, data: dict):
    url = BASE_URL + path
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers=HEADERS_JSON, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def record_event(event: dict):
    """Record event to JSONL log file."""
    with lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

        etype = event.get("type", "")
        
        # Capture errors
        if etype in ("error", "phase_error", "command_error", "command_failed"):
            msg = event.get("message") or event.get("error") or event.get("detail") or str(event)
            phase = event.get("phase", event.get("category", "unknown"))
            errors.append({"phase": phase, "type": etype, "msg": msg, "event": event})
            phase_errors[phase].append(msg)
            log(f"ERROR [{phase}]: {msg[:200]}", "ERROR")

        # Capture warnings
        elif etype == "log" and event.get("level") in ("warning", "warn", "error", "critical"):
            msg = event.get("message", "")
            phase = event.get("phase", "system")
            warnings.append({"phase": phase, "msg": msg})
            log(f"WARN [{phase}]: {msg[:150]}", "WARN")

        # Capture console lines with errors/warnings
        elif etype in ("console_output", "console_batch"):
            lines = event.get("lines", [])
            if not lines and "text" in event:
                lines = [event]
            for line in lines:
                text = line.get("text", "")
                level = line.get("level", "info")
                phase = line.get("phase", "")
                if level in ("error", "warn", "warning", "critical") or \
                   any(kw in text.lower() for kw in ["error", "fail", "exception", "traceback", "timeout", "abort", "crash", "killed"]):
                    entry = {"phase": phase, "level": level, "text": text}
                    console_lines.append(entry)
                    if level in ("error", "critical") or "error" in text.lower() or "fail" in text.lower():
                        phase_errors[phase].append(text)
                        log(f"CONSOLE [{phase}] {level.upper()}: {text[:200]}", "ERROR")

        # Phase completion tracking
        elif etype == "phase_complete":
            phase = event.get("phase", "")
            status = event.get("status", "")
            phase_status[phase] = {"status": status, "event": event}
            if status in ("error", "failed", "timeout", "aborted"):
                phase_errors[phase].append(f"Phase completed with status={status}")
                log(f"PHASE FAIL [{phase}]: status={status}", "ERROR")
            else:
                log(f"Phase complete [{phase}]: status={status}", "INFO")

        elif etype == "phase_start":
            phase = event.get("phase", "")
            log(f"Phase started: {phase}", "INFO")

        elif etype == "preflight":
            checks = event.get("checks", [])
            for check in checks:
                if check.get("status") != "ok":
                    msg = f"Preflight FAIL: {check.get('name')}: {check.get('detail', '')}"
                    errors.append({"phase": "preflight", "type": "preflight_fail", "msg": msg})
                    log(msg, "ERROR")

        elif etype == "command_result":
            if event.get("exit_code", 0) != 0 or event.get("status") == "error":
                phase = event.get("phase", event.get("category", "unknown"))
                cmd = event.get("command", event.get("tool", ""))
                ec = event.get("exit_code", "?")
                msg = f"Command failed (exit={ec}): {cmd}"
                errors.append({"phase": phase, "type": "command_result_fail", "msg": msg})
                phase_errors[phase].append(msg)
                log(f"CMD FAIL [{phase}]: {msg[:200]}", "ERROR")


def poll_state():
    """Poll /api/status for full state snapshot including phase results."""
    consecutive_errors = 0
    last_phase_statuses = {}
    while not stop_event.is_set():
        try:
            data = api_get("/api/status")
            # Check phase results for errors
            phases = data.get("phases", [])
            for phase in phases:
                name = phase.get("name", "")
                status = phase.get("status", "")
                prev_status = last_phase_statuses.get(name)
                if status != prev_status:
                    last_phase_statuses[name] = status
                    if status in ("error", "failed", "timeout", "aborted"):
                        msg = f"Phase '{name}' status={status}"
                        with lock:
                            errors.append({"phase": name, "type": "phase_status", "msg": msg})
                            phase_errors[name].append(msg)
                        log(f"PHASE ERROR [{name}]: {status}", "ERROR")
                    elif status == "complete":
                        log(f"Phase complete: {name}", "INFO")

            # Check for scan-level error messages
            scan_errors = data.get("errors", [])
            for err in scan_errors:
                phase = err.get("phase", "system")
                msg = err.get("message", str(err))
                entry = {"phase": phase, "type": "scan_error", "msg": msg, "event": err}
                with lock:
                    if entry not in errors:
                        errors.append(entry)
                        phase_errors[phase].append(msg)
                log(f"SCAN ERROR [{phase}]: {msg[:200]}", "ERROR")

            consecutive_errors = 0
        except Exception as exc:
            consecutive_errors += 1
            if consecutive_errors % 10 == 1:
                log(f"State poll error: {exc}", "WARN")
        time.sleep(3.0)


def poll_status():
    """Poll /api/scan/status for phase-level progress."""
    last_completed = 0
    while not stop_event.is_set():
        try:
            data = api_get("/api/scan/status")
            running = data.get("scan_running", False)
            completed = data.get("phases_completed", 0)
            total = data.get("phases_total", 0)
            
            if completed != last_completed:
                log(f"Progress: {completed}/{total} phases complete", "INFO")
                last_completed = completed
            
            if not running and total > 0:
                log(f"Scan finished! {completed}/{total} phases complete", "INFO")
                stop_event.set()
                break

        except Exception as exc:
            log(f"Status poll error: {exc}", "WARN")
        time.sleep(5.0)


def poll_console():
    """Poll /api/standalone/console for raw console output."""
    seq = 0
    seen_seqs = set()
    while not stop_event.is_set():
        try:
            data = api_get(f"/api/standalone/console?since={seq}&limit=500")
            lines = data.get("lines", [])
            for line in lines:
                text = line.get("text", "")
                level = line.get("level", "info")
                phase = line.get("phase", "")
                s = line.get("seq", 0)
                if s:
                    if s in seen_seqs:
                        continue
                    seen_seqs.add(s)
                    if s > seq:
                        seq = s
                # Write ALL console lines to the log file
                record_event({"type": "console_line", "phase": phase, "level": level, "text": text, "seq": s})
                # Capture error/warning lines for summary
                if level in ("error", "warn", "warning", "critical") or \
                   any(kw in text.lower() for kw in ["error:", " error ", "failed:", "exception:", "traceback", "timeout", "abort", "killed"]):
                    entry = {"phase": phase, "level": level, "text": text, "seq": s}
                    with lock:
                        if entry not in console_lines:
                            console_lines.append(entry)
                    if level in ("error", "critical"):
                        log(f"CONSOLE [{phase}]: {text[:200]}", "ERROR")
        except Exception as exc:
            pass
        time.sleep(2.0)


def write_summary():
    """Write comprehensive summary of all issues found."""
    lines = []
    lines.append("=" * 80)
    lines.append("FULL 31-PHASE PARALLEL RECON PIPELINE - ISSUE SUMMARY")
    lines.append(f"Target: {TARGET}")
    lines.append(f"Completed: {datetime.now(timezone.utc).isoformat()}")
    lines.append("=" * 80)
    lines.append("")

    # Overall stats
    lines.append(f"TOTAL ERRORS CAPTURED: {len(errors)}")
    lines.append(f"TOTAL WARNINGS CAPTURED: {len(warnings)}")
    lines.append(f"TOTAL CONSOLE ERROR LINES: {len(console_lines)}")
    lines.append(f"PHASES WITH ERRORS: {len(phase_errors)}")
    lines.append("")

    # Phase completion status
    lines.append("── PHASE COMPLETION STATUS ──")
    if phase_status:
        for phase, info in sorted(phase_status.items()):
            status = info.get("status", "?")
            lines.append(f"  {phase}: {status}")
    else:
        lines.append("  (No phase completion events captured)")
    lines.append("")

    # Errors by phase
    lines.append("── ERRORS BY PHASE ──")
    if phase_errors:
        for phase, errs in sorted(phase_errors.items()):
            lines.append(f"\n  [{phase}] ({len(errs)} errors)")
            for err in errs[:20]:  # Cap at 20 per phase
                lines.append(f"    • {err[:300]}")
    else:
        lines.append("  No phase errors captured.")
    lines.append("")

    # Global errors list
    lines.append("── ALL ERRORS (chronological) ──")
    if errors:
        for i, err in enumerate(errors, 1):
            lines.append(f"\n  [{i}] Phase={err.get('phase','?')} Type={err.get('type','?')}")
            lines.append(f"      {err.get('msg','')[:400]}")
    else:
        lines.append("  No errors captured.")
    lines.append("")

    # Warnings
    lines.append("── WARNINGS ──")
    if warnings:
        for w in warnings[:50]:
            lines.append(f"  [{w.get('phase','?')}] {w.get('msg','')[:300]}")
    else:
        lines.append("  No warnings captured.")
    lines.append("")

    # Console error lines
    lines.append("── CONSOLE ERRORS / FAILURES ──")
    if console_lines:
        for cl in console_lines[:100]:
            lines.append(f"  [{cl.get('phase','?')}] ({cl.get('level','info').upper()}) {cl.get('text','')[:300]}")
    else:
        lines.append("  No console error lines captured.")

    summary = "\n".join(lines)
    with open(SUMMARY_FILE, "w", encoding="utf-8") as f:
        f.write(summary)
    print("\n" + summary)
    return summary


def main():
    global stop_event
    stop_event = threading.Event()

    log("Starting full 31-phase parallel recon monitor")
    log(f"Target: {TARGET}")

    # Clear previous log
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)

    # Verify dashboard is reachable
    try:
        status = api_get("/api/scan/status")
        if status.get("scan_running"):
            log("WARNING: A scan is already running!", "WARN")
    except Exception as exc:
        log(f"Dashboard not reachable: {exc}", "ERROR")
        sys.exit(1)

    # Start background monitoring threads
    t_state = threading.Thread(target=poll_state, daemon=True)
    t_status = threading.Thread(target=poll_status, daemon=True)
    t_console = threading.Thread(target=poll_console, daemon=True)
    t_state.start()
    t_status.start()
    t_console.start()

    # Launch the scan via API
    log("Launching full 31-phase PARALLEL scan via API...", "INFO")
    try:
        result = api_post("/api/scan/start", {
            "target": TARGET,
            # No "phases" key = all 31 phases
        })
        log(f"Scan start response: {result}", "INFO")
        if not result.get("ok"):
            log(f"Scan failed to start: {result.get('error', '?')}", "ERROR")
            errors.append({"phase": "startup", "type": "start_fail", "msg": str(result)})
    except Exception as exc:
        log(f"Failed to start scan: {exc}", "ERROR")
        traceback.print_exc()
        errors.append({"phase": "startup", "type": "exception", "msg": str(exc)})

    # Wait for scan to complete (with periodic progress updates)
    log("Monitoring scan (Ctrl+C to stop early and get summary)...")
    MAX_WAIT = 7200  # 2 hours max
    start_time = time.time()
    
    try:
        while not stop_event.is_set():
            elapsed = time.time() - start_time
            if elapsed > MAX_WAIT:
                log(f"Max wait time ({MAX_WAIT}s) exceeded, stopping monitor", "WARN")
                stop_event.set()
                break
            time.sleep(5)
    except KeyboardInterrupt:
        log("Interrupted by user - generating summary...", "WARN")
        stop_event.set()

    time.sleep(3)  # Let final events drain

    # Check final status
    try:
        final_status = api_get("/api/scan/status")
        log(f"Final status: {final_status}", "INFO")
    except Exception:
        pass

    # Write summary
    log("Generating comprehensive issue summary...", "INFO")
    write_summary()
    log(f"Summary written to: {SUMMARY_FILE}", "INFO")
    log(f"Full event log written to: {LOG_FILE}", "INFO")


if __name__ == "__main__":
    main()
