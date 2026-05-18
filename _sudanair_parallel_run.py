#!/usr/bin/env python3
"""
Full 40+ Phase Parallel Recon Monitor for sudanair.com
Captures ALL console output, errors, failures, and warnings.
"""

import json
import os
import sys
import time
import threading
import urllib.request
import urllib.error
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone

TARGET = "https://www.sudanair.com/"
BASE_URL = "http://localhost:8770"
TOKEN = "Z0X9gA6vOKlUn-exULaut4J-AIxFr3uOsGi2pf1mTfg"
HEADERS_JSON = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {TOKEN}",
}
HEADERS_GET = {"Authorization": f"Bearer {TOKEN}"}

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_sudanair_run_log.jsonl")
CONSOLE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_sudanair_console.txt")
SUMMARY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_sudanair_summary.txt")

# Clear previous run logs
for f in [LOG_FILE, CONSOLE_FILE, SUMMARY_FILE]:
    if os.path.exists(f):
        os.remove(f)

# Tracking
errors = []
warnings = []
phase_errors = defaultdict(list)
phase_status = {}
console_lines = []
findings_count = 0
phases_started = set()
phases_completed = set()
phases_failed = set()
lock = threading.Lock()


def ts():
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def log(msg: str, level: str = "INFO"):
    line = f"[{ts()}] [{level}] {msg}"
    print(line, flush=True)
    with lock:
        with open(CONSOLE_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")


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
    global findings_count
    with lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

    etype = event.get("type", "")
    phase = event.get("phase", event.get("category", event.get("phase_name", "unknown")))

    # Phase lifecycle
    if etype == "phase_start":
        with lock:
            phases_started.add(phase)
        log(f"PHASE START: {phase}", "PHASE")

    elif etype in ("phase_complete", "phase_done"):
        with lock:
            phases_completed.add(phase)
        duration = event.get("duration_s", event.get("elapsed", "?"))
        log(f"PHASE DONE: {phase} [{duration}s]", "PHASE")

    elif etype == "phase_error":
        msg = event.get("message") or event.get("error") or str(event)
        with lock:
            phases_failed.add(phase)
            errors.append({"phase": phase, "type": etype, "msg": msg, "event": event})
            phase_errors[phase].append(msg)
        log(f"PHASE ERROR [{phase}]: {msg[:300]}", "ERROR")

    # Findings
    elif etype == "finding":
        with lock:
            findings_count += 1
        title = event.get("title", event.get("name", ""))
        sev = event.get("severity", event.get("risk", ""))
        log(f"FINDING [{sev}] {title[:100]}", "FIND")

    # Command errors
    elif etype in ("error", "command_error", "command_failed", "tool_error"):
        msg = event.get("message") or event.get("error") or event.get("detail") or str(event)
        with lock:
            errors.append({"phase": phase, "type": etype, "msg": msg, "event": event})
            phase_errors[phase].append(msg)
        log(f"ERROR [{phase}]: {msg[:250]}", "ERROR")

    # Warnings
    elif etype == "log" and event.get("level") in ("warning", "warn", "error", "critical"):
        msg = event.get("message", "")
        with lock:
            warnings.append({"phase": phase, "msg": msg})
        log(f"WARN [{phase}]: {msg[:200]}", "WARN")

    # Console output - capture errors/warnings
    elif etype in ("console_output", "console_batch"):
        lines = event.get("lines", [])
        if not lines and "text" in event:
            lines = [event]
        for line in lines:
            text = line.get("text", "") if isinstance(line, dict) else str(line)
            lvl = (line.get("level", "info") if isinstance(line, dict) else "info").lower()
            ph = (line.get("phase", phase) if isinstance(line, dict) else phase)
            is_err = lvl in ("error", "critical") or any(
                kw in text.lower() for kw in
                ["error", "fail", "exception", "traceback", "timeout", "abort", "crash", "killed", "refused", "denied"]
            )
            is_warn = lvl in ("warn", "warning") or any(
                kw in text.lower() for kw in ["warn", "timeout", "retry", "skip", "unavailable", "missing"]
            )
            if is_err:
                entry = {"phase": ph, "level": lvl, "text": text}
                with lock:
                    console_lines.append(entry)
                    phase_errors[ph].append(text)
                log(f"CONSOLE ERR [{ph}]: {text[:250]}", "ERROR")
            elif is_warn:
                entry = {"phase": ph, "level": lvl, "text": text}
                with lock:
                    console_lines.append(entry)
                log(f"CONSOLE WARN [{ph}]: {text[:200]}", "WARN")

    # Scan complete
    elif etype in ("scan_complete", "scan_done", "run_complete"):
        log(f"SCAN COMPLETE: {event}", "DONE")

    # Scan error
    elif etype == "scan_error":
        msg = event.get("message") or event.get("error") or str(event)
        with lock:
            errors.append({"phase": "scan", "type": etype, "msg": msg, "event": event})
        log(f"SCAN ERROR: {msg[:300]}", "ERROR")


def poll_events(last_seq: int) -> tuple[list, int]:
    """Poll for new events since last_seq."""
    try:
        data = api_get(f"/api/events?since={last_seq}&limit=200")
        events = data.get("events", [])
        new_seq = data.get("seq", last_seq)
        return events, new_seq
    except Exception as e:
        log(f"Poll error: {e}", "WARN")
        return [], last_seq


def main():
    log("=" * 70, "INFO")
    log(f"SUDANAIR.COM FULL PARALLEL RECON RUN", "INFO")
    log(f"Target: {TARGET}", "INFO")
    log(f"Dashboard: {BASE_URL}", "INFO")
    log("=" * 70, "INFO")

    # Step 1: Start (or verify) parallel scan via correct endpoint
    log("Starting full parallel scan...", "INFO")
    try:
        r = api_post("/api/standalone/run", {
            "target_url": TARGET,
            "parallel": True,
        })
        log(f"Scan start response: {r}", "INFO")
        if not r.get("ok"):
            log(f"Scan start warning: {r}", "WARN")
    except Exception as e:
        log(f"Scan start error (may already be running): {e}", "WARN")

    # Step 3: Poll events until scan completes or timeout
    log("Polling events...", "INFO")
    last_seq = 0
    scan_done = False
    start_time = time.time()
    MAX_RUNTIME = 7200  # 2 hours max
    idle_since = time.time()
    MAX_IDLE = 600  # 10 min idle = done

    while not scan_done and (time.time() - start_time) < MAX_RUNTIME:
        events, last_seq = poll_events(last_seq)
        
        if events:
            idle_since = time.time()
            for ev in events:
                record_event(ev)
                etype = ev.get("type", "")
                if etype in ("scan_complete", "scan_done", "run_complete", "runner_complete"):
                    scan_done = True
        
        # Check scan status
        try:
            status = api_get("/api/status")
            is_complete = status.get("is_complete", False)
            completed = status.get("completed_phases", 0)
            total = status.get("total_phases", 0)
            current = status.get("current_phase", "")
            running = status.get("running_phases", [])
            if is_complete and completed > 0:
                scan_done = True
                log(f"Scan complete: {completed}/{total} phases done", "INFO")
        except Exception:
            pass

        # Idle timeout
        if time.time() - idle_since > MAX_IDLE:
            log(f"No new events for {MAX_IDLE}s — assuming scan complete", "INFO")
            scan_done = True

        if not scan_done:
            elapsed = int(time.time() - start_time)
            try:
                status = api_get("/api/status")
                completed = status.get("completed_phases", 0)
                total = status.get("total_phases", 0)
                running = status.get("running_phases", [])
                current = status.get("current_phase", "")
                running_str = f" | running: {running}" if running else (f" | current: {current}" if current else "")
                log(f"Running... {elapsed}s | {completed}/{total} phases | "
                    f"{findings_count} findings | {len(errors)} errors{running_str}", "STATUS")
            except Exception:
                log(f"Running... {elapsed}s elapsed | {len(phases_completed)} phases done | "
                    f"{findings_count} findings | {len(errors)} errors", "STATUS")
            time.sleep(5)

    # Final status
    elapsed_total = int(time.time() - start_time)
    log("=" * 70, "INFO")
    log(f"RUN COMPLETE — Total time: {elapsed_total}s", "INFO")
    log(f"Phases started:   {len(phases_started)}", "INFO")
    log(f"Phases completed: {len(phases_completed)}", "INFO")
    log(f"Phases failed:    {len(phases_failed)}", "INFO")
    log(f"Total findings:   {findings_count}", "INFO")
    log(f"Total errors:     {len(errors)}", "INFO")
    log(f"Total warnings:   {len(warnings)}", "INFO")
    log("=" * 70, "INFO")

    # Write summary
    with open(SUMMARY_FILE, "w", encoding="utf-8") as f:
        f.write(f"SUDANAIR.COM PARALLEL RECON SUMMARY\n")
        f.write(f"Generated: {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"Target: {TARGET}\n")
        f.write(f"Elapsed: {elapsed_total}s\n")
        f.write(f"Phases started: {len(phases_started)}\n")
        f.write(f"Phases completed: {len(phases_completed)}\n")
        f.write(f"Phases failed: {len(phases_failed)}\n")
        f.write(f"Total findings: {findings_count}\n")
        f.write(f"Total errors: {len(errors)}\n")
        f.write(f"Total warnings: {len(warnings)}\n\n")

        if phases_failed:
            f.write("\n=== FAILED PHASES ===\n")
            for p in sorted(phases_failed):
                f.write(f"  - {p}\n")

        if errors:
            f.write(f"\n=== ERRORS ({len(errors)}) ===\n")
            for i, e in enumerate(errors[:100], 1):
                f.write(f"\n[{i}] Phase: {e['phase']} | Type: {e['type']}\n")
                f.write(f"    {e['msg'][:500]}\n")

        if warnings:
            f.write(f"\n=== WARNINGS ({len(warnings)}) ===\n")
            for i, w in enumerate(warnings[:50], 1):
                f.write(f"[{i}] [{w['phase']}] {w['msg'][:300]}\n")

        if phase_errors:
            f.write(f"\n=== ERRORS BY PHASE ===\n")
            for phase, errs in sorted(phase_errors.items()):
                f.write(f"\n  {phase} ({len(errs)} errors):\n")
                for e in errs[:5]:
                    f.write(f"    - {str(e)[:200]}\n")

        f.write(f"\n=== PHASES STARTED ===\n")
        for p in sorted(phases_started):
            status_mark = "DONE" if p in phases_completed else ("FAIL" if p in phases_failed else "??")
            f.write(f"  [{status_mark}] {p}\n")

    log(f"Summary written to: {SUMMARY_FILE}", "INFO")
    log(f"Full log:           {LOG_FILE}", "INFO")
    log(f"Console output:     {CONSOLE_FILE}", "INFO")

    if errors:
        log(f"\n*** {len(errors)} ERRORS ENCOUNTERED — see {SUMMARY_FILE} ***", "ERROR")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
