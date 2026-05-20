#!/usr/bin/env python3
"""
Full 31-Phase Parallel Recon Suite - Run v2
Launches all phases in parallel mode against sugarrushed.ca,
captures every single error/failure/warning from the console,
and writes a comprehensive summary.
"""

import json
import os
import sys
import time
import threading
import traceback
import urllib.request
import urllib.error
from collections import defaultdict, OrderedDict
from datetime import datetime, timezone

TARGET = "https://sugarrushed.ca"
BASE_URL = "http://localhost:8770"
TOKEN = "OCNU6wFZZhLYle9cdX4K_5Nlrj_yUT84GPMD3B1v4no"
HEADERS_JSON = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {TOKEN}",
}
HEADERS_GET = {"Authorization": f"Bearer {TOKEN}"}

LOG_FILE = os.path.join(os.path.dirname(__file__), "_recon_v2_log.jsonl")
SUMMARY_FILE = os.path.join(os.path.dirname(__file__), "_RECON_V2_SUMMARY.md")

# All collected data
all_console_lines = []      # every console line
error_lines = []            # lines with level=error/critical or error keywords
warning_lines = []          # lines with level=warning/warn
phase_status_map = OrderedDict()  # phase_name -> final status
phase_errors_map = defaultdict(list)   # phase_name -> [error msgs]
phase_warnings_map = defaultdict(list) # phase_name -> [warning msgs]
phase_findings_map = defaultdict(int)  # phase_name -> finding count
global_errors = []          # structural errors (API, start failures, etc.)
scan_start_time = None
scan_end_time = None
lock = threading.Lock()
stop_event = threading.Event()

# Error keyword detection
ERROR_KEYWORDS = [
    "error:", " error ", "failed:", "exception:", "traceback",
    "timeout:", "abort", "killed", "crash", "unexpected",
    "unknown action", "invalid choice", "permission denied",
    "no such file", "connection refused", "timed out",
    "degraded", "not found", "missing", "cannot",
]
WARN_KEYWORDS = [
    "warn", "warning", "deprecated", "retry", "slow", "stale",
    "fallback", "skipping", "skip", "no results", "empty",
]


def ts():
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def log(msg: str, level: str = "INFO"):
    print(f"[{ts()}] [{level}] {msg}", flush=True)


def api_get(path: str, timeout: int = 30):
    url = BASE_URL + path
    req = urllib.request.Request(url, headers=HEADERS_GET)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def api_post(path: str, data: dict, timeout: int = 30):
    url = BASE_URL + path
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers=HEADERS_JSON, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def is_error_text(text: str, level: str) -> bool:
    if level in ("error", "critical"):
        return True
    tl = text.lower()
    return any(kw in tl for kw in ERROR_KEYWORDS)


def is_warn_text(text: str, level: str) -> bool:
    if level in ("warn", "warning"):
        return True
    tl = text.lower()
    return any(kw in tl for kw in WARN_KEYWORDS)


def process_console_line(line: dict):
    text = line.get("text", "")
    level = line.get("level", "info")
    phase = line.get("phase", "") or "system"
    seq = line.get("seq", 0)

    entry = {"seq": seq, "phase": phase, "level": level, "text": text}

    with lock:
        all_console_lines.append(entry)

        if is_error_text(text, level):
            error_lines.append(entry)
            phase_errors_map[phase].append(text)

        elif is_warn_text(text, level):
            warning_lines.append(entry)
            phase_warnings_map[phase].append(text)


def poll_console():
    """Continuously poll all console output, seq-tracked to avoid duplicates."""
    max_seq = 0
    seen_seqs = set()
    consecutive_fails = 0
    initial_batch_done = False

    while not stop_event.is_set():
        try:
            # First pull everything, then follow from last seq
            limit = 2000 if not initial_batch_done else 500
            data = api_get(f"/api/standalone/console?since={max_seq}&limit={limit}")
            lines = data.get("lines", [])

            new_lines = []
            for line in lines:
                s = line.get("seq", 0)
                if s and s in seen_seqs:
                    continue
                if s:
                    seen_seqs.add(s)
                    if s > max_seq:
                        max_seq = s
                new_lines.append(line)

            for line in new_lines:
                process_console_line(line)

            if not initial_batch_done and lines is not None:
                initial_batch_done = True
                log(f"Initial console batch: {len(new_lines)} lines (max_seq={max_seq})", "INFO")

            consecutive_fails = 0
        except Exception as exc:
            consecutive_fails += 1
            if consecutive_fails % 20 == 1:
                log(f"Console poll error: {exc}", "WARN")

        time.sleep(1.5)


def poll_scan_status():
    """Poll scan completion status."""
    global scan_end_time
    last_completed = -1
    last_total = 0

    while not stop_event.is_set():
        try:
            data = api_get("/api/scan/status")
            running = data.get("scan_running", False)
            completed = data.get("phases_completed", 0)
            total = data.get("phases_total", 0)

            if total != last_total or completed != last_completed:
                last_total = total
                last_completed = completed
                pct = f"{100*completed//total}%" if total else "?"
                log(f"Progress: {completed}/{total} phases ({pct}) running={running}", "INFO")

            if not running and total > 0:
                scan_end_time = time.time()
                log(f"Scan complete! {completed}/{total} phases", "INFO")
                stop_event.set()
                break

        except Exception as exc:
            log(f"Status poll error: {exc}", "WARN")

        time.sleep(4.0)


def poll_phase_details():
    """Poll phase details to capture per-phase status."""
    last_seen = {}
    while not stop_event.is_set():
        try:
            data = api_get("/api/status")
            phases = data.get("phases", [])
            for phase in phases:
                name = phase.get("name", "")
                status = phase.get("status", "")
                findings = phase.get("findings_count", 0) or 0
                if not name:
                    continue

                prev = last_seen.get(name)
                if prev != status:
                    last_seen[name] = status
                    with lock:
                        phase_status_map[name] = {
                            "status": status,
                            "findings": findings,
                            "commands_run": phase.get("commands_run", 0),
                            "commands_total": phase.get("commands_total", 0),
                            "duration": phase.get("duration_seconds", 0),
                        }
                    if status in ("error", "failed", "timeout", "aborted", "degraded"):
                        with lock:
                            phase_errors_map[name].append(f"Phase completed with status={status}")
                        log(f"PHASE DEGRADED [{name}]: status={status}", "WARN")
                    elif status == "complete":
                        log(f"Phase complete: {name} (findings={findings})", "INFO")
                else:
                    # Always keep latest findings count
                    with lock:
                        if name in phase_status_map:
                            phase_status_map[name]["findings"] = findings

        except Exception:
            pass
        time.sleep(5.0)


def write_summary(elapsed_seconds: float):
    """Write comprehensive markdown summary."""
    lines = []
    now = datetime.now(timezone.utc).isoformat()

    lines.append("# Full 31-Phase Parallel Recon — Comprehensive Issue Summary")
    lines.append(f"**Target:** {TARGET}")
    lines.append(f"**Run completed:** {now}")
    lines.append(f"**Elapsed:** {elapsed_seconds/60:.1f} minutes ({elapsed_seconds:.0f}s)")
    lines.append("")

    # Stats
    total_errors = len(error_lines)
    total_warnings = len(warning_lines)
    phases_with_errors = sum(1 for v in phase_errors_map.values() if v)
    phases_degraded = sum(1 for v in phase_status_map.values()
                          if v.get("status") in ("error", "failed", "timeout", "aborted", "degraded"))
    total_findings = sum(v.get("findings", 0) for v in phase_status_map.values())

    lines.append("## Summary Statistics")
    lines.append(f"| Metric | Count |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total console error lines | {total_errors} |")
    lines.append(f"| Total console warning lines | {total_warnings} |")
    lines.append(f"| Total console lines captured | {len(all_console_lines)} |")
    lines.append(f"| Phases with errors | {phases_with_errors} |")
    lines.append(f"| Phases with degraded/failed status | {phases_degraded} |")
    lines.append(f"| Total findings across all phases | {total_findings} |")
    if global_errors:
        lines.append(f"| Structural/startup errors | {len(global_errors)} |")
    lines.append("")

    # Phase status table
    lines.append("## Phase Status Overview")
    lines.append("| Phase | Status | Findings | Duration |")
    lines.append("|-------|--------|----------|----------|")
    for name, info in phase_status_map.items():
        status = info.get("status", "?")
        findings = info.get("findings", 0)
        dur = info.get("duration", 0)
        dur_str = f"{dur:.0f}s" if dur else "—"
        status_badge = f"**{status.upper()}**" if status in ("error", "failed", "timeout", "aborted", "degraded") else status
        lines.append(f"| {name} | {status_badge} | {findings} | {dur_str} |")
    if not phase_status_map:
        lines.append("| — | No phase data captured | — | — |")
    lines.append("")

    # Degraded phases detail
    degraded = [(n, v) for n, v in phase_status_map.items()
                if v.get("status") in ("error", "failed", "timeout", "aborted", "degraded")]
    if degraded:
        lines.append("## Degraded / Failed Phases")
        for name, info in degraded:
            lines.append(f"\n### {name} (status={info['status']})")
            errs = phase_errors_map.get(name, [])
            if errs:
                lines.append("**Errors:**")
                for e in errs[:30]:
                    lines.append(f"- `{e[:350]}`")
            warns = phase_warnings_map.get(name, [])
            if warns:
                lines.append("**Warnings:**")
                for w in warns[:20]:
                    lines.append(f"- {w[:300]}")
        lines.append("")

    # All errors section (chronological)
    lines.append("## All Error Lines (Chronological)")
    lines.append(f"*{len(error_lines)} total error-level console lines*")
    lines.append("")
    if error_lines:
        cur_phase = None
        for entry in error_lines:
            phase = entry.get("phase", "system")
            if phase != cur_phase:
                cur_phase = phase
                lines.append(f"\n### Phase: {phase or 'system'}")
            lvl = entry.get("level", "").upper()
            text = entry.get("text", "")
            lines.append(f"- [{lvl}] `{text[:400]}`")
    else:
        lines.append("*No error lines captured.*")
    lines.append("")

    # All warnings section
    lines.append("## All Warning Lines (Chronological)")
    lines.append(f"*{len(warning_lines)} total warning-level console lines*")
    lines.append("")
    if warning_lines:
        cur_phase = None
        for entry in warning_lines[:200]:  # cap at 200
            phase = entry.get("phase", "system")
            if phase != cur_phase:
                cur_phase = phase
                lines.append(f"\n### Phase: {phase or 'system'}")
            text = entry.get("text", "")
            lines.append(f"- `{text[:350]}`")
        if len(warning_lines) > 200:
            lines.append(f"\n*... and {len(warning_lines) - 200} more warnings (truncated)*")
    else:
        lines.append("*No warning lines captured.*")
    lines.append("")

    # Errors grouped by phase
    lines.append("## Errors Grouped by Phase")
    if phase_errors_map:
        for phase in sorted(phase_errors_map.keys()):
            errs = phase_errors_map[phase]
            # Deduplicate
            seen = set()
            deduped = []
            for e in errs:
                key = e[:120]
                if key not in seen:
                    seen.add(key)
                    deduped.append(e)
            lines.append(f"\n### {phase or 'system'} ({len(deduped)} unique errors)")
            for err in deduped[:50]:
                lines.append(f"- `{err[:350]}`")
            if len(deduped) > 50:
                lines.append(f"- *... and {len(deduped)-50} more*")
    else:
        lines.append("*No phase errors captured.*")
    lines.append("")

    # Global / structural errors
    if global_errors:
        lines.append("## Structural / API Errors")
        for err in global_errors:
            lines.append(f"- {err}")
        lines.append("")

    # Full console dump (errors+warnings only, deduped)
    lines.append("## Complete Error+Warning Console Dump")
    combined = sorted(error_lines + warning_lines, key=lambda x: x.get("seq", 0))
    lines.append(f"*{len(combined)} total error/warning lines*")
    lines.append("")
    if combined:
        for entry in combined:
            phase = entry.get("phase", "system") or "system"
            lvl = entry.get("level", "info").upper()
            text = entry.get("text", "")
            seq = entry.get("seq", "")
            lines.append(f"[{phase}] [{lvl}] {text[:400]}")
    lines.append("")

    content = "\n".join(lines)
    with open(SUMMARY_FILE, "w", encoding="utf-8") as f:
        f.write(content)

    # Also write plain text for quick terminal view
    txt_path = SUMMARY_FILE.replace(".md", ".txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(content)

    print("\n" + "="*80)
    print("SUMMARY WRITTEN TO:", SUMMARY_FILE)
    print("="*80)
    return content


def main():
    global scan_start_time

    log("=" * 60)
    log("FULL 31-PHASE PARALLEL RECON — RUN v2")
    log(f"Target: {TARGET}")
    log("=" * 60)

    # Clear previous logs
    for f in [LOG_FILE]:
        if os.path.exists(f):
            os.remove(f)

    # Check dashboard
    try:
        status = api_get("/api/scan/status")
        running = status.get("scan_running", False)
        if running:
            log("WARNING: A scan is already running! Stopping it first...", "WARN")
            try:
                api_post("/api/scan/stop", {})
                time.sleep(3)
            except Exception:
                pass
    except Exception as exc:
        log(f"FATAL: Dashboard not reachable at {BASE_URL}: {exc}", "ERROR")
        sys.exit(1)

    # Start monitoring threads BEFORE launching scan
    t_console = threading.Thread(target=poll_console, daemon=True, name="console-poller")
    t_status = threading.Thread(target=poll_scan_status, daemon=True, name="status-poller")
    t_details = threading.Thread(target=poll_phase_details, daemon=True, name="detail-poller")
    t_console.start()
    t_status.start()
    t_details.start()
    log("Monitoring threads started", "INFO")

    # Launch scan
    scan_start_time = time.time()
    log("Launching full parallel scan...", "INFO")
    try:
        result = api_post("/api/scan/start", {"target": TARGET})
        log(f"Scan start response: {result}", "INFO")
        if not result.get("ok"):
            msg = f"Scan failed to start: {result.get('error', str(result))}"
            log(msg, "ERROR")
            global_errors.append(msg)
    except Exception as exc:
        msg = f"Exception starting scan: {exc}"
        log(msg, "ERROR")
        global_errors.append(msg)
        traceback.print_exc()

    log("Monitoring scan (Ctrl+C to generate early summary)...")
    log("Max wait: 3 hours")

    MAX_WAIT = 10800  # 3 hours
    start = time.time()

    try:
        while not stop_event.is_set():
            elapsed = time.time() - start
            if elapsed > MAX_WAIT:
                log(f"Max wait exceeded ({MAX_WAIT}s), stopping.", "WARN")
                stop_event.set()
                break
            time.sleep(5)
    except KeyboardInterrupt:
        log("Interrupted — generating summary now...", "WARN")
        stop_event.set()

    # Drain final events
    time.sleep(5)

    # Final console sweep — get everything up to now
    log("Final console sweep...", "INFO")
    try:
        data = api_get("/api/standalone/console?limit=10000")
        lines = data.get("lines", [])
        log(f"Final sweep: {len(lines)} total console lines", "INFO")
        for line in lines:
            s = line.get("seq", 0)
            text = line.get("text", "")
            level = line.get("level", "info")
            phase = line.get("phase", "") or "system"
            entry = {"seq": s, "phase": phase, "level": level, "text": text}
            with lock:
                # Add to all_console_lines if not already there
                existing_seqs = {e.get("seq") for e in all_console_lines if e.get("seq")}
                if not s or s not in existing_seqs:
                    all_console_lines.append(entry)
                    if is_error_text(text, level):
                        if entry not in error_lines:
                            error_lines.append(entry)
                            phase_errors_map[phase].append(text)
                    elif is_warn_text(text, level):
                        if entry not in warning_lines:
                            warning_lines.append(entry)
                            phase_warnings_map[phase].append(text)
    except Exception as exc:
        log(f"Final sweep error: {exc}", "WARN")

    # Dedup error/warning lists by seq
    def dedup_by_seq(lst):
        seen = set()
        out = []
        for e in lst:
            key = (e.get("seq"), e.get("text", "")[:80])
            if key not in seen:
                seen.add(key)
                out.append(e)
        return sorted(out, key=lambda x: x.get("seq", 0))

    with lock:
        error_lines[:] = dedup_by_seq(error_lines)
        warning_lines[:] = dedup_by_seq(warning_lines)
        all_console_lines[:] = dedup_by_seq(all_console_lines)

    elapsed = time.time() - scan_start_time if scan_start_time else 0
    log(f"Total elapsed: {elapsed:.0f}s", "INFO")
    log(f"Total console lines captured: {len(all_console_lines)}", "INFO")
    log(f"Error lines: {len(error_lines)}", "INFO")
    log(f"Warning lines: {len(warning_lines)}", "INFO")

    write_summary(elapsed)
    log(f"Summary: {SUMMARY_FILE}", "INFO")


if __name__ == "__main__":
    main()
