"""
Real-time monitor for olympus-entertainment.com scan run.
Polls the dashboard API and records all events, errors, and failures.
"""
import time
import json
import requests
import sys
from datetime import datetime, timezone

API_BASE = "http://localhost:8770"
LOG_FILE = "_scan_monitor_olympus.log"
ISSUES_FILE = "_scan_issues_olympus.txt"
POLL_INTERVAL = 10  # seconds

def ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def main():
    print(f"[{ts()}] Monitor started for olympus-entertainment.com scan", flush=True)

    seen_phases_running = set()
    seen_phases_complete = set()
    seen_phases_degraded = set()
    last_findings = 0
    last_phase_count = 0
    issues_count = 0
    consecutive_errors = 0

    with open(LOG_FILE, "w", encoding="utf-8") as log, \
         open(ISSUES_FILE, "w", encoding="utf-8") as issues:

        def write(msg, is_issue=False):
            nonlocal issues_count
            line = f"[{ts()}] {msg}"
            print(line, flush=True)
            log.write(line + "\n")
            log.flush()
            if is_issue:
                issues_count += 1
                issues.write(line + "\n")
                issues.flush()

        write(f"=== Monitor started for https://olympus-entertainment.com/ ===")
        issues.write(f"=== Issues Log started at {ts()} UTC ===\n")
        issues.flush()

        while True:
            try:
                r = requests.get(f"{API_BASE}/api/standalone/status", timeout=15)
                r.raise_for_status()
                data = r.json()
                consecutive_errors = 0
            except Exception as e:
                consecutive_errors += 1
                write(f"ERROR: API unreachable ({e})", is_issue=True)
                if consecutive_errors >= 5:
                    write("FATAL: Dashboard unreachable 5x in a row — aborting monitor", is_issue=True)
                    break
                time.sleep(POLL_INTERVAL)
                continue

            # Newly running phases
            running = set(data.get("running_phases", []))
            for p in running - seen_phases_running:
                write(f"PHASE START: {p}")
                seen_phases_running.add(p)

            # Newly completed phases
            phase_status = data.get("phase_status", {})
            completed_now = {p for p, s in phase_status.items() if s == "completed"}
            for p in completed_now - seen_phases_complete:
                write(f"PHASE DONE:  {p}")
                seen_phases_complete.add(p)

            # Degraded / errored phases (report once per phase per state)
            for p, s in phase_status.items():
                if s in ("degraded", "error", "failed", "timeout"):
                    key = f"{p}:{s}"
                    if key not in seen_phases_degraded:
                        write(f"PHASE {s.upper()}: {p}", is_issue=True)
                        seen_phases_degraded.add(key)

            # Findings delta
            findings = data.get("findings_count", 0)
            if findings != last_findings:
                write(f"FINDINGS: {findings} (delta +{findings - last_findings})")
                last_findings = findings

            # Phase count delta
            phases_done = data.get("completed_phases", 0)
            total = len(data.get("phase_status", {})) or "?"
            if phases_done != last_phase_count:
                write(f"PROGRESS: {phases_done}/{total} phases complete")
                last_phase_count = phases_done

            # Error count
            err_count = data.get("errors", 0)
            if err_count and err_count > 0:
                write(f"SCAN ERRORS REPORTED: {err_count}", is_issue=True)

            # Completion
            if data.get("is_complete"):
                write(f"SCAN COMPLETE: {phases_done}/{total} phases, {findings} findings, {issues_count} issues recorded")
                write(f"Session ID: {data.get('session_id', 'unknown')}")
                break

            time.sleep(POLL_INTERVAL)

        write(f"=== Monitor exited. Total issues: {issues_count} ===")

if __name__ == "__main__":
    main()
