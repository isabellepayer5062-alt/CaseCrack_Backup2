#!/usr/bin/env python3
"""
Full 36-Phase Parallel Recon — empireminecraft.com
====================================================
Restarts the dashboard with a fresh target, launches all 36 phases in
parallel mode, captures every error/failure/warning from console output,
SSE events, and state polls, and writes a comprehensive issue log.

Run:
    python _run_empireminecraft_scan.py
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

TARGET = "https://empireminecraft.com"
BASE_URL = "http://localhost:8770"
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_empireminecraft_log.jsonl")
SUMMARY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_empireminecraft_summary.txt")
CONSOLE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_empireminecraft_console.txt")

# ── Auth ──────────────────────────────────────────────────────────────────────

def _get_token() -> str:
    r = urllib.request.urlopen(f"{BASE_URL}/api/token", timeout=5)
    return json.loads(r.read()).get("token", "")

TOKEN = ""  # filled at startup

def _headers_get() -> dict:
    return {"Authorization": f"Bearer {TOKEN}"}

def _headers_json() -> dict:
    return {"Content-Type": "application/json", "Authorization": f"Bearer {TOKEN}"}

# ── State ─────────────────────────────────────────────────────────────────────

errors       = []
warnings     = []
phase_errors = defaultdict(list)
phase_status = {}
console_lines = []
all_console  = []   # every console line (unfiltered)
lock         = threading.Lock()
stop_event   = threading.Event()
STARTED_AT   = time.monotonic()

# ── Logging ───────────────────────────────────────────────────────────────────

def log(msg: str, level: str = "INFO"):
    elapsed = int(time.monotonic() - STARTED_AT)
    ts = f"{elapsed//60:02d}:{elapsed%60:02d}"
    line = f"[{ts}] [{level:7s}] {msg}"
    print(line, flush=True)

# ── API helpers ───────────────────────────────────────────────────────────────

def api_get(path: str) -> dict:
    url = BASE_URL + path
    req = urllib.request.Request(url, headers=_headers_get())
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def api_post(path: str, data: dict) -> dict:
    url = BASE_URL + path
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers=_headers_json(), method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())

# ── Event recording ───────────────────────────────────────────────────────────

_ERROR_KW = ("error:", " error ", "exception:", "traceback", " failed:", "abort",
             "killed", "crash", "timeout", "cannot", "could not", "unable to",
             "unexpected", "critical", "fatal", "oops", "panic")

def _is_bad(text: str, level: str) -> bool:
    if level in ("error", "warn", "warning", "critical"):
        return True
    tl = text.lower()
    return any(kw in tl for kw in _ERROR_KW)


def record_event(event: dict):
    with lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

        etype = event.get("type", "")

        if etype in ("error", "phase_error", "command_error", "command_failed"):
            msg   = event.get("message") or event.get("error") or event.get("detail") or str(event)
            phase = event.get("phase", event.get("category", "unknown"))
            errors.append({"phase": phase, "type": etype, "msg": msg})
            phase_errors[phase].append(msg)
            log(f"ERROR [{phase}]: {msg[:200]}", "ERROR")

        elif etype == "log" and event.get("level") in ("warning", "warn", "error", "critical"):
            msg   = event.get("message", "")
            phase = event.get("phase", "system")
            warnings.append({"phase": phase, "msg": msg})
            log(f"WARN  [{phase}]: {msg[:150]}", "WARN")

        elif etype == "phase_complete":
            phase  = event.get("phase", "")
            status = event.get("status", "")
            phase_status[phase] = {"status": status}
            if status in ("error", "failed", "timeout", "aborted"):
                phase_errors[phase].append(f"Phase completed with status={status}")
                log(f"PHASE-FAIL [{phase}]: status={status}", "ERROR")
            else:
                log(f"Phase complete [{phase}]: {status}", "INFO")

        elif etype == "phase_start":
            log(f"Phase started: {event.get('phase','?')}", "INFO")

        elif etype == "preflight":
            for check in event.get("checks", []):
                if check.get("status") != "ok":
                    msg = f"Preflight FAIL: {check.get('name')}: {check.get('detail','')}"
                    errors.append({"phase": "preflight", "type": "preflight_fail", "msg": msg})
                    log(msg, "ERROR")

        elif etype == "command_result":
            if event.get("exit_code", 0) != 0 or event.get("status") == "error":
                phase = event.get("phase", "unknown")
                cmd   = event.get("command", event.get("tool", ""))
                ec    = event.get("exit_code", "?")
                msg   = f"Command failed (exit={ec}): {cmd}"
                errors.append({"phase": phase, "type": "command_result_fail", "msg": msg})
                phase_errors[phase].append(msg)
                log(f"CMD-FAIL [{phase}]: {msg[:200]}", "ERROR")


# ── Poll threads ──────────────────────────────────────────────────────────────

def poll_state():
    """Poll /api/status for phase-level state changes."""
    consecutive_errors = 0
    last_phase_statuses: dict = {}
    while not stop_event.is_set():
        try:
            data = api_get("/api/status")
            for phase in data.get("phases", []):
                name   = phase.get("name", "")
                status = phase.get("status", "")
                if status != last_phase_statuses.get(name):
                    last_phase_statuses[name] = status
                    if status in ("error", "failed", "timeout", "aborted"):
                        msg = f"Phase '{name}' state changed to {status}"
                        with lock:
                            errors.append({"phase": name, "type": "phase_status", "msg": msg})
                            phase_errors[name].append(msg)
                        log(f"PHASE-ERR [{name}]: {status}", "ERROR")
                    elif status == "complete":
                        record_event({"type": "phase_complete", "phase": name, "status": "complete"})
            for err in data.get("errors", []):
                phase = err.get("phase", "system")
                msg   = err.get("message", str(err))
                entry = {"phase": phase, "type": "scan_error", "msg": msg}
                with lock:
                    if entry not in errors:
                        errors.append(entry)
                        phase_errors[phase].append(msg)
                log(f"SCAN-ERR [{phase}]: {msg[:200]}", "ERROR")
            consecutive_errors = 0
        except Exception as exc:
            consecutive_errors += 1
            if consecutive_errors % 10 == 1:
                log(f"State poll error: {exc}", "WARN")
        time.sleep(4.0)


def poll_scan_status():
    """Poll /api/scan/status for overall completion."""
    last_completed = -1
    while not stop_event.is_set():
        try:
            data = api_get("/api/scan/status")
            running   = data.get("scan_running", data.get("running", False))
            completed = data.get("phases_completed", 0)
            total     = data.get("phases_total", 0)
            if completed != last_completed:
                log(f"Progress: {completed}/{total} phases complete", "INFO")
                last_completed = completed
            if not running and total > 0 and completed > 0:
                log(f"Scan finished! {completed}/{total} phases", "INFO")
                stop_event.set()
                break
        except Exception as exc:
            log(f"Status poll error: {exc}", "WARN")
        time.sleep(6.0)


def poll_sse_events():
    """Subscribe to /api/events/stream SSE for real-time phase completion events."""
    consecutive_errors = 0
    while not stop_event.is_set():
        try:
            req = urllib.request.Request(
                BASE_URL + "/api/events/stream",
                headers=_headers_get(),
            )
            with urllib.request.urlopen(req, timeout=600) as resp:
                consecutive_errors = 0
                for raw_line in resp:
                    if stop_event.is_set():
                        break
                    line = raw_line.decode("utf-8", errors="replace").strip()
                    if not line.startswith("data:"):
                        continue
                    payload = line[5:].strip()
                    if not payload or payload == "{}":
                        continue
                    try:
                        event = json.loads(payload)
                    except Exception:
                        continue
                    etype = event.get("type", "")
                    if etype in ("phase_complete", "phase_start", "phase_error",
                                 "command_result", "error"):
                        record_event(event)
        except Exception as exc:
            consecutive_errors += 1
            if consecutive_errors % 5 == 1:
                log(f"SSE stream error: {exc}", "WARN")
            if stop_event.is_set():
                break
            time.sleep(min(consecutive_errors * 2, 30))


def poll_console():
    """Poll /api/standalone/console for raw tool output.

    The console endpoint may return all lines with seq=0. We dedup by
    (phase, level, text) hash so repeated deliveries of the same line
    don't bloat the log.  Once the highest real seq advances we switch
    to seq-based pagination.
    """
    import hashlib
    seq            = 0
    seen_seq: set  = set()      # for real seq numbers > 0
    seen_hash: set = set()      # for seq-0 dedup by content hash
    consecutive_errors = 0
    while not stop_event.is_set():
        try:
            data  = api_get(f"/api/standalone/console?since={seq}&limit=1000")
            lines = data.get("lines", [])
            new_lines = 0
            for line in lines:
                text  = line.get("text", "")
                level = line.get("level", "info")
                phase = line.get("phase", "")
                s     = line.get("seq", 0) or 0

                # Dedup by seq when real seq numbers are provided
                if s > 0:
                    if s in seen_seq:
                        continue
                    seen_seq.add(s)
                    if s > seq:
                        seq = s
                else:
                    # Seq=0 — dedup by content hash
                    h = hashlib.md5(f"{phase}|{level}|{text}".encode(), usedforsecurity=False).hexdigest()
                    if h in seen_hash:
                        continue
                    seen_hash.add(h)

                new_lines += 1
                with lock:
                    all_console.append({"phase": phase, "level": level, "text": text, "seq": s})
                record_event({"type": "console_line", "phase": phase, "level": level, "text": text, "seq": s})
                if _is_bad(text, level):
                    entry = {"phase": phase, "level": level, "text": text, "seq": s}
                    with lock:
                        console_lines.append(entry)
                    if level in ("error", "critical"):
                        log(f"CONSOLE [{phase}]: {text[:200]}", "ERROR")
                    elif level in ("warn", "warning"):
                        log(f"CONSOLE [{phase}]: {text[:150]}", "WARN")
            consecutive_errors = 0
        except Exception as exc:
            consecutive_errors += 1
            if consecutive_errors % 20 == 1:
                log(f"Console poll error: {exc}", "WARN")
        time.sleep(2.0)


# ── Summary writer ────────────────────────────────────────────────────────────

def write_summary() -> str:
    lines = []
    sep   = "=" * 80
    lines += [sep,
              "FULL 36-PHASE PARALLEL RECON — empireminecraft.com",
              f"Run completed : {datetime.now(timezone.utc).isoformat()}",
              f"Elapsed       : {int(time.monotonic()-STARTED_AT)} seconds",
              sep, ""]

    lines += [
        f"TOTAL ERRORS          : {len(errors)}",
        f"TOTAL WARNINGS        : {len(warnings)}",
        f"CONSOLE ERROR LINES   : {len(console_lines)}",
        f"PHASES WITH ERRORS    : {len(phase_errors)}",
        f"TOTAL CONSOLE LINES   : {len(all_console)}",
        "",
    ]

    lines += ["── PHASE COMPLETION STATUS " + "─" * 52]
    if phase_status:
        for ph, info in sorted(phase_status.items()):
            lines.append(f"  {ph:50s} {info.get('status','?')}")
    else:
        lines.append("  (no phase completion events received)")
    lines.append("")

    lines += ["── ERRORS BY PHASE " + "─" * 60]
    if phase_errors:
        for ph in sorted(phase_errors):
            errs = phase_errors[ph]
            lines.append(f"\n  [{ph}]  ({len(errs)} error(s))")
            for e in errs[:25]:
                lines.append(f"    • {e[:350]}")
    else:
        lines.append("  None.")
    lines.append("")

    lines += ["── ALL ERRORS (chronological) " + "─" * 49]
    if errors:
        for i, e in enumerate(errors, 1):
            lines.append(f"\n  [{i:03d}] phase={e.get('phase','?')}  type={e.get('type','?')}")
            lines.append(f"        {e.get('msg','')[:400]}")
    else:
        lines.append("  None.")
    lines.append("")

    lines += ["── WARNINGS " + "─" * 67]
    if warnings:
        for w in warnings[:60]:
            lines.append(f"  [{w.get('phase','?')}] {w.get('msg','')[:300]}")
    else:
        lines.append("  None.")
    lines.append("")

    lines += ["── CONSOLE ERRORS / FAILURES " + "─" * 50]
    if console_lines:
        for cl in console_lines[:120]:
            ph = cl.get("phase", "?")
            lv = cl.get("level", "info").upper()
            tx = cl.get("text", "")
            lines.append(f"  [{ph}] ({lv}) {tx[:300]}")
    else:
        lines.append("  None.")
    lines.append("")

    summary = "\n".join(lines)
    with open(SUMMARY_FILE, "w", encoding="utf-8") as f:
        f.write(summary)

    # Write full console log separately
    with open(CONSOLE_FILE, "w", encoding="utf-8") as f:
        for cl in all_console:
            f.write(f"[{cl.get('seq',0):06d}] [{cl.get('level','info'):7s}] [{cl.get('phase','?')}] {cl.get('text','')}\n")

    print("\n" + summary)
    log(f"Summary → {SUMMARY_FILE}", "INFO")
    log(f"Console → {CONSOLE_FILE}  ({len(all_console)} lines)", "INFO")
    return summary


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    global TOKEN

    # ── Reconfigure stdout for Unicode on Windows ──
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    log("=" * 60)
    log("  CaseCrack Full 36-Phase Scan — empireminecraft.com")
    log("=" * 60)

    # Clear previous run files
    for f in (LOG_FILE, SUMMARY_FILE, CONSOLE_FILE):
        if os.path.exists(f):
            os.remove(f)

    # Fetch fresh token
    try:
        TOKEN = _get_token()
        log(f"Dashboard token acquired ({TOKEN[:8]}...)", "INFO")
    except Exception as exc:
        log(f"Cannot reach dashboard at {BASE_URL}: {exc}", "ERROR")
        sys.exit(1)

    # ── Set target via phase settings ──────────────────────────────────────────
    log(f"Setting target to {TARGET} ...", "INFO")
    try:
        r = api_post("/api/phase/settings", {"target_url": TARGET})
        log(f"Phase settings update: {r}", "INFO")
    except Exception as exc:
        log(f"Phase settings update failed (non-fatal): {exc}", "WARN")

    # ── Start parallel scan ────────────────────────────────────────────────────
    log("Launching 36-phase parallel scan ...", "INFO")
    try:
        result = api_post("/api/standalone/run", {
            "target":   TARGET,
            "parallel": True,
            "profile":  "deep",
        })
        log(f"Scan start response: {result}", "INFO")
        if not result.get("ok") and "error" in result:
            log(f"Scan start warning: {result.get('error','?')}", "WARN")
    except urllib.error.HTTPError as exc:
        body = exc.read(512).decode(errors="replace")
        log(f"Scan start HTTP {exc.code}: {body}", "ERROR")
        # Try alternate endpoint
        try:
            result = api_post("/api/scan/start", {"target": TARGET})
            log(f"Scan start (alt endpoint) response: {result}", "INFO")
        except Exception as exc2:
            log(f"Alt endpoint also failed: {exc2}", "ERROR")
            errors.append({"phase": "startup", "type": "start_fail", "msg": str(exc2)})
    except Exception as exc:
        log(f"Scan start exception: {exc}", "ERROR")
        traceback.print_exc()
        errors.append({"phase": "startup", "type": "exception", "msg": str(exc)})

    # ── Start monitor threads ──────────────────────────────────────────────────
    threads = [
        threading.Thread(target=poll_state,       daemon=True, name="poll_state"),
        threading.Thread(target=poll_scan_status, daemon=True, name="poll_scan_status"),
        threading.Thread(target=poll_console,     daemon=True, name="poll_console"),
        threading.Thread(target=poll_sse_events,  daemon=True, name="poll_sse"),
    ]
    for t in threads:
        t.start()
    log("Monitor threads started (state + status + console + SSE)", "INFO")

    # ── Wait ───────────────────────────────────────────────────────────────────
    MAX_WAIT = 4 * 3600   # 4 hours hard cap
    log(f"Monitoring (max {MAX_WAIT//3600}h). Ctrl+C to stop early...", "INFO")
    try:
        while not stop_event.is_set():
            elapsed = int(time.monotonic() - STARTED_AT)
            if elapsed > MAX_WAIT:
                log(f"Max wait {MAX_WAIT}s reached, stopping monitor", "WARN")
                stop_event.set()
                break
            time.sleep(5)
    except KeyboardInterrupt:
        log("Interrupted — generating summary ...", "WARN")
        stop_event.set()

    time.sleep(3)   # let final events drain

    # Final state snapshot
    try:
        fs = api_get("/api/status")
        completed = sum(1 for p in fs.get("phases", []) if p.get("status") == "complete")
        failed    = sum(1 for p in fs.get("phases", []) if p.get("status") in ("error", "failed"))
        total     = len(fs.get("phases", []))
        log(f"Final: {completed}/{total} complete, {failed} failed", "INFO")
    except Exception:
        pass

    write_summary()


if __name__ == "__main__":
    main()
