#!/usr/bin/env python3
"""
Full 14-Phase Recon Monitor v2 — empireminecraft.com
======================================================
Uses the CURRENT dashboard API (no auth token, target_url key).
Starts the dashboard, kicks off all phases, and records every
console line, error, and warning.

Run:
    python _run_empireminecraft_v2.py
"""

import json
import os
import sys
import time
import threading
import subprocess
import traceback
import urllib.request
import urllib.error
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────

TARGET   = "https://empireminecraft.com"
BASE_URL = "http://localhost:8770"

ROOT        = Path(__file__).resolve().parent
LOG_FILE    = str(ROOT / "_empireminecraft_v2_log.jsonl")
SUMMARY_FILE = str(ROOT / "_empireminecraft_v2_summary.txt")
CONSOLE_FILE = str(ROOT / "_empireminecraft_v2_console.txt")

STARTED_AT = time.monotonic()

# ── State ─────────────────────────────────────────────────────────────────────

errors        = []
warnings      = []
phase_errors  = defaultdict(list)
phase_status  = {}
all_console   = []   # every line unfiltered
bad_console   = []   # lines that look like errors/warnings
lock          = threading.Lock()
stop_event    = threading.Event()

# Auth token (fetched at startup)
_TOKEN = ""

def _auth_headers() -> dict:
    return {"Authorization": f"Bearer {_TOKEN}"} if _TOKEN else {}

def _auth_json_headers() -> dict:
    h = {"Content-Type": "application/json"}
    if _TOKEN:
        h["Authorization"] = f"Bearer {_TOKEN}"
    return h

# Keywords that flag a console line as noteworthy
_ERROR_KW = (
    "error:", " error ", "exception:", "traceback", " failed:",
    "abort", "killed", "crash", "timeout", "cannot", "could not",
    "unable to", "unexpected", "critical", "fatal", "oops", "panic",
    "no such file", "permission denied", "connection refused",
    "ssl error", "attributeerror", "typeerror", "valueerror",
    "keyerror", "importerror", "runtimeerror", "indexerror",
    "nameerror", "filenotfounderror", "oserror",
)
_WARN_KW = (
    "warn", "warning", "deprecated", "retry", "slow", "stale",
    "fallback", "skipping", "skip", "no results", "rate limit",
    "429", "soft-timeout",
)

def _classify(text: str, level: str) -> str:
    """Return 'error', 'warn', or '' based on text + level."""
    if level in ("error", "critical"):
        return "error"
    if level in ("warn", "warning"):
        return "warn"
    tl = text.lower()
    if any(k in tl for k in _ERROR_KW):
        return "error"
    if any(k in tl for k in _WARN_KW):
        return "warn"
    return ""


# ── Logging ───────────────────────────────────────────────────────────────────

def log(msg: str, level: str = "INFO"):
    elapsed = int(time.monotonic() - STARTED_AT)
    ts = f"{elapsed//60:02d}:{elapsed%60:02d}"
    print(f"[{ts}] [{level:7s}] {msg}", flush=True)


# ── API helpers ───────────────────────────────────────────────────────────────

def api_get(path: str, timeout: int = 30) -> dict:
    url = BASE_URL + path
    req = urllib.request.Request(url, headers=_auth_headers())
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def api_post(path: str, data: dict, timeout: int = 30) -> dict:
    url = BASE_URL + path
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body,
                                  headers=_auth_json_headers(),
                                  method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def fetch_token() -> str:
    """GET /api/token — returns the session Bearer token."""
    r = urllib.request.urlopen(f"{BASE_URL}/api/token", timeout=5)
    return json.loads(r.read()).get("token", "")


# ── Record ────────────────────────────────────────────────────────────────────

def record(event: dict):
    with lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")


# ── Poll threads ──────────────────────────────────────────────────────────────

def poll_console():
    """Continuously pull new console lines and classify them."""
    idx = 0
    import hashlib
    seen_hash: set = set()
    consecutive_errors = 0
    while not stop_event.is_set():
        try:
            data = api_get(f"/api/standalone/console?since={idx}&limit=2000", timeout=15)
            lines = data.get("lines", [])
            for line in lines:
                text  = line.get("text", "")
                level = line.get("level", line.get("stream", "info"))
                phase = line.get("phase", "")

                # Dedup by content hash (the endpoint sometimes re-delivers)
                h = hashlib.md5(f"{phase}|{level}|{text}".encode(),
                                usedforsecurity=False).hexdigest()
                if h in seen_hash:
                    continue
                seen_hash.add(h)

                entry = {"phase": phase, "level": level, "text": text}
                with lock:
                    all_console.append(entry)
                record({"type": "console", "phase": phase, "level": level, "text": text})

                cls = _classify(text, level)
                if cls == "error":
                    with lock:
                        bad_console.append(entry)
                        phase_errors[phase].append(text)
                    log(f"CONSOLE [{phase}]: {text[:200]}", "ERROR")
                elif cls == "warn":
                    with lock:
                        bad_console.append(entry)
                        warnings.append({"phase": phase, "msg": text})
                    log(f"CONSOLE [{phase}]: {text[:150]}", "WARN")

            # Advance index
            total = data.get("total", 0)
            if total > idx:
                idx = total
            consecutive_errors = 0
        except Exception as exc:
            consecutive_errors += 1
            if consecutive_errors % 15 == 1:
                log(f"Console poll error: {exc}", "WARN")
        time.sleep(2.0)


def poll_runner_status():
    """Poll /api/standalone/status for overall runner state."""
    last_running = None
    while not stop_event.is_set():
        try:
            data = api_get("/api/standalone/status", timeout=10)
            running  = data.get("running", data.get("ok", False))
            # Try multiple keys that might indicate completion
            if data.get("ok") and not data.get("running"):
                pass  # might just be the ok=True, running not set yet
            # When the runner explicitly says it's done
            if last_running is True and running is False:
                log("Runner completed — stopping monitor in 30s...", "INFO")
                time.sleep(30)
                stop_event.set()
                break
            last_running = running
        except Exception as exc:
            log(f"Runner status poll error: {exc}", "WARN")
        time.sleep(5.0)


def poll_dashboard_state():
    """Poll /api/status for phase-level status changes."""
    last_statuses: dict = {}
    consecutive_errors = 0
    while not stop_event.is_set():
        try:
            data = api_get("/api/status", timeout=15)
            phases = data.get("phases", [])
            for ph in phases:
                name   = ph.get("name", "")
                status = ph.get("status", "")
                if name and status != last_statuses.get(name):
                    last_statuses[name] = status
                    phase_status[name] = status
                    record({"type": "phase_status", "phase": name, "status": status})
                    if status in ("error", "failed", "timeout", "aborted"):
                        msg = f"Phase '{name}' → {status}"
                        with lock:
                            errors.append({"phase": name, "type": "phase_fail", "msg": msg})
                            phase_errors[name].append(msg)
                        log(f"PHASE-FAIL [{name}]: {status}", "ERROR")
                    elif status == "complete":
                        log(f"Phase complete: {name}", "INFO")
                    elif status == "running":
                        log(f"Phase running: {name}", "INFO")

            # Check for scan-level errors in the state
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
                log(f"Dashboard state poll error: {exc}", "WARN")
        time.sleep(5.0)


# ── Summary writer ────────────────────────────────────────────────────────────

def write_summary():
    sep = "=" * 80
    lines = [
        sep,
        "FULL RECON v2 — empireminecraft.com",
        f"Run completed : {datetime.now(timezone.utc).isoformat()}",
        f"Elapsed       : {int(time.monotonic() - STARTED_AT)} seconds",
        sep, "",
        f"TOTAL ERRORS          : {len(errors)}",
        f"TOTAL WARNINGS        : {len(warnings)}",
        f"CONSOLE ISSUE LINES   : {len(bad_console)}",
        f"PHASES WITH ERRORS    : {len(phase_errors)}",
        f"TOTAL CONSOLE LINES   : {len(all_console)}",
        "",
    ]

    lines += ["── PHASE STATUS " + "─" * 63]
    if phase_status:
        for ph, st in sorted(phase_status.items()):
            lines.append(f"  {ph:55s} {st}")
    else:
        lines.append("  (no phase status events received)")
    lines.append("")

    lines += ["── ERRORS BY PHASE " + "─" * 60]
    if phase_errors:
        for ph in sorted(phase_errors):
            errs = phase_errors[ph]
            lines.append(f"\n  [{ph}]  ({len(errs)} error(s))")
            for e in errs[:30]:
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
        for w in warnings[:80]:
            lines.append(f"  [{w.get('phase','?')}] {w.get('msg','')[:300]}")
    else:
        lines.append("  None.")
    lines.append("")

    lines += ["── CONSOLE ISSUES (errors & warnings) " + "─" * 40]
    if bad_console:
        for cl in bad_console[:200]:
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

    # Full console dump
    with open(CONSOLE_FILE, "w", encoding="utf-8") as f:
        for i, cl in enumerate(all_console):
            f.write(f"[{i:06d}] [{cl.get('level','info'):7s}] [{cl.get('phase','?')}] {cl.get('text','')}\n")

    print("\n" + summary)
    log(f"Summary  → {SUMMARY_FILE}", "INFO")
    log(f"Console  → {CONSOLE_FILE}  ({len(all_console)} lines)", "INFO")
    log(f"JSONL    → {LOG_FILE}", "INFO")
    return summary


# ── Main ──────────────────────────────────────────────────────────────────────

def wait_for_dashboard(timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{BASE_URL}/health", timeout=1.5) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.4)
    return False


def main():
    global _TOKEN

    # ── Unicode safety on Windows ──
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    log("=" * 60)
    log("  CaseCrack Full Recon v2 — empireminecraft.com")
    log("=" * 60)

    # Clear previous run files
    for f in (LOG_FILE, SUMMARY_FILE, CONSOLE_FILE):
        if os.path.exists(f):
            os.remove(f)

    # ── Check / start dashboard ────────────────────────────────────────────────
    log("Checking if dashboard is up...", "INFO")
    if not wait_for_dashboard(timeout=5.0):
        log("Dashboard not running — starting it now...", "INFO")
        env = os.environ.copy()
        casecrack_dir = str(ROOT / "CaseCrack")
        env["PYTHONPATH"] = casecrack_dir + (os.pathsep + env.get("PYTHONPATH", ""))
        launch_cmd = [
            sys.executable, "-c",
            (
                "import sys; sys.path.insert(0, 'CaseCrack'); "
                "from tools.burp_enterprise.recon_dashboard import ReconDashboard; "
                "d = ReconDashboard(target_url='', http_port=8770, ws_port=8771, auto_open=False); "
                "d.start()"
            ),
        ]
        log_out = open(ROOT / "dashboard_stdout.log", "w", encoding="utf-8")
        log_err = open(ROOT / "dashboard_stderr.log", "w", encoding="utf-8")
        proc = subprocess.Popen(
            launch_cmd, stdout=log_out, stderr=log_err,
            cwd=str(ROOT), env=env,
        )
        log(f"Dashboard PID: {proc.pid}", "INFO")
        if not wait_for_dashboard(timeout=25.0):
            log("Dashboard failed to start within 25s — check dashboard_stderr.log", "ERROR")
            sys.exit(1)
        log("Dashboard is up.", "INFO")
    else:
        log("Dashboard already running.", "INFO")

    # ── Fetch auth token ──────────────────────────────────────────────────────
    try:
        _TOKEN = fetch_token()
        log(f"Auth token acquired: {_TOKEN[:8]}...", "INFO")
    except Exception as exc:
        log(f"Token fetch failed: {exc} — proceeding without auth", "WARN")

    # ── Start the scan ─────────────────────────────────────────────────────────
    log(f"Starting full recon against {TARGET} ...", "INFO")
    try:
        result = api_post("/api/standalone/run", {"target_url": TARGET})
        if result.get("ok"):
            phases_n = result.get("phases_selected", "?")
            log(f"Scan started — {phases_n} phases queued", "INFO")
            record({"type": "scan_start", "target": TARGET, "response": result})
        else:
            msg = result.get("error", str(result))
            log(f"Scan start warning: {msg}", "WARN")
            errors.append({"phase": "startup", "type": "start_warn", "msg": msg})
    except urllib.error.HTTPError as exc:
        body = exc.read(512).decode(errors="replace")
        log(f"Scan start HTTP {exc.code}: {body}", "ERROR")
        errors.append({"phase": "startup", "type": "http_error", "msg": f"HTTP {exc.code}: {body}"})
    except Exception as exc:
        log(f"Scan start exception: {exc}", "ERROR")
        traceback.print_exc()
        errors.append({"phase": "startup", "type": "exception", "msg": str(exc)})
        sys.exit(1)

    # ── Start monitor threads ──────────────────────────────────────────────────
    threads = [
        threading.Thread(target=poll_console,          daemon=True, name="console"),
        threading.Thread(target=poll_runner_status,    daemon=True, name="runner"),
        threading.Thread(target=poll_dashboard_state,  daemon=True, name="state"),
    ]
    for t in threads:
        t.start()
    log("Monitor threads started (console + runner + state)", "INFO")

    # ── Wait ───────────────────────────────────────────────────────────────────
    MAX_WAIT = 5 * 3600   # 5-hour hard cap
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
        log("Interrupted — generating summary...", "WARN")
        stop_event.set()

    time.sleep(5)   # let final events drain

    # ── Final snapshot ─────────────────────────────────────────────────────────
    try:
        fs = api_get("/api/status")
        phases = fs.get("phases", [])
        completed = sum(1 for p in phases if p.get("status") == "complete")
        failed    = sum(1 for p in phases if p.get("status") in ("error", "failed"))
        total     = len(phases)
        log(f"Final: {completed}/{total} phases complete, {failed} failed", "INFO")
        # Capture any final phase errors not yet seen
        for ph in phases:
            name   = ph.get("name", "")
            status = ph.get("status", "")
            if status in ("error", "failed") and name not in phase_status:
                msg = f"Phase '{name}' → {status}"
                errors.append({"phase": name, "type": "final_status", "msg": msg})
                phase_errors[name].append(msg)
    except Exception:
        pass

    write_summary()


if __name__ == "__main__":
    main()
