"""
CaseCrack Full Parallel Recon Monitor — hypixel.net
Starts the recon dashboard, launches a full 40+ phase parallel scan,
and records all console output, events, errors and failures.
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen, Request

# ── configuration ──────────────────────────────────────────────────────────────
TARGET_URL      = "https://hypixel.net"
DASHBOARD_PORT  = 8770
WS_PORT         = 8771
AUTH_TOKEN      = "HypixelScanToken2026XSecure"      # fixed token for this run
PARALLEL        = True
MAX_SLOTS       = 5
BASE_DIR        = Path(__file__).parent
CASECRACK_DIR   = BASE_DIR / "CaseCrack"
PYTHON_EXE      = str(BASE_DIR / "CaseCrack" / ".." / ".venv" / "Scripts" / "python.exe")
# Normalise
PYTHON_EXE      = str(Path(PYTHON_EXE).resolve())

CONSOLE_FILE    = BASE_DIR / "_hypixel_console.txt"
LOG_FILE        = BASE_DIR / "_hypixel_log.jsonl"
SUMMARY_FILE    = BASE_DIR / "_hypixel_summary.txt"

# Issue keywords to flag (case-insensitive)
ISSUE_KEYWORDS  = [
    "error", "exception", "traceback", "crash", "fail",
    "timeout", "killed", "timed out", "unicode", "oserror",
    "zerodivision", "keyerror", "attributeerror", "typeerror",
    "valueerror", "runtimeerror", "connectionerror", "warning",
]

# ── helpers ────────────────────────────────────────────────────────────────────

def ts() -> str:
    """Current time as [MM:SS] elapsed string from start."""
    elapsed = int(time.time() - _START_TIME)
    return f"[{elapsed//60:02d}:{elapsed%60:02d}]"


def log(level: str, msg: str) -> None:
    line = f"{ts()} [{level:<7}] {msg}"
    print(line, flush=True)
    _console_lines.append(line)
    for _attempt in range(8):
        try:
            with open(CONSOLE_FILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            break
        except PermissionError:
            time.sleep(0.1 * (2 ** _attempt))
    # If all retries fail, we already printed to stdout — don't crash.


def write_event(ev: dict) -> None:
    for _attempt in range(8):
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")
            break
        except PermissionError:
            time.sleep(0.1 * (2 ** _attempt))


def _is_dashboard_running() -> bool:
    # /health is public (no auth required) — /api/status would return 401 which
    # Python's urlopen raises as HTTPError, causing a false "not running" result.
    for path in ("/health", "/api/standalone/status"):
        try:
            with urlopen(f"http://localhost:{DASHBOARD_PORT}{path}", timeout=3):
                return True
        except Exception:
            pass
    return False


def _kill_existing_dashboard() -> None:
    """Kill any Python process hosting the dashboard on our port."""
    import socket
    for pid_guess in range(1, 65535):
        pass  # Not iterating PIDs — use netstat
    # Use PowerShell/netstat approach via subprocess
    try:
        result = subprocess.run(
            ["netstat", "-ano"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10
        )
        for line in result.stdout.splitlines():
            if f":{DASHBOARD_PORT}" in line and "LISTENING" in line:
                parts = line.split()
                pid = int(parts[-1])
                subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                                capture_output=True, timeout=5)
                log("INFO", f"Killed existing dashboard process PID {pid}")
                time.sleep(1)
                return
    except Exception as exc:
        log("WARN", f"Could not kill existing dashboard: {exc}")


def _start_dashboard() -> subprocess.Popen:
    """Start the recon dashboard as a background subprocess.
    
    NOTE: Do NOT pass --url to the CLI — that causes an automatic scan start.
    We want to control the scan start via /api/standalone/run instead.
    """
    cmd = [
        PYTHON_EXE, "-m", "tools.burp_enterprise.cli",
        "recon-dashboard", "start",
        "--port", str(DASHBOARD_PORT),
        "--ws-port", str(WS_PORT),
        "--no-open",
        "--auth-token", AUTH_TOKEN,
    ]
    # NOTE: Do NOT pass --parallel/--max-parallel-slots here — those set defaults
    # on the dashboard but the actual parallel mode is specified in /api/standalone/run

    log("INFO", f"Starting dashboard on port {DASHBOARD_PORT}...")

    env = os.environ.copy()
    env["CASECRACK_DASHBOARD_TOKEN"] = AUTH_TOKEN

    proc = subprocess.Popen(
        cmd,
        cwd=str(CASECRACK_DIR),
        stdout=open(BASE_DIR / "_hypixel_dashboard_stdout.log", "w", encoding="utf-8"),
        stderr=subprocess.STDOUT,
        env=env,
        encoding=None,   # binary mode since we opened stdout as text file
    )
    return proc


def _wait_for_dashboard(timeout: int = 60) -> bool:
    deadline = time.time() + timeout
    log("INFO", "Waiting for dashboard to become ready (checking /health — auth-exempt)...")
    while time.time() < deadline:
        if _is_dashboard_running():
            log("INFO", "Dashboard is ready.")
            return True
        time.sleep(1)
    return False


def _api(path: str, data: dict | None = None) -> dict:
    url = f"http://localhost:{DASHBOARD_PORT}{path}"
    body = json.dumps(data).encode() if data is not None else None
    req = Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {AUTH_TOKEN}",
            "Content-Type": "application/json",
        },
        method="POST" if data is not None else "GET",
    )
    try:
        with urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _start_scan() -> dict:
    payload = {
        "target_url": TARGET_URL,
        "parallel": PARALLEL,
        "max_parallel_slots": MAX_SLOTS,
    }
    resp = _api("/api/standalone/run", payload)
    return resp


# ── stats tracking ──────────────────────────────────────────────────────────────
_console_lines: list[str] = []
_issue_lines: list[str] = []
_errors: list[dict] = []
_warnings: list[dict] = []
_findings: list[dict] = []
_phases_with_errors: set[str] = set()
_phase_status: dict[str, str] = {}
_phase_errors: dict[str, list[str]] = defaultdict(list)
_START_TIME = time.time()


def _categorise_console(phase: str, level: str, text: str) -> None:
    """Classify a console line as error, warning, or issue."""
    text_lower = text.lower()
    level_lower = level.lower()

    is_issue = any(kw in text_lower for kw in ISSUE_KEYWORDS)
    is_error = level_lower in ("error", "critical") or "error" in text_lower
    is_warning = level_lower == "warning" or "warning" in text_lower

    if is_error:
        _errors.append({"phase": phase, "text": text})
        _phases_with_errors.add(phase)
    if is_warning:
        _warnings.append({"phase": phase, "text": text})

    if is_issue:
        _issue_lines.append(f"[{phase}] {text}")


# ── WebSocket monitor ─────────────────────────────────────────────────────────

async def _process_event(ev: dict) -> bool:
    """Process a single event. Returns True if scan_complete was signaled."""
    ev_type = ev.get("type", "")
    write_event(ev)

    # ── console / log lines ──
    if ev_type in ("console_output", "console"):
        phase = ev.get("phase", "?")
        level = ev.get("level", "info")
        text  = ev.get("text", ev.get("message", ""))
        _categorise_console(phase, level, text)

        level_upper = level.upper()
        if level_upper in ("ERROR", "CRITICAL"):
            log("ERROR", f"[{phase}] {text}")
        elif level_upper == "WARNING":
            log("WARN", f"[{phase}] {text}")
        else:
            log("INFO", f"[{phase}] {text}")

    # ── console_batch ──
    elif ev_type == "console_batch":
        for line in ev.get("lines", []):
            phase = line.get("phase", line.get("stream", "?"))
            level = line.get("level", "info")
            text  = line.get("text", line.get("message", ""))
            _categorise_console(phase, level, text)

            level_upper = level.upper()
            if level_upper in ("ERROR", "CRITICAL"):
                log("ERROR", f"[{phase}] {text}")
            elif level_upper == "WARNING":
                log("WARN", f"[{phase}] {text}")
            else:
                log("INFO", f"[{phase}] {text}")

    # ── event_batch (container for multiple events) ──
    elif ev_type == "event_batch":
        for sub_ev in ev.get("events", []):
            done = await _process_event(sub_ev)
            if done:
                return True

    # ── findings ──
    elif ev_type == "finding":
        sev = ev.get("severity", "?")
        title = ev.get("title", "?")
        phase = ev.get("phase", "?")
        _findings.append(ev)
        if sev in ("critical", "high"):
            log("FINDING", f"[{sev.upper()}][{phase}] {title}")
        else:
            log("INFO", f"[finding/{sev}][{phase}] {title}")

    # ── phase events ──
    elif ev_type == "phase_start":
        phase = ev.get("phase", "?")
        _phase_status[phase] = "running"
        log("INFO", f"Phase STARTED: {phase}")

    elif ev_type == "phase_complete":
        phase = ev.get("phase", "?")
        _phase_status[phase] = "complete"
        log("INFO", f"Phase COMPLETE: {phase}")

    elif ev_type == "phase_error":
        phase = ev.get("phase", "?")
        msg   = ev.get("message", ev.get("error", "?"))
        _phase_status[phase] = "error"
        _phases_with_errors.add(phase)
        _phase_errors[phase].append(msg)
        log("ERROR", f"Phase ERROR [{phase}]: {msg}")

    # ── scan lifecycle ──
    elif ev_type == "scan_complete":
        log("INFO", "=" * 60)
        log("INFO", "SCAN COMPLETE")
        log("INFO", "=" * 60)
        return True

    elif ev_type == "scan_aborted":
        log("WARN", "Scan ABORTED")
        return True

    elif ev_type == "error":
        msg = ev.get("message", ev.get("error", str(ev)))
        log("ERROR", f"Dashboard error: {msg}")
        _errors.append({"phase": "dashboard", "text": msg})

    elif ev_type not in (
        "heartbeat", "ping", "pong", "state_diff",
        "state_snapshot", "metric", "resource_snapshot",
        "coalescent_update", "auth_ok", "preflight",
        "init",
    ):
        # Log unknown event types for debugging
        log("DEBUG", f"Event [{ev_type}]: {str(ev)[:120]}")

    return False


# ── WebSocket monitor ─────────────────────────────────────────────────────────

async def _monitor_ws(stop_event: asyncio.Event) -> None:
    """Connect to the dashboard WS and stream events until scan completes."""
    import websockets

    ws_url = f"ws://localhost:{WS_PORT}?token={AUTH_TOKEN}"
    log("INFO", f"Connecting to WebSocket: ws://localhost:{WS_PORT}")

    reconnect_delay = 2

    while not stop_event.is_set():
        try:
            async with websockets.connect(ws_url, ping_interval=20, ping_timeout=30,
                                               max_size=64 * 1024 * 1024) as ws:  # 64 MB — dashboard batches can be large
                log("INFO", "WebSocket connected.")
                reconnect_delay = 2

                # Send auth
                await ws.send(json.dumps({"type": "auth", "token": AUTH_TOKEN}))

                async for raw_msg in ws:
                    try:
                        ev = json.loads(raw_msg)
                    except json.JSONDecodeError:
                        continue

                    done = await _process_event(ev)
                    if done:
                        stop_event.set()
                        break

                if stop_event.is_set():
                    break

        except Exception as exc:
            if stop_event.is_set():
                break
            log("WARN", f"WS error ({type(exc).__name__}: {exc}), reconnecting in {reconnect_delay}s...")
            await asyncio.sleep(reconnect_delay)
            reconnect_delay = min(reconnect_delay * 2, 30)


# ── status poller ─────────────────────────────────────────────────────────────

async def _poll_status(stop_event: asyncio.Event) -> None:
    """Periodically poll /api/standalone/status (public) as a fallback to detect scan completion."""
    while not stop_event.is_set():
        await asyncio.sleep(30)
        if stop_event.is_set():
            break
        try:
            # Use public endpoint — no auth needed
            with urlopen(f"http://localhost:{DASHBOARD_PORT}/api/standalone/status", timeout=5) as resp:
                data = json.loads(resp.read())
            running = data.get("running", data.get("scan_running", True))
            phases_done = data.get("phases_completed", data.get("completed_phases", 0))
            total = data.get("phases_total", data.get("total_phases", 0))
            log("POLL", f"Status: phases={phases_done}/{total}, running={running}")

            if not running and phases_done > 0:
                log("INFO", "Status poll: scan appears complete.")
                stop_event.set()
        except Exception as exc:
            log("WARN", f"Status poll error: {exc}")


# ── summary writer ────────────────────────────────────────────────────────────

def _write_summary(elapsed: float) -> None:
    lines: list[str] = []
    sep = "=" * 80

    lines += [
        sep,
        f"FULL RECON — hypixel.net (PARALLEL MODE, {MAX_SLOTS} slots)",
        f"Run completed : {datetime.now(timezone.utc).isoformat()}",
        f"Elapsed       : {int(elapsed)} seconds",
        sep,
        "",
        f"TOTAL ERRORS          : {len(_errors)}",
        f"TOTAL WARNINGS        : {len(_warnings)}",
        f"CONSOLE ISSUE LINES   : {len(_issue_lines)}",
        f"PHASES WITH ERRORS    : {len(_phases_with_errors)}",
        f"TOTAL FINDINGS        : {len(_findings)}",
        f"TOTAL CONSOLE LINES   : {len(_console_lines)}",
        "",
    ]

    # Phase completion status
    lines.append("── PHASE STATUS " + "─" * 64)
    if _phase_status:
        for ph, st in sorted(_phase_status.items()):
            lines.append(f"  {ph:<50} {st}")
    else:
        lines.append("  (no phase events received)")
    lines.append("")

    # Errors by phase
    lines.append("── ERRORS BY PHASE " + "─" * 61)
    if _phase_errors:
        for ph, msgs in sorted(_phase_errors.items()):
            lines.append(f"  [{ph}]")
            for m in msgs[:5]:
                lines.append(f"    {m[:120]}")
    elif _phases_with_errors:
        for ph in sorted(_phases_with_errors):
            lines.append(f"  {ph}")
    else:
        lines.append("  None.")
    lines.append("")

    # All errors (chronological)
    lines.append("── ALL ERRORS (chronological) " + "─" * 50)
    if _errors:
        for i, e in enumerate(_errors[:100], 1):
            lines.append(f"  {i:3}. [{e.get('phase','?')}] {str(e.get('text',''))[:120]}")
    else:
        lines.append("  None.")
    lines.append("")

    # Console issue lines
    lines.append("── CONSOLE ISSUE LINES " + "─" * 57)
    if _issue_lines:
        for il in _issue_lines[:200]:
            lines.append(f"  {il[:140]}")
    else:
        lines.append("  None.")
    lines.append("")

    # Findings by severity
    sev_count: dict[str, int] = defaultdict(int)
    for f in _findings:
        sev_count[f.get("severity", "unknown")] += 1
    lines.append("── FINDINGS BY SEVERITY " + "─" * 56)
    for sev in ("critical", "high", "medium", "low", "info", "unknown"):
        if sev in sev_count:
            lines.append(f"  {sev:<10}: {sev_count[sev]}")
    lines.append(f"  {'TOTAL':<10}: {len(_findings)}")
    lines.append("")

    with open(SUMMARY_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    log("INFO", f"Summary written → {SUMMARY_FILE.name}")


# ── main ───────────────────────────────────────────────────────────────────────

async def _main() -> None:
    global _START_TIME
    _START_TIME = time.time()

    # Clear/init output files
    CONSOLE_FILE.write_text("", encoding="utf-8")
    LOG_FILE.write_text("", encoding="utf-8")

    log("INFO", "=" * 60)
    log("INFO", f"  CaseCrack Full Parallel Recon — hypixel.net")
    log("INFO", "=" * 60)

    # ── Step 1: Kill any existing dashboard ──────────────────────────
    if _is_dashboard_running():
        log("INFO", "Existing dashboard detected — stopping it...")
        # Try graceful stop first
        try:
            _api("/api/session/reset")
            time.sleep(1)
        except Exception:
            pass
        _kill_existing_dashboard()
        time.sleep(2)

    # ── Step 2: Start fresh dashboard ────────────────────────────────
    dash_proc = _start_dashboard()
    if not _wait_for_dashboard(timeout=180):
        log("ERROR", "Dashboard failed to start within 90s — aborting.")
        dash_proc.terminate()
        sys.exit(1)

    # Read back what the dashboard printed for token confirmation
    log("INFO", f"Dashboard ready. Auth token: {AUTH_TOKEN[:8]}...")

    # ── Step 3: Start the scan ────────────────────────────────────────
    log("INFO", f"Starting parallel scan against {TARGET_URL} ...")
    scan_resp = _start_scan()
    log("INFO", f"Scan start response: {json.dumps(scan_resp)}")
    write_event({"type": "scan_start", "target": TARGET_URL, "response": scan_resp})

    if not scan_resp.get("ok"):
        log("ERROR", f"Scan start failed: {scan_resp.get('error', '?')}")
        # Continue monitoring anyway in case it started despite error

    # ── Step 4: Monitor ───────────────────────────────────────────────
    stop_event = asyncio.Event()
    await asyncio.gather(
        _monitor_ws(stop_event),
        _poll_status(stop_event),
    )

    # ── Step 5: Summary ───────────────────────────────────────────────
    elapsed = time.time() - _START_TIME
    log("INFO", f"Total elapsed: {int(elapsed)}s ({elapsed/60:.1f} min)")
    _write_summary(elapsed)

    # Gracefully stop dashboard
    log("INFO", "Stopping dashboard...")
    try:
        _api("/api/session/reset")
    except Exception:
        pass
    try:
        dash_proc.terminate()
    except Exception:
        pass


if __name__ == "__main__":
    asyncio.run(_main())
