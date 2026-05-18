#!/usr/bin/env python3
"""
Real-time scan monitor — hjhospitals.org run (2026-05-07)
Target: https://www.hjhospitals.org/

Pulls console feed every 3 s and records:
  • All errors / warnings / failures / degraded phases
  • Attack chains as they're discovered
  • All findings with severity >= MEDIUM

Run:  python _monitor_scan_hjhospitals.py
Output:
  _scan_monitor_hjhospitals.log  (all events)
  _scan_issues_hjhospitals.txt   (issues/errors only)
  _attack_chains_hjhospitals.txt (attack chains only)
"""

import json
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

BASE           = "http://localhost:8770"
LOG_FILE       = "_scan_monitor_hjhospitals.log"
ISSUE_FILE     = "_scan_issues_hjhospitals.txt"
CHAIN_FILE     = "_attack_chains_hjhospitals.txt"
POLL_INTERVAL  = 3  # seconds

TARGET = "https://www.hjhospitals.org/"

def _get_token() -> str:
    """Fetch a fresh API token from the dashboard."""
    try:
        with urllib.request.urlopen("http://localhost:8770/api/token", timeout=5) as r:
            return json.loads(r.read()).get("token", "")
    except Exception:
        return ""

_TOKEN: str = ""  # populated at startup

# ── keywords that flag a console line as an issue ────────────────────────────
ISSUE_KEYWORDS = [
    "error", "traceback", "exception", "failed", "failure",
    "degraded", "crash", "critical", "fatal", "abort",
    "circuit breaker", "OPEN", "timeout", "timed out",
    "connection refused", "cannot connect", "not found",
    "module not found", "importerror", "attributeerror",
    "typeerror", "valueerror", "keyerror", "indexerror",
    "runtimeerror", "notimplementederror", "oserror",
    "permission denied", "access denied", "unauthorized",
    "docker", "cannot pull", "image not found",
    "stall", "hung", "deadlock",
    "unexpected keyword argument",
    "is not a valid",
    "object has no attribute",
    "got an unexpected",
    "no module named",
    "syntax error",
    "assertion error",
    "zero division",
]

# ── patterns that look like issues but aren't ─────────────────────────────────
FALSE_POSITIVE_PATTERNS = [
    "[dorking]",
    "q/s eta=",
    '"failure_count"',
    '"last_failure_at"',
    "polling for oob",
    "polling for callbacks",
    "soft-timeout",
    "tests queued",
    "skipped tests",
    "skipped (",
    "waf/rate-limit",
    "passive observation",
    "fix-84",
    "fix-86",
    "fix-151",
    "cdn_challenge",
    "http 429",
    "port 8080 is closed",
    "zap sidecar not running",
    "mitmproxy sidecar not running",
    "stale production build",
    "42 tests queued",
    "6 skipped",
]

# ── keywords that flag a line as an attack chain event ───────────────────────
CHAIN_KEYWORDS = [
    "attack chain", "chain identified", "chain found", "exploit chain",
    "multi-step", "chained", "pivot", "lateral movement",
    "privilege escalation", "auth bypass", "rce chain",
    "sqli chain", "xss chain", "ssrf chain", "ssti chain",
    "exploit path", "exploitation path", "attack path",
    "high confidence chain", "critical chain",
    "combined impact", "amplified",
]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _is_issue(line: str) -> bool:
    ll = line.lower()
    for fp in FALSE_POSITIVE_PATTERNS:
        if fp.lower() in ll:
            return False
    for kw in ISSUE_KEYWORDS:
        if kw.lower() in ll:
            return True
    return False


def _is_chain(line: str) -> bool:
    ll = line.lower()
    for kw in CHAIN_KEYWORDS:
        if kw in ll:
            return True
    return False


def _fetch(path: str):
    try:
        headers = {}
        if _TOKEN:
            headers["Authorization"] = f"Bearer {_TOKEN}"
        req = urllib.request.Request(f"{BASE}{path}", headers=headers)
        with urllib.request.urlopen(req, timeout=8) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def _post(path: str, payload: dict):
    try:
        data = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
        if _TOKEN:
            headers["Authorization"] = f"Bearer {_TOKEN}"
        req = urllib.request.Request(
            f"{BASE}{path}",
            data=data,
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {"error": str(e)}


def _start_scan() -> str | None:
    """POST to kick off the full parallel scan. Returns a status string."""
    payload = {
        "target_url": TARGET,
        "parallel": True,
    }
    print(f"[{_now()}] Starting scan: POST /api/standalone/run  parallel=true  target={TARGET}")
    result = _post("/api/standalone/run", payload)
    if not result or "error" in result:
        print(f"[{_now()}] ERROR starting scan: {result}")
        return None
    phases = result.get("phases_selected", "?")
    mode   = result.get("execution_mode", "?")
    print(f"[{_now()}] Scan started  phases={phases}  mode={mode}")
    print(f"[{_now()}] Full API response: {json.dumps(result)[:400]}")
    return f"phases={phases} mode={mode}"


def main() -> None:
    global _TOKEN
    _TOKEN = _get_token()
    if not _TOKEN:
        print("FATAL: Could not fetch auth token from http://localhost:8770/api/token")
        sys.exit(1)
    print(f"[{_now()}] Auth token acquired ({_TOKEN[:8]}...)")

    since             = 0
    consecutive_done  = 0
    seen_degraded: set[str]        = set()
    seen_chains:   set[str]        = set()
    total_findings_prev            = 0
    phase_counts: dict[str, int]   = defaultdict(int)

    # ── verify scan is active (or start it if not) ───────────────────────
    status = _fetch("/api/standalone/status")
    if status and len(status.get("phase_status", {})) > 0:
        ph = len(status.get("phase_status", {}))
        print(f"[{_now()}] Scan already running — {ph} phases detected. Attaching monitor.")
        start_tag = f"phases={ph} mode=parallel (already running)"
    else:
        # Scan not running yet — try to start it
        start_tag = _start_scan()
        if not start_tag:
            print("Failed to start scan — aborting monitor.")
            sys.exit(1)

    with open(LOG_FILE,   "w", encoding="utf-8", errors="replace") as log_f, \
         open(ISSUE_FILE, "w", encoding="utf-8", errors="replace") as iss_f, \
         open(CHAIN_FILE, "w", encoding="utf-8", errors="replace") as chain_f:

        hdr = (
            f"=== hjhospitals.org scan monitor started {_now()} UTC ===\n"
            f"=== Target: {TARGET} ===\n"
            f"=== Scan: {start_tag} ===\n"
        )
        for f in (log_f, iss_f, chain_f):
            f.write(hdr)
            f.flush()

        print(hdr.strip())

        while True:
            # ── poll status ──────────────────────────────────────────────
            status = _fetch("/api/standalone/status")
            if status:
                completed  = status.get("completed_phases", 0)
                ps         = status.get("phase_status", {})
                total_ph   = len(ps)
                findings   = status.get("findings_count", 0)
                running    = status.get("running_phases", [])
                is_done    = status.get("is_complete", False)

                # New degraded phases
                for phase, st in ps.items():
                    if st == "degraded" and phase not in seen_degraded:
                        seen_degraded.add(phase)
                        msg = f"[{_now()}] *** DEGRADED PHASE: {phase} ***\n"
                        print(msg.strip())
                        log_f.write(msg); iss_f.write(msg)
                        log_f.flush(); iss_f.flush()

                # Findings burst
                delta = findings - total_findings_prev
                if delta > 0:
                    total_findings_prev = findings

                summary = (
                    f"[{_now()}] {completed}/{total_ph} phases | "
                    f"findings={findings}(+{delta}) | "
                    f"running={' | '.join(running[:4]) if running else 'none'}"
                )
                print(summary)
                log_f.write(summary + "\n"); log_f.flush()

                if is_done:
                    consecutive_done += 1
                    if consecutive_done >= 2:
                        # ── final findings dump ──────────────────────────
                        findings_data = _fetch("/api/standalone/findings")
                        if findings_data:
                            high_med = [
                                f for f in findings_data.get("findings", [])
                                if f.get("severity", "").upper() in ("CRITICAL", "HIGH", "MEDIUM")
                            ]
                            log_f.write(f"\n=== Final HIGH/MEDIUM findings ({len(high_med)}) ===\n")
                            for fi in high_med[:100]:
                                log_f.write(
                                    f"  [{fi.get('severity','?')}] {fi.get('title','?')} "
                                    f"— {fi.get('url', fi.get('target',''))[:120]}\n"
                                )

                        # ── attack graph dump ────────────────────────────
                        ag = _fetch("/api/standalone/attack_graph")
                        if ag:
                            chains = ag.get("attack_chains", [])
                            nodes  = ag.get("node_count", ag.get("nodes", 0))
                            edges  = ag.get("edge_count", ag.get("edges", 0))
                            log_f.write(
                                f"\n=== Attack Graph: nodes={nodes} edges={edges} "
                                f"chains={len(chains)} ===\n"
                            )
                            chain_f.write(
                                f"\n=== FINAL ATTACK GRAPH ===\n"
                                f"nodes={nodes}  edges={edges}  chains={len(chains)}\n"
                            )
                            for c in chains[:50]:
                                chain_f.write(f"  {json.dumps(c)}\n")
                            chain_f.flush()

                        fin_msg = (
                            f"\n[{_now()}] === SCAN COMPLETE ===\n"
                            f"  findings   : {findings}\n"
                            f"  degraded   : {len(seen_degraded)} phases\n"
                            f"  chains seen: {len(seen_chains)}\n"
                        )
                        print(fin_msg)
                        for f in (log_f, iss_f, chain_f):
                            f.write(fin_msg)
                            f.flush()
                        break
                else:
                    consecutive_done = 0

            # ── poll console feed ────────────────────────────────────────
            console = _fetch(f"/api/standalone/console?limit=500&since={since}")
            if console:
                entries = console.get("entries", [])
                for entry in entries:
                    ts    = entry.get("ts", since + 1)
                    if ts <= since:
                        continue
                    since = max(since, ts)

                    level = entry.get("level", "")
                    phase = entry.get("phase", "")
                    text  = entry.get("text", "")
                    line  = f"[{level}][{phase}] {text}"

                    log_f.write(line + "\n")

                    # Issue detection
                    if _is_issue(line):
                        stamp = f"[{_now()}] ISSUE: {line}\n"
                        iss_f.write(stamp)
                        iss_f.flush()
                        print(f"  !! {line[:140]}")

                    # Attack chain detection
                    if _is_chain(line) and line not in seen_chains:
                        seen_chains.add(line)
                        stamp = f"[{_now()}] CHAIN: {line}\n"
                        chain_f.write(stamp)
                        chain_f.flush()
                        print(f"  ** CHAIN: {line[:140]}")

                log_f.flush()

            time.sleep(POLL_INTERVAL)

    print(f"\nDone.")
    print(f"  Log   : {LOG_FILE}")
    print(f"  Issues: {ISSUE_FILE}")
    print(f"  Chains: {CHAIN_FILE}")


if __name__ == "__main__":
    main()
