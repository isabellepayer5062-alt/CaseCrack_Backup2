"""
Scan Run 3 console monitor — deduplicates by (ts, text) composite key.
Polls /api/standalone/console and /api/standalone/status until is_complete=True.
"""
import requests
import time
import os
from datetime import datetime

TOKEN = "Bt2_JT92onXgTOdcfuKABZ8Ym8i-jwtFPrrf2-wPFXw"
BASE = "http://127.0.0.1:8770"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}
LOG_FILE = "CaseCrack/reports/scan-run3-console-20260504.txt"

seen_keys: set = set()
last_status_str = ""
poll_interval = 4.0

os.makedirs("CaseCrack/reports", exist_ok=True)


def ts():
    return datetime.now().strftime("%H:%M:%S")


def format_entry(entry):
    ets = entry.get("ts", "")[:19].replace("T", " ")
    phase = entry.get("phase", "")
    level = entry.get("level", "info")
    text = entry.get("text", "")
    level_tag = {"error": "[-]", "warning": "[!]", "info": "[*]", "cmd": "$"}.get(level, "[*]")
    if phase and phase not in ("preflight", "init"):
        return f"[{ets}] [{phase}] {level_tag} {text}"
    return f"[{ets}] {level_tag} {text}"


with open(LOG_FILE, "w", encoding="utf-8") as log:
    log.write(f"=== SCAN RUN 3 — sugarrushed.ca — {datetime.now().isoformat()} ===\n\n")
    log.flush()

    print(f"[{ts()}] Logging to {LOG_FILE}", flush=True)
    start_time = time.time()

    while True:
        try:
            # ── Status ───────────────────────────────────────────────────
            r = requests.get(f"{BASE}/api/standalone/status", headers=HEADERS, timeout=10)
            is_complete = False
            if r.status_code == 200:
                status = r.json()
                completed = status.get("completed_phases", 0)
                total_phases = len(status.get("phase_status", {})) or status.get("total_phases", 0)
                is_complete = status.get("is_complete", False)
                findings = status.get("findings", 0)
                current = status.get("current_phase", "")

                status_str = f"{completed}/{total_phases}|{findings}|{current}|{is_complete}"
                if status_str != last_status_str:
                    line = f"[{ts()}] STATUS: {completed}/{total_phases} phases | findings={findings} | current={current} | complete={is_complete}"
                    log.write(line + "\n")
                    log.flush()
                    print(line, flush=True)
                    last_status_str = status_str

            # ── Console entries ──────────────────────────────────────────
            r2 = requests.get(f"{BASE}/api/standalone/console", headers=HEADERS, timeout=15)
            if r2.status_code == 200:
                data = r2.json()
                entries = data.get("lines", data.get("entries", []))
                new_count = 0
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    # Composite dedup key: timestamp + text (ts is unique per event)
                    dedup_key = entry.get("ts", "") + "|" + entry.get("text", "")
                    if dedup_key not in seen_keys:
                        seen_keys.add(dedup_key)
                        log.write(format_entry(entry) + "\n")
                        new_count += 1
                if new_count:
                    log.flush()

            if is_complete:
                elapsed = int(time.time() - start_time)
                log.write(f"\n=== SCAN COMPLETE at {datetime.now().isoformat()} ===\n")
                log.write(f"Total time: {elapsed}s | Phases: {completed}/{total_phases} | Findings: {findings}\n")
                log.flush()
                print(f"[{ts()}] SCAN COMPLETE — {completed}/{total_phases} phases, {findings} findings, {elapsed}s", flush=True)
                break

            # 65-minute hard timeout
            if time.time() - start_time > 3900:
                log.write(f"\n=== MONITOR TIMEOUT (65 min) at {datetime.now().isoformat()} ===\n")
                log.flush()
                print(f"[{ts()}] Monitor timeout (65 min)", flush=True)
                break

        except Exception as e:
            msg = f"[{ts()}] Monitor error: {e}"
            log.write(msg + "\n")
            log.flush()
            print(msg, flush=True)

        time.sleep(poll_interval)

print(f"[{ts()}] Monitor finished — log at {LOG_FILE}", flush=True)
