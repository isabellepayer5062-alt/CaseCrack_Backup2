#!/usr/bin/env python3
"""
Launch script for the Venator Recon Dashboard.
Starts the server in a background process, prints access info,
and auto-opens the browser.
"""
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CASECRACK = ROOT / "CaseCrack"
PORT_FILE = ROOT / ".dashboard_port.json"

def wait_for_server(port: int, timeout: float = 15.0) -> bool:
    """Poll /health until the server responds or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(
                f"http://localhost:{port}/health", timeout=1.0
            ) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.3)
    return False


def main() -> int:
    # Add CaseCrack to path so the package resolves
    env = os.environ.copy()
    python_path = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(CASECRACK) + (os.pathsep + python_path if python_path else "")

    # Use a local scan_data/ directory to avoid the corrupted default Venator
    # AppData path (agent.db was malformed there).  This keeps all databases
    # inside the workspace so they are easy to inspect and reset.
    scan_data_dir = ROOT / "scan_data"
    scan_data_dir.mkdir(parents=True, exist_ok=True)
    (scan_data_dir / "databases").mkdir(parents=True, exist_ok=True)
    if not env.get("VENATOR_DATA_DIR"):
        env["VENATOR_DATA_DIR"] = str(scan_data_dir)

    # Determine ports (auto-scan if 8770 is taken)
    http_port = 8770
    ws_port = 8771

    # Reconfigure stdout for Unicode safety on Windows cp1252 terminals
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    print("=" * 60)
    print("  Venator Recon Dashboard - Launcher")
    print("=" * 60)

    # Start the dashboard as a subprocess so it survives this script exiting
    cmd = [
        sys.executable,
        "-c",
        (
            "import sys; sys.path.insert(0, 'CaseCrack'); "
            "from tools.burp_enterprise.recon_dashboard import ReconDashboard; "
            f"d = ReconDashboard(target_url='', http_port={http_port}, ws_port={ws_port}, "
            "auto_open=False, parallel=True, max_parallel_slots=6); "
            "d.start()"
        ),
    ]

    log_out = open(ROOT / "dashboard_stdout.log", "w", encoding="utf-8")
    log_err = open(ROOT / "dashboard_stderr.log", "w", encoding="utf-8")

    proc = subprocess.Popen(
        cmd,
        stdout=log_out,
        stderr=log_err,
        cwd=str(ROOT),
        env=env,
    )

    print(f"[PID {proc.pid}] Starting server ...")
    print(f"[Logs]  dashboard_stdout.log / dashboard_stderr.log")

    # Wait for port-discovery file or health endpoint
    discovered_port = None
    for _ in range(40):  # up to ~12 s
        time.sleep(0.3)
        if PORT_FILE.exists():
            try:
                data = json.loads(PORT_FILE.read_text(encoding="utf-8"))
                discovered_port = data.get("http_port")
                if discovered_port:
                    break
            except Exception:
                pass
        # Also try direct health check on requested port
        if wait_for_server(http_port, timeout=0.5):
            discovered_port = http_port
            break

    if discovered_port is None:
        print("[ERROR] Server did not start within timeout.")
        print("        Check dashboard_stderr.log for details.")
        proc.terminate()
        return 1

    print(f"[OK]    HTTP  -> http://localhost:{discovered_port}")
    print(f"[OK]    WS    -> ws://localhost:{discovered_port + 1}")

    # Fetch token
    try:
        with urllib.request.urlopen(
            f"http://localhost:{discovered_port}/api/token", timeout=2
        ) as resp:
            token_data = json.loads(resp.read())
            token = token_data.get("token", "")
            session_id = token_data.get("session_id", "")
            if token:
                masked = token[:6] + "..." + token[-4:]
                print(f"[OK]    Token -> {masked}")
            if session_id:
                print(f"[OK]    Session -> {session_id[:16]}...")
    except Exception as exc:
        print(f"[WARN]  Could not fetch token: {exc}")

    # Open browser
    url = f"http://localhost:{discovered_port}"
    print(f"[Open]  {url}")
    try:
        import webbrowser
        webbrowser.open(url)
    except Exception as exc:
        print(f"[WARN]  Could not auto-open browser: {exc}")

    print("=" * 60)
    print("  Dashboard is running. Press Ctrl+C here to stop.")
    print("=" * 60)

    # Save PID for later management
    (ROOT / ".dashboard_pid.txt").write_text(str(proc.pid), encoding="utf-8")

    try:
        proc.wait()
    except KeyboardInterrupt:
        print("\n[Stop]  Shutting down dashboard ...")
        proc.terminate()
        proc.wait(timeout=10)
        print("[Done]  Dashboard stopped.")
    finally:
        log_out.close()
        log_err.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
