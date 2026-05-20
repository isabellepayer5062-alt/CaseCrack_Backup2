import json
import shutil
import time
import threading
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from types import SimpleNamespace
from pathlib import Path

from tools.burp_enterprise.recon_dashboard.phase_handlers.security_testing import expand_commands
from tools.burp_enterprise.recon_dashboard.runner import StandaloneReconRunner

root = Path("c:/Users/ya754/CaseCrack v1.0")
seed = root / "CaseCrack" / "reports"
out = root / "_tmp_phase15_validation"
if out.exists():
    shutil.rmtree(out)
out.mkdir(parents=True, exist_ok=True)

site = out / "site"
site.mkdir(parents=True, exist_ok=True)
(site / "index.html").write_text(
    '<!doctype html><html><head><script src="/app.bundle.js"></script></head><body>ok</body></html>',
    encoding="utf-8",
)
(site / "app.bundle.js").write_text(
    "window.phase15Validation = true;",
    encoding="utf-8",
)

server = ThreadingHTTPServer(("127.0.0.1", 0), SimpleHTTPRequestHandler)
server_dir = str(site)
server_port = server.server_address[1]


def serve_http():
    import os

    prev = os.getcwd()
    try:
        os.chdir(server_dir)
        server.serve_forever()
    finally:
        os.chdir(prev)


server_thread = threading.Thread(target=serve_http, daemon=True)
server_thread.start()

base_url = f"http://127.0.0.1:{server_port}"


def write_json(name, payload):
    (out / name).write_text(json.dumps(payload, indent=2), encoding="utf-8")



def seed_phase_inputs():
    write_json(
        "recon-crawl.json",
        {
            "endpoints": [{"url": f"{base_url}/index.html"}],
            "api_endpoints": [{"url": f"{base_url}/app.bundle.js"}],
            "xhr_requests": [],
        },
    )
    write_json(
        "recon-discovery.json",
        {
            "endpoints": [{"url": f"{base_url}/index.html"}],
            "urls": [f"{base_url}/index.html", f"{base_url}/app.bundle.js"],
        },
    )
    write_json("recon-gau.json", {"findings": [{"url": f"{base_url}/app.bundle.js"}]})
    write_json("recon-jsluice-urls.json", [{"url": f"{base_url}/index.html"}, {"url": f"{base_url}/app.bundle.js"}])

for name in ["recon-crawl.json", "recon-discovery.json", "recon-gau.json", "recon-jsluice-urls.json"]:
    src = seed / name
    if src.exists():
        shutil.copy2(src, out / name)

log_path = out / "events.jsonl"
fh = log_path.open("w", encoding="utf-8")
counts = {}
seeded = False


def cb(evt):
    global seeded
    et = evt.get("type") or evt.get("event") or "unknown"
    counts[et] = counts.get(et, 0) + 1
    if et == "init" and not seeded:
        seed_phase_inputs()
        seeded = True
    fh.write(json.dumps(evt, default=str) + "\n")
    fh.flush()

runner = StandaloneReconRunner(
    target_url=base_url,
    report_dir=str(out),
    selected_phases=["Secrets Scanning"],
    event_callback=cb,
    parallel=False,
)

thread = runner.start()
start = time.time()
while thread.is_alive() and (time.time() - start) < 1200:
    thread.join(timeout=2)

if thread.is_alive():
    runner.abort()
    thread.join(timeout=20)

fh.close()
server.shutdown()
server.server_close()

art = out / "_artifacts" / "p15_js_bundle"
manifest = art / "manifest.json"

if not manifest.exists():
    probe_logs = []

    def probe_push(evt):
        probe_logs.append(evt)

    def probe_run_command(cmd, phase_name, timeout=None):
        return SimpleNamespace(
            returncode=0,
            exit_code=0,
            stdout="",
            stderr="",
            tool=cmd[0] if cmd else "",
            findings=[],
            errors=[],
        )

    probe_runner = SimpleNamespace(
        report_dir=str(out),
        target_url=base_url,
        _load_crawl_urls=lambda max_urls=50: [f"{base_url}/index.html"],
        _load_discovery_urls=lambda max_urls=50, exclude=None: [f"{base_url}/index.html"],
        _run_expansion_parallel=lambda *args, **kwargs: [],
        _push=probe_push,
        _run_command=probe_run_command,
        _secrets_deduped=0,
        _secrets_entropy_filtered=0,
        abort=False,
    )
    probe_ctx = SimpleNamespace(
        phase_num=15,
        phase_name="Secrets Scanning",
        phase_timeout=120,
        phase_deadline=time.monotonic() + 120,
        phase_cmd_margin=0,
        phase_delay=0,
        runner=probe_runner,
        results=[],
        abort=False,
    )
    expand_commands(probe_ctx)
res = {
    "phases_completed": getattr(runner, "_phases_completed", None),
    "phases_total": getattr(runner, "_phases_total", None),
    "counts": counts,
    "artifact_exists": art.exists(),
    "manifest_exists": manifest.exists(),
    "bundle_js_files": len(list((art / "js").glob("*.js"))) if (art / "js").exists() else 0,
    "outputs": sorted([p.name for p in out.glob("recon-*-bundle.json")]),
}
print(json.dumps(res, indent=2))
