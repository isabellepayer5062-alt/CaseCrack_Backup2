#!/usr/bin/env python3
"""
End-to-End System Test Harness
================================

A single-file, comprehensive harness that:

  1. Self-maps the backend wiring (AST-based import graph).
  2. Attempts to import every module under ``tools.burp_enterprise`` and
     records ImportError / SyntaxError / side-effect crashes.
  3. Probes the major subsystems (LLM bridge, ML / Bayesian prioritizer,
     event bus, tool-wrapper registry, canonical finding pipeline,
     StandaloneReconRunner) — NOT mocked, actually instantiated.
  4. Executes a live, targeted scan against https://sugarrushed.ca using
     the canonical ``StandaloneReconRunner`` (31-phase pipeline) with a
     direct ``event_callback`` capturing every event the backend emits.
  5. Captures EVERY failure across the full suite — LLM, ML, tool
     execution, logic, unhandled exceptions, stderr from subprocess
     scans, and warnings-level log records from any module — into a
     single unified JSON + Markdown report.

Run:
    .venv\\Scripts\\python.exe e2e_test_harness.py                  # default scan
    .venv\\Scripts\\python.exe e2e_test_harness.py --full            # all 31 phases
    .venv\\Scripts\\python.exe e2e_test_harness.py --no-scan         # static audit only
    .venv\\Scripts\\python.exe e2e_test_harness.py --target URL      # override target

Outputs (in ``./e2e_harness_reports/<timestamp>/``):
    report.md           — human-readable summary
    report.json         — full structured results
    wiring_graph.json   — module → module import edges
    events.jsonl        — every event emitted during the live scan
    errors.jsonl        — every captured failure, categorized
    all.log             — raw logging output at DEBUG level
"""
from __future__ import annotations

import argparse
import ast
import importlib
import io
import json
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
import traceback
import warnings
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Bootstrap ────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent
CC_ROOT = ROOT / "CaseCrack"
PKG_ROOT = CC_ROOT / "tools" / "burp_enterprise"
if str(CC_ROOT) not in sys.path:
    sys.path.insert(0, str(CC_ROOT))

OUT_ROOT = ROOT / "e2e_harness_reports"
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
OUT_DIR = OUT_ROOT / RUN_TS
OUT_DIR.mkdir(parents=True, exist_ok=True)

# ── Universal failure capture ────────────────────────────────────────
_ERRORS: list[dict[str, Any]] = []
_ERRORS_LOCK = threading.Lock()
_EVENTS: list[dict[str, Any]] = []
_EVENTS_LOCK = threading.Lock()


def _classify(msg: str, source: str) -> str:
    m = (msg or "").lower()
    s = (source or "").lower()
    if "llm" in s or "llm" in m or "openai" in m or "anthropic" in m or "ollama" in m or "prompt" in m:
        return "LLM"
    if any(k in s for k in ("bayesian", "ml_", "weight_tuner", "reasoning", "qtable", "inference")):
        return "ML"
    if any(k in s for k in ("tool_wrapper", "command_executor", "subprocess", "docker", "tool_registry")):
        return "TOOL"
    if any(k in m for k in ("connection", "timeout", "refused", "dns", "tls", "ssl", "network")):
        return "NETWORK"
    if "import" in m or "syntax" in m or "modulenotfound" in m:
        return "IMPORT"
    if any(k in s for k in ("orchestrator", "runner", "phase", "pipeline", "event_bus", "finding")):
        return "LOGIC"
    return "OTHER"


def record_error(
    category: str | None,
    source: str,
    message: str,
    *,
    exc: BaseException | None = None,
    extra: dict[str, Any] | None = None,
) -> None:
    entry = {
        "ts": time.time(),
        "category": category or _classify(message, source),
        "source": source,
        "message": message[:5000],
        "exc_type": type(exc).__name__ if exc else None,
        "traceback": "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))[:8000]
        if exc
        else None,
    }
    if extra:
        entry["extra"] = {k: str(v)[:2000] for k, v in extra.items()}
    with _ERRORS_LOCK:
        _ERRORS.append(entry)


class _HarnessLogHandler(logging.Handler):
    """Capture every WARNING+ log record from any module into _ERRORS."""

    def emit(self, record: logging.LogRecord) -> None:  # noqa: D401
        try:
            if record.levelno < logging.WARNING:
                return
            msg = record.getMessage()
            record_error(
                None,
                f"log:{record.name}",
                f"[{record.levelname}] {msg}",
                extra={"pathname": record.pathname, "lineno": record.lineno},
            )
        except Exception:
            pass


def _install_global_capture() -> logging.Handler:
    # Global logger capture
    handler = _HarnessLogHandler()
    handler.setLevel(logging.WARNING)
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(handler)

    # Also tee everything to disk at DEBUG
    fh = logging.FileHandler(OUT_DIR / "all.log", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    root.addHandler(fh)

    # Route warnings through logging
    logging.captureWarnings(True)
    warnings.simplefilter("default")

    # Unraisable / threading / sys.excepthook
    def _excepthook(exc_type, exc, tb):
        record_error(None, "sys.excepthook", f"{exc_type.__name__}: {exc}", exc=exc)

    sys.excepthook = _excepthook

    def _threadhook(args):  # type: ignore[no-untyped-def]
        record_error(
            None,
            f"thread:{args.thread.name if args.thread else '?'}",
            f"{args.exc_type.__name__}: {args.exc_value}",
            exc=args.exc_value,
        )

    try:
        threading.excepthook = _threadhook  # type: ignore[assignment]
    except Exception:
        pass

    return handler


# ── STAGE 1: Wiring self-map via AST ─────────────────────────────────
def build_wiring_graph() -> dict[str, Any]:
    """Scan every .py file under ``tools/burp_enterprise`` and build an
    import graph using the AST (no execution)."""
    edges: list[tuple[str, str]] = []
    nodes: set[str] = set()
    syntax_errors: list[dict[str, Any]] = []
    file_count = 0

    for path in PKG_ROOT.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        if "_archive" in path.parts:
            continue
        file_count += 1
        rel = path.relative_to(CC_ROOT).with_suffix("")
        mod = ".".join(rel.parts)
        if mod.endswith(".__init__"):
            mod = mod[: -len(".__init__")]
        nodes.add(mod)
        try:
            src = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(src, filename=str(path))
        except SyntaxError as e:
            syntax_errors.append(
                {"module": mod, "line": e.lineno, "msg": str(e), "file": str(path)}
            )
            record_error("IMPORT", mod, f"SyntaxError in {path}: {e}", exc=e)
            continue
        except Exception as e:
            record_error("IMPORT", mod, f"Parse error in {path}: {e}", exc=e)
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("tools."):
                        edges.append((mod, alias.name))
            elif isinstance(node, ast.ImportFrom):
                if node.module is None:
                    continue
                target = node.module
                if node.level:
                    # Resolve relative import to absolute
                    parts = mod.split(".")
                    base = parts[: len(parts) - node.level]
                    target = ".".join(base + [node.module]) if node.module else ".".join(base)
                if target.startswith("tools."):
                    edges.append((mod, target))

    # Reachability from a handful of canonical entrypoints
    entrypoints = {
        "tools.burp_enterprise.cli.main",
        "tools.burp_enterprise.recon_dashboard",
        "tools.burp_enterprise.recon_dashboard.runner",
        "tools.burp_enterprise.recon_dashboard.server",
        "tools.burp_enterprise.agents.llm_bridge",
        "tools.burp_enterprise.full_scan_orchestrator",
        "tools.burp_enterprise.event_bus",
    }
    adj: dict[str, set[str]] = defaultdict(set)
    for a, b in edges:
        adj[a].add(b)

    reachable: set[str] = set()
    stack = [e for e in entrypoints if e in nodes]
    while stack:
        n = stack.pop()
        if n in reachable:
            continue
        reachable.add(n)
        for nbr in adj.get(n, ()):
            if nbr in nodes and nbr not in reachable:
                stack.append(nbr)

    # Dangling edges point to modules that don't exist on disk
    dangling = sorted({b for a, b in edges if b.startswith("tools.") and b not in nodes})
    orphans = sorted(nodes - reachable)

    graph = {
        "file_count": file_count,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "reachable_count": len(reachable),
        "orphan_modules": orphans,
        "dangling_imports": dangling,
        "syntax_errors": syntax_errors,
        "entrypoints": sorted(entrypoints & nodes),
    }
    # Save raw graph
    (OUT_DIR / "wiring_graph.json").write_text(
        json.dumps(
            {
                "nodes": sorted(nodes),
                "edges": [{"from": a, "to": b} for a, b in edges],
                "reachable": sorted(reachable),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return graph


# ── STAGE 2: Import smoke of every module ────────────────────────────
def import_every_module(limit: int | None = None) -> dict[str, Any]:
    """Attempt to import every module under ``tools.burp_enterprise``.

    We skip known-heavy side-effect modules that bind ports or spawn
    background threads on import (they are exercised later by Stage 3).
    """
    SKIP_PREFIXES = (
        "tools.burp_enterprise.recon_dashboard.server",
        "tools.burp_enterprise.recon_dashboard.__main__",
        "tools.burp_enterprise.recon_dashboard.appliance_api",
        "tools.burp_enterprise.mcp_server",
        "tools.burp_enterprise.mcp.server",
        "tools.burp_enterprise.cli.__main__",
        "tools.burp_enterprise.cli.daemon",
    )
    ok: list[str] = []
    failed: list[dict[str, Any]] = []

    modules: list[str] = []
    for path in sorted(PKG_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts or "_archive" in path.parts:
            continue
        rel = path.relative_to(CC_ROOT).with_suffix("")
        mod = ".".join(rel.parts)
        if mod.endswith(".__init__"):
            mod = mod[: -len(".__init__")]
        if any(mod.startswith(p) for p in SKIP_PREFIXES):
            continue
        modules.append(mod)

    if limit:
        modules = modules[:limit]

    for mod in modules:
        try:
            importlib.import_module(mod)
            ok.append(mod)
        except BaseException as e:  # catch SystemExit too
            failed.append(
                {"module": mod, "exc_type": type(e).__name__, "error": str(e)[:1000]}
            )
            record_error("IMPORT", mod, f"import failed: {e}", exc=e if isinstance(e, Exception) else None)

    return {
        "attempted": len(modules),
        "ok": len(ok),
        "failed": len(failed),
        "skipped_prefixes": list(SKIP_PREFIXES),
        "failures": failed,
    }


# ── STAGE 3: Subsystem probes ────────────────────────────────────────
def _probe(name: str, fn) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    t0 = time.time()
    try:
        detail = fn()
        return {
            "name": name,
            "ok": True,
            "elapsed_s": round(time.time() - t0, 3),
            "detail": detail,
        }
    except BaseException as e:
        record_error(None, f"probe:{name}", str(e), exc=e if isinstance(e, Exception) else None)
        return {
            "name": name,
            "ok": False,
            "elapsed_s": round(time.time() - t0, 3),
            "error": f"{type(e).__name__}: {e}",
            "traceback": traceback.format_exc()[-2000:],
        }


def probe_event_bus() -> Any:
    from tools.burp_enterprise.event_bus import get_event_bus, reset_global_bus

    reset_global_bus()
    bus = get_event_bus()
    received: list[Any] = []
    bus.subscribe("harness.test", lambda payload: received.append(payload))
    bus.publish("harness.test", {"hello": "world"})
    # Allow async dispatch a beat
    time.sleep(0.2)
    return {"class": type(bus).__name__, "received": len(received)}


def probe_llm_bridge() -> Any:
    from tools.burp_enterprise.agents.llm_bridge import LLMBridge, LLMConfig  # type: ignore

    cfg = LLMConfig.from_env()
    b = LLMBridge(cfg)
    info: dict[str, Any] = {
        "config_provider": getattr(cfg, "provider", None),
        "config_model": getattr(cfg, "model", None),
        "has_client": b.client is not None,
        "router": type(b.router).__name__,
        "tracker": type(b.tracker).__name__,
    }
    # Attempt trivial analysis — we don't want to actually make API calls
    # during a test; just confirm method surface exists.
    for m in ("analyze_response", "generate_hypothesis", "explain_finding", "reason"):
        info[f"has_{m}"] = hasattr(b, m)
    return info


def probe_ml_stack() -> Any:
    out: dict[str, Any] = {}
    from tools.burp_enterprise.bayesian_prioritizer import BayesianPrioritizer  # type: ignore

    bp = BayesianPrioritizer()
    out["bayesian_prioritizer"] = type(bp).__name__
    try:
        from tools.burp_enterprise.exploit_chains.weight_tuner import WeightTuner  # type: ignore

        out["weight_tuner"] = type(WeightTuner()).__name__
    except Exception as e:
        out["weight_tuner_error"] = str(e)
    try:
        from tools.burp_enterprise.qtable_advisor import QTableAdvisor  # type: ignore

        out["qtable_advisor"] = type(QTableAdvisor()).__name__
    except Exception as e:
        out["qtable_advisor_error"] = str(e)
    try:
        from tools.burp_enterprise.hypothesis_engine import HypothesisEngine  # type: ignore

        out["hypothesis_engine"] = type(HypothesisEngine()).__name__
    except Exception as e:
        out["hypothesis_engine_error"] = str(e)
    return out


def probe_canonical_findings() -> Any:
    from tools.burp_enterprise.canonical_finding import normalize_finding, finding_fingerprint

    f = {"title": "Test", "severity": "high", "url": "https://x", "description": "y"}
    n = normalize_finding(f)
    fp = finding_fingerprint(n if isinstance(n, dict) else f)
    return {"normalized_keys": sorted(list(n.keys())) if isinstance(n, dict) else "?", "fingerprint_len": len(fp) if fp else 0}


def probe_tool_wrappers() -> Any:
    out: dict[str, Any] = {}
    try:
        from tools.burp_enterprise import tool_wrapper_bridge as twb  # type: ignore

        # Enumerate providers if possible
        reg = getattr(twb, "ToolWrapperBridge", None)
        if reg:
            try:
                inst = reg()
                out["bridge_class"] = type(inst).__name__
                for attr in ("list_providers", "available_providers", "providers"):
                    if hasattr(inst, attr):
                        v = getattr(inst, attr)
                        out[attr] = v() if callable(v) else list(v)
                        break
            except Exception as e:
                out["bridge_error"] = str(e)
    except Exception as e:
        out["import_error"] = str(e)

    # Check CLI binary availability for common external tools
    bins = [
        "subfinder", "amass", "nuclei", "httpx", "naabu",
        "gau", "waybackurls", "katana", "ffuf", "masscan",
        "nmap", "gowitness", "jsluice", "trufflehog", "gitleaks",
        "docker", "curl",
    ]
    out["binaries"] = {b: bool(shutil.which(b)) for b in bins}
    return out


def probe_runner_construction() -> Any:
    from tools.burp_enterprise.recon_dashboard.runner import StandaloneReconRunner

    r = StandaloneReconRunner(
        target_url="https://example.invalid",
        report_dir=str(OUT_DIR / "_probe_reports"),
    )
    return {
        "class": type(r).__name__,
        "phase_count": r._effective_total_phases,
        "parallel": r._parallel,
    }


def probe_config_loading() -> Any:
    out: dict[str, Any] = {}
    cfg_dir = CC_ROOT / "config"
    out["config_files"] = [p.name for p in cfg_dir.iterdir() if p.is_file()]
    try:
        import yaml  # type: ignore

        prof = cfg_dir / "live_test_profile.yaml"
        if prof.exists():
            out["live_test_profile_keys"] = list(
                (yaml.safe_load(prof.read_text(encoding="utf-8")) or {}).keys()
            )
    except Exception as e:
        out["yaml_error"] = str(e)
    return out


def run_subsystem_probes() -> list[dict[str, Any]]:
    probes = [
        ("event_bus", probe_event_bus),
        ("llm_bridge", probe_llm_bridge),
        ("ml_stack", probe_ml_stack),
        ("canonical_findings", probe_canonical_findings),
        ("tool_wrappers", probe_tool_wrappers),
        ("runner_construction", probe_runner_construction),
        ("config_loading", probe_config_loading),
    ]
    return [_probe(name, fn) for name, fn in probes]


# ── STAGE 4: Live scan ───────────────────────────────────────────────
DEFAULT_PHASES = [
    "Fingerprinting & Technology",
    "Endpoint & Asset Discovery",
    "JS Analysis & Source Maps",
    "Subdomain Discovery",
    "DNS Resolution & Brute-force",
    "TLS & Certificate Analysis",
    "WAF Detection & Fingerprinting",
    "Secrets Scanning",
    "CVE Correlation",
    "OSINT Intelligence",
]


def run_live_scan(target: str, phases: list[str] | None, timeout_s: int) -> dict[str, Any]:
    from tools.burp_enterprise.recon_dashboard.runner import StandaloneReconRunner

    events_path = OUT_DIR / "events.jsonl"
    events_fh = events_path.open("w", encoding="utf-8")
    counters: Counter[str] = Counter()
    findings_by_sev: Counter[str] = Counter()
    per_phase: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "started_at": None,
            "completed_at": None,
            "findings": 0,
            "errors": [],
            "events": 0,
        }
    )
    phase_errors_log: list[dict[str, Any]] = []

    def _cb(event: dict[str, Any]) -> None:
        try:
            with _EVENTS_LOCK:
                _EVENTS.append(event)
            events_fh.write(json.dumps(event, default=str) + "\n")
            events_fh.flush()
            etype = event.get("type") or event.get("event") or "unknown"
            counters[etype] += 1
            phase = event.get("phase") or event.get("phase_name") or ""
            if phase:
                per_phase[phase]["events"] += 1
            if etype in ("phase_start", "phase_started"):
                per_phase[phase]["started_at"] = event.get("ts") or time.time()
            if etype in ("phase_complete", "phase_completed"):
                per_phase[phase]["completed_at"] = event.get("ts") or time.time()
            if etype == "finding":
                per_phase[phase]["findings"] += 1
                sev = (
                    event.get("severity")
                    or event.get("finding", {}).get("severity")
                    or "unknown"
                )
                findings_by_sev[str(sev).lower()] += 1
            if etype in ("error", "phase_error") or event.get("error"):
                err = {
                    "phase": phase,
                    "type": etype,
                    "message": str(event.get("error") or event.get("message") or event)[:2000],
                }
                phase_errors_log.append(err)
                per_phase[phase]["errors"].append(err["message"])
                record_error("LOGIC", f"scan:{phase}", err["message"])
        except Exception as e:
            record_error(None, "event_callback", str(e), exc=e)

    runner = StandaloneReconRunner(
        target_url=target,
        report_dir=str(OUT_DIR / "scan_reports"),
        selected_phases=phases,
        event_callback=_cb,
        parallel=False,  # deterministic order for observability
    )

    scan_start = time.time()
    try:
        thread = runner.start()
    except Exception as e:
        record_error("LOGIC", "runner.start", str(e), exc=e)
        events_fh.close()
        return {"ok": False, "error": str(e), "elapsed_s": 0}

    deadline = scan_start + timeout_s
    last_progress_ts = scan_start
    last_event_count = 0
    while thread.is_alive():
        thread.join(timeout=5)
        now = time.time()
        with _EVENTS_LOCK:
            cur_events = len(_EVENTS)
        if cur_events > last_event_count:
            last_event_count = cur_events
            last_progress_ts = now
        elapsed = now - scan_start
        # Heartbeat to stdout so user sees progress
        print(
            f"  [scan {elapsed:6.1f}s] phases_done={runner._phases_completed}/"
            f"{runner._phases_total} events={cur_events} findings={sum(findings_by_sev.values())}"
            f" current={runner._current_phase!r}",
            flush=True,
        )
        if now > deadline:
            record_error(
                "LOGIC",
                "runner.watchdog",
                f"Scan exceeded {timeout_s}s wall-clock; aborting",
            )
            try:
                runner.abort()
            except Exception as e:
                record_error("LOGIC", "runner.abort", str(e), exc=e)
            thread.join(timeout=30)
            break
        # Stall detector: no new events for 10 minutes
        if now - last_progress_ts > 600:
            record_error(
                "LOGIC",
                "runner.stall",
                f"No events for 600s (phase={runner._current_phase!r}); aborting",
            )
            try:
                runner.abort()
            except Exception:
                pass
            thread.join(timeout=30)
            break

    events_fh.close()
    elapsed = time.time() - scan_start

    # Drain remaining runner errors
    try:
        for e in getattr(runner, "errors", []) or []:
            record_error("LOGIC", "runner.errors", str(e))
    except Exception:
        pass

    return {
        "ok": True,
        "elapsed_s": round(elapsed, 1),
        "target": target,
        "phases_requested": phases or "ALL",
        "phases_completed": runner._phases_completed,
        "phases_total": runner._phases_total,
        "event_type_counts": dict(counters),
        "findings_by_severity": dict(findings_by_sev),
        "total_findings": sum(findings_by_sev.values()),
        "per_phase": {
            k: {**v, "errors": v["errors"][:50]} for k, v in per_phase.items()
        },
        "phase_errors": phase_errors_log[:500],
        "events_path": str(events_path),
    }


# ── STAGE 5: Report generation ───────────────────────────────────────
def write_reports(results: dict[str, Any]) -> None:
    # Errors jsonl
    errors_path = OUT_DIR / "errors.jsonl"
    with _ERRORS_LOCK:
        with errors_path.open("w", encoding="utf-8") as fh:
            for e in _ERRORS:
                fh.write(json.dumps(e, default=str) + "\n")
        err_count = len(_ERRORS)
        categories = Counter(e["category"] for e in _ERRORS)
        by_source = Counter(e["source"] for e in _ERRORS).most_common(25)

    results["error_summary"] = {
        "total": err_count,
        "by_category": dict(categories),
        "top_sources": by_source,
    }

    (OUT_DIR / "report.json").write_text(
        json.dumps(results, indent=2, default=str), encoding="utf-8"
    )

    # Markdown
    md = io.StringIO()
    md.write(f"# End-to-End Test Harness Report\n\n")
    md.write(f"- Run ID: `{RUN_TS}`\n")
    md.write(f"- Output dir: `{OUT_DIR}`\n")
    md.write(f"- Target: `{results.get('config', {}).get('target')}`\n")
    md.write(f"- Start: `{results.get('config', {}).get('start_iso')}`\n")
    md.write(f"- Total wall-clock: **{results.get('elapsed_total_s')}s**\n\n")

    # Wiring
    w = results.get("wiring_graph", {})
    md.write("## Wiring Self-Map\n\n")
    md.write(f"- Files scanned: {w.get('file_count')}\n")
    md.write(f"- Modules: {w.get('node_count')}  |  Edges: {w.get('edge_count')}\n")
    md.write(f"- Reachable from canonical entrypoints: {w.get('reachable_count')}\n")
    md.write(f"- **Orphan modules** (not reached): {len(w.get('orphan_modules', []))}\n")
    md.write(f"- **Dangling imports** (module refs not on disk): {len(w.get('dangling_imports', []))}\n")
    md.write(f"- **Syntax errors**: {len(w.get('syntax_errors', []))}\n")
    if w.get("syntax_errors"):
        md.write("\n### Syntax Errors\n")
        for s in w["syntax_errors"][:50]:
            md.write(f"- `{s['module']}`:{s['line']} — {s['msg']}\n")
    if w.get("dangling_imports"):
        md.write("\n### Dangling Imports (first 50)\n")
        for d in w["dangling_imports"][:50]:
            md.write(f"- `{d}`\n")
    if w.get("orphan_modules"):
        md.write(f"\n### Orphan Modules (first 50 of {len(w['orphan_modules'])})\n")
        for m in w["orphan_modules"][:50]:
            md.write(f"- `{m}`\n")

    # Import smoke
    imp = results.get("import_smoke", {})
    md.write("\n## Module Import Smoke Test\n\n")
    md.write(f"- Attempted: {imp.get('attempted')}\n")
    md.write(f"- OK: {imp.get('ok')}\n")
    md.write(f"- **Failed: {imp.get('failed')}**\n")
    if imp.get("failures"):
        md.write("\n### Import Failures\n")
        for f in imp["failures"][:80]:
            md.write(f"- `{f['module']}` — {f['exc_type']}: {f['error']}\n")

    # Probes
    md.write("\n## Subsystem Probes\n\n")
    md.write("| Probe | OK | Elapsed | Detail |\n|---|---|---|---|\n")
    for p in results.get("probes", []):
        status = "✅" if p.get("ok") else "❌"
        detail = (
            json.dumps(p.get("detail"), default=str)[:200]
            if p.get("ok")
            else p.get("error", "")[:200]
        )
        md.write(
            f"| {p['name']} | {status} | {p['elapsed_s']}s | `{detail}` |\n"
        )
    for p in results.get("probes", []):
        if not p.get("ok"):
            md.write(f"\n### ❌ Probe: {p['name']}\n\n```\n{p.get('traceback','')}\n```\n")

    # Scan
    scan = results.get("live_scan")
    if scan and scan.get("ok"):
        md.write("\n## Live Scan Against Target\n\n")
        md.write(f"- Target: `{scan['target']}`\n")
        md.write(f"- Elapsed: **{scan['elapsed_s']}s**\n")
        md.write(f"- Phases completed: {scan['phases_completed']}/{scan['phases_total']}\n")
        md.write(f"- Total findings: **{scan['total_findings']}**\n")
        if scan.get("findings_by_severity"):
            md.write(
                "- By severity: "
                + ", ".join(f"{k}={v}" for k, v in scan["findings_by_severity"].items())
                + "\n"
            )
        md.write("\n### Event Counts\n")
        for et, n in sorted(scan.get("event_type_counts", {}).items(), key=lambda x: -x[1])[:30]:
            md.write(f"- `{et}`: {n}\n")
        md.write("\n### Per-Phase Summary\n\n")
        md.write("| Phase | Events | Findings | Errors |\n|---|---|---|---|\n")
        for ph, meta in scan.get("per_phase", {}).items():
            md.write(
                f"| {ph} | {meta['events']} | {meta['findings']} | {len(meta['errors'])} |\n"
            )
        if scan.get("phase_errors"):
            md.write("\n### Phase Errors (first 50)\n")
            for err in scan["phase_errors"][:50]:
                md.write(f"- **{err['phase']}** [{err['type']}]: {err['message']}\n")
    elif scan:
        md.write("\n## Live Scan — FAILED\n\n")
        md.write(f"Error: {scan.get('error')}\n")

    # Errors
    md.write("\n## Unified Error Summary\n\n")
    md.write(f"- Total captured failures: **{err_count}**\n")
    md.write("- By category:\n")
    for cat, n in sorted(categories.items(), key=lambda x: -x[1]):
        md.write(f"  - `{cat}`: {n}\n")
    md.write("\n### Top Error Sources\n\n")
    for src, n in by_source:
        md.write(f"- `{src}`: {n}\n")
    md.write(
        f"\n(Full error detail in `{errors_path.name}` and `all.log`.)\n"
    )

    (OUT_DIR / "report.md").write_text(md.getvalue(), encoding="utf-8")


# ── Main ─────────────────────────────────────────────────────────────
def main() -> int:
    p = argparse.ArgumentParser(description="Venator/CaseCrack E2E Test Harness")
    p.add_argument("--target", default="https://sugarrushed.ca", help="Scan target URL")
    p.add_argument("--full", action="store_true", help="Run ALL 31 phases (long)")
    p.add_argument(
        "--phases",
        nargs="*",
        default=None,
        help="Explicit phase names to run (overrides --full)",
    )
    p.add_argument("--no-scan", action="store_true", help="Skip the live scan")
    p.add_argument("--no-imports", action="store_true", help="Skip module import smoke")
    p.add_argument(
        "--timeout", type=int, default=1800, help="Scan wall-clock timeout seconds"
    )
    p.add_argument(
        "--import-limit", type=int, default=None, help="Limit number of modules imported"
    )
    args = p.parse_args()

    _install_global_capture()
    t0 = time.time()
    start_iso = datetime.now(timezone.utc).isoformat()

    results: dict[str, Any] = {
        "config": {
            "target": args.target,
            "full": args.full,
            "phases": args.phases,
            "no_scan": args.no_scan,
            "start_iso": start_iso,
            "python": sys.version.split()[0],
            "platform": sys.platform,
            "cwd": str(ROOT),
        }
    }

    print("─" * 72)
    print(f"  E2E Test Harness  —  run {RUN_TS}")
    print(f"  Output: {OUT_DIR}")
    print("─" * 72)

    # Stage 1
    print("\n[1/4] Building wiring self-map …", flush=True)
    try:
        results["wiring_graph"] = build_wiring_graph()
        w = results["wiring_graph"]
        print(
            f"     modules={w['node_count']} edges={w['edge_count']} "
            f"orphans={len(w['orphan_modules'])} dangling={len(w['dangling_imports'])} "
            f"syntax_err={len(w['syntax_errors'])}"
        )
    except Exception as e:
        record_error("LOGIC", "build_wiring_graph", str(e), exc=e)
        results["wiring_graph"] = {"error": str(e)}

    # Stage 2
    if not args.no_imports:
        print("\n[2/4] Importing every module …", flush=True)
        try:
            results["import_smoke"] = import_every_module(limit=args.import_limit)
            imp = results["import_smoke"]
            print(f"     attempted={imp['attempted']} ok={imp['ok']} failed={imp['failed']}")
        except Exception as e:
            record_error("IMPORT", "import_every_module", str(e), exc=e)
            results["import_smoke"] = {"error": str(e)}
    else:
        results["import_smoke"] = {"skipped": True}

    # Stage 3
    print("\n[3/4] Subsystem probes …", flush=True)
    try:
        results["probes"] = run_subsystem_probes()
        for pr in results["probes"]:
            status = "✅" if pr["ok"] else "❌"
            print(f"     {status} {pr['name']:22s} {pr['elapsed_s']:6.2f}s")
    except Exception as e:
        record_error("LOGIC", "run_subsystem_probes", str(e), exc=e)
        results["probes"] = [{"error": str(e)}]

    # Stage 4
    if not args.no_scan:
        print(f"\n[4/4] Live scan against {args.target} …", flush=True)
        if args.phases:
            selected = args.phases
        elif args.full:
            selected = None  # all
        else:
            selected = DEFAULT_PHASES
        try:
            results["live_scan"] = run_live_scan(
                args.target, selected, timeout_s=args.timeout
            )
        except Exception as e:
            record_error("LOGIC", "run_live_scan", str(e), exc=e)
            results["live_scan"] = {"ok": False, "error": str(e)}
    else:
        results["live_scan"] = {"skipped": True}

    results["elapsed_total_s"] = round(time.time() - t0, 1)
    write_reports(results)

    print("\n" + "─" * 72)
    print(f"  Done in {results['elapsed_total_s']}s")
    print(f"  Report: {OUT_DIR / 'report.md'}")
    print(f"  JSON:   {OUT_DIR / 'report.json'}")
    print(f"  Errors: {len(_ERRORS)} captured  ({OUT_DIR / 'errors.jsonl'})")
    print("─" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
