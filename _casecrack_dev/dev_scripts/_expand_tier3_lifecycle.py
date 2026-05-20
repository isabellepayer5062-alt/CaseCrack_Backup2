"""Phase 3: Feature depth expansion.

Adds a production lifecycle pack (health/reset/close/metrics_snapshot) to the
*main engine class* of each recovered module — i.e. the last non-dataclass
class. Idempotent via marker `# __TIER3_LIFECYCLE__`.
"""
from __future__ import annotations
import ast
import re
from pathlib import Path

ROOT = Path(__file__).parent / "CaseCrack" / "tools" / "burp_enterprise"
MARKER = "# __TIER3_LIFECYCLE__"

MODULES = {
    "network": [
        "dns_resolver", "http_fingerprint", "proxy_chain", "ssl_analyzer",
        "traffic_analyzer",
    ],
    "integrations": [
        "ci_cd_pipeline", "defect_dojo", "jira_client", "slack_notifier",
        "sonarqube", "webhook_dispatcher",
    ],
    "caap": [
        "caap_coordinator", "chat_interface", "compliance_checker",
        "discovery_agent", "exploitation_agent", "hypothesis_engine",
        "knowledge_graph", "recon_agent", "session_orchestrator",
    ],
    "testing_tools": [
        "api_fuzzer", "benchmark_runner", "compliance_validator",
        "integration_harness", "load_tester", "mock_server",
        "regression_tracker",
    ],
}


def find_main_class(src: str):
    """Return (class_name, end_lineno) of the last non-dataclass class, or None."""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return None
    last = None
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            # detect @dataclass decorator
            is_dc = any(
                (isinstance(d, ast.Name) and d.id == "dataclass") or
                (isinstance(d, ast.Call) and isinstance(d.func, ast.Name)
                 and d.func.id == "dataclass")
                for d in node.decorator_list
            )
            if not is_dc:
                last = (node.name, node.end_lineno, node.body)
    return last


def lifecycle_block(modname: str, classname: str) -> str:
    return f'''
    {MARKER}
    def health(self) -> dict:
        """Return module health snapshot (Tier 3 production lifecycle)."""
        try:
            metrics = _rs_metrics()
            return {{
                "module": "{modname}",
                "class": "{classname}",
                "status": "ok",
                "ready": True,
                "metrics_backend": type(metrics).__name__,
            }}
        except Exception as exc:
            return {{"module": "{modname}", "status": "degraded",
                    "ready": False, "error": str(exc)}}

    def metrics_snapshot(self) -> dict:
        """Return per-instance counters/state for observability dashboards."""
        snap = {{"module": "{modname}", "class": "{classname}"}}
        # Auto-discover countable collections on the instance
        for attr in dir(self):
            if attr.startswith("_") and not attr.startswith("__"):
                try:
                    val = getattr(self, attr)
                except Exception:
                    continue
                if isinstance(val, (list, tuple, set, dict)):
                    snap[f"{{attr.lstrip('_')}}_size"] = len(val)
        return snap

    def reset(self) -> None:
        """Clear in-memory caches/state without breaking external connections."""
        for attr in list(vars(self)):
            try:
                val = getattr(self, attr)
            except Exception:
                continue
            if isinstance(val, list):
                val.clear()
            elif isinstance(val, dict):
                val.clear()
            elif isinstance(val, set):
                val.clear()
        try:
            _emit("MODULE_RESET", {{"module": "{modname}"}})
            _rs_metrics().increment("{modname}.reset.calls")
        except Exception:
            pass

    def close(self) -> None:
        """Release resources (sessions, sockets, file handles)."""
        sess = getattr(self, "_session", None)
        if sess is not None:
            try:
                sess.close()
            except Exception:
                pass
            try:
                self._session = None  # type: ignore[assignment]
            except Exception:
                pass
        self.reset()
        try:
            _emit("MODULE_CLOSED", {{"module": "{modname}"}})
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False
'''


def patch(path: Path, modname: str) -> str:
    src = path.read_text(encoding="utf-8")
    if MARKER in src:
        return "skip"
    info = find_main_class(src)
    if info is None:
        return "no-class"
    classname, end_line, body = info
    block = lifecycle_block(modname, classname)
    lines = src.splitlines(keepends=True)
    # Insert at end of class body. ast end_lineno is 1-based and inclusive of
    # the last statement's last line. We want to insert *after* it but inside
    # the class — meaning before any subsequent top-level construct. Use the
    # class's end_lineno + 0 → insert before line[end_lineno] (0-based).
    insert_at = end_line  # convert 1-based "after" to 0-based "before"
    lines.insert(insert_at, block)
    path.write_text("".join(lines), encoding="utf-8")
    return "ok"


def main() -> int:
    for sub, mods in MODULES.items():
        for m in mods:
            p = ROOT / sub / f"{m}.py"
            if not p.exists():
                print(f"  no-file {sub}/{m}.py")
                continue
            r = patch(p, m)
            print(f"  {r:8s} {sub}/{m}.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
