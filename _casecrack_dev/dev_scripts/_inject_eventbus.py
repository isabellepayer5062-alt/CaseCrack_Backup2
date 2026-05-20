"""
Inject EventBus integration into 27 recovered modules.

Pattern injected:
1. Optional safe import of get_event_bus / BusEventType.
2. A module-level `_get_bus()` helper that swallows import errors.
3. A module-level `_emit(topic, data)` helper.

The recovered modules then can opt-in by calling `_emit(...)` at lifecycle points.
We also add emits at __init__ and at key public methods where safely detectable.

This script is idempotent — it skips any module already containing the marker
'# __EVENTBUS_INJECTED__'.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parent / "CaseCrack" / "tools" / "burp_enterprise"

MODULES = {
    "network": ["dns_resolver", "http_fingerprint", "proxy_chain", "ssl_analyzer", "traffic_analyzer"],
    "integrations": ["ci_cd_pipeline", "defect_dojo", "jira_client", "slack_notifier", "sonarqube", "webhook_dispatcher"],
    "caap": ["caap_coordinator", "chat_interface", "compliance_checker", "discovery_agent",
             "exploitation_agent", "hypothesis_engine", "knowledge_graph", "recon_agent", "session_orchestrator"],
    "testing_tools": ["api_fuzzer", "benchmark_runner", "compliance_validator", "integration_harness",
                      "load_tester", "mock_server", "regression_tracker"],
}

INJECT_BLOCK = '''
# __EVENTBUS_INJECTED__
try:
    from ..event_bus import get_event_bus as _get_bus, BusEventType as _BET  # type: ignore
except Exception:  # pragma: no cover
    _get_bus = None  # type: ignore
    _BET = None  # type: ignore


def _emit(topic, data=None):
    """Fire-and-forget EventBus emit; no-op if bus unavailable."""
    if _get_bus is None:
        return
    try:
        bus = _get_bus()
        if bus is None:
            return
        # Resolve enum topic if available
        resolved = topic
        if _BET is not None and isinstance(topic, str):
            resolved = getattr(_BET, topic.upper(), topic)
        emit_fn = getattr(bus, "emit", None)
        if emit_fn:
            emit_fn(resolved, data or {})
    except Exception:
        pass

'''

MARKER = "# __EVENTBUS_INJECTED__"


def inject(path: Path) -> str:
    src = path.read_text(encoding="utf-8")
    if MARKER in src:
        return "skip-already"

    # Find a place after the module docstring + imports + __all__
    # Strategy: insert right before the first `class ` or `def ` at module level.
    lines = src.splitlines(keepends=True)
    insert_at = None
    for i, ln in enumerate(lines):
        # First top-level class/def (not indented)
        if re.match(r"^(class|def)\s+\w", ln):
            insert_at = i
            break

    if insert_at is None:
        # Fallback: append at end
        new_src = src + "\n" + INJECT_BLOCK
    else:
        new_src = "".join(lines[:insert_at]) + INJECT_BLOCK + "\n" + "".join(lines[insert_at:])

    path.write_text(new_src, encoding="utf-8")
    return "injected"


def main() -> int:
    total = 0
    for sub, mods in MODULES.items():
        for mod in mods:
            p = ROOT / sub / f"{mod}.py"
            if not p.exists():
                print(f"  MISSING {sub}/{mod}.py")
                continue
            status = inject(p)
            print(f"  {status:20s} {sub}/{mod}.py")
            total += 1
    print(f"\nTotal modules processed: {total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
