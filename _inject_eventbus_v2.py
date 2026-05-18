"""Revert and re-inject EventBus more safely.

Strategy: place the EventBus block at TOP of file, right after imports
(before any decorator/class/dataclass), so we never split decorators from classes.
"""
from __future__ import annotations
from pathlib import Path
import re

ROOT = Path(__file__).parent / "CaseCrack" / "tools" / "burp_enterprise"
MARKER_START = "# __EVENTBUS_INJECTED__"
MARKER_END = "# __EVENTBUS_INJECTED_END__"

INJECT_BLOCK = f'''
{MARKER_START}
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
        resolved = topic
        if _BET is not None and isinstance(topic, str):
            resolved = getattr(_BET, topic.upper(), topic)
        emit_fn = getattr(bus, "emit", None)
        if emit_fn:
            emit_fn(resolved, data or {{}})
    except Exception:
        pass
{MARKER_END}
'''

MODULES = {
    "network": ["dns_resolver", "http_fingerprint", "proxy_chain", "ssl_analyzer", "traffic_analyzer"],
    "integrations": ["ci_cd_pipeline", "defect_dojo", "jira_client", "slack_notifier", "sonarqube", "webhook_dispatcher"],
    "caap": ["caap_coordinator", "chat_interface", "compliance_checker", "discovery_agent",
             "exploitation_agent", "hypothesis_engine", "knowledge_graph", "recon_agent", "session_orchestrator"],
    "testing_tools": ["api_fuzzer", "benchmark_runner", "compliance_validator", "integration_harness",
                      "load_tester", "mock_server", "regression_tracker"],
}


def strip_existing(src: str) -> str:
    """Remove any prior injected block, including malformed splits."""
    # Remove blocks delimited by markers
    pattern = re.compile(
        r"\n?\s*" + re.escape(MARKER_START) + r".*?" + re.escape(MARKER_END) + r"\n?",
        re.DOTALL,
    )
    src = pattern.sub("\n", src)
    # Also remove orphan markers / orphan blocks from prior buggy injection.
    if MARKER_START in src:
        # Surgical: find marker, remove until next 'class ' or 'def ' at column 0 that's NOT _emit
        lines = src.splitlines(keepends=True)
        start = None
        for i, ln in enumerate(lines):
            if MARKER_START in ln:
                start = i
                break
        if start is not None:
            # Walk back to remove trailing blank line + decorator that may have been re-grafted
            # Walk forward: end after '        pass\n' line
            end = start
            for j in range(start, len(lines)):
                if lines[j].strip() == "pass" and (j + 1 < len(lines)):
                    end = j + 1
                    # consume one blank line after
                    if end < len(lines) and lines[end].strip() == "":
                        end += 1
                    break
            del lines[start:end]
            src = "".join(lines)
    return src


def inject(path: Path) -> str:
    src = path.read_text(encoding="utf-8")
    src = strip_existing(src)

    # Find insertion point: after the imports / __all__ / module-level constants,
    # but BEFORE any decorator (@) or any class/def.
    lines = src.splitlines(keepends=True)
    insert_at = len(lines)
    for i, ln in enumerate(lines):
        stripped = ln.lstrip()
        # Stop at first decorator or first top-level class/def
        if stripped.startswith("@") or re.match(r"^(class|def)\s+\w", ln):
            insert_at = i
            break

    # Walk back over any blank lines so decorator stays attached to class
    while insert_at > 0 and lines[insert_at - 1].strip() == "":
        insert_at -= 1

    new_src = "".join(lines[:insert_at]) + INJECT_BLOCK + "\n\n" + "".join(lines[insert_at:])
    path.write_text(new_src, encoding="utf-8")
    return "ok"


def main() -> int:
    for sub, mods in MODULES.items():
        for mod in mods:
            p = ROOT / sub / f"{mod}.py"
            if not p.exists():
                continue
            r = inject(p)
            print(f"  {r:5s} {sub}/{mod}.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
