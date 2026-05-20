"""Inject EVENTBUS + TIER2 + TIER4A hardening blocks into Sprint 4/5 modules that are missing them."""
from __future__ import annotations
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))

# Sprint 5: encoder, interactive_mode, intercept need full hardening
# Sprint 4: all 5 need TIER2/TIER4A/EventBus (some also need _robust_stats wiring)
TARGETS = [
    # (subdir, module_name)
    ("testing_tools", "encoder"),
    ("testing_tools", "interactive_mode"),
    ("testing_tools", "intercept"),
    ("scanners", "timing_attack_scanner"),
    ("scanners", "rate_limit_tester"),
    ("scanners", "response_time_analyzer"),
    ("scanners", "vuln_intel_advisor"),
    ("scanners", "web_cache_tester"),
]

EVENTBUS_BLOCK = """\
# __EVENTBUS_INJECTED__
try:
    from ..event_bus import get_event_bus as _get_bus, BusEventType as _BET  # type: ignore
except Exception:  # pragma: no cover
    _get_bus = None  # type: ignore
    _BET = None  # type: ignore


def _emit(topic, data=None):
    \"\"\"Fire-and-forget EventBus emit; no-op if bus unavailable.\"\"\"
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
            emit_fn(resolved, data or {})
    except Exception:
        pass

"""

TIER2_BLOCK = """\
# __TIER2_HELPERS_INJECTED__
try:
    from .._recovered_support import (
        get_logger as _rs_logger,
        get_metrics as _rs_metrics,
        require_scope as _rs_require_scope,
        create_session as _rs_session,
        RateLimiter as _RSRateLimiter,
        retry as _rs_retry,
        audit_log as _rs_audit,
        timed as _rs_timed,
    )
except Exception:  # pragma: no cover
    from contextlib import contextmanager as _cm

    def _rs_logger(*_a, **_kw):
        import logging as _l
        return _l.getLogger(__name__)

    def _rs_metrics():
        class _N:
            def increment(self, *a, **k): pass
            def gauge(self, *a, **k): pass
            def observe(self, *a, **k): pass
            @_cm
            def timer(self, *a, **k):
                yield
        return _N()

    def _rs_require_scope(*_a, **_kw): pass
    def _rs_session(*_a, **_kw): return None

    class _RSRateLimiter:
        def __init__(self, *_a, **_kw): pass
        def wait(self): pass

    def _rs_retry(**_kw):
        def _d(f): return f
        return _d

    def _rs_audit(*_a, **_kw): pass

    @_cm
    def _rs_timed(*_a, **_kw):
        yield
# __EVENTBUS_INJECTED_END__

"""


def tier4a_block(module_name: str) -> str:
    class_prefix = "".join(p.capitalize() for p in module_name.split("_"))
    return f"""\
# __TIER4A_ERRORS__
try:
    from .._recovered_support import make_error_classes as _rs_make_errors
    _RS_ERRORS = _rs_make_errors('{module_name}')
    {class_prefix}Error = _RS_ERRORS['{class_prefix}Error']
    {class_prefix}ConfigError = _RS_ERRORS['{class_prefix}ConfigError']
    {class_prefix}OperationError = _RS_ERRORS['{class_prefix}OperationError']
    {class_prefix}TimeoutError = _RS_ERRORS['{class_prefix}TimeoutError']
except Exception:
    class {class_prefix}Error(Exception): pass
    class {class_prefix}ConfigError({class_prefix}Error): pass
    class {class_prefix}OperationError({class_prefix}Error): pass
    class {class_prefix}TimeoutError({class_prefix}Error): pass

"""


ROOT = pathlib.Path("tools/burp_enterprise")

for subdir, name in TARGETS:
    path = ROOT / subdir / f"{name}.py"
    if not path.exists():
        print(f"  [MISS] {subdir}/{name}.py")
        continue

    src = path.read_text(encoding="utf-8")

    if "__TIER2_HELPERS_INJECTED__" in src:
        print(f"  [SKIP already has TIER2] {subdir}/{name}.py")
        continue

    lines = src.splitlines(keepends=True)

    # Find injection point: after logger = logging.getLogger line
    inject_after = -1
    for i, line in enumerate(lines):
        if line.strip().startswith("logger = logging.getLogger"):
            inject_after = i
            break

    if inject_after == -1:
        # Fallback: after last import statement in the first 30 lines
        for i in range(min(30, len(lines))):
            if lines[i].startswith("import ") or lines[i].startswith("from "):
                inject_after = i
        print(f"  [WARN fallback at line {inject_after + 1}] {subdir}/{name}.py")
    else:
        print(f"  [OK inject after line {inject_after + 1}] {subdir}/{name}.py")

    hardening = "\n" + EVENTBUS_BLOCK + TIER2_BLOCK + tier4a_block(name)
    new_lines = lines[:inject_after + 1] + [hardening] + lines[inject_after + 1:]
    path.write_text("".join(new_lines), encoding="utf-8")
    print(f"  [INJECTED] {subdir}/{name}.py")

print()
print("Done.")
