"""Inject Tier 2 helper imports into the EventBus block of all 27 recovered modules.

Adds, right above `# __EVENTBUS_INJECTED_END__`:

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
    except Exception:
        _rs_logger = lambda *a, **kw: None
        _rs_metrics = lambda: None
        def _rs_require_scope(*a, **kw): pass
        def _rs_session(*a, **kw): return None
        class _RSRateLimiter:  # noqa: D401
            def __init__(self, *_a, **_kw): pass
            def wait(self): pass
        def _rs_retry(**_kw):
            def _d(f): return f
            return _d
        def _rs_audit(*_a, **_kw): pass
        from contextlib import contextmanager as _cm
        @_cm
        def _rs_timed(*_a, **_kw):
            yield

Idempotent: skipped if marker `# __TIER2_HELPERS_INJECTED__` already present.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parent / "CaseCrack" / "tools" / "burp_enterprise"
MARKER_END = "# __EVENTBUS_INJECTED_END__"
MARKER_T2 = "# __TIER2_HELPERS_INJECTED__"

INJECT = '''
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
'''

MODULES = {
    "network": ["dns_resolver", "http_fingerprint", "proxy_chain", "ssl_analyzer", "traffic_analyzer"],
    "integrations": ["ci_cd_pipeline", "defect_dojo", "jira_client", "slack_notifier", "sonarqube", "webhook_dispatcher"],
    "caap": ["caap_coordinator", "chat_interface", "compliance_checker", "discovery_agent",
             "exploitation_agent", "hypothesis_engine", "knowledge_graph", "recon_agent", "session_orchestrator"],
    "testing_tools": ["api_fuzzer", "benchmark_runner", "compliance_validator", "integration_harness",
                      "load_tester", "mock_server", "regression_tracker"],
}


def inject(path: Path) -> str:
    src = path.read_text(encoding="utf-8")
    if MARKER_T2 in src:
        return "skip"
    if MARKER_END not in src:
        return "no-eventbus-block"
    new_src = src.replace(MARKER_END, INJECT.rstrip() + "\n" + MARKER_END, 1)
    path.write_text(new_src, encoding="utf-8")
    return "ok"


def main() -> int:
    for sub, mods in MODULES.items():
        for mod in mods:
            p = ROOT / sub / f"{mod}.py"
            if not p.exists():
                continue
            print(f"  {inject(p):20s} {sub}/{mod}.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
