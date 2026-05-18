# __TIER4B_TESTING__
# Tier 4B Testing — integration_harness: fixtures + JUnit XML
import time as _t4b_time
import json as _t4b_json
import os as _t4b_os
import traceback as _t4b_tb
import threading as _t4b_th
import contextlib as _t4b_ctx
import xml.sax.saxutils as _t4b_sax
import inspect as _t4b_inspect
from typing import Any, Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class _T4BFixture:
    name: str
    setup: Callable[..., Any]
    teardown: Optional[Callable[..., None]] = None
    scope: str = "function"  # function, module, session
    autouse: bool = False
    deps: List[str] = field(default_factory=list)


@dataclass
class _T4BTestCase:
    name: str
    fn: Callable[..., Any]
    fixtures: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    timeout_s: float = 60.0
    skip: bool = False
    skip_reason: str = ""


@dataclass
class _T4BTestResult:
    name: str
    classname: str
    status: str  # pass/fail/error/skip
    duration_s: float
    message: str = ""
    stack_trace: str = ""
    fixtures_used: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    captured_output: str = ""


def _t4b_ih_register_fixture(self, name: str, setup: Callable[..., Any],
                                    teardown: Optional[Callable[..., None]] = None,
                                    scope: str = "function",
                                    autouse: bool = False,
                                    deps: Optional[List[str]] = None) -> bool:
    fixtures: Dict[str, _T4BFixture] = getattr(self, "_t4b_ih_fixtures", None) or {}
    if name in fixtures:
        return False
    fixtures[name] = _T4BFixture(name=name, setup=setup, teardown=teardown,
                                          scope=scope, autouse=autouse, deps=deps or [])
    setattr(self, "_t4b_ih_fixtures", fixtures)
    return True


def _t4b_ih_register_test(self, name: str, fn: Callable[..., Any],
                                 fixtures: Optional[List[str]] = None,
                                 tags: Optional[List[str]] = None,
                                 timeout_s: float = 60.0,
                                 skip: bool = False,
                                 skip_reason: str = "") -> bool:
    tests: List[_T4BTestCase] = getattr(self, "_t4b_ih_tests", None) or []
    tests.append(_T4BTestCase(name=name, fn=fn, fixtures=fixtures or [],
                                   tags=tags or [], timeout_s=timeout_s,
                                   skip=skip, skip_reason=skip_reason))
    setattr(self, "_t4b_ih_tests", tests)
    return True


def _t4b_ih_test(self, name: str, fixtures: Optional[List[str]] = None,
                      tags: Optional[List[str]] = None, timeout_s: float = 60.0,
                      skip: bool = False, skip_reason: str = ""):
    """Decorator form: @harness.test('my_test')"""
    def deco(fn):
        _t4b_ih_register_test(self, name, fn, fixtures, tags, timeout_s, skip, skip_reason)
        return fn
    return deco


def _t4b_ih_fixture(self, name: Optional[str] = None, scope: str = "function",
                          autouse: bool = False, deps: Optional[List[str]] = None,
                          teardown: Optional[Callable] = None):
    """Decorator form: @harness.fixture(name='db')"""
    def deco(fn):
        nm = name or fn.__name__
        _t4b_ih_register_fixture(self, nm, fn, teardown, scope, autouse, deps)
        return fn
    return deco


def _t4b_ih_resolve_fixtures(self, needed: List[str],
                                     scope_cache: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """Resolve fixture deps in topological order, return values + ordered list of names."""
    fixtures: Dict[str, _T4BFixture] = getattr(self, "_t4b_ih_fixtures", {}) or {}
    autos = [f.name for f in fixtures.values() if f.autouse]
    full_needed = list(set(needed) | set(autos))

    # topo sort
    ordered: List[str] = []
    visited: set = set()
    def visit(n: str):
        if n in visited or n not in fixtures:
            return
        visited.add(n)
        for d in fixtures[n].deps:
            visit(d)
        ordered.append(n)
    for n in full_needed:
        visit(n)

    values: Dict[str, Any] = {}
    for n in ordered:
        f = fixtures[n]
        if f.scope in ("session", "module") and n in scope_cache:
            values[n] = scope_cache[n]
            continue
        # call setup with dep values
        sig = _t4b_inspect.signature(f.setup)
        kwargs = {p: values[p] for p in sig.parameters if p in values}
        try:
            v = f.setup(**kwargs)
        except Exception:
            v = None
        values[n] = v
        if f.scope in ("session", "module"):
            scope_cache[n] = v
    return values, ordered


def _t4b_ih_teardown_fixtures(self, used: List[str], values: Dict[str, Any],
                                     scope: str) -> None:
    fixtures: Dict[str, _T4BFixture] = getattr(self, "_t4b_ih_fixtures", {}) or {}
    for n in reversed(used):
        f = fixtures.get(n)
        if not f or not f.teardown:
            continue
        if scope == "function" and f.scope != "function":
            continue
        try:
            sig = _t4b_inspect.signature(f.teardown)
            kwargs = {p: values[p] for p in sig.parameters if p in values}
            f.teardown(**kwargs)
        except Exception:
            pass


def _t4b_ih_run_one(self, tc: _T4BTestCase,
                          scope_cache: Dict[str, Any],
                          classname: str = "harness") -> _T4BTestResult:
    if tc.skip:
        return _T4BTestResult(name=tc.name, classname=classname, status="skip",
                                    duration_s=0.0, message=tc.skip_reason or "skipped",
                                    tags=tc.tags)
    values, used = _t4b_ih_resolve_fixtures(self, tc.fixtures, scope_cache)
    sig = _t4b_inspect.signature(tc.fn)
    kwargs = {p: values[p] for p in sig.parameters if p in values}

    # Capture stdout
    import io as _io
    cap = _io.StringIO()

    t0 = _t4b_time.time()
    status = "pass"
    msg = ""
    trace = ""
    result_holder: List[Any] = [None]
    exc_holder: List[Any] = [None]

    def runner():
        try:
            with _t4b_ctx.redirect_stdout(cap), _t4b_ctx.redirect_stderr(cap):
                result_holder[0] = tc.fn(**kwargs)
        except BaseException as e:
            exc_holder[0] = e

    th = _t4b_th.Thread(target=runner, daemon=True)
    th.start()
    th.join(tc.timeout_s)
    duration = _t4b_time.time() - t0
    if th.is_alive():
        status = "error"
        msg = f"timeout after {tc.timeout_s}s"
    elif exc_holder[0] is not None:
        e = exc_holder[0]
        if isinstance(e, AssertionError):
            status = "fail"
        else:
            status = "error"
        msg = f"{type(e).__name__}: {e}"
        trace = "".join(_t4b_tb.format_exception(type(e), e, e.__traceback__))
    elif result_holder[0] is False:
        status = "fail"
        msg = "test returned False"

    _t4b_ih_teardown_fixtures(self, used, values, "function")

    return _T4BTestResult(name=tc.name, classname=classname, status=status,
                                duration_s=duration, message=msg, stack_trace=trace,
                                fixtures_used=used, tags=tc.tags,
                                captured_output=cap.getvalue()[:4096])


def _t4b_ih_run_all(self, classname: str = "harness",
                          tag_filter: Optional[List[str]] = None) -> Dict[str, Any]:
    tests: List[_T4BTestCase] = getattr(self, "_t4b_ih_tests", []) or []
    if tag_filter:
        tests = [t for t in tests if any(tg in t.tags for tg in tag_filter)]
    scope_cache: Dict[str, Any] = {}
    results: List[_T4BTestResult] = []
    t0 = _t4b_time.time()
    for tc in tests:
        results.append(_t4b_ih_run_one(self, tc, scope_cache, classname))
    elapsed = _t4b_time.time() - t0

    # Teardown session/module fixtures
    fixtures: Dict[str, _T4BFixture] = getattr(self, "_t4b_ih_fixtures", {}) or {}
    for name, val in scope_cache.items():
        f = fixtures.get(name)
        if f and f.teardown:
            try:
                sig = _t4b_inspect.signature(f.teardown)
                if name in sig.parameters:
                    f.teardown(**{name: val})
                else:
                    f.teardown()
            except Exception:
                pass

    by_status: Dict[str, int] = {"pass": 0, "fail": 0, "error": 0, "skip": 0}
    for r in results:
        by_status[r.status] = by_status.get(r.status, 0) + 1
    setattr(self, "_t4b_ih_last_results", results)
    return {
        "ok": True,
        "total": len(results),
        "passed": by_status["pass"],
        "failed": by_status["fail"],
        "errors": by_status["error"],
        "skipped": by_status["skip"],
        "duration_s": elapsed,
        "results": [vars(r) for r in results],
    }


def _t4b_ih_export_junit_xml(self, results: Optional[List[Dict[str, Any]]] = None,
                                      suite_name: str = "harness") -> str:
    """Export results as JUnit XML (compatible with Jenkins, GitLab CI, GitHub Actions)."""
    if results is None:
        last = getattr(self, "_t4b_ih_last_results", [])
        results = [vars(r) for r in last]
    total = len(results)
    failures = sum(1 for r in results if r.get("status") == "fail")
    errors = sum(1 for r in results if r.get("status") == "error")
    skipped = sum(1 for r in results if r.get("status") == "skip")
    total_time = sum(r.get("duration_s", 0) for r in results)
    esc = _t4b_sax.escape
    xml = ['<?xml version="1.0" encoding="UTF-8"?>']
    xml.append('<testsuites>')
    xml.append(f'<testsuite name="{esc(suite_name)}" tests="{total}" '
                  f'failures="{failures}" errors="{errors}" skipped="{skipped}" '
                  f'time="{total_time:.3f}" timestamp="{_t4b_time.strftime("%Y-%m-%dT%H:%M:%S")}">')
    for r in results:
        cn = esc(r.get("classname", "harness"))
        nm = esc(r.get("name", "anon"))
        dur = r.get("duration_s", 0)
        xml.append(f'  <testcase classname="{cn}" name="{nm}" time="{dur:.3f}">')
        status = r.get("status")
        msg = esc(r.get("message", ""))
        trace = esc(r.get("stack_trace", ""))
        if status == "fail":
            xml.append(f'    <failure message="{msg}" type="AssertionError"><![CDATA[{r.get("stack_trace", "")}]]></failure>')
        elif status == "error":
            xml.append(f'    <error message="{msg}" type="Error"><![CDATA[{r.get("stack_trace", "")}]]></error>')
        elif status == "skip":
            xml.append(f'    <skipped message="{msg}"/>')
        captured = r.get("captured_output", "")
        if captured:
            xml.append(f'    <system-out><![CDATA[{captured}]]></system-out>')
        xml.append('  </testcase>')
    xml.append('</testsuite>')
    xml.append('</testsuites>')
    return "\n".join(xml)


def _t4b_ih_save_junit(self, path: str, suite_name: str = "harness") -> Dict[str, Any]:
    xml = _t4b_ih_export_junit_xml(self, suite_name=suite_name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(xml)
    return {"ok": True, "path": path, "size_bytes": len(xml)}


def _t4b_ih_clear(self) -> Dict[str, Any]:
    setattr(self, "_t4b_ih_tests", [])
    setattr(self, "_t4b_ih_fixtures", {})
    setattr(self, "_t4b_ih_last_results", [])
    return {"ok": True}


def _t4b_ih_summary(self) -> Dict[str, Any]:
    return {
        "tests_registered": len(getattr(self, "_t4b_ih_tests", [])),
        "fixtures_registered": len(getattr(self, "_t4b_ih_fixtures", {}) or {}),
        "last_run_count": len(getattr(self, "_t4b_ih_last_results", [])),
    }


# --- Bind to IntegrationHarness -----------------------------------------
try:
    IntegrationHarness.register_fixture = _t4b_ih_register_fixture  # type: ignore[name-defined]
    IntegrationHarness.register_test = _t4b_ih_register_test  # type: ignore[name-defined]
    IntegrationHarness.test = _t4b_ih_test  # type: ignore[name-defined]
    IntegrationHarness.fixture = _t4b_ih_fixture  # type: ignore[name-defined]
    IntegrationHarness.run_all_tests = _t4b_ih_run_all  # type: ignore[name-defined]
    IntegrationHarness.export_junit_xml = _t4b_ih_export_junit_xml  # type: ignore[name-defined]
    IntegrationHarness.save_junit_xml = _t4b_ih_save_junit  # type: ignore[name-defined]
    IntegrationHarness.clear_harness = _t4b_ih_clear  # type: ignore[name-defined]
    IntegrationHarness.harness_summary = _t4b_ih_summary  # type: ignore[name-defined]
except NameError:
    pass
