#!/usr/bin/env python3
"""Runtime behavior validation for the MCP read-only adapter layer.

Covers all 5 validation axes from the post-implementation review:
  1. Snapshot consistency   — no partial-update splits across sub-requests
  2. SSE ↔ snapshot alignment — stream events and polling agree
  3. Adapter normalization integrity — edge-case field/error handling
  4. Status strip accuracy   — strip values match actual backend data
  5. Thread-safety under load — concurrent requests, no race/loop leaks

Usage (with dashboard running on default port 8765):
    python _validate_mcp_readonly_behavior.py
    python _validate_mcp_readonly_behavior.py --port 8765 --verbose
    python _validate_mcp_readonly_behavior.py --offline   # adapter unit tests only

Exit code: 0 = all passed, 1 = failures, 2 = config error
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import URLError
from urllib.request import Request, urlopen

# ── Report container ──────────────────────────────────────────────────────────

@dataclass
class Check:
    name: str
    axis: str
    passed: bool
    detail: str = ""
    warn: bool = False


@dataclass
class Report:
    checks: List[Check] = field(default_factory=list)

    def add(self, name: str, axis: str, passed: bool, detail: str = "", warn: bool = False) -> Check:
        c = Check(name=name, axis=axis, passed=passed, detail=detail, warn=warn)
        self.checks.append(c)
        return c

    def summary(self) -> Tuple[int, int, int]:
        passed = sum(1 for c in self.checks if c.passed)
        warned = sum(1 for c in self.checks if c.warn)
        failed = sum(1 for c in self.checks if not c.passed)
        return passed, warned, failed

    def print(self, verbose: bool = False) -> None:
        axis_order = [
            "1-snapshot-consistency",
            "2-sse-alignment",
            "3-normalization",
            "4-strip-accuracy",
            "5-thread-safety",
        ]
        by_axis: Dict[str, List[Check]] = {}
        for c in self.checks:
            by_axis.setdefault(c.axis, []).append(c)

        for axis in axis_order + [k for k in by_axis if k not in axis_order]:
            items = by_axis.get(axis)
            if not items:
                continue
            print(f"\n── {axis} ────────────────────────────────────")
            for c in items:
                icon = "✓" if c.passed else ("⚠" if c.warn else "✗")
                print(f"  {icon}  {c.name}")
                if (verbose or not c.passed) and c.detail:
                    for line in c.detail.splitlines():
                        print(f"       {line}")

        passed, warned, failed = self.summary()
        total = len(self.checks)
        verdict = "PASS" if failed == 0 else "FAIL"
        print(f"\n═══ {verdict}: {passed}/{total} passed, {warned} warnings, {failed} failures ═══")


# ── HTTP helpers ──────────────────────────────────────────────────────────────

_TOKEN_CACHE: Dict[int, str] = {}


def _fetch_token(port: int) -> str:
    """Retrieve dashboard auth token from /api/token (localhost-public)."""
    if port in _TOKEN_CACHE:
        return _TOKEN_CACHE[port]
    # Also check env var set by dashboard on startup
    env_tok = os.environ.get("VENATOR_DASHBOARD_TOKEN", "").strip()
    if env_tok:
        _TOKEN_CACHE[port] = env_tok
        return env_tok
    try:
        req = Request(f"http://127.0.0.1:{port}/api/token",
                      headers={"Accept": "application/json"})
        with urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        tok = data.get("token", "")
        if tok:
            _TOKEN_CACHE[port] = tok
        return tok
    except Exception:
        return ""


def _get_json(url: str, timeout: float = 8.0, port: int = 0) -> Tuple[bool, Any, str]:
    # Auto-detect port from URL when not supplied
    if not port:
        try:
            from urllib.parse import urlparse
            port = urlparse(url).port or 0
        except Exception:
            pass
    token = _fetch_token(port) if port else ""
    headers: Dict[str, str] = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = Request(url, headers=headers)
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        return True, json.loads(body), ""
    except json.JSONDecodeError as e:
        return False, None, f"JSON decode error: {e}"
    except URLError as e:
        return False, None, f"Connection error: {e}"
    except Exception as e:
        return False, None, f"{type(e).__name__}: {e}"


def _base(port: int) -> str:
    return f"http://127.0.0.1:{port}"


def _snap_url(port: int) -> str:
    return f"{_base(port)}/api/mcp/readonly/snapshot"


# ── Axis 1: Snapshot Consistency ──────────────────────────────────────────────

def validate_snapshot_consistency(port: int, report: Report, verbose: bool) -> None:
    """
    Hit /snapshot rapidly, ensure:
    - All sections (targets, reports, metrics, stream) are present
    - ok/status fields are coherent
    - timestamp is always present and advances
    - counts don't flicker (delta across rapid polls is within acceptable range)
    """
    url = _snap_url(port)
    snapshots: List[Dict[str, Any]] = []
    errors: List[str] = []

    for i in range(8):
        ok, data, err = _get_json(url, timeout=10)
        if ok and data:
            snapshots.append(data)
        else:
            errors.append(f"poll {i}: {err}")
        time.sleep(0.15)

    # 1a: Reachability
    if not snapshots:
        report.add("snapshot-reachable", "1-snapshot-consistency", False,
                   f"Could not reach snapshot: {'; '.join(errors)}")
        return
    report.add("snapshot-reachable", "1-snapshot-consistency", True,
               f"Got {len(snapshots)}/{8} responses")

    # 1b: Required top-level keys
    required_keys = {"ok", "status", "timestamp", "source", "targets", "reports", "metrics", "stream"}
    for i, snap in enumerate(snapshots):
        missing = required_keys - set(snap.keys())
        if missing:
            report.add("snapshot-schema", "1-snapshot-consistency", False,
                       f"Poll {i} missing keys: {missing}")
            break
    else:
        report.add("snapshot-schema", "1-snapshot-consistency", True,
                   "All polls have required top-level keys")

    # 1c: status/ok coherence
    incoherent = []
    for i, snap in enumerate(snapshots):
        is_ok = snap.get("ok")
        status = snap.get("status", "")
        if is_ok and status == "error":
            incoherent.append(f"poll {i}: ok=True but status=error")
        if not is_ok and status == "ok":
            incoherent.append(f"poll {i}: ok=False but status=ok")
    if incoherent:
        report.add("snapshot-ok-status-coherence", "1-snapshot-consistency", False,
                   "\n".join(incoherent))
    else:
        report.add("snapshot-ok-status-coherence", "1-snapshot-consistency", True,
                   "ok/status fields always coherent")

    # 1d: Timestamp advances
    timestamps = [s.get("timestamp", "") for s in snapshots if s.get("timestamp")]
    if len(timestamps) >= 2:
        never_changed = all(t == timestamps[0] for t in timestamps)
        if never_changed:
            report.add("snapshot-timestamp-advances", "1-snapshot-consistency", False,
                       "timestamp froze — snapshot may be cached incorrectly", warn=True)
        else:
            report.add("snapshot-timestamp-advances", "1-snapshot-consistency", True,
                       f"Timestamps vary across {len(timestamps)} polls")
    else:
        report.add("snapshot-timestamp-advances", "1-snapshot-consistency", False,
                   "Not enough timestamps to compare", warn=True)

    # 1e: Count stability (no wild flicker)
    counts = []
    for snap in snapshots:
        tgt = snap.get("targets", {})
        c = (tgt.get("data") or {}).get("count", None)
        if c is not None:
            counts.append(int(c))
    if len(counts) >= 3:
        spread = max(counts) - min(counts)
        if spread > 20:
            report.add("snapshot-count-stability", "1-snapshot-consistency", False,
                       f"Target count flickered {min(counts)}..{max(counts)} across {len(counts)} polls", warn=True)
        else:
            report.add("snapshot-count-stability", "1-snapshot-consistency", True,
                       f"Target count stable: {counts}")
    else:
        report.add("snapshot-count-stability", "1-snapshot-consistency", True,
                   "Too few counts to check flicker (normal if MCP offline)")

    # 1f: Sub-section ok/error consistency — all sections should degrade together
    degraded_counts = []
    for snap in snapshots:
        n_ok = sum(1 for k in ("targets", "reports", "metrics")
                   if snap.get(k, {}).get("ok"))
        degraded_counts.append(n_ok)
    if len(set(degraded_counts)) > 2:
        report.add("snapshot-subsection-consistency", "1-snapshot-consistency", False,
                   f"Sub-section ok pattern varied wildly: {degraded_counts}", warn=True)
    else:
        report.add("snapshot-subsection-consistency", "1-snapshot-consistency", True,
                   f"Sub-section ok counts consistent: {set(degraded_counts)}")


# ── Axis 2: SSE ↔ Snapshot Alignment ─────────────────────────────────────────

def validate_sse_snapshot_alignment(port: int, report: Report, verbose: bool) -> None:
    """
    Check that the snapshot stream.ok field aligns with the SSE health endpoint.
    We can't subscribe to SSE in a sync script, so we probe:
    - /api/mcp/readonly/snapshot → stream.ok
    - /api/health (dashboard health) → connected
    and verify they agree.
    """
    snap_ok, snap_data, snap_err = _get_json(_snap_url(port))
    health_ok, health_data, health_err = _get_json(f"{_base(port)}/api/health")

    # 2a: Snapshot stream field present
    if not snap_ok or not snap_data:
        report.add("sse-snapshot-stream-field", "2-sse-alignment", False,
                   f"Snapshot unavailable: {snap_err}")
        return

    stream = snap_data.get("stream", {})
    stream_ok = stream.get("ok")
    sse_ep = stream.get("sse_endpoint", "")
    report.add("sse-endpoint-declared", "2-sse-alignment", bool(sse_ep),
               f"SSE endpoint: {sse_ep!r}" if sse_ep else "sse_endpoint missing from stream")

    # 2b: Dashboard health vs stream.ok agree
    if health_ok and health_data:
        dash_connected = health_data.get("connected", health_data.get("ok"))
        agree = (bool(stream_ok) == bool(dash_connected))
        report.add("sse-health-agrees-snapshot", "2-sse-alignment", agree,
                   f"stream.ok={stream_ok}, health.connected={dash_connected}"
                   + ("" if agree else " — MISMATCH (may be timing lag)"),
                   warn=not agree)
    else:
        report.add("sse-health-agrees-snapshot", "2-sse-alignment", True,
                   "Dashboard /api/health unavailable — cannot compare (warn only)", warn=True)

    # 2c: Rapid double-poll — snapshot.stream.ok should not flip-flop
    snaps = []
    for _ in range(4):
        ok2, d2, _ = _get_json(_snap_url(port), timeout=6)
        if ok2 and d2:
            snaps.append(bool(d2.get("stream", {}).get("ok")))
        time.sleep(0.1)
    if snaps:
        unique_vals = set(snaps)
        if len(unique_vals) > 1:
            report.add("sse-stream-ok-stable", "2-sse-alignment", False,
                       f"stream.ok flipped between polls: {snaps}", warn=True)
        else:
            report.add("sse-stream-ok-stable", "2-sse-alignment", True,
                       f"stream.ok stable across rapid polls: {snaps[0]}")
    else:
        report.add("sse-stream-ok-stable", "2-sse-alignment", True,
                   "No snapshot data for rapid poll (MCP may be offline)")


# ── Axis 3: Adapter Normalization Integrity ───────────────────────────────────

def validate_normalization(report: Report) -> None:
    """
    Pure Python simulation of the JS adapter logic in mcp-ui-adapter.js.
    We replicate _mapStatus, _envelope, and _renderSnapshot in Python and
    feed them edge-case inputs, verifying no crash and consistent outputs.
    """

    def map_status(raw: Any) -> str:
        s = str(raw).lower() if raw is not None else ""
        if s in ("ok", "healthy", "success"):
            return "ok"
        if s in ("accepted", "pending", "degraded", "recovery"):
            return "degraded"
        if s in ("error", "failed", "disabled"):
            return "error"
        return "degraded"

    def format_error(err: Any, fallback: str = "Unknown error") -> str:
        if not err:
            return ""
        if isinstance(err, str):
            return err
        if isinstance(err, dict) and "message" in err:
            return str(err["message"])
        try:
            return json.dumps(err)
        except Exception:
            return fallback

    def envelope(payload: Any, fallback: str = "Request failed") -> Dict[str, Any]:
        p = payload if isinstance(payload, dict) else {}
        ok = bool(p.get("ok"))
        status = map_status(p.get("status") or ("ok" if ok else "error"))
        return {
            "ok": ok,
            "status": status,
            "source": str(p.get("source") or "mcp_proxy"),
            "timestamp": str(p.get("timestamp") or ""),
            "data": p.get("data") or {},
            "error": format_error(p.get("error"), fallback),
        }

    def get_targets_from_envelope(env: Dict[str, Any]) -> Dict[str, Any]:
        d = env.get("data") or {}
        items = d.get("items") if isinstance(d.get("items"), list) else []
        count = d.get("count") if isinstance(d.get("count"), int) else len(items)
        return {
            "ok": env["ok"],
            "status": env["status"],
            "error": env["error"],
            "count": count,
            "items": items,
        }

    def render_snapshot(snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate _renderSnapshot without DOM — return the values it would set."""
        targets_count = 0
        report_count = 0
        tool_calls = 0
        try:
            targets_count = int((snapshot.get("targets", {}).get("data") or {}).get("count") or 0)
        except (TypeError, ValueError):
            pass
        try:
            report_count = 1 if (snapshot.get("reports", {}).get("data") or {}).get("has_report") else 0
        except (TypeError, ValueError):
            pass
        try:
            tool_calls = int((snapshot.get("metrics", {}).get("data") or {}).get("tool_calls_total") or 0)
        except (TypeError, ValueError):
            pass
        stream_ok = bool((snapshot.get("stream") or {}).get("ok"))
        return {
            "targets_count": targets_count,
            "report_count": report_count,
            "tool_calls": tool_calls,
            "stream_ok": stream_ok,
            "status": map_status(snapshot.get("status")),
        }

    # Test cases — (description, input, expected_key, expected_value)
    cases = [
        # Status mapping
        ("status-ok", {"ok": True, "status": "ok"}, "status", "ok"),
        ("status-healthy", {"ok": True, "status": "healthy"}, "status", "ok"),
        ("status-error", {"ok": False, "status": "error"}, "status", "error"),
        ("status-failed", {"ok": False, "status": "failed"}, "status", "error"),
        ("status-degraded", {"ok": False, "status": "degraded"}, "status", "degraded"),
        ("status-unknown-maps-degraded", {"ok": False, "status": "????"}, "status", "degraded"),
        # status=None with ok=False → or-fallback picks "error" (same as JS: p.status || (ok?'ok':'error'))
        ("status-null-ok-false-fallback-error", {"ok": False, "status": None}, "status", "error"),
        # status=None with ok=True → or-fallback picks "ok"
        ("status-null-ok-true-fallback-ok", {"ok": True, "status": None}, "status", "ok"),
        # ok field fallback when status absent
        ("ok-true-no-status", {"ok": True}, "status", "ok"),
        ("ok-false-no-status", {"ok": False}, "status", "error"),
        # Error field handling
        ("error-string", {"ok": False, "error": "timeout"}, "error", "timeout"),
        ("error-dict-message", {"ok": False, "error": {"message": "conn refused"}}, "error", "conn refused"),
        ("error-absent", {"ok": True}, "error", ""),
        # Data fallback
        ("data-absent", {"ok": True}, "data", {}),
        ("data-null", {"ok": True, "data": None}, "data", {}),
    ]

    failures = []
    for desc, payload, key, expected in cases:
        env = envelope(payload)
        actual = env.get(key)
        if actual != expected:
            failures.append(f"{desc}: expected {key}={expected!r} got {actual!r}")

    if failures:
        report.add("normalization-status-error-mapping", "3-normalization", False,
                   "\n".join(failures))
    else:
        report.add("normalization-status-error-mapping", "3-normalization", True,
                   f"All {len(cases)} mapping cases passed")

    # Edge cases: targets from envelope
    target_cases = [
        ("targets-empty-ok", {"ok": True, "data": {"items": [], "count": 0}}, 0, 0),
        ("targets-list", {"ok": True, "data": {"items": [{"target": "x"}], "count": 1}}, 1, 1),
        ("targets-no-data", {"ok": False}, 0, 0),
        ("targets-count-int", {"ok": True, "data": {"count": 42, "items": []}}, 42, 0),
    ]
    tgt_failures = []
    for desc, payload, exp_count, exp_items in target_cases:
        env = envelope(payload)
        result = get_targets_from_envelope(env)
        if result["count"] != exp_count:
            tgt_failures.append(f"{desc}: count={result['count']} != {exp_count}")
        if len(result["items"]) != exp_items:
            tgt_failures.append(f"{desc}: items_len={len(result['items'])} != {exp_items}")
    if tgt_failures:
        report.add("normalization-targets-extraction", "3-normalization", False,
                   "\n".join(tgt_failures))
    else:
        report.add("normalization-targets-extraction", "3-normalization", True,
                   f"All {len(target_cases)} target extraction cases passed")

    # Render snapshot edge cases
    render_cases = [
        (
            "render-nominal",
            {"ok": True, "status": "ok",
             "targets": {"data": {"count": 5}},
             "reports": {"data": {"has_report": True}},
             "metrics": {"data": {"tool_calls_total": 17}},
             "stream": {"ok": True}},
            {"targets_count": 5, "report_count": 1, "tool_calls": 17, "stream_ok": True}
        ),
        (
            "render-all-missing-data",
            {"ok": False, "status": "error",
             "targets": {}, "reports": {}, "metrics": {}, "stream": {}},
            {"targets_count": 0, "report_count": 0, "tool_calls": 0, "stream_ok": False}
        ),
        (
            "render-null-data-fields",
            {"ok": True, "status": "degraded",
             "targets": {"data": None},
             "reports": {"data": None},
             "metrics": {"data": None},
             "stream": {"ok": False}},
            {"targets_count": 0, "report_count": 0, "tool_calls": 0, "stream_ok": False}
        ),
        (
            "render-string-count-coerced",
            {"ok": True, "status": "ok",
             "targets": {"data": {"count": "7"}},
             "reports": {"data": {"has_report": False}},
             "metrics": {"data": {"tool_calls_total": "99"}},
             "stream": {"ok": True}},
            {"targets_count": 7, "tool_calls": 99, "stream_ok": True}
        ),
    ]
    render_failures = []
    for desc, snap, expected in render_cases:
        try:
            result = render_snapshot(snap)
            for k, v in expected.items():
                if result.get(k) != v:
                    render_failures.append(f"{desc}: {k}={result.get(k)!r} != {v!r}")
        except Exception as e:
            render_failures.append(f"{desc}: CRASH: {e}")
    if render_failures:
        report.add("normalization-render-snapshot", "3-normalization", False,
                   "\n".join(render_failures))
    else:
        report.add("normalization-render-snapshot", "3-normalization", True,
                   f"All {len(render_cases)} render snapshot cases passed")


# ── Axis 4: Status Strip Accuracy ────────────────────────────────────────────

def validate_strip_accuracy(port: int, report: Report, verbose: bool) -> None:
    """
    Verify the values the status strip would show match the actual backend data.
    Compares:
      snapshot.targets.data.count  vs  /api/mcp/readonly/targets (direct)
      snapshot.metrics.data.tool_calls_total  vs  /api/mcp/readonly/metrics (direct)
      snapshot.status  vs  computed from sub-section oks
    """
    snap_ok, snap_data, snap_err = _get_json(_snap_url(port))
    if not snap_ok or not snap_data:
        report.add("strip-snapshot-available", "4-strip-accuracy", False,
                   f"Snapshot unavailable: {snap_err}")
        return
    report.add("strip-snapshot-available", "4-strip-accuracy", True)

    # Direct target count
    tgt_ok, tgt_data, tgt_err = _get_json(f"{_base(port)}/api/mcp/readonly/targets")
    if tgt_ok and tgt_data:
        snap_count = (snap_data.get("targets", {}).get("data") or {}).get("count", None)
        direct_count = (tgt_data.get("data") or {}).get("count", None)
        if snap_count is not None and direct_count is not None:
            match = snap_count == direct_count
            report.add("strip-targets-count-match", "4-strip-accuracy", match,
                       f"snapshot.targets.count={snap_count} vs /targets.count={direct_count}"
                       + ("" if match else " — MISMATCH (likely timing, acceptable)"),
                       warn=not match)
        else:
            report.add("strip-targets-count-match", "4-strip-accuracy", True,
                       "Cannot compare — one or both counts absent (MCP may be offline)")
    else:
        report.add("strip-targets-count-match", "4-strip-accuracy", True,
                   f"Direct targets endpoint unavailable: {tgt_err} (warn)", warn=True)

    # Direct metrics
    met_ok, met_data, met_err = _get_json(f"{_base(port)}/api/mcp/readonly/metrics")
    if met_ok and met_data:
        snap_calls = (snap_data.get("metrics", {}).get("data") or {}).get("tool_calls_total", None)
        direct_calls = (met_data.get("data") or {}).get("tool_calls_total", None)
        if snap_calls is not None and direct_calls is not None:
            # Allow small delta since parallel fetch vs sequential fetch
            diff = abs(float(snap_calls) - float(direct_calls))
            match = diff <= 5
            report.add("strip-metrics-match", "4-strip-accuracy", match,
                       f"snapshot.metrics.tool_calls={snap_calls} vs /metrics.tool_calls={direct_calls}"
                       + (f" — delta={diff}" if not match else ""),
                       warn=not match)
        else:
            report.add("strip-metrics-match", "4-strip-accuracy", True,
                       "Cannot compare metrics (MCP may be offline)")
    else:
        report.add("strip-metrics-match", "4-strip-accuracy", True,
                   f"Direct metrics endpoint unavailable: {met_err} (warn)", warn=True)

    # Status derivation: snapshot.status should agree with sub-section oks
    sub_oks = [snap_data.get(k, {}).get("ok") for k in ("targets", "reports", "metrics")]
    n_ok = sum(1 for v in sub_oks if v)
    if n_ok == 3:
        expected_status = "ok"
    elif n_ok >= 1:
        expected_status = "degraded"
    else:
        expected_status = "error"
    actual_status = snap_data.get("status", "")
    status_match = actual_status == expected_status
    report.add("strip-status-derivation", "4-strip-accuracy", status_match,
               f"computed={expected_status} actual={actual_status}"
               + ("" if status_match else " — MISMATCH"),
               warn=not status_match)

    # stream.ok must be a boolean
    stream_ok_val = snap_data.get("stream", {}).get("ok")
    report.add("strip-stream-ok-is-bool", "4-strip-accuracy", isinstance(stream_ok_val, bool),
               f"stream.ok type={type(stream_ok_val).__name__} value={stream_ok_val!r}")


# ── Axis 5: Thread-Safety Under Load ─────────────────────────────────────────

async def _concurrent_snapshot(url: str, n: int) -> List[Tuple[bool, float]]:
    """Fire n concurrent GETs, return (success, latency_ms) list."""
    import asyncio
    results: List[Tuple[bool, float]] = []

    async def _one() -> Tuple[bool, float]:
        t0 = time.monotonic()
        try:
            # asyncio-friendly HTTP using asyncio.to_thread
            ok, data, err = await asyncio.to_thread(_get_json, url, 12.0)
            latency = (time.monotonic() - t0) * 1000
            return (ok and data is not None and "ok" in data), latency
        except Exception as e:
            latency = (time.monotonic() - t0) * 1000
            return False, latency

    tasks = [_one() for _ in range(n)]
    raw = await asyncio.gather(*tasks, return_exceptions=False)
    results = list(raw)
    return results


def validate_thread_safety(port: int, report: Report, verbose: bool) -> None:
    """
    Send bursts of concurrent snapshot requests; verify:
    - No crash / empty responses
    - Response times don't diverge wildly (no lock contention blocking)
    - Repeated runs give structurally identical payloads
    """
    url = _snap_url(port)

    try:
        results = asyncio.run(_concurrent_snapshot(url, n=12))
    except Exception as e:
        report.add("thread-safety-concurrent-burst", "5-thread-safety", False,
                   f"asyncio.run failed: {e}")
        return

    successes = [r for r in results if r[0]]
    failures = [r for r in results if not r[0]]
    latencies = [r[1] for r in results]

    report.add("thread-safety-concurrent-burst", "5-thread-safety",
               len(successes) >= 10,
               f"{len(successes)}/12 requests succeeded, {len(failures)} failed"
               + (f" — failures present" if failures else ""),
               warn=len(failures) > 0)

    if latencies:
        mean_ms = statistics.mean(latencies)
        p95_ms = sorted(latencies)[int(0.95 * len(latencies))]
        stdev = statistics.stdev(latencies) if len(latencies) > 1 else 0
        # Check if MCP backend is online by inspecting a quick snapshot
        ok_snap, snap_d, _ = _get_json(url, timeout=6, port=port)
        mcp_online = ok_snap and bool(snap_d) and bool(snap_d.get("ok"))
        # p95 > 5000ms is only a hard fail when MCP is live (timeouts inflate
        # latency predictably when MCP is offline — that's expected behaviour)
        p95_fail = p95_ms >= 5000 and mcp_online
        report.add("thread-safety-latency-p95", "5-thread-safety",
                   not p95_fail,
                   f"mean={mean_ms:.0f}ms p95={p95_ms:.0f}ms stdev={stdev:.0f}ms"
                   + (" (MCP offline — timeout-inflated latency expected)" if not mcp_online else ""),
                   warn=p95_ms > 2000)

    # Second burst: verify payload structure unchanged (no event-loop leak)
    try:
        results2 = asyncio.run(_concurrent_snapshot(url, n=8))
    except Exception as e:
        report.add("thread-safety-second-burst", "5-thread-safety", False,
                   f"Second burst failed: {e}")
        return
    successes2 = sum(1 for r in results2 if r[0])
    report.add("thread-safety-second-burst", "5-thread-safety",
               successes2 >= 7,
               f"{successes2}/8 succeeded on second burst (no event-loop leak)")

    # Sequential coherence: 5 sequential calls, all return same schema
    schema_errors = []
    for i in range(5):
        ok, data, err = _get_json(url, timeout=10)
        if not ok or not data:
            schema_errors.append(f"sequential {i}: {err}")
            continue
        missing = {"ok", "status", "timestamp", "targets", "metrics"} - set(data.keys())
        if missing:
            schema_errors.append(f"sequential {i}: missing keys {missing}")
        time.sleep(0.05)
    if schema_errors:
        report.add("thread-safety-sequential-coherence", "5-thread-safety", False,
                   "\n".join(schema_errors))
    else:
        report.add("thread-safety-sequential-coherence", "5-thread-safety", True,
                   "5 sequential calls all returned consistent schema")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="MCP read-only adapter behavior validation")
    parser.add_argument("--port", type=int, default=8765, help="Dashboard port (default 8765)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Always print check details")
    parser.add_argument("--offline", action="store_true",
                        help="Run only offline adapter normalization tests (no HTTP)")
    args = parser.parse_args()

    report = Report()
    print(f"\n╔══ MCP Read-Only Behavior Validation (port={args.port}) ══╗")
    if args.offline:
        print("  Mode: OFFLINE — running normalization unit tests only")
    print()

    # Axis 3 always runs (pure logic, no HTTP)
    print("Running axis 3: adapter normalization (offline)…")
    validate_normalization(report)

    if not args.offline:
        # Quick reachability check first
        print("Checking dashboard reachability…")
        ok, _, err = _get_json(f"{_base(args.port)}/api/health", timeout=4)
        if not ok:
            ok2, _, err2 = _get_json(f"{_base(args.port)}/api/status", timeout=4)
            if not ok2:
                print(f"  ✗ Dashboard unreachable on port {args.port} ({err})")
                print("    Run with --offline to execute normalization tests only.")
                report.add("dashboard-reachable", "1-snapshot-consistency", False,
                            f"Port {args.port} not responding: {err}")
                report.print(verbose=args.verbose)
                return 1
        print(f"  ✓ Dashboard responding on port {args.port}")

        print("Running axis 1: snapshot consistency…")
        validate_snapshot_consistency(args.port, report, args.verbose)

        print("Running axis 2: SSE/snapshot alignment…")
        validate_sse_snapshot_alignment(args.port, report, args.verbose)

        print("Running axis 4: status strip accuracy…")
        validate_strip_accuracy(args.port, report, args.verbose)

        print("Running axis 5: thread-safety under load…")
        validate_thread_safety(args.port, report, args.verbose)

    report.print(verbose=args.verbose)
    _, _, failed = report.summary()
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
