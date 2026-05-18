# __TIER4B_TESTING__
# Tier 4B Testing — benchmark_runner: stats + HTML report + cProfile integration
import time as _t4b_time
import math as _t4b_math
import statistics as _t4b_stats
import cProfile as _t4b_cprof
import pstats as _t4b_pstats
import io as _t4b_io
import json as _t4b_json
import os as _t4b_os
import gc as _t4b_gc
import sys as _t4b_sys
import threading as _t4b_th
import tracemalloc as _t4b_tm
from typing import Any, Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class _T4BBenchSample:
    name: str
    iterations: int
    elapsed_s: float
    per_op_us: float
    ops_per_sec: float
    mem_peak_kb: int = 0
    cpu_user_s: float = 0.0


def _t4b_bench_percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * p
    f = _t4b_math.floor(k)
    c = _t4b_math.ceil(k)
    if f == c:
        return s[int(k)]
    return s[f] + (s[c] - s[f]) * (k - f)


def _t4b_bench_compute_stats(self, samples: List[float]) -> Dict[str, Any]:
    """Compute comprehensive stats: mean/median/stdev/percentiles."""
    if not samples:
        return {"count": 0}
    s = sorted(samples)
    n = len(s)
    mean = _t4b_stats.fmean(s)
    median = _t4b_stats.median(s)
    stdev = _t4b_stats.pstdev(s) if n > 1 else 0.0
    return {
        "count": n,
        "min": s[0], "max": s[-1],
        "mean": mean, "median": median,
        "stdev": stdev, "cv": (stdev / mean) if mean else 0.0,
        "p50": _t4b_bench_percentile(s, 0.50),
        "p75": _t4b_bench_percentile(s, 0.75),
        "p90": _t4b_bench_percentile(s, 0.90),
        "p95": _t4b_bench_percentile(s, 0.95),
        "p99": _t4b_bench_percentile(s, 0.99),
        "p999": _t4b_bench_percentile(s, 0.999),
        "iqr": _t4b_bench_percentile(s, 0.75) - _t4b_bench_percentile(s, 0.25),
        "outliers_high": sum(1 for v in s if v > mean + 3 * stdev),
        "outliers_low": sum(1 for v in s if v < mean - 3 * stdev),
    }


def _t4b_bench_run_timed(self, fn: Callable[[], Any], iterations: int = 1000,
                              warmup: int = 100, gc_disable: bool = True) -> _T4BBenchSample:
    """Run a callable N times, return aggregate timing sample."""
    name = getattr(fn, "__name__", "anon")
    for _ in range(warmup):
        fn()
    if gc_disable:
        was_enabled = _t4b_gc.isenabled()
        _t4b_gc.disable()
    try:
        t0 = _t4b_time.perf_counter()
        for _ in range(iterations):
            fn()
        elapsed = _t4b_time.perf_counter() - t0
    finally:
        if gc_disable and was_enabled:
            _t4b_gc.enable()
    per_op_us = (elapsed / max(iterations, 1)) * 1e6
    ops = iterations / elapsed if elapsed > 0 else 0
    return _T4BBenchSample(name=name, iterations=iterations,
                                  elapsed_s=elapsed, per_op_us=per_op_us, ops_per_sec=ops)


def _t4b_bench_run_per_call(self, fn: Callable[[], Any], iterations: int = 1000,
                                  warmup: int = 100) -> Dict[str, Any]:
    """Time each invocation individually for distribution analysis."""
    for _ in range(warmup):
        fn()
    samples_us: List[float] = []
    _t4b_gc.collect()
    t_start = _t4b_time.perf_counter()
    for _ in range(iterations):
        t0 = _t4b_time.perf_counter()
        fn()
        samples_us.append((_t4b_time.perf_counter() - t0) * 1e6)
    total = _t4b_time.perf_counter() - t_start
    stats = _t4b_bench_compute_stats(self, samples_us)
    return {
        "name": getattr(fn, "__name__", "anon"),
        "iterations": iterations,
        "total_s": total,
        "stats_us": stats,
        "samples_first10_us": samples_us[:10],
        "throughput_ops_per_sec": iterations / total if total > 0 else 0,
    }


def _t4b_bench_with_cprofile(self, fn: Callable[[], Any],
                                    iterations: int = 1000,
                                    sort_by: str = "cumulative",
                                    top_n: int = 30) -> Dict[str, Any]:
    """Run under cProfile, return ranked function call statistics."""
    profiler = _t4b_cprof.Profile()
    profiler.enable()
    for _ in range(iterations):
        fn()
    profiler.disable()
    s = _t4b_io.StringIO()
    ps = _t4b_pstats.Stats(profiler, stream=s).sort_stats(sort_by)
    ps.print_stats(top_n)
    raw = s.getvalue()
    # Parse top entries
    top: List[Dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith(("ncalls", "Ordered", "function", "List")):
            continue
        parts = line.split(None, 5)
        if len(parts) >= 6 and parts[0].replace("/", "").isdigit():
            try:
                top.append({
                    "ncalls": parts[0], "tottime": float(parts[1]),
                    "percall_t": float(parts[2]), "cumtime": float(parts[3]),
                    "percall_c": float(parts[4]), "function": parts[5][:120],
                })
            except (ValueError, IndexError):
                continue
        if len(top) >= top_n:
            break
    return {"sort_by": sort_by, "iterations": iterations,
              "top": top, "raw_text": raw[:4000]}


def _t4b_bench_with_memory(self, fn: Callable[[], Any],
                                  iterations: int = 1000,
                                  top_n: int = 15) -> Dict[str, Any]:
    """Track memory allocations using tracemalloc."""
    _t4b_tm.start()
    snap_before = _t4b_tm.take_snapshot()
    for _ in range(iterations):
        fn()
    snap_after = _t4b_tm.take_snapshot()
    diffs = snap_after.compare_to(snap_before, "lineno")
    current, peak = _t4b_tm.get_traced_memory()
    _t4b_tm.stop()
    top_diffs = []
    for stat in diffs[:top_n]:
        top_diffs.append({"file_line": str(stat.traceback)[-200:],
                              "size_diff_kb": stat.size_diff / 1024,
                              "count_diff": stat.count_diff})
    return {"iterations": iterations,
              "current_kb": current / 1024, "peak_kb": peak / 1024,
              "top_allocations": top_diffs}


def _t4b_bench_compare(self, baseline: Dict[str, Any], current: Dict[str, Any],
                            regression_threshold_pct: float = 10.0) -> Dict[str, Any]:
    """Compare two benchmark results — flag regressions."""
    out: Dict[str, Any] = {"regressions": [], "improvements": [], "stable": []}
    b_mean = baseline.get("stats_us", {}).get("mean")
    c_mean = current.get("stats_us", {}).get("mean")
    if b_mean is None or c_mean is None or b_mean == 0:
        return {"ok": False, "error": "missing_or_zero_mean"}
    delta_pct = (c_mean - b_mean) / b_mean * 100
    entry = {"name": current.get("name"), "baseline_us": b_mean,
              "current_us": c_mean, "delta_pct": round(delta_pct, 2)}
    if delta_pct > regression_threshold_pct:
        out["regressions"].append(entry)
    elif delta_pct < -regression_threshold_pct:
        out["improvements"].append(entry)
    else:
        out["stable"].append(entry)
    out["regression_threshold_pct"] = regression_threshold_pct
    out["ok"] = True
    return out


def _t4b_bench_export_html(self, results: List[Dict[str, Any]],
                                   title: str = "Benchmark Report") -> str:
    """Render benchmark results as a self-contained HTML page."""
    head = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>{title}</title>
<style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:24px;background:#f9fafb;color:#111}}
h1{{color:#1f2937;border-bottom:3px solid #2563eb;padding-bottom:6px}}
h2{{color:#2563eb;margin-top:30px}}
table{{border-collapse:collapse;width:100%;margin:12px 0;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,0.1)}}
th,td{{border:1px solid #e5e7eb;padding:8px 12px;text-align:left;font-size:13px}}
th{{background:#f3f4f6;font-weight:600;color:#374151}}
tr:nth-child(even){{background:#f9fafb}}
.metric{{display:inline-block;padding:4px 10px;border-radius:4px;font-weight:600}}
.good{{background:#d1fae5;color:#065f46}}
.warn{{background:#fef3c7;color:#92400e}}
.bad{{background:#fee2e2;color:#991b1b}}
.summary-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:16px 0}}
.card{{background:#fff;padding:16px;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,0.1)}}
.card .label{{color:#6b7280;font-size:12px;text-transform:uppercase}}
.card .value{{font-size:24px;font-weight:700;color:#111;margin-top:4px}}
</style></head><body>
<h1>{title}</h1>
<p>Generated at {_t4b_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
"""
    body = ""
    for r in results:
        name = r.get("name", "unnamed")
        stats = r.get("stats_us", {})
        body += f"<h2>{name}</h2>\n"
        body += f"<p>Iterations: <b>{r.get('iterations',0):,}</b> &nbsp; Throughput: <b>{r.get('throughput_ops_per_sec',0):,.0f} ops/s</b> &nbsp; Total: <b>{r.get('total_s',0):.3f}s</b></p>\n"
        if stats:
            body += '<div class="summary-grid">'
            for label, key, fmt in [
                ("Mean (μs)", "mean", "{:.2f}"), ("Median (μs)", "median", "{:.2f}"),
                ("p95 (μs)", "p95", "{:.2f}"), ("p99 (μs)", "p99", "{:.2f}"),
                ("StDev (μs)", "stdev", "{:.2f}"), ("Outliers", "outliers_high", "{:d}"),
            ]:
                v = stats.get(key, 0)
                body += f'<div class="card"><div class="label">{label}</div><div class="value">{fmt.format(v)}</div></div>'
            body += '</div>\n'
            body += "<table><tr><th>Stat</th><th>Value (μs)</th></tr>"
            for k in ["min","p50","p75","p90","p95","p99","p999","max","iqr","cv"]:
                if k in stats:
                    fmt = "{:.4f}" if k == "cv" else "{:.2f}"
                    body += f"<tr><td>{k}</td><td>{fmt.format(stats[k])}</td></tr>"
            body += "</table>\n"
    return head + body + "</body></html>"


def _t4b_bench_export_json(self, results: List[Dict[str, Any]]) -> str:
    return _t4b_json.dumps({"generated_at": _t4b_time.time(),
                                  "results": results}, default=str, indent=2)


def _t4b_bench_save_baseline(self, results: List[Dict[str, Any]], path: str) -> Dict[str, Any]:
    data = {"saved_at": _t4b_time.time(), "results": results}
    with open(path, "w", encoding="utf-8") as fh:
        _t4b_json.dump(data, fh, default=str, indent=2)
    return {"ok": True, "path": path, "results_count": len(results)}


def _t4b_bench_load_baseline(self, path: str) -> Optional[Dict[str, Any]]:
    if not _t4b_os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return _t4b_json.load(fh)


def _t4b_bench_supported_modes(self) -> List[str]:
    return ["timed", "per_call", "cprofile", "memory"]


# --- Bind to BenchmarkRunner --------------------------------------------
try:
    BenchmarkRunner.compute_stats = _t4b_bench_compute_stats  # type: ignore[name-defined]
    BenchmarkRunner.run_timed = _t4b_bench_run_timed  # type: ignore[name-defined]
    BenchmarkRunner.run_per_call = _t4b_bench_run_per_call  # type: ignore[name-defined]
    BenchmarkRunner.run_with_cprofile = _t4b_bench_with_cprofile  # type: ignore[name-defined]
    BenchmarkRunner.run_with_memory = _t4b_bench_with_memory  # type: ignore[name-defined]
    BenchmarkRunner.compare_results = _t4b_bench_compare  # type: ignore[name-defined]
    BenchmarkRunner.export_html_report = _t4b_bench_export_html  # type: ignore[name-defined]
    BenchmarkRunner.export_json_report = _t4b_bench_export_json  # type: ignore[name-defined]
    BenchmarkRunner.save_baseline = _t4b_bench_save_baseline  # type: ignore[name-defined]
    BenchmarkRunner.load_baseline = _t4b_bench_load_baseline  # type: ignore[name-defined]
    BenchmarkRunner.supported_bench_modes = _t4b_bench_supported_modes  # type: ignore[name-defined]
except NameError:
    pass
