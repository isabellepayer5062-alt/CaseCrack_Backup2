# __TIER4B_TESTING__
# Tier 4B Testing — load_tester: aiohttp async engine + HDR histogram
import asyncio as _t4b_aio
import time as _t4b_time
import math as _t4b_math
import json as _t4b_json
import bisect as _t4b_bisect
import threading as _t4b_th
import urllib.request as _t4b_ur
import urllib.error as _t4b_uerr
import concurrent.futures as _t4b_cf
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

# Try aiohttp; fall back to threaded urllib if absent
try:
    import aiohttp as _t4b_aiohttp  # type: ignore
    _T4B_HAS_AIOHTTP = True
except ImportError:
    _T4B_HAS_AIOHTTP = False


# ---- HDR-style histogram (logarithmic bucketing) -----------------------
class _T4BHdrHistogram:
    """Lightweight HDR-inspired histogram for latency tracking.

    Uses log-linear bucketing: 10 sub-buckets per power of 10.
    Range: 1us .. 100s (8 magnitudes × 10 = 80 buckets).
    """
    def __init__(self, lo_us: float = 1.0, hi_us: float = 1e8, sub_buckets: int = 10):
        self.lo = lo_us
        self.hi = hi_us
        self.sub = sub_buckets
        self.boundaries: List[float] = self._build_boundaries()
        self.counts: List[int] = [0] * (len(self.boundaries) + 1)
        self.total_count = 0
        self.sum = 0.0
        self.min_seen = float("inf")
        self.max_seen = 0.0

    def _build_boundaries(self) -> List[float]:
        bounds: List[float] = []
        magnitudes = int(_t4b_math.log10(self.hi / self.lo)) + 1
        for mag in range(magnitudes):
            base = self.lo * (10 ** mag)
            for k in range(self.sub):
                bounds.append(base * (1 + k / self.sub))
        return sorted(set(bounds))

    def record(self, value_us: float) -> None:
        idx = _t4b_bisect.bisect_right(self.boundaries, value_us)
        self.counts[idx] += 1
        self.total_count += 1
        self.sum += value_us
        if value_us < self.min_seen:
            self.min_seen = value_us
        if value_us > self.max_seen:
            self.max_seen = value_us

    def percentile(self, p: float) -> float:
        if self.total_count == 0:
            return 0.0
        target = p * self.total_count
        cumulative = 0
        for i, c in enumerate(self.counts):
            cumulative += c
            if cumulative >= target:
                if i == 0:
                    return self.boundaries[0]
                if i >= len(self.boundaries):
                    return self.max_seen
                return self.boundaries[i]
        return self.max_seen

    def mean(self) -> float:
        return self.sum / self.total_count if self.total_count else 0.0

    def to_dict(self) -> Dict[str, Any]:
        if self.total_count == 0:
            return {"count": 0}
        return {
            "count": self.total_count,
            "mean_us": self.mean(),
            "min_us": self.min_seen,
            "max_us": self.max_seen,
            "p50_us": self.percentile(0.50),
            "p75_us": self.percentile(0.75),
            "p90_us": self.percentile(0.90),
            "p95_us": self.percentile(0.95),
            "p99_us": self.percentile(0.99),
            "p999_us": self.percentile(0.999),
            "p9999_us": self.percentile(0.9999),
        }


def _t4b_lt_new_histogram(self) -> _T4BHdrHistogram:
    return _T4BHdrHistogram()


# ---- Async aiohttp engine -----------------------------------------------
async def _t4b_lt_async_request(session: Any, method: str, url: str,
                                       headers: Optional[Dict[str, str]],
                                       body: Optional[bytes],
                                       timeout: float, hist: _T4BHdrHistogram,
                                       result_acc: Dict[str, Any]) -> None:
    t0 = _t4b_time.perf_counter()
    try:
        async with session.request(method, url, headers=headers, data=body,
                                          timeout=_t4b_aiohttp.ClientTimeout(total=timeout)) as resp:
            await resp.read()
            elapsed_us = (_t4b_time.perf_counter() - t0) * 1e6
            hist.record(elapsed_us)
            sc = resp.status
            result_acc["by_status"][sc] = result_acc["by_status"].get(sc, 0) + 1
            if sc >= 400:
                result_acc["error_count"] += 1
            else:
                result_acc["success_count"] += 1
    except _t4b_aio.TimeoutError:
        result_acc["timeout_count"] += 1
        result_acc["error_count"] += 1
    except Exception as e:
        result_acc["error_count"] += 1
        et = type(e).__name__
        result_acc["errors_by_type"][et] = result_acc["errors_by_type"].get(et, 0) + 1


async def _t4b_lt_async_worker(queue: "_t4b_aio.Queue[Tuple[str,str]]",
                                       session: Any, headers: Dict[str, str],
                                       body: Optional[bytes], timeout: float,
                                       hist: _T4BHdrHistogram,
                                       result_acc: Dict[str, Any],
                                       stop_event: _t4b_aio.Event) -> None:
    while not stop_event.is_set():
        try:
            method, url = await _t4b_aio.wait_for(queue.get(), timeout=0.5)
        except _t4b_aio.TimeoutError:
            continue
        await _t4b_lt_async_request(session, method, url, headers, body, timeout, hist, result_acc)
        queue.task_done()


async def _t4b_lt_async_run_loop(self, url: str, method: str = "GET",
                                          concurrency: int = 50, duration_s: float = 10.0,
                                          rps: Optional[float] = None,
                                          headers: Optional[Dict[str, str]] = None,
                                          body: Optional[bytes] = None,
                                          timeout: float = 10.0) -> Dict[str, Any]:
    if not _T4B_HAS_AIOHTTP:
        return {"ok": False, "error": "aiohttp_not_installed"}
    hist = _T4BHdrHistogram()
    result_acc: Dict[str, Any] = {
        "by_status": {}, "errors_by_type": {},
        "success_count": 0, "error_count": 0, "timeout_count": 0,
    }
    h = headers or {"User-Agent": "CaseCrack-Load/1.0"}
    queue: "_t4b_aio.Queue[Tuple[str,str]]" = _t4b_aio.Queue(maxsize=concurrency * 4)
    stop_event = _t4b_aio.Event()

    async with _t4b_aiohttp.ClientSession() as session:
        workers = [
            _t4b_aio.create_task(_t4b_lt_async_worker(
                queue, session, h, body, timeout, hist, result_acc, stop_event
            ))
            for _ in range(concurrency)
        ]
        t0 = _t4b_time.perf_counter()
        deadline = t0 + duration_s
        next_send = t0
        send_interval = 1.0 / rps if rps else 0.0
        produced = 0
        while _t4b_time.perf_counter() < deadline:
            if rps:
                now = _t4b_time.perf_counter()
                if now < next_send:
                    await _t4b_aio.sleep(max(0, next_send - now))
                next_send += send_interval
            try:
                await _t4b_aio.wait_for(queue.put((method, url)), timeout=0.5)
                produced += 1
            except _t4b_aio.TimeoutError:
                pass
        await queue.join()
        stop_event.set()
        await _t4b_aio.gather(*workers, return_exceptions=True)
    elapsed = _t4b_time.perf_counter() - t0
    total = result_acc["success_count"] + result_acc["error_count"]
    return {
        "ok": True, "engine": "aiohttp",
        "url": url, "method": method,
        "concurrency": concurrency, "duration_s": elapsed,
        "rps_target": rps, "rps_actual": total / elapsed if elapsed else 0,
        "requests_produced": produced,
        "requests_completed": total,
        "success": result_acc["success_count"],
        "errors": result_acc["error_count"],
        "timeouts": result_acc["timeout_count"],
        "by_status": result_acc["by_status"],
        "errors_by_type": result_acc["errors_by_type"],
        "latency_us": hist.to_dict(),
    }


def _t4b_lt_run_async(self, url: str, method: str = "GET",
                            concurrency: int = 50, duration_s: float = 10.0,
                            rps: Optional[float] = None,
                            headers: Optional[Dict[str, str]] = None,
                            body: Optional[bytes] = None,
                            timeout: float = 10.0) -> Dict[str, Any]:
    """Synchronous wrapper around the async engine."""
    if not _T4B_HAS_AIOHTTP:
        # Fallback to threaded urllib
        return _t4b_lt_run_threaded(self, url, method, concurrency, duration_s,
                                            rps, headers, body, timeout)
    try:
        loop = _t4b_aio.new_event_loop()
        try:
            return loop.run_until_complete(_t4b_lt_async_run_loop(
                self, url, method, concurrency, duration_s, rps, headers, body, timeout
            ))
        finally:
            loop.close()
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


# ---- Threaded fallback --------------------------------------------------
def _t4b_lt_run_threaded(self, url: str, method: str = "GET",
                                concurrency: int = 50, duration_s: float = 10.0,
                                rps: Optional[float] = None,
                                headers: Optional[Dict[str, str]] = None,
                                body: Optional[bytes] = None,
                                timeout: float = 10.0) -> Dict[str, Any]:
    hist = _T4BHdrHistogram()
    result_acc: Dict[str, Any] = {
        "by_status": {}, "errors_by_type": {},
        "success_count": 0, "error_count": 0, "timeout_count": 0,
    }
    h = headers or {"User-Agent": "CaseCrack-Load/1.0"}
    lock = _t4b_th.Lock()
    stop = _t4b_th.Event()
    deadline = _t4b_time.perf_counter() + duration_s
    completed = [0]

    def one_req():
        t0 = _t4b_time.perf_counter()
        try:
            req = _t4b_ur.Request(url, data=body, method=method.upper(), headers=h)
            with _t4b_ur.urlopen(req, timeout=timeout) as resp:
                resp.read()
                elapsed_us = (_t4b_time.perf_counter() - t0) * 1e6
                with lock:
                    hist.record(elapsed_us)
                    result_acc["by_status"][resp.status] = result_acc["by_status"].get(resp.status, 0) + 1
                    if resp.status >= 400:
                        result_acc["error_count"] += 1
                    else:
                        result_acc["success_count"] += 1
        except _t4b_uerr.HTTPError as e:
            with lock:
                result_acc["error_count"] += 1
                result_acc["by_status"][e.code] = result_acc["by_status"].get(e.code, 0) + 1
        except Exception as e:
            with lock:
                result_acc["error_count"] += 1
                et = type(e).__name__
                result_acc["errors_by_type"][et] = result_acc["errors_by_type"].get(et, 0) + 1
                if "timeout" in str(e).lower():
                    result_acc["timeout_count"] += 1

    def worker():
        while not stop.is_set() and _t4b_time.perf_counter() < deadline:
            one_req()
            with lock:
                completed[0] += 1
            if rps:
                _t4b_time.sleep(max(0, concurrency / rps - 0.001))

    with _t4b_cf.ThreadPoolExecutor(max_workers=concurrency) as pool:
        t0 = _t4b_time.perf_counter()
        futures = [pool.submit(worker) for _ in range(concurrency)]
        for f in _t4b_cf.as_completed(futures, timeout=duration_s + 30):
            try: f.result()
            except Exception: pass
        stop.set()
    elapsed = _t4b_time.perf_counter() - t0
    return {
        "ok": True, "engine": "threaded_urllib",
        "url": url, "method": method,
        "concurrency": concurrency, "duration_s": elapsed,
        "rps_target": rps, "rps_actual": completed[0] / elapsed if elapsed else 0,
        "requests_completed": completed[0],
        "success": result_acc["success_count"],
        "errors": result_acc["error_count"],
        "timeouts": result_acc["timeout_count"],
        "by_status": result_acc["by_status"],
        "errors_by_type": result_acc["errors_by_type"],
        "latency_us": hist.to_dict(),
    }


# ---- Stepped/ramp profiles ---------------------------------------------
def _t4b_lt_run_ramp(self, url: str, method: str = "GET",
                          start_concurrency: int = 1, max_concurrency: int = 100,
                          step_size: int = 10, step_duration_s: float = 5.0,
                          headers: Optional[Dict[str, str]] = None,
                          body: Optional[bytes] = None) -> Dict[str, Any]:
    """Step-up ramp test: identify saturation point."""
    steps: List[Dict[str, Any]] = []
    saturation_step: Optional[int] = None
    prev_rps = 0.0
    c = start_concurrency
    while c <= max_concurrency:
        result = _t4b_lt_run_async(self, url, method, concurrency=c,
                                            duration_s=step_duration_s,
                                            headers=headers, body=body)
        result["concurrency"] = c
        steps.append(result)
        cur_rps = result.get("rps_actual", 0)
        if saturation_step is None and prev_rps > 0 and cur_rps < prev_rps * 1.05:
            saturation_step = c
        prev_rps = cur_rps
        c += step_size
    return {"ok": True, "url": url, "steps": steps,
              "saturation_concurrency": saturation_step,
              "step_count": len(steps)}


# ---- Result analysis ---------------------------------------------------
def _t4b_lt_analyze(self, result: Dict[str, Any],
                          sla_p99_us: Optional[float] = None,
                          sla_error_rate: Optional[float] = None) -> Dict[str, Any]:
    lat = result.get("latency_us", {})
    total = result.get("requests_completed", 0)
    errors = result.get("errors", 0)
    error_rate = errors / total if total else 0.0
    p99 = lat.get("p99_us", 0)
    issues: List[str] = []
    if sla_p99_us and p99 > sla_p99_us:
        issues.append(f"p99 latency {p99:.0f}us exceeds SLA {sla_p99_us:.0f}us")
    if sla_error_rate is not None and error_rate > sla_error_rate:
        issues.append(f"error rate {error_rate:.4%} exceeds SLA {sla_error_rate:.4%}")
    return {
        "ok": True, "total_requests": total, "error_rate": error_rate,
        "rps_actual": result.get("rps_actual", 0),
        "p50_us": lat.get("p50_us", 0),
        "p95_us": lat.get("p95_us", 0),
        "p99_us": p99,
        "p999_us": lat.get("p999_us", 0),
        "sla_violations": issues,
        "sla_pass": not issues,
    }


def _t4b_lt_supported_engines(self) -> List[str]:
    out = ["threaded_urllib"]
    if _T4B_HAS_AIOHTTP:
        out.insert(0, "aiohttp")
    return out


# --- Bind to LoadTester -------------------------------------------------
try:
    LoadTester.new_hdr_histogram = _t4b_lt_new_histogram  # type: ignore[name-defined]
    LoadTester.run_async = _t4b_lt_run_async  # type: ignore[name-defined]
    LoadTester.run_threaded = _t4b_lt_run_threaded  # type: ignore[name-defined]
    LoadTester.run_ramp = _t4b_lt_run_ramp  # type: ignore[name-defined]
    LoadTester.analyze_load_result = _t4b_lt_analyze  # type: ignore[name-defined]
    LoadTester.supported_engines = _t4b_lt_supported_engines  # type: ignore[name-defined]
except NameError:
    pass
