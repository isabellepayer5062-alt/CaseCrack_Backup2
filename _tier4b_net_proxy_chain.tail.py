
# ======================================================================
# __TIER4B_NETWORK__  proxy_chain: health-check threads + scoring
# ======================================================================
import threading as _t4b_threading
import time as _t4b_time
import socket as _t4b_socket
import ssl as _t4b_ssl
import urllib.request as _t4b_urlreq
import urllib.error as _t4b_urlerr
from dataclasses import dataclass as _t4b_dataclass, field as _t4b_field
from typing import Any as _T4BAny, Dict as _T4BDict, List as _T4BList, Optional as _T4BOptional


@_t4b_dataclass
class HealthCheckResult:
    """Result of a single proxy health probe."""
    proxy_id: str
    proxy_url: str
    success: bool
    latency_ms: float
    status_code: int = 0
    anonymity: str = "unknown"   # "elite" | "anonymous" | "transparent" | "unknown"
    egress_ip: _T4BOptional[str] = None
    error: _T4BOptional[str] = None
    checked_at: float = _t4b_field(default_factory=lambda: _t4b_time.time())
    checked_via: str = "default"


_T4B_PROXY_HEALTH_TARGETS = [
    "https://api.ipify.org?format=json",
    "https://www.google.com/generate_204",
    "https://httpbin.org/get",
    "https://www.cloudflare.com/cdn-cgi/trace",
]


def _t4b_assess_anonymity(self, response_body: str, request_headers: dict, original_ip: str) -> str:
    """Assess proxy anonymity level based on response from echo service."""
    body_lower = (response_body or "").lower()
    if original_ip and original_ip in body_lower:
        return "transparent"
    forwarded_headers = ["x-forwarded-for", "via", "forwarded", "x-real-ip"]
    if any(h in body_lower for h in forwarded_headers):
        return "anonymous"
    return "elite"


def _t4b_check_one_proxy(self, proxy, target_url: str = None,
                         timeout: float = 8.0,
                         original_ip: str = None) -> HealthCheckResult:
    """Probe a single proxy; return HealthCheckResult."""
    if hasattr(self, "_check_dry_run"):
        stub = self._check_dry_run("check_one_proxy", proxy=str(proxy)[:60])
        if stub is not None:
            return stub
    target_url = target_url or _T4B_PROXY_HEALTH_TARGETS[0]
    if isinstance(proxy, dict):
        proxy_url = proxy.get("url") or f"{proxy.get('scheme', 'http')}://{proxy.get('host')}:{proxy.get('port')}"
        proxy_id = proxy.get("id") or proxy_url
    elif hasattr(proxy, "url"):
        proxy_url = proxy.url
        proxy_id = getattr(proxy, "id", proxy_url)
    else:
        proxy_url = str(proxy)
        proxy_id = proxy_url

    handler = _t4b_urlreq.ProxyHandler({"http": proxy_url, "https": proxy_url})
    opener = _t4b_urlreq.build_opener(handler)
    req = _t4b_urlreq.Request(target_url, headers={
        "User-Agent": "CaseCrack/T4B-ProxyHealth",
    })

    start = _t4b_time.time()
    try:
        with opener.open(req, timeout=timeout) as resp:
            elapsed_ms = (_t4b_time.time() - start) * 1000
            body = resp.read(2048).decode("utf-8", errors="replace")
            status = resp.status
            egress_ip = None
            # naive egress IP extraction from common echo bodies
            import re as _re
            m = _re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", body)
            if m:
                egress_ip = m.group(1)
            anon = _t4b_assess_anonymity(self, body, dict(resp.getheaders()), original_ip or "")
            return HealthCheckResult(
                proxy_id=proxy_id, proxy_url=proxy_url, success=True,
                latency_ms=elapsed_ms, status_code=status,
                anonymity=anon, egress_ip=egress_ip, checked_via=target_url,
            )
    except _t4b_urlerr.HTTPError as ex:
        return HealthCheckResult(
            proxy_id=proxy_id, proxy_url=proxy_url, success=False,
            latency_ms=(_t4b_time.time() - start) * 1000,
            status_code=ex.code, error=f"HTTP {ex.code}", checked_via=target_url,
        )
    except Exception as ex:
        return HealthCheckResult(
            proxy_id=proxy_id, proxy_url=proxy_url, success=False,
            latency_ms=(_t4b_time.time() - start) * 1000,
            error=str(ex)[:200], checked_via=target_url,
        )


def _t4b_proxy_score(self, proxy_id: str = None,
                      results: _T4BOptional[_T4BList[HealthCheckResult]] = None) -> _T4BDict[str, _T4BAny]:
    """Compute composite score (0..100) from recent health results."""
    history = getattr(self, "_health_history", None)
    if history is None or proxy_id is None:
        rs = results or []
    else:
        rs = list(history.get(proxy_id, []))
    if not rs:
        return {"proxy_id": proxy_id, "score": 0, "samples": 0,
                "reason": "no health data"}
    n = len(rs)
    success_rate = sum(1 for r in rs if r.success) / n
    avg_latency = sum(r.latency_ms for r in rs) / n
    anon_bonus = 0
    last = rs[-1]
    if last.anonymity == "elite":
        anon_bonus = 15
    elif last.anonymity == "anonymous":
        anon_bonus = 8
    elif last.anonymity == "transparent":
        anon_bonus = -10
    # Latency component: 0 latency → +50, 5000ms → 0
    lat_score = max(0, 50 - (avg_latency / 100))
    score = round(min(100, max(0, success_rate * 50 + lat_score + anon_bonus)), 1)
    return {
        "proxy_id": proxy_id, "score": score, "samples": n,
        "success_rate": round(success_rate, 3),
        "avg_latency_ms": round(avg_latency, 1),
        "anonymity": last.anonymity,
        "last_check": last.checked_at,
    }


def _t4b_health_check_loop(self, interval: float, target_url: str, timeout: float):
    """Background loop: probe all proxies every interval seconds."""
    history = self._health_history
    history_lock = self._health_history_lock
    stop = self._health_stop_event
    while not stop.is_set():
        cycle_start = _t4b_time.time()
        proxies = []
        # Discover proxies — read from common attribute names
        for attr in ("_proxies", "proxies", "_proxy_pool", "pool"):
            v = getattr(self, attr, None)
            if v:
                proxies = list(v.values()) if isinstance(v, dict) else list(v)
                break
        results_this_cycle = []
        for proxy in proxies:
            if stop.is_set():
                break
            try:
                res = _t4b_check_one_proxy(self, proxy, target_url=target_url, timeout=timeout)
            except Exception as ex:
                res = HealthCheckResult(
                    proxy_id=str(proxy)[:40], proxy_url=str(proxy),
                    success=False, latency_ms=0, error=f"check_exception: {ex}",
                )
            with history_lock:
                lst = history.setdefault(res.proxy_id, [])
                lst.append(res)
                # Keep last 50 per proxy
                if len(lst) > 50:
                    del lst[:len(lst) - 50]
            results_this_cycle.append(res)
        # Auto-disable repeatedly failing proxies
        try:
            _t4b_auto_disable_unhealthy(self)
        except Exception:
            pass
        # Sleep remainder of interval
        elapsed = _t4b_time.time() - cycle_start
        sleep_for = max(0.0, interval - elapsed)
        # responsive sleep
        end_at = _t4b_time.time() + sleep_for
        while _t4b_time.time() < end_at:
            if stop.is_set():
                break
            _t4b_time.sleep(0.5)


def _t4b_start_health_checks(self, interval: float = 30.0,
                              target_url: str = None,
                              timeout: float = 8.0,
                              num_threads: int = 1) -> _T4BDict[str, _T4BAny]:
    """Spawn daemon thread(s) that continuously probe proxies."""
    if hasattr(self, "_check_dry_run"):
        stub = self._check_dry_run("start_health_checks", interval=interval)
        if stub is not None:
            return stub
    if not hasattr(self, "_health_history"):
        self._health_history = {}
    if not hasattr(self, "_health_history_lock"):
        self._health_history_lock = _t4b_threading.RLock()
    if not hasattr(self, "_health_stop_event"):
        self._health_stop_event = _t4b_threading.Event()
    if not hasattr(self, "_health_threads"):
        self._health_threads = []

    if any(t.is_alive() for t in self._health_threads):
        return {"status": "already_running", "threads": len(self._health_threads)}

    self._health_stop_event.clear()
    target = target_url or _T4B_PROXY_HEALTH_TARGETS[0]
    threads = []
    for i in range(max(1, num_threads)):
        t = _t4b_threading.Thread(
            target=_t4b_health_check_loop,
            args=(self, interval, target, timeout),
            name=f"ProxyHealthCheck-{i}",
            daemon=True,
        )
        t.start()
        threads.append(t)
    self._health_threads = threads
    return {"status": "started", "threads": len(threads),
            "interval_s": interval, "target": target}


def _t4b_stop_health_checks(self, join_timeout: float = 5.0) -> _T4BDict[str, _T4BAny]:
    """Signal health-check threads to stop and join them."""
    if hasattr(self, "_check_dry_run"):
        stub = self._check_dry_run("stop_health_checks")
        if stub is not None:
            return stub
    stop = getattr(self, "_health_stop_event", None)
    threads = getattr(self, "_health_threads", []) or []
    if stop is None or not threads:
        return {"status": "not_running"}
    stop.set()
    joined = 0
    for t in threads:
        t.join(timeout=join_timeout)
        if not t.is_alive():
            joined += 1
    self._health_threads = [t for t in threads if t.is_alive()]
    return {"status": "stopped" if joined == len(threads) else "partial",
            "joined": joined, "still_alive": len(self._health_threads)}


def _t4b_auto_disable_unhealthy(self, min_samples: int = 5,
                                 success_threshold: float = 0.3) -> _T4BList[str]:
    """Disable proxies whose recent success rate is below threshold."""
    history = getattr(self, "_health_history", {}) or {}
    disabled = []
    for pid, results in history.items():
        if len(results) < min_samples:
            continue
        recent = results[-min_samples:]
        sr = sum(1 for r in recent if r.success) / len(recent)
        if sr < success_threshold:
            # Try to mark proxy disabled
            for attr in ("_proxies", "proxies", "_proxy_pool", "pool"):
                pool = getattr(self, attr, None)
                if not pool:
                    continue
                if isinstance(pool, dict):
                    p = pool.get(pid)
                    if p is not None:
                        if isinstance(p, dict):
                            p["enabled"] = False
                            p["disabled_reason"] = f"unhealthy: success_rate={sr:.2f}"
                        else:
                            try:
                                setattr(p, "enabled", False)
                                setattr(p, "disabled_reason", f"unhealthy: {sr:.2f}")
                            except Exception:
                                pass
                        disabled.append(pid)
                        break
                elif isinstance(pool, list):
                    for p in pool:
                        if (isinstance(p, dict) and p.get("id") == pid) or getattr(p, "id", None) == pid:
                            if isinstance(p, dict):
                                p["enabled"] = False
                                p["disabled_reason"] = f"unhealthy: {sr:.2f}"
                            else:
                                try:
                                    setattr(p, "enabled", False)
                                except Exception:
                                    pass
                            disabled.append(pid)
                            break
                    break
    return disabled


def _t4b_health_report(self) -> _T4BDict[str, _T4BAny]:
    """Aggregate health report across all proxies."""
    history = getattr(self, "_health_history", {}) or {}
    report = {"proxy_count": len(history), "proxies": [], "summary": {}}
    healthy = 0; degraded = 0; dead = 0
    for pid in history:
        score = _t4b_proxy_score(self, proxy_id=pid)
        report["proxies"].append(score)
        s = score["score"]
        if s >= 70:
            healthy += 1
        elif s >= 30:
            degraded += 1
        else:
            dead += 1
    report["summary"] = {"healthy": healthy, "degraded": degraded, "dead": dead}
    report["proxies"].sort(key=lambda x: -x["score"])
    return report


def _t4b_get_best_proxy(self) -> _T4BOptional[_T4BDict[str, _T4BAny]]:
    """Return highest-scoring proxy from health data."""
    rep = _t4b_health_report(self)
    return rep["proxies"][0] if rep["proxies"] else None


def _t4b_circuit_state(self, proxy_id: str, fail_threshold: int = 5,
                        recovery_window_s: float = 60.0) -> str:
    """Per-proxy circuit-breaker state: 'closed' | 'open' | 'half_open'."""
    history = getattr(self, "_health_history", {}) or {}
    results = list(history.get(proxy_id, []))
    if not results:
        return "closed"
    recent_failures = 0
    last_failure_ts = 0
    for r in reversed(results):
        if r.success:
            break
        recent_failures += 1
        last_failure_ts = max(last_failure_ts, r.checked_at)
    if recent_failures >= fail_threshold:
        if _t4b_time.time() - last_failure_ts > recovery_window_s:
            return "half_open"
        return "open"
    return "closed"


# Bind to ProxyChain
try:
    ProxyChain.start_health_checks = _t4b_start_health_checks  # type: ignore[name-defined]
    ProxyChain.stop_health_checks = _t4b_stop_health_checks  # type: ignore[name-defined]
    ProxyChain.check_one_proxy = _t4b_check_one_proxy  # type: ignore[name-defined]
    ProxyChain.proxy_score = _t4b_proxy_score  # type: ignore[name-defined]
    ProxyChain.health_report = _t4b_health_report  # type: ignore[name-defined]
    ProxyChain.auto_disable_unhealthy = _t4b_auto_disable_unhealthy  # type: ignore[name-defined]
    ProxyChain.get_best_proxy = _t4b_get_best_proxy  # type: ignore[name-defined]
    ProxyChain.circuit_state = _t4b_circuit_state  # type: ignore[name-defined]
except NameError:
    pass

# ====================== END __TIER4B_NETWORK__ ========================
