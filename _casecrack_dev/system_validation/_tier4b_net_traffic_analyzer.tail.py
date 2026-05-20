
# ======================================================================
# __TIER4B_NETWORK__  traffic_analyzer: HAR I/O + anomaly heuristics
# ======================================================================
import json as _t4b_json
import re as _t4b_re
import time as _t4b_time
import statistics as _t4b_statistics
import base64 as _t4b_base64
import datetime as _t4b_dt
from typing import Any as _T4BAny, Dict as _T4BDict, List as _T4BList, Optional as _T4BOptional


# Heuristic regex banks for anomaly detection
_T4B_PII_PATTERNS = {
    "email": _t4b_re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "ssn_us": _t4b_re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": _t4b_re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    "phone_us": _t4b_re.compile(r"\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "ipv4": _t4b_re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "iban": _t4b_re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b"),
    "aws_key": _t4b_re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "google_api_key": _t4b_re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "private_key_block": _t4b_re.compile(r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----"),
}

_T4B_JWT_RX = _t4b_re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")

_T4B_SQLI_INDICATORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "ora-00933", "ora-00921", "ora-00936",
    "pg_query", "psqlexception",
    "sqlite3.operationalerror",
    "microsoft odbc sql server",
    "syntax error at or near",
]

_T4B_XSS_INDICATORS = [
    "<script>alert(", "<svg onload=", "javascript:alert",
    "onerror=alert", "onmouseover=alert", "<iframe src=javascript",
]

_T4B_DIRTRAVERSAL = [
    "../../../etc/passwd", "..\\..\\..\\windows\\system32",
    "/etc/shadow", "/proc/self/environ",
    "boot.ini", "win.ini",
]

_T4B_BANNER_LEAK_HEADERS = {
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-runtime", "x-version", "x-debug", "x-debug-token",
    "x-generator", "x-drupal-cache",
}


def _t4b_safe_b64decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    try:
        return _t4b_base64.urlsafe_b64decode(s + pad)
    except Exception:
        return b""


def _t4b_decode_jwt(token: str) -> _T4BOptional[_T4BDict[str, _T4BAny]]:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = _t4b_json.loads(_t4b_safe_b64decode(parts[0]).decode("utf-8", errors="replace"))
        payload = _t4b_json.loads(_t4b_safe_b64decode(parts[1]).decode("utf-8", errors="replace"))
        return {"header": header, "payload": payload, "signature_present": bool(parts[2])}
    except Exception:
        return None


def _t4b_iso_now() -> str:
    return _t4b_dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _t4b_har_entry_from_exchange(self, ex) -> _T4BDict[str, _T4BAny]:
    """Convert HTTPExchange (or dict-like) to HAR 1.2 entry."""
    def g(o, k, default=None):
        if isinstance(o, dict):
            return o.get(k, default)
        return getattr(o, k, default)

    method = g(ex, "method", "GET")
    url = g(ex, "url", "")
    req_headers = g(ex, "request_headers", {}) or {}
    resp_headers = g(ex, "response_headers", {}) or {}
    status = g(ex, "status_code", g(ex, "status", 0))
    req_body = g(ex, "request_body", "")
    resp_body = g(ex, "response_body", "")
    started = g(ex, "started", g(ex, "timestamp", _t4b_time.time()))
    duration_ms = g(ex, "duration_ms", g(ex, "elapsed_ms", 0))
    if isinstance(started, (int, float)):
        started_dt = _t4b_dt.datetime.utcfromtimestamp(float(started))
        started_iso = started_dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int((started % 1) * 1000):03d}Z"
    else:
        started_iso = str(started)

    def hdrs_to_har(h):
        if isinstance(h, dict):
            return [{"name": k, "value": str(v)} for k, v in h.items()]
        if isinstance(h, list):
            return [{"name": k, "value": str(v)} for k, v in h]
        return []

    request = {
        "method": method,
        "url": url,
        "httpVersion": g(ex, "http_version", "HTTP/1.1"),
        "headers": hdrs_to_har(req_headers),
        "queryString": [],
        "cookies": [],
        "headersSize": -1,
        "bodySize": len(req_body or "") if isinstance(req_body, (str, bytes)) else -1,
    }
    # parse query string
    if "?" in url:
        try:
            from urllib.parse import urlparse, parse_qsl
            qs = parse_qsl(urlparse(url).query, keep_blank_values=True)
            request["queryString"] = [{"name": k, "value": v} for k, v in qs]
        except Exception:
            pass
    if req_body:
        body_str = req_body if isinstance(req_body, str) else req_body.decode("utf-8", errors="replace")
        request["postData"] = {
            "mimeType": (g(req_headers, "Content-Type") if isinstance(req_headers, dict) else None) or "application/octet-stream",
            "text": body_str,
        }

    resp_body_str = resp_body if isinstance(resp_body, str) else (
        resp_body.decode("utf-8", errors="replace") if isinstance(resp_body, (bytes, bytearray)) else "")
    response = {
        "status": int(status) if status else 0,
        "statusText": g(ex, "status_text", ""),
        "httpVersion": g(ex, "http_version", "HTTP/1.1"),
        "headers": hdrs_to_har(resp_headers),
        "cookies": [],
        "content": {
            "size": len(resp_body_str),
            "mimeType": (g(resp_headers, "Content-Type") if isinstance(resp_headers, dict) else None) or "text/plain",
            "text": resp_body_str[:1024 * 1024],  # cap 1 MiB
        },
        "redirectURL": g(resp_headers, "Location") if isinstance(resp_headers, dict) else "",
        "headersSize": -1,
        "bodySize": len(resp_body_str),
    }

    return {
        "startedDateTime": started_iso,
        "time": float(duration_ms) if duration_ms else 0,
        "request": request,
        "response": response,
        "cache": {},
        "timings": {"send": 0, "wait": float(duration_ms) if duration_ms else 0, "receive": 0},
    }


def _t4b_export_har(self, path: _T4BOptional[str] = None,
                     exchanges: _T4BOptional[_T4BList] = None,
                     creator: str = "CaseCrack-T4B") -> _T4BDict[str, _T4BAny]:
    """Export current/given exchanges as HAR 1.2 to file or return dict."""
    if hasattr(self, "_check_dry_run"):
        stub = self._check_dry_run("export_har", path=path)
        if stub is not None:
            return stub
    src = exchanges if exchanges is not None else getattr(self, "_exchanges", []) or getattr(self, "exchanges", [])
    entries = []
    for ex in src:
        try:
            entries.append(_t4b_har_entry_from_exchange(self, ex))
        except Exception as ex_err:  # noqa: F841
            continue
    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": creator, "version": "1.0"},
            "browser": {"name": "CaseCrack", "version": "1.0"},
            "pages": [],
            "entries": entries,
        }
    }
    if path:
        with open(path, "w", encoding="utf-8") as f:
            _t4b_json.dump(har, f, indent=2)
        return {"path": path, "entries": len(entries)}
    return har


def _t4b_exchange_from_har_entry(self, entry: _T4BDict[str, _T4BAny]) -> _T4BDict[str, _T4BAny]:
    """Convert HAR entry → simple exchange dict."""
    req = entry.get("request", {})
    resp = entry.get("response", {})
    return {
        "method": req.get("method"),
        "url": req.get("url"),
        "request_headers": {h["name"]: h["value"] for h in req.get("headers", [])},
        "response_headers": {h["name"]: h["value"] for h in resp.get("headers", [])},
        "status_code": resp.get("status"),
        "request_body": (req.get("postData", {}) or {}).get("text", ""),
        "response_body": (resp.get("content", {}) or {}).get("text", ""),
        "duration_ms": entry.get("time", 0),
        "started": entry.get("startedDateTime"),
    }


def _t4b_import_har(self, path_or_data) -> _T4BDict[str, _T4BAny]:
    """Load HAR from path or dict; return list of exchanges."""
    if hasattr(self, "_check_dry_run"):
        stub = self._check_dry_run("import_har", source=str(path_or_data)[:80])
        if stub is not None:
            return stub
    if isinstance(path_or_data, str):
        with open(path_or_data, "r", encoding="utf-8") as f:
            data = _t4b_json.load(f)
    elif isinstance(path_or_data, (dict, list)):
        data = path_or_data
    else:
        raise ValueError("path_or_data must be str path or dict")
    log = data.get("log", {}) if isinstance(data, dict) else {}
    entries = log.get("entries", [])
    exchanges = [_t4b_exchange_from_har_entry(self, e) for e in entries]
    if hasattr(self, "_exchanges") and isinstance(self._exchanges, list):
        self._exchanges.extend(exchanges)
    return {"entries": len(exchanges), "exchanges": exchanges}


def _t4b_detect_anomalies(self, exchanges: _T4BOptional[_T4BList] = None,
                           sigma: float = 3.0) -> _T4BList[_T4BDict[str, _T4BAny]]:
    """Run 10 heuristic detectors over exchanges; return findings."""
    if hasattr(self, "_check_dry_run"):
        stub = self._check_dry_run("detect_anomalies")
        if stub is not None:
            return stub
    src = exchanges if exchanges is not None else getattr(self, "_exchanges", []) or getattr(self, "exchanges", [])
    if not src:
        return []
    anoms: _T4BList[_T4BDict[str, _T4BAny]] = []

    def g(o, k, default=None):
        if isinstance(o, dict):
            return o.get(k, default)
        return getattr(o, k, default)

    # 1. Unusually large response (>μ+σ·n)
    sizes = []
    for ex in src:
        rb = g(ex, "response_body", "") or ""
        sizes.append(len(rb) if isinstance(rb, (str, bytes)) else 0)
    if len(sizes) >= 5:
        try:
            mean = _t4b_statistics.mean(sizes)
            stdev = _t4b_statistics.stdev(sizes) if len(sizes) >= 2 else 0
            threshold = mean + sigma * stdev
            for ex, sz in zip(src, sizes):
                if sz > threshold and sz > 10240:
                    anoms.append({"type": "large_response", "severity": "low",
                                  "url": g(ex, "url"), "size": sz,
                                  "reason": f"size {sz} > μ+{sigma}σ ({threshold:.0f})"})
        except Exception:
            pass

    # 2. Slow request (>p95)
    durations = [float(g(ex, "duration_ms", 0) or 0) for ex in src]
    if len(durations) >= 10:
        sorted_d = sorted(durations)
        p95 = sorted_d[int(len(sorted_d) * 0.95)]
        for ex, d in zip(src, durations):
            if d > p95 and d > 1000:
                anoms.append({"type": "slow_request", "severity": "low",
                              "url": g(ex, "url"), "duration_ms": d,
                              "reason": f"duration {d:.0f}ms > p95 ({p95:.0f}ms)"})

    # 3. 5xx burst (≥3 in window of 10 consecutive)
    statuses = [int(g(ex, "status_code", 0) or 0) for ex in src]
    for i in range(len(statuses) - 9):
        window = statuses[i:i + 10]
        five_xx = sum(1 for s in window if 500 <= s < 600)
        if five_xx >= 3:
            anoms.append({"type": "5xx_burst", "severity": "medium",
                          "window_start": i, "five_xx_count": five_xx,
                          "reason": f"{five_xx} 5xx errors in window of 10"})
            break  # one per scan to avoid spam

    # 4. Redirect loops
    seen_chains = {}
    for ex in src:
        url = g(ex, "url", "")
        status = int(g(ex, "status_code", 0) or 0)
        loc = ""
        rh = g(ex, "response_headers", {}) or {}
        if isinstance(rh, dict):
            loc = rh.get("Location") or rh.get("location") or ""
        if 300 <= status < 400 and loc:
            seen_chains.setdefault(url, []).append(loc)
    for src_url, dests in seen_chains.items():
        if len(dests) > 1 and src_url in dests:
            anoms.append({"type": "redirect_loop", "severity": "medium",
                          "url": src_url, "chain": dests[:5],
                          "reason": "destination loops back to source"})

    # 5. Banner leaks
    for ex in src:
        rh = g(ex, "response_headers", {}) or {}
        if isinstance(rh, dict):
            leaks = []
            for k, v in rh.items():
                if k.lower() in _T4B_BANNER_LEAK_HEADERS and v:
                    if any(c.isdigit() for c in str(v)):
                        leaks.append(f"{k}={v}")
            if leaks:
                anoms.append({"type": "banner_leak", "severity": "low",
                              "url": g(ex, "url"), "headers": leaks[:5],
                              "reason": "version-revealing headers exposed"})

    # 6. PII in bodies / URLs
    pii_seen = set()
    for ex in src:
        url = g(ex, "url", "") or ""
        rb = g(ex, "response_body", "") or ""
        body_str = rb if isinstance(rb, str) else (rb.decode("utf-8", errors="replace") if isinstance(rb, bytes) else "")
        haystack = url + "\n" + body_str[:65536]
        for label, rx in _T4B_PII_PATTERNS.items():
            m = rx.search(haystack)
            if m:
                key = (g(ex, "url"), label)
                if key in pii_seen:
                    continue
                pii_seen.add(key)
                sev = "high" if label in ("ssn_us", "credit_card", "private_key_block",
                                            "aws_key", "google_api_key") else "medium"
                anoms.append({"type": "pii_exposure", "severity": sev,
                              "url": g(ex, "url"), "pattern": label,
                              "sample": m.group(0)[:32] + "...",
                              "reason": f"PII pattern '{label}' detected"})

    # 7. JWT in URL or response body
    for ex in src:
        url = g(ex, "url", "") or ""
        rh = g(ex, "response_headers", {}) or {}
        rh_str = " ".join(f"{k}:{v}" for k, v in (rh.items() if isinstance(rh, dict) else []))
        for blob, location in [(url, "url"), (rh_str, "header")]:
            m = _T4B_JWT_RX.search(blob)
            if m:
                tok = m.group(0)
                decoded = _t4b_decode_jwt(tok)
                anoms.append({"type": "jwt_in_url" if location == "url" else "jwt_in_header",
                              "severity": "medium" if location == "header" else "high",
                              "url": g(ex, "url"),
                              "decoded_header": decoded.get("header") if decoded else None,
                              "reason": f"JWT detected in {location}"})

    # 8. Cleartext credentials in URL
    for ex in src:
        url = g(ex, "url", "") or ""
        if _t4b_re.search(r"[?&](password|passwd|pwd|secret|api_key|apikey|token)=[^&\s]+",
                          url, _t4b_re.IGNORECASE):
            anoms.append({"type": "cleartext_credentials", "severity": "high",
                          "url": url[:80], "reason": "credentials transmitted in URL query string"})

    # 9. Directory traversal patterns
    for ex in src:
        url = g(ex, "url", "") or ""
        rb = g(ex, "response_body", "") or ""
        body_str = rb if isinstance(rb, str) else ""
        for ind in _T4B_DIRTRAVERSAL:
            if ind in url or ind in body_str[:8192]:
                anoms.append({"type": "directory_traversal", "severity": "high",
                              "url": g(ex, "url"), "indicator": ind,
                              "reason": f"path traversal indicator in traffic"})
                break

    # 10. SQLi / XSS reflection
    for ex in src:
        rb = g(ex, "response_body", "") or ""
        body_str = (rb if isinstance(rb, str) else "").lower()[:65536]
        for ind in _T4B_SQLI_INDICATORS:
            if ind in body_str:
                anoms.append({"type": "sql_error_disclosure", "severity": "high",
                              "url": g(ex, "url"), "indicator": ind,
                              "reason": "SQL error message in response body"})
                break
        for ind in _T4B_XSS_INDICATORS:
            if ind in (rb if isinstance(rb, str) else ""):
                anoms.append({"type": "xss_reflection", "severity": "high",
                              "url": g(ex, "url"), "indicator": ind,
                              "reason": "potential XSS payload reflected"})
                break

    return anoms


def _t4b_traffic_baseline(self, exchanges: _T4BOptional[_T4BList] = None) -> _T4BDict[str, _T4BAny]:
    """Compute statistical baseline of traffic for later comparison."""
    if hasattr(self, "_check_dry_run"):
        stub = self._check_dry_run("traffic_baseline")
        if stub is not None:
            return stub
    src = exchanges if exchanges is not None else getattr(self, "_exchanges", []) or getattr(self, "exchanges", [])

    def g(o, k, d=None):
        if isinstance(o, dict):
            return o.get(k, d)
        return getattr(o, k, d)

    sizes = [len(g(e, "response_body", "") or "") for e in src]
    durs = [float(g(e, "duration_ms", 0) or 0) for e in src]
    statuses = [int(g(e, "status_code", 0) or 0) for e in src]
    methods = {}
    for e in src:
        m = g(e, "method", "GET")
        methods[m] = methods.get(m, 0) + 1
    status_class = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0}
    for s in statuses:
        if 200 <= s < 300:
            status_class["2xx"] += 1
        elif 300 <= s < 400:
            status_class["3xx"] += 1
        elif 400 <= s < 500:
            status_class["4xx"] += 1
        elif 500 <= s < 600:
            status_class["5xx"] += 1
        else:
            status_class["other"] += 1

    return {
        "exchange_count": len(src),
        "size_mean": (_t4b_statistics.mean(sizes) if sizes else 0),
        "size_stdev": (_t4b_statistics.stdev(sizes) if len(sizes) >= 2 else 0),
        "size_max": max(sizes) if sizes else 0,
        "duration_mean_ms": (_t4b_statistics.mean(durs) if durs else 0),
        "duration_p95_ms": (sorted(durs)[int(len(durs) * 0.95)] if len(durs) >= 10 else 0),
        "methods": methods, "status_class": status_class,
    }


def _t4b_compare_to_baseline(self, baseline: _T4BDict[str, _T4BAny],
                              exchanges: _T4BOptional[_T4BList] = None,
                              tolerance: float = 0.5) -> _T4BDict[str, _T4BAny]:
    """Compare current traffic against a saved baseline; report divergence."""
    cur = _t4b_traffic_baseline(self, exchanges=exchanges)
    divergence = {}
    for key in ("size_mean", "duration_mean_ms", "duration_p95_ms"):
        b = baseline.get(key, 0) or 0
        c = cur.get(key, 0) or 0
        if b == 0:
            continue
        rel = abs(c - b) / b
        divergence[key] = {"baseline": b, "current": c, "rel_change": round(rel, 3),
                           "exceeds_tolerance": rel > tolerance}
    # status class drift
    status_drift = {}
    bsc = baseline.get("status_class", {}) or {}
    csc = cur.get("status_class", {}) or {}
    for cls in ("2xx", "3xx", "4xx", "5xx"):
        b = bsc.get(cls, 0); c = csc.get(cls, 0)
        if b + c == 0:
            continue
        status_drift[cls] = {"baseline": b, "current": c, "delta": c - b}
    return {"current": cur, "baseline": baseline, "divergence": divergence,
            "status_drift": status_drift,
            "alarm": any(d.get("exceeds_tolerance") for d in divergence.values())}


def _t4b_filter_exchanges(self, predicate=None, host=None, status=None, method=None):
    """Filter stored exchanges by predicate/host/status/method. Returns list."""
    src = getattr(self, "_exchanges", []) or getattr(self, "exchanges", [])
    out = []
    for ex in src:
        def g(k, d=None):
            return ex.get(k, d) if isinstance(ex, dict) else getattr(ex, k, d)
        if host and host not in (g("url") or ""):
            continue
        if status is not None and int(g("status_code", 0) or 0) != status:
            continue
        if method and (g("method") or "").upper() != method.upper():
            continue
        if predicate and not predicate(ex):
            continue
        out.append(ex)
    return out


# Bind to TrafficAnalyzer
try:
    TrafficAnalyzer.export_har = _t4b_export_har  # type: ignore[name-defined]
    TrafficAnalyzer.import_har = _t4b_import_har  # type: ignore[name-defined]
    TrafficAnalyzer.detect_anomalies = _t4b_detect_anomalies  # type: ignore[name-defined]
    TrafficAnalyzer.traffic_baseline = _t4b_traffic_baseline  # type: ignore[name-defined]
    TrafficAnalyzer.compare_to_baseline = _t4b_compare_to_baseline  # type: ignore[name-defined]
    TrafficAnalyzer.filter_exchanges = _t4b_filter_exchanges  # type: ignore[name-defined]
except NameError:
    pass

# ====================== END __TIER4B_NETWORK__ ========================
