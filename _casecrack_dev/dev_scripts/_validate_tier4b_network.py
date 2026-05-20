"""Tier 4B Network validation: imports + per-module deep-feature smoke tests."""
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "CaseCrack"))

PASS = "✅"
FAIL = "❌"


def section(name):
    print(f"\n=== {name} ===")


def check(label, fn):
    try:
        result = fn()
        ok = bool(result) if not isinstance(result, dict) else True
        print(f"  {PASS if ok else FAIL} {label}: {result if not isinstance(result, dict) else list(result.keys())[:6]}")
        return ok
    except Exception as ex:
        print(f"  {FAIL} {label}: {type(ex).__name__}: {ex}")
        traceback.print_exc(limit=2)
        return False


def main() -> int:
    section("IMPORTS (5 modules)")
    from tools.burp_enterprise.network import (
        dns_resolver, http_fingerprint, ssl_analyzer,
        traffic_analyzer, proxy_chain,
    )
    print(f"  {PASS} all 5 network modules imported")

    section("Tier 4B method presence")
    expected = {
        dns_resolver.DNSResolver: [
            "axfr_zone_transfer", "try_axfr", "doh_query",
            "doh_wireformat_query", "dnssec_validate",
            "dnssec_chain_walk", "reverse_lookup",
        ],
        http_fingerprint.HTTPFingerprinter: [
            "wappalyzer_match", "fingerprint_with_wappalyzer",
            "wappalyzer_register_tech", "wappalyzer_categories",
            "wappalyzer_db_size", "extract_security_headers",
        ],
        ssl_analyzer.SSLAnalyzer: [
            "enumerate_ciphers", "weak_cipher_report", "ocsp_check",
            "extract_ocsp_url", "ct_log_search",
            "ct_extract_subdomains", "assess_cipher_strength",
        ],
        traffic_analyzer.TrafficAnalyzer: [
            "export_har", "import_har", "detect_anomalies",
            "traffic_baseline", "compare_to_baseline", "filter_exchanges",
        ],
        proxy_chain.ProxyChain: [
            "start_health_checks", "stop_health_checks", "check_one_proxy",
            "proxy_score", "health_report", "auto_disable_unhealthy",
            "get_best_proxy", "circuit_state",
        ],
    }
    total_methods = 0
    missing = []
    for cls, methods in expected.items():
        for m in methods:
            total_methods += 1
            if not hasattr(cls, m):
                missing.append(f"{cls.__name__}.{m}")
    if missing:
        print(f"  {FAIL} missing methods: {missing}")
        return 1
    print(f"  {PASS} all {total_methods} new methods present across 5 classes")

    section("DNS resolver — DoH JSON (live, may fail offline)")
    r = dns_resolver.DNSResolver()
    try:
        out = r.doh_query("example.com", "A", provider="cloudflare", timeout=8)
        print(f"  ✅ doh_query: status={out.get('status')} answers={len(out.get('answers', []))}")
    except Exception as ex:
        print(f"  ⚠ doh_query offline/cert: {type(ex).__name__}: {str(ex)[:100]}")

    section("DNS resolver — DoH wireformat + DNSSEC")
    try:
        out = r.doh_wireformat_query("cloudflare.com", "A", timeout=8)
        print(f"  ✅ doh_wireformat: rcode={out.get('rcode')} answers={len(out.get('answers', []))}")
    except Exception as ex:
        print(f"  ⚠ doh_wireformat offline/cert: {type(ex).__name__}: {str(ex)[:100]}")
    try:
        v = r.dnssec_validate("cloudflare.com", timeout=8)
        check("dnssec_validate returns report", lambda: "dnssec_present" in v)
    except Exception as ex:
        print(f"  ⚠ dnssec_validate offline: {ex}")

    section("DNS resolver — query/parse primitives")
    from tools.burp_enterprise.network.dns_resolver import (
        _t4b_build_query, _t4b_parse_response, _T4B_RR_TYPES,
    )
    type_by_name = {v: k for k, v in _T4B_RR_TYPES.items()}
    msg = _t4b_build_query("example.com", type_by_name["A"])
    check("build_query produces ≥25 bytes (DNS wire format)", lambda: len(msg) >= 25)

    section("HTTP fingerprint — Wappalyzer DB")
    fp = http_fingerprint.HTTPFingerprinter()
    sz = fp.wappalyzer_db_size()
    print(f"  ℹ DB: {sz}")
    check("DB has ≥40 techs and ≥10 categories",
          lambda: sz["techs"] >= 40 and sz["categories"] >= 10)

    section("HTTP fingerprint — match against synthetic page")
    html = ('<html><head>'
            '<meta name="generator" content="WordPress 6.4">'
            '<script src="/wp-content/plugins/woocommerce/assets/js/x.js"></script>'
            '<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>'
            '<script src="https://www.google-analytics.com/analytics.js"></script>'
            '</head><body class="container"><script src="bootstrap.bundle.min.js"></script>'
            '<div data-reactroot></div></body></html>')
    headers = {"Server": "nginx/1.21.6", "X-Powered-By": "PHP/8.1.0",
               "X-Pingback": "https://x.com/xmlrpc.php"}
    cookies = "PHPSESSID=abc; _shopify_y=xyz"
    techs = fp.wappalyzer_match(html=html, headers=headers, cookies=cookies, url="https://x.com")
    detected = {t["tech"] for t in techs}
    expected_techs = {"WordPress", "WooCommerce", "jQuery", "Bootstrap", "Nginx", "PHP", "Google Analytics"}
    found = detected & expected_techs
    print(f"  detected: {sorted(detected)[:12]}")
    check(f"≥6 of {len(expected_techs)} expected detected", lambda: len(found) >= 6)
    check("WordPress version captured",
          lambda: any(t["tech"] == "WordPress" and t["version"] == "6.4" for t in techs))
    check("Nginx version captured",
          lambda: any(t["tech"] == "Nginx" and (t["version"] or "").startswith("1.21") for t in techs))

    section("HTTP fingerprint — security headers audit")
    audit = fp.extract_security_headers({"Strict-Transport-Security": "max-age=31536000",
                                          "X-Content-Type-Options": "nosniff"})
    check("audit reports score + missing", lambda: "score" in audit and isinstance(audit["missing"], list))

    section("SSL analyzer — cipher DB + assessment")
    sa = ssl_analyzer.SSLAnalyzer()
    a = sa.assess_cipher_strength("TLS_AES_128_GCM_SHA256")
    check("TLS 1.3 cipher recognized as secure", lambda: a["strength"] == "secure")
    b = sa.assess_cipher_strength("RC4-MD5")
    check("RC4-MD5 flagged insecure", lambda: b["strength"] == "insecure")

    section("SSL analyzer — weak cipher report")
    fake_results = {
        "TLSv1.0": {"supported": [{"name": "RC4-MD5", "strength": "insecure"}],
                    "rejected": [], "errors": []},
        "TLSv1.2": {"supported": [{"name": "ECDHE-RSA-AES128-GCM-SHA256", "strength": "secure"}],
                    "rejected": [], "errors": []},
    }
    rep = sa.weak_cipher_report(fake_results)
    print(f"  report: insecure={rep['insecure_count']} weak={rep['weak_count']} score={rep['score']}")
    check("weak_cipher_report flags RC4 + deprecated TLSv1.0",
          lambda: rep["insecure_count"] >= 1 and len(rep["findings"]) >= 2)

    section("SSL analyzer — CT log search (live, may fail offline)")
    try:
        ct = sa.ct_log_search("example.com", log="crt.sh", timeout=15, limit=20)
        if "error" in ct:
            print(f"  ⚠ ct_log_search offline/error: {ct.get('error')}")
        else:
            print(f"  {PASS} crt.sh: {ct.get('cert_count', 0)} certs, {ct.get('subdomain_count', 0)} subdomains")
    except Exception as ex:
        print(f"  ⚠ CT log query exception (network): {ex}")

    section("Traffic analyzer — HAR roundtrip")
    ta = traffic_analyzer.TrafficAnalyzer()
    sample_exchanges = [
        {"method": "GET", "url": "https://x.com/?password=secret123",
         "request_headers": {"User-Agent": "x"},
         "response_headers": {"Content-Type": "text/html", "Server": "nginx/1.21"},
         "status_code": 200, "request_body": "",
         "response_body": "<html>OK</html>", "duration_ms": 120, "started": 1700000000},
        {"method": "POST", "url": "https://x.com/api",
         "request_headers": {"Content-Type": "application/json"},
         "response_headers": {"Content-Type": "application/json"},
         "status_code": 500, "request_body": '{"a":1}',
         "response_body": "you have an error in your sql syntax",
         "duration_ms": 5500, "started": 1700000010},
    ]
    har = ta.export_har(exchanges=sample_exchanges)
    check("HAR has 2 entries", lambda: len(har["log"]["entries"]) == 2)
    check("HAR creator metadata", lambda: har["log"]["creator"]["name"].startswith("CaseCrack"))

    rt = ta.import_har(har)
    check("HAR roundtrip preserves count", lambda: rt["entries"] == 2)

    section("Traffic analyzer — anomaly heuristics")
    anoms = ta.detect_anomalies(exchanges=sample_exchanges)
    types = {a["type"] for a in anoms}
    print(f"  {len(anoms)} anomalies: {sorted(types)}")
    check("cleartext_credentials detected", lambda: "cleartext_credentials" in types)
    check("sql_error_disclosure detected", lambda: "sql_error_disclosure" in types)
    check("banner_leak detected", lambda: "banner_leak" in types)

    section("Traffic analyzer — baseline + compare")
    bl = ta.traffic_baseline(exchanges=sample_exchanges)
    check("baseline has stats", lambda: bl["exchange_count"] == 2 and "size_mean" in bl)
    cmp = ta.compare_to_baseline(bl, exchanges=sample_exchanges)
    check("baseline compare returns alarm flag", lambda: "alarm" in cmp)

    section("Proxy chain — health-check infra (no network)")
    pc = proxy_chain.ProxyChain()
    # check infra without actually probing
    started = pc.start_health_checks(interval=999, timeout=2)
    check("start returns status", lambda: started.get("status") in ("started", "already_running"))
    rep_p = pc.health_report()
    check("health_report shape", lambda: "summary" in rep_p and "proxies" in rep_p)
    stopped = pc.stop_health_checks(join_timeout=2.0)
    check("stop signals", lambda: stopped.get("status") in ("stopped", "partial", "not_running"))

    section("Proxy chain — circuit breaker")
    pc._health_history = {"px1": []}
    from tools.burp_enterprise.network.proxy_chain import HealthCheckResult
    import time as _t
    pc._health_history["px1"] = [
        HealthCheckResult(proxy_id="px1", proxy_url="http://x", success=False,
                           latency_ms=100, error="x", checked_at=_t.time())
        for _ in range(6)
    ]
    state = pc.circuit_state("px1", fail_threshold=5, recovery_window_s=60)
    check("circuit opens after 6 consecutive failures", lambda: state == "open")

    section("LOC growth")
    sizes = {}
    for m in ("dns_resolver", "http_fingerprint", "ssl_analyzer",
               "traffic_analyzer", "proxy_chain"):
        p = ROOT / "CaseCrack" / "tools" / "burp_enterprise" / "network" / f"{m}.py"
        sizes[m] = len(p.read_text(encoding="utf-8").splitlines())
    for m, n in sizes.items():
        print(f"  {m}.py: {n} LOC")
    print(f"  TOTAL: {sum(sizes.values())} LOC across 5 modules (avg {sum(sizes.values())//5})")

    print("\n=== TIER 4B NETWORK VALIDATION COMPLETE ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
