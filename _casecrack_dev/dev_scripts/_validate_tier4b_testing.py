"""Tier 4B Testing — validator: ~80 functional checks.

Imports each testing_tools module, instantiates engines, exercises the
new T4B methods, and reports PASS/FAIL counts.
"""
from __future__ import annotations
import importlib
import sys
import json
import time
import os
import traceback
from pathlib import Path
from typing import Any, Callable, List, Tuple

ROOT = Path(__file__).parent
PKG = "CaseCrack.tools.burp_enterprise.testing_tools"
sys.path.insert(0, str(ROOT))

results: List[Tuple[str, str, str]] = []  # (name, status, detail)


def check(name: str, fn: Callable[[], Any]) -> None:
    try:
        v = fn()
        if v is False:
            results.append((name, "FAIL", "returned False"))
        elif v is None:
            results.append((name, "PASS", ""))
        else:
            results.append((name, "PASS", str(v)[:80]))
    except AssertionError as e:
        results.append((name, "FAIL", f"AssertionError: {e}"))
    except Exception as e:
        tb = traceback.format_exc().splitlines()[-1]
        results.append((name, "FAIL", f"{type(e).__name__}: {e} | {tb}"))


# === Imports & engine class presence ===
def import_mod(short: str):
    return importlib.import_module(f"{PKG}.{short}")

modules = {}
for nm in ("api_fuzzer","benchmark_runner","compliance_validator",
              "integration_harness","load_tester","mock_server","regression_tracker"):
    check(f"import_{nm}", lambda nm=nm: modules.setdefault(nm, import_mod(nm)) is not None)

if any(s == "FAIL" for _, s, _ in results):
    print("Imports failed — aborting")
    for n, s, d in results:
        if s == "FAIL":
            print(f"  {s}: {n}: {d}")
    sys.exit(2)

api_fuzz = modules["api_fuzzer"]
bench    = modules["benchmark_runner"]
cv       = modules["compliance_validator"]
ih       = modules["integration_harness"]
lt       = modules["load_tester"]
mock     = modules["mock_server"]
reg      = modules["regression_tracker"]

# === Engine class lookup ===
def get_engine(mod, name):
    return getattr(mod, name)

ApiFuzzer           = get_engine(api_fuzz, "ApiFuzzer")
BenchmarkRunner     = get_engine(bench,    "BenchmarkRunner")
ComplianceValidator = get_engine(cv,       "ComplianceValidator")
IntegrationHarness  = get_engine(ih,       "IntegrationHarness")
LoadTester          = get_engine(lt,       "LoadTester")
MockServer          = get_engine(mock,     "MockServer")
RegressionTracker   = get_engine(reg,      "RegressionTracker")

# === Method presence ===
EXPECTED = {
    ApiFuzzer:           ["supported_strategies","fuzz_strategy_mutation","fuzz_strategy_random",
                            "fuzz_strategy_boundary","fuzz_strategy_dictionary","fuzz_strategy_grammar",
                            "generate_fuzz_cases","run_fuzz_campaign","register_dictionary_payload"],
    BenchmarkRunner:     ["compute_stats","run_timed","run_per_call","run_with_cprofile",
                            "run_with_memory","compare_results","export_html_report",
                            "export_json_report","save_baseline","load_baseline","supported_bench_modes"],
    ComplianceValidator: ["dsl_load_rules","dsl_loaded_rules","dsl_validate_record",
                            "dsl_validate_batch","dsl_register_operator","dsl_supported_operators",
                            "dsl_export_rules_json","dsl_explain_rule","dsl_test_rule"],
    IntegrationHarness:  ["register_fixture","register_test","test","fixture",
                            "run_all_tests","export_junit_xml","save_junit_xml",
                            "clear_harness","harness_summary"],
    LoadTester:          ["new_hdr_histogram","run_async","run_threaded","run_ramp",
                            "analyze_load_result","supported_engines"],
    MockServer:          ["render_template","render_json_template","register_ws_route",
                            "serve_ws_socket","register_graphql_schema","graphql_execute",
                            "register_grpc_service","grpc_call","encode_grpc_frame",
                            "decode_grpc_frame","supported_protocols","mock_summary"],
    RegressionTracker:   ["db_open","db_close","save_baseline","load_baseline","list_baselines",
                            "record_run","compare_to_baseline","check_sla","list_breaches",
                            "regression_report","export_csv","prune_old_runs","db_summary"],
}
for cls, methods in EXPECTED.items():
    for m in methods:
        check(f"method_{cls.__name__}.{m}", lambda c=cls, m=m: callable(getattr(c, m, None)))


# === Helper: build instance ===
def build(cls):
    """Try multiple construction strategies."""
    try: return cls()
    except TypeError: pass
    # Try with one positional dict
    try: return cls({})
    except Exception: pass
    # Try empty kwargs subset
    try: return cls.__new__(cls)
    except Exception: pass
    raise RuntimeError(f"could_not_instantiate {cls.__name__}")

# === Section: ApiFuzzer ===
af = build(ApiFuzzer)
check("af.supported_strategies==5",
        lambda: len(af.supported_strategies()) == 5)
check("af.fuzz_strategy_mutation produces variants",
        lambda: len(af.fuzz_strategy_mutation({"s": "hello"})) >= 3)
check("af.fuzz_strategy_random produces typed values",
        lambda: len(af.fuzz_strategy_random({"x": 1, "y": "a"}, cases_per_param=3)) >= 5)
check("af.fuzz_strategy_boundary contains 0",
        lambda: 0 in [c.payload for c in af.fuzz_strategy_boundary({"n": 0})])
check("af.fuzz_strategy_boundary contains empty string",
        lambda: "" in [c.payload for c in af.fuzz_strategy_boundary({"s": "x"})])
check("af.fuzz_strategy_dictionary contains SQLi",
        lambda: any("OR" in str(c.payload).upper()
                        for c in af.fuzz_strategy_dictionary({"q": "test"})))
check("af.fuzz_strategy_grammar produces JSON",
        lambda: len(af.fuzz_strategy_grammar({"q": "x"}, "json")) >= 1)
check("af.generate_fuzz_cases mutation strategy",
        lambda: len(af.generate_fuzz_cases({"a": 1, "b": "x"}, ["mutation"])) >= 4)
check("af.generate_fuzz_cases dictionary strategy",
        lambda: len(af.generate_fuzz_cases({"q": "test"}, ["dictionary"])) >= 5)
check("af.run_fuzz_campaign returns dict",
        lambda: isinstance(af.run_fuzz_campaign(
            "http://127.0.0.1:1", "GET", {"id": 1},
            strategies=["random"], max_cases=2, timeout=0.5), dict))
check("af.register_dictionary_payload new",
        lambda: af.register_dictionary_payload("__t4b_test_payload__") is True)


# === Section: BenchmarkRunner ===
br = build(BenchmarkRunner)
check("br.compute_stats basic",
        lambda: br.compute_stats([1.0,2.0,3.0,4.0,5.0,6.0,7.0,8.0,9.0,10.0])["mean"] == 5.5)
check("br.compute_stats has p99",
        lambda: "p99" in br.compute_stats([1.0,2.0,3.0,4.0,5.0]))
def _bench_fn(): return sum(range(100))
check("br.run_timed lambda",
        lambda: br.run_timed(_bench_fn, iterations=20).iterations == 20)
check("br.run_per_call returns stats",
        lambda: "stats_us" in br.run_per_call(_bench_fn, iterations=10))
check("br.run_with_cprofile returns top",
        lambda: isinstance(br.run_with_cprofile(_bench_fn, iterations=5).get("top"), list))
check("br.run_with_memory returns peak",
        lambda: "peak_kb" in br.run_with_memory(_bench_fn, iterations=5))
def _r(): return br.run_per_call(_bench_fn, iterations=10)
check("br.compare_results no regression",
        lambda: isinstance(br.compare_results(_r(), _r(), regression_threshold_pct=50.0), dict))
check("br.export_html_report contains <html",
        lambda: "<html" in br.export_html_report([_r()]).lower())
check("br.export_json_report parseable",
        lambda: isinstance(json.loads(br.export_json_report([_r()])), (dict, list)))
import tempfile
_tmp = tempfile.mkdtemp()
_blpath = os.path.join(_tmp, "baseline.json")
check("br.save_baseline file",
        lambda: br.save_baseline([_r()], _blpath).get("ok") is True)
check("br.load_baseline file",
        lambda: br.load_baseline(_blpath) is not None)
check("br.supported_bench_modes >=4",
        lambda: len(br.supported_bench_modes()) >= 4)


# === Section: ComplianceValidator ===
cvi = build(ComplianceValidator)
sample_rules = [
    {"rule_id": "R1", "description": "Status must be active",
      "severity": "high",
      "when": [{"field": "status", "op": "==", "value": "inactive"}],
      "framework": "PCI", "tags": ["account"]},
    {"rule_id": "R2", "description": "Email matches",
      "severity": "medium",
      "when": [{"field": "email", "op": "matches", "value": r".*@evil\.com"}],
      "framework": "GDPR", "tags": ["data"]},
]
check("cvi.dsl_load_rules ok",
        lambda: cvi.dsl_load_rules(sample_rules)["loaded"] == 2)
check("cvi.dsl_loaded_rules count==2",
        lambda: len(cvi.dsl_loaded_rules()) == 2)
check("cvi.dsl_validate_record matches inactive",
        lambda: any(m["rule_id"] == "R1"
                        for m in cvi.dsl_validate_record({"status": "inactive", "email": "a@b.com"})))
check("cvi.dsl_validate_record matches evil email",
        lambda: any(m["rule_id"] == "R2"
                        for m in cvi.dsl_validate_record({"status": "active", "email": "x@evil.com"})))
check("cvi.dsl_validate_record no match clean",
        lambda: cvi.dsl_validate_record({"status": "active", "email": "a@b.com"}) == [])
batch = [{"status": "inactive", "email": "a@b.com"},
            {"status": "active", "email": "x@evil.com"},
            {"status": "active", "email": "a@b.com"}]
res = cvi.dsl_validate_batch(batch)
check("cvi.dsl_validate_batch records_evaluated==3",
        lambda: res["records_evaluated"] == 3)
check("cvi.dsl_validate_batch by_severity has high>=1",
        lambda: res["by_severity"]["high"] >= 1)
check("cvi.dsl_supported_operators >=18",
        lambda: len(cvi.dsl_supported_operators()) >= 18)
check("cvi.dsl_register_operator new",
        lambda: cvi.dsl_register_operator("__t4b_op__", lambda a, b: a == b) is True)
check("cvi.dsl_explain_rule R1",
        lambda: cvi.dsl_explain_rule("R1")["rule_id"] == "R1")
check("cvi.dsl_export_rules_json parseable",
        lambda: isinstance(json.loads(cvi.dsl_export_rules_json()), list))
check("cvi.dsl_test_rule ad-hoc",
        lambda: cvi.dsl_test_rule(
            {"rule_id": "T", "when": [{"field": "x", "op": "==", "value": 1}]},
            {"x": 1})["matched"] is True)


# === Section: IntegrationHarness ===
ihi = build(IntegrationHarness)
ihi.clear_harness()
check("ihi.register_fixture",
        lambda: ihi.register_fixture("db", lambda: {"conn": True}) is True)
def _t_pass(db): assert db["conn"] is True
def _t_fail(): assert 1 == 2, "intentional failure"
def _t_error(): raise RuntimeError("boom")
ihi.register_test("test_pass", _t_pass, fixtures=["db"])
ihi.register_test("test_fail", _t_fail)
ihi.register_test("test_error", _t_error)
ihi.register_test("test_skip", lambda: None, skip=True, skip_reason="manual")
run_res = ihi.run_all_tests()
check("ihi.run_all_tests total==4",
        lambda: run_res["total"] == 4)
check("ihi.run_all_tests passed==1",
        lambda: run_res["passed"] == 1)
check("ihi.run_all_tests failed==1",
        lambda: run_res["failed"] == 1)
check("ihi.run_all_tests errors==1",
        lambda: run_res["errors"] == 1)
check("ihi.run_all_tests skipped==1",
        lambda: run_res["skipped"] == 1)
xml = ihi.export_junit_xml()
check("ihi.export_junit_xml has <testsuites>",
        lambda: "<testsuites>" in xml)
check("ihi.export_junit_xml has <testcase",
        lambda: "<testcase" in xml)
check("ihi.export_junit_xml has <failure",
        lambda: "<failure" in xml)
check("ihi.export_junit_xml has <error",
        lambda: "<error" in xml)
check("ihi.export_junit_xml has <skipped",
        lambda: "<skipped" in xml)
_jpath = os.path.join(_tmp, "junit.xml")
check("ihi.save_junit_xml file",
        lambda: ihi.save_junit_xml(_jpath)["ok"] is True)
check("ihi.harness_summary",
        lambda: ihi.harness_summary()["tests_registered"] == 4)


# === Section: LoadTester ===
lti = build(LoadTester)
hist = lti.new_hdr_histogram()
for v in (100, 200, 500, 1000, 2000, 5000, 10000):
    hist.record(v)
check("lt.HdrHistogram count==7",
        lambda: hist.total_count == 7)
check("lt.HdrHistogram p50>0",
        lambda: hist.percentile(0.5) > 0)
check("lt.HdrHistogram p99>=p50",
        lambda: hist.percentile(0.99) >= hist.percentile(0.5))
check("lt.supported_engines includes threaded",
        lambda: "threaded_urllib" in lti.supported_engines())
fake_result = {
    "requests_completed": 100, "errors": 1,
    "rps_actual": 50.0,
    "latency_us": {"p50_us": 1000, "p95_us": 2000, "p99_us": 3000, "p999_us": 5000},
}
check("lt.analyze_load_result no SLA",
        lambda: lti.analyze_load_result(fake_result)["sla_pass"] is True)
check("lt.analyze_load_result SLA breach",
        lambda: lti.analyze_load_result(fake_result, sla_p99_us=1000)["sla_pass"] is False)
check("lt.analyze_load_result error rate breach",
        lambda: lti.analyze_load_result(fake_result, sla_error_rate=0.001)["sla_pass"] is False)


# === Section: MockServer ===
mki = build(MockServer)
check("mk.render_template basic",
        lambda: mki.render_template("hello {{name}}", {"name": "world"}) == "hello world")
check("mk.render_template uuid",
        lambda: len(mki.render_template("{{uuid}}", {})) > 10)
check("mk.render_template now",
        lambda: mki.render_template("{{now}}", {}).isdigit())
check("mk.render_template random_int",
        lambda: 1 <= int(mki.render_template("{{random_int(1,5)}}", {})) <= 5)
check("mk.render_template nested path",
        lambda: mki.render_template("{{user.name}}", {"user": {"name": "alice"}}) == "alice")
check("mk.render_json_template",
        lambda: mki.render_json_template({"k": "{{name}}"}, {"name": "v"})["k"] == "v")
check("mk.register_ws_route",
        lambda: mki.register_ws_route("/echo", lambda data, ctx: data) is True)
gql_schema = {
    "Query": {
        "user": lambda args, ctx: {"id": args.get("id", 1), "name": "Alice"},
        "users": [{"id": 1, "name": "{{ args.prefix }}1"}],
    },
    "Mutation": {
        "createUser": lambda args, ctx: {"id": 99, "name": args.get("name")},
    },
}
check("mk.register_graphql_schema",
        lambda: mki.register_graphql_schema(gql_schema) is True)
res = mki.graphql_execute('query { user(id: 42) }', variables={})
check("mk.graphql_execute query user",
        lambda: res["data"]["user"]["id"] == 42)
res2 = mki.graphql_execute('mutation { createUser(name: "Bob") }')
check("mk.graphql_execute mutation",
        lambda: res2["data"]["createUser"]["name"] == "Bob")
res3 = mki.graphql_execute('query { unknown_field }')
check("mk.graphql_execute unknown returns errors",
        lambda: "errors" in res3)
check("mk.register_grpc_service",
        lambda: mki.register_grpc_service("UserService",
                                                  {"GetUser": lambda r: {"id": r.get("id"), "name": "X"}}) is True)
gres = mki.grpc_call("UserService", "GetUser", {"id": 7})
check("mk.grpc_call OK",
        lambda: gres["status"] == "OK" and gres["response"]["id"] == 7)
gerr = mki.grpc_call("Unknown", "X", {})
check("mk.grpc_call UNIMPLEMENTED",
        lambda: gerr["status"] == "UNIMPLEMENTED")
frame = mki.encode_grpc_frame({"hello": "world"})
check("mk.encode_grpc_frame bytes",
        lambda: isinstance(frame, bytes) and len(frame) > 5)
check("mk.decode_grpc_frame roundtrip",
        lambda: mki.decode_grpc_frame(frame)["hello"] == "world")
check("mk.supported_protocols 4",
        lambda: len(mki.supported_protocols()) == 4)
check("mk.mock_summary",
        lambda: "ws_routes" in mki.mock_summary())


# === Section: RegressionTracker ===
rti = build(RegressionTracker)
check("rt.db_open in-memory",
        lambda: rti.db_open(":memory:")["ok"] is True)
check("rt.save_baseline",
        lambda: rti.save_baseline("api_p99_ms", 100.0,
                                          target_p95=80, target_p99=150,
                                          sla_threshold_pct=10.0)["ok"] is True)
check("rt.load_baseline",
        lambda: rti.load_baseline("api_p99_ms")["value"] == 100.0)
check("rt.list_baselines",
        lambda: len(rti.list_baselines()) == 1)
rec1 = rti.record_run("api_p99_ms", 105.0, p50=50, p95=85, p99=130)
check("rt.record_run returns id",
        lambda: rec1["run_id"] is not None)
rti.record_run("api_p99_ms", 180.0, p50=80, p95=120, p99=200)
cmp = rti.compare_to_baseline("api_p99_ms", 150.0)
check("rt.compare_to_baseline regression flagged",
        lambda: cmp["regressed"] is True)
cmp_ok = rti.compare_to_baseline("api_p99_ms", 102.0)
check("rt.compare_to_baseline stable",
        lambda: cmp_ok["verdict"] == "stable")
sla = rti.check_sla("api_p99_ms", current_p95=120, current_p99=200, run_id=rec1["run_id"])
check("rt.check_sla detects breach",
        lambda: sla["sla_pass"] is False and sla["breach_count"] >= 1)
sla_ok = rti.check_sla("api_p99_ms", current_p95=70, current_p99=100)
check("rt.check_sla pass",
        lambda: sla_ok["sla_pass"] is True)
breaches = rti.list_breaches("api_p99_ms")
check("rt.list_breaches >=1",
        lambda: len(breaches) >= 1)
rep = rti.regression_report("api_p99_ms")
check("rt.regression_report has stability_score",
        lambda: "stability_score" in rep)
csv_out = rti.export_csv("api_p99_ms")
check("rt.export_csv non-empty",
        lambda: len(csv_out) > 0 and "metric_name" in csv_out)
prune = rti.prune_old_runs(keep_per_metric=1)
check("rt.prune_old_runs",
        lambda: prune["ok"] is True)
summ = rti.db_summary()
check("rt.db_summary has counts",
        lambda: "baselines" in summ and "breaches" in summ)
rti.db_close()

# === Print results ===
passed = sum(1 for _, s, _ in results if s == "PASS")
failed = sum(1 for _, s, _ in results if s == "FAIL")
total = len(results)
print()
print("=" * 70)
for n, s, d in results:
    if s == "FAIL":
        print(f"  {s}: {n}: {d}")
print("=" * 70)
print(f"PASSED: {passed}/{total}")
print(f"FAILED: {failed}/{total}")
print(f"PASS RATE: {passed/total*100:.1f}%")
sys.exit(0 if failed == 0 else 1)
