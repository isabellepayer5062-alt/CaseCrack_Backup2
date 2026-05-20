# __TIER4B_TESTING__
# Tier 4B Testing — api_fuzzer: 5 strategy implementations
import random as _t4b_rand
import string as _t4b_str
import re as _t4b_re
import json as _t4b_json
import time as _t4b_time
import urllib.request as _t4b_ur
import urllib.parse as _t4b_up
import urllib.error as _t4b_uerr
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from dataclasses import dataclass, field

# Strategy registry
_T4B_FUZZ_STRATEGIES = ("mutation", "random", "boundary", "dictionary", "grammar")

# Boundary values for numeric/string params
_T4B_BOUNDARY_INT = [0, 1, -1, 2147483647, -2147483648, 9223372036854775807,
                          -9223372036854775808, 65535, 65536, 4294967295]
_T4B_BOUNDARY_STR = ["", "A", "A" * 1, "A" * 1024, "A" * 65536, "\x00",
                          "\xff" * 16, "\u0000\u0001\u0002", "\\", "/", "../"]
_T4B_BOUNDARY_FLOAT = [0.0, -0.0, 1e308, -1e308, 1e-308, float("inf"),
                            float("-inf"), float("nan")]

# Dictionary attack payloads (well-known fuzz seeds)
_T4B_DICT_PAYLOADS = [
    # SQLi
    "' OR '1'='1", "'; DROP TABLE x;--", "' UNION SELECT NULL--", "1' AND SLEEP(5)--",
    # XSS
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)",
    # Path traversal
    "../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam",
    "%2e%2e%2f%2e%2e%2f", "....//....//etc/passwd",
    # Command injection
    "; cat /etc/passwd", "| whoami", "`id`", "$(id)", "& net user",
    # SSRF
    "http://127.0.0.1:80", "http://169.254.169.254/latest/meta-data/",
    "file:///etc/passwd", "gopher://127.0.0.1:6379/_INFO",
    # Format string
    "%s%s%s%s%s%s%n", "%x%x%x%x", "{0}{0}{0}",
    # NULL bytes & special
    "\x00", "\r\n", "\n", "\\", "%00",
    # Buffer overflow seeds
    "A" * 10000, "%n" * 100,
    # XXE
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><x>&a;</x>',
    # NoSQL injection
    '{"$gt": ""}', '{"$ne": null}', '{"$where": "this.password.match(/.*/)"}',
    # LDAP
    "*)(uid=*))(|(uid=*", "admin)(&(password=*",
]

# Grammar templates: simple BNF-style productions
_T4B_GRAMMARS: Dict[str, Dict[str, List[List[str]]]] = {
    "json": {
        "value": [["object"], ["array"], ["string"], ["number"], ["bool"], ["null"]],
        "object": [["{", "pairs", "}"], ["{", "}"]],
        "pairs": [["pair"], ["pair", ",", "pairs"]],
        "pair": [["string", ":", "value"]],
        "array": [["[", "values", "]"], ["[", "]"]],
        "values": [["value"], ["value", ",", "values"]],
        "string": [['"abc"'], ['""'], ['"' + "A"*1000 + '"']],
        "number": [["0"], ["-1"], ["1.5e308"], ["NaN"]],
        "bool": [["true"], ["false"]],
        "null": [["null"]],
    },
    "url_path": {
        "path": [["/", "segs"]],
        "segs": [["seg"], ["seg", "/", "segs"]],
        "seg": [["a"], ["1"], [".."], ["%2e%2e"], [""], ["a%00b"]],
    },
    "sql_where": {
        "expr": [["col", "op", "val"], ["expr", "logop", "expr"], ["(", "expr", ")"]],
        "col": [["id"], ["name"], ["1"]],
        "op": [["="], ["<"], ["LIKE"], ["IN"]],
        "val": [["1"], ["'a'"], ["NULL"], ["(SELECT 1)"]],
        "logop": [["AND"], ["OR"]],
    },
}


@dataclass
class _T4BFuzzCase:
    strategy: str
    param: str
    payload: Any
    seed_value: Any = None
    rationale: str = ""


# ---- Strategy: mutation -------------------------------------------------
def _t4b_fuzz_mutate_value(value: Any, n: int = 5) -> List[Any]:
    """Bit-flip / byte-swap / char-insert / truncate / repeat-section."""
    out: List[Any] = []
    if value is None:
        return [0, "", [], {}, "null"]
    if isinstance(value, bool):
        return [not value, 0, 1, "true", None]
    if isinstance(value, (int, float)):
        v = value
        out.extend([v + 1, v - 1, v * -1, v * 2, 0, str(v), v + 1e6, v / 2 if v else 1])
        return out[:n]
    if isinstance(value, str):
        if not value:
            return ["A", "0", " ", "\x00", "<x>"]
        s = value
        # bit flip on first char
        out.append(chr(ord(s[0]) ^ 0xFF) + s[1:])
        # truncate
        out.append(s[:max(1, len(s)//2)])
        # extend
        out.append(s + s)
        # uppercase
        out.append(s.upper())
        # null injection
        out.append(s + "\x00")
        # quote injection
        out.append(s + "'\"`")
        return out[:n]
    if isinstance(value, list):
        return [[], value * 2, list(reversed(value)), value + [None]]
    if isinstance(value, dict):
        return [{}, dict(value, **{"_x": "fuzz"}), {k: None for k in value}]
    return [str(value), repr(value), None]


def _t4b_fuzz_strategy_mutation(self, params: Dict[str, Any], cases_per_param: int = 5) -> List[_T4BFuzzCase]:
    out: List[_T4BFuzzCase] = []
    for k, v in params.items():
        for mutated in _t4b_fuzz_mutate_value(v, cases_per_param):
            out.append(_T4BFuzzCase("mutation", k, mutated, seed_value=v,
                                          rationale="mutated_seed"))
    return out


# ---- Strategy: random --------------------------------------------------
def _t4b_fuzz_random_value(rng: _t4b_rand.Random, max_len: int = 64) -> Any:
    kind = rng.choice(["str", "int", "float", "bool", "null", "list", "dict", "binary"])
    if kind == "str":
        ln = rng.randint(0, max_len)
        return "".join(rng.choice(_t4b_str.printable) for _ in range(ln))
    if kind == "int":
        return rng.randint(-2**63, 2**63 - 1)
    if kind == "float":
        return rng.uniform(-1e10, 1e10)
    if kind == "bool":
        return rng.choice([True, False])
    if kind == "null":
        return None
    if kind == "list":
        return [_t4b_fuzz_random_value(rng, 16) for _ in range(rng.randint(0, 5))]
    if kind == "dict":
        return {"k": _t4b_fuzz_random_value(rng, 16) for _ in range(rng.randint(0, 3))}
    return "".join(chr(rng.randint(0, 255)) for _ in range(rng.randint(0, 32)))


def _t4b_fuzz_strategy_random(self, params: Dict[str, Any],
                                    cases_per_param: int = 10,
                                    seed: Optional[int] = None) -> List[_T4BFuzzCase]:
    rng = _t4b_rand.Random(seed)
    out: List[_T4BFuzzCase] = []
    for k in params:
        for _ in range(cases_per_param):
            out.append(_T4BFuzzCase("random", k, _t4b_fuzz_random_value(rng),
                                          rationale="random_typed"))
    return out


# ---- Strategy: boundary ------------------------------------------------
def _t4b_fuzz_strategy_boundary(self, params: Dict[str, Any]) -> List[_T4BFuzzCase]:
    out: List[_T4BFuzzCase] = []
    for k, v in params.items():
        if isinstance(v, bool):
            for b in [True, False, 0, 1, "true", "false"]:
                out.append(_T4BFuzzCase("boundary", k, b, seed_value=v, rationale="boundary_bool"))
        elif isinstance(v, int):
            for b in _T4B_BOUNDARY_INT:
                out.append(_T4BFuzzCase("boundary", k, b, seed_value=v, rationale="boundary_int"))
        elif isinstance(v, float):
            for b in _T4B_BOUNDARY_FLOAT:
                out.append(_T4BFuzzCase("boundary", k, b, seed_value=v, rationale="boundary_float"))
        else:
            for b in _T4B_BOUNDARY_STR:
                out.append(_T4BFuzzCase("boundary", k, b, seed_value=v, rationale="boundary_str"))
    return out


# ---- Strategy: dictionary ----------------------------------------------
def _t4b_fuzz_strategy_dictionary(self, params: Dict[str, Any],
                                          extra: Optional[List[str]] = None) -> List[_T4BFuzzCase]:
    payloads = list(_T4B_DICT_PAYLOADS)
    if extra:
        payloads.extend(extra)
    out: List[_T4BFuzzCase] = []
    for k in params:
        for p in payloads:
            out.append(_T4BFuzzCase("dictionary", k, p, seed_value=params[k],
                                          rationale="known_attack_payload"))
    return out


# ---- Strategy: grammar -------------------------------------------------
def _t4b_fuzz_grammar_generate(grammar: Dict[str, List[List[str]]],
                                     start: str, max_depth: int = 6,
                                     rng: Optional[_t4b_rand.Random] = None) -> str:
    rng = rng or _t4b_rand.Random()
    def expand(sym: str, depth: int) -> str:
        if depth <= 0 or sym not in grammar:
            return sym
        prods = grammar[sym]
        prod = rng.choice(prods)
        return "".join(expand(s, depth - 1) for s in prod)
    return expand(start, max_depth)


def _t4b_fuzz_strategy_grammar(self, params: Dict[str, Any],
                                      grammar_name: str = "json",
                                      cases_per_param: int = 10,
                                      seed: Optional[int] = None) -> List[_T4BFuzzCase]:
    grammar = _T4B_GRAMMARS.get(grammar_name)
    if not grammar:
        return []
    start = next(iter(grammar))
    rng = _t4b_rand.Random(seed)
    out: List[_T4BFuzzCase] = []
    for k in params:
        for _ in range(cases_per_param):
            payload = _t4b_fuzz_grammar_generate(grammar, start, max_depth=6, rng=rng)
            out.append(_T4BFuzzCase("grammar", k, payload, seed_value=params[k],
                                          rationale=f"grammar:{grammar_name}"))
    return out


# ---- Strategy dispatch + executor ---------------------------------------
def _t4b_fuzz_supported_strategies(self) -> List[str]:
    return list(_T4B_FUZZ_STRATEGIES)


def _t4b_fuzz_generate_cases(self, params: Dict[str, Any],
                                   strategies: Optional[List[str]] = None,
                                   cases_per_strategy: int = 5) -> List[_T4BFuzzCase]:
    strats = strategies or list(_T4B_FUZZ_STRATEGIES)
    out: List[_T4BFuzzCase] = []
    if "mutation" in strats:
        out.extend(_t4b_fuzz_strategy_mutation(self, params, cases_per_strategy))
    if "random" in strats:
        out.extend(_t4b_fuzz_strategy_random(self, params, cases_per_strategy))
    if "boundary" in strats:
        out.extend(_t4b_fuzz_strategy_boundary(self, params))
    if "dictionary" in strats:
        out.extend(_t4b_fuzz_strategy_dictionary(self, params))
    if "grammar" in strats:
        out.extend(_t4b_fuzz_strategy_grammar(self, params, "json", cases_per_strategy))
    return out


def _t4b_fuzz_send_case(url: str, method: str, case: _T4BFuzzCase,
                            base_params: Dict[str, Any],
                            timeout: float = 8.0) -> Dict[str, Any]:
    p = dict(base_params)
    p[case.param] = case.payload
    t0 = _t4b_time.time()
    try:
        if method.upper() == "GET":
            full = url + ("&" if "?" in url else "?") + _t4b_up.urlencode(
                {k: ("" if v is None else str(v)) for k, v in p.items()})
            req = _t4b_ur.Request(full, headers={"User-Agent": "CaseCrack-Fuzz/1.0"})
        else:
            data = _t4b_json.dumps(p, default=str).encode()
            req = _t4b_ur.Request(url, data=data, method=method.upper(),
                                       headers={"User-Agent": "CaseCrack-Fuzz/1.0",
                                                  "Content-Type": "application/json"})
        with _t4b_ur.urlopen(req, timeout=timeout) as resp:
            body = resp.read(64 * 1024)
            return {"ok": True, "status": resp.status, "duration_s": round(_t4b_time.time()-t0, 3),
                      "body_len": len(body), "body_sample": body[:512].decode("utf-8", "ignore"),
                      "case": {"strategy": case.strategy, "param": case.param,
                                  "payload_repr": repr(case.payload)[:120]}}
    except _t4b_uerr.HTTPError as e:
        return {"ok": False, "status": e.code, "duration_s": round(_t4b_time.time()-t0, 3),
                  "case": {"strategy": case.strategy, "param": case.param,
                              "payload_repr": repr(case.payload)[:120]},
                  "error": "http_error"}
    except Exception as e:
        return {"ok": False, "status": 0, "duration_s": round(_t4b_time.time()-t0, 3),
                  "case": {"strategy": case.strategy, "param": case.param,
                              "payload_repr": repr(case.payload)[:120]},
                  "error": f"{type(e).__name__}: {e}"}


def _t4b_fuzz_run(self, url: str, method: str, base_params: Dict[str, Any],
                       strategies: Optional[List[str]] = None,
                       cases_per_strategy: int = 5,
                       max_cases: int = 200,
                       timeout: float = 8.0) -> Dict[str, Any]:
    cases = _t4b_fuzz_generate_cases(self, base_params, strategies, cases_per_strategy)
    cases = cases[:max_cases]
    results: List[Dict[str, Any]] = []
    anomalies: List[Dict[str, Any]] = []
    by_strategy: Dict[str, int] = {}
    by_status: Dict[int, int] = {}
    t0 = _t4b_time.time()
    for c in cases:
        r = _t4b_fuzz_send_case(url, method, c, base_params, timeout)
        results.append(r)
        by_strategy[c.strategy] = by_strategy.get(c.strategy, 0) + 1
        st = r.get("status", 0)
        by_status[st] = by_status.get(st, 0) + 1
        # anomaly: 5xx or unusually slow or large body
        if st >= 500 or r.get("duration_s", 0) > timeout * 0.9 or r.get("body_len", 0) > 10000:
            anomalies.append(r)
    return {"ok": True, "url": url, "method": method,
              "cases_sent": len(results), "duration_s": round(_t4b_time.time()-t0, 3),
              "by_strategy": by_strategy, "by_status": by_status,
              "anomalies": anomalies, "anomaly_count": len(anomalies),
              "results_sample": results[:20]}


def _t4b_fuzz_register_payload(self, payload: str) -> bool:
    """Allow runtime addition to dictionary payload list."""
    if payload not in _T4B_DICT_PAYLOADS:
        _T4B_DICT_PAYLOADS.append(payload)
        return True
    return False


# --- Bind to ApiFuzzer --------------------------------------------------
try:
    ApiFuzzer.supported_strategies = _t4b_fuzz_supported_strategies  # type: ignore[name-defined]
    ApiFuzzer.fuzz_strategy_mutation = _t4b_fuzz_strategy_mutation  # type: ignore[name-defined]
    ApiFuzzer.fuzz_strategy_random = _t4b_fuzz_strategy_random  # type: ignore[name-defined]
    ApiFuzzer.fuzz_strategy_boundary = _t4b_fuzz_strategy_boundary  # type: ignore[name-defined]
    ApiFuzzer.fuzz_strategy_dictionary = _t4b_fuzz_strategy_dictionary  # type: ignore[name-defined]
    ApiFuzzer.fuzz_strategy_grammar = _t4b_fuzz_strategy_grammar  # type: ignore[name-defined]
    ApiFuzzer.generate_fuzz_cases = _t4b_fuzz_generate_cases  # type: ignore[name-defined]
    ApiFuzzer.run_fuzz_campaign = _t4b_fuzz_run  # type: ignore[name-defined]
    ApiFuzzer.register_dictionary_payload = _t4b_fuzz_register_payload  # type: ignore[name-defined]
except NameError:
    pass
