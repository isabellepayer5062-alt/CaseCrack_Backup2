# __TIER4B_TESTING__
# Tier 4B Testing — compliance_validator: rule DSL engine
import re as _t4b_re
import json as _t4b_json
import operator as _t4b_op
import time as _t4b_time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field

# DSL operators
_T4B_DSL_OPS: Dict[str, Callable[[Any, Any], bool]] = {
    "==": _t4b_op.eq, "!=": _t4b_op.ne,
    ">": _t4b_op.gt, ">=": _t4b_op.ge,
    "<": _t4b_op.lt, "<=": _t4b_op.le,
    "in": lambda a, b: a in (b or []),
    "not_in": lambda a, b: a not in (b or []),
    "contains": lambda a, b: (b in a) if a is not None else False,
    "not_contains": lambda a, b: (b not in a) if a is not None else True,
    "matches": lambda a, b: bool(_t4b_re.search(b, str(a or ""))),
    "not_matches": lambda a, b: not bool(_t4b_re.search(b, str(a or ""))),
    "exists": lambda a, b: a is not None if b else a is None,
    "is_empty": lambda a, b: (not a) if b else bool(a),
    "len_eq": lambda a, b: len(a or []) == b,
    "len_gt": lambda a, b: len(a or []) > b,
    "len_lt": lambda a, b: len(a or []) < b,
    "starts_with": lambda a, b: str(a or "").startswith(b),
    "ends_with": lambda a, b: str(a or "").endswith(b),
}


@dataclass
class _T4BDslRule:
    rule_id: str
    description: str
    severity: str
    when: List[Dict[str, Any]]   # field+op+value clauses (AND)
    any_of: Optional[List[Dict[str, Any]]] = None  # OR group
    require: Optional[List[Dict[str, Any]]] = None  # additional AND clauses
    framework: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    remediation: Optional[str] = None


def _t4b_dsl_resolve_field(data: Dict[str, Any], path: str) -> Any:
    """Dotted-path resolver: 'a.b.c' or 'a.0.b' for list indexing."""
    cur: Any = data
    for part in path.split("."):
        if cur is None:
            return None
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            try:
                cur = getattr(cur, part)
            except AttributeError:
                return None
    return cur


def _t4b_dsl_eval_clause(clause: Dict[str, Any], data: Dict[str, Any]) -> bool:
    """Evaluate one clause: {'field': 'a.b', 'op': '==', 'value': 'x'}."""
    field_path = clause.get("field")
    op_name = clause.get("op")
    value = clause.get("value")
    op_fn = _T4B_DSL_OPS.get(op_name)
    if not op_fn or not field_path:
        return False
    actual = _t4b_dsl_resolve_field(data, field_path)
    try:
        return bool(op_fn(actual, value))
    except Exception:
        return False


def _t4b_dsl_eval_rule(rule: Union[_T4BDslRule, Dict[str, Any]],
                            data: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluate a rule against a data record. Returns match info."""
    if isinstance(rule, dict):
        rid = rule.get("rule_id", "anon")
        when = rule.get("when") or []
        any_of = rule.get("any_of")
        require = rule.get("require")
        sev = rule.get("severity", "medium")
        desc = rule.get("description", "")
        rem = rule.get("remediation")
    else:
        rid = rule.rule_id
        when = rule.when
        any_of = rule.any_of
        require = rule.require
        sev = rule.severity
        desc = rule.description
        rem = rule.remediation

    matched_clauses: List[str] = []
    failed_clauses: List[str] = []

    # AND: all 'when' must match
    for c in when:
        ok = _t4b_dsl_eval_clause(c, data)
        sig = f"{c.get('field')} {c.get('op')} {c.get('value')!r}"
        (matched_clauses if ok else failed_clauses).append(sig)
    when_pass = (not failed_clauses) and bool(when)

    # OR: at least one of any_of must match (if specified)
    any_pass = True
    if any_of:
        any_pass = False
        for c in any_of:
            if _t4b_dsl_eval_clause(c, data):
                any_pass = True
                matched_clauses.append(f"any: {c.get('field')} {c.get('op')} {c.get('value')!r}")
                break

    # Additional require clauses (AND, but only matter if when matched)
    require_pass = True
    if require:
        for c in require:
            if not _t4b_dsl_eval_clause(c, data):
                require_pass = False
                failed_clauses.append(f"require: {c.get('field')} {c.get('op')} {c.get('value')!r}")
                break

    matched = when_pass and any_pass and require_pass
    return {
        "rule_id": rid,
        "matched": matched,
        "severity": sev,
        "description": desc,
        "remediation": rem,
        "matched_clauses": matched_clauses,
        "failed_clauses": failed_clauses,
    }


def _t4b_dsl_load_rules(self, rules_data: Union[List[Dict[str, Any]], str]) -> Dict[str, Any]:
    """Load rules from list-of-dicts or JSON string."""
    if isinstance(rules_data, str):
        try:
            rules_data = _t4b_json.loads(rules_data)
        except Exception as e:
            return {"ok": False, "error": f"json_parse: {e}"}
    if not isinstance(rules_data, list):
        return {"ok": False, "error": "expected_list"}
    parsed: List[_T4BDslRule] = []
    errors: List[str] = []
    for i, r in enumerate(rules_data):
        if not isinstance(r, dict) or "rule_id" not in r:
            errors.append(f"rule[{i}]: missing rule_id")
            continue
        if "when" not in r and "any_of" not in r:
            errors.append(f"rule[{i}]: missing when/any_of")
            continue
        try:
            parsed.append(_T4BDslRule(
                rule_id=r["rule_id"], description=r.get("description", ""),
                severity=r.get("severity", "medium"),
                when=r.get("when", []), any_of=r.get("any_of"),
                require=r.get("require"), framework=r.get("framework"),
                tags=r.get("tags", []), remediation=r.get("remediation"),
            ))
        except Exception as e:
            errors.append(f"rule[{i}]: {type(e).__name__}: {e}")
    setattr(self, "_t4b_dsl_rules", parsed)
    return {"ok": True, "loaded": len(parsed), "errors": errors}


def _t4b_dsl_loaded_rules(self) -> List[Dict[str, Any]]:
    rules = getattr(self, "_t4b_dsl_rules", [])
    return [{"rule_id": r.rule_id, "severity": r.severity,
              "framework": r.framework, "tags": r.tags,
              "description": r.description} for r in rules]


def _t4b_dsl_validate_record(self, record: Dict[str, Any],
                                    rule_filter: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Run all loaded rules against a single record."""
    rules: List[_T4BDslRule] = getattr(self, "_t4b_dsl_rules", [])
    out: List[Dict[str, Any]] = []
    for r in rules:
        if rule_filter:
            if rule_filter.get("framework") and r.framework != rule_filter["framework"]:
                continue
            if rule_filter.get("severity") and r.severity != rule_filter["severity"]:
                continue
            if rule_filter.get("tag") and rule_filter["tag"] not in r.tags:
                continue
        res = _t4b_dsl_eval_rule(r, record)
        if res["matched"]:
            out.append(res)
    return out


def _t4b_dsl_validate_batch(self, records: List[Dict[str, Any]],
                                  rule_filter: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Validate a batch of records, return per-record + aggregate findings."""
    by_record: List[Dict[str, Any]] = []
    aggregate: Dict[str, int] = {}
    sev_count: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for i, rec in enumerate(records):
        matches = _t4b_dsl_validate_record(self, rec, rule_filter)
        by_record.append({"record_index": i, "matches": matches, "match_count": len(matches)})
        for m in matches:
            aggregate[m["rule_id"]] = aggregate.get(m["rule_id"], 0) + 1
            sev = m.get("severity", "medium")
            sev_count[sev] = sev_count.get(sev, 0) + 1
    return {
        "records_evaluated": len(records),
        "rules_loaded": len(getattr(self, "_t4b_dsl_rules", [])),
        "total_matches": sum(r["match_count"] for r in by_record),
        "by_rule_id": aggregate,
        "by_severity": sev_count,
        "by_record": by_record,
    }


def _t4b_dsl_register_operator(self, op_name: str, op_fn: Callable[[Any, Any], bool]) -> bool:
    """Allow plugging in custom DSL operators."""
    if op_name in _T4B_DSL_OPS:
        return False
    _T4B_DSL_OPS[op_name] = op_fn
    return True


def _t4b_dsl_supported_operators(self) -> List[str]:
    return sorted(_T4B_DSL_OPS.keys())


def _t4b_dsl_export_rules_json(self) -> str:
    rules: List[_T4BDslRule] = getattr(self, "_t4b_dsl_rules", [])
    return _t4b_json.dumps([{
        "rule_id": r.rule_id, "description": r.description,
        "severity": r.severity, "when": r.when, "any_of": r.any_of,
        "require": r.require, "framework": r.framework,
        "tags": r.tags, "remediation": r.remediation,
    } for r in rules], indent=2, default=str)


def _t4b_dsl_explain_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
    rules: List[_T4BDslRule] = getattr(self, "_t4b_dsl_rules", [])
    for r in rules:
        if r.rule_id == rule_id:
            return {
                "rule_id": r.rule_id,
                "description": r.description,
                "severity": r.severity,
                "framework": r.framework,
                "tags": r.tags,
                "remediation": r.remediation,
                "logic": {
                    "all_must_match": r.when,
                    "at_least_one_of": r.any_of,
                    "must_also_match": r.require,
                },
            }
    return None


def _t4b_dsl_test_rule(self, rule: Dict[str, Any], record: Dict[str, Any]) -> Dict[str, Any]:
    """Test an ad-hoc rule against a record without loading it."""
    return _t4b_dsl_eval_rule(rule, record)


# --- Bind to ComplianceValidator ----------------------------------------
try:
    ComplianceValidator.dsl_load_rules = _t4b_dsl_load_rules  # type: ignore[name-defined]
    ComplianceValidator.dsl_loaded_rules = _t4b_dsl_loaded_rules  # type: ignore[name-defined]
    ComplianceValidator.dsl_validate_record = _t4b_dsl_validate_record  # type: ignore[name-defined]
    ComplianceValidator.dsl_validate_batch = _t4b_dsl_validate_batch  # type: ignore[name-defined]
    ComplianceValidator.dsl_register_operator = _t4b_dsl_register_operator  # type: ignore[name-defined]
    ComplianceValidator.dsl_supported_operators = _t4b_dsl_supported_operators  # type: ignore[name-defined]
    ComplianceValidator.dsl_export_rules_json = _t4b_dsl_export_rules_json  # type: ignore[name-defined]
    ComplianceValidator.dsl_explain_rule = _t4b_dsl_explain_rule  # type: ignore[name-defined]
    ComplianceValidator.dsl_test_rule = _t4b_dsl_test_rule  # type: ignore[name-defined]
except NameError:
    pass
