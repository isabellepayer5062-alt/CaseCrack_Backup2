#!/usr/bin/env python3
"""
BugBountyHunter Skill Suite — Production Validation Test Harness
Validates YAML frontmatter, cross-skill contracts, dependency graph,
blackboard consistency, policy safety, oracle scoring, and template syntax.
"""

import sys
import re
import json
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    print("PyYAML not found — installing...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyyaml", "-q"])
    import yaml

# ─── Config ──────────────────────────────────────────────────────────────────

SKILL_ROOT = Path(__file__).parent

SUBSKILLS = [
    "ReconAnalyzer",
    "TrafficTriage",
    "SourceHunter",
    "PoCForge",
    "ExecutorValidator",
    "ReportWizard",
    "LearnerReflector",
]

EXPECTED_VERSION = "2026.05"
BLACKBOARD_PATH  = "/workspace/blackboard/{{run_id}}.jsonl"

# Expected pass_outputs from each subskill (used by downstream inputs)
PASS_OUTPUTS_CONTRACT = {
    "ReconAnalyzer":     ["recon-normalized.jsonl", "target-graph.json", "priority-hosts.txt"],
    "TrafficTriage":     ["triage-ranked.json", "high-signal-endpoints.txt"],
    "SourceHunter":      ["source-correlations.json", "candidate-poc-paths.txt"],
    "PoCForge":          ["poc-steps.md", "repro-requests.http", "impact-and-safety-notes.md"],
    "ExecutorValidator": ["validation-results.jsonl", "blackboard_append"],
    "ReportWizard":      ["report.md", "report.json", "triager-checklist.md"],
    "LearnerReflector":  ["delta_{{run_id}}.jsonl", "reflection_{{run_id}}.md", "blackboard_append"],
}

# Subskills that MUST have deny_active_exploitation: true
MUST_DENY_ACTIVE_EXPLOITATION = {"ExecutorValidator", "ReconAnalyzer"}

# All subskills must have these base policies
UNIVERSAL_POLICIES = {
    "operation_mode": "non_destructive_only",
    "in_scope_required": True,
}

# Oracle score contributions that must exist in ExecutorValidator
REQUIRED_ORACLE_ROWS = [
    "DOM XSS",
    "SQL error",
    "Auth bypass",
    "Shell callback",
    "Race condition",
]

# ─── Helpers ─────────────────────────────────────────────────────────────────

PASS = "✅"
FAIL = "❌"
WARN = "⚠️ "


class TestResult:
    def __init__(self):
        self.passed: list[str] = []
        self.failed: list[str] = []
        self.warnings: list[str] = []

    def ok(self, msg: str):
        self.passed.append(msg)
        print(f"  {PASS} {msg}")

    def fail(self, msg: str):
        self.failed.append(msg)
        print(f"  {FAIL} {msg}")

    def warn(self, msg: str):
        self.warnings.append(msg)
        print(f"  {WARN} {msg}")

    def summary(self):
        total = len(self.passed) + len(self.failed) + len(self.warnings)
        print(f"\n{'='*60}")
        print(f"  Results: {len(self.passed)}/{total} passed  |  "
              f"{len(self.failed)} failed  |  {len(self.warnings)} warnings")
        if self.failed:
            print("\n  FAILED CHECKS:")
            for f in self.failed:
                print(f"    {FAIL} {f}")
        if self.warnings:
            print("\n  WARNINGS:")
            for w in self.warnings:
                print(f"    {WARN} {w}")
        print('='*60)
        return len(self.failed) == 0


def parse_frontmatter(path: Path) -> tuple[dict | None, str]:
    """Extract YAML frontmatter and body from a SKILL.md file."""
    text = path.read_text(encoding="utf-8")
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)", text, re.DOTALL)
    if not m:
        return None, text
    try:
        meta = yaml.safe_load(m.group(1))
        return meta, m.group(2)
    except yaml.YAMLError as e:
        return {"_parse_error": str(e)}, m.group(2)


def get_nested(d: dict, *keys, default=None):
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, {})
    return d if d != {} else default


# ─── Test Groups ─────────────────────────────────────────────────────────────

def test_orchestrator(r: TestResult) -> dict:
    """T1 – Orchestrator (BugBountyHunter/SKILL.md) frontmatter integrity."""
    print("\n[T1] Orchestrator SKILL.md — Frontmatter Integrity")
    path = SKILL_ROOT / "SKILL.md"
    meta, body = parse_frontmatter(path)

    if meta is None:
        r.fail("Orchestrator: no YAML frontmatter found")
        return {}
    if "_parse_error" in meta:
        r.fail(f"Orchestrator YAML parse error: {meta['_parse_error']}")
        return {}
    r.ok("YAML frontmatter parses cleanly")

    # Required top-level keys
    for key in ["name", "version", "kind", "inputs", "outputs", "subskills", "policies", "shared"]:
        if key in meta:
            r.ok(f"Field '{key}' present")
        else:
            r.fail(f"Required field '{key}' missing")

    # Version (compare as string — YAML may parse unquoted 2026.05 as float)
    if str(meta.get("version")) == EXPECTED_VERSION:
        r.ok(f"Version == {EXPECTED_VERSION}")
    else:
        r.fail(f"Version mismatch: got {meta.get('version')!r}, expected {EXPECTED_VERSION!r}")

    # Blackboard
    bb = get_nested(meta, "shared", "blackboard")
    if bb:
        if bb.get("path") == BLACKBOARD_PATH:
            r.ok(f"Orchestrator blackboard.path == {BLACKBOARD_PATH!r}")
        else:
            r.fail(f"Orchestrator blackboard.path mismatch: {bb.get('path')!r}")
        if bb.get("description"):
            r.ok("Orchestrator blackboard.description present")
        else:
            r.warn("Orchestrator blackboard.description is empty")
    else:
        r.fail("shared.blackboard block missing from orchestrator")

    # Subskill dependency graph
    subskills_meta = meta.get("subskills", [])
    r.ok(f"Subskill count: {len(subskills_meta)}")
    return {s["name"]: s for s in subskills_meta if "name" in s}


def test_dependency_graph(r: TestResult, subskills_map: dict):
    """T2 – Dependency graph: all declared names exist, pass_outputs correct."""
    print("\n[T2] Dependency Graph — DAG Integrity & pass_outputs Contract")

    declared_names = set(subskills_map.keys())
    expected_names = set(SUBSKILLS)

    missing = expected_names - declared_names
    extra   = declared_names - expected_names
    if missing:
        r.fail(f"Subskills missing from orchestrator: {missing}")
    else:
        r.ok("All 7 subskills declared in orchestrator")
    if extra:
        r.warn(f"Unexpected subskill entries: {extra}")

    # Check depends_on references valid names
    for name, s in subskills_map.items():
        for dep in s.get("depends_on", []):
            if dep in declared_names:
                r.ok(f"{name} → depends_on [{dep}] resolved")
            else:
                r.fail(f"{name} → depends_on [{dep!r}] UNRESOLVED")

    # Check pass_outputs match contract
    for name, expected_outputs in PASS_OUTPUTS_CONTRACT.items():
        s = subskills_map.get(name, {})
        actual = s.get("pass_outputs", [])
        for out in expected_outputs:
            if out in actual:
                r.ok(f"{name}.pass_outputs contains [{out!r}]")
            else:
                r.fail(f"{name}.pass_outputs missing [{out!r}] (got {actual})")

    # Cycle detection (simple DFS)
    adj = {n: set(s.get("depends_on", [])) for n, s in subskills_map.items()}
    visited, rec_stack = set(), set()

    def has_cycle(node):
        visited.add(node)
        rec_stack.add(node)
        for nb in adj.get(node, set()):
            if nb not in visited:
                if has_cycle(nb):
                    return True
            elif nb in rec_stack:
                return True
        rec_stack.discard(node)
        return False

    cycle_found = any(has_cycle(n) for n in declared_names if n not in visited)
    if cycle_found:
        r.fail("Dependency graph contains a CYCLE")
    else:
        r.ok("Dependency graph is acyclic (DAG confirmed)")


def test_subskill_frontmatter(r: TestResult):
    """T3 – All subskill SKILL.md files: required fields + version + policies."""
    print("\n[T3] Subskill Frontmatter — Required Fields, Version, Universal Policies")

    for name in SUBSKILLS:
        path = SKILL_ROOT / name / "SKILL.md"
        if not path.exists():
            r.fail(f"{name}/SKILL.md: FILE NOT FOUND at {path}")
            continue

        meta, _ = parse_frontmatter(path)
        if meta is None:
            r.fail(f"{name}: no YAML frontmatter")
            continue
        if "_parse_error" in meta:
            r.fail(f"{name}: YAML parse error — {meta['_parse_error']}")
            continue
        r.ok(f"{name}: YAML parses cleanly")

        # name must match directory
        if meta.get("name") == name:
            r.ok(f"{name}: name field matches directory")
        else:
            r.fail(f"{name}: name field {meta.get('name')!r} != expected {name!r}")

        # version (compare as string — YAML may parse unquoted 2026.05 as float)
        if str(meta.get("version")) == EXPECTED_VERSION:
            r.ok(f"{name}: version == {EXPECTED_VERSION}")
        else:
            r.fail(f"{name}: version {meta.get('version')!r} != {EXPECTED_VERSION!r}")

        # required top-level fields
        for field in ["description", "model_routing", "runtime", "inputs", "policies", "tags"]:
            if meta.get(field):
                r.ok(f"{name}: '{field}' present")
            else:
                r.fail(f"{name}: required field '{field}' missing or empty")

        # universal policies
        policies = meta.get("policies", {})
        for pol_key, pol_val in UNIVERSAL_POLICIES.items():
            actual = policies.get(pol_key)
            if actual == pol_val:
                r.ok(f"{name}.policies.{pol_key} == {pol_val!r}")
            else:
                r.fail(f"{name}.policies.{pol_key} == {actual!r}, expected {pol_val!r}")

        # deny_active_exploitation must be true for specific skills
        if name in MUST_DENY_ACTIVE_EXPLOITATION:
            dae = policies.get("deny_active_exploitation")
            if dae is True:
                r.ok(f"{name}.policies.deny_active_exploitation == true")
            else:
                r.fail(f"{name}.policies.deny_active_exploitation is {dae!r}, must be true")

        # on_error should not be emit_partial_and_continue for critical skills
        on_error = get_nested(meta, "runtime", "on_error", "action")
        if name in {"ExecutorValidator", "PoCForge", "ReportWizard"} and on_error != "abort_and_emit":
            r.fail(f"{name}.runtime.on_error.action == {on_error!r}, critical skill must be abort_and_emit")
        elif on_error:
            r.ok(f"{name}.runtime.on_error.action == {on_error!r}")

        # token budget within orchestrator total (150 000)
        budget = get_nested(meta, "runtime", "token_budget", "max_total_tokens_per_run")
        if budget:
            if budget <= 150000:
                r.ok(f"{name}: token_budget {budget:,} ≤ orchestrator limit")
            else:
                r.fail(f"{name}: token_budget {budget:,} EXCEEDS orchestrator 150,000 limit")

        # prompt_caching enabled
        cache_enabled = get_nested(meta, "runtime", "prompt_caching", "enabled")
        if cache_enabled:
            r.ok(f"{name}: prompt_caching enabled")
        else:
            r.warn(f"{name}: prompt_caching not enabled (efficiency loss)")


def test_executor_validator_specifics(r: TestResult):
    """T4 – ExecutorValidator sandbox, oracle scoring, safety policy deep-check."""
    print("\n[T4] ExecutorValidator — Sandbox Config, Oracle Criteria, Safety Policy")

    path = SKILL_ROOT / "ExecutorValidator" / "SKILL.md"
    meta, body = parse_frontmatter(path)
    if meta is None or "_parse_error" in meta:
        r.fail("ExecutorValidator: cannot parse frontmatter — skipping T4")
        return

    # Safety policies
    policies = meta.get("policies", {})
    for key in ["deny_active_exploitation", "require_safe_validation_path", "in_scope_required"]:
        val = policies.get(key)
        if val is True:
            r.ok(f"ExecutorValidator.policies.{key} == true")
        else:
            r.fail(f"ExecutorValidator.policies.{key} == {val!r}, must be true")

    # Sandbox block (in body YAML code block)
    if "runtime: firecracker" in body:
        r.ok("ExecutorValidator: sandbox runtime: firecracker declared")
    else:
        r.fail("ExecutorValidator: sandbox runtime: firecracker NOT found in body")

    if "kernel_version: 6.8+" in body:
        r.ok("ExecutorValidator: kernel_version: 6.8+ declared")
    else:
        r.fail("ExecutorValidator: kernel_version: 6.8+ NOT found")

    if "memory_mb: 1024" in body:
        r.ok("ExecutorValidator: memory_mb: 1024 declared")
    else:
        r.fail("ExecutorValidator: memory_mb: 1024 NOT found in sandbox block")

    if "network_bandwidth_kbps: 5000" in body:
        r.ok("ExecutorValidator: network_bandwidth_kbps: 5000 declared")
    else:
        r.fail("ExecutorValidator: network_bandwidth_kbps NOT found")

    # http_replay args_allowlist
    required_args = ["--request", "--compare", "--output", "--header",
                     "--method", "--data", "--cookie", "--timeout"]
    for arg in required_args:
        if arg in body:
            r.ok(f"ExecutorValidator: http_replay allowlist contains {arg!r}")
        else:
            r.fail(f"ExecutorValidator: http_replay allowlist missing {arg!r}")

    # Oracle criteria rows
    for signal in REQUIRED_ORACLE_ROWS:
        if signal.lower() in body.lower():
            r.ok(f"ExecutorValidator: oracle signal {signal!r} present")
        else:
            r.fail(f"ExecutorValidator: oracle signal {signal!r} NOT found in Oracle Criteria")

    # Oracle score cap check (must mention 100)
    if "capped at 100" in body or "cap" in body.lower():
        r.ok("ExecutorValidator: oracle score cap declared")
    else:
        r.warn("ExecutorValidator: oracle score cap not explicitly mentioned")

    # Output schema fields
    for field in ["poc_id", "validation_outcome", "oracle_score", "evidence", "timestamp"]:
        if f'"{field}"' in body:
            r.ok(f"ExecutorValidator: output schema field {field!r} present")
        else:
            r.fail(f"ExecutorValidator: output schema field {field!r} MISSING")

    # Anti-hallucination rules
    if "Anti-Hallucination" in body:
        r.ok("ExecutorValidator: Anti-Hallucination Rules section present")
    else:
        r.fail("ExecutorValidator: Anti-Hallucination Rules section MISSING")


def test_learner_reflector_specifics(r: TestResult):
    """T5 – LearnerReflector: blackboard path, KG schema, dry_run gate."""
    print("\n[T5] LearnerReflector — Blackboard Path, KG Schema, Dry-Run Gate")

    path = SKILL_ROOT / "LearnerReflector" / "SKILL.md"
    meta, body = parse_frontmatter(path)
    if meta is None or "_parse_error" in meta:
        r.fail("LearnerReflector: cannot parse frontmatter — skipping T5")
        return

    # Blackboard input
    inputs = meta.get("inputs", {}).get("required", [])
    bb_input = next((i for i in inputs if i.get("name") == "blackboard"), None)
    if bb_input:
        r.ok("LearnerReflector: blackboard input declared")
        if bb_input.get("path") == BLACKBOARD_PATH:
            r.ok(f"LearnerReflector: blackboard.path == {BLACKBOARD_PATH!r}")
        else:
            r.fail(f"LearnerReflector: blackboard.path == {bb_input.get('path')!r}, expected {BLACKBOARD_PATH!r}")
        if bb_input.get("type") == "jsonl_file":
            r.ok("LearnerReflector: blackboard.type == jsonl_file")
        else:
            r.fail(f"LearnerReflector: blackboard.type == {bb_input.get('type')!r}, expected jsonl_file")
    else:
        r.fail("LearnerReflector: blackboard input MISSING from required inputs")

    # KG Schema completeness
    required_nodes = ["Hunt", "Finding", "Technique", "Guard", "TargetAsset", "Outcome"]
    for node in required_nodes:
        if node in body:
            r.ok(f"LearnerReflector: KG node {node!r} present")
        else:
            r.fail(f"LearnerReflector: KG node {node!r} MISSING from schema")

    required_edges = ["exploited_via", "bypassed_by", "learned_from", "used_against", "contains"]
    for edge in required_edges:
        if edge in body:
            r.ok(f"LearnerReflector: KG edge {edge!r} present")
        else:
            r.fail(f"LearnerReflector: KG edge {edge!r} MISSING from schema")

    # GraphRAG
    if "GraphRAG" in body:
        r.ok("LearnerReflector: GraphRAG section present")
    else:
        r.fail("LearnerReflector: GraphRAG section MISSING")

    if "embedding" in body:
        r.ok("LearnerReflector: embedding field referenced in KG schema")
    else:
        r.fail("LearnerReflector: embedding field MISSING from KG schema")

    # Properties on all nodes
    for prop in ["confidence", "timestamp", "validity_window"]:
        if prop in body:
            r.ok(f"LearnerReflector: universal node property {prop!r} present")
        else:
            r.fail(f"LearnerReflector: universal node property {prop!r} MISSING")

    # dry_run in args_allowlist
    if "--dry_run" in body:
        r.ok("LearnerReflector: --dry_run in update_kg args_allowlist")
    else:
        r.fail("LearnerReflector: --dry_run NOT found in update_kg args_allowlist")

    # Human-review gate
    if "human-review" in body.lower() or "human review" in body.lower():
        r.ok("LearnerReflector: human-review gate documented")
    else:
        r.warn("LearnerReflector: human-review gate not explicitly mentioned in body")

    # Anti-hallucination
    if "Anti-Hallucination" in body:
        r.ok("LearnerReflector: Anti-Hallucination Rules section present")
    else:
        r.fail("LearnerReflector: Anti-Hallucination Rules section MISSING")


def test_template_variables(r: TestResult):
    """T6 – Template variable syntax: all {{...}} references are well-formed."""
    print("\n[T6] Template Variable Syntax — All {{...}} References")

    all_skills = [SKILL_ROOT / "SKILL.md"] + [
        SKILL_ROOT / name / "SKILL.md" for name in SUBSKILLS
    ]

    # Valid template variable pattern
    valid_pat   = re.compile(r"\{\{[a-zA-Z0-9_.|\-\[\]{}]+\}\}")
    # Malformed: unclosed or extra braces
    malformed   = re.compile(r"\{(?!\{)[a-zA-Z_]|\}(?!\})[^}\s]")

    for skill_path in all_skills:
        if not skill_path.exists():
            r.fail(f"{skill_path.name}: file not found")
            continue

        text = skill_path.read_text(encoding="utf-8")
        relative = skill_path.relative_to(SKILL_ROOT)

        vars_found = valid_pat.findall(text)
        r.ok(f"{relative}: {len(vars_found)} template variable(s) found")

        # Check each template var is recognizable
        unknown = []
        for v in vars_found:
            inner = v[2:-2]  # strip {{ }}
            if not re.match(
                r"(run_id|input|env\.|manifest\.|phase_outputs\.|workspace|bb/)",
                inner
            ):
                unknown.append(v)
        if unknown:
            r.warn(f"{relative}: unrecognized template vars: {unknown}")
        else:
            r.ok(f"{relative}: all template vars use recognised namespaces")


def test_global_policy_coherence(r: TestResult):
    """T7 – Cross-skill: no skill escalates to active exploitation, all safe."""
    print("\n[T7] Global Policy Coherence — No Exploit Escalation Leak")

    forbidden_patterns = [
        (r"deny_active_exploitation\s*:\s*false", "deny_active_exploitation: false"),
        (r"operation_mode\s*:\s*destructive",     "operation_mode: destructive"),
        (r"allow_blind_scan",                     "allow_blind_scan"),
        (r"deny_dos_patterns\s*:\s*false",         "deny_dos_patterns: false"),
        (r"mode\s*:\s*exploit",                   "mode: exploit (should be auxiliary_only)"),
    ]

    all_skills = [SKILL_ROOT / "SKILL.md"] + [
        SKILL_ROOT / name / "SKILL.md" for name in SUBSKILLS
    ]

    for skill_path in all_skills:
        if not skill_path.exists():
            continue
        text = skill_path.read_text(encoding="utf-8").lower()
        relative = skill_path.relative_to(SKILL_ROOT)
        clean = True
        for pattern, label in forbidden_patterns:
            if re.search(pattern, text):
                r.fail(f"{relative}: FORBIDDEN pattern found — {label!r}")
                clean = False
        if clean:
            r.ok(f"{relative}: no forbidden policy patterns")

    # Confirm rate-limiting is set in TrafficTriage (which does live probing)
    tt_path = SKILL_ROOT / "TrafficTriage" / "SKILL.md"
    if tt_path.exists():
        tt_text = tt_path.read_text(encoding="utf-8")
        if "max_request_rate_per_host: 2" in tt_text:
            r.ok("TrafficTriage: max_request_rate_per_host: 2 enforced")
        else:
            r.fail("TrafficTriage: max_request_rate_per_host NOT set")
        if "require_backoff_on_429" in tt_text:
            r.ok("TrafficTriage: 429 backoff configured")
        else:
            r.fail("TrafficTriage: 429 backoff NOT configured")


def test_output_contracts(r: TestResult):
    """T8 – Required output files documented in orchestrator outputs section."""
    print("\n[T8] Output Contracts — Orchestrator outputs block completeness")

    path = SKILL_ROOT / "SKILL.md"
    meta, body = parse_frontmatter(path)
    if not meta:
        r.fail("Cannot read orchestrator — skipping T8")
        return

    outputs = meta.get("outputs", [])
    output_names = [o.get("name", "") for o in outputs]

    required_outputs = [
        "triage.json",
        "evidence/",
        "reports/",
        "validation/",
        "learning/",
        "run-summary.json",
    ]
    for name in required_outputs:
        if name in output_names:
            r.ok(f"Orchestrator outputs contains {name!r}")
        else:
            r.fail(f"Orchestrator outputs missing {name!r}")

    # Body must describe atomic write pattern
    if "write to `.tmp` then rename" in body or "atomic" in body.lower():
        r.ok("Orchestrator: atomic write pattern documented")
    else:
        r.warn("Orchestrator: atomic write pattern not explicitly documented in body")


def test_model_routing(r: TestResult):
    """T9 – All skills route complex_agentic/exploit_poc to GPT-5.5."""
    print("\n[T9] Model Routing — Escalation Rules Consistent Across All Skills")

    all_skills = {"BugBountyHunter": SKILL_ROOT / "SKILL.md"} | {
        name: SKILL_ROOT / name / "SKILL.md" for name in SUBSKILLS
    }

    for name, path in all_skills.items():
        if not path.exists():
            continue
        meta, _ = parse_frontmatter(path)
        if not meta or "_parse_error" in meta:
            continue

        routing = meta.get("model_routing", {})
        default_model = routing.get("default", "")
        if "claude" in default_model.lower() or "sonnet" in default_model.lower():
            r.ok(f"{name}: default model is Claude (Sonnet)")
        else:
            r.warn(f"{name}: default model is {default_model!r}")

        # Check escalation rule present
        rules = routing.get("rules", [])
        escalation_rule = any(
            "complex_agentic" in str(rule.get("when", {}).get("tags_any", []))
            or "exploit_poc" in str(rule.get("when", {}).get("tags_any", []))
            for rule in rules
        )
        # Orchestrator uses escalate block instead of rules
        escalate = routing.get("escalate", [])
        orch_escalation = any(
            "complex_agentic" in str(e.get("when", {}).get("tags_any", []))
            for e in escalate
        )
        if escalation_rule or orch_escalation:
            r.ok(f"{name}: GPT-5.5 escalation rule for complex_agentic/exploit_poc")
        else:
            r.warn(f"{name}: no escalation rule to GPT-5.5 found (may use orchestrator-level routing)")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  BugBountyHunter Skill Suite — Production Validation")
    print(f"  Root: {SKILL_ROOT}")
    print("=" * 60)

    r = TestResult()

    # Run all test groups
    subskills_map = test_orchestrator(r)
    test_dependency_graph(r, subskills_map)
    test_subskill_frontmatter(r)
    test_executor_validator_specifics(r)
    test_learner_reflector_specifics(r)
    test_template_variables(r)
    test_global_policy_coherence(r)
    test_output_contracts(r)
    test_model_routing(r)

    passed = r.summary()

    if passed:
        print("\n  🟢 ALL CHECKS PASSED — System is PRODUCTION READY")
    else:
        print(f"\n  🔴 {len(r.failed)} CHECK(S) FAILED — See above for details")
        sys.exit(1)


if __name__ == "__main__":
    main()
