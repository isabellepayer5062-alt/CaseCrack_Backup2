#!/usr/bin/env python3
"""Quick ASCII-only validation of BugBountyHunter skill suite."""
import sys, re
from pathlib import Path

try:
    import yaml
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyyaml", "-q"])
    import yaml

SKILL_ROOT = Path(__file__).parent
SUBSKILLS = ["ReconAnalyzer","TrafficTriage","SourceHunter","ChainHunter",
             "PoCForge","ExecutorValidator","ReportWizard","LearnerReflector",
             "PlatformSubmitter"]
EXPECTED_VERSION = "2026.05"

PASS_OUTPUTS_CONTRACT = {
    "ReconAnalyzer":     ["recon-normalized.jsonl", "target-graph.json", "priority-hosts.txt"],
    "TrafficTriage":     ["triage-ranked.json", "high-signal-endpoints.txt"],
    "SourceHunter":      ["source-correlations.json", "candidate-poc-paths.txt"],
    "ChainHunter":       ["chains-discovered.json", "chain-poc-requests.md"],
    "PoCForge":          ["poc-steps.md", "repro-requests.http", "impact-and-safety-notes.md"],
    "ExecutorValidator": ["validation-results.jsonl", "blackboard_append"],
    "ReportWizard":      ["report.md", "report.json", "triager-checklist.md"],
    "LearnerReflector":  ["delta_{{run_id}}.jsonl", "reflection_{{run_id}}.md", "blackboard_append"],
    "PlatformSubmitter": ["submission-receipts.json", "submission-log.md"],
}

passed, failed, warned = [], [], []

def ok(msg):
    passed.append(msg)
    print(f"  [PASS] {msg}")

def fail(msg):
    failed.append(msg)
    print(f"  [FAIL] {msg}")

def warn(msg):
    warned.append(msg)
    print(f"  [WARN] {msg}")

def parse_fm(path):
    text = path.read_text(encoding="utf-8")
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)", text, re.DOTALL)
    if not m:
        return None, text
    try:
        return yaml.safe_load(m.group(1)), m.group(2)
    except yaml.YAMLError as e:
        return {"_parse_error": str(e)}, m.group(2)

# T1: Orchestrator
print("\n[T1] Orchestrator SKILL.md")
orch_path = SKILL_ROOT / "SKILL.md"
meta, body = parse_fm(orch_path)
if meta is None:
    fail("No YAML frontmatter")
elif "_parse_error" in meta:
    fail(f"YAML parse error: {meta['_parse_error']}")
else:
    ok("YAML frontmatter parses cleanly")
    for key in ["name","version","kind","inputs","outputs","subskills","policies","shared"]:
        if key in meta: ok(f"Field '{key}' present")
        else: fail(f"Required field '{key}' MISSING")

    version = str(meta.get("version",""))
    if version == EXPECTED_VERSION: ok(f"Version == {EXPECTED_VERSION}")
    else: fail(f"Version mismatch: got '{version}', expected '{EXPECTED_VERSION}'")

    bb = (meta.get("shared") or {}).get("blackboard")
    if bb:
        ok("shared.blackboard block present")
        expected_bb_path = "/workspace/blackboard/{{run_id}}.jsonl"
        if bb.get("path") == expected_bb_path: ok("blackboard.path correct")
        else: fail(f"blackboard.path mismatch: '{bb.get('path')}'")
    else:
        fail("shared.blackboard block MISSING")

    subskills_meta = meta.get("subskills", [])
    ok(f"Subskill count declared: {len(subskills_meta)}")
    if len(subskills_meta) == len(SUBSKILLS):
        ok(f"Subskill count correct: {len(SUBSKILLS)}")
    else:
        warn(f"Subskill count: got {len(subskills_meta)}, expected {len(SUBSKILLS)} ({SUBSKILLS})")
    subskills_map = {s["name"]: s for s in subskills_meta if "name" in s}

    # T2: Dependency graph
    print("\n[T2] Dependency Graph")
    declared = set(subskills_map.keys())
    expected = set(SUBSKILLS)
    missing = expected - declared
    extra = declared - expected
    if not missing: ok(f"All {len(SUBSKILLS)} subskills declared")
    else: fail(f"Subskills missing from orchestrator: {missing}")
    if extra: warn(f"Unexpected subskill entries: {extra}")

    for name, s in subskills_map.items():
        for dep in s.get("depends_on", []):
            if dep in declared: ok(f"{name} depends_on [{dep}] resolved")
            else: fail(f"{name} depends_on [{dep}] UNRESOLVED")

    for name, expected_outputs in PASS_OUTPUTS_CONTRACT.items():
        s = subskills_map.get(name, {})
        actual = s.get("pass_outputs", [])
        for out in expected_outputs:
            if out in actual: ok(f"{name}.pass_outputs has '{out}'")
            else: fail(f"{name}.pass_outputs MISSING '{out}' (actual: {actual})")

    # Cycle check
    adj = {n: set(s.get("depends_on", [])) for n, s in subskills_map.items()}
    visited, rec_stack = set(), set()
    def has_cycle(node):
        visited.add(node); rec_stack.add(node)
        for nb in adj.get(node, set()):
            if nb not in visited:
                if has_cycle(nb): return True
            elif nb in rec_stack: return True
        rec_stack.discard(node); return False
    cycle = any(has_cycle(n) for n in declared if n not in visited)
    if cycle: fail("Dependency graph has a CYCLE")
    else: ok("DAG is acyclic")

# T3: Subskill frontmatter
print("\n[T3] Subskill Frontmatter")
for name in SUBSKILLS:
    p = SKILL_ROOT / name / "SKILL.md"
    if not p.exists():
        fail(f"{name}/SKILL.md NOT FOUND"); continue
    m2, body2 = parse_fm(p)
    if m2 is None: fail(f"{name}: no YAML frontmatter"); continue
    if "_parse_error" in m2: fail(f"{name}: YAML parse error: {m2['_parse_error']}"); continue
    ok(f"{name}: YAML parses cleanly")

    for field in ["name","version","description","model_routing","runtime","inputs","policies","tags"]:
        if field in m2: ok(f"{name}.{field} present")
        else: fail(f"{name} MISSING required field '{field}'")

    v2 = str(m2.get("version",""))
    if v2 == EXPECTED_VERSION: ok(f"{name}: version == {EXPECTED_VERSION}")
    else: fail(f"{name}: version mismatch: '{v2}'")

    pol = m2.get("policies") or {}
    if pol.get("operation_mode") == "non_destructive_only": ok(f"{name}: policy non_destructive_only OK")
    else: fail(f"{name}: policy non_destructive_only MISSING")
    if pol.get("in_scope_required") is True: ok(f"{name}: policy in_scope_required OK")
    else: fail(f"{name}: policy in_scope_required MISSING")

    # Deny active exploitation check
    if name in ("ExecutorValidator", "ReconAnalyzer"):
        if pol.get("deny_active_exploitation") is True: ok(f"{name}: deny_active_exploitation OK")
        else: fail(f"{name}: deny_active_exploitation MISSING")

    # Model routing
    mr = m2.get("model_routing") or {}
    if mr.get("default"): ok(f"{name}: model_routing.default present")
    else: fail(f"{name}: model_routing.default MISSING")

    # Tags
    tags = m2.get("tags") or []
    if tags: ok(f"{name}: tags present ({tags})")
    else: warn(f"{name}: no tags defined")

    # Token budget
    tb = ((m2.get("runtime") or {}).get("token_budget") or {})
    if tb.get("max_total_tokens_per_run"): ok(f"{name}: token_budget.max_total_tokens_per_run present")
    else: fail(f"{name}: token_budget.max_total_tokens_per_run MISSING")
    if tb.get("hard_fail_on_overflow") is True: ok(f"{name}: hard_fail_on_overflow=true")
    else: warn(f"{name}: hard_fail_on_overflow not set to true")

    # Temperature
    rt = m2.get("runtime") or {}
    temp = rt.get("temperature")
    if temp is not None:
        if temp <= 0.3: ok(f"{name}: temperature={temp} (low, appropriate)")
        else: warn(f"{name}: temperature={temp} (high for security tool)")
    else:
        warn(f"{name}: temperature not set")

    # Retry
    retry = rt.get("retry") or {}
    if retry.get("max_attempts"): ok(f"{name}: retry.max_attempts present")
    else: warn(f"{name}: retry.max_attempts not set")

    # Observability
    obs = m2.get("observability") or {}
    if obs.get("emit_phase_events"): ok(f"{name}: emit_phase_events enabled")
    else: warn(f"{name}: emit_phase_events not enabled")
    if obs.get("log_token_usage"): ok(f"{name}: log_token_usage enabled")
    else: warn(f"{name}: log_token_usage not enabled")

    # Anti-hallucination check in body
    if "Anti-Hallucination" in body2 or "anti-hallucination" in body2.lower():
        ok(f"{name}: Anti-Hallucination rules section present")
    else:
        fail(f"{name}: Anti-Hallucination rules section MISSING")

    # Tool execution layer
    if "execute_tool" in body2:
        ok(f"{name}: execute_tool contract defined")
    else:
        warn(f"{name}: execute_tool contract not found")

    # Self-reflection
    if "REFLECTION CHECKPOINT" in body2:
        ok(f"{name}: Self-reflection checkpoint present")
    else:
        warn(f"{name}: REFLECTION CHECKPOINT not found")

    # Blackboard protocol
    if "blackboard" in body2.lower():
        ok(f"{name}: Blackboard protocol referenced")
    else:
        warn(f"{name}: Blackboard protocol not referenced")

    # Knowledge graph / persistent memory
    if "knowledge_graph" in (m2.get("tags") or []) or "query_kg" in body2 or "update_knowledge_graph" in body2:
        ok(f"{name}: Persistent memory/KG integration present")
    else:
        warn(f"{name}: No persistent memory/KG integration found")

    # Swarm workers
    if "swarm_workers" in body2:
        ok(f"{name}: Swarm workers defined")
    else:
        warn(f"{name}: No swarm workers defined")

    # OOB infrastructure check for ExecutorValidator
    if name == "ExecutorValidator":
        if "oob_listener" in body2 and "oob_poller" in body2:
            ok(f"{name}: OOB listener/poller tools defined")
        else:
            fail(f"{name}: OOB listener/poller MISSING (required for blind vuln validation)")
        if "OOB Validation Protocol" in body2:
            ok(f"{name}: OOB Validation Protocol section present")
        else:
            fail(f"{name}: OOB Validation Protocol section MISSING")

    # WAF bypass check for PoCForge
    if name == "PoCForge":
        if "WAF Bypass Protocol" in body2:
            ok(f"{name}: WAF Bypass Protocol section present")
        else:
            fail(f"{name}: WAF Bypass Protocol section MISSING")
        if "chains-discovered.json" in body2:
            ok(f"{name}: chains-discovered.json input correctly referenced")
        else:
            fail(f"{name}: chains-discovered.json NOT referenced (chain input path bug)")

    # Bounty estimation check for TrafficTriage
    if name == "TrafficTriage":
        if "estimated_bounty_usd_range" in body2:
            ok(f"{name}: Bounty estimation field present")
        else:
            fail(f"{name}: estimated_bounty_usd_range MISSING")
        if "Bounty Estimation" in body2:
            ok(f"{name}: Bounty Estimation section present")
        else:
            fail(f"{name}: Bounty Estimation section MISSING")

    # Validation results input check for ReportWizard
    if name == "ReportWizard":
        # Check both frontmatter inputs dict and body text
        inputs_text = str(m2.get("inputs", {}))
        has_val_results = ("validation_results" in inputs_text
                           or "validation-results.jsonl" in inputs_text
                           or "validation_results" in body2
                           or "validation-results.jsonl" in body2)
        if has_val_results:
            ok(f"{name}: validation_results input present")
        else:
            fail(f"{name}: validation_results input MISSING (can't show oracle scores)")
        if "CVSS Temporal Score" in body2 or "cvss_temporal" in body2:
            ok(f"{name}: CVSS Temporal Score section present")
        else:
            fail(f"{name}: CVSS Temporal Score section MISSING")
        if "triager-checklist.md" in body2:
            ok(f"{name}: triager-checklist.md referenced")
        else:
            fail(f"{name}: triager-checklist.md MISSING")

# Summary
total = len(passed) + len(failed) + len(warned)
print(f"\n{'='*60}")
print(f"  RESULTS: {len(passed)}/{total} passed | {len(failed)} failed | {len(warned)} warnings")
if failed:
    print("\n  FAILURES:")
    for f in failed: print(f"    FAIL: {f}")
if warned:
    print("\n  WARNINGS:")
    for w in warned: print(f"    WARN: {w}")
print("="*60)
sys.exit(0 if not failed else 1)
