#!/usr/bin/env python3
"""
Commercial-Grade Wiring Remediation Plan
=========================================

Loads the dead module audit and generates an actionable remediation plan
with clear priority tiers, specific actions per module, and cost estimates.

Tiers:
  TIER-1 (URGENT):    Substantial dead modules NOT dynamically/string-ref'd.
                      These are the real disconnected production subsystems.
  TIER-2 (HIGH):      Dynamically imported "dead" - need reality map fix only.
  TIER-3 (MEDIUM):    String-referenced registry targets.
  TIER-4 (LOW):       Stub __init__.py / small helpers.
  DELETE (LOW):       Archive/backup/legacy clearly-unused files.

Run:
    .venv\\Scripts\\python.exe wiring_remediation_plan.py
    .venv\\Scripts\\python.exe wiring_remediation_plan.py --tier 1
    .venv\\Scripts\\python.exe wiring_remediation_plan.py --subsystem scanners
"""
from __future__ import annotations
import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CC = ROOT / "CaseCrack"


# ── Classification logic ──────────────────────────────────────────────

LEGACY_MARKERS = re.compile(r"(?:archive|_old|_bak|legacy|deprecated|_obsolete|_removed)", re.IGNORECASE)
STUB_INIT_RE = re.compile(r"__init__$")


@dataclass
class RemediationItem:
    module: str
    tier: str                 # TIER-1..4 / DELETE
    action: str               # wire_back / update_reality_map / keep_dynamic / deprecate
    subsystem: str
    loc: int
    class_count: int
    public_funcs: int
    is_dynamically_imported: bool
    is_string_referenced: bool
    is_stub: bool
    grade: str                # substantial / medium / stub
    suggested_wiring: str     # Where/how to wire it
    notes: str = ""


def _suggest_wiring(mod: str, subsystem: str) -> str:
    """Suggest where this module should be wired based on its subsystem."""
    SUGGESTIONS = {
        "scanners": "Register via scanner_hooks.register_scanner() in scanner_providers",
        "agents": "Register in agent_factory / add to unified_agent pipeline",
        "exploit_chains": "Register via exploit_graph.register_chain() or chain_handlers",
        "tool_wrappers": "Add to tool_wrapper_bridge._providers dict",
        "cli": "Add dispatch in cli/commands/__init__.py CMD_HANDLERS",
        "recon": "Register as phase_handler in phase_commands.PHASE_COMMANDS",
        "recon_dashboard": "Hook into runner.py phase dispatch or server.py routes",
        "core_infra": "Import into recon_dashboard/__init__.py for runner initialization",
        "output": "Register as finding parser in finding_pipeline / report_generator",
        "pipeline": "Wire into full_scan_orchestrator.py pipeline stages",
        "discovery_pkg": "Add to discovery phase handlers",
        "secrets": "Register via secrets_scanner / phase_commands",
        "testing_tools": "Internal test utilities — evaluate if kept or moved to tests/",
        "caap": "Wire into caap orchestrator or mark as optional CAAP feature",
        "network": "Register via network phase handlers",
        "intel": "Wire into vuln_intel pipeline or mark optional",
        "platforms": "Register via platforms/_detector.py dispatch",
        "cloud": "Wire into cloud scanner subsystem",
        "osint_providers": "Register in provider_registry",
        "integrations": "Wire into notification / reporting bridges",
        "inference": "Register in model_management subsystem",
        "compliance_pkg": "Register compliance checks with compliance orchestrator",
        "reporting": "Add to report_generator outputs",
        "graph": "Register as graph node/edge type",
        "swarm": "Wire into swarm agent registry",
        "vuln_intel": "Add to vuln_intel pipeline",
        "email_hardening": "Wire into email scanner chain",
        "wasm_analysis": "Wire into wasm discovery phase",
        "ai_ml": "Register ML model in model_management",
        "graphql": "Wire into GraphQL phase handlers",
        "notifications": "Register as notification channel",
        "mcp": "Add to mcp_server tool registry",
        "loop": "Wire into autonomous_loop dispatch",
        "strategy": "Wire into DecisionOrchestrator or strategy registry",
        "database": "Wire into db_persistence layer",
        "passive_templates": "Register in passive template loader",
        "session_auth": "Wire into auth_context subsystem",
        "secrets_pkg": "Register in secrets scanner",
    }
    return SUGGESTIONS.get(subsystem, f"Review and wire into {subsystem} subsystem")


def _is_legacy(mod: str) -> bool:
    return bool(LEGACY_MARKERS.search(mod))


def _is_stub_init(mod: str) -> bool:
    # tools.burp_enterprise.X.__init__ patterns
    return mod.endswith(".__init__") or "_helper" in mod or "_utils" in mod


def classify_module(mod: str, evidence: dict, dyn: set, strref: set, subsystem: str) -> RemediationItem:
    grade = evidence.get("grade", "stub")
    loc = evidence.get("loc", 0)
    cls_count = evidence.get("class_count", 0)
    pub_funcs = evidence.get("public_func_count", 0)

    is_dyn = mod in dyn
    is_str = mod in strref
    is_stub = grade == "stub" or (loc < 30 and cls_count == 0)

    # Decision tree
    if _is_legacy(mod):
        tier = "DELETE"
        action = "deprecate"
        notes = "Legacy/archive marker in path"
    elif is_dyn and grade == "substantial":
        tier = "TIER-2"
        action = "update_reality_map"
        notes = "Substantial code loaded dynamically — add loader to entrypoints"
    elif is_str and grade in ("substantial", "medium"):
        tier = "TIER-3"
        action = "update_reality_map"
        notes = "Referenced via string/registry — confirm loader"
    elif grade == "substantial" and not is_dyn and not is_str:
        tier = "TIER-1"
        action = "wire_back"
        notes = f"Substantial production code ({loc} LOC, {cls_count} classes) — NOT wired"
    elif grade == "medium":
        tier = "TIER-3"
        action = "wire_back"
        notes = "Medium-size helper — evaluate usefulness"
    elif is_stub:
        tier = "TIER-4"
        action = "keep_stub"
        notes = "Stub / helper — low priority"
    else:
        tier = "TIER-4"
        action = "review"
        notes = "Small module — manual review"

    return RemediationItem(
        module=mod,
        tier=tier,
        action=action,
        subsystem=subsystem,
        loc=loc,
        class_count=cls_count,
        public_funcs=pub_funcs,
        is_dynamically_imported=is_dyn,
        is_string_referenced=is_str,
        is_stub=is_stub,
        grade=grade,
        suggested_wiring=_suggest_wiring(mod, subsystem),
        notes=notes,
    )


def build_plan() -> dict:
    audit = json.loads((ROOT / "dead_module_audit.json").read_text(encoding="utf-8"))
    reality = json.loads((ROOT / "execution_reality_map.json").read_text(encoding="utf-8"))

    dead = set(reality["dead_modules"])
    dyn = set(audit["dead_dynamically_imported"])
    strref = set(audit["dead_string_referenced"].keys())
    evidence_all = audit["evidence_per_module"]

    # Get subsystem per module
    subsystem_of: dict[str, str] = {}
    for sub, mods in audit["subsystem_modules"].items():
        for m in mods:
            subsystem_of[m] = sub

    items: list[RemediationItem] = []
    for mod in sorted(dead):
        ev = evidence_all.get(mod, {"grade": "stub", "loc": 0, "class_count": 0, "public_func_count": 0})
        sub = subsystem_of.get(mod, "_other")
        items.append(classify_module(mod, ev, dyn, strref, sub))

    return {
        "total_dead": len(items),
        "by_tier": {
            "TIER-1": [i for i in items if i.tier == "TIER-1"],
            "TIER-2": [i for i in items if i.tier == "TIER-2"],
            "TIER-3": [i for i in items if i.tier == "TIER-3"],
            "TIER-4": [i for i in items if i.tier == "TIER-4"],
            "DELETE": [i for i in items if i.tier == "DELETE"],
        },
        "by_subsystem": {
            sub: [i for i in items if i.subsystem == sub]
            for sub in sorted({i.subsystem for i in items})
        },
        "all_items": items,
    }


def print_summary(plan: dict) -> None:
    print(f"\n{'═'*75}")
    print(f"  COMMERCIAL-GRADE WIRING REMEDIATION PLAN")
    print(f"{'═'*75}")
    print(f"  Total dead modules: {plan['total_dead']}")
    print()
    print(f"  {'Tier':<10} {'Count':<8} {'Action':<25} {'Description'}")
    print(f"  {'-'*70}")
    tier_desc = {
        "TIER-1": ("wire_back",       "Substantial code NOT wired — URGENT"),
        "TIER-2": ("update_reality",  "Dynamically imported — false positive"),
        "TIER-3": ("wire_back/map",   "Medium or registry-referenced"),
        "TIER-4": ("keep/review",     "Stubs / helpers — low priority"),
        "DELETE": ("deprecate",       "Legacy / archive"),
    }
    for tier, (action, desc) in tier_desc.items():
        count = len(plan["by_tier"][tier])
        print(f"  {tier:<10} {count:<8} {action:<25} {desc}")

    t1 = plan["by_tier"]["TIER-1"]
    print(f"\n┌─ TIER-1 URGENT ({len(t1)} modules) ──────────────────────")
    print(f"│  Substantial production code with NO static or dynamic reference.")
    print(f"│  These are the actual disconnected commercial subsystems.")
    print(f"└──────────────────────────────────────────────────────────")

    # Group Tier 1 by subsystem
    by_sub: dict[str, list] = defaultdict(list)
    for item in t1:
        by_sub[item.subsystem].append(item)

    print(f"\n  TIER-1 by subsystem (top 20):")
    for sub, items in sorted(by_sub.items(), key=lambda x: -len(x[1]))[:20]:
        total_loc = sum(i.loc for i in items)
        print(f"    {len(items):3d} modules  {total_loc:6d} LOC  {sub}")

    # Top 30 largest TIER-1 modules
    print(f"\n  TOP 30 LARGEST TIER-1 MODULES (by LOC):")
    for item in sorted(t1, key=lambda x: -x.loc)[:30]:
        short = item.module.replace("tools.burp_enterprise.", "")
        print(f"    {item.loc:5d} LOC  {item.class_count:2d}C/{item.public_funcs:2d}F  {short}")

    # Summary by subsystem with actionable counts
    print(f"\n  SUBSYSTEM REMEDIATION OVERVIEW:")
    all_items = plan["all_items"]
    by_sub_all: dict[str, dict] = defaultdict(lambda: {"t1": 0, "t2": 0, "t3": 0, "t4": 0, "del": 0, "loc": 0})
    for i in all_items:
        key = i.subsystem
        by_sub_all[key][i.tier.lower().replace("tier-", "t").replace("delete", "del")] += 1
        by_sub_all[key]["loc"] += i.loc
    print(f"    {'Subsystem':<28} {'T1':>4} {'T2':>4} {'T3':>4} {'T4':>4} {'Del':>4} {'LOC':>7}")
    print(f"    {'-'*62}")
    for sub, counts in sorted(by_sub_all.items(), key=lambda x: -x[1]["t1"])[:25]:
        print(f"    {sub:<28} {counts['t1']:>4} {counts['t2']:>4} "
              f"{counts['t3']:>4} {counts['t4']:>4} {counts['del']:>4} {counts['loc']:>7}")


def write_json(plan: dict) -> None:
    serial = {
        "total_dead": plan["total_dead"],
        "counts": {t: len(plan["by_tier"][t]) for t in plan["by_tier"]},
        "tiers": {
            t: [asdict(i) for i in plan["by_tier"][t]]
            for t in plan["by_tier"]
        },
        "by_subsystem_counts": {
            sub: len(items) for sub, items in plan["by_subsystem"].items()
        },
    }
    out = ROOT / "wiring_remediation_plan.json"
    out.write_text(json.dumps(serial, indent=2), encoding="utf-8")
    print(f"\nJSON saved: {out}")


def write_markdown(plan: dict) -> None:
    out = ROOT / "wiring_remediation_plan.md"
    lines = [
        "# Commercial-Grade Wiring Remediation Plan",
        "",
        f"**Total dead modules: {plan['total_dead']}**",
        "",
        "## Tier Summary",
        "",
        "| Tier | Count | Action | Description |",
        "|------|-------|--------|-------------|",
    ]
    tier_desc = {
        "TIER-1": ("wire_back",      "Substantial production code NOT wired — **URGENT**"),
        "TIER-2": ("update_reality", "Dynamically imported — reachable at runtime"),
        "TIER-3": ("wire_back/map",  "Medium or registry-referenced"),
        "TIER-4": ("keep/review",    "Stubs / helpers"),
        "DELETE": ("deprecate",      "Legacy / archive"),
    }
    for t, (act, desc) in tier_desc.items():
        lines.append(f"| {t} | {len(plan['by_tier'][t])} | `{act}` | {desc} |")

    # Tier 1 detail
    t1 = plan["by_tier"]["TIER-1"]
    lines.extend([
        "",
        f"## TIER-1 Urgent Remediation ({len(t1)} modules)",
        "",
        "Substantial (>100 LOC, with classes) modules NOT reachable statically OR dynamically.",
        "These represent real disconnected commercial subsystems.",
        "",
    ])

    by_sub: dict[str, list] = defaultdict(list)
    for item in t1:
        by_sub[item.subsystem].append(item)

    for sub in sorted(by_sub, key=lambda s: -len(by_sub[s])):
        items = sorted(by_sub[sub], key=lambda x: -x.loc)
        total_loc = sum(i.loc for i in items)
        lines.append(f"### `{sub}` ({len(items)} modules, {total_loc:,} LOC)")
        lines.append("")
        lines.append(f"**Wiring target:** {items[0].suggested_wiring}")
        lines.append("")
        lines.append("| Module | LOC | Classes | Funcs |")
        lines.append("|--------|-----|---------|-------|")
        for i in items[:50]:
            short = i.module.replace("tools.burp_enterprise.", "")
            lines.append(f"| `{short}` | {i.loc} | {i.class_count} | {i.public_funcs} |")
        if len(items) > 50:
            lines.append(f"| ...and {len(items) - 50} more | | | |")
        lines.append("")

    # Tier 2 summary
    t2 = plan["by_tier"]["TIER-2"]
    lines.extend([
        f"## TIER-2 Reality Map Update ({len(t2)} modules)",
        "",
        "These modules are **dynamically imported** but not detected by static AST analysis.",
        "Fix by adding their loader sites to `CANONICAL_ENTRYPOINTS` in `execution_reality_map.py`.",
        "",
    ])
    t2_by_sub: dict[str, int] = defaultdict(int)
    for i in t2:
        t2_by_sub[i.subsystem] += 1
    lines.append("| Subsystem | Count |")
    lines.append("|-----------|-------|")
    for sub, n in sorted(t2_by_sub.items(), key=lambda x: -x[1])[:20]:
        lines.append(f"| `{sub}` | {n} |")
    lines.append("")

    # Tier 3
    t3 = plan["by_tier"]["TIER-3"]
    lines.extend([
        f"## TIER-3 Medium / String-Referenced ({len(t3)} modules)",
        "",
        "Either medium-sized helpers or referenced via registry strings.",
        "Mostly reachable through plugin registries — verify loader exists.",
        "",
    ])

    # Execution roadmap
    lines.extend([
        "## Execution Roadmap",
        "",
        "### Week 1: TIER-2 Reality Map Fix (Quick Win)",
        f"- Identify {len(t2)} dynamically-imported modules",
        "- Add their registry/loader modules to `CANONICAL_ENTRYPOINTS`",
        "- Rerun `execution_reality_map.py` — expect reachability to jump significantly",
        "",
        "### Week 2-3: TIER-1 Subsystem-by-Subsystem Wiring",
        "Priority order based on production value:",
    ])
    priority_subs = ["scanners", "exploit_chains", "agents", "recon", "recon_dashboard",
                      "pipeline", "core_infra", "output", "tool_wrappers", "cli"]
    for i, sub in enumerate(priority_subs, 1):
        count = sum(1 for it in t1 if it.subsystem == sub)
        if count:
            loc = sum(it.loc for it in t1 if it.subsystem == sub)
            lines.append(f"{i}. `{sub}` — {count} modules, {loc:,} LOC")

    lines.extend([
        "",
        "### Week 4: TIER-3 Registry Verification",
        f"- Verify all {len(t3)} registry-referenced modules are actually loaded",
        "- Add missing loaders to plugin dispatch",
        "",
        "### Week 5: TIER-4 / DELETE Cleanup",
        f"- Review {len(plan['by_tier']['TIER-4'])} stub modules",
        f"- Remove {len(plan['by_tier']['DELETE'])} legacy modules",
        "",
    ])

    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"Markdown saved: {out}")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--tier", help="Show only this tier (TIER-1..4, DELETE)")
    p.add_argument("--subsystem", help="Show only this subsystem")
    p.add_argument("--limit", type=int, default=100)
    args = p.parse_args()

    plan = build_plan()

    if args.tier or args.subsystem:
        items = plan["all_items"]
        if args.tier:
            items = [i for i in items if i.tier == args.tier.upper()]
        if args.subsystem:
            items = [i for i in items if i.subsystem == args.subsystem]
        items.sort(key=lambda x: -x.loc)
        for item in items[:args.limit]:
            short = item.module.replace("tools.burp_enterprise.", "")
            print(f"  [{item.tier}] {item.loc:5d} LOC  {short}")
            print(f"           ↳ {item.suggested_wiring}")
            print(f"           ↳ {item.notes}")
        print(f"\n  {len(items)} modules match filter")
        return 0

    print_summary(plan)
    write_json(plan)
    write_markdown(plan)
    return 0


if __name__ == "__main__":
    sys.exit(main())
