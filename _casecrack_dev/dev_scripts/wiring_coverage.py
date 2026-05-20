#!/usr/bin/env python3
"""
Wiring Coverage Metric — Production KPI #1
============================================

Answers: "What % of capability is actually usable in a real run?"

Formula:
  WIRING_COVERAGE =
      (modules reachable statically + modules reachable dynamically)
      ÷ total meaningful modules (excluding stubs/inits)

Broken into 4 domain gauges:
  • TOOL_COVERAGE     — scanners, tool_wrappers, discovery_pkg
  • AGENT_COVERAGE    — agents, swarm, loop
  • STRATEGY_COVERAGE — strategy, intel, ai_ml, inference
  • CLI_COVERAGE      — cli command dispatch

Each domain also computes:
  • static_coverage   — via import graph reachability
  • runtime_coverage  — adds dynamic imports + string-ref registry loads
  • weighted_coverage — LOC-weighted (big modules count more)

Usage:
  python wiring_coverage.py                # Full dashboard
  python wiring_coverage.py --json         # JSON for CI/CD
  python wiring_coverage.py --watch        # Recompute (after wiring changes)
  python wiring_coverage.py --diff <old.json>  # Show delta from baseline
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent

# ── Domain definitions ─────────────────────────────────────────────
# Maps each coverage domain to the subsystems (first path component) it owns.
DOMAIN_SUBSYSTEMS: dict[str, list[str]] = {
    "tool": ["scanners", "tool_wrappers", "discovery_pkg"],
    "agent": ["agents", "swarm", "loop"],
    "strategy": ["strategy", "intel", "ai_ml", "inference"],
    "cli": ["cli"],
}

# Subsystems that are always meaningful (not test/helper scaffolding)
MEANINGFUL_SUBSYSTEMS: set[str] = {
    "scanners", "tool_wrappers", "discovery_pkg", "agents", "swarm", "loop",
    "strategy", "intel", "ai_ml", "inference", "cli", "recon", "recon_dashboard",
    "pipeline", "core_infra", "output", "exploit_chains", "secrets", "caap",
    "network", "integrations", "platforms", "cloud", "osint_providers",
    "session_auth", "graph", "mcp", "database", "atlas", "exploitation",
    "tool_registry", "reasoning", "graphql", "compliance_pkg", "vuln_intel",
    "notifications", "email_hardening", "passive_templates", "wasm_analysis",
    "memory", "reporting",
}


def _get_subsystem(mod: str) -> str:
    parts = mod.replace("tools.burp_enterprise.", "").split(".")
    return parts[0] if len(parts) >= 2 else "_root"


def _compute_all_loc() -> dict[str, int]:
    """Compute LOC for ALL modules (executed + dead) via file system scan."""
    pkg = ROOT / "CaseCrack" / "tools" / "burp_enterprise"
    loc_map: dict[str, int] = {}
    for py in pkg.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        try:
            lines = len(py.read_text(encoding="utf-8-sig", errors="replace").splitlines())
        except Exception:
            lines = 0
        rel = py.relative_to(ROOT / "CaseCrack")
        mod = str(rel).replace("\\", ".").replace("/", ".").removesuffix(".py")
        if mod.endswith(".__init__"):
            mod = mod.removesuffix(".__init__")
        loc_map[mod] = lines
    return loc_map


# ── Data structures ────────────────────────────────────────────────

@dataclass
class DomainCoverage:
    name: str
    subsystems: list[str]
    total_modules: int = 0
    meaningful_modules: int = 0       # excludes stubs
    static_reachable: int = 0         # from import graph
    runtime_reachable: int = 0        # + dynamic/string-ref
    total_loc: int = 0
    reachable_loc: int = 0            # LOC in reachable modules
    # Computed
    static_pct: float = 0.0
    runtime_pct: float = 0.0
    weighted_pct: float = 0.0         # LOC-weighted
    gap_modules: list[str] = field(default_factory=list)  # meaningful & unreachable
    gap_loc: int = 0


@dataclass
class WiringCoverage:
    timestamp: str = ""
    # Global
    total_modules: int = 0
    meaningful_modules: int = 0
    static_reachable: int = 0
    runtime_reachable: int = 0
    total_loc: int = 0
    reachable_loc: int = 0
    # Headline KPIs
    static_coverage_pct: float = 0.0
    runtime_coverage_pct: float = 0.0
    weighted_coverage_pct: float = 0.0
    # Domains
    tool: Optional[DomainCoverage] = None
    agent: Optional[DomainCoverage] = None
    strategy: Optional[DomainCoverage] = None
    cli: Optional[DomainCoverage] = None
    # Per-subsystem breakdown
    subsystem_coverage: dict[str, dict] = field(default_factory=dict)
    # Health grade
    grade: str = ""
    grade_details: str = ""


# ── Grade computation ──────────────────────────────────────────────

def _compute_grade(pct: float) -> tuple[str, str]:
    if pct >= 90:
        return "A", "Production-ready — excellent coverage"
    if pct >= 75:
        return "B", "Good — minor gaps remain"
    if pct >= 60:
        return "C", "Moderate — significant subsystems disconnected"
    if pct >= 40:
        return "D", "Poor — major capability loss"
    return "F", "Critical — majority of code unreachable"


# ── Core computation ───────────────────────────────────────────────

def compute_coverage() -> WiringCoverage:
    reality = json.loads((ROOT / "execution_reality_map.json").read_text(encoding="utf-8"))
    audit = json.loads((ROOT / "dead_module_audit.json").read_text(encoding="utf-8"))

    executed = set(reality["executed_modules"])
    dead = set(reality["dead_modules"])
    all_modules = executed | dead

    # Runtime-reachable dead: dynamically imported OR string-referenced
    dyn_imported = set(audit["dead_dynamically_imported"])
    str_referenced = set(audit["dead_string_referenced"].keys())
    runtime_extra = dyn_imported | str_referenced  # dead but runtime-reachable

    evidence = audit["evidence_per_module"]

    # Compute LOC for ALL modules (evidence only covers dead)
    all_loc = _compute_all_loc()

    # ── Classify every module ──────────────────────────────────────
    module_sub: dict[str, str] = {}
    module_loc: dict[str, int] = {}
    module_grade: dict[str, str] = {}
    module_meaningful: dict[str, bool] = {}

    for mod in all_modules:
        sub = _get_subsystem(mod)
        module_sub[mod] = sub
        ev = evidence.get(mod, {})
        # Use filesystem LOC for all modules, fall back to evidence
        loc = all_loc.get(mod, ev.get("loc", 0))
        grade = ev.get("grade", "")
        # For executed modules without evidence, infer grade from LOC
        if not grade:
            if loc > 100:
                grade = "substantial"
            elif loc > 30:
                grade = "medium"
            else:
                grade = "stub"
        module_loc[mod] = loc
        module_grade[mod] = grade
        # A module is "meaningful" if:
        # - It has real code (>30 LOC or substantial/medium grade)
        # - Its subsystem is in the meaningful set OR it has substantial code
        is_meaningful = (
            (grade in ("substantial", "medium") or loc > 30)
            or (sub in MEANINGFUL_SUBSYSTEMS and grade != "stub")
        )
        module_meaningful[mod] = is_meaningful

    # ── Module reachability states ─────────────────────────────────
    # static: in executed set
    # runtime: in executed set OR in runtime_extra set
    def is_static(m: str) -> bool:
        return m in executed

    def is_runtime(m: str) -> bool:
        return m in executed or m in runtime_extra

    # ── Compute domain coverages ───────────────────────────────────
    domains: dict[str, DomainCoverage] = {}

    for domain_name, subs in DOMAIN_SUBSYSTEMS.items():
        dc = DomainCoverage(name=domain_name, subsystems=subs)
        domain_mods = [m for m in all_modules if module_sub[m] in subs]
        meaningful = [m for m in domain_mods if module_meaningful[m]]

        dc.total_modules = len(domain_mods)
        dc.meaningful_modules = len(meaningful)
        dc.static_reachable = sum(1 for m in meaningful if is_static(m))
        dc.runtime_reachable = sum(1 for m in meaningful if is_runtime(m))
        dc.total_loc = sum(module_loc.get(m, 0) for m in meaningful)
        dc.reachable_loc = sum(module_loc.get(m, 0) for m in meaningful if is_runtime(m))

        dc.static_pct = round((dc.static_reachable / dc.meaningful_modules * 100) if dc.meaningful_modules else 0, 1)
        dc.runtime_pct = round((dc.runtime_reachable / dc.meaningful_modules * 100) if dc.meaningful_modules else 0, 1)
        dc.weighted_pct = round((dc.reachable_loc / dc.total_loc * 100) if dc.total_loc else 0, 1)

        dc.gap_modules = sorted(
            [m for m in meaningful if not is_runtime(m)],
            key=lambda m: -module_loc.get(m, 0),
        )
        dc.gap_loc = sum(module_loc.get(m, 0) for m in dc.gap_modules)

        domains[domain_name] = dc

    # ── Global metrics ─────────────────────────────────────────────
    all_meaningful = [m for m in all_modules if module_meaningful[m]]
    global_static = sum(1 for m in all_meaningful if is_static(m))
    global_runtime = sum(1 for m in all_meaningful if is_runtime(m))
    global_loc = sum(module_loc.get(m, 0) for m in all_meaningful)
    global_reach_loc = sum(module_loc.get(m, 0) for m in all_meaningful if is_runtime(m))

    static_pct = (global_static / len(all_meaningful) * 100) if all_meaningful else 0
    runtime_pct = (global_runtime / len(all_meaningful) * 100) if all_meaningful else 0
    weighted_pct = (global_reach_loc / global_loc * 100) if global_loc else 0

    grade, grade_details = _compute_grade(runtime_pct)

    # ── Per-subsystem breakdown ────────────────────────────────────
    sub_data: dict[str, dict] = {}
    for sub in sorted(MEANINGFUL_SUBSYSTEMS):
        sub_mods = [m for m in all_meaningful if module_sub[m] == sub]
        if not sub_mods:
            continue
        n_total = len(sub_mods)
        n_reach = sum(1 for m in sub_mods if is_runtime(m))
        loc_total = sum(module_loc.get(m, 0) for m in sub_mods)
        loc_reach = sum(module_loc.get(m, 0) for m in sub_mods if is_runtime(m))
        sub_data[sub] = {
            "total": n_total,
            "reachable": n_reach,
            "coverage_pct": round(n_reach / n_total * 100, 1) if n_total else 0,
            "total_loc": loc_total,
            "reachable_loc": loc_reach,
            "weighted_pct": round(loc_reach / loc_total * 100, 1) if loc_total else 0,
        }

    return WiringCoverage(
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
        total_modules=len(all_modules),
        meaningful_modules=len(all_meaningful),
        static_reachable=global_static,
        runtime_reachable=global_runtime,
        total_loc=global_loc,
        reachable_loc=global_reach_loc,
        static_coverage_pct=round(static_pct, 1),
        runtime_coverage_pct=round(runtime_pct, 1),
        weighted_coverage_pct=round(weighted_pct, 1),
        tool=domains["tool"],
        agent=domains["agent"],
        strategy=domains["strategy"],
        cli=domains["cli"],
        subsystem_coverage=sub_data,
        grade=grade,
        grade_details=grade_details,
    )


# ── Display ────────────────────────────────────────────────────────

BAR_WIDTH = 30


def _bar(pct: float, width: int = BAR_WIDTH) -> str:
    filled = int(pct / 100 * width)
    return f"[{'█' * filled}{'░' * (width - filled)}]"


def _color_pct(pct: float) -> str:
    if pct >= 75:
        return f"{pct:5.1f}%  ✅"
    if pct >= 50:
        return f"{pct:5.1f}%  ⚠️"
    return f"{pct:5.1f}%  ❌"


def print_dashboard(cov: WiringCoverage) -> None:
    print()
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║           WIRING COVERAGE DASHBOARD — Production KPI #1        ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print()

    # Headline
    print(f"  OVERALL WIRING COVERAGE:  {_color_pct(cov.runtime_coverage_pct)}")
    print(f"  {_bar(cov.runtime_coverage_pct)} {cov.runtime_reachable}/{cov.meaningful_modules} modules")
    print()
    print(f"  Static coverage (import graph):    {_color_pct(cov.static_coverage_pct)}")
    print(f"  Runtime coverage (+dynamic/ref):   {_color_pct(cov.runtime_coverage_pct)}")
    print(f"  Weighted coverage (LOC-based):     {_color_pct(cov.weighted_coverage_pct)}")
    print(f"  Grade: {cov.grade} — {cov.grade_details}")
    print()

    # Domain gauges
    print("┌─────────────────────────────────────────────────────────────────┐")
    print("│  DOMAIN COVERAGE GAUGES                                        │")
    print("├─────────────────────────────────────────────────────────────────┤")

    for dc in [cov.tool, cov.agent, cov.strategy, cov.cli]:
        if dc is None:
            continue
        label = f"{dc.name.upper()}_COVERAGE"
        print(f"│                                                                 │")
        print(f"│  {label:<18} {_bar(dc.runtime_pct)} {_color_pct(dc.runtime_pct)}   │")
        print(f"│    Static:  {dc.static_reachable:3d}/{dc.meaningful_modules:3d}  "
              f"Runtime: {dc.runtime_reachable:3d}/{dc.meaningful_modules:3d}  "
              f"LOC-wt: {dc.weighted_pct:5.1f}%{' ' * 9}│")
        print(f"│    Gap: {len(dc.gap_modules)} modules, {dc.gap_loc:,} LOC unreachable"
              f"{' ' * (27 - len(f'{dc.gap_loc:,}'))}│")

    print("│                                                                 │")
    print("└─────────────────────────────────────────────────────────────────┘")
    print()

    # Top gaps per domain
    print("┌─────────────────────────────────────────────────────────────────┐")
    print("│  TOP COVERAGE GAPS (highest-LOC unreachable modules)           │")
    print("├─────────────────────────────────────────────────────────────────┤")
    for dc in [cov.tool, cov.agent, cov.strategy, cov.cli]:
        if dc is None or not dc.gap_modules:
            continue
        print(f"│  {dc.name.upper()}:{'':57}│")
        for mod in dc.gap_modules[:5]:
            short = mod.replace("tools.burp_enterprise.", "")
            loc = 0
            try:
                audit = json.loads((ROOT / "dead_module_audit.json").read_text(encoding="utf-8"))
                loc = audit["evidence_per_module"].get(mod, {}).get("loc", 0)
            except Exception:
                pass
            line = f"    {loc:5d} LOC  {short}"
            print(f"│  {line:<63}│")
    print("└─────────────────────────────────────────────────────────────────┘")
    print()

    # Subsystem heatmap
    print("┌─────────────────────────────────────────────────────────────────┐")
    print("│  SUBSYSTEM HEATMAP                                             │")
    print("├─────────────────────────────────────────────────────────────────┤")
    print(f"│  {'Subsystem':<22} {'Reach':>5} {'Total':>5} {'Pct':>6}  {'Bar':<18}  │")
    print(f"│  {'─'*60}   │")
    for sub, data in sorted(cov.subsystem_coverage.items(), key=lambda x: x[1]["coverage_pct"]):
        pct = data["coverage_pct"]
        mini_bar = _bar(pct, 15)
        status = "✅" if pct >= 75 else ("⚠️" if pct >= 40 else "❌")
        line = f"  {sub:<22} {data['reachable']:5d} {data['total']:5d} {pct:5.1f}%  {mini_bar} {status}"
        print(f"│{line:<65}│")
    print("└─────────────────────────────────────────────────────────────────┘")


def write_json(cov: WiringCoverage, path: Path) -> None:
    """Serialize coverage to JSON for CI/CD pipelines and trend tracking."""
    def _dc_dict(dc: Optional[DomainCoverage]) -> Optional[dict]:
        if dc is None:
            return None
        d = asdict(dc)
        # Trim gap_modules to top 20 for JSON size
        d["gap_modules"] = d["gap_modules"][:20]
        return d

    obj = {
        "timestamp": cov.timestamp,
        "headline": {
            "static_coverage_pct": cov.static_coverage_pct,
            "runtime_coverage_pct": cov.runtime_coverage_pct,
            "weighted_coverage_pct": cov.weighted_coverage_pct,
            "grade": cov.grade,
        },
        "counts": {
            "total_modules": cov.total_modules,
            "meaningful_modules": cov.meaningful_modules,
            "static_reachable": cov.static_reachable,
            "runtime_reachable": cov.runtime_reachable,
            "total_loc": cov.total_loc,
            "reachable_loc": cov.reachable_loc,
        },
        "domains": {
            "tool": _dc_dict(cov.tool),
            "agent": _dc_dict(cov.agent),
            "strategy": _dc_dict(cov.strategy),
            "cli": _dc_dict(cov.cli),
        },
        "subsystem_coverage": cov.subsystem_coverage,
    }
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")
    print(f"  JSON saved: {path}")


def diff_coverage(cov: WiringCoverage, old_path: Path) -> None:
    """Show delta from a previous baseline."""
    old = json.loads(old_path.read_text(encoding="utf-8"))
    oh = old["headline"]

    print()
    print("┌─────────────────────────────────────────────────────────────────┐")
    print("│  COVERAGE DELTA                                                │")
    print("├─────────────────────────────────────────────────────────────────┤")
    for metric, old_val, new_val in [
        ("Static",   oh["static_coverage_pct"],   cov.static_coverage_pct),
        ("Runtime",  oh["runtime_coverage_pct"],   cov.runtime_coverage_pct),
        ("Weighted", oh["weighted_coverage_pct"],  cov.weighted_coverage_pct),
    ]:
        delta = new_val - old_val
        arrow = "↑" if delta > 0 else ("↓" if delta < 0 else "→")
        sign = "+" if delta > 0 else ""
        print(f"│  {metric:<12} {old_val:5.1f}% → {new_val:5.1f}%  ({sign}{delta:+.1f}% {arrow})"
              f"{'':30}│")

    if "domains" in old:
        for dname in ["tool", "agent", "strategy", "cli"]:
            od = old["domains"].get(dname) or {}
            nd = getattr(cov, dname)
            if od and nd:
                old_r = od.get("runtime_pct", 0)
                new_r = nd.runtime_pct
                delta = new_r - old_r
                arrow = "↑" if delta > 0 else ("↓" if delta < 0 else "→")
                sign = "+" if delta > 0 else ""
                print(f"│  {dname.upper():<12} {old_r:5.1f}% → {new_r:5.1f}%  ({sign}{delta:+.1f}% {arrow})"
                      f"{'':30}│")

    print("└─────────────────────────────────────────────────────────────────┘")


# ── Main ───────────────────────────────────────────────────────────

def main() -> int:
    p = argparse.ArgumentParser(description="Wiring Coverage KPI — Production Metric #1")
    p.add_argument("--json", action="store_true", help="Output JSON for CI/CD")
    p.add_argument("--diff", metavar="OLD.json", help="Show delta from baseline")
    p.add_argument("--quiet", action="store_true", help="Only print headline number")
    args = p.parse_args()

    # Check prerequisites
    for f in ["execution_reality_map.json", "dead_module_audit.json"]:
        if not (ROOT / f).exists():
            print(f"ERROR: {f} not found. Run execution_reality_map.py and dead_module_audit.py first.", file=sys.stderr)
            return 1

    cov = compute_coverage()

    if args.quiet:
        print(f"WIRING_COVERAGE={cov.runtime_coverage_pct:.1f}%")
        return 0

    print_dashboard(cov)

    out = ROOT / "wiring_coverage.json"
    write_json(cov, out)

    if args.diff:
        diff_coverage(cov, Path(args.diff))

    return 0


if __name__ == "__main__":
    sys.exit(main())
