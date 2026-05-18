#!/usr/bin/env python3
"""Analyze dead modules comprehensively - find dynamic imports, classify by subsystem."""
from __future__ import annotations
import ast
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CC = ROOT / "CaseCrack"
PKG = CC / "tools" / "burp_enterprise"
sys.path.insert(0, str(CC))


def find_dynamic_imports() -> tuple[list[tuple[str, str, int]], Counter]:
    """Scan all .py files for importlib.import_module / __import__ calls with string args."""
    sites: list[tuple[str, str, int]] = []  # (file, target, line)
    refs: Counter = Counter()

    # Match: import_module("tools.burp_enterprise.xxx")
    pat_import_module = re.compile(r"""import_module\s*\(\s*['"]([^'"]+)['"]""")
    pat_dunder = re.compile(r"""__import__\s*\(\s*['"]([^'"]+)['"]""")

    for py in PKG.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        try:
            src = py.read_text(encoding="utf-8-sig", errors="replace")
        except Exception:
            continue
        rel = str(py.relative_to(CC))

        for pat in (pat_import_module, pat_dunder):
            for m in pat.finditer(src):
                line = src.count("\n", 0, m.start()) + 1
                tgt = m.group(1)
                if tgt.startswith("tools.") or "." in tgt:
                    sites.append((rel, tgt, line))
                    refs[tgt] += 1

    return sites, refs


def find_string_references(dead_modules: set[str]) -> dict[str, list[str]]:
    """Scan for string literals that match dead module names (plugin/registry patterns)."""
    refs: dict[str, list[str]] = defaultdict(list)
    # Build a single regex matching any dead module (escaped)
    # To keep regex small, match the longest common prefix then lookup
    # Simpler: one alternation per ~100 modules
    dead_list = sorted(dead_modules, key=len, reverse=True)

    # Group into chunks and compile one regex per chunk
    patterns = []
    for i in range(0, len(dead_list), 200):
        chunk = dead_list[i:i + 200]
        escaped = "|".join(re.escape(m) for m in chunk)
        patterns.append(re.compile(f"['\"]({escaped})['\"]"))

    for py in PKG.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        try:
            src = py.read_text(encoding="utf-8-sig", errors="replace")
        except Exception:
            continue
        rel = str(py.relative_to(CC))
        for pat in patterns:
            for m in pat.finditer(src):
                refs[m.group(1)].append(rel)

    return dict(refs)


def categorize_dead(dead: set[str], adj: dict, rev: dict) -> dict:
    """Group dead modules by subsystem and analyze structure."""
    subsystems: dict[str, list[str]] = defaultdict(list)
    for m in dead:
        parts = m.split(".")
        if len(parts) >= 3 and parts[0] == "tools" and parts[1] == "burp_enterprise":
            subsystems[parts[2]].append(m)
        else:
            subsystems["_other"].append(m)

    result = {}
    for sub, mods in subsystems.items():
        mods_set = set(mods)
        # How self-contained is this subsystem?
        internal_edges = 0
        external_in_edges = 0  # from OUTSIDE the subsystem into this subsystem (dead)
        external_out_edges = 0  # from this subsystem OUT

        for m in mods:
            for dep in adj.get(m, set()):
                if dep in mods_set:
                    internal_edges += 1
                else:
                    external_out_edges += 1
            for src in rev.get(m, set()):
                if src not in mods_set:
                    external_in_edges += 1

        # Find roots (no deps on others in subsystem) and hubs (high in-degree in subsystem)
        hub_score: Counter = Counter()
        root_score: Counter = Counter()
        for m in mods:
            hub_score[m] = len(rev.get(m, set()) & mods_set)
            root_score[m] = len(adj.get(m, set()) & mods_set)

        result[sub] = {
            "module_count": len(mods),
            "internal_edges": internal_edges,
            "external_in_edges": external_in_edges,  # dead modules imported from other subsystems
            "external_out_edges": external_out_edges,
            "top_hubs": hub_score.most_common(3),
            "top_roots": root_score.most_common(3),
            "modules": sorted(mods),
        }

    return result


def find_commercial_grade_indicators(dead: set[str]) -> dict[str, dict]:
    """For each dead module, extract evidence of commercial/production intent."""
    evidence: dict[str, dict] = {}

    INDICATORS = [
        (re.compile(r"class\s+(\w*Engine|\w*Orchestrator|\w*Manager|\w*Service|\w*Provider|\w*Scanner|\w*Agent|\w*Pipeline)\b"), "class_role"),
        (re.compile(r"#\s*(Phase\s*\d+|Gap\s*\d+|P[0-3]|Tier\s*\d+|Production)", re.IGNORECASE), "roadmap_marker"),
        (re.compile(r"async\s+def\s+(run|execute|start|process|scan|analyze|detect|validate)\b"), "primary_async_method"),
        (re.compile(r"def\s+(run|execute|start|process|scan|analyze|detect|validate)\b"), "primary_sync_method"),
        (re.compile(r"@(register|plugin|tool|hook)\b"), "registration_decorator"),
        (re.compile(r"(?:REGISTRY|HOOKS|PLUGINS)\s*=\s*\{"), "has_registry"),
    ]

    for m in dead:
        parts = m.replace(".", "/")
        candidates = [
            CC / (parts + ".py"),
            CC / parts / "__init__.py",
        ]
        src_path = next((c for c in candidates if c.exists()), None)
        if not src_path:
            continue

        try:
            src = src_path.read_text(encoding="utf-8-sig", errors="replace")
        except Exception:
            continue

        ev = {"loc": 0, "class_count": 0, "public_func_count": 0, "markers": []}
        lines = src.splitlines()
        ev["loc"] = len([l for l in lines if l.strip() and not l.strip().startswith("#")])

        try:
            tree = ast.parse(src)
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    ev["class_count"] += 1
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if not node.name.startswith("_"):
                        ev["public_func_count"] += 1
        except Exception:
            pass

        for pat, label in INDICATORS:
            matches = pat.findall(src[:5000])  # just head
            if matches:
                ev["markers"].append({"type": label, "samples": matches[:3]})

        # Grade: substantial (>100 LOC with classes or public funcs) vs stub
        if ev["loc"] > 100 and (ev["class_count"] > 0 or ev["public_func_count"] > 3):
            ev["grade"] = "substantial"
        elif ev["loc"] > 30:
            ev["grade"] = "medium"
        else:
            ev["grade"] = "stub"

        evidence[m] = ev

    return evidence


def main():
    from execution_reality_map import build_import_graph

    print("Building import graph...", flush=True)
    adj, nodes, _ = build_import_graph()
    rev: dict[str, set[str]] = defaultdict(set)
    for src, deps in adj.items():
        for d in deps:
            rev[d].add(src)

    r = json.load(open("execution_reality_map.json", encoding="utf-8"))
    dead = set(r["dead_modules"])
    executed = set(r["executed_modules"])

    print("Scanning for dynamic imports...", flush=True)
    dyn_sites, dyn_refs = find_dynamic_imports()

    dead_dynamically_imported = set()
    for src, tgt, _line in dyn_sites:
        if tgt in dead:
            dead_dynamically_imported.add(tgt)

    print("Scanning for string references to dead modules...", flush=True)
    string_refs = find_string_references(dead)

    print("Categorizing by subsystem...", flush=True)
    subsystems = categorize_dead(dead, adj, rev)

    print("Extracting commercial-grade indicators...", flush=True)
    evidence = find_commercial_grade_indicators(dead)

    # Summary counts
    substantial_dead = [m for m, e in evidence.items() if e.get("grade") == "substantial"]
    medium_dead = [m for m, e in evidence.items() if e.get("grade") == "medium"]
    stub_dead = [m for m, e in evidence.items() if e.get("grade") == "stub"]

    # Dynamically-referenced dead = highest-value wire-backs
    # These should actually be reached at runtime but our static graph missed them

    report = {
        "summary": {
            "total_dead": len(dead),
            "dynamically_imported": len(dead_dynamically_imported),
            "string_referenced": len(string_refs),
            "substantial": len(substantial_dead),
            "medium": len(medium_dead),
            "stub": len(stub_dead),
            "subsystem_count": len(subsystems),
        },
        "dynamic_import_sites": [
            {"file": s, "target": t, "line": l} for s, t, l in dyn_sites
        ][:500],
        "dead_dynamically_imported": sorted(dead_dynamically_imported),
        "dead_string_referenced": {k: v for k, v in string_refs.items()},
        "subsystem_analysis": {
            k: {kk: vv for kk, vv in v.items() if kk != "modules"}
            for k, v in sorted(subsystems.items(), key=lambda x: -x[1]["module_count"])
        },
        "subsystem_modules": {k: v["modules"] for k, v in subsystems.items()},
        "substantial_dead_modules": sorted(substantial_dead),
        "medium_dead_modules": sorted(medium_dead),
        "stub_dead_modules": sorted(stub_dead),
        "evidence_per_module": evidence,
    }

    out = ROOT / "dead_module_audit.json"
    out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

    s = report["summary"]
    print(f"\n{'='*70}")
    print(f"  DEAD MODULE AUDIT")
    print(f"{'='*70}")
    print(f"  Total dead modules:              {s['total_dead']}")
    print(f"  Dynamically imported:            {s['dynamically_imported']}")
    print(f"  String-referenced (plugin-like): {s['string_referenced']}")
    print(f"  Substantial (LOC>100+ classes):  {s['substantial']}")
    print(f"  Medium (30-100 LOC):             {s['medium']}")
    print(f"  Stub (<30 LOC):                  {s['stub']}")
    print(f"  Subsystems:                      {s['subsystem_count']}")
    print()
    print("TOP 20 SUBSYSTEMS (by dead module count):")
    for sub, info in list(report["subsystem_analysis"].items())[:20]:
        print(f"  {info['module_count']:4d} {sub:30s} "
              f"internal={info['internal_edges']:3d} "
              f"ext_out={info['external_out_edges']:3d} "
              f"ext_in={info['external_in_edges']:3d}")

    if dead_dynamically_imported:
        print(f"\nDYNAMICALLY-IMPORTED DEAD MODULES ({len(dead_dynamically_imported)}):")
        for m in sorted(dead_dynamically_imported)[:30]:
            print(f"  {m}")

    print(f"\nSaved: {out}")


if __name__ == "__main__":
    main()
