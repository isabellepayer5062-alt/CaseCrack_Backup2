"""
Dead Module Triage: 3-Bucket Classifier
========================================

Splits 384 truly-dead modules into:
  🗑️  GARBAGE        — delete safely (stubs, deprecated, empty)
  📦  COLD_STORAGE   — archive (valuable but no current gap)
  🔌  RECONNECT      — wire back in (fills real capability gap)

Scoring logic:
  1. Check if module's subsystem has live siblings (active subsystem)
  2. Check if the module name signals strategic capability
  3. Check if the module would fill an architectural gap
  4. Check for deprecated/test/legacy patterns
  5. Read source for class hierarchy and docstrings
"""

from __future__ import annotations

import ast
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent
CC   = ROOT / "CaseCrack"
PKG  = CC / "tools" / "burp_enterprise"

CLASSIFICATION = ROOT / "true_dead_classification.json"
REALITY_MAP    = ROOT / "execution_reality_map.json"
OUTPUT_JSON    = ROOT / "dead_module_triage.json"

# ── Strategic capability keywords ────────────────────────────────────────────
# Modules whose names contain these ARE the intelligence layers
STRATEGIC_KEYWORDS = {
    "engine", "intelligence", "orchestrator", "validator", "validation",
    "reasoning", "planner", "optimizer", "consensus", "convergence",
    "resilience", "adaptation", "learning", "knowledge", "memory",
    "exploitation", "audit", "scanner", "provider", "bridge",
    "synthesis", "strategy", "decision", "agent", "swarm",
}

# Modules whose names contain these are LOW strategic value
GARBAGE_PATTERNS = re.compile(
    r"_deprecated|_old$|_legacy|_stub$|__pycache__|_example$|_demo$|_test$"
    r"|_placeholder$|_noop$|_dummy$|_compat$"
)

# ── Load data ────────────────────────────────────────────────────────────────

def load_data():
    with open(CLASSIFICATION) as f:
        cls_data = json.load(f)
    with open(REALITY_MAP) as f:
        reality = json.load(f)
    return cls_data, reality


def _module_short(mod: str) -> str:
    return mod.replace("tools.burp_enterprise.", "")


def _subsystem_of(mod: str) -> str:
    """Extract the subsystem from a fully-qualified module name."""
    short = _module_short(mod)
    parts = short.split(".")
    if len(parts) >= 2:
        return parts[0]
    return short  # top-level module IS its own subsystem


def _get_source(mod: str) -> str | None:
    """Get source code for a module."""
    rel = mod.replace(".", "/")
    # Try as module
    path = CC / f"{rel}.py"
    if path.exists():
        try:
            return path.read_text(encoding="utf-8-sig", errors="replace")
        except Exception:
            return None
    # Try as package
    path = CC / rel / "__init__.py"
    if path.exists():
        try:
            return path.read_text(encoding="utf-8-sig", errors="replace")
        except Exception:
            return None
    return None


def _extract_capability_summary(mod: str, src: str) -> dict:
    """Extract what a module actually provides."""
    result = {
        "docstring": "",
        "classes": [],
        "base_classes": [],
        "key_methods": [],
    }

    try:
        tree = ast.parse(src)
    except SyntaxError:
        return result

    # Module docstring
    if (tree.body and isinstance(tree.body[0], ast.Expr)
            and isinstance(tree.body[0].value, (ast.Constant, ast.Str))):
        val = tree.body[0].value
        ds = val.value if isinstance(val, ast.Constant) else val.s
        if isinstance(ds, str):
            # First 200 chars
            result["docstring"] = ds.strip()[:200]

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            result["classes"].append(node.name)
            # Base classes
            for base in node.bases:
                if isinstance(base, ast.Name):
                    result["base_classes"].append(base.id)
                elif isinstance(base, ast.Attribute):
                    result["base_classes"].append(base.attr)
            # Key methods (public, non-dunder)
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if not item.name.startswith("_"):
                        result["key_methods"].append(f"{node.name}.{item.name}")

    return result


# ── Subsystem activity analysis ──────────────────────────────────────────────

def build_subsystem_map(reality: dict, cls_data: dict) -> dict:
    """
    For each subsystem, count: live modules, dead modules, ratio.
    A subsystem with high live ratio = active = reconnection opportunity.
    """
    subsystems: dict[str, dict] = defaultdict(lambda: {
        "live": 0, "dead": 0, "live_modules": [], "dead_modules": []
    })

    for mod in reality["executed_modules"]:
        sub = _subsystem_of(mod)
        subsystems[sub]["live"] += 1
        subsystems[sub]["live_modules"].append(mod)

    for mod in cls_data["truly_dead"]:
        sub = _subsystem_of(mod)
        subsystems[sub]["dead"] += 1
        subsystems[sub]["dead_modules"].append(mod)

    # Compute ratios
    for sub, data in subsystems.items():
        total = data["live"] + data["dead"]
        data["live_ratio"] = data["live"] / total if total > 0 else 0
        data["total"] = total

    return dict(subsystems)


# ── Reconnection gap analysis ────────────────────────────────────────────────

def _compute_reconnection_score(
    mod: str,
    meta: dict,
    sub_map: dict,
    cap: dict,
) -> tuple[float, list[str]]:
    """
    Score a module for reconnection priority (0-100).
    Returns (score, [reasons]).
    """
    score = 0.0
    reasons: list[str] = []
    short = _module_short(mod)
    subsystem = _subsystem_of(mod)
    sub_data = sub_map.get(subsystem, {"live": 0, "dead": 0, "live_ratio": 0})

    # ── Factor 1: LOC weight (bigger = more investment) ──────────────────
    loc = meta.get("loc", 0)
    if loc > 500:
        score += 25
        reasons.append(f"large_investment({loc}_LOC)")
    elif loc > 200:
        score += 15
        reasons.append(f"medium_investment({loc}_LOC)")
    elif loc > 100:
        score += 8

    # ── Factor 2: Active subsystem (live siblings exist) ─────────────────
    if sub_data["live_ratio"] > 0.5:
        score += 25
        reasons.append(f"active_subsystem({subsystem}:{sub_data['live']}_live/{sub_data['total']}_total)")
    elif sub_data["live_ratio"] > 0.2:
        score += 12
        reasons.append(f"partially_active({subsystem})")
    elif sub_data["live"] == 0:
        score -= 15  # entirely dead subsystem = cold storage signal
        reasons.append(f"dead_subsystem({subsystem})")

    # ── Factor 3: Strategic naming ───────────────────────────────────────
    name_parts = set(re.split(r"[._]", short.lower()))
    strategic_hits = name_parts & STRATEGIC_KEYWORDS
    if strategic_hits:
        score += 15
        reasons.append(f"strategic_name({','.join(sorted(strategic_hits))})")

    # ── Factor 4: Class/function richness ────────────────────────────────
    classes = meta.get("class_count", 0)
    funcs = meta.get("public_func_count", 0)
    if classes >= 5 and funcs >= 10:
        score += 10
        reasons.append(f"rich_API({classes}_classes,{funcs}_funcs)")
    elif classes >= 2:
        score += 5

    # ── Factor 5: Implements known patterns ──────────────────────────────
    bases = set(cap.get("base_classes", []))
    pattern_bases = {"BaseAgent", "Agent", "BaseTool", "BaseProvider",
                     "ToolProvider", "DockerToolProvider", "BaseScanner",
                     "BaseEngine", "Strategy", "BaseBridge"}
    hits = bases & pattern_bases
    if hits:
        score += 15
        reasons.append(f"implements_pattern({','.join(sorted(hits))})")

    # ── Factor 6: Docstring indicates capability ─────────────────────────
    doc = cap.get("docstring", "").lower()
    capability_signals = [
        "parallel", "consensus", "convergence", "intelligence",
        "adaptive", "learning", "exploit", "resilience", "orchestrat",
        "validation", "audit", "real-time", "autonomous", "self-healing",
    ]
    doc_hits = [s for s in capability_signals if s in doc]
    if doc_hits:
        score += 10
        reasons.append(f"capability_doc({','.join(doc_hits[:3])})")

    return max(0, min(100, score)), reasons


# ── Main classification ──────────────────────────────────────────────────────

def triage():
    cls_data, reality = load_data()
    sub_map = build_subsystem_map(reality, cls_data)

    garbage: list[dict] = []
    cold_storage: list[dict] = []
    reconnect: list[dict] = []

    all_classifications = cls_data.get("classification", {})

    for mod in cls_data["truly_dead"]:
        meta = all_classifications.get(mod, {})
        short = _module_short(mod)
        loc = meta.get("loc", 0)
        grade = meta.get("grade", "stub")
        classes = meta.get("class_count", 0)
        funcs = meta.get("public_func_count", 0)
        subsystem = _subsystem_of(mod)

        # ── GARBAGE: stubs, empty, deprecated ────────────────────────────
        if grade == "stub":
            garbage.append({
                "module": short,
                "loc": loc,
                "reason": "stub(<30_LOC)",
                "subsystem": subsystem,
            })
            continue

        if grade == "missing":
            garbage.append({
                "module": short,
                "loc": 0,
                "reason": "missing_file",
                "subsystem": subsystem,
            })
            continue

        if GARBAGE_PATTERNS.search(short):
            garbage.append({
                "module": short,
                "loc": loc,
                "reason": "deprecated_naming",
                "subsystem": subsystem,
            })
            continue

        # Medium modules with no classes and <=1 function → garbage
        if grade == "medium" and classes == 0 and funcs <= 1:
            garbage.append({
                "module": short,
                "loc": loc,
                "reason": "medium_no_api",
                "subsystem": subsystem,
            })
            continue

        # ── For substantial and rich medium: compute reconnection score ──
        src = _get_source(mod)
        cap = _extract_capability_summary(mod, src) if src else {}

        score, reasons = _compute_reconnection_score(
            mod, meta, sub_map, cap,
        )

        entry = {
            "module": short,
            "loc": loc,
            "classes": classes,
            "funcs": funcs,
            "subsystem": subsystem,
            "score": round(score, 1),
            "reasons": reasons,
            "docstring": (cap.get("docstring", "") or "")[:150],
            "key_classes": cap.get("classes", [])[:5],
        }

        # ── RECONNECT: score >= 40 ──────────────────────────────────────
        if score >= 40:
            reconnect.append(entry)
        # ── COLD STORAGE: everything else with substance ────────────────
        else:
            cold_storage.append(entry)

    # Sort by score descending
    reconnect.sort(key=lambda x: -x["score"])
    cold_storage.sort(key=lambda x: -x["loc"])
    garbage.sort(key=lambda x: -x["loc"])

    return garbage, cold_storage, reconnect, sub_map


# ── Output ───────────────────────────────────────────────────────────────────

def main():
    garbage, cold_storage, reconnect, sub_map = triage()

    # ── Summary ──────────────────────────────────────────────────────────
    total = len(garbage) + len(cold_storage) + len(reconnect)
    garbage_loc = sum(e["loc"] for e in garbage)
    cold_loc = sum(e["loc"] for e in cold_storage)
    recon_loc = sum(e["loc"] for e in reconnect)

    print()
    print("=" * 70)
    print("  DEAD MODULE TRIAGE — 3-BUCKET CLASSIFICATION")
    print("=" * 70)
    print()
    print(f"  Input: {total} truly dead modules")
    print()
    print(f"  🗑️  GARBAGE (delete):       {len(garbage):>4}  ({garbage_loc:>6} LOC)")
    print(f"  📦  COLD STORAGE (archive):  {len(cold_storage):>4}  ({cold_loc:>6} LOC)")
    print(f"  🔌  RECONNECT (wire back):   {len(reconnect):>4}  ({recon_loc:>6} LOC)")
    print()

    # ── Reconnection candidates (the money list) ────────────────────────
    print("─" * 70)
    print("  🔌 RECONNECTION CANDIDATES  (sorted by ROI score)")
    print("─" * 70)
    for i, e in enumerate(reconnect, 1):
        print(f"\n  #{i:02d}  [{e['score']:5.1f}]  {e['module']}")
        print(f"        {e['loc']} LOC | {e['classes']} cls | {e['funcs']} fn | sub: {e['subsystem']}")
        if e["docstring"]:
            ds = e["docstring"].replace("\n", " ")[:100]
            print(f"        \"{ds}\"")
        if e["key_classes"]:
            print(f"        classes: {', '.join(e['key_classes'][:4])}")
        if e["reasons"]:
            print(f"        signals: {', '.join(e['reasons'][:4])}")

    # ── Cold storage ─────────────────────────────────────────────────────
    print()
    print("─" * 70)
    print("  📦 COLD STORAGE  (sorted by LOC)")
    print("─" * 70)
    for e in cold_storage[:20]:
        print(f"    {e['loc']:>5} LOC  {e['module']}")
        if e["reasons"]:
            print(f"             {', '.join(e['reasons'][:3])}")

    if len(cold_storage) > 20:
        remaining = len(cold_storage) - 20
        remaining_loc = sum(e["loc"] for e in cold_storage[20:])
        print(f"    ... +{remaining} more ({remaining_loc} LOC)")

    # ── Garbage summary ──────────────────────────────────────────────────
    print()
    print("─" * 70)
    print("  🗑️  GARBAGE  (safe to delete)")
    print("─" * 70)
    reason_counts: dict[str, int] = defaultdict(int)
    for e in garbage:
        reason_counts[e["reason"]] += 1
    for reason, count in sorted(reason_counts.items(), key=lambda x: -x[1]):
        print(f"    {count:>4}  {reason}")

    # Non-stub garbage
    non_stub = [e for e in garbage if e["reason"] != "stub(<30_LOC)"]
    if non_stub:
        print()
        print("  Non-stub garbage:")
        for e in non_stub[:10]:
            print(f"    {e['loc']:>5} LOC  {e['module']}  ({e['reason']})")

    # ── Subsystem intelligence ───────────────────────────────────────────
    print()
    print("─" * 70)
    print("  SUBSYSTEM INTELLIGENCE GAP  (active subsystems with dead modules)")
    print("─" * 70)
    # Show subsystems where reconnection candidates live
    recon_subs: dict[str, list] = defaultdict(list)
    for e in reconnect:
        recon_subs[e["subsystem"]].append(e["module"])

    for sub in sorted(recon_subs, key=lambda s: -len(recon_subs[s])):
        sd = sub_map.get(sub, {"live": 0, "dead": 0, "total": 0})
        modules = recon_subs[sub]
        print(f"\n    {sub}  ({sd['live']} live, {sd['dead']} dead)")
        print(f"    Reconnection candidates ({len(modules)}):")
        for m in modules[:5]:
            print(f"      → {m}")
        if len(modules) > 5:
            print(f"      ... +{len(modules) - 5} more")

    # ── Save JSON ────────────────────────────────────────────────────────
    output = {
        "summary": {
            "total_triaged": total,
            "garbage_count": len(garbage),
            "garbage_loc": garbage_loc,
            "cold_storage_count": len(cold_storage),
            "cold_storage_loc": cold_loc,
            "reconnect_count": len(reconnect),
            "reconnect_loc": recon_loc,
        },
        "reconnect": reconnect,
        "cold_storage": cold_storage,
        "garbage": garbage,
    }

    with open(OUTPUT_JSON, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n  JSON saved: {OUTPUT_JSON}")


if __name__ == "__main__":
    main()
