#!/usr/bin/env python3
"""
True Dead Module Classifier
============================

Splits the 856 "dead" modules into:
  ✅  RUNTIME_REACHABLE  — dynamically loaded via registries, shims, lazy imports
  ⚠️  CONDITIONALLY_REACHABLE  — loaded behind try/except, EventBus, or feature flags
  ❌  TRULY_DEAD  — no static or dynamic path reaches this code

Reachability signals (from most to least certain):
  P1   importlib shim → target          (deterministic)
  P2a  COMMAND_REGISTRY handler          (deterministic)
  P2b  PROVIDER_REGISTRY / _LAZY_IMPORTS (conditional — first-access)
  P2d  _HANDLER_MODULES phase map        (deterministic)
  P3   EventBus .on() subscriber         (conditional — event must fire)
  P5   __getattr__ lazy delegation       (conditional — attribute must be accessed)
  P6   try: import X except ImportError  (conditional — module must be importable)
  P7   Copilot SDK _EXTENSION_MODULES    (conditional — agent session)
  P8   Phase command string dispatch     (deterministic during scans)
  STR  String-referenced in live module  (evidence of runtime loading)
  DYN  importlib.import_module() target  (evidence of runtime loading)

Run:
    .venv\\Scripts\\python.exe true_dead_classifier.py

Output:
    true_dead_classification.json
"""
from __future__ import annotations

import ast
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CC = ROOT / "CaseCrack"
PKG = CC / "tools" / "burp_enterprise"
sys.path.insert(0, str(CC))


# ═══════════════════════════════════════════════════════════════════════
#  Signal detectors
# ═══════════════════════════════════════════════════════════════════════

def _detect_shim_targets() -> dict[str, str]:
    """P1: Find importlib shim modules and their real targets.

    Pattern:
        _real = _importlib.import_module("tools.burp_enterprise.subpkg.real_mod")
        def __getattr__(name): return getattr(_real, name)
    """
    shim_map: dict[str, str] = {}  # shim_module → target_module
    PAT = re.compile(
        r"""import_module\s*\(\s*['"]"""
        r"""(tools\.burp_enterprise\.[^'"]+)['"]""",
    )

    # Shims are at the package root level
    for py in PKG.glob("*.py"):
        if py.name == "__init__.py" or "__pycache__" in str(py):
            continue
        try:
            src = py.read_text(encoding="utf-8-sig", errors="replace")
        except Exception:
            continue
        # Must have __getattr__ AND import_module — that's the shim signature
        if "__getattr__" not in src:
            continue
        m = PAT.search(src)
        if m:
            rel = py.relative_to(CC).with_suffix("")
            shim_mod = ".".join(rel.parts)
            shim_map[shim_mod] = m.group(1)

    return shim_map


def _detect_lazy_imports_targets() -> set[str]:
    """P5a: Scan tool_wrappers/__init__.py for _LAZY_IMPORTS entries."""
    targets: set[str] = set()
    init = PKG / "tool_wrappers" / "__init__.py"
    if not init.exists():
        return targets
    try:
        src = init.read_text(encoding="utf-8-sig", errors="replace")
    except Exception:
        return targets

    # Pattern: "ClassName": (".submodule_name", "ClassName")
    # Note: _LAZY_IMPORTS uses relative paths like ".zap_provider"
    for m in re.finditer(r'''\(\s*["']\.?(\w+)["']\s*,\s*["']\w+["']\s*\)''', src):
        submod = m.group(1)
        targets.add(f"tools.burp_enterprise.tool_wrappers.{submod}")

    return targets


def _detect_provider_registry() -> set[str]:
    """P2b: Scan tool_wrappers/_registry.py for PROVIDER_REGISTRY entries."""
    targets: set[str] = set()
    reg = PKG / "tool_wrappers" / "_registry.py"
    if not reg.exists():
        return targets
    try:
        src = reg.read_text(encoding="utf-8-sig", errors="replace")
    except Exception:
        return targets

    # Pattern: "tool_name": ("module_name", "ClassName")
    for m in re.finditer(r'''\(\s*["'](\w+_provider|[\w]+)["']\s*,\s*["']\w+["']\s*\)''', src):
        submod = m.group(1)
        targets.add(f"tools.burp_enterprise.tool_wrappers.{submod}")

    return targets


def _detect_command_registry_modules() -> set[str]:
    """P2a: All modules that contribute handlers to COMMAND_REGISTRY."""
    targets: set[str] = set()
    init = PKG / "cli" / "commands" / "__init__.py"
    if not init.exists():
        return targets
    try:
        src = init.read_text(encoding="utf-8-sig", errors="replace")
        tree = ast.parse(src)
    except Exception:
        return targets

    # Every ImportFrom in this file brings in cmd_* handlers
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level == 1 and node.module:
                targets.add(f"tools.burp_enterprise.cli.commands.{node.module}")
            elif node.level == 0 and node.module and node.module.startswith("tools."):
                targets.add(node.module)

    return targets


def _detect_handler_modules() -> set[str]:
    """P2d: Phase handler modules from _HANDLER_MODULES dict."""
    targets: set[str] = set()
    init = PKG / "recon_dashboard" / "phase_handlers" / "__init__.py"
    if not init.exists():
        return targets
    try:
        src = init.read_text(encoding="utf-8-sig", errors="replace")
        tree = ast.parse(src)
    except Exception:
        return targets

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level == 1 and node.module:
                targets.add(f"tools.burp_enterprise.recon_dashboard.phase_handlers.{node.module}")

    return targets


def _detect_eventbus_subscribers() -> set[str]:
    """P3: Modules that subscribe to EventBus events via .on() / .subscribe()."""
    subscribers: set[str] = set()
    PAT = re.compile(r"""(?:bus|event_bus|_bus|self\._bus|self\.bus|self\.event_bus|self\.signals|self\._mailbox)"""
                      r"""\.(?:on|subscribe)\s*\(""")

    for py in PKG.rglob("*.py"):
        if "__pycache__" in py.parts or "_archive" in py.parts:
            continue
        try:
            src = py.read_text(encoding="utf-8-sig", errors="replace")
        except Exception:
            continue
        if PAT.search(src):
            rel = py.relative_to(CC).with_suffix("")
            mod = ".".join(rel.parts)
            if mod.endswith(".__init__"):
                mod = mod[:-len(".__init__")]
            subscribers.add(mod)

    return subscribers


def _detect_conditional_imports() -> dict[str, set[str]]:
    """P6: Modules imported inside try/except blocks.

    Returns {importer → {imported_modules}} for try/except import patterns.
    """
    conditional: dict[str, set[str]] = defaultdict(set)

    for py in PKG.rglob("*.py"):
        if "__pycache__" in py.parts or "_archive" in py.parts:
            continue
        try:
            src = py.read_text(encoding="utf-8-sig", errors="replace")
            tree = ast.parse(src)
        except Exception:
            continue

        rel = py.relative_to(CC).with_suffix("")
        is_package = py.name == "__init__.py"
        mod = ".".join(rel.parts)
        if mod.endswith(".__init__"):
            mod = mod[:-len(".__init__")]

        # Walk AST looking for try blocks that contain imports
        for node in ast.walk(tree):
            if isinstance(node, ast.Try):
                # Check if any except handler catches ImportError/ModuleNotFoundError
                catches_import_error = False
                for handler in node.handlers:
                    if handler.type is None:
                        catches_import_error = True
                    elif isinstance(handler.type, ast.Name):
                        if handler.type.id in ("ImportError", "ModuleNotFoundError", "Exception"):
                            catches_import_error = True
                    elif isinstance(handler.type, ast.Tuple):
                        for elt in handler.type.elts:
                            if isinstance(elt, ast.Name) and elt.id in ("ImportError", "ModuleNotFoundError"):
                                catches_import_error = True

                if not catches_import_error:
                    continue

                # Extract imports from the try body
                for child in ast.walk(node):
                    if isinstance(child, ast.ImportFrom):
                        if child.module is None:
                            continue
                        target = child.module
                        if child.level:
                            from execution_reality_map import _resolve_relative
                            target = _resolve_relative(mod, child.level, child.module,
                                                       is_package=is_package)
                        if target.startswith("tools."):
                            conditional[mod].add(target)
                    elif isinstance(child, ast.Import):
                        for alias in child.names:
                            if alias.name.startswith("tools."):
                                conditional[mod].add(alias.name)

    return conditional


def _detect_sdk_extension_modules() -> set[str]:
    """P7: Copilot SDK _EXTENSION_MODULES list."""
    targets: set[str] = set()
    sdk_reg = PKG / "agents" / "copilot_sdk_tool_registry.py"
    if not sdk_reg.exists():
        return targets
    try:
        src = sdk_reg.read_text(encoding="utf-8-sig", errors="replace")
    except Exception:
        return targets

    # Pattern: ".copilot_sdk_xxx_tools"
    for m in re.finditer(r'''["']\.(copilot_sdk_\w+)["']''', src):
        targets.add(f"tools.burp_enterprise.agents.{m.group(1)}")

    return targets


def _detect_dynamic_imports() -> tuple[set[str], dict[str, list[str]]]:
    """DYN: All importlib.import_module() / __import__() targets.

    Returns (target_modules, {target → [source_files]}).
    """
    targets: set[str] = set()
    sources: dict[str, list[str]] = defaultdict(list)

    PAT_IM = re.compile(r"""import_module\s*\(\s*['"]([^'"]+)['"]""")
    PAT_DI = re.compile(r"""__import__\s*\(\s*['"]([^'"]+)['"]""")

    for py in PKG.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        try:
            src = py.read_text(encoding="utf-8-sig", errors="replace")
        except Exception:
            continue
        rel = str(py.relative_to(CC))

        for pat in (PAT_IM, PAT_DI):
            for m in pat.finditer(src):
                tgt = m.group(1)
                if tgt.startswith("tools."):
                    targets.add(tgt)
                    sources[tgt].append(rel)

    return targets, sources


def _detect_string_refs(dead: set[str]) -> set[str]:
    """STR: Dead modules referenced as string literals in live code."""
    refs: set[str] = set()
    dead_list = sorted(dead, key=len, reverse=True)

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
        for pat in patterns:
            for m in pat.finditer(src):
                refs.add(m.group(1))

    return refs


# ═══════════════════════════════════════════════════════════════════════
#  Module metadata (LOC, grade)
# ═══════════════════════════════════════════════════════════════════════

def _compute_module_metadata(modules: set[str]) -> dict[str, dict]:
    """Compute LOC, class_count, public_func_count, grade for each module."""
    meta: dict[str, dict] = {}
    for mod in modules:
        parts = mod.replace(".", "/")
        candidates = [CC / (parts + ".py"), CC / parts / "__init__.py"]
        src_path = next((c for c in candidates if c.exists()), None)
        if not src_path:
            meta[mod] = {"loc": 0, "class_count": 0, "public_func_count": 0, "grade": "missing"}
            continue

        try:
            src = src_path.read_text(encoding="utf-8-sig", errors="replace")
        except Exception:
            meta[mod] = {"loc": 0, "class_count": 0, "public_func_count": 0, "grade": "unreadable"}
            continue

        lines = src.splitlines()
        loc = len([l for l in lines if l.strip() and not l.strip().startswith("#")])
        class_count = 0
        public_func_count = 0

        try:
            tree = ast.parse(src)
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    class_count += 1
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if not node.name.startswith("_"):
                        public_func_count += 1
        except Exception:
            pass

        if loc > 100 and (class_count > 0 or public_func_count > 3):
            grade = "substantial"
        elif loc > 30:
            grade = "medium"
        else:
            grade = "stub"

        meta[mod] = {
            "loc": loc,
            "class_count": class_count,
            "public_func_count": public_func_count,
            "grade": grade,
        }

    return meta


def _get_subsystem(mod: str) -> str:
    parts = mod.split(".")
    if len(parts) >= 3 and parts[0] == "tools" and parts[1] == "burp_enterprise":
        return parts[2]
    return "_other"


# ═══════════════════════════════════════════════════════════════════════
#  Main classifier
# ═══════════════════════════════════════════════════════════════════════

def classify() -> dict:
    """Run all detectors and produce the final classification."""
    # Load the reality map
    reality = json.loads((ROOT / "execution_reality_map.json").read_text(encoding="utf-8"))
    dead = set(reality["dead_modules"])
    executed = set(reality["executed_modules"])

    print(f"  Dead modules to classify: {len(dead)}", flush=True)

    # ── Run all detectors ──────────────────────────────────────────
    print("  [P1]  Detecting importlib shims...", flush=True)
    shim_map = _detect_shim_targets()
    # Shim targets that are dead → runtime reachable (if the shim itself is live)
    p1_live_shim_targets: set[str] = set()
    for shim_mod, target_mod in shim_map.items():
        if shim_mod in executed and target_mod in dead:
            p1_live_shim_targets.add(target_mod)
        # Also: if the shim is dead but its target is dead,
        # the shim is a backward-compat relay — both are equally dead
        # But if the target is live, the shim is effectively an alias

    print("  [P2a] Detecting COMMAND_REGISTRY modules...", flush=True)
    p2a_cmd_registry = _detect_command_registry_modules() & dead

    print("  [P2b] Detecting PROVIDER_REGISTRY...", flush=True)
    p2b_provider = _detect_provider_registry() & dead

    print("  [P2d] Detecting phase handler modules...", flush=True)
    p2d_handlers = _detect_handler_modules() & dead

    print("  [P5a] Detecting _LAZY_IMPORTS targets...", flush=True)
    p5a_lazy = _detect_lazy_imports_targets() & dead

    print("  [P3]  Detecting EventBus subscribers...", flush=True)
    p3_eventbus = _detect_eventbus_subscribers() & dead

    print("  [P6]  Detecting conditional imports (try/except)...", flush=True)
    conditional_map = _detect_conditional_imports()
    # Dead modules imported conditionally by LIVE modules
    p6_conditional: set[str] = set()
    p6_conditional_by_dead: set[str] = set()
    for importer, imported in conditional_map.items():
        for imp in imported:
            if imp in dead:
                if importer in executed:
                    p6_conditional.add(imp)
                else:
                    p6_conditional_by_dead.add(imp)

    print("  [P7]  Detecting Copilot SDK extension modules...", flush=True)
    p7_sdk = _detect_sdk_extension_modules() & dead

    print("  [DYN] Detecting dynamic import targets...", flush=True)
    dyn_targets, dyn_sources = _detect_dynamic_imports()
    p_dyn = dyn_targets & dead

    print("  [STR] Detecting string references...", flush=True)
    p_str = _detect_string_refs(dead)

    # ── Classify each dead module ──────────────────────────────────
    print("  Classifying...", flush=True)

    # Priority: deterministic > conditional > string evidence > truly dead
    DETERMINISTIC_SIGNALS = {
        "P1_shim_target": p1_live_shim_targets,
        "P2a_command_registry": p2a_cmd_registry,
        "P2d_phase_handlers": p2d_handlers,
    }
    CONDITIONAL_SIGNALS = {
        "P2b_provider_registry": p2b_provider,
        "P3_eventbus_subscriber": p3_eventbus,
        "P5a_lazy_imports": p5a_lazy,
        "P6_try_except_import": p6_conditional,
        "P7_sdk_extension": p7_sdk,
        "DYN_dynamic_import": p_dyn,
    }
    WEAK_SIGNALS = {
        "STR_string_reference": p_str,
        "P6_conditional_by_dead": p6_conditional_by_dead,
    }

    classification: dict[str, dict] = {}
    cat_runtime: list[str] = []
    cat_conditional: list[str] = []
    cat_truly_dead: list[str] = []

    for mod in sorted(dead):
        signals: list[str] = []
        category = "TRULY_DEAD"

        # Check deterministic signals first
        for sig_name, sig_set in DETERMINISTIC_SIGNALS.items():
            if mod in sig_set:
                signals.append(sig_name)
                category = "RUNTIME_REACHABLE"

        # Check conditional signals
        for sig_name, sig_set in CONDITIONAL_SIGNALS.items():
            if mod in sig_set:
                signals.append(sig_name)
                if category == "TRULY_DEAD":
                    category = "CONDITIONALLY_REACHABLE"

        # Check weak signals
        for sig_name, sig_set in WEAK_SIGNALS.items():
            if mod in sig_set:
                signals.append(sig_name)
                if category == "TRULY_DEAD":
                    category = "CONDITIONALLY_REACHABLE"

        classification[mod] = {
            "category": category,
            "signals": signals,
            "subsystem": _get_subsystem(mod),
        }

        if category == "RUNTIME_REACHABLE":
            cat_runtime.append(mod)
        elif category == "CONDITIONALLY_REACHABLE":
            cat_conditional.append(mod)
        else:
            cat_truly_dead.append(mod)

    # ── Add metadata to truly dead modules ─────────────────────────
    print("  Computing metadata for truly dead modules...", flush=True)
    truly_dead_set = set(cat_truly_dead)
    meta = _compute_module_metadata(truly_dead_set)
    for mod in cat_truly_dead:
        classification[mod].update(meta.get(mod, {}))

    # ── Subsystem breakdown ────────────────────────────────────────
    sub_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    sub_loc: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for mod, info in classification.items():
        sub = info["subsystem"]
        cat = info["category"]
        sub_counts[sub][cat] += 1
        loc = info.get("loc", 0)
        if cat == "TRULY_DEAD":
            sub_loc[sub]["truly_dead_loc"] += loc
        elif cat == "CONDITIONALLY_REACHABLE":
            sub_loc[sub]["conditional_loc"] += loc
        else:
            sub_loc[sub]["runtime_loc"] += loc

    # ── Build report ───────────────────────────────────────────────
    truly_dead_by_grade: dict[str, list[str]] = defaultdict(list)
    for mod in cat_truly_dead:
        g = classification[mod].get("grade", "unknown")
        truly_dead_by_grade[g].append(mod)

    total_truly_dead_loc = sum(meta.get(m, {}).get("loc", 0) for m in cat_truly_dead)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_dead_input": len(dead),
            "runtime_reachable": len(cat_runtime),
            "conditionally_reachable": len(cat_conditional),
            "truly_dead": len(cat_truly_dead),
            "truly_dead_substantial": len(truly_dead_by_grade.get("substantial", [])),
            "truly_dead_medium": len(truly_dead_by_grade.get("medium", [])),
            "truly_dead_stub": len(truly_dead_by_grade.get("stub", [])),
            "truly_dead_missing": len(truly_dead_by_grade.get("missing", [])),
            "truly_dead_total_loc": total_truly_dead_loc,
        },
        "signal_counts": {
            "P1_shim_targets": len(p1_live_shim_targets),
            "P2a_command_registry": len(p2a_cmd_registry),
            "P2b_provider_registry": len(p2b_provider),
            "P2d_phase_handlers": len(p2d_handlers),
            "P3_eventbus_subscribers": len(p3_eventbus),
            "P5a_lazy_imports": len(p5a_lazy),
            "P6_try_except_from_live": len(p6_conditional),
            "P6_try_except_from_dead": len(p6_conditional_by_dead),
            "P7_sdk_extensions": len(p7_sdk),
            "DYN_dynamic_imports": len(p_dyn),
            "STR_string_references": len(p_str),
        },
        "runtime_reachable": sorted(cat_runtime),
        "conditionally_reachable": sorted(cat_conditional),
        "truly_dead": sorted(cat_truly_dead),
        "truly_dead_by_grade": {
            "substantial": sorted(truly_dead_by_grade.get("substantial", [])),
            "medium": sorted(truly_dead_by_grade.get("medium", [])),
            "stub": sorted(truly_dead_by_grade.get("stub", [])),
            "missing": sorted(truly_dead_by_grade.get("missing", [])),
        },
        "subsystem_breakdown": {
            sub: {
                **dict(counts),
                **dict(sub_loc.get(sub, {})),
            }
            for sub, counts in sorted(sub_counts.items(),
                key=lambda x: x[1].get("TRULY_DEAD", 0), reverse=True)
        },
        "classification": classification,
    }

    return report


def print_dashboard(report: dict) -> None:
    s = report["summary"]
    sc = report["signal_counts"]

    print()
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║           TRUE DEAD MODULE CLASSIFIER                          ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print()
    print(f"  Input: {s['total_dead_input']} static-dead modules")
    print()

    # Traffic light summary
    pct_rt = s["runtime_reachable"] / max(1, s["total_dead_input"]) * 100
    pct_cond = s["conditionally_reachable"] / max(1, s["total_dead_input"]) * 100
    pct_dead = s["truly_dead"] / max(1, s["total_dead_input"]) * 100

    print(f"  ✅ RUNTIME REACHABLE:        {s['runtime_reachable']:>4}  ({pct_rt:5.1f}%)  — deterministic dynamic loading")
    print(f"  ⚠️  CONDITIONALLY REACHABLE:  {s['conditionally_reachable']:>4}  ({pct_cond:5.1f}%)  — loaded behind feature flags/try-except")
    print(f"  ❌ TRULY DEAD:               {s['truly_dead']:>4}  ({pct_dead:5.1f}%)  — no path reaches this code")
    print()

    # Signal breakdown
    print("┌─────────────────────────────────────────────────────────────────┐")
    print("│  SIGNAL BREAKDOWN                                              │")
    print("├─────────────────────────────────────────────────────────────────┤")
    for sig, count in sorted(sc.items(), key=lambda x: -x[1]):
        bar = "█" * min(40, count // 2) + "░" * max(0, 20 - count // 2)
        print(f"│  {sig:<35} {count:>4}  {bar[:20]} │")
    print("└─────────────────────────────────────────────────────────────────┘")
    print()

    # Truly dead breakdown by grade
    print("┌─────────────────────────────────────────────────────────────────┐")
    print("│  TRULY DEAD — SEVERITY BREAKDOWN                               │")
    print("├─────────────────────────────────────────────────────────────────┤")
    print(f"│  Substantial (>100 LOC, classes/funcs):  {s['truly_dead_substantial']:>4} modules        │")
    print(f"│  Medium (30-100 LOC):                    {s['truly_dead_medium']:>4} modules        │")
    print(f"│  Stub (<30 LOC):                         {s['truly_dead_stub']:>4} modules        │")
    print(f"│  Missing (no file on disk):              {s['truly_dead_missing']:>4} modules        │")
    print(f"│                                                                 │")
    print(f"│  Total truly dead LOC:                 {s['truly_dead_total_loc']:>6}              │")
    print("└─────────────────────────────────────────────────────────────────┘")
    print()

    # Subsystem heatmap
    print("┌─────────────────────────────────────────────────────────────────┐")
    print("│  SUBSYSTEM HEATMAP  (truly dead count)                         │")
    print("├─────────────────────────────────────────────────────────────────┤")
    for sub, counts in report["subsystem_breakdown"].items():
        td = counts.get("TRULY_DEAD", 0)
        rt = counts.get("RUNTIME_REACHABLE", 0)
        cond = counts.get("CONDITIONALLY_REACHABLE", 0)
        total = td + rt + cond
        if total == 0:
            continue
        td_pct = td / total * 100
        bar_dead = "█" * (td * 15 // max(1, total))
        bar_ok = "░" * (15 - td * 15 // max(1, total))
        icon = "❌" if td_pct > 60 else "⚠️" if td_pct > 30 else "✅"
        print(f"│  {sub:<22} TD:{td:>3} CR:{cond:>3} RR:{rt:>3}  [{bar_dead}{bar_ok}] {icon} │")
    print("└─────────────────────────────────────────────────────────────────┘")
    print()

    # Top truly dead substantial modules
    substantial = report["truly_dead_by_grade"].get("substantial", [])
    if substantial:
        print("┌─────────────────────────────────────────────────────────────────┐")
        print("│  TOP TRULY DEAD SUBSTANTIAL MODULES  (highest LOC)             │")
        print("├─────────────────────────────────────────────────────────────────┤")
        # Sort by LOC
        by_loc = sorted(
            [(m, report["classification"][m].get("loc", 0)) for m in substantial],
            key=lambda x: -x[1],
        )
        for mod, loc in by_loc[:25]:
            short = mod.replace("tools.burp_enterprise.", "")
            sub = report["classification"][mod]["subsystem"]
            print(f"│  {loc:>5} LOC  {sub:<16} {short:<38} │")
        if len(by_loc) > 25:
            print(f"│  ... and {len(by_loc) - 25} more substantial modules                       │")
        print("└─────────────────────────────────────────────────────────────────┘")


def main():
    print("=" * 70)
    print("  TRUE DEAD MODULE CLASSIFIER")
    print("=" * 70)
    print()

    report = classify()

    # Write JSON
    out = ROOT / "true_dead_classification.json"
    out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(f"  JSON saved: {out}")

    print_dashboard(report)


if __name__ == "__main__":
    main()
