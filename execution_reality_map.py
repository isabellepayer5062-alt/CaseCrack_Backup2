#!/usr/bin/env python3
"""
Execution Reality Map  —  Phase 1 of Wiring Stabilization
==========================================================

Answers: "What code actually runs in a real scan?"

Method:
  1. Static AST analysis to build the import graph
  2. Trace from canonical entrypoints (runner.py, server.py, agent loop)
  3. Cross-reference with runtime evidence (phase_commands, tool_registry,
     scanner_hooks) to tag modules as ✅ / ⚠️ / ❌
  4. Produce a full classification + actionable kill/reconnect lists

Run:
    .venv\\Scripts\\python.exe execution_reality_map.py
    .venv\\Scripts\\python.exe execution_reality_map.py --output report.json

Outputs:
    execution_reality_map.json  — structured classification
    execution_reality_map.md    — human-readable summary
"""
from __future__ import annotations

import ast
import importlib
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
CC = ROOT / "CaseCrack"
PKG = CC / "tools" / "burp_enterprise"
if str(CC) not in sys.path:
    sys.path.insert(0, str(CC))


# ── 1. Build the full import graph via AST ──────────────────────────────
def _resolve_relative(mod_fqn: str, level: int, target: str | None, *, is_package: bool = False) -> str:
    parts = mod_fqn.split(".")
    # For __init__.py (is_package=True), level=1 means "this package",
    # so we strip (level - 1) segments.  For regular .py files,
    # level=1 means "parent package", so we strip level segments.
    strip = level - 1 if is_package else level
    base = parts[:max(1, len(parts) - strip)]
    if target:
        return ".".join(base + [target])
    return ".".join(base)


def build_import_graph() -> tuple[dict[str, set[str]], set[str], list[dict]]:
    """Return adjacency list, all nodes, and syntax errors."""
    adj: dict[str, set[str]] = defaultdict(set)
    nodes: set[str] = set()
    syntax_errors: list[dict] = []

    for path in PKG.rglob("*.py"):
        if "__pycache__" in path.parts or "_archive" in path.parts:
            continue
        rel = path.relative_to(CC).with_suffix("")
        mod = ".".join(rel.parts)
        is_package = path.name == "__init__.py"
        if mod.endswith(".__init__"):
            mod = mod[:-len(".__init__")]
        nodes.add(mod)

        try:
            src = path.read_text(encoding="utf-8-sig", errors="replace")
            tree = ast.parse(src, filename=str(path))
        except SyntaxError as e:
            syntax_errors.append({"module": mod, "line": e.lineno, "msg": str(e)})
            continue
        except Exception:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("tools."):
                        adj[mod].add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module is None:
                    continue
                target = node.module
                if node.level:
                    target = _resolve_relative(mod, node.level, node.module, is_package=is_package)
                if target.startswith("tools."):
                    adj[mod].add(target)

    return adj, nodes, syntax_errors


# ── 2. Define entrypoints + runtime-known modules ───────────────────────
CANONICAL_ENTRYPOINTS = [
    "tools.burp_enterprise.cli.main",
    "tools.burp_enterprise.cli.commands",
    "tools.burp_enterprise.recon_dashboard",
    "tools.burp_enterprise.recon_dashboard.runner",
    "tools.burp_enterprise.recon_dashboard.server",
    "tools.burp_enterprise.recon_dashboard.command_executor",
    "tools.burp_enterprise.recon_dashboard.finding_pipeline",
    "tools.burp_enterprise.recon_dashboard.phase_commands",
    "tools.burp_enterprise.recon_dashboard.phase_handlers",
    "tools.burp_enterprise.agents.llm_bridge",
    "tools.burp_enterprise.full_scan_orchestrator",
    "tools.burp_enterprise.event_bus",
    "tools.burp_enterprise.mcp_server",
    "tools.burp_enterprise.mcp.mcp_server",
    "tools.burp_enterprise.graph.state_graph",
    "tools.burp_enterprise.graph.builder",
    "tools.burp_enterprise.graph.reasoning.builder",
    "tools.burp_enterprise.graph.multi_agent.builder",
    "tools.burp_enterprise.loop.autonomous_loop",
]


def _collect_runtime_modules() -> set[str]:
    """Modules known to be invoked at runtime via CLI dispatch or phase commands."""
    rt: set[str] = set()

    # Phase commands reference specific CLI subcommands
    try:
        from tools.burp_enterprise.recon_dashboard.phase_commands import PHASE_COMMANDS
        for pc in PHASE_COMMANDS:
            for cmd in pc.get("commands", []):
                if isinstance(cmd, list) and len(cmd) > 0:
                    # The first arg is usually a CLI command name; the runner
                    # invokes ``python -m tools.burp_enterprise.cli <cmd>``
                    rt.add(f"tools.burp_enterprise.cli.commands")
    except Exception:
        pass

    # Scanner hooks registry
    try:
        from tools.burp_enterprise.scanner_hooks import _SCANNER_REGISTRY
        for name, info in _SCANNER_REGISTRY.items():
            mod = getattr(info, "module", None) or ""
            if mod.startswith("tools."):
                rt.add(mod)
    except Exception:
        pass

    # Tool wrapper providers
    try:
        from tools.burp_enterprise.tool_wrapper_bridge import ToolWrapperBridge
        b = ToolWrapperBridge()
        for p in b.list_providers():
            rt.add(f"tools.burp_enterprise.tool_wrappers.{p}")
    except Exception:
        pass

    return rt


# ── 3. BFS reachability from entrypoints ────────────────────────────────
def compute_reachability(
    adj: dict[str, set[str]], nodes: set[str], entrypoints: list[str]
) -> set[str]:
    reachable: set[str] = set()
    stack = [e for e in entrypoints if e in nodes]
    while stack:
        n = stack.pop()
        if n in reachable:
            continue
        reachable.add(n)
        for dep in adj.get(n, ()):
            if dep in nodes and dep not in reachable:
                stack.append(dep)
    return reachable


# ── 4. Classify modules ─────────────────────────────────────────────────
CONDITIONAL_MARKERS = {
    "try:", "ImportError", "except ImportError", "except ModuleNotFoundError",
    "HAS_", "is_available", "optional", "OPTIONAL",
}

def classify_modules(
    adj: dict[str, set[str]],
    nodes: set[str],
    reachable: set[str],
    runtime: set[str],
    syntax_errors: list[dict],
) -> dict[str, dict]:
    """Classify each module as executed / conditional / dead."""
    results: dict[str, dict] = {}
    syntax_mods = {e["module"] for e in syntax_errors}

    for mod in sorted(nodes):
        info: dict[str, Any] = {
            "status": "unknown",
            "reachable_from_entrypoint": mod in reachable,
            "runtime_referenced": mod in runtime,
            "has_syntax_error": mod in syntax_mods,
            "imported_by": [],
            "imports": sorted(adj.get(mod, ())),
        }

        # Who imports this module?
        for src, deps in adj.items():
            if mod in deps:
                info["imported_by"].append(src)

        if mod in syntax_mods:
            info["status"] = "❌ SYNTAX_ERROR"
        elif mod in reachable and mod in runtime:
            info["status"] = "✅ EXECUTED"
        elif mod in reachable:
            # Check if the import is wrapped in try/except
            info["status"] = "✅ REACHABLE"
        elif mod in runtime:
            info["status"] = "⚠️ RUNTIME_ONLY"
        else:
            info["status"] = "❌ DEAD"

        results[mod] = info

    return results


# ── 5. Find dangling imports (refs to modules not on disk) ──────────────
def find_dangling(adj: dict[str, set[str]], nodes: set[str]) -> dict[str, list[str]]:
    """Return {missing_module: [referencing_modules]}"""
    dangling: dict[str, list[str]] = defaultdict(list)
    for src, deps in adj.items():
        for dep in deps:
            if dep.startswith("tools.") and dep not in nodes:
                dangling[dep].append(src)
    return dict(dangling)


# ── 6. Generate report ──────────────────────────────────────────────────
def generate_report(
    classification: dict[str, dict],
    dangling: dict[str, list[str]],
    syntax_errors: list[dict],
    nodes: set[str],
    edges_count: int,
    reachable: set[str],
) -> dict[str, Any]:
    counts = defaultdict(int)
    for info in classification.values():
        s = info["status"].split(" ", 1)[0]  # emoji prefix
        counts[s] += 1

    executed = [m for m, i in classification.items() if "EXECUTED" in i["status"] or "REACHABLE" in i["status"]]
    conditional = [m for m, i in classification.items() if "RUNTIME_ONLY" in i["status"]]
    dead = [m for m, i in classification.items() if "DEAD" in i["status"]]
    broken = [m for m, i in classification.items() if "SYNTAX_ERROR" in i["status"]]

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_modules": len(classification),
            "executed": len(executed),
            "conditional": len(conditional),
            "dead": len(dead),
            "syntax_errors": len(broken),
            "dangling_imports": len(dangling),
            "edge_count": edges_count,
            "reachable_from_entrypoints": len(reachable),
        },
        "executed_modules": sorted(executed),
        "conditional_modules": sorted(conditional),
        "dead_modules": sorted(dead),
        "syntax_error_modules": sorted(broken),
        "dangling_imports": {k: sorted(v) for k, v in sorted(dangling.items())},
        "syntax_errors": syntax_errors,
    }


def write_markdown(report: dict[str, Any], path: Path) -> None:
    s = report["summary"]
    lines = [
        "# Execution Reality Map\n",
        f"Generated: {report['timestamp']}\n",
        "## Summary\n",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| Total modules | {s['total_modules']} |",
        f"| ✅ Executed / Reachable | {s['executed']} |",
        f"| ⚠️ Conditional (runtime-only) | {s['conditional']} |",
        f"| ❌ Dead (unreachable) | {s['dead']} |",
        f"| ❌ Syntax errors | {s['syntax_errors']} |",
        f"| Dangling imports (module not on disk) | {s['dangling_imports']} |",
        f"| Import edges | {s['edge_count']} |",
        "",
        "## ✅ Executed / Reachable Modules\n",
    ]
    for m in report["executed_modules"][:200]:
        lines.append(f"- `{m}`")

    lines.append(f"\n## ⚠️ Conditional Modules ({len(report['conditional_modules'])})\n")
    for m in report["conditional_modules"][:100]:
        lines.append(f"- `{m}`")

    lines.append(f"\n## ❌ Dead Modules ({len(report['dead_modules'])})\n")
    lines.append("These modules are not reachable from any canonical entrypoint.\n")
    for m in report["dead_modules"][:200]:
        lines.append(f"- `{m}`")
    if len(report["dead_modules"]) > 200:
        lines.append(f"... and {len(report['dead_modules']) - 200} more")

    lines.append(f"\n## ❌ Syntax Errors ({len(report['syntax_errors'])})\n")
    for e in report["syntax_errors"]:
        lines.append(f"- `{e['module']}` line {e['line']}: {e['msg']}")

    lines.append(f"\n## Dangling Imports ({s['dangling_imports']})\n")
    lines.append("Import targets that don't exist on disk.\n")
    for target, refs in list(report["dangling_imports"].items())[:100]:
        lines.append(f"- `{target}` ← referenced by {', '.join(f'`{r}`' for r in refs[:5])}")

    path.write_text("\n".join(lines), encoding="utf-8")


# ── Main ─────────────────────────────────────────────────────────────────
def main() -> int:
    import argparse
    p = argparse.ArgumentParser(description="Execution Reality Map")
    p.add_argument("--output", default=str(ROOT / "execution_reality_map.json"))
    args = p.parse_args()

    print("Building import graph...", flush=True)
    adj, nodes, syntax_errors = build_import_graph()
    edge_count = sum(len(v) for v in adj.values())
    print(f"  {len(nodes)} modules, {edge_count} edges, {len(syntax_errors)} syntax errors")

    print("Collecting runtime-known modules...", flush=True)
    runtime = _collect_runtime_modules()
    print(f"  {len(runtime)} modules known at runtime")

    print("Computing reachability...", flush=True)
    reachable = compute_reachability(adj, nodes, CANONICAL_ENTRYPOINTS)
    print(f"  {len(reachable)} reachable from {len(CANONICAL_ENTRYPOINTS)} entrypoints")

    print("Classifying modules...", flush=True)
    classification = classify_modules(adj, nodes, reachable, runtime, syntax_errors)

    print("Finding dangling imports...", flush=True)
    dangling = find_dangling(adj, nodes)
    print(f"  {len(dangling)} dangling imports")

    report = generate_report(classification, dangling, syntax_errors, nodes, edge_count, reachable)

    out = Path(args.output)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"JSON: {out}")

    md_out = out.with_suffix(".md")
    write_markdown(report, md_out)
    print(f"MD:   {md_out}")

    s = report["summary"]
    print(f"\n{'─'*60}")
    print(f"  ✅ Executed/Reachable: {s['executed']}")
    print(f"  ⚠️  Conditional:       {s['conditional']}")
    print(f"  ❌ Dead:               {s['dead']}")
    print(f"  ❌ Syntax errors:      {s['syntax_errors']}")
    print(f"  🔗 Dangling imports:   {s['dangling_imports']}")
    print(f"{'─'*60}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
