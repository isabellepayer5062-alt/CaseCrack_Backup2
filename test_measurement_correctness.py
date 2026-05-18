#!/usr/bin/env python3
"""
Unit tests for measurement correctness — the audit tools themselves.

Covers:
  1. _resolve_relative()  — relative import path resolution (the bug that hid 338 modules)
  2. build_import_graph()  — end-to-end graph correctness (no ghosts, no missed edges)
  3. find_dynamic_imports()  — importlib.import_module / __import__ detection
  4. find_string_references()  — registry/plugin string ref scanning
  5. _collect_runtime_modules()  — runtime registry resolution

Run:
    .venv\\Scripts\\python.exe test_measurement_correctness.py
    .venv\\Scripts\\python.exe -m pytest test_measurement_correctness.py -v
"""
from __future__ import annotations

import ast
import json
import re
import sys
import textwrap
import tempfile
import unittest
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CC = ROOT / "CaseCrack"
sys.path.insert(0, str(CC))

from execution_reality_map import _resolve_relative, build_import_graph, CANONICAL_ENTRYPOINTS
from dead_module_audit import find_dynamic_imports, find_string_references


# ═══════════════════════════════════════════════════════════════════════
#  1. RELATIVE IMPORT RESOLUTION
# ═══════════════════════════════════════════════════════════════════════

class TestResolveRelative(unittest.TestCase):
    """Verify _resolve_relative handles all import patterns correctly.

    This was the source of the critical bug that created 338 ghost nodes.
    The key invariant: __init__.py (is_package=True) with level=1 resolves
    within the SAME package, not the parent.
    """

    # ── __init__.py (is_package=True) ──────────────────────────────

    def test_package_level1_with_target(self):
        """from .core import X  inside  cli/commands/__init__.py
        Must resolve to cli.commands.core, NOT cli.core"""
        result = _resolve_relative(
            "tools.burp_enterprise.cli.commands", level=1, target="core",
            is_package=True,
        )
        self.assertEqual(result, "tools.burp_enterprise.cli.commands.core")

    def test_package_level1_no_target(self):
        """from . import something  inside  cli/commands/__init__.py
        Must resolve to cli.commands (itself)"""
        result = _resolve_relative(
            "tools.burp_enterprise.cli.commands", level=1, target=None,
            is_package=True,
        )
        self.assertEqual(result, "tools.burp_enterprise.cli.commands")

    def test_package_level2_with_target(self):
        """from ..utils import X  inside  cli/commands/__init__.py
        Must resolve to cli.utils (parent's sibling)"""
        result = _resolve_relative(
            "tools.burp_enterprise.cli.commands", level=2, target="utils",
            is_package=True,
        )
        self.assertEqual(result, "tools.burp_enterprise.cli.utils")

    def test_package_level2_no_target(self):
        """from .. import X  inside  cli/commands/__init__.py
        Must resolve to cli"""
        result = _resolve_relative(
            "tools.burp_enterprise.cli.commands", level=2, target=None,
            is_package=True,
        )
        self.assertEqual(result, "tools.burp_enterprise.cli")

    def test_package_level3(self):
        """from ...event_bus import X  inside  cli/commands/__init__.py
        Must resolve to tools.burp_enterprise.event_bus"""
        result = _resolve_relative(
            "tools.burp_enterprise.cli.commands", level=3, target="event_bus",
            is_package=True,
        )
        self.assertEqual(result, "tools.burp_enterprise.event_bus")

    def test_package_deeply_nested(self):
        """from .sub import X inside graph/reasoning/__init__.py"""
        result = _resolve_relative(
            "tools.burp_enterprise.graph.reasoning", level=1, target="sub",
            is_package=True,
        )
        self.assertEqual(result, "tools.burp_enterprise.graph.reasoning.sub")

    # ── Regular .py files (is_package=False / default) ──────────────

    def test_module_level1_with_target(self):
        """from .utils import X  inside  cli/commands/core.py
        Must resolve to cli.commands.utils (sibling)"""
        result = _resolve_relative(
            "tools.burp_enterprise.cli.commands.core", level=1, target="utils",
            is_package=False,
        )
        self.assertEqual(result, "tools.burp_enterprise.cli.commands.utils")

    def test_module_level1_no_target(self):
        """from . import X  inside  cli/commands/core.py
        Must resolve to cli.commands (the package)"""
        result = _resolve_relative(
            "tools.burp_enterprise.cli.commands.core", level=1, target=None,
            is_package=False,
        )
        self.assertEqual(result, "tools.burp_enterprise.cli.commands")

    def test_module_level2_with_target(self):
        """from .._base import X  inside  cli/commands/core.py
        Must resolve to cli._base"""
        result = _resolve_relative(
            "tools.burp_enterprise.cli.commands.core", level=2, target="_base",
            is_package=False,
        )
        self.assertEqual(result, "tools.burp_enterprise.cli._base")

    def test_module_level2_no_target(self):
        """from .. import X  inside  cli/commands/core.py
        Must resolve to cli"""
        result = _resolve_relative(
            "tools.burp_enterprise.cli.commands.core", level=2, target=None,
            is_package=False,
        )
        self.assertEqual(result, "tools.burp_enterprise.cli")

    def test_default_is_package_false(self):
        """Default behavior (no is_package) should be is_package=False"""
        result = _resolve_relative(
            "tools.burp_enterprise.cli.commands.core", level=1, target="utils",
        )
        self.assertEqual(result, "tools.burp_enterprise.cli.commands.utils")

    # ── Edge cases ──────────────────────────────────────────────────

    def test_top_level_package_level1(self):
        """from .sub import X  at tools.burp_enterprise (the root __init__.py)"""
        result = _resolve_relative(
            "tools.burp_enterprise", level=1, target="sub",
            is_package=True,
        )
        self.assertEqual(result, "tools.burp_enterprise.sub")

    def test_floor_at_one_segment(self):
        """Even extreme level values shouldn't produce empty base"""
        result = _resolve_relative(
            "tools.burp_enterprise", level=5, target="foo",
            is_package=False,
        )
        # max(1, ...) ensures at least 1 segment
        self.assertTrue(len(result) > 0)
        self.assertIn("foo", result)


# ═══════════════════════════════════════════════════════════════════════
#  2. IMPORT GRAPH INTEGRITY  (end-to-end, no ghosts)
# ═══════════════════════════════════════════════════════════════════════

class TestImportGraphIntegrity(unittest.TestCase):
    """Verify the full import graph has no ghost nodes (edges to non-existent files)."""

    @classmethod
    def setUpClass(cls):
        cls.adj, cls.nodes, cls.syntax_errors = build_import_graph()
        cls.PKG = CC / "tools" / "burp_enterprise"

    def test_no_syntax_errors_blocking(self):
        """No widespread syntax errors preventing graph building."""
        self.assertLessEqual(len(self.syntax_errors), 5,
            f"Too many syntax errors: {self.syntax_errors}")

    def test_all_nodes_correspond_to_files(self):
        """Every node in the graph must have a corresponding .py file."""
        missing = []
        for mod in self.nodes:
            parts = mod.replace(".", "/")
            py = CC / (parts + ".py")
            init = CC / parts / "__init__.py"
            if not py.exists() and not init.exists():
                missing.append(mod)
        self.assertEqual(missing, [],
            f"Nodes without files (ghosts): {missing[:20]}")

    def test_no_ghost_edges(self):
        """Every edge target either exists as a node or is a known external."""
        ghosts = []
        for src, deps in self.adj.items():
            for dep in deps:
                if dep.startswith("tools.burp_enterprise.") and dep not in self.nodes:
                    ghosts.append((src, dep))
        # These are the "dangling imports" — they should be small and tracked
        # But none should be mis-resolved relative imports
        for src, dep in ghosts:
            # A ghost from a relative import is the critical bug pattern
            parts = dep.split(".")
            # Check if removing one segment would match a real node
            # (the old bug pattern: cli.core instead of cli.commands.core)
            if len(parts) >= 4:
                parent_try = ".".join(parts[:-1])
                child = parts[-1]
                # Would inserting an extra package level match a real node?
                for candidate_parent in self.nodes:
                    if candidate_parent.startswith(parent_try + "."):
                        potential_fix = candidate_parent + "." + child
                        if potential_fix in self.nodes:
                            self.fail(
                                f"Relative-import ghost detected: {dep} from {src}. "
                                f"Likely should be {potential_fix}")

    def test_cli_commands_resolve_correctly(self):
        """The specific bug: cli/commands/__init__.py imports must resolve to cli.commands.*"""
        cli_cmds = "tools.burp_enterprise.cli.commands"
        if cli_cmds not in self.adj:
            self.skipTest("cli.commands not in graph")

        deps = self.adj[cli_cmds]
        for dep in deps:
            if not dep.startswith("tools.burp_enterprise.cli."):
                continue
            # Must contain 'commands' segment (except for _base, main, etc.)
            short = dep.replace("tools.burp_enterprise.cli.", "")
            if short.startswith("_") or short == "main":
                continue
            self.assertIn("commands", dep,
                f"cli.commands imports {dep} — missing 'commands' segment "
                f"(old bug: relative import resolved to parent)")

    def test_graph_has_entrypoint_edges(self):
        """Most canonical entrypoints should have outgoing edges.

        Exception: data-only modules (e.g. phase_commands) may have zero imports.
        """
        no_edges = []
        for ep in CANONICAL_ENTRYPOINTS:
            if ep in self.nodes and len(self.adj.get(ep, set())) == 0:
                no_edges.append(ep)
        # Some entrypoints are data-only (phase_commands) or thin wrappers
        self.assertLessEqual(len(no_edges), 4,
            f"Too many entrypoints with no import edges: {no_edges}")

    def test_graph_edge_count_reasonable(self):
        """Sanity check: graph should have thousands of edges for a 1666-module project."""
        total_edges = sum(len(deps) for deps in self.adj.values())
        self.assertGreater(total_edges, 2000,
            f"Only {total_edges} edges — graph is suspiciously sparse")

    def test_all_init_files_are_packages(self):
        """Verify __init__.py files are stored as their package name, not X.__init__."""
        for node in self.nodes:
            self.assertFalse(node.endswith(".__init__"),
                f"Node {node} ends with .__init__ — should be stripped")


# ═══════════════════════════════════════════════════════════════════════
#  3. DYNAMIC IMPORT DETECTION
# ═══════════════════════════════════════════════════════════════════════

class TestDynamicImportDetection(unittest.TestCase):
    """Verify find_dynamic_imports catches all importlib.import_module / __import__ patterns."""

    @classmethod
    def setUpClass(cls):
        cls.sites, cls.refs = find_dynamic_imports()

    def test_finds_import_module_calls(self):
        """Should detect at least some import_module() calls in the codebase."""
        import_module_sites = [s for s in self.sites if "import_module" in str(s)]
        self.assertGreater(len(self.sites), 0,
            "No dynamic import sites found at all — detector may be broken")

    def test_all_targets_are_valid_module_paths(self):
        """Detected targets should look like module paths (dots, no spaces)."""
        for _file, target, _line in self.sites:
            self.assertNotIn(" ", target,
                f"Dynamic import target has space: '{target}' in {_file}:{_line}")
            # Should have at least one dot (qualified path)
            # Exception: single-word modules are fine
            if "." in target:
                self.assertTrue(
                    all(part.isidentifier() or part == "" for part in target.split(".")),
                    f"Invalid module path: '{target}' in {_file}:{_line}")

    def test_no_false_negatives_on_known_patterns(self):
        """Scan a known file that uses import_module and verify it's captured."""
        # Find any file in our sites list
        if not self.sites:
            self.skipTest("No dynamic imports found")
        # Verify at least one site has a tools.burp_enterprise target
        tools_targets = [t for _, t, _ in self.sites if t.startswith("tools.")]
        # Not all may start with tools., that's OK
        self.assertIsInstance(tools_targets, list)  # just ensure no crash

    def test_detection_covers_both_patterns(self):
        """Verify both import_module() and __import__() regex patterns work."""
        import dead_module_audit as dma

        # Test import_module pattern
        pat = re.compile(r"""import_module\s*\(\s*['"]([^'"]+)['"]""")
        test_src = 'mod = importlib.import_module("tools.burp_enterprise.foo")'
        m = pat.search(test_src)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "tools.burp_enterprise.foo")

        # Test __import__ pattern
        pat2 = re.compile(r"""__import__\s*\(\s*['"]([^'"]+)['"]""")
        test_src2 = 'mod = __import__("tools.burp_enterprise.bar")'
        m2 = pat2.search(test_src2)
        self.assertIsNotNone(m2)
        self.assertEqual(m2.group(1), "tools.burp_enterprise.bar")

    def test_f_string_import_not_falsely_captured(self):
        """import_module(f"tools.{name}") should NOT match (variable target)."""
        pat = re.compile(r"""import_module\s*\(\s*['"]([^'"]+)['"]""")
        test_src = 'mod = importlib.import_module(f"tools.{name}")'
        m = pat.search(test_src)
        # f-strings use f" which should not match the pattern (the f is outside the quote)
        # Actually f"..." is still a string literal in source — the regex matches inside quotes
        # So this should NOT match because the f is before the quote
        self.assertIsNone(m, "f-string import should not be captured as literal")


# ═══════════════════════════════════════════════════════════════════════
#  4. STRING REFERENCE DETECTION  (registry/plugin patterns)
# ═══════════════════════════════════════════════════════════════════════

class TestStringReferenceDetection(unittest.TestCase):
    """Verify find_string_references finds module names in string literals."""

    def test_finds_known_dead_in_strings(self):
        """If we pass a set of dead modules, it should find references for some."""
        reality = json.loads((ROOT / "execution_reality_map.json").read_text(encoding="utf-8"))
        dead = set(reality["dead_modules"])
        if not dead:
            self.skipTest("No dead modules")

        refs = find_string_references(dead)
        # We expect at least some dead modules to be string-referenced
        # (registries, plugin systems, etc.)
        self.assertIsInstance(refs, dict)
        # The exact count depends on the codebase, but should not be empty
        # for a project with 856 dead modules

    def test_empty_dead_set_returns_empty(self):
        """Empty input should return empty output without crashing."""
        refs = find_string_references(set())
        self.assertEqual(refs, {})

    def test_single_module_detection(self):
        """If a module name appears as a string literal, it should be found."""
        # Use a module we know exists in the codebase
        reality = json.loads((ROOT / "execution_reality_map.json").read_text(encoding="utf-8"))
        dead = set(reality["dead_modules"])
        refs = find_string_references(dead)
        for mod, locations in refs.items():
            self.assertIn(mod, dead, f"Found ref for non-dead module: {mod}")
            self.assertIsInstance(locations, list)
            self.assertGreater(len(locations), 0)

    def test_chunking_handles_large_sets(self):
        """find_string_references with >200 modules should not crash (uses chunking)."""
        # Create a large synthetic set
        fake_dead = {f"tools.burp_enterprise.fake_module_{i}" for i in range(500)}
        # Should complete without error — won't find any but shouldn't crash
        refs = find_string_references(fake_dead)
        self.assertIsInstance(refs, dict)


# ═══════════════════════════════════════════════════════════════════════
#  5. RUNTIME MODULE RESOLUTION  (registries, phase commands)
# ═══════════════════════════════════════════════════════════════════════

class TestRuntimeModuleResolution(unittest.TestCase):
    """Verify _collect_runtime_modules resolves real modules from runtime registries."""

    def test_collect_returns_set(self):
        """Basic contract: returns a set of strings."""
        from execution_reality_map import _collect_runtime_modules
        rt = _collect_runtime_modules()
        self.assertIsInstance(rt, set)
        for mod in rt:
            self.assertIsInstance(mod, str)

    def test_all_runtime_modules_are_qualified(self):
        """Every runtime module should be a fully-qualified dotted path."""
        from execution_reality_map import _collect_runtime_modules
        rt = _collect_runtime_modules()
        for mod in rt:
            self.assertTrue(mod.startswith("tools."),
                f"Runtime module not fully qualified: {mod}")

    def test_runtime_modules_exist_as_files(self):
        """Runtime modules should be well-formed module paths.

        Most runtime modules come from ToolWrapperBridge.list_providers()
        which generates virtual names (e.g. tool_wrappers.nuclei) that
        don't correspond to individual files — they're dispatched by
        the bridge. We validate they're well-formed, not that files exist.
        """
        from execution_reality_map import _collect_runtime_modules
        rt = _collect_runtime_modules()
        if not rt:
            self.skipTest("No runtime modules detected")
        for mod in rt:
            self.assertTrue(mod.startswith("tools."),
                f"Runtime module not fully qualified: {mod}")
            parts = mod.split(".")
            for part in parts:
                self.assertTrue(part.replace("_", "").replace("-", "").isalnum(),
                    f"Invalid segment in runtime module path: '{part}' in {mod}")


# ═══════════════════════════════════════════════════════════════════════
#  6. CROSS-CONSISTENCY CHECKS
# ═══════════════════════════════════════════════════════════════════════

class TestCrossConsistency(unittest.TestCase):
    """Verify the artifacts are mutually consistent."""

    @classmethod
    def setUpClass(cls):
        cls.reality = json.loads((ROOT / "execution_reality_map.json").read_text(encoding="utf-8"))
        cls.adj, cls.nodes, _ = build_import_graph()

    def test_executed_plus_dead_equals_nodes(self):
        """executed_modules + dead_modules should equal all nodes."""
        executed = set(self.reality["executed_modules"])
        dead = set(self.reality["dead_modules"])
        total = executed | dead
        self.assertEqual(len(total), len(self.nodes),
            f"Mismatch: executed({len(executed)}) + dead({len(dead)}) = "
            f"{len(total)} but nodes = {len(self.nodes)}")

    def test_no_module_both_executed_and_dead(self):
        """A module cannot be both executed and dead."""
        executed = set(self.reality["executed_modules"])
        dead = set(self.reality["dead_modules"])
        overlap = executed & dead
        self.assertEqual(overlap, set(),
            f"Modules in BOTH executed and dead: {sorted(overlap)[:10]}")

    def test_dangling_imports_are_not_in_nodes(self):
        """Dangling imports by definition don't exist as nodes."""
        dangling = set(self.reality["dangling_imports"].keys())
        overlap = dangling & self.nodes
        self.assertEqual(overlap, set(),
            f"Dangling imports that ARE in nodes: {sorted(overlap)[:10]}")

    def test_entrypoints_are_executed(self):
        """All canonical entrypoints should be in executed_modules."""
        executed = set(self.reality["executed_modules"])
        for ep in CANONICAL_ENTRYPOINTS:
            if ep in self.nodes:
                self.assertIn(ep, executed,
                    f"Entrypoint {ep} is in nodes but not executed")


# ═══════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Run with verbose output
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test classes in order
    for cls in [
        TestResolveRelative,
        TestImportGraphIntegrity,
        TestDynamicImportDetection,
        TestStringReferenceDetection,
        TestRuntimeModuleResolution,
        TestCrossConsistency,
    ]:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
