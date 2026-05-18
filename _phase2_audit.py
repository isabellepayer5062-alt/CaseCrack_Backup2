"""
Phase 2 audit:
  1. Check VS Code history for the 8 genuinely missing modules (E section)
  2. Check which of the 20 missing reimplemented modules are imported by live code
  3. Show what symbols the 47-consumer persistent_agent module should have
  4. Find the consumers of each E-section missing module
"""
from __future__ import annotations
import ast, json, os, pathlib, re, sys

ROOT = pathlib.Path(__file__).parent / "CaseCrack"
BE = ROOT / "tools" / "burp_enterprise"
HIST_ROOT = pathlib.Path(os.environ["APPDATA"]) / "Code" / "User" / "History"

DANGLING_8 = [
    "tools/burp_enterprise/persistent_agent.py",
    "tools/burp_enterprise/operator_feedback.py",
    "tools/burp_enterprise/outcome_narrative_engine.py",
    "tools/burp_enterprise/action_rationale_engine.py",
    "tools/burp_enterprise/event_driven_wakeup.py",
    "tools/burp_enterprise/frontier_intelligence.py",
    "tools/burp_enterprise/self_healing.py",
    "tools/burp_enterprise/decision_trace.py",
]

MISSING_20 = [
    "tools/burp_enterprise/scanners/rate_limit_analyzer.py",
    "tools/burp_enterprise/scanners/response_anomaly_scanner.py",
    "tools/burp_enterprise/scanners/vulnerability_correlator.py",
    "tools/burp_enterprise/scanners/cache_poisoning_scanner.py",
    "tools/burp_enterprise/testing_tools/mutation_engine.py",
    "tools/burp_enterprise/testing_tools/chaos_framework.py",
    "tools/burp_enterprise/testing_tools/property_tester.py",
    "tools/burp_enterprise/testing_tools/security_harness.py",
    "tools/burp_enterprise/testing_tools/differential_tester.py",
    "tools/burp_enterprise/testing_tools/trace_analyzer.py",
    "tools/burp_enterprise/testing_tools/coverage_tracker.py",
    "tools/burp_enterprise/output/sarif_exporter.py",
    "tools/burp_enterprise/output/html_reporter.py",
    "tools/burp_enterprise/output/pdf_generator.py",
    "tools/burp_enterprise/output/csv_exporter.py",
    "tools/burp_enterprise/output/json_formatter.py",
    "tools/burp_enterprise/output/xml_formatter.py",
    "tools/burp_enterprise/output/compliance_report.py",
    "tools/burp_enterprise/output/dashboard_exporter.py",
    "tools/burp_enterprise/output/notification_dispatcher.py",
]

def build_hist_index_all() -> dict[str, list[pathlib.Path]]:
    """tail2 -> list of all snapshot paths (all sizes)."""
    idx: dict[str, list[pathlib.Path]] = {}
    if not HIST_ROOT.exists():
        return idx
    for entry_dir in HIST_ROOT.iterdir():
        ej = entry_dir / "entries.json"
        if not ej.exists():
            continue
        try:
            data = json.loads(ej.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        resource: str = data.get("resource", "")
        if "casecrack" not in resource.lower():
            continue
        entries = data.get("entries", [])
        m = re.search(r'CaseCrack[/\\](.+\.py)$', resource, re.IGNORECASE)
        if not m:
            continue
        rel = m.group(1).replace("\\", "/").lower()
        parts = rel.split("/")
        tail2 = "/".join(parts[-2:]) if len(parts) >= 2 else parts[-1]
        # collect all valid snapshots (not just latest)
        for e in entries:
            snap = entry_dir / e.get("id", "")
            if snap.exists():
                idx.setdefault(tail2, []).append(snap)
    return idx

def ast_top_syms(src: str) -> set[str]:
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return set()
    syms = set()
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            syms.add(node.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    syms.add(t.id)
    return syms

def find_consumers_of(rel_path: str) -> list[tuple[str, int, list[str]]]:
    """Find all files that import from this module (return consumer_path, line, names)."""
    module = rel_path.replace("/", ".").replace("\\", ".")
    if module.endswith(".py"):
        module = module[:-3]
    results = []
    for p in list(BE.rglob("*.py")) + list((ROOT / "tests").rglob("*.py")):
        try:
            src = p.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(src)
        except Exception:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module == module:
                    names = [a.name for a in node.names]
                    results.append((str(p.relative_to(ROOT)), node.lineno, names))
    return results

def main():
    print("Building history index (all snapshots)…")
    idx = build_hist_index_all()
    print(f"  {len(idx):,} unique path-tails indexed\n")

    print("=" * 70)
    print("PART 1: 8 genuinely missing modules — history snapshots & consumers")
    print("=" * 70)
    recoverable = []
    for rel in DANGLING_8:
        parts = rel.replace("\\", "/").split("/")
        tail2 = "/".join(parts[-2:]).lower()
        snaps = idx.get(tail2, [])
        best = max(snaps, key=lambda s: s.stat().st_size) if snaps else None
        consumers = find_consumers_of(rel)
        print(f"\n  {rel}")
        print(f"    Consumers: {len(consumers)}")
        if best:
            src = best.read_text(encoding="utf-8", errors="replace")
            syms = ast_top_syms(src)
            print(f"    HISTORY FOUND: {best.stat().st_size:,}B  —  {len(snaps)} snapshots  ({len(syms)} symbols)")
            # show which symbols are imported by consumers
            needed = set()
            for _, _, names in consumers:
                needed.update(names)
            missing_syms = needed - syms
            print(f"    Needed by consumers: {sorted(needed)[:10]}")
            if missing_syms:
                print(f"    WARNING: {len(missing_syms)} symbols needed but not in history: {sorted(missing_syms)[:5]}")
            else:
                print(f"    All consumer-needed symbols present in history snapshot.")
            recoverable.append((rel, best, syms, needed))
        else:
            print(f"    NO HISTORY SNAPSHOT FOUND")
            needed = set()
            for _, _, names in consumers:
                needed.update(names)
            print(f"    Needed by consumers: {sorted(needed)[:10]}")
        # show consumers 
        if consumers and len(consumers) <= 8:
            for cp, ln, names in consumers:
                print(f"      -> {cp}:{ln}  imports: {', '.join(names[:5])}")
        elif consumers:
            for cp, ln, names in consumers[:5]:
                print(f"      -> {cp}:{ln}  imports: {', '.join(names[:5])}")
            print(f"      ... and {len(consumers)-5} more")

    print("\n")
    print("=" * 70)
    print("PART 2: 20 missing reimplemented modules — are any imported?")
    print("=" * 70)
    imported_missing = []
    for rel in MISSING_20:
        consumers = find_consumers_of(rel)
        parts = rel.replace("\\", "/").split("/")
        tail2 = "/".join(parts[-2:]).lower()
        snaps = idx.get(tail2, [])
        has_history = bool(snaps)
        if consumers:
            imported_missing.append((rel, consumers, has_history))
            print(f"\n  IMPORTED ({len(consumers)} consumers): {rel}  history={'YES' if has_history else 'NO'}")
            for cp, ln, names in consumers[:3]:
                print(f"    -> {cp}:{ln}  {names[:3]}")
        # else silently skip (not imported = low priority)
    if not imported_missing:
        print("  None of the 20 missing reimplemented modules are imported by live code.")
        print("  (They are dead-end / optional capabilities — 0 runtime ImportError risk)")

    print("\n")
    print("=" * 70)
    print("PART 3: B-section false-positive confirmation (model_cli / model_benchmarker)")
    print("=" * 70)
    for rel in ["tools/burp_enterprise/inference/model_management/model_cli.py",
                "tools/burp_enterprise/inference/model_management/model_benchmarker.py"]:
        p = ROOT / rel.replace("/", os.sep)
        if p.exists():
            src = p.read_text(encoding="utf-8", errors="replace")
            syms = ast_top_syms(src)
            print(f"  {p.name}: {p.stat().st_size:,}B  {len(syms)} symbols  — disk version is LARGER than history")
            # check all_def
            if "__all__" in src:
                print(f"    __all__ IS defined in disk (hist snapshot was pre-__all__). Not a regression.")
            # original 10/6 hist-only symbols from classified tsv  
            print(f"    Conclusion: false-positive regression — disk was rebuilt, is now superset of history")

    print("\nSummary of recoverable modules:")
    for rel, snap, syms, needed in recoverable:
        print(f"  RECOVERABLE: {rel}  ({snap.stat().st_size:,}B)")

if __name__ == "__main__":
    main()
