"""
Comprehensive final audit — 2026-04-21
Checks:
  A. Still-missing production modules (exist in history, absent from disk, any live imports)
  B. 8 PURE_REGRESSION files: compare disk vs best history snapshot
  C. 42 REFACTORED files: flag "rough reimplementation" candidates (disk << history, many hist-only symbols)
  D. 53 reimplemented modules: verify health (LOC, hardening markers, importability)
  E. Full-tree dangling import scan: catch any new ImportError-class symbols
Outputs: _comprehensive_final_report.tsv  +  printed summary
"""
from __future__ import annotations
import ast, hashlib, json, os, pathlib, re, sys, textwrap
from typing import NamedTuple

ROOT = pathlib.Path(__file__).parent / "CaseCrack"
BE = ROOT / "tools" / "burp_enterprise"
TESTS = ROOT / "tests"
HIST_ROOT = pathlib.Path(os.environ["APPDATA"]) / "Code" / "User" / "History"

# ── helpers ────────────────────────────────────────────────────────────────────

def sha256(p: pathlib.Path) -> str:
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return h.hexdigest()

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
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            pass  # not top-level defs
    return syms

def build_hist_index() -> dict[str, pathlib.Path]:
    """path-tail (last2) -> latest snapshot path"""
    idx: dict[str, pathlib.Path] = {}
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
        if "CaseCrack" not in resource and "caseCrack" not in resource:
            # also allow case-insensitive 
            if "casecrack" not in resource.lower():
                continue
        entries = data.get("entries", [])
        if not entries:
            continue
        latest_id = entries[-1].get("id", "")
        snap = entry_dir / latest_id
        if not snap.exists():
            continue
        # extract path tail from resource
        # resource looks like file:///c:/Users/.../CaseCrack/tools/burp_enterprise/...
        m = re.search(r'CaseCrack[/\\](.+\.py)$', resource, re.IGNORECASE)
        if not m:
            continue
        rel = m.group(1).replace("\\", "/").lower()
        parts = rel.split("/")
        if len(parts) >= 2:
            tail2 = "/".join(parts[-2:])
        else:
            tail2 = parts[-1]
        # store best (largest) snapshot per tail2
        if tail2 not in idx or snap.stat().st_size > idx[tail2].stat().st_size:
            idx[tail2] = snap
    return idx

def hist_snap_for(disk_path: pathlib.Path, idx: dict) -> pathlib.Path | None:
    rel = disk_path.relative_to(ROOT).as_posix().lower()
    parts = rel.split("/")
    tail2 = "/".join(parts[-2:]) if len(parts) >= 2 else parts[-1]
    return idx.get(tail2)

# ── Section A: missing production modules ─────────────────────────────────────

def scan_missing(hist_idx: dict) -> list[dict]:
    """Find all tools/burp_enterprise + tests .py files absent from disk but in history."""
    # walk history index for CaseCrack paths
    results = []
    for tail2, snap in hist_idx.items():
        # reconstruct disk path
        # tail2 is like "tools/burp_enterprise/foo.py" (already lowercased)
        # We need to find the real capitalisation — use a glob
        # For now, check if CaseCrack/tail2 exists (case-insensitive on Windows)
        candidate = ROOT / tail2.replace("/", os.sep)
        if candidate.exists():
            continue
        # Only care about production code (not temp scripts, ctemp, audit scripts)
        skip_patterns = ["ctemp/", "_audit_", "_fix_", "_final_", "_build_",
                         "_check_", "_inject_", "_extract_", "_verify_",
                         "_cascade_", "_execute_", "_exhaustive_", "_expand_",
                         "_merge_", "_compare_", "_convergence_", "_correct_",
                         "_hist_server", "_sibling_", "_comprehensive_",
                         "_apply_", "_migrate_", "_skip_", "_assess_",
                         "_deep_", "_find_", "_recover", "_restore",
                         "ctemp/", "static/"]
        skip = False
        for pat in skip_patterns:
            if pat in tail2:
                skip = True
                break
        if skip:
            continue
        if not (tail2.startswith("tools/burp_enterprise") or tail2.startswith("tests/")):
            continue
        # check refs
        snap_size = snap.stat().st_size
        results.append({"tail2": tail2, "snap_size": snap_size, "snap": str(snap)})
    return results

# ── Section B: PURE_REGRESSION files ─────────────────────────────────────────

PURE_REGRESSIONS = [
    BE / "decision_orchestrator.py",
    BE / "inference/model_management/model_cli.py",
    BE / "inference/model_management/model_benchmarker.py",
    TESTS / "test_organism_health_gaps.py",
    BE / "intel/github_client_base.py",
    BE / "output/findings_formatter.py",
    BE / "mcp/mcp_server.py",
    BE / "agents/bayesian_prioritizer.py",
]

def audit_regressions(hist_idx: dict) -> list[dict]:
    results = []
    for disk_p in PURE_REGRESSIONS:
        if not disk_p.exists():
            results.append({"path": str(disk_p.relative_to(ROOT)), "status": "MISSING_FROM_DISK",
                           "disk_size": 0, "hist_size": 0, "hist_only": [], "note": ""})
            continue
        snap = hist_snap_for(disk_p, hist_idx)
        if not snap:
            results.append({"path": str(disk_p.relative_to(ROOT)), "status": "NO_HISTORY",
                           "disk_size": disk_p.stat().st_size, "hist_size": 0, "hist_only": [], "note": ""})
            continue
        disk_src = disk_p.read_text(encoding="utf-8", errors="replace")
        hist_src = snap.read_text(encoding="utf-8", errors="replace")
        disk_syms = ast_top_syms(disk_src)
        hist_syms = ast_top_syms(hist_src)
        hist_only = sorted(hist_syms - disk_syms)
        disk_size = disk_p.stat().st_size
        hist_size = snap.stat().st_size
        ratio = disk_size / hist_size if hist_size else 1.0
        status = "OK" if not hist_only else "REGRESSION"
        results.append({
            "path": str(disk_p.relative_to(ROOT)),
            "status": status,
            "disk_size": disk_size,
            "hist_size": hist_size,
            "ratio": round(ratio, 3),
            "hist_only": hist_only,
            "snap": str(snap),
        })
    return results

# ── Section C: REFACTORED files — identify rough reimplementations ─────────────

def audit_refactored(hist_idx: dict) -> list[dict]:
    """Read _final_audit_coverage_tight.tsv, check REFACTORED rows."""
    tsv = pathlib.Path(__file__).parent / "_final_audit_coverage_tight.tsv"
    if not tsv.exists():
        return []
    results = []
    for line in tsv.read_text(encoding="utf-8", errors="replace").splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) < 6 or parts[0] != "REFACTORED":
            continue
        only_hist = int(parts[1])
        only_disk = int(parts[2])
        disk_size = int(parts[3])
        hist_size = int(parts[4])
        rel_path = parts[5]  # relative path
        snap_path = parts[6] if len(parts) > 6 else ""
        ratio = disk_size / hist_size if hist_size else 1.0
        # "rough reimplementation" = disk is small fraction of history AND many hist-only symbols
        is_rough = ratio < 0.5 and only_hist >= 10
        disk_p = ROOT / rel_path.replace("\\", "/")
        if not disk_p.exists():
            status = "MISSING"
        elif is_rough:
            status = "ROUGH_REIMPLEMENT"
        elif ratio < 0.7 and only_hist >= 5:
            status = "PARTIAL"
        else:
            status = "ACCEPTABLE"
        results.append({
            "path": rel_path,
            "status": status,
            "disk_size": disk_size,
            "hist_size": hist_size,
            "ratio": round(ratio, 3),
            "only_hist": only_hist,
            "only_disk": only_disk,
            "snap": snap_path,
        })
    return sorted(results, key=lambda r: r["ratio"])

# ── Section D: reimplemented modules health check ─────────────────────────────

REIMPLEMENTED_MODULES = [
    # Tier 2 network
    "tools/burp_enterprise/network/dns_resolver.py",
    "tools/burp_enterprise/network/http_fingerprint.py",
    "tools/burp_enterprise/network/proxy_chain.py",
    "tools/burp_enterprise/network/ssl_analyzer.py",
    "tools/burp_enterprise/network/traffic_analyzer.py",
    # Tier 2 integrations
    "tools/burp_enterprise/integrations/ci_cd_pipeline.py",
    "tools/burp_enterprise/integrations/defect_dojo.py",
    "tools/burp_enterprise/integrations/jira_client.py",
    "tools/burp_enterprise/integrations/slack_notifier.py",
    "tools/burp_enterprise/integrations/sonarqube.py",
    "tools/burp_enterprise/integrations/webhook_dispatcher.py",
    # CAAP
    "tools/burp_enterprise/caap/caap_coordinator.py",
    "tools/burp_enterprise/caap/chat_interface.py",
    "tools/burp_enterprise/caap/compliance_checker.py",
    "tools/burp_enterprise/caap/discovery_agent.py",
    "tools/burp_enterprise/caap/exploitation_agent.py",
    "tools/burp_enterprise/caap/hypothesis_engine.py",
    "tools/burp_enterprise/caap/knowledge_graph.py",
    "tools/burp_enterprise/caap/recon_agent.py",
    "tools/burp_enterprise/caap/session_orchestrator.py",
    # testing_tools
    "tools/burp_enterprise/testing_tools/api_fuzzer.py",
    "tools/burp_enterprise/testing_tools/benchmark_runner.py",
    "tools/burp_enterprise/testing_tools/compliance_validator.py",
    "tools/burp_enterprise/testing_tools/integration_harness.py",
    "tools/burp_enterprise/testing_tools/load_tester.py",
    "tools/burp_enterprise/testing_tools/mock_server.py",
    "tools/burp_enterprise/testing_tools/regression_tracker.py",
    # Sprint 4 scanners
    "tools/burp_enterprise/scanners/timing_attack_scanner.py",
    "tools/burp_enterprise/scanners/rate_limit_analyzer.py",
    "tools/burp_enterprise/scanners/response_anomaly_scanner.py",
    "tools/burp_enterprise/scanners/vulnerability_correlator.py",
    "tools/burp_enterprise/scanners/cache_poisoning_scanner.py",
    # Sprint 5 testing_tools upgrades
    "tools/burp_enterprise/testing_tools/mutation_engine.py",
    "tools/burp_enterprise/testing_tools/chaos_framework.py",
    "tools/burp_enterprise/testing_tools/property_tester.py",
    "tools/burp_enterprise/testing_tools/security_harness.py",
    "tools/burp_enterprise/testing_tools/differential_tester.py",
    "tools/burp_enterprise/testing_tools/trace_analyzer.py",
    "tools/burp_enterprise/testing_tools/coverage_tracker.py",
    # Sprint 6 output
    "tools/burp_enterprise/output/cvss_calculator.py",
    "tools/burp_enterprise/output/sarif_exporter.py",
    "tools/burp_enterprise/output/html_reporter.py",
    "tools/burp_enterprise/output/pdf_generator.py",
    "tools/burp_enterprise/output/csv_exporter.py",
    "tools/burp_enterprise/output/json_formatter.py",
    "tools/burp_enterprise/output/xml_formatter.py",
    "tools/burp_enterprise/output/executive_summary.py",
    "tools/burp_enterprise/output/compliance_report.py",
    "tools/burp_enterprise/output/dashboard_exporter.py",
    "tools/burp_enterprise/output/notification_dispatcher.py",
]

HARDENING_MARKERS = [
    "__EVENTBUS_INJECTED__",
    "__TIER2_HELPERS_INJECTED__",
    "__TIER4A_ERRORS__",
    "__TIER2_INSTRUMENTED__",
]

def audit_reimplemented(hist_idx: dict) -> list[dict]:
    results = []
    for rel in REIMPLEMENTED_MODULES:
        p = ROOT / rel.replace("/", os.sep)
        if not p.exists():
            results.append({"path": rel, "status": "MISSING", "loc": 0, "markers": [], "snap_larger": False})
            continue
        src = p.read_text(encoding="utf-8", errors="replace")
        loc = len([l for l in src.splitlines() if l.strip()])
        markers_found = [m for m in HARDENING_MARKERS if m in src]
        # check if there's a better history snapshot
        snap = hist_snap_for(p, hist_idx)
        snap_larger = snap and snap.stat().st_size > p.stat().st_size * 1.2
        status = "OK"
        if loc < 20:
            status = "STUB"
        elif len(markers_found) < 3:
            status = "PARTIAL_HARDENING"
        elif snap_larger:
            status = "HISTORY_LARGER"
        results.append({
            "path": rel,
            "status": status,
            "loc": loc,
            "markers": markers_found,
            "snap_larger": snap_larger,
            "snap": str(snap) if snap else "",
        })
    return results

# ── Section E: dangling imports scan ─────────────────────────────────────────

def scan_dangling_imports() -> list[dict]:
    """Find from tools.burp_enterprise.X import Y where X doesn't exist on disk."""
    results = []
    for p in list(BE.rglob("*.py")) + list(TESTS.rglob("*.py")):
        try:
            src = p.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(src)
        except (SyntaxError, OSError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            module = node.module or ""
            if not module.startswith("tools.burp_enterprise"):
                continue
            # Convert dotted module name to path under ROOT (CaseCrack/)
            mod_path = ROOT / module.replace(".", "/")
            mod_file = mod_path.with_suffix(".py")
            mod_pkg = mod_path / "__init__.py"
            if mod_file.exists() or mod_pkg.exists():
                continue
            # module is missing — skip if inside try/except block (guarded import)
            # Simple heuristic: check if wrapped in try block by inspecting parent nodes
            names = [alias.name for alias in node.names]
            results.append({
                "consumer": str(p.relative_to(ROOT)),
                "missing_module": module,
                "names": names,
                "line": node.lineno,
            })
    return results

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print("Building VS Code history index…")
    hist_idx = build_hist_index()
    print(f"  {len(hist_idx):,} history snapshots indexed by path-tail")

    print("\n── A: Missing production modules ──")
    missing = scan_missing(hist_idx)
    prod_missing = [m for m in missing if "tests/" not in m["tail2"]]
    test_missing = [m for m in missing if "tests/" in m["tail2"]]
    print(f"  tools/burp_enterprise: {len(prod_missing)} absent from disk, have history snapshots")
    print(f"  tests/: {len(test_missing)} absent from disk, have history snapshots")
    if prod_missing:
        print("  Top production missing (by snapshot size):")
        for m in sorted(prod_missing, key=lambda x: -x["snap_size"])[:15]:
            print(f"    {m['snap_size']:>8,}B  {m['tail2']}")

    print("\n── B: PURE_REGRESSION files ──")
    regressions = audit_regressions(hist_idx)
    for r in regressions:
        syms_preview = ", ".join(r.get("hist_only", [])[:5])
        if len(r.get("hist_only", [])) > 5:
            syms_preview += f"… +{len(r['hist_only'])-5} more"
        print(f"  [{r['status']:12}] {r['path']}")
        if r.get("hist_only"):
            print(f"               disk={r['disk_size']:,}B  hist={r['hist_size']:,}B  ratio={r.get('ratio','?')}")
            print(f"               hist-only: {syms_preview}")

    print("\n── C: REFACTORED files — rough reimplementations ──")
    refactored = audit_refactored(hist_idx)
    rough = [r for r in refactored if r["status"] in ("ROUGH_REIMPLEMENT", "PARTIAL")]
    print(f"  {len(rough)} potential rough reimplementations (out of {len(refactored)} REFACTORED files)")
    for r in rough:
        print(f"  [{r['status']:18}] ratio={r['ratio']:.2f}  hist_only={r['only_hist']}  {r['path']}")

    print("\n── D: Reimplemented modules health ──")
    reimplem = audit_reimplemented(hist_idx)
    missing_re = [r for r in reimplem if r["status"] == "MISSING"]
    stubs = [r for r in reimplem if r["status"] == "STUB"]
    partial_hard = [r for r in reimplem if r["status"] == "PARTIAL_HARDENING"]
    hist_larger = [r for r in reimplem if r["status"] == "HISTORY_LARGER"]
    ok = [r for r in reimplem if r["status"] == "OK"]
    print(f"  OK: {len(ok)}  HistoryLarger: {len(hist_larger)}  PartialHardening: {len(partial_hard)}  Stub: {len(stubs)}  Missing: {len(missing_re)}")
    if missing_re:
        print("  MISSING reimplemented modules:")
        for r in missing_re: print(f"    {r['path']}")
    if stubs:
        print("  STUB (< 20 LOC):")
        for r in stubs: print(f"    {r['path']}")
    if hist_larger:
        print("  HISTORY_LARGER (might be better version in history):")
        for r in hist_larger:
            print(f"    {r['path']}  snap={r['snap']}")

    print("\n── E: Dangling imports scan ──")
    dangling = scan_dangling_imports()
    # deduplicate by missing_module
    by_mod: dict[str, list] = {}
    for d in dangling:
        by_mod.setdefault(d["missing_module"], []).append(d)
    print(f"  {len(by_mod)} unique missing modules referenced by imports:")
    for mod, consumers in sorted(by_mod.items(), key=lambda x: -len(x[1]))[:20]:
        print(f"    {len(consumers):2} consumers: {mod}")

    # ── Write TSV report ──
    report_path = pathlib.Path(__file__).parent / "_comprehensive_final_report.tsv"
    with report_path.open("w", encoding="utf-8") as f:
        f.write("section\tstatus\tpath\tdisk_size\thist_size\tratio\tnotes\n")
        for r in prod_missing:
            f.write(f"A_MISSING\tMISSING\t{r['tail2']}\t0\t{r['snap_size']}\t0\t\n")
        for r in regressions:
            notes = "|".join(r.get("hist_only", [])[:10])
            f.write(f"B_REGRESSION\t{r['status']}\t{r['path']}\t{r.get('disk_size',0)}\t{r.get('hist_size',0)}\t{r.get('ratio','')}\t{notes}\n")
        for r in refactored:
            f.write(f"C_REFACTORED\t{r['status']}\t{r['path']}\t{r['disk_size']}\t{r['hist_size']}\t{r['ratio']}\tonly_hist={r['only_hist']}\n")
        for r in reimplem:
            f.write(f"D_REIMPLEM\t{r['status']}\t{r['path']}\t{r['loc']}\t0\t\t\n")
        for mod, consumers in by_mod.items():
            f.write(f"E_DANGLING\tDANGLING\t{mod}\t0\t0\t\t{len(consumers)} consumers\n")

    print(f"\nReport written: {report_path}")
    print("\n=== SUMMARY ===")
    print(f"  A. Missing prod modules with history snapshots: {len(prod_missing)}")
    print(f"  B. Pure regression files still needing restore: {sum(1 for r in regressions if r['status']=='REGRESSION')}")
    print(f"  C. Rough reimplementations (< 50% hist size, many missing syms): {sum(1 for r in refactored if r['status']=='ROUGH_REIMPLEMENT')}")
    print(f"  D. Reimplemented modules with issues: {len(missing_re)+len(stubs)+len(partial_hard)+len(hist_larger)}")
    print(f"  E. Unique missing modules referenced by dangling imports: {len(by_mod)}")

if __name__ == "__main__":
    main()
