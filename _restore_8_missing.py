"""
Restore 8 genuinely missing modules from VS Code history.
All 8 have confirmed history snapshots with all consumer-needed symbols present.

Modules to restore:
  1. persistent_agent.py          — 117KB, 47 consumers
  2. operator_feedback.py         — 15KB,  5 consumers
  3. outcome_narrative_engine.py  — 22KB,  3 consumers
  4. action_rationale_engine.py   — 19KB,  2 consumers
  5. event_driven_wakeup.py       — 39KB,  2 consumers
  6. frontier_intelligence.py     — 48KB,  1 consumer
  7. self_healing.py              — 68KB,  1 consumer
  8. decision_trace.py            — 44KB,  4 snapshots, 1 consumer
"""
from __future__ import annotations
import ast, json, os, pathlib, re, shutil

ROOT = pathlib.Path(__file__).parent / "CaseCrack"
BE = ROOT / "tools" / "burp_enterprise"
HIST_ROOT = pathlib.Path(os.environ["APPDATA"]) / "Code" / "User" / "History"

TARGETS = [
    "tools/burp_enterprise/persistent_agent.py",
    "tools/burp_enterprise/operator_feedback.py",
    "tools/burp_enterprise/outcome_narrative_engine.py",
    "tools/burp_enterprise/action_rationale_engine.py",
    "tools/burp_enterprise/event_driven_wakeup.py",
    "tools/burp_enterprise/frontier_intelligence.py",
    "tools/burp_enterprise/self_healing.py",
    "tools/burp_enterprise/decision_trace.py",
]

def build_hist_index_all() -> dict[str, list[pathlib.Path]]:
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

def strip_bom(src: bytes) -> bytes:
    return src[3:] if src.startswith(b'\xef\xbb\xbf') else src

def main():
    print("Building history index…")
    idx = build_hist_index_all()

    restored = []
    skipped = []
    
    for rel in TARGETS:
        disk_p = ROOT / rel.replace("/", os.sep)
        
        # Already exists?
        if disk_p.exists():
            print(f"  SKIP (already exists, {disk_p.stat().st_size:,}B): {rel}")
            skipped.append(rel)
            continue
        
        # Find best snapshot
        parts = rel.replace("\\", "/").split("/")
        tail2 = "/".join(parts[-2:]).lower()
        snaps = idx.get(tail2, [])
        if not snaps:
            print(f"  ERROR (no history): {rel}")
            continue
        
        best = max(snaps, key=lambda s: s.stat().st_size)
        raw = best.read_bytes()
        raw = strip_bom(raw)
        src = raw.decode("utf-8", errors="replace")
        
        # Validate: must parse cleanly
        try:
            ast.parse(src)
        except SyntaxError as e:
            # Try other snapshots
            for snap in sorted(snaps, key=lambda s: -s.stat().st_size):
                if snap == best:
                    continue
                try:
                    r2 = strip_bom(snap.read_bytes()).decode("utf-8", errors="replace")
                    ast.parse(r2)
                    best, src = snap, r2
                    break
                except SyntaxError:
                    continue
            else:
                print(f"  ERROR (all snapshots fail parse): {rel}")
                continue
        
        # Write
        disk_p.parent.mkdir(parents=True, exist_ok=True)
        disk_p.write_bytes(src.encode("utf-8"))
        syms = ast_top_syms(src)
        print(f"  RESTORED ({disk_p.stat().st_size:,}B, {len(syms)} symbols): {rel}")
        restored.append(rel)

    print(f"\nDone. Restored: {len(restored)}  Skipped (already present): {len(skipped)}")
    
    # Quick import validation for restored files
    if restored:
        print("\nValidating restored files parse cleanly…")
        import sys
        sys.path.insert(0, str(ROOT))
        for rel in restored:
            p = ROOT / rel.replace("/", os.sep)
            src = p.read_text(encoding="utf-8", errors="replace")
            try:
                ast.parse(src)
                syms = ast_top_syms(src)
                print(f"  OK  {len(syms):>3} symbols  {p.name}")
            except SyntaxError as e:
                print(f"  PARSE_ERROR  {p.name}: {e}")

if __name__ == "__main__":
    main()
