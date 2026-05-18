"""Static scan of recovered modules (sprints A1.18 → A1.25) for silent-degradation
patterns. We classify each occurrence and rank the riskiest modules.

Patterns hunted:
  P1  getattr(obj, "name", None)          # may be None at call site
  P2  except ImportError:  pass / log     # optional dep that goes silent
  P3  hasattr(x, "y") and ...             # branch may be skipped silently
  P4  if X is None: return / pass         # guard that becomes a no-op
  P5  TODO / FIXME / NotImplementedError  # admitted gap
  P6  pragma: no cover                    # tested-only-in-prod paths
"""
from __future__ import annotations
import re
import sys
from pathlib import Path
from collections import defaultdict

ROOT = Path(r"c:\Users\ya754\CaseCrack v1.0\CaseCrack")
LIST = Path(r"c:\Users\ya754\CaseCrack v1.0\_recovered_modules_a118_a125.txt")

PATTERNS = {
    "P1_getattr_None":  re.compile(r"getattr\([^,]+,\s*['\"][^'\"]+['\"],\s*None\s*\)"),
    "P2_except_import": re.compile(r"except\s+(ImportError|ModuleNotFoundError|AttributeError)\s*[:\(]"),
    "P3_hasattr":       re.compile(r"\bhasattr\s*\("),
    "P4_is_None_skip":  re.compile(r"\bif\s+\w+\s+is\s+None\s*:\s*$", re.MULTILINE),
    "P5_todo":          re.compile(r"\b(TODO|FIXME|XXX|NotImplementedError)\b"),
    "P6_no_cover":      re.compile(r"#\s*pragma:\s*no\s*cover"),
}

def collect_modules() -> list[Path]:
    raw = LIST.read_text(encoding="utf-8").splitlines()
    seen, out = set(), []
    for line in raw:
        line = line.strip()
        if not line.endswith(".py") or line.startswith("=="):
            continue
        if line in seen:
            continue
        seen.add(line)
        p = ROOT / line.replace("/", "\\")
        if p.exists():
            out.append(p)
    return out

def scan(p: Path) -> dict:
    txt = p.read_text(encoding="utf-8", errors="ignore")
    counts = {k: len(rx.findall(txt)) for k, rx in PATTERNS.items()}
    counts["LOC"] = txt.count("\n")
    return counts

def main() -> int:
    mods = collect_modules()
    print(f"Scanning {len(mods)} recovered modules\n")
    rows = []
    totals = defaultdict(int)
    for p in mods:
        c = scan(p)
        rel = p.relative_to(ROOT).as_posix()
        risk = c["P1_getattr_None"]*3 + c["P2_except_import"]*2 + c["P3_hasattr"] + c["P5_todo"]*2
        rows.append((risk, rel, c))
        for k, v in c.items():
            totals[k] += v

    rows.sort(reverse=True)
    print(f"{'Risk':>5}  {'LOC':>6}  {'P1':>3} {'P2':>3} {'P3':>3} {'P4':>3} {'P5':>3} {'P6':>3}  Module")
    for risk, rel, c in rows[:30]:
        print(f"{risk:>5}  {c['LOC']:>6}  "
              f"{c['P1_getattr_None']:>3} {c['P2_except_import']:>3} "
              f"{c['P3_hasattr']:>3} {c['P4_is_None_skip']:>3} "
              f"{c['P5_todo']:>3} {c['P6_no_cover']:>3}  {rel}")
    print()
    print(f"TOTALS: P1_getattr_None={totals['P1_getattr_None']}  "
          f"P2_except_import={totals['P2_except_import']}  "
          f"P3_hasattr={totals['P3_hasattr']}  "
          f"P4_is_None_skip={totals['P4_is_None_skip']}  "
          f"P5_todo={totals['P5_todo']}  "
          f"P6_no_cover={totals['P6_no_cover']}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
