#!/usr/bin/env python3
"""
Comprehensive analysis of report files to find zero-findings / stub / broken tools.
"""
import json
import sys
from pathlib import Path

report_dir = Path("CaseCrack/reports")
results = []

for f in sorted(report_dir.glob("*.json")):
    try:
        raw = f.read_text(encoding="utf-8", errors="replace")
        data = json.loads(raw)
        size = f.stat().st_size

        is_placeholder = False
        is_skipped = False
        if isinstance(data, dict):
            if data.get("_placeholder") or data.get("_placeholder_none") or data.get("placeholder"):
                is_placeholder = True
            if data.get("skipped") or data.get("_skipped"):
                is_skipped = True

        findings = 0
        if isinstance(data, list):
            findings = len(data)
        elif isinstance(data, dict):
            for key in ("findings", "vulnerabilities", "issues", "results", "urls", "endpoints"):
                v = data.get(key)
                if v is not None:
                    if isinstance(v, list):
                        findings = max(findings, len(v))
                    elif isinstance(v, int):
                        findings = max(findings, v)

        results.append({
            "file": f.name,
            "size": size,
            "findings": findings,
            "placeholder": is_placeholder,
            "skipped": is_skipped,
            "data": data,
        })
    except Exception as e:
        results.append({
            "file": f.name,
            "size": f.stat().st_size,
            "findings": -1,
            "placeholder": False,
            "skipped": False,
            "data": None,
            "err": str(e),
        })

placeholders = [r for r in results if r["placeholder"]]
skipped = [r for r in results if r["skipped"]]
with_findings = [r for r in results if r["findings"] > 0]
zero = [r for r in results if r["findings"] == 0 and not r["placeholder"] and not r["skipped"]]
errors = [r for r in results if r["findings"] == -1]
# stub = tiny files with essentially no content
stubs = [r for r in zero if r["size"] <= 200]
# zero but bigger (tool ran, processed, returned nothing meaningful)
zero_nonstub = [r for r in zero if r["size"] > 200]

total_findings = sum(r["findings"] for r in with_findings)

print(f"Total JSON reports     : {len(results)}")
print(f"  With findings        : {len(with_findings)}  ({total_findings} total findings)")
print(f"  Zero findings        : {len(zero)}")
print(f"    -- stubs (<=200B)  : {len(stubs)}")
print(f"    -- ran but empty   : {len(zero_nonstub)}")
print(f"  Placeholder/skip     : {len(placeholders) + len(skipped)}")
print(f"  Parse errors         : {len(errors)}")
print()

# ── STUB FILES (empty/skeleton output) ──────────────────────────
print("=" * 70)
print("STUB/EMPTY FILES (<=200 bytes, 0 findings, not placeholder)")
print("=" * 70)
for r in sorted(stubs, key=lambda x: x["size"]):
    d = r["data"]
    sample = str(d)[:120] if d else "(parse error)"
    print(f"  {r['size']:>5}B  {r['file']}")
    print(f"         {sample}")
print()

# ── RAN BUT ZERO ─────────────────────────────────────────────────
print("=" * 70)
print("TOOLS THAT RAN (>200B output) BUT PRODUCED ZERO FINDINGS")
print("=" * 70)
for r in sorted(zero_nonstub, key=lambda x: x["size"]):
    d = r["data"]
    if isinstance(d, dict):
        keys = list(d.keys())[:10]
        sample = f"keys={keys}"
        # show interesting sub-values
        for k in ("summary", "status", "total", "count", "message", "tool", "error"):
            if k in d:
                sample += f"  {k}={str(d[k])[:60]}"
    elif isinstance(d, list):
        sample = f"list[{len(d)}]"
    else:
        sample = str(d)[:120]
    print(f"  {r['size']:>7}B  {r['file']}")
    print(f"             {sample}")
print()

# ── PLACEHOLDER/SKIPPED ──────────────────────────────────────────
print("=" * 70)
print("PLACEHOLDER / SKIPPED (tool not installed or no CLI handler)")
print("=" * 70)
for r in sorted(placeholders + skipped, key=lambda x: x["file"]):
    d = r["data"]
    sample = str(d)[:120] if isinstance(d, dict) else ""
    flag = "[PLACEHOLDER]" if r["placeholder"] else "[SKIPPED]"
    print(f"  {flag:15s}  {r['file']}")
    print(f"                  {sample[:100]}")
print()

# ── TOP PRODUCERS ─────────────────────────────────────────────────
print("=" * 70)
print("TOP FINDING PRODUCERS")
print("=" * 70)
for r in sorted(with_findings, key=lambda x: -x["findings"])[:30]:
    print(f"  {r['findings']:>6}  {r['file']}")
print()

# ── ERRORS ───────────────────────────────────────────────────────
if errors:
    print("=" * 70)
    print("PARSE ERRORS")
    print("=" * 70)
    for r in errors:
        print(f"  {r['file']}  -- {r.get('err', '?')[:80]}")
    print()
