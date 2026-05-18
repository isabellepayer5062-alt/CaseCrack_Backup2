#!/usr/bin/env python3
"""Deep investigation of all-findings.json for production issues."""
import json, pathlib, collections, sys

findings_path = pathlib.Path(r"C:\Users\ya754\CaseCrack v1.0\reports\recon-all-findings.json")
data = json.loads(findings_path.read_bytes())
findings = data if isinstance(data, list) else data.get("findings", data.get("results", []))
print(f"Total findings: {len(findings)}")

# ── Severity distribution ──
sev = collections.Counter(str(f.get("severity","")).lower() for f in findings)
print(f"\nSeverity: {dict(sev.most_common())}")

# ── Category distribution (top 25) ──
cats = collections.Counter(str(f.get("category","unknown")) for f in findings)
print(f"\nTop categories (25): {dict(cats.most_common(25))}")

# ── Findings with empty/missing url ──
no_url = [f for f in findings if not str(f.get("url","")).strip()]
print(f"\nFindings with empty url: {len(no_url)}")
by_cat = collections.Counter(f.get("category","?") for f in no_url)
print(f"  By category: {dict(by_cat.most_common(15))}")
print("  Titles (first 20):")
for f in no_url[:20]:
    print(f"    [{f.get('severity','?')}] {f.get('title','')[:70]}")

# ── Confidence/confidence_score analysis ──
no_confidence = [f for f in findings if "confidence" not in f and "confidence_score" not in f]
print(f"\nFindings missing confidence: {len(no_confidence)}")

def _conf(f):
    v = f.get("confidence_score", f.get("confidence", 100))
    try:
        return float(v)
    except (TypeError, ValueError):
        return 100.0

low_conf = [f for f in findings if _conf(f) < 40]
print(f"Findings with confidence < 40: {len(low_conf)}")
for f in low_conf[:10]:
    conf = _conf(f)
    print(f"  [{f.get('severity','?')}|conf={conf}] {f.get('title','')[:60]}")

# ── Duplicate title analysis ──
title_counts = collections.Counter(f.get("title","") for f in findings)
dupes = {t: c for t, c in title_counts.items() if c > 5}
print(f"\nTitles with >5 occurrences ({len(dupes)} total):")
for title, count in sorted(dupes.items(), key=lambda x: -x[1])[:20]:
    print(f"  {count:4d}x  {title[:70]}")

# ── Findings where title == description (lazy/duplicate) ──
lazy = [f for f in findings if f.get("title","") == f.get("description","") and f.get("title")]
print(f"\nFindings where title==description: {len(lazy)}")
for f in lazy[:5]:
    print(f"  {f.get('title','')[:60]}")

# ── Missing remediation ──
no_remed = [f for f in findings if not f.get("remediation","").strip()]
print(f"\nFindings missing remediation: {len(no_remed)}")
by_sev = collections.Counter(f.get("severity","?") for f in no_remed)
print(f"  By severity: {dict(by_sev.most_common())}")

# ── Severity=critical findings ──
crits = [f for f in findings if str(f.get("severity","")).lower() == "critical"]
print(f"\nCRITICAL findings ({len(crits)}):")
for f in crits[:30]:
    conf = _conf(f)
    print(f"  [{conf}%conf] {str(f.get('url','<no-url>'))[:50]} | {f.get('title','')[:60]}")

# ── High-severity findings ──
highs = [f for f in findings if str(f.get("severity","")).lower() == "high"]
print(f"\nHIGH findings ({len(highs)} total) — first 30:")
for f in highs[:30]:
    conf = _conf(f)
    print(f"  [{conf}%conf] {str(f.get('url','<no-url>'))[:50]} | {f.get('title','')[:60]}")

# ── Phase/source analysis ──
phases = collections.Counter(f.get("phase", f.get("source","?")) for f in findings)
print(f"\nTop phases/sources (20): {dict(phases.most_common(20))}")

# ── Findings with likely_false_positive flag ──
fps = [f for f in findings if f.get("likely_false_positive") or f.get("fp_reason")]
print(f"\nFindings flagged likely_false_positive: {len(fps)}")
for f in fps[:10]:
    print(f"  {f.get('title','')[:60]} | reason: {f.get('fp_reason','')[:50]}")

# ── Check for cvss_score distribution ──
cvss_vals = [f.get("cvss_score") for f in findings if f.get("cvss_score") is not None]
if cvss_vals:
    print(f"\nCVSS scores: min={min(cvss_vals):.1f} max={max(cvss_vals):.1f} mean={sum(cvss_vals)/len(cvss_vals):.1f} count={len(cvss_vals)}")

# ── Findings with evidence dict but no request/response ──
has_evidence = [f for f in findings if f.get("evidence") and isinstance(f["evidence"], dict)]
print(f"\nFindings with evidence dict: {len(has_evidence)}")
