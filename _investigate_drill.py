#!/usr/bin/env python3
"""Second-pass deep drill: specific production issues."""
import json, pathlib, collections, sys

findings_path = pathlib.Path(r"C:\Users\ya754\CaseCrack v1.0\reports\recon-all-findings.json")
data = json.loads(findings_path.read_bytes())
findings = data if isinstance(data, list) else data.get("findings", data.get("results", []))

# ═══════════════════════════════════════════════════════════
# ISSUE A: "discovery" category with empty url (20 findings)
# These should have a url — what are they?
# ═══════════════════════════════════════════════════════════
print("=" * 70)
print("ISSUE A: 'discovery' category findings with empty URL")
for f in findings:
    if f.get("category") == "discovery" and not str(f.get("url","")).strip():
        title = f.get("title","")
        detail = str(f.get("detail", f.get("description","")))[:80]
        phase = f.get("phase","?")
        print(f"  [{f.get('severity','?')}] {title[:60]}  | {detail} | phase={phase}")

# ═══════════════════════════════════════════════════════════
# ISSUE B: "finding" category (53 total) — what are these?
# ═══════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("ISSUE B: raw 'finding' category (53 total)")
finding_titles = collections.Counter(f.get("title","") for f in findings if f.get("category") == "finding")
print("Title distribution:")
for t, c in finding_titles.most_common(25):
    print(f"  {c:3d}x  {t[:70]}")
# Show some examples with full detail
print("\nSample records (first 8):")
for f in [x for x in findings if x.get("category") == "finding"][:8]:
    print(f"  sev={f.get('severity','?')} title={f.get('title','')[:50]}")
    print(f"    url={f.get('url','')[:60]}")
    print(f"    detail={str(f.get('detail',''))[:80]}")
    print(f"    phase={f.get('phase','?')}")

# ═══════════════════════════════════════════════════════════
# ISSUE C: "Interesting path" findings — url missing
# ═══════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("ISSUE C: 'Interesting path' findings (medium/low) — all url fields")
ipath = [f for f in findings if "Interesting path" in f.get("title","")]
for f in ipath[:15]:
    print(f"  [{f.get('severity','?')}] {f.get('title','')[:50]}")
    print(f"    url={repr(f.get('url',''))[:60]}")
    print(f"    detail={str(f.get('detail',''))[:80]}")
    print(f"    bypass_endpoint={f.get('bypass_endpoint','N/A')}")

# ═══════════════════════════════════════════════════════════
# ISSUE D: "Critical Malicious Patterns Detected" — likely FP
# ═══════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("ISSUE D: 'Critical Malicious Patterns Detected' findings")
for f in findings:
    if "Malicious Patterns" in f.get("title",""):
        print(f"  url={f.get('url','')[:80]}")
        print(f"  phase={f.get('phase','?')}")
        evidence = f.get("evidence", {})
        if isinstance(evidence, dict):
            for k, v in evidence.items():
                print(f"    evidence.{k}: {str(v)[:100]}")
        detail = f.get("detail","")
        print(f"  detail: {str(detail)[:200]}")
        print()

# ═══════════════════════════════════════════════════════════
# ISSUE E: "forms" category — why no URL?
# ═══════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("ISSUE E: 'forms' category with empty URL")
for f in findings:
    if f.get("category") == "forms" and not str(f.get("url","")).strip():
        print(f"  [{f.get('severity','?')}] {f.get('title','')[:60]}")
        print(f"    detail={str(f.get('detail',''))[:100]}")
        print(f"    phase={f.get('phase','?')}")

# ═══════════════════════════════════════════════════════════
# ISSUE F: "misconfiguration" + "access_control" + "security_header" 
#          with empty URL (should ALWAYS have a url)
# ═══════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("ISSUE F: misconfiguration / access_control / security_header — no URL (high severity impact)")
for cat in ("misconfiguration", "access_control", "security_header"):
    for f in findings:
        if f.get("category") == cat and not str(f.get("url","")).strip():
            print(f"  [{cat}|{f.get('severity','?')}] {f.get('title','')[:60]}")
            print(f"    detail={str(f.get('detail',''))[:100]}")
            all_keys = {k: v for k, v in f.items() if "url" in k.lower() or "host" in k.lower() or "target" in k.lower()}
            print(f"    url-like keys: {all_keys}")

# ═══════════════════════════════════════════════════════════
# ISSUE G: "source_code" (15) with empty URL — phase?
# ═══════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("ISSUE G: 'source_code' category — all url fields")
for f in findings:
    if f.get("category") == "source_code":
        url_like = {k: v for k, v in f.items() if "url" in k.lower() or "file" in k.lower() or "path" in k.lower() or "source" in k.lower()}
        print(f"  [{f.get('severity','?')}] {f.get('title','')[:60]}")
        print(f"    url_like_fields: {url_like}")

# ═══════════════════════════════════════════════════════════
# ISSUE H: DNS security (5) with empty URL
# ═══════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("ISSUE H: 'dns_security' category with empty URL")
for f in findings:
    if f.get("category") == "dns_security" and not str(f.get("url","")).strip():
        print(f"  [{f.get('severity','?')}] {f.get('title','')[:60]}")
        url_like = {k: v for k, v in f.items() if k in ("url","host","target","domain","nameserver","record")}
        print(f"    url_like_fields: {url_like}")
        print(f"    phase={f.get('phase','?')}")

# ═══════════════════════════════════════════════════════════
# ISSUE I: "tls" category (3) with empty URL
# ═══════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("ISSUE I: 'tls' category with empty URL")
for f in findings:
    if f.get("category") == "tls" and not str(f.get("url","")).strip():
        print(f"  [{f.get('severity','?')}] {f.get('title','')[:60]}")
        url_like = {k: v for k, v in f.items() if k in ("url","host","target","domain","ip","port")}
        print(f"    url_like_fields: {url_like}")

# ═══════════════════════════════════════════════════════════
# ISSUE J: "fingerprint" category (14) with empty URL
# ═══════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("ISSUE J: 'fingerprint' category — all url-like fields")
fp_sample = [f for f in findings if f.get("category") == "fingerprint"][:5]
for f in fp_sample:
    print(f"  [{f.get('severity','?')}] {f.get('title','')[:60]}")
    all_keys = {k: str(v)[:80] for k, v in f.items()}
    print(f"    all_keys: {all_keys}")
