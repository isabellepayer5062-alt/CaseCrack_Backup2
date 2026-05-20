"""
Comprehensive gap analysis v2: tools available vs findings produced vs Shopify surface coverage.
"""
import json, collections, re, os
from pathlib import Path

# ── Load findings ──────────────────────────────────────────────────────────────
with open("reports/recon-all-findings.json") as f:
    findings = json.load(f)

print(f"Total findings: {len(findings)}\n")

# ── Phase names from phase_commands.py ────────────────────────────────────────
with open("CaseCrack/tools/burp_enterprise/recon_dashboard/phase_commands.py", encoding="utf-8") as f:
    phase_src = f.read()

phase_names = re.findall(r'"name":\s*"([^"]+)"', phase_src)
print(f"Total phases defined: {len(phase_names)}")

finding_phases = set(x.get("phase", "") for x in findings)
by_phase = collections.Counter(x.get("phase", "") for x in findings if x.get("phase"))

print("\n=== PHASES WITH ZERO FINDINGS ===")
for name in phase_names:
    if name not in finding_phases:
        print(f"  ZERO  {name}")

print("\n=== PHASES WITH FINDINGS ===")
for name in phase_names:
    if name in by_phase:
        print(f"  {by_phase[name]:4d}  {name}")

# ── All available CLI tools ────────────────────────────────────────────────────
commands_dir = Path("CaseCrack/tools/burp_enterprise/cli/commands")
if commands_dir.exists():
    cli_tools = sorted(p.stem for p in commands_dir.glob("*.py") if p.stem != "__init__")
else:
    cli_tools = []

# All available scanners
scanners_dir = Path("CaseCrack/tools/burp_enterprise/scanners")
scanner_files = sorted(p.stem for p in scanners_dir.glob("*.py") if p.stem != "__init__") if scanners_dir.exists() else []

print(f"\n=== CLI TOOLS AVAILABLE ({len(cli_tools)}) ===")
for t in cli_tools:
    print(f"  {t}")

print(f"\n=== SCANNER MODULES AVAILABLE ({len(scanner_files)}) ===")
for t in scanner_files:
    print(f"  {t}")

# ── Commands actually used in phase_commands.py ────────────────────────────────
# extract first element of each command list  
used_cmds = re.findall(r'\["([a-z_A-Z][a-z_A-Z0-9-]*)"', phase_src)
used_cmd_counts = collections.Counter(used_cmds)

print(f"\n=== COMMANDS USED IN PHASES (unique: {len(set(used_cmds))}) ===")
for cmd, count in used_cmd_counts.most_common():
    print(f"  {count:3d}x  {cmd}")

# CLI tools NOT referenced in any phase
unused_tools = [t for t in cli_tools if t not in used_cmd_counts and t.replace("_", "-") not in used_cmd_counts]
print(f"\n=== CLI TOOLS NOT USED IN ANY PHASE ({len(unused_tools)}) ===")
for t in unused_tools:
    print(f"  UNUSED  {t}")

# ── Endpoints discovered during recon ─────────────────────────────────────────
# Load endpoint list if available
endpoint_files = list(Path("reports").glob("*endpoint*")) + list(Path("reports").glob("*url*"))
print(f"\n=== ENDPOINT REPORT FILES ===")
for ef in sorted(endpoint_files):
    print(f"  {ef.name}  ({ef.stat().st_size//1024}KB)")

# ── Parameters discovered ──────────────────────────────────────────────────────
# Look for parameter discovery findings
param_findings = [x for x in findings if "parameter" in str(x.get("phase","")).lower() 
                  or x.get("scan_type","") == "parameter_discovery"
                  or x.get("category","") == "parameter"]

print(f"\n=== PARAMETER DISCOVERY FINDINGS: {len(param_findings)} ===")
# Group by URL+param
param_urls = collections.Counter()
for pf in param_findings:
    url = pf.get("url","") or pf.get("target_url","") or ""
    param = pf.get("param","") or pf.get("parameter","") or pf.get("name","") or ""
    if url and param:
        param_urls[(url.split("?")[0], param)] += 1
    elif url:
        param_urls[(url.split("?")[0], "?")] += 1

print("  Top 25 URL+param combos discovered:")
for (url, param), cnt in sorted(param_urls.items(), key=lambda x: -x[1])[:25]:
    print(f"    {cnt}x  {url[:70]}  param={param}")

# ── Shopify-specific endpoints NOT being tested ────────────────────────────────
shopify_endpoints = [
    "/search",
    "/search?type=product&q=",
    "/collections",
    "/collections/all",
    "/products",
    "/account/login",
    "/account/register",
    "/account/forgot_password",
    "/account/reset_password",
    "/checkout",
    "/cart",
    "/cart.js",
    "/cart/add.js",
    "/cart/update.js",
    "/products.json",
    "/collections.json",
    "/sitemap.xml",
    "/robots.txt",
    "/customer_authentication/login",
    "/customer_authentication/redirect",
    "/discount/TESTCODE",
    "/pages",
    "/blogs",
    "/api/2024-04/graphql.json",
    "/.well-known/shopify/monorail",
    "/cdn/shop/t/",
    "/admin",
    "/admin/login",
    "/?preview_theme_id=",
    "/?_ab=",
    "/?variant=",
]

# What URLs appear in findings
tested_urls = set()
for f in findings:
    for k in ("url","secret_url","target_url"):
        u = f.get(k,"") or ""
        if u:
            tested_urls.add(u.split("?")[0].rstrip("/"))

print("\n=== SHOPIFY ENDPOINTS: TESTED vs UNTESTED ===")
for ep in shopify_endpoints:
    full = "https://sugarrushed.ca" + ep
    base = full.split("?")[0].rstrip("/")
    hit = any(tu == base or tu.startswith(base) for tu in tested_urls)
    status = "TESTED" if hit else "UNTESTED"
    print(f"  {status}  {ep}")

# ── High-value finding types present vs possible ──────────────────────────────
print("\n=== HIGH-VALUE FINDING TYPES PRESENT ===")
vuln_types = collections.Counter(
    x.get("title","") or x.get("type","") or x.get("vulnerability_type","") or x.get("vuln_type","") 
    for x in findings if x.get("severity") in ("critical","high")
)
for title, cnt in vuln_types.most_common(30):
    print(f"  {cnt:3d}x  {title[:80]}")

# ── Report files produced ──────────────────────────────────────────────────────
print("\n=== REPORT FILES IN reports/ ===")
report_dir = Path("reports")
for rp in sorted(report_dir.glob("*.json")):
    size = rp.stat().st_size
    print(f"  {size//1024:5d}KB  {rp.name}")
