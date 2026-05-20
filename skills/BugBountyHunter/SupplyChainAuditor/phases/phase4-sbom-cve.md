## Phase 4: SBOM & CVE Analysis

### SBOM Discovery

```bash
# Look for SBOM artifacts in repos and release assets
find . -name "*.spdx" -o -name "sbom.json" -o -name "bom.xml" -o -name "cyclonedx.json"

# GitHub release artifacts
curl -s "https://api.github.com/repos/{org}/{repo}/releases/latest" | 
  jq '.assets[].name' | grep -i sbom

# Container image SBOM (if image registry accessible)
docker sbom {image}:latest
```

### CVE Matching Pipeline

For each dependency in SBOM:
1. Query NVD API for CVEs matching package + version range
2. Filter: `severity >= HIGH AND has_public_PoC`
3. Filter: `version in installed_version_range`
4. Score by: EPSS (Exploit Prediction Scoring System) probability

```python
def score_cve_candidate(cve_id, installed_version, package_name):
    nvd = query_nvd(cve_id)
    epss = query_epss(cve_id)
    return {
        "cve_id": cve_id,
        "package": package_name,
        "installed_version": installed_version,
        "cvss_score": nvd["cvss_v3_base_score"],
        "epss_score": epss["score"],  # 0.0-1.0 probability of exploitation in wild
        "has_public_poc": check_exploitdb(cve_id) or check_github_poc(cve_id),
        "is_exploitable": epss["score"] > 0.1 and nvd["cvss_v3_base_score"] >= 7.0
    }
```

**Only report CVEs with `is_exploitable: true` — do not flood program with
theoretical CVEs that have no public exploit and low EPSS scores.**

### OSV-Scanner (Preferred Tool)

**OSV.dev** provides ecosystem-normalized vulnerability data superior to raw NVD
for open source packages. Use `osv-scanner` (Google) as the primary scanning tool—
it operates directly on lockfiles and SBOMs without manual version parsing:

```bash
# osv-scanner — scan lockfiles and SBOMs directly
# Supports: package-lock.json, yarn.lock, poetry.lock, Pipfile.lock,
#           go.sum, Cargo.lock, Gemfile.lock, pom.xml, packages.lock.json
osv-scanner scan --lockfile package-lock.json
osv-scanner scan --lockfile poetry.lock
osv-scanner scan --sbom sbom.cyclonedx.json  # CycloneDX/SPDX SBOM input
osv-scanner scan --format json -o osv-results.json .

# Filter for exploitable output (CVSS ≥ 7.0 + EPSS > 0.1)
osv-scanner scan --format json . | python3 -c "
import sys, json
data = json.load(sys.stdin)
for result in data.get('results', []):
    for pkg in result.get('packages', []):
        for v in pkg.get('vulnerabilities', []):
            severity = v.get('database_specific', {}).get('severity', 'N/A')
            if severity in ('HIGH', 'CRITICAL'):
                print(f\"{v['id']} | {pkg['package']['name']}@{pkg['package']['version']} | {severity}\")
"
```

### CI SBOM Generation Detection

The presence (or absence) of automated SBOM generation in CI is a SLSA compliance
signal and affects downstream vulnerability management quality:

```bash
# Detect Syft (anchore/syft) or CycloneDX generation in workflows
grep -r 'syft\|anchore/sbom-action\|cyclonedx-bom\|spdx' .github/workflows/ -l

# Check for Grype (vulnerability scanner) paired with Syft
grep -r 'anchore/scan-action\|grype' .github/workflows/ -l

# Check if SBOMs are attached to releases and signed
curl -s "https://api.github.com/repos/{org}/{repo}/releases/latest" \
  | jq '.assets[] | select(.name | test("sbom|spdx|cyclonedx"; "i")) | .name'

# SBOM signing check — look for Cosign sign step after SBOM generation
grep -r 'cosign sign\|sigstore' .github/workflows/ -A3 | grep -i sbom
```

**Assessment guidance:** No SBOM in CI → SLSA Level 0 signal; SBOM present but unsigned
→ SLSA L1 gap; SBOM generated + signed with Cosign → SLSA L2 minimum.

