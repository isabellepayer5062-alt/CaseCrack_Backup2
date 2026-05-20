## Phase 3: Dependency Confusion Attack Analysis

### Dependency Confusion Fundamentals

Dependency confusion exploits the package registry resolution order:
1. Target's internal registry (private packages)
2. Public registry (PyPI, npm, RubyGems)

If a **private package name** is published to the **public registry** with a
**higher version number**, many build tools install the malicious public package instead.

### Identifying Confusion Candidates

**Step 1**: Find dependency manifests in public repos:
```bash
# package.json — look for @internal-scope packages or non-public names
jq '.dependencies | keys[]' package.json | grep -E '^(@company|internal-|private-)'

# requirements.txt — look for packages with company-specific prefixes
grep -E '^(company-|internal-|acme-)' requirements.txt

# .npmrc — look for custom registry scopes
grep '@scope' .npmrc
```

**Step 2**: Check if private package name exists on public registry:
```python
def check_confusion_candidate(package_name, ecosystem):
    """PASSIVE CHECK ONLY — do not publish"""
    if ecosystem == "npm":
        r = requests.get(f"https://registry.npmjs.org/{package_name}")
        return r.status_code == 404  # 404 → name available → confusion candidate
    elif ecosystem == "pypi":
        r = requests.get(f"https://pypi.org/pypi/{package_name}/json")
        return r.status_code == 404
    elif ecosystem == "rubygems":
        r = requests.get(f"https://rubygems.org/api/v1/gems/{package_name}.json")
        return r.status_code == 404
```

**Step 3**: If candidate confirmed, report WITHOUT publishing.
Emit as `dependency_confusion_candidate` in supply-chain-findings.json with:
- `package_name`: the private package name
- `ecosystem`: npm/pypi/rubygems/etc.
- `internal_version`: version used internally (from manifest)
- `public_status`: not_exists / exists_lower_version / exists_same_version
- `exploitation_impact`: code execution in CI and developer builds
- `severity`: HIGH to CRITICAL depending on package's use context

**STOP here** — do NOT publish any packages. Report the theoretical vulnerability.

### Typosquatting Detection

```python
TYPOSQUAT_TRANSFORMS = [
    lambda n: n.replace('-', '_'),      # requests-toolbelt vs requests_toolbelt
    lambda n: n.replace('_', '-'),
    lambda n: n + '-dev',               # appended suffixes
    lambda n: n + '-utils',
    lambda n: 'python-' + n,            # python- prefix
    lambda n: n.replace('crypto', 'cryptoo'),  # doubled letters
    lambda n: n[:len(n)//2] + n[len(n)//2:].replace('l','1'),  # homoglyph
]

def check_typosquats(package_name, ecosystem):
    candidates = [t(package_name) for t in TYPOSQUAT_TRANSFORMS]
    malicious_candidates = []
    for candidate in candidates:
        if package_exists(candidate, ecosystem):
            meta = get_package_metadata(candidate, ecosystem)
            if meta['maintainer'] not in KNOWN_LEGITIMATE_MAINTAINERS:
                malicious_candidates.append(candidate)
    return malicious_candidates
```

### Slopsquatting Detection (2025 Emerging Vector)

**Slopsquatting** targets package names *hallucinated by AI coding assistants* (Copilot,
Cursor, Claude). LLMs confidently suggest plausible-but-nonexistent package names;
attackers register these names in anticipation of the hallucination being reused.
Especially dangerous in AI-heavy dev pipelines where developers `npm install` or
`pip install` names from AI suggestions without verifying first.

```python
# Additional transforms for AI hallucination patterns
SLOPSQUAT_TRANSFORMS = [
    # Python: AI commonly hallucinates these patterns
    lambda n: f"python-{n}-client",       # python-stripe-client (doesn't exist)
    lambda n: f"{n}-sdk",                 # openai-python-sdk (wrong; openai is correct)
    lambda n: f"{n}-official",            # requests-official
    lambda n: f"{n}-async",               # sync library + -async suffix
    # npm: AI confuses scoped package resolution
    lambda n: n.lstrip('@').replace('/', '-'),  # @org/pkg → org-pkg (wrong registry path)
    lambda n: f"{n}-latest",
    lambda n: f"{n}-wrapper",
]

# Detection: find package names from AI-assisted code that return 404 on registry
# Look in:
#  - package.json / requirements.txt (imports AI suggested and dev added without checking)
#  - README "install" sections (AI-generated snippets)
#  - PR descriptions mentioning package names
# Signal: repo uses Copilot/Cursor (.vscode/settings.json, .cursor/) + 404 package name
```

### Lockfile & Registry Configuration Analysis

Lockfiles provide exact installed versions + integrity hashes — far more reliable
than top-level manifests for CVE matching and tamper detection. Scoped registry
configs can also reveal internal registry endpoints (confusion surface).

```bash
# package-lock.json — verify resolved registries and integrity hashes
jq '.packages | to_entries[] | select(.key != "") |
    {name: .key, version: .value.version,
     resolved: .value.resolved, integrity: .value.integrity}' package-lock.json

# Flag packages resolved from non-standard registries (confusion indicator)
jq -r '.packages[].resolved // empty' package-lock.json \
  | grep -v 'registry.npmjs.org' | sort -u

# poetry.lock (Python) — exact versions for OSV scanning
grep -A2 '^\[\[package\]\]' poetry.lock | grep -E 'name|version' | paste - -

# Pipfile.lock — source field reveals index override
jq '._meta.sources[] | .url' Pipfile.lock

# .npmrc — scoped registry configs that may point to internal registries
# If scope @company → internal.registry.com, check if @company/* also has no npm listing
grep -r '@[a-zA-Z0-9-]*:registry' .npmrc .npmrc.example package.json 2>/dev/null

# pip.conf / pip.ini — index-url and extra-index-url overrides
grep -r 'index-url\|extra-index-url\|trusted-host' \
    . --include='*.cfg' --include='*.ini' --include='pip.conf' 2>/dev/null
```

**Specialized tools** (passive, read-only analysis):
- `super-confused`: automated dependency confusion detection across npm/PyPI/RubyGems/Maven
- `combobulator`: multi-ecosystem confusion + typosquat scoring with risk classification

