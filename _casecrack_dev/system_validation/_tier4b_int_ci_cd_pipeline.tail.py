

# __TIER4B_INTEGRATIONS__ ci_cd_pipeline
# Tier 4B: 4 CI/CD platform implementations (GitHub Actions, GitLab CI, Jenkins, CircleCI/Azure DevOps)
#          + branch/PR scoping, SARIF/SBOM artifact generation/upload, status check posting

import os as _t4b_os
import json as _t4b_json
import time as _t4b_time
import base64 as _t4b_b64
import hashlib as _t4b_hashlib
import urllib.request as _t4b_req
import urllib.parse as _t4b_urlparse
import urllib.error as _t4b_urlerr
from dataclasses import dataclass as _t4b_dataclass, field as _t4b_field
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# CI Platform identification & env detection
# ---------------------------------------------------------------------------
_T4B_CI_PLATFORMS = {
    "github_actions": {
        "env_marker": "GITHUB_ACTIONS",
        "branch": "GITHUB_REF_NAME",
        "pr": "GITHUB_HEAD_REF",
        "sha": "GITHUB_SHA",
        "repo": "GITHUB_REPOSITORY",
        "run_id": "GITHUB_RUN_ID",
        "run_url_tmpl": "https://github.com/{repo}/actions/runs/{run_id}",
        "api_base": "https://api.github.com",
    },
    "gitlab_ci": {
        "env_marker": "GITLAB_CI",
        "branch": "CI_COMMIT_REF_NAME",
        "pr": "CI_MERGE_REQUEST_IID",
        "sha": "CI_COMMIT_SHA",
        "repo": "CI_PROJECT_PATH",
        "run_id": "CI_PIPELINE_ID",
        "run_url_tmpl": "{CI_PIPELINE_URL}",
        "api_base": "https://gitlab.com/api/v4",
    },
    "jenkins": {
        "env_marker": "JENKINS_HOME",
        "branch": "GIT_BRANCH",
        "pr": "CHANGE_ID",
        "sha": "GIT_COMMIT",
        "repo": "JOB_NAME",
        "run_id": "BUILD_NUMBER",
        "run_url_tmpl": "{BUILD_URL}",
        "api_base": None,
    },
    "circleci": {
        "env_marker": "CIRCLECI",
        "branch": "CIRCLE_BRANCH",
        "pr": "CIRCLE_PR_NUMBER",
        "sha": "CIRCLE_SHA1",
        "repo": "CIRCLE_PROJECT_REPONAME",
        "run_id": "CIRCLE_BUILD_NUM",
        "run_url_tmpl": "{CIRCLE_BUILD_URL}",
        "api_base": "https://circleci.com/api/v2",
    },
    "azure_pipelines": {
        "env_marker": "TF_BUILD",
        "branch": "BUILD_SOURCEBRANCHNAME",
        "pr": "SYSTEM_PULLREQUEST_PULLREQUESTNUMBER",
        "sha": "BUILD_SOURCEVERSION",
        "repo": "BUILD_REPOSITORY_NAME",
        "run_id": "BUILD_BUILDID",
        "run_url_tmpl": "{SYSTEM_TEAMFOUNDATIONCOLLECTIONURI}{SYSTEM_TEAMPROJECT}/_build/results?buildId={BUILD_BUILDID}",
        "api_base": None,
    },
}


def _t4b_detect_platform() -> Optional[str]:
    """Auto-detect current CI platform from env vars."""
    for name, cfg in _T4B_CI_PLATFORMS.items():
        if _t4b_os.environ.get(cfg["env_marker"]):
            return name
    return None


def _t4b_collect_ci_context() -> Dict[str, Any]:
    """Collect branch/PR/sha/repo from environment for current CI platform."""
    plat = _t4b_detect_platform()
    if not plat:
        return {"platform": None, "detected": False}
    cfg = _T4B_CI_PLATFORMS[plat]
    ctx = {
        "platform": plat,
        "detected": True,
        "branch": _t4b_os.environ.get(cfg["branch"]),
        "pr_number": _t4b_os.environ.get(cfg["pr"]),
        "commit_sha": _t4b_os.environ.get(cfg["sha"]),
        "repo": _t4b_os.environ.get(cfg["repo"]),
        "run_id": _t4b_os.environ.get(cfg["run_id"]),
    }
    # Build run URL with template substitution
    tmpl = cfg["run_url_tmpl"]
    try:
        ctx["run_url"] = tmpl.format(**ctx, **{k: _t4b_os.environ.get(k, "") for k in _t4b_os.environ})
    except Exception:
        ctx["run_url"] = None
    return ctx


# ---------------------------------------------------------------------------
# SARIF 2.1.0 generator (OASIS standard)
# ---------------------------------------------------------------------------
def _t4b_findings_to_sarif(findings: List[Dict[str, Any]], tool_name: str = "CaseCrack",
                            tool_version: str = "1.0", info_uri: str = "https://casecrack.local") -> Dict[str, Any]:
    """Convert finding dicts to SARIF 2.1.0 format for upload to GH Code Scanning, GL SAST, etc."""
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    severity_to_level = {
        "critical": "error", "high": "error", "medium": "warning",
        "low": "note", "info": "none", "informational": "none",
    }
    for f in findings or []:
        rule_id = str(f.get("rule_id") or f.get("type") or f.get("title") or "generic")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id.replace("_", " ").title(),
                "shortDescription": {"text": str(f.get("title") or rule_id)[:200]},
                "fullDescription": {"text": str(f.get("description") or f.get("title") or rule_id)[:1000]},
                "defaultConfiguration": {"level": severity_to_level.get(str(f.get("severity", "medium")).lower(), "warning")},
                "helpUri": str(f.get("references", [None])[0] or f.get("help_uri") or info_uri),
            }
        # Build location
        location: Dict[str, Any] = {}
        url = f.get("url") or f.get("uri") or f.get("location")
        if url:
            location["physicalLocation"] = {
                "artifactLocation": {"uri": str(url)},
                "region": {"startLine": int(f.get("line", 1) or 1)},
            }
        result_entry = {
            "ruleId": rule_id,
            "level": severity_to_level.get(str(f.get("severity", "medium")).lower(), "warning"),
            "message": {"text": str(f.get("description") or f.get("title") or rule_id)[:1000]},
            "locations": [location] if location else [],
        }
        # Optional partial fingerprints for CGS dedup
        fp = f.get("fingerprint") or _t4b_hashlib.sha256(
            (rule_id + str(url or "") + str(f.get("description", ""))[:100]).encode()
        ).hexdigest()
        result_entry["partialFingerprints"] = {"primary/v1": fp}
        results.append(result_entry)
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "informationUri": info_uri,
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }


def _t4b_findings_to_sbom_cyclonedx(components: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate CycloneDX 1.4 SBOM from component list."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "serialNumber": f"urn:uuid:{_t4b_hashlib.sha256(_t4b_json.dumps(components, sort_keys=True).encode()).hexdigest()[:32]}",
        "metadata": {
            "timestamp": _t4b_time.strftime("%Y-%m-%dT%H:%M:%SZ", _t4b_time.gmtime()),
            "tools": [{"vendor": "CaseCrack", "name": "sbom-gen", "version": "1.0"}],
        },
        "components": [
            {
                "type": str(c.get("type", "library")),
                "name": str(c.get("name", "unknown")),
                "version": str(c.get("version", "0")),
                "purl": str(c.get("purl") or f"pkg:generic/{c.get('name', 'unknown')}@{c.get('version', '0')}"),
            }
            for c in (components or [])
        ],
    }


# ---------------------------------------------------------------------------
# Method implementations
# ---------------------------------------------------------------------------
def _t4b_detect_ci_environment(self) -> Dict[str, Any]:
    """Detect and return current CI platform context (branch/PR/sha/repo)."""
    return _t4b_collect_ci_context()


def _t4b_should_scan_branch(self, branch: Optional[str] = None,
                              allowed_branches: Optional[List[str]] = None,
                              skip_patterns: Optional[List[str]] = None) -> Tuple[bool, str]:
    """Branch scoping: decide if scan should run for this branch."""
    ctx = _t4b_collect_ci_context()
    branch = branch or ctx.get("branch")
    if not branch:
        return True, "no_branch_info"
    skip_patterns = skip_patterns or ["dependabot/", "renovate/", "wip/"]
    for pat in skip_patterns:
        if branch.startswith(pat):
            return False, f"skip_pattern_match:{pat}"
    if allowed_branches:
        for ab in allowed_branches:
            if branch == ab or (ab.endswith("*") and branch.startswith(ab[:-1])):
                return True, f"allowed:{ab}"
        return False, "not_in_allowed_list"
    return True, "default_allow"


def _t4b_is_pull_request(self) -> bool:
    """True if running in a PR context."""
    ctx = _t4b_collect_ci_context()
    return bool(ctx.get("pr_number"))


def _t4b_generate_sarif(self, findings: List[Dict[str, Any]],
                         tool_name: str = "CaseCrack", tool_version: str = "1.0") -> Dict[str, Any]:
    """Generate SARIF 2.1.0 report from findings."""
    return _t4b_findings_to_sarif(findings, tool_name, tool_version)


def _t4b_save_sarif(self, findings: List[Dict[str, Any]], path: str) -> Dict[str, Any]:
    """Write SARIF 2.1.0 report to disk for CI artifact upload."""
    sarif = _t4b_findings_to_sarif(findings)
    with open(path, "w", encoding="utf-8") as fh:
        _t4b_json.dump(sarif, fh, indent=2)
    return {"path": path, "results": len(sarif["runs"][0]["results"]),
            "rules": len(sarif["runs"][0]["tool"]["driver"]["rules"])}


def _t4b_generate_sbom(self, components: List[Dict[str, Any]], fmt: str = "cyclonedx") -> Dict[str, Any]:
    """Generate SBOM in CycloneDX or SPDX format."""
    if fmt.lower() == "cyclonedx":
        return _t4b_findings_to_sbom_cyclonedx(components)
    elif fmt.lower() == "spdx":
        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "CaseCrack-SBOM",
            "documentNamespace": f"https://casecrack.local/sbom/{int(_t4b_time.time())}",
            "creationInfo": {
                "created": _t4b_time.strftime("%Y-%m-%dT%H:%M:%SZ", _t4b_time.gmtime()),
                "creators": ["Tool: CaseCrack-1.0"],
            },
            "packages": [
                {
                    "SPDXID": f"SPDXRef-Package-{i}",
                    "name": str(c.get("name", "unknown")),
                    "versionInfo": str(c.get("version", "0")),
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                    "licenseConcluded": str(c.get("license", "NOASSERTION")),
                }
                for i, c in enumerate(components or [])
            ],
        }
    else:
        raise ValueError(f"Unknown SBOM format: {fmt}")


def _t4b_post_status_check(self, sha: Optional[str] = None, state: str = "success",
                             description: str = "", target_url: str = "",
                             context: str = "casecrack/security",
                             token: Optional[str] = None) -> Dict[str, Any]:
    """Post commit status check (GitHub/GitLab) for current PR."""
    rs = self._check_dry_run("post_status_check", sha=sha, state=state, context=context)
    if rs is not None:
        return rs
    ctx = _t4b_collect_ci_context()
    sha = sha or ctx.get("commit_sha")
    plat = ctx.get("platform")
    token = token or _t4b_os.environ.get("GITHUB_TOKEN") or _t4b_os.environ.get("CI_JOB_TOKEN")
    if not (sha and plat and token):
        return {"posted": False, "reason": "missing sha/platform/token", "platform": plat}
    if plat == "github_actions":
        repo = ctx.get("repo")
        url = f"https://api.github.com/repos/{repo}/statuses/{sha}"
        body = _t4b_json.dumps({
            "state": state, "description": description[:140], "target_url": target_url, "context": context,
        }).encode()
        req = _t4b_req.Request(url, data=body, headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        }, method="POST")
        try:
            with _t4b_req.urlopen(req, timeout=15) as resp:
                return {"posted": True, "platform": plat, "code": resp.status}
        except _t4b_urlerr.HTTPError as e:
            return {"posted": False, "platform": plat, "code": e.code, "error": e.reason}
        except Exception as e:
            return {"posted": False, "platform": plat, "error": str(e)}
    return {"posted": False, "reason": "unsupported_platform", "platform": plat}


def _t4b_upload_sarif_to_github(self, sarif_path: str, repo: Optional[str] = None,
                                  sha: Optional[str] = None, ref: Optional[str] = None,
                                  token: Optional[str] = None) -> Dict[str, Any]:
    """Upload SARIF to GitHub Code Scanning API (POST /repos/:owner/:repo/code-scanning/sarifs)."""
    rs = self._check_dry_run("upload_sarif_to_github", repo=repo, sha=sha)
    if rs is not None:
        return rs
    ctx = _t4b_collect_ci_context()
    repo = repo or ctx.get("repo")
    sha = sha or ctx.get("commit_sha")
    ref = ref or (f"refs/heads/{ctx.get('branch')}" if ctx.get("branch") else None)
    token = token or _t4b_os.environ.get("GITHUB_TOKEN")
    if not (repo and sha and ref and token):
        return {"uploaded": False, "reason": "missing repo/sha/ref/token"}
    import gzip as _t4b_gzip
    with open(sarif_path, "rb") as fh:
        sarif_raw = fh.read()
    encoded = _t4b_b64.b64encode(_t4b_gzip.compress(sarif_raw)).decode("ascii")
    body = _t4b_json.dumps({
        "commit_sha": sha, "ref": ref, "sarif": encoded,
        "tool_name": "CaseCrack",
    }).encode()
    url = f"https://api.github.com/repos/{repo}/code-scanning/sarifs"
    req = _t4b_req.Request(url, data=body, headers={
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
    }, method="POST")
    try:
        with _t4b_req.urlopen(req, timeout=30) as resp:
            data = _t4b_json.loads(resp.read().decode("utf-8"))
            return {"uploaded": True, "id": data.get("id"), "url": data.get("url"), "code": resp.status}
    except _t4b_urlerr.HTTPError as e:
        return {"uploaded": False, "code": e.code, "error": e.reason}
    except Exception as e:
        return {"uploaded": False, "error": str(e)}


def _t4b_generate_github_actions_workflow(self, scan_steps: Optional[List[str]] = None,
                                           branches: Optional[List[str]] = None) -> str:
    """Emit a GitHub Actions workflow YAML for CaseCrack scanning."""
    branches = branches or ["main", "master", "develop"]
    steps = scan_steps or [
        "casecrack scan --target ${{ github.repository }}",
        "casecrack export --format sarif --output results.sarif",
    ]
    branch_list = ", ".join(f'"{b}"' for b in branches)
    step_block = "\n".join(f"      - name: {s.split()[0].title()}\n        run: {s}" for s in steps)
    return f"""name: CaseCrack Security Scan
on:
  push:
    branches: [{branch_list}]
  pull_request:
    branches: [{branch_list}]
permissions:
  contents: read
  security-events: write
  pull-requests: write
jobs:
  casecrack:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install CaseCrack
        run: pip install casecrack
{step_block}
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
      - name: Upload Artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: casecrack-results
          path: results.sarif
"""


def _t4b_generate_gitlab_ci_yaml(self, branches: Optional[List[str]] = None) -> str:
    """Emit GitLab CI .gitlab-ci.yml for CaseCrack."""
    only = branches or ["main", "develop", "merge_requests"]
    only_block = "\n".join(f"    - {b}" for b in only)
    return f"""stages:
  - security

casecrack_sast:
  stage: security
  image: python:3.11-slim
  script:
    - pip install casecrack
    - casecrack scan --target $CI_PROJECT_PATH
    - casecrack export --format sarif --output gl-sast-report.json
  artifacts:
    when: always
    reports:
      sast: gl-sast-report.json
    paths:
      - gl-sast-report.json
    expire_in: 30 days
  only:
{only_block}
  allow_failure: true
"""


def _t4b_generate_jenkins_pipeline(self) -> str:
    """Emit Jenkinsfile (declarative) for CaseCrack."""
    return """pipeline {
    agent any
    stages {
        stage('CaseCrack Scan') {
            steps {
                sh 'pip install casecrack'
                sh 'casecrack scan --target $JOB_NAME'
                sh 'casecrack export --format sarif --output results.sarif'
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'results.sarif', allowEmptyArchive: true
            recordIssues enabledForFailure: true, tools: [sarif(pattern: 'results.sarif')]
        }
    }
}
"""


def _t4b_generate_circleci_config(self) -> str:
    """Emit CircleCI .circleci/config.yml for CaseCrack."""
    return """version: 2.1
jobs:
  casecrack-scan:
    docker:
      - image: cimg/python:3.11
    steps:
      - checkout
      - run:
          name: Install CaseCrack
          command: pip install casecrack
      - run:
          name: Run scan
          command: casecrack scan --target $CIRCLE_PROJECT_REPONAME
      - run:
          name: Export SARIF
          command: casecrack export --format sarif --output results.sarif
      - store_artifacts:
          path: results.sarif
workflows:
  security:
    jobs:
      - casecrack-scan
"""


def _t4b_generate_azure_pipelines_yaml(self) -> str:
    """Emit Azure Pipelines azure-pipelines.yml for CaseCrack."""
    return """trigger:
  branches:
    include:
      - main
      - develop
pool:
  vmImage: ubuntu-latest
steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.11'
  - script: pip install casecrack
    displayName: Install CaseCrack
  - script: casecrack scan --target $(Build.Repository.Name)
    displayName: Run scan
  - script: casecrack export --format sarif --output $(Build.ArtifactStagingDirectory)/results.sarif
    displayName: Export SARIF
  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: '$(Build.ArtifactStagingDirectory)'
      artifactName: 'casecrack-results'
"""


# Bind methods to engine class
try:
    CICDPipeline.detect_ci_environment = _t4b_detect_ci_environment       # type: ignore[name-defined]
    CICDPipeline.should_scan_branch = _t4b_should_scan_branch              # type: ignore[name-defined]
    CICDPipeline.is_pull_request = _t4b_is_pull_request                    # type: ignore[name-defined]
    CICDPipeline.generate_sarif = _t4b_generate_sarif                       # type: ignore[name-defined]
    CICDPipeline.save_sarif = _t4b_save_sarif                               # type: ignore[name-defined]
    CICDPipeline.generate_sbom = _t4b_generate_sbom                         # type: ignore[name-defined]
    CICDPipeline.post_status_check = _t4b_post_status_check                 # type: ignore[name-defined]
    CICDPipeline.upload_sarif_to_github = _t4b_upload_sarif_to_github       # type: ignore[name-defined]
    CICDPipeline.generate_github_actions_workflow = _t4b_generate_github_actions_workflow   # type: ignore[name-defined]
    CICDPipeline.generate_gitlab_ci_yaml = _t4b_generate_gitlab_ci_yaml     # type: ignore[name-defined]
    CICDPipeline.generate_jenkins_pipeline = _t4b_generate_jenkins_pipeline # type: ignore[name-defined]
    CICDPipeline.generate_circleci_config = _t4b_generate_circleci_config   # type: ignore[name-defined]
    CICDPipeline.generate_azure_pipelines_yaml = _t4b_generate_azure_pipelines_yaml   # type: ignore[name-defined]
except NameError:
    pass
