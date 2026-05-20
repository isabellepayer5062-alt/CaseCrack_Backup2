#!/usr/bin/env python3
"""
Wave 2 automation runner for federation and cloud pivot paths:
- SSO/Federated Auth
- Bucket/Cloud Exposure
- SSH/DB Exposure

Features:
- --repro-rounds N: re-runs positive findings N extra times (all paths)
- Expanded endpoint coverage per path
- Promotion Gate: auto-labels each path as Candidate/Supported/Confirmed
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class Wave2Test:
    test_id: str
    path: str
    description: str
    cli_args: list
    expected_transition: str
    expected_impact: str


@dataclass
class Wave2Result:
    test_id: str
    path: str
    description: str
    command: str
    exit_code: object  # int or None
    duration_s: float
    status: str
    output_file: str
    transition_evidence: bool
    impact_evidence: bool
    error: str = ""


@dataclass
class ReproRound:
    test_id: str
    round_num: int
    status: str
    transition_evidence: bool
    impact_evidence: bool
    duration_s: float
    exit_code: object  # int or None
    error: str = ""


# ---------------------------------------------------------------------------
# Promotion labels
# ---------------------------------------------------------------------------
PROMOTION_CONFIRMED = "Confirmed"
PROMOTION_SUPPORTED = "Supported"
PROMOTION_CANDIDATE = "Candidate"

_LABEL_BADGE = {
    PROMOTION_CONFIRMED: "[CONFIRMED]",
    PROMOTION_SUPPORTED: "[SUPPORTED]",
    PROMOTION_CANDIDATE: "[CANDIDATE]",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_utc():
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _extract_domain(url):
    """Strip scheme and www. prefix to get bare hostname."""
    host = urlparse(url).hostname or url
    if host.startswith("www."):
        host = host[4:]
    return host


def _safe_slug(value):
    return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in value)


def _classify_output(combined):
    """Return (transition_evidence, impact_evidence, cls_status)."""
    lower = combined.lower()
    parser_error = "usage:" in lower and "error:" in lower

    positive_terms = (
        # generic finding signals
        "vulnerability detected",
        "vulnerable:",
        " vulnerabilities found",
        "issues!",
        " confirmed",
        "bypass",
        "token exposed",
        "exposed in response",
        "injection detected",
        # federation-specific
        "oauth misconfiguration",
        "saml vulnerability",
        "jwt vulnerability",
        "csrf token missing",
        "open redirect",
        "state parameter missing",
        "implicit flow",
        "token leakage",
        "sso bypass",
        "id token",
        # cloud/bucket-specific
        "bucket exposed",
        "public bucket",
        "bucket readable",
        "bucket writable",
        "cloud credentials",
        "aws key",
        "azure key",
        "gcp key",
        "api key found",
        "secret found",
        "metadata endpoint",
        "ssrf confirmed",
        # ssh/db-specific
        "open port",
        "ssh port",
        "database port",
        "port 22",
        "port 3306",
        "port 5432",
        "port 6379",
        "port 27017",
        "exposed service",
    )
    negative_terms = (
        "no vulnerabilities detected",
        "no oauth vulnerabilities",
        "no saml vulnerabilities",
        "no jwt vulnerabilities",
        "no cloud vulnerabilities",
        "no secrets found",
        "no open ports",
        "no exposed buckets",
        "no ssrf vulnerabilities detected",
        "no csrf vulnerabilities detected",
        "no account security vulnerabilities detected",
        "found 0 issues",
        "found 0 vulnerabilities",
        "0 issues found",
        "0 findings",
    )
    impact_terms = (
        "impact:",
        "attacker can",
        "admin access",
        "cloud storage",
        "s3 bucket",
        "azure blob",
        "gcp bucket",
        "aws credentials",
        "iam role",
        "ssh access",
        "database access",
        "credential",
        "exfiltration",
        "lateral movement",
        "privilege escalation",
        "session hijack",
        "identity provider",
    )

    has_positive = any(term in lower for term in positive_terms)
    has_negative = any(term in lower for term in negative_terms)
    transition = (not parser_error) and has_positive and not has_negative
    impact = (not parser_error) and transition and any(term in lower for term in impact_terms)
    return transition, impact, ("error" if parser_error else "ok")


# ---------------------------------------------------------------------------
# Test definitions
# ---------------------------------------------------------------------------

def _build_wave2_tests(target):
    target = target.rstrip("/")
    domain = _extract_domain(target)

    # ------------------------------------------------------------------
    # D path: SSO/Federated Auth
    # ------------------------------------------------------------------
    sso_tests = [
        Wave2Test(
            test_id="D1_OAUTH_FULL",
            path="SSO/Federated Auth",
            description="OAuth/OIDC full assessment",
            cli_args=["oauth", "--url", target, "full"],
            expected_transition="unauthenticated -> federated token foothold",
            expected_impact="session token or auth flow compromise via OAuth misconfiguration",
        ),
        Wave2Test(
            test_id="D2_SAML_SCAN",
            path="SSO/Federated Auth",
            description="SAML security scan",
            cli_args=["saml", "--url", target, "scan"],
            expected_transition="unauthenticated -> SAML assertion bypass",
            expected_impact="account takeover via SAML response manipulation",
        ),
        Wave2Test(
            test_id="D3_JWT_SCAN",
            path="SSO/Federated Auth",
            description="JWT security scan (alg:none, key confusion, weak secret)",
            cli_args=["jwt", "--url", target, "test"],
            expected_transition="valid_token -> forged_token",
            expected_impact="arbitrary identity claim; privilege escalation",
        ),
        Wave2Test(
            test_id="D4_CSRF_LOGIN",
            path="SSO/Federated Auth",
            description="CSRF scan on /login (federated CSRF)",
            cli_args=["csrf", "--url", target + "/login", "full"],
            expected_transition="unauthenticated -> forced login to attacker IdP",
            expected_impact="login CSRF enabling account linking hijack",
        ),
        Wave2Test(
            test_id="D5_CSRF_OAUTH_CALLBACK",
            path="SSO/Federated Auth",
            description="CSRF scan on /auth/callback (OAuth state param check)",
            cli_args=["csrf", "--url", target + "/auth/callback", "full"],
            expected_transition="in-flight OAuth flow -> state bypass",
            expected_impact="OAuth CSRF enabling token theft",
        ),
        Wave2Test(
            test_id="D6_OAUTH_RECON",
            path="SSO/Federated Auth",
            description="OAuth deep recon (endpoints, scopes, redirect_uri, PKCE)",
            cli_args=["oauth-recon", "--url", target],
            expected_transition="unauthenticated -> OAuth surface enumeration",
            expected_impact="exposed scopes or unvalidated redirect_uri enabling token exfiltration",
        ),
        Wave2Test(
            test_id="D7_JWT_API",
            path="SSO/Federated Auth",
            description="JWT attack on /api/v1 endpoint (bearer token usage)",
            cli_args=["jwt", "--url", target + "/api/v1", "test"],
            expected_transition="valid_token -> forged_token on API",
            expected_impact="API-level privilege escalation via JWT forgery",
        ),
    ]

    # ------------------------------------------------------------------
    # E path: Bucket/Cloud Exposure
    # ------------------------------------------------------------------
    bucket_tests = [
        Wave2Test(
            test_id="E1_CLOUD_DISCOVERY",
            path="Bucket/Cloud Exposure",
            description="Cloud asset discovery (S3/Azure Blob/GCP bucket enumeration)",
            cli_args=["cloud-discovery", "--target", target, "--domain", domain],
            expected_transition="unauthenticated -> cloud storage asset list",
            expected_impact="public bucket read/write enabling data exfiltration or backdoor upload",
        ),
        Wave2Test(
            test_id="E2_CLOUD_SCAN",
            path="Bucket/Cloud Exposure",
            description="Cloud security scan (AWS/Azure/GCP misconfigurations)",
            cli_args=["cloud", "--url", target, "scan"],
            expected_transition="unauthenticated -> cloud misconfiguration",
            expected_impact="cloud credential leak or metadata service access",
        ),
        Wave2Test(
            test_id="E3_SECRETS_SCAN",
            path="Bucket/Cloud Exposure",
            description="Secrets detection scan (800+ patterns: API keys, cloud creds)",
            cli_args=["secrets", "--url", target, "scan"],
            expected_transition="unauthenticated -> credential in response/page",
            expected_impact="cloud credential exfiltration enabling direct cloud access",
        ),
        Wave2Test(
            test_id="E4_SECRETS_API",
            path="Bucket/Cloud Exposure",
            description="Secrets detection on /api (REST endpoint secrets leak)",
            cli_args=["secrets", "--url", target + "/api", "scan"],
            expected_transition="api_response -> credential leak",
            expected_impact="exposed API keys enabling cloud resource takeover",
        ),
        Wave2Test(
            test_id="E5_SUBDOMAIN_SCAN",
            path="Bucket/Cloud Exposure",
            description="Subdomain enumeration (cloud-linked subdomains: s3, cdn, storage)",
            cli_args=["subdomain", "--domain", domain],
            expected_transition="domain -> cloud-linked subdomain discovery",
            expected_impact="dangling CNAME or public cloud subdomain enabling takeover",
        ),
        Wave2Test(
            test_id="E6_SSRF_CLOUD_META",
            path="Bucket/Cloud Exposure",
            description="SSRF scan targeting cloud metadata endpoint (169.254.169.254)",
            cli_args=["ssrf", "--url", target + "/api/fetch", "--param", "url", "--webhook", "https://burpcollaborator.net"],
            expected_transition="user_input -> SSRF to cloud metadata",
            expected_impact="IAM credential theft via EC2/GCE metadata service",
        ),
        Wave2Test(
            test_id="E7_SSRF_INTERNAL",
            path="Bucket/Cloud Exposure",
            description="SSRF scan on /proxy endpoint",
            cli_args=["ssrf", "--url", target + "/proxy", "--param", "target", "--webhook", "https://burpcollaborator.net"],
            expected_transition="user_input -> SSRF to internal service",
            expected_impact="internal cloud service access via SSRF pivot",
        ),
    ]

    # ------------------------------------------------------------------
    # F path: SSH/DB Exposure
    # ------------------------------------------------------------------
    sshdb_tests = [
        Wave2Test(
            test_id="F1_NETWORK_MAP",
            path="SSH/DB Exposure",
            description="Network infrastructure map (identify DB and SSH ports)",
            cli_args=["network-map", "--targets", target],
            expected_transition="domain -> exposed service port",
            expected_impact="direct SSH or database access from internet",
        ),
        Wave2Test(
            test_id="F2_DNS_SCAN",
            path="SSH/DB Exposure",
            description="DNS security scan (A/MX/TXT leaking internal infra)",
            cli_args=["dns", "--domain", domain, "scan"],
            expected_transition="domain -> DNS record leaking internal IP/service",
            expected_impact="internal IP disclosure enabling pivot to SSH/DB",
        ),
        Wave2Test(
            test_id="F3_CLOUD_SSH_DB",
            path="SSH/DB Exposure",
            description="Cloud scan focused on SSH/DB security group misconfigurations",
            cli_args=["cloud", "--url", target, "scan"],
            expected_transition="unauthenticated -> misconfigured security group",
            expected_impact="SSH/database port exposed to internet via cloud misconfiguration",
        ),
        Wave2Test(
            test_id="F4_SECRETS_DB_CREDS",
            path="SSH/DB Exposure",
            description="Secrets scan targeting DB connection strings and SSH keys",
            cli_args=["secrets", "--url", target, "scan"],
            expected_transition="page/response -> DB connection string or SSH private key",
            expected_impact="direct database authentication or SSH login",
        ),
        Wave2Test(
            test_id="F5_TRAVERSAL_ENV",
            path="SSH/DB Exposure",
            description="Path traversal targeting .env and config files with DB creds",
            cli_args=["traversal", "--url", target + "/api", "--param", "file", "scan"],
            expected_transition="public_endpoint -> .env or config file read",
            expected_impact="DB connection string or SSH private key exposure",
        ),
        Wave2Test(
            test_id="F6_SSRF_INTERNAL_DB",
            path="SSH/DB Exposure",
            description="SSRF scan probing internal DB ports via request parameter",
            cli_args=["ssrf", "--url", target + "/api/connect", "--param", "host", "--webhook", "https://burpcollaborator.net"],
            expected_transition="user_input -> SSRF to internal DB port",
            expected_impact="internal DB service access via SSRF pivot",
        ),
    ]

    return sso_tests + bucket_tests + sshdb_tests


# ---------------------------------------------------------------------------
# Test execution
# ---------------------------------------------------------------------------

def _run_single_cli(python_exe, workspace_root, cli_args, log_file, timeout_s):
    """Run one CLI command, write log, return (combined_output, exit_code, duration, error)."""
    cmd = [python_exe, "-m", "tools.burp_enterprise.cli"] + list(cli_args)
    env = os.environ.copy()
    env["PYTHONPATH"] = "CaseCrack"
    start = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(workspace_root),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        duration = time.monotonic() - start
        combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
        log_file.write_text(combined, encoding="utf-8", errors="replace")
        return combined, proc.returncode, duration, None
    except subprocess.TimeoutExpired:
        duration = time.monotonic() - start
        msg = "TIMEOUT after {}s\n".format(timeout_s)
        log_file.write_text(msg, encoding="utf-8")
        return msg, None, duration, "Timeout after {}s".format(timeout_s)
    except Exception as exc:
        duration = time.monotonic() - start
        msg = "ERROR: {}\n".format(exc)
        log_file.write_text(msg, encoding="utf-8")
        return msg, None, duration, str(exc)


def _run_cli_test(python_exe, workspace_root, test, output_dir, timeout_s, dry_run):
    test_dir = output_dir / _safe_slug(test.path)
    test_dir.mkdir(parents=True, exist_ok=True)
    output_file = test_dir / (test.test_id + ".log")

    cmd = [python_exe, "-m", "tools.burp_enterprise.cli"] + list(test.cli_args)
    cmd_str = " ".join(shlex.quote(part) for part in cmd)

    if dry_run:
        output_file.write_text("DRY_RUN\n" + cmd_str + "\n", encoding="utf-8")
        return Wave2Result(
            test_id=test.test_id,
            path=test.path,
            description=test.description,
            command=cmd_str,
            exit_code=0,
            duration_s=0.0,
            status="dry-run",
            output_file=str(output_file),
            transition_evidence=False,
            impact_evidence=False,
        )

    combined, exit_code, duration, err = _run_single_cli(
        python_exe, workspace_root, test.cli_args, output_file, timeout_s
    )

    if err:
        return Wave2Result(
            test_id=test.test_id,
            path=test.path,
            description=test.description,
            command=cmd_str,
            exit_code=exit_code,
            duration_s=round(duration, 2),
            status="timeout" if "Timeout" in err else "error",
            output_file=str(output_file),
            transition_evidence=False,
            impact_evidence=False,
            error=err,
        )

    transition, impact, cls_status = _classify_output(combined)

    if cls_status == "error":
        status = "error"
    elif exit_code == 2:
        status = "findings"
    elif exit_code == 0:
        status = "ok"
    else:
        status = "error"

    return Wave2Result(
        test_id=test.test_id,
        path=test.path,
        description=test.description,
        command=cmd_str,
        exit_code=exit_code,
        duration_s=round(duration, 2),
        status=status,
        output_file=str(output_file),
        transition_evidence=transition,
        impact_evidence=impact,
    )


# ---------------------------------------------------------------------------
# Reproducibility rounds — applied to all positive findings (all 3 paths)
# ---------------------------------------------------------------------------

def _run_repro_rounds(python_exe, workspace_root, positive_results, all_tests, output_dir, timeout_s, num_rounds):
    test_map = {t.test_id: t for t in all_tests}
    rounds = []
    repro_dir = output_dir / "repro"
    repro_dir.mkdir(parents=True, exist_ok=True)

    for result in positive_results:
        test = test_map.get(result.test_id)
        if test is None:
            continue
        for rn in range(1, num_rounds + 1):
            log_file = repro_dir / "{}_r{}.log".format(result.test_id, rn)
            combined, exit_code, duration, err = _run_single_cli(
                python_exe, workspace_root, test.cli_args, log_file, timeout_s
            )
            if err:
                rounds.append(ReproRound(
                    test_id=result.test_id,
                    round_num=rn,
                    status="timeout" if "Timeout" in err else "error",
                    transition_evidence=False,
                    impact_evidence=False,
                    duration_s=round(duration, 2),
                    exit_code=exit_code,
                    error=err,
                ))
                continue
            transition, impact, cls_status = _classify_output(combined)
            if cls_status == "error":
                r_status = "error"
            elif exit_code == 2:
                r_status = "findings"
            elif exit_code == 0:
                r_status = "ok"
            else:
                r_status = "error"
            rounds.append(ReproRound(
                test_id=result.test_id,
                round_num=rn,
                status=r_status,
                transition_evidence=transition,
                impact_evidence=impact,
                duration_s=round(duration, 2),
                exit_code=exit_code,
            ))
    return rounds


# ---------------------------------------------------------------------------
# Promotion gate
# ---------------------------------------------------------------------------

def _compute_promotion(path_name, results, repro_rounds, required_repro):
    path_results = [r for r in results if r.path == path_name]
    positive = [r for r in path_results if r.transition_evidence and r.impact_evidence]

    if not positive:
        return {
            "label": PROMOTION_CANDIDATE,
            "reason": "No tests produced both transition and impact evidence.",
            "positive_tests": [],
            "repro_summary": {},
        }

    repro_summary = {}
    any_confirmed = False
    for p in positive:
        rounds_for_test = [r for r in repro_rounds if r.test_id == p.test_id]
        positive_rounds = [r for r in rounds_for_test if r.transition_evidence and r.impact_evidence]
        repro_summary[p.test_id] = {
            "rounds_run": len(rounds_for_test),
            "rounds_positive": len(positive_rounds),
            "required": required_repro,
            "all_positive": len(rounds_for_test) > 0 and len(positive_rounds) == len(rounds_for_test),
        }
        if len(rounds_for_test) >= required_repro and len(positive_rounds) >= required_repro:
            any_confirmed = True

    label = PROMOTION_CONFIRMED if any_confirmed else PROMOTION_SUPPORTED
    if any_confirmed:
        reason = "All {} reproducibility rounds positive — chain promotion approved.".format(required_repro)
    else:
        reason = (
            "Positive finding detected but reproducibility threshold not met "
            "({} rounds required).".format(required_repro)
        )
    return {
        "label": label,
        "reason": reason,
        "positive_tests": [p.test_id for p in positive],
        "repro_summary": repro_summary,
    }


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

PATH_NAMES = ("SSO/Federated Auth", "Bucket/Cloud Exposure", "SSH/DB Exposure")


def _build_markdown_report(target, started_at, results, repro_rounds, required_repro):
    by_path = {}
    for result in results:
        by_path.setdefault(result.path, []).append(result)

    lines = []
    lines.append("# Wave 2 Federation & Cloud Pivots Execution Report")
    lines.append("")
    lines.append("**Target:** {}".format(target))
    lines.append("**Generated:** {}".format(datetime.now(timezone.utc).isoformat()))
    lines.append("**Run ID:** {}".format(started_at))
    lines.append("**Repro rounds required:** {}".format(required_repro))
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    total = len(results)
    findings = sum(1 for r in results if r.status == "findings")
    errors = sum(1 for r in results if r.status in {"error", "timeout"})
    transition_hits = sum(1 for r in results if r.transition_evidence)
    impact_hits = sum(1 for r in results if r.impact_evidence)
    lines.append("- Total tests: {}".format(total))
    lines.append("- Finding-positive tests: {}".format(findings))
    lines.append("- Error/timeout tests: {}".format(errors))
    lines.append("- Transition-evidence tests: {}".format(transition_hits))
    lines.append("- Impact-evidence tests: {}".format(impact_hits))
    lines.append("- Repro rounds run: {}".format(len(repro_rounds)))
    lines.append("")

    for path_name in PATH_NAMES:
        path_results = by_path.get(path_name, [])
        lines.append("## {}".format(path_name))
        lines.append("")
        if not path_results:
            lines.append("No tests executed.")
            lines.append("")
            continue

        lines.append("| Test ID | Status | Exit | Transition | Impact | Duration (s) | Output |")
        lines.append("| --- | --- | ---: | --- | --- | ---: | --- |")
        for row in path_results:
            exit_display = "-" if row.exit_code is None else str(row.exit_code)
            lines.append(
                "| {} | {} | {} | {} | {} | {:.2f} | {} |".format(
                    row.test_id, row.status, exit_display,
                    "yes" if row.transition_evidence else "no",
                    "yes" if row.impact_evidence else "no",
                    row.duration_s, row.output_file,
                )
            )
        lines.append("")

        # Reproducibility sub-table (for any positive findings in this path)
        test_ids_in_path = {pr.test_id for pr in path_results}
        path_repros = [r for r in repro_rounds if r.test_id in test_ids_in_path]
        if path_repros:
            lines.append("### Reproducibility Rounds ({} required for Confirmed)".format(required_repro))
            lines.append("")
            lines.append("| Test ID | Round | Status | Transition | Impact | Duration (s) |")
            lines.append("| --- | ---: | --- | --- | --- | ---: |")
            for rr in path_repros:
                lines.append(
                    "| {} | {} | {} | {} | {} | {:.2f} |".format(
                        rr.test_id, rr.round_num, rr.status,
                        "yes" if rr.transition_evidence else "no",
                        "yes" if rr.impact_evidence else "no",
                        rr.duration_s,
                    )
                )
            lines.append("")

    # Promotion Gate
    lines.append("## Promotion Gate")
    lines.append("")
    lines.append(
        "**Thresholds:** CONFIRMED = positive finding + all {} repro rounds positive "
        "| SUPPORTED = positive finding, repro threshold not met "
        "| CANDIDATE = no positive finding.".format(required_repro)
    )
    lines.append("")
    lines.append("| Path | Label | Positive Tests | Repro (passed/run) | Reason |")
    lines.append("| --- | :---: | --- | --- | --- |")

    for path_name in PATH_NAMES:
        gate = _compute_promotion(path_name, results, repro_rounds, required_repro)
        badge = _LABEL_BADGE.get(gate["label"], gate["label"])
        pos_tests = ", ".join(gate["positive_tests"]) if gate["positive_tests"] else "none"
        repro_parts = []
        for tid, rs in gate["repro_summary"].items():
            repro_parts.append("{}: {}/{}".format(tid, rs["rounds_positive"], rs["rounds_run"]))
        repro_display = "; ".join(repro_parts) if repro_parts else "N/A"
        lines.append(
            "| {} | {} | {} | {} | {} |".format(
                path_name, badge, pos_tests, repro_display, gate["reason"]
            )
        )

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(description="Run Wave 2 federation & cloud pivot automation")
    parser.add_argument("--target", default="https://www.tw.coupang.com", help="Base target URL")
    parser.add_argument("--timeout", type=int, default=180, help="Per-test timeout in seconds")
    parser.add_argument("--dry-run", action="store_true", help="Print and record commands without executing")
    parser.add_argument("--out-dir", default="reports/wave2", help="Output base directory")
    parser.add_argument(
        "--repro-rounds",
        type=int,
        default=3,
        help="Reproducibility rounds for positive findings (default: 3)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    workspace_root = Path(__file__).resolve().parent
    python_exe = sys.executable

    run_id = _now_utc()
    output_dir = (workspace_root / args.out_dir / run_id).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    tests = _build_wave2_tests(args.target)
    results = []

    print("[Wave 2] Running {} tests against {} ...".format(len(tests), args.target))
    for test in tests:
        print("  [{}] {} ...".format(test.test_id, test.description), flush=True)
        result = _run_cli_test(
            python_exe=python_exe,
            workspace_root=workspace_root,
            test=test,
            output_dir=output_dir,
            timeout_s=args.timeout,
            dry_run=args.dry_run,
        )
        print(
            "  [{}] done — status={} transition={} impact={}".format(
                test.test_id, result.status, result.transition_evidence, result.impact_evidence
            ),
            flush=True,
        )
        results.append(result)

    # Reproducibility rounds for ALL positive findings across all paths
    all_positives = [
        r for r in results
        if r.transition_evidence and r.impact_evidence
    ]
    repro_rounds = []

    if all_positives and not args.dry_run:
        print(
            "\n[Repro] {} positive finding(s) across all paths. Running {} reproducibility round(s) ...".format(
                len(all_positives), args.repro_rounds
            ),
            flush=True,
        )
        repro_rounds = _run_repro_rounds(
            python_exe=python_exe,
            workspace_root=workspace_root,
            positive_results=all_positives,
            all_tests=tests,
            output_dir=output_dir,
            timeout_s=args.timeout,
            num_rounds=args.repro_rounds,
        )
        for rr in repro_rounds:
            print(
                "  [{} r{}] status={} transition={} impact={}".format(
                    rr.test_id, rr.round_num, rr.status,
                    rr.transition_evidence, rr.impact_evidence
                ),
                flush=True,
            )
    else:
        print("\n[Repro] No positive findings — reproducibility rounds skipped.", flush=True)

    promotion = {
        pn: _compute_promotion(pn, results, repro_rounds, args.repro_rounds)
        for pn in PATH_NAMES
    }

    json_report = output_dir / "wave2_results.json"
    with json_report.open("w", encoding="utf-8") as f:
        json.dump(
            {
                "target": args.target,
                "run_id": run_id,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "dry_run": bool(args.dry_run),
                "repro_rounds_required": args.repro_rounds,
                "results": [asdict(item) for item in results],
                "repro_rounds": [asdict(rr) for rr in repro_rounds],
                "promotion": promotion,
            },
            f,
            indent=2,
        )

    md_report = output_dir / "wave2_report.md"
    md_report.write_text(
        _build_markdown_report(args.target, run_id, results, repro_rounds, args.repro_rounds),
        encoding="utf-8",
    )

    print("\nWave 2 complete. Run ID: {}".format(run_id))
    print("  JSON: {}".format(json_report))
    print("  Markdown: {}".format(md_report))

    print("\n[Promotion Gate]")
    for pn, gate in promotion.items():
        badge = _LABEL_BADGE.get(gate["label"], gate["label"])
        print("  {}: {} -- {}".format(pn, badge, gate["reason"]))

    any_findings = any(item.status == "findings" for item in results)
    return 2 if any_findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
