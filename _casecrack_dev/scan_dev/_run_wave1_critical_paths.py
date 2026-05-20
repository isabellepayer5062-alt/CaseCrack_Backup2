#!/usr/bin/env python3
"""
Wave 1 automation runner for critical 1-hop paths:
- Authenticated User Session
- Source Code Access
- Database Dump

v2 enhancements:
- --repro-rounds N: re-runs positive Auth findings N extra times
- Expanded Source/DB endpoint coverage (9 Source + 8 DB tests)
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


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class Wave1Test:
    test_id: str
    path: str
    description: str
    cli_args: list
    expected_transition: str
    expected_impact: str


@dataclass
class Wave1Result:
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


def _safe_slug(value):
    return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in value)


def _classify_output(combined):
    """Return (transition_evidence, impact_evidence, cls_status)."""
    lower = combined.lower()
    parser_error = "usage:" in lower and "error:" in lower

    positive_terms = (
        "vulnerability detected",
        "vulnerable:",
        " vulnerabilities found",
        "found ",
        "issues!",
        " confirmed",
        "bypass",
        "token exposed",
        "exposed in response",
        "injection detected",
    )
    negative_terms = (
        "no sql injection vulnerabilities detected",
        "no path traversal vulnerabilities found",
        "no xxe vulnerabilities detected",
        "no account security vulnerabilities detected",
        "no vulnerabilities detected",
        "no blind command injection detected",
        "no ssti vulnerabilities found",
    )
    impact_terms = ("impact:", "attacker can", "admin access", "database dump", "source code")

    has_positive = any(term in lower for term in positive_terms)
    has_negative = any(term in lower for term in negative_terms)
    transition = (not parser_error) and has_positive and not has_negative
    impact = (not parser_error) and transition and any(term in lower for term in impact_terms)
    return transition, impact, ("error" if parser_error else "ok")


# ---------------------------------------------------------------------------
# Test definitions
# ---------------------------------------------------------------------------

def _build_wave1_tests(target):
    target = target.rstrip("/")

    auth_tests = [
        Wave1Test(
            test_id="A1_ACCOUNT_SCAN",
            path="Authenticated User Session",
            description="Account workflow security scan across login/register/reset",
            cli_args=[
                "account",
                "--url", target,
                "--login-url", target + "/login",
                "--register-url", target + "/register",
                "--reset-url", target + "/password/reset",
                "scan",
            ],
            expected_transition="unauthenticated -> user_session",
            expected_impact="access to user-only session state",
        ),
        Wave1Test(
            test_id="A2_ACCOUNT_ENUM",
            path="Authenticated User Session",
            description="Account enumeration and reset flow behavior",
            cli_args=[
                "account",
                "--url", target,
                "--login-url", target + "/login",
                "--reset-url", target + "/password/reset",
                "enum",
            ],
            expected_transition="unauthenticated -> auth workflow weakness",
            expected_impact="user/session acquisition precondition",
        ),
        Wave1Test(
            test_id="A3_OAUTH_FULL",
            path="Authenticated User Session",
            description="OAuth/OIDC full assessment",
            cli_args=["oauth", "--url", target, "full"],
            expected_transition="unauthenticated -> federated/session foothold",
            expected_impact="session token or auth flow compromise",
        ),
    ]

    source_tests = [
        Wave1Test(
            test_id="B1_TRAVERSAL_SEARCH",
            path="Source Code Access",
            description="Path traversal on /search (?q=)",
            cli_args=["traversal", "--url", target + "/search", "--param", "q", "scan"],
            expected_transition="public_data -> file read",
            expected_impact="source/config disclosure",
        ),
        Wave1Test(
            test_id="B2_TRAVERSAL_DOWNLOAD",
            path="Source Code Access",
            description="Path traversal on /download (?file=)",
            cli_args=["traversal", "--url", target + "/download", "--param", "file", "scan"],
            expected_transition="public_data -> file read",
            expected_impact="source/config disclosure",
        ),
        Wave1Test(
            test_id="B3_XXE_XML",
            path="Source Code Access",
            description="XXE scan on /api/xml POST",
            cli_args=["xxe", "--url", target + "/api/xml", "--method", "POST", "scan"],
            expected_transition="public_data -> parser file access",
            expected_impact="source/code or secret file read",
        ),
        Wave1Test(
            test_id="B4_SSTI_SEARCH",
            path="Source Code Access",
            description="SSTI on /search (?q=)",
            cli_args=["ssi", "--url", target + "/search", "--param", "q", "ssti"],
            expected_transition="public_data -> template execution context",
            expected_impact="server-side data exposure",
        ),
        Wave1Test(
            test_id="B5_TRAVERSAL_CATALOG",
            path="Source Code Access",
            description="Path traversal on /api/v1/catalog (?path=)",
            cli_args=["traversal", "--url", target + "/api/v1/catalog", "--param", "path", "scan"],
            expected_transition="public_data -> file read",
            expected_impact="source/config disclosure",
        ),
        Wave1Test(
            test_id="B6_TRAVERSAL_STATIC",
            path="Source Code Access",
            description="Path traversal on /static (?name=)",
            cli_args=["traversal", "--url", target + "/static", "--param", "name", "scan"],
            expected_transition="public_data -> file read",
            expected_impact="source/config disclosure",
        ),
        Wave1Test(
            test_id="B7_XXE_IMPORT",
            path="Source Code Access",
            description="XXE scan on /api/import POST",
            cli_args=["xxe", "--url", target + "/api/import", "--method", "POST", "scan"],
            expected_transition="public_data -> parser file access",
            expected_impact="source/code or secret file read",
        ),
        Wave1Test(
            test_id="B8_TRAVERSAL_PRODUCT_IMG",
            path="Source Code Access",
            description="Path traversal on /product/image (?img=)",
            cli_args=["traversal", "--url", target + "/product/image", "--param", "img", "scan"],
            expected_transition="public_data -> file read",
            expected_impact="source/config disclosure",
        ),
        Wave1Test(
            test_id="B9_SSTI_TEMPLATE",
            path="Source Code Access",
            description="SSTI on /template (?tpl=)",
            cli_args=["ssi", "--url", target + "/template", "--param", "tpl", "ssti"],
            expected_transition="public_data -> template execution context",
            expected_impact="server-side data exposure",
        ),
    ]

    db_tests = [
        Wave1Test(
            test_id="C1_SQLI_SEARCH",
            path="Database Dump",
            description="SQLi scan on /search (?q=)",
            cli_args=["sqli", "--url", target + "/search", "--param", "q", "scan"],
            expected_transition="public_data -> injectable query",
            expected_impact="database extraction",
        ),
        Wave1Test(
            test_id="C2_SQLI_PRODUCT",
            path="Database Dump",
            description="SQLi scan on /product (?id=)",
            cli_args=["sqli", "--url", target + "/product", "--param", "id", "scan"],
            expected_transition="public_data -> injectable query",
            expected_impact="database extraction",
        ),
        Wave1Test(
            test_id="C3_SQLI_GRAPHQL",
            path="Database Dump",
            description="SQLi scan on /graphql POST (?query=)",
            cli_args=["sqli", "--url", target + "/graphql", "--param", "query", "--method", "POST", "scan"],
            expected_transition="public_data -> injectable query",
            expected_impact="database extraction",
        ),
        Wave1Test(
            test_id="C4_SQLI_KEYWORD",
            path="Database Dump",
            description="SQLi scan on /search (?keyword=)",
            cli_args=["sqli", "--url", target + "/search", "--param", "keyword", "scan"],
            expected_transition="public_data -> injectable query",
            expected_impact="database extraction",
        ),
        Wave1Test(
            test_id="C5_SQLI_CATEGORY",
            path="Database Dump",
            description="SQLi scan on /category (?id=)",
            cli_args=["sqli", "--url", target + "/category", "--param", "id", "scan"],
            expected_transition="public_data -> injectable query",
            expected_impact="database extraction",
        ),
        Wave1Test(
            test_id="C6_SQLI_ORDER",
            path="Database Dump",
            description="SQLi scan on /api/orders (?order_id=)",
            cli_args=["sqli", "--url", target + "/api/orders", "--param", "order_id", "scan"],
            expected_transition="public_data -> injectable query",
            expected_impact="database extraction",
        ),
        Wave1Test(
            test_id="C7_SQLI_USER",
            path="Database Dump",
            description="SQLi scan on /api/user (?user_id=)",
            cli_args=["sqli", "--url", target + "/api/user", "--param", "user_id", "scan"],
            expected_transition="public_data -> injectable query",
            expected_impact="database extraction",
        ),
        Wave1Test(
            test_id="C8_SQLI_SORT",
            path="Database Dump",
            description="SQLi scan on /search (?sort=) - ORDER BY injection vector",
            cli_args=["sqli", "--url", target + "/search", "--param", "sort", "scan"],
            expected_transition="public_data -> injectable query",
            expected_impact="database extraction",
        ),
    ]

    return auth_tests + source_tests + db_tests


# ---------------------------------------------------------------------------
# Test execution
# ---------------------------------------------------------------------------

def _run_single_cli(python_exe, workspace_root, cli_args, log_file, timeout_s):
    """Run one CLI command, write log, return (combined_output, exit_code, duration)."""
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
        return Wave1Result(
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
        return Wave1Result(
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

    return Wave1Result(
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
# Reproducibility rounds
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

def _build_markdown_report(target, started_at, results, repro_rounds, required_repro):
    by_path = {}
    for result in results:
        by_path.setdefault(result.path, []).append(result)

    lines = []
    lines.append("# Wave 1 Critical Paths Execution Report")
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

    for path_name in ("Authenticated User Session", "Source Code Access", "Database Dump"):
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

        # Reproducibility sub-table (only populated for Auth path)
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

    for path_name in ("Authenticated User Session", "Source Code Access", "Database Dump"):
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
    parser = argparse.ArgumentParser(description="Run Wave 1 critical-path automation")
    parser.add_argument("--target", default="https://www.tw.coupang.com", help="Base target URL")
    parser.add_argument("--timeout", type=int, default=180, help="Per-test timeout in seconds")
    parser.add_argument("--dry-run", action="store_true", help="Print and record commands without executing")
    parser.add_argument("--out-dir", default="reports/wave1", help="Output base directory")
    parser.add_argument(
        "--repro-rounds",
        type=int,
        default=3,
        help="Reproducibility rounds for positive Auth findings (default: 3)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    workspace_root = Path(__file__).resolve().parent
    python_exe = sys.executable

    run_id = _now_utc()
    output_dir = (workspace_root / args.out_dir / run_id).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    tests = _build_wave1_tests(args.target)
    results = []

    print("[Wave 1] Running {} tests against {} ...".format(len(tests), args.target))
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

    # Reproducibility rounds for positive Auth findings only
    auth_positives = [
        r for r in results
        if r.path == "Authenticated User Session"
        and r.transition_evidence
        and r.impact_evidence
    ]
    repro_rounds = []

    if auth_positives and not args.dry_run:
        print(
            "\n[Repro] {} positive Auth finding(s) detected. Running {} reproducibility round(s) ...".format(
                len(auth_positives), args.repro_rounds
            ),
            flush=True,
        )
        repro_rounds = _run_repro_rounds(
            python_exe=python_exe,
            workspace_root=workspace_root,
            positive_results=auth_positives,
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
        print("\n[Repro] No positive Auth findings — reproducibility rounds skipped.", flush=True)

    promotion = {
        pn: _compute_promotion(pn, results, repro_rounds, args.repro_rounds)
        for pn in ("Authenticated User Session", "Source Code Access", "Database Dump")
    }

    json_report = output_dir / "wave1_results.json"
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

    md_report = output_dir / "wave1_report.md"
    md_report.write_text(
        _build_markdown_report(args.target, run_id, results, repro_rounds, args.repro_rounds),
        encoding="utf-8",
    )

    print("\nWave 1 complete. Run ID: {}".format(run_id))
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
