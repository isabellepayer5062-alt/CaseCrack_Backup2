"""Tier 4B Integrations validation harness — validates all 6 integration modules."""
import sys
import os
import json
import pathlib
import importlib

ROOT = pathlib.Path(__file__).parent
sys.path.insert(0, str(ROOT / "CaseCrack"))

PASS = 0
FAIL = 0


def check(name: str, fn):
    global PASS, FAIL
    try:
        result = fn()
        ok = bool(result) if not isinstance(result, dict) else result.get("ok", True)
        if ok:
            PASS += 1
            print(f"  OK {name}: {result if not isinstance(result, dict) else 'pass'}")
        else:
            FAIL += 1
            print(f"  FAIL {name}: {result}")
    except Exception as e:
        FAIL += 1
        print(f"  FAIL {name}: {type(e).__name__}: {e}")


def main():
    print("\n=== IMPORTS (6 integration modules) ===")
    mods = {}
    for n in ("ci_cd_pipeline", "defect_dojo", "jira_client", "slack_notifier",
              "sonarqube", "webhook_dispatcher"):
        try:
            m = importlib.import_module(f"tools.burp_enterprise.integrations.{n}")
            mods[n] = m
            print(f"  OK import {n}")
        except Exception as e:
            print(f"  FAIL import {n}: {type(e).__name__}: {e}")
            return

    print("\n=== Tier 4B method presence ===")
    expected = {
        "ci_cd_pipeline": ("CICDPipeline", [
            "detect_ci_environment", "should_scan_branch", "is_pull_request",
            "generate_sarif", "save_sarif", "generate_sbom",
            "post_status_check", "upload_sarif_to_github",
            "generate_github_actions_workflow", "generate_gitlab_ci_yaml",
            "generate_jenkins_pipeline", "generate_circleci_config",
            "generate_azure_pipelines_yaml",
        ]),
        "defect_dojo": ("DefectDojoClient", [
            "upload_sarif", "upload_sbom", "reimport_scan",
            "list_products", "create_product", "close_engagement",
            "accept_risk", "get_metrics", "dedup_findings", "search_findings",
        ]),
        "jira_client": ("JiraClient", [
            "jql_builder", "search_jql", "search_all", "bulk_create_issues",
            "get_transitions", "transition_issue", "link_issues",
            "attach_file", "get_custom_field_id", "set_custom_fields",
            "add_to_sprint", "text_to_adf",
        ]),
        "slack_notifier": ("SlackNotifier", [
            "block_kit", "send_blocks", "finding_card", "send_finding",
            "send_batch_summary", "open_thread", "send_modal_payload",
            "send_alert", "validate_blocks",
        ]),
        "sonarqube": ("SonarClient", [
            "search_hotspots", "get_hotspot_detail", "change_hotspot_status",
            "assign_hotspot", "hotspot_summary", "get_quality_gate_status",
            "get_measures", "list_projects", "list_branches", "list_pull_requests",
            "assign_issue", "change_issue_severity", "resolve_issue",
            "register_webhook", "list_webhooks",
        ]),
        "webhook_dispatcher": ("WebhookDispatcher", [
            "dispatch_signed", "replay_dlq", "dlq_stats", "dlq_dead_letters",
            "dlq_purge_dead", "verify_incoming", "sign_outgoing",
            "circuit_state", "circuit_snapshot", "batch_dispatch",
        ]),
    }
    total = 0
    missing = []
    for mod_name, (cls_name, methods) in expected.items():
        cls = getattr(mods[mod_name], cls_name, None)
        if cls is None:
            missing.append(f"{mod_name}.{cls_name}")
            continue
        for m in methods:
            total += 1
            if not hasattr(cls, m):
                missing.append(f"{cls_name}.{m}")
    if missing:
        print(f"  FAIL missing: {missing}")
    else:
        print(f"  OK all {total} methods present across 6 classes")

    # ---------------------------------------------------------
    # CI/CD
    # ---------------------------------------------------------
    print("\n=== CI/CD pipeline ===")
    from tools.burp_enterprise.integrations.ci_cd_pipeline import CICDPipeline
    p = CICDPipeline()
    ctx = p.detect_ci_environment()
    check("detect_ci_environment returns dict", lambda: isinstance(ctx, dict) and "platform" in ctx)
    allowed, reason = p.should_scan_branch(branch="main", allowed_branches=["main", "develop"])
    check("should_scan_branch allows main", lambda: allowed and "allowed" in reason)
    blocked, reason = p.should_scan_branch(branch="dependabot/foo", skip_patterns=["dependabot/"])
    check("should_scan_branch skips dependabot/", lambda: not blocked)
    findings = [
        {"title": "SQL Injection", "severity": "high", "url": "/login", "line": 42,
         "description": "User input not sanitized", "rule_id": "sqli"},
        {"title": "XSS", "severity": "medium", "url": "/search", "line": 88,
         "description": "Reflected", "rule_id": "xss_reflected"},
    ]
    sarif = p.generate_sarif(findings)
    check("SARIF has 2 results", lambda: len(sarif["runs"][0]["results"]) == 2)
    check("SARIF has rules", lambda: len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 2)
    check("SARIF schema URL", lambda: sarif.get("$schema", "").startswith("https://raw"))
    check("SARIF version 2.1.0", lambda: sarif["version"] == "2.1.0")
    sarif_path = str(ROOT / "_t4b_int_test.sarif")
    saved = p.save_sarif(findings, sarif_path)
    check("save_sarif persists", lambda: pathlib.Path(sarif_path).exists() and saved["results"] == 2)
    pathlib.Path(sarif_path).unlink(missing_ok=True)
    sbom_cdx = p.generate_sbom([{"name": "django", "version": "4.2", "type": "library"}], fmt="cyclonedx")
    check("CycloneDX SBOM", lambda: sbom_cdx["bomFormat"] == "CycloneDX" and sbom_cdx["specVersion"] == "1.4")
    sbom_spdx = p.generate_sbom([{"name": "django", "version": "4.2"}], fmt="spdx")
    check("SPDX SBOM", lambda: sbom_spdx["spdxVersion"] == "SPDX-2.3")
    gha = p.generate_github_actions_workflow()
    check("GHA workflow has codeql upload", lambda: "codeql-action/upload-sarif" in gha)
    glab = p.generate_gitlab_ci_yaml()
    check("GitLab CI yaml has SAST report", lambda: "sast: gl-sast-report.json" in glab)
    jenk = p.generate_jenkins_pipeline()
    check("Jenkinsfile has pipeline {", lambda: "pipeline {" in jenk and "recordIssues" in jenk)
    circle = p.generate_circleci_config()
    check("CircleCI config has version 2.1", lambda: 'version: 2.1' in circle)
    azure = p.generate_azure_pipelines_yaml()
    check("Azure Pipelines yaml has UsePythonVersion", lambda: "UsePythonVersion@0" in azure)

    # ---------------------------------------------------------
    # Jira JQL builder
    # ---------------------------------------------------------
    print("\n=== Jira — JQL builder ===")
    from tools.burp_enterprise.integrations.jira_client import JiraClient, JQLBuilder
    jc = JiraClient()
    jql = jc.jql_builder().project("SEC").status(["Open", "In Progress"]).priority("High").assignee("currentuser").order_by("created", "DESC").build()
    check("JQL contains project=SEC", lambda: 'project = "SEC"' in jql)
    check("JQL contains status in", lambda: "status in" in jql)
    check("JQL contains currentUser()", lambda: "currentUser()" in jql)
    check("JQL ORDER BY DESC", lambda: "ORDER BY created DESC" in jql)
    jql2 = jc.jql_builder().project("SEC").is_open().created_after(7).text_contains("XSS").build()
    check("JQL has -7d", lambda: "-7d" in jql2)
    check("JQL text~", lambda: 'text ~ "XSS"' in jql2)
    jql3 = jc.jql_builder().sprint("open").epic_link("SEC-100").build()
    check("JQL openSprints()", lambda: "openSprints()" in jql3)
    check("JQL Epic Link", lambda: '"Epic Link" = "SEC-100"' in jql3)
    adf = jc.text_to_adf("Hello\n\nWorld")
    check("ADF doc structure", lambda: adf["type"] == "doc" and len(adf["content"]) == 2)

    # ---------------------------------------------------------
    # Slack Block Kit
    # ---------------------------------------------------------
    print("\n=== Slack — Block Kit ===")
    from tools.burp_enterprise.integrations.slack_notifier import SlackNotifier, BlockKit
    sn = SlackNotifier()
    bk = sn.block_kit()
    bk.header("Test Header").section(text="*Bold* text").divider().context("footer")
    bk.actions(BlockKit.button("OK", "btn_ok", value="1", style="primary"),
               BlockKit.button("Cancel", "btn_cancel", value="0"))
    blocks = bk.blocks()
    check("BlockKit has 5 blocks", lambda: len(blocks) == 5)
    check("Header type", lambda: blocks[0]["type"] == "header")
    check("Actions has 2 buttons", lambda: len(blocks[4]["elements"]) == 2)
    check("Primary button style", lambda: blocks[4]["elements"][0]["style"] == "primary")
    fc = sn.finding_card({"id": "F-1", "title": "SQL Injection", "severity": "high",
                            "url": "/login", "rule_id": "sqli", "description": "test"})
    check("Finding card has header", lambda: any(b["type"] == "header" for b in fc))
    check("Finding card has 3 actions", lambda: any(b["type"] == "actions" and len(b["elements"]) == 3 for b in fc))
    select = BlockKit.static_select("sev_select", "Choose severity",
                                      [("Critical", "critical"), ("High", "high"), ("Medium", "medium")])
    check("static_select has 3 options", lambda: len(select["options"]) == 3)
    dp = BlockKit.datepicker("date_select", "Pick a date", initial_date="2026-04-20")
    check("datepicker initial_date", lambda: dp["initial_date"] == "2026-04-20")
    val = sn.validate_blocks(blocks)
    check("validate_blocks returns valid=True", lambda: val["valid"])
    bad_blocks = [{"type": "header", "text": {"type": "plain_text", "text": "x" * 200}}]
    val_bad = sn.validate_blocks(bad_blocks)
    check("validate_blocks flags too-long header", lambda: not val_bad["valid"])
    modal = sn.send_modal_payload("Review Finding", bk, callback_id="cb_review")
    check("modal payload type", lambda: modal["type"] == "modal" and modal["callback_id"] == "cb_review")

    # ---------------------------------------------------------
    # SARIF/SBOM upload — defect_dojo
    # ---------------------------------------------------------
    print("\n=== DefectDojo — local-side primitives ===")
    from tools.burp_enterprise.integrations.defect_dojo import DefectDojoClient
    dd = DefectDojoClient()
    dups = [
        {"title": "SQLi", "severity": "high", "url": "/x", "line": 1},
        {"title": "SQLi", "severity": "high", "url": "/x", "line": 1},
        {"title": "XSS", "severity": "medium", "url": "/y", "line": 5},
    ]
    deduped = dd.dedup_findings(dups)
    check("dedup_findings collapses duplicates", lambda: len(deduped) == 2)

    # ---------------------------------------------------------
    # SonarQube — local primitives
    # ---------------------------------------------------------
    print("\n=== SonarQube — local primitives ===")
    from tools.burp_enterprise.integrations.sonarqube import SonarClient
    sc = SonarClient()
    # Just verify methods callable signatures (won't hit network without token)
    check("hotspot_summary callable", lambda: callable(sc.hotspot_summary))
    check("get_quality_gate_status callable", lambda: callable(sc.get_quality_gate_status))

    # ---------------------------------------------------------
    # Webhook dispatcher — DLQ + signing + circuit breaker
    # ---------------------------------------------------------
    print("\n=== Webhook dispatcher — DLQ + HMAC + circuit breaker ===")
    from tools.burp_enterprise.integrations.webhook_dispatcher import WebhookDispatcher, DLQEntry
    wd = WebhookDispatcher()
    # HMAC roundtrip
    sig = wd.sign_outgoing("topsecret", b'{"x": 1}', "sha256")
    check("sign_outgoing format", lambda: sig.startswith("sha256="))
    check("verify_incoming roundtrip", lambda: wd.verify_incoming("topsecret", b'{"x": 1}', sig))
    check("verify_incoming bad sig", lambda: not wd.verify_incoming("topsecret", b'{"x": 1}', "sha256=" + "0" * 64))
    # Dispatch to invalid endpoint → DLQ
    res = wd.dispatch_signed("http://127.0.0.1:1/nonexistent", "test.event",
                              {"hello": "world"}, secret="s", max_attempts=1, timeout=2)
    check("dispatch to invalid endpoint queued to DLQ",
          lambda: not res["sent"] and res.get("queued_to_dlq"))
    stats = wd.dlq_stats()
    check("DLQ stats has pending", lambda: stats["by_status"].get("pending", 0) >= 1)
    dead = wd.dlq_dead_letters(limit=10)
    check("dlq_dead_letters returns list", lambda: isinstance(dead, list))
    # Circuit breaker
    for _ in range(6):
        wd.dispatch_signed("http://127.0.0.1:2/badendpoint", "evt", {}, max_attempts=1, timeout=1)
    state = wd.circuit_state("http://127.0.0.1:2/badendpoint")
    check("circuit opens after threshold failures", lambda: state in ("open", "half_open"))
    # Replay (will fail because endpoints still bad — should mark retrying or dead)
    replay = wd.replay_dlq(max_attempts=2, batch=10)
    check("replay_dlq processes entries", lambda: replay["processed"] >= 1)

    # ---------------------------------------------------------
    # LOC growth
    # ---------------------------------------------------------
    print("\n=== LOC growth ===")
    pkg = ROOT / "CaseCrack" / "tools" / "burp_enterprise" / "integrations"
    total = 0
    for n in ("ci_cd_pipeline", "defect_dojo", "jira_client", "slack_notifier",
              "sonarqube", "webhook_dispatcher"):
        path = pkg / f"{n}.py"
        loc = path.read_text(encoding="utf-8").count("\n")
        total += loc
        print(f"  {n}.py: {loc} LOC")
    print(f"  TOTAL: {total} LOC across 6 modules (avg {total // 6})")

    print(f"\n=== TIER 4B INTEGRATIONS VALIDATION COMPLETE: PASS={PASS}, FAIL={FAIL} ===")


if __name__ == "__main__":
    main()
