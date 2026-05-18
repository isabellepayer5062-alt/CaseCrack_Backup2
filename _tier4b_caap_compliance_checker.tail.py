# __TIER4B_CAAP__
# Tier 4B CAAP — compliance_checker: per-control evaluators × 8 frameworks
import re as _t4b_re
import json as _t4b_json
from typing import Any, Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

# 8 compliance frameworks with structured controls
_T4B_FRAMEWORKS: Dict[str, Dict[str, Dict[str, Any]]] = {
    "owasp_top10": {
        "A01_broken_access_control": {"title": "Broken Access Control", "severity": "high"},
        "A02_crypto_failures": {"title": "Cryptographic Failures", "severity": "high"},
        "A03_injection": {"title": "Injection", "severity": "critical"},
        "A04_insecure_design": {"title": "Insecure Design", "severity": "high"},
        "A05_security_misconfig": {"title": "Security Misconfiguration", "severity": "medium"},
        "A06_vulnerable_components": {"title": "Vulnerable & Outdated Components", "severity": "high"},
        "A07_auth_failures": {"title": "Identification & Authentication Failures", "severity": "high"},
        "A08_software_integrity": {"title": "Software & Data Integrity Failures", "severity": "high"},
        "A09_logging_failures": {"title": "Security Logging & Monitoring Failures", "severity": "medium"},
        "A10_ssrf": {"title": "Server-Side Request Forgery", "severity": "high"},
    },
    "pci_dss_v4": {
        "1.3.1": {"title": "Inbound traffic restricted", "severity": "high"},
        "2.2.1": {"title": "Configuration standards", "severity": "medium"},
        "3.5.1": {"title": "PAN protection", "severity": "critical"},
        "4.2.1": {"title": "Strong cryptography in transit", "severity": "high"},
        "6.2.1": {"title": "Bespoke software security", "severity": "high"},
        "6.2.4": {"title": "Engineer training", "severity": "low"},
        "6.4.2": {"title": "Public-facing apps protected", "severity": "high"},
        "8.3.1": {"title": "MFA for non-console admin", "severity": "high"},
        "11.3.1": {"title": "Internal vulnerability scans", "severity": "medium"},
        "11.4.1": {"title": "Penetration testing", "severity": "high"},
    },
    "hipaa": {
        "164.312_a_1": {"title": "Access control", "severity": "high"},
        "164.312_a_2": {"title": "Unique user identification", "severity": "high"},
        "164.312_b": {"title": "Audit controls", "severity": "medium"},
        "164.312_c_1": {"title": "Integrity", "severity": "high"},
        "164.312_d": {"title": "Person/entity authentication", "severity": "high"},
        "164.312_e_1": {"title": "Transmission security", "severity": "high"},
    },
    "gdpr": {
        "art_25": {"title": "Data protection by design", "severity": "high"},
        "art_32": {"title": "Security of processing", "severity": "high"},
        "art_33": {"title": "Breach notification", "severity": "medium"},
        "art_35": {"title": "DPIA", "severity": "medium"},
    },
    "iso27001": {
        "A.5.10": {"title": "Acceptable use of info", "severity": "low"},
        "A.8.2": {"title": "Privileged access", "severity": "high"},
        "A.8.3": {"title": "Information access restriction", "severity": "high"},
        "A.8.16": {"title": "Monitoring activities", "severity": "medium"},
        "A.8.23": {"title": "Web filtering", "severity": "medium"},
        "A.8.24": {"title": "Use of cryptography", "severity": "high"},
        "A.8.25": {"title": "Secure development lifecycle", "severity": "high"},
    },
    "nist_csf": {
        "ID.AM-1": {"title": "Physical devices inventory", "severity": "low"},
        "PR.AC-1": {"title": "Identities/credentials managed", "severity": "high"},
        "PR.DS-1": {"title": "Data-at-rest protected", "severity": "high"},
        "PR.DS-2": {"title": "Data-in-transit protected", "severity": "high"},
        "DE.CM-1": {"title": "Network monitored", "severity": "medium"},
        "DE.CM-4": {"title": "Malicious code detected", "severity": "medium"},
    },
    "soc2": {
        "CC6.1": {"title": "Logical access controls", "severity": "high"},
        "CC6.6": {"title": "Boundary protection", "severity": "high"},
        "CC6.7": {"title": "Data transmission", "severity": "high"},
        "CC7.1": {"title": "Vulnerability detection", "severity": "medium"},
        "CC7.2": {"title": "System monitoring", "severity": "medium"},
    },
    "cis_v8": {
        "1.1": {"title": "Enterprise asset inventory", "severity": "low"},
        "3.10": {"title": "Encrypt sensitive data in transit", "severity": "high"},
        "3.11": {"title": "Encrypt sensitive data at rest", "severity": "high"},
        "5.2": {"title": "Unique passwords", "severity": "high"},
        "6.3": {"title": "MFA for externally-exposed apps", "severity": "high"},
        "7.5": {"title": "Automated vulnerability scans", "severity": "medium"},
        "16.1": {"title": "Establish secure dev process", "severity": "medium"},
    },
}


# Per-control evaluator functions
def _eval_injection(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    matches = [f for f in findings
                  if any(k in (f.get("title", "") + f.get("type", "")).lower()
                            for k in ("sqli", "sql injection", "command injection", "xxe", "ldap injection",
                                       "nosql injection", "template injection", "ssti", "code injection"))]
    return {"violated": len(matches) > 0, "evidence_count": len(matches),
              "evidence": [f.get("id") or f.get("title") for f in matches[:5]]}


def _eval_access_control(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    matches = [f for f in findings
                  if any(k in (f.get("title", "") + f.get("type", "")).lower()
                            for k in ("idor", "broken access", "privilege escalation", "directory traversal",
                                       "path traversal", "missing authorization"))]
    return {"violated": len(matches) > 0, "evidence_count": len(matches),
              "evidence": [f.get("id") or f.get("title") for f in matches[:5]]}


def _eval_crypto(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    matches = [f for f in findings
                  if any(k in (f.get("title", "") + f.get("type", "")).lower()
                            for k in ("weak cipher", "weak tls", "ssl", "md5", "sha1", "rc4", "cleartext",
                                       "weak random", "weak crypto", "self-signed"))]
    return {"violated": len(matches) > 0, "evidence_count": len(matches),
              "evidence": [f.get("id") or f.get("title") for f in matches[:5]]}


def _eval_misconfig(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    matches = [f for f in findings
                  if any(k in (f.get("title", "") + f.get("type", "")).lower()
                            for k in ("misconfiguration", "default credentials", "exposed admin",
                                       "directory listing", "verbose error", "debug mode"))]
    return {"violated": len(matches) > 0, "evidence_count": len(matches),
              "evidence": [f.get("id") or f.get("title") for f in matches[:5]]}


def _eval_outdated(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    matches = [f for f in findings
                  if any(k in (f.get("title", "") + f.get("type", "")).lower()
                            for k in ("outdated", "vulnerable component", "cve-", "end-of-life", "unsupported version"))]
    return {"violated": len(matches) > 0, "evidence_count": len(matches),
              "evidence": [f.get("id") or f.get("title") for f in matches[:5]]}


def _eval_auth(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    matches = [f for f in findings
                  if any(k in (f.get("title", "") + f.get("type", "")).lower()
                            for k in ("weak password", "no rate limit", "brute", "session fixation",
                                       "no mfa", "credential stuffing", "weak auth"))]
    return {"violated": len(matches) > 0, "evidence_count": len(matches),
              "evidence": [f.get("id") or f.get("title") for f in matches[:5]]}


def _eval_ssrf(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    matches = [f for f in findings
                  if "ssrf" in (f.get("title", "") + f.get("type", "")).lower()]
    return {"violated": len(matches) > 0, "evidence_count": len(matches),
              "evidence": [f.get("id") or f.get("title") for f in matches[:5]]}


def _eval_logging(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    matches = [f for f in findings
                  if any(k in (f.get("title", "") + f.get("type", "")).lower()
                            for k in ("missing log", "no audit", "insufficient logging", "no monitoring"))]
    return {"violated": len(matches) > 0, "evidence_count": len(matches),
              "evidence": [f.get("id") or f.get("title") for f in matches[:5]]}


def _eval_transmission(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    matches = [f for f in findings
                  if any(k in (f.get("title", "") + f.get("type", "")).lower()
                            for k in ("http only", "no tls", "missing https", "mixed content", "weak tls"))]
    return {"violated": len(matches) > 0, "evidence_count": len(matches),
              "evidence": [f.get("id") or f.get("title") for f in matches[:5]]}


# Mapping from control ID to evaluator
_T4B_CONTROL_EVALS: Dict[str, Callable[[List[Dict[str, Any]]], Dict[str, Any]]] = {
    "owasp_top10:A01_broken_access_control": _eval_access_control,
    "owasp_top10:A02_crypto_failures": _eval_crypto,
    "owasp_top10:A03_injection": _eval_injection,
    "owasp_top10:A05_security_misconfig": _eval_misconfig,
    "owasp_top10:A06_vulnerable_components": _eval_outdated,
    "owasp_top10:A07_auth_failures": _eval_auth,
    "owasp_top10:A09_logging_failures": _eval_logging,
    "owasp_top10:A10_ssrf": _eval_ssrf,
    "pci_dss_v4:3.5.1": _eval_crypto,
    "pci_dss_v4:4.2.1": _eval_transmission,
    "pci_dss_v4:6.4.2": _eval_misconfig,
    "pci_dss_v4:8.3.1": _eval_auth,
    "pci_dss_v4:11.3.1": _eval_outdated,
    "hipaa:164.312_a_1": _eval_access_control,
    "hipaa:164.312_b": _eval_logging,
    "hipaa:164.312_d": _eval_auth,
    "hipaa:164.312_e_1": _eval_transmission,
    "gdpr:art_32": _eval_crypto,
    "iso27001:A.8.2": _eval_access_control,
    "iso27001:A.8.16": _eval_logging,
    "iso27001:A.8.24": _eval_crypto,
    "nist_csf:PR.AC-1": _eval_auth,
    "nist_csf:PR.DS-1": _eval_crypto,
    "nist_csf:PR.DS-2": _eval_transmission,
    "nist_csf:DE.CM-1": _eval_logging,
    "soc2:CC6.1": _eval_access_control,
    "soc2:CC6.7": _eval_transmission,
    "soc2:CC7.1": _eval_outdated,
    "soc2:CC7.2": _eval_logging,
    "cis_v8:3.10": _eval_transmission,
    "cis_v8:3.11": _eval_crypto,
    "cis_v8:5.2": _eval_auth,
    "cis_v8:6.3": _eval_auth,
    "cis_v8:7.5": _eval_outdated,
}


def _t4b_supported_frameworks(self) -> List[str]:
    return list(_T4B_FRAMEWORKS.keys())


def _t4b_framework_controls(self, framework: str) -> Dict[str, Any]:
    return dict(_T4B_FRAMEWORKS.get(framework, {}))


def _t4b_evaluate_control(self, framework: str, control_id: str,
                              findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    fw = _T4B_FRAMEWORKS.get(framework)
    if not fw or control_id not in fw:
        return {"ok": False, "error": "unknown_control"}
    meta = fw[control_id]
    key = f"{framework}:{control_id}"
    evaluator = _T4B_CONTROL_EVALS.get(key)
    if evaluator is None:
        # No automated evaluator — treat as inconclusive
        return {"ok": True, "framework": framework, "control_id": control_id,
                  "title": meta["title"], "severity": meta["severity"],
                  "status": "manual_review_required", "violated": False,
                  "evidence": [], "automated": False}
    eval_result = evaluator(findings)
    status = "fail" if eval_result["violated"] else "pass"
    return {"ok": True, "framework": framework, "control_id": control_id,
              "title": meta["title"], "severity": meta["severity"],
              "status": status, "violated": eval_result["violated"],
              "evidence": eval_result["evidence"], "evidence_count": eval_result["evidence_count"],
              "automated": True}


def _t4b_evaluate_framework(self, framework: str,
                                findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    fw = _T4B_FRAMEWORKS.get(framework)
    if not fw:
        return {"ok": False, "error": "unknown_framework"}
    results = []
    for cid in fw:
        results.append(_t4b_evaluate_control(self, framework, cid, findings))
    failed = [r for r in results if r.get("status") == "fail"]
    passed = [r for r in results if r.get("status") == "pass"]
    manual = [r for r in results if r.get("status") == "manual_review_required"]
    score = round(100.0 * len(passed) / max(1, len(passed) + len(failed)), 1)
    return {"ok": True, "framework": framework, "controls_total": len(results),
              "controls_failed": len(failed), "controls_passed": len(passed),
              "controls_manual": len(manual), "score_pct": score,
              "results": results}


def _t4b_evaluate_all_frameworks(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    out = {"frameworks": {}, "summary": {}}
    overall_failed = 0
    overall_total = 0
    for fw in _T4B_FRAMEWORKS:
        r = _t4b_evaluate_framework(self, fw, findings)
        out["frameworks"][fw] = r
        overall_failed += r.get("controls_failed", 0)
        overall_total += r.get("controls_total", 0)
    out["summary"] = {
        "frameworks_evaluated": len(_T4B_FRAMEWORKS),
        "total_controls": overall_total,
        "total_failures": overall_failed,
        "overall_score_pct": round(100.0 * (overall_total - overall_failed) / max(1, overall_total), 1),
    }
    return out


def _t4b_compliance_gap_report(self, framework: str,
                                    findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    res = _t4b_evaluate_framework(self, framework, findings)
    if not res.get("ok"):
        return res
    gaps = [r for r in res["results"] if r.get("status") == "fail"]
    by_severity: Dict[str, int] = {}
    for g in gaps:
        sev = g["severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1
    return {
        "framework": framework,
        "gap_count": len(gaps),
        "gaps_by_severity": by_severity,
        "gaps": [{"control": g["control_id"], "title": g["title"],
                    "severity": g["severity"], "evidence_count": g["evidence_count"]}
                   for g in gaps],
    }


def _t4b_register_control_evaluator(self, framework: str, control_id: str,
                                          evaluator: Callable[[List[Dict[str, Any]]], Dict[str, Any]]) -> bool:
    if framework not in _T4B_FRAMEWORKS or control_id not in _T4B_FRAMEWORKS[framework]:
        return False
    _T4B_CONTROL_EVALS[f"{framework}:{control_id}"] = evaluator
    return True


def _t4b_export_compliance_csv(self, results: Dict[str, Any]) -> str:
    lines = ["framework,control_id,title,severity,status,evidence_count"]
    for fw, fw_res in results.get("frameworks", {}).items():
        for r in fw_res.get("results", []):
            lines.append(
                f'{fw},{r["control_id"]},"{r["title"]}",{r["severity"]},'
                f'{r["status"]},{r.get("evidence_count", 0)}'
            )
    return "\n".join(lines)


# --- Bind to ComplianceChecker ------------------------------------------
try:
    ComplianceChecker.supported_frameworks = _t4b_supported_frameworks  # type: ignore[name-defined]
    ComplianceChecker.framework_controls = _t4b_framework_controls  # type: ignore[name-defined]
    ComplianceChecker.evaluate_control = _t4b_evaluate_control  # type: ignore[name-defined]
    ComplianceChecker.evaluate_framework = _t4b_evaluate_framework  # type: ignore[name-defined]
    ComplianceChecker.evaluate_all_frameworks = _t4b_evaluate_all_frameworks  # type: ignore[name-defined]
    ComplianceChecker.compliance_gap_report = _t4b_compliance_gap_report  # type: ignore[name-defined]
    ComplianceChecker.register_control_evaluator = _t4b_register_control_evaluator  # type: ignore[name-defined]
    ComplianceChecker.export_compliance_csv = _t4b_export_compliance_csv  # type: ignore[name-defined]
except NameError:
    pass
