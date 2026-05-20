

# __TIER4B_INTEGRATIONS__ sonarqube
# Tier 4B: Hotspot review (security_hotspots/search, change_status, assign),
#          quality gate metrics, project/branch APIs, issue assignment, Webhook integration

import os as _t4b_os
import json as _t4b_json
import time as _t4b_time
import base64 as _t4b_b64
import urllib.request as _t4b_req
import urllib.parse as _t4b_urlparse
import urllib.error as _t4b_urlerr
from typing import Any, Dict, List, Optional, Tuple


_T4B_SQ_HOTSPOT_STATUSES = ("TO_REVIEW", "REVIEWED")
_T4B_SQ_HOTSPOT_RESOLUTIONS = ("FIXED", "SAFE", "ACKNOWLEDGED")
_T4B_SQ_HOTSPOT_VULN_PROBABILITY = ("HIGH", "MEDIUM", "LOW")


def _t4b_sq_request(self, method: str, path: str, params: Optional[Dict[str, Any]] = None,
                     form_body: Optional[Dict[str, Any]] = None,
                     timeout: int = 30) -> Tuple[int, Any]:
    """Generic authenticated SonarQube Web API request (Bearer token)."""
    cfg = getattr(self, "config", None)
    base = (getattr(cfg, "url", None) if cfg else None) or _t4b_os.environ.get("SONAR_URL", "")
    token = (getattr(cfg, "token", None) if cfg else None) or _t4b_os.environ.get("SONAR_TOKEN", "")
    if not base:
        raise RuntimeError("Sonar URL not configured")
    base = base.rstrip("/")
    url = f"{base}/api/{path.lstrip('/')}"
    if params:
        url += "?" + _t4b_urlparse.urlencode(params, doseq=True)
    # SonarQube prefers Basic auth with token as username, no password
    creds = _t4b_b64.b64encode(f"{token}:".encode()).decode("ascii") if token else ""
    headers = {"Authorization": f"Basic {creds}", "Accept": "application/json"} if token else {"Accept": "application/json"}
    if form_body:
        data = _t4b_urlparse.urlencode(form_body).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    else:
        data = None
    req = _t4b_req.Request(url, data=data, headers=headers, method=method.upper())
    try:
        with _t4b_req.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            try:
                return resp.status, _t4b_json.loads(raw.decode("utf-8")) if raw else None
            except Exception:
                return resp.status, raw
    except _t4b_urlerr.HTTPError as e:
        try:
            err = _t4b_json.loads(e.read().decode("utf-8"))
        except Exception:
            err = {"error": e.reason}
        return e.code, err


# ---------------------------------------------------------------------------
# Hotspot review (security hotspots are tracked separately from issues)
# ---------------------------------------------------------------------------
def _t4b_search_hotspots(self, project_key: str, branch: Optional[str] = None,
                          status: Optional[str] = None, resolution: Optional[str] = None,
                          page_size: int = 100, max_pages: int = 10) -> List[Dict[str, Any]]:
    """List security hotspots for a project."""
    rs = self._check_dry_run("search_hotspots", project=project_key, status=status)
    if rs is not None:
        return rs if isinstance(rs, list) else []
    hotspots: List[Dict[str, Any]] = []
    page = 1
    while page <= max_pages:
        params: Dict[str, Any] = {"projectKey": project_key, "ps": page_size, "p": page}
        if branch:
            params["branch"] = branch
        if status and status in _T4B_SQ_HOTSPOT_STATUSES:
            params["status"] = status
        if resolution and resolution in _T4B_SQ_HOTSPOT_RESOLUTIONS:
            params["resolution"] = resolution
        code, resp = _t4b_sq_request(self, "GET", "hotspots/search", params=params)
        if not (200 <= code < 300 and isinstance(resp, dict)):
            break
        batch = resp.get("hotspots", [])
        hotspots.extend(batch)
        paging = resp.get("paging", {})
        total = paging.get("total", 0)
        if not batch or len(hotspots) >= total:
            break
        page += 1
    return hotspots


def _t4b_get_hotspot_detail(self, hotspot_key: str) -> Dict[str, Any]:
    """Get full hotspot detail including code context, rule, history."""
    code, resp = _t4b_sq_request(self, "GET", "hotspots/show", params={"hotspot": hotspot_key})
    if 200 <= code < 300:
        return resp or {}
    return {"error": resp, "code": code}


def _t4b_change_hotspot_status(self, hotspot_key: str, status: str = "REVIEWED",
                                 resolution: Optional[str] = "SAFE", comment: Optional[str] = None) -> Dict[str, Any]:
    """Change hotspot status (review workflow). status='REVIEWED' requires resolution in (FIXED, SAFE, ACKNOWLEDGED)."""
    rs = self._check_dry_run("change_hotspot_status", hotspot=hotspot_key, status=status, resolution=resolution)
    if rs is not None:
        return rs
    if status not in _T4B_SQ_HOTSPOT_STATUSES:
        return {"changed": False, "error": f"invalid status: {status}"}
    body: Dict[str, Any] = {"hotspot": hotspot_key, "status": status}
    if status == "REVIEWED":
        if resolution not in _T4B_SQ_HOTSPOT_RESOLUTIONS:
            return {"changed": False, "error": f"REVIEWED requires resolution in {_T4B_SQ_HOTSPOT_RESOLUTIONS}"}
        body["resolution"] = resolution
    if comment:
        body["comment"] = comment[:1000]
    code, resp = _t4b_sq_request(self, "POST", "hotspots/change_status", form_body=body)
    return {"changed": 200 <= code < 300, "code": code, "response": resp}


def _t4b_assign_hotspot(self, hotspot_key: str, assignee: str, comment: Optional[str] = None) -> Dict[str, Any]:
    """Assign hotspot to user."""
    rs = self._check_dry_run("assign_hotspot", hotspot=hotspot_key, assignee=assignee)
    if rs is not None:
        return rs
    body: Dict[str, Any] = {"hotspot": hotspot_key, "assignee": assignee}
    if comment:
        body["comment"] = comment[:1000]
    code, resp = _t4b_sq_request(self, "POST", "hotspots/assign", form_body=body)
    return {"assigned": 200 <= code < 300, "code": code}


def _t4b_hotspot_summary(self, project_key: str, branch: Optional[str] = None) -> Dict[str, Any]:
    """Aggregate hotspot stats by status × probability."""
    hotspots = _t4b_search_hotspots(self, project_key, branch=branch, page_size=500)
    by_status: Dict[str, int] = {}
    by_prob: Dict[str, int] = {}
    by_category: Dict[str, int] = {}
    unassigned = 0
    for h in hotspots:
        s = h.get("status", "UNKNOWN")
        by_status[s] = by_status.get(s, 0) + 1
        vp = h.get("vulnerabilityProbability", "UNKNOWN")
        by_prob[vp] = by_prob.get(vp, 0) + 1
        cat = h.get("securityCategory", "UNKNOWN")
        by_category[cat] = by_category.get(cat, 0) + 1
        if not h.get("assignee"):
            unassigned += 1
    return {
        "total": len(hotspots),
        "by_status": by_status,
        "by_vulnerability_probability": by_prob,
        "by_security_category": by_category,
        "unassigned": unassigned,
        "to_review": by_status.get("TO_REVIEW", 0),
    }


# ---------------------------------------------------------------------------
# Quality gate
# ---------------------------------------------------------------------------
def _t4b_get_quality_gate_status(self, project_key: str, branch: Optional[str] = None) -> Dict[str, Any]:
    """Get full quality gate status with failed conditions."""
    params: Dict[str, Any] = {"projectKey": project_key}
    if branch:
        params["branch"] = branch
    code, resp = _t4b_sq_request(self, "GET", "qualitygates/project_status", params=params)
    if 200 <= code < 300 and isinstance(resp, dict):
        ps = resp.get("projectStatus", {})
        conditions = ps.get("conditions", [])
        failed = [c for c in conditions if c.get("status") == "ERROR"]
        warnings = [c for c in conditions if c.get("status") == "WARN"]
        return {
            "status": ps.get("status", "NONE"),
            "passed": ps.get("status") == "OK",
            "failed_conditions": failed,
            "warning_conditions": warnings,
            "total_conditions": len(conditions),
            "ignored_for_new_code": ps.get("ignoredConditions", False),
        }
    return {"error": resp, "code": code}


def _t4b_get_measures(self, project_key: str, metrics: Optional[List[str]] = None,
                       branch: Optional[str] = None) -> Dict[str, Any]:
    """Get project measures (bugs/vulnerabilities/code_smells/coverage/duplications/etc.)."""
    metrics = metrics or [
        "bugs", "vulnerabilities", "security_hotspots", "code_smells",
        "coverage", "duplicated_lines_density", "ncloc", "sqale_rating",
        "reliability_rating", "security_rating", "alert_status",
        "new_bugs", "new_vulnerabilities", "new_code_smells",
    ]
    params: Dict[str, Any] = {"component": project_key, "metricKeys": ",".join(metrics)}
    if branch:
        params["branch"] = branch
    code, resp = _t4b_sq_request(self, "GET", "measures/component", params=params)
    if 200 <= code < 300 and isinstance(resp, dict):
        comp = resp.get("component", {})
        out = {m.get("metric"): m.get("value") for m in comp.get("measures", [])}
        return {"project": project_key, "metrics": out}
    return {"error": resp, "code": code}


# ---------------------------------------------------------------------------
# Project & branch APIs
# ---------------------------------------------------------------------------
def _t4b_list_projects(self, query: Optional[str] = None, page_size: int = 100,
                        max_pages: int = 10) -> List[Dict[str, Any]]:
    """List visible projects."""
    out: List[Dict[str, Any]] = []
    page = 1
    while page <= max_pages:
        params: Dict[str, Any] = {"ps": page_size, "p": page}
        if query:
            params["q"] = query
        code, resp = _t4b_sq_request(self, "GET", "projects/search", params=params)
        if not (200 <= code < 300 and isinstance(resp, dict)):
            break
        batch = resp.get("components", [])
        out.extend(batch)
        if not batch or len(out) >= resp.get("paging", {}).get("total", 0):
            break
        page += 1
    return out


def _t4b_list_branches(self, project_key: str) -> List[Dict[str, Any]]:
    """List branches for a project."""
    code, resp = _t4b_sq_request(self, "GET", "project_branches/list", params={"project": project_key})
    if 200 <= code < 300 and isinstance(resp, dict):
        return resp.get("branches", [])
    return []


def _t4b_list_pull_requests(self, project_key: str) -> List[Dict[str, Any]]:
    """List pull requests for a project."""
    code, resp = _t4b_sq_request(self, "GET", "project_pull_requests/list", params={"project": project_key})
    if 200 <= code < 300 and isinstance(resp, dict):
        return resp.get("pullRequests", [])
    return []


# ---------------------------------------------------------------------------
# Issue management
# ---------------------------------------------------------------------------
def _t4b_assign_issue(self, issue_key: str, assignee: str) -> Dict[str, Any]:
    """Assign issue to user."""
    rs = self._check_dry_run("assign_issue", issue=issue_key, assignee=assignee)
    if rs is not None:
        return rs
    code, resp = _t4b_sq_request(self, "POST", "issues/assign",
                                   form_body={"issue": issue_key, "assignee": assignee})
    return {"assigned": 200 <= code < 300, "code": code}


def _t4b_change_issue_severity(self, issue_key: str, severity: str) -> Dict[str, Any]:
    """Override issue severity (BLOCKER/CRITICAL/MAJOR/MINOR/INFO)."""
    rs = self._check_dry_run("change_issue_severity", issue=issue_key, severity=severity)
    if rs is not None:
        return rs
    if severity.upper() not in ("BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"):
        return {"changed": False, "error": f"invalid severity: {severity}"}
    code, resp = _t4b_sq_request(self, "POST", "issues/set_severity",
                                   form_body={"issue": issue_key, "severity": severity.upper()})
    return {"changed": 200 <= code < 300, "code": code}


def _t4b_resolve_issue(self, issue_key: str, transition: str = "resolve",
                        comment: Optional[str] = None) -> Dict[str, Any]:
    """Apply transition: confirm/resolve/falsepositive/wontfix/reopen."""
    rs = self._check_dry_run("resolve_issue", issue=issue_key, transition=transition)
    if rs is not None:
        return rs
    code, resp = _t4b_sq_request(self, "POST", "issues/do_transition",
                                   form_body={"issue": issue_key, "transition": transition})
    if comment:
        _t4b_sq_request(self, "POST", "issues/add_comment",
                          form_body={"issue": issue_key, "text": comment[:1000]})
    return {"resolved": 200 <= code < 300, "code": code}


# ---------------------------------------------------------------------------
# Webhooks (server-side configuration)
# ---------------------------------------------------------------------------
def _t4b_register_webhook(self, name: str, url: str, project_key: Optional[str] = None,
                            secret: Optional[str] = None) -> Dict[str, Any]:
    """Register a webhook at project or global scope."""
    rs = self._check_dry_run("register_webhook", name=name, url=url)
    if rs is not None:
        return rs
    body: Dict[str, Any] = {"name": name[:100], "url": url}
    if project_key:
        body["project"] = project_key
    if secret:
        body["secret"] = secret
    code, resp = _t4b_sq_request(self, "POST", "webhooks/create", form_body=body)
    return {"registered": 200 <= code < 300, "code": code, "response": resp}


def _t4b_list_webhooks(self, project_key: Optional[str] = None) -> List[Dict[str, Any]]:
    """List configured webhooks."""
    params: Dict[str, Any] = {}
    if project_key:
        params["project"] = project_key
    code, resp = _t4b_sq_request(self, "GET", "webhooks/list", params=params)
    if 200 <= code < 300 and isinstance(resp, dict):
        return resp.get("webhooks", [])
    return []


try:
    SonarClient.search_hotspots = _t4b_search_hotspots               # type: ignore[name-defined]
    SonarClient.get_hotspot_detail = _t4b_get_hotspot_detail         # type: ignore[name-defined]
    SonarClient.change_hotspot_status = _t4b_change_hotspot_status   # type: ignore[name-defined]
    SonarClient.assign_hotspot = _t4b_assign_hotspot                 # type: ignore[name-defined]
    SonarClient.hotspot_summary = _t4b_hotspot_summary               # type: ignore[name-defined]
    SonarClient.get_quality_gate_status = _t4b_get_quality_gate_status   # type: ignore[name-defined]
    SonarClient.get_measures = _t4b_get_measures                     # type: ignore[name-defined]
    SonarClient.list_projects = _t4b_list_projects                   # type: ignore[name-defined]
    SonarClient.list_branches = _t4b_list_branches                   # type: ignore[name-defined]
    SonarClient.list_pull_requests = _t4b_list_pull_requests         # type: ignore[name-defined]
    SonarClient.assign_issue = _t4b_assign_issue                     # type: ignore[name-defined]
    SonarClient.change_issue_severity = _t4b_change_issue_severity   # type: ignore[name-defined]
    SonarClient.resolve_issue = _t4b_resolve_issue                   # type: ignore[name-defined]
    SonarClient.register_webhook = _t4b_register_webhook             # type: ignore[name-defined]
    SonarClient.list_webhooks = _t4b_list_webhooks                   # type: ignore[name-defined]
except NameError:
    pass
