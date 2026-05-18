

# __TIER4B_INTEGRATIONS__ jira_client
# Tier 4B: JQL builder DSL, bulk operations, custom field mapping, attachments,
#          link/transition workflows, sprint integration

import os as _t4b_os
import json as _t4b_json
import time as _t4b_time
import base64 as _t4b_b64
import urllib.request as _t4b_req
import urllib.parse as _t4b_urlparse
import urllib.error as _t4b_urlerr
from typing import Any, Dict, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# JQL builder DSL — fluent chainable query builder
# ---------------------------------------------------------------------------
class JQLBuilder:
    """Fluent JQL builder. Use .project(), .status(), etc. then .build()."""

    def __init__(self):
        self._clauses: List[str] = []
        self._order_by: Optional[str] = None
        self._order_dir: str = "ASC"

    @staticmethod
    def _quote(v: Any) -> str:
        if isinstance(v, (int, float)):
            return str(v)
        s = str(v).replace('"', '\\"')
        return f'"{s}"'

    def _add(self, clause: str) -> "JQLBuilder":
        self._clauses.append(clause)
        return self

    def project(self, key: Union[str, List[str]]) -> "JQLBuilder":
        if isinstance(key, list):
            return self._add(f"project in ({', '.join(self._quote(k) for k in key)})")
        return self._add(f"project = {self._quote(key)}")

    def status(self, status: Union[str, List[str]]) -> "JQLBuilder":
        if isinstance(status, list):
            return self._add(f"status in ({', '.join(self._quote(s) for s in status)})")
        return self._add(f"status = {self._quote(status)}")

    def status_not(self, status: Union[str, List[str]]) -> "JQLBuilder":
        if isinstance(status, list):
            return self._add(f"status not in ({', '.join(self._quote(s) for s in status)})")
        return self._add(f"status != {self._quote(status)}")

    def assignee(self, user: str) -> "JQLBuilder":
        if user.lower() in ("currentuser", "me"):
            return self._add("assignee = currentUser()")
        if user.lower() in ("unassigned", "none"):
            return self._add("assignee is EMPTY")
        return self._add(f"assignee = {self._quote(user)}")

    def reporter(self, user: str) -> "JQLBuilder":
        return self._add(f"reporter = {self._quote(user)}")

    def priority(self, p: Union[str, List[str]]) -> "JQLBuilder":
        if isinstance(p, list):
            return self._add(f"priority in ({', '.join(self._quote(x) for x in p)})")
        return self._add(f"priority = {self._quote(p)}")

    def issue_type(self, t: Union[str, List[str]]) -> "JQLBuilder":
        if isinstance(t, list):
            return self._add(f"issuetype in ({', '.join(self._quote(x) for x in t)})")
        return self._add(f"issuetype = {self._quote(t)}")

    def label(self, label: Union[str, List[str]]) -> "JQLBuilder":
        if isinstance(label, list):
            return self._add(f"labels in ({', '.join(self._quote(x) for x in label)})")
        return self._add(f"labels = {self._quote(label)}")

    def has_label(self, label: str) -> "JQLBuilder":
        return self._add(f"labels = {self._quote(label)}")

    def created_after(self, days_ago: int) -> "JQLBuilder":
        return self._add(f"created >= -{days_ago}d")

    def updated_after(self, days_ago: int) -> "JQLBuilder":
        return self._add(f"updated >= -{days_ago}d")

    def resolved_after(self, days_ago: int) -> "JQLBuilder":
        return self._add(f"resolved >= -{days_ago}d")

    def text_contains(self, text: str) -> "JQLBuilder":
        return self._add(f'text ~ {self._quote(text)}')

    def summary_contains(self, text: str) -> "JQLBuilder":
        return self._add(f'summary ~ {self._quote(text)}')

    def description_contains(self, text: str) -> "JQLBuilder":
        return self._add(f'description ~ {self._quote(text)}')

    def sprint(self, sprint: Union[str, int]) -> "JQLBuilder":
        if sprint == "open":
            return self._add("sprint in openSprints()")
        if sprint == "closed":
            return self._add("sprint in closedSprints()")
        if sprint == "future":
            return self._add("sprint in futureSprints()")
        return self._add(f"sprint = {self._quote(sprint)}")

    def epic_link(self, epic_key: str) -> "JQLBuilder":
        return self._add(f"\"Epic Link\" = {self._quote(epic_key)}")

    def component(self, comp: str) -> "JQLBuilder":
        return self._add(f"component = {self._quote(comp)}")

    def fix_version(self, version: str) -> "JQLBuilder":
        return self._add(f"fixVersion = {self._quote(version)}")

    def is_open(self) -> "JQLBuilder":
        return self._add("statusCategory != Done")

    def is_resolved(self) -> "JQLBuilder":
        return self._add("statusCategory = Done")

    def custom_field(self, field_id: str, op: str, value: Any) -> "JQLBuilder":
        return self._add(f'cf[{field_id}] {op} {self._quote(value)}')

    def raw(self, jql_fragment: str) -> "JQLBuilder":
        return self._add(f"({jql_fragment})")

    def order_by(self, field: str, direction: str = "ASC") -> "JQLBuilder":
        self._order_by = field
        self._order_dir = "DESC" if direction.upper() == "DESC" else "ASC"
        return self

    def build(self) -> str:
        jql = " AND ".join(self._clauses) if self._clauses else ""
        if self._order_by:
            jql += f" ORDER BY {self._order_by} {self._order_dir}"
        return jql.strip()

    def __str__(self) -> str:
        return self.build()


def _t4b_jira_request(self, method: str, path: str, params: Optional[Dict[str, Any]] = None,
                       json_body: Optional[Any] = None, raw_data: Optional[bytes] = None,
                       extra_headers: Optional[Dict[str, str]] = None,
                       timeout: int = 30) -> Tuple[int, Any]:
    """Generic authenticated Jira REST API v3 request (Basic auth: email:api_token)."""
    cfg = getattr(self, "config", None)
    base = (getattr(cfg, "url", None) if cfg else None) or _t4b_os.environ.get("JIRA_URL", "")
    email = (getattr(cfg, "email", None) if cfg else None) or _t4b_os.environ.get("JIRA_EMAIL", "")
    token = (getattr(cfg, "api_token", None) if cfg else None) or _t4b_os.environ.get("JIRA_API_TOKEN", "")
    if not base:
        raise RuntimeError("Jira URL not configured")
    base = base.rstrip("/")
    url = f"{base}/rest/api/3/{path.lstrip('/')}"
    if params:
        url += "?" + _t4b_urlparse.urlencode(params, doseq=True)
    creds = _t4b_b64.b64encode(f"{email}:{token}".encode()).decode("ascii")
    headers = {"Authorization": f"Basic {creds}", "Accept": "application/json"}
    if json_body is not None:
        data = _t4b_json.dumps(json_body).encode()
        headers["Content-Type"] = "application/json"
    elif raw_data is not None:
        data = raw_data
    else:
        data = None
    if extra_headers:
        headers.update(extra_headers)
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


def _t4b_jql_builder(self) -> JQLBuilder:
    """Return a new JQLBuilder for fluent query construction."""
    return JQLBuilder()


def _t4b_search_jql(self, jql: Union[str, JQLBuilder], fields: Optional[List[str]] = None,
                     start_at: int = 0, max_results: int = 50) -> Dict[str, Any]:
    """Search issues with JQL (string or JQLBuilder). Returns full JSON result."""
    rs = self._check_dry_run("search_jql", jql=str(jql), max_results=max_results)
    if rs is not None:
        return rs
    body = {
        "jql": str(jql),
        "startAt": start_at,
        "maxResults": min(100, max(1, max_results)),
        "fields": fields or ["summary", "status", "priority", "assignee", "created", "updated", "labels"],
    }
    code, resp = _t4b_jira_request(self, "POST", "search", json_body=body)
    if 200 <= code < 300:
        return resp or {}
    return {"error": resp, "code": code}


def _t4b_search_all(self, jql: Union[str, JQLBuilder], fields: Optional[List[str]] = None,
                     page_size: int = 50, max_pages: int = 20) -> List[Dict[str, Any]]:
    """Search and auto-paginate all matching issues."""
    issues: List[Dict[str, Any]] = []
    start = 0
    for _ in range(max_pages):
        page = _t4b_search_jql(self, jql, fields=fields, start_at=start, max_results=page_size)
        if "error" in page:
            break
        batch = page.get("issues", [])
        issues.extend(batch)
        if len(batch) < page_size or start + len(batch) >= page.get("total", 0):
            break
        start += page_size
    return issues


def _t4b_bulk_create_issues(self, issues: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Bulk-create up to 50 issues in a single request."""
    rs = self._check_dry_run("bulk_create_issues", count=len(issues))
    if rs is not None:
        return rs
    if len(issues) > 50:
        return {"error": "max 50 issues per bulk create", "count": len(issues)}
    body = {"issueUpdates": [{"fields": i} for i in issues]}
    code, resp = _t4b_jira_request(self, "POST", "issue/bulk", json_body=body)
    return {"created": 200 <= code < 300, "code": code, "issues": (resp or {}).get("issues", []),
            "errors": (resp or {}).get("errors", [])}


def _t4b_get_transitions(self, issue_key: str) -> List[Dict[str, Any]]:
    """Get available transitions for an issue."""
    code, resp = _t4b_jira_request(self, "GET", f"issue/{issue_key}/transitions")
    if 200 <= code < 300:
        return (resp or {}).get("transitions", [])
    return []


def _t4b_transition_issue(self, issue_key: str, transition_name_or_id: Union[str, int],
                            comment: Optional[str] = None) -> Dict[str, Any]:
    """Transition issue to new status by name or ID."""
    rs = self._check_dry_run("transition_issue", issue=issue_key, to=str(transition_name_or_id))
    if rs is not None:
        return rs
    if isinstance(transition_name_or_id, str) and not transition_name_or_id.isdigit():
        for t in _t4b_get_transitions(self, issue_key):
            if t.get("name", "").lower() == transition_name_or_id.lower():
                transition_id = t.get("id")
                break
        else:
            return {"transitioned": False, "error": f"transition not found: {transition_name_or_id}"}
    else:
        transition_id = str(transition_name_or_id)
    body: Dict[str, Any] = {"transition": {"id": transition_id}}
    if comment:
        body["update"] = {"comment": [{"add": {"body": _t4b_adf_text(comment)}}]}
    code, resp = _t4b_jira_request(self, "POST", f"issue/{issue_key}/transitions", json_body=body)
    return {"transitioned": 200 <= code < 300, "code": code}


def _t4b_link_issues(self, inward_key: str, outward_key: str, link_type: str = "Relates") -> Dict[str, Any]:
    """Create issue link (Blocks/Relates/Duplicates/Cloners/etc.)."""
    rs = self._check_dry_run("link_issues", inward=inward_key, outward=outward_key, type=link_type)
    if rs is not None:
        return rs
    body = {"type": {"name": link_type}, "inwardIssue": {"key": inward_key}, "outwardIssue": {"key": outward_key}}
    code, resp = _t4b_jira_request(self, "POST", "issueLink", json_body=body)
    return {"linked": 200 <= code < 300, "code": code}


def _t4b_attach_file(self, issue_key: str, filename: str, content: bytes,
                      mime: str = "application/octet-stream") -> Dict[str, Any]:
    """Attach binary file to issue."""
    rs = self._check_dry_run("attach_file", issue=issue_key, filename=filename)
    if rs is not None:
        return rs
    boundary = "----t4bJiraAttach" + str(int(_t4b_time.time() * 1000))
    body = b"".join([
        f"--{boundary}\r\n".encode(),
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode(),
        f"Content-Type: {mime}\r\n\r\n".encode(),
        content,
        f"\r\n--{boundary}--\r\n".encode(),
    ])
    headers = {"X-Atlassian-Token": "no-check",
               "Content-Type": f"multipart/form-data; boundary={boundary}"}
    code, resp = _t4b_jira_request(self, "POST", f"issue/{issue_key}/attachments",
                                     raw_data=body, extra_headers=headers)
    return {"attached": 200 <= code < 300, "code": code, "attachments": resp or []}


def _t4b_get_custom_field_id(self, field_name: str) -> Optional[str]:
    """Look up custom field id by display name."""
    code, resp = _t4b_jira_request(self, "GET", "field")
    if not (200 <= code < 300 and isinstance(resp, list)):
        return None
    for f in resp:
        if f.get("name", "").lower() == field_name.lower() and f.get("custom"):
            return f.get("id")
    return None


def _t4b_set_custom_fields(self, issue_key: str, fields: Dict[str, Any]) -> Dict[str, Any]:
    """Set custom fields by display name (auto-resolves to cf[id])."""
    rs = self._check_dry_run("set_custom_fields", issue=issue_key, fields=list(fields.keys()))
    if rs is not None:
        return rs
    resolved: Dict[str, Any] = {}
    for name, value in fields.items():
        if name.startswith("customfield_"):
            resolved[name] = value
            continue
        fid = _t4b_get_custom_field_id(self, name)
        if fid:
            resolved[fid] = value
    body = {"fields": resolved}
    code, resp = _t4b_jira_request(self, "PUT", f"issue/{issue_key}", json_body=body)
    return {"updated": 200 <= code < 300, "code": code, "resolved_fields": list(resolved.keys())}


def _t4b_add_to_sprint(self, sprint_id: int, issue_keys: List[str]) -> Dict[str, Any]:
    """Add issues to a sprint via Agile API v1.0."""
    rs = self._check_dry_run("add_to_sprint", sprint=sprint_id, issues=issue_keys)
    if rs is not None:
        return rs
    cfg = getattr(self, "config", None)
    base = (getattr(cfg, "url", None) if cfg else None) or _t4b_os.environ.get("JIRA_URL", "")
    email = (getattr(cfg, "email", None) if cfg else None) or _t4b_os.environ.get("JIRA_EMAIL", "")
    token = (getattr(cfg, "api_token", None) if cfg else None) or _t4b_os.environ.get("JIRA_API_TOKEN", "")
    if not base:
        return {"error": "Jira URL not configured"}
    creds = _t4b_b64.b64encode(f"{email}:{token}".encode()).decode("ascii")
    url = f"{base.rstrip('/')}/rest/agile/1.0/sprint/{sprint_id}/issue"
    body = _t4b_json.dumps({"issues": issue_keys}).encode()
    req = _t4b_req.Request(url, data=body, headers={
        "Authorization": f"Basic {creds}", "Content-Type": "application/json",
    }, method="POST")
    try:
        with _t4b_req.urlopen(req, timeout=30) as resp:
            return {"added": True, "code": resp.status}
    except _t4b_urlerr.HTTPError as e:
        return {"added": False, "code": e.code, "error": e.reason}


def _t4b_adf_text(text: str) -> Dict[str, Any]:
    """Convert plain text to Atlassian Document Format (ADF) for v3 API comments/descriptions."""
    paragraphs = text.split("\n\n")
    return {
        "type": "doc", "version": 1,
        "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": p}]}
            for p in paragraphs if p
        ],
    }


def _t4b_text_to_adf(self, text: str) -> Dict[str, Any]:
    """Public wrapper for ADF conversion."""
    return _t4b_adf_text(text)


try:
    JiraClient.jql_builder = _t4b_jql_builder           # type: ignore[name-defined]
    JiraClient.search_jql = _t4b_search_jql              # type: ignore[name-defined]
    JiraClient.search_all = _t4b_search_all              # type: ignore[name-defined]
    JiraClient.bulk_create_issues = _t4b_bulk_create_issues  # type: ignore[name-defined]
    JiraClient.get_transitions = _t4b_get_transitions    # type: ignore[name-defined]
    JiraClient.transition_issue = _t4b_transition_issue  # type: ignore[name-defined]
    JiraClient.link_issues = _t4b_link_issues            # type: ignore[name-defined]
    JiraClient.attach_file = _t4b_attach_file            # type: ignore[name-defined]
    JiraClient.get_custom_field_id = _t4b_get_custom_field_id  # type: ignore[name-defined]
    JiraClient.set_custom_fields = _t4b_set_custom_fields  # type: ignore[name-defined]
    JiraClient.add_to_sprint = _t4b_add_to_sprint        # type: ignore[name-defined]
    JiraClient.text_to_adf = _t4b_text_to_adf            # type: ignore[name-defined]
    JiraClient.JQLBuilder = JQLBuilder                    # type: ignore[name-defined,attr-defined]
except NameError:
    pass
