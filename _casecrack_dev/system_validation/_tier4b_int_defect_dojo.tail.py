

# __TIER4B_INTEGRATIONS__ defect_dojo
# Tier 4B: SARIF + SBOM (CycloneDX/SPDX) upload, full DefectDojo v2 API coverage,
#          findings dedup, engagement lifecycle, risk acceptance, metrics

import os as _t4b_os
import json as _t4b_json
import time as _t4b_time
import hashlib as _t4b_hashlib
import urllib.request as _t4b_req
import urllib.parse as _t4b_urlparse
import urllib.error as _t4b_urlerr
from typing import Any, Dict, List, Optional, Tuple
from io import BytesIO as _t4b_BytesIO


_T4B_DD_SCAN_TYPES = {
    "sarif": "SARIF",
    "cyclonedx": "CycloneDX Scan",
    "spdx": "SPDX Scan",
    "burp": "Burp Scan",
    "nuclei": "Nuclei Scan",
    "nmap": "Nmap Scan",
    "trivy": "Trivy Scan",
    "ggrep": "Generic Findings Import",
    "generic": "Generic Findings Import",
    "zap": "ZAP Scan",
    "semgrep": "Semgrep JSON Report",
    "snyk": "Snyk Scan",
    "anchore": "Anchore Engine Scan",
    "openvas": "OpenVAS Parser",
    "sslyze": "Sslyze 3 Scan (JSON)",
}


def _t4b_dd_request(self, method: str, path: str, params: Optional[Dict[str, Any]] = None,
                     json_body: Optional[Any] = None, files: Optional[Dict[str, Tuple[str, bytes, str]]] = None,
                     timeout: int = 30) -> Tuple[int, Any]:
    """Generic authenticated DefectDojo v2 API request."""
    cfg = getattr(self, "config", None)
    base = (getattr(cfg, "url", None) if cfg else None) or _t4b_os.environ.get("DEFECTDOJO_URL", "")
    token = (getattr(cfg, "api_token", None) if cfg else None) or _t4b_os.environ.get("DEFECTDOJO_API_TOKEN", "")
    if not base:
        raise RuntimeError("DefectDojo URL not configured")
    base = base.rstrip("/")
    url = f"{base}/api/v2/{path.lstrip('/')}"
    if params:
        url = url + "?" + _t4b_urlparse.urlencode(params, doseq=True)
    headers = {"Authorization": f"Token {token}"} if token else {}
    if files:
        # multipart upload
        boundary = "----t4bDDBoundary" + _t4b_hashlib.sha1(str(_t4b_time.time()).encode()).hexdigest()[:16]
        body = _t4b_BytesIO()
        if json_body and isinstance(json_body, dict):
            for k, v in json_body.items():
                body.write(f"--{boundary}\r\n".encode())
                body.write(f'Content-Disposition: form-data; name="{k}"\r\n\r\n'.encode())
                body.write(f"{v}\r\n".encode())
        for fname, (filename, content, ctype) in files.items():
            body.write(f"--{boundary}\r\n".encode())
            body.write(f'Content-Disposition: form-data; name="{fname}"; filename="{filename}"\r\n'.encode())
            body.write(f"Content-Type: {ctype}\r\n\r\n".encode())
            body.write(content)
            body.write(b"\r\n")
        body.write(f"--{boundary}--\r\n".encode())
        data = body.getvalue()
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    elif json_body is not None:
        data = _t4b_json.dumps(json_body).encode()
        headers["Content-Type"] = "application/json"
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
            err_body = _t4b_json.loads(e.read().decode("utf-8"))
        except Exception:
            err_body = {"error": e.reason}
        return e.code, err_body


def _t4b_upload_sarif(self, sarif_path_or_data, engagement_id: int,
                       scan_date: Optional[str] = None,
                       active: bool = True, verified: bool = False,
                       minimum_severity: str = "Info") -> Dict[str, Any]:
    """Upload SARIF report to DefectDojo as new finding import."""
    rs = self._check_dry_run("upload_sarif", engagement_id=engagement_id)
    if rs is not None:
        return rs
    if isinstance(sarif_path_or_data, (str, bytes)):
        if isinstance(sarif_path_or_data, str) and _t4b_os.path.exists(sarif_path_or_data):
            with open(sarif_path_or_data, "rb") as fh:
                content = fh.read()
            filename = _t4b_os.path.basename(sarif_path_or_data)
        else:
            content = sarif_path_or_data if isinstance(sarif_path_or_data, bytes) else sarif_path_or_data.encode()
            filename = "report.sarif"
    else:
        content = _t4b_json.dumps(sarif_path_or_data).encode()
        filename = "report.sarif"
    body = {
        "engagement": engagement_id,
        "scan_type": _T4B_DD_SCAN_TYPES["sarif"],
        "active": str(active).lower(),
        "verified": str(verified).lower(),
        "minimum_severity": minimum_severity,
        "scan_date": scan_date or _t4b_time.strftime("%Y-%m-%d"),
        "close_old_findings": "true",
        "deduplication_on_engagement": "true",
    }
    code, resp = _t4b_dd_request(self, "POST", "import-scan/", json_body=body,
                                   files={"file": (filename, content, "application/json")})
    return {"uploaded": 200 <= code < 300, "code": code, "response": resp}


def _t4b_upload_sbom(self, sbom_path_or_data, engagement_id: int, fmt: str = "cyclonedx",
                      scan_date: Optional[str] = None) -> Dict[str, Any]:
    """Upload SBOM (CycloneDX/SPDX) to DefectDojo for SCA findings import."""
    rs = self._check_dry_run("upload_sbom", engagement_id=engagement_id, fmt=fmt)
    if rs is not None:
        return rs
    scan_type = _T4B_DD_SCAN_TYPES.get(fmt.lower())
    if not scan_type:
        return {"uploaded": False, "error": f"unknown format: {fmt}"}
    if isinstance(sbom_path_or_data, (str, bytes)):
        if isinstance(sbom_path_or_data, str) and _t4b_os.path.exists(sbom_path_or_data):
            with open(sbom_path_or_data, "rb") as fh:
                content = fh.read()
            filename = _t4b_os.path.basename(sbom_path_or_data)
        else:
            content = sbom_path_or_data if isinstance(sbom_path_or_data, bytes) else sbom_path_or_data.encode()
            filename = f"sbom.{fmt}.json"
    else:
        content = _t4b_json.dumps(sbom_path_or_data).encode()
        filename = f"sbom.{fmt}.json"
    body = {
        "engagement": engagement_id,
        "scan_type": scan_type,
        "active": "true",
        "verified": "false",
        "scan_date": scan_date or _t4b_time.strftime("%Y-%m-%d"),
    }
    code, resp = _t4b_dd_request(self, "POST", "import-scan/", json_body=body,
                                   files={"file": (filename, content, "application/json")})
    return {"uploaded": 200 <= code < 300, "code": code, "response": resp}


def _t4b_reimport_scan(self, scan_path: str, test_id: int, scan_type: str = "sarif") -> Dict[str, Any]:
    """Reimport into existing test (preserves history; updates statuses)."""
    rs = self._check_dry_run("reimport_scan", test_id=test_id, scan_type=scan_type)
    if rs is not None:
        return rs
    with open(scan_path, "rb") as fh:
        content = fh.read()
    sct = _T4B_DD_SCAN_TYPES.get(scan_type.lower(), scan_type)
    body = {
        "test": test_id,
        "scan_type": sct,
        "active": "true",
        "scan_date": _t4b_time.strftime("%Y-%m-%d"),
    }
    code, resp = _t4b_dd_request(self, "POST", "reimport-scan/", json_body=body,
                                   files={"file": (_t4b_os.path.basename(scan_path), content, "application/json")})
    return {"reimported": 200 <= code < 300, "code": code, "response": resp}


def _t4b_list_products(self, name_contains: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    """List DefectDojo products (paginated)."""
    params = {"limit": limit}
    if name_contains:
        params["name__icontains"] = name_contains
    code, resp = _t4b_dd_request(self, "GET", "products/", params=params)
    if 200 <= code < 300 and isinstance(resp, dict):
        return resp.get("results", [])
    return []


def _t4b_create_product(self, name: str, description: str = "", prod_type: int = 1) -> Dict[str, Any]:
    """Create new DefectDojo product."""
    rs = self._check_dry_run("create_product", name=name)
    if rs is not None:
        return rs
    body = {"name": name, "description": description or name, "prod_type": prod_type}
    code, resp = _t4b_dd_request(self, "POST", "products/", json_body=body)
    return {"created": 200 <= code < 300, "code": code, "id": (resp or {}).get("id"), "response": resp}


def _t4b_close_engagement(self, engagement_id: int) -> Dict[str, Any]:
    """Close an engagement."""
    rs = self._check_dry_run("close_engagement", engagement_id=engagement_id)
    if rs is not None:
        return rs
    code, resp = _t4b_dd_request(self, "POST", f"engagements/{engagement_id}/close/", json_body={})
    return {"closed": 200 <= code < 300, "code": code}


def _t4b_accept_risk(self, finding_ids: List[int], reason: str, accepted_by: str,
                      expiration_date: Optional[str] = None) -> Dict[str, Any]:
    """Risk acceptance: mark findings as accepted with rationale."""
    rs = self._check_dry_run("accept_risk", finding_ids=finding_ids, accepted_by=accepted_by)
    if rs is not None:
        return rs
    body = {
        "name": f"Risk Acceptance {_t4b_time.strftime('%Y-%m-%d %H:%M')}",
        "owner": accepted_by,
        "decision": "Accept",
        "decision_details": reason,
        "accepted_findings": finding_ids,
    }
    if expiration_date:
        body["expiration_date"] = expiration_date
    code, resp = _t4b_dd_request(self, "POST", "risk_acceptance/", json_body=body)
    return {"accepted": 200 <= code < 300, "code": code, "id": (resp or {}).get("id"), "response": resp}


def _t4b_get_metrics(self, product_id: Optional[int] = None) -> Dict[str, Any]:
    """Aggregate metrics for product or all products."""
    params = {"limit": 1000}
    if product_id:
        params["product"] = product_id
    code, resp = _t4b_dd_request(self, "GET", "findings/", params=params)
    if not (200 <= code < 300 and isinstance(resp, dict)):
        return {"error": resp, "code": code}
    findings = resp.get("results", [])
    by_sev: Dict[str, int] = {}
    active = 0
    verified = 0
    for f in findings:
        sev = f.get("severity", "Info")
        by_sev[sev] = by_sev.get(sev, 0) + 1
        if f.get("active"):
            active += 1
        if f.get("verified"):
            verified += 1
    return {
        "total": len(findings),
        "active": active,
        "verified": verified,
        "by_severity": by_sev,
        "product_id": product_id,
    }


def _t4b_dedup_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Local-side dedup of findings before upload (key: title|severity|file|line)."""
    seen: Dict[str, Dict[str, Any]] = {}
    for f in findings or []:
        key = "|".join([
            str(f.get("title", "")),
            str(f.get("severity", "")),
            str(f.get("file_path") or f.get("url") or ""),
            str(f.get("line", 0)),
        ])
        h = _t4b_hashlib.sha256(key.encode()).hexdigest()
        if h not in seen:
            seen[h] = f
    return list(seen.values())


def _t4b_search_findings(self, query: Optional[str] = None,
                          severity: Optional[str] = None,
                          status: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    """Search findings with filters."""
    params: Dict[str, Any] = {"limit": limit}
    if query:
        params["title__icontains"] = query
    if severity:
        params["severity"] = severity
    if status == "active":
        params["active"] = "true"
    elif status == "closed":
        params["active"] = "false"
    code, resp = _t4b_dd_request(self, "GET", "findings/", params=params)
    if 200 <= code < 300 and isinstance(resp, dict):
        return resp.get("results", [])
    return []


try:
    DefectDojoClient.upload_sarif = _t4b_upload_sarif       # type: ignore[name-defined]
    DefectDojoClient.upload_sbom = _t4b_upload_sbom         # type: ignore[name-defined]
    DefectDojoClient.reimport_scan = _t4b_reimport_scan     # type: ignore[name-defined]
    DefectDojoClient.list_products = _t4b_list_products     # type: ignore[name-defined]
    DefectDojoClient.create_product = _t4b_create_product   # type: ignore[name-defined]
    DefectDojoClient.close_engagement = _t4b_close_engagement   # type: ignore[name-defined]
    DefectDojoClient.accept_risk = _t4b_accept_risk         # type: ignore[name-defined]
    DefectDojoClient.get_metrics = _t4b_get_metrics         # type: ignore[name-defined]
    DefectDojoClient.dedup_findings = _t4b_dedup_findings   # type: ignore[name-defined]
    DefectDojoClient.search_findings = _t4b_search_findings # type: ignore[name-defined]
except NameError:
    pass
