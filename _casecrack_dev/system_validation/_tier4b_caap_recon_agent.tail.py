# __TIER4B_CAAP__
# Tier 4B CAAP — recon_agent: shodan / censys / crt.sh / github / s3 clients
import urllib.request as _t4b_ur
import urllib.parse as _t4b_up
import urllib.error as _t4b_uerr
import json as _t4b_json
import time as _t4b_time
import re as _t4b_re
import base64 as _t4b_b64
import hashlib as _t4b_hash
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

_T4B_RECON_UA = "CaseCrack-Recon/1.0"
_T4B_DEFAULT_TO = 15.0


def _t4b_recon_get(url: str, headers: Optional[Dict[str, str]] = None,
                       timeout: float = _T4B_DEFAULT_TO) -> Dict[str, Any]:
    h = {"User-Agent": _T4B_RECON_UA, "Accept": "application/json"}
    if headers:
        h.update(headers)
    req = _t4b_ur.Request(url, headers=h)
    t0 = _t4b_time.time()
    try:
        with _t4b_ur.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            text = body.decode("utf-8", "ignore")
            try:
                data = _t4b_json.loads(text) if text.strip().startswith(("{", "[")) else text
            except Exception:
                data = text
            return {"ok": True, "status": resp.status, "data": data,
                      "duration_s": round(_t4b_time.time() - t0, 3)}
    except _t4b_uerr.HTTPError as e:
        try:
            etext = e.read().decode("utf-8", "ignore")
        except Exception:
            etext = ""
        return {"ok": False, "status": e.code, "error": str(e), "body": etext,
                  "duration_s": round(_t4b_time.time() - t0, 3)}
    except Exception as e:
        return {"ok": False, "status": 0, "error": f"{type(e).__name__}: {e}",
                  "duration_s": round(_t4b_time.time() - t0, 3)}


# ---- Shodan ------------------------------------------------------------
def _t4b_recon_shodan_set_key(self, api_key: str) -> None:
    setattr(self, "_t4b_shodan_key", api_key)


def _t4b_recon_shodan_host(self, ip: str, history: bool = False) -> Dict[str, Any]:
    key = getattr(self, "_t4b_shodan_key", None)
    if not key:
        return {"ok": False, "error": "no_shodan_key"}
    url = f"https://api.shodan.io/shodan/host/{_t4b_up.quote(ip)}?key={_t4b_up.quote(key)}"
    if history:
        url += "&history=true"
    res = _t4b_recon_get(url)
    if not res.get("ok"):
        return res
    d = res.get("data") or {}
    if isinstance(d, dict):
        return {"ok": True, "ip": ip, "ports": d.get("ports", []),
                  "org": d.get("org"), "isp": d.get("isp"),
                  "country": d.get("country_name"), "city": d.get("city"),
                  "hostnames": d.get("hostnames", []), "tags": d.get("tags", []),
                  "vulns": d.get("vulns", []), "data_count": len(d.get("data", []))}
    return res


def _t4b_recon_shodan_search(self, query: str, page: int = 1,
                                  facets: Optional[str] = None) -> Dict[str, Any]:
    key = getattr(self, "_t4b_shodan_key", None)
    if not key:
        return {"ok": False, "error": "no_shodan_key"}
    qs = {"key": key, "query": query, "page": page}
    if facets:
        qs["facets"] = facets
    url = "https://api.shodan.io/shodan/host/search?" + _t4b_up.urlencode(qs)
    res = _t4b_recon_get(url, timeout=30.0)
    if not res.get("ok"):
        return res
    d = res.get("data") or {}
    matches = d.get("matches", []) if isinstance(d, dict) else []
    return {"ok": True, "query": query, "total": d.get("total", 0) if isinstance(d, dict) else 0,
              "matches": [{"ip_str": m.get("ip_str"), "port": m.get("port"),
                              "org": m.get("org"), "product": m.get("product"),
                              "hostnames": m.get("hostnames", [])} for m in matches],
              "match_count": len(matches)}


# ---- Censys ------------------------------------------------------------
def _t4b_recon_censys_set_creds(self, api_id: str, api_secret: str) -> None:
    setattr(self, "_t4b_censys_id", api_id)
    setattr(self, "_t4b_censys_secret", api_secret)


def _t4b_recon_censys_auth_header(self) -> Optional[str]:
    aid = getattr(self, "_t4b_censys_id", None)
    asec = getattr(self, "_t4b_censys_secret", None)
    if not aid or not asec:
        return None
    return "Basic " + _t4b_b64.b64encode(f"{aid}:{asec}".encode()).decode()


def _t4b_recon_censys_host(self, ip: str) -> Dict[str, Any]:
    auth = _t4b_recon_censys_auth_header(self)
    if not auth:
        return {"ok": False, "error": "no_censys_creds"}
    url = f"https://search.censys.io/api/v2/hosts/{_t4b_up.quote(ip)}"
    res = _t4b_recon_get(url, headers={"Authorization": auth})
    if not res.get("ok"):
        return res
    d = res.get("data") or {}
    result = d.get("result") if isinstance(d, dict) else {}
    return {"ok": True, "ip": ip, "services": result.get("services", []),
              "operating_system": result.get("operating_system", {}),
              "autonomous_system": result.get("autonomous_system", {}),
              "location": result.get("location", {})}


def _t4b_recon_censys_search(self, query: str, per_page: int = 100,
                                  cursor: Optional[str] = None) -> Dict[str, Any]:
    auth = _t4b_recon_censys_auth_header(self)
    if not auth:
        return {"ok": False, "error": "no_censys_creds"}
    qs = {"q": query, "per_page": per_page}
    if cursor:
        qs["cursor"] = cursor
    url = "https://search.censys.io/api/v2/hosts/search?" + _t4b_up.urlencode(qs)
    res = _t4b_recon_get(url, headers={"Authorization": auth}, timeout=30.0)
    if not res.get("ok"):
        return res
    d = res.get("data") or {}
    result = d.get("result", {}) if isinstance(d, dict) else {}
    hits = result.get("hits", [])
    return {"ok": True, "query": query, "total": result.get("total", 0),
              "hits": hits, "next_cursor": result.get("links", {}).get("next")}


# ---- crt.sh ------------------------------------------------------------
def _t4b_recon_crtsh(self, domain: str, include_expired: bool = True) -> Dict[str, Any]:
    """Query crt.sh for certificate transparency logs."""
    url = f"https://crt.sh/?q={_t4b_up.quote('%.' + domain)}&output=json"
    if not include_expired:
        url += "&exclude=expired"
    res = _t4b_recon_get(url, timeout=30.0)
    if not res.get("ok"):
        return res
    d = res.get("data") or []
    if isinstance(d, str):
        try:
            d = _t4b_json.loads(d)
        except Exception:
            d = []
    if not isinstance(d, list):
        return {"ok": False, "error": "unexpected_response"}
    subdomains: set = set()
    issuers: Dict[str, int] = {}
    for entry in d:
        name = (entry.get("name_value") or "").strip()
        for ln in name.split("\n"):
            ln = ln.strip().lower().lstrip("*.")
            if ln and (ln == domain or ln.endswith("." + domain)):
                subdomains.add(ln)
        iss = (entry.get("issuer_name") or "").split(",")[0].replace("O=", "").strip()
        if iss:
            issuers[iss] = issuers.get(iss, 0) + 1
    return {"ok": True, "domain": domain,
              "subdomain_count": len(subdomains),
              "subdomains": sorted(subdomains),
              "cert_count": len(d),
              "top_issuers": sorted(issuers.items(), key=lambda x: -x[1])[:10]}


# ---- GitHub ------------------------------------------------------------
def _t4b_recon_github_set_token(self, token: str) -> None:
    setattr(self, "_t4b_gh_token", token)


def _t4b_recon_github_headers(self) -> Dict[str, str]:
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    tok = getattr(self, "_t4b_gh_token", None)
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def _t4b_recon_github_org_repos(self, org: str, per_page: int = 100,
                                       max_pages: int = 5) -> Dict[str, Any]:
    repos: List[Dict[str, Any]] = []
    for page in range(1, max_pages + 1):
        url = f"https://api.github.com/orgs/{_t4b_up.quote(org)}/repos?per_page={per_page}&page={page}"
        res = _t4b_recon_get(url, headers=_t4b_recon_github_headers(self))
        if not res.get("ok"):
            return res
        d = res.get("data") or []
        if not isinstance(d, list) or not d:
            break
        for r in d:
            repos.append({"name": r.get("name"), "full_name": r.get("full_name"),
                              "private": r.get("private"), "fork": r.get("fork"),
                              "archived": r.get("archived"),
                              "default_branch": r.get("default_branch"),
                              "stars": r.get("stargazers_count"),
                              "language": r.get("language")})
        if len(d) < per_page:
            break
    return {"ok": True, "org": org, "repo_count": len(repos), "repos": repos}


def _t4b_recon_github_search_code(self, query: str, per_page: int = 50) -> Dict[str, Any]:
    url = f"https://api.github.com/search/code?q={_t4b_up.quote(query)}&per_page={per_page}"
    res = _t4b_recon_get(url, headers=_t4b_recon_github_headers(self), timeout=30.0)
    if not res.get("ok"):
        return res
    d = res.get("data") or {}
    items = d.get("items", []) if isinstance(d, dict) else []
    return {"ok": True, "query": query,
              "total_count": d.get("total_count", 0) if isinstance(d, dict) else 0,
              "matches": [{"path": i.get("path"), "repo": i.get("repository", {}).get("full_name"),
                              "html_url": i.get("html_url")} for i in items],
              "match_count": len(items)}


def _t4b_recon_github_secret_search(self, target_org: str) -> Dict[str, Any]:
    """Search org repos for common secret patterns (leaked tokens)."""
    queries = [
        f'org:{target_org} "AKIA"',  # AWS
        f'org:{target_org} "ghp_"',  # GitHub PAT
        f'org:{target_org} "xoxb-"',  # Slack bot token
        f'org:{target_org} BEGIN_PRIVATE_KEY',
        f'org:{target_org} api_key',
        f'org:{target_org} aws_secret_access_key',
    ]
    findings: List[Dict[str, Any]] = []
    for q in queries:
        r = _t4b_recon_github_search_code(self, q, per_page=10)
        if r.get("ok") and r.get("match_count", 0) > 0:
            findings.append({"query": q, "matches": r.get("matches", [])[:5],
                                "count": r.get("match_count", 0)})
    return {"ok": True, "org": target_org, "patterns_tried": len(queries),
              "patterns_with_hits": len(findings), "findings": findings}


# ---- S3 buckets --------------------------------------------------------
def _t4b_recon_s3_check_bucket(self, bucket: str, region: str = "us-east-1") -> Dict[str, Any]:
    """Check bucket exists, listable, and write status by HTTP probing."""
    base = f"https://{bucket}.s3.{region}.amazonaws.com" if region != "us-east-1" else f"https://{bucket}.s3.amazonaws.com"
    # HEAD
    res = _t4b_recon_get(base, timeout=8.0)
    status = res.get("status", 0)
    # GET listing
    res_list = _t4b_recon_get(base + "/?list-type=2", timeout=10.0)
    list_status = res_list.get("status", 0)
    list_data = res_list.get("data", "") if isinstance(res_list.get("data"), str) else ""
    listable = list_status == 200 and "<ListBucketResult" in list_data
    public = status in (200, 403) and status != 404
    return {"ok": True, "bucket": bucket, "region": region,
              "exists": public, "head_status": status,
              "listable": listable, "list_status": list_status,
              "url": base}


def _t4b_recon_s3_enum_org(self, org: str, suffixes: Optional[List[str]] = None) -> Dict[str, Any]:
    """Enumerate likely bucket names for an org."""
    sfx = suffixes or ["", "-prod", "-dev", "-staging", "-backup", "-data", "-logs",
                            "-assets", "-public", "-static", "-uploads", "-images", "-media",
                            "-test", "-internal", "-private", "-archive"]
    candidates = [f"{org}{s}" for s in sfx]
    results: List[Dict[str, Any]] = []
    for c in candidates:
        r = _t4b_recon_s3_check_bucket(self, c)
        if r.get("exists") or r.get("listable"):
            results.append(r)
    return {"ok": True, "org": org, "candidates_tested": len(candidates),
              "exposed_count": len(results), "exposed": results}


# ---- Aggregator --------------------------------------------------------
def _t4b_recon_aggregate(self, target_domain: str,
                              include: Optional[List[str]] = None) -> Dict[str, Any]:
    """Run all recon clients in sequence; honours per-client API keys (skips if missing)."""
    inc = include or ["crtsh", "shodan", "censys", "github", "s3"]
    out: Dict[str, Any] = {"target": target_domain, "results": {}}
    if "crtsh" in inc:
        out["results"]["crtsh"] = _t4b_recon_crtsh(self, target_domain)
    if "shodan" in inc:
        # Shodan needs IP — skip unless caller already has one
        out["results"]["shodan"] = {"ok": False, "skipped": "needs_ip"}
    if "censys" in inc:
        out["results"]["censys"] = _t4b_recon_censys_search(self, f"services.tls.certificates.leaf_data.subject.common_name: \"{target_domain}\"") \
            if getattr(self, "_t4b_censys_id", None) else {"ok": False, "skipped": "no_creds"}
    if "github" in inc:
        org = target_domain.split(".")[0]
        out["results"]["github"] = _t4b_recon_github_org_repos(self, org)
    if "s3" in inc:
        org = target_domain.split(".")[0]
        out["results"]["s3"] = _t4b_recon_s3_enum_org(self, org)
    return out


def _t4b_recon_supported_sources(self) -> List[str]:
    return ["shodan", "censys", "crtsh", "github", "s3"]


# --- Bind to ReconAgent -------------------------------------------------
try:
    ReconAgent.shodan_set_key = _t4b_recon_shodan_set_key  # type: ignore[name-defined]
    ReconAgent.shodan_host = _t4b_recon_shodan_host  # type: ignore[name-defined]
    ReconAgent.shodan_search = _t4b_recon_shodan_search  # type: ignore[name-defined]
    ReconAgent.censys_set_creds = _t4b_recon_censys_set_creds  # type: ignore[name-defined]
    ReconAgent.censys_host = _t4b_recon_censys_host  # type: ignore[name-defined]
    ReconAgent.censys_search = _t4b_recon_censys_search  # type: ignore[name-defined]
    ReconAgent.crtsh_query = _t4b_recon_crtsh  # type: ignore[name-defined]
    ReconAgent.github_set_token = _t4b_recon_github_set_token  # type: ignore[name-defined]
    ReconAgent.github_org_repos = _t4b_recon_github_org_repos  # type: ignore[name-defined]
    ReconAgent.github_search_code = _t4b_recon_github_search_code  # type: ignore[name-defined]
    ReconAgent.github_secret_search = _t4b_recon_github_secret_search  # type: ignore[name-defined]
    ReconAgent.s3_check_bucket = _t4b_recon_s3_check_bucket  # type: ignore[name-defined]
    ReconAgent.s3_enum_org = _t4b_recon_s3_enum_org  # type: ignore[name-defined]
    ReconAgent.recon_aggregate = _t4b_recon_aggregate  # type: ignore[name-defined]
    ReconAgent.supported_recon_sources = _t4b_recon_supported_sources  # type: ignore[name-defined]
except NameError:
    pass
