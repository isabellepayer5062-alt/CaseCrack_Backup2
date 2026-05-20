# __TIER4B_CAAP__
# Tier 4B CAAP — discovery_agent: crawler + JS endpoint extraction engine
import re as _t4b_re
import json as _t4b_json
import urllib.parse as _t4b_up
import urllib.request as _t4b_ur
import urllib.error as _t4b_uerr
import threading as _t4b_th
import time as _t4b_time
import gzip as _t4b_gz
import io as _t4b_io
import hashlib as _t4b_hash
import collections as _t4b_col
import concurrent.futures as _t4b_cf
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

_T4B_DEFAULT_UA = "CaseCrack-Crawler/1.0 (+https://github.com/casecrack)"
_T4B_RES_EXT_SKIP = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
                       ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".tar",
                       ".gz", ".bz2", ".mp3", ".mp4", ".mov", ".avi"}

# Regex patterns for endpoint extraction from JS
_T4B_JS_PATTERNS = [
    # quoted URL paths
    _t4b_re.compile(r'["\'](\/[a-zA-Z0-9_\-\/\.]{2,200})(?:["\'\?#])'),
    # fetch/axios/$.ajax patterns
    _t4b_re.compile(r'(?:fetch|axios\.(?:get|post|put|delete|patch)|\$\.(?:get|post|ajax))\s*\(\s*["\']([^"\']+)["\']'),
    # XHR open
    _t4b_re.compile(r'\.open\s*\(\s*["\'](?:GET|POST|PUT|DELETE|PATCH)["\']\s*,\s*["\']([^"\']+)["\']'),
    # API_BASE / apiUrl etc.
    _t4b_re.compile(r'(?:api[_-]?(?:base|url|endpoint)|baseURL|API_URL)\s*[:=]\s*["\']([^"\']+)["\']', _t4b_re.IGNORECASE),
    # URLs in template literals
    _t4b_re.compile(r'`([\/a-zA-Z0-9_\-\.]{2,200}\$\{[^}]+\}[\/a-zA-Z0-9_\-\.]*)`'),
]

_T4B_HREF_RE = _t4b_re.compile(r'href\s*=\s*["\']([^"\']+)["\']', _t4b_re.IGNORECASE)
_T4B_SRC_RE = _t4b_re.compile(r'src\s*=\s*["\']([^"\']+)["\']', _t4b_re.IGNORECASE)
_T4B_FORM_ACTION_RE = _t4b_re.compile(r'<form[^>]*action\s*=\s*["\']([^"\']+)["\']', _t4b_re.IGNORECASE)
_T4B_FORM_INPUT_RE = _t4b_re.compile(r'<input[^>]*name\s*=\s*["\']([^"\']+)["\']', _t4b_re.IGNORECASE)
_T4B_SCRIPT_TAG_RE = _t4b_re.compile(r'<script[^>]*src\s*=\s*["\']([^"\']+)["\']', _t4b_re.IGNORECASE)
_T4B_INLINE_SCRIPT_RE = _t4b_re.compile(r'<script[^>]*>([^<]+)</script>', _t4b_re.IGNORECASE | _t4b_re.DOTALL)


@dataclass
class _T4BCrawlNode:
    url: str
    depth: int
    method: str = "GET"
    parent: Optional[str] = None
    status_code: int = 0
    content_type: str = ""
    content_length: int = 0
    fetched: bool = False
    error: Optional[str] = None
    discovered_at: float = field(default_factory=_t4b_time.time)


def _t4b_normalize_url(url: str, base: Optional[str] = None) -> Optional[str]:
    if not url:
        return None
    url = url.strip()
    if url.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
        return None
    if base:
        url = _t4b_up.urljoin(base, url)
    p = _t4b_up.urlparse(url)
    if p.scheme not in ("http", "https"):
        return None
    # Strip fragment
    return _t4b_up.urlunparse(p._replace(fragment=""))


def _t4b_same_origin(u1: str, u2: str) -> bool:
    p1 = _t4b_up.urlparse(u1)
    p2 = _t4b_up.urlparse(u2)
    return (p1.scheme, p1.netloc) == (p2.scheme, p2.netloc)


def _t4b_in_scope(url: str, scope_hosts: Set[str], allow_subdomains: bool = True) -> bool:
    host = _t4b_up.urlparse(url).hostname or ""
    if not host:
        return False
    if host in scope_hosts:
        return True
    if allow_subdomains:
        for s in scope_hosts:
            if host.endswith("." + s):
                return True
    return False


def _t4b_should_skip_ext(url: str) -> bool:
    path = _t4b_up.urlparse(url).path.lower()
    for ext in _T4B_RES_EXT_SKIP:
        if path.endswith(ext):
            return True
    return False


def _t4b_fetch(url: str, timeout: float = 10.0,
                  headers: Optional[Dict[str, str]] = None,
                  method: str = "GET") -> Dict[str, Any]:
    h = {"User-Agent": _T4B_DEFAULT_UA, "Accept-Encoding": "gzip"}
    if headers:
        h.update(headers)
    req = _t4b_ur.Request(url, headers=h, method=method)
    t0 = _t4b_time.time()
    try:
        with _t4b_ur.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
            if resp.headers.get("Content-Encoding") == "gzip":
                try:
                    data = _t4b_gz.decompress(data)
                except Exception:
                    pass
            ct = resp.headers.get("Content-Type", "").lower()
            return {"ok": True, "status": resp.status, "headers": dict(resp.headers),
                      "content_type": ct, "body": data,
                      "duration_s": round(_t4b_time.time() - t0, 3)}
    except _t4b_uerr.HTTPError as e:
        return {"ok": False, "status": e.code, "error": str(e),
                  "duration_s": round(_t4b_time.time() - t0, 3)}
    except Exception as e:
        return {"ok": False, "status": 0, "error": f"{type(e).__name__}: {e}",
                  "duration_s": round(_t4b_time.time() - t0, 3)}


def _t4b_extract_links_from_html(html: str, base_url: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {"links": [], "scripts": [], "forms": [], "form_inputs": []}
    seen = set()
    for rx, key in [(_T4B_HREF_RE, "links"), (_T4B_SRC_RE, "links"),
                       (_T4B_SCRIPT_TAG_RE, "scripts"), (_T4B_FORM_ACTION_RE, "forms")]:
        for m in rx.finditer(html):
            u = _t4b_normalize_url(m.group(1), base_url)
            if u and u not in seen:
                seen.add(u)
                out[key].append(u)
    for m in _T4B_FORM_INPUT_RE.finditer(html):
        out["form_inputs"].append(m.group(1))
    return out


def _t4b_extract_endpoints_from_js(js_source: str) -> List[str]:
    """Extract API endpoints from JavaScript source."""
    out: Set[str] = set()
    for rx in _T4B_JS_PATTERNS:
        for m in rx.finditer(js_source):
            ep = m.group(1).strip()
            if not ep or len(ep) < 3:
                continue
            # Skip obvious non-endpoints
            if ep.startswith(("data:", "javascript:", "blob:")):
                continue
            # Strip template literal interpolation
            ep = _t4b_re.sub(r'\$\{[^}]+\}', '<param>', ep)
            out.add(ep)
    return sorted(out)


def _t4b_extract_inline_js_endpoints(html: str) -> List[str]:
    """Extract endpoints from <script>...</script> blocks."""
    out: Set[str] = set()
    for m in _T4B_INLINE_SCRIPT_RE.finditer(html):
        for ep in _t4b_extract_endpoints_from_js(m.group(1)):
            out.add(ep)
    return sorted(out)


def _t4b_robots_txt(self, base_url: str, timeout: float = 5.0) -> Dict[str, Any]:
    """Parse robots.txt for disallow paths and sitemaps."""
    p = _t4b_up.urlparse(base_url)
    robots_url = f"{p.scheme}://{p.netloc}/robots.txt"
    res = _t4b_fetch(robots_url, timeout=timeout)
    if not res.get("ok"):
        return {"ok": False, "url": robots_url, "error": res.get("error")}
    body = res["body"].decode("utf-8", "ignore") if isinstance(res["body"], bytes) else res["body"]
    disallow: List[str] = []
    sitemaps: List[str] = []
    user_agent: Optional[str] = None
    for ln in body.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        if ":" not in ln:
            continue
        key, _, val = ln.partition(":")
        key = key.strip().lower()
        val = val.strip()
        if key == "user-agent":
            user_agent = val
        elif key == "disallow" and val:
            disallow.append(val)
        elif key == "sitemap" and val:
            sitemaps.append(val)
    return {"ok": True, "url": robots_url, "disallow": disallow,
              "sitemaps": sitemaps, "raw_lines": len(body.splitlines())}


def _t4b_sitemap_urls(self, sitemap_url: str, timeout: float = 10.0,
                          max_urls: int = 5000) -> Dict[str, Any]:
    res = _t4b_fetch(sitemap_url, timeout=timeout)
    if not res.get("ok"):
        return {"ok": False, "error": res.get("error"), "url": sitemap_url}
    body = res["body"].decode("utf-8", "ignore") if isinstance(res["body"], bytes) else res["body"]
    urls = _t4b_re.findall(r"<loc>([^<]+)</loc>", body)
    urls = [u.strip() for u in urls if u.strip()][:max_urls]
    return {"ok": True, "url": sitemap_url, "urls": urls, "count": len(urls)}


def _t4b_crawl(self, start_url: str, max_depth: int = 2, max_pages: int = 100,
                  max_workers: int = 4, timeout: float = 10.0,
                  allow_subdomains: bool = True,
                  honor_robots: bool = True,
                  extra_headers: Optional[Dict[str, str]] = None,
                  on_page: Optional[Callable[[Dict[str, Any]], None]] = None) -> Dict[str, Any]:
    """Multi-threaded BFS crawl with JS endpoint extraction."""
    start_url = _t4b_normalize_url(start_url) or start_url
    scope_hosts = {_t4b_up.urlparse(start_url).hostname or ""}
    visited: Set[str] = set()
    visited_lock = _t4b_th.RLock()
    nodes: Dict[str, _T4BCrawlNode] = {}
    js_endpoints: Set[str] = set()
    forms: List[Dict[str, Any]] = []
    disallow: Set[str] = set()
    if honor_robots:
        rb = _t4b_robots_txt(self, start_url, timeout=5.0)
        if rb.get("ok"):
            for d in rb["disallow"]:
                disallow.add(d)
    queue: List[Tuple[str, int, Optional[str]]] = [(start_url, 0, None)]
    nodes[start_url] = _T4BCrawlNode(url=start_url, depth=0)

    def _process(url: str, depth: int, parent: Optional[str]) -> Tuple[str, Dict[str, Any]]:
        node = nodes.get(url) or _T4BCrawlNode(url=url, depth=depth, parent=parent)
        nodes[url] = node
        if _t4b_should_skip_ext(url):
            node.status_code = 0
            node.error = "skipped_ext"
            return url, {"new_links": [], "js_eps": [], "forms": []}
        # Honor robots disallow
        if any(_t4b_up.urlparse(url).path.startswith(d) for d in disallow):
            node.error = "robots_disallow"
            return url, {"new_links": [], "js_eps": [], "forms": []}
        res = _t4b_fetch(url, timeout=timeout, headers=extra_headers)
        node.fetched = True
        node.status_code = res.get("status", 0)
        node.content_type = res.get("content_type", "")
        body = res.get("body", b"")
        node.content_length = len(body) if body else 0
        if not res.get("ok"):
            node.error = res.get("error", "")
            return url, {"new_links": [], "js_eps": [], "forms": []}
        new_links: List[str] = []
        page_js_eps: List[str] = []
        page_forms: List[Dict[str, Any]] = []
        try:
            text = body.decode("utf-8", "ignore") if isinstance(body, bytes) else str(body)
        except Exception:
            text = ""
        ct = node.content_type
        if "html" in ct or "xml" in ct or text.lstrip().startswith("<"):
            extracted = _t4b_extract_links_from_html(text, url)
            new_links.extend(extracted["links"])
            new_links.extend(extracted["scripts"])
            for fa in extracted["forms"]:
                page_forms.append({"action": fa, "page": url,
                                      "inputs": list(extracted["form_inputs"])})
            page_js_eps = _t4b_extract_inline_js_endpoints(text)
        elif "javascript" in ct or url.endswith(".js"):
            page_js_eps = _t4b_extract_endpoints_from_js(text)
        return url, {"new_links": new_links, "js_eps": page_js_eps, "forms": page_forms}

    pages_done = 0
    while queue and pages_done < max_pages:
        # Take a batch
        batch_size = min(max_workers, len(queue), max_pages - pages_done)
        batch = queue[:batch_size]
        queue = queue[batch_size:]
        with _t4b_cf.ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = []
            for url, d, parent in batch:
                with visited_lock:
                    if url in visited:
                        continue
                    visited.add(url)
                futs.append(ex.submit(_process, url, d, parent))
            for fut in _t4b_cf.as_completed(futs):
                try:
                    url, ext = fut.result()
                except Exception:
                    continue
                pages_done += 1
                node = nodes.get(url)
                if on_page:
                    try: on_page({"url": url, "status": node.status_code if node else 0})
                    except Exception: pass
                for ep in ext["js_eps"]:
                    js_endpoints.add(ep)
                forms.extend(ext["forms"])
                d = nodes[url].depth
                if d < max_depth:
                    for link in ext["new_links"]:
                        if link in visited or link in nodes:
                            continue
                        if not _t4b_in_scope(link, scope_hosts, allow_subdomains):
                            continue
                        nodes[link] = _T4BCrawlNode(url=link, depth=d + 1, parent=url)
                        queue.append((link, d + 1, url))
    # Summary
    by_status: Dict[int, int] = {}
    by_ct: Dict[str, int] = {}
    for n in nodes.values():
        if n.fetched:
            by_status[n.status_code] = by_status.get(n.status_code, 0) + 1
            ct = n.content_type.split(";")[0]
            by_ct[ct] = by_ct.get(ct, 0) + 1
    return {
        "start_url": start_url,
        "pages_visited": pages_done,
        "pages_discovered": len(nodes),
        "js_endpoints_discovered": sorted(js_endpoints),
        "js_endpoint_count": len(js_endpoints),
        "forms_discovered": forms,
        "form_count": len(forms),
        "by_status": by_status,
        "by_content_type": by_ct,
        "nodes": {u: {"depth": n.depth, "status": n.status_code,
                          "content_type": n.content_type, "error": n.error,
                          "size": n.content_length, "parent": n.parent}
                       for u, n in nodes.items()},
    }


def _t4b_extract_endpoints_only(self, js_source: str) -> List[str]:
    return _t4b_extract_endpoints_from_js(js_source)


def _t4b_diff_endpoints(self, baseline: List[str], current: List[str]) -> Dict[str, Any]:
    bs = set(baseline)
    cs = set(current)
    return {"added": sorted(cs - bs), "removed": sorted(bs - cs),
              "common_count": len(bs & cs)}


def _t4b_endpoint_dedup_by_pattern(self, endpoints: List[str]) -> List[str]:
    """Collapse /users/123/posts/456 → /users/<id>/posts/<id>"""
    seen: Set[str] = set()
    out = []
    for ep in endpoints:
        norm = _t4b_re.sub(r"/\d+", "/<id>", ep)
        norm = _t4b_re.sub(r"/[a-f0-9]{20,}", "/<hash>", norm)
        norm = _t4b_re.sub(r"/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
                            "/<uuid>", norm)
        if norm not in seen:
            seen.add(norm)
            out.append(norm)
    return out


# --- Bind to DiscoveryAgent --------------------------------------------
try:
    DiscoveryAgent.crawl = _t4b_crawl  # type: ignore[name-defined]
    DiscoveryAgent.fetch_robots = _t4b_robots_txt  # type: ignore[name-defined]
    DiscoveryAgent.fetch_sitemap = _t4b_sitemap_urls  # type: ignore[name-defined]
    DiscoveryAgent.extract_endpoints_from_js = _t4b_extract_endpoints_only  # type: ignore[name-defined]
    DiscoveryAgent.diff_endpoints = _t4b_diff_endpoints  # type: ignore[name-defined]
    DiscoveryAgent.dedup_endpoints_by_pattern = _t4b_endpoint_dedup_by_pattern  # type: ignore[name-defined]
except NameError:
    pass
