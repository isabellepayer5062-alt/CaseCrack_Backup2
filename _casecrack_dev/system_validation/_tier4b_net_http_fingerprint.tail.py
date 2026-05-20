
# ======================================================================
# __TIER4B_NETWORK__  http_fingerprint: Wappalyzer-style technology DB
# ======================================================================
import re as _t4b_re
import json as _t4b_json
import urllib.request as _t4b_urlreq
import urllib.parse as _t4b_urlparse
import ssl as _t4b_ssl
from typing import Any as _T4BAny, Dict as _T4BDict, List as _T4BList, Optional as _T4BOptional

# Embedded Wappalyzer-style technology database (subset, production-grade)
# Format follows wappalyzer: each tech has cats, headers, html, scripts, cookies, meta, implies, website
_T4B_WAPPALYZER_DB = {
    # CMS
    "WordPress": {"cats": ["CMS"], "headers": {"X-Pingback": r"/xmlrpc\.php"},
                  "html": [r'<meta name="generator" content="WordPress\s*([\d.]+)?"\;version:\1'],
                  "meta": {"generator": r"WordPress\s*([\d.]+)?\;version:\1"},
                  "scripts": [r"/wp-content/", r"/wp-includes/"],
                  "website": "https://wordpress.org"},
    "Drupal": {"cats": ["CMS"], "headers": {"X-Generator": r"Drupal\s*([\d.]+)?\;version:\1"},
               "html": [r'<meta name="generator" content="Drupal\s*([\d.]+)?'],
               "scripts": [r"/sites/default/", r"/misc/drupal\.js"],
               "website": "https://drupal.org"},
    "Joomla": {"cats": ["CMS"], "html": [r'<meta name="generator" content="Joomla!\s*([\d.]+)?\;version:\1'],
               "meta": {"generator": r"Joomla!\s*([\d.]+)?"}, "website": "https://joomla.org"},
    "Ghost": {"cats": ["CMS"], "meta": {"generator": r"Ghost\s*([\d.]+)?\;version:\1"},
              "headers": {"X-Powered-By": r"Express"}, "website": "https://ghost.org"},
    "Magento": {"cats": ["E-commerce"], "cookies": {"X-Magento-Vary": ""},
                "scripts": [r"/skin/frontend/", r"mage/cookies\.js"],
                "html": [r"Mage\.Cookies"]},
    "Shopify": {"cats": ["E-commerce"], "cookies": {"_shopify_y": ""},
                "html": [r"cdn\.shopify\.com"], "scripts": [r"shopify\.com"]},
    "WooCommerce": {"cats": ["E-commerce"], "html": [r'<meta name="generator" content="WooCommerce\s*([\d.]+)?\;version:\1'],
                    "scripts": [r"/wp-content/plugins/woocommerce/"], "implies": ["WordPress"]},
    "PrestaShop": {"cats": ["E-commerce"], "cookies": {"PrestaShop-": ""},
                   "html": [r'name="generator" content="PrestaShop']},
    # Frameworks - server
    "Django": {"cats": ["Framework"], "headers": {"X-Frame-Options": "", "Server": r"WSGIServer/([\d.]+)?"},
               "cookies": {"csrftoken": "", "django_language": ""},
               "implies": ["Python"], "website": "https://djangoproject.com"},
    "Flask": {"cats": ["Framework"], "headers": {"Server": r"Werkzeug/([\d.]+)?\;version:\1"},
              "implies": ["Python"], "website": "https://flask.palletsprojects.com"},
    "FastAPI": {"cats": ["Framework"], "html": [r"FastAPI"], "scripts": [r"swagger-ui"],
                "implies": ["Python"], "website": "https://fastapi.tiangolo.com"},
    "Ruby on Rails": {"cats": ["Framework"], "headers": {"X-Powered-By": r"Phusion Passenger"},
                      "cookies": {"_rails_session": ""}, "implies": ["Ruby"]},
    "Laravel": {"cats": ["Framework"], "cookies": {"laravel_session": "", "XSRF-TOKEN": ""},
                "implies": ["PHP"]},
    "Symfony": {"cats": ["Framework"], "headers": {"X-Powered-By": r"PHP"},
                "html": [r"symfony"], "cookies": {"sf_redirect": ""}, "implies": ["PHP"]},
    "Express": {"cats": ["Framework"], "headers": {"X-Powered-By": r"^Express$"},
                "implies": ["Node.js"], "website": "https://expressjs.com"},
    "Next.js": {"cats": ["Framework"], "headers": {"X-Powered-By": r"Next\.js\s*([\d.]+)?\;version:\1"},
                "html": [r'id="__next"', r"/_next/static/"], "implies": ["React", "Node.js"]},
    "Nuxt.js": {"cats": ["Framework"], "html": [r'id="__nuxt"', r"/_nuxt/"], "implies": ["Vue.js"]},
    "ASP.NET": {"cats": ["Framework"], "headers": {"X-AspNet-Version": r"([\d.]+)\;version:\1",
                                                    "X-Powered-By": r"ASP\.NET"},
                "cookies": {"ASP.NET_SessionId": ""}, "website": "https://dotnet.microsoft.com"},
    "Spring": {"cats": ["Framework"], "headers": {"X-Application-Context": ""},
               "implies": ["Java"]},
    # JS frameworks
    "React": {"cats": ["JS Framework"], "html": [r"data-reactroot", r"data-reactid", r"react-dom"],
              "scripts": [r"react(?:-dom)?(?:\.production)?(?:\.min)?\.js"],
              "website": "https://react.dev"},
    "Vue.js": {"cats": ["JS Framework"], "html": [r"v-bind:", r"v-if=", r"v-for="],
               "scripts": [r"vue(?:\.runtime)?(?:\.min)?\.js"]},
    "Angular": {"cats": ["JS Framework"], "html": [r"ng-app=", r"ng-controller=", r"ng-version="],
                "scripts": [r"angular(?:\.min)?\.js"]},
    "jQuery": {"cats": ["JS Library"], "scripts": [r"jquery[.-]([\d.]+)?(?:\.min)?\.js\;version:\1"]},
    "Lodash": {"cats": ["JS Library"], "scripts": [r"lodash(?:\.min)?\.js"]},
    "Bootstrap": {"cats": ["UI Framework"], "html": [r'class="(?:navbar|container|row|col-)'],
                  "scripts": [r"bootstrap(?:\.bundle)?(?:\.min)?\.js"]},
    "Tailwind CSS": {"cats": ["UI Framework"], "html": [r'class="[^"]*\b(?:flex|grid|text-(?:xs|sm|lg|xl)|bg-\w+-\d{3})']},
    # Servers
    "Nginx": {"cats": ["Web Server"], "headers": {"Server": r"nginx/?([\d.]+)?\;version:\1"},
              "website": "https://nginx.org"},
    "Apache": {"cats": ["Web Server"], "headers": {"Server": r"Apache/?([\d.]+)?\;version:\1"}},
    "IIS": {"cats": ["Web Server"], "headers": {"Server": r"Microsoft-IIS/([\d.]+)?\;version:\1"}},
    "Caddy": {"cats": ["Web Server"], "headers": {"Server": r"Caddy"}},
    "LiteSpeed": {"cats": ["Web Server"], "headers": {"Server": r"LiteSpeed"}},
    "OpenResty": {"cats": ["Web Server"], "headers": {"Server": r"openresty/?([\d.]+)?\;version:\1"}},
    # Languages
    "PHP": {"cats": ["Language"], "headers": {"X-Powered-By": r"PHP/?([\d.]+)?\;version:\1",
                                                "Server": r"PHP/([\d.]+)?\;version:\1"},
            "cookies": {"PHPSESSID": ""}},
    "Python": {"cats": ["Language"], "headers": {"Server": r"Python/?([\d.]+)?\;version:\1"}},
    "Node.js": {"cats": ["Language"], "headers": {"X-Powered-By": r"Express|Next\.js"}},
    "Ruby": {"cats": ["Language"]},
    "Java": {"cats": ["Language"], "headers": {"X-Powered-By": r"JSP/?([\d.]+)?\;version:\1"}},
    # CDN
    "Cloudflare": {"cats": ["CDN"], "headers": {"Server": r"cloudflare", "CF-RAY": "", "CF-Cache-Status": ""},
                   "cookies": {"__cfduid": "", "__cf_bm": ""},
                   "website": "https://cloudflare.com"},
    "Akamai": {"cats": ["CDN"], "headers": {"X-Akamai-Transformed": "", "Server": r"AkamaiGHost"}},
    "Fastly": {"cats": ["CDN"], "headers": {"Fastly-Debug-Digest": "", "X-Served-By": r"cache-",
                                             "X-Cache": r"HIT|MISS"}},
    "Amazon CloudFront": {"cats": ["CDN"], "headers": {"X-Amz-Cf-Id": "", "Via": r"CloudFront"}},
    "KeyCDN": {"cats": ["CDN"], "headers": {"Server": r"keycdn-engine"}},
    # Analytics
    "Google Analytics": {"cats": ["Analytics"],
                         "scripts": [r"google-analytics\.com/(?:ga|analytics)\.js",
                                     r"googletagmanager\.com/gtag/js"]},
    "Matomo": {"cats": ["Analytics"], "scripts": [r"matomo\.js", r"piwik\.js"]},
    "Hotjar": {"cats": ["Analytics"], "scripts": [r"static\.hotjar\.com"]},
    "Mixpanel": {"cats": ["Analytics"], "scripts": [r"mixpanel"]},
    "Segment": {"cats": ["Analytics"], "scripts": [r"cdn\.segment\.com"]},
    # Security
    "reCAPTCHA": {"cats": ["Security"], "scripts": [r"www\.google\.com/recaptcha", r"www\.gstatic\.com/recaptcha"],
                  "html": [r'class="g-recaptcha"']},
    "Cloudflare Bot Management": {"cats": ["Security"], "scripts": [r"cdn-cgi/challenge-platform"]},
    "Imperva": {"cats": ["Security"], "headers": {"X-Iinfo": "", "X-CDN": r"Incapsula"}},
    "Sucuri": {"cats": ["Security"], "headers": {"X-Sucuri-ID": "", "Server": r"Sucuri/Cloudproxy"}},
    # Caches
    "Varnish": {"cats": ["Cache"], "headers": {"X-Varnish": "", "Via": r"varnish"}},
    "Squid": {"cats": ["Cache"], "headers": {"X-Cache": r"\bsquid\b", "Via": r"squid/"}},
    # Containers
    "Kubernetes Ingress": {"cats": ["Infrastructure"], "headers": {"Server": r"openresty/?[\d.]*"}},
    # Auth
    "Auth0": {"cats": ["Auth"], "scripts": [r"auth0\.com/js/", r"cdn\.auth0\.com"]},
    "Okta": {"cats": ["Auth"], "scripts": [r"okta\.com"], "headers": {"Set-Cookie": r"sid="}},
    # Misc
    "GraphQL": {"cats": ["API"], "html": [r"__schema", r"GraphiQL"],
                "scripts": [r"graphql"], "website": "https://graphql.org"},
    "Swagger UI": {"cats": ["API"], "html": [r"swagger-ui"], "scripts": [r"swagger-ui"]},
    "OpenAPI": {"cats": ["API"], "html": [r"openapi\.json", r"openapi\.yaml"]},
    # Build tools / bundlers (script hints)
    "Webpack": {"cats": ["Build"], "scripts": [r"webpackChunk", r"__webpack_require__"]},
    "Vite": {"cats": ["Build"], "scripts": [r"/@vite/client", r"/_vite/"]},
}

# Wappalyzer-like categories (informational)
_T4B_WAPPALYZER_CATEGORIES = {
    "CMS": 1, "JS Framework": 2, "Framework": 3, "JS Library": 4,
    "UI Framework": 5, "Web Server": 6, "Language": 7, "CDN": 8,
    "Analytics": 9, "Security": 10, "Cache": 11, "E-commerce": 12,
    "Auth": 13, "API": 14, "Build": 15, "Infrastructure": 16,
}


def _t4b_compile_pattern(pattern: str):
    """Wappalyzer pattern syntax: regex + optional ;version:\\1 or ;confidence:50."""
    if not isinstance(pattern, str):
        return None, None, 100
    parts = pattern.split("\\;")
    parts = "\\;".join(parts).split(";")
    rx_str = parts[0]
    version_template = None
    confidence = 100
    for extra in parts[1:]:
        extra = extra.strip()
        if extra.startswith("version:"):
            version_template = extra[len("version:"):]
        elif extra.startswith("confidence:"):
            try:
                confidence = int(extra[len("confidence:"):])
            except Exception:
                pass
    try:
        rx = _t4b_re.compile(rx_str, _t4b_re.IGNORECASE)
    except Exception:
        return None, version_template, confidence
    return rx, version_template, confidence


def _t4b_apply_version(template: _T4BOptional[str], match) -> _T4BOptional[str]:
    if not template or not match:
        return None
    out = template
    try:
        for i, g in enumerate(match.groups(), start=1):
            out = out.replace(f"\\{i}", g if g else "")
    except Exception:
        return None
    return out.strip() or None


def _t4b_match_field(value: str, pattern: str):
    if value is None:
        return None, 0, None
    rx, ver_t, conf = _t4b_compile_pattern(pattern)
    if not rx:
        return None, 0, None
    m = rx.search(str(value))
    if not m:
        return None, 0, None
    return m, conf, _t4b_apply_version(ver_t, m)


def _t4b_extract_meta_tags(html: str) -> _T4BDict[str, str]:
    out = {}
    if not html:
        return out
    for m in _t4b_re.finditer(
        r'<meta\s+[^>]*name=["\']([^"\']+)["\'][^>]*content=["\']([^"\']*)["\']',
        html, _t4b_re.IGNORECASE,
    ):
        out[m.group(1).lower()] = m.group(2)
    return out


def _t4b_extract_script_srcs(html: str) -> _T4BList[str]:
    if not html:
        return []
    return [m.group(1) for m in _t4b_re.finditer(
        r'<script\s+[^>]*src=["\']([^"\']+)["\']', html, _t4b_re.IGNORECASE)]


def _t4b_normalize_headers(headers: _T4BAny) -> _T4BDict[str, str]:
    if headers is None:
        return {}
    if hasattr(headers, "items"):
        return {str(k).lower(): str(v) for k, v in headers.items()}
    if isinstance(headers, list):
        return {str(k).lower(): str(v) for k, v in headers}
    return {}


def _t4b_normalize_cookies(cookies: _T4BAny) -> _T4BDict[str, str]:
    if cookies is None:
        return {}
    if hasattr(cookies, "items"):
        return {str(k): str(v) for k, v in cookies.items()}
    if isinstance(cookies, str):
        out = {}
        for part in cookies.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip()] = v.strip()
        return out
    return {}


def _t4b_wappalyzer_match(self, html: str = "", headers=None, cookies=None,
                           scripts: _T4BOptional[_T4BList[str]] = None,
                           url: str = "") -> _T4BList[_T4BDict[str, _T4BAny]]:
    """Run Wappalyzer-style pattern matching against html/headers/cookies/scripts.
    Returns list of {tech, version, confidence, categories, evidence}."""
    if hasattr(self, "_check_dry_run"):
        stub = self._check_dry_run("wappalyzer_match", url=url)
        if stub is not None:
            return stub
    headers_n = _t4b_normalize_headers(headers)
    cookies_n = _t4b_normalize_cookies(cookies)
    meta = _t4b_extract_meta_tags(html or "")
    auto_scripts = _t4b_extract_script_srcs(html or "")
    all_scripts = list(scripts or []) + auto_scripts

    matches = {}
    for tech, defn in _T4B_WAPPALYZER_DB.items():
        evidence = []
        version = None
        confidence_total = 0

        # headers
        for hk, hpat in (defn.get("headers") or {}).items():
            hv = headers_n.get(hk.lower(), "")
            if hpat == "":
                if hv:
                    evidence.append(f"header:{hk}")
                    confidence_total += 50
                continue
            m, conf, ver = _t4b_match_field(hv, hpat)
            if m:
                evidence.append(f"header:{hk}={hv[:60]}")
                confidence_total += conf
                version = version or ver

        # cookies
        for ck, cpat in (defn.get("cookies") or {}).items():
            for cookie_name in cookies_n:
                if cookie_name.startswith(ck) or cookie_name == ck:
                    if cpat:
                        m, conf, ver = _t4b_match_field(cookies_n[cookie_name], cpat)
                        if m:
                            evidence.append(f"cookie:{cookie_name}")
                            confidence_total += conf
                            version = version or ver
                    else:
                        evidence.append(f"cookie:{cookie_name}")
                        confidence_total += 50

        # html
        for hpat in (defn.get("html") or []):
            m, conf, ver = _t4b_match_field(html or "", hpat)
            if m:
                evidence.append(f"html:{hpat[:40]}")
                confidence_total += conf
                version = version or ver

        # scripts
        for spat in (defn.get("scripts") or []):
            for sc in all_scripts:
                m, conf, ver = _t4b_match_field(sc, spat)
                if m:
                    evidence.append(f"script:{sc[:60]}")
                    confidence_total += conf
                    version = version or ver
                    break

        # meta
        for mk, mpat in (defn.get("meta") or {}).items():
            mv = meta.get(mk.lower(), "")
            m, conf, ver = _t4b_match_field(mv, mpat)
            if m:
                evidence.append(f"meta:{mk}={mv[:40]}")
                confidence_total += conf
                version = version or ver

        if evidence:
            matches[tech] = {
                "tech": tech, "version": version,
                "confidence": min(confidence_total, 100),
                "categories": defn.get("cats", []),
                "evidence": evidence[:6],
                "website": defn.get("website"),
            }

    # Apply implies (transitive)
    added = True
    safety = 0
    while added and safety < 5:
        added = False
        safety += 1
        for tech in list(matches):
            for implied in (_T4B_WAPPALYZER_DB.get(tech, {}).get("implies") or []):
                if implied not in matches and implied in _T4B_WAPPALYZER_DB:
                    matches[implied] = {
                        "tech": implied, "version": None, "confidence": 50,
                        "categories": _T4B_WAPPALYZER_DB[implied].get("cats", []),
                        "evidence": [f"implied_by:{tech}"],
                        "website": _T4B_WAPPALYZER_DB[implied].get("website"),
                    }
                    added = True

    return sorted(matches.values(), key=lambda x: (-x["confidence"], x["tech"]))


def _t4b_fingerprint_with_wappalyzer(self, url: str, timeout: float = 10.0,
                                      verify: bool = True, follow_redirects: bool = True):
    """Fetch URL and run wappalyzer_match against the response."""
    if hasattr(self, "_check_dry_run"):
        stub = self._check_dry_run("fingerprint_with_wappalyzer", url=url)
        if stub is not None:
            return stub
    ctx = _t4b_ssl.create_default_context() if verify else _t4b_ssl._create_unverified_context()
    req = _t4b_urlreq.Request(url, headers={"User-Agent": "CaseCrack/T4B-Fingerprint"})
    try:
        resp = _t4b_urlreq.urlopen(req, timeout=timeout, context=ctx)
    except Exception as ex:
        return {"error": str(ex), "url": url}
    body = resp.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
    headers = dict(resp.getheaders())
    cookies_hdr = "; ".join(v for k, v in resp.getheaders() if k.lower() == "set-cookie")
    techs = _t4b_wappalyzer_match(self, html=body, headers=headers, cookies=cookies_hdr, url=url)
    return {
        "url": url, "status": resp.status,
        "final_url": resp.geturl(),
        "headers_count": len(headers),
        "techs": techs,
        "categories": sorted({c for t in techs for c in t["categories"]}),
    }


def _t4b_wappalyzer_register_tech(self, name: str, definition: dict):
    """Add a custom tech definition at runtime."""
    if not isinstance(name, str) or not isinstance(definition, dict):
        raise ValueError("name must be str, definition must be dict")
    _T4B_WAPPALYZER_DB[name] = definition
    return True


def _t4b_wappalyzer_categories(self):
    return dict(_T4B_WAPPALYZER_CATEGORIES)


def _t4b_wappalyzer_db_size(self):
    return {"techs": len(_T4B_WAPPALYZER_DB),
            "categories": len(_T4B_WAPPALYZER_CATEGORIES)}


def _t4b_extract_security_headers(self, headers) -> _T4BDict[str, _T4BAny]:
    """Audit security-relevant headers in a response."""
    h = _t4b_normalize_headers(headers)
    audit = {
        "strict_transport_security": h.get("strict-transport-security"),
        "content_security_policy": h.get("content-security-policy"),
        "x_frame_options": h.get("x-frame-options"),
        "x_content_type_options": h.get("x-content-type-options"),
        "referrer_policy": h.get("referrer-policy"),
        "permissions_policy": h.get("permissions-policy"),
        "cross_origin_opener_policy": h.get("cross-origin-opener-policy"),
        "cross_origin_resource_policy": h.get("cross-origin-resource-policy"),
        "cross_origin_embedder_policy": h.get("cross-origin-embedder-policy"),
    }
    score = sum(1 for v in audit.values() if v) / max(len(audit), 1) * 100
    missing = [k for k, v in audit.items() if not v]
    return {"score": round(score, 1), "missing": missing, "values": audit}


# Bind to HTTPFingerprinter
try:
    HTTPFingerprinter.wappalyzer_match = _t4b_wappalyzer_match  # type: ignore[name-defined]
    HTTPFingerprinter.fingerprint_with_wappalyzer = _t4b_fingerprint_with_wappalyzer  # type: ignore[name-defined]
    HTTPFingerprinter.wappalyzer_register_tech = _t4b_wappalyzer_register_tech  # type: ignore[name-defined]
    HTTPFingerprinter.wappalyzer_categories = _t4b_wappalyzer_categories  # type: ignore[name-defined]
    HTTPFingerprinter.wappalyzer_db_size = _t4b_wappalyzer_db_size  # type: ignore[name-defined]
    HTTPFingerprinter.extract_security_headers = _t4b_extract_security_headers  # type: ignore[name-defined]
except NameError:
    pass

# ====================== END __TIER4B_NETWORK__ ========================
