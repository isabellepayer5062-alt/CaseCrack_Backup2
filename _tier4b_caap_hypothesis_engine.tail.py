# __TIER4B_CAAP__
# Tier 4B CAAP — hypothesis_engine: 8 category generators
import re as _t4b_re
import time as _t4b_time
import hashlib as _t4b_hash
import uuid as _t4b_uuid
from typing import Any, Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

# 8 hypothesis categories
_T4B_HYP_CATEGORIES = (
    "injection",        # SQL/NoSQL/Command/Template injection
    "auth_bypass",      # JWT/session/MFA/IDOR
    "access_control",   # broken access, privilege escalation, IDOR
    "data_exposure",    # PII leak, error verbosity, dir listing
    "ssrf_xxe",         # SSRF, XXE, file inclusion
    "client_side",      # XSS, CSRF, CORS misconfig, clickjacking
    "infrastructure",   # outdated software, default creds, misconfig
    "business_logic",   # race condition, workflow bypass, price manipulation
)


@dataclass
class _T4BHypothesis:
    id: str
    category: str
    title: str
    target: str
    indicators: List[str] = field(default_factory=list)
    suggested_tests: List[Dict[str, Any]] = field(default_factory=list)
    confidence_prior: float = 0.5
    severity_estimate: str = "medium"  # critical|high|medium|low|info
    rationale: str = ""
    created_at: float = field(default_factory=_t4b_time.time)


def _t4b_hyp_id(category: str, target: str, title: str) -> str:
    raw = f"{category}|{target}|{title}".encode()
    return f"H-{category[:3]}-{_t4b_hash.sha256(raw).hexdigest()[:12]}"


# ---- Generator helpers (signature-based) -------------------------------
def _gen_injection(signal: Dict[str, Any]) -> List[_T4BHypothesis]:
    out: List[_T4BHypothesis] = []
    target = signal.get("url", "") or signal.get("target", "")
    params = signal.get("params") or signal.get("parameters") or []
    methods = signal.get("methods") or [signal.get("method", "GET")]
    body = (signal.get("body") or signal.get("response") or "").lower()
    for p in params:
        for m in methods:
            ind = []
            sev = "high"
            if any(k in p.lower() for k in ("id", "user", "search", "q", "query", "filter")):
                ind.append(f"param '{p}' commonly tied to DB queries")
                sev = "high"
            if "sql syntax" in body or "ora-" in body:
                ind.append("DB error string in baseline response")
                sev = "critical"
            h = _T4BHypothesis(
                id=_t4b_hyp_id("injection", target, f"SQLi via {p}"),
                category="injection", title=f"SQL injection via {p}",
                target=target, indicators=ind,
                suggested_tests=[{"type": "sqli", "param": p, "method": m}],
                confidence_prior=0.55 if ind else 0.3,
                severity_estimate=sev,
                rationale=f"Parameter '{p}' on {m} {target} likely flows to SQL.",
            )
            out.append(h)
    return out


def _gen_auth_bypass(signal: Dict[str, Any]) -> List[_T4BHypothesis]:
    out = []
    target = signal.get("url", "") or signal.get("target", "")
    headers = signal.get("headers", {})
    cookies = signal.get("cookies", "")
    if "authorization" in {k.lower() for k in headers}:
        bearer = headers.get("Authorization", "").lower()
        if "bearer" in bearer and bearer.count(".") == 2:
            out.append(_T4BHypothesis(
                id=_t4b_hyp_id("auth_bypass", target, "JWT none algorithm"),
                category="auth_bypass", title="JWT none algorithm bypass",
                target=target, indicators=["JWT detected in Authorization header"],
                suggested_tests=[{"type": "jwt_none", "header": "Authorization"}],
                confidence_prior=0.5, severity_estimate="critical",
                rationale="Bearer JWT may accept alg=none if validation is weak.",
            ))
            out.append(_T4BHypothesis(
                id=_t4b_hyp_id("auth_bypass", target, "JWT key confusion"),
                category="auth_bypass", title="JWT RS256→HS256 key confusion",
                target=target, indicators=["JWT detected"],
                suggested_tests=[{"type": "jwt_key_confusion"}],
                confidence_prior=0.4, severity_estimate="critical",
                rationale="If RS256 public key is known, HS256 with public key may forge tokens.",
            ))
    if cookies and "secure" not in cookies.lower():
        out.append(_T4BHypothesis(
            id=_t4b_hyp_id("auth_bypass", target, "Session over HTTP"),
            category="auth_bypass", title="Session cookie missing Secure flag",
            target=target, indicators=["Cookie lacks Secure attribute"],
            suggested_tests=[{"type": "cookie_audit"}],
            confidence_prior=0.7, severity_estimate="medium",
            rationale="Session can leak over HTTP if Secure flag absent.",
        ))
    return out


def _gen_access_control(signal: Dict[str, Any]) -> List[_T4BHypothesis]:
    out = []
    target = signal.get("url", "") or signal.get("target", "")
    if _t4b_re.search(r"/(users?|accounts?|orders?|invoices?|files?)/\d+", target):
        out.append(_T4BHypothesis(
            id=_t4b_hyp_id("access_control", target, "IDOR numeric id"),
            category="access_control", title="IDOR via predictable numeric ID",
            target=target, indicators=["Numeric id in resource path"],
            suggested_tests=[{"type": "idor", "id_param": "path", "strategy": "increment"}],
            confidence_prior=0.6, severity_estimate="high",
            rationale="Sequential IDs in path commonly enable IDOR.",
        ))
    if _t4b_re.search(r"/(admin|internal|debug)/", target):
        out.append(_T4BHypothesis(
            id=_t4b_hyp_id("access_control", target, "Admin path exposure"),
            category="access_control", title="Admin/internal path access",
            target=target, indicators=["Path contains admin/internal/debug segment"],
            suggested_tests=[{"type": "auth_required_check"}],
            confidence_prior=0.5, severity_estimate="high",
            rationale="Admin paths must enforce auth.",
        ))
    return out


def _gen_data_exposure(signal: Dict[str, Any]) -> List[_T4BHypothesis]:
    out = []
    target = signal.get("url", "") or signal.get("target", "")
    body = signal.get("body") or signal.get("response") or ""
    if _t4b_re.search(r"\b(stack trace|exception|traceback|at\s+\w+\.\w+\(|warning:)", body, _t4b_re.IGNORECASE):
        out.append(_T4BHypothesis(
            id=_t4b_hyp_id("data_exposure", target, "Verbose error"),
            category="data_exposure", title="Verbose error / stack trace",
            target=target, indicators=["Stack trace pattern in response"],
            suggested_tests=[{"type": "verbose_error_probe"}],
            confidence_prior=0.85, severity_estimate="medium",
            rationale="Stack traces leak internal paths and library versions.",
        ))
    if _t4b_re.search(r"\b\d{3}-\d{2}-\d{4}\b|\b4\d{15}\b|\b3[47]\d{13}\b", body):
        out.append(_T4BHypothesis(
            id=_t4b_hyp_id("data_exposure", target, "PII leak"),
            category="data_exposure", title="PII (SSN/CC) in response",
            target=target, indicators=["SSN or credit card pattern detected"],
            suggested_tests=[{"type": "pii_extraction_audit"}],
            confidence_prior=0.7, severity_estimate="critical",
            rationale="Direct PII in API response.",
        ))
    if "<title>index of /" in body.lower() or "directory listing for /" in body.lower():
        out.append(_T4BHypothesis(
            id=_t4b_hyp_id("data_exposure", target, "Directory listing"),
            category="data_exposure", title="Directory listing enabled",
            target=target, indicators=["Apache/Nginx directory listing detected"],
            suggested_tests=[{"type": "dir_listing_enum"}],
            confidence_prior=0.95, severity_estimate="medium",
            rationale="Directory listing exposes file inventory.",
        ))
    return out


def _gen_ssrf_xxe(signal: Dict[str, Any]) -> List[_T4BHypothesis]:
    out = []
    target = signal.get("url", "") or signal.get("target", "")
    params = signal.get("params") or []
    content_type = (signal.get("content_type") or "").lower()
    for p in params:
        if any(k in p.lower() for k in ("url", "callback", "redirect", "next", "target", "image", "uri", "feed", "host")):
            out.append(_T4BHypothesis(
                id=_t4b_hyp_id("ssrf_xxe", target, f"SSRF via {p}"),
                category="ssrf_xxe", title=f"SSRF via {p}",
                target=target, indicators=[f"URL-like param: {p}"],
                suggested_tests=[{"type": "ssrf", "param": p}],
                confidence_prior=0.6, severity_estimate="high",
                rationale=f"Param '{p}' typically accepts URLs and may fetch internal resources.",
            ))
    if "xml" in content_type:
        out.append(_T4BHypothesis(
            id=_t4b_hyp_id("ssrf_xxe", target, "XXE on XML endpoint"),
            category="ssrf_xxe", title="XXE on XML endpoint",
            target=target, indicators=["Endpoint accepts XML payload"],
            suggested_tests=[{"type": "xxe", "content_type": content_type}],
            confidence_prior=0.55, severity_estimate="critical",
            rationale="XML parsers may resolve external entities by default.",
        ))
    return out


def _gen_client_side(signal: Dict[str, Any]) -> List[_T4BHypothesis]:
    out = []
    target = signal.get("url", "") or signal.get("target", "")
    params = signal.get("params") or []
    headers = signal.get("headers", {}) or {}
    body = signal.get("body") or signal.get("response") or ""
    for p in params:
        if any(k in p.lower() for k in ("name", "search", "q", "comment", "message", "title", "subject")):
            out.append(_T4BHypothesis(
                id=_t4b_hyp_id("client_side", target, f"Reflected XSS via {p}"),
                category="client_side", title=f"Reflected XSS via {p}",
                target=target, indicators=[f"Free-text param: {p}"],
                suggested_tests=[{"type": "xss", "param": p}],
                confidence_prior=0.55, severity_estimate="high",
                rationale=f"Free-text param '{p}' often reflected in HTML.",
            ))
    cors = headers.get("access-control-allow-origin", "") or headers.get("Access-Control-Allow-Origin", "")
    if cors == "*" or (cors and headers.get("Access-Control-Allow-Credentials", "").lower() == "true"):
        out.append(_T4BHypothesis(
            id=_t4b_hyp_id("client_side", target, "CORS misconfig"),
            category="client_side", title="CORS misconfiguration (* or null with credentials)",
            target=target, indicators=[f"ACAO: {cors}"],
            suggested_tests=[{"type": "cors_probe"}],
            confidence_prior=0.7, severity_estimate="high",
            rationale="Permissive CORS allows credentialed cross-origin reads.",
        ))
    if "x-frame-options" not in {k.lower() for k in headers}:
        out.append(_T4BHypothesis(
            id=_t4b_hyp_id("client_side", target, "Clickjacking"),
            category="client_side", title="Clickjacking — X-Frame-Options missing",
            target=target, indicators=["X-Frame-Options header absent"],
            suggested_tests=[{"type": "clickjack_probe"}],
            confidence_prior=0.5, severity_estimate="medium",
            rationale="No frame-busting header set.",
        ))
    return out


def _gen_infrastructure(signal: Dict[str, Any]) -> List[_T4BHypothesis]:
    out = []
    target = signal.get("url", "") or signal.get("target", "")
    headers = signal.get("headers", {}) or {}
    server = (headers.get("Server") or headers.get("server") or "").lower()
    powered = (headers.get("X-Powered-By") or "").lower()
    if any(t in server for t in ("apache/2.2", "apache/2.0", "iis/6", "iis/7", "nginx/1.1", "nginx/1.0")):
        out.append(_T4BHypothesis(
            id=_t4b_hyp_id("infrastructure", target, f"Outdated server: {server}"),
            category="infrastructure", title=f"Outdated server software: {server}",
            target=target, indicators=[f"Server: {server}"],
            suggested_tests=[{"type": "version_cve_lookup", "software": server}],
            confidence_prior=0.85, severity_estimate="high",
            rationale="Server version banner indicates EoL software.",
        ))
    if powered and any(t in powered for t in ("php/5", "asp.net/2", "asp.net/3")):
        out.append(_T4BHypothesis(
            id=_t4b_hyp_id("infrastructure", target, f"Outdated runtime: {powered}"),
            category="infrastructure", title=f"Outdated runtime: {powered}",
            target=target, indicators=[f"X-Powered-By: {powered}"],
            suggested_tests=[{"type": "version_cve_lookup", "software": powered}],
            confidence_prior=0.85, severity_estimate="high",
            rationale="Runtime is EoL.",
        ))
    if _t4b_re.search(r"/(login|admin)", target):
        out.append(_T4BHypothesis(
            id=_t4b_hyp_id("infrastructure", target, "Default creds"),
            category="infrastructure", title="Default/weak credentials probe",
            target=target, indicators=["Login endpoint detected"],
            suggested_tests=[{"type": "default_creds_probe"}],
            confidence_prior=0.4, severity_estimate="critical",
            rationale="Test admin/admin, root/root, common defaults.",
        ))
    return out


def _gen_business_logic(signal: Dict[str, Any]) -> List[_T4BHypothesis]:
    out = []
    target = signal.get("url", "") or signal.get("target", "")
    if _t4b_re.search(r"/(checkout|payment|order|coupon|discount|refund)", target):
        out.append(_T4BHypothesis(
            id=_t4b_hyp_id("business_logic", target, "Race condition in checkout"),
            category="business_logic", title="Race condition in payment/checkout",
            target=target, indicators=["Payment-related endpoint detected"],
            suggested_tests=[{"type": "race_condition", "concurrency": 20}],
            confidence_prior=0.4, severity_estimate="critical",
            rationale="Concurrent submissions may double-apply coupons or duplicate orders.",
        ))
        out.append(_T4BHypothesis(
            id=_t4b_hyp_id("business_logic", target, "Negative price"),
            category="business_logic", title="Negative or zero quantity/price",
            target=target, indicators=["Payment-related endpoint detected"],
            suggested_tests=[{"type": "negative_value_probe"}],
            confidence_prior=0.45, severity_estimate="high",
            rationale="Negative qty/amount may produce credits.",
        ))
    if _t4b_re.search(r"/(register|signup|invite)", target):
        out.append(_T4BHypothesis(
            id=_t4b_hyp_id("business_logic", target, "Mass-assignment"),
            category="business_logic", title="Mass-assignment via extra fields (role/admin)",
            target=target, indicators=["Registration endpoint detected"],
            suggested_tests=[{"type": "mass_assignment", "field": "role"}],
            confidence_prior=0.5, severity_estimate="high",
            rationale="Submitting role=admin may be accepted unfiltered.",
        ))
    return out


_T4B_GENERATORS: Dict[str, Callable[[Dict[str, Any]], List[_T4BHypothesis]]] = {
    "injection": _gen_injection,
    "auth_bypass": _gen_auth_bypass,
    "access_control": _gen_access_control,
    "data_exposure": _gen_data_exposure,
    "ssrf_xxe": _gen_ssrf_xxe,
    "client_side": _gen_client_side,
    "infrastructure": _gen_infrastructure,
    "business_logic": _gen_business_logic,
}


def _t4b_hyp_categories(self) -> List[str]:
    return list(_T4B_HYP_CATEGORIES)


def _t4b_generate_hypotheses(self, signal: Dict[str, Any],
                                  categories: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    cats = categories or list(_T4B_HYP_CATEGORIES)
    out: List[Dict[str, Any]] = []
    for c in cats:
        gen = _T4B_GENERATORS.get(c)
        if gen is None:
            continue
        try:
            for h in gen(signal):
                out.append(h.__dict__)
        except Exception:
            continue
    return out


def _t4b_generate_for_category(self, category: str,
                                    signal: Dict[str, Any]) -> List[Dict[str, Any]]:
    gen = _T4B_GENERATORS.get(category)
    if gen is None:
        return []
    try:
        return [h.__dict__ for h in gen(signal)]
    except Exception:
        return []


def _t4b_score_hypothesis(self, hypothesis: Dict[str, Any]) -> float:
    """Composite score: prior * severity_weight * indicator_boost."""
    sev_w = {"critical": 1.0, "high": 0.85, "medium": 0.6, "low": 0.4, "info": 0.2}
    sw = sev_w.get(hypothesis.get("severity_estimate", "medium"), 0.6)
    prior = float(hypothesis.get("confidence_prior", 0.5))
    ind_count = len(hypothesis.get("indicators", []))
    ind_boost = min(1.5, 1.0 + 0.15 * ind_count)
    return round(min(1.0, prior * sw * ind_boost), 3)


def _t4b_rank_hypotheses(self, hypotheses: List[Dict[str, Any]],
                              top_n: Optional[int] = None) -> List[Dict[str, Any]]:
    scored = []
    for h in hypotheses:
        s = _t4b_score_hypothesis(self, h)
        scored.append({**h, "score": s})
    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored[:top_n] if top_n else scored


def _t4b_dedup_hypotheses(self, hypotheses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out = []
    for h in hypotheses:
        k = h.get("id") or _t4b_hyp_id(h.get("category", "?"),
                                                  h.get("target", "?"), h.get("title", "?"))
        if k in seen:
            continue
        seen.add(k)
        out.append(h)
    return out


def _t4b_register_generator(self, category: str,
                                  generator: Callable[[Dict[str, Any]], List[Any]]) -> bool:
    if category not in _T4B_HYP_CATEGORIES:
        return False
    _T4B_GENERATORS[category] = generator
    return True


# --- Bind to HypothesisEngine -------------------------------------------
try:
    HypothesisEngine.hypothesis_categories = _t4b_hyp_categories  # type: ignore[name-defined]
    HypothesisEngine.generate_hypotheses = _t4b_generate_hypotheses  # type: ignore[name-defined]
    HypothesisEngine.generate_for_category = _t4b_generate_for_category  # type: ignore[name-defined]
    HypothesisEngine.score_hypothesis = _t4b_score_hypothesis  # type: ignore[name-defined]
    HypothesisEngine.rank_hypotheses = _t4b_rank_hypotheses  # type: ignore[name-defined]
    HypothesisEngine.dedup_hypotheses = _t4b_dedup_hypotheses  # type: ignore[name-defined]
    HypothesisEngine.register_generator = _t4b_register_generator  # type: ignore[name-defined]
except NameError:
    pass
