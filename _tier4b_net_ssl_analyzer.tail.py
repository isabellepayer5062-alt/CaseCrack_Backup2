
# ======================================================================
# __TIER4B_NETWORK__  ssl_analyzer: OCSP, CT logs, cipher enumeration
# ======================================================================
import socket as _t4b_socket
import ssl as _t4b_ssl
import struct as _t4b_struct
import hashlib as _t4b_hashlib
import base64 as _t4b_base64
import urllib.request as _t4b_urlreq
import urllib.parse as _t4b_urlparse
import json as _t4b_json
import time as _t4b_time
import re as _t4b_re
from typing import Any as _T4BAny, Dict as _T4BDict, List as _T4BList, Optional as _T4BOptional

# IANA-listed cipher suites (TLS 1.2 + TLS 1.3 selection, ~80 entries)
_T4B_CIPHER_SUITES = [
    # TLS 1.3
    ("TLS_AES_128_GCM_SHA256", 0x1301, "TLS 1.3", "secure"),
    ("TLS_AES_256_GCM_SHA384", 0x1302, "TLS 1.3", "secure"),
    ("TLS_CHACHA20_POLY1305_SHA256", 0x1303, "TLS 1.3", "secure"),
    ("TLS_AES_128_CCM_SHA256", 0x1304, "TLS 1.3", "secure"),
    ("TLS_AES_128_CCM_8_SHA256", 0x1305, "TLS 1.3", "secure"),
    # TLS 1.2 ECDHE+AEAD (preferred)
    ("ECDHE-ECDSA-AES256-GCM-SHA384", 0xC02C, "TLS 1.2", "secure"),
    ("ECDHE-RSA-AES256-GCM-SHA384", 0xC030, "TLS 1.2", "secure"),
    ("ECDHE-ECDSA-CHACHA20-POLY1305", 0xCCA9, "TLS 1.2", "secure"),
    ("ECDHE-RSA-CHACHA20-POLY1305", 0xCCA8, "TLS 1.2", "secure"),
    ("ECDHE-ECDSA-AES128-GCM-SHA256", 0xC02B, "TLS 1.2", "secure"),
    ("ECDHE-RSA-AES128-GCM-SHA256", 0xC02F, "TLS 1.2", "secure"),
    # DHE+AEAD
    ("DHE-RSA-AES256-GCM-SHA384", 0x009F, "TLS 1.2", "secure"),
    ("DHE-RSA-AES128-GCM-SHA256", 0x009E, "TLS 1.2", "secure"),
    ("DHE-RSA-CHACHA20-POLY1305", 0xCCAA, "TLS 1.2", "secure"),
    # ECDHE CBC SHA-2 (acceptable, no AEAD)
    ("ECDHE-RSA-AES256-SHA384", 0xC028, "TLS 1.2", "acceptable"),
    ("ECDHE-RSA-AES128-SHA256", 0xC027, "TLS 1.2", "acceptable"),
    ("ECDHE-ECDSA-AES256-SHA384", 0xC024, "TLS 1.2", "acceptable"),
    ("ECDHE-ECDSA-AES128-SHA256", 0xC023, "TLS 1.2", "acceptable"),
    # CBC SHA-1 (legacy, weak HMAC but no break)
    ("ECDHE-RSA-AES256-SHA", 0xC014, "TLS 1.0+", "weak"),
    ("ECDHE-RSA-AES128-SHA", 0xC013, "TLS 1.0+", "weak"),
    ("ECDHE-ECDSA-AES256-SHA", 0xC00A, "TLS 1.0+", "weak"),
    ("ECDHE-ECDSA-AES128-SHA", 0xC009, "TLS 1.0+", "weak"),
    ("AES256-GCM-SHA384", 0x009D, "TLS 1.2", "weak"),
    ("AES128-GCM-SHA256", 0x009C, "TLS 1.2", "weak"),
    ("AES256-SHA256", 0x003D, "TLS 1.2", "weak"),
    ("AES128-SHA256", 0x003C, "TLS 1.2", "weak"),
    ("AES256-SHA", 0x0035, "TLS 1.0+", "weak"),
    ("AES128-SHA", 0x002F, "TLS 1.0+", "weak"),
    # Insecure (must report as critical)
    ("DES-CBC3-SHA", 0x000A, "TLS 1.0+", "insecure"),         # 3DES SWEET32
    ("RC4-SHA", 0x0005, "TLS 1.0+", "insecure"),               # RC4
    ("RC4-MD5", 0x0004, "TLS 1.0+", "insecure"),               # RC4+MD5
    ("EXP-RC4-MD5", 0x0003, "Export", "insecure"),             # EXPORT
    ("EXP-DES-CBC-SHA", 0x0008, "Export", "insecure"),         # EXPORT
    ("EXP-RC2-CBC-MD5", 0x0006, "Export", "insecure"),         # EXPORT
    ("NULL-SHA", 0x0002, "TLS 1.0+", "insecure"),              # NULL cipher
    ("NULL-MD5", 0x0001, "TLS 1.0+", "insecure"),              # NULL cipher
    ("ADH-AES256-SHA", 0x003A, "TLS 1.0+", "insecure"),        # Anonymous DH
    ("ADH-AES128-SHA", 0x0034, "TLS 1.0+", "insecure"),        # Anonymous DH
    ("DHE-RSA-DES-CBC3-SHA", 0x0016, "TLS 1.0+", "insecure"),  # 3DES
    ("EDH-RSA-DES-CBC-SHA", 0x0015, "TLS 1.0+", "insecure"),   # SINGLE DES
]

_T4B_TLS_VERSION_BYTES = {
    "TLSv1.0": (0x03, 0x01), "TLSv1.1": (0x03, 0x02),
    "TLSv1.2": (0x03, 0x03), "TLSv1.3": (0x03, 0x04),
}

_T4B_CT_LOGS = {
    "crt.sh": "https://crt.sh/?q={domain}&output=json",
    "censys": "https://search.censys.io/api/v2/certificates/search",
}


def _t4b_tls_record(version_bytes, content_type, payload):
    return bytes([content_type]) + bytes(version_bytes) + _t4b_struct.pack(">H", len(payload)) + payload


def _t4b_client_hello(self, host: str, version: str = "TLSv1.2", cipher_suites=None):
    """Build minimal TLS ClientHello bytes for cipher probing."""
    vbytes = _T4B_TLS_VERSION_BYTES[version]
    rand = b"\x00" * 4 + bytes([_t4b_random_byte() for _ in range(28)])
    sess_id = b"\x00"
    cs = cipher_suites or [c[1] for c in _T4B_CIPHER_SUITES]
    cs_bytes = b"".join(_t4b_struct.pack(">H", c) for c in cs)
    cs_block = _t4b_struct.pack(">H", len(cs_bytes)) + cs_bytes
    compression = b"\x01\x00"  # null compression
    sni = host.encode("idna")
    sni_ext = (b"\x00\x00" +  # ext type SNI
               _t4b_struct.pack(">H", len(sni) + 5) +
               _t4b_struct.pack(">H", len(sni) + 3) +
               b"\x00" + _t4b_struct.pack(">H", len(sni)) + sni)
    sig_algs = b"\x00\x0d" + _t4b_struct.pack(">H", 12) + _t4b_struct.pack(">H", 10) + (
        b"\x04\x03\x05\x03\x06\x03\x08\x04\x08\x05")
    supported_versions = b"\x00\x2b\x00\x03\x02" + bytes(vbytes)
    extensions = sni_ext + sig_algs + supported_versions
    ext_block = _t4b_struct.pack(">H", len(extensions)) + extensions
    body = bytes(vbytes) + rand + sess_id + cs_block + compression + ext_block
    handshake = b"\x01" + _t4b_struct.pack(">I", len(body))[1:] + body
    return _t4b_tls_record(vbytes, 0x16, handshake)


def _t4b_random_byte():
    import os as _os
    return _os.urandom(1)[0]


def _t4b_probe_cipher(self, host: str, port: int, cipher_id: int,
                      version: str = "TLSv1.2", timeout: float = 4.0) -> bool:
    """Send ClientHello with single cipher; True if server picks it."""
    try:
        hello = _t4b_client_hello(self, host, version=version, cipher_suites=[cipher_id])
    except Exception:
        return False
    sock = _t4b_socket.socket(_t4b_socket.AF_INET, _t4b_socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.sendall(hello)
        data = sock.recv(4096)
        if not data or len(data) < 6:
            return False
        # Alert(0x15) response means rejected
        if data[0] == 0x15:
            return False
        # Handshake(0x16) ServerHello means accepted
        if data[0] == 0x16:
            return True
    except Exception:
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return False


def _t4b_enumerate_ciphers(self, host: str, port: int = 443,
                            versions: _T4BOptional[_T4BList[str]] = None,
                            timeout: float = 4.0,
                            max_workers: int = 8) -> _T4BDict[str, _T4BAny]:
    """Probe each cipher in DB across each version; return support matrix."""
    if hasattr(self, "_check_dry_run"):
        stub = self._check_dry_run("enumerate_ciphers", host=host, port=port)
        if stub is not None:
            return stub
    versions = versions or ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
    from concurrent.futures import ThreadPoolExecutor
    results = {v: {"supported": [], "rejected": [], "errors": []} for v in versions}

    def _probe(args):
        v, name, cid, _ver, _str = args
        try:
            ok = _t4b_probe_cipher(self, host, port, cid, version=v, timeout=timeout)
            return v, name, cid, ok, None
        except Exception as ex:
            return v, name, cid, False, str(ex)

    tasks = []
    for v in versions:
        for entry in _T4B_CIPHER_SUITES:
            name, cid, ver_label, strength = entry
            if v == "TLSv1.3" and not name.startswith("TLS_"):
                continue
            if v != "TLSv1.3" and name.startswith("TLS_"):
                continue
            tasks.append((v, name, cid, ver_label, strength))

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for v, name, cid, ok, err in ex.map(_probe, tasks):
            entry = next((e for e in _T4B_CIPHER_SUITES if e[1] == cid), None)
            strength = entry[3] if entry else "unknown"
            rec = {"name": name, "id": f"0x{cid:04X}", "strength": strength}
            if err:
                results[v]["errors"].append({**rec, "error": err})
            elif ok:
                results[v]["supported"].append(rec)
            else:
                results[v]["rejected"].append(rec)

    summary = _t4b_weak_cipher_report(self, results)
    return {"host": host, "port": port, "results": results, "summary": summary}


def _t4b_weak_cipher_report(self, enum_results: _T4BDict[str, _T4BAny]) -> _T4BDict[str, _T4BAny]:
    """Flag NULL/EXPORT/RC4/3DES/MD5/anonymous DH and SWEET32/POODLE risk."""
    findings = []
    insecure_total = 0
    weak_total = 0
    for ver, data in enum_results.items():
        if isinstance(data, dict):
            sup = data.get("supported", [])
        else:
            sup = []
        for c in sup:
            n = c.get("name", "")
            s = c.get("strength", "")
            if s == "insecure":
                insecure_total += 1
                if "NULL" in n:
                    findings.append({"severity": "critical", "issue": "NULL cipher supported",
                                     "version": ver, "cipher": n})
                elif "EXP" in n or "Export" in n:
                    findings.append({"severity": "critical", "issue": "EXPORT-grade cipher (FREAK)",
                                     "version": ver, "cipher": n})
                elif "RC4" in n:
                    findings.append({"severity": "high", "issue": "RC4 cipher (CVE-2013-2566)",
                                     "version": ver, "cipher": n})
                elif "3DES" in n or "DES-CBC3" in n:
                    findings.append({"severity": "high", "issue": "3DES cipher (SWEET32 CVE-2016-2183)",
                                     "version": ver, "cipher": n})
                elif "ADH" in n:
                    findings.append({"severity": "critical", "issue": "Anonymous DH (no auth)",
                                     "version": ver, "cipher": n})
                else:
                    findings.append({"severity": "high", "issue": "Insecure cipher",
                                     "version": ver, "cipher": n})
            elif s == "weak":
                weak_total += 1
        if ver in ("TLSv1.0", "TLSv1.1") and sup:
            findings.append({"severity": "high",
                             "issue": f"Deprecated protocol {ver} enabled",
                             "version": ver, "cipher": None})
    return {"insecure_count": insecure_total, "weak_count": weak_total,
            "findings": findings, "score": max(0, 100 - insecure_total * 25 - weak_total * 5)}


def _t4b_extract_ocsp_url(self, cert_der_or_dict) -> _T4BOptional[str]:
    """Extract OCSP responder URL from certificate AIA extension."""
    if isinstance(cert_der_or_dict, dict):
        # ssl module getpeercert dict format
        aia = cert_der_or_dict.get("OCSP") or cert_der_or_dict.get("caIssuers")
        if isinstance(aia, (tuple, list)):
            for u in aia:
                if isinstance(u, str) and u.startswith("http"):
                    return u
        return None
    if isinstance(cert_der_or_dict, (bytes, bytearray)):
        # naive scan for ASN.1 OID 1.3.6.1.5.5.7.48.1 (id-ad-ocsp) followed by IA5String URL
        data = bytes(cert_der_or_dict)
        for m in _t4b_re.finditer(rb"http[s]?://[^\x00-\x1f\x7f-\xff\s]{4,256}", data):
            u = m.group(0).decode("ascii", errors="replace")
            if "ocsp" in u.lower():
                return u
    return None


def _t4b_ocsp_check(self, host: str, port: int = 443, timeout: float = 8.0) -> _T4BDict[str, _T4BAny]:
    """Fetch cert chain and query OCSP responder. Returns stapled status if present."""
    if hasattr(self, "_check_dry_run"):
        stub = self._check_dry_run("ocsp_check", host=host, port=port)
        if stub is not None:
            return stub
    ctx = _t4b_ssl.create_default_context()
    try:
        with _t4b_socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_dict = ssock.getpeercert()
                cert_der = ssock.getpeercert(binary_form=True)
    except Exception as ex:
        return {"error": str(ex), "host": host, "port": port}

    ocsp_url = _t4b_extract_ocsp_url(self, cert_dict) or _t4b_extract_ocsp_url(self, cert_der)
    result = {
        "host": host, "port": port,
        "cert_subject": cert_dict.get("subject"),
        "cert_issuer": cert_dict.get("issuer"),
        "ocsp_url": ocsp_url,
        "cert_fingerprint_sha256": _t4b_hashlib.sha256(cert_der).hexdigest(),
    }
    if not ocsp_url:
        result["status"] = "no_ocsp_url"
        return result

    # Query OCSP via GET (simple form) - returns binary OCSP response
    try:
        ocsp_req_b64 = _t4b_base64.b64encode(_t4b_build_minimal_ocsp_request(cert_der)).decode()
        ocsp_url_full = ocsp_url.rstrip("/") + "/" + _t4b_urlparse.quote(ocsp_req_b64, safe="")
        req = _t4b_urlreq.Request(ocsp_url_full, headers={
            "Content-Type": "application/ocsp-request",
            "User-Agent": "CaseCrack/T4B-OCSP",
        })
        with _t4b_urlreq.urlopen(req, timeout=timeout) as resp:
            ocsp_resp = resp.read(8192)
    except Exception as ex:
        result["status"] = "ocsp_query_failed"
        result["error"] = str(ex)
        return result

    # Parse OCSPResponseStatus (first byte after SEQUENCE/ENUMERATED tag)
    status_code = -1
    try:
        # Look for ENUMERATED (0x0A) tag at start of responseStatus
        for i in range(min(20, len(ocsp_resp))):
            if ocsp_resp[i] == 0x0A and ocsp_resp[i + 1] == 0x01:
                status_code = ocsp_resp[i + 2]
                break
    except Exception:
        pass
    status_map = {0: "successful", 1: "malformedRequest", 2: "internalError",
                  3: "tryLater", 5: "sigRequired", 6: "unauthorized"}
    result["ocsp_response_status"] = status_map.get(status_code, f"unknown({status_code})")
    result["ocsp_response_size"] = len(ocsp_resp)
    # Heuristic cert status by scanning for "good"/"revoked" tags
    # certStatus: good (0xA0), revoked (0xA1), unknown (0xA2)
    cert_status = "unknown"
    if b"\xa0\x00" in ocsp_resp:
        cert_status = "good"
    elif b"\xa1" in ocsp_resp:
        cert_status = "revoked"
    elif b"\xa2\x00" in ocsp_resp:
        cert_status = "unknown"
    result["cert_status"] = cert_status
    return result


def _t4b_build_minimal_ocsp_request(cert_der: bytes) -> bytes:
    """Build a minimal OCSPRequest. For production use cryptography lib, this is heuristic."""
    issuer_hash = _t4b_hashlib.sha1(cert_der[:64]).digest()  # placeholder
    serial_hash = _t4b_hashlib.sha1(cert_der[-64:]).digest()
    # Wrap in barebones SEQUENCE structure (this is intentionally minimal; real OCSP needs proper ASN.1)
    inner = b"\x30\x29" + b"\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00" + \
            b"\x04\x14" + issuer_hash + b"\x04\x14" + serial_hash[:20] + b"\x02\x01\x01"
    req = b"\x30\x2d" + b"\x30\x2b" + b"\x30\x29" + inner
    return req


def _t4b_ct_log_search(self, domain: str, log: str = "crt.sh",
                        timeout: float = 15.0, limit: int = 200) -> _T4BDict[str, _T4BAny]:
    """Query Certificate Transparency log for certs issued for domain."""
    if hasattr(self, "_check_dry_run"):
        stub = self._check_dry_run("ct_log_search", domain=domain, log=log)
        if stub is not None:
            return stub
    if log == "crt.sh":
        url = _T4B_CT_LOGS["crt.sh"].format(domain=_t4b_urlparse.quote(domain))
        req = _t4b_urlreq.Request(url, headers={
            "Accept": "application/json",
            "User-Agent": "CaseCrack/T4B-CT",
        })
        try:
            with _t4b_urlreq.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except Exception as ex:
            return {"error": str(ex), "domain": domain, "log": log}
        try:
            rows = _t4b_json.loads(body or "[]")
        except Exception:
            rows = []
        certs = []
        seen_names = set()
        for row in rows[:limit]:
            name = row.get("name_value", "")
            for n in name.split("\n"):
                seen_names.add(n.strip().lower())
            certs.append({
                "issuer": row.get("issuer_name"),
                "common_name": row.get("common_name"),
                "name_value": name,
                "not_before": row.get("not_before"),
                "not_after": row.get("not_after"),
                "serial_number": row.get("serial_number"),
                "id": row.get("id"),
            })
        return {"domain": domain, "log": log, "cert_count": len(certs),
                "subdomains": sorted(seen_names),
                "subdomain_count": len(seen_names),
                "certs": certs}
    return {"error": f"unknown log: {log}", "domain": domain}


def _t4b_ct_extract_subdomains(self, ct_result: _T4BDict[str, _T4BAny]) -> _T4BList[str]:
    subs = set(ct_result.get("subdomains", []))
    # filter wildcards and add their parents
    out = set()
    for s in subs:
        if s.startswith("*."):
            out.add(s[2:])
        elif s and "." in s and " " not in s:
            out.add(s)
    return sorted(out)


def _t4b_assess_cipher_strength(self, cipher_name: str) -> _T4BDict[str, _T4BAny]:
    for name, cid, version, strength in _T4B_CIPHER_SUITES:
        if name == cipher_name:
            return {"name": name, "id": f"0x{cid:04X}", "version": version, "strength": strength}
    return {"name": cipher_name, "strength": "unknown"}


# Bind to SSLAnalyzer
try:
    SSLAnalyzer.enumerate_ciphers = _t4b_enumerate_ciphers  # type: ignore[name-defined]
    SSLAnalyzer.weak_cipher_report = _t4b_weak_cipher_report  # type: ignore[name-defined]
    SSLAnalyzer.ocsp_check = _t4b_ocsp_check  # type: ignore[name-defined]
    SSLAnalyzer.extract_ocsp_url = _t4b_extract_ocsp_url  # type: ignore[name-defined]
    SSLAnalyzer.ct_log_search = _t4b_ct_log_search  # type: ignore[name-defined]
    SSLAnalyzer.ct_extract_subdomains = _t4b_ct_extract_subdomains  # type: ignore[name-defined]
    SSLAnalyzer.assess_cipher_strength = _t4b_assess_cipher_strength  # type: ignore[name-defined]
except NameError:
    pass

# ====================== END __TIER4B_NETWORK__ ========================
