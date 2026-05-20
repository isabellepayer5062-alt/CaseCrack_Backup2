
# ======================================================================
# __TIER4B_NETWORK__  dns_resolver: zone transfer, DoH, DNSSEC
# ======================================================================
import socket as _t4b_socket
import struct as _t4b_struct
import random as _t4b_random
import json as _t4b_json
import base64 as _t4b_base64
import urllib.request as _t4b_urlreq
import urllib.parse as _t4b_urlparse
import ssl as _t4b_ssl
import time as _t4b_time
from typing import Iterable as _T4BIterable, Optional as _T4BOptional

_T4B_RR_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 41: "OPT",
    43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 50: "NSEC3",
    51: "NSEC3PARAM", 52: "TLSA", 257: "CAA", 252: "AXFR", 255: "ANY",
}
_T4B_TYPE_BY_NAME = {v: k for k, v in _T4B_RR_TYPES.items()}

_T4B_DOH_PROVIDERS = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "google": "https://dns.google/resolve",
    "quad9": "https://dns.quad9.net/dns-query",
    "adguard": "https://dns.adguard.com/resolve",
}


def _t4b_encode_qname(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        b = label.encode("idna")
        if len(b) > 63:
            raise ValueError("label too long")
        out += bytes([len(b)]) + b
    return out + b"\x00"


def _t4b_decode_qname(buf: bytes, offset: int):
    labels = []
    jumped = False
    original = offset
    safety = 0
    while True:
        safety += 1
        if safety > 64:
            raise ValueError("qname loop")
        ln = buf[offset]
        if ln == 0:
            offset += 1
            break
        if (ln & 0xC0) == 0xC0:
            ptr = ((ln & 0x3F) << 8) | buf[offset + 1]
            if not jumped:
                original = offset + 2
            offset = ptr
            jumped = True
            continue
        offset += 1
        labels.append(buf[offset:offset + ln].decode("ascii", errors="replace"))
        offset += ln
    return ".".join(labels), (original if jumped else offset)


def _t4b_build_query(qname: str, qtype: int, want_dnssec: bool = False, qid: _T4BOptional[int] = None) -> bytes:
    qid = qid if qid is not None else _t4b_random.randint(0, 0xFFFF)
    flags = 0x0100  # standard query, RD=1
    header = _t4b_struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 1 if want_dnssec else 0)
    body = _t4b_encode_qname(qname) + _t4b_struct.pack(">HH", qtype, 1)
    if want_dnssec:
        # OPT pseudo-record with DO bit set, EDNS0 4096 bufsize
        opt = b"\x00" + _t4b_struct.pack(">HHIH", 41, 4096, 0x00008000, 0)
        body += opt
    return header + body


def _t4b_parse_rr(buf: bytes, offset: int):
    name, offset = _t4b_decode_qname(buf, offset)
    rtype, rclass, ttl, rdlen = _t4b_struct.unpack(">HHIH", buf[offset:offset + 10])
    offset += 10
    rdata = buf[offset:offset + rdlen]
    new_offset = offset + rdlen
    rtype_name = _T4B_RR_TYPES.get(rtype, str(rtype))
    value = _t4b_decode_rdata(buf, offset, rtype, rdlen)
    return {"name": name, "type": rtype_name, "class": rclass, "ttl": ttl, "data": value}, new_offset


def _t4b_decode_rdata(buf: bytes, offset: int, rtype: int, rdlen: int):
    end = offset + rdlen
    if rtype == 1 and rdlen == 4:
        return ".".join(str(b) for b in buf[offset:end])
    if rtype == 28 and rdlen == 16:
        parts = [buf[offset + i:offset + i + 2].hex() for i in range(0, 16, 2)]
        return ":".join(parts)
    if rtype in (2, 5, 12):
        nm, _ = _t4b_decode_qname(buf, offset)
        return nm
    if rtype == 15:
        pref = _t4b_struct.unpack(">H", buf[offset:offset + 2])[0]
        nm, _ = _t4b_decode_qname(buf, offset + 2)
        return f"{pref} {nm}"
    if rtype == 6:
        mname, off2 = _t4b_decode_qname(buf, offset)
        rname, off3 = _t4b_decode_qname(buf, off2)
        rest = _t4b_struct.unpack(">IIIII", buf[off3:off3 + 20])
        return {"mname": mname, "rname": rname, "serial": rest[0], "refresh": rest[1],
                "retry": rest[2], "expire": rest[3], "minimum": rest[4]}
    if rtype == 16:
        out, p = [], offset
        while p < end:
            ln = buf[p]; p += 1
            out.append(buf[p:p + ln].decode("utf-8", errors="replace"))
            p += ln
        return "".join(out)
    if rtype == 48:  # DNSKEY
        flags, proto, alg = _t4b_struct.unpack(">HBB", buf[offset:offset + 4])
        key = _t4b_base64.b64encode(buf[offset + 4:end]).decode()
        return {"flags": flags, "protocol": proto, "algorithm": alg, "public_key": key}
    if rtype == 43:  # DS
        keytag, alg, dtype = _t4b_struct.unpack(">HBB", buf[offset:offset + 4])
        digest = buf[offset + 4:end].hex()
        return {"key_tag": keytag, "algorithm": alg, "digest_type": dtype, "digest": digest}
    if rtype == 46:  # RRSIG
        tcov, alg, lab, ttl_orig, sig_exp, sig_inc, keytag = _t4b_struct.unpack(">HBBIIIH", buf[offset:offset + 18])
        sname, off2 = _t4b_decode_qname(buf, offset + 18)
        sig = _t4b_base64.b64encode(buf[off2:end]).decode()
        return {"type_covered": _T4B_RR_TYPES.get(tcov, str(tcov)), "algorithm": alg, "labels": lab,
                "original_ttl": ttl_orig, "signature_expiration": sig_exp,
                "signature_inception": sig_inc, "key_tag": keytag, "signer": sname,
                "signature": sig[:64] + "..."}
    if rtype == 47:  # NSEC
        nm, off2 = _t4b_decode_qname(buf, offset)
        return {"next_name": nm, "type_bitmap_bytes": (end - off2)}
    return buf[offset:end].hex()


def _t4b_parse_response(buf: bytes) -> dict:
    if len(buf) < 12:
        raise ValueError("response too short")
    qid, flags, qd, an, ns, ar = _t4b_struct.unpack(">HHHHHH", buf[:12])
    rcode = flags & 0x000F
    offset = 12
    questions = []
    for _ in range(qd):
        nm, offset = _t4b_decode_qname(buf, offset)
        qt, qc = _t4b_struct.unpack(">HH", buf[offset:offset + 4])
        offset += 4
        questions.append({"name": nm, "type": _T4B_RR_TYPES.get(qt, str(qt)), "class": qc})
    answers, authority, additional = [], [], []
    for _ in range(an):
        rr, offset = _t4b_parse_rr(buf, offset)
        answers.append(rr)
    for _ in range(ns):
        rr, offset = _t4b_parse_rr(buf, offset)
        authority.append(rr)
    for _ in range(ar):
        try:
            rr, offset = _t4b_parse_rr(buf, offset)
            additional.append(rr)
        except Exception:
            break
    return {"id": qid, "flags": flags, "rcode": rcode, "ad": bool(flags & 0x0020),
            "questions": questions, "answers": answers,
            "authority": authority, "additional": additional}


def _t4b_axfr(self, domain: str, nameserver: str, port: int = 53, timeout: float = 8.0):
    """Attempt AXFR zone transfer from nameserver. Returns list of records or raises."""
    if hasattr(self, "_check_dry_run"):
        stub = self._check_dry_run("axfr_zone_transfer", domain=domain, nameserver=nameserver)
        if stub is not None:
            return stub
    qid = _t4b_random.randint(0, 0xFFFF)
    msg = _t4b_build_query(domain, _T4B_TYPE_BY_NAME["AXFR"], want_dnssec=False, qid=qid)
    framed = _t4b_struct.pack(">H", len(msg)) + msg
    sock = _t4b_socket.socket(_t4b_socket.AF_INET, _t4b_socket.SOCK_STREAM)
    sock.settimeout(timeout)
    records = []
    try:
        sock.connect((nameserver, port))
        sock.sendall(framed)
        buf = b""
        deadline = _t4b_time.time() + timeout
        while _t4b_time.time() < deadline:
            chunk = sock.recv(65535)
            if not chunk:
                break
            buf += chunk
            # parse all available DNS messages
            while len(buf) >= 2:
                msg_len = _t4b_struct.unpack(">H", buf[:2])[0]
                if len(buf) < 2 + msg_len:
                    break
                msg_bytes = buf[2:2 + msg_len]
                buf = buf[2 + msg_len:]
                try:
                    parsed = _t4b_parse_response(msg_bytes)
                    if parsed["rcode"] != 0:
                        raise RuntimeError(f"AXFR refused: rcode={parsed['rcode']}")
                    records.extend(parsed["answers"])
                    # AXFR ends when we see the SOA twice
                    soas = [r for r in records if r["type"] == "SOA"]
                    if len(soas) >= 2:
                        return records
                except Exception:
                    raise
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return records


def _t4b_try_axfr(self, domain: str, timeout: float = 8.0):
    """Resolve NS records and try AXFR against each. Returns dict of ns -> records|error."""
    if hasattr(self, "_check_dry_run"):
        stub = self._check_dry_run("try_axfr", domain=domain)
        if stub is not None:
            return stub
    out = {}
    try:
        ns_list = self.resolve(domain, "NS") if hasattr(self, "resolve") else []
    except Exception:
        ns_list = []
    if not ns_list:
        # fallback via socket gethostbyname for nameservers via well-known root
        ns_list = []
    for ns in ns_list[:8]:
        target = ns.value if hasattr(ns, "value") else (ns.get("data") if isinstance(ns, dict) else str(ns))
        if not target:
            continue
        try:
            ns_ip = _t4b_socket.gethostbyname(str(target).rstrip("."))
        except Exception as ex:
            out[str(target)] = {"error": f"resolve_ns_failed: {ex}"}
            continue
        try:
            recs = _t4b_axfr(self, domain, ns_ip, timeout=timeout)
            out[str(target)] = {"records": recs, "count": len(recs)}
        except Exception as ex:
            out[str(target)] = {"error": str(ex)}
    return out


def _t4b_doh_query(self, name: str, rtype: str = "A", provider: str = "cloudflare", timeout: float = 5.0):
    """Query DNS-over-HTTPS using JSON API (dns.google style) or wireformat fallback."""
    if hasattr(self, "_check_dry_run"):
        stub = self._check_dry_run("doh_query", name=name, rtype=rtype, provider=provider)
        if stub is not None:
            return stub
    url = _T4B_DOH_PROVIDERS.get(provider, _T4B_DOH_PROVIDERS["cloudflare"])
    qs = _t4b_urlparse.urlencode({"name": name, "type": rtype})
    full_url = f"{url}?{qs}"
    req = _t4b_urlreq.Request(full_url, headers={
        "Accept": "application/dns-json",
        "User-Agent": "CaseCrack/T4B-DoH",
    })
    ctx = _t4b_ssl.create_default_context()
    with _t4b_urlreq.urlopen(req, timeout=timeout, context=ctx) as resp:
        data = _t4b_json.loads(resp.read().decode("utf-8"))
    answers = data.get("Answer", []) or []
    return {
        "provider": provider, "name": name, "type": rtype,
        "status": data.get("Status"),
        "ad": bool(data.get("AD")),
        "rcode": data.get("Status"),
        "answers": [{"name": a.get("name"), "type": _T4B_RR_TYPES.get(a.get("type"), a.get("type")),
                     "ttl": a.get("TTL"), "data": a.get("data")} for a in answers],
    }


def _t4b_doh_wireformat_query(self, name: str, rtype: str = "A", provider: str = "cloudflare", timeout: float = 5.0):
    """DoH using RFC 8484 wire-format binary."""
    if hasattr(self, "_check_dry_run"):
        stub = self._check_dry_run("doh_wireformat_query", name=name, rtype=rtype)
        if stub is not None:
            return stub
    qtype = _T4B_TYPE_BY_NAME.get(rtype.upper(), 1)
    msg = _t4b_build_query(name, qtype, want_dnssec=True)
    b64 = _t4b_base64.urlsafe_b64encode(msg).rstrip(b"=").decode()
    url = _T4B_DOH_PROVIDERS.get(provider, _T4B_DOH_PROVIDERS["cloudflare"])
    full = f"{url}?dns={b64}"
    req = _t4b_urlreq.Request(full, headers={
        "Accept": "application/dns-message",
        "User-Agent": "CaseCrack/T4B-DoH",
    })
    ctx = _t4b_ssl.create_default_context()
    with _t4b_urlreq.urlopen(req, timeout=timeout, context=ctx) as resp:
        body = resp.read()
    return _t4b_parse_response(body)


def _t4b_dnssec_validate(self, domain: str, timeout: float = 5.0):
    """Check DNSSEC chain: DNSKEY presence, DS in parent, AD bit on validated query."""
    if hasattr(self, "_check_dry_run"):
        stub = self._check_dry_run("dnssec_validate", domain=domain)
        if stub is not None:
            return stub
    report = {"domain": domain, "dnssec_present": False, "ad_bit": False,
              "dnskey_count": 0, "ds_count": 0, "rrsig_count": 0,
              "algorithms": [], "warnings": [], "checks": []}
    try:
        dnskey = _t4b_doh_wireformat_query(self, domain, "DNSKEY", timeout=timeout)
        report["dnskey_count"] = sum(1 for a in dnskey.get("answers", []) if a["type"] == "DNSKEY")
        report["rrsig_count"] += sum(1 for a in dnskey.get("answers", []) if a["type"] == "RRSIG")
        report["ad_bit"] = report["ad_bit"] or dnskey.get("ad", False)
        for rr in dnskey.get("answers", []):
            if rr["type"] == "DNSKEY" and isinstance(rr["data"], dict):
                alg = rr["data"].get("algorithm")
                if alg and alg not in report["algorithms"]:
                    report["algorithms"].append(alg)
        report["checks"].append({"step": "DNSKEY", "ok": report["dnskey_count"] > 0})
    except Exception as ex:
        report["warnings"].append(f"dnskey_query_failed: {ex}")

    try:
        ds = _t4b_doh_wireformat_query(self, domain, "DS", timeout=timeout)
        report["ds_count"] = sum(1 for a in ds.get("answers", []) if a["type"] == "DS")
        report["ad_bit"] = report["ad_bit"] or ds.get("ad", False)
        report["checks"].append({"step": "DS", "ok": report["ds_count"] > 0})
    except Exception as ex:
        report["warnings"].append(f"ds_query_failed: {ex}")

    # Validated query of a canonical record
    try:
        a = _t4b_doh_wireformat_query(self, domain, "A", timeout=timeout)
        report["ad_bit"] = report["ad_bit"] or a.get("ad", False)
        report["rrsig_count"] += sum(1 for r in a.get("answers", []) if r["type"] == "RRSIG")
    except Exception as ex:
        report["warnings"].append(f"a_query_failed: {ex}")

    report["dnssec_present"] = (report["dnskey_count"] > 0 and report["ds_count"] > 0)
    if report["dnssec_present"] and not report["ad_bit"]:
        report["warnings"].append("DNSSEC keys present but AD bit not set on validated resolver")
    if any(alg in (1, 3, 5, 7) for alg in report["algorithms"]):
        report["warnings"].append("Weak DNSSEC algorithm in use (RSAMD5/DSA/RSASHA1/NSEC3-RSASHA1)")
    return report


def _t4b_dnssec_chain_walk(self, domain: str, timeout: float = 5.0):
    """Walk parent labels checking DS/DNSKEY at each level."""
    if hasattr(self, "_check_dry_run"):
        stub = self._check_dry_run("dnssec_chain_walk", domain=domain)
        if stub is not None:
            return stub
    labels = domain.rstrip(".").split(".")
    chain = []
    for i in range(len(labels)):
        zone = ".".join(labels[i:])
        if not zone:
            continue
        node = {"zone": zone}
        try:
            r = _t4b_doh_wireformat_query(self, zone, "DNSKEY", timeout=timeout)
            node["dnskey"] = sum(1 for a in r.get("answers", []) if a["type"] == "DNSKEY")
        except Exception as ex:
            node["dnskey_error"] = str(ex)
        try:
            r = _t4b_doh_wireformat_query(self, zone, "DS", timeout=timeout)
            node["ds"] = sum(1 for a in r.get("answers", []) if a["type"] == "DS")
        except Exception as ex:
            node["ds_error"] = str(ex)
        chain.append(node)
    chain.append({"zone": ".", "root": True, "trust_anchor": "IANA-2017"})
    broken = []
    for i, node in enumerate(chain[:-1]):
        if node.get("dnskey", 0) > 0 and node.get("ds", 0) == 0 and i + 1 < len(chain) - 1:
            broken.append(f"{node['zone']}: DNSKEY present but no DS in parent")
    return {"domain": domain, "chain": chain, "intact": not broken, "broken_links": broken}


def _t4b_reverse_lookup(self, ip: str, doh: bool = False, provider: str = "cloudflare"):
    """PTR lookup. Constructs in-addr.arpa name and queries."""
    if hasattr(self, "_check_dry_run"):
        stub = self._check_dry_run("reverse_lookup", ip=ip)
        if stub is not None:
            return stub
    if ":" in ip:
        # IPv6 reverse
        groups = ip.split(":")
        # expand
        expanded = []
        for g in groups:
            if g == "":
                expanded.extend(["0"] * (8 - len([x for x in groups if x])))
            else:
                expanded.append(g.zfill(4))
        full = "".join(expanded).zfill(32)
        name = ".".join(reversed(list(full))) + ".ip6.arpa"
    else:
        parts = ip.split(".")
        name = ".".join(reversed(parts)) + ".in-addr.arpa"
    if doh:
        return _t4b_doh_query(self, name, "PTR", provider=provider)
    if hasattr(self, "resolve"):
        try:
            return self.resolve(name, "PTR")
        except Exception:
            pass
    try:
        return _t4b_socket.gethostbyaddr(ip)[0]
    except Exception as ex:
        return {"error": str(ex)}


# Bind to DNSResolver class
try:
    DNSResolver.axfr_zone_transfer = _t4b_axfr  # type: ignore[name-defined]
    DNSResolver.try_axfr = _t4b_try_axfr  # type: ignore[name-defined]
    DNSResolver.doh_query = _t4b_doh_query  # type: ignore[name-defined]
    DNSResolver.doh_wireformat_query = _t4b_doh_wireformat_query  # type: ignore[name-defined]
    DNSResolver.dnssec_validate = _t4b_dnssec_validate  # type: ignore[name-defined]
    DNSResolver.dnssec_chain_walk = _t4b_dnssec_chain_walk  # type: ignore[name-defined]
    DNSResolver.reverse_lookup = _t4b_reverse_lookup  # type: ignore[name-defined]
except NameError:
    pass

__all__ = list(set(globals().get("__all__", []))) + [
    "_t4b_build_query", "_t4b_parse_response", "_T4B_RR_TYPES", "_T4B_DOH_PROVIDERS",
]
# ====================== END __TIER4B_NETWORK__ ========================
