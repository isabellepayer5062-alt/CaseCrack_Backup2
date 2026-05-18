"""Tier 4B Network sweep: append per-module deep-feature tail blocks (idempotent)."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NET_DIR = ROOT / "CaseCrack" / "tools" / "burp_enterprise" / "network"
MARKER = "# __TIER4B_NETWORK__"

TAILS = {
    "dns_resolver":     ROOT / "_tier4b_net_dns_resolver.tail.py",
    "http_fingerprint": ROOT / "_tier4b_net_http_fingerprint.tail.py",
    "ssl_analyzer":     ROOT / "_tier4b_net_ssl_analyzer.tail.py",
    "traffic_analyzer": ROOT / "_tier4b_net_traffic_analyzer.tail.py",
    "proxy_chain":      ROOT / "_tier4b_net_proxy_chain.tail.py",
}


def append_tail(target: Path, tail: Path) -> str:
    src = target.read_text(encoding="utf-8")
    if MARKER in src:
        return "skipped"
    block = tail.read_text(encoding="utf-8")
    if not src.endswith("\n"):
        src += "\n"
    target.write_text(src + "\n\n" + block, encoding="utf-8")
    return "applied"


def main() -> int:
    if not NET_DIR.exists():
        print(f"ERROR: network dir not found: {NET_DIR}", file=sys.stderr)
        return 2
    out = {}
    for mod, tail_path in TAILS.items():
        target = NET_DIR / f"{mod}.py"
        if not target.exists():
            print(f"  {mod}: MISSING TARGET")
            out[mod] = "missing_target"
            continue
        if not tail_path.exists():
            print(f"  {mod}: MISSING TAIL ({tail_path.name})")
            out[mod] = "missing_tail"
            continue
        before = len(target.read_text(encoding="utf-8").splitlines())
        status = append_tail(target, tail_path)
        after = len(target.read_text(encoding="utf-8").splitlines())
        delta = after - before
        out[mod] = status
        print(f"  {mod}: {status:8s}  {before} -> {after} (+{delta})")
    print()
    print("Summary:", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
