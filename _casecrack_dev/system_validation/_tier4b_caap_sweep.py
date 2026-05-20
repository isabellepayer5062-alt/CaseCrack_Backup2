"""Tier 4B CAAP sweep — idempotent injection of tail files into CAAP modules."""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).parent
CAAP = ROOT / "CaseCrack" / "tools" / "burp_enterprise" / "caap"
MARKER = "# __TIER4B_CAAP__"

PAIRS = {
    "caap_coordinator.py":    "_tier4b_caap_coordinator.tail.py",
    "chat_interface.py":      "_tier4b_caap_chat_interface.tail.py",
    "compliance_checker.py":  "_tier4b_caap_compliance_checker.tail.py",
    "discovery_agent.py":     "_tier4b_caap_discovery_agent.tail.py",
    "exploitation_agent.py":  "_tier4b_caap_exploitation_agent.tail.py",
    "hypothesis_engine.py":   "_tier4b_caap_hypothesis_engine.tail.py",
    "knowledge_graph.py":     "_tier4b_caap_knowledge_graph.tail.py",
    "recon_agent.py":         "_tier4b_caap_recon_agent.tail.py",
    "session_orchestrator.py":"_tier4b_caap_session_orchestrator.tail.py",
}


def append_tail(target: Path, tail_src: Path) -> str:
    if not target.exists():
        return f"MISSING_TARGET   {target.name}"
    if not tail_src.exists():
        return f"MISSING_TAIL     {tail_src.name}"
    body = target.read_text(encoding="utf-8")
    if MARKER in body:
        return f"ALREADY_INJECTED {target.name}  (marker present)"
    tail = tail_src.read_text(encoding="utf-8")
    sep = "\n\n# ============================================================\n"
    target.write_text(body.rstrip() + sep + tail, encoding="utf-8")
    return f"INJECTED         {target.name}  +{len(tail.splitlines())} lines"


def main() -> int:
    print("=" * 70)
    print("TIER 4B CAAP SWEEP")
    print("=" * 70)
    print(f"CAAP dir: {CAAP}")
    if not CAAP.is_dir():
        print("FATAL: CAAP dir not found", file=sys.stderr)
        return 2
    results = []
    for module, tail in PAIRS.items():
        results.append(append_tail(CAAP / module, ROOT / tail))
    for r in results:
        print(r)
    fails = [r for r in results if r.startswith("MISSING")]
    print("=" * 70)
    print(f"Total: {len(results)}  Failures: {len(fails)}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
