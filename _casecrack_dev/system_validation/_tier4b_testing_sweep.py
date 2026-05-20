"""Tier 4B Testing — sweep driver: append tail files to testing_tools modules.

Idempotent: marker `# __TIER4B_TESTING__` prevents double-injection.
"""
from __future__ import annotations
import os
import sys
from pathlib import Path

ROOT = Path(__file__).parent
TESTING_DIR = ROOT / "CaseCrack" / "tools" / "burp_enterprise" / "testing_tools"
MARKER = "# __TIER4B_TESTING__"

PAIRS = {
    "api_fuzzer.py":            "_tier4b_test_api_fuzzer.tail.py",
    "benchmark_runner.py":      "_tier4b_test_benchmark_runner.tail.py",
    "compliance_validator.py":  "_tier4b_test_compliance_validator.tail.py",
    "integration_harness.py":   "_tier4b_test_integration_harness.tail.py",
    "load_tester.py":           "_tier4b_test_load_tester.tail.py",
    "mock_server.py":           "_tier4b_test_mock_server.tail.py",
    "regression_tracker.py":    "_tier4b_test_regression_tracker.tail.py",
}


def main() -> int:
    if not TESTING_DIR.exists():
        print(f"[ERR] testing_tools dir not found: {TESTING_DIR}")
        return 2
    applied = 0
    skipped = 0
    missing_tail = 0
    missing_mod = 0
    for mod_name, tail_name in PAIRS.items():
        mod = TESTING_DIR / mod_name
        tail = ROOT / tail_name
        if not mod.exists():
            print(f"[MISS] module: {mod_name}")
            missing_mod += 1
            continue
        if not tail.exists():
            print(f"[MISS] tail: {tail_name}")
            missing_tail += 1
            continue
        body = mod.read_text(encoding="utf-8", errors="replace")
        if MARKER in body:
            print(f"[SKIP] already injected: {mod_name}")
            skipped += 1
            continue
        tail_body = tail.read_text(encoding="utf-8", errors="replace")
        before_loc = body.count("\n")
        new_body = body.rstrip() + "\n\n\n" + tail_body.rstrip() + "\n"
        mod.write_text(new_body, encoding="utf-8")
        after_loc = new_body.count("\n")
        added = after_loc - before_loc
        print(f"[OK] {mod_name}: +{added} LOC ({before_loc} -> {after_loc})")
        applied += 1
    print()
    print(f"applied={applied} skipped={skipped} "
              f"missing_mod={missing_mod} missing_tail={missing_tail}")
    return 0 if (missing_mod == 0 and missing_tail == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
