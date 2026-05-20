#!/usr/bin/env python3
"""Verify Phase 15 lifecycle metadata additions in code."""

import ast
import re
from pathlib import Path


def check_lifecycle_metadata_in_code():
    """Verify lifecycle metadata tracking is present in security_testing.py."""
    
    file_path = Path("CaseCrack/tools/burp_enterprise/recon_dashboard/phase_handlers/security_testing.py")
    content = file_path.read_text()
    
    print("[*] Checking Phase 15 lifecycle metadata implementation in security_testing.py")
    print()
    
    checks_passed = 0
    checks_total = 0
    
    # Check 1: Timestamp tracking dictionaries initialized
    checks_total += 1
    if "_p15_encountered_at: dict[str, float] = {}" in content and "_p15_persisted_at: dict[str, float] = {}" in content:
        print("[✓] Check 1: Timestamp tracking dictionaries initialized")
        checks_passed += 1
    else:
        print("[✗] Check 1: Timestamp tracking dictionaries NOT found")
    
    # Check 2: Capture encountered_at timestamp
    checks_total += 1
    if "_p15_encountered_at.setdefault(_nu, time.time())" in content:
        print("[✓] Check 2: Capture encountered_at timestamp on first discovery")
        checks_passed += 1
    else:
        print("[✗] Check 2: encountered_at capture NOT found")
    
    # Check 3: Capture persisted_at timestamp
    checks_total += 1
    if "_p15_persisted_at.setdefault(_nu, time.time())" in content:
        print("[✓] Check 3: Capture persisted_at timestamp on persist")
        checks_passed += 1
    else:
        print("[✗] Check 3: persisted_at capture NOT found")
    
    # Check 4: Download attempts tracking
    checks_total += 1
    if "_p15_download_attempts: dict[str, int] = {}" in content and "_p15_download_attempts.get(_nu, 0) + 1" in content:
        print("[✓] Check 4: Download attempts tracking initialized and used")
        checks_passed += 1
    else:
        print("[✗] Check 4: Download attempts tracking NOT found")
    
    # Check 5: Skip reasons tracking
    checks_total += 1
    if "_p15_skip_reasons: dict[str, str] = {}" in content:
        print("[✓] Check 5: Skip reasons dictionary initialized")
        checks_passed += 1
    else:
        print("[✗] Check 5: Skip reasons tracking NOT found")
    
    # Check 6: Manifest entry includes first_seen_stage
    checks_total += 1
    if '"first_seen_stage": _p15_seen_origin.get(_nu, "<unknown>")' in content:
        print("[✓] Check 6: Manifest entry includes first_seen_stage")
        checks_passed += 1
    else:
        print("[✗] Check 6: first_seen_stage in manifest NOT found")
    
    # Check 7: Manifest entry includes persisted_stage
    checks_total += 1
    if '"persisted_stage": "bundle_direct_write"' in content:
        print("[✓] Check 7: Manifest entry includes persisted_stage")
        checks_passed += 1
    else:
        print("[✗] Check 7: persisted_stage in manifest NOT found")
    
    # Check 8: Manifest entry includes encountered_at timestamp
    checks_total += 1
    if '"encountered_at": _p15_encountered_at.get(_nu, time.time())' in content:
        print("[✓] Check 8: Manifest entry includes encountered_at timestamp")
        checks_passed += 1
    else:
        print("[✗] Check 8: encountered_at in manifest NOT found")
    
    # Check 9: Manifest entry includes persisted_at timestamp
    checks_total += 1
    if '"persisted_at": _p15_persisted_at.get(_nu, time.time())' in content:
        print("[✓] Check 9: Manifest entry includes persisted_at timestamp")
        checks_passed += 1
    else:
        print("[✗] Check 9: persisted_at in manifest NOT found")
    
    # Check 10: Manifest entry includes download_attempts
    checks_total += 1
    if '"download_attempts": _p15_download_attempts.get(_nu, 1)' in content:
        print("[✓] Check 10: Manifest entry includes download_attempts count")
        checks_passed += 1
    else:
        print("[✗] Check 10: download_attempts in manifest NOT found")
    
    # Check 11: Manifest entry includes persisted boolean
    checks_total += 1
    if '"persisted": True' in content and '"manifested": True' in content:
        print("[✓] Check 11: Manifest entry includes persisted and manifested flags")
        checks_passed += 1
    else:
        print("[✗] Check 11: persisted/manifested flags in manifest NOT found")
    
    # Check 12: Manifest entry includes skip_reason
    checks_total += 1
    if '"skip_reason": None' in content or '"skip_reason"' in content:
        print("[✓] Check 12: Manifest entry includes skip_reason field")
        checks_passed += 1
    else:
        print("[✗] Check 12: skip_reason in manifest NOT found")
    
    # Check 13: Manifest summary includes totals
    checks_total += 1
    if '"total_encountered": len(_p15_encountered_urls)' in content:
        print("[✓] Check 13: Manifest summary includes total_encountered count")
        checks_passed += 1
    else:
        print("[✗] Check 13: total_encountered in manifest NOT found")
    
    # Check 14: Skip reasons are being recorded during download
    checks_total += 1
    if '_p15_skip_reasons[_nu] = "already_persisted"' in content:
        print("[✓] Check 14: Skip reasons recorded during URL processing")
        checks_passed += 1
    else:
        print("[✗] Check 14: Skip reason recording NOT found")
    
    # Check 15: Operational state not reading from manifest (sanity check)
    checks_total += 1
    # Count how many times we reference _p15_persisted_urls (runtime state) for gating
    persisted_urls_gating = content.count("if _nu in _p15_persisted_urls:")
    if persisted_urls_gating >= 2:  # At least in direct and HTML pass
        print(f"[✓] Check 15: Runtime state (_p15_persisted_urls) used for gating ({persisted_urls_gating} checks)")
        checks_passed += 1
    else:
        print(f"[✗] Check 15: Runtime state gating NOT found (found {persisted_urls_gating})")
    
    print()
    print(f"[{'=' * 60}]")
    print(f"[+] Results: {checks_passed}/{checks_total} checks passed")
    print(f"[{'=' * 60}]")
    
    if checks_passed == checks_total:
        print("\n[✓] PHASE 15 LIFECYCLE METADATA HARDENING: COMPLETE")
        return 0
    else:
        print(f"\n[!] {checks_total - checks_passed} checks failed")
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(check_lifecycle_metadata_in_code())
