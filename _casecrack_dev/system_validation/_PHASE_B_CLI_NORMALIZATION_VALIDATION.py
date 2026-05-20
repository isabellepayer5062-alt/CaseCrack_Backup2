#!/usr/bin/env python3
"""Validation script for Phase B: CLI Normalization with Three-Layer Traceability."""

import re

def validate_phase_b():
    """Validate Phase B CLI normalization implementation."""
    results = []
    
    # Check CLI main.py
    with open('CaseCrack/tools/burp_enterprise/cli/main.py', 'r', encoding='utf-8') as f:
        cli_content = f.read()
    
    # 1. Verify _CLI_COMMAND_TO_ENTRY_POINT mapping exists
    mapping_exists = '_CLI_COMMAND_TO_ENTRY_POINT = {' in cli_content
    results.append(("_CLI_COMMAND_TO_ENTRY_POINT mapping defined", mapping_exists))
    
    # 2. Count mapping entries (should be >= 20)
    mapping_matches = re.findall(r'"([^"]+)":\s*"operator_', cli_content)
    mapping_count = len(mapping_matches)
    results.append((f"CLI entry_point mappings (count: {mapping_count}, min: 20)", mapping_count >= 20))
    
    # 3. Verify _get_cli_entry_point method
    get_entry_point_exists = 'def _get_cli_entry_point(command: str) -> str:' in cli_content
    results.append(("_get_cli_entry_point method defined", get_entry_point_exists))
    
    # 4. Verify auto-fallback pattern
    fallback_pattern = 'operator_{command' in cli_content
    results.append(("Auto-fallback pattern (operator_*) present", fallback_pattern))
    
    # 5. Verify _audit_cli_event updated with transport parameter
    transport_param = 'transport: str = "CLI"' in cli_content
    results.append(("transport parameter in _audit_cli_event", transport_param))
    
    # 6. Verify _audit_cli_event updated with entry_point parameter
    entry_point_param = 'entry_point: str = ""' in cli_content
    results.append(("entry_point parameter in _audit_cli_event", entry_point_param))
    
    # 7. Verify transport is passed to audit
    transport_to_audit = 'transport=transport,' in cli_content
    results.append(("transport passed to _CLI_AUDIT.log_event", transport_to_audit))
    
    # 8. Verify entry_point is passed to audit
    entry_point_to_audit = 'entry_point=ep,' in cli_content
    results.append(("entry_point passed to _CLI_AUDIT.log_event", entry_point_to_audit))
    
    # 9. Verify execution_path is still "CLI"
    execution_path_cli = 'execution_path="CLI",' in cli_content
    results.append(("execution_path still set to CLI (Layer 1)", execution_path_cli))
    
    # Print results
    print("="*70)
    print("PHASE B: CLI NORMALIZATION WITH THREE-LAYER TRACEABILITY")
    print("="*70)
    print()
    
    all_pass = True
    for check_name, passed in results:
        status = "PASS" if passed else "FAIL"
        symbol = "✓" if passed else "✗"
        print(f"{symbol} {check_name}: {status}")
        if not passed:
            all_pass = False
    
    print()
    print("="*70)
    if all_pass:
        print("RESULT: PASS - All Phase B checks verified")
    else:
        print("RESULT: FAIL - Some checks failed")
    print("="*70)
    
    return all_pass

if __name__ == "__main__":
    import sys
    success = validate_phase_b()
    sys.exit(0 if success else 1)
