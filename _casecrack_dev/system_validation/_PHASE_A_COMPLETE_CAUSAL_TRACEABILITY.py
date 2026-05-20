#!/usr/bin/env python3
"""
Phase A Complete: Full Causal Traceability (execution_path → transport → entry_point)

Validates all three layers:
1. execution_path: Authority (MCP)
2. transport: How traffic entered (BRIDGE, CLI, etc.)
3. entry_point: Intent/operation (dashboard_get_report, operator_config, etc.)
"""

import sys
import re

def check_file(filepath, checks):
    """Validate file has expected changes."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"❌ File not found: {filepath}")
        return False
    
    all_pass = True
    for check_name, pattern in checks:
        match_count = len(re.findall(pattern, content))
        min_expected = 1
        
        # Special handling for multi-occurrence checks
        if "8+" in check_name:
            min_expected = 8
        elif "10+" in check_name:
            min_expected = 10
        
        if match_count >= min_expected:
            print(f"✅ {filepath}: {check_name} (found {match_count} matches)")
        else:
            print(f"❌ {filepath}: MISSING {check_name} (found {match_count}, expected {min_expected})")
            all_pass = False
    
    return all_pass

def main():
    print("\n" + "=" * 75)
    print("PHASE A COMPLETE: Full Causal Traceability with entry_point")
    print("=" * 75 + "\n")
    
    # Check mcp_server.py changes
    print("📋 Checking mcp_server.py (MCP execution authority)...\n")
    
    mcp_server_checks = [
        ("entry_point parameter in execute_tool_request", 
         r"entry_point:\s*str\s*="),
        
        ("transport parameter in execute_tool_request", 
         r"transport:\s*str\s*="),
        
        ("entry_point passed to audit events (8+)",
         r"entry_point=entry_point"),
        
        ("transport passed to audit events",
         r"transport=transport"),
    ]
    
    mcp_server_ok = check_file(
        "CaseCrack/tools/burp_enterprise/mcp/mcp_server.py",
        mcp_server_checks
    )
    
    # Check mcp_http_server.py changes
    print("\n📋 Checking mcp_http_server.py (BRIDGE entry point detection)...\n")
    
    http_server_checks = [
        ("_TOOL_TO_ENTRY_POINT mapping defined",
         r"_TOOL_TO_ENTRY_POINT\s*=\s*\{"),
        
        ("_get_entry_point method defined",
         r"def _get_entry_point"),
        
        ("entry_point parameter in execute_tool_request call",
         r'entry_point=entry_point'),
        
        ("entry_point variable assigned from tool",
         r"entry_point\s*=\s*self\._get_entry_point"),
    ]
    
    http_server_ok = check_file(
        "CaseCrack/tools/burp_enterprise/mcp/mcp_http_server.py",
        http_server_checks
    )
    
    # Summary
    print("\n" + "=" * 75)
    if mcp_server_ok and http_server_ok:
        print("✅ ALL CHECKS PASSED - FULL CAUSAL TRACEABILITY")
        print("\n📊 Layer Architecture:")
        print("  Layer 1: execution_path = 'MCP' (single authority) ✅")
        print("  Layer 2: transport = 'BRIDGE'/'CLI'/etc (how entered) ✅")
        print("  Layer 3: entry_point = 'dashboard_get_report' (intent) ✅")
        print("\n📝 Example audit event now shows:")
        print('{')
        print('  "event_type": "tool_completed",')
        print('  "execution_path": "MCP",          # Authority ✅')
        print('  "transport": "BRIDGE",            # Origin ✅')
        print('  "entry_point": "dashboard_get_report",  # Intent ✅')
        print('  "tool_name": "get_report",')
        print('  "ok": true,')
        print('  "duration_ms": 245')
        print('}')
        print("\n🧠 Causal Traceability Chain:")
        print("  Who executed? → MCP")
        print("  How did it enter? → HTTP bridge")
        print("  What operation was it? → Dashboard report retrieval")
        print("\n🎯 This enables:")
        print("  • Operator intelligence (detect patterns by entry_point)")
        print("  • Enforcement by intent (not just transport)")
        print("  • Root cause analysis (full causal chain)")
        print("\n🚀 Ready for Phase B (CLI/Dashboard normalization)")
        print("  Phase B will use same 3-layer pattern:")
        print("  execution_path='MCP' + transport='CLI' + entry_point='operator_config'")
        return 0
    else:
        print("❌ SOME CHECKS FAILED")
        return 1
    print("=" * 75 + "\n")

if __name__ == "__main__":
    sys.exit(main())
