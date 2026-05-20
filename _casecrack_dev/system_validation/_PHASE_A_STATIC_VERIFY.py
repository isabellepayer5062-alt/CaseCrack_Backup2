#!/usr/bin/env python3
"""
Phase A: Static Verification
=============================

Verify that mcp_http_server.py no longer emits bridge_tool_request/result audit events.
This does NOT require running the server, just checks the source code.
"""

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
HTTP_SERVER = ROOT / "CaseCrack" / "tools" / "burp_enterprise" / "mcp" / "mcp_http_server.py"

def verify_phase_a_changes():
    """Verify Phase A implementation in source code."""
    print("🔍 Phase A: Static Code Verification")
    print(f"📄 File: {HTTP_SERVER}")
    print()
    
    content = HTTP_SERVER.read_text(encoding="utf-8")
    
    # Check 1: No active bridge_tool_request audit calls
    bridge_request_active = re.search(
        r'self\._audit\.log_event\s*\(\s*event_type\s*=\s*["\']bridge_tool_request["\']',
        content
    )
    
    # Check 2: No active bridge_tool_result audit calls
    bridge_result_active = re.search(
        r'self\._audit\.log_event\s*\(\s*event_type\s*=\s*["\']bridge_tool_result["\']',
        content
    )
    
    # Check 3: Comments exist explaining Phase A changes
    phase_a_comment_request = "Phase A: Removed bridge_tool_request" in content
    phase_a_comment_result = "Phase A: Removed bridge_tool_result" in content
    
    # Check 4: SSE broadcasts still present
    sse_request = "tool_request" in content and "self._broadcast" in content
    
    print("✅ Checks:")
    print(f"  1. bridge_tool_request audit removed:   {'✓' if not bridge_request_active else '✗'}")
    print(f"  2. bridge_tool_result audit removed:    {'✓' if not bridge_result_active else '✗'}")
    print(f"  3. Phase A comment for request added:   {'✓' if phase_a_comment_request else '✗'}")
    print(f"  4. Phase A comment for result added:    {'✓' if phase_a_comment_result else '✗'}")
    print(f"  5. SSE broadcasts still active:         {'✓' if sse_request else '✗'}")
    
    all_passed = (
        not bridge_request_active and
        not bridge_result_active and
        phase_a_comment_request and
        phase_a_comment_result and
        sse_request
    )
    
    print()
    if all_passed:
        print("✅ Phase A Implementation VERIFIED")
        print("   BRIDGE audit events successfully removed")
        print("   SSE broadcasts kept for UI visibility")
        return 0
    else:
        print("⚠️  Phase A Implementation INCOMPLETE")
        return 1

if __name__ == "__main__":
    import sys
    exit_code = verify_phase_a_changes()
    sys.exit(exit_code)
