#!/usr/bin/env python3
"""
Phase A Validation Test: BRIDGE Collapse
========================================

Generates BRIDGE HTTP traffic to verify:
1. MCP server is reachable via HTTP
2. Tool results are returned correctly
3. Audit trail shows execution_path="MCP" (not "BRIDGE")

Expected behavior:
- 5 calls to each of 3 BRIDGE tools = 15 total calls
- Each call generates 1 MCP audit event pair (request + completed)
- Zero bridge_tool_request/bridge_tool_result events
- Validator should show: non_mcp_execution_rate ≈ 0.0
"""

import asyncio
import aiohttp
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
AUDIT_LOG = ROOT / "CaseCrack" / "mcp_audit.jsonl"

# Phase A target tools (3 BRIDGE reads to collapse)
PHASE_A_TOOLS = [
    ("help", {}),
    ("get_report", {"format": "json"}),
    ("get_system_health", {}),
]

async def test_bridge_tool(session, tool_name, arguments):
    """Make one BRIDGE HTTP call to MCP server."""
    url = "http://localhost:8765/mcp/call"
    payload = {"name": tool_name, "arguments": arguments}
    
    try:
        async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status == 200:
                result = await resp.json()
                return result.get("ok", False), result
            else:
                return False, {"error": f"HTTP {resp.status}"}
    except Exception as e:
        return False, {"error": str(e)}

async def run_phase_a_validation():
    """Generate Phase A test traffic."""
    print("🚀 Phase A Validation: BRIDGE Collapse Test")
    print(f"📊 Audit log: {AUDIT_LOG}")
    print(f"🎯 Target: 5 calls × 3 tools = 15 HTTP requests")
    print()
    
    # Count existing audit events before test
    before_count = 0
    if AUDIT_LOG.exists():
        with AUDIT_LOG.open("r") as f:
            before_count = sum(1 for _ in f)
    print(f"📈 Audit events before: {before_count}")
    
    # Start HTTP client
    async with aiohttp.ClientSession() as session:
        total_ok = 0
        total_failed = 0
        
        for call_num in range(5):
            for tool_name, arguments in PHASE_A_TOOLS:
                ok, result = await test_bridge_tool(session, tool_name, arguments)
                if ok:
                    total_ok += 1
                    print(f"✅ Call {total_ok:2d}: {tool_name:20s} → success")
                else:
                    total_failed += 1
                    print(f"❌ Call {total_failed:2d}: {tool_name:20s} → {result.get('error', 'unknown')}")
                await asyncio.sleep(0.1)  # Small delay between calls
    
    print()
    print(f"📊 Results: {total_ok} OK, {total_failed} FAILED")
    
    # Count audit events after test
    after_count = 0
    if AUDIT_LOG.exists():
        with AUDIT_LOG.open("r") as f:
            after_count = sum(1 for _ in f)
    
    new_events = after_count - before_count
    print(f"📈 Audit events after:  {after_count} (+{new_events} new)")
    
    # Check for bridge_tool events (should be ZERO)
    bridge_events = 0
    mcp_events = 0
    if AUDIT_LOG.exists():
        with AUDIT_LOG.open("r") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    et = entry.get("event_type", "")
                    if et.startswith("bridge_tool"):
                        bridge_events += 1
                    elif et in ("tool_request", "tool_completed"):
                        mcp_events += 1
                except:
                    pass
    
    print()
    print(f"🔍 Audit Trail Analysis:")
    print(f"   - bridge_tool_* events: {bridge_events} (target: 0)")
    print(f"   - tool_request/completed: {mcp_events} (target: ≥30)")
    
    if bridge_events == 0 and mcp_events >= 30:
        print()
        print("✅ Phase A Validation PASSED")
        print("   BRIDGE calls are now MCP-only in audit trail!")
        return 0
    else:
        print()
        print("⚠️  Phase A Validation INCOMPLETE")
        if bridge_events > 0:
            print(f"   Still seeing {bridge_events} bridge_tool_* events (should be 0)")
        if mcp_events < 30:
            print(f"   Only {mcp_events} MCP events (expected ≥30)")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(run_phase_a_validation())
    sys.exit(exit_code)
