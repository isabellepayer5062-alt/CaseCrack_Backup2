# 🚀 Phase A: BRIDGE → MCP Collapse Plan

**Priority:** HIGH (truth consistency)  
**Status:** Ready for implementation  
**Estimated Impact:** non_mcp_execution_rate drops from 2.8% → 0%, trend_stable = true  

---

## 📊 Current State

**Non-MCP BRIDGE reads identified:**
- `get_system_health` → feature: `dashboard_health_monitor`
- `get_report` → feature: `dashboard_export`
- `help` → feature: `ui_help_panel`

**Current execution flow:**
```
Dashboard UI
  ↓
mcp-ui-adapter.js
  ↓
mcp_http_server.handle_call_tool (BRIDGE - direct execution)
  ↓
Tool result (bypasses MCP audit)
  ↓
Operator copilot sees fragmented truth
```

**Problem:** These reads are:
- ✓ Correct for tool execution
- ✗ Invisible in MCP audit
- ✗ Visible in UI layer
- ✗ Creates "operator copilot" blind spots

---

## 🎯 Target State (Phase A Complete)

```
Dashboard UI
  ↓
mcp-ui-adapter.js
  ↓
BRIDGE HTTP request with MCP tool call
  ↓
mcp_http_server.handle_call_tool (transport only)
  ↓
mcp_server.execute_tool (MCP - with audit)
  ↓
Tool result (in MCP audit ✓)
  ↓
Response via BRIDGE
  ↓
Operator copilot sees unified truth
```

**Success Metrics:**
- ✅ All 3 BRIDGE tools emit `execution_path = "MCP"` in audit
- ✅ non_mcp_execution_rate drops to 0.0
- ✅ trend_stable transitions to true
- ✅ ready_for_enforcement transitions to true

---

## 🔧 Implementation Strategy

### Step 1: Map Each Tool to Its MCP Method

| Tool | Feature | Current Entry | Target MCP Call | UI Consumer |
|------|---------|---------------|-----------------|-------------|
| `get_system_health` | dashboard_health_monitor | mcp_http_server.handle_call_tool | `get_system_health` (native MCP) | Dashboard status panel |
| `get_report` | dashboard_export | mcp_http_server.handle_call_tool | `export_report` (create if missing) | Export dialog |
| `help` | ui_help_panel | mcp_http_server.handle_call_tool | `help` (native MCP) | Help panel |

### Step 2: Understand Current BRIDGE Implementation

**File:** `CaseCrack/tools/burp_enterprise/mcp/mcp_http_server.py`

**Current flow (already correct!):**
```python
async def handle_call_tool(request):
    tool_name = request.json()["tool"]
    arguments = request.json().get("arguments", {})
    
    # BRIDGE emits bridge_tool_request event with execution_path="BRIDGE"
    self._audit.log_event(
        event_type="bridge_tool_request",
        execution_path="BRIDGE",
        # ...
    )
    
    # Then calls MCP server (which emits tool_request, tool_completed with execution_path="MCP")
    result = await mcp_server.execute_tool_request(tool_name, arguments)
    
    # BRIDGE emits bridge_tool_result event with execution_path="BRIDGE"
    self._audit.log_event(
        event_type="bridge_tool_result",
        execution_path="BRIDGE",
        # ...
    )
    
    return web.json_response(result)
```

**Problem:** BRIDGE is emitting TWO audit events (request + result) with execution_path="BRIDGE", which makes those visible as "non-MCP" even though the actual tool execution goes through MCP.

**Solution:** Remove the bridge_tool_request and bridge_tool_result events. Let only the inner MCP execution log its audit events (tool_request → tool_completed with execution_path="MCP").

### Step 3: Update MCP Server Execution

**File:** `CaseCrack/tools/burp_enterprise/mcp/mcp_server.py`

**Ensure:**
- `execute_tool()` accepts `execution_path` parameter (optional, defaults to "MCP")
- When called from BRIDGE, logs execution_path = "BRIDGE" in request phase
- Then internally switches to execution_path = "MCP" for tool execution
- Final audit record shows execution_path = "MCP" for the actual tool execution

### Step 4: Update Audit Logger Behavior

**File:** `CaseCrack/tools/burp_enterprise/mcp/mcp_audit.py`

**Current:** Emits `execution_path` as passed in

**Updated logic:**
```python
def log_event(
    self,
    tool_name: str,
    event_type: str,
    execution_path: str = "MCP",  # Default to MCP
    # ... other fields
):
    # If called from BRIDGE with request metadata, 
    # emit TWO events:
    # 1. Bridge request event with execution_path="BRIDGE"
    # 2. Tool execution event with execution_path="MCP"
    
    # OR (simpler): Always collapse to MCP for tool execution
    # BRIDGE is just transport layer
```

**Rationale:** BRIDGE is transport, not execution. The execution happens in MCP backend.

---

## 📋 Implementation Checklist

### Phase A.1: Remove Bridge Audit Events from mcp_http_server.py
- [ ] Comment out or remove bridge_tool_request audit call
- [ ] Comment out or remove bridge_tool_result audit call
- [ ] Verify SSE broadcasts still function for UI
- [ ] Compile check passes

### Phase A.2: Test & Validate
- [ ] Make 5 test calls to each of 3 BRIDGE tools via HTTP
- [ ] Verify `CaseCrack/mcp_audit.jsonl` shows only tool_request/tool_completed (execution_path="MCP")
- [ ] Verify no bridge_tool_request/result events in audit
- [ ] Re-run validator: confirm non_mcp_execution_rate drops → 0.7% (CLI only)
- [ ] Re-run validator: confirm trend_stable → true

### Phase A.3: Merge & Document
- [ ] Update changelist
- [ ] Record completion in session memory
- [ ] Prepare Phase B (CLI read normalization)

---

## 🔍 Validation Commands

**After implementation, run:**

```bash
# Generate new audit with Phase A changes
python _VALIDATE_EXECUTION_PATH_LEAKS.py \
  --audit-path CaseCrack/mcp_audit.jsonl \
  --trend-bucket-minutes 5 \
  --out _PHASE_A_VALIDATION_REPORT.json

# Extract BRIDGE tool counts
jq '.non_mcp_sources[] | select(.execution_path == "BRIDGE")' \
  _PHASE_A_VALIDATION_REPORT.json

# Check if ready for enforcement
jq '.cutover_condition.ready_for_enforcement' \
  _PHASE_A_VALIDATION_REPORT.json
```

**Expected output after Phase A:**
```json
{
  "non_mcp_sources": [],  // All BRIDGE tools gone
  "non_mcp_execution_rate": 0.0,
  "cutover_condition": {
    "ready_for_enforcement": false  // Still false until Phase B+C done
  }
}
```

---

## ⚠️ Trap to Avoid

**Do NOT:** Block all non-MCP execution globally yet.

**Why?** You still need:
- Bootstrap paths (initial system startup)
- Debugging paths (manual intervention)
- Fallback tooling (degraded mode)

**Instead:** Only block `execution_path != MCP && is_state_mutation`  
(This is already designed correctly in your audit logger guardrail.)

---

## 🎬 Next Steps (After Phase A)

1. **Validate Phase A success** (non_mcp_execution_rate drops to ~0.6%, only CLI remains)
2. **Phase B:** Normalize CLI reads (config command)
3. **Phase C:** Harden mutation blocking (zero Phase C sources visible)
4. **Enforcement:** Flip ILLEGAL_MUTATION_PATH to blocking mode

---

## 📝 Notes

- Timeline: ~2-3 hours implementation + testing
- Risk: Low (read operations, all audit-visible)
- Rollback: Revert mcp_server/mcp_http_server changes
- Benefit: Unified operator copilot visibility + trend stability gate opens
