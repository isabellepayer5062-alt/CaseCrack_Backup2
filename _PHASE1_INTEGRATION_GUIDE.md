# 🔌 Phase 1 Integration Guide

**Quick Reference**: How to wire Phase 1 tool definitions, validation, and shadow runner into MCP server

---

## File Organization

```
mcp_server/
├── mcp_server.py                          # Main server
├── mcp_auth.py                            # Authentication
├── mcp_config.py                          # Configuration
├── mcp_metrics.py                         # Metrics collection
│
├── _phase1_tool_definitions.py            # Tool schemas + validators + policy
├── _phase1_shadow_runner.py               # A/B comparison harness
│
├── _PHASE1_EXECUTION_PLAN.md              # Strategic overview
├── _PHASE1_MIGRATION_CHECKLIST.md         # Week-by-week tasks
└── _PHASE1_INTEGRATION_GUIDE.md           # This file
```

---

## Step 1: Import Tool Definitions & Validators

**File**: `mcp_server.py`

```python
# At top of file
from _phase1_tool_definitions import (
    ToolDefinitions,
    ToolValidator,
    PolicyEnforcer
)
from _phase1_shadow_runner import ShadowRunner

# In SecurityMCPServer.__init__()
class SecurityMCPServer:
    def __init__(self, config, authenticator, policy_resolver, metrics):
        # ... existing init code ...
        
        # Phase 1 enforcement
        self.tool_definitions = ToolDefinitions()
        self.tool_validator = ToolValidator()
        self.policy_enforcer = PolicyEnforcer(policy_resolver, metrics)
        
        # Phase 1 shadow runner (for A/B testing during migration)
        shadow_level = os.getenv("MCP_PHASE1_SHADOW_LEVEL", "off")  # off, light, full
        self.shadow_runner = ShadowRunner(
            mcp_server=self,
            metrics=metrics,
            shadow_level=shadow_level,
            max_log_entries=10000
        )
```

---

## Step 2: Implement Typed Tool Methods

**File**: `mcp_server.py`

Add these methods to `SecurityMCPServer` class:

```python
# =============================================================================
# Phase 1: Typed Tool Implementations
# =============================================================================

async def run_burp_scan_typed(
    self,
    principal: MCPPrincipal,
    params: Dict[str, Any]
) -> Dict[str, Any]:
    """Execute run_burp_scan with strict validation and policy enforcement"""
    
    # 1. Validate parameters
    validation = self.tool_validator.validate_run_burp_scan(params)
    if not validation['valid']:
        return {
            "error": "validation_failed",
            "errors": validation['errors']
        }
    
    # 2. Check policy (role, plan, quota, concurrency)
    policy_check = self.policy_enforcer.check_run_burp_scan(principal, params)
    if not policy_check['allowed']:
        # Audit log the rejection
        self._audit_log({
            "action": "run_burp_scan_denied",
            "reason": policy_check['reason'],
            "principal": principal.principal_id,
            "tenant_id": principal.tenant_id
        })
        return {
            "error": "policy_violation",
            "reason": policy_check['reason']
        }
    
    # 3. Execute (with timeout enforcement)
    timeout = params.get("timeout_seconds", 600)
    try:
        result = await asyncio.wait_for(
            self._execute_run_burp_scan_impl(principal, params),
            timeout=timeout
        )
        
        # 4. Audit log success
        self._audit_log({
            "action": "run_burp_scan_executed",
            "principal": principal.principal_id,
            "tenant_id": principal.tenant_id,
            "target": params.get("target"),
            "scan_profile": params.get("scan_profile")
        })
        
        return result
    
    except asyncio.TimeoutError:
        return {
            "error": "timeout",
            "timeout_seconds": timeout
        }
    except Exception as e:
        logger.exception(f"run_burp_scan failed: {e}")
        return {
            "error": "execution_failed",
            "message": str(e)
        }

async def list_targets_typed(
    self,
    principal: MCPPrincipal,
    params: Dict[str, Any]
) -> Dict[str, Any]:
    """Execute list_targets with strict validation"""
    
    # 1. Validate
    validation = self.tool_validator.validate_list_targets(params)
    if not validation['valid']:
        return {
            "error": "validation_failed",
            "errors": validation['errors']
        }
    
    # 2. Check policy
    policy_check = self.policy_enforcer.check_list_targets(principal, params)
    if not policy_check['allowed']:
        self._audit_log({
            "action": "list_targets_denied",
            "reason": policy_check['reason'],
            "principal": principal.principal_id
        })
        return {
            "error": "policy_violation",
            "reason": policy_check['reason']
        }
    
    # 3. Execute
    try:
        timeout = 300  # 5 minutes max
        result = await asyncio.wait_for(
            self._execute_list_targets_impl(principal, params),
            timeout=timeout
        )
        
        self._audit_log({
            "action": "list_targets_executed",
            "principal": principal.principal_id,
            "tenant_id": principal.tenant_id,
            "limit": params.get("limit", 100),
            "offset": params.get("offset", 0)
        })
        
        return result
    except Exception as e:
        logger.exception(f"list_targets failed: {e}")
        return {
            "error": "execution_failed",
            "message": str(e)
        }

async def get_report_typed(
    self,
    principal: MCPPrincipal,
    params: Dict[str, Any]
) -> Dict[str, Any]:
    """Execute get_report with strict validation"""
    
    # 1. Validate
    validation = self.tool_validator.validate_get_report(params)
    if not validation['valid']:
        return {
            "error": "validation_failed",
            "errors": validation['errors']
        }
    
    # 2. Check policy
    policy_check = self.policy_enforcer.check_get_report(principal, params)
    if not policy_check['allowed']:
        self._audit_log({
            "action": "get_report_denied",
            "reason": policy_check['reason'],
            "principal": principal.principal_id
        })
        return {
            "error": "policy_violation",
            "reason": policy_check['reason']
        }
    
    # 3. Execute
    try:
        timeout = 600  # 10 minutes max
        result = await asyncio.wait_for(
            self._execute_get_report_impl(principal, params),
            timeout=timeout
        )
        
        self._audit_log({
            "action": "get_report_executed",
            "principal": principal.principal_id,
            "tenant_id": principal.tenant_id,
            "report_id": params.get("report_id")
        })
        
        return result
    except Exception as e:
        logger.exception(f"get_report failed: {e}")
        return {
            "error": "execution_failed",
            "message": str(e)
        }

# Placeholder implementations (replace with actual logic)
async def _execute_run_burp_scan_impl(self, principal, params):
    """Actual Burp scan execution"""
    # TODO: Implement actual Burp API call
    return {"status": "queued", "scan_id": "scan-123"}

async def _execute_list_targets_impl(self, principal, params):
    """Actual target listing"""
    # TODO: Query database
    return {"targets": [], "count": 0}

async def _execute_get_report_impl(self, principal, params):
    """Actual report retrieval"""
    # TODO: Query database
    return {"report": None}
```

---

## Step 3: Route Phase 1 Requests Through Shadow Runner

**File**: `mcp_server.py`

Update the request dispatch logic:

```python
async def execute_tool(
    self,
    principal: MCPPrincipal,
    command: str,
    params: Dict[str, Any],
    request_id: str
) -> Dict[str, Any]:
    """Execute a tool command"""
    
    # Phase 1 commands: Shadow run (A/B test) or typed-only
    PHASE1_COMMANDS = {
        "run_burp_scan",
        "list_targets",
        "get_report"
    }
    
    if command in PHASE1_COMMANDS:
        # If shadow runner enabled, use it for A/B testing
        if self.shadow_runner.shadow_level != "off":
            if command == "run_burp_scan":
                return await self.shadow_runner.run_burp_scan_shadow(
                    request_id, principal, params
                )
            elif command == "list_targets":
                return await self.shadow_runner.list_targets_shadow(
                    request_id, principal, params
                )
            elif command == "get_report":
                return await self.shadow_runner.get_report_shadow(
                    request_id, principal, params
                )
        else:
            # Shadow runner disabled: Use typed implementation directly
            if command == "run_burp_scan":
                return await self.run_burp_scan_typed(principal, params)
            elif command == "list_targets":
                return await self.list_targets_typed(principal, params)
            elif command == "get_report":
                return await self.get_report_typed(principal, params)
    
    # Other commands: Still use passthrough for now (Phase 2/3)
    # But check if passthrough is allowed
    if not self._check_passthrough_allowed(command, principal):
        raise PolicyViolation(f"Passthrough not allowed for {command}")
    
    return await self._execute_passthrough(principal, command, params)

def _check_passthrough_allowed(self, command: str, principal: MCPPrincipal) -> bool:
    """Check if passthrough is allowed for this command"""
    
    PHASE1_COMMANDS = {"run_burp_scan", "list_targets", "get_report"}
    
    # Phase 1 commands are no longer available via passthrough
    if command in PHASE1_COMMANDS:
        raise PolicyViolation(
            f"Command '{command}' is no longer available via passthrough. "
            f"Use typed implementation."
        )
    
    # Other commands still allowed
    return True
```

---

## Step 4: Enable Shadow Runner Via Environment Variable

**File**: `.env` or deployment config

```bash
# Shadow runner level during migration
# off     = Typed implementation only (after migration complete)
# light   = Log divergences only (production canary)
# full    = Log all runs for comparison (staging testing)
MCP_PHASE1_SHADOW_LEVEL=off

# Or during canary:
MCP_PHASE1_SHADOW_LEVEL=light
```

---

## Step 5: Add Health Check Endpoint for Shadow Status

**File**: `mcp_http_server.py` (or health check module)

```python
@app.get("/mcp/health/phase1-shadow")
async def phase1_shadow_health():
    """Health check for Phase 1 shadow runner status"""
    
    readiness = mcp_server.shadow_runner.generate_readiness_report()
    
    return {
        "shadow_level": mcp_server.shadow_runner.shadow_level,
        "commands": readiness["commands"],
        "overall_readiness": readiness["overall_readiness"],
        "shadow_log_size": readiness["shadow_log_size"],
        "divergence_log_size": readiness["divergence_log_size"],
        "recommendations": readiness["recommendations"]
    }
```

---

## Step 6: Add Monitoring & Alerting

**File**: `mcp_metrics.py` or monitoring module

```python
def record_shadow_run(
    self,
    command: str,
    match: bool,
    pt_latency: float,
    typed_latency: float
):
    """Record shadow run for monitoring"""
    
    # Track shadow runs per command
    self._shadow_runs_total[(command)] = self._shadow_runs_total.get(command, 0) + 1
    
    # Track divergences
    if not match:
        self._shadow_divergences_total[(command)] = \
            self._shadow_divergences_total.get(command, 0) + 1
    
    # Track latency overhead
    overhead = typed_latency - pt_latency
    self._shadow_latency_overhead[(command)].append(overhead)
    
    # Alert if divergence rate > threshold
    total = self._shadow_runs_total[command]
    diverged = self._shadow_divergences_total.get(command, 0)
    rate = diverged / total if total > 0 else 0
    
    if rate > 0.05:  # >5% divergence
        logger.error(
            f"ALERT: {command} divergence rate {rate*100:.1f}% exceeds threshold"
        )
```

---

## Step 7: Test Integration

**File**: `test_phase1_integration.py` (create new)

```python
import asyncio
from unittest.mock import Mock
from mcp_server import SecurityMCPServer
from mcp_auth import MCPPrincipal

async def test_phase1_integration():
    """Test Phase 1 tool definitions, validation, and policy enforcement"""
    
    # Mock dependencies
    config = Mock()
    auth = Mock()
    policy_resolver = Mock()
    metrics = Mock()
    
    server = SecurityMCPServer(config, auth, policy_resolver, metrics)
    
    # Create test principal
    principal = MCPPrincipal(
        principal_id="user-123",
        tenant_id="tenant-456",
        claims={
            "role": "user",
            "plan_id": "pro"
        }
    )
    
    # Test 1: Valid run_burp_scan
    result = await server.run_burp_scan_typed(principal, {
        "target": "example.com",
        "scan_profile": "balanced"
    })
    assert "error" not in result, f"Unexpected error: {result}"
    print("✓ Valid run_burp_scan passed")
    
    # Test 2: Invalid run_burp_scan (bad target)
    result = await server.run_burp_scan_typed(principal, {
        "target": "!!!invalid!!!",
        "scan_profile": "balanced"
    })
    assert result.get("error") == "validation_failed", "Expected validation failure"
    print("✓ Invalid run_burp_scan rejected")
    
    # Test 3: Valid list_targets
    result = await server.list_targets_typed(principal, {
        "limit": 100
    })
    assert "error" not in result, f"Unexpected error: {result}"
    print("✓ Valid list_targets passed")
    
    # Test 4: Valid get_report
    result = await server.get_report_typed(principal, {
        "report_id": "550e8400-e29b-41d4-a716-446655440000"
    })
    assert "error" not in result, f"Unexpected error: {result}"
    print("✓ Valid get_report passed")
    
    print("\n✅ All Phase 1 integration tests passed!")

if __name__ == "__main__":
    asyncio.run(test_phase1_integration())
```

Run:
```bash
python test_phase1_integration.py
```

---

## Deployment Checklist

Before deploying Phase 1:

- [ ] All typed implementations wired into mcp_server.py
- [ ] Shadow runner initialized and logging working
- [ ] Test suite passes (test_phase1_integration.py)
- [ ] Staging environment has shadow_level="full"
- [ ] Production environment has shadow_level="off" (initially)
- [ ] Monitoring alerts configured
- [ ] On-call playbook updated
- [ ] Team trained on new API (schema, validation, policies)
- [ ] Documentation updated (API migration guide, FAQ)

---

## Quick Debugging

### Check Tool Definitions
```bash
python -c "
from _phase1_tool_definitions import ToolDefinitions
import json
defs = ToolDefinitions()
print(json.dumps(defs.get_run_burp_scan(), indent=2))
"
```

### Test Validator
```bash
python -c "
from _phase1_tool_definitions import ToolValidator
v = ToolValidator()
print('Valid:', v.validate_run_burp_scan({'target': 'example.com', 'scan_profile': 'balanced'}))
print('Invalid:', v.validate_run_burp_scan({'target': '!!!', 'scan_profile': 'bad'}))
"
```

### Test Shadow Runner
```bash
python _phase1_shadow_runner.py
```

### Check Readiness
```bash
python -c "
from mcp_server import SecurityMCPServer
# Get server instance
report = server.shadow_runner.generate_readiness_report()
import json
print(json.dumps(report, indent=2))
"
```

---

## Next Steps

1. **Week 1**: Implement typed methods in mcp_server.py
2. **Week 2**: Wire shadow runner into request dispatch
3. **Week 3**: Deploy to staging with shadow_level="full"
4. **Week 4**: Production canary (10% → 50% → 100%)
5. **Week 5**: Kill passthrough, decommission shadow runner
6. **Week 6**: Monitor and celebrate Phase 1 complete! 🎉

---

**Questions?** Refer to:
- `_PHASE1_EXECUTION_PLAN.md` — Strategy & approach
- `_PHASE1_MIGRATION_CHECKLIST.md` — Week-by-week tasks
- `_phase1_tool_definitions.py` — Schema & policy docs
- `_phase1_shadow_runner.py` — Shadow runner implementation
