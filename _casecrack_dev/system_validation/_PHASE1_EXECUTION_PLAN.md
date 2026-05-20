# 🚀 Phase 1 Execution Plan — Typed Tools + Policy + Validation

**Objective**: Remove 75% of uncontrolled passthrough surface by hardening 3 core commands  
**Timeline**: 4-6 weeks (2-3 weeks dev + testing, 1 week staging, 1-2 weeks production)  
**Expected Outcome**: 100% of Phase 1 traffic (2,076/2,537 calls) through enforced types/policies  

---

## 📋 What Happens in Phase 1

### Current State (Uncontrolled)
```
run_burp_scan  → passthrough, no validation, accepts any args
list_targets   → passthrough, no validation, accepts any args  
get_report     → passthrough, no validation, accepts any args
```
**Risk**: Argument injection, timeout chaos, quota bypass, no audit trail

### Phase 1 State (Typed + Enforced)
```
run_burp_scan  → strict schema, validated args, policy-enforced limits, audited
list_targets   → strict schema, validated args, policy-enforced limits, audited
get_report     → strict schema, validated args, policy-enforced limits, audited
```
**Benefit**: Controlled surface, full audit, quota enforcement, deterministic behavior

---

## 🔧 Implementation Strategy

### Step 1: Define Typed Tools (Week 1)
**File**: `_phase1_tool_definitions.py`

For each command:
```python
{
  "tool": "run_burp_scan",
  "version": "1.0",
  "description": "Execute security scan with profile-based configuration",
  "params": {
    "target": {
      "type": "string",
      "pattern": "^[a-zA-Z0-9:./\\-]+$",  # hostname, IP, CIDR
      "required": True,
      "validation": "dns_or_ip_or_cidr"
    },
    "scan_profile": {
      "type": "enum",
      "values": ["quick", "balanced", "thorough"],
      "required": True,
      "default": "balanced"
    },
    "timeout_seconds": {
      "type": "int",
      "min": 30,
      "max": 3600,
      "required": False,
      "default": 600
    },
    "output_format": {
      "type": "enum",
      "values": ["json", "xml", "sarif"],
      "required": False,
      "default": "json"
    }
  },
  "policy": {
    "category": "security_scan",
    "roles_allowed": ["user", "admin"],
    "plans_allowed": ["pro", "enterprise"],
    "concurrency_limit": 3,
    "per_tenant_quota": 100,
    "quota_window_hours": 24,
    "requires_mfa": False
  }
}
```

### Step 2: Attach Policy (Week 1)
**File**: `_phase1_tool_definitions.py` (Policy section)

```python
POLICIES = {
  "run_burp_scan": {
    "category": "security_scan",
    "role_access": {
      "admin": ["run", "view_all"],
      "user": ["run"],
      "viewer": []
    },
    "plan_limits": {
      "free": {"calls_per_day": 0},         # Disabled for free tier
      "pro": {"calls_per_day": 50},
      "enterprise": {"calls_per_day": 500}
    },
    "concurrency": 3,
    "timeout_global_seconds": 3600,
    "allowed_tenants": ["*"],              # all tenants can use
    "audit_level": "full"
  },
  "list_targets": {
    "category": "read_only",
    "role_access": {
      "admin": ["run", "view_all"],
      "user": ["run"],
      "viewer": ["run"]
    },
    "plan_limits": {
      "free": {"calls_per_day": 1000},
      "pro": {"calls_per_day": 10000},
      "enterprise": {"calls_per_day": -1}  # unlimited
    },
    "concurrency": 10,
    "timeout_global_seconds": 300,
    "audit_level": "light"
  },
  "get_report": {
    "category": "read_only",
    "role_access": {
      "admin": ["run", "view_all"],
      "user": ["run"],
      "viewer": ["run"]
    },
    "plan_limits": {
      "free": {"calls_per_day": 500},
      "pro": {"calls_per_day": 5000},
      "enterprise": {"calls_per_day": -1}
    },
    "concurrency": 5,
    "timeout_global_seconds": 600,
    "audit_level": "light"
  }
}
```

### Step 3: Add Validation (Week 1-2)
**File**: `_phase1_tool_definitions.py` (Validators section)

```python
class ToolValidator:
  def validate_run_burp_scan(self, params):
    """Validate run_burp_scan parameters"""
    errors = []
    
    # target: must be valid DNS/IP/CIDR
    if not params.get("target"):
      errors.append("target is required")
    elif not self._is_valid_target(params["target"]):
      errors.append(f"target '{params['target']}' is invalid (not DNS/IP/CIDR)")
    
    # scan_profile: must be known enum
    if params.get("scan_profile") not in ["quick", "balanced", "thorough"]:
      errors.append(f"scan_profile must be one of: quick, balanced, thorough")
    
    # timeout_seconds: must be in bounds
    timeout = params.get("timeout_seconds", 600)
    if not isinstance(timeout, int) or timeout < 30 or timeout > 3600:
      errors.append(f"timeout_seconds must be 30-3600, got {timeout}")
    
    # output_format: must be known enum
    if params.get("output_format", "json") not in ["json", "xml", "sarif"]:
      errors.append(f"output_format must be one of: json, xml, sarif")
    
    return {"valid": len(errors) == 0, "errors": errors}
  
  def validate_list_targets(self, params):
    """Validate list_targets parameters"""
    errors = []
    
    # filter_tag: optional, must be string if provided
    if "filter_tag" in params and not isinstance(params["filter_tag"], str):
      errors.append("filter_tag must be a string")
    
    # limit: optional, must be positive int
    if "limit" in params:
      limit = params["limit"]
      if not isinstance(limit, int) or limit <= 0 or limit > 10000:
        errors.append("limit must be positive int, max 10000")
    
    # offset: optional, must be non-negative int
    if "offset" in params:
      offset = params["offset"]
      if not isinstance(offset, int) or offset < 0:
        errors.append("offset must be non-negative int")
    
    return {"valid": len(errors) == 0, "errors": errors}
  
  def validate_get_report(self, params):
    """Validate get_report parameters"""
    errors = []
    
    # report_id: required, must be UUID
    if not params.get("report_id"):
      errors.append("report_id is required")
    elif not self._is_valid_uuid(params["report_id"]):
      errors.append(f"report_id must be UUID format, got {params['report_id']}")
    
    # format: optional enum
    if params.get("format", "json") not in ["json", "pdf", "html"]:
      errors.append("format must be one of: json, pdf, html")
    
    return {"valid": len(errors) == 0, "errors": errors}
```

### Step 4: Shadow-Run Harness (Week 2)
**File**: `_phase1_shadow_runner.py`

Compare passthrough vs. typed output in real-time:
- Route requests to BOTH passthrough and typed implementation
- Log results in parallel
- Compare outputs, flag mismatches
- Track error rates, latencies, behavior drift

```python
class ShadowRunner:
  def __init__(self, mcp_server, metrics):
    self.mcp_server = mcp_server
    self.metrics = metrics
    self.shadow_log = []
  
  async def run_burp_scan_shadow(self, request_id, principal, params):
    """Run both passthrough and typed, compare results"""
    
    # Run passthrough (current implementation)
    pt_start = time.monotonic()
    try:
      pt_result = await self.mcp_server._execute_passthrough_impl(
        "run_burp_scan", params
      )
      pt_latency = time.monotonic() - pt_start
      pt_success = True
      pt_error = None
    except Exception as e:
      pt_latency = time.monotonic() - pt_start
      pt_success = False
      pt_error = str(e)
    
    # Run typed (new implementation)
    typed_start = time.monotonic()
    try:
      typed_result = await self.mcp_server.run_burp_scan_typed(principal, params)
      typed_latency = time.monotonic() - typed_start
      typed_success = True
      typed_error = None
    except Exception as e:
      typed_latency = time.monotonic() - typed_start
      typed_success = False
      typed_error = str(e)
    
    # Compare
    match = self._compare_results(pt_result, typed_result)
    
    # Log
    entry = {
      "timestamp": datetime.now().isoformat(),
      "request_id": request_id,
      "command": "run_burp_scan",
      "params": params,
      "passthrough": {
        "success": pt_success,
        "latency_ms": int(pt_latency * 1000),
        "error": pt_error,
        "result_type": type(pt_result).__name__ if pt_success else None
      },
      "typed": {
        "success": typed_success,
        "latency_ms": int(typed_latency * 1000),
        "error": typed_error,
        "result_type": type(typed_result).__name__ if typed_success else None
      },
      "match": match,
      "divergence": not match
    }
    
    self.shadow_log.append(entry)
    self.metrics.record_shadow_run("run_burp_scan", match, pt_latency, typed_latency)
    
    # Return typed result (new implementation wins)
    # But log divergence for investigation
    if not match:
      logger.warning(f"Shadow divergence in run_burp_scan: {entry}")
    
    return typed_result
```

### Step 5: Migration Phases (Week 3-4)

**Phase 5a: Deployment to Staging**
- Deploy typed tools to staging environment
- Route 100% of traffic through shadow runner
- Collect divergence data for 1 week
- Monitor error rates, latencies, behavior

**Phase 5b: Canary to Production (10% → 50% → 100%)**
- Week 1: 10% of production traffic → typed tools (shadow log all)
- Week 2: 50% of production traffic → typed tools
- Week 3: 100% of production traffic → typed tools
- Maintain shadow logging for 1 week post-100% for final audit

**Phase 5c: Decommission Passthrough**
- After 1 week at 100% typed with zero divergence:
  - Disable passthrough for phase 1 commands
  - Disable shadow runner
  - Archive shadow logs
  - Update documentation

### Step 6: Kill Passthrough (Week 4)
**Implementation**:
```python
# In MCP server policy resolver
PHASE1_COMMANDS_TYPED = {"run_burp_scan", "list_targets", "get_report"}

def _check_passthrough_allowed(self, command, principal):
  """Check if passthrough is allowed for this command"""
  
  # Phase 1 commands are now enforced-typed only
  if command in PHASE1_COMMANDS_TYPED:
    # Raise error if caller tries passthrough
    raise PolicyViolation(
      f"Command '{command}' is no longer available via passthrough. "
      f"Use typed implementation. See mcp_server.{command}_typed()"
    )
  
  # Other commands still allowed via passthrough
  return self._policy_resolver.check_passthrough_allowed(command, principal)
```

---

## 📊 Success Criteria

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Traffic Coverage** | 100% of Phase 1 | via `mcp_metrics.get_passthrough_calls()` |
| **Error Divergence** | 0% | shadow runner logs (no unmatched failures) |
| **Latency Impact** | <20% overhead | typed vs passthrough in shadow logs |
| **Policy Enforcement** | 100% | audit logs show enforced limits applied |
| **Quota Compliance** | 100% | no calls exceed plan limits |
| **Passthrough Disabled** | Yes | CLI logs show rejection of passthrough requests |

---

## 🗓️ Weekly Milestones

| Week | Goal | Deliverable |
|------|------|-------------|
| **Week 1** | Tool definitions + validation | `_phase1_tool_definitions.py` |
| **Week 2** | Shadow runner + staging deploy | `_phase1_shadow_runner.py` + staging logs |
| **Week 3** | Canary to production (10→50→100%) | Production shadow logs, divergence report |
| **Week 4** | Kill passthrough + document | Decommissioning complete, docs updated |

---

## 🚨 Rollback Plan

If divergence detected or errors spike during canary:
1. **Immediate**: Route traffic back to passthrough (panic button)
2. **Investigate**: Review shadow logs for divergence pattern
3. **Fix**: Update typed implementation or validation logic
4. **Re-test**: Run in staging for 3+ days with zero divergence
5. **Restart**: Begin canary again at 10%

---

## 📝 Implementation Checklist

See: `_PHASE1_MIGRATION_CHECKLIST.md`

---

## 🔗 Related Files

- `_phase1_tool_definitions.py` — Tool schemas, policies, validators
- `_phase1_shadow_runner.py` — Shadow-run harness for A/B comparison
- `_PHASE1_MIGRATION_CHECKLIST.md` — Step-by-step tasks
- `_analyze_passthrough_metrics.py` — Data that informed this plan
