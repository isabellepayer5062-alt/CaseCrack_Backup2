#!/usr/bin/env python3
"""
Phase 1 Integration & Deployment Guide (Complete)
==================================================

This is THE DEFINITIVE guide for wiring Phase 1 safety infrastructure
into mcp_server.py and deploying safely to production.

QUICK START:
1. Review this entire file for context
2. Copy code snippets into mcp_server.py
3. Set MCP_PHASE1_SHADOW_LEVEL environment variable
4. Run Week 3 staging test
5. Follow 3-stage canary (Week 4)

FILE STRUCTURE:
1. Initialization (Module init + imports)
2. Request dispatch routing (In mcp_server request handler)
3. Typed method implementations (New methods for Phase 1)
4. Instrumentation (Metrics + logging)
5. Emergency procedures (Disable typed, revert to passthrough)

================================================================================
PART 1: INITIALIZATION
================================================================================

Add to mcp_server.py top-level initialization:

```python
# Import Phase 1 safety infrastructure
from _phase1_tool_definitions import ToolDefinitions, ToolValidator, PolicyEnforcer
from _phase1_shadow_runner import ShadowRunner
from _phase1_divergence_detection import DivergenceDetector
from _phase1_safety_upgrades import (
    FailSafeMode, MigrationMetrics, RegressionDetector, 
    ToolVersionRegistry, DependencyTracer
)
from _phase1_load_test import LoadTestHarness

import os

# Initialize Phase 1 components
class Phase1Infrastructure:
    def __init__(self):
        self.tool_defs = ToolDefinitions()
        self.validator = ToolValidator()
        self.policy_enforcer = PolicyEnforcer()
        self.shadow_runner = ShadowRunner()
        self.divergence_detector = DivergenceDetector()
        self.failsafe = FailSafeMode(enabled=False)  # Disabled by default
        self.metrics = MigrationMetrics()
        self.regression_detector = RegressionDetector()
        self.tool_registry = ToolVersionRegistry()
        self.dependency_tracer = DependencyTracer()
        self.load_tester = LoadTestHarness(self)
        
        # Shadow level controls tracing
        # Values: "off" (no shadow), "soft" (compare, passthrough wins), 
        #         "full" (compare, typed wins but log divergences), "strict" (typed only)
        self.shadow_level = os.getenv("MCP_PHASE1_SHADOW_LEVEL", "off")
        
        # Tool versioning
        self._register_tool_versions()
    
    def _register_tool_versions(self):
        """Register all Phase 1 tool versions"""
        self.tool_registry.register_tool(
            "run_burp_scan", "v1", "hash_run_burp_scan_v1", []
        )
        self.tool_registry.register_tool(
            "list_targets", "v1", "hash_list_targets_v1", []
        )
        self.tool_registry.register_tool(
            "get_report", "v1", "hash_get_report_v1", []
        )

# Create global instance
phase1 = Phase1Infrastructure()
```

================================================================================
PART 2: REQUEST DISPATCH ROUTING
================================================================================

In the mcp_server request handler (where you dispatch to tool handlers),
add this routing logic:

```python
async def handle_mcp_request(request):
    \"\"\"Main MCP request handler with Phase 1 routing\"\"\"
    
    command = request.get("command")
    params = request.get("params", {})
    principal = request.get("principal")  # User/role info
    request_id = request.get("request_id")
    
    # Phase 1 commands get special treatment
    phase1_commands = {"run_burp_scan", "list_targets", "get_report"}
    
    if command in phase1_commands:
        return await handle_phase1_request(
            command, params, principal, request_id
        )
    
    # Phase 2/3 commands use passthrough (for now)
    return await handle_passthrough_request(command, params)


async def handle_phase1_request(command, params, principal, request_id):
    \"\"\"
    Handle Phase 1 commands with shadow runner and safety
    
    Flow:
    1. Validate parameters (strict)
    2. Check policy (role/quota/concurrency)
    3. Route based on shadow_level:
       - "off": Use passthrough (legacy)
       - "soft": Run shadow, return passthrough result
       - "full": Run shadow, return typed result
       - "strict": Run typed only, no fallback
    4. Record metrics and detect regressions
    \"\"\"
    
    try:
        # Step 1: Validate
        validation_result = phase1.validator.validate(command, params)
        if not validation_result['valid']:
            return {
                "error": "VALIDATION_ERROR",
                "details": validation_result['errors']
            }
        
        # Step 2: Check policy
        principal_obj = {"user": principal, "role": "admin"}  # Simplified
        policy_result = phase1.policy_enforcer.check(command, principal_obj)
        if not policy_result['allowed']:
            return {
                "error": "POLICY_ERROR",
                "reason": policy_result['reason']
            }
        
        # Step 3: Route based on shadow level
        if phase1.shadow_level == "off":
            # Pure passthrough (legacy)
            phase1.metrics.record_passthrough_call(command)
            phase1.regression_detector.check_regression(command, 
                                                       {"request_id": request_id})
            return await execute_passthrough(command, params)
        
        elif phase1.shadow_level == "soft":
            # Shadow: passthrough wins, typed result logged
            result = await phase1.shadow_runner.run_shadow(
                request_id, command, params, principal_obj
            )
            # ShadowRunner returns passthrough result by default in soft mode
            phase1.metrics.record_passthrough_call(command)
            return result
        
        elif phase1.shadow_level == "full":
            # Shadow: typed wins, all divergences logged
            result = await phase1.shadow_runner.run_shadow(
                request_id, command, params, principal_obj
            )
            # ShadowRunner returns typed result by default in full mode
            phase1.metrics.record_typed_call(command)
            return result
        
        elif phase1.shadow_level == "strict":
            # Typed only: no passthrough fallback
            try:
                result = await execute_typed(command, params, principal_obj)
                phase1.metrics.record_typed_call(command)
                return result
            
            except Exception as e:
                # In strict mode, typed failures are failures
                if phase1.failsafe.should_use_failsafe(command):
                    # Attempt passthrough fallback
                    try:
                        fallback = await execute_passthrough(command, params)
                        phase1.failsafe.log_critical_divergence(
                            command, e, passthrough_ok=True
                        )
                        phase1.metrics.record_failsafe_triggered(command)
                        return fallback
                    except:
                        # Passthrough also failed
                        raise e
                raise
    
    except Exception as e:
        logger.error(f"Phase 1 error ({command}): {e}")
        return {
            "error": "INTERNAL_ERROR",
            "command": command,
            "request_id": request_id
        }


async def execute_passthrough(command, params):
    \"\"\"Execute command via old passthrough system\"\"\"
    # Call your existing passthrough implementation
    # For now, placeholder
    logger.info(f"Passthrough: {command}")
    return {"status": "ok", "implementation": "passthrough"}


async def execute_typed(command, params, principal):
    \"\"\"Execute command via new typed implementation\"\"\"
    
    if command == "run_burp_scan":
        return await execute_run_burp_scan_typed(params, principal)
    elif command == "list_targets":
        return await execute_list_targets_typed(params, principal)
    elif command == "get_report":
        return await execute_get_report_typed(params, principal)
    else:
        raise ValueError(f"Unknown Phase 1 command: {command}")
```

================================================================================
PART 3: TYPED METHOD IMPLEMENTATIONS
================================================================================

Add these new methods to mcp_server.py:

```python
async def execute_run_burp_scan_typed(params, principal):
    \"\"\"
    Typed implementation of run_burp_scan
    
    Input validation: STRICT
    Policy enforcement: Applied
    \"\"\"
    
    target = params.get("target")
    scan_profile = params.get("scan_profile", "standard")
    timeout_seconds = params.get("timeout_seconds", 300)
    output_format = params.get("output_format", "json")
    
    # All validation already done before this point
    # But do it again here for safety (defense in depth)
    if not target or len(target) > 255:
        raise ValueError("Invalid target")
    
    if scan_profile not in ["quick", "standard", "thorough"]:
        raise ValueError("Invalid scan_profile")
    
    if not 30 <= timeout_seconds <= 3600:
        raise ValueError("Invalid timeout_seconds")
    
    # Call actual Burp integration
    # This is where YOUR actual scan logic goes
    try:
        # Example: scan_result = await burp_client.run_scan(
        #     target=target,
        #     profile=scan_profile,
        #     timeout=timeout_seconds
        # )
        
        # For now, mock
        scan_result = {
            "scan_id": f"scan_{int(time.time())}",
            "target": target,
            "profile": scan_profile,
            "status": "queued",
            "estimated_time_seconds": 180
        }
        
        logger.info(f"Typed scan started: {scan_result['scan_id']} on {target}")
        return scan_result
    
    except Exception as e:
        logger.error(f"Typed scan failed: {e}")
        raise


async def execute_list_targets_typed(params, principal):
    \"\"\"
    Typed implementation of list_targets
    
    Supports filtering and pagination
    \"\"\"
    
    filter_tag = params.get("filter_tag")
    limit = params.get("limit", 100)
    offset = params.get("offset", 0)
    
    # Validate
    if not 1 <= limit <= 10000:
        raise ValueError("Limit must be 1-10000")
    if offset < 0:
        raise ValueError("Offset cannot be negative")
    
    # Query targets from your backend
    # Example: targets = await db.list_targets(tag=filter_tag, limit=limit, offset=offset)
    
    # For now, mock
    targets = [
        {"id": f"target_{i}", "name": f"example{i}.com", "tags": [filter_tag or "default"]}
        for i in range(offset, min(offset + limit, offset + 10))
    ]
    
    logger.info(f"Typed list_targets: {len(targets)} targets")
    return {
        "targets": targets,
        "count": len(targets),
        "limit": limit,
        "offset": offset,
        "total": 500  # Mock total
    }


async def execute_get_report_typed(params, principal):
    \"\"\"
    Typed implementation of get_report
    
    Retrieves previously generated scan report
    \"\"\"
    
    report_id = params.get("report_id")
    format_type = params.get("format", "json")
    
    # Validate
    import uuid as uuid_lib
    try:
        uuid_lib.UUID(report_id)
    except:
        raise ValueError("Invalid report_id format (must be UUID)")
    
    if format_type not in ["json", "html", "pdf"]:
        raise ValueError("Invalid format")
    
    # Query report from backend
    # Example: report = await db.get_report(report_id)
    
    # For now, mock
    report = {
        "report_id": report_id,
        "created_at": "2024-01-15T10:30:00Z",
        "findings_count": 7,
        "severity_distribution": {
            "critical": 1,
            "high": 3,
            "medium": 3,
            "low": 0,
            "info": 0
        }
    }
    
    logger.info(f"Typed get_report: {report_id}")
    return report
```

================================================================================
PART 4: INSTRUMENTATION & MONITORING
================================================================================

Add monitoring endpoints:

```python
async def get_phase1_metrics():
    \"\"\"Get Phase 1 migration metrics\"\"\"
    return {
        "progress": phase1.metrics.get_migration_progress(),
        "failsafe_triggers": phase1.failsafe.get_critical_divergences(),
        "regressions": phase1.regression_detector.get_regressions(),
        "shadow_level": phase1.shadow_level
    }


async def get_phase1_status():
    \"\"\"Get Phase 1 health status\"\"\"
    progress = phase1.metrics.get_migration_progress()
    
    status = "UNKNOWN"
    if phase1.shadow_level == "off":
        status = "PRE_DEPLOYMENT"
    elif phase1.shadow_level == "soft":
        status = "CANARY_10"
    elif phase1.shadow_level == "full":
        if progress['typed_percentage'] < 50:
            status = "CANARY_25"
        elif progress['typed_percentage'] < 100:
            status = "CANARY_50_TO_100"
        else:
            status = "CANARY_100"
    elif phase1.shadow_level == "strict":
        if phase1.metrics.check_migration_complete():
            status = "PRODUCTION"
        else:
            status = "ROLLING_BACK"
    
    return {
        "status": status,
        "progress": progress,
        "failsafe_enabled": phase1.failsafe.enabled,
        "shadow_level": phase1.shadow_level
    }
```

================================================================================
PART 5: EMERGENCY PROCEDURES
================================================================================

Add these emergency commands:

```python
async def emergency_disable_typed():
    \"\"\"
    EMERGENCY: Disable typed implementations, revert to pure passthrough
    
    Use only if:
    - Typed implementations causing widespread failures
    - Unable to fix bugs in time
    - Production impact severe
    \"\"\"
    
    logger.critical("EMERGENCY: Disabling typed implementations")
    phase1.shadow_level = "off"
    phase1.failsafe.enabled = False
    
    # Force all Phase 1 requests through passthrough
    # Metrics will show regression (passthrough calls increasing)
    
    return {
        "status": "TYPED_DISABLED",
        "shadow_level": "off",
        "action": "All Phase 1 requests now use passthrough"
    }


async def emergency_enable_failsafe():
    \"\"\"
    EMERGENCY: Enable fail-safe fallback during production incident
    
    If typed starts failing frequently:
    1. Enable failsafe (typed fails -> use passthrough)
    2. Alert on-call team
    3. Investigate typed failure root cause
    4. Either fix bugs or disable typed
    \"\"\"
    
    logger.critical("EMERGENCY: Enabling fail-safe fallback")
    phase1.failsafe.enabled = True
    
    return {
        "status": "FAILSAFE_ENABLED",
        "action": "Typed failures will fallback to passthrough",
        "alert": "Check Phase 1 team Slack for root cause investigation"
    }


async def disable_shadow_runner():
    \"\"\"
    Disable shadow runner to reduce overhead
    
    Call this after migration complete and confidence high (1+ weeks at 100%)
    \"\"\"
    
    logger.info("Disabling shadow runner")
    phase1.shadow_runner.enabled = False
    phase1.shadow_level = "strict"
    
    # Mark regression detector as active
    phase1.regression_detector.mark_migration_complete()
    
    return {
        "status": "SHADOW_DISABLED",
        "action": "Production now running typed only",
        "regression_detection": "ACTIVE"
    }
```

================================================================================
PART 6: TESTING IN STAGING (WEEK 3)
================================================================================

Run this comprehensive test before canary:

```python
async def week3_staging_test():
    \"\"\"
    Full Week 3 staging test before production canary
    
    Requirements:
    - 7 days of shadow testing at full concurrency
    - 100+ runs per command minimum
    - Match rate ≥99%
    - Zero unresolved divergences
    - Latency overhead <20%
    - Load test at peak concurrency passes
    \"\"\"
    
    results = {}
    
    # 1. Load test
    logger.info("Running load test...")
    load_report = await phase1.load_tester.run_load_test(
        "run_burp_scan",
        concurrency_levels=[10, 25, 50, 100],
        requests_per_level=100
    )
    results['load_test'] = load_report.to_dict()
    
    # 2. Check shadow runner readiness
    logger.info("Analyzing shadow runner results...")
    readiness = phase1.shadow_runner.generate_readiness_report()
    results['shadow_readiness'] = readiness
    
    # 3. Check divergences
    logger.info("Analyzing divergences...")
    divergences = phase1.shadow_runner.get_divergence_summary()
    results['divergences'] = {
        'total': len(divergences),
        'by_type': {}
    }
    for div in divergences:
        div_type = div.get('classification', 'UNKNOWN')
        if div_type not in results['divergences']['by_type']:
            results['divergences']['by_type'][div_type] = 0
        results['divergences']['by_type'][div_type] += 1
    
    # 4. Verify dependencies traced
    logger.info("Checking Phase 1 dependencies...")
    deps = phase1.dependency_tracer.find_phase1_dependencies()
    results['dependencies'] = deps
    
    # 5. Final verdict
    can_proceed = (
        load_report.safe_concurrency_ceiling >= 100 and
        readiness['overall_ready'] and
        results['divergences']['total'] == 0
    )
    
    results['verdict'] = "READY_FOR_CANARY" if can_proceed else "NOT_READY"
    
    logger.info(f"Week 3 Test Result: {results['verdict']}")
    
    return results
```

================================================================================
ENVIRONMENT VARIABLE REFERENCE
================================================================================

Set during deployment:

```bash
# During development (Week 0-2)
export MCP_PHASE1_SHADOW_LEVEL="off"

# During staging (Week 3)
export MCP_PHASE1_SHADOW_LEVEL="full"

# During canary 10% (Week 4, Days 1-3)
export MCP_PHASE1_SHADOW_LEVEL="soft"

# During canary 50% (Week 4, Days 4-6)
export MCP_PHASE1_SHADOW_LEVEL="soft"

# During canary 100% (Week 4, Days 7+)
export MCP_PHASE1_SHADOW_LEVEL="full"

# After confidence is high (Week 5+, disable shadow)
export MCP_PHASE1_SHADOW_LEVEL="strict"
```

================================================================================
DEPLOYMENT COMMANDS
================================================================================

# Week 1 checklist
python _phase1_tool_definitions.py  # Verify tool defs
python _phase1_divergence_detection.py  # Verify divergence detection

# Week 2 checklist
# (Actual implementation in mcp_server.py)

# Week 3 staging test
python -c "import asyncio; from mcp_server import week3_staging_test; asyncio.run(week3_staging_test())"

# Week 4 canary deployment (use k8s or your deployment tool)
kubectl set env deployment/mcp-server MCP_PHASE1_SHADOW_LEVEL=soft

# Week 5 finalization
python -c "import asyncio; from mcp_server import disable_shadow_runner; asyncio.run(disable_shadow_runner())"

# Emergency: Disable typed
python -c "import asyncio; from mcp_server import emergency_disable_typed; asyncio.run(emergency_disable_typed())"
"""

# Note: This file is documentation/reference
# Copy code snippets from above into your mcp_server.py
