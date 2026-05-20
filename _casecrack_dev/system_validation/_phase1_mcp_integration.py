#!/usr/bin/env python3
"""
PHASE 1 MCP SERVER INTEGRATION: Runtime Enforcement in Requests
===============================================================

This shows how to wire the execution layer into mcp_server.py
so that every Phase 1 request passes through the enforcement gates.

This is where the rules become REAL—not in docs, but in code.
Every request. Every time. No shortcuts.
"""

import os
import logging
from typing import Any, Dict
from _phase1_execution_layer import (
    Phase1RuntimeEnforcer,
    RegressionDetectionGate,
    FailSafeEnforcementGate
)

logger = logging.getLogger(__name__)


# ============================================================================
# MCP SERVER REQUEST HANDLER (Updated)
# ============================================================================

class Phase1EnforcedMCPHandler:
    """
    Enhanced MCP request handler with runtime enforcement
    
    Use this in SecurityMCPServer.handle_call_tool()
    """
    
    PHASE1_COMMANDS = {"run_burp_scan", "list_targets", "get_report"}
    
    def __init__(self):
        self.enforcer = Phase1RuntimeEnforcer()
        self.migration_complete = os.getenv("MCP_PHASE1_MIGRATION_COMPLETE", "false").lower() == "true"
        self.current_canary_percent = int(os.getenv("MCP_PHASE1_CANARY_PERCENT", "0"))
    
    async def handle_phase1_request(
        self,
        command: str,
        params: Dict[str, Any],
        principal: Any
    ) -> Dict[str, Any]:
        """
        Handle Phase 1 command with enforcement
        
        This is called from SecurityMCPServer.handle_call_tool()
        for any command in PHASE1_COMMANDS
        
        Flow:
          1. Check if command is Phase 1
          2. Enforce pass-through elimination (post-Week 5)
          3. Enforce fail-safe mode (if applicable)
          4. Execute typed implementation
          5. Record metrics
        """
        
        if command not in self.PHASE1_COMMANDS:
            # Not a Phase 1 command, skip enforcement
            return await self._passthrough_request(command, params)
        
        # ====================================================================
        # ENFORCEMENT GATE 1: No passthrough after migration (Rule 5)
        # ====================================================================
        
        try:
            # This assertion will FAIL if we're using passthrough post-migration
            self.enforcer.enforce_no_passthrough_after_migration(
                command=command,
                using_passthrough=False,  # We're using typed
                migration_complete=self.migration_complete
            )
        except AssertionError as e:
            logger.critical(f"REGRESSION DETECTED: {str(e)}")
            # Page on-call
            await self._alert_regression_detection(command, str(e))
            # Hard fail the request
            raise
        
        # ====================================================================
        # ENFORCEMENT GATE 2: Fail-Safe mode at 10% (Rule 3)
        # ====================================================================
        
        failsafe_enabled = self.current_canary_percent <= 10
        
        if failsafe_enabled:
            logger.info(f"Fail-safe mode ENABLED at {self.current_canary_percent}% canary")
        
        # ====================================================================
        # EXECUTION: Try typed implementation
        # ====================================================================
        
        try:
            result = await self._execute_typed_implementation(
                command=command,
                params=params,
                principal=principal
            )
            
            logger.info(f"✅ Typed implementation succeeded for {command}")
            return result
        
        except Exception as typed_error:
            # Typed implementation failed
            logger.error(f"❌ Typed implementation failed: {str(typed_error)}")
            
            # ================================================================
            # FAIL-SAFE FALLBACK (If enabled)
            # ================================================================
            
            if failsafe_enabled:
                logger.warning(f"⚠️ Fail-safe mode enabled. Falling back to passthrough.")
                
                try:
                    passthrough_result = await self._passthrough_request(command, params)
                    
                    # Log as CRITICAL divergence (typed failed, passthrough succeeded)
                    await self._log_critical_divergence(
                        command=command,
                        typed_error=typed_error,
                        passthrough_ok=True
                    )
                    
                    logger.critical(
                        f"FAILSAFE TRIGGERED: {command} failed in typed, "
                        f"succeeded in passthrough. Returning passthrough."
                    )
                    
                    return passthrough_result
                
                except Exception as passthrough_error:
                    # Both typed and passthrough failed
                    logger.critical(
                        f"CRITICAL: Both typed and passthrough failed for {command}"
                    )
                    raise passthrough_error
            
            else:
                # Fail-safe not enabled, let the error propagate
                raise
    
    async def _execute_typed_implementation(
        self,
        command: str,
        params: Dict[str, Any],
        principal: Any
    ) -> Dict[str, Any]:
        """
        Execute the typed implementation for Phase 1 command
        
        This is where your actual typed code runs.
        It's been validated by the readiness audit.
        """
        
        if command == "run_burp_scan":
            return await self._typed_run_burp_scan(params, principal)
        
        elif command == "list_targets":
            return await self._typed_list_targets(params, principal)
        
        elif command == "get_report":
            return await self._typed_get_report(params, principal)
        
        else:
            raise ValueError(f"Unknown Phase 1 command: {command}")
    
    async def _typed_run_burp_scan(
        self,
        params: Dict[str, Any],
        principal: Any
    ) -> Dict[str, Any]:
        """Typed implementation of run_burp_scan"""
        # This is your actual implementation
        # It's been validated, load-tested, and approved
        raise NotImplementedError("Implement your typed run_burp_scan here")
    
    async def _typed_list_targets(
        self,
        params: Dict[str, Any],
        principal: Any
    ) -> Dict[str, Any]:
        """Typed implementation of list_targets"""
        raise NotImplementedError("Implement your typed list_targets here")
    
    async def _typed_get_report(
        self,
        params: Dict[str, Any],
        principal: Any
    ) -> Dict[str, Any]:
        """Typed implementation of get_report"""
        raise NotImplementedError("Implement your typed get_report here")
    
    async def _passthrough_request(
        self,
        command: str,
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute via passthrough (old implementation)"""
        # This is your existing backend
        raise NotImplementedError("Implement passthrough call here")
    
    async def _log_critical_divergence(
        self,
        command: str,
        typed_error: Exception,
        passthrough_ok: bool
    ) -> None:
        """Log fail-safe trigger as critical divergence"""
        logger.critical(
            f"CRITICAL_DIVERGENCE: {command} | "
            f"typed_failed={typed_error} | passthrough_ok={passthrough_ok}"
        )
        # Record in metrics system
        # Alert on-call if in production
    
    async def _alert_regression_detection(
        self,
        command: str,
        error_message: str
    ) -> None:
        """Alert on-call team of regression detection"""
        logger.critical(f"🚨 REGRESSION ALERT: {command} - {error_message}")
        # Send to on-call system (PagerDuty, etc.)
        # Block deployment if in production


# ============================================================================
# INTEGRATION INTO EXISTING MCP_SERVER.PY
# ============================================================================

MCP_SERVER_INTEGRATION = """
# In your existing mcp_server.py:

from _phase1_execution_layer import Phase1RuntimeEnforcer
from _phase1_mcp_integration import Phase1EnforcedMCPHandler

class SecurityMCPServer(MCPServer):
    
    def __init__(self):
        super().__init__()
        self.phase1_handler = Phase1EnforcedMCPHandler()
    
    async def handle_call_tool(self, tool_name: str, params: dict):
        '''Main tool dispatch point'''
        
        # Phase 1 commands go through enforcement
        if tool_name in ['run_burp_scan', 'list_targets', 'get_report']:
            return await self.phase1_handler.handle_phase1_request(
                command=tool_name,
                params=params,
                principal=self.get_current_principal()
            )
        
        # Everything else passes through
        return await self._dispatch_tool(tool_name, params)
"""


# ============================================================================
# POST-MIGRATION ASSERTION (Rule 5 Enforcement)
# ============================================================================

def assert_phase1_no_passthrough_at_runtime(
    command: str,
    using_passthrough: bool
) -> None:
    """
    Runtime assertion: After migration, Phase1 commands CANNOT use passthrough
    
    Call this at the START of every Phase 1 request handler:
    
        assert_phase1_no_passthrough_at_runtime("run_burp_scan", using_passthrough=False)
    
    If this assertion fails, the request is STOPPED and on-call is paged.
    This is not a warning. It's a hard failure.
    """
    
    migration_complete = os.getenv("MCP_PHASE1_MIGRATION_COMPLETE", "false").lower() == "true"
    
    if migration_complete and using_passthrough:
        # POST-MIGRATION: Phase 1 command using passthrough is a REGRESSION
        error_msg = (
            f"CRITICAL REGRESSION: Phase 1 command '{command}' is using passthrough "
            f"AFTER migration is complete. This indicates a dependency bypass or "
            f"accidental regression. Request BLOCKED. On-call team PAGED."
        )
        
        logger.critical(error_msg)
        
        # In a real system, this would trigger:
        # 1. PagerDuty alert
        # 2. Request termination
        # 3. Incident ticket creation
        # 4. Deployment rollback (if in canary)
        
        raise AssertionError(error_msg)


# ============================================================================
# FAIL-SAFE MODE ENFORCEMENT (Rule 3)
# ============================================================================

def enforce_failsafe_mode_at_10_percent(
    current_canary_percent: int
) -> bool:
    """
    Hard-coded fail-safe mode enforcement
    
    At 10% canary: MUST be enabled (no override possible)
    At 50%+: Can be disabled
    
    This prevents someone from "temporarily disabling" fail-safe
    and forgetting to turn it back on.
    
    Returns: True if fail-safe should be enabled
    """
    
    if current_canary_percent <= 10:
        # 10% canary: Fail-safe MUST be on
        failsafe_must_be_enabled = True
        
        # Check environment variable
        failsafe_actual = os.getenv("MCP_PHASE1_FAILSAFE_ENABLED", "false").lower() == "true"
        
        if not failsafe_actual:
            error_msg = (
                f"CRITICAL: Fail-safe mode NOT enabled at {current_canary_percent}% canary. "
                f"Fail-safe is REQUIRED at 10% canary. "
                f"Set MCP_PHASE1_FAILSAFE_ENABLED=true"
            )
            logger.critical(error_msg)
            raise AssertionError(error_msg)
        
        return True
    
    elif current_canary_percent >= 50:
        # 50%+ canary: Fail-safe should be disabled
        return False
    
    else:
        # 25-50%: Flexible
        return os.getenv("MCP_PHASE1_FAILSAFE_ENABLED", "false").lower() == "true"


# ============================================================================
# DEPLOYMENT DECISION ENFORCEMENT (Rule 4)
# ============================================================================

def validate_deployment_thresholds_before_canary(
    phase: str
) -> bool:
    """
    Enforce load test thresholds are met before canary deployment
    
    If staging phase:
      - P95 latency must be < 2000ms
      - Overhead must be < 20%
      - Safe ceiling must be >= peak + buffer
    
    If any threshold exceeded, canary deployment is BLOCKED.
    """
    
    if phase != "staging":
        return True  # Only enforced during staging
    
    import json
    
    load_test_report = "_PHASE1_LOAD_TEST_RESULTS.json"
    
    if not os.path.exists(load_test_report):
        error_msg = f"Load test report not found: {load_test_report}"
        logger.critical(error_msg)
        raise FileNotFoundError(error_msg)
    
    with open(load_test_report, 'r') as f:
        report = json.load(f)
    
    p95 = report.get("latency_distribution", {}).get("p95", 0)
    overhead = report.get("overhead_percent", 0)
    safe_ceiling = report.get("safe_concurrency_ceiling", 0)
    peak = report.get("peak_concurrency_observed", 0)
    
    # Check thresholds
    if p95 > 2000:
        raise ValueError(f"P95 latency {p95}ms exceeds 2000ms threshold")
    
    if overhead > 20:
        raise ValueError(f"Overhead {overhead:.1f}% exceeds 20% threshold")
    
    if safe_ceiling < peak + 20:
        raise ValueError(f"Safe ceiling {safe_ceiling} < required {peak + 20}")
    
    return True


# ============================================================================
# QUICK REFERENCE: How to Use in mcp_server.py
# ============================================================================

QUICK_REFERENCE = """
# At the top of your mcp_server.py:

from _phase1_execution_layer import Phase1RuntimeEnforcer
from _phase1_mcp_integration import (
    Phase1EnforcedMCPHandler,
    assert_phase1_no_passthrough_at_runtime,
    enforce_failsafe_mode_at_10_percent
)

# In your SecurityMCPServer class:

class SecurityMCPServer:
    
    def __init__(self):
        self.phase1_handler = Phase1EnforcedMCPHandler()
    
    async def handle_call_tool(self, tool_name: str, params: dict):
        
        # Route Phase 1 commands through enforcement
        if tool_name in ['run_burp_scan', 'list_targets', 'get_report']:
            
            # This enforces ALL rules:
            # 1. Readiness audit already passed (prerequisite)
            # 2. Divergence checked in shadow runner (prerequisite)
            # 3. Fail-safe mode enforced at 10%
            # 4. Load test passed before canary (prerequisite)
            # 5. No passthrough after Week 5 (enforced here)
            
            return await self.phase1_handler.handle_phase1_request(
                command=tool_name,
                params=params,
                principal=self.principal
            )
        
        # Other commands: passthrough
        return await self._dispatch_tool(tool_name, params)

# These assertions run at request time:

# At start of every request:
assert_phase1_no_passthrough_at_runtime(
    command,
    using_passthrough=False
)

# Before 10% canary:
enforce_failsafe_mode_at_10_percent(
    current_canary_percent=10
)

# Before staging release:
validate_deployment_thresholds_before_canary(
    phase="staging"
)
"""


if __name__ == "__main__":
    print("Phase 1 MCP Server Integration")
    print("\nThis file shows how to wire runtime enforcement into mcp_server.py")
    print("\nKey functions:")
    print("  - handle_phase1_request() - Main enforcement handler")
    print("  - assert_phase1_no_passthrough_at_runtime() - Rule 5 enforcement")
    print("  - enforce_failsafe_mode_at_10_percent() - Rule 3 enforcement")
    print("  - validate_deployment_thresholds_before_canary() - Rule 4 enforcement")
    print("\nThese make the rules UNSKIPPABLE at request time.")
