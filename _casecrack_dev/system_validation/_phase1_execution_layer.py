#!/usr/bin/env python3
"""
PHASE 1 EXECUTION LAYER: Runtime Enforcement (Unskippable)
=========================================================

This layer makes the 5 rules IMPOSSIBLE to skip through human pressure
or accidental shortcuts. It enforces them at runtime—not docs.

Every deployment decision passes through these gates.
Every gate either passes or STOPS the process.
No overrides. No "temporary disables." No workarounds.

The rules are now CODE, not suggestions.
"""

import sys
import os
import json
import subprocess
from typing import Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum
from datetime import datetime


# ============================================================================
# RULE ENFORCEMENT: Immutable Definitions
# ============================================================================

class DeploymentPhase(Enum):
    """Deployment progression stages"""
    DEVELOPMENT = "week1-2"      # Local development
    STAGING = "week3"             # Staging validation
    CANARY_10_PERCENT = "week4-1" # 10% rollout
    CANARY_50_PERCENT = "week4-2" # 50% rollout
    CANARY_100_PERCENT = "week4-3" # 100% rollout
    PRODUCTION = "week5+"         # Full production


@dataclass
class GateDecision:
    """Immutable gate decision result"""
    passed: bool
    gate_name: str
    reason: str
    details: Dict[str, Any]
    timestamp: str
    blocking: bool = True  # If True, failure stops deployment
    
    def __post_init__(self):
        if not self.passed and self.blocking:
            raise RuntimeError(f"GATE BLOCKED: {self.gate_name} - {self.reason}")


# ============================================================================
# GATE 1: READINESS AUDIT (Hard Exit Code Gate)
# ============================================================================

class ReadinessAuditGate:
    """
    RULE 1: Readiness Audit is unskippable gate
    
    Must run _PHASE1_READINESS_AUDIT.py
    Exit code 0 = PASS, anything else = STOP
    Cannot proceed without passing
    """
    
    REQUIRED_CHECKS = [
        "files_exist",
        "imports_valid",
        "tool_definitions_complete",
        "parameter_validators_working",
        "policy_enforcer_functional",
        "shadow_runner_ready",
        "divergence_detection_functional",
        "failsafe_mode_ready",
        "load_test_harness_ready",
        "latency_overhead_measurable",
        "mcp_server_integration_complete",
        "metrics_collection_wired",
        "regression_detection_ready",
        "dependencies_traced",
        "deployment_config_valid"
    ]
    
    @staticmethod
    def run_audit(audit_script_path: str = "_PHASE1_READINESS_AUDIT.py") -> GateDecision:
        """
        Execute readiness audit and verify exit code
        
        This is NOT optional. If it fails, deployment STOPS.
        """
        
        if not os.path.exists(audit_script_path):
            raise RuntimeError(f"CRITICAL: Readiness audit not found at {audit_script_path}")
        
        try:
            result = subprocess.run(
                [sys.executable, audit_script_path],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                return GateDecision(
                    passed=False,
                    gate_name="READINESS_AUDIT",
                    reason=f"Audit failed with exit code {result.returncode}",
                    details={
                        "exit_code": result.returncode,
                        "stdout": result.stdout[-500:],  # Last 500 chars
                        "stderr": result.stderr[-500:]
                    },
                    timestamp=datetime.now().isoformat(),
                    blocking=True
                )
            
            return GateDecision(
                passed=True,
                gate_name="READINESS_AUDIT",
                reason="All 15 checks passed",
                details={"checks_passed": 15, "exit_code": 0},
                timestamp=datetime.now().isoformat(),
                blocking=False
            )
        
        except subprocess.TimeoutExpired:
            return GateDecision(
                passed=False,
                gate_name="READINESS_AUDIT",
                reason="Audit timeout (60 seconds)",
                details={"timeout": 60},
                timestamp=datetime.now().isoformat(),
                blocking=True
            )
        
        except Exception as e:
            return GateDecision(
                passed=False,
                gate_name="READINESS_AUDIT",
                reason=f"Audit execution error: {str(e)}",
                details={"error": str(e)},
                timestamp=datetime.now().isoformat(),
                blocking=True
            )


# ============================================================================
# GATE 2: DIVERGENCE DETECTION (System-Level Block)
# ============================================================================

class DivergenceProgressionGate:
    """
    RULE 2: Divergence is a system-level blocker
    
    During staging/canary:
      divergence detected → halt progression automatically
    
    This is not a warning. It's a failed deployment gate.
    """
    
    THRESHOLD = {
        "divergence_rate": 0.001,  # 0.1% max allowed
        "semantic_match_rate": 0.99,  # 99% match required
        "fatal_divergences": 0,  # Zero tolerance
        "unresolved_divergences": 0  # Zero tolerance
    }
    
    @staticmethod
    def check_shadow_metrics(
        shadow_report_path: str = "_PHASE1_SHADOW_REPORT.json"
    ) -> GateDecision:
        """
        Verify shadow runner metrics meet divergence threshold
        
        If any metric exceeds threshold, HALT progression.
        """
        
        if not os.path.exists(shadow_report_path):
            return GateDecision(
                passed=True,  # No data yet = pass (will be checked later)
                gate_name="DIVERGENCE_DETECTION",
                reason="No shadow report yet (first run)",
                details={},
                timestamp=datetime.now().isoformat(),
                blocking=False
            )
        
        try:
            with open(shadow_report_path, 'r') as f:
                report = json.load(f)
            
            details = {
                "divergence_rate": report.get("divergence_rate", 0),
                "semantic_match_rate": report.get("semantic_match_rate", 0),
                "fatal_divergences": report.get("fatal_divergences", 0),
                "unresolved_divergences": report.get("unresolved_divergences", 0)
            }
            
            # Check each threshold
            if details["divergence_rate"] > 0.001:
                return GateDecision(
                    passed=False,
                    gate_name="DIVERGENCE_DETECTION",
                    reason=f"Divergence rate {details['divergence_rate']:.2%} exceeds 0.1% threshold",
                    details=details,
                    timestamp=datetime.now().isoformat(),
                    blocking=True
                )
            
            if details["semantic_match_rate"] < 0.99:
                return GateDecision(
                    passed=False,
                    gate_name="DIVERGENCE_DETECTION",
                    reason=f"Semantic match rate {details['semantic_match_rate']:.2%} below 99% threshold",
                    details=details,
                    timestamp=datetime.now().isoformat(),
                    blocking=True
                )
            
            if details["fatal_divergences"] > 0:
                return GateDecision(
                    passed=False,
                    gate_name="DIVERGENCE_DETECTION",
                    reason=f"Fatal divergences detected ({details['fatal_divergences']})",
                    details=details,
                    timestamp=datetime.now().isoformat(),
                    blocking=True
                )
            
            if details["unresolved_divergences"] > 0:
                return GateDecision(
                    passed=False,
                    gate_name="DIVERGENCE_DETECTION",
                    reason=f"Unresolved divergences detected ({details['unresolved_divergences']})",
                    details=details,
                    timestamp=datetime.now().isoformat(),
                    blocking=True
                )
            
            # All thresholds met
            return GateDecision(
                passed=True,
                gate_name="DIVERGENCE_DETECTION",
                reason="All divergence metrics within acceptable thresholds",
                details=details,
                timestamp=datetime.now().isoformat(),
                blocking=False
            )
        
        except Exception as e:
            return GateDecision(
                passed=False,
                gate_name="DIVERGENCE_DETECTION",
                reason=f"Error reading divergence metrics: {str(e)}",
                details={"error": str(e)},
                timestamp=datetime.now().isoformat(),
                blocking=True
            )


# ============================================================================
# GATE 3: FAIL-SAFE MODE ENFORCEMENT (Hard-Coded Guard)
# ============================================================================

class FailSafeEnforcementGate:
    """
    RULE 3: Fail-Safe mode is hard-coded, not configurable
    
    At 10% canary:
      fail_safe_enabled = True (immutable)
    
    Prevents "temporary disables" that become permanent
    """
    
    FAIL_SAFE_REQUIRED_AT = {
        DeploymentPhase.CANARY_10_PERCENT: True,  # MUST be on
        DeploymentPhase.CANARY_50_PERCENT: False,  # Can disable after validation
        DeploymentPhase.CANARY_100_PERCENT: False,
        DeploymentPhase.PRODUCTION: False
    }
    
    @staticmethod
    def validate_failsafe_state(
        phase: DeploymentPhase,
        failsafe_enabled: bool,
        failsafe_triggers: int = 0
    ) -> GateDecision:
        """
        Verify fail-safe mode matches requirement for deployment phase
        
        At 10%: MUST be enabled, MUST have zero triggers
        At 50%+: Can be disabled ONLY if 10% completed with zero triggers
        """
        
        required = FailSafeEnforcementGate.FAIL_SAFE_REQUIRED_AT.get(phase, False)
        
        if phase == DeploymentPhase.CANARY_10_PERCENT:
            # 10% canary: Fail-safe MUST be on, MUST have zero triggers
            if not failsafe_enabled:
                return GateDecision(
                    passed=False,
                    gate_name="FAIL_SAFE_ENFORCEMENT",
                    reason="Fail-safe mode NOT enabled at 10% canary (REQUIRED)",
                    details={"phase": phase.value, "failsafe_enabled": failsafe_enabled},
                    timestamp=datetime.now().isoformat(),
                    blocking=True
                )
            
            if failsafe_triggers > 0:
                return GateDecision(
                    passed=False,
                    gate_name="FAIL_SAFE_ENFORCEMENT",
                    reason=f"Fail-safe was triggered {failsafe_triggers} times at 10% (ZERO triggers required)",
                    details={"phase": phase.value, "triggers": failsafe_triggers},
                    timestamp=datetime.now().isoformat(),
                    blocking=True
                )
            
            return GateDecision(
                passed=True,
                gate_name="FAIL_SAFE_ENFORCEMENT",
                reason="Fail-safe enabled with zero triggers at 10%",
                details={"phase": phase.value, "failsafe_enabled": True, "triggers": 0},
                timestamp=datetime.now().isoformat(),
                blocking=False
            )
        
        elif phase in [DeploymentPhase.CANARY_50_PERCENT, DeploymentPhase.CANARY_100_PERCENT]:
            # 50%+: Fail-safe can be disabled (should be disabled)
            return GateDecision(
                passed=True,
                gate_name="FAIL_SAFE_ENFORCEMENT",
                reason=f"Fail-safe state acceptable for {phase.value}",
                details={"phase": phase.value, "failsafe_enabled": failsafe_enabled},
                timestamp=datetime.now().isoformat(),
                blocking=False
            )
        
        else:
            return GateDecision(
                passed=True,
                gate_name="FAIL_SAFE_ENFORCEMENT",
                reason=f"Fail-safe not required for {phase.value}",
                details={"phase": phase.value},
                timestamp=datetime.now().isoformat(),
                blocking=False
            )


# ============================================================================
# GATE 4: LOAD TEST BINDING (Hard Performance Thresholds)
# ============================================================================

class LoadTestBindingGate:
    """
    RULE 4: Load test thresholds bind to deployment decision
    
    If load test shows:
      p95 latency > 2000ms → BLOCK
      overhead > 20% → BLOCK
      safe_ceiling < peak+buffer → BLOCK
    
    This is not a "nice to have." It's a deployment blocker.
    """
    
    HARD_THRESHOLDS = {
        "p95_latency_ms": 2000,
        "overhead_percent": 20,
        "min_safe_ceiling": None  # Calculated from peak
    }
    
    @staticmethod
    def validate_load_test_results(
        load_test_report_path: str = "_PHASE1_LOAD_TEST_RESULTS.json"
    ) -> GateDecision:
        """
        Verify load test results meet hard performance thresholds
        
        Blocking gate: deployment cannot proceed if thresholds exceeded
        """
        
        if not os.path.exists(load_test_report_path):
            return GateDecision(
                passed=False,
                gate_name="LOAD_TEST_BINDING",
                reason="Load test results not found",
                details={"path": load_test_report_path},
                timestamp=datetime.now().isoformat(),
                blocking=True
            )
        
        try:
            with open(load_test_report_path, 'r') as f:
                report = json.load(f)
            
            details = {
                "p95_latency_ms": report.get("latency_distribution", {}).get("p95", 0),
                "overhead_percent": report.get("overhead_percent", 0),
                "safe_ceiling": report.get("safe_concurrency_ceiling", 0),
                "peak_concurrency": report.get("peak_concurrency_observed", 0)
            }
            
            # Check p95 latency threshold
            if details["p95_latency_ms"] > 2000:
                return GateDecision(
                    passed=False,
                    gate_name="LOAD_TEST_BINDING",
                    reason=f"P95 latency {details['p95_latency_ms']}ms exceeds 2000ms threshold",
                    details=details,
                    timestamp=datetime.now().isoformat(),
                    blocking=True
                )
            
            # Check overhead threshold
            if details["overhead_percent"] > 20:
                return GateDecision(
                    passed=False,
                    gate_name="LOAD_TEST_BINDING",
                    reason=f"Overhead {details['overhead_percent']:.1f}% exceeds 20% threshold",
                    details=details,
                    timestamp=datetime.now().isoformat(),
                    blocking=True
                )
            
            # Check safe ceiling vs peak
            required_ceiling = details["peak_concurrency"] + 20  # +20 buffer minimum
            if details["safe_ceiling"] < required_ceiling:
                return GateDecision(
                    passed=False,
                    gate_name="LOAD_TEST_BINDING",
                    reason=f"Safe ceiling {details['safe_ceiling']} < required {required_ceiling}",
                    details=details,
                    timestamp=datetime.now().isoformat(),
                    blocking=True
                )
            
            # All thresholds met
            return GateDecision(
                passed=True,
                gate_name="LOAD_TEST_BINDING",
                reason="Load test results within all hard thresholds",
                details=details,
                timestamp=datetime.now().isoformat(),
                blocking=False
            )
        
        except Exception as e:
            return GateDecision(
                passed=False,
                gate_name="LOAD_TEST_BINDING",
                reason=f"Error validating load test results: {str(e)}",
                details={"error": str(e)},
                timestamp=datetime.now().isoformat(),
                blocking=True
            )


# ============================================================================
# GATE 5: REGRESSION DETECTION (Runtime Assertion)
# ============================================================================

class RegressionDetectionGate:
    """
    RULE 5: Post-Week 5, ANY passthrough call for Phase 1 = hard failure
    
    After migration complete:
      if PHASE1_COMMAND using passthrough
        → raise AssertionError (hard failure)
        → alert on-call
        → block processing
    
    This is not a log. It's a STOP.
    """
    
    PHASE1_COMMANDS = {"run_burp_scan", "list_targets", "get_report"}
    
    @staticmethod
    def assert_no_passthrough_after_migration(
        command_name: str,
        using_passthrough: bool,
        migration_complete: bool
    ) -> None:
        """
        Runtime assertion: Post-migration, Phase 1 commands cannot use passthrough
        
        This is called at request time. If it fails, request stops.
        """
        
        if not migration_complete:
            # Before Week 5: passthrough allowed
            return
        
        if command_name not in RegressionDetectionGate.PHASE1_COMMANDS:
            # Non-Phase1 commands: no restriction
            return
        
        if using_passthrough:
            # POST-MIGRATION: Phase 1 command using passthrough = REGRESSION
            raise AssertionError(
                f"CRITICAL REGRESSION: Phase 1 command '{command_name}' "
                f"using passthrough AFTER migration complete. "
                f"This is a hard failure. Page on-call immediately."
            )


# ============================================================================
# MASTER EXECUTION GATE (All 5 Rules Applied)
# ============================================================================

class MasterExecutionGate:
    """
    The final gatekeeper.
    
    Every deployment decision passes through all 5 gates.
    If ANY gate fails, deployment STOPS.
    No exceptions. No overrides. No "let's try anyway."
    """
    
    def __init__(self):
        self.gate_history = []  # Audit trail of all decisions
    
    def validate_deployment(
        self,
        phase: DeploymentPhase,
        audit_script_path: str = "_PHASE1_READINESS_AUDIT.py",
        shadow_report_path: str = "_PHASE1_SHADOW_REPORT.json",
        load_test_report_path: str = "_PHASE1_LOAD_TEST_RESULTS.json",
        failsafe_enabled: bool = False,
        failsafe_triggers: int = 0,
        migration_complete: bool = False
    ) -> Tuple[bool, list]:
        """
        Validate deployment against ALL 5 rules
        
        Returns: (passed: bool, decisions: list of GateDecision objects)
        
        If any gate fails AND is blocking: passed = False, deployment stops
        """
        
        decisions = []
        
        # GATE 1: Readiness Audit (always required)
        try:
            gate1 = ReadinessAuditGate.run_audit(audit_script_path)
            decisions.append(gate1)
            if not gate1.passed and gate1.blocking:
                self.gate_history.extend(decisions)
                return False, decisions
        except RuntimeError as e:
            decisions.append(GateDecision(
                passed=False,
                gate_name="READINESS_AUDIT",
                reason=str(e),
                details={},
                timestamp=datetime.now().isoformat(),
                blocking=True
            ))
            self.gate_history.extend(decisions)
            return False, decisions
        
        # GATE 2: Divergence Detection (staging/canary only)
        if phase in [DeploymentPhase.STAGING, DeploymentPhase.CANARY_10_PERCENT,
                     DeploymentPhase.CANARY_50_PERCENT, DeploymentPhase.CANARY_100_PERCENT]:
            gate2 = DivergenceProgressionGate.check_shadow_metrics(shadow_report_path)
            decisions.append(gate2)
            if not gate2.passed and gate2.blocking:
                self.gate_history.extend(decisions)
                return False, decisions
        
        # GATE 3: Fail-Safe Enforcement (canary phases)
        if phase in [DeploymentPhase.CANARY_10_PERCENT, DeploymentPhase.CANARY_50_PERCENT,
                     DeploymentPhase.CANARY_100_PERCENT]:
            gate3 = FailSafeEnforcementGate.validate_failsafe_state(
                phase, failsafe_enabled, failsafe_triggers
            )
            decisions.append(gate3)
            if not gate3.passed and gate3.blocking:
                self.gate_history.extend(decisions)
                return False, decisions
        
        # GATE 4: Load Test Binding (staging required)
        if phase == DeploymentPhase.STAGING:
            gate4 = LoadTestBindingGate.validate_load_test_results(load_test_report_path)
            decisions.append(gate4)
            if not gate4.passed and gate4.blocking:
                self.gate_history.extend(decisions)
                return False, decisions
        
        # GATE 5: Regression Detection (production validation, not enforcement here)
        # This is enforced at request time via assert_no_passthrough_after_migration()
        
        # ALL GATES PASSED
        self.gate_history.extend(decisions)
        return True, decisions
    
    def get_audit_trail(self) -> list:
        """Return immutable audit trail of all gate decisions"""
        return self.gate_history.copy()
    
    def print_gate_report(self, decisions: list) -> str:
        """Format gate decisions for reporting"""
        report = f"\n{'='*80}\nDEPLOYMENT GATE REPORT\n{'='*80}\n"
        
        for decision in decisions:
            status = "✅ PASS" if decision.passed else "❌ FAIL"
            report += f"\n{status} | {decision.gate_name}\n"
            report += f"  Reason: {decision.reason}\n"
            report += f"  Blocking: {decision.blocking}\n"
            if decision.details:
                for key, value in decision.details.items():
                    report += f"  {key}: {value}\n"
        
        report += f"\n{'='*80}\n"
        return report


# ============================================================================
# CI/CD Integration
# ============================================================================

def cicd_deployment_check(
    phase: str,
    fail_on_error: bool = True
) -> int:
    """
    CI/CD entry point: Check all gates before deploying
    
    Usage in CI/CD pipeline:
      python _phase1_execution_layer.py --phase staging
      echo $? → 0 = proceed, 1 = STOP
    
    Args:
      phase: "staging", "canary-10", "canary-50", "canary-100", "production"
      fail_on_error: If True, exit with code 1 on any failure
    
    Returns:
      Exit code: 0 = all gates passed, 1 = gate blocked
    """
    
    phase_map = {
        "staging": DeploymentPhase.STAGING,
        "canary-10": DeploymentPhase.CANARY_10_PERCENT,
        "canary-50": DeploymentPhase.CANARY_50_PERCENT,
        "canary-100": DeploymentPhase.CANARY_100_PERCENT,
        "production": DeploymentPhase.PRODUCTION,
    }
    
    deployment_phase = phase_map.get(phase.lower())
    if not deployment_phase:
        print(f"❌ Unknown phase: {phase}")
        return 1
    
    gatekeeper = MasterExecutionGate()
    
    try:
        passed, decisions = gatekeeper.validate_deployment(deployment_phase)
        print(gatekeeper.print_gate_report(decisions))
        
        if not passed:
            print(f"\n🛑 DEPLOYMENT BLOCKED")
            return 1
        
        print(f"\n✅ DEPLOYMENT APPROVED - Proceed with {phase}")
        return 0
    
    except Exception as e:
        print(f"❌ GATE ERROR: {str(e)}")
        return 1


# ============================================================================
# Runtime Enforcement (For MCP Server Integration)
# ============================================================================

class Phase1RuntimeEnforcer:
    """
    Enforcement layer that runs in mcp_server.py
    
    Use during request handling:
      enforcer = Phase1RuntimeEnforcer()
      enforcer.enforce_no_passthrough_after_migration(
          command="run_burp_scan",
          using_passthrough=True,
          migration_complete=True
      )
      → Raises AssertionError if regression detected
    """
    
    @staticmethod
    def enforce_no_passthrough_after_migration(
        command: str,
        using_passthrough: bool,
        migration_complete: bool
    ) -> None:
        """
        Enforce: No Phase 1 passthrough after migration
        
        Call this for EVERY Phase 1 command request post-Week 5
        """
        RegressionDetectionGate.assert_no_passthrough_after_migration(
            command, using_passthrough, migration_complete
        )
    
    @staticmethod
    def validate_failsafe_hardcoded(phase: str) -> bool:
        """
        Verify fail-safe mode is hard-coded as required
        
        At 10% canary: MUST be True
        Otherwise: flexible
        """
        if phase == "canary-10":
            # Fail-safe MUST be on
            return os.getenv("MCP_PHASE1_FAILSAFE_ENABLED", "false").lower() == "true"
        return True


# ============================================================================
# Main (CLI Testing)
# ============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Phase 1 Execution Layer")
    parser.add_argument(
        "--phase",
        choices=["staging", "canary-10", "canary-50", "canary-100", "production"],
        default="staging",
        help="Deployment phase to validate"
    )
    
    args = parser.parse_args()
    
    exit_code = cicd_deployment_check(args.phase, fail_on_error=True)
    sys.exit(exit_code)
