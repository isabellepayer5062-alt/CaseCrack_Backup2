#!/usr/bin/env python3
"""
Phase 1 Fail-Safe Mode & Safety Upgrades
===========================================

Implements 4 critical safety improvements:

1. FAIL-SAFE MODE (Early Canary)
   - If typed fails & passthrough succeeds → return passthrough
   - Log CRITICAL divergence for investigation
   - Prevents users from hitting typed bugs
   - Disable after confidence is high (usually 1 week at 100%)

2. MIGRATION PROGRESS METRICS
   - Track phase1_typed_calls_total
   - Track phase1_passthrough_calls_total
   - Graph should show: passthrough ↓ → 0, typed ↑ → 100%
   - Alert if regression (passthrough calls reappear)

3. REGRESSION ALERTS
   - If ANY Phase 1 command hits passthrough after migration
   - Trigger immediate alert
   - Prevents silent bypass of enforcement

4. TOOL VERSIONING
   - All tools tagged: "tool:command:v1"
   - Prevents future breaking changes
   - Enables canary deployment of tool versions

Usage:
  from _phase1_safety_upgrades import FailSafeMode, MigrationMetrics, RegressionDetector
  
  # Initialize
  fail_safe = FailSafeMode(enabled=True)  # During early canary
  metrics = MigrationMetrics()
  detector = RegressionDetector()
  
  # In shadow runner or typed path:
  if fail_safe.should_use_failsafe(command):
    try:
      return await typed_impl(params)
    except Exception as e:
      if await passthrough_impl_succeeds(command, params):
        fail_safe.log_critical_divergence(command, e, passthrough_ok=True)
        metrics.record_failsafe_triggered(command)
        return await passthrough_impl(params)
      raise
  
  # Check for regressions
  if regression_detected := detector.check_regression("run_burp_scan", request):
    alert(f"REGRESSION: Phase 1 command hit passthrough after migration!")
"""

import logging
from typing import Dict, Set, Any, Optional, List
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import json

logger = logging.getLogger(__name__)


# ============================================================================
# 1. Fail-Safe Mode
# ============================================================================

class FailSafeMode:
    """
    Early canary protection: Return passthrough result if typed fails
    
    Prevents users from hitting typed implementation bugs during
    confidence-building phase (first 1-2 weeks at 100%).
    """
    
    def __init__(self, enabled: bool = False):
        """
        Initialize fail-safe
        
        Args:
          enabled: Set True during canary phase (10%/50%), False after 100% stable
        """
        self.enabled = enabled
        self.phase1_commands = {"run_burp_scan", "list_targets", "get_report"}
        self.critical_divergences = []
    
    def should_use_failsafe(self, command: str) -> bool:
        """Check if fail-safe should be active for this command"""
        return self.enabled and command in self.phase1_commands
    
    def log_critical_divergence(
        self,
        command: str,
        typed_error: Exception,
        passthrough_ok: bool
    ) -> None:
        """Log when typed fails but passthrough succeeds"""
        
        divergence = {
            "timestamp": datetime.now().isoformat(),
            "command": command,
            "typed_error": str(typed_error),
            "typed_error_type": type(typed_error).__name__,
            "passthrough_ok": passthrough_ok,
            "severity": "CRITICAL"
        }
        
        self.critical_divergences.append(divergence)
        
        logger.critical(
            f"[FAIL-SAFE TRIGGERED] {command}: Typed failed, using passthrough instead. "
            f"Error: {type(typed_error).__name__}: {typed_error}"
        )
    
    def get_critical_divergences(self) -> List[Dict[str, Any]]:
        """Get all logged critical divergences"""
        return self.critical_divergences


# ============================================================================
# 2. Migration Progress Metrics
# ============================================================================

class MigrationMetrics:
    """Track migration progress: passthrough → typed"""
    
    def __init__(self):
        self.phase1_typed_calls = 0
        self.phase1_passthrough_calls = 0
        self.failsafe_triggers = {}  # command -> count
        self.regression_events = []
    
    def record_typed_call(self, command: str) -> None:
        """Record call to typed implementation"""
        self.phase1_typed_calls += 1
    
    def record_passthrough_call(self, command: str) -> None:
        """Record call to passthrough (should decrease to 0)"""
        self.phase1_passthrough_calls += 1
    
    def record_failsafe_triggered(self, command: str) -> None:
        """Record fail-safe fallback"""
        if command not in self.failsafe_triggers:
            self.failsafe_triggers[command] = 0
        self.failsafe_triggers[command] += 1
    
    def get_migration_progress(self) -> Dict[str, Any]:
        """Get migration progress report"""
        total = self.phase1_typed_calls + self.phase1_passthrough_calls
        typed_pct = (self.phase1_typed_calls / total * 100) if total > 0 else 0
        
        return {
            "typed_calls": self.phase1_typed_calls,
            "passthrough_calls": self.phase1_passthrough_calls,
            "typed_percentage": typed_pct,
            "total_calls": total,
            "failsafe_triggers": self.failsafe_triggers,
            "migration_status": "COMPLETE" if typed_pct >= 99.9 else "IN_PROGRESS"
        }
    
    def check_migration_complete(self) -> bool:
        """Check if migration is complete (99.9%+ typed)"""
        progress = self.get_migration_progress()
        return progress['typed_percentage'] >= 99.9 and progress['passthrough_calls'] == 0


# ============================================================================
# 3. Regression Detector
# ============================================================================

class RegressionDetector:
    """Detect regressions: Phase 1 commands hitting passthrough after migration"""
    
    def __init__(self):
        self.phase1_commands = {"run_burp_scan", "list_targets", "get_report"}
        self.migration_complete = False
        self.regression_events = []
    
    def mark_migration_complete(self) -> None:
        """Call after Phase 1 migration is done and passthrough disabled"""
        self.migration_complete = True
        logger.info("Migration marked complete. Regression detection ACTIVE.")
    
    def check_regression(self, command: str, request: Dict[str, Any]) -> bool:
        """
        Check if Phase 1 command is using passthrough after migration
        
        After mark_migration_complete(), ANY passthrough call to Phase 1
        command indicates a regression.
        """
        
        if not self.migration_complete or command not in self.phase1_commands:
            return False
        
        # If we get here during a passthrough call (after migration), that's a regression
        regression = {
            "timestamp": datetime.now().isoformat(),
            "command": command,
            "request_id": request.get('request_id', 'unknown'),
            "severity": "CRITICAL"
        }
        
        self.regression_events.append(regression)
        
        logger.critical(
            f"[REGRESSION DETECTED] Phase 1 command '{command}' hit passthrough "
            f"AFTER migration! This should not happen."
        )
        
        return True
    
    def get_regressions(self) -> List[Dict[str, Any]]:
        """Get all detected regressions"""
        return self.regression_events


# ============================================================================
# 4. Tool Versioning & Registry
# ============================================================================

@dataclass
class ToolVersion:
    """Tool version metadata"""
    command: str
    version: str
    created_at: str
    schema_hash: str  # Hash of tool schema for change detection
    breaking_changes: List[str]  # List of breaking changes from prev version


class ToolVersionRegistry:
    """Manage tool versions and detect breaking changes"""
    
    def __init__(self):
        self.registry: Dict[str, ToolVersion] = {}
        self.version_history: Dict[str, List[ToolVersion]] = {}
    
    def register_tool(
        self,
        command: str,
        version: str,
        schema_hash: str,
        breaking_changes: List[str] = None
    ) -> None:
        """Register a tool version"""
        
        tool_version = ToolVersion(
            command=command,
            version=version,
            created_at=datetime.now().isoformat(),
            schema_hash=schema_hash,
            breaking_changes=breaking_changes or []
        )
        
        self.registry[command] = tool_version
        
        if command not in self.version_history:
            self.version_history[command] = []
        self.version_history[command].append(tool_version)
        
        if breaking_changes:
            logger.warning(
                f"Tool {command}:{version} has breaking changes: {breaking_changes}"
            )
    
    def get_tool_version(self, command: str) -> Optional[ToolVersion]:
        """Get current version of tool"""
        return self.registry.get(command)
    
    def has_breaking_changes(self, command: str) -> bool:
        """Check if current tool version has breaking changes"""
        tool = self.get_tool_version(command)
        return bool(tool and tool.breaking_changes)
    
    def get_version_history(self, command: str) -> List[ToolVersion]:
        """Get all versions of a tool"""
        return self.version_history.get(command, [])
    
    def detect_version_compatibility(
        self,
        command: str,
        client_version: str
    ) -> Dict[str, Any]:
        """Check compatibility between client version and current version"""
        
        current = self.get_tool_version(command)
        if not current:
            return {"compatible": False, "reason": "Tool not found"}
        
        if client_version == current.version:
            return {
                "compatible": True,
                "reason": "Exact version match",
                "current_version": current.version
            }
        
        # Check if breaking changes would affect client
        if current.breaking_changes:
            return {
                "compatible": False,
                "reason": "Breaking changes in new version",
                "breaking_changes": current.breaking_changes,
                "current_version": current.version,
                "client_version": client_version
            }
        
        return {
            "compatible": True,
            "reason": "Backward compatible",
            "current_version": current.version,
            "client_version": client_version
        }


# ============================================================================
# 5. Dependency Tracer
# ============================================================================

class DependencyTracer:
    """Trace which Phase 2/3 commands call Phase 1 commands internally"""
    
    def __init__(self):
        self.phase1_commands = {"run_burp_scan", "list_targets", "get_report"}
        self.phase2_phase3_commands = {"export_findings", "check_status"}  # Example
        self.call_graph = {}  # caller -> set(callees)
    
    def trace_dependencies(self, caller: str, callees: List[str]) -> None:
        """Record that caller invokes these commands"""
        
        if caller not in self.call_graph:
            self.call_graph[caller] = set()
        
        for callee in callees:
            self.call_graph[caller].add(callee)
    
    def find_phase1_dependencies(self) -> Dict[str, List[str]]:
        """Find which Phase 2/3 commands call Phase 1 internally"""
        
        dependencies = {}
        
        for caller, callees in self.call_graph.items():
            phase1_calls = [c for c in callees if c in self.phase1_commands]
            if phase1_calls:
                dependencies[caller] = phase1_calls
                logger.warning(
                    f"[DEPENDENCY] {caller} (Phase 2/3) calls Phase 1: {phase1_calls}"
                )
        
        return dependencies
    
    def check_passthrough_bypass(self, caller: str) -> Optional[str]:
        """
        Check if caller is trying to bypass Phase 1 enforcement
        
        E.g., if export_findings (Phase 2) internally calls run_burp_scan
        via passthrough, it bypasses typed enforcement.
        """
        
        phase1_deps = self.find_phase1_dependencies()
        
        if caller in phase1_deps:
            return (
                f"ALERT: {caller} internally calls Phase 1 commands: {phase1_deps[caller]}. "
                f"Ensure these are called through typed path, not passthrough!"
            )
        
        return None


# ============================================================================
# Export
# ============================================================================

__all__ = [
    "FailSafeMode",
    "MigrationMetrics",
    "RegressionDetector",
    "ToolVersionRegistry",
    "ToolVersion",
    "DependencyTracer",
]


if __name__ == "__main__":
    # Demo
    
    # 1. Fail-safe during canary
    failsafe = FailSafeMode(enabled=True)
    failsafe.log_critical_divergence("run_burp_scan", 
                                    Exception("Connection timeout"), 
                                    passthrough_ok=True)
    print(f"Fail-safe divergences: {len(failsafe.get_critical_divergences())}")
    
    # 2. Migration metrics
    metrics = MigrationMetrics()
    metrics.record_typed_call("run_burp_scan")
    metrics.record_typed_call("list_targets")
    metrics.record_passthrough_call("run_burp_scan")
    progress = metrics.get_migration_progress()
    print(f"Migration progress: {progress['typed_percentage']:.1f}%")
    
    # 3. Regression detection
    detector = RegressionDetector()
    detector.mark_migration_complete()
    regression = detector.check_regression("run_burp_scan", {"request_id": "123"})
    print(f"Regression detected: {regression}")
    
    # 4. Tool versioning
    registry = ToolVersionRegistry()
    registry.register_tool("run_burp_scan", "v1", "hash123abc")
    compat = registry.detect_version_compatibility("run_burp_scan", "v1")
    print(f"Compatibility: {compat['compatible']}")
    
    # 5. Dependency tracing
    tracer = DependencyTracer()
    tracer.trace_dependencies("export_findings", ["run_burp_scan"])
    deps = tracer.find_phase1_dependencies()
    print(f"Phase 1 dependencies: {deps}")
