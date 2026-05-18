#!/usr/bin/env python3
"""
Phase 1 Shadow Runner — A/B Comparison Harness
===============================================

Runs Phase 1 commands through BOTH passthrough (legacy) and typed (new) implementations
in parallel, comparing results and tracking divergence for safe migration.

Key capabilities:
- Parallel execution of passthrough vs. typed
- Result comparison (success/failure, latency, output structure)
- Divergence logging with full request context
- Metrics collection for migration readiness assessment
- Configurable shadow logging level (off, light, full)

Usage:
  from _phase1_shadow_runner import ShadowRunner
  
  runner = ShadowRunner(
    mcp_server=mcp_server,
    metrics=mcp_server.metrics,
    shadow_level="full"  # or "light", "off"
  )
  
  # Shadow run a command
  result = await runner.run_burp_scan_shadow(
    request_id="req-123",
    principal=principal,
    params={"target": "example.com", "scan_profile": "balanced"}
  )
  
  # Generate migration readiness report
  report = runner.generate_readiness_report()
"""

import asyncio
import time
import json
import logging
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from collections import defaultdict
import hashlib

logger = logging.getLogger(__name__)


# ============================================================================
# Data Structures
# ============================================================================

@dataclass
class ExecutionResult:
    """Result from executing a command"""
    success: bool
    latency_ms: float
    error: Optional[str] = None
    error_type: Optional[str] = None
    result_type: Optional[str] = None
    result_hash: Optional[str] = None
    output_sample: Optional[str] = None  # First 500 chars for debugging


@dataclass
class ShadowRunRecord:
    """Single shadow run comparison record"""
    timestamp: str
    request_id: str
    command: str
    params_hash: str
    params_sample: str
    
    passthrough: ExecutionResult
    typed: ExecutionResult
    
    # Comparison results
    match: bool
    divergence_type: Optional[str]  # "success_mismatch", "error_mismatch", "latency_spike", etc.
    divergence_detail: Optional[str]
    
    # Metadata
    principal_role: str
    principal_plan: str
    tenant_id: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict"""
        return {
            "timestamp": self.timestamp,
            "request_id": self.request_id,
            "command": self.command,
            "params_hash": self.params_hash,
            "params_sample": self.params_sample,
            "passthrough": asdict(self.passthrough),
            "typed": asdict(self.typed),
            "match": self.match,
            "divergence_type": self.divergence_type,
            "divergence_detail": self.divergence_detail,
            "principal_role": self.principal_role,
            "principal_plan": self.principal_plan,
            "tenant_id": self.tenant_id,
        }


@dataclass
class ShadowRunStats:
    """Aggregated stats from shadow runs"""
    total_runs: int = 0
    matched: int = 0
    diverged: int = 0
    match_rate: float = 0.0
    
    passthrough_success_rate: float = 0.0
    typed_success_rate: float = 0.0
    
    passthrough_avg_latency_ms: float = 0.0
    typed_avg_latency_ms: float = 0.0
    latency_overhead_pct: float = 0.0
    
    divergence_breakdown: Dict[str, int] = field(default_factory=dict)


# ============================================================================
# Shadow Runner
# ============================================================================

class ShadowRunner:
    """A/B test harness for passthrough vs. typed implementations"""
    
    def __init__(
        self,
        mcp_server,
        metrics=None,
        shadow_level: str = "full",
        max_log_entries: int = 10000
    ):
        """
        Initialize shadow runner
        
        Args:
          mcp_server: SecurityMCPServer instance
          metrics: MCPMetrics instance
          shadow_level: "off" (no logging), "light" (divergence only), "full" (all runs)
          max_log_entries: Max shadow log records to keep in memory
        """
        self.mcp_server = mcp_server
        self.metrics = metrics
        self.shadow_level = shadow_level
        self.max_log_entries = max_log_entries
        
        # Shadow log (circular buffer)
        self.shadow_log: List[ShadowRunRecord] = []
        self.divergence_log: List[ShadowRunRecord] = []
        
        # Stats accumulator
        self.stats = {
            "run_burp_scan": defaultdict(int),
            "list_targets": defaultdict(int),
            "get_report": defaultdict(int)
        }
    
    # ==========================================================================
    # Shadow Execution Methods
    # ==========================================================================
    
    async def run_burp_scan_shadow(
        self,
        request_id: str,
        principal: 'MCPPrincipal',
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute run_burp_scan through both passthrough and typed implementations
        
        Returns typed result (new implementation wins), but logs divergence
        """
        return await self._shadow_run(
            command="run_burp_scan",
            request_id=request_id,
            principal=principal,
            params=params,
            passthrough_impl=self._impl_passthrough_run_burp_scan,
            typed_impl=self._impl_typed_run_burp_scan
        )
    
    async def list_targets_shadow(
        self,
        request_id: str,
        principal: 'MCPPrincipal',
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute list_targets through both implementations"""
        return await self._shadow_run(
            command="list_targets",
            request_id=request_id,
            principal=principal,
            params=params,
            passthrough_impl=self._impl_passthrough_list_targets,
            typed_impl=self._impl_typed_list_targets
        )
    
    async def get_report_shadow(
        self,
        request_id: str,
        principal: 'MCPPrincipal',
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute get_report through both implementations"""
        return await self._shadow_run(
            command="get_report",
            request_id=request_id,
            principal=principal,
            params=params,
            passthrough_impl=self._impl_passthrough_get_report,
            typed_impl=self._impl_typed_get_report
        )
    
    # ==========================================================================
    # Internal Shadow Run Logic
    # ==========================================================================
    
    async def _shadow_run(
        self,
        command: str,
        request_id: str,
        principal: 'MCPPrincipal',
        params: Dict[str, Any],
        passthrough_impl,
        typed_impl
    ) -> Dict[str, Any]:
        """
        Execute command through both implementations and compare
        
        Returns typed result (new implementation wins)
        """
        
        # Execute both in parallel
        pt_task = asyncio.create_task(
            self._safe_execute(passthrough_impl, params)
        )
        typed_task = asyncio.create_task(
            self._safe_execute(typed_impl, params)
        )
        
        pt_result, pt_error = await pt_task
        typed_result, typed_error = await typed_task
        
        # Convert to ExecutionResult objects
        pt_exec = ExecutionResult(
            success=pt_error is None,
            latency_ms=pt_result.get("_latency_ms", 0) if isinstance(pt_result, dict) else 0,
            error=pt_error,
            error_type=type(pt_error).__name__ if pt_error else None,
            result_type=type(pt_result).__name__ if pt_result else None,
            result_hash=self._hash_result(pt_result) if pt_result else None,
            output_sample=self._sample_output(pt_result)
        )
        
        typed_exec = ExecutionResult(
            success=typed_error is None,
            latency_ms=typed_result.get("_latency_ms", 0) if isinstance(typed_result, dict) else 0,
            error=typed_error,
            error_type=type(typed_error).__name__ if typed_error else None,
            result_type=type(typed_result).__name__ if typed_result else None,
            result_hash=self._hash_result(typed_result) if typed_result else None,
            output_sample=self._sample_output(typed_result)
        )
        
        # Compare results
        match, divergence_type, divergence_detail = self._compare_results(
            pt_exec, typed_exec
        )
        
        # Create shadow log record
        record = ShadowRunRecord(
            timestamp=datetime.now().isoformat(),
            request_id=request_id,
            command=command,
            params_hash=self._hash_params(params),
            params_sample=self._sample_params(params),
            passthrough=pt_exec,
            typed=typed_exec,
            match=match,
            divergence_type=divergence_type,
            divergence_detail=divergence_detail,
            principal_role=principal.claims.get("role", "unknown"),
            principal_plan=principal.claims.get("plan_id", "unknown"),
            tenant_id=principal.tenant_id
        )
        
        # Log record
        self._log_shadow_record(command, record, match)
        
        # Update metrics
        if self.metrics:
            self.metrics.record_shadow_run(
                command,
                match,
                pt_exec.latency_ms / 1000.0,
                typed_exec.latency_ms / 1000.0
            )
        
        # Return typed result (new implementation)
        return typed_result if typed_result else {"error": typed_error}
    
    async def _safe_execute(self, impl, params: Dict[str, Any]) -> Tuple[Any, Optional[Exception]]:
        """Safely execute implementation, capturing errors"""
        start = time.monotonic()
        try:
            result = await impl(params) if asyncio.iscoroutinefunction(impl) else impl(params)
            latency_ms = (time.monotonic() - start) * 1000
            
            # Add latency metadata if dict
            if isinstance(result, dict):
                result = {**result, "_latency_ms": latency_ms}
            
            return result, None
        except Exception as e:
            latency_ms = (time.monotonic() - start) * 1000
            logger.exception(f"Implementation raised: {type(e).__name__}: {e}")
            return {"_latency_ms": latency_ms}, e
    
    # ==========================================================================
    # Result Comparison
    # ==========================================================================
    
    def _compare_results(
        self,
        pt: ExecutionResult,
        typed: ExecutionResult
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Compare passthrough vs. typed execution
        
        Returns: (match, divergence_type, detail)
        """
        
        # Both succeeded
        if pt.success and typed.success:
            # Check if outputs match
            if pt.result_hash == typed.result_hash:
                return (True, None, None)
            else:
                return (
                    False,
                    "output_mismatch",
                    f"Hash PT:{pt.result_hash[:8]} vs Typed:{typed.result_hash[:8]}"
                )
        
        # Both failed with same error
        if not pt.success and not typed.success:
            if pt.error_type == typed.error_type:
                return (True, None, None)
            else:
                return (
                    False,
                    "error_type_mismatch",
                    f"PT:{pt.error_type} vs Typed:{typed.error_type}"
                )
        
        # One succeeded, one failed
        if pt.success != typed.success:
            return (
                False,
                "success_mismatch",
                f"PT:success={pt.success} vs Typed:success={typed.success}"
            )
        
        # Latency spike (>50% slower)
        latency_ratio = typed.latency_ms / pt.latency_ms if pt.latency_ms > 0 else 1.0
        if latency_ratio > 1.5:
            return (
                False,
                "latency_spike",
                f"{latency_ratio:.2f}x slower ({typed.latency_ms:.0f}ms vs {pt.latency_ms:.0f}ms)"
            )
        
        return (True, None, None)
    
    # ==========================================================================
    # Placeholder Implementations
    # ==========================================================================
    
    async def _impl_passthrough_run_burp_scan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Placeholder for passthrough implementation"""
        await asyncio.sleep(0.05)  # Simulate work
        return {"status": "queued", "scan_id": "scan-pt-123"}
    
    async def _impl_typed_run_burp_scan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Placeholder for typed implementation"""
        await asyncio.sleep(0.07)  # Simulate slightly slower work
        return {"status": "queued", "scan_id": "scan-typed-123"}
    
    async def _impl_passthrough_list_targets(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Placeholder for passthrough implementation"""
        await asyncio.sleep(0.02)
        return {"targets": [], "count": 0}
    
    async def _impl_typed_list_targets(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Placeholder for typed implementation"""
        await asyncio.sleep(0.02)
        return {"targets": [], "count": 0}
    
    async def _impl_passthrough_get_report(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Placeholder for passthrough implementation"""
        await asyncio.sleep(0.03)
        return {"report": None, "status": "not_found"}
    
    async def _impl_typed_get_report(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Placeholder for typed implementation"""
        await asyncio.sleep(0.03)
        return {"report": None, "status": "not_found"}
    
    # ==========================================================================
    # Logging & Metrics
    # ==========================================================================
    
    def _log_shadow_record(
        self,
        command: str,
        record: ShadowRunRecord,
        match: bool
    ) -> None:
        """Log shadow run record"""
        
        # Add to main log (circular buffer)
        if self.shadow_level in ["full"]:
            self.shadow_log.append(record)
            if len(self.shadow_log) > self.max_log_entries:
                self.shadow_log.pop(0)
        
        # Add to divergence log if mismatch
        if not match:
            self.divergence_log.append(record)
            
            # Log warning immediately
            logger.warning(
                f"[SHADOW DIVERGENCE] {record.command} "
                f"(request={record.request_id}): "
                f"{record.divergence_type} - {record.divergence_detail}"
            )
        
        # Update stats
        self.stats[command]["total"] += 1
        if match:
            self.stats[command]["matched"] += 1
        else:
            self.stats[command]["diverged"] += 1
            dt = record.divergence_type or "unknown"
            self.stats[command][f"divergence_{dt}"] = \
                self.stats[command].get(f"divergence_{dt}", 0) + 1
    
    # ==========================================================================
    # Report Generation
    # ==========================================================================
    
    def generate_readiness_report(self) -> Dict[str, Any]:
        """Generate migration readiness assessment"""
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "overall_readiness": "UNKNOWN",  # Will be calculated below
            "commands": {},
            "divergence_summary": {},
            "recommendations": [],
            "shadow_log_size": len(self.shadow_log),
            "divergence_log_size": len(self.divergence_log)
        }
        
        # Per-command assessment
        all_ready = True
        for command in ["run_burp_scan", "list_targets", "get_report"]:
            stats = self.stats[command]
            total = stats.get("total", 0)
            
            if total == 0:
                report["commands"][command] = {
                    "status": "NO_DATA",
                    "total_runs": 0,
                    "readiness": "UNKNOWN"
                }
                continue
            
            matched = stats.get("matched", 0)
            match_rate = matched / total if total > 0 else 0.0
            
            # Ready if match_rate >= 99% and total >= 100
            readiness = (
                "READY" if (match_rate >= 0.99 and total >= 100)
                else "CAUTION" if match_rate >= 0.95
                else "NOT_READY"
            )
            
            if readiness != "READY":
                all_ready = False
            
            report["commands"][command] = {
                "total_runs": total,
                "matched": matched,
                "diverged": stats.get("diverged", 0),
                "match_rate": f"{match_rate*100:.2f}%",
                "readiness": readiness,
                "divergence_types": {
                    k: v for k, v in stats.items()
                    if k.startswith("divergence_")
                }
            }
        
        # Summary
        report["overall_readiness"] = "READY" if all_ready else "CAUTION"
        
        # Divergence patterns
        if self.divergence_log:
            divergence_types = defaultdict(int)
            for record in self.divergence_log:
                if record.divergence_type:
                    divergence_types[record.divergence_type] += 1
            report["divergence_summary"] = dict(divergence_types)
        
        # Recommendations
        if all_ready:
            report["recommendations"].append(
                "✓ Safe to proceed with production canary (start at 10%)"
            )
        else:
            report["recommendations"].append(
                "⚠ Investigate divergences before production deployment"
            )
            if self.divergence_log:
                report["recommendations"].append(
                    f"Review {len(self.divergence_log)} divergence records in detail"
                )
        
        return report
    
    def get_divergence_summary(self) -> Dict[str, Any]:
        """Get summary of divergences for investigation"""
        summary = {
            "total_divergences": len(self.divergence_log),
            "by_command": defaultdict(list),
            "by_type": defaultdict(list)
        }
        
        for record in self.divergence_log:
            summary["by_command"][record.command].append(record.to_dict())
            if record.divergence_type:
                summary["by_type"][record.divergence_type].append(record.to_dict())
        
        return dict(summary)
    
    # ==========================================================================
    # Utilities
    # ==========================================================================
    
    @staticmethod
    def _hash_result(result: Any) -> str:
        """Hash result for comparison"""
        try:
            if isinstance(result, dict):
                json_str = json.dumps(result, sort_keys=True, default=str)
            else:
                json_str = str(result)
            return hashlib.sha256(json_str.encode()).hexdigest()[:16]
        except Exception:
            return "ERROR"
    
    @staticmethod
    def _hash_params(params: Dict[str, Any]) -> str:
        """Hash parameters"""
        try:
            json_str = json.dumps(params, sort_keys=True, default=str)
            return hashlib.sha256(json_str.encode()).hexdigest()[:16]
        except Exception:
            return "ERROR"
    
    @staticmethod
    def _sample_params(params: Dict[str, Any]) -> str:
        """Create sample of params for logging"""
        try:
            json_str = json.dumps(params, default=str)
            if len(json_str) > 200:
                return json_str[:200] + "..."
            return json_str
        except Exception:
            return str(params)[:200]
    
    @staticmethod
    def _sample_output(result: Any) -> str:
        """Create sample of output for logging"""
        try:
            if isinstance(result, dict):
                json_str = json.dumps(result, default=str)
            else:
                json_str = str(result)
            if len(json_str) > 500:
                return json_str[:500] + "..."
            return json_str
        except Exception:
            return str(result)[:500]


# ============================================================================
# Export
# ============================================================================

__all__ = [
    "ShadowRunner",
    "ShadowRunRecord",
    "ExecutionResult",
    "ShadowRunStats",
]


if __name__ == "__main__":
    # Demo: Create and use shadow runner
    import asyncio
    
    async def demo():
        runner = ShadowRunner(
            mcp_server=None,
            metrics=None,
            shadow_level="full"
        )
        
        # Simulate some shadow runs
        for i in range(5):
            result = await runner._shadow_run(
                command="run_burp_scan",
                request_id=f"req-{i}",
                principal=None,
                params={"target": "example.com", "scan_profile": "balanced"},
                passthrough_impl=runner._impl_passthrough_run_burp_scan,
                typed_impl=runner._impl_typed_run_burp_scan
            )
            print(f"Run {i}: {result}")
        
        # Generate report
        report = runner.generate_readiness_report()
        print("\nReadiness Report:")
        print(json.dumps(report, indent=2))
    
    asyncio.run(demo())
