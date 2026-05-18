#!/usr/bin/env python3
"""
PHASE 1 POLICY IMPACT TRACKER
==============================

Logs policy side-effects separately from output divergence.

These are NOT divergences but BEHAVIOR CHANGES that need to be tracked:
  - Would have been denied by policy
  - Would have been rate limited
  - Latency overhead from policy checks

Implementation in shadow runner + metrics pipeline.
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from collections import defaultdict
from statistics import mean, stdev
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


# ============================================================================
# Data Structures
# ============================================================================

@dataclass
class PolicyDenial:
    """Record of a policy denial"""
    timestamp: str
    command: str
    principal_id: str
    principal_role: str
    denial_reason: str  # quota_exceeded, role_unauthorized, concurrency_exceeded
    principal_quota_remaining: int = 0
    principal_concurrency_current: int = 0


@dataclass
class RateLimit:
    """Record of rate limiting"""
    timestamp: str
    command: str
    principal_id: str
    limit_type: str  # concurrency_limit, quota_limit, per_second_limit
    limited_at_value: int
    would_have_failed: bool


@dataclass
class LatencyOverhead:
    """Latency impact from policy checks"""
    timestamp: str
    command: str
    validation_overhead_ms: float
    policy_check_overhead_ms: float
    total_overhead_ms: float


# ============================================================================
# Policy Impact Tracker
# ============================================================================

class PolicyImpactTracker:
    """Tracks policy side-effects (denials, rate limits, overhead)"""
    
    def __init__(self):
        self.policy_denials: List[PolicyDenial] = []
        self.rate_limits: List[RateLimit] = []
        self.latency_overhead: List[LatencyOverhead] = []
        
        # Aggregated counts by category
        self.denial_counts = defaultdict(int)
        self.rate_limit_counts = defaultdict(int)
    
    def log_policy_denial(
        self,
        command: str,
        principal_id: str,
        principal_role: str,
        denial_reason: str,
        quota_remaining: int = 0,
        concurrency_current: int = 0
    ) -> None:
        """
        Log a request that would have been denied by policy
        
        Args:
          command: Phase 1 command name
          principal_id: User/tenant ID
          principal_role: User role (admin/user/viewer)
          denial_reason: Why it would be denied
          quota_remaining: For quota denials, remaining quota
          concurrency_current: For concurrency denials, current concurrency
        """
        
        denial = PolicyDenial(
            timestamp=datetime.now().isoformat(),
            command=command,
            principal_id=principal_id,
            principal_role=principal_role,
            denial_reason=denial_reason,
            principal_quota_remaining=quota_remaining,
            principal_concurrency_current=concurrency_current
        )
        
        self.policy_denials.append(denial)
        self.denial_counts[denial_reason] += 1
        
        logger.info(
            f"Policy denial (would have occurred): "
            f"command={command}, principal={principal_id}, "
            f"reason={denial_reason}"
        )
    
    def log_rate_limit(
        self,
        command: str,
        principal_id: str,
        limit_type: str,
        limited_at_value: int,
        would_have_failed: bool = False
    ) -> None:
        """
        Log rate limiting that would have occurred
        
        Args:
          command: Phase 1 command
          principal_id: User/tenant ID
          limit_type: Type of limit (concurrency, quota, per_second)
          limited_at_value: Value at which limit was hit
          would_have_failed: If True, request would have failed (not just delayed)
        """
        
        rate_limit = RateLimit(
            timestamp=datetime.now().isoformat(),
            command=command,
            principal_id=principal_id,
            limit_type=limit_type,
            limited_at_value=limited_at_value,
            would_have_failed=would_have_failed
        )
        
        self.rate_limits.append(rate_limit)
        self.rate_limit_counts[limit_type] += 1
        
        logger.info(
            f"Rate limit: command={command}, principal={principal_id}, "
            f"type={limit_type}, value={limited_at_value}, "
            f"would_fail={would_have_failed}"
        )
    
    def log_latency_overhead(
        self,
        command: str,
        validation_ms: float,
        policy_check_ms: float
    ) -> None:
        """
        Log latency overhead from policy checks
        
        Args:
          command: Phase 1 command
          validation_ms: Time spent on parameter validation
          policy_check_ms: Time spent on policy enforcement
        """
        
        overhead = LatencyOverhead(
            timestamp=datetime.now().isoformat(),
            command=command,
            validation_overhead_ms=validation_ms,
            policy_check_overhead_ms=policy_check_ms,
            total_overhead_ms=validation_ms + policy_check_ms
        )
        
        self.latency_overhead.append(overhead)
    
    def get_policy_report(self) -> Dict[str, Any]:
        """Generate policy impact summary report"""
        
        # Calculate latency stats
        if self.latency_overhead:
            latency_values = [o.total_overhead_ms for o in self.latency_overhead]
            latency_stats = {
                "samples": len(latency_values),
                "mean_ms": mean(latency_values),
                "stdev_ms": stdev(latency_values) if len(latency_values) > 1 else 0,
                "min_ms": min(latency_values),
                "max_ms": max(latency_values),
                "p95_ms": sorted(latency_values)[int(len(latency_values) * 0.95)] if latency_values else 0,
            }
        else:
            latency_stats = {
                "samples": 0,
                "mean_ms": 0,
                "stdev_ms": 0,
                "min_ms": 0,
                "max_ms": 0,
                "p95_ms": 0,
            }
        
        return {
            "timestamp": datetime.now().isoformat(),
            "policy_denials": {
                "total": len(self.policy_denials),
                "by_reason": dict(self.denial_counts)
            },
            "rate_limits": {
                "total": len(self.rate_limits),
                "by_type": dict(self.rate_limit_counts),
                "would_have_failed": sum(1 for r in self.rate_limits if r.would_have_failed)
            },
            "latency_overhead": latency_stats,
            "assessment": self._assess_impact()
        }
    
    def _assess_impact(self) -> str:
        """Generate assessment of policy impact"""
        
        denial_count = len(self.policy_denials)
        rate_limit_count = len(self.rate_limits)
        failed_rate_limits = sum(1 for r in self.rate_limits if r.would_have_failed)
        
        if denial_count == 0 and failed_rate_limits == 0:
            return "No policy impact - safe to enforce"
        
        if denial_count > 100 or failed_rate_limits > 50:
            return "ALERT: High policy impact - review thresholds"
        
        if denial_count > 10 or failed_rate_limits > 10:
            return "Moderate policy impact - monitor closely"
        
        return "Low policy impact - acceptable"
    
    def get_denial_details(self) -> List[Dict[str, Any]]:
        """Get detailed list of all denials"""
        return [asdict(d) for d in self.policy_denials]
    
    def get_rate_limit_details(self) -> List[Dict[str, Any]]:
        """Get detailed list of all rate limits"""
        return [asdict(r) for r in self.rate_limits]
    
    def get_commands_with_highest_impact(self, limit: int = 5) -> List[tuple]:
        """Get commands most affected by policy (denials + rate limits)"""
        
        impact_by_command = defaultdict(int)
        
        for denial in self.policy_denials:
            impact_by_command[denial.command] += 1
        
        for rate_limit in self.rate_limits:
            impact_by_command[rate_limit.command] += 1
        
        return sorted(impact_by_command.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    def get_principals_with_most_denials(self, limit: int = 10) -> List[tuple]:
        """Get principals (users/tenants) with most policy denials"""
        
        denial_by_principal = defaultdict(int)
        
        for denial in self.policy_denials:
            denial_by_principal[denial.principal_id] += 1
        
        return sorted(denial_by_principal.items(), key=lambda x: x[1], reverse=True)[:limit]


# ============================================================================
# Integration with Shadow Runner
# ============================================================================

class ShadowRunnerPolicyTracking:
    """
    Mixin for ShadowRunner to track policy impacts
    
    Use in ShadowRunner.run_shadow():
      tracker = PolicyImpactTracker()
      
      # During comparison
      if would_be_denied:
          tracker.log_policy_denial(...)
      
      # Log overhead
      tracker.log_latency_overhead(
          validation_ms=time_validation,
          policy_check_ms=time_policy_check
      )
    """
    
    pass


# ============================================================================
# Metrics Export
# ============================================================================

def export_policy_impact_to_metrics(
    tracker: PolicyImpactTracker,
    metrics_registry
) -> None:
    """Export policy impact data to metrics system"""
    
    report = tracker.get_policy_report()
    
    # Record metrics
    metrics_registry.gauge(
        "phase1_policy_denials_total",
        report["policy_denials"]["total"]
    )
    metrics_registry.gauge(
        "phase1_rate_limits_total",
        report["rate_limits"]["total"]
    )
    metrics_registry.gauge(
        "phase1_latency_overhead_mean_ms",
        report["latency_overhead"]["mean_ms"]
    )
    
    # Record by denial reason
    for reason, count in report["policy_denials"]["by_reason"].items():
        metrics_registry.gauge(
            f"phase1_policy_denial_{reason}",
            count
        )
    
    # Record by rate limit type
    for limit_type, count in report["rate_limits"]["by_type"].items():
        metrics_registry.gauge(
            f"phase1_rate_limit_{limit_type}",
            count
        )


# ============================================================================
# Report Generation
# ============================================================================

def generate_policy_impact_report(
    tracker: PolicyImpactTracker,
    output_file: str = "_PHASE1_POLICY_IMPACT_REPORT.json"
) -> str:
    """Generate and save policy impact report"""
    
    import json
    
    report = {
        "summary": tracker.get_policy_report(),
        "highest_impact_commands": tracker.get_commands_with_highest_impact(),
        "principals_with_most_denials": tracker.get_principals_with_most_denials(),
        "denial_details": tracker.get_denial_details()[:100],  # Last 100
        "rate_limit_details": tracker.get_rate_limit_details()[:100],
    }
    
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)
    
    logger.info(f"Policy impact report saved to {output_file}")
    
    return output_file


# ============================================================================
# Example Usage
# ============================================================================

if __name__ == "__main__":
    tracker = PolicyImpactTracker()
    
    # Simulate some denials
    tracker.log_policy_denial(
        "run_burp_scan",
        "user_123",
        "user",
        "quota_exceeded",
        quota_remaining=0
    )
    
    tracker.log_policy_denial(
        "list_targets",
        "user_456",
        "viewer",
        "role_unauthorized"
    )
    
    # Simulate latency overhead
    tracker.log_latency_overhead("run_burp_scan", 5.2, 8.1)
    tracker.log_latency_overhead("list_targets", 2.1, 3.5)
    
    # Generate report
    report = tracker.get_policy_report()
    print("\n" + "="*60)
    print("POLICY IMPACT REPORT")
    print("="*60)
    print(f"Denials: {report['policy_denials']['total']}")
    print(f"Rate Limits: {report['rate_limits']['total']}")
    print(f"Mean Latency Overhead: {report['latency_overhead']['mean_ms']:.1f}ms")
    print(f"Assessment: {report['assessment']}")
