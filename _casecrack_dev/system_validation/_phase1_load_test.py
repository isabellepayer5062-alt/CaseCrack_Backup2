#!/usr/bin/env python3
"""
Phase 1 Load Testing & Latency Analysis
========================================

Validates that latency overhead doesn't compound under real-world concurrency.

Problem: +5-12% per command looks fine in isolation, but validation + policy + 
shadow + execution can stack under concurrent load, causing:
- Queue buildup
- p95/p99 latency spikes
- Perceived degradation despite healthy error rates

This tool:
1. Simulates concurrent requests (10-100 in flight)
2. Measures latency distribution (min/avg/p50/p95/p99)
3. Compares passthrough vs typed latencies
4. Detects queue buildup patterns
5. Identifies safe concurrency ceiling

Usage:
  from _phase1_load_test import LoadTestHarness
  
  harness = LoadTestHarness(mcp_server)
  
  # Run load test
  report = harness.run_load_test(
    command="run_burp_scan",
    concurrency_levels=[10, 25, 50, 100],
    requests_per_level=100,
    test_timeout_seconds=300
  )
  
  # Check results
  if report['p99_latency_ms'] > 2000:  # 2 second p99 is bad
    logger.error("Latency spike detected!")
"""

import asyncio
import time
import logging
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field, asdict
from statistics import mean, median, stdev
from collections import defaultdict
import numpy as np

logger = logging.getLogger(__name__)


# ============================================================================
# Data Structures
# ============================================================================

@dataclass
class LatencyMetrics:
    """Latency statistics"""
    min_ms: float
    max_ms: float
    mean_ms: float
    median_ms: float
    p95_ms: float
    p99_ms: float
    stddev_ms: float
    samples: int


@dataclass
class ConcurrencyLevel:
    """Results for a single concurrency level"""
    level: int  # Number of concurrent requests
    passthrough_latency: LatencyMetrics
    typed_latency: LatencyMetrics
    overhead_pct: float  # (typed - passthrough) / passthrough * 100
    queue_buildup: bool  # Did latency spike with concurrency?
    errors_passthrough: int
    errors_typed: int
    requests: int


@dataclass
class LoadTestReport:
    """Full load test results"""
    command: str
    timestamp: str
    concurrency_levels: List[ConcurrencyLevel] = field(default_factory=list)
    safe_concurrency_ceiling: int = 0
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "timestamp": self.timestamp,
            "concurrency_levels": [asdict(level) for level in self.concurrency_levels],
            "safe_concurrency_ceiling": self.safe_concurrency_ceiling,
            "recommendations": self.recommendations
        }


# ============================================================================
# Load Test Harness
# ============================================================================

class LoadTestHarness:
    """Run load tests to validate latency under concurrency"""
    
    def __init__(self, mcp_server):
        self.mcp_server = mcp_server
        self.latency_threshold_p99_ms = 2000  # Alert if p99 > 2sec
        self.overhead_threshold_pct = 25  # Alert if overhead > 25%
    
    async def run_load_test(
        self,
        command: str,
        concurrency_levels: List[int] = None,
        requests_per_level: int = 100,
        test_timeout_seconds: int = 300,
        test_params: Optional[Dict[str, Any]] = None
    ) -> LoadTestReport:
        """
        Run load test across concurrency levels
        
        Args:
          command: Command to test (run_burp_scan, list_targets, get_report)
          concurrency_levels: Levels to test (default: [10, 25, 50, 100])
          requests_per_level: Requests to send at each level
          test_timeout_seconds: Max time per level
          test_params: Parameters to use (sensible defaults if None)
        
        Returns:
          LoadTestReport with detailed latency analysis
        """
        
        from datetime import datetime
        
        if concurrency_levels is None:
            concurrency_levels = [10, 25, 50, 100]
        
        if test_params is None:
            test_params = self._get_default_test_params(command)
        
        report = LoadTestReport(
            command=command,
            timestamp=datetime.now().isoformat()
        )
        
        # Test each concurrency level
        for level in concurrency_levels:
            logger.info(f"Testing {command} at concurrency={level}...")
            
            try:
                result = await asyncio.wait_for(
                    self._test_concurrency_level(
                        command,
                        level,
                        requests_per_level,
                        test_params
                    ),
                    timeout=test_timeout_seconds
                )
                report.concurrency_levels.append(result)
                
                # Check for issues
                if result.queue_buildup:
                    logger.warning(f"Queue buildup detected at {level} concurrent")
                if result.overhead_pct > self.overhead_threshold_pct:
                    logger.warning(f"Overhead {result.overhead_pct:.1f}% exceeds threshold")
                if result.typed_latency.p99_ms > self.latency_threshold_p99_ms:
                    logger.warning(f"p99 latency {result.typed_latency.p99_ms:.0f}ms exceeds {self.latency_threshold_p99_ms}ms")
            
            except asyncio.TimeoutError:
                logger.error(f"Load test timeout at concurrency={level}")
                break
        
        # Analyze and generate recommendations
        self._analyze_results(report)
        
        return report
    
    async def _test_concurrency_level(
        self,
        command: str,
        concurrency: int,
        requests: int,
        params: Dict[str, Any]
    ) -> ConcurrencyLevel:
        """Run requests at specific concurrency level"""
        
        # Create semaphore to limit concurrency
        semaphore = asyncio.Semaphore(concurrency)
        
        async def bounded_request(impl_type: str):
            """Execute single request with semaphore"""
            async with semaphore:
                start = time.monotonic()
                try:
                    if impl_type == "passthrough":
                        # Call passthrough implementation
                        result = await self._execute_passthrough(command, params)
                    else:
                        # Call typed implementation
                        result = await self._execute_typed(command, params)
                    
                    latency_ms = (time.monotonic() - start) * 1000
                    return ("ok", latency_ms)
                except Exception as e:
                    latency_ms = (time.monotonic() - start) * 1000
                    return ("error", latency_ms)
        
        # Run requests in parallel
        tasks_pt = [bounded_request("passthrough") for _ in range(requests)]
        tasks_typed = [bounded_request("typed") for _ in range(requests)]
        
        pt_results = await asyncio.gather(*tasks_pt)
        typed_results = await asyncio.gather(*tasks_typed)
        
        # Analyze results
        pt_latencies = [lat for status, lat in pt_results if status == "ok"]
        typed_latencies = [lat for status, lat in typed_results if status == "ok"]
        
        pt_errors = sum(1 for status, _ in pt_results if status == "error")
        typed_errors = sum(1 for status, _ in typed_results if status == "error")
        
        # Calculate metrics
        pt_metrics = self._calc_metrics(pt_latencies)
        typed_metrics = self._calc_metrics(typed_latencies)
        
        # Detect queue buildup (p99 latency increases with concurrency)
        buildup = typed_metrics.p99_ms > (pt_metrics.p99_ms * 1.5)  # >50% increase
        
        # Calculate overhead
        overhead_pct = ((typed_metrics.mean_ms - pt_metrics.mean_ms) / pt_metrics.mean_ms * 100) \
                      if pt_metrics.mean_ms > 0 else 0
        
        return ConcurrencyLevel(
            level=concurrency,
            passthrough_latency=pt_metrics,
            typed_latency=typed_metrics,
            overhead_pct=overhead_pct,
            queue_buildup=buildup,
            errors_passthrough=pt_errors,
            errors_typed=typed_errors,
            requests=requests
        )
    
    def _calc_metrics(self, latencies: List[float]) -> LatencyMetrics:
        """Calculate latency statistics"""
        if not latencies:
            return LatencyMetrics(0, 0, 0, 0, 0, 0, 0, 0)
        
        sorted_lat = sorted(latencies)
        
        return LatencyMetrics(
            min_ms=min(sorted_lat),
            max_ms=max(sorted_lat),
            mean_ms=mean(sorted_lat),
            median_ms=median(sorted_lat),
            p95_ms=np.percentile(sorted_lat, 95),
            p99_ms=np.percentile(sorted_lat, 99),
            stddev_ms=stdev(sorted_lat) if len(sorted_lat) > 1 else 0,
            samples=len(sorted_lat)
        )
    
    def _analyze_results(self, report: LoadTestReport) -> None:
        """Generate recommendations from results"""
        
        if not report.concurrency_levels:
            report.recommendations.append("⚠ No load test results")
            return
        
        # Find safe ceiling (before queue buildup)
        safe_ceiling = 100
        for level in report.concurrency_levels:
            if level.queue_buildup or level.typed_latency.p99_ms > self.latency_threshold_p99_ms:
                safe_ceiling = level.level - 10
                break
        
        report.safe_concurrency_ceiling = max(10, safe_ceiling)
        
        # Check latencies
        max_p99 = max(level.typed_latency.p99_ms for level in report.concurrency_levels)
        if max_p99 > self.latency_threshold_p99_ms:
            report.recommendations.append(
                f"⚠ p99 latency {max_p99:.0f}ms exceeds {self.latency_threshold_p99_ms}ms threshold"
            )
        
        # Check overhead
        avg_overhead = mean(level.overhead_pct for level in report.concurrency_levels)
        if avg_overhead > self.overhead_threshold_pct:
            report.recommendations.append(
                f"⚠ Overhead {avg_overhead:.1f}% exceeds {self.overhead_threshold_pct}% threshold"
            )
        
        # Check errors
        total_typed_errors = sum(level.errors_typed for level in report.concurrency_levels)
        if total_typed_errors > 0:
            report.recommendations.append(
                f"⚠ {total_typed_errors} errors in typed implementation"
            )
        
        # Safe recommendation
        if avg_overhead <= self.overhead_threshold_pct and max_p99 <= self.latency_threshold_p99_ms:
            report.recommendations.append(
                f"✓ Safe to proceed: overhead {avg_overhead:.1f}%, p99 {max_p99:.0f}ms, "
                f"ceiling {report.safe_concurrency_ceiling} concurrent"
            )
    
    # Placeholder implementations
    async def _execute_passthrough(self, command: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute passthrough implementation"""
        await asyncio.sleep(0.05)  # Simulate work
        return {"status": "ok"}
    
    async def _execute_typed(self, command: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute typed implementation"""
        await asyncio.sleep(0.07)  # Simulate slightly slower work
        return {"status": "ok"}
    
    @staticmethod
    def _get_default_test_params(command: str) -> Dict[str, Any]:
        """Get sensible test parameters by command"""
        if command == "run_burp_scan":
            return {"target": "example.com", "scan_profile": "quick"}
        elif command == "list_targets":
            return {"limit": 100}
        elif command == "get_report":
            return {"report_id": "550e8400-e29b-41d4-a716-446655440000"}
        return {}


# ============================================================================
# Export
# ============================================================================

__all__ = [
    "LoadTestHarness",
    "LoadTestReport",
    "ConcurrencyLevel",
    "LatencyMetrics",
]


if __name__ == "__main__":
    # Demo
    import asyncio
    
    async def demo():
        harness = LoadTestHarness(mcp_server=None)
        
        # Note: This would need a real mcp_server for actual testing
        # For demo purposes, we just show the structure
        
        print("Load test harness ready.")
        print("To run actual load test:")
        print("  report = await harness.run_load_test('run_burp_scan')")
        print(f"  safe_ceiling: {report.safe_concurrency_ceiling}")
        print(f"  recommendations: {report.recommendations}")
    
    # asyncio.run(demo())
