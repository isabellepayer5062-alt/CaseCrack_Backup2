#!/usr/bin/env python3
"""
Analyze Passthrough Command Usage Metrics
==========================================

Extracts and ranks passthrough commands by:
- Volume (total calls)
- Tenant count (unique tenants per command)
- Error rate (failures vs total)

Categorizes into:
- Core workflows (80%+ volume, <5% error)
- Edge/debug (10-20% volume, variable error)
- Dead/rare (<5% volume, defer or risk)

Run standalone or import metrics from running MCP server.
"""

import json
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Add workspace to path
WORKSPACE_ROOT = Path(__file__).parent
sys.path.insert(0, str(WORKSPACE_ROOT / "CaseCrack" / "tools" / "burp_enterprise" / "mcp"))

try:
    from mcp_metrics import MCPMetrics
except ImportError as e:
    print(f"[!] Failed to import mcp_metrics: {e}")
    print("[!] Ensure you're running from workspace root with .venv activated")
    sys.exit(1)


class PassthroughAnalyzer:
    """Analyze passthrough command usage patterns."""

    def __init__(self, metrics: MCPMetrics):
        self.metrics = metrics
        self.timestamp = time.time()
        
    def extract_command_stats(self) -> Dict[str, Dict[str, Any]]:
        """
        Extract usage statistics for each passthrough command.
        
        Returns:
            Dict mapping command_name -> {
                volume: total_calls,
                tenant_count: unique_tenants,
                tenants: [list of tenant_ids],
                error_rate: (failed / total),
                failed_count: count_failures,
                success_count: count_successes
            }
        """
        stats = defaultdict(lambda: {
            "volume": 0,
            "tenant_set": set(),
            "failed_count": 0,
            "success_count": 0,
        })
        
        # Extract passthrough calls by command
        with self.metrics._lock:
            for (tenant_id, command), count in self.metrics._passthrough_calls_total.items():
                if command not in stats:
                    stats[command] = {
                        "volume": 0,
                        "tenant_set": set(),
                        "failed_count": 0,
                        "success_count": 0,
                    }
                stats[command]["volume"] += count
                stats[command]["tenant_set"].add(tenant_id)
                
            # Estimate error rates from request outcomes
            # Count failures per tenant (request_id, outcome) tuple
            for (tenant_id, _request_id, outcome), count in self.metrics._request_outcomes.items():
                if outcome in ("failed", "error", "rate_limited", "invalid"):
                    # Estimate: distribute failures across passthrough commands proportionally
                    # For now, use a simpler approach: sum failures per tenant
                    if outcome == "failed" or outcome == "error":
                        for cmd in stats:
                            if tenant_id in stats[cmd]["tenant_set"]:
                                # Roughly estimate proportion
                                pass
        
        # Convert to final format
        result = {}
        for command, data in stats.items():
            tenant_list = sorted(list(data["tenant_set"]))
            tenant_count = len(tenant_list)
            
            # Simplified error rate: use outcome totals
            total_calls = data["volume"]
            # Estimate error count from request_outcomes per tenant using this command
            error_count = 0
            with self.metrics._lock:
                for (t_id, _, outcome), count in self.metrics._request_outcomes.items():
                    if t_id in data["tenant_set"] and outcome in ("failed", "error"):
                        error_count += count
            
            error_rate = (error_count / total_calls) if total_calls > 0 else 0.0
            
            result[command] = {
                "volume": total_calls,
                "tenant_count": tenant_count,
                "tenants": tenant_list,
                "error_rate": error_rate,
                "failed_count": error_count,
                "success_count": total_calls - error_count,
            }
        
        return result

    def rank_by_metric(
        self,
        stats: Dict[str, Dict[str, Any]],
        metric: str,
        top_n: int = 10,
    ) -> List[Tuple[str, float]]:
        """Rank commands by a specific metric."""
        if not stats:
            return []
        
        ranked = sorted(
            [(cmd, data[metric]) for cmd, data in stats.items()],
            key=lambda x: x[1],
            reverse=True
        )
        return ranked[:top_n]

    def categorize_commands(
        self,
        stats: Dict[str, Dict[str, Any]],
    ) -> Dict[str, List[str]]:
        """
        Categorize commands into:
        - core: High volume, low error, many tenants
        - edge: Medium volume or higher error
        - dead: Low volume, rare usage
        """
        if not stats:
            return {"core": [], "edge": [], "dead": []}
        
        # Calculate percentiles
        volumes = [data["volume"] for data in stats.values()]
        error_rates = [data["error_rate"] for data in stats.values()]
        tenant_counts = [data["tenant_count"] for data in stats.values()]
        
        total_volume = sum(volumes)
        cumulative_pct = 0.0
        
        categories = {"core": [], "edge": [], "dead": []}
        volume_ranked = sorted(stats.items(), key=lambda x: x[1]["volume"], reverse=True)
        
        for cmd, data in volume_ranked:
            pct_of_total = (data["volume"] / total_volume) if total_volume > 0 else 0.0
            cumulative_pct += pct_of_total
            
            # Core: 80% cumulative volume, <5% error, used by multiple tenants
            if cumulative_pct <= 0.80 and data["error_rate"] < 0.05 and data["tenant_count"] >= 2:
                categories["core"].append(cmd)
            # Dead: <5% individual volume
            elif pct_of_total < 0.05:
                categories["dead"].append(cmd)
            # Edge: everything else
            else:
                categories["edge"].append(cmd)
        
        return categories

    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive analysis report."""
        stats = self.extract_command_stats()
        
        if not stats:
            return {
                "timestamp": self.timestamp,
                "message": "No passthrough command metrics available",
                "recommendation": "Run some passthrough commands to collect metrics",
            }
        
        # Rankings
        by_volume = self.rank_by_metric(stats, "volume", top_n=10)
        by_tenant_count = self.rank_by_metric(stats, "tenant_count", top_n=10)
        by_error_rate = sorted(
            [(cmd, data["error_rate"]) for cmd, data in stats.items()],
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        # Categories
        categories = self.categorize_commands(stats)
        
        # Summary
        total_commands = len(stats)
        total_volume = sum(data["volume"] for data in stats.values())
        avg_error_rate = sum(data["error_rate"] for data in stats.values()) / total_commands if total_commands > 0 else 0.0
        
        # Engagement matrix
        single_tenant_commands = [cmd for cmd, data in stats.items() if data["tenant_count"] == 1]
        multi_tenant_commands = [cmd for cmd, data in stats.items() if data["tenant_count"] > 1]
        
        return {
            "timestamp": self.timestamp,
            "summary": {
                "total_commands": total_commands,
                "total_volume": total_volume,
                "avg_error_rate": round(avg_error_rate, 4),
                "single_tenant_commands": len(single_tenant_commands),
                "multi_tenant_commands": len(multi_tenant_commands),
            },
            "rankings": {
                "by_volume": [
                    {
                        "rank": idx + 1,
                        "command": cmd,
                        "volume": volume,
                        "pct_of_total": round(100.0 * volume / total_volume, 2) if total_volume > 0 else 0.0,
                        "error_rate": round(stats[cmd]["error_rate"], 4),
                        "tenant_count": stats[cmd]["tenant_count"],
                    }
                    for idx, (cmd, volume) in enumerate(by_volume)
                ],
                "by_tenant_count": [
                    {
                        "rank": idx + 1,
                        "command": cmd,
                        "tenant_count": count,
                        "volume": stats[cmd]["volume"],
                        "tenants": stats[cmd]["tenants"],
                        "error_rate": round(stats[cmd]["error_rate"], 4),
                    }
                    for idx, (cmd, count) in enumerate(by_tenant_count)
                ],
                "by_error_rate": [
                    {
                        "rank": idx + 1,
                        "command": cmd,
                        "error_rate": round(rate, 4),
                        "failed_count": stats[cmd]["failed_count"],
                        "success_count": stats[cmd]["success_count"],
                        "volume": stats[cmd]["volume"],
                        "tenant_count": stats[cmd]["tenant_count"],
                    }
                    for idx, (cmd, rate) in enumerate(by_error_rate)
                ],
            },
            "categories": {
                "core_workflows": {
                    "count": len(categories["core"]),
                    "description": "High volume, low error (<5%), multi-tenant → MUST CONVERT FIRST",
                    "commands": sorted(categories["core"]),
                    "stats": [
                        {
                            "command": cmd,
                            "volume": stats[cmd]["volume"],
                            "pct_of_total": round(100.0 * stats[cmd]["volume"] / total_volume, 2) if total_volume > 0 else 0.0,
                            "error_rate": round(stats[cmd]["error_rate"], 4),
                            "tenant_count": stats[cmd]["tenant_count"],
                        }
                        for cmd in sorted(categories["core"])
                    ],
                },
                "edge_debug": {
                    "count": len(categories["edge"]),
                    "description": "Medium volume, variable error, or higher risk → REVIEW BEFORE CONVERT",
                    "commands": sorted(categories["edge"]),
                    "stats": [
                        {
                            "command": cmd,
                            "volume": stats[cmd]["volume"],
                            "pct_of_total": round(100.0 * stats[cmd]["volume"] / total_volume, 2) if total_volume > 0 else 0.0,
                            "error_rate": round(stats[cmd]["error_rate"], 4),
                            "tenant_count": stats[cmd]["tenant_count"],
                        }
                        for cmd in sorted(categories["edge"])
                    ],
                },
                "dead_rare": {
                    "count": len(categories["dead"]),
                    "description": "Low volume (<5%), rare or experimental → DEFER OR DOCUMENT",
                    "commands": sorted(categories["dead"]),
                    "stats": [
                        {
                            "command": cmd,
                            "volume": stats[cmd]["volume"],
                            "pct_of_total": round(100.0 * stats[cmd]["volume"] / total_volume, 2) if total_volume > 0 else 0.0,
                            "error_rate": round(stats[cmd]["error_rate"], 4),
                            "tenant_count": stats[cmd]["tenant_count"],
                        }
                        for cmd in sorted(categories["dead"])
                    ],
                },
            },
            "roadmap": self._generate_roadmap(categories, stats, total_volume),
        }

    def _generate_roadmap(
        self,
        categories: Dict[str, List[str]],
        stats: Dict[str, Dict[str, Any]],
        total_volume: float,
    ) -> Dict[str, Any]:
        """Generate migration/hardening roadmap."""
        core = categories["core"]
        edge = categories["edge"]
        dead = categories["dead"]
        
        core_volume = sum(stats[cmd]["volume"] for cmd in core)
        edge_volume = sum(stats[cmd]["volume"] for cmd in edge)
        dead_volume = sum(stats[cmd]["volume"] for cmd in dead)
        
        return {
            "phase_1_high_priority": {
                "title": "Core Workflows (80%+ of traffic)",
                "commands": sorted(core),
                "volume": core_volume,
                "pct_of_total": round(100.0 * core_volume / total_volume, 2) if total_volume > 0 else 0.0,
                "action": "Complete MCP integration + hardening, test thoroughly",
                "risk": "LOW (high coverage, stable patterns)",
                "effort": "HIGH (most commands, but well-defined)",
            },
            "phase_2_medium_priority": {
                "title": "Edge/Debug Commands (10-20% of traffic)",
                "commands": sorted(edge),
                "volume": edge_volume,
                "pct_of_total": round(100.0 * edge_volume / total_volume, 2) if total_volume > 0 else 0.0,
                "action": "Audit for errors, plan targeted hardening",
                "risk": "MEDIUM (variable error rates, lower volume)",
                "effort": "MEDIUM (fewer commands, but may need investigation)",
            },
            "phase_3_deferred": {
                "title": "Dead/Rare Commands (<5% of traffic)",
                "commands": sorted(dead),
                "volume": dead_volume,
                "pct_of_total": round(100.0 * dead_volume / total_volume, 2) if total_volume > 0 else 0.0,
                "action": "Document as experimental, deprecate if obsolete",
                "risk": "HIGH (unclear patterns, rare usage = less tested)",
                "effort": "LOW (few commands, can defer safely)",
            },
        }


def main():
    """Run analysis and output report."""
    # Create metrics instance and populate with test data
    metrics = MCPMetrics()
    
    # Add sample data for demonstration
    # In production, these would be collected from actual passthrough calls
    sample_commands = {
        "run_burp_scan": 850,      # High volume
        "list_targets": 650,        # High volume
        "get_report": 420,          # Medium-high volume
        "export_findings": 280,     # Medium volume
        "check_status": 190,        # Medium-low volume
        "admin_config": 85,         # Low volume
        "debug_verbose": 32,        # Rare
        "experimental_ml": 8,       # Dead
    }
    
    # Populate passthrough calls
    for cmd, volume in sample_commands.items():
        # Distribute across tenants
        if cmd in ["run_burp_scan", "list_targets", "get_report", "export_findings"]:
            # Multi-tenant commands
            for tenant in ["tenant-a", "tenant-b", "tenant-c"]:
                metrics.record_passthrough_call(tenant_id=tenant, command=cmd)
                metrics.record_passthrough_call(tenant_id=tenant, command=cmd)
        elif cmd in ["check_status", "admin_config"]:
            # Few tenants
            for tenant in ["tenant-a", "tenant-b"]:
                metrics.record_passthrough_call(tenant_id=tenant, command=cmd)
        else:
            # Single tenant or rare
            metrics.record_passthrough_call(tenant_id="tenant-a", command=cmd)
    
    # Populate with realistic volume
    for cmd, volume in sample_commands.items():
        for _ in range(volume - 1):  # -1 because we already did 1-2 records
            tenant = ["tenant-a", "tenant-b", "tenant-c"][hash(cmd + str(_)) % 3]
            metrics.record_passthrough_call(tenant_id=tenant, command=cmd)
    
    # Add some error outcomes
    metrics.record_request(tenant_id="tenant-a", request_id="req-1", outcome="error")
    metrics.record_request(tenant_id="tenant-b", request_id="req-2", outcome="failed")
    metrics.record_request(tenant_id="tenant-c", request_id="req-3", outcome="success")
    
    # Run analysis
    analyzer = PassthroughAnalyzer(metrics)
    report = analyzer.generate_report()
    
    # Output report
    print("\n" + "="*80)
    print("PASSTHROUGH COMMAND USAGE ANALYSIS")
    print("="*80)
    print()
    
    # Summary
    if "message" in report:
        print(f"[i] {report['message']}")
        print(f"    {report.get('recommendation', '')}")
        return
    
    summary = report["summary"]
    print(f"Total Commands Tracked: {summary['total_commands']}")
    print(f"Total Volume: {summary['total_volume']} calls")
    print(f"Avg Error Rate: {summary['avg_error_rate']*100:.2f}%")
    print(f"Single-Tenant Commands: {summary['single_tenant_commands']}")
    print(f"Multi-Tenant Commands: {summary['multi_tenant_commands']}")
    print()
    
    # Top by volume
    print("-" * 80)
    print("TOP 10 COMMANDS BY VOLUME")
    print("-" * 80)
    for item in report["rankings"]["by_volume"]:
        print(f"  #{item['rank']:2d} | {item['command']:30s} | Vol: {item['volume']:5d} ({item['pct_of_total']:5.1f}%) | Err: {item['error_rate']*100:5.1f}% | Tenants: {item['tenant_count']}")
    print()
    
    # Top by tenant count
    print("-" * 80)
    print("TOP 10 COMMANDS BY TENANT COUNT")
    print("-" * 80)
    for item in report["rankings"]["by_tenant_count"]:
        print(f"  #{item['rank']:2d} | {item['command']:30s} | Tenants: {item['tenant_count']:2d} | Vol: {item['volume']:5d} | Err: {item['error_rate']*100:5.1f}%")
    print()
    
    # Top by error rate
    print("-" * 80)
    print("TOP 10 COMMANDS BY ERROR RATE")
    print("-" * 80)
    for item in report["rankings"]["by_error_rate"]:
        print(f"  #{item['rank']:2d} | {item['command']:30s} | Err: {item['error_rate']*100:5.1f}% | Fail: {item['failed_count']:3d}/{item['volume']:5d} | Tenants: {item['tenant_count']}")
    print()
    
    # Categories
    print("-" * 80)
    print("COMMAND CATEGORIZATION")
    print("-" * 80)
    
    for category_key in ["core_workflows", "edge_debug", "dead_rare"]:
        cat = report["categories"][category_key]
        print()
        print(f"[{category_key.upper()}]")
        print(f"  Description: {cat['description']}")
        print(f"  Count: {cat['count']} commands")
        print(f"  Commands: {', '.join(cat['commands']) if cat['commands'] else 'None'}")
        if cat.get("stats"):
            for stat in cat["stats"][:5]:  # Show top 5
                print(f"    - {stat['command']:25s} | Vol: {stat['volume']:5d} ({stat['pct_of_total']:5.1f}%) | Err: {stat['error_rate']*100:5.1f}%")
    print()
    
    # Roadmap
    print("-" * 80)
    print("MIGRATION/HARDENING ROADMAP")
    print("-" * 80)
    for phase_key in ["phase_1_high_priority", "phase_2_medium_priority", "phase_3_deferred"]:
        phase = report["roadmap"][phase_key]
        print()
        print(f"[{phase['title'].upper()}]")
        print(f"  Commands: {len(phase['commands'])} ({phase['pct_of_total']:.1f}% of traffic)")
        print(f"  Volume: {phase['volume']} calls")
        print(f"  Risk: {phase['risk']}")
        print(f"  Effort: {phase['effort']}")
        print(f"  Action: {phase['action']}")
        print(f"  List: {', '.join(phase['commands']) if phase['commands'] else 'None'}")
    print()
    
    # JSON output for machine processing
    output_file = Path(__file__).parent / "_passthrough_analysis_report.json"
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\n[✓] Report saved to: {output_file}")
    print()


if __name__ == "__main__":
    main()
