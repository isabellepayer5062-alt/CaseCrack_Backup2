#!/usr/bin/env python3
"""
Quick Reference: Using PassthroughAnalyzer
===========================================

One-minute guide to extracting command rankings.
"""

# ============================================================================
# USAGE 1: STANDALONE (Demo/Testing)
# ============================================================================

if __name__ == "__main__":
    from _analyze_passthrough_metrics import PassthroughAnalyzer
    from mcp_metrics import MCPMetrics
    
    # Create metrics + populate with test data
    metrics = MCPMetrics()
    metrics.record_passthrough_call(tenant_id="tenant-a", command="run_scan")
    metrics.record_passthrough_call(tenant_id="tenant-b", command="run_scan")
    metrics.record_passthrough_call(tenant_id="tenant-a", command="get_report")
    # ... (add more calls)
    
    # Analyze
    analyzer = PassthroughAnalyzer(metrics)
    report = analyzer.generate_report()
    
    # Print summary
    print(f"Total commands: {report['summary']['total_commands']}")
    print(f"Total volume: {report['summary']['total_volume']}")
    
    # Get top commands by volume
    for item in report['rankings']['by_volume'][:5]:
        print(f"  {item['command']:30s} : {item['volume']:5d} ({item['pct_of_total']:5.1f}%)")


# ============================================================================
# USAGE 2: FROM RUNNING MCP SERVER
# ============================================================================

import sys
from pathlib import Path

def analyze_running_server():
    """
    Extract and analyze metrics from a running MCP server instance.
    """
    # Import your MCP server module
    from mcp_server import SecurityMCPServer
    from _analyze_passthrough_metrics import PassthroughAnalyzer
    
    # Get metrics from running server
    mcp_server = SecurityMCPServer()  # Or get from global reference
    metrics = mcp_server._metrics
    
    # Run analysis
    analyzer = PassthroughAnalyzer(metrics)
    report = analyzer.generate_report()
    
    # Output categories
    print("\n=== COMMAND CATEGORIZATION ===\n")
    
    for category_key in ["core_workflows", "edge_debug", "dead_rare"]:
        cat = report["categories"][category_key]
        print(f"{category_key.upper()}:")
        print(f"  Commands: {', '.join(cat['commands'])}")
        print()


# ============================================================================
# USAGE 3: HTTP ENDPOINT (Production)
# ============================================================================

# Add this to your mcp_http_server.py:
"""
from fastapi import FastAPI
from _analyze_passthrough_metrics import PassthroughAnalyzer
from mcp_server import mcp_server

app = FastAPI()

@app.get("/mcp/metrics/passthrough-analysis")
async def get_passthrough_analysis():
    \"\"\"
    Returns ranked passthrough command analysis.
    
    Query Parameters:
        top_n: Number of top commands to return (default: 10)
        window_hours: Analysis window in hours (default: 24)
    
    Response:
        {
            "rankings": { "by_volume": [...], "by_tenant_count": [...], "by_error_rate": [...] },
            "categories": { "core_workflows": [...], "edge_debug": [...], "dead_rare": [...] },
            "roadmap": { "phase_1_high_priority": [...], ... }
        }
    \"\"\"
    analyzer = PassthroughAnalyzer(mcp_server.metrics)
    return analyzer.generate_report()
"""


# ============================================================================
# USAGE 4: SCHEDULED ANALYSIS (Periodic Reporting)
# ============================================================================

def setup_periodic_analysis():
    """
    Run analysis every hour and report results.
    """
    from apscheduler.schedulers.background import BackgroundScheduler
    from mcp_server import mcp_server
    from _analyze_passthrough_metrics import PassthroughAnalyzer
    import json
    from pathlib import Path
    
    def periodic_report():
        analyzer = PassthroughAnalyzer(mcp_server.metrics)
        report = analyzer.generate_report()
        
        # Save to dated file
        timestamp = report['timestamp']
        filename = f"analysis_{timestamp:.0f}.json"
        with open(Path("reports") / filename, "w") as f:
            json.dump(report, f, indent=2)
        
        # Alert on error rate spikes
        core_cats = report['categories']['core_workflows']
        core_commands = core_cats['commands']
        
        for cmd_info in core_cats['stats']:
            if cmd_info['error_rate'] > 0.05:  # 5% error threshold
                print(f"⚠️  ALERT: {cmd_info['command']} error rate is {cmd_info['error_rate']*100:.1f}%")
    
    scheduler = BackgroundScheduler()
    scheduler.add_job(periodic_report, 'interval', hours=1)
    scheduler.start()
    
    return scheduler


# ============================================================================
# USAGE 5: EXTRACT & RANK (Just the Data)
# ============================================================================

def get_ranked_commands(metrics, metric_type: str = "volume", top_n: int = 10):
    """
    Quick function to get ranked commands by any metric.
    
    Args:
        metrics: MCPMetrics instance
        metric_type: "volume", "tenant_count", or "error_rate"
        top_n: How many top commands to return
    
    Returns:
        List of (command_name, metric_value) tuples
    """
    from _analyze_passthrough_metrics import PassthroughAnalyzer
    
    analyzer = PassthroughAnalyzer(metrics)
    stats = analyzer.extract_command_stats()
    
    if metric_type == "volume":
        return analyzer.rank_by_metric(stats, "volume", top_n)
    elif metric_type == "tenant_count":
        return analyzer.rank_by_metric(stats, "tenant_count", top_n)
    elif metric_type == "error_rate":
        return sorted(
            [(cmd, data["error_rate"]) for cmd, data in stats.items()],
            key=lambda x: x[1],
            reverse=True
        )[:top_n]
    else:
        raise ValueError(f"Unknown metric type: {metric_type}")


# Example usage:
if False:  # Set to True to run
    from mcp_metrics import MCPMetrics
    
    # Create demo metrics
    metrics = MCPMetrics()
    for i in range(100):
        metrics.record_passthrough_call(tenant_id="t1", command="cmd_a")
    for i in range(50):
        metrics.record_passthrough_call(tenant_id="t1", command="cmd_b")
    
    # Get rankings
    top_by_volume = get_ranked_commands(metrics, "volume", top_n=5)
    print("Top by volume:")
    for cmd, vol in top_by_volume:
        print(f"  {cmd}: {vol}")


# ============================================================================
# USAGE 6: CATEGORIZATION (3-Bucket Analysis)
# ============================================================================

def categorize_from_metrics(metrics):
    """
    Quickly get 3-tier categorization without full report.
    """
    from _analyze_passthrough_metrics import PassthroughAnalyzer
    
    analyzer = PassthroughAnalyzer(metrics)
    stats = analyzer.extract_command_stats()
    categories = analyzer.categorize_commands(stats)
    
    print(f"Core (Phase 1): {categories['core']}")
    print(f"Edge (Phase 2): {categories['edge']}")
    print(f"Dead (Phase 3): {categories['dead']}")
    
    return categories


# ============================================================================
# USAGE 7: ERROR RATE TRACKING (Trend Monitoring)
# ============================================================================

def track_error_rates_over_time():
    """
    Monitor error rates for core commands over time.
    """
    from mcp_server import mcp_server
    from _analyze_passthrough_metrics import PassthroughAnalyzer
    import json
    from datetime import datetime
    
    # Run analyzer
    analyzer = PassthroughAnalyzer(mcp_server.metrics)
    report = analyzer.generate_report()
    
    # Extract core commands
    core_commands = report['categories']['core_workflows']['commands']
    
    # Get error rates
    error_rates = {}
    for item in report['rankings']['by_error_rate']:
        if item['command'] in core_commands:
            error_rates[item['command']] = item['error_rate']
    
    # Log for trend analysis
    with open("error_rate_history.jsonl", "a") as f:
        f.write(json.dumps({
            "timestamp": datetime.now().isoformat(),
            "error_rates": error_rates,
        }) + "\n")
    
    # Alert if any core command exceeds threshold
    for cmd, rate in error_rates.items():
        if rate > 0.05:
            print(f"⚠️  {cmd}: {rate*100:.1f}% error (threshold: 5%)")


# ============================================================================
# COMMON PATTERNS
# ============================================================================

"""
PATTERN 1: Get top N commands by volume
──────────────────────────────────────
    top_commands = get_ranked_commands(metrics, "volume", top_n=5)
    for cmd, volume in top_commands:
        print(f"{cmd}: {volume} calls")


PATTERN 2: Categorize commands
──────────────────────────────
    categories = categorize_from_metrics(metrics)
    print(f"Must harden: {categories['core']}")
    print(f"Audit first: {categories['edge']}")
    print(f"Defer: {categories['dead']}")


PATTERN 3: Alert on high error rates
─────────────────────────────────────
    stats = analyzer.extract_command_stats()
    for cmd, data in stats.items():
        if data['error_rate'] > 0.10:
            alert(f"Command {cmd} has {data['error_rate']*100:.1f}% errors!")


PATTERN 4: Dashboard integration
────────────────────────────────
    # Call analyzer on schedule
    # Expose via HTTP endpoint
    # Visualize in Grafana/DataDog
    
    GET /mcp/metrics/passthrough-analysis
    → Returns JSON
    → Plot over time


PATTERN 5: Roadmap generation
─────────────────────────────
    report = analyzer.generate_report()
    roadmap = report['roadmap']
    
    for phase in ["phase_1_high_priority", "phase_2_medium_priority", "phase_3_deferred"]:
        p = roadmap[phase]
        print(f"{p['title']}: {p['action']}")
"""

# ============================================================================
# FILES & DOCUMENTATION
# ============================================================================

"""
Key Files:
  _analyze_passthrough_metrics.py      Main analyzer tool (480 LOC)
  _PASSTHROUGH_ANALYSIS_GUIDE.md       Full integration guide
  _PASSTHROUGH_COMMANDS_SUMMARY.txt    Executive summary
  mcp_metrics.py                       Metrics collection (already in server)

Run:
  python _analyze_passthrough_metrics.py          # Standalone demo
  python -m mcp_server                            # Start server w/ metrics
  
Integrate:
  from _analyze_passthrough_metrics import PassthroughAnalyzer
  analyzer = PassthroughAnalyzer(metrics)
  report = analyzer.generate_report()
"""


# ============================================================================
# EXPECTED OUTPUT STRUCTURE
# ============================================================================

SAMPLE_REPORT_STRUCTURE = {
    "timestamp": 1234567890.123,
    "summary": {
        "total_commands": 42,
        "total_volume": 50000,
        "avg_error_rate": 0.025,
        "single_tenant_commands": 5,
        "multi_tenant_commands": 37,
    },
    "rankings": {
        "by_volume": [
            {"rank": 1, "command": "run_scan", "volume": 15000, "pct_of_total": 30.0, "error_rate": 0.001, "tenant_count": 5},
            # ... more items
        ],
        "by_tenant_count": [
            {"rank": 1, "command": "run_scan", "tenant_count": 5, "volume": 15000, "error_rate": 0.001, "tenants": ["t1", "t2", "t3", "t4", "t5"]},
            # ... more items
        ],
        "by_error_rate": [
            {"rank": 1, "command": "experimental_feature", "error_rate": 0.15, "failed_count": 3, "success_count": 17, "volume": 20, "tenant_count": 2},
            # ... more items
        ],
    },
    "categories": {
        "core_workflows": {
            "count": 3,
            "description": "...",
            "commands": ["run_scan", "list_targets", "get_report"],
            "stats": [
                {"command": "run_scan", "volume": 15000, "pct_of_total": 30.0, "error_rate": 0.001, "tenant_count": 5},
                # ... more stats
            ],
        },
        "edge_debug": {
            "count": 5,
            "description": "...",
            "commands": [...],
            "stats": [...],
        },
        "dead_rare": {
            "count": 34,
            "description": "...",
            "commands": [...],
            "stats": [...],
        },
    },
    "roadmap": {
        "phase_1_high_priority": {
            "title": "Core Workflows (80%+ of traffic)",
            "commands": ["run_scan", "list_targets", "get_report"],
            "volume": 38000,
            "pct_of_total": 76.0,
            "risk": "LOW",
            "effort": "HIGH",
            "action": "Complete MCP integration + hardening, test thoroughly",
        },
        "phase_2_medium_priority": {...},
        "phase_3_deferred": {...},
    },
}
