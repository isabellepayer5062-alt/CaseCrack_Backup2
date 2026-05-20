"""Focused validator for Phase 2 MCP tool contract consistency.

Checks that UI-exposed MCP tools are sourced from the shared registry and that
Phase 2 tools define the required contract metadata.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "CaseCrack"))

from tools.burp_enterprise.mcp.mcp_tools import (  # noqa: E402
    MCP_TOOLS,
    get_tool_schema,
    get_ui_exposed_tool_names,
    validate_phase2_contract,
)
from tools.burp_enterprise.recon_dashboard.server import ReconDashboard  # noqa: E402


PHASE2_TOOLS = {
    "run_burp_scan",
    "list_targets",
    "get_report",
    "get_scan_status",
    "stop_scan",
    "manage_tenant_controls",
    "get_tenant_control_status",
    "get_tenant_control_summary",
    "get_recent_tenant_control_events",
}


def main() -> int:
    errors: list[str] = []

    for tool_name in sorted(PHASE2_TOOLS):
        schema = get_tool_schema(tool_name)
        if not schema:
            errors.append(f"missing tool schema: {tool_name}")
            continue
        for problem in validate_phase2_contract(schema):
            errors.append(f"{tool_name}: {problem}")

    ui_expected = get_ui_exposed_tool_names()
    ui_actual = set(ReconDashboard._MCP_ALLOWED_TOOLS)
    if ui_actual != ui_expected:
        errors.append(
            "dashboard allowlist mismatch: "
            f"expected={sorted(ui_expected)} actual={sorted(ui_actual)}"
        )

    tool_names = [tool.name for tool in MCP_TOOLS]
    if len(tool_names) != len(set(tool_names)):
        errors.append("duplicate MCP tool names detected")

    payload = {
        "ok": not errors,
        "validated_tools": sorted(PHASE2_TOOLS),
        "ui_exposed_tools": sorted(ui_expected),
        "errors": errors,
    }
    print(json.dumps(payload, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())