"""Phase 1 reconnection smoke tests for package boot wiring."""

from __future__ import annotations

import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "CaseCrack"))


def test_exploit_chains_exports_manual_audit_engine_symbols() -> None:
    from CaseCrack.tools.burp_enterprise.exploit_chains import (
        DecisionSnapshot,
        InterestType,
        WalkedDecision,
        traced_run,
    )

    assert DecisionSnapshot is not None
    assert InterestType is not None
    assert WalkedDecision is not None
    assert callable(traced_run)


def test_database_boot_path_exports_data_migration() -> None:
    from CaseCrack.tools.burp_enterprise.database import (
        MigrationEngine,
        MigrationReport,
        TableMigrationResult,
    )

    assert MigrationEngine is not None
    assert MigrationReport is not None
    assert TableMigrationResult is not None


def test_core_infra_boot_path_exports_chaos_v2() -> None:
    from CaseCrack.tools.burp_enterprise.core_infra import (
        ChaosConfig,
        ChaosEngine,
        FaultOutcome,
        FaultType,
    )

    assert ChaosConfig is not None
    assert ChaosEngine is not None
    assert FaultOutcome is not None
    assert FaultType is not None


def test_cli_boot_path_exports_daemon_symbols() -> None:
    from CaseCrack.tools.burp_enterprise.cli import StreamingWriter, run_daemon

    assert StreamingWriter is not None
    assert callable(run_daemon)


def test_discovery_and_intel_boot_exports() -> None:
    from CaseCrack.tools.burp_enterprise.discovery_pkg import ExternalToolResult
    from CaseCrack.tools.burp_enterprise.intel import BaseGitHubClient

    assert ExternalToolResult is not None
    assert BaseGitHubClient is not None


def test_agents_boot_path_exports_role_registry() -> None:
    from CaseCrack.tools.burp_enterprise.agents import RoleID, RoleRegistry, get_registry

    assert RoleID is not None
    assert RoleRegistry is not None
    assert callable(get_registry)


def test_tool_wrappers_boot_path_exports_evidence_utilities() -> None:
    from CaseCrack.tools.burp_enterprise.tool_wrappers import (
        bundle_evidence,
        collect_run_config,
        collect_tool_versions,
    )

    assert callable(bundle_evidence)
    assert callable(collect_run_config)
    assert callable(collect_tool_versions)
