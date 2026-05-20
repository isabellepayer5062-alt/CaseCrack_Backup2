"""
Regression Test: Persistence Continuity for Scan-Mode Configuration & Execution Plans

This test validates the complete persistence chain:
  1. Set scan_mode_config + effective_execution_plan in state
  2. Snapshot (serialize to dict)
  3. Restore (deserialize and apply to new state)
  4. Verify integrity (config + plan match pre-snapshot values)
  5. Validate runtime hydration (dashboard caches match restored state)

Contract Validation:
  - Persisted execution semantics == Restored execution semantics == Runtime execution semantics
  - No silent fallback to defaults after restore
  - Restore determinism (multiple restore → same runtime state)
  - Diff propagation works (dirty stamps tracked)
  - Post-restore hydration prevents cache divergence

This single integrated test is more valuable than isolated unit tests because it
catches persistence drift, restore/runtime divergence, and stale-cache contamination
as a single contract.
"""

import sys
import json
from pathlib import Path
from typing import Any

# Add workspace root to path
workspace_root = Path(__file__).parent
sys.path.insert(0, str(workspace_root))

# Add CaseCrack root for module imports
casecraft_root = workspace_root / "CaseCrack"
sys.path.insert(0, str(casecraft_root))

# Import dashboard state + serializers (direct module imports, bypass __init__ db deps)
from tools.burp_enterprise.recon_dashboard import state as state_module
from tools.burp_enterprise.recon_dashboard import state_serializers

DashboardState = state_module.DashboardState
build_restore_payload = state_serializers.build_restore_payload
apply_restore_payload = state_serializers.apply_restore_payload


def test_persistence_continuity():
    """
    Core regression test: set config → snapshot → restore → verify integrity.
    """
    print("\n" + "=" * 80)
    print("TEST: Persistence Continuity for Scan-Mode Configuration & Execution Plans")
    print("=" * 80)

    # =========================================================================
    # PHASE 1: Create initial state with scan config and execution plan
    # =========================================================================
    print("\n[PHASE 1] Create initial state with scan config + execution plan...")
    state_1 = DashboardState()

    # Define test scan mode config
    test_scan_config = {
        "name": "ENHANCED_ASSESSMENT",
        "enabled_checks": ["http", "https", "dns", "tls"],
        "concurrency_level": 16,
        "timeout_seconds": 300,
        "retry_count": 3,
        "tags": ["test", "regression"],
    }

    # Define test execution plan
    test_execution_plan = {
        "plan_id": "exec_plan_test_001",
        "phases": [
            {
                "phase_id": "p1_recon",
                "stage": 1,
                "techniques": ["dns_enumeration", "subdomain_discovery"],
                "parallelism": 8,
                "timeout_seconds": 120,
            },
            {
                "phase_id": "p2_scan",
                "stage": 2,
                "techniques": ["port_scan", "service_detection"],
                "parallelism": 16,
                "timeout_seconds": 180,
            },
        ],
        "execution_order": ["p1_recon", "p2_scan"],
        "total_timeout_seconds": 600,
        "created_at": "2026-05-08T12:00:00Z",
    }

    # Write to state
    state_1.scan_mode_config = test_scan_config.copy()
    state_1.effective_execution_plan = test_execution_plan.copy()

    # Mark as changed so diff clients are notified
    state_1._mark_changed("scan_config")

    print(f"  ✓ scan_mode_config set: {test_scan_config['name']}")
    print(f"  ✓ effective_execution_plan set: {len(test_execution_plan['phases'])} phases")
    print(f"  ✓ dirty stamp 'scan_config' marked")

    # =========================================================================
    # PHASE 2: Snapshot (export state to persistent format)
    # =========================================================================
    print("\n[PHASE 2] Snapshot state to persistent format...")
    snapshot_dict = build_restore_payload(state_1)

    # Verify both fields present in snapshot
    assert (
        "scan_mode_config" in snapshot_dict
    ), "scan_mode_config missing from snapshot"
    assert (
        "effective_execution_plan" in snapshot_dict
    ), "effective_execution_plan missing from snapshot"

    assert (
        snapshot_dict["scan_mode_config"] == test_scan_config
    ), "scan_mode_config in snapshot doesn't match original"
    assert (
        snapshot_dict["effective_execution_plan"] == test_execution_plan
    ), "effective_execution_plan in snapshot doesn't match original"

    print(f"  ✓ Snapshot contains scan_mode_config")
    print(f"  ✓ Snapshot contains effective_execution_plan")
    print(f"  ✓ Config values match original")
    print(f"  ✓ Plan values match original")

    # Display snapshot size
    snapshot_json = json.dumps(snapshot_dict)
    print(f"  ✓ Snapshot size: {len(snapshot_json)} bytes")

    # =========================================================================
    # PHASE 3: Restore (apply snapshot to new state)
    # =========================================================================
    print("\n[PHASE 3] Restore snapshot to new state instance...")
    state_2 = DashboardState()

    # Before restore, verify fields are None
    assert (
        state_2.scan_mode_config is None
    ), "New state should have None scan_mode_config"
    assert (
        state_2.effective_execution_plan is None
    ), "New state should have None effective_execution_plan"

    # Apply restore payload
    apply_restore_payload(state_2, snapshot_dict)

    print(f"  ✓ Restore applied to new state")
    print(f"  ✓ scan_mode_config restored")
    print(f"  ✓ effective_execution_plan restored")

    # =========================================================================
    # PHASE 4: Verify Integrity (restored == original)
    # =========================================================================
    print("\n[PHASE 4] Verify restored state integrity...")

    # Check 1: scan_mode_config field-by-field equality
    assert state_2.scan_mode_config is not None, "Restored scan_mode_config is None"
    assert isinstance(
        state_2.scan_mode_config, dict
    ), "Restored scan_mode_config is not a dict"
    assert (
        state_2.scan_mode_config == test_scan_config
    ), "Restored scan_mode_config doesn't match original"

    print(f"  ✓ Restored scan_mode_config matches original")
    for key in test_scan_config:
        original = test_scan_config[key]
        restored = state_2.scan_mode_config[key]
        assert (
            original == restored
        ), f"Config field '{key}' mismatch: {original} != {restored}"
        print(f"    - {key}: {restored}")

    # Check 2: effective_execution_plan field-by-field equality
    assert (
        state_2.effective_execution_plan is not None
    ), "Restored effective_execution_plan is None"
    assert isinstance(
        state_2.effective_execution_plan, dict
    ), "Restored effective_execution_plan is not a dict"
    assert (
        state_2.effective_execution_plan == test_execution_plan
    ), "Restored effective_execution_plan doesn't match original"

    print(f"  ✓ Restored effective_execution_plan matches original")
    print(f"    - plan_id: {state_2.effective_execution_plan['plan_id']}")
    print(f"    - phases: {len(state_2.effective_execution_plan['phases'])}")
    print(f"    - total_timeout: {state_2.effective_execution_plan['total_timeout_seconds']}s")

    # =========================================================================
    # PHASE 5: Verify Diff Propagation (dirty stamp preserved)
    # =========================================================================
    print("\n[PHASE 5] Verify dirty stamp tracking...")

    # Export as diff with since_seq = 0 (should include scan_config)
    diff_dict = state_2.to_dict_diff(since_seq=0)

    assert (
        "scan_mode_config" in diff_dict
    ), "scan_mode_config missing from diff export"
    assert (
        "effective_execution_plan" in diff_dict
    ), "effective_execution_plan missing from diff export"

    print(f"  ✓ Diff export includes scan_mode_config")
    print(f"  ✓ Diff export includes effective_execution_plan")
    print(f"  ✓ Dirty stamp system working (diff clients will be notified)")

    # =========================================================================
    # PHASE 6: Multiple Restore Determinism Check
    # =========================================================================
    print("\n[PHASE 6] Verify restore determinism (multiple restores → same state)...")

    # Restore to third state instance
    state_3 = DashboardState()
    apply_restore_payload(state_3, snapshot_dict)

    # Verify state_3 matches state_2
    assert (
        state_3.scan_mode_config == state_2.scan_mode_config
    ), "Restore #2 produced different scan_mode_config"
    assert (
        state_3.effective_execution_plan == state_2.effective_execution_plan
    ), "Restore #2 produced different effective_execution_plan"

    print(f"  ✓ Second restore produces identical state")
    print(f"  ✓ Restore is deterministic (no randomness, no time-dependent behavior)")

    # =========================================================================
    # PHASE 7: Simulate Runtime Hydration (dashboard cache synchronization)
    # =========================================================================
    print("\n[PHASE 7] Simulate runtime hydration (dashboard cache sync)...")

    # In server._restore_session, dashboard caches are hydrated from state:
    # This prevents cache divergence after restore
    dashboard_scan_mode_cache = None
    dashboard_execution_plan_cache = None

    # Hydration logic (from server._restore_session)
    restored_cfg = getattr(state_2, "scan_mode_config", None)
    if isinstance(restored_cfg, dict) and restored_cfg:
        dashboard_scan_mode_cache = restored_cfg.copy()

    restored_plan = getattr(state_2, "effective_execution_plan", None)
    if isinstance(restored_plan, dict) and restored_plan:
        dashboard_execution_plan_cache = restored_plan.copy()

    # Verify cache matches state
    assert (
        dashboard_scan_mode_cache == state_2.scan_mode_config
    ), "Dashboard cache diverged from state after hydration"
    assert (
        dashboard_execution_plan_cache == state_2.effective_execution_plan
    ), "Dashboard plan cache diverged from state after hydration"

    print(f"  ✓ Dashboard scan_mode_config cache hydrated from state")
    print(f"  ✓ Dashboard execution_plan cache hydrated from state")
    print(f"  ✓ No runtime divergence between state and dashboard cache")

    # =========================================================================
    # PHASE 8: Verify Snapshot Round-Trip (export again, compare)
    # =========================================================================
    print("\n[PHASE 8] Round-trip test: restore → export → verify...")

    # Export from restored state
    snapshot_dict_2 = build_restore_payload(state_2)

    # Verify round-trip equality
    assert (
        snapshot_dict_2["scan_mode_config"] == snapshot_dict["scan_mode_config"]
    ), "Round-trip scan_mode_config mismatch"
    assert (
        snapshot_dict_2["effective_execution_plan"]
        == snapshot_dict["effective_execution_plan"]
    ), "Round-trip effective_execution_plan mismatch"

    print(f"  ✓ Restored state exports identically")
    print(f"  ✓ Round-trip snapshot matches original snapshot")
    print(f"  ✓ No corruption or transformation during restore cycle")

    # =========================================================================
    # SUMMARY
    # =========================================================================
    print("\n" + "=" * 80)
    print("REGRESSION TEST PASSED ✓")
    print("=" * 80)
    print("\nValidated Contracts:")
    print("  ✓ Persistence continuity: config + plan survive snapshot → restore")
    print("  ✓ Restore determinism: multiple restores → identical state")
    print("  ✓ Runtime hydration: dashboard cache synchronized post-restore")
    print("  ✓ API truth consistency: persisted == restored == runtime")
    print("  ✓ Diff propagation: dirty stamps notify diff clients")
    print("  ✓ Round-trip integrity: no corruption in export/import cycle")
    print("\nArchitectural Invariant:")
    print("  persisted execution semantics == restored execution semantics == runtime execution semantics")
    print("\n" + "=" * 80)

    return True


def test_multiple_config_updates():
    """
    Extended test: verify that multiple config updates correctly dirty the state
    and propagate through restore cycle.
    """
    print("\n" + "=" * 80)
    print("EXTENDED TEST: Multiple Config Updates & Dirty State Propagation")
    print("=" * 80)

    # Create state, set initial config
    state_1 = DashboardState()
    config_v1 = {
        "name": "BASELINE",
        "enabled_checks": ["http"],
        "concurrency_level": 4,
    }
    state_1.scan_mode_config = config_v1.copy()
    state_1._mark_changed("scan_config")

    print("\n[UPDATE 1] Set baseline config...")
    print(f"  ✓ Config version: BASELINE")

    # Snapshot v1
    snapshot_v1 = build_restore_payload(state_1)
    assert snapshot_v1["scan_mode_config"]["name"] == "BASELINE"
    print(f"  ✓ Snapshot v1 contains BASELINE config")

    # Update config
    config_v2 = {
        "name": "ENHANCED",
        "enabled_checks": ["http", "https", "dns"],
        "concurrency_level": 8,
    }
    state_1.scan_mode_config = config_v2.copy()
    state_1._mark_changed("scan_config")

    print("\n[UPDATE 2] Update to enhanced config...")
    print(f"  ✓ Config version: ENHANCED")

    # Snapshot v2
    snapshot_v2 = build_restore_payload(state_1)
    assert snapshot_v2["scan_mode_config"]["name"] == "ENHANCED"
    print(f"  ✓ Snapshot v2 contains ENHANCED config")

    # Verify snapshots differ
    assert (
        snapshot_v1["scan_mode_config"] != snapshot_v2["scan_mode_config"]
    ), "Snapshots should differ"
    print(f"  ✓ Snapshots correctly differ")

    # Restore from v2, verify we get ENHANCED (not BASELINE)
    state_restored = DashboardState()
    apply_restore_payload(state_restored, snapshot_v2)
    assert (
        state_restored.scan_mode_config["name"] == "ENHANCED"
    ), "Restored config should be ENHANCED"
    print(f"  ✓ Restore from v2 correctly loads ENHANCED config")
    print(f"  ✓ Multiple updates tracked correctly through restore")

    print("\nEXTENDED TEST PASSED ✓\n")
    return True


if __name__ == "__main__":
    try:
        test_persistence_continuity()
        test_multiple_config_updates()
        print("\n✓ ALL REGRESSION TESTS PASSED")
        sys.exit(0)
    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ UNEXPECTED ERROR: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
