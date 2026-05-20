#!/usr/bin/env python3
"""
Enforced Contracts Layer  —  Phase 2 of Wiring Stabilization
=============================================================

Startup-time interface validation.  Import this module early and call
``validate_contracts()`` to catch wiring mismatches *before* a 14-minute
scan silently eats the errors.

Why:
  - EventBus callers silently fall back to ``pass`` when ``.publish()``
    doesn't exist — the scan runs but emits zero dashboard events.
  - LLMBridge consumers assume ``.invoke()`` but the real method is
    ``.complete()`` — again swallowed by try/except.
  - DecisionOrchestrator bind-methods are called with wrong kwargs.

This module defines the canonical interface contracts and checks them at
import time.

Run standalone:
    .venv\\Scripts\\python.exe enforced_contracts.py

Or import:
    from enforced_contracts import validate_contracts
    errors = validate_contracts()
"""
from __future__ import annotations

import importlib
import inspect
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
CC = ROOT / "CaseCrack"
if str(CC) not in sys.path:
    sys.path.insert(0, str(CC))


# ════════════════════════════════════════════════════════════════════════
# CONTRACT DEFINITIONS
# ════════════════════════════════════════════════════════════════════════

@dataclass
class MethodContract:
    name: str
    min_params: int = 0          # excluding self
    required_params: list[str] = field(default_factory=list)
    is_async: bool = False


@dataclass
class ClassContract:
    module: str                   # e.g. "tools.burp_enterprise.event_bus"
    class_name: str               # e.g. "EventBus"
    factory: str | None = None    # e.g. "get_event_bus"
    methods: list[MethodContract] = field(default_factory=list)


# ── EventBus ─────────────────────────────────────────────────────────
EVENT_BUS_CONTRACT = ClassContract(
    module="tools.burp_enterprise.event_bus",
    class_name="EventBus",
    factory="get_event_bus",
    methods=[
        MethodContract("on", min_params=2, required_params=["event_type", "handler"]),
        MethodContract("once", min_params=2, required_params=["event_type", "handler"]),
        MethodContract("off", min_params=1, required_params=["subscription_id"]),
        MethodContract("emit", min_params=1, required_params=["event_type"]),
        MethodContract("emit_event", min_params=1, required_params=["event"]),
        MethodContract("emit_async", min_params=1, required_params=["event_type"]),
        MethodContract("use", min_params=1, required_params=["middleware"]),
        MethodContract("list_subscriptions"),
    ],
)

# ── LLMBridge ────────────────────────────────────────────────────────
LLM_BRIDGE_CONTRACT = ClassContract(
    module="tools.burp_enterprise.agents.llm_bridge",
    class_name="LLMBridge",
    methods=[
        MethodContract("complete", min_params=1, required_params=["prompt"], is_async=True),
        MethodContract("analyze_response", min_params=1, is_async=True),
        MethodContract("generate_hypothesis", min_params=1, is_async=True),
        MethodContract("agent_chat", min_params=1, is_async=True),
        MethodContract("suggest_payloads", min_params=1, is_async=True),
        MethodContract("validate_finding", min_params=1, is_async=True),
        MethodContract("get_stats"),
        MethodContract("reset_session"),
    ],
)

# ── DecisionOrchestrator ─────────────────────────────────────────────
DECISION_ORCHESTRATOR_CONTRACT = ClassContract(
    module="tools.burp_enterprise.decision_orchestrator",
    class_name="DecisionOrchestrator",
    factory="get_decision_orchestrator",
    methods=[
        MethodContract("recommend_actions"),
        MethodContract("recommend_strategy"),
        MethodContract("update_state", min_params=1),
        MethodContract("record_outcome", min_params=1),
        MethodContract("bind_event_bus", min_params=1),
        MethodContract("bind_exploit_graph", min_params=1),
        MethodContract("validate_bindings"),
        MethodContract("get_strategic_state"),
        MethodContract("get_metrics"),
    ],
)

# ── StandaloneReconRunner ────────────────────────────────────────────
RUNNER_CONTRACT = ClassContract(
    module="tools.burp_enterprise.recon_dashboard.runner",
    class_name="StandaloneReconRunner",
    methods=[
        MethodContract("run"),
        MethodContract("start"),
        MethodContract("abort"),
        MethodContract("stop"),
        MethodContract("pause"),
        MethodContract("resume"),
        MethodContract("skip_phase"),
        MethodContract("is_running"),
        MethodContract("status"),
        MethodContract("preflight_check"),
    ],
)

# ── ToolRegistry ─────────────────────────────────────────────────────
TOOL_REGISTRY_CONTRACT = ClassContract(
    module="tools.burp_enterprise.tool_registry.registry",
    class_name="ToolRegistry",
    factory="build_default_registry",
    methods=[
        MethodContract("register", min_params=1),
        MethodContract("get", min_params=1, required_params=["name"]),
        MethodContract("has", min_params=1),
        MethodContract("get_all"),
        MethodContract("find_by_capability", min_params=1),
        MethodContract("build_command", min_params=1),
        MethodContract("check_availability", min_params=1),
        MethodContract("get_llm_tool_descriptions"),
    ],
)

# ── ExploitGraph ─────────────────────────────────────────────────────
EXPLOIT_GRAPH_CONTRACT = ClassContract(
    module="tools.burp_enterprise.exploit_chains.exploit_graph",
    class_name="ExploitGraph",
    methods=[
        MethodContract("add_state", min_params=1),
        MethodContract("add_transition", min_params=1),
        MethodContract("process_finding", min_params=1),
        MethodContract("process_findings_batch", min_params=1),
        MethodContract("build_from_knowledge_base"),
    ],
)

ALL_CONTRACTS = [
    EVENT_BUS_CONTRACT,
    LLM_BRIDGE_CONTRACT,
    DECISION_ORCHESTRATOR_CONTRACT,
    RUNNER_CONTRACT,
    TOOL_REGISTRY_CONTRACT,
    EXPLOIT_GRAPH_CONTRACT,
]


# ════════════════════════════════════════════════════════════════════════
# VALIDATION ENGINE
# ════════════════════════════════════════════════════════════════════════

@dataclass
class ValidationError:
    subsystem: str
    severity: str          # "CRITICAL", "WARNING"
    message: str

    def __str__(self) -> str:
        return f"[{self.severity}] {self.subsystem}: {self.message}"


def _check_contract(contract: ClassContract) -> list[ValidationError]:
    errors: list[ValidationError] = []
    name = f"{contract.class_name}"

    # 1. Can we import the module?
    try:
        mod = importlib.import_module(contract.module)
    except Exception as exc:
        errors.append(ValidationError(name, "CRITICAL", f"Cannot import {contract.module}: {exc}"))
        return errors

    # 2. Does the class exist?
    cls = getattr(mod, contract.class_name, None)
    if cls is None:
        errors.append(ValidationError(name, "CRITICAL", f"Class {contract.class_name} not found in {contract.module}"))
        return errors

    # 3. Check factory if defined
    if contract.factory:
        factory = getattr(mod, contract.factory, None)
        if factory is None:
            errors.append(ValidationError(name, "WARNING", f"Factory {contract.factory} not found"))
        elif not callable(factory):
            errors.append(ValidationError(name, "WARNING", f"Factory {contract.factory} is not callable"))

    # 4. Check each method
    for mc in contract.methods:
        meth = getattr(cls, mc.name, None)
        if meth is None:
            errors.append(ValidationError(name, "CRITICAL", f"Missing method: {mc.name}()"))
            continue

        # Check signature
        try:
            sig = inspect.signature(meth)
            params = [p for p in sig.parameters.values() if p.name != "self"]

            # Check required params exist
            param_names = {p.name for p in params}
            for rp in mc.required_params:
                if rp not in param_names:
                    errors.append(ValidationError(
                        name, "WARNING",
                        f"{mc.name}() missing expected param '{rp}' (has: {sorted(param_names)})"
                    ))

            # Check async-ness
            if mc.is_async and not inspect.iscoroutinefunction(meth):
                errors.append(ValidationError(
                    name, "WARNING",
                    f"{mc.name}() expected to be async but is sync"
                ))
        except (ValueError, TypeError):
            pass  # Some built-in methods can't be introspected

    # 5. Check for WRONG method names that callers use (ghost API detection)
    ghost_methods = {
        "EventBus": ["publish", "subscribe", "unsubscribe", "send"],
        "LLMBridge": ["invoke", "generate", "chat", "query", "ask"],
        "DecisionOrchestrator": ["decide", "evaluate", "score"],
        "StandaloneReconRunner": ["execute", "launch"],
        "ToolRegistry": ["lookup", "find", "search"],
        "ExploitGraph": ["add_node", "add_edge"],
    }

    for ghost in ghost_methods.get(contract.class_name, []):
        if hasattr(cls, ghost):
            errors.append(ValidationError(
                name, "WARNING",
                f"Ghost method '{ghost}' exists — callers may use it instead of canonical API"
            ))

    return errors


# ════════════════════════════════════════════════════════════════════════
# CROSS-CALLER AUDIT
# ════════════════════════════════════════════════════════════════════════

def _audit_event_bus_callers() -> list[ValidationError]:
    """Check that known EventBus callers use .on()/.emit() not .publish()/.subscribe().
    
    Only flags calls on objects that appear to be the global EventBus
    (from event_bus module), not separate bus classes like MessageBus,
    ScanEventBus, or event_bridge helpers.
    """
    import ast as _ast
    errors: list[ValidationError] = []
    pkg = CC / "tools" / "burp_enterprise"
    wrong_methods = {"publish", "subscribe", "unsubscribe"}
    
    # Names that indicate a different bus implementation (not the global EventBus)
    _EXEMPT_OBJECTS = {
        "_bus",           # swarm MessageBus
        "event_bridge",   # server event_bridge helper
        "scan_bus",       # ScanEventBus
    }
    # Files that use a local bus class, not the global EventBus
    _EXEMPT_FILES = {
        "enterprise_scale_executor.py",  # uses ScanEventBus, not EventBus
    }

    for py in pkg.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        if py.name in _EXEMPT_FILES:
            continue
        try:
            src = py.read_text(encoding="utf-8-sig", errors="replace")
            tree = _ast.parse(src, filename=str(py))
        except Exception:
            continue

        # Check if file imports from event_bus module (the global one)
        imports_global_bus = False
        for node in _ast.walk(tree):
            if isinstance(node, _ast.ImportFrom) and node.module:
                if "event_bus" in node.module and "swarm" not in node.module:
                    imports_global_bus = True
                    break
            if isinstance(node, _ast.Import):
                for alias in node.names:
                    if "event_bus" in alias.name and "swarm" not in alias.name:
                        imports_global_bus = True

        for node in _ast.walk(tree):
            if isinstance(node, _ast.Call) and isinstance(node.func, _ast.Attribute):
                attr = node.func.attr
                if attr in wrong_methods:
                    val = node.func.value
                    obj_name = ""
                    if isinstance(val, _ast.Name):
                        obj_name = val.id
                    elif isinstance(val, _ast.Attribute):
                        obj_name = val.attr
                    
                    # Skip known non-EventBus objects
                    if obj_name in _EXEMPT_OBJECTS:
                        continue
                    
                    # Only flag if the object name suggests EventBus AND file imports it
                    is_bus_like = "bus" in obj_name.lower() or "event" in obj_name.lower()
                    if is_bus_like and (imports_global_bus or "event_bus" in obj_name.lower()):
                        rel = py.relative_to(CC)
                        errors.append(ValidationError(
                            "EventBus:caller",
                            "CRITICAL",
                            f"{rel}:{node.lineno} — calls .{attr}() on '{obj_name}' (should be .emit/.on/.off)"
                        ))

    return errors


# ════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ════════════════════════════════════════════════════════════════════════

def validate_contracts(
    contracts: list[ClassContract] | None = None,
    audit_callers: bool = True,
) -> list[ValidationError]:
    """Run all contract checks.  Returns list of errors (empty = pass)."""
    contracts = contracts or ALL_CONTRACTS
    all_errors: list[ValidationError] = []

    for c in contracts:
        all_errors.extend(_check_contract(c))

    if audit_callers:
        all_errors.extend(_audit_event_bus_callers())

    return all_errors


def print_report(errors: list[ValidationError]) -> None:
    critical = [e for e in errors if e.severity == "CRITICAL"]
    warnings = [e for e in errors if e.severity == "WARNING"]

    print(f"\n{'═'*70}")
    print(f"  ENFORCED CONTRACTS VALIDATION")
    print(f"  {len(critical)} critical │ {len(warnings)} warnings │ {len(ALL_CONTRACTS)} subsystems")
    print(f"{'═'*70}\n")

    if critical:
        print("CRITICAL:\n")
        for e in critical:
            print(f"  ✘ {e}")
        print()

    if warnings:
        print("WARNINGS:\n")
        for e in warnings:
            print(f"  ⚠ {e}")
        print()

    if not errors:
        print("  ✓ All contracts pass\n")


# ── Main ─────────────────────────────────────────────────────────────
def main() -> int:
    errors = validate_contracts()
    print_report(errors)
    return 1 if any(e.severity == "CRITICAL" for e in errors) else 0


if __name__ == "__main__":
    sys.exit(main())
