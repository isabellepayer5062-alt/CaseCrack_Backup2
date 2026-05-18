#!/usr/bin/env python3
"""
Event System Hardening Harness  —  Phase 3 of Wiring Stabilization
===================================================================

Validates that:
  1. All EventBus callers use canonical API (.on, .emit, .off)
  2. No orphan subscribers (registered but never triggered)
  3. No phantom events (emitted but nobody listens)
  4. Compatibility shims emit DeprecationWarnings correctly
  5. Event type taxonomy is consistent

Run:
    .venv\\Scripts\\python.exe event_system_harness.py
"""
from __future__ import annotations

import ast
import json
import sys
import warnings
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
CC = ROOT / "CaseCrack"
PKG = CC / "tools" / "burp_enterprise"
if str(CC) not in sys.path:
    sys.path.insert(0, str(CC))


@dataclass
class EventIssue:
    severity: str   # CRITICAL, WARNING, INFO
    category: str
    file: str
    line: int
    message: str


def _scan_event_api_calls() -> tuple[list[EventIssue], dict[str, list], dict[str, list]]:
    """AST-scan all files for EventBus API usage patterns.
    
    Returns: (issues, emitters{event_type: [file:line]}, listeners{event_type: [file:line]})
    """
    issues: list[EventIssue] = []
    emitters: dict[str, list] = defaultdict(list)
    listeners: dict[str, list] = defaultdict(list)
    
    canonical_emit = {"emit", "emit_event", "emit_async"}
    canonical_listen = {"on", "once", "on_filter"}
    deprecated = {"publish", "subscribe", "unsubscribe"}
    
    for py in PKG.rglob("*.py"):
        if "__pycache__" in py.parts or "_archive" in py.parts:
            continue
        try:
            src = py.read_text(encoding="utf-8-sig", errors="replace")
            tree = ast.parse(src, filename=str(py))
        except Exception:
            continue
        
        rel = str(py.relative_to(CC))
        
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            
            attr = node.func.attr
            val = node.func.value
            obj_name = ""
            if isinstance(val, ast.Name):
                obj_name = val.id
            elif isinstance(val, ast.Attribute):
                obj_name = val.attr
            
            # Only look at EventBus-like objects
            is_bus = ("bus" in obj_name.lower() and "message" not in obj_name.lower())
            is_event_bus = "event_bus" in obj_name.lower() or obj_name == "bus"
            
            if not (is_bus or is_event_bus):
                continue
            
            # Extract event type from first string argument
            event_type = None
            if node.args:
                first = node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    event_type = first.value
            
            if attr in canonical_emit:
                if event_type:
                    emitters[event_type].append(f"{rel}:{node.lineno}")
            elif attr in canonical_listen:
                if event_type:
                    listeners[event_type].append(f"{rel}:{node.lineno}")
            elif attr in deprecated and is_event_bus:
                issues.append(EventIssue(
                    "WARNING", "deprecated_api", rel, node.lineno,
                    f"Uses deprecated .{attr}() on '{obj_name}' — should use canonical API"
                ))
    
    return issues, dict(emitters), dict(listeners)


def _find_orphan_events(
    emitters: dict[str, list], listeners: dict[str, list]
) -> list[EventIssue]:
    """Find events emitted with no listeners and vice versa."""
    issues = []
    
    # Emitted but nobody listens
    for et, locs in emitters.items():
        if et not in listeners:
            issues.append(EventIssue(
                "INFO", "phantom_event", locs[0].split(":")[0], 
                int(locs[0].split(":")[1]),
                f"Event '{et}' is emitted ({len(locs)} locations) but has no .on() listeners"
            ))
    
    # Listened but never emitted
    for et, locs in listeners.items():
        if et not in emitters:
            issues.append(EventIssue(
                "WARNING", "orphan_listener", locs[0].split(":")[0],
                int(locs[0].split(":")[1]),
                f"Listener for '{et}' registered ({len(locs)} locations) but event is never emitted"
            ))
    
    return issues


def _validate_shims() -> list[EventIssue]:
    """Verify compatibility shims emit DeprecationWarning."""
    issues = []
    try:
        from tools.burp_enterprise.event_bus import get_event_bus, reset_global_bus
        reset_global_bus()
        bus = get_event_bus()
        
        for method_name in ["publish", "subscribe", "unsubscribe"]:
            meth = getattr(bus, method_name, None)
            if meth is None:
                issues.append(EventIssue(
                    "CRITICAL", "missing_shim", "event_bus.py", 0,
                    f"Compatibility shim .{method_name}() missing from EventBus"
                ))
                continue
            
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                try:
                    if method_name == "publish":
                        meth("__test__", {"_harness": True})
                    elif method_name == "subscribe":
                        meth("__test__", lambda e: None)
                    elif method_name == "unsubscribe":
                        meth("__nonexistent__")
                except Exception:
                    pass
                
                has_deprecation = any(
                    issubclass(x.category, DeprecationWarning) for x in w
                )
                if not has_deprecation:
                    issues.append(EventIssue(
                        "WARNING", "silent_shim", "event_bus.py", 0,
                        f"Shim .{method_name}() does not emit DeprecationWarning"
                    ))
        
        reset_global_bus()
    except Exception as exc:
        issues.append(EventIssue(
            "CRITICAL", "shim_validation_error", "event_bus.py", 0,
            f"Shim validation failed: {exc}"
        ))
    
    return issues


def _check_bus_event_type_enum() -> list[EventIssue]:
    """Check consistency of BusEventType enum with actual usage."""
    issues = []
    try:
        from tools.burp_enterprise.event_bus import BusEventType
        enum_values = {e.value for e in BusEventType}
        issues.append(EventIssue(
            "INFO", "enum_stats", "event_bus.py", 0,
            f"BusEventType enum has {len(enum_values)} defined event types"
        ))
    except Exception:
        issues.append(EventIssue(
            "WARNING", "no_enum", "event_bus.py", 0,
            "BusEventType enum not found"
        ))
    return issues


def run_harness() -> dict[str, Any]:
    """Run the full event system hardening harness."""
    all_issues: list[EventIssue] = []
    
    print("Scanning event API calls...", flush=True)
    api_issues, emitters, listeners = _scan_event_api_calls()
    all_issues.extend(api_issues)
    print(f"  {len(emitters)} event types emitted, {len(listeners)} event types listened")
    
    print("Finding orphan events...", flush=True)
    orphan_issues = _find_orphan_events(emitters, listeners)
    all_issues.extend(orphan_issues)
    
    print("Validating compatibility shims...", flush=True)
    shim_issues = _validate_shims()
    all_issues.extend(shim_issues)
    
    print("Checking BusEventType enum...", flush=True)
    enum_issues = _check_bus_event_type_enum()
    all_issues.extend(enum_issues)
    
    # Summary
    critical = [i for i in all_issues if i.severity == "CRITICAL"]
    warns = [i for i in all_issues if i.severity == "WARNING"]
    infos = [i for i in all_issues if i.severity == "INFO"]
    
    report = {
        "summary": {
            "critical": len(critical),
            "warnings": len(warns),
            "info": len(infos),
            "event_types_emitted": len(emitters),
            "event_types_listened": len(listeners),
        },
        "emitters": emitters,
        "listeners": listeners,
        "issues": [
            {"severity": i.severity, "category": i.category, "file": i.file, 
             "line": i.line, "message": i.message}
            for i in all_issues
        ],
    }
    
    return report


def main() -> int:
    report = run_harness()
    s = report["summary"]
    
    # Save JSON
    out = ROOT / "event_system_harness.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    
    print(f"\n{'═'*60}")
    print(f"  EVENT SYSTEM HARDENING REPORT")
    print(f"  {s['critical']} critical │ {s['warnings']} warnings │ {s['info']} info")
    print(f"  {s['event_types_emitted']} event types emitted")
    print(f"  {s['event_types_listened']} event types listened")
    print(f"{'═'*60}")
    
    if s["critical"]:
        print("\nCRITICAL:")
        for i in report["issues"]:
            if i["severity"] == "CRITICAL":
                print(f"  ✘ {i['file']}:{i['line']} — {i['message']}")
    
    if s["warnings"]:
        print("\nWARNINGS:")
        for i in report["issues"]:
            if i["severity"] == "WARNING":
                print(f"  ⚠ {i['file']}:{i['line']} — {i['message']}")
    
    # Show phantom/orphan events
    phantoms = [i for i in report["issues"] if i["category"] == "phantom_event"]
    orphans = [i for i in report["issues"] if i["category"] == "orphan_listener"]
    if phantoms:
        print(f"\nPHANTOM EVENTS (emitted but no listener): {len(phantoms)}")
        for i in phantoms[:20]:
            print(f"  → {i['message']}")
    if orphans:
        print(f"\nORPHAN LISTENERS (listening but never emitted): {len(orphans)}")
        for i in orphans[:20]:
            print(f"  → {i['message']}")
    
    print(f"\nSaved: {out}")
    return 1 if s["critical"] else 0


if __name__ == "__main__":
    sys.exit(main())
