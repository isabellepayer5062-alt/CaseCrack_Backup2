"""Wire MODULE_STARTED emit + metrics increment + audit_log at the top of
the primary action method of each recovered module.

Inserts (after the method docstring, if any) a 3-line block:

    _emit("MODULE_STARTED", {"module": "<mod>", "method": "<method>"})
    _rs_metrics().increment("<mod>.<method>.calls")
    _rs_audit("<mod>", "<method>")

Idempotent (skips if marker `# __TIER2_INSTRUMENTED__` already in module).
"""
from __future__ import annotations
import ast
from pathlib import Path

ROOT = Path(__file__).parent / "CaseCrack" / "tools" / "burp_enterprise"
MARKER = "# __TIER2_INSTRUMENTED__"

# (subdir, modname, method_name_or_prefix)
TARGETS = [
    ("network", "dns_resolver", "resolve_all"),  # already done; will be skipped
    ("network", "http_fingerprint", "fingerprint_headers"),
    ("network", "ssl_analyzer", "analyze"),
    ("network", "traffic_analyzer", "analyze"),
    ("integrations", "ci_cd_pipeline", "trigger_scan"),
    ("integrations", "defect_dojo", "create_engagement"),
    ("integrations", "jira_client", "create_issue"),
    ("integrations", "slack_notifier", "notify_finding"),
    ("integrations", "webhook_dispatcher", "dispatch"),
    ("caap", "caap_coordinator", "start"),
    ("caap", "chat_interface", "process"),
    ("caap", "compliance_checker", "check_compliance"),
    ("caap", "discovery_agent", "run"),
    ("caap", "exploitation_agent", "run"),
    ("caap", "hypothesis_engine", "generate"),
    ("caap", "recon_agent", "run"),
    ("caap", "session_orchestrator", "create_session"),
    ("testing_tools", "api_fuzzer", "fuzz_endpoint"),
    ("testing_tools", "benchmark_runner", "run"),
    ("testing_tools", "compliance_validator", "validate"),
    ("testing_tools", "integration_harness", "run"),
    ("testing_tools", "load_tester", "run"),
    ("testing_tools", "mock_server", "start"),
]


def find_method(src: str, method: str):
    """Return (start_line_0based, body_indent, body_first_line_0based) for the
    *first method body line* of ``method`` in ``src``, or None."""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == method:
                    if not item.body:
                        return None
                    first = item.body[0]
                    # Skip docstring
                    if (isinstance(first, ast.Expr)
                            and isinstance(first.value, ast.Constant)
                            and isinstance(first.value.value, str)):
                        if len(item.body) >= 2:
                            insert_after = first.end_lineno  # 1-based
                            indent = first.col_offset
                            return insert_after, indent
                        # Only docstring, no body — insert right after it
                        return first.end_lineno, first.col_offset
                    return first.lineno - 1, first.col_offset
    return None


def patch(path: Path, modname: str, method: str) -> str:
    src = path.read_text(encoding="utf-8")
    if MARKER in src and f'"{modname}.{method}.calls"' in src:
        return "skip-already"

    found = find_method(src, method)
    if found is None:
        return f"miss:{method}"

    insert_line, indent = found
    indent_str = " " * indent

    block = (
        f'{indent_str}{MARKER}\n'
        f'{indent_str}try:\n'
        f'{indent_str}    _emit("MODULE_STARTED", {{"module": "{modname}", "method": "{method}"}})\n'
        f'{indent_str}    _rs_metrics().increment("{modname}.{method}.calls")\n'
        f'{indent_str}    _rs_audit("{modname}", "{method}")\n'
        f'{indent_str}except Exception:\n'
        f'{indent_str}    pass\n'
    )

    lines = src.splitlines(keepends=True)
    # insert_line is 1-based "after" → use as 0-based "before"
    lines.insert(insert_line, block)
    path.write_text("".join(lines), encoding="utf-8")
    return "ok"


def main() -> int:
    for sub, mod, method in TARGETS:
        p = ROOT / sub / f"{mod}.py"
        if not p.exists():
            print(f"  no-file {sub}/{mod}.py")
            continue
        r = patch(p, mod, method)
        print(f"  {r:25s} {sub}/{mod}.{method}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
