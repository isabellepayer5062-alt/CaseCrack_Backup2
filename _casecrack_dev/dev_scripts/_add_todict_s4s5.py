"""Add to_dict() to Sprint 4/5 dataclasses that are missing it."""
from __future__ import annotations
import ast
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))

ROOT = pathlib.Path("tools/burp_enterprise")

# For each target: find the end of the class body and insert to_dict before end
# We'll inject right before the class ends (after last method/field)
TARGETS = {
    "scanners/timing_attack_scanner.py": {
        "TimingTestCase": (
            "    def to_dict(self) -> dict:\n"
            "        return {\n"
            "            'label': self.label,\n"
            "            'request_kwargs': self.request_kwargs,\n"
            "            'expected_slower': self.expected_slower,\n"
            "        }\n"
        ),
        "TimingAttackConfig": (
            "    def to_dict(self) -> dict:\n"
            "        return {\n"
            "            'samples_per_case': self.samples_per_case,\n"
            "            'warmup_requests': self.warmup_requests,\n"
            "            'request_delay_ms': self.request_delay_ms,\n"
            "            'timeout': self.timeout,\n"
            "            'significance_threshold': self.significance_threshold,\n"
            "        }\n"
        ),
    },
    "scanners/rate_limit_tester.py": {
        "RateLimitTestConfig": (
            "    def to_dict(self) -> dict:\n"
            "        return {\n"
            "            'burst_size': self.burst_size,\n"
            "            'burst_delay_ms': self.burst_delay_ms,\n"
            "            'max_bursts': self.max_bursts,\n"
            "            'test_bypass_headers': self.test_bypass_headers,\n"
            "            'timeout_per_request': self.timeout_per_request,\n"
            "            'safe_mode': self.safe_mode,\n"
            "        }\n"
        ),
        "ActorTimelineEvent": (
            "    def to_dict(self) -> dict:\n"
            "        return {\n"
            "            'actor_id': self.actor_id,\n"
            "            'timestamp': self.timestamp,\n"
            "            'status_code': self.status_code,\n"
            "        }\n"
        ),
    },
    "scanners/response_time_analyzer.py": {
        "ResponseTimeConfig": (
            "    def to_dict(self) -> dict:\n"
            "        return {\n"
            "            'sample_size': self.sample_size,\n"
            "            'warmup_requests': self.warmup_requests,\n"
            "            'request_delay_ms': self.request_delay_ms,\n"
            "            'timeout_per_request': self.timeout_per_request,\n"
            "            'anomaly_stdev_threshold': self.anomaly_stdev_threshold,\n"
            "        }\n"
        ),
    },
    "scanners/vuln_intel_advisor.py": {
        "AgingPolicy": (
            "    def to_dict(self) -> dict:\n"
            "        return {\n"
            "            'max_age_seconds': self.max_age_seconds,\n"
            "            'stale_priority_penalty': self.stale_priority_penalty,\n"
            "            'drop_after_seconds': self.drop_after_seconds,\n"
            "        }\n"
        ),
    },
    "testing_tools/encoder.py": {
        "TransformResult": (
            "    def to_dict(self) -> dict:\n"
            "        return {\n"
            "            'success': self.success,\n"
            "            'input_value': self.input_value,\n"
            "            'output_value': self.output_value,\n"
            "            'encoding_type': self.encoding_type,\n"
            "            'error': self.error,\n"
            "        }\n"
        ),
    },
}


def find_class_end_line(tree: ast.AST, class_name: str, source_lines: list[str]) -> int:
    """Find the last line of a class body (0-indexed)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            # Class ends at the last line of its last body node
            last_line = node.end_lineno  # 1-indexed
            return last_line - 1  # Convert to 0-indexed
    return -1


for rel_path, class_methods in TARGETS.items():
    path = ROOT / rel_path
    src = path.read_text(encoding="utf-8")
    lines = src.splitlines(keepends=True)
    tree = ast.parse(src)

    # Process in reverse order so line numbers stay valid
    inserts: list[tuple[int, str]] = []
    for class_name, method_code in class_methods.items():
        end_line = find_class_end_line(tree, class_name, lines)
        if end_line == -1:
            print(f"  [MISS] {rel_path}: class {class_name} not found")
            continue
        inserts.append((end_line, method_code))
        print(f"  [PLAN] {rel_path}: insert to_dict into {class_name} before line {end_line + 1}")

    # Apply inserts in reverse order (highest line first)
    for insert_at, code in sorted(inserts, reverse=True):
        new_line = "\n" + code + "\n"
        lines.insert(insert_at, new_line)

    path.write_text("".join(lines), encoding="utf-8")
    print(f"  [DONE] {rel_path}")

print()
print("Verifying syntax...")
import py_compile
for rel_path in TARGETS:
    p = ROOT / rel_path
    try:
        py_compile.compile(str(p), doraise=True)
        print(f"  [OK] {rel_path}")
    except py_compile.PyCompileError as e:
        print(f"  [SYNERR] {rel_path}: {e}")
