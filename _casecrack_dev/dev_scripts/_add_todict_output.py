"""
Batch-inject to_dict() into ALL output module dataclasses missing it.
Uses dataclasses.asdict(self) to avoid manually listing fields.
"""
from __future__ import annotations
import ast
import pathlib
import py_compile

ROOT = pathlib.Path("tools/burp_enterprise/output")

# Files that need to_dict() added to some/all of their dataclasses
TARGET_FILES = [
    "composite_rule_engine.py",
    "correlation_engine.py",
    "dashboard_renderer.py",
    "reporter.py",
    "severity_engine.py",
]

TO_DICT_BODY = (
    "\n"
    "    def to_dict(self) -> dict:\n"
    "        import dataclasses\n"
    "        return dataclasses.asdict(self)\n"
    "\n"
)


def get_classes_missing_to_dict(src: str) -> list[tuple[str, int]]:
    """Return list of (class_name, end_lineno_0indexed) for public dataclasses missing to_dict."""
    tree = ast.parse(src)
    results = []
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef) or cls.name.startswith("_"):
            continue
        is_dc = any(
            (isinstance(d, ast.Name) and d.id == "dataclass")
            or (isinstance(d, ast.Attribute) and d.attr == "dataclass")
            for d in cls.decorator_list
        )
        if not is_dc:
            continue
        has_to_dict = any(
            isinstance(n, ast.FunctionDef) and n.name == "to_dict" for n in cls.body
        )
        if not has_to_dict:
            # end_lineno is 1-indexed; insert before it (0-indexed = end_lineno - 1)
            results.append((cls.name, cls.end_lineno - 1))
    return results


total_added = 0
for fname in TARGET_FILES:
    path = ROOT / fname
    if not path.exists():
        print(f"  [SKIP] {fname} not found")
        continue

    src = path.read_text(encoding="utf-8")
    missing = get_classes_missing_to_dict(src)
    if not missing:
        print(f"  [SKIP] {fname}: no missing to_dict")
        continue

    lines = src.splitlines(keepends=True)
    # Process in reverse order so line numbers stay valid
    for class_name, insert_before in sorted(missing, key=lambda x: x[1], reverse=True):
        lines.insert(insert_before, TO_DICT_BODY)
        print(f"  [ADD] {fname}::{class_name}")
        total_added += 1

    path.write_text("".join(lines), encoding="utf-8")

    # Verify syntax
    try:
        py_compile.compile(str(path), doraise=True)
        print(f"  [SYNTAX OK] {fname}")
    except py_compile.PyCompileError as e:
        print(f"  [SYNTAX FAIL] {fname}: {e}")

print(f"\nTotal to_dict() methods added: {total_added}")
