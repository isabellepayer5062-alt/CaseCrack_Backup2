"""
Batch-inject to_dict() into ALL public dataclasses missing it.

Fix over _add_todict_output.py: use `lines.insert(end_lineno, ...)` not
`lines.insert(end_lineno - 1, ...)` so the method lands AFTER the last
line of the class (never inside a method body or multi-line field expression).
"""
from __future__ import annotations
import ast
import pathlib
import py_compile
import sys

ROOT = pathlib.Path("tools/burp_enterprise")

TO_DICT_METHOD = (
    "\n"
    "    def to_dict(self) -> dict:\n"
    "        import dataclasses\n"
    "        return dataclasses.asdict(self)\n"
)


def classes_missing_to_dict(src: str) -> list[tuple[str, int]]:
    """Return [(class_name, end_lineno_1indexed)] for public dataclasses without to_dict."""
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
            results.append((cls.name, cls.end_lineno))  # 1-indexed
    return results


total_added = 0
total_fail = []
subdirs = ["output", "scanners", "testing_tools"]

for subdir in subdirs:
    for p in sorted((ROOT / subdir).glob("*.py")):
        if p.name.startswith("_"):
            continue
        src = p.read_text(encoding="utf-8")
        missing = classes_missing_to_dict(src)
        if not missing:
            continue

        lines = src.splitlines(keepends=True)
        # Process in reverse order (highest line first) so indices stay valid
        for class_name, end_lineno_1idx in sorted(missing, key=lambda x: x[1], reverse=True):
            # Insert AFTER the last line of the class
            # end_lineno_1idx is 1-indexed; 0-indexed = end_lineno_1idx - 1
            # lines.insert(end_lineno_1idx, ...) inserts AFTER 0-indexed position end_lineno_1idx-1
            lines.insert(end_lineno_1idx, TO_DICT_METHOD)
            print(f"  [ADD] {subdir}/{p.name}::{class_name}")
            total_added += 1

        new_src = "".join(lines)
        p.write_text(new_src, encoding="utf-8")

        # Immediate syntax check
        try:
            py_compile.compile(str(p), doraise=True)
        except py_compile.PyCompileError as e:
            total_fail.append(f"{subdir}/{p.name}: {e}")
            print(f"  [SYNTAX FAIL] {subdir}/{p.name}: {e}")
            # Revert
            p.write_text(src, encoding="utf-8")
            print(f"  [REVERTED] {subdir}/{p.name}")

print(f"\nTotal to_dict() added: {total_added}")
if total_fail:
    print("SYNTAX FAILURES (reverted):")
    for f in total_fail:
        print(f"  {f}")
else:
    print("All files OK.")
