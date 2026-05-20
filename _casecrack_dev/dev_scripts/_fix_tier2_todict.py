"""Add to_dict to the 2 remaining dataclass gaps in Tier 2 recovered modules."""
import ast, pathlib, py_compile

TARGETS = [
    ("tools/burp_enterprise/network/traffic_analyzer.py", "HTTPExchange"),
    ("tools/burp_enterprise/caap/chat_interface.py", "ChatCommand"),
]

METHOD = (
    "\n"
    "    def to_dict(self) -> dict:\n"
    "        import dataclasses\n"
    "        return dataclasses.asdict(self)\n"
)

for fpath, cls_name in TARGETS:
    p = pathlib.Path(fpath)
    src = p.read_text(encoding="utf-8")
    tree = ast.parse(src)
    end_lineno = None
    for cls in ast.walk(tree):
        if isinstance(cls, ast.ClassDef) and cls.name == cls_name:
            end_lineno = cls.end_lineno
            break
    if end_lineno is None:
        print(f"  [MISS] {fpath}::{cls_name}")
        continue
    lines = src.splitlines(keepends=True)
    lines.insert(end_lineno, METHOD)
    p.write_text("".join(lines), encoding="utf-8")
    try:
        py_compile.compile(str(p), doraise=True)
        print(f"  [OK] {fpath}::{cls_name}")
    except py_compile.PyCompileError as e:
        print(f"  [SYNTAX FAIL] {fpath}: {e}")
        p.write_text(src, encoding="utf-8")
        print(f"  [REVERTED]")
