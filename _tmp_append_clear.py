import ast
p = r"CaseCrack/tools/burp_enterprise/memory/vector_index.py"
t = open(p, encoding="utf-8").read()
if "def clear(" in t:
    print("already present"); raise SystemExit
addition = (
    "\n"
    "    def clear(self) -> None:\n"
    '        """Remove all vectors and reset storage (preserves SQLite schema)."""\n'
    "        with self._lock:\n"
    "            keys = list(self._key_to_idx.keys())\n"
    "            for key in keys:\n"
    "                self._remove_unlocked(key)\n"
    "            self._index = None\n"
    "            self._backend = 'none'\n"
    "            self._next_label = 0\n"
    "            self._init_index()\n"
)
tree = ast.parse(t)
cls = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "VectorMemoryIndex"][0]
lines = t.splitlines(keepends=True)
lines.insert(cls.end_lineno, addition)
new = "".join(lines)
# validate ast
ast.parse(new)
open(p, "w", encoding="utf-8").write(new)
print("ok, size", len(new))
