"""Fix EventBus injection that split @decorator from class."""
from __future__ import annotations
from pathlib import Path
import re

ROOT = Path(__file__).parent / "CaseCrack" / "tools" / "burp_enterprise"
MARKER = "# __EVENTBUS_INJECTED__"

# Pattern: decorator line(s), blank line, MARKER, ..., class/def
# We want: MARKER block, blank line, decorator(s), class/def

def fix(path: Path) -> str:
    src = path.read_text(encoding="utf-8")
    if MARKER not in src:
        return "no-marker"

    lines = src.splitlines(keepends=True)
    # Find marker line
    marker_idx = None
    for i, ln in enumerate(lines):
        if MARKER in ln:
            marker_idx = i
            break
    if marker_idx is None:
        return "no-marker"

    # Walk backwards from marker, collect any decorators (and trailing blank lines)
    # The injection added "\n" before INJECT_BLOCK; INJECT_BLOCK starts with "\n# __EVENTBUS..."
    # so the marker is on its own line, preceded by blank lines and possibly decorators.
    decorator_start = marker_idx
    j = marker_idx - 1
    while j >= 0:
        stripped = lines[j].strip()
        if stripped == "":
            j -= 1
            continue
        if stripped.startswith("@"):
            decorator_start = j
            j -= 1
            continue
        break

    if decorator_start == marker_idx:
        return "no-decorator-issue"

    # Find end of injected block: continues until blank line + class/def
    # Injected block is fixed; find the class/def that follows it
    k = marker_idx
    while k < len(lines):
        if re.match(r"^(class|def)\s+\w", lines[k]):
            break
        k += 1
    if k >= len(lines):
        return "no-target-class"

    # Decorators that were lifted away from the class
    decorators = lines[decorator_start:marker_idx]
    # Strip trailing blank lines from decorators
    while decorators and decorators[-1].strip() == "":
        decorators.pop()

    # Injected block (from marker to class line)
    injected = lines[marker_idx:k]

    # Reassemble: pre-decorator + injected + decorators + class
    new_lines = lines[:decorator_start] + injected + decorators + lines[k:]
    path.write_text("".join(new_lines), encoding="utf-8")
    return "fixed"


def main():
    subs = ["network", "integrations", "caap", "testing_tools"]
    for sub in subs:
        d = ROOT / sub
        for p in d.glob("*.py"):
            if p.name == "__init__.py":
                continue
            r = fix(p)
            if r != "no-marker" and r != "no-decorator-issue":
                print(f"  {r:25s} {sub}/{p.name}")


if __name__ == "__main__":
    main()
