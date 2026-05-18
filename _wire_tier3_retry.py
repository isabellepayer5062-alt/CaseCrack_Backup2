"""Add @_rs_retry decorators to external API methods of recovered integrations.

Idempotent (skips if `# __TIER2_RETRY__` marker is on the line above the def).
"""
from __future__ import annotations
import re
from pathlib import Path

ROOT = Path(__file__).parent / "CaseCrack" / "tools" / "burp_enterprise" / "integrations"
MARKER = "# __TIER2_RETRY__"

# (file, method_name)
TARGETS = [
    ("jira_client.py", "create_issue"),
    ("jira_client.py", "get_issue"),
    ("jira_client.py", "add_comment"),
    ("jira_client.py", "search_issues"),
    ("defect_dojo.py", "create_engagement"),
    ("defect_dojo.py", "import_findings"),
    ("defect_dojo.py", "import_sarif"),
    ("defect_dojo.py", "get_findings"),
    ("sonarqube.py", "get_issues"),
    ("sonarqube.py", "get_vulnerabilities"),
    ("sonarqube.py", "get_quality_gate"),
    ("sonarqube.py", "import_as_findings"),
    ("slack_notifier.py", "notify_finding"),
    ("slack_notifier.py", "notify_scan_complete"),
    ("slack_notifier.py", "notify_batch"),
]


def patch(path: Path, method: str) -> str:
    src = path.read_text(encoding="utf-8")
    lines = src.splitlines(keepends=True)
    # find `    def {method}(...)`
    pat = re.compile(rf"^    def {re.escape(method)}\s*\(")
    for i, ln in enumerate(lines):
        if pat.match(ln):
            # check if marker already present in any of the previous 3 lines
            window = "".join(lines[max(0, i-3):i])
            if MARKER in window:
                return "skip"
            # find indent (4 spaces)
            indent = "    "
            block = (
                f"{indent}{MARKER}\n"
                f"{indent}@_rs_retry(max_attempts=3, backoff=1.0, max_backoff=10.0, "
                f'on=(Exception,), operation="{path.stem}.{method}")\n'
            )
            lines.insert(i, block)
            path.write_text("".join(lines), encoding="utf-8")
            return "ok"
    return "miss"


def main() -> int:
    for fname, method in TARGETS:
        p = ROOT / fname
        if not p.exists():
            print(f"  no-file {fname}")
            continue
        r = patch(p, method)
        print(f"  {r:6s} {fname}::{method}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
