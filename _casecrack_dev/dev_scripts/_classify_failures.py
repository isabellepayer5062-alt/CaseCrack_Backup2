"""Classify the 100 tool_registry test failures into A/B/C buckets."""
import re
from pathlib import Path
from collections import defaultdict

raw = Path("_bucketC_failures_detail.txt").read_text(encoding="utf-8", errors="replace")
blocks = re.split(r"_{5,}\s+(?:ERROR at setup of )?(.+?)\s+_{5,}", raw)

rows = []
for i in range(1, len(blocks) - 1, 2):
    name = blocks[i].strip()
    body = blocks[i + 1]
    errs = re.findall(r"^E\s+(.+?)$", body, re.MULTILINE)
    err = errs[0] if errs else ""
    rows.append((name, err))


def classify(err: str):
    if "VULN_SCAN" in err or "has no attribute 'PLAIN_TEXT'" in err:
        return ("A", "enum-member-renamed-or-removed")
    if "unexpected keyword argument" in err:
        m = re.search(r"unexpected keyword argument '(\w+)'", err)
        return ("A", f"kwarg-renamed:{m.group(1) if m else '?'}")
    if "missing 1 required positional argument: 'ctx'" in err:
        return ("B", "parse-api-requires-ctx")
    if "ParsedFinding" in err:
        return ("B", "ParsedFinding-schema-migration")
    if "ParseContext" in err:
        return ("B", "ParseContext-schema-migration")
    if "has no attribute 'from_dict'" in err:
        return ("A", "missing-from_dict-classmethod")
    if "has no attribute 'registered_tools'" in err or "has no attribute 'has_parser'" in err:
        return ("A", "ParserRegistry-api-rename")
    if "has no attribute 'prefer_docker'" in err or "'FallbackConfig' object has no attribute 'enabled'" in err:
        return ("A", "config-attr-renamed")
    if "'ActionTranslator' object has no attribute" in err:
        return ("A", "ActionTranslator-missing-method")
    if "'_availability_cache'" in err:
        return ("C", "test-fixture-setup")
    if "GenericNDJSONParser() takes no arguments" in err:
        return ("A", "parser-ctor-changed")
    if "'tool_registry'" in err:
        return ("A", "config-key-renamed-tool_registry")
    if "'_allowed'" in err:
        return ("C", "private-attr-test")
    if "DID NOT RAISE" in err:
        return ("C", "raise-contract-changed")
    if "is not None" in err:
        return ("C", "nullability-contract-changed")
    if "_safe_json" in err or "_extract_" in err:
        return ("C", "private-helper-import")
    if "Missing 'tool' key" in err:
        return ("A", "finding-schema-missing-tool-key")
    if "'sqli'" in err:
        return ("A", "capability-catalog-renamed")
    if "KeyError: 'severity'" in err:
        return ("A", "finding-schema-missing-severity")
    return ("?", err[:100])


buckets = defaultdict(list)
for name, err in rows:
    cat, sub = classify(err)
    buckets[(cat, sub)].append((name, err))

print(f"TOTAL: {sum(len(v) for v in buckets.values())} failures\n")
for cat in ["A", "B", "C", "?"]:
    items = [(s, v) for (c, s), v in buckets.items() if c == cat]
    total = sum(len(v) for _, v in items)
    if not total:
        continue
    label = {"A": "CONTRACT MISMATCH (design decision)",
             "B": "MISSING CAPABILITY / API evolution",
             "C": "TEST DRIFT (fix tests, not code)",
             "?": "UNCLASSIFIED"}[cat]
    print(f"=== Category {cat} — {label} ({total}) ===")
    for sub, v in sorted(items, key=lambda x: -len(x[1])):
        print(f"  [{len(v):>3}] {sub}")
        for n, e in v[:2]:
            short_n = n.split("::")[-1]
            print(f"        - {short_n}  ::  {e[:90]}")
    print()
