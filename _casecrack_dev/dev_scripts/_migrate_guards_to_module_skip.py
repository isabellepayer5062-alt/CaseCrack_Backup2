"""Convert the ImportError guards to module-level skips.

Previous guard set a pytestmark on ImportError but let the file continue
parsing — subsequent top-level imports then raise NameError.
The fix: call pytest.skip(..., allow_module_level=True) inside the except
so module loading halts immediately.
"""
from __future__ import annotations
import re
from pathlib import Path

ROOT = Path(r"C:\Users\ya754\CaseCrack v1.0\CaseCrack")

files = [
    "tests/test_canary_detector.py",
    "tests/test_crawl_secrets_pipeline.py",
    "tests/test_cross_fork_scanner.py",
    "tests/test_custom_detector.py",
    "tests/test_custom_detector_loader_comprehensive.py",
    "tests/test_docker_image_scanner.py",
    "tests/test_docker_layer_analyzer.py",
    "tests/test_entropy_analyzer.py",
    "tests/test_entropy_intelligence.py",
    "tests/test_fix140_secrets_hardening.py",
    "tests/test_git_deep_scanner.py",
    "tests/test_keyword_prefilter.py",
    "tests/test_keyword_prefilter_comprehensive.py",
    "tests/test_phase_c_adaptive_fuzzing.py",
    "tests/test_secret_verifier.py",
    "tests/test_secret_verifiers_extended.py",
]

# Replace:
#   except ImportError as _e:
#       pytestmark = _pytest_skip_guard.mark.skip(
#           reason=(...)
#       )
# With:
#   except ImportError as _e:
#       import pytest as _pytest_mod_skip
#       _pytest_mod_skip.skip(
#           "..." ,
#           allow_module_level=True,
#       )

PATTERN = re.compile(
    r"except ImportError as _e:\s*\n"
    r"    pytestmark = _pytest_skip_guard\.mark\.skip\(\s*\n"
    r"        reason=\(\s*\n"
    r"(?P<lines>(?:            [^\n]*\n)+)"
    r"        \)\s*\n"
    r"    \)",
)

changed = 0
for rel in files:
    p = ROOT / rel
    src = p.read_text(encoding="utf-8")
    m = PATTERN.search(src)
    if not m:
        # already migrated or different format — verify
        if "allow_module_level=True" in src:
            continue
        print(f"!! no guard block matched in {rel}")
        continue
    reason_lines = m.group("lines")
    # Flatten reason lines (they are Python string literal pieces)
    reason_text = "".join(line.strip() for line in reason_lines.splitlines())
    replacement = (
        "except ImportError as _e:\n"
        "    import pytest as _pytest_mod_skip\n"
        f"    _pytest_mod_skip.skip(\n"
        f"        {reason_text},\n"
        "        allow_module_level=True,\n"
        "    )"
    )
    new_src = src[:m.start()] + replacement + src[m.end():]
    p.write_text(new_src, encoding="utf-8")
    changed += 1
    print(f"OK  {rel}")

print(f"\nMigrated {changed} files to module-level skip")
