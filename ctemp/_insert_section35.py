"""Insert Section 35 tests into test_validation_fleet.py."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN = os.path.join(ROOT, "test_validation_fleet.py")
SEC35 = os.path.join(ROOT, "ctemp", "_section35_tests.py")

with open(MAIN, "r", encoding="utf-8") as f:
    main_text = f.read()

with open(SEC35, "r", encoding="utf-8") as f:
    sec35_text = f.read()

# Insert before the Results block
MARKER = "# \u2550" * 5  # ═════
results_idx = main_text.rfind("# \u2550\u2550\u2550")
if results_idx == -1:
    # Fallback: find "RESULTS:"
    results_idx = main_text.rfind("# Results")
    if results_idx == -1:
        print("ERROR: Could not find Results marker")
        sys.exit(1)

# Go back to the start of the line
while results_idx > 0 and main_text[results_idx - 1] != '\n':
    results_idx -= 1

new_text = main_text[:results_idx] + sec35_text + "\n\n" + main_text[results_idx:]

with open(MAIN, "w", encoding="utf-8") as f:
    f.write(new_text)

print(f"Section 35 inserted at position {results_idx}")
print(f"New file size: {len(new_text)} chars")
