"""Insert Section 33 tests into test_validation_fleet.py."""
import sys
sys.path.insert(0, r"c:\Users\ya754\CaseCrack v1.0")

# Read current test file
test_path = r"c:\Users\ya754\CaseCrack v1.0\test_validation_fleet.py"
with open(test_path, "r", encoding="utf-8") as f:
    content = f.read()

# Read Section 33 tests
from ctemp._section33_tests import SECTION_33_TESTS

# Find insertion point: before the Results section
marker = "# \u2550" * 5  # Start of the box-drawing Results header
results_markers = [
    "print(f\"\\n{'='*60}\")",
    "RESULTS: {passed}",
]

# Find the last section end and insert before Results
import re
# Find the last occurrence of the results print block
idx = content.rfind("print(f\"\\n{'='*60}\")")
if idx == -1:
    print("ERROR: Could not find results section marker")
    sys.exit(1)

# Go back to find the comment line before it
line_start = content.rfind("\n", 0, idx)
# Go back more to find the box-drawing separator
prev_line_start = content.rfind("\n", 0, line_start)
while prev_line_start > 0:
    line = content[prev_line_start+1:content.find("\n", prev_line_start+1)]
    if line.strip().startswith("#") and ("\u2550" in line or "Results" in line or "=" * 20 in line):
        break
    prev_line_start = content.rfind("\n", 0, prev_line_start)

# Find the actual block start (the comment with ═ or Results)
block_start = prev_line_start
# Go back one more line to capture the full block
prev2 = content.rfind("\n", 0, block_start)
if prev2 > 0:
    check_line = content[prev2+1:block_start+1].strip()
    if check_line.startswith("#"):
        block_start = prev2

insertion_point = block_start

# Insert Section 33 tests before Results
new_content = (
    content[:insertion_point] +
    "\n\n" + SECTION_33_TESTS.strip() + "\n\n\n" +
    content[insertion_point:]
)

# Write back
with open(test_path, "w", encoding="utf-8") as f:
    f.write(new_content)

# Count tests
import re as re2
test_count = len(re2.findall(r'check\("33\.', SECTION_33_TESTS))
print(f"SUCCESS: Inserted Section 33 with {test_count} tests")
print(f"File size: {len(new_content)} chars")
