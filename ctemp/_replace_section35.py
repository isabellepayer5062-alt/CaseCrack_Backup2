"""Replace Section 35 in test_validation_fleet.py with corrected version."""

import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN = os.path.join(ROOT, "test_validation_fleet.py")
SEC35 = os.path.join(ROOT, "ctemp", "_section35_tests.py")

with open(MAIN, "r", encoding="utf-8") as f:
    text = f.read()

with open(SEC35, "r", encoding="utf-8") as f:
    new_sec35 = f.read()

# Find section 35 start
marker_start = "# Section 35:"
idx_start = text.find(marker_start)
if idx_start == -1:
    print("ERROR: Section 35 not found")
    exit(1)

# Go back to find the section header block start
while idx_start > 0 and text[idx_start - 1] != '\n':
    idx_start -= 1
# Include the preceding blank lines/box
while idx_start > 0 and text[idx_start - 1] == '\n':
    idx_start -= 1
idx_start += 1  # keep one newline

# Find end: the Results block
results_marker = text.find("# Results", idx_start)
if results_marker == -1:
    results_marker = text.rfind("# Results")

# Go back to start of line
while results_marker > 0 and text[results_marker - 1] != '\n':
    results_marker -= 1

new_text = text[:idx_start] + "\n" + new_sec35 + "\n\n" + text[results_marker:]

with open(MAIN, "w", encoding="utf-8") as f:
    f.write(new_text)

print(f"Section 35 replaced. New file size: {len(new_text)}")
