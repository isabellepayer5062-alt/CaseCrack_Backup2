"""Remove old section 34 and insert updated version."""
import re

test_file = r"c:\Users\ya754\CaseCrack v1.0\test_validation_fleet.py"
section_file = r"c:\Users\ya754\CaseCrack v1.0\ctemp\_section34_tests.py"

with open(test_file, "r", encoding="utf-8") as f:
    content = f.read()

with open(section_file, "r", encoding="utf-8") as f:
    section = f.read()

# Find old section 34 boundaries
old_start_marker = "# Section 34: Production Subsystems (Token Budget, FlushGate, Crash Recovery)"
old_start = content.find(old_start_marker)
if old_start == -1:
    print("ERROR: Could not find section 34 start marker")
    exit(1)

# Find the Results block that comes after section 34
results_marker = "\n# \u2550" * 1  # box-drawing line before "# Results"
# Find the line "# Results" 
results_idx = content.find("# Results\n", old_start)
if results_idx == -1:
    print("ERROR: Could not find '# Results' marker")
    exit(1)

# Go back to find the box-drawing line before Results
box_line_start = content.rfind("\n#", 0, results_idx - 2)
if box_line_start == -1:
    box_line_start = results_idx
else:
    box_line_start += 1  # skip the newline

# Remove everything from old_start to box_line_start
content = content[:old_start] + section + "\n\n\n" + content[box_line_start:]

with open(test_file, "w", encoding="utf-8") as f:
    f.write(content)

test_count = len(re.findall(r'check\("34\.', section))
print(f"SUCCESS: Section 34 re-inserted ({test_count} tests)")
