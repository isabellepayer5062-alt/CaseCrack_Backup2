"""Insert Section 34 tests into test_validation_fleet.py."""
import re

test_file = r"c:\Users\ya754\CaseCrack v1.0\test_validation_fleet.py"
section_file = r"c:\Users\ya754\CaseCrack v1.0\ctemp\_section34_tests.py"

with open(test_file, "r", encoding="utf-8") as f:
    content = f.read()

with open(section_file, "r", encoding="utf-8") as f:
    section = f.read()

# Find "# Results" line and insert before the line above it
idx = content.find("# Results\n")
if idx == -1:
    print("ERROR: Could not find '# Results' marker")
else:
    # Go back to find the start of the box-drawing comment line above Results
    # Find the line before "# Results" — it's a box-drawing line
    line_start = content.rfind("\n#", 0, idx - 2)
    if line_start == -1:
        line_start = idx
    else:
        line_start += 1  # skip the newline

    content = content[:line_start] + section + "\n\n\n" + content[line_start:]
    with open(test_file, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"SUCCESS: Section 34 inserted before Results block")
    test_count = len(re.findall(r'check\("34\.', section))
    print(f"Tests added: {test_count}")
