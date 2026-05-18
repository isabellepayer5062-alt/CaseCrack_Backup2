"""Insert Section 36 tests into test_validation_fleet.py."""
import sys, os

test_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "test_validation_fleet.py")

# Read section 36 tests
sec36_file = os.path.join(os.path.dirname(__file__), "_section36_tests.py")
with open(sec36_file, "r", encoding="utf-8") as f:
    sec36_mod = {}
    exec(f.read(), sec36_mod)
    section36_code = sec36_mod["SECTION_36_TESTS"]

# Read current test file
with open(test_file, "r", encoding="utf-8") as f:
    content = f.read()

if "SECTION 36" in content:
    print("Section 36 already present, skipping insertion.")
    sys.exit(0)

# Find insertion point - before the results summary
marker = "# ===== RESULTS ====="
if marker not in content:
    # Try alternate markers
    for alt in ["print(f\"\\n{'='*60}\")", "print(f\"RESULTS", "# Print results"]:
        if alt in content:
            marker = alt
            break

idx = content.index(marker)
new_content = content[:idx] + section36_code + "\n" + content[idx:]

with open(test_file, "w", encoding="utf-8") as f:
    f.write(new_content)

print("Section 36 inserted successfully.")
