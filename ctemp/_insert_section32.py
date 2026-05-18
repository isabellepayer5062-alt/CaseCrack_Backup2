"""Helper script to insert Section 32 tests into test_validation_fleet.py."""
import sys

path = r'c:\Users\ya754\CaseCrack v1.0\test_validation_fleet.py'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# Find the separator line before '# Results'
idx = content.rfind('# Results\n')
if idx == -1:
    print("ERROR: Could not find '# Results' in file")
    sys.exit(1)

sep_start = content.rfind('\n', 0, idx - 1) + 1

section32_path = r'c:\Users\ya754\CaseCrack v1.0\ctemp\_section32_tests.py'
with open(section32_path, 'r', encoding='utf-8') as f:
    section32 = f.read()

new_content = content[:sep_start] + section32 + '\n' + content[sep_start:]

with open(path, 'w', encoding='utf-8') as f:
    f.write(new_content)

print(f'Inserted Section 32 ({len(section32)} chars) into test_validation_fleet.py')
print(f'New file size: {len(new_content)} chars')
