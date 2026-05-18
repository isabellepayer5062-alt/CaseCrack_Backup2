# Fix Unicode characters in test file
with open('_FINAL_ENFORCEMENT_ACTIVATION_TEST.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace Unicode characters
content = content.replace('✓', '[OK]')
content = content.replace('✗', '[FAIL]')

with open('_FINAL_ENFORCEMENT_ACTIVATION_TEST.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Fixed Unicode characters - test file ready")
