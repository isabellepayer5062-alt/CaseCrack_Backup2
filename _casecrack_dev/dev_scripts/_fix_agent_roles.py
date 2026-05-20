"""One-time fix script for agent_roles.py corrupt lines."""
import os

path = os.path.join(os.path.dirname(__file__), "tools", "burp_enterprise", "agent_roles.py")

with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

# Find the corrupt line: logger.info("Agent %s: abort signalled", self.agent_id
# followed by leftover old code
corrupt_idx = None
for i, line in enumerate(lines):
    if 'abort signalled' in line and line.rstrip().endswith('self.agent_id'):
        corrupt_idx = i
        break

if corrupt_idx is None:
    print("No corrupt line found - file may already be fixed")
    exit(0)

print(f"Found corrupt line at {corrupt_idx + 1}: {lines[corrupt_idx].rstrip()}")

# Find the end of the corrupt section - it ends with '"""' (the close of old docstring)
end_idx = None
for i in range(corrupt_idx + 1, min(corrupt_idx + 20, len(lines))):
    if lines[i].strip() == '"""':
        end_idx = i + 1  # inclusive
        break

if end_idx is None:
    print("Could not find end of corrupt section")
    exit(1)

print(f"Corrupt section: lines {corrupt_idx + 1} to {end_idx}")

# Replace with correct code
new_lines = [
    '        logger.info("Agent %s: abort signalled", self.agent_id)\n',
    '        return True\n',
    '\n',
    '    def _execute_task(self, task: TaskAssignment) -> None:\n',
    '        """Execute a task in a background thread.\n',
    '\n',
    '        Cross-examination additions: abort check, turn counting with\n',
    '        maxTurns enforcement, timeout enforcement, comprehensive\n',
    '        cleanup protocol with comprehensive finally block.\n',
    '        """\n',
]

lines[corrupt_idx:end_idx] = new_lines

with open(path, "w", encoding="utf-8") as f:
    f.writelines(lines)

print("FIXED successfully")
