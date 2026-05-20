"""One-time fix script #2 for agent_roles.py - remove duplicate finally block."""

import os

path = os.path.join(os.path.dirname(__file__), "tools", "burp_enterprise", "agent_roles.py")

with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

# Find the corrupt line 935: starts with correct code but merges into junk
# Pattern: "if self._state not in (AgentState.RETIRED, AgentState.PAUSED),"
corrupt_start = None
for i, line in enumerate(lines):
    if "AgentState.RETIRED, AgentState.PAUSED)," in line and "sender" not in line:
        corrupt_start = i
        break

if corrupt_start is None:
    print("No corrupt line found at expected location")
    # Try alternate detection: find old "finally:" at line ~950
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped == "# Return to IDLE for next task":
            corrupt_start = i - 1  # the "finally:" line before it
            break

if corrupt_start is None:
    print("Cannot find corruption point")
    exit(1)

# Find the next "def _default_execute" which marks the clean code resumption
next_def = None
for i in range(corrupt_start, len(lines)):
    if "def _default_execute" in lines[i]:
        next_def = i
        break

if next_def is None:
    print("Cannot find _default_execute boundary")
    exit(1)

print(f"Corrupt section: lines {corrupt_start + 1} to {next_def}")
print(f"Replacing with correct IDLE return + blank line")

# Replace the entire corrupt section (line 935 to just before def _default_execute)
new_lines = [
    "            if self._state not in (AgentState.RETIRED, AgentState.PAUSED):\n",
    "                self._set_state(AgentState.IDLE)\n",
    "\n",
]

lines[corrupt_start:next_def] = new_lines

with open(path, "w", encoding="utf-8") as f:
    f.writelines(lines)

print("FIXED successfully")
