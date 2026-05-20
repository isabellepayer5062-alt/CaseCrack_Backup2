"""Comprehensive fix #4 for agent_roles.py - regenerate corrupted methods section."""
import os

path = os.path.join(os.path.dirname(__file__), "tools", "burp_enterprise", "agent_roles.py")

with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

# Find "def write_memory" (line 1081, index 1080)
write_mem_idx = None
for i, line in enumerate(lines):
    if "def write_memory" in line:
        write_mem_idx = i
        break

# Find "def _evaluate_dissent" (line 1167, index 1166)
eval_dissent_idx = None
for i, line in enumerate(lines):
    if "def _evaluate_dissent" in line:
        eval_dissent_idx = i
        break

if write_mem_idx is None or eval_dissent_idx is None:
    print(f"write_memory: {write_mem_idx}, _evaluate_dissent: {eval_dissent_idx}")
    print("Cannot find boundaries")
    exit(1)

# Also find the comment line before write_memory (should be "Agent-Scoped Memory" comment)
comment_start = write_mem_idx
for i in range(write_mem_idx - 1, max(write_mem_idx - 5, 0), -1):
    if "Agent-Scoped Memory" in lines[i] or lines[i].strip().startswith("#"):
        comment_start = i
    else:
        break

print(f"Replacing lines {comment_start + 1} to {eval_dissent_idx}")

# Generate clean replacement
clean_code = '''    # -- Agent-Scoped Memory (Anthropic: 3 memory scopes) --

    def write_memory(self, key: str, value: Any, scope: str | None = None) -> None:
        """Write to agent-scoped memory.

        Re-written from Anthropic agentMemory.ts - per-agent-type directories
        with 3 scopes: user, project, local.
        """
        scope = scope or self._memory_scope
        if scope not in self._agent_memory:
            scope = "local"
        with self._lock:
            self._agent_memory[scope][key] = value

    def read_memory(self, key: str, scope: str | None = None, default: Any = None) -> Any:
        """Read from agent-scoped memory."""
        scope = scope or self._memory_scope
        if scope not in self._agent_memory:
            scope = "local"
        with self._lock:
            return self._agent_memory[scope].get(key, default)

    def get_memory_snapshot(self) -> dict[str, dict[str, Any]]:
        """Return all memory scopes for serialization."""
        with self._lock:
            import copy
            return copy.deepcopy(self._agent_memory)

'''

lines[comment_start:eval_dissent_idx] = [clean_code]

with open(path, "w", encoding="utf-8") as f:
    f.writelines(lines)

print("FIXED successfully")
