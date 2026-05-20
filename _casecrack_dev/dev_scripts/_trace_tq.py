"""Trace all triple-quote positions after fixes 0-5."""
FILE = "tools/burp_enterprise/agent_roles.py"

with open(FILE, "r", encoding="utf-8") as f:
    src = f.read()

# Apply FIX 0
BAD0 = '  - State isolation (own working memory)AGENT_COLORS = {'
GOOD0 = '  - State isolation (own working memory)\n"""\nfrom __future__ import annotations\n\nimport enum\nimport logging\nimport threading\nimport time\nimport uuid\nfrom collections import defaultdict, deque\nfrom dataclasses import dataclass, field\nfrom typing import Any, Callable\n\nlogger = logging.getLogger(__name__)\n\n# *******************************************************************\n# CONSTANTS (Cross-examination: typed task IDs, agent colors, limits)\n# *******************************************************************\n\nTASK_PREFIX_MAP = {\n    "recon": "r",\n    "exploit": "e",\n    "strategy": "s",\n    "memory": "m",\n    "defense": "d",\n    "coordinator": "c",\n}\n\nAGENT_AUTO_TIMEOUT_S = 120.0\nDEFAULT_MAX_TURNS = 100\n\nAGENT_COLORS = {'
src = src.replace(BAD0, GOOD0, 1)

# Apply FIX 1
BAD1 = '        self._current_task: TaskAssignment | None = Noneelf   "tasks_completed": 0,'
GOOD1 = '        self._current_task: TaskAssignment | None = None\n        self._thread: threading.Thread | None = None\n        self._abort_event = threading.Event()\n        self._turns = 0\n        self._turn_count = 0\n        self._max_turns = self.capabilities.max_turns\n        self._timeout_s = self.capabilities.timeout_s\n\n        # Stats\n        self._stats: dict[str, Any] = {\n            "tasks_completed": 0,'
src = src.replace(BAD1, GOOD1, 1)

# Apply FIX 2
BAD2 = '    def assign_task(self, task: TaskAssignment) -> bool:\n        """Assign a task to this agent. Returns True if accepted."""\n        if self._state not in (AgentState.IDLE, AgentState.COMPLETED):\n            return False\n)\n        return True\n\n    def _execute_task(self, task: TaskAssignment) -> None:\n        """Execute a task in a background thread.\n\n        Cross-examination additions:\n        - Abort check (Anthropic: AbortController)\n        - Turn counting with maxTurns enforcement\n        - Timeout enforcement\n        - Comprehensive cleanup protocol (Anthropic\n        self._thread = threading.Thread(\n            target=self._execute_task,\n            args=(task,),\n            daemon=True,\n            name=f"agent-{self.agent_id}",\n        )\n        self._thread.start()\n        return True\n'
GOOD2 = '    def assign_task(self, task: TaskAssignment) -> bool:\n        """Assign a task to this agent. Returns True if accepted."""\n        if self._state not in (AgentState.IDLE, AgentState.COMPLETED):\n            return False\n        self._current_task = task\n        self._abort_event.clear()\n        self._turns = 0\n        self._set_state(AgentState.RUNNING)\n        self._thread = threading.Thread(\n            target=self._execute_task,\n            args=(task,),\n            daemon=True,\n            name=f"agent-{self.agent_id}",\n        )\n        self._thread.start()\n        return True\n'
src = src.replace(BAD2, GOOD2, 1)

# Apply FIX 3
BAD3_MARKER = "        Cross-examination additions:\n        - Typed task ID prefix (Anthropic: a/b/r/t/w/m/d)\n        - Worker tool visibility injection into context\n        - Dead-agent guard\n\n        Returns the TaskAssignment, or None if agent is busy or dead.\n"
if BAD3_MARKER in src:
    dt_def = "    def dispatch_task(\n"
    dt_start = src.rfind(dt_def, 0, src.index(BAD3_MARKER))
    dp_def = "    def dispatch_parallel("
    dp_start = src.index(dp_def, src.index(BAD3_MARKER))
    CLEAN_DT = '    def dispatch_task(\n        self,\n        role: AgentRoleType,\n        description: str,\n        instructions: str = "",\n        context: dict[str, Any] | None = None,\n        priority: int = 0,\n    ) -> TaskAssignment | None:\n        """Dispatch a task to a specific agent role."""\n        agent = self._agents.get(role)\n        if not agent:\n            return None\n        if agent.state == AgentState.RETIRED:\n            return None\n        prefix = TASK_PREFIX_MAP.get(role.value, "c")\n        task_id = f"{prefix}-{uuid.uuid4().hex[:8]}"\n        enriched_context = dict(context or {})\n        enriched_context["worker_tools"] = agent.capabilities.allowed_tools\n        enriched_context["worker_mode"] = agent.capabilities.execution_mode.value\n        enriched_context["worker_read_only"] = agent.capabilities.read_only\n        enriched_context["max_turns"] = agent.capabilities.max_turns\n        enriched_context["timeout_s"] = agent.capabilities.timeout_s\n        task = TaskAssignment(\n            task_id=task_id,\n            description=description,\n            instructions=instructions,\n            assigned_to=agent.agent_id,\n            priority=priority,\n            context=enriched_context,\n        )\n        success = agent.assign_task(task)\n        if success:\n            with self._lock:\n                self._pending_results[task.task_id] = task\n            self._emit({"type": "agent_task_dispatched", "role": role.value, "task_id": task.task_id})\n            return task\n        return None\n\n'
    src = src[:dt_start] + CLEAN_DT + src[dp_start:]

# Apply FIX 4
BAD4 = '        Cross-examination: now handles aborted/timeout terminal states.\n        """\n'
if BAD4 in src:
    frag_start = src.index(BAD4)
    clean_wait = "    def _wait_for_tasks("
    frag_end = src.index(clean_wait, frag_start)
    src = src[:frag_start] + '        return results\n\n' + src[frag_end:]

# Apply FIX 5
BAD5 = "            agent._set_state(AgentState.ID\n"
if BAD5 in src:
    idx5 = src.index(BAD5)
    first_abort = src.index("    def abort_agent(", idx5)
    merged_end = "snapshot()LE)"
    me_idx = src.index(merged_end, first_abort)
    next_nl = src.index("\n", me_idx) + 1
    second_abort = src.index("    def abort_agent(", next_nl)
    GOOD5 = "            agent._set_state(AgentState.IDLE)\n            return True\n        return False\n\n"
    src = src[:idx5] + GOOD5 + src[second_abort:]

# Now trace ALL triple-quote positions
lines = src.splitlines()
tq = '"""'
in_tq = False
total_toggles = 0
for i, line in enumerate(lines, 1):
    cnt = line.count(tq)
    if cnt > 0:
        total_toggles += cnt
        old_state = in_tq
        for _ in range(cnt):
            in_tq = not in_tq
        state_str = "OPEN" if in_tq else "CLOSE"
        print(f"L{i:4d} x{cnt} -> {state_str}: {line.rstrip()[:80]}")

print(f"\nTotal toggles: {total_toggles}")
print(f"Final state: {'INSIDE string (ODD!)' if in_tq else 'outside string (EVEN, OK)'}")
"""Trace triple-quote state through the repaired content."""
import re

FILE = "tools/burp_enterprise/agent_roles.py"
with open(FILE, "r", encoding="utf-8") as f:
    src = f.read()

# Apply all fixes from the repair script (simplified - just apply FIX 0 through 5)
exec(open("_repair_agent_roles.py").read().split("# ── VALIDATE")[0].replace(
    "sys.exit(1)", "pass"
).replace("import re, sys", "import re, sys; pass"))

# Now trace triple-quotes in the fixed src
lines = src.splitlines()
tq = '"""'
in_tq = False
toggles = []
for i, line in enumerate(lines, 1):
    count = line.count(tq)
    if count > 0:
        for _ in range(count):
            in_tq = not in_tq
            toggles.append((i, "OPEN" if in_tq else "CLOSE", line.rstrip()[:80]))

print("Triple-quote toggles (last 30):")
for ln, state, text in toggles[-30:]:
    print(f"  L{ln} {state}: {text}")

print(f"\nFinal state: {'INSIDE' if in_tq else 'OUTSIDE'}")
if in_tq:
    print("Looking for unclosed triple-quote...")
    for ln, state, text in reversed(toggles):
        if state == "OPEN":
            print(f"  Last OPEN without matching CLOSE: L{ln}: {text}")
            break
