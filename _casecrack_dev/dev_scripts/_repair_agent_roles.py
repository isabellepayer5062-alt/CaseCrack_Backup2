"""Comprehensive repair of agent_roles.py v4 - fixes corruption + triple-quote audit."""
import re
import sys
import ast

FILE = "tools/burp_enterprise/agent_roles.py"

with open(FILE, "r", encoding="utf-8") as f:
    src = f.read()

original_len = len(src.splitlines())
print(f"Read {original_len} lines")

# ─────────────── FIX 0: Module docstring merged with AGENT_COLORS ───────
BAD0 = '  - State isolation (own working memory)AGENT_COLORS = {'
GOOD0 = '  - State isolation (own working memory)\n"""\nfrom __future__ import annotations\n\nimport enum\nimport logging\nimport threading\nimport time\nimport uuid\nfrom collections import defaultdict, deque\nfrom dataclasses import dataclass, field\nfrom typing import Any, Callable\n\nlogger = logging.getLogger(__name__)\n\n# *******************************************************************\n# CONSTANTS (Cross-examination: typed task IDs, agent colors, limits)\n# *******************************************************************\n\nTASK_PREFIX_MAP = {\n    "recon": "r",\n    "exploit": "e",\n    "strategy": "s",\n    "memory": "m",\n    "defense": "d",\n    "coordinator": "c",\n}\n\nAGENT_AUTO_TIMEOUT_S = 120.0\nDEFAULT_MAX_TURNS = 100\n\nAGENT_COLORS = {'
if BAD0 in src:
    src = src.replace(BAD0, GOOD0, 1)
    print("[0] Fixed merged docstring/imports/AGENT_COLORS")

# ─────────────── FIX 1: Merged current_task/stats ──────────────────────
BAD1 = '        self._current_task: TaskAssignment | None = Noneelf   "tasks_completed": 0,'
GOOD1 = '        self._current_task: TaskAssignment | None = None\n        self._thread: threading.Thread | None = None\n        self._abort_event = threading.Event()\n        self._turns = 0\n        self._turn_count = 0\n        self._max_turns = self.capabilities.max_turns\n        self._timeout_s = self.capabilities.timeout_s\n\n        # Stats\n        self._stats: dict[str, Any] = {\n            "tasks_completed": 0,'
if BAD1 in src:
    src = src.replace(BAD1, GOOD1, 1)
    print("[1] Fixed merged current_task/stats line")

# ─────────────── FIX 2: Broken assign_task + first broken _execute_task ─
BAD2 = '    def assign_task(self, task: TaskAssignment) -> bool:\n        """Assign a task to this agent. Returns True if accepted."""\n        if self._state not in (AgentState.IDLE, AgentState.COMPLETED):\n            return False\n)\n        return True\n\n    def _execute_task(self, task: TaskAssignment) -> None:\n        """Execute a task in a background thread.\n\n        Cross-examination additions:\n        - Abort check (Anthropic: AbortController)\n        - Turn counting with maxTurns enforcement\n        - Timeout enforcement\n        - Comprehensive cleanup protocol (Anthropic\n        self._thread = threading.Thread(\n            target=self._execute_task,\n            args=(task,),\n            daemon=True,\n            name=f"agent-{self.agent_id}",\n        )\n        self._thread.start()\n        return True\n'
GOOD2 = '    def assign_task(self, task: TaskAssignment) -> bool:\n        """Assign a task to this agent. Returns True if accepted."""\n        if self._state not in (AgentState.IDLE, AgentState.COMPLETED):\n            return False\n        self._current_task = task\n        self._abort_event.clear()\n        self._turns = 0\n        self._set_state(AgentState.RUNNING)\n        self._thread = threading.Thread(\n            target=self._execute_task,\n            args=(task,),\n            daemon=True,\n            name=f"agent-{self.agent_id}",\n        )\n        self._thread.start()\n        return True\n'
if BAD2 in src:
    src = src.replace(BAD2, GOOD2, 1)
    print("[2] Fixed broken assign_task + removed first broken _execute_task")

# ─────────────── FIX 3: dispatch_task duplicate ─────────────────────────
BAD3_MARKER = "        Cross-examination additions:\n        - Typed task ID prefix (Anthropic: a/b/r/t/w/m/d)\n        - Worker tool visibility injection into context\n        - Dead-agent guard\n\n        Returns the TaskAssignment, or None if agent is busy or dead.\n"
if BAD3_MARKER in src:
    dt_def = "    def dispatch_task(\n"
    dt_start = src.rfind(dt_def, 0, src.index(BAD3_MARKER))
    dp_def = "    def dispatch_parallel("
    dp_start = src.index(dp_def, src.index(BAD3_MARKER))
    CLEAN_DT = '    def dispatch_task(\n        self,\n        role: AgentRoleType,\n        description: str,\n        instructions: str = "",\n        context: dict[str, Any] | None = None,\n        priority: int = 0,\n    ) -> TaskAssignment | None:\n        """Dispatch a task to a specific agent role."""\n        agent = self._agents.get(role)\n        if not agent:\n            return None\n\n        if agent.state == AgentState.RETIRED:\n            logger.warning("Coordinator: %s is retired, cannot dispatch", agent.name)\n            return None\n\n        prefix = TASK_PREFIX_MAP.get(role.value, "c")\n        task_id = f"{prefix}-{uuid.uuid4().hex[:8]}"\n\n        enriched_context = dict(context or {})\n        enriched_context["worker_tools"] = agent.capabilities.allowed_tools\n        enriched_context["worker_mode"] = agent.capabilities.execution_mode.value\n        enriched_context["worker_read_only"] = agent.capabilities.read_only\n        enriched_context["max_turns"] = agent.capabilities.max_turns\n        enriched_context["timeout_s"] = agent.capabilities.timeout_s\n\n        task = TaskAssignment(\n            task_id=task_id,\n            description=description,\n            instructions=instructions,\n            assigned_to=agent.agent_id,\n            priority=priority,\n            context=enriched_context,\n        )\n\n        success = agent.assign_task(task)\n        if success:\n            with self._lock:\n                self._pending_results[task.task_id] = task\n            self._emit({\n                "type": "agent_task_dispatched",\n                "role": role.value,\n                "agent_id": agent.agent_id,\n                "task_id": task.task_id,\n                "description": description,\n            })\n            return task\n\n        return None\n\n'
    src = src[:dt_start] + CLEAN_DT + src[dp_start:]
    print("[3] Fixed duplicate dispatch_task")

# ─────────────── FIX 4: Old _wait_for_tasks fragment ────────────────────
BAD4 = '        Cross-examination: now handles aborted/timeout terminal states.\n        """\n'
if BAD4 in src:
    frag_start = src.index(BAD4)
    clean_wait = "    def _wait_for_tasks("
    frag_end = src.index(clean_wait, frag_start)
    src = src[:frag_start] + '        return results\n\n' + src[frag_end:]
    print("[4] Removed old _wait_for_tasks fragment + added return results")

# ─────────────── FIX 5: Truncated resume_agent + dup abort/memory ───────
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
    print("[5] Fixed resume_agent + removed first dup abort/get_agent_memory")

# ─────────────── FIX 6: Triple-quote audit and repair ───────────────────
# Instead of docstring simplification, properly trace and repair triple-quote pairing.
# Walk through the source and ensure all """ pairs match.
lines_list = src.splitlines(True)
tq = '"""'
in_tq = False
opens = []  # stack of (line_idx, line_content)
fixes_needed = []

for idx, line in enumerate(lines_list):
    count = line.count(tq)
    for c in range(count):
        if not in_tq:
            in_tq = True
            opens.append(idx)
        else:
            in_tq = False
            opens.pop()

if in_tq and opens:
    # There's an unclosed triple-quote
    bad_line = opens[-1]
    print(f"[6] Found unclosed triple-quote at line {bad_line + 1}: {lines_list[bad_line].rstrip()[:80]}")
    # The unclosed """ is likely from a docstring that had its closing """ removed
    # or a bare text section that looks like it starts/ends a docstring.
    # Let's trace all triple-quote positions for diagnosis
    tq_positions = []
    for idx, line in enumerate(lines_list):
        if tq in line:
            tq_positions.append((idx + 1, line.count(tq), line.rstrip()[:80]))
    print(f"  Total triple-quote lines: {len(tq_positions)}")
    for ln, cnt, text in tq_positions:
        if ln > bad_line - 5 and ln < bad_line + 20:
            print(f"    L{ln} (x{cnt}): {text}")
else:
    print("[6] Triple-quotes all properly paired")

# ─────────────── VALIDATE ───────────────────────────────────────────────
new_lines = src.splitlines()
print(f"\nResult: {len(new_lines)} lines (was {original_len})")

# Corruption check
corruption = False
for i, line in enumerate(new_lines, 1):
    if "Noneelf" in line:
        print(f"  CORRUPTION L{i}: Noneelf")
        corruption = True
    if "snapshot()LE)" in line:
        print(f"  CORRUPTION L{i}: snapshot()LE)")
        corruption = True
    if line.rstrip().endswith("AgentState.ID") and "IDLE" not in line:
        print(f"  CORRUPTION L{i}: truncated AgentState.ID")
        corruption = True
if not corruption:
    print("No corruption patterns remain")

# Duplicate check
methods = {}
for i, line in enumerate(new_lines, 1):
    m = re.match(r"^(\s+)def (\w+)\(", line)
    if m:
        key = (len(m.group(1)), m.group(2))
        methods.setdefault(key, []).append(i)
dups = {k: v for k, v in methods.items() if len(v) > 1 and k[1] not in ("__init__", "to_dict")}
if dups:
    for key, locs in sorted(dups.items()):
        print(f"  DUPLICATE: {key[1]} (indent={key[0]}): lines {locs}")
else:
    print("No duplicate methods")

# AST check
try:
    ast.parse(src)
    print("\nAST parse: OK -- writing file")
    with open(FILE, "w", encoding="utf-8", newline="\n") as f:
        f.write(src)
    print(f"Written {len(new_lines)} lines to {FILE}")
except SyntaxError as e:
    print(f"\nAST FAILED L{e.lineno}: {e.msg}")
    print(f"  Text: {e.text!r}")
    for j in range(max(0, e.lineno - 3), min(len(new_lines), e.lineno + 3)):
        marker = ">>>" if j + 1 == e.lineno else "   "
        print(f"  {marker} L{j+1}: {new_lines[j][:100]}")
    print("NOT writing file")
    sys.exit(1)
"""Comprehensive repair of agent_roles.py v3."""
import re
import sys
import ast

FILE = "tools/burp_enterprise/agent_roles.py"

with open(FILE, "r", encoding="utf-8") as f:
    src = f.read()

original_len = len(src.splitlines())
print(f"Read {original_len} lines")

# ─────────────────────────────────────────────────────────────────────
# FIX 0: Module docstring merged with AGENT_COLORS, all imports missing
# ─────────────────────────────────────────────────────────────────────
BAD0 = '  - State isolation (own working memory)AGENT_COLORS = {'
GOOD0 = '  - State isolation (own working memory)\n"""\nfrom __future__ import annotations\n\nimport enum\nimport logging\nimport threading\nimport time\nimport uuid\nfrom collections import defaultdict, deque\nfrom dataclasses import dataclass, field\nfrom typing import Any, Callable\n\nlogger = logging.getLogger(__name__)\n\n# *******************************************************************\n# CONSTANTS (Cross-examination: typed task IDs, agent colors, limits)\n# *******************************************************************\n\nTASK_PREFIX_MAP = {\n    "recon": "r",\n    "exploit": "e",\n    "strategy": "s",\n    "memory": "m",\n    "defense": "d",\n    "coordinator": "c",\n}\n\nAGENT_AUTO_TIMEOUT_S = 120.0\nDEFAULT_MAX_TURNS = 100\n\nAGENT_COLORS = {'
if BAD0 in src:
    src = src.replace(BAD0, GOOD0, 1)
    print("[0] Fixed merged docstring/imports/AGENT_COLORS")

# ─────────────────────────────────────────────────────────────────────
# FIX 1: Merged line in SpecialistAgent.__init__
# ─────────────────────────────────────────────────────────────────────
BAD1 = '        self._current_task: TaskAssignment | None = Noneelf   "tasks_completed": 0,'
GOOD1 = '        self._current_task: TaskAssignment | None = None\n        self._thread: threading.Thread | None = None\n        self._abort_event = threading.Event()\n        self._turns = 0\n        self._turn_count = 0\n        self._max_turns = self.capabilities.max_turns\n        self._timeout_s = self.capabilities.timeout_s\n\n        # Stats\n        self._stats: dict[str, Any] = {\n            "tasks_completed": 0,'
if BAD1 in src:
    src = src.replace(BAD1, GOOD1, 1)
    print("[1] Fixed merged current_task/stats line")

# ─────────────────────────────────────────────────────────────────────
# FIX 2: Broken assign_task + first broken _execute_task
# ─────────────────────────────────────────────────────────────────────
BAD2 = '    def assign_task(self, task: TaskAssignment) -> bool:\n        """Assign a task to this agent. Returns True if accepted."""\n        if self._state not in (AgentState.IDLE, AgentState.COMPLETED):\n            return False\n)\n        return True\n\n    def _execute_task(self, task: TaskAssignment) -> None:\n        """Execute a task in a background thread.\n\n        Cross-examination additions:\n        - Abort check (Anthropic: AbortController)\n        - Turn counting with maxTurns enforcement\n        - Timeout enforcement\n        - Comprehensive cleanup protocol (Anthropic\n        self._thread = threading.Thread(\n            target=self._execute_task,\n            args=(task,),\n            daemon=True,\n            name=f"agent-{self.agent_id}",\n        )\n        self._thread.start()\n        return True\n'
GOOD2 = '    def assign_task(self, task: TaskAssignment) -> bool:\n        """Assign a task to this agent. Returns True if accepted."""\n        if self._state not in (AgentState.IDLE, AgentState.COMPLETED):\n            return False\n        self._current_task = task\n        self._abort_event.clear()\n        self._turns = 0\n        self._set_state(AgentState.RUNNING)\n        self._thread = threading.Thread(\n            target=self._execute_task,\n            args=(task,),\n            daemon=True,\n            name=f"agent-{self.agent_id}",\n        )\n        self._thread.start()\n        return True\n'
if BAD2 in src:
    src = src.replace(BAD2, GOOD2, 1)
    print("[2] Fixed broken assign_task + removed first broken _execute_task")

# ─────────────────────────────────────────────────────────────────────
# FIX 3: dispatch_task duplicate - replace entire dispatch_task method
# ─────────────────────────────────────────────────────────────────────
BAD3_MARKER = "        Cross-examination additions:\n        - Typed task ID prefix (Anthropic: a/b/r/t/w/m/d)\n        - Worker tool visibility injection into context\n        - Dead-agent guard\n\n        Returns the TaskAssignment, or None if agent is busy or dead.\n"
if BAD3_MARKER in src:
    dt_def = "    def dispatch_task(\n"
    dt_start = src.rfind(dt_def, 0, src.index(BAD3_MARKER))
    dp_def = "    def dispatch_parallel("
    dp_start = src.index(dp_def, src.index(BAD3_MARKER))

    CLEAN_DT = '    def dispatch_task(\n        self,\n        role: AgentRoleType,\n        description: str,\n        instructions: str = "",\n        context: dict[str, Any] | None = None,\n        priority: int = 0,\n    ) -> TaskAssignment | None:\n        """Dispatch a task to a specific agent role."""\n        agent = self._agents.get(role)\n        if not agent:\n            return None\n\n        # Dead-agent guard (Anthropic: isTerminalTaskStatus)\n        if agent.state == AgentState.RETIRED:\n            logger.warning("Coordinator: %s is retired, cannot dispatch", agent.name)\n            return None\n\n        # Typed task ID with role prefix\n        prefix = TASK_PREFIX_MAP.get(role.value, "c")\n        task_id = f"{prefix}-{uuid.uuid4().hex[:8]}"\n\n        # Inject worker tool visibility\n        enriched_context = dict(context or {})\n        enriched_context["worker_tools"] = agent.capabilities.allowed_tools\n        enriched_context["worker_mode"] = agent.capabilities.execution_mode.value\n        enriched_context["worker_read_only"] = agent.capabilities.read_only\n        enriched_context["max_turns"] = agent.capabilities.max_turns\n        enriched_context["timeout_s"] = agent.capabilities.timeout_s\n\n        task = TaskAssignment(\n            task_id=task_id,\n            description=description,\n            instructions=instructions,\n            assigned_to=agent.agent_id,\n            priority=priority,\n            context=enriched_context,\n        )\n\n        success = agent.assign_task(task)\n        if success:\n            with self._lock:\n                self._pending_results[task.task_id] = task\n            self._emit({\n                "type": "agent_task_dispatched",\n                "role": role.value,\n                "agent_id": agent.agent_id,\n                "task_id": task.task_id,\n                "description": description,\n            })\n            logger.info(\n                "Coordinator: dispatched task to %s (%s)",\n                agent.name, agent.agent_id,\n            )\n            return task\n\n        logger.warning(\n            "Coordinator: %s is busy, cannot dispatch",\n            agent.name,\n        )\n        return None\n\n'
    src = src[:dt_start] + CLEAN_DT + src[dp_start:]
    print("[3] Fixed duplicate dispatch_task")

# ─────────────────────────────────────────────────────────────────────
# FIX 3b: dispatch_parallel docstring contains Anthropic's (apostrophe)
# ─────────────────────────────────────────────────────────────────────
BAD3B = '        """Dispatch multiple tasks in parallel.\n\n        Re-written from Anthropic\'s coordinator pattern:\n        "To launch workers in parallel, make multiple tool calls in a single message."\n        """'
GOOD3B = '        """Dispatch multiple tasks in parallel."""'
if BAD3B in src:
    src = src.replace(BAD3B, GOOD3B, 1)
    print("[3b] Simplified dispatch_parallel docstring")

# ─────────────────────────────────────────────────────────────────────
# FIX 3c: run_cycle docstring contains Anthropic's (apostrophe)
# ─────────────────────────────────────────────────────────────────────
BAD3C = '        """Run one full agent cycle: Defense -> Recon -> Strategy -> Exploit -> Memory.\n\n        Re-written from Anthropic\'s coordinator phase model:\n        Research (parallel) -> Synthesis (coordinator) -> Implementation -> Verification\n        """'
GOOD3C = '        """Run one full agent cycle: Defense -> Recon -> Strategy -> Exploit -> Memory."""'
if BAD3C in src:
    src = src.replace(BAD3C, GOOD3C, 1)
    print("[3c] Simplified run_cycle docstring")

# ─────────────────────────────────────────────────────────────────────
# FIX 4: Old _wait_for_tasks fragment + missing return
# ─────────────────────────────────────────────────────────────────────
BAD4 = '        Cross-examination: now handles aborted/timeout terminal states.\n        """\n'
if BAD4 in src:
    frag_start = src.index(BAD4)
    clean_wait = "    def _wait_for_tasks("
    frag_end = src.index(clean_wait, frag_start)
    src = src[:frag_start] + '        return results\n\n' + src[frag_end:]
    print("[4] Removed old _wait_for_tasks fragment + added return results")

# ─────────────────────────────────────────────────────────────────────
# FIX 5: Truncated resume_agent + dup abort/get_agent_memory
# ─────────────────────────────────────────────────────────────────────
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
    print("[5] Fixed resume_agent + removed first dup abort/get_agent_memory")

# ─────────────────────────────────────────────────────────────────────
# FIX 6: Any remaining docstrings with unescaped Anthropic's
# ─────────────────────────────────────────────────────────────────────
# Replace multi-line docstrings that contain "Anthropic's" with simplified versions
# This fixes any remaining triple-quote pairing issues caused by apostrophes
# Let's find and fix them
lines_list = src.splitlines(True)
fixed_docstrings = 0
i = 0
while i < len(lines_list):
    line = lines_list[i]
    stripped = line.rstrip()
    # Multi-line docstring opening (not self-closing)
    if '"""' in stripped and stripped.count('"""') == 1 and stripped.endswith('"""') is False:
        # This might be a multi-line docstring opening
        # Check if any line before the closing """ contains Anthropic's
        j = i + 1
        has_anthropic = False
        close_idx = None
        while j < len(lines_list) and j < i + 20:
            jline = lines_list[j].rstrip()
            if "Anthropic's" in jline or "Anthropic\\'s" in jline:
                has_anthropic = True
            if '"""' in jline:
                close_idx = j
                break
            j += 1
        # Don't modify the module docstring (line 1)
        if has_anthropic and close_idx and i > 5:
            # Simplify to single-line docstring
            # Extract the first line of the docstring
            opening = stripped
            first_sentence = opening.split('"""', 1)[1].strip()
            if first_sentence:
                indent = line[:len(line) - len(line.lstrip())]
                new_line = f'{indent}"""{first_sentence}"""\n'
                lines_list[i] = new_line
                # Remove lines i+1 through close_idx
                del lines_list[i+1:close_idx+1]
                fixed_docstrings += 1
    i += 1

if fixed_docstrings:
    src = "".join(lines_list)
    print(f"[6] Simplified {fixed_docstrings} multi-line docstrings with apostrophes")

# ─────────────────────────────────────────────────────────────────────
# VALIDATE
# ─────────────────────────────────────────────────────────────────────
new_lines = src.splitlines()
print(f"\nResult: {len(new_lines)} lines (was {original_len})")

# Check corruption
issues = []
for i, line in enumerate(new_lines, 1):
    if "Noneelf" in line:
        issues.append(f"  L{i}: Noneelf")
    if "snapshot()LE)" in line:
        issues.append(f"  L{i}: snapshot()LE)")
    if line.rstrip().endswith("AgentState.ID") and "IDLE" not in line:
        issues.append(f"  L{i}: truncated AgentState.ID")
if issues:
    print("REMAINING CORRUPTION:")
    for iss in issues:
        print(iss)
else:
    print("No known corruption patterns remain")

# Check duplicates
methods = {}
for i, line in enumerate(new_lines, 1):
    m = re.match(r"^(\s+)def (\w+)\(", line)
    if m:
        key = (len(m.group(1)), m.group(2))
        methods.setdefault(key, []).append(i)
dups = {k: v for k, v in methods.items() if len(v) > 1 and k[1] not in ("__init__", "to_dict")}
if dups:
    print("REMAINING DUPLICATES:")
    for key, locs in sorted(dups.items()):
        print(f"  {key[1]} (indent={key[0]}): lines {locs}")
else:
    print("No duplicate methods remain")

# Triple-quote trace
tq = '"""'
in_tq = False
last_open_line = 0
for i, line in enumerate(new_lines, 1):
    count = line.count(tq)
    for _ in range(count):
        in_tq = not in_tq
        if in_tq:
            last_open_line = i
if in_tq:
    print(f"UNCLOSED triple-quote at L{last_open_line}: {new_lines[last_open_line-1].rstrip()[:80]}")
    for j in range(max(0, last_open_line-2), min(len(new_lines), last_open_line+5)):
        print(f"  L{j+1}: {new_lines[j].rstrip()[:100]}")
else:
    print("Triple-quotes all paired correctly")

# AST check
try:
    ast.parse(src)
    print("\nAST parse: OK")
    with open(FILE, "w", encoding="utf-8", newline="\n") as f:
        f.write(src)
    print(f"Written {len(new_lines)} lines to {FILE}")
except SyntaxError as e:
    print(f"\nAST FAILED L{e.lineno}: {e.msg}")
    print(f"  Text: {e.text!r}")
    for j in range(max(0, e.lineno - 5), min(len(new_lines), e.lineno + 3)):
        marker = ">>>" if j + 1 == e.lineno else "   "
        print(f"  {marker} L{j+1}: {new_lines[j][:100]}")
    print("NOT writing file")
    sys.exit(1)
"""Comprehensive repair of agent_roles.py -- v2 (no textwrap.dedent)."""
import re, sys

FILE = "tools/burp_enterprise/agent_roles.py"

with open(FILE, "r", encoding="utf-8") as f:
    src = f.read()

original_len = len(src.splitlines())
print(f"[0] Read {original_len} lines")

# ── FIX 0: Module docstring merged with AGENT_COLORS, imports missing ───
BAD0 = '  - State isolation (own working memory)AGENT_COLORS = {'
GOOD0 = (
    '  - State isolation (own working memory)\n'
    '"""\n'
    'from __future__ import annotations\n'
    '\n'
    'import enum\n'
    'import logging\n'
    'import threading\n'
    'import time\n'
    'import uuid\n'
    'from collections import defaultdict, deque\n'
    'from dataclasses import dataclass, field\n'
    'from typing import Any, Callable\n'
    '\n'
    'logger = logging.getLogger(__name__)\n'
    '\n'
    '# *******************************************************************\n'
    '# CONSTANTS (Cross-examination: typed task IDs, agent colors, limits)\n'
    '# *******************************************************************\n'
    '\n'
    'TASK_PREFIX_MAP = {\n'
    '    "recon": "r",\n'
    '    "exploit": "e",\n'
    '    "strategy": "s",\n'
    '    "memory": "m",\n'
    '    "defense": "d",\n'
    '    "coordinator": "c",\n'
    '}\n'
    '\n'
    'AGENT_AUTO_TIMEOUT_S = 120.0\n'
    'DEFAULT_MAX_TURNS = 100\n'
    '\n'
    'AGENT_COLORS = {'
)
if BAD0 in src:
    src = src.replace(BAD0, GOOD0, 1)
    print("[0] Fixed merged docstring/imports/AGENT_COLORS")
else:
    print("[0] SKIP: already fixed")

# ── FIX 1: Merged line in SpecialistAgent.__init__ ──────────────────────
BAD1 = '        self._current_task: TaskAssignment | None = Noneelf   "tasks_completed": 0,'
GOOD1 = (
    '        self._current_task: TaskAssignment | None = None\n'
    '        self._thread: threading.Thread | None = None\n'
    '        self._abort_event = threading.Event()\n'
    '        self._turns = 0\n'
    '        self._turn_count = 0\n'
    '        self._max_turns = self.capabilities.max_turns\n'
    '        self._timeout_s = self.capabilities.timeout_s\n'
    '\n'
    '        # Stats\n'
    '        self._stats: dict[str, Any] = {\n'
    '            "tasks_completed": 0,'
)
if BAD1 in src:
    src = src.replace(BAD1, GOOD1, 1)
    print("[1] Fixed merged current_task/stats line")
else:
    print("[1] SKIP: already fixed")

# ── FIX 2: Broken assign_task + first broken _execute_task ──────────────
BAD2 = (
    '    def assign_task(self, task: TaskAssignment) -> bool:\n'
    '        """Assign a task to this agent. Returns True if accepted."""\n'
    '        if self._state not in (AgentState.IDLE, AgentState.COMPLETED):\n'
    '            return False\n'
    ')\n'
    '        return True\n'
    '\n'
    '    def _execute_task(self, task: TaskAssignment) -> None:\n'
    '        """Execute a task in a background thread.\n'
    '\n'
    '        Cross-examination additions:\n'
    '        - Abort check (Anthropic: AbortController)\n'
    '        - Turn counting with maxTurns enforcement\n'
    '        - Timeout enforcement\n'
    '        - Comprehensive cleanup protocol (Anthropic\n'
    '        self._thread = threading.Thread(\n'
    '            target=self._execute_task,\n'
    '            args=(task,),\n'
    '            daemon=True,\n'
    '            name=f"agent-{self.agent_id}",\n'
    '        )\n'
    '        self._thread.start()\n'
    '        return True\n'
)
GOOD2 = (
    '    def assign_task(self, task: TaskAssignment) -> bool:\n'
    '        """Assign a task to this agent. Returns True if accepted."""\n'
    '        if self._state not in (AgentState.IDLE, AgentState.COMPLETED):\n'
    '            return False\n'
    '        self._current_task = task\n'
    '        self._abort_event.clear()\n'
    '        self._turns = 0\n'
    '        self._set_state(AgentState.RUNNING)\n'
    '        self._thread = threading.Thread(\n'
    '            target=self._execute_task,\n'
    '            args=(task,),\n'
    '            daemon=True,\n'
    '            name=f"agent-{self.agent_id}",\n'
    '        )\n'
    '        self._thread.start()\n'
    '        return True\n'
)
if BAD2 in src:
    src = src.replace(BAD2, GOOD2, 1)
    print("[2] Fixed broken assign_task + removed first broken _execute_task")
else:
    print("[2] SKIP: already fixed")

# ── FIX 3: dispatch_task duplicate ──────────────────────────────────────
BAD3_MARKER = (
    "        Cross-examination additions:\n"
    "        - Typed task ID prefix (Anthropic: a/b/r/t/w/m/d)\n"
    "        - Worker tool visibility injection into context\n"
    "        - Dead-agent guard\n"
    "\n"
    "        Returns the TaskAssignment, or None if agent is busy or dead.\n"
)
if BAD3_MARKER in src:
    dt_def = "    def dispatch_task(\n"
    dt_start = src.rfind(dt_def, 0, src.index(BAD3_MARKER))
    dp_def = "    def dispatch_parallel("
    dp_start = src.index(dp_def, src.index(BAD3_MARKER))

    CLEAN_DT = (
        '    def dispatch_task(\n'
        '        self,\n'
        '        role: AgentRoleType,\n'
        '        description: str,\n'
        '        instructions: str = "",\n'
        '        context: dict[str, Any] | None = None,\n'
        '        priority: int = 0,\n'
        '    ) -> TaskAssignment | None:\n'
        '        """Dispatch a task to a specific agent role."""\n'
        '        agent = self._agents.get(role)\n'
        '        if not agent:\n'
        '            return None\n'
        '\n'
        '        # Dead-agent guard (Anthropic: isTerminalTaskStatus)\n'
        '        if agent.state == AgentState.RETIRED:\n'
        '            logger.warning("Coordinator: %s is retired, cannot dispatch", agent.name)\n'
        '            return None\n'
        '\n'
        '        # Typed task ID with role prefix\n'
        '        prefix = TASK_PREFIX_MAP.get(role.value, "c")\n'
        '        task_id = f"{prefix}-{uuid.uuid4().hex[:8]}"\n'
        '\n'
        '        # Inject worker tool visibility\n'
        '        enriched_context = dict(context or {})\n'
        '        enriched_context["worker_tools"] = agent.capabilities.allowed_tools\n'
        '        enriched_context["worker_mode"] = agent.capabilities.execution_mode.value\n'
        '        enriched_context["worker_read_only"] = agent.capabilities.read_only\n'
        '        enriched_context["max_turns"] = agent.capabilities.max_turns\n'
        '        enriched_context["timeout_s"] = agent.capabilities.timeout_s\n'
        '\n'
        '        task = TaskAssignment(\n'
        '            task_id=task_id,\n'
        '            description=description,\n'
        '            instructions=instructions,\n'
        '            assigned_to=agent.agent_id,\n'
        '            priority=priority,\n'
        '            context=enriched_context,\n'
        '        )\n'
        '\n'
        '        success = agent.assign_task(task)\n'
        '        if success:\n'
        '            with self._lock:\n'
        '                self._pending_results[task.task_id] = task\n'
        '            self._emit({\n'
        '                "type": "agent_task_dispatched",\n'
        '                "role": role.value,\n'
        '                "agent_id": agent.agent_id,\n'
        '                "task_id": task.task_id,\n'
        '                "description": description,\n'
        '            })\n'
        '            logger.info(\n'
        '                "Coordinator: dispatched \'%s\' to %s (%s)",\n'
        '                description, agent.name, agent.agent_id,\n'
        '            )\n'
        '            return task\n'
        '\n'
        '        logger.warning(\n'
        '            "Coordinator: %s is busy, cannot dispatch \'%s\'",\n'
        '            agent.name, description,\n'
        '        )\n'
        '        return None\n'
        '\n'
    )
    src = src[:dt_start] + CLEAN_DT + src[dp_start:]
    print("[3] Fixed duplicate dispatch_task")
else:
    print("[3] SKIP: already fixed")

# ── FIX 3b: dispatch_parallel docstring with Anthropic's ────────────────
BAD3B = (
    '    def dispatch_parallel(\n'
    '        self,\n'
    '        tasks: list[tuple[AgentRoleType, str, str, dict[str, Any] | None]],\n'
    '    ) -> list[TaskAssignment]:\n'
    '        """Dispatch multiple tasks in parallel.\n'
    '\n'
    "        Re-written from Anthropic's coordinator pattern:\n"
    '        "To launch workers in parallel, make multiple tool calls in a single message."\n'
    '        """'
)
GOOD3B = (
    '    def dispatch_parallel(\n'
    '        self,\n'
    '        tasks: list[tuple[AgentRoleType, str, str, dict[str, Any] | None]],\n'
    '    ) -> list[TaskAssignment]:\n'
    '        """Dispatch multiple tasks in parallel."""'
)
if BAD3B in src:
    src = src.replace(BAD3B, GOOD3B, 1)
    print("[3b] Simplified dispatch_parallel docstring")
else:
    print("[3b] SKIP: already fixed")

# ── FIX 4: Old _wait_for_tasks fragment ─────────────────────────────────
BAD4 = '        Cross-examination: now handles aborted/timeout terminal states.\n        """\n'
if BAD4 in src:
    frag_start = src.index(BAD4)
    clean_wait = "    def _wait_for_tasks("
    frag_end = src.index(clean_wait, frag_start)
    # Insert missing return statement for run_cycle before the clean _wait_for_tasks
    src = src[:frag_start] + '        return results\n\n' + src[frag_end:]
    print("[4] Removed old _wait_for_tasks fragment + added return results")
else:
    print("[4] SKIP: already fixed")

# ── FIX 5: Truncated resume_agent + dup abort/get_agent_memory ──────────
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
    print("[5] Fixed resume_agent + removed first dup abort/get_agent_memory")
else:
    print("[5] SKIP: already fixed")

# ── VALIDATE ────────────────────────────────────────────────────────────
new_lines = src.splitlines()
print(f"\n[*] Result: {len(new_lines)} lines (was {original_len})")

issues = []
for i, line in enumerate(new_lines, 1):
    if "Noneelf" in line: issues.append(f"  L{i}: Noneelf")
    if "snapshot()LE)" in line: issues.append(f"  L{i}: snapshot()LE)")
    if line.rstrip().endswith("AgentState.ID") and "IDLE" not in line:
        issues.append(f"  L{i}: truncated AgentState.ID")

if issues:
    print("REMAINING CORRUPTION:")
    for iss in issues: print(iss)
else:
    print("[*] No known corruption patterns remain")

methods = {}
for i, line in enumerate(new_lines, 1):
    m = re.match(r"^(\s+)def (\w+)\(", line)
    if m:
        key = (len(m.group(1)), m.group(2))
        methods.setdefault(key, []).append(i)

dups = {k: v for k, v in methods.items() if len(v) > 1 and k[1] not in ("__init__", "to_dict")}
if dups:
    print("REMAINING DUPLICATES:")
    for key, locs in sorted(dups.items()):
        print(f"  {key[1]} (indent={key[0]}): lines {locs}")
else:
    print("[*] No duplicate methods remain")

import ast
try:
    ast.parse(src)
    print("[*] AST parse: OK")
    with open(FILE, "w", encoding="utf-8", newline="\n") as f:
        f.write(src)
    print(f"[*] Written {len(new_lines)} lines to {FILE}")
except SyntaxError as e:
    print(f"\n[!] AST FAILED L{e.lineno}: {e.msg}")
    print(f"    Text: {e.text!r}")
    # Show context around the error
    for j in range(max(0, e.lineno - 5), min(len(new_lines), e.lineno + 3)):
        marker = ">>>" if j + 1 == e.lineno else "   "
        print(f"  {marker} L{j+1}: {new_lines[j][:100]}")
    # Show all triple-quotes within 100 lines of error
    tq = '"""'
    print("\n  Triple-quotes within +/-100 lines of error:")
    for j in range(max(0, e.lineno - 100), min(len(new_lines), e.lineno + 10)):
        if tq in new_lines[j]:
            print(f"    L{j+1}: {new_lines[j].rstrip()[:100]}")
    print("[!] NOT writing file")
    sys.exit(1)
"""
Comprehensive repair of agent_roles.py.
Strategy: content‑based string replacements for each known corruption,
then duplicate‑method removal by keeping the SECOND (complete) copy.
"""
import re, textwrap, sys

FILE = "tools/burp_enterprise/agent_roles.py"

with open(FILE, "r", encoding="utf-8") as f:
    src = f.read()

original_len = len(src.splitlines())
print(f"[1] Read {original_len} lines")

# ── FIX 1: Merged line in SpecialistAgent.__init__ ──────────────────────
# "self._current_task: TaskAssignment | None = Noneelf   "tasks_completed": 0,"
# Should be the current_task line, then several init lines, then stats dict.
BAD1 = '        self._current_task: TaskAssignment | None = Noneelf   "tasks_completed": 0,'
GOOD1 = textwrap.dedent("""\
        self._current_task: TaskAssignment | None = None
        self._thread: threading.Thread | None = None
        self._abort_event = threading.Event()
        self._turns = 0
        self._turn_count = 0
        self._max_turns = self.capabilities.max_turns
        self._timeout_s = self.capabilities.timeout_s

        # Stats
        self._stats: dict[str, Any] = {
            "tasks_completed": 0,""")
if BAD1 in src:
    src = src.replace(BAD1, GOOD1, 1)
    print("[1] Fixed merged current_task/stats line")
else:
    print("[1] WARN: merged line not found (already fixed?)")

# ── FIX 2: Broken assign_task + first broken _execute_task ──────────────
# assign_task body is truncated to just the state check + orphaned ')' + 'return True',
# then the first (incomplete) _execute_task docstring contains the assign_task thread-start code.
# We replace from the assign_task def through the end of the first broken _execute_task
# (up to but NOT including `def abort(self)`).
BAD2_START = '    def assign_task(self, task: TaskAssignment) -> bool:\n        """Assign a task to this agent. Returns True if accepted."""\n        if self._state not in (AgentState.IDLE, AgentState.COMPLETED):\n            return False\n)\n        return True\n\n    def _execute_task(self, task: TaskAssignment) -> None:\n        """Execute a task in a background thread.\n\n        Cross-examination additions:\n        - Abort check (Anthropic: AbortController)\n        - Turn counting with maxTurns enforcement\n        - Timeout enforcement\n        - Comprehensive cleanup protocol (Anthropic\n        self._thread = threading.Thread(\n            target=self._execute_task,\n            args=(task,),\n            daemon=True,\n            name=f"agent-{self.agent_id}",\n        )\n        self._thread.start()\n        return True\n'
GOOD2 = textwrap.dedent("""\
    def assign_task(self, task: TaskAssignment) -> bool:
        \"\"\"Assign a task to this agent. Returns True if accepted.\"\"\"
        if self._state not in (AgentState.IDLE, AgentState.COMPLETED):
            return False
        self._current_task = task
        self._abort_event.clear()
        self._turns = 0
        self._set_state(AgentState.RUNNING)
        self._thread = threading.Thread(
            target=self._execute_task,
            args=(task,),
            daemon=True,
            name=f"agent-{self.agent_id}",
        )
        self._thread.start()
        return True

""")
if BAD2_START in src:
    src = src.replace(BAD2_START, GOOD2, 1)
    print("[2] Fixed broken assign_task + removed first broken _execute_task")
else:
    print("[2] WARN: broken assign_task pattern not found")

# ── FIX 3: dispatch_task duplicate ──────────────────────────────────────
# The dispatch_task has a clean start (def + docstring + first few lines of body)
# then raw text from old docstring, then a second complete body, then
# duplicate tool-visibility injection.
# We replace from `def dispatch_task(` through `return None\n\n    def dispatch_parallel(`
# with a single clean implementation.
BAD3_MARKER = "        Cross-examination additions:\n        - Typed task ID prefix (Anthropic: a/b/r/t/w/m/d)\n        - Worker tool visibility injection into context\n        - Dead-agent guard\n\n        Returns the TaskAssignment, or None if agent is busy or dead.\n"
if BAD3_MARKER in src:
    # Find the dispatch_task def that precedes the bad marker
    dt_def = "    def dispatch_task(\n"
    dt_start = src.rfind(dt_def, 0, src.index(BAD3_MARKER))
    # Find where dispatch_parallel def starts
    dp_def = "    def dispatch_parallel("
    dp_start = src.index(dp_def, src.index(BAD3_MARKER))
    
    CLEAN_DISPATCH = textwrap.dedent("""\
    def dispatch_task(
            self,
            role: AgentRoleType,
            description: str,
            instructions: str = "",
            context: dict[str, Any] | None = None,
            priority: int = 0,
        ) -> TaskAssignment | None:
            \"\"\"Dispatch a task to a specific agent role.\"\"\"
            agent = self._agents.get(role)
            if not agent:
                return None

            # Dead-agent guard (Anthropic: isTerminalTaskStatus)
            if agent.state == AgentState.RETIRED:
                logger.warning("Coordinator: %s is retired, cannot dispatch", agent.name)
                return None

            # Typed task ID with role prefix
            prefix = TASK_PREFIX_MAP.get(role.value, "c")
            task_id = f"{prefix}-{uuid.uuid4().hex[:8]}"

            # Inject worker tool visibility (Anthropic: getCoordinatorUserContext)
            enriched_context = dict(context or {})
            enriched_context["worker_tools"] = agent.capabilities.allowed_tools
            enriched_context["worker_mode"] = agent.capabilities.execution_mode.value
            enriched_context["worker_read_only"] = agent.capabilities.read_only
            enriched_context["max_turns"] = agent.capabilities.max_turns
            enriched_context["timeout_s"] = agent.capabilities.timeout_s

            task = TaskAssignment(
                task_id=task_id,
                description=description,
                instructions=instructions,
                assigned_to=agent.agent_id,
                priority=priority,
                context=enriched_context,
            )

            success = agent.assign_task(task)
            if success:
                with self._lock:
                    self._pending_results[task.task_id] = task
                self._emit({
                    "type": "agent_task_dispatched",
                    "role": role.value,
                    "agent_id": agent.agent_id,
                    "task_id": task.task_id,
                    "description": description,
                })
                logger.info(
                    "Coordinator: dispatched '%s' to %s (%s)",
                    description, agent.name, agent.agent_id,
                )
                return task

            logger.warning(
                "Coordinator: %s is busy, cannot dispatch '%s'",
                agent.name, description,
            )
            return None

    """)
    src = src[:dt_start] + CLEAN_DISPATCH + src[dp_start:]
    print("[3] Fixed duplicate dispatch_task")
else:
    print("[3] WARN: dispatch_task duplicate marker not found")

# ── FIX 4: Old _wait_for_tasks fragment ─────────────────────────────────
# After run_cycle's return statement there's an old fragment:
#   "        Cross-examination: now handles aborted/timeout terminal states.\n        \"\"\"\n"
# followed by incomplete code, then the clean _wait_for_tasks.
BAD4_START = '        Cross-examination: now handles aborted/timeout terminal states.\n        """\n'
if BAD4_START in src:
    # Find the start of this fragment
    frag_start = src.index(BAD4_START)
    # The fragment runs until the clean `def _wait_for_tasks` line
    clean_wait = "    def _wait_for_tasks("
    frag_end = src.index(clean_wait, frag_start)
    # Also need to remove the preceding line that may have `results["duration_s"]`
    # Go back to find the line before the fragment
    src = src[:frag_start] + src[frag_end:]
    print("[4] Removed old _wait_for_tasks fragment")
else:
    print("[4] WARN: old _wait_for_tasks fragment not found")

# ── FIX 5: Truncated resume_agent + first duplicate abort_agent/get_agent_memory ──
# "agent._set_state(AgentState.ID\n\n    def abort_agent..." is garbled.
# The resume_agent body is missing `LE)\n            return True\n        return False`.
# Then the first abort_agent + get_agent_memory appear, followed by garbled `snapshot()LE)`.
# Then the clean second copies appear.
BAD5 = "            agent._set_state(AgentState.ID\n"
if BAD5 in src:
    idx5 = src.index(BAD5)
    # Find the second (clean) abort_agent - it's the one with docstring "Abort a running agent's current task."
    # Actually, find the first abort_agent AFTER idx5
    first_abort = src.index("    def abort_agent(", idx5)
    # Find where get_agent_memory ends (after snapshot()LE))
    merged_end_marker = "snapshot()LE)"
    me_idx = src.index(merged_end_marker, first_abort)
    # Find the next line after the merged end
    next_nl = src.index("\n", me_idx) + 1
    # Now find the second abort_agent (the clean one)
    second_abort = src.index("    def abort_agent(", next_nl)
    
    # Replace from BAD5 through the garbled get_agent_memory end with clean resume_agent ending
    GOOD5 = "            agent._set_state(AgentState.IDLE)\n            return True\n        return False\n\n"
    src = src[:idx5] + GOOD5 + src[second_abort:]
    print("[5] Fixed resume_agent + removed first duplicate abort_agent/get_agent_memory")
else:
    print("[5] WARN: truncated resume_agent not found")

# ── VALIDATE ────────────────────────────────────────────────────────────
new_lines = src.splitlines()
print(f"[*] Result: {len(new_lines)} lines (was {original_len})")

# Check for remaining corruption
issues = []
for i, line in enumerate(new_lines, 1):
    s = line.rstrip()
    if "Noneelf" in s:
        issues.append(f"  L{i}: Still has Noneelf")
    if s.endswith("snapshot()LE)"):
        issues.append(f"  L{i}: Still has snapshot()LE)")
    if s.rstrip().endswith("AgentState.ID") and "IDLE" not in s:
        issues.append(f"  L{i}: Still has truncated AgentState.ID")

if issues:
    print("REMAINING ISSUES:")
    for iss in issues:
        print(iss)
else:
    print("[*] No known corruption patterns remain")

# Check for duplicate methods
methods = {}
for i, line in enumerate(new_lines, 1):
    m = re.match(r"^(\s+)def (\w+)\(", line)
    if m:
        indent = len(m.group(1))
        name = m.group(2)
        key = (indent, name)
        if key not in methods:
            methods[key] = []
        methods[key].append(i)

dups = {k: v for k, v in methods.items() if len(v) > 1 and k[1] not in ("__init__", "to_dict")}
if dups:
    print("REMAINING DUPLICATES:")
    for key, locs in sorted(dups.items()):
        print(f"  {key[1]} (indent={key[0]}): lines {locs}")
else:
    print("[*] No duplicate methods remain")

# Try AST parse
import ast
try:
    ast.parse(src)
    print("[*] AST parse: OK")
    # Write it!
    with open(FILE, "w", encoding="utf-8", newline="\n") as f:
        f.write(src)
    print(f"[*] Written {len(new_lines)} lines to {FILE}")
except SyntaxError as e:
    print(f"[!] AST FAILED L{e.lineno}: {e.msg}")
    print(f"    Text: {e.text!r}")
    print("[!] NOT writing file -- manual review needed")
    sys.exit(1)
