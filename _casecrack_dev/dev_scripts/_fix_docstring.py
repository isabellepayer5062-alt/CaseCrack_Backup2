"""Replace the mangled module docstring in agent_roles.py."""
import os

path = os.path.join(os.path.dirname(__file__), "tools", "burp_enterprise", "agent_roles.py")

with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

# Find line with 'from __future__' - that's where real code starts
code_start = None
for i, line in enumerate(lines):
    if "from __future__" in line:
        code_start = i
        break

if code_start is None:
    print("Cannot find 'from __future__' import")
    exit(1)

print(f"Code starts at line {code_start + 1}")

# Replace everything before code_start with clean docstring
new_docstring = '''"""Explicit Multi-Agent Role System -- parallel reasoning, specialization, cleaner scaling.

Re-written from Anthropic's multi-agent architecture. Key patterns preserved:

  Anthropic pattern                   -> CaseCrack re-write
  ------------------------------------------------------------------
  Coordinator Mode (orchestrator)     -> AgentCoordinator (central dispatch)
  Agent tool + BaseAgentDefinition    -> AgentRole (explicit role contracts)
  TeamFile + teammate members         -> AgentRegistry (live agent tracking)
  task-notification XML               -> AgentMessage (typed message bus)
  SendMessage + mailbox filesystem    -> AgentMailbox (in-memory + EventBus)
  TeamCreate/TeamDelete lifecycle     -> AgentCoordinator.spawn/retire
  In-process AsyncLocalStorage        -> Thread-based context isolation
  Scratchpad directory                -> SharedContext (cross-agent state)
  Fork prompt cache sharing           -> SharedContext.findings / beliefs
  Coordinator phase model             -> Phase-based dispatch to specialists

Architecture:
  +------------------------------------------------------------------+
  | AgentCoordinator (orchestrates all specialist agents)             |
  |  +-- ReconAgent    -- discovery: subdomains, ports, tech, crawl   |
  |  +-- ExploitAgent  -- validation: PoC, exploit chains, proof      |
  |  +-- StrategyAgent -- prioritization: phase/budget/mode choice    |
  |  +-- MemoryAgent   -- learning: cross-scan patterns, recall       |
  |  +-- DefenseAgent  -- evasion: WAF bypass, stealth, rate-limit    |
  |                                                                    |
  |  Communication:                                                    |
  |  AgentMailbox (typed messages) + SharedContext (shared state)      |
  |  AgentMessage (structured)     + EventBus (real-time events)      |
  +------------------------------------------------------------------+

Each agent is a logical role with:
  - Defined inputs/outputs (contract)
  - Allowed tools (capability boundary)
  - Priority level (execution order)
  - Parallel execution flag (can run concurrently?)
  - State isolation (own working memory)
"""

'''

lines[:code_start] = [new_docstring]

with open(path, "w", encoding="utf-8") as f:
    f.writelines(lines)

print("FIXED - clean docstring written")
