#!/usr/bin/env python
"""Patch: Add immutable effective execution plans storage to server.py"""

import sys

# Insert effective execution plans storage into server.py
with open(r'CaseCrack/tools/burp_enterprise/recon_dashboard/server.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Find the insertion point: after self._agent_loop_task
insert_idx = None
for i, line in enumerate(lines):
    if 'self._agent_loop_task: asyncio.Task' in line:
        insert_idx = i + 1
        break

if insert_idx:
    new_lines = [
        '\n',
        '        # ── Immutable Effective Execution Plans (Phase C1) ──\n',
        '        # Storage for frozen execution plans, keyed by plan_id (UUID).\n',
        '        # Plans become the authoritative runtime contract per scan session,\n',
        '        # enabling reproducibility, forensic replay, operator auditing,\n',
        '        # regression validation, and post-run analysis.\n',
        '        # Plans are immutable-per-run: UI edits apply only to future scans,\n',
        '        # not active ones (otherwise execution semantics shift mid-run).\n',
        '        self._effective_execution_plans: dict[str, dict[str, Any]] = {}\n',
        '        self._plans_lock = threading.Lock()  # Protects _effective_execution_plans\n',
        '        self._plan_id_to_session_id: dict[str, str] = {}  # Temp mapping while session_id resolves\n',
    ]
    lines = lines[:insert_idx] + new_lines + lines[insert_idx:]
    
    with open(r'CaseCrack/tools/burp_enterprise/recon_dashboard/server.py', 'w', encoding='utf-8') as f:
        f.writelines(lines)
    print("✓ Inserted effective_execution_plans storage into server.py")
    sys.exit(0)
else:
    print("✗ Could not find insertion point")
    sys.exit(1)
