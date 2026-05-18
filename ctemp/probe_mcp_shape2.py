import sys
import asyncio

sys.path.insert(0, r'c:\Users\ya754\CaseCrack v1.0\CaseCrack')

from tools.burp_enterprise.mcp.mcp_server import SecurityMCPServer
from tools.burp_enterprise.mcp.mcp_auth import MCPPrincipal

async def main():
    s = SecurityMCPServer()
    p = MCPPrincipal(principal_id='probe', tenant_id='control-plane', role='system', auth_type='probe', claims={'plan': 'enterprise', 'admin_control': True})
    probes = [
        ('get_progress_snapshot', {}),
        ('get_tenant_control_summary', {}),
        ('get_tenant_control_status', {'tenant_id': 'control-plane'}),
        ('get_recent_tenant_control_events', {'tenant_id': 'control-plane', 'limit': 5}),
        ('list_targets', {'include_sessions': True, 'limit': 5}),
        ('get_report', {}),
    ]
    for i, (name, args) in enumerate(probes, start=1):
        rid = f'probe{i}'
        try:
            payload, is_error = await s.execute_tool_request(name, args, principal=p, request_id=rid)
            print('===', name, 'error=', is_error)
            print(payload[:2000])
        except Exception as exc:
            print('===', name, 'EXC', type(exc).__name__, str(exc))

asyncio.run(main())
