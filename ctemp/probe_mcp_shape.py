import sys
import asyncio

sys.path.insert(0, r'c:\Users\ya754\CaseCrack v1.0\CaseCrack')

from tools.burp_enterprise.mcp.mcp_server import SecurityMCPServer
from tools.burp_enterprise.mcp.mcp_auth import MCPPrincipal

async def main():
    s = SecurityMCPServer()
    p = MCPPrincipal(
        principal_id='probe',
        tenant_id='control-plane',
        role='system',
        auth_type='probe',
        claims={'plan': 'enterprise', 'admin_control': True},
    )
    for name, rid, args in [
        ('get_dashboard', 'probe1', {}),
        ('get_tenant_control_summary', 'probe2', {}),
        ('list_targets', 'probe3', {'include_sessions': True, 'limit': 5}),
        ('get_report', 'probe4', {}),
    ]:
        payload, is_error = await s.execute_tool_request(name, args, principal=p, request_id=rid)
        print('===', name, 'error=', is_error)
        print(payload[:3000])

asyncio.run(main())
