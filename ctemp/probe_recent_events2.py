import sys
import asyncio
sys.path.insert(0, r'c:\Users\ya754\CaseCrack v1.0\CaseCrack')
from tools.burp_enterprise.mcp.mcp_server import SecurityMCPServer
from tools.burp_enterprise.mcp.mcp_auth import MCPPrincipal

async def main():
    s = SecurityMCPServer()
    p = MCPPrincipal(principal_id='probe', tenant_id='control-plane', role='system', auth_type='probe', claims={'plan': 'enterprise', 'admin_control': True})
    args={'tenant_id':'control-plane'}
    payload, is_error = await s.execute_tool_request('get_recent_tenant_control_events', args, principal=p, request_id='x')
    print(is_error)
    print(payload[:2000])

asyncio.run(main())
