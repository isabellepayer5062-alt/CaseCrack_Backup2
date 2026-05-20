#!/usr/bin/env python3
"""Final verification that Phase A implementation is complete."""

# Verify mcp_server.py
with open('CaseCrack/tools/burp_enterprise/mcp/mcp_server.py', 'r', encoding='utf-8') as f:
    server_content = f.read()
    
transport_count = server_content.count('transport=transport')
entry_point_count = server_content.count('entry_point=entry_point')
transport_param = 'transport: str = ' in server_content
entry_point_param = 'entry_point: str = ' in server_content

print('mcp_server.py:')
print(f'  transport parameter: {transport_param}')
print(f'  entry_point parameter: {entry_point_param}')
print(f'  transport=transport in audits: {transport_count} times')
print(f'  entry_point=entry_point in audits: {entry_point_count} times')

# Verify mcp_http_server.py
with open('CaseCrack/tools/burp_enterprise/mcp/mcp_http_server.py', 'r', encoding='utf-8') as f:
    http_content = f.read()

mapping_defined = '_TOOL_TO_ENTRY_POINT = {' in http_content
get_entry_point = 'def _get_entry_point' in http_content
execute_call = 'transport="BRIDGE"' in http_content and 'entry_point=entry_point' in http_content

print('\nmcp_http_server.py:')
print(f'  mapping defined: {mapping_defined}')
print(f'  _get_entry_point method: {get_entry_point}')
print(f'  execute_tool_request call: {execute_call}')

all_good = all([transport_param, entry_point_param, transport_count == 8, 
                entry_point_count == 8, mapping_defined, get_entry_point, execute_call])
                
print(f'\n{"="*50}')
print(f'RESULT: {"PASS - ALL CHECKS VERIFIED" if all_good else "FAIL - SOME CHECKS FAILED"}')
print(f'{"="*50}')

import sys
sys.exit(0 if all_good else 1)
