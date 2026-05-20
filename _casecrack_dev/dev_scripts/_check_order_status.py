#!/usr/bin/env python3
"""Check order status and available captures for refund testing."""

import json
import os
import requests

token = os.getenv('PAYPAL_SB_USER_BEARER_A', '').strip()
base = 'https://api-m.sandbox.paypal.com'
order_id = '43782398JL607945X'

url = f'{base}/v2/checkout/orders/{order_id}'
headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/json'}

try:
    r = requests.get(url, headers=headers, timeout=10)
    print(f'[*] Order Status Check')
    print(f'    HTTP Status: {r.status_code}')
    
    if r.status_code == 200:
        data = r.json()
        print(f'    Order Status: {data.get("status")}')
        
        pu = data.get('purchase_units', [])
        if pu:
            amount = pu[0].get('amount', {})
            print(f'    Amount: {amount.get("value")} {amount.get("currency_code")}')
            
            payments = pu[0].get('payments', {})
            captures = payments.get('captures', [])
            authorizations = payments.get('authorizations', [])
            
            print(f'    Captures: {len(captures)}')
            if captures:
                for cap in captures:
                    print(f'      - {cap.get("id")}: {cap.get("status")}')
            
            print(f'    Authorizations: {len(authorizations)}')
            if authorizations:
                for auth in authorizations:
                    print(f'      - {auth.get("id")}: {auth.get("status")}')
        
        # Can we use this for refund testing?
        if captures and any(c.get('status') == 'COMPLETED' for c in captures):
            print('[+] ORDER READY FOR REFUND TESTING')
        else:
            print('[-] Order has no completed captures - refund test cannot proceed without approval')
    else:
        print(f'    Error: {r.status_code}')
        
except Exception as e:
    print(f'Error: {e}')
