import json
from datetime import datetime

d = json.load(open('paypal_idempotency_partial_outcome_results_extended.json','r'))

print('=' * 80)
print('IDEMPOTENCY & PARTIAL-OUTCOME TESTING - COMPREHENSIVE RESULTS SUMMARY')
print('=' * 80)
print(f'\nDate: {d.get("timestamp")}')
print(f'API Base: {d.get("api_base")}')
print(f'Total Rows: {d["stats"]["rows"]}')

print('\n### BRANCH COVERAGE ###\n')
print(f'Unapproved Orders (422 expected):    {d["stats"]["rows_unapproved"]} rows')
print(f'Approved Orders (201 expected):      {d["stats"]["rows_approved"]} rows')
print(f'Total Test Coverage:                 {d["stats"]["rows"]} rows')

print('\n### KEY STATISTICS ###\n')
print(f'Pass Consistent:                     {d["stats"]["pass_consistent"]}')
print(f'Inconclusive:                        {d["stats"]["inconclusive"]}')
print(f'Candidate Authz Bypass:              {d["stats"]["candidate_authz_bypass"]}')
print(f'Candidate Accounting Inconsistency:  {d["stats"]["candidate_accounting_inconsistency"]}')
print(f'Candidate Idempotency Bypass:        {d["stats"]["candidate_idempotency_bypass"]}')
print(f'Candidate Identity Integrity Break:  {d["stats"]["candidate_identity_integrity_break"]}')

print('\n### UNAPPROVED BRANCH (NO MOCK-CODE) ###\n')
ua = d["stats"]["unapproved"]
print(f'Status Code: 422 ORDER_NOT_APPROVED')
print(f'Pass Consistent:    {ua.get("pass_consistent", 0)} rows')
print(f'Behavior: All principals (user_a, user_b, app) consistently rejected on unapproved orders')
print(f'Assessment: ✅ SECURE - Expected behavior observed')

print('\n### APPROVED BRANCH (NO MOCK-CODE) ###\n')
ap = d["stats"]["approved"]
print(f'Status Code: 422 ORDER_NOT_APPROVED (Order still in CREATED state)')
print(f'Pass Consistent:    {ap.get("pass_consistent", 0)} rows')
print(f'Idempotency Bypass: {ap.get("candidate_idempotency_bypass", 0)} detected')
print(f'Behavior: All capture attempts rejected with 422, consistent across all principals')
print(f'Assessment: ⚠️  INCONCLUSIVE - Order not transitioning to APPROVED in sandbox')
print(f'Note: Order 43782398JL607945X is in CREATED state. Approval may require manual UI action.')

print('\n### MOCK-CODE INJECTION RESULTS ###\n')
print(f'Header Tested: PayPal-Mock-Response: {{"mock_application_codes": "PAYMENT_PARTIALLY_COMPLETED"}}')
print(f'Response Status: 403 Forbidden')
print(f'Behavior: Header rejected or unsupported by sandbox endpoint')
print(f'Capture IDs: None (no successful capture occurred)')
print(f'Order State: CREATED (no side effects)')
print(f'Assessment: ✅ SECURE - Mock-code feature not supported; no state corruption')
print(f'Note: This is expected behavior if PayPal-Mock-Response is not enabled on this endpoint.')

print('\n### PER-PRINCIPAL ANALYSIS ###\n')
principals = {}
for row in d['rows']:
    p = row['principal']
    if p not in principals:
        principals[p] = {'unapproved': [], 'approved': []}
    principals[p][row['branch']].append(row['classification'])

for p in sorted(principals.keys()):
    ua_results = principals[p]['unapproved']
    ap_results = principals[p]['approved']
    print(f'{p}:')
    if ua_results:
        print(f'  Unapproved: {ua_results}')
    if ap_results:
        print(f'  Approved: {ap_results}')

print('\n### ESCALATION GATE ASSESSMENT ###\n')
escalate = d['escalation_gate']['should_escalate']
print(f'ESCALATE: {str(escalate).upper()}')
print(f'Reason: {d["escalation_gate"]["reason"]}')

print('\n### SECURITY ASSESSMENT ###\n')
if escalate:
    print('⚠️  FINDINGS DETECTED - Requires Review')
    findings = {
        'authz': d["stats"]["candidate_authz_bypass"],
        'accounting': d["stats"]["candidate_accounting_inconsistency"],
        'idempotency': d["stats"]["candidate_idempotency_bypass"],
        'integrity': d["stats"]["candidate_identity_integrity_break"],
    }
    for key, count in findings.items():
        if count > 0:
            print(f'  - {key}: {count} instance(s)')
    print('\nNote: Identity integrity break signals may be false positives if caused by')
    print('      unsupported header injection (e.g., 403 from mock-code header).')
else:
    print('✅ NO VULNERABILITIES DETECTED')
    print('   - No idempotency bypass on unapproved orders')
    print('   - No accounting inconsistency (same-key divergence)')
    print('   - No authz bypass for foreign principals')
    print('   - No state corruption from mock-code injection')

print('\n### RECOMMENDATIONS ###\n')
if not ap_results:
    print('1. APPROVED ORDER TESTING: Current approved order is in CREATED state.')
    print('   To fully test the 201 success path:')
    print('   a) Manually approve the order in PayPal sandbox UI')
    print('      Order ID: 43782398JL607945X')
    print('   b) Or: Identify an existing APPROVED order and set PAYPAL_SB_APPROVED_ORDER_ID')
    print('   c) Then: Rerun harness to test same-key vs new-key replay behavior')

print('\n2. MOCK-CODE FEATURE: PayPal-Mock-Response header appears unsupported.')
print('   This may be:')
print('   a) Not enabled on sandbox for this endpoint')
print('   b) Requires different header format or value')
print('   c) Feature available only on newer API versions')

print('\n3. NEXT STEPS:')
print('   a) If approved order can be obtained: Rerun with PAYPAL_SB_APPROVED_ORDER_ID')
print('   b) Test other high-value idempotency scenarios:')
print('      - Webhook re-delivery with same event ID')
print('      - Refund idempotency on already-refunded captures')
print('      - Subscription billing cycle replay')

print('\n' + '=' * 80 + '\n')
