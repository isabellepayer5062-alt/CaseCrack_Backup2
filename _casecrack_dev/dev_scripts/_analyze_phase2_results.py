#!/usr/bin/env python3
"""
Comprehensive Phase 2 High-ROI Idempotency Testing Analysis

Aggregates results from webhook, refund, and subscription tests.
"""

import json
import os
from typing import Any, Dict, List

def analyze_webhook_results() -> Dict[str, Any]:
    """Analyze webhook test results."""
    try:
        with open("paypal_webhook_idempotency_results.json") as f:
            data = json.load(f)
        
        stats = data.get("stats", {})
        escalation = data.get("escalation_gate", {})
        rows = data.get("rows", [])
        
        # Classify webhook findings
        findings = []
        for row in rows:
            principal = row.get("principal")
            classification = row.get("classification")
            webhook_exists = row.get("first_delivery", {}).get("webhook_exists")
            
            if classification == "pass_consistent" and webhook_exists:
                findings.append(f"✅ {principal}: Webhook events consistently handled (200)")
            elif not webhook_exists:
                findings.append(f"⚠️  {principal}: Webhook not found (404) - expected for foreign principal")
        
        return {
            "test": "Webhook Re-Delivery Idempotency",
            "status": "completed",
            "escalate": escalation.get("should_escalate", False),
            "stats": stats,
            "findings": findings,
        }
    except FileNotFoundError:
        return {"test": "Webhook", "status": "not_run", "error": "results_file_not_found"}


def analyze_refund_results() -> Dict[str, Any]:
    """Analyze refund test results."""
    try:
        with open("paypal_refund_idempotency_results.json") as f:
            data = json.load(f)
        
        error = data.get("error")
        if error:
            return {
                "test": "Refund Idempotency",
                "status": "failed",
                "error": error,
                "reason": data.get("result", {}).get("error"),
                "escalate": False,
                "recommendation": "Refund test requires order creation with capture. May require approved order or additional scopes.",
            }
        
        stats = data.get("stats", {})
        escalation = data.get("escalation_gate", {})
        
        return {
            "test": "Refund Idempotency",
            "status": "completed",
            "escalate": escalation.get("should_escalate", False),
            "stats": stats,
            "findings": [
                f"✅ No authz bypass detected (user_b denied refunds)" if stats.get("candidate_authz_bypass", 0) == 0 else "🔴 Authz bypass possible",
                f"✅ No accounting inconsistency (refund IDs unique)" if stats.get("candidate_accounting_inconsistency", 0) == 0 else "🔴 Accounting inconsistency",
                f"✅ No refund bypass (double-refund prevented)" if stats.get("candidate_refund_bypass", 0) == 0 else "🔴 Double-refund possible",
            ],
        }
    except FileNotFoundError:
        return {"test": "Refund", "status": "not_run", "error": "results_file_not_found"}


def analyze_subscription_results() -> Dict[str, Any]:
    """Analyze subscription test results."""
    try:
        with open("paypal_subscription_idempotency_results.json") as f:
            data = json.load(f)
        
        error = data.get("error")
        if error:
            return {
                "test": "Subscription Billing Cycle Replay",
                "status": "failed",
                "error": error,
                "reason": data.get("result", {}).get("error"),
                "escalate": False,
                "recommendation": "Subscription test requires plan and subscription creation. May require specific API scopes or plan types.",
            }
        
        stats = data.get("stats", {})
        escalation = data.get("escalation_gate", {})
        
        return {
            "test": "Subscription Billing Cycle Replay",
            "status": "completed",
            "escalate": escalation.get("should_escalate", False),
            "stats": stats,
            "findings": [
                f"✅ No idempotency bypass (same key not processed twice)" if stats.get("candidate_idempotency_bypass", 0) == 0 else "🔴 Idempotency bypass possible",
                f"✅ No multiple billing cycles (phantom charges prevented)" if stats.get("candidate_multiple_billing_cycles", 0) == 0 else "🔴 Multiple cycles possible",
            ],
        }
    except FileNotFoundError:
        return {"test": "Subscription", "status": "not_run", "error": "results_file_not_found"}


def main() -> None:
    """Analyze all Phase 2 tests."""
    
    print("\n" + "=" * 80)
    print("PAYPAL HIGH-ROI IDEMPOTENCY TESTING - PHASE 2 ANALYSIS")
    print("=" * 80)
    
    # Analyze all three tests
    tests = [
        analyze_webhook_results(),
        analyze_refund_results(),
        analyze_subscription_results(),
    ]
    
    total_escalate = 0
    total_completed = 0
    
    for test in tests:
        print(f"\n{'─' * 80}")
        print(f"TEST: {test['test']}")
        print(f"{'─' * 80}")
        
        if test.get("status") == "failed":
            print(f"❌ Status: FAILED")
            print(f"   Error: {test.get('error')}")
            print(f"   Reason: {test.get('reason')}")
            print(f"   Recommendation: {test.get('recommendation')}")
        elif test.get("status") == "not_run":
            print(f"⏭️  Status: NOT RUN")
            print(f"   {test.get('error')}")
        else:
            print(f"✅ Status: COMPLETED")
            total_completed += 1
            
            stats = test.get("stats", {})
            print(f"\n   Statistics:")
            for key, value in stats.items():
                if key != "rows":
                    print(f"     - {key}: {value}")
            
            print(f"\n   Key Findings:")
            for finding in test.get("findings", []):
                print(f"     {finding}")
            
            escalate = test.get("escalate", False)
            print(f"\n   Escalation: {'🔴 YES - NEEDS ESCALATION' if escalate else '✅ NO - SECURE'}")
            total_escalate += escalate
    
    # Summary
    print(f"\n{'=' * 80}")
    print("SUMMARY")
    print(f"{'=' * 80}")
    print(f"Total tests completed: {total_completed}/3")
    print(f"Total escalations: {total_escalate}")
    
    if total_escalate > 0:
        print(f"\n🔴 CRITICAL: {total_escalate} test(s) flagged for escalation!")
        print("   Prepare HackerOne report with findings.")
    else:
        print(f"\n✅ All completed tests passed idempotency validation.")
    
    # Recommendations
    print(f"\n{'─' * 80}")
    print("NEXT STEPS")
    print(f"{'─' * 80}")
    
    if any(t.get("status") == "failed" for t in tests):
        print("""
1. FIX FAILING TESTS:
   - Refund test: May require approved order setup first
   - Subscription test: May require additional API scopes
   
   Recommendation: Use approved order from earlier phase
   $env:PAYPAL_SB_APPROVED_ORDER_ID = '43782398JL607945X'
   
2. RERUN WITH APPROVED ORDER:
   python paypal_refund_idempotency_harness.py
   python paypal_subscription_idempotency_harness.py
        """)
    else:
        print("""
1. REVIEW DETAILED RESULTS:
   - paypal_webhook_idempotency_results.json
   - paypal_refund_idempotency_results.json
   - paypal_subscription_idempotency_results.json
   
2. IF ESCALATIONS FOUND:
   - Extract key findings from JSON
   - Prepare HackerOne report
   - Include reproduction steps and proof
   
3. IF NO ESCALATIONS:
   - Continue to Phase 3 testing (advanced scenarios)
   - Consider payment authorization flows
   - Test cross-tenant payment tampering
        """)
    
    print()


if __name__ == "__main__":
    main()
