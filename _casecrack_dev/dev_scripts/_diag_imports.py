"""Quick diagnostic — check key modules import and report what's broken."""
import sys, traceback, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

errors = []

modules = [
    "tools.burp_enterprise.tool_wrappers._defaults",
    "tools.burp_enterprise.decision_trace",
    "tools.burp_enterprise.loop.feedback_loop_breaker",
    "tools.burp_enterprise.recon_dashboard.server",
]

for m in modules:
    try:
        __import__(m)
        print(f"OK  {m}")
    except Exception as e:
        err = traceback.format_exc()
        print(f"ERR {m}: {e}")
        errors.append((m, err))

if errors:
    print("\n=== FULL TRACEBACKS ===")
    for m, tb in errors:
        print(f"\n--- {m} ---")
        print(tb)

sys.exit(len(errors))
