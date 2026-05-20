import tempfile, os, threading
import tools.burp_enterprise.decision_orchestrator as mod
AT = None
for name in dir(mod):
    obj = getattr(mod, name)
    if isinstance(obj, type) and hasattr(obj, "save") and hasattr(obj, "_maybe_auto_persist"):
        AT = obj; break
print("Class:", AT.__name__)
with tempfile.TemporaryDirectory() as td:
    path = os.path.join(td, "x.json")
    t = AT(persist_path=path)
    def target():
        with t._lock:
            t.save()
    th = threading.Thread(target=target)
    th.start(); th.join(timeout=5)
    if th.is_alive():
        print("DEADLOCK STILL PRESENT"); os._exit(1)
    print("save() re-entrant OK, file size:", os.path.getsize(path))
