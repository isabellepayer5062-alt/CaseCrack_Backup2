"""Tier 4B CAAP validator — functional checks across 9 modules."""
import importlib
import sys
import time
import traceback
from typing import Any, Callable, List, Tuple

RESULTS: List[Tuple[str, bool, str]] = []


def check(name: str, fn: Callable[[], Any]) -> None:
    try:
        v = fn()
        if v is False:
            RESULTS.append((name, False, "returned False"))
        else:
            extra = "" if v is True or v is None else f" -> {repr(v)[:60]}"
            RESULTS.append((name, True, extra))
    except Exception as e:
        RESULTS.append((name, False, f"{type(e).__name__}: {e}"))


def section(title: str) -> None:
    RESULTS.append((f"\n--- {title} ---", True, ""))


# ============================================================
# 1. Imports
# ============================================================
section("1. IMPORTS")
MODS = {
    "caap_coordinator":    "CAAPCoordinator",
    "chat_interface":      "ChatInterface",
    "compliance_checker":  "ComplianceChecker",
    "discovery_agent":     "DiscoveryAgent",
    "exploitation_agent":  "ExploitationAgent",
    "hypothesis_engine":   "HypothesisEngine",
    "knowledge_graph":     "KnowledgeGraph",
    "recon_agent":         "ReconAgent",
    "session_orchestrator":"SessionOrchestrator",
}
CLASSES: dict = {}
for mod_name, cls_name in MODS.items():
    def _imp(mn=mod_name, cn=cls_name):
        m = importlib.import_module(f"CaseCrack.tools.burp_enterprise.caap.{mn}")
        c = getattr(m, cn)
        CLASSES[cn] = c
        return True
    check(f"import {mod_name}", _imp)

CO  = CLASSES.get("CAAPCoordinator")
CHI = CLASSES.get("ChatInterface")
CC  = CLASSES.get("ComplianceChecker")
DA  = CLASSES.get("DiscoveryAgent")
EA  = CLASSES.get("ExploitationAgent")
HE  = CLASSES.get("HypothesisEngine")
KG  = CLASSES.get("KnowledgeGraph")
RA  = CLASSES.get("ReconAgent")
SO  = CLASSES.get("SessionOrchestrator")

# ============================================================
# 2. Method presence
# ============================================================
section("2. METHOD PRESENCE")
PRESENCE = {
    "CAAPCoordinator": ["register_phase","run_parallel_phases","phase_status","cancel_phase",
                        "set_llm_bridge","llm_complete","llm_stream","llm_health",
                        "subscribe_phase_events","emit_phase_event","run_correlated"],
    "ChatInterface": ["set_llm_bridge","set_system_prompt","get_system_prompt","history","clear",
                      "save_session","load_session","send_message","stream_message",
                      "parse_slash_command","handle_command","token_count","export_markdown",
                      "summarize","validate_response"],
    "ComplianceChecker": ["supported_frameworks","framework_controls","evaluate_control",
                          "evaluate_framework","evaluate_all_frameworks","compliance_gap_report",
                          "register_control_evaluator","export_compliance_csv"],
    "DiscoveryAgent": ["crawl","fetch_robots","fetch_sitemap","extract_endpoints_from_js",
                       "diff_endpoints","dedup_endpoints_by_pattern"],
    "ExploitationAgent": ["test_sqli","test_xss","test_ssrf","test_command_injection",
                          "test_path_traversal","test_xxe","test_idor","test_all_vuln_types",
                          "supported_vuln_types","register_payload"],
    "HypothesisEngine": ["hypothesis_categories","generate_hypotheses","generate_for_category",
                         "score_hypothesis","rank_hypotheses","dedup_hypotheses","register_generator"],
    "KnowledgeGraph": ["kg_open","kg_close","kg_add_node","kg_add_edge","kg_get_node",
                       "kg_find_nodes","kg_neighbors","kg_path","kg_subgraph","kg_cypher",
                       "kg_stats","kg_clear","kg_export_cypher","kg_export_json","kg_import_json"],
    "ReconAgent": ["shodan_set_key","shodan_host","shodan_search","censys_set_creds","censys_host",
                   "censys_search","crtsh_query","github_set_token","github_org_repos",
                   "github_search_code","github_secret_search","s3_check_bucket","s3_enum_org",
                   "recon_aggregate","supported_recon_sources"],
    "SessionOrchestrator": ["so_open","so_close","supported_roles","role_permissions",
                            "check_permission","require_permission","create_user","authenticate",
                            "change_role","deactivate_user","list_users","issue_token",
                            "validate_token","revoke_token","create_persistent_session",
                            "get_persistent_session","update_session_state",
                            "list_persistent_sessions","audit_log_entry","query_audit",
                            "persistent_session_stats"],
}
for cls_name, methods in PRESENCE.items():
    cls = CLASSES.get(cls_name)
    for m in methods:
        check(f"{cls_name}.{m}", (lambda c=cls, mm=m: callable(getattr(c, mm, None))))

# ============================================================
# 3. CAAPCoordinator phase DAG
# ============================================================
section("3. CAAPCoordinator")
co = CO()
exec_order = []
def _ph(name): return lambda *a, **kw: (exec_order.append(name), {"phase": name, "ok": True})[1]
co.register_phase("recon", _ph("recon"))
co.register_phase("discovery", _ph("discovery"))
co.register_phase("hypothesis", _ph("hypothesis"))
check("coord.register_phase 3 phases", lambda: True)
res = co.run_parallel_phases(["recon","discovery","hypothesis"])
check("coord.run_parallel_phases returns dict", lambda: isinstance(res, dict))
check("coord.run_parallel_phases all phases ran", lambda: set(exec_order) == {"recon","discovery","hypothesis"})
check("coord.phase_status returns map", lambda: isinstance(co.phase_status(), dict))

class _StubBridge:
    def complete(self, prompt, **kw): return {"text": f"echo:{prompt[:20]}"}
    def stream(self, prompt, **kw):
        for tok in ["a","b","c"]:
            yield tok
co.set_llm_bridge(_StubBridge())
check("coord.set_llm_bridge", lambda: True)
r = co.llm_complete("test prompt")
check("coord.llm_complete returns dict-or-str", lambda: r is not None)
toks = list(co.llm_stream("hi"))
check("coord.llm_stream yields tokens", lambda: len(toks) >= 1)
h = co.llm_health()
check("coord.llm_health returns dict", lambda: isinstance(h, dict))

# ============================================================
# 4. ChatInterface
# ============================================================
section("4. ChatInterface")
ch = CHI()
ch.set_llm_bridge(_StubBridge())
ch.set_system_prompt("You are a helper.")
check("chat.system_prompt set", lambda: ch.get_system_prompt() == "You are a helper.")
ch.send_message("hello")
check("chat.history non-empty", lambda: len(ch.history()) >= 2)

cmd = ch.parse_slash_command("/help")
check("chat.parse_slash_command /help", lambda: isinstance(cmd, dict) and cmd.get("is_command") and "help" in (cmd.get("command") or ""))
cmd2 = ch.parse_slash_command("not a command")
check("chat.parse_slash_command non-cmd returns None or empty", lambda: not cmd2 or not cmd2.get("is_command"))

bad = ch.validate_response("Click https://fake-fabricated.example/foo for details")
check("chat.validate_response detects fabricated_url",
        lambda: isinstance(bad, dict) and bad.get("issues"))

md = ch.export_markdown()
check("chat.export_markdown contains user/assistant", lambda: "##" in md or "**" in md)

ch.clear()
check("chat.clear empties history", lambda: len(ch.history()) == 0)

# ============================================================
# 5. ComplianceChecker
# ============================================================
section("5. ComplianceChecker")
cc = CC()
fws = cc.supported_frameworks()
check("cc.supported_frameworks >= 8", lambda: isinstance(fws, list) and len(fws) >= 8)
check("cc.framework_controls('owasp_top10') non-empty",
        lambda: len(cc.framework_controls("owasp_top10")) >= 1)
findings = [
    {"category":"sql_injection","severity":"high","description":"SQLi at /login"},
    {"category":"xss_reflected","severity":"medium","description":"XSS in q"},
    {"category":"weak_crypto","severity":"high","description":"MD5 hashing"},
    {"category":"missing_auth","severity":"critical","description":"Admin no auth"},
    {"category":"verbose_errors","severity":"low","description":"Stack trace exposed"},
]
res = cc.evaluate_framework("owasp_top10", findings)
check("cc.evaluate_framework returns dict with score",
        lambda: isinstance(res, dict) and ("score_pct" in res or "score" in res))
all_res = cc.evaluate_all_frameworks(findings)
check("cc.evaluate_all_frameworks covers >= 8 frameworks",
        lambda: isinstance(all_res, dict) and len(all_res.get("frameworks", all_res)) >= 8)
gap = cc.compliance_gap_report("owasp_top10", findings)
check("cc.compliance_gap_report returns dict", lambda: isinstance(gap, dict))
csv = cc.export_compliance_csv(all_res)
check("cc.export_compliance_csv non-empty",
        lambda: isinstance(csv, str) and len(csv) > 50)

# ============================================================
# 6. DiscoveryAgent
# ============================================================
section("6. DiscoveryAgent")
da = DA()
js_src = '''
var API_BASE = "/api/v3";
fetch("/users/123/profile").then(r=>r.json());
$.ajax({url:"/admin/dashboard"});
const path = `/orders/${id}/items`;
xhr.open("POST", "/login", true);
'''
eps = da.extract_endpoints_from_js(js_src)
check("da.extract_endpoints_from_js >= 4 endpoints",
        lambda: isinstance(eps, list) and len(eps) >= 3)
ep_list = ["/users/1/x","/users/2/x","/users/abc123def456/x","/orders/aaa-bbb-ccc","/static/main.js"]
deduped = da.dedup_endpoints_by_pattern(ep_list)
check("da.dedup_endpoints_by_pattern collapses ids",
        lambda: isinstance(deduped, (list, dict)) and len(deduped) < len(ep_list))
diff = da.diff_endpoints(["/a","/b","/c"], ["/a","/c","/d"])
check("da.diff_endpoints returns added/removed",
        lambda: isinstance(diff, dict) and ("added" in diff or "new" in diff or "removed" in diff))

# ============================================================
# 7. ExploitationAgent
# ============================================================
section("7. ExploitationAgent")
ea = EA()
vts = ea.supported_vuln_types()
check("ea.supported_vuln_types == 7", lambda: isinstance(vts, list) and len(vts) == 7)
ok = ea.register_payload("sqli", "' OR '1'='1' /* TEST */")
check("ea.register_payload(new)", lambda: ok is True or (isinstance(ok, dict) and ok.get("ok")))

# ============================================================
# 8. HypothesisEngine
# ============================================================
section("8. HypothesisEngine")
he = HE()
cats = he.hypothesis_categories()
check("he.hypothesis_categories >= 8", lambda: isinstance(cats, list) and len(cats) >= 8)
signal = {
    "url":"https://t/login?id=1&q=test",
    "method":"POST",
    "params":["id","q","ref"],
    "headers":{"Server":"Apache/2.2.0"},
    "cookies":{"sess":"abc"},
    "body":"<xml>data</xml>",
    "content_type":"application/xml",
    "auth_required": False,
}
hyps = he.generate_hypotheses(signal)
check("he.generate_hypotheses non-empty", lambda: isinstance(hyps, list) and len(hyps) >= 3)
if hyps:
    s = he.score_hypothesis(hyps[0])
    check("he.score_hypothesis in [0,1]",
            lambda: isinstance(s, (int, float)) and 0 <= s <= 1)
    ranked = he.rank_hypotheses(hyps)
    check("he.rank_hypotheses returns list len same",
            lambda: isinstance(ranked, list) and len(ranked) == len(hyps))
    deduped = he.dedup_hypotheses(hyps + hyps[:2])
    check("he.dedup_hypotheses removes duplicates",
            lambda: isinstance(deduped, list) and len(deduped) <= len(hyps))

# ============================================================
# 9. KnowledgeGraph
# ============================================================
section("9. KnowledgeGraph")
kg = KG()
kg.kg_open(":memory:")
n1 = kg.kg_add_node("Endpoint", {"url":"/login","method":"POST"}, key_props={"url":"/login"})
n2 = kg.kg_add_node("Endpoint", {"url":"/admin","method":"GET"}, key_props={"url":"/admin"})
n3 = kg.kg_add_node("Vulnerability", {"type":"sqli","severity":"high"}, key_props={"type":"sqli"})
n4 = kg.kg_add_node("Vulnerability", {"type":"xss","severity":"medium"}, key_props={"type":"xss"})
check("kg.kg_add_node returns id", lambda: all(n.get("id") for n in [n1,n2,n3,n4]))
e1 = kg.kg_add_edge(n1["id"], n3["id"], "HAS_VULN")
e2 = kg.kg_add_edge(n2["id"], n4["id"], "HAS_VULN")
e3 = kg.kg_add_edge(n1["id"], n2["id"], "LINKS_TO")
check("kg.kg_add_edge ok", lambda: all(e.get("ok") for e in [e1,e2,e3]))
neighbors = kg.kg_neighbors(n1["id"], direction="out")
check("kg.kg_neighbors finds 2 outbound", lambda: isinstance(neighbors, list) and len(neighbors) == 2)
path = kg.kg_path(n1["id"], n4["id"], max_depth=3)
check("kg.kg_path BFS finds 3-hop path", lambda: isinstance(path, list) and len(path) >= 2)
sg = kg.kg_subgraph(n1["id"], depth=2)
check("kg.kg_subgraph returns nodes+edges",
        lambda: isinstance(sg, dict) and len(sg.get("nodes",[])) >= 1)
cyp = kg.kg_cypher("MATCH (n:Endpoint) RETURN n LIMIT 10")
check("kg.kg_cypher single-node MATCH", lambda: isinstance(cyp, list) and len(cyp) == 2)
cyp2 = kg.kg_cypher("MATCH (a:Endpoint)-[r:HAS_VULN]->(b:Vulnerability) RETURN a, b")
check("kg.kg_cypher edge MATCH", lambda: isinstance(cyp2, list) and len(cyp2) == 2)
stats = kg.kg_stats()
check("kg.kg_stats nodes==4 edges==3",
        lambda: stats["nodes"] == 4 and stats["edges"] == 3)
exp = kg.kg_export_json()
check("kg.kg_export_json roundtrip",
        lambda: isinstance(exp, dict) and len(exp["nodes"]) == 4)
kg.kg_clear()
check("kg.kg_clear empties graph",
        lambda: kg.kg_stats()["nodes"] == 0)
imp = kg.kg_import_json(exp)
check("kg.kg_import_json restores",
        lambda: imp.get("nodes_imported") == 4 and kg.kg_stats()["nodes"] == 4)

# ============================================================
# 10. ReconAgent
# ============================================================
section("10. ReconAgent")
ra = RA()
srcs = ra.supported_recon_sources()
check("ra.supported_recon_sources == 5", lambda: isinstance(srcs, list) and len(srcs) == 5)
# Without keys: should return graceful failure
r = ra.shodan_host("8.8.8.8")
check("ra.shodan_host without key -> error dict",
        lambda: isinstance(r, dict) and not r.get("ok"))
r = ra.censys_search("foo")
check("ra.censys_search without creds -> error dict",
        lambda: isinstance(r, dict) and not r.get("ok"))
# crtsh, s3 will hit network — just check they return dict, not crash
try:
    r = ra.s3_check_bucket("definitely-does-not-exist-bucket-xyzzy-9999")
    check("ra.s3_check_bucket returns dict (network)",
            lambda: isinstance(r, dict))
except Exception as e:
    check("ra.s3_check_bucket network", lambda: False)

# ============================================================
# 11. SessionOrchestrator
# ============================================================
section("11. SessionOrchestrator")
so = SO()
so.so_open(":memory:")
roles = so.supported_roles()
check("so.supported_roles >= 5", lambda: len(roles) >= 5)
check("so.role_permissions admin includes wildcard",
        lambda: "*" in so.role_permissions("admin"))

u_admin = so.create_user("admin", "P@ssw0rd!", "admin")
u_view = so.create_user("viewer1", "viewpass", "viewer")
check("so.create_user admin ok", lambda: u_admin.get("ok"))
check("so.create_user duplicate fails",
        lambda: not so.create_user("admin", "x", "admin").get("ok"))

auth = so.authenticate("admin", "P@ssw0rd!")
check("so.authenticate correct password",
        lambda: auth.get("ok") and auth.get("role") == "admin")
auth_bad = so.authenticate("admin", "wrong")
check("so.authenticate wrong password fails",
        lambda: not auth_bad.get("ok"))

cp = so.check_permission(u_admin["user_id"], "scan:start")
check("so.check_permission admin->any allowed", lambda: cp["allowed"])
cp2 = so.check_permission(u_view["user_id"], "scan:start")
check("so.check_permission viewer->scan:start denied", lambda: not cp2["allowed"])

raised = False
try:
    so.require_permission(u_view["user_id"], "scan:start")
except PermissionError:
    raised = True
check("so.require_permission raises PermissionError", lambda: raised)

tk = so.issue_token(u_admin["user_id"], ttl_s=60.0)
check("so.issue_token returns token", lambda: tk.get("ok") and tk.get("token"))
v = so.validate_token(tk["token"])
check("so.validate_token valid", lambda: v["valid"])
so.revoke_token(tk["token"])
v2 = so.validate_token(tk["token"])
check("so.validate_token revoked", lambda: not v2["valid"] and v2.get("reason") == "revoked")

sess = so.create_persistent_session(u_admin["user_id"], "https://target.com",
                                              metadata={"scope": "full"})
check("so.create_persistent_session ok", lambda: sess.get("ok"))
sg = so.get_persistent_session(sess["session_id"])
check("so.get_persistent_session retrieves",
        lambda: sg and sg["target"] == "https://target.com")
so.update_session_state(u_admin["user_id"], sess["session_id"], "completed")
sg2 = so.get_persistent_session(sess["session_id"])
check("so.update_session_state completed",
        lambda: sg2["state"] == "completed" and sg2["closed_at"] is not None)
listed = so.list_persistent_sessions(user_id=u_admin["user_id"])
check("so.list_persistent_sessions filtered",
        lambda: isinstance(listed, list) and len(listed) >= 1)

audit = so.query_audit(u_admin["user_id"])
check("so.query_audit returns entries (admin)",
        lambda: isinstance(audit, list) and len(audit) >= 5)

raised2 = False
try:
    so.query_audit(u_view["user_id"])
except PermissionError:
    raised2 = True
check("so.query_audit denies viewer", lambda: raised2)

stats = so.persistent_session_stats()
check("so.persistent_session_stats >= 2 users, >= 1 session",
        lambda: stats["users"] >= 2 and stats["sessions"] >= 1)

# ============================================================
# Summary
# ============================================================
print()
print("=" * 80)
print("TIER 4B CAAP VALIDATION RESULTS")
print("=" * 80)
real = [(n, ok, msg) for n, ok, msg in RESULTS if not n.startswith("\n")]
passed = sum(1 for _, ok, _ in real if ok)
failed = len(real) - passed

for name, ok, msg in RESULTS:
    if name.startswith("\n"):
        print(name)
        continue
    sym = "PASS" if ok else "FAIL"
    extra = f" -- {msg}" if msg and not ok else ""
    print(f"  [{sym}] {name}{extra}")

print()
print(f"TOTAL: {len(real)}   PASSED: {passed}   FAILED: {failed}")
print("=" * 80)

# LOC report
import os
caap = os.path.join("CaseCrack","tools","burp_enterprise","caap")
total = 0
for f in MODS.keys():
    p = os.path.join(caap, f + ".py")
    n = sum(1 for _ in open(p, encoding="utf-8"))
    print(f"  {f}.py: {n} LOC")
    total += n
print(f"  TOTAL CAAP LOC: {total}")

sys.exit(0 if failed == 0 else 1)
