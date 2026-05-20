"""Generate the human-readable RECONNECTION_ROADMAP.md from the JSON data."""
import json
from pathlib import Path

WORKSPACE = Path(r"C:\Users\ya754\CaseCrack v1.0")
data = json.load(open(WORKSPACE / "RECONNECTION_ROADMAP.json"))

lines = []
P = lines.append

# ── Header ──────────────────────────────────────────────────────────────
P("# CaseCrack Reconnection & Reimplementation Roadmap")
P("")
P("**Generated:** 2026-04-16  ")
P("**Sources:** True Dead Module Classifier (RR/CR/TD) · 3-Bucket Triage (Garbage/Cold/Reconnect) · Final Loss Inventory")
P("")
P("---")
P("")
P("## 0 · Executive Summary")
P("")
s = data["summary"]
P(f"- **{s['active_modules']}** modules total in the package after recovery")
P(f"- **{s['reconnect_tasks']}** Reconnect tasks (alive code, needs wiring)")
P(f"- **{s['cr_documentation_tasks']}** Conditionally-reachable modules (alive, need flag/trigger documentation)")
P(f"- **{s['rr_baseline_tasks']}** Runtime-reachable modules (already wired — verification only)")
P(f"- **{s['reimplementation_tasks']}** Permanently lost modules requiring reimplementation")
P(f"- **{s['dangling_imports']}** dangling import sites in the current graph (canary for missing surfaces)")
P("")
P("Total work units: **{}** (50 wiring + 130 doc + 201 reimpl)".format(50 + 130 + 201))
P("")
P("---")
P("")

# ── Phase 0: Foundation ─────────────────────────────────────────────────
P("## Phase 0 · Foundations (do this first)")
P("")
P("Pre-requisites that unblock every later phase. Estimated 1–2 working days.")
P("")
P("| # | Task | Output | Why |")
P("|---|------|--------|-----|")
P("| 0.1 | **Audit the 382 dangling imports** — group by missing target module to know which lost modules are *actively referenced* by surviving code | `dangling_imports_by_target.json` | Tells us which lost modules MUST be reimplemented vs which are nice-to-have |")
P("| 0.2 | **Inventory canonical entrypoints** in `execution_reality_map.py` (currently 19) and confirm none are broken | green-light run of reality map | All reachability flows from these |")
P("| 0.3 | **Document EventBus contract** (`.on/.emit/.off`) — the *only* sanctioned cross-module wire | `EVENTBUS_CONTRACT.md` | Reconnections must use this; ad-hoc imports caused the original drift |")
P("| 0.4 | **Stand up an integration smoke harness** that imports each entrypoint and exercises a 30-second mock scan against `https://example.com` | `tests/test_smoke_entrypoints.py` | Catch silent regressions during reconnections |")
P("| 0.5 | **Lock the cleanup script behind `--apply`** and add a unit test that asserts no `rmtree` calls in `dead_module_cleanup.py` | passing test | Prevent another mass-deletion |")
P("")
P("**Exit criteria:** smoke harness green for all 19 entrypoints, dangling-import index built, EventBus contract written.")
P("")
P("---")
P("")

# ── Phase 1: Reconnect (highest ROI, code is alive) ─────────────────────
P("## Phase 1 · Reconnect 50 High-Value Modules (code is alive)")
P("")
P("These modules survived recovery and have **ROI scores ≥ 40** from the triage.")
P("They are sorted by score (highest first). Each one needs an entrypoint wire,")
P("an EventBus subscription, or a registry registration.")
P("")
P("### 1.1 Wiring Pattern (apply to every task in this phase)")
P("")
P("```python")
P("# 1. Identify canonical entrypoint that should own this module")
P("# 2. Add lazy import inside that entrypoint's __init__ or boot path")
P("# 3. Register with the canonical Registry / EventBus")
P("# 4. Add a unit test that imports the module + asserts a public class is wired")
P("# 5. Re-run execution_reality_map.py and confirm module is now reachable")
P("```")
P("")
P("### 1.2 Reconnect Task Table")
P("")
P("| Score | Subsystem | Module | LOC | Public API (excerpt) | Wiring Target |")
P("|-------|-----------|--------|-----|----------------------|----------------|")

# Sort by score desc
recon_sorted = sorted(data["reconnect_tasks"], key=lambda t: -t["score"])
for t in recon_sorted:
    classes = ", ".join(t["api_classes"][:3]) or "—"
    target = t["subsystem"]  # heuristic — owner is the subsystem
    mod_link = t["module"].replace(".", "/")
    P(f"| {int(t['score'])} | `{t['subsystem']}` | [`{t['module']}`]({t['path'].replace(chr(92), '/')}) | {t['loc']} | {classes} | `{target}` boot path |")

P("")
P("**Exit criteria:** all 50 modules reachable from at least one entrypoint;")
P("reachability count climbs from 721 → ≥ 770.")
P("")
P("---")
P("")

# ── Phase 2: Document conditional reachability ──────────────────────────
P("## Phase 2 · Document 130 Conditionally-Reachable Modules")
P("")
P("These modules ARE wired but only fire under specific conditions:")
P("CLI flags, config toggles, scan modes, or feature gates. They look 'dead'")
P("to the static reality map but are part of the live system.")
P("")
P("### 2.1 Per-Subsystem CR Inventory")
P("")
cr_data = data["cr_alive_by_subsystem"]
for sub in sorted(cr_data, key=lambda s: -len(cr_data[s])):
    mods = cr_data[sub]
    if not mods: continue
    P(f"#### `{sub}` — {len(mods)} modules")
    P("")
    for m in sorted(mods)[:10]:
        P(f"- `{m}`")
    if len(mods) > 10:
        P(f"- _… and {len(mods) - 10} more — see `RECONNECTION_ROADMAP.json`_")
    P("")

P("### 2.2 Documentation Template (one per module)")
P("")
P("```markdown")
P("## Module: <fqn>")
P("- **Trigger:** <CLI flag | config key | EventBus topic | scan mode>")
P("- **Owner:** <subsystem entrypoint>")
P("- **Activation test:** `pytest tests/cr/test_<module>.py`")
P("- **Failure mode:** <what breaks if it doesn't activate>")
P("```")
P("")
P("**Exit criteria:** every CR module has a `# .. activates_when:` comment")
P("at the top, AND a test under `tests/cr/` proving the trigger fires the import.")
P("")
P("---")
P("")

# ── Phase 3: Reimplement lost modules (THE big one) ─────────────────────
P("## Phase 3 · Reimplement 201 Permanently Lost Modules")
P("")
P("**This is the production-grade reimplementation phase.** No source survived")
P("for these modules — neither in VS Code local history, the three workspace")
P("backups, the Shopigy flat-layout source, OneDrive, the Recycle Bin,")
P("Volume Shadow Copies, Windows File History, nor archived `.pyc` files.")
P("")
P("Reconstruction sources available:")
P("")
P("- 410 design notes under `/memories/repo/*.md` (most subsystems documented)")
P("- 382 dangling-import call sites (tells us the EXACT public API surface needed)")
P("- Surviving sibling modules in the same subsystem (style + patterns)")
P("- Canonical schemas: `canonical-finding-schema.md`, `recon-output-formats-schema.md`")
P("- EventBus topic registry (subscriber expectations)")
P("")
P("### 3.1 Subsystem Priority Order (by composite score)")
P("")
P("Score = (reconnect tasks × 5) + (lost modules × 2) + (CR alive)")
P("")
P("| Rank | Subsystem | Reconnect | Lost | CR Alive | Score | Phase |")
P("|------|-----------|-----------|------|----------|-------|-------|")
for i, (sub, d) in enumerate(list(data["subsystem_priority"].items())[:25], 1):
    phase = "3a" if d["score"] >= 30 else ("3b" if d["score"] >= 15 else "3c")
    P(f"| {i} | `{sub}` | {d['reconnect']} | {d['lost']} | {d['cr_alive']} | {d['score']} | {phase} |")
P("")

# Top subsystems get full reimpl plans
P("### 3.2 Reimplementation Plans by Subsystem")
P("")
P("Each plan contains: missing modules, recommended interfaces, dependency wire-up,")
P("test strategy, and acceptance criteria.")
P("")

reimpl = data["reimpl_tasks_by_subsystem"]
# Order by priority score
priority_order = list(data["subsystem_priority"].keys())

for sub in priority_order:
    if sub not in reimpl:
        continue
    mods = reimpl[sub]
    if not mods:
        continue
    pri = data["subsystem_priority"][sub]
    P(f"#### `{sub}` ({len(mods)} modules to reimplement)")
    P("")
    P(f"_Composite priority score: **{pri['score']}** · {pri['reconnect']} reconnect · {pri['cr_alive']} CR alive_")
    P("")
    P("**Modules:**")
    P("")
    for card in mods[:15]:
        P(f"- `{card['module']}`")
    if len(mods) > 15:
        P(f"- _… and {len(mods) - 15} more — see JSON_")
    P("")
    P("**Reconstruction protocol:**")
    P("")
    P("1. Grep `/memories/repo/` for matches on the module name and subsystem")
    P("2. List all dangling imports targeting these modules — that defines the public API")
    P("3. Inspect 3 surviving siblings in this subsystem for conventions")
    P(f"4. Stub each module under `CaseCrack/tools/burp_enterprise/{sub}/` with the imported names")
    P("5. Implement against the EventBus contract (subscribe to topics this subsystem owns)")
    P("6. Add unit tests: contract test (import + public API present) + at least one behavior test")
    P("7. Wire into the subsystem's entrypoint and re-run reality map")
    P("")
    P("---")
    P("")

# ── Phase 4: Hardening ──────────────────────────────────────────────────
P("## Phase 4 · Production Hardening (after each subsystem ships)")
P("")
P("Per-module gates before declaring 'production-grade':")
P("")
P("1. **Type completeness** — `mypy --strict` clean (or per-file pragma with TODO)")
P("2. **Test coverage** — ≥ 80% line coverage for each new module (`pytest --cov`)")
P("3. **Contract tests** — every EventBus topic has a producer test AND a consumer test")
P("4. **Schema conformance** — outputs validate against the canonical finding schema")
P("5. **Resource budget** — CPU + RSS + wall-clock recorded under the budget manager")
P("6. **Failure mode test** — kill-the-network + bad-config + malformed-input cases")
P("7. **Observability** — module emits structured logs with `module=` and `subsystem=` tags")
P("8. **Idempotency** — reruns produce identical findings (no random IDs in output)")
P("9. **Concurrency safety** — no global mutable state without a lock or queue")
P("10. **Documentation** — public-API docstring + subsystem README entry")
P("")
P("---")
P("")

# ── Phase 5: Verification ───────────────────────────────────────────────
P("## Phase 5 · End-to-End Verification")
P("")
P("After all subsystems ship:")
P("")
P("1. **Reality map** — reachable count ≥ 1000 / 1300+; dangling imports < 30")
P("2. **E2E scan** — full pipeline against `https://example.com` produces ≥ baseline findings")
P("3. **Performance baseline** — wall-clock within 110% of pre-incident baseline")
P("4. **Memory baseline** — peak RSS within 105% of pre-incident baseline")
P("5. **Audit pyramid** — every finding has chain-of-evidence back to a canonical signal")
P("6. **Reconnaissance corpus** — re-scan stored targets, diff findings against historical record")
P("")
P("---")
P("")

# ── Risk register ───────────────────────────────────────────────────────
P("## Risk Register")
P("")
P("| Risk | Likelihood | Impact | Mitigation |")
P("|------|-----------|--------|------------|")
P("| Reimplementation drifts from original behavior | High | Med | Pin behavior via E2E golden-file tests before deletion incidents repeat |")
P("| Recovered Shopigy/PayPal sources are stale (older API) | High | Med | Treat as starting point; rerun against the dangling-import surface to detect deltas |")
P("| Subsystem owners unknown — wiring assignments may go to wrong module | Med | Med | Phase 0.2 establishes ownership before Phase 1 starts |")
P("| EventBus contract not enforced — ad-hoc imports creep back | Med | High | Add a static checker that fails CI on cross-subsystem direct imports |")
P("| Cleanup script gets re-broken by a future change | Med | Critical | Phase 0.5 adds the regression test |")
P("")
P("---")
P("")

# ── Sequencing ──────────────────────────────────────────────────────────
P("## Suggested Sequencing")
P("")
P("```")
P("Week 1: Phase 0 (foundations) + start Phase 1 top-10 reconnects")
P("Week 2: Finish Phase 1 (50 reconnects) + Phase 2 docs for top 3 subsystems")
P("Week 3: Phase 3a — top-priority subsystems (scanners, agents, secrets)")
P("Week 4: Phase 3a continued (core_infra, pipeline, recon)")
P("Week 5: Phase 3b — medium-priority (output, misc, caap, cloud, discovery_pkg)")
P("Week 6: Phase 3c — remainder + Phase 4 hardening pass on every shipped module")
P("Week 7: Phase 5 verification + perf/memory baselining")
P("```")
P("")
P("---")
P("")
P("## Appendix · How to Use This Roadmap")
P("")
P("- Source data: [`RECONNECTION_ROADMAP.json`](RECONNECTION_ROADMAP.json)")
P("- Loss inventory: [`_final_loss_inventory.json`](_final_loss_inventory.json)")
P("- Recovery audit: [`_RECOVERY_REPORT.md`](_RECOVERY_REPORT.md)")
P("- Triage data: [`dead_module_triage.json`](dead_module_triage.json)")
P("- Classification: [`true_dead_classification.json`](true_dead_classification.json)")
P("- Current reality: [`execution_reality_map.json`](execution_reality_map.json)")
P("")
P("Each task should be opened as a GitHub-style issue (or todo list entry) with a")
P("link back to its row in the relevant table above.")

out = WORKSPACE / "RECONNECTION_ROADMAP.md"
out.write_text("\n".join(lines), encoding="utf-8")
print(f"Wrote {out} ({len(lines)} lines)")
