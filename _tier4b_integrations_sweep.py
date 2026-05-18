"""Tier 4B Integrations sweep — idempotent injection of tail blocks into 6 integration modules."""
import pathlib
import sys

ROOT = pathlib.Path(__file__).parent
TARGETS = {
    "ci_cd_pipeline": "_tier4b_int_ci_cd_pipeline.tail.py",
    "defect_dojo": "_tier4b_int_defect_dojo.tail.py",
    "jira_client": "_tier4b_int_jira_client.tail.py",
    "slack_notifier": "_tier4b_int_slack_notifier.tail.py",
    "sonarqube": "_tier4b_int_sonarqube.tail.py",
    "webhook_dispatcher": "_tier4b_int_webhook_dispatcher.tail.py",
}
MARKER = "# __TIER4B_INTEGRATIONS__"
PKG = ROOT / "CaseCrack" / "tools" / "burp_enterprise" / "integrations"


def main() -> int:
    applied = 0
    skipped = 0
    grew = []
    for mod_name, tail_filename in TARGETS.items():
        target = PKG / f"{mod_name}.py"
        tail = ROOT / tail_filename
        if not target.exists():
            print(f"  MISS: {target}")
            continue
        if not tail.exists():
            print(f"  MISS tail: {tail}")
            continue
        src = target.read_text(encoding="utf-8")
        before_loc = src.count("\n")
        if MARKER in src and mod_name in src.split(MARKER, 1)[1][:200]:
            skipped += 1
            print(f"  SKIP {mod_name} (marker present)")
            continue
        tail_src = tail.read_text(encoding="utf-8")
        new = src.rstrip() + "\n\n" + tail_src.rstrip() + "\n"
        target.write_text(new, encoding="utf-8")
        after_loc = new.count("\n")
        grew.append((mod_name, before_loc, after_loc))
        applied += 1
        print(f"  APPLY {mod_name}: {before_loc} -> {after_loc} LOC (+{after_loc - before_loc})")
    print(f"\n=== APPLIED: {applied}, SKIPPED: {skipped} ===")
    if grew:
        total_before = sum(b for _, b, _ in grew)
        total_after = sum(a for _, _, a in grew)
        print(f"Total LOC: {total_before} -> {total_after} (+{total_after - total_before})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
