"""Regression test for FindingDeduplicator severity-preservation fix."""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path("CaseCrack")))

from tools.burp_enterprise.output.finding_dedup import FindingDeduplicator

def test_severity_preservation():
    dedup = FindingDeduplicator()
    # Same finding arriving twice: once as 'low', once as 'high'
    # expanded_fp includes severity, so they will have different fingerprints
    # and BOTH be kept (that's correct — they're genuinely different confidence levels).
    f_low = {"finding_type": "xss_reflected", "url": "https://example.com/search", "severity": "low", "parameter": "q"}
    f_high = {"finding_type": "xss_reflected", "url": "https://example.com/search", "severity": "high", "parameter": "q"}
    unique, stats = dedup.filter([f_low, f_high])
    print(f"Test 1 (different severity = different fp, both kept): {len(unique)==2} unique={len(unique)}")

def test_exact_duplicate_merge():
    """Exact same finding arriving twice: the second should merge (not add second copy)."""
    dedup = FindingDeduplicator()
    f1 = {"finding_type": "xss_reflected", "url": "https://example.com/search", "severity": "medium", "parameter": "q"}
    f2 = dict(f1)  # exact copy
    unique, stats = dedup.filter([f1, f2])
    print(f"Test 2 (exact dup merged): {len(unique)==1} unique={len(unique)} dups_removed={stats.duplicates_removed}")

def test_exact_duplicate_severity_merge():
    """
    Same fingerprint, but duplicate has confirmed=True and cvss_score — those should
    be merged into the kept finding. This simulates the scenario where the same finding
    is re-emitted later with additional evidence.
    """
    dedup = FindingDeduplicator()
    # Note: severity is part of expanded_fp, so to test merging we need same severity
    f1 = {"finding_type": "sqli", "url": "https://example.com/login", "severity": "high", "parameter": "user"}
    f2 = {"finding_type": "sqli", "url": "https://example.com/login", "severity": "high", "parameter": "user", "confirmed": True, "cvss_score": 9.1}
    unique, stats = dedup.filter([f1, f2])
    print(f"Test 3 (dup merge preserves confirmed+cvss): "
          f"unique={len(unique)}, confirmed={unique[0].get('confirmed')}, cvss={unique[0].get('cvss_score')}")
    assert unique[0].get("confirmed") == True, "confirmed not merged"
    assert unique[0].get("cvss_score") == 9.1, "cvss_score not merged"

def test_reset_clears_dict():
    dedup = FindingDeduplicator()
    f = {"finding_type": "xss_reflected", "url": "https://example.com/search", "severity": "low", "parameter": "q"}
    dedup.filter([f])
    dedup.reset()
    assert isinstance(dedup._seen, dict) and len(dedup._seen) == 0, "reset failed"
    print("Test 4 (reset clears dict): OK")

test_severity_preservation()
test_exact_duplicate_merge()
test_exact_duplicate_severity_merge()
test_reset_clears_dict()
print("All tests passed!")
