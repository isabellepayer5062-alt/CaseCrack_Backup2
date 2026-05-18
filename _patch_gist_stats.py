"""Patch: expand stats block with rich gist metrics."""
import ast

FILEPATH = 'CaseCrack/tools/burp_enterprise/intel/github_deep_recon.py'

with open(FILEPATH, 'r', encoding='utf-8') as f:
    lines = f.readlines()

START = 2161  # 0-indexed (line 2162: gist_matches)
END   = 2163  # 0-indexed exclusive (line 2164: wiki_matches)

new_stats = [
    '            "gist_matches": len(report.gist_results),\n',
    '            "gist_with_secrets": sum(1 for g in report.gist_results if g.secrets_detected),\n',
    '            "gist_with_deleted_secrets": sum(1 for g in report.gist_results if g.deleted_secrets),\n',
    '            "gist_false_positives": sum(1 for g in report.gist_results if g.is_false_positive),\n',
    '            "gist_high_confidence": sum(1 for g in report.gist_results if g.confidence >= 70),\n',
]

new_lines = lines[:START] + new_stats + lines[END:]
with open(FILEPATH, 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print(f"Replaced {END - START} lines with {len(new_stats)} lines in stats block")

with open(FILEPATH, 'r', encoding='utf-8') as f:
    src = f.read()
try:
    ast.parse(src)
    print("Syntax OK")
except SyntaxError as e:
    print(f"SyntaxError: {e}")
