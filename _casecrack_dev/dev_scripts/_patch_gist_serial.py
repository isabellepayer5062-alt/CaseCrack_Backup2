"""Patch: expand gist_results serialization to include all new fields."""
import ast

FILEPATH = 'CaseCrack/tools/burp_enterprise/intel/github_deep_recon.py'

with open(FILEPATH, 'r', encoding='utf-8') as f:
    lines = f.readlines()

START = 2320  # 0-indexed (line 2321: "gist_results": [)
END   = 2329  # 0-indexed exclusive (line 2330: "wiki_results")

new_serial = [
    '        "gist_results": [\n',
    '            {\n',
    '                "gist_id": g.gist_id,\n',
    '                "gist_url": g.gist_url,\n',
    '                "owner": g.owner,\n',
    '                "filename": g.filename,\n',
    '                "description": g.description,\n',
    '                "language": g.language,\n',
    '                "file_size_bytes": g.file_size,\n',
    '                "file_count": g.file_count,\n',
    '                "is_public": g.is_public,\n',
    '                "created_at": g.created_at,\n',
    '                "updated_at": g.updated_at,\n',
    '                "forks": g.forks_count,\n',
    '                "comments": g.comments_count,\n',
    '                "revisions": g.revision_count,\n',
    '                "secrets_in_content": g.secrets_detected,\n',
    '                "secrets_in_history": g.deleted_secrets,\n',
    '                "severity": g.severity.value,\n',
    '                "confidence": g.confidence,\n',
    '                "domain_match_score": round(g.domain_match_score, 3),\n',
    '                "search_strategy": g.search_strategy,\n',
    '                "is_false_positive": g.is_false_positive,\n',
    '                "fp_reason": g.fp_reason,\n',
    '                "raw_url": g.raw_url,\n',
    '                "snippet": g.snippet[:300],\n',
    '            }\n',
    '            for g in report.gist_results\n',
    '        ],\n',
]

new_lines = lines[:START] + new_serial + lines[END:]
with open(FILEPATH, 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print(f"Replaced {END - START} lines with {len(new_serial)} lines in gist_results serialization")

with open(FILEPATH, 'r', encoding='utf-8') as f:
    src = f.read()
try:
    ast.parse(src)
    print("Syntax OK")
except SyntaxError as e:
    print(f"SyntaxError: {e}")
