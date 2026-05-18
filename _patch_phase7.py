"""Patch: update Phase 7 gist findings generation with enriched output."""
import ast

FILEPATH = 'CaseCrack/tools/burp_enterprise/intel/github_deep_recon.py'

with open(FILEPATH, 'r', encoding='utf-8') as f:
    lines = f.readlines()

START = 2014  # 0-indexed (line 2015)
END   = 2043  # 0-indexed exclusive (up to blank line before Phase 8)

new_phase7 = [
    "        # Phase 7: gist search\n",
    "        if self._cfg.check_gists:\n",
    "            logger.emit(EventType.PHASE_START, {\"phase\": \"gist_search\"})\n",
    "            try:\n",
    "                # Pass org members for Strategy 5 (member gist crawl)\n",
    "                _member_logins = [m.login for m in report.org_members]\n",
    "                gists = GistSearcher(\n",
    "                    self._client,\n",
    "                    domain,\n",
    "                    self._cfg.max_gists,\n",
    "                    org_members=_member_logins,\n",
    "                ).run()\n",
    "                report.gist_results = gists\n",
    "                real_hits = [g for g in gists if not g.is_false_positive]\n",
    "                fp_hits   = [g for g in gists if g.is_false_positive]\n",
    "                for g in real_hits:\n",
    "                    # Determine finding type: GIST_SECRET if live secrets,\n",
    "                    # GIST_DELETED_SECRET if only in history, else GIST_MATCH\n",
    "                    if g.secrets_detected:\n",
    "                        ft = GHFindingType.GIST_SECRET\n",
    "                    elif g.deleted_secrets:\n",
    "                        ft = GHFindingType.GIST_SECRET  # historical leak still warrants attention\n",
    "                    else:\n",
    "                        ft = GHFindingType.GIST_MATCH\n",
    "\n",
    "                    secret_summary = \", \".join(g.secrets_detected) if g.secrets_detected else \"none\"\n",
    "                    hist_summary   = \", \".join(g.deleted_secrets)   if g.deleted_secrets   else \"none\"\n",
    "\n",
    "                    detail_parts = [f\"Secrets in content: {secret_summary}\"]\n",
    "                    if g.deleted_secrets:\n",
    "                        detail_parts.append(f\"Secrets in revision history (deleted): {hist_summary}\")\n",
    "                    if g.forks_count:\n",
    "                        detail_parts.append(f\"Forked {g.forks_count} time(s) — secret exposure may be wider\")\n",
    "\n",
    "                    remediation = (\n",
    "                        \"Revoke any leaked credentials immediately. \"\n",
    "                        \"Delete the gist or remove sensitive content and purge revision history. \"\n",
    "                        \"Note: gist fork history persists after deletion.\"\n",
    "                        if g.secrets_detected or g.deleted_secrets\n",
    "                        else \"Review the gist content for inadvertent information disclosure.\"\n",
    "                    )\n",
    "\n",
    "                    report.findings.append(\n",
    "                        GHFinding(\n",
    "                            finding_type=ft,\n",
    "                            severity=g.severity,\n",
    "                            title=(\n",
    "                                f\"Gist secret: {g.owner}/{g.filename}\"\n",
    "                                if g.secrets_detected else\n",
    "                                f\"Gist match: {g.owner}/{g.filename}\"\n",
    "                            ),\n",
    "                            detail=\"  |\".join(detail_parts),\n",
    "                            url=g.gist_url,\n",
    "                            evidence={\n",
    "                                \"gist_id\": g.gist_id,\n",
    "                                \"owner\": g.owner,\n",
    "                                \"filename\": g.filename,\n",
    "                                \"description\": g.description,\n",
    "                                \"secrets_in_content\": g.secrets_detected,\n",
    "                                \"secrets_in_history\": g.deleted_secrets,\n",
    "                                \"language\": g.language,\n",
    "                                \"file_size_bytes\": g.file_size,\n",
    "                                \"file_count\": g.file_count,\n",
    "                                \"is_public\": g.is_public,\n",
    "                                \"forks\": g.forks_count,\n",
    "                                \"revisions\": g.revision_count,\n",
    "                                \"created_at\": g.created_at,\n",
    "                                \"updated_at\": g.updated_at,\n",
    "                                \"search_strategy\": g.search_strategy,\n",
    "                                \"confidence\": g.confidence,\n",
    "                                \"domain_match_score\": round(g.domain_match_score, 3),\n",
    "                                \"snippet\": g.snippet[:300],\n",
    "                                \"raw_url\": g.raw_url,\n",
    "                            },\n",
    "                            remediation=remediation,\n",
    "                            references=[\n",
    "                                g.gist_url,\n",
    "                                \"https://docs.github.com/en/site-policy/privacy-policies/github-privacy-statement#github-gists\",\n",
    "                            ],\n",
    "                        )\n",
    "                    )\n",
    "                logger.emit(\n",
    "                    EventType.PHASE_COMPLETE,\n",
    "                    {\n",
    "                        \"phase\": \"gist_search\",\n",
    "                        \"count\": len(gists),\n",
    "                        \"real\": len(real_hits),\n",
    "                        \"fp_suppressed\": len(fp_hits),\n",
    "                        \"with_secrets\": sum(1 for g in real_hits if g.secrets_detected),\n",
    "                        \"with_deleted_secrets\": sum(1 for g in real_hits if g.deleted_secrets),\n",
    "                    },\n",
    "                )\n",
    "            except (KeyError, OSError, Exception) as exc:\n",
    "                logger.debug(\"Suppressed %s in _run_phases\", type(exc).__name__, exc_info=True)\n",
    "                report.errors.append(f\"Gist search: {exc}\")\n",
    "\n",
]

new_lines = lines[:START] + new_phase7 + lines[END:]
with open(FILEPATH, 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print(f"Replaced {END - START} lines with {len(new_phase7)} lines in Phase 7 block")

with open(FILEPATH, 'r', encoding='utf-8') as f:
    src = f.read()
try:
    ast.parse(src)
    print("Syntax OK")
except SyntaxError as e:
    print(f"SyntaxError: {e}")
