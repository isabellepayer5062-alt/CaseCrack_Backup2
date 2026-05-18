"""Patch: replace GistSearcher with full multi-strategy commercial-grade implementation."""
import ast

FILEPATH = 'CaseCrack/tools/burp_enterprise/intel/github_deep_recon.py'

with open(FILEPATH, 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Find GistSearcher class start and WikiEnumerator start (end marker)
gist_start = None
wiki_start = None
for i, line in enumerate(lines):
    if 'class GistSearcher:' in line and gist_start is None:
        gist_start = i
    if 'class WikiEnumerator:' in line and gist_start is not None:
        wiki_start = i
        break

print(f"GistSearcher at line {gist_start+1}, WikiEnumerator at line {wiki_start+1}")

NEW_GIST_SEARCHER = '''\
# ---------------------------------------------------------------------------
# Gist scoring constants
# ---------------------------------------------------------------------------

# Secret types that are immediately HIGH/CRITICAL severity
_CRITICAL_SECRET_TYPES = frozenset({
    "aws_key", "aws_secret", "private_key", "github_token", "github_fine_grained",
    "stripe_key", "jwt",
})

# Tools / scanners that publish their own code as gists — common false positives
# when scanning targets that use popular security frameworks.
_SCANNER_FP_OWNERS: frozenset[str] = frozenset({
    "Sandmanmmm719",   # CaseCrack own repo
    "gitleaks",
    "trufflesecurity",
    "github",
    "dependabot",
    "renovate-bot",
    "snyk-bot",
})

# Gist filenames that are almost always false positives (test fixtures / docs)
_FP_FILENAME_PATTERNS = (
    "test_", "_test.", "fixture", "example", "sample", "demo",
    "README", "CHANGELOG", "CONTRIBUTING",
)


def _compute_domain_match_score(domain: str, text: str) -> float:
    """Return 0.0–1.0 for how strongly *domain* appears in *text*."""
    if not text:
        return 0.0
    tl = text.lower()
    dl = domain.lower()
    base = dl.split(".")[0]          # e.g. "sugarrushed" from "sugarrushed.ca"
    if dl in tl:
        return 1.0                   # exact domain in content
    if f".{base}." in tl or f"/{base}/" in tl or f"@{base}" in tl:
        return 0.8                   # base in common URL/email pattern
    if base in tl:
        return 0.5                   # bare base domain keyword
    return 0.1                       # matched only via search API (weak)


def _is_fp_gist(owner: str, filename: str, description: str) -> tuple[bool, str]:
    """Check common false-positive signals. Returns (is_fp, reason)."""
    if owner in _SCANNER_FP_OWNERS:
        return True, f"gist owner '{owner}' is a known scanner/tool account"
    fn_lower = filename.lower()
    for pat in _FP_FILENAME_PATTERNS:
        if pat.lower() in fn_lower:
            return True, f"filename '{filename}' matches false-positive pattern '{pat}'"
    return False, ""


def _severity_from_secrets(secrets: list[str], base: GHSeverity = GHSeverity.MEDIUM) -> GHSeverity:
    """Escalate severity if critical secrets were found."""
    if not secrets:
        return base
    if any(s in _CRITICAL_SECRET_TYPES for s in secrets):
        return GHSeverity.CRITICAL
    return GHSeverity.HIGH


class GistSearcher:
    """Phase 7: multi-strategy gist intelligence engine.

    Strategies executed (in order, up to ``max_gists`` total unique results):

    1. **Code search — exact domain** ``"{domain}" in:file``
    2. **Code search — base domain + secret keywords** (``password``, ``secret``,
       ``api_key``, ``token``) to maximise recall for secrets that co-occur with
       the domain.
    3. **Code search — sensitive extensions** (``.env``, ``.yaml``, ``.json``)
       containing the domain.
    4. **Description search** — ``GET /gists/public`` stream filtered by domain
       in the *description* field (misses content-only search above).
    5. **Org-member gist crawl** — if org members were discovered earlier, fetch
       each member's public gists and scan for domain mentions.

    For each unique gist found the searcher:
    - Fetches the full content via ``GET /gists/{id}``
    - Runs the full ``_SECRET_RE`` pattern bank over the complete text
    - Scans up to the 3 most recent revision snapshots for *deleted* secrets
    - Computes a ``domain_match_score`` and ``confidence`` for prioritisation
    - Applies false-positive heuristics (scanner accounts, test filenames, etc.)
    """

    def __init__(
        self,
        client: GitHubAPIClient,
        domain: str,
        max_gists: int = 50,
        org_members: list[str] | None = None,
    ) -> None:
        self._client = client
        self._domain = domain
        self._max_gists = max_gists
        self._org_members: list[str] = org_members or []

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self) -> list[GHGistResult]:
        seen_gist_ids: set[str] = set()
        raw_hits: list[tuple[dict, str]] = []   # (code_search_item, strategy)

        # ── Strategy 1: exact domain code search ──────────────────────
        self._code_search(f'"{self._domain}"', "code_exact", raw_hits, seen_gist_ids)

        # ── Strategy 2: domain + secret keyword variants ──────────────
        base = self._domain.split(".")[0]
        for kw in ("password", "secret", "api_key", "token", "credentials"):
            if len(raw_hits) >= self._max_gists * 2:
                break
            self._code_search(f'"{base}" {kw}', f"code_kw_{kw}", raw_hits, seen_gist_ids)

        # ── Strategy 3: sensitive extension + domain ──────────────────
        for ext in ("env", "yaml", "json", "config"):
            if len(raw_hits) >= self._max_gists * 3:
                break
            self._code_search(
                f'"{base}" extension:{ext}',
                f"code_ext_{ext}",
                raw_hits,
                seen_gist_ids,
            )

        # ── Strategy 4: description-field search ──────────────────────
        desc_gists = self._client.search_gists_by_description(self._domain) or []
        for g in desc_gists:
            gist_id = g.get("id", "")
            if not gist_id or gist_id in seen_gist_ids:
                continue
            seen_gist_ids.add(gist_id)
            raw_hits.append((g, "description"))

        # ── Strategy 5: org-member gist crawl ─────────────────────────
        for member in self._org_members[:20]:   # cap at 20 members
            if len(raw_hits) >= self._max_gists * 4:
                break
            member_gists = self._client.list_user_gists(member) or []
            for g in member_gists:
                gist_id = g.get("id", "")
                if not gist_id or gist_id in seen_gist_ids:
                    continue
                # Check if domain appears in description or any file name
                desc = (g.get("description") or "").lower()
                file_names = " ".join(g.get("files", {}).keys()).lower()
                if self._domain.lower() in desc or self._domain.split(".")[0] in file_names:
                    seen_gist_ids.add(gist_id)
                    raw_hits.append((g, f"member:{member}"))

        # ── Hydrate each hit into GHGistResult ────────────────────────
        results: list[GHGistResult] = []
        for item, strategy in raw_hits[: self._max_gists]:
            result = self._hydrate(item, strategy)
            if result is not None:
                results.append(result)

        # Sort: secrets first, then by confidence desc
        results.sort(
            key=lambda r: (
                0 if r.secrets_detected or r.deleted_secrets else 1,
                -r.confidence,
            )
        )
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _code_search(
        self,
        query: str,
        strategy: str,
        out: list[tuple[dict, str]],
        seen: set[str],
    ) -> None:
        """Run one code-search query and append gist-only hits to *out*."""
        items = self._client.search_gists(query) or []
        for item in items:
            html_url = item.get("html_url", "")
            # Code search returns both repo files and gist files; filter to gists
            if "gist.github.com" not in html_url:
                continue
            repo_info = item.get("repository", {})
            gist_id = repo_info.get("name", "")
            if not gist_id or gist_id in seen:
                continue
            seen.add(gist_id)
            out.append((item, strategy))

    def _hydrate(self, item: dict, strategy: str) -> "GHGistResult | None":
        """Convert a raw API item to a fully populated GHGistResult."""
        # Determine gist_id from either code-search item or list-gist item
        repo_info = item.get("repository", {})
        gist_id = repo_info.get("name", "") or item.get("id", "")
        if not gist_id:
            return None

        owner = (
            repo_info.get("owner", {}).get("login", "")
            or (item.get("owner") or {}).get("login", "unknown")
        )
        html_url = item.get("html_url", "") or f"https://gist.github.com/{owner}/{gist_id}"
        filename = item.get("path", "") or next(iter(item.get("files", {})), "")
        description = item.get("description", "")

        # Collect snippet from text_matches (code search path)
        snippet = ""
        for tm in item.get("text_matches", []):
            snippet += tm.get("fragment", "") + "\\n"

        # ── Fetch full content ─────────────────────────────────────────
        full_text = snippet
        full_data: dict = {}
        raw_url = ""
        language = ""
        file_size = 0
        file_count = 0
        is_public = True
        created_at = ""
        updated_at = ""
        forks_count = 0
        comments_count = 0

        gist_detail = self._client.fetch_gist(gist_id)
        if gist_detail:
            full_data = gist_detail
            is_public = gist_detail.get("public", True)
            created_at = gist_detail.get("created_at", "")
            updated_at = gist_detail.get("updated_at", "")
            comments_count = gist_detail.get("comments", 0)
            forks_count = len(gist_detail.get("forks", []))
            files = gist_detail.get("files", {})
            file_count = len(files)
            description = gist_detail.get("description", description)
            owner_data = gist_detail.get("owner") or {}
            owner = owner_data.get("login", owner)

            # Collect raw content from all files
            all_content_parts: list[str] = []
            for fname, fdata in files.items():
                if not filename:
                    filename = fname
                raw_url = raw_url or fdata.get("raw_url", "")
                language = language or fdata.get("language", "")
                file_size += fdata.get("size", 0)
                content = fdata.get("content", "")
                if content:
                    all_content_parts.append(content)
                elif fdata.get("truncated"):
                    # Fetch raw content for truncated files
                    raw = self._client.api_get_raw(fdata.get("raw_url", ""))
                    if raw:
                        all_content_parts.append(raw)

            full_text = "\\n".join(all_content_parts) or snippet

        # ── Secret extraction on full content ─────────────────────────
        secrets_in_content = [stype for stype, _ in _extract_secrets_from_text(full_text)]

        # ── History scan for deleted secrets ──────────────────────────
        deleted_secrets: list[str] = []
        commits = self._client.list_gist_commits(gist_id) or []
        revision_count = len(commits)
        # Check up to 3 old revisions for previously-leaked secrets
        for commit in commits[1:4]:
            sha = commit.get("version", "")
            if not sha:
                continue
            rev = self._client.fetch_gist_revision(gist_id, sha)
            if not rev:
                continue
            rev_files = rev.get("files") or {}
            for _, fdata in rev_files.items():
                old_content = fdata.get("content", "") if fdata else ""
                if not old_content:
                    old_url = (fdata or {}).get("raw_url", "")
                    if old_url:
                        old_content = self._client.api_get_raw(old_url) or ""
                for stype, _ in _extract_secrets_from_text(old_content):
                    if stype not in secrets_in_content and stype not in deleted_secrets:
                        deleted_secrets.append(stype)

        # ── False-positive detection ───────────────────────────────────
        is_fp, fp_reason = _is_fp_gist(owner, filename, description)

        # ── Domain match score ─────────────────────────────────────────
        dm_score = _compute_domain_match_score(
            self._domain,
            full_text + " " + description + " " + filename,
        )

        # ── Severity ──────────────────────────────────────────────────
        all_secrets = list(dict.fromkeys(secrets_in_content + deleted_secrets))
        base_sev = GHSeverity.INFO if is_fp else GHSeverity.MEDIUM
        severity = _severity_from_secrets(all_secrets, base_sev)

        # ── Confidence (0-100) ────────────────────────────────────────
        # Base: domain match score, boosted by secrets, penalised by FP
        confidence = int(dm_score * 60)                   # 0-60 from domain relevance
        if secrets_in_content:
            confidence += 30
        elif deleted_secrets:
            confidence += 15
        if forks_count > 0:
            confidence += 5                               # wider exposure
        if is_fp:
            confidence = min(confidence, 15)              # cap FP at low confidence
        confidence = min(confidence, 100)

        return GHGistResult(
            gist_id=gist_id,
            gist_url=html_url,
            description=description,
            owner=owner,
            filename=filename,
            snippet=(full_text[:800] if full_text else snippet[:500]),
            secrets_detected=secrets_in_content,
            severity=severity,
            raw_url=raw_url,
            language=language,
            file_size=file_size,
            file_count=file_count,
            is_public=is_public,
            created_at=created_at,
            updated_at=updated_at,
            forks_count=forks_count,
            comments_count=comments_count,
            revision_count=revision_count,
            deleted_secrets=deleted_secrets,
            confidence=confidence,
            domain_match_score=dm_score,
            search_strategy=strategy,
            is_false_positive=is_fp,
            fp_reason=fp_reason,
        )

'''

# Encode as bytes to avoid any encoding issues
new_lines = lines[:gist_start] + [NEW_GIST_SEARCHER] + lines[wiki_start:]

with open(FILEPATH, 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

replaced = wiki_start - gist_start
print(f"Replaced {replaced} lines with {len(NEW_GIST_SEARCHER.splitlines())} lines of new GistSearcher")

with open(FILEPATH, 'r', encoding='utf-8') as f:
    src = f.read()
try:
    ast.parse(src)
    print("Syntax OK")
except SyntaxError as e:
    print(f"SyntaxError: {e}")
